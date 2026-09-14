// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/sshtest"
)

// The tests in this file are about what a channel's teardown waits for, so
// they drive the two goroutines that race in it rather than watching them.
//
// The defect they cover — pump closing the client's half while a request the
// client is blocked on has been accepted by the target but not yet relayed
// back — was reported as a 1-in-70 flake in the two tests that send pty-req
// and exec on one channel. That flake is the symptom, and it is not a test: it
// depends on losing a race. What makes the ordering drivable is replacing the
// target's half of the pump with something the test decides for — when the
// output has drained, and when the request is answered — which a real target,
// answering as fast as its own scheduler allows, cannot be made to do without
// a sleep.

// withExitGrace shortens the teardown bound for one test and puts it back
// afterwards. Nothing in this package runs in parallel, and nothing outside a
// test writes it.
func withExitGrace(t *testing.T, d time.Duration) {
	t.Helper()
	previous := exitGrace
	exitGrace = d
	t.Cleanup(func() { exitGrace = previous })
}

// stalledTarget is the far half of a pump, driven by hand.
type stalledTarget struct {
	sent   chan struct{} // closed once a request is at the target, unanswered
	answer chan bool     // what the target answers, if it ever does
	drain  chan struct{} // closed when the channel's output has run out
	closed chan struct{} // closed when the proxy closes the target's half

	sentOnce  sync.Once
	closeOnce sync.Once
}

var _ ssh.Channel = (*stalledTarget)(nil)

func newStalledTarget() *stalledTarget {
	return &stalledTarget{
		sent:   make(chan struct{}),
		answer: make(chan bool, 1),
		drain:  make(chan struct{}),
		closed: make(chan struct{}),
	}
}

// Read is the target's output, and it ends when the test says the command has
// finished. Draining it is what releases pump into its teardown.
func (t *stalledTarget) Read([]byte) (int, error) {
	<-t.drain
	return 0, io.EOF
}

func (t *stalledTarget) Write(p []byte) (int, error) { return len(p), nil }

func (t *stalledTarget) CloseWrite() error { return nil }

func (t *stalledTarget) Close() error {
	t.closeOnce.Do(func() { close(t.closed) })
	return nil
}

func (t *stalledTarget) Stderr() io.ReadWriter { return stalledStderr{t} }

// SendRequest is the relay the defect loses. It reports that the request has
// reached the target and then waits — for the answer the test hands it, or for
// the proxy to close the channel out from under it, whichever happens first.
func (t *stalledTarget) SendRequest(string, bool, []byte) (bool, error) {
	t.sentOnce.Do(func() { close(t.sent) })
	select {
	case ok := <-t.answer:
		return ok, nil
	case <-t.closed:
		return false, io.EOF
	}
}

// stalledStderr is the target's stderr, and drains with the rest of its output.
type stalledStderr struct{ target *stalledTarget }

func (s stalledStderr) Read([]byte) (int, error) {
	<-s.target.drain
	return 0, io.EOF
}

func (s stalledStderr) Write(p []byte) (int, error) { return len(p), nil }

// clientChannel is a real SSH connection with one channel open on it: near is
// the half pump is given, and client is what a user's SSH client holds. The
// client half has to be real, because the lost answer is only observable as
// what the client's own SendRequest returns.
type clientChannel struct {
	client     *ssh.Client
	clientCh   ssh.Channel
	clientReqs <-chan *ssh.Request
	near       ssh.Channel
	nearReqs   <-chan *ssh.Request
}

func newClientChannel(t *testing.T) *clientChannel {
	t.Helper()

	// A loopback socket rather than net.Pipe: the version exchange has both
	// ends writing before either reads, which an unbuffered pipe deadlocks on.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	serverCfg := &ssh.ServerConfig{NoClientAuth: true}
	serverCfg.AddHostKey(sshtest.MustGenerateSigner())

	type serverSide struct {
		conn  *ssh.ServerConn
		chans <-chan ssh.NewChannel
		reqs  <-chan *ssh.Request
		err   error
	}
	accepted := make(chan serverSide, 1)
	go func() {
		serverConn, err := listener.Accept()
		if err != nil {
			accepted <- serverSide{err: err}
			return
		}
		conn, chans, reqs, err := ssh.NewServerConn(serverConn, serverCfg)
		accepted <- serverSide{conn, chans, reqs, err}
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn, chans, reqs, err := ssh.NewClientConn(clientConn, listener.Addr().String(), &ssh.ClientConfig{
		User:            testLogin,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	client := ssh.NewClient(conn, chans, reqs)
	t.Cleanup(func() { _ = client.Close() })

	server := <-accepted
	if server.err != nil {
		t.Fatalf("server handshake: %v", server.err)
	}
	t.Cleanup(func() { _ = server.conn.Close() })
	// Answering connection-level requests is what makes roundTrip a barrier.
	go ssh.DiscardRequests(server.reqs)

	type openedByClient struct {
		ch   ssh.Channel
		reqs <-chan *ssh.Request
		err  error
	}
	opened := make(chan openedByClient, 1)
	go func() {
		ch, chReqs, err := client.OpenChannel(channelSession, nil)
		opened <- openedByClient{ch, chReqs, err}
	}()

	newChannel, ok := <-server.chans
	if !ok {
		t.Fatal("the client opened no channel")
	}
	near, nearReqs, err := newChannel.Accept()
	if err != nil {
		t.Fatalf("accept channel: %v", err)
	}
	result := <-opened
	if result.err != nil {
		t.Fatalf("open channel: %v", result.err)
	}

	return &clientChannel{
		client:     client,
		clientCh:   result.ch,
		clientReqs: result.reqs,
		near:       near,
		nearReqs:   nearReqs,
	}
}

// roundTrip runs one request the whole way to the far end of the client's
// connection and back.
//
// It is the barrier these tests are ordered against: once it has returned, the
// proxy has had a complete round trip's worth of time in which to run the two
// statements of a teardown. A close that was going to happen has happened.
func (c *clientChannel) roundTrip(t *testing.T) {
	t.Helper()
	if _, _, err := c.client.SendRequest("teardown-barrier@hoplock", true, nil); err != nil {
		t.Fatalf("barrier round trip: %v", err)
	}
}

// exitStatusRequest is the target's last word, and the message whose ordering
// pump already held: captured as it arrives and replayed once the output has
// drained.
func exitStatusRequest(status uint32) *ssh.Request {
	return &ssh.Request{
		Type:    requestExitStatus,
		Payload: ssh.Marshal(struct{ Status uint32 }{status}),
	}
}

// TestAChannelRequestIsAnsweredBeforeItsChannelCloses is the regression.
//
// The client sends an exec and blocks on the answer. The target accepts it,
// and while the answer is still in flight everything teardown waits for
// happens: the output drains and the exit status arrives. The proxy must not
// close the client's half in that window — the target said yes, and a client
// that can tell "exec refused" from "the channel ended" would read a permitted
// command as a denied one (PLAN §4.3, §6.3).
func TestAChannelRequestIsAnsweredBeforeItsChannelCloses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pair := newClientChannel(t)
	target := newStalledTarget()
	targetReqs := make(chan *ssh.Request, 1)
	targetReqs <- exitStatusRequest(0)
	close(targetReqs)

	s := &session{ctx: ctx, id: testSessionID}
	pumped := make(chan struct{})
	go func() {
		defer close(pumped)
		s.pump(pair.near, pair.nearReqs, target, targetReqs, nil)
	}()

	type answer struct {
		ok  bool
		err error
	}
	answered := make(chan answer, 1)
	go func() {
		ok, err := pair.clientCh.SendRequest(requestExec, true, ssh.Marshal(struct{ Command string }{"true"}))
		answered <- answer{ok, err}
	}()

	<-target.sent

	// The command has finished faster than the proxy could relay the answer to
	// the request that started it, which is every `true`, every `uptime`, and
	// every one-liner on a fast target.
	close(target.drain)
	pair.roundTrip(t)

	target.answer <- true

	got := <-answered
	if got.err != nil {
		t.Fatalf("the client's exec was cut off: %v; want the target's answer", got.err)
	}
	if !got.ok {
		t.Error("the client was told its exec failed; the target accepted it")
	}

	// Only now, after the answer: the client's channel requests were never read
	// while the exec was outstanding, so this is the exit status teardown
	// replayed once the answer was out.
	select {
	case req, ok := <-pair.clientReqs:
		if !ok {
			t.Fatal("the channel ended without an exit status")
		}
		if req.Type != requestExitStatus {
			t.Errorf("first channel request = %q, want %q", req.Type, requestExitStatus)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no exit status reached the client")
	}

	select {
	case <-pumped:
	case <-time.After(10 * time.Second):
		t.Fatal("pump did not unwind")
	}
}

// TestATargetThatNeverAnswersDoesNotHoldTheChannelOpen is the bound, and it is
// what stops the fix above from being a deadlock.
//
// Waiting for the near-side forwarder to RETURN — moving pump's all.Wait()
// above the closes — would hang here forever: it ranges over the client's
// request stream, and that stream does not close until the channel does. The
// wait is therefore a grace, and it is exitGrace, the same bound the target's
// exit status gets.
func TestATargetThatNeverAnswersDoesNotHoldTheChannelOpen(t *testing.T) {
	withExitGrace(t, 200*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pair := newClientChannel(t)
	go ssh.DiscardRequests(pair.clientReqs)
	target := newStalledTarget()
	targetReqs := make(chan *ssh.Request, 1)
	targetReqs <- exitStatusRequest(0)
	close(targetReqs)

	s := &session{ctx: ctx, id: testSessionID}
	pumped := make(chan struct{})
	go func() {
		defer close(pumped)
		s.pump(pair.near, pair.nearReqs, target, targetReqs, nil)
	}()

	answered := make(chan error, 1)
	go func() {
		_, err := pair.clientCh.SendRequest(requestExec, true, ssh.Marshal(struct{ Command string }{"true"}))
		answered <- err
	}()

	<-target.sent
	started := time.Now()
	close(target.drain)

	// The client is answered rather than left hanging. Nothing ever came back
	// from the target, so the answer it gets is the end of its channel — which
	// is the correct outcome, and the reason this wait is bounded.
	select {
	case err := <-answered:
		if err == nil {
			t.Error("the client was told the target accepted a request it never answered")
		}
	case <-time.After(20 * exitGrace):
		t.Fatal("the client was left hanging on a request the target never answered")
	}

	select {
	case <-pumped:
	case <-time.After(20 * exitGrace):
		t.Fatal("the channel was held open by a request the target never answered")
	}

	elapsed := time.Since(started)
	if elapsed < exitGrace {
		t.Errorf("teardown waited %v, want at least the %v grace: an answer already on its way is lost", elapsed, exitGrace)
	}
	if elapsed > 10*exitGrace {
		t.Errorf("teardown waited %v, want no more than a few times the %v grace", elapsed, exitGrace)
	}
}
