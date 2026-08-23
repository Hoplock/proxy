// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSH channel and request names this engine reasons about by name. Everything
// else is forwarded generically (D5): the proxy proxies channel types it has
// never heard of, and only Hoplock Control's allow-list decides which are
// allowed to exist.
const (
	channelSession = "session"

	requestPTY        = "pty-req"
	requestShell      = "shell"
	requestExec       = "exec"
	requestSubsystem  = "subsystem"
	requestExitStatus = "exit-status"
	requestExitSignal = "exit-signal"
)

// exitGrace bounds how long a finished channel waits for the target's
// exit-status after its output has been drained. A well-behaved server sends
// exit-status and closes immediately; this stops one that does not from pinning
// the client's channel open.
const exitGrace = 5 * time.Second

// openedChannel is the result of opening the far side of a channel.
type openedChannel struct {
	ch   ssh.Channel
	reqs <-chan *ssh.Request
	err  error
}

// handleClientChannel proxies one channel the client opened.
func (s *session) handleClientChannel(nc ssh.NewChannel) {
	if nc.ChannelType() == channelSession {
		s.handleSessionChannel(nc)
		return
	}

	// Every other channel type needs the target leg before it can exist: there
	// is nothing to write to on an unopened channel, so the honest answer to a
	// failure is a rejection carrying the reason.
	if err := s.waitReady(); err != nil {
		s.rejectChannel(nc, ssh.ConnectionFailed, err)
		return
	}
	if !s.route.ChannelPermitted(nc.ChannelType()) {
		s.logf("proxy: session=%s channel %q refused: not permitted by policy", s.id, nc.ChannelType())
		_ = nc.Reject(ssh.Prohibited, deniedChannelText(nc.ChannelType()))
		return
	}
	leg, err := s.legConnWhenReady()
	if err != nil {
		s.rejectChannel(nc, ssh.ConnectionFailed, err)
		return
	}
	s.forwardChannel(nc, leg)
}

// handleTargetChannel proxies a channel the target opened towards the client
// (forwarded-tcpip, x11, auth-agent). The allow-list applies in this direction
// too: a channel the session may not open is not one it may be handed.
func (s *session) handleTargetChannel(nc ssh.NewChannel) {
	if s.route == nil || !s.route.ChannelPermitted(nc.ChannelType()) {
		s.logf("proxy: session=%s target-opened channel %q refused: not permitted by policy",
			s.id, nc.ChannelType())
		_ = nc.Reject(ssh.Prohibited, deniedChannelText(nc.ChannelType()))
		return
	}
	s.forwardChannel(nc, s.conn.Conn)
}

// serveTargetChannels accepts channel opens coming from the target.
func (s *session) serveTargetChannels(chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		s.wg.Add(1)
		go func(nc ssh.NewChannel) {
			defer s.wg.Done()
			defer s.recoverPanic("target channel")
			s.handleTargetChannel(nc)
		}(newChannel)
	}
}

// forwardChannel opens the matching channel on dst and pumps both sides.
func (s *session) forwardChannel(nc ssh.NewChannel, dst ssh.Conn) {
	farCh, farReqs, err := dst.OpenChannel(nc.ChannelType(), nc.ExtraData())
	if err != nil {
		// Relay the far side's own rejection verbatim where there is one: the
		// client asked a question the target answered, and inventing a reason
		// would hide it.
		if openErr, ok := err.(*ssh.OpenChannelError); ok {
			_ = nc.Reject(openErr.Reason, openErr.Message)
			return
		}
		s.rejectChannel(nc, ssh.ConnectionFailed, err)
		return
	}

	nearCh, nearReqs, err := nc.Accept()
	if err != nil {
		_ = farCh.Close()
		return
	}
	s.pump(nearCh, nearReqs, farCh, farReqs)
}

// handleSessionChannel proxies a session channel, and is where this engine's
// ordering requirement lives (PLAN §4.3).
//
// The channel is accepted immediately — before the route is known and before
// the target leg exists — so that authorize, provisioning, and the dial all
// happen with somewhere to write to. The client's requests are held while that
// runs and replayed to the target in order once it is up, which is invisible to
// the client beyond the delay it was going to wait anyway.
func (s *session) handleSessionChannel(nc ssh.NewChannel) {
	clientCh, clientReqs, err := nc.Accept()
	if err != nil {
		s.logf("proxy: session=%s accept session channel: %v", s.id, err)
		return
	}
	s.addChannel(clientCh)
	defer s.removeChannel(clientCh)

	var (
		queued    []*ssh.Request
		hasPTY    bool
		asked     bool // the client has said what it wants to run
		pending   error
		grace     <-chan time.Time
		ready     = s.ready
		opened    chan openedChannel
		targetCh  ssh.Channel
		targetReq <-chan *ssh.Request
	)

	for targetCh == nil {
		select {
		case req, ok := <-clientReqs:
			if !ok {
				// The client closed the channel before the target leg existed.
				_ = clientCh.Close()
				return
			}
			switch req.Type {
			case requestPTY:
				hasPTY = true
			case requestShell, requestExec, requestSubsystem:
				asked = true
				// The client has said what it wants and is now waiting. Say why
				// the wait is happening — but only on an interactive channel:
				// progress written into an scp or sftp stream corrupts it, so
				// there only failures are reported (PLAN §4.3).
				if hasPTY && opened == nil && pending == nil {
					writeUser(clientCh, connectingText(s.target))
				}
			}
			queued = append(queued, req)
			if pending != nil && asked {
				s.failChannel(clientCh, queued, pending)
				return
			}

		case <-ready:
			ready = nil // a closed channel is always ready; stop selecting on it
			pending = s.setupErr
			if pending == nil && !s.route.ChannelPermitted(channelSession) {
				pending = errChannelNotPermitted(channelSession)
			}
			if pending != nil {
				// Do not report yet unless the client has asked for something.
				// An SSH client only starts reading a channel's output once it
				// has sent its shell or exec request, so a failure written
				// before that is written into a stream nobody is reading:
				// explaining too early is the same as not explaining at all.
				if asked {
					s.failChannel(clientCh, queued, pending)
					return
				}
				grace = time.After(failureDeliveryGrace)
				continue
			}
			// Opening runs in its own goroutine so that requests keep being
			// drained: a blocked request queue stalls the whole client
			// connection, not just this channel.
			opened = make(chan openedChannel, 1)
			go func() {
				leg, err := s.legConnWhenReady()
				if err != nil {
					opened <- openedChannel{err: err}
					return
				}
				ch, reqs, err := leg.OpenChannel(channelSession, nc.ExtraData())
				opened <- openedChannel{ch: ch, reqs: reqs, err: err}
			}()

		case result := <-opened:
			if result.err != nil {
				s.failChannel(clientCh, queued, &setupError{stage: stageChannel, err: result.err})
				return
			}
			targetCh, targetReq = result.ch, result.reqs

		case <-grace:
			// The client opened a session channel and then asked for nothing.
			// Say what happened anyway and end the channel rather than holding
			// it open on a session that cannot work.
			s.failChannel(clientCh, queued, pending)
			return

		case <-s.ctx.Done():
			_ = clientCh.Close()
			return
		}
	}

	for _, req := range queued {
		forwardRequest(targetCh, req)
	}
	s.pump(clientCh, clientReqs, targetCh, targetReq)
}

// pump moves every byte and every request between the two halves of a channel
// until both are done, then closes both.
//
// near is the client's side, far the target's. The asymmetry that matters is
// the exit status: it is captured rather than forwarded as it arrives, and
// replayed once the target's output has been drained, so a client cannot see
// "the command finished" before the output the command produced.
func (s *session) pump(near ssh.Channel, nearReqs <-chan *ssh.Request, far ssh.Channel, farReqs <-chan *ssh.Request) {
	var (
		all      sync.WaitGroup
		output   sync.WaitGroup
		exitMu   sync.Mutex
		exitReq  *ssh.Request
		drained  = make(chan struct{})
		reqsDone = make(chan struct{})
	)

	// client → target
	all.Add(1)
	go func() {
		defer all.Done()
		_, _ = io.Copy(far, near)
		_ = far.CloseWrite()
	}()
	all.Add(1)
	go func() {
		defer all.Done()
		_, _ = io.Copy(far.Stderr(), near.Stderr())
	}()

	// target → client
	output.Add(2)
	all.Add(1)
	go func() {
		defer all.Done()
		defer output.Done()
		_, _ = io.Copy(near, far)
	}()
	all.Add(1)
	go func() {
		defer all.Done()
		defer output.Done()
		_, _ = io.Copy(near.Stderr(), far.Stderr())
	}()
	go func() {
		output.Wait()
		close(drained)
	}()

	// Requests, both ways.
	all.Add(1)
	go func() {
		defer all.Done()
		forwardRequests(nearReqs, far, nil)
	}()
	all.Add(1)
	go func() {
		defer all.Done()
		defer close(reqsDone)
		forwardRequests(farReqs, near, func(req *ssh.Request) bool {
			if req.Type != requestExitStatus && req.Type != requestExitSignal {
				return false
			}
			exitMu.Lock()
			exitReq = req
			exitMu.Unlock()
			return true
		})
	}()

	<-drained
	select {
	case <-reqsDone:
	case <-time.After(exitGrace):
	case <-s.ctx.Done():
	}

	exitMu.Lock()
	captured := exitReq
	exitMu.Unlock()
	if captured != nil {
		// exit-status and exit-signal never want a reply (RFC 4254 §6.10).
		_, _ = near.SendRequest(captured.Type, false, captured.Payload)
	}

	_ = near.Close()
	_ = far.Close()
	all.Wait()
}

// forwardRequests relays channel requests, letting intercept claim the ones the
// engine handles itself. A claimed request is answered here so a client that
// asked for a reply still gets one.
func forwardRequests(in <-chan *ssh.Request, dst ssh.Channel, intercept func(*ssh.Request) bool) {
	for req := range in {
		if intercept != nil && intercept(req) {
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			continue
		}
		forwardRequest(dst, req)
	}
}

// forwardRequest relays one channel request and its answer.
func forwardRequest(dst ssh.Channel, req *ssh.Request) {
	ok, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
	if err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
}

// serveGlobalRequests relays connection-level requests (keepalives,
// tcpip-forward, no-more-sessions) to the far connection, which dst supplies
// once it exists.
//
// Requests that arrive before the target leg is up wait for it rather than
// being refused: a refusal the client cannot distinguish from "the server does
// not support this" would silently disable port forwarding on a race.
//
// intercept claims the requests the engine answers itself, and is consulted
// BEFORE dst: the hop trail (D11) arrives while setup is still waiting for it,
// so asking for the far connection first would deadlock the session against its
// own precondition.
func (s *session) serveGlobalRequests(in <-chan *ssh.Request, dst func() (ssh.Conn, error), intercept func(*ssh.Request) bool) {
	for req := range in {
		if intercept != nil && intercept(req) {
			continue
		}
		conn, err := dst()
		if err != nil {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		ok, payload, err := conn.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		if req.WantReply {
			_ = req.Reply(ok, payload)
		}
	}
}
