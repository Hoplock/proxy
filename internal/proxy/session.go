// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/auth/target"
	"github.com/hoplock/proxy/internal/auth/user"
	"github.com/hoplock/proxy/internal/channel"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/filter"
	"github.com/hoplock/proxy/internal/filter/inspect"
	"github.com/hoplock/proxy/internal/identity"
	"github.com/hoplock/proxy/internal/logging"
	"github.com/hoplock/proxy/internal/routing"
)

// failureDeliveryGrace is how long a failed session waits for the client to
// open a channel it can explain itself on, before closing the connection.
//
// It is needed because the client and the proxy work in parallel after
// authentication: the client opens its session channel while the proxy is
// still authorizing, and either can win. Closing the moment setup fails would
// lose the message for a client that was a millisecond behind; waiting forever
// would strand a client that opens no channel at all (`ssh -N`).
const failureDeliveryGrace = 3 * time.Second

// failureLinger is how long a failed session waits for the client to hang up
// after being told why, before closing the connection itself.
const failureLinger = time.Second

// teardownTimeout bounds the credential teardown that runs when a session ends.
// Teardown removes what was provisioned on the target (D6), so it must not be
// abandoned instantly on a cancelled context — but it also cannot hold the
// session open indefinitely.
const teardownTimeout = 30 * time.Second

// session is one client connection and the target leg it is proxied onto.
//
// Its lifecycle is deliberately ordered so that the proxy can always speak to
// the user (PLAN §4.3): the client's session channel is accepted *before* the
// target leg exists, so authorize, provisioning, and the dial all happen with
// somewhere to write progress and failures to. Everything else here follows
// from that ordering.
type session struct {
	srv   *Server
	id    string
	conn  *ssh.ServerConn
	chans <-chan ssh.NewChannel
	greqs <-chan *ssh.Request

	ctx     context.Context
	cancel  context.CancelFunc
	started time.Time

	// rec is this session's telemetry recorder (PLAN §7). It is nil when the
	// proxy was built without a Shipper, and every capture point tolerates
	// that, so the transport never branches on whether logging is configured.
	rec *logging.SessionRecorder

	// ready is closed when setup has finished, successfully or not. route,
	// pipe, setupErr, and the target leg are written before it closes and only
	// read after, which is what makes them safe to read without a lock.
	ready    chan struct{}
	route    *routing.Route
	pipe     *channel.Pipeline
	setupErr error
	access   *target.ProvisionedAccess

	// login, target, and identity are established by setup, before ready.
	login    string
	target   string
	identity *identity.Identity

	// hostKeyErr records why the host-key callback refused, because the
	// handshake error that carries it back is x/crypto's to format, not ours.
	hostKeyErr error

	// hopPeer is set when the connection came from another proxy extending a
	// chain rather than from a user's SSH client (routing.IsHopPeer). Such a
	// session owes a hop trail before it can be authorized.
	hopPeer bool
	// chainReady is closed once the upstream proxy has declared the chain.
	// chainState is written before it closes and read after, under the mutex
	// because the request arrives on the global-request goroutine.
	chainReady chan struct{}
	chainOnce  sync.Once
	chainState routing.Chain

	mu       sync.Mutex
	leg      ssh.Conn
	channels map[ssh.Channel]struct{}
	killed   bool

	failedOnce sync.Once
	failure    chan struct{}

	wg sync.WaitGroup
}

func (s *Server) newSession(ctx context.Context, id string, conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) *session {
	ctx, cancel := context.WithCancel(ctx)
	return &session{
		srv:        s,
		id:         id,
		conn:       conn,
		chans:      chans,
		greqs:      reqs,
		ctx:        ctx,
		cancel:     cancel,
		started:    s.now(),
		ready:      make(chan struct{}),
		chainReady: make(chan struct{}),
		channels:   make(map[ssh.Channel]struct{}),
		failure:    make(chan struct{}),
		rec:        s.recorder.Session(logging.SessionInfo{SessionID: id, ProxyID: s.proxyID}),
	}
}

// run drives the session until the client connection ends.
func (s *session) run() {
	defer s.close()

	go s.setup()
	go func() {
		defer s.recoverPanic("global requests")
		s.serveGlobalRequests(s.greqs, s.legConnWhenReady, s.interceptClientRequest, policeRequests)
	}()

	for newChannel := range s.chans {
		s.wg.Add(1)
		go func(nc ssh.NewChannel) {
			defer s.wg.Done()
			defer s.recoverPanic("client channel")
			s.handleClientChannel(nc)
		}(newChannel)
	}
	s.wg.Wait()
}

// recoverPanic ends this session on a panic instead of taking the process — and
// every other user's session — with it. It also keeps PLAN §5's guarantee that
// teardown runs on a crash: closing the client connection unwinds run, whose
// deferred close removes whatever was provisioned.
func (s *session) recoverPanic(where string) {
	r := recover()
	if r == nil {
		return
	}
	s.logf("proxy: session=%s panic in %s: %v\n%s", s.id, where, r, debug.Stack())
	s.cancel()
	_ = s.conn.Close()
}

// setup resolves the route and brings up the target leg, while the client is
// already connected and possibly already waiting on an open channel.
//
// Every failure it can produce is classified by stage, because what the user is
// told depends on it: a deny from Hoplock Control is "access denied" and
// nothing more, while everything else says plainly which part of the service
// failed (PLAN §4.3).
func (s *session) setup() {
	defer func() {
		if r := recover(); r != nil {
			s.logf("proxy: session=%s panic during setup: %v\n%s", s.id, r, debug.Stack())
			// Reported as a failure rather than swallowed: a session that
			// crashed while being set up must still tell the user something.
			s.failSetup(&setupError{stage: stageRoute, err: fmt.Errorf("panic during setup: %v", r)})
		}
		close(s.ready)
	}()

	if err := s.identify(); err != nil {
		s.failSetup(err)
		return
	}

	// An inbound chain leg declares where it has been before anything is
	// authorized: the trail is what carries loop detection and the hop count
	// (PLAN §6.1), and it reaches Hoplock Control on this hop's own
	// authorize call.
	if s.hopPeer {
		if err := s.awaitHopTrail(); err != nil {
			s.failSetup(err)
			return
		}
	}

	s.logf("proxy: session=%s start subject=%s login=%s target=%s client=%s method=%s hop_peer=%t trail=%s",
		s.id, s.identity.Subject, s.login, s.target, s.conn.RemoteAddr(), s.identity.Method,
		s.hopPeer, s.chain().Trail)
	s.recordStart()

	route, err := s.srv.resolver.Resolve(s.ctx, routing.Request{
		Identity: s.identity,
		Target:   s.target,
		Conn:     s.connMeta(),
	})
	if err != nil {
		s.failSetup(&setupError{stage: stageAuthorize, err: err})
		return
	}
	s.route = route
	s.recordAuthorize(route)

	// Command policy belongs to this connection, not to the proxy: the engine
	// is compiled from this route's filter policy and attached to this
	// session's own inspector chain (PLAN §6.3, D2, D12).
	inspectors, err := s.sessionInspectors(route)
	if err != nil {
		s.failSetup(&setupError{stage: stageRoute, err: err})
		return
	}

	// Every policy answer about a channel from here on comes from the
	// pipeline, which is built as soon as there is a policy to build it from
	// and before ready closes, so no channel handler ever sees a half-built
	// one (PLAN §6.2).
	pipe, err := channel.New(channel.Options{
		Policy:     route,
		Inspectors: inspectors,
		SessionID:  s.id,
		Logf:       s.logf,
	})
	if err != nil {
		s.failSetup(&setupError{stage: stageRoute, err: err})
		return
	}
	s.pipe = pipe

	// Where the two route types diverge (PLAN §6.1). A next-hop route is not a
	// target: the next proxy authenticates this one, authorizes the user
	// itself, and provisions whatever the far end needs, so none of the
	// credential machinery below applies to it.
	switch {
	case route.IsNextHop():
		if err := s.openNextHop(); err != nil {
			s.failSetup(err)
		}
		return
	case !route.IsDirect():
		s.failSetup(&setupError{stage: stageRoute,
			err: fmt.Errorf("%w: %q", routing.ErrUnsupportedRoute, route.Type)})
		return
	}

	// The route carries the credential method Hoplock Control chose for this
	// connection (D6a) and the session carries the host-key policy (D7); the
	// authenticator owns neither. A provisioner that opens its own connection
	// to the target — the ephemeral method's management login does — borrows
	// the callback rather than deciding host trust for itself.
	access, err := s.srv.targetAuth.Provision(s.ctx, s.identity, target.Target{
		Host:            route.Host,
		Port:            route.Port,
		Auth:            route.TargetAuth,
		Ladder:          route.TargetAuthLadder,
		SessionID:       s.id,
		HostKeyCallback: s.hostKeyCallback,
	})
	if err != nil {
		s.failSetup(&setupError{stage: stageProvision, err: err})
		return
	}
	s.access = access
	s.recordCredential(route, access)

	if err := s.dialTarget(access); err != nil {
		s.failSetup(err)
		return
	}

	s.logf("proxy: session=%s target leg up target=%s route=%s permissions=%s channels=%v",
		s.id, s.route.Addr(), s.route.Type, s.route.Permissions, s.route.PermittedChannels)
}

// sessionInspectors builds the inspector registry for this session: the
// proxy-wide chains, plus command policy when this connection's policy can ever
// say no (PLAN §6.3), plus this session's stream capture (PLAN §7).
//
// A policy that does not compile fails the session closed. It should be
// unreachable — the contract validates the same shape on the way in — and that
// is exactly why it must not be treated as "no policy": the one reading of "the
// policy could not be understood" that is never available is the one that lets
// a command run.
func (s *session) sessionInspectors(route *routing.Route) (*channel.Registry, error) {
	engine, err := filter.New(route.Filter)
	if err != nil {
		return nil, err
	}

	// A blacklist with no rules filters nothing, and a proxy with no telemetry
	// pipeline captures nothing. When neither has anything to attach, the
	// session keeps phase 0009's straight-copy path: no wrapper, no per-command
	// work, nothing to say about any command.
	if !engine.Filters() && s.rec == nil {
		return s.srv.inspectors, nil
	}

	reg := s.srv.inspectors.Clone()
	if engine.Filters() {
		inspect.Register(reg, inspect.Options{
			// The audit sink is the telemetry pipeline (PLAN §7, D8): a blocked
			// command is a critical record and takes the priority endpoint, so
			// it is at Hoplock Control before the batch it would have waited
			// in. A proxy without a pipeline discards the events rather than
			// failing the session over them.
			Audit:  s.rec.AuditSink(),
			Engine: engine,
		})
		s.logf("proxy: session=%s command policy tier=%s mode=%s", s.id, engine.Tier(), engine.Mode())
	}
	// Stream capture is registered after the command inspectors, so a command
	// the filter refuses is refused before the recorder is asked for anything.
	logging.Register(reg, s.rec)
	return reg, nil
}

// identify recovers who the connection belongs to and what it asked for.
func (s *session) identify() error {
	id, err := user.IdentityFromPermissions(s.conn.Permissions)
	if err != nil {
		// The connection authenticated but carries no readable identity: a
		// session that cannot be attributed cannot be authorized or audited.
		return &setupError{stage: stageIdentity, err: err}
	}
	s.setIdentity(id)

	login, tgt, err := routing.ParseUsername(s.conn.User(), s.srv.delimiter)
	if err != nil {
		return &setupError{stage: stageUsername, err: err}
	}
	s.login, s.target = login, tgt
	return nil
}

// dialTarget opens the second SSH leg with the provisioned credentials.
func (s *session) dialTarget(access *target.ProvisionedAccess) error {
	if access.ClientConfig == nil {
		return &setupError{stage: stageProvision, err: errors.New("target authenticator returned no client configuration")}
	}
	// Copy: the authenticator may reuse its configuration across sessions, and
	// the host-key callback below is this session's.
	cfg := *access.ClientConfig
	cfg.HostKeyCallback = s.hostKeyCallback
	cfg.Timeout = s.srv.dialTimeout

	addr := s.route.Addr()
	dialer := net.Dialer{Timeout: s.srv.dialTimeout}
	conn, err := dialer.DialContext(s.ctx, "tcp", addr)
	if err != nil {
		return &setupError{stage: stageDial, err: err}
	}

	// The handshake includes the host-key report round trip, so it gets the
	// same bound as the dial rather than running unbounded.
	_ = conn.SetDeadline(s.srv.now().Add(s.srv.dialTimeout))
	legConn, legChans, legReqs, err := ssh.NewClientConn(conn, addr, &cfg)
	if err != nil {
		_ = conn.Close()
		if hostKeyErr := s.takeHostKeyErr(); hostKeyErr != nil {
			// The host key is why the handshake failed; report that rather than
			// x/crypto's rendering of it.
			return &setupError{stage: stageHostKey, err: hostKeyErr}
		}
		return &setupError{stage: stageDial, err: err}
	}
	_ = conn.SetDeadline(time.Time{})

	s.setLeg(legConn)

	// The target can open channels too (forwarded-tcpip, x11, auth-agent), and
	// its global requests have to be answered or the connection hangs.
	go s.serveTargetChannels(legChans)
	go s.serveGlobalRequests(legReqs, func() (ssh.Conn, error) { return s.conn, nil }, nil, relayRequests)
	return nil
}

// failSetup records why the session cannot proceed and makes sure the user
// hears about it.
func (s *session) failSetup(err error) {
	s.setupErr = err
	s.logf("proxy: session=%s setup failed: %v", s.id, err)
	s.recordFailure(err)

	// Whoever delivers the message (an open session channel, or a channel the
	// client opens moments later) signals it; if nobody can, the connection is
	// closed anyway rather than left hanging. A bare TCP drop is never the
	// intended outcome, but an unexplained close beats an unbounded wait.
	go func() {
		select {
		case <-s.failure:
			// The explanation is on the wire. Let the client read it and close
			// on its own; pulling the socket out from under a client that has
			// not read the message yet would waste it.
			s.lingerUntilClosed()
		case <-s.ctx.Done():
		case <-time.After(failureDeliveryGrace):
			s.logf("proxy: session=%s closing without a channel to report the failure on", s.id)
		}
		s.disconnect(s.failureText(err))
	}()
}

// lingerUntilClosed waits for the client to hang up, or briefly, whichever is
// first.
func (s *session) lingerUntilClosed() {
	closed := make(chan struct{})
	go func() {
		_ = s.conn.Wait()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(failureLinger):
	case <-s.ctx.Done():
	}
}

// failureDelivered marks the failure as explained to the user.
func (s *session) failureDelivered() {
	s.failedOnce.Do(func() { close(s.failure) })
}

// waitReady blocks until setup has finished, returning its error.
func (s *session) waitReady() error {
	select {
	case <-s.ready:
		return s.setupErr
	case <-s.ctx.Done():
		return &setupError{stage: stageRoute, err: s.ctx.Err()}
	}
}

// legConnWhenReady returns the target connection once setup has finished.
func (s *session) legConnWhenReady() (ssh.Conn, error) {
	if err := s.waitReady(); err != nil {
		return nil, err
	}
	leg := s.legConn()
	if leg == nil {
		return nil, &setupError{stage: stageDial, err: errors.New("target connection is not available")}
	}
	return leg, nil
}

func (s *session) legConn() ssh.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.leg
}

// closeLeg closes the target-leg connection if there is one. It is idempotent,
// which is what lets close() call it on both sides of the setup wait.
func (s *session) closeLeg() {
	if leg := s.legConn(); leg != nil {
		_ = leg.Close()
	}
}

func (s *session) setLeg(conn ssh.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leg = conn
}

func (s *session) addChannel(ch ssh.Channel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.channels[ch] = struct{}{}
}

func (s *session) removeChannel(ch ssh.Channel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.channels, ch)
}

// connMeta is the connection metadata every management call carries.
func (s *session) connMeta() control.ConnMeta {
	return control.ConnMeta{
		SessionID:     s.id,
		ProxyID:       s.srv.proxyID,
		HopTrail:      s.chain().Trail,
		ClientAddr:    s.conn.RemoteAddr().String(),
		ServerAddr:    s.conn.LocalAddr().String(),
		ClientVersion: string(s.conn.ClientVersion()),
		Timestamp:     s.srv.now(),
	}
}

// kill ends the session on Hoplock Control's orders, telling the user why
// first (PLAN §4.3, §6.4). A revoked session must never look like a crash.
func (s *session) kill(reason string) {
	s.mu.Lock()
	if s.killed {
		s.mu.Unlock()
		return
	}
	s.killed = true
	channels := make([]ssh.Channel, 0, len(s.channels))
	for ch := range s.channels {
		channels = append(channels, ch)
	}
	s.mu.Unlock()

	s.logf("proxy: session=%s killed: %s", s.id, reason)
	s.recordKill(reason)
	text := bannerPrefix + reason
	for _, ch := range channels {
		writeUser(ch, text)
		sendExitStatus(ch, exitProxyFailure)
		_ = ch.Close()
	}
	s.disconnect(text)
}

// disconnect ends the client connection.
//
// SSH_MSG_DISCONNECT carries a reason code and a description, and that is what
// PLAN §4.3 asks for here — but golang.org/x/crypto/ssh does not expose it
// (ssh.Conn deliberately offers only Close; sending a disconnect is on its
// TODO list). The duck-typed assertion below uses it if a future version does,
// and the engine's real answer to the gap is structural: the client's session
// channel is accepted before anything can fail, so the explanation reaches the
// user over that channel and this path is the last resort for a client that
// never opened one.
func (s *session) disconnect(message string) {
	type disconnecter interface {
		Disconnect(reason uint32, message string) error
	}
	if d, ok := s.conn.Conn.(disconnecter); ok {
		// 11 is SSH_DISCONNECT_BY_APPLICATION (RFC 4253 §11.1).
		_ = d.Disconnect(11, message)
	}
	_ = s.conn.Close()
}

// close tears the session down. It runs on every exit path — normal close,
// error, kill, and panic in a channel goroutine — because the credentials the
// target authenticator provisioned must not outlive the session that used them
// (D6, PLAN §5).
func (s *session) close() {
	s.cancel()
	_ = s.conn.Close()
	// Closed here so an in-flight transfer stops at once rather than draining.
	s.closeLeg()

	// Setup may still be in flight (a client that hung up mid-dial, or a kill
	// that arrived between this session registering and its target leg coming
	// up); waiting for it is what stops teardown from racing the provisioning
	// it undoes.
	<-s.ready

	// And closed AGAIN, because setup may have established the leg during that
	// wait. Closing only before the wait leaves that connection open forever:
	// nothing after this point looks at it, the target keeps its end alive, and
	// a revoked session goes on holding an SSH connection to the host it was
	// revoked from. The credential is still removed below — but "the session
	// was killed" has to mean the connection is gone, not just the account.
	s.closeLeg()

	if s.access != nil {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(s.ctx), teardownTimeout)
		defer cancel()
		if err := s.access.Close(ctx); err != nil {
			s.logf("proxy: session=%s teardown failed: %v", s.id, err)
		}
	}

	subject := ""
	if s.identity != nil {
		subject = s.identity.Subject
	}
	s.recordEnd()
	s.logf("proxy: session=%s end subject=%s target=%s duration=%s",
		s.id, subject, s.target, s.srv.now().Sub(s.started).Round(time.Millisecond))
}

func (s *session) logf(format string, args ...any) { s.srv.logf(format, args...) }

// subjectID is the subject this session belongs to, or "" before setup has read
// the identity back off the connection.
//
// It is locked because the revocation stream calls it (KillSubject) on its own
// goroutine, concurrently with setup establishing the identity.
func (s *session) subjectID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.identity == nil {
		return ""
	}
	return s.identity.Subject
}

// chain returns what the upstream proxy declared about this session. The zero
// Chain is a user's first hop.
func (s *session) chain() routing.Chain {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.chainState
}

// setChain records the chain an upstream proxy declared. Only the first
// declaration counts: a second one would rewrite the loop detection and the hop
// count of a session that has already been authorized against the first.
func (s *session) setChain(c routing.Chain) {
	s.chainOnce.Do(func() {
		s.mu.Lock()
		s.chainState = c
		s.mu.Unlock()
		close(s.chainReady)
	})
}

// setIdentity records who the connection belongs to.
func (s *session) setIdentity(id *identity.Identity) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identity = id
}
