// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/channel"
)

// SSH channel and request names this engine reasons about by name. Everything
// else is forwarded generically (D5): the proxy proxies channel types it has
// never heard of, and internal/channel is what decides which may exist, which
// requests they may carry, and where they may go (PLAN §6.2).
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

// policing says whether a connection-level request stream is the client's, and
// therefore carries the session's own policy (D5a axis 3). The target's
// requests travel the other way and are relayed: the allow-list is about what
// this session may ask its target for.
type policing bool

const (
	policeRequests policing = true
	relayRequests  policing = false
)

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
	insp, decision := s.openChannel(nc, channel.FromClient)
	if decision.Denied() {
		_ = nc.Reject(ssh.Prohibited, deniedText(decision.Reason))
		return
	}
	leg, err := s.legConnWhenReady()
	if err != nil {
		s.rejectChannel(nc, ssh.ConnectionFailed, err)
		return
	}
	s.forwardChannel(nc, leg, insp, decision.PayloadOr(nc.ExtraData()))
}

// openChannel puts a channel open through the pipeline: the channel-type
// allow-list, and — for direct-tcpip and forwarded-tcpip — the destination
// inside the payload, which is where a port forward's whole meaning lives
// (PLAN §6.2, D5a).
func (s *session) openChannel(nc ssh.NewChannel, dir channel.Direction) (*channel.Inspection, channel.Decision) {
	if s.pipe == nil {
		// Unreachable: the pipeline exists before ready closes, and nothing
		// opens a channel before then. Denying rather than trusting a nil is
		// the only reading of "no policy" that cannot open a session.
		return nil, channel.Deny(deniedChannelReason(nc.ChannelType()))
	}
	return s.pipe.Open(s.ctx, channel.OpenEvent{
		ChannelType: nc.ChannelType(),
		Direction:   dir,
		Payload:     nc.ExtraData(),
	})
}

// handleTargetChannel proxies a channel the target opened towards the client
// (forwarded-tcpip, x11, auth-agent). The pipeline applies in this direction
// too: a channel the session may not open is not one it may be handed, and a
// forwarded-tcpip has its own destination list for exactly the same reason.
func (s *session) handleTargetChannel(nc ssh.NewChannel) {
	insp, decision := s.openChannel(nc, channel.FromTarget)
	if decision.Denied() {
		_ = nc.Reject(ssh.Prohibited, deniedText(decision.Reason))
		return
	}
	s.forwardChannel(nc, s.conn.Conn, insp, decision.PayloadOr(nc.ExtraData()))
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

// forwardChannel opens the matching channel on dst and pumps both sides. data
// is the open payload the pipeline passed, which is nc.ExtraData() unless an
// inspector replaced it.
func (s *session) forwardChannel(nc ssh.NewChannel, dst ssh.Conn, insp *channel.Inspection, data []byte) {
	farCh, farReqs, err := dst.OpenChannel(nc.ChannelType(), data)
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
	s.pump(nearCh, nearReqs, farCh, farReqs, insp)
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
		insp      *channel.Inspection
		openData  = nc.ExtraData()
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
			if pending == nil {
				// The session channel goes through the same pipeline as every
				// other channel; it just cannot be refused with a rejection,
				// because it was accepted before the policy existed. The
				// refusal therefore arrives as an explained close below.
				var decision channel.Decision
				insp, decision = s.openChannel(nc, channel.FromClient)
				if decision.Denied() {
					pending = errChannelNotPermitted(channelSession)
				}
				openData = decision.PayloadOr(openData)
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
				ch, reqs, err := leg.OpenChannel(channelSession, openData)
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

	// The requests the client made while the target leg was coming up are
	// replayed in order, and policed on the way through: the axis is about the
	// request, not about when it happened to arrive (PLAN §6.2, D5a).
	for _, req := range queued {
		relay, alive := s.policeRequest(clientCh, insp, req)
		if relay {
			forwardRequest(targetCh, req)
		}
		if !alive {
			_ = targetCh.Close()
			return
		}
	}
	s.pump(clientCh, clientReqs, targetCh, targetReq, insp)
}

// policeRequest applies the in-channel request axis to one request the client
// made (PLAN §6.2, D5a axis 2). It reports whether the request may be relayed,
// and whether the channel has anything left to do afterwards.
//
// A denial is never a bare close, and never a silent one either. The request is
// answered, the reason goes to the channel's stderr, and — when what was
// refused is the request that would have started the work — the channel ends
// with a non-zero exit status so a script sees a failure rather than an empty
// success (PLAN §4.3). Refusing a pty leaves the channel alive on purpose:
// "CI may run commands but never gets an interactive terminal" is a session
// that still runs the command.
func (s *session) policeRequest(ch ssh.Channel, insp *channel.Inspection, req *ssh.Request) (relay, alive bool) {
	decision := insp.Request(s.ctx, channel.RequestEvent{
		Direction: channel.FromClient,
		Type:      req.Type,
		WantReply: req.WantReply,
		Payload:   req.Payload,
	})
	if !decision.Denied() {
		// A permitted-but-flagged request carries a notice: the warn-and-
		// continue half of command policy, where the command runs and the user
		// hears about it before it does (PLAN §6.3).
		if decision.Notice != "" {
			writeUser(ch, noticeText(decision.Notice))
		}
		req.Payload = decision.PayloadOr(req.Payload)
		return true, true
	}

	if req.WantReply {
		// A command policy's refusal is answered affirmatively and then
		// reported as the channel's own failure below: the request was
		// permitted, the command it carried was not, and a false reply would
		// make the client print its own generic error instead of reading the
		// reason (PLAN §4.3, and the same argument failChannel makes).
		_ = req.Reply(decision.CommandFailure, nil)
	}

	// A policy that ends the session says so and then ends it, on every channel
	// at once rather than on this one: the same path a revocation takes, for
	// the same reason — a terminated session must never look like a crash
	// (PLAN §4.3, §6.4).
	if decision.Terminates() {
		s.kill(decision.Reason)
		return false, false
	}

	writeUser(ch, deniedText(decision.Reason))
	if !channel.RequestStartsExecution(req.Type) {
		return false, true
	}
	sendExitStatus(ch, exitProxyFailure)
	_ = ch.Close()
	return false, false
}

// pump moves every byte and every request between the two halves of a channel
// until both are done, then closes both.
//
// near is the side that opened the channel, far the side it was forwarded to —
// which is the client and the target respectively for everything the client
// opens, and the other way round for a channel the target opened back. The
// asymmetry that matters is the exit status: it is captured rather than
// forwarded as it arrives, and replayed once the target's output has been
// drained, so a client cannot see "the command finished" before the output the
// command produced.
//
// insp is the channel's inspection. Every stream goes through it, and on a
// channel with no stream inspectors it hands each one straight back, so an
// un-inspected channel is the same four io.Copy calls phase 0005 shipped.
func (s *session) pump(near ssh.Channel, nearReqs <-chan *ssh.Request, far ssh.Channel, farReqs <-chan *ssh.Request, insp *channel.Inspection) {
	var (
		all      sync.WaitGroup
		output   sync.WaitGroup
		exitMu   sync.Mutex
		exitReq  *ssh.Request
		drained  = make(chan struct{})
		reqsDone = make(chan struct{})
	)

	nearDir := insp.Opener()
	farDir := nearDir.Opposite()

	// near → far
	all.Add(1)
	go func() {
		defer all.Done()
		_, _ = io.Copy(far, insp.Reader(s.ctx, nearDir, false, near))
		_ = far.CloseWrite()
	}()
	all.Add(1)
	go func() {
		defer all.Done()
		_, _ = io.Copy(far.Stderr(), insp.Reader(s.ctx, nearDir, true, near.Stderr()))
	}()

	// far → near
	output.Add(2)
	all.Add(1)
	go func() {
		defer all.Done()
		defer output.Done()
		_, _ = io.Copy(near, insp.Reader(s.ctx, farDir, false, far))
	}()
	all.Add(1)
	go func() {
		defer all.Done()
		defer output.Done()
		_, _ = io.Copy(near.Stderr(), insp.Reader(s.ctx, farDir, true, far.Stderr()))
	}()
	go func() {
		output.Wait()
		close(drained)
	}()

	// Requests, both ways. The near side's are policed when near is the client
	// — a request axis is about what this session may ask its target for — and
	// relayed when the target opened the channel.
	all.Add(1)
	go func() {
		defer all.Done()
		if nearDir == channel.FromClient {
			s.forwardClientRequests(nearReqs, near, far, insp)
			return
		}
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

// forwardClientRequests relays the client's in-channel requests through the
// request axis. A denial that leaves the channel with nothing left to do closes
// both halves, which unwinds the pump.
func (s *session) forwardClientRequests(in <-chan *ssh.Request, near, far ssh.Channel, insp *channel.Inspection) {
	for req := range in {
		relay, alive := s.policeRequest(near, insp, req)
		if relay {
			forwardRequest(far, req)
		}
		if !alive {
			_ = near.Close()
			_ = far.Close()
			return
		}
	}
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
// once it exists, and applies the global-request allow-list to the ones the
// client made (D5a axis 3).
//
// Requests that arrive before the target leg is up wait for it rather than
// being refused: a refusal the client cannot distinguish from "the server does
// not support this" would silently disable port forwarding on a race.
//
// intercept claims the requests the engine answers itself, and is consulted
// BEFORE dst: the hop trail (D11) arrives while setup is still waiting for it,
// so asking for the far connection first would deadlock the session against its
// own precondition.
func (s *session) serveGlobalRequests(in <-chan *ssh.Request, dst func() (ssh.Conn, error), intercept func(*ssh.Request) bool, police policing) {
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
		// After dst() the route exists, and with it the pipeline: waiting for
		// the far connection is also what makes the policy available. A denied
		// request is answered false and goes no further — relaying a
		// tcpip-forward and then refusing the forwarded-tcpip channels it
		// produces would still leave the listener standing on the target
		// (PLAN §6.2).
		if police == policeRequests && s.pipe != nil && s.pipe.GlobalRequest(s.ctx, req.Type).Denied() {
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
