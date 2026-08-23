// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/routing"
)

// RelayOpener reaches a proxy that has registered an outbound relay connection
// with this one (D11). It is satisfied by *relay.Hub; the engine takes the
// interface so the transport can be wired in without the session lifecycle
// depending on it.
type RelayOpener interface {
	// Open returns a connection to the registered proxy, or an error when
	// there is no live registration for it.
	Open(ctx context.Context, proxyID string) (net.Conn, error)
}

// hopTrailWait bounds how long a session from a peer that announced itself as
// another proxy waits for that peer's hop trail before it gives up.
//
// It is short because the trail is the first thing an upstream sends after it
// authenticates, and because nothing can be authorized until it arrives: the
// trail is what carries loop detection and the hop count (PLAN §6.1).
const hopTrailWait = 10 * time.Second

// errNoHopIdentity means this proxy has no key to present to the next hop, so
// a chain cannot be extended from here.
var errNoHopIdentity = errors.New("proxy: this proxy has no chain identity key configured")

// errNoRelay means a relay hop arrived at a proxy that accepts no relay
// registrations, so there is nothing to open a channel over.
var errNoRelay = errors.New("proxy: this proxy accepts no relay registrations")

// openNextHop extends the chain by one leg (D11, PLAN §6.1).
//
// The next hop is a full proxy, not a target: it authenticates this proxy,
// authorizes the user itself, and resolves its own route, so what happens here
// is deliberately not "connect to a target". Nothing about the user's identity
// is asserted to it beyond the login in the SSH username — this proxy's key is
// what it authenticates, and Hoplock Control is what turns that into an
// identity on the far side.
func (s *session) openNextHop() error {
	plan, err := routing.PlanHop(s.srv.proxyID, s.chain(), s.route, s.srv.maxHops)
	if err != nil {
		// A loop or an exceeded hop count is a refusal this proxy makes about a
		// route it was given, so it is auditable on its own: the trail is the
		// only place the shape of the chain is visible from one hop.
		if errors.Is(err, routing.ErrHopLoop) || errors.Is(err, routing.ErrHopLimit) {
			s.auditHopRefused(err)
		}
		return &setupError{stage: stageHop, err: err}
	}
	if s.srv.hopSigner == nil {
		return &setupError{stage: stageHop, err: errNoHopIdentity}
	}

	conn, err := s.openHopTransport(plan)
	if err != nil {
		return err
	}

	legConn, legChans, legReqs, err := s.handshakeNextHop(conn, plan)
	if err != nil {
		_ = conn.Close()
		return err
	}

	s.setLeg(legConn)
	go s.serveTargetChannels(legChans)
	go s.serveGlobalRequests(legReqs, func() (ssh.Conn, error) { return s.conn, nil }, nil)

	s.logf("proxy: session=%s hop leg up direction=%s next=%s addr=%s trail=%s final=%s max_hops=%d",
		s.id, plan.Direction, hopName(plan), hopAddr(plan), plan.Chain.Trail, plan.FinalTarget,
		plan.Chain.MaxHops)
	return nil
}

// openHopTransport gets the byte stream the next leg runs over: a socket this
// proxy dialled, or a channel over a registration the next proxy opened to it.
func (s *session) openHopTransport(plan *routing.HopPlan) (net.Conn, error) {
	switch plan.Direction {
	case control.HopConnectionRelay:
		if s.srv.relay == nil {
			return nil, &setupError{stage: stageRelay, err: errNoRelay}
		}
		ctx, cancel := context.WithTimeout(s.ctx, s.srv.dialTimeout)
		defer cancel()
		conn, err := s.srv.relay.Open(ctx, plan.NextProxyID)
		if err != nil {
			// Never a dial instead. The route said relay because the next
			// proxy sits behind a boundary with no inbound rule; reaching for
			// one anyway is the thing D11 exists to prevent.
			return nil, &setupError{stage: stageRelay, err: err}
		}
		return conn, nil
	default:
		dialer := net.Dialer{Timeout: s.srv.dialTimeout}
		conn, err := dialer.DialContext(s.ctx, "tcp", plan.Addr)
		if err != nil {
			return nil, &setupError{stage: stageHopDial, err: err}
		}
		return conn, nil
	}
}

// handshakeNextHop authenticates to the next proxy and declares the chain.
func (s *session) handshakeNextHop(conn net.Conn, plan *routing.HopPlan) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	addr := hopAddr(plan)
	cfg := &ssh.ClientConfig{
		// The next hop parses this exactly as it parses a user's username
		// (D1) and asks Hoplock Control about the login and the final
		// target, which is what makes every hop authorize independently.
		User:            s.login + s.srv.delimiter + plan.FinalTarget,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(s.srv.hopSigner)},
		HostKeyCallback: s.hostKeyCallback,
		ClientVersion:   routing.HopClientVersion,
		Timeout:         s.srv.dialTimeout,
	}

	// The handshake includes this proxy's host-key report round trip for the
	// next hop's key, so it gets the same bound as a target dial.
	_ = conn.SetDeadline(s.srv.now().Add(s.srv.dialTimeout))
	legConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		if hostKeyErr := s.takeHostKeyErr(); hostKeyErr != nil {
			return nil, nil, nil, &setupError{stage: stageHostKey, err: hostKeyErr}
		}
		return nil, nil, nil, &setupError{stage: stageHopDial, err: err}
	}
	_ = conn.SetDeadline(time.Time{})

	// The chain is declared before any channel is opened, because the next hop
	// cannot authorize anything without it: it is what carries loop detection
	// and the hop count. A hop that does not answer true has not recorded it,
	// and continuing would mean running the chain with the trail lost.
	ok, _, err := legConn.SendRequest(routing.RequestHopTrail, true, routing.MarshalChain(plan.Chain))
	if err != nil || !ok {
		_ = legConn.Close()
		if err == nil {
			err = fmt.Errorf("the next proxy refused the hop trail")
		}
		return nil, nil, nil, &setupError{stage: stageHop, err: fmt.Errorf("declare the hop trail: %w", err)}
	}
	return legConn, chans, reqs, nil
}

// interceptClientRequest claims the connection-level requests the engine
// answers itself rather than relaying to the far side.
//
// Only the hop trail qualifies today. It is proxy-to-proxy plumbing: relaying
// it onward would declare this proxy's chain to a target, and answering it late
// would let the session be authorized without it.
func (s *session) interceptClientRequest(req *ssh.Request) bool {
	if req.Type != routing.RequestHopTrail {
		return false
	}
	if !s.hopPeer {
		// The peer did not identify itself as a proxy. Nothing here is a
		// credential — a trail can only ever refuse a session, never widen one
		// (routing.HopTrail) — but a request the engine will not act on is
		// answered false rather than silently accepted.
		s.logf("proxy: session=%s ignoring a hop trail from a peer that is not a proxy", s.id)
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return true
	}
	chain, err := routing.ParseChain(req.Payload)
	if err != nil {
		s.logf("proxy: session=%s hop trail rejected: %v", s.id, err)
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return true
	}
	s.setChain(chain)
	s.logf("proxy: session=%s inbound hop leg trail=%s final=%s max_hops=%d",
		s.id, chain.Trail, chain.FinalTarget, chain.MaxHops)
	if req.WantReply {
		_ = req.Reply(true, nil)
	}
	return true
}

// awaitHopTrail blocks until the upstream proxy has declared the chain.
//
// It runs only for a peer that announced itself as a proxy, so an ordinary user
// never waits: an inbound leg is identified by its SSH client version before
// anything else happens (routing.IsHopPeer). A peer that claims to be a hop and
// then does not declare one is refused rather than served with an empty trail,
// because an empty trail is exactly what would defeat the loop detection and
// the hop cap.
func (s *session) awaitHopTrail() error {
	timer := time.NewTimer(hopTrailWait)
	defer timer.Stop()
	select {
	case <-s.chainReady:
		return nil
	case <-s.ctx.Done():
		return &setupError{stage: stageHop, err: s.ctx.Err()}
	case <-timer.C:
		return &setupError{stage: stageHop, err: fmt.Errorf(
			"the upstream proxy did not declare a hop trail within %s", hopTrailWait)}
	}
}

// auditHopRefused records a chain this proxy would not extend. It is a
// security-relevant refusal about the shape of the estate's routing, so it is
// logged in its own right and not only as a session failure.
func (s *session) auditHopRefused(err error) {
	s.logf("proxy: audit=hop_refused session=%s subject=%s target=%s proxy=%s trail=%s next=%s reason=%v",
		s.id, s.subjectID(), s.target, s.srv.proxyID, s.chain().Trail, s.nextProxyID(), err)
}

// nextProxyID is the id of the hop the route named, or "" when it named none.
func (s *session) nextProxyID() string {
	if s.route == nil || s.route.Hop == nil {
		return ""
	}
	return s.route.Hop.NextProxyID
}

func hopName(plan *routing.HopPlan) string {
	if plan.NextProxyID == "" {
		return "(unnamed)"
	}
	return plan.NextProxyID
}

func hopAddr(plan *routing.HopPlan) string {
	if plan.Addr != "" {
		return plan.Addr
	}
	return "relay:" + plan.NextProxyID
}
