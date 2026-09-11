// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"errors"
	"fmt"

	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/routing"
)

// This file enforces the three session bounds that are not the deadline
// (contract v4, D16, PLAN §6.5; the deadline is deadline.go). They ride the same
// contract revision and are otherwise unalike, and what separates them is which
// class PLAN §4.3 puts each refusal in:
//
//   - require_session_capture is an OUTAGE. The estate cannot record, the user
//     asked for nothing wrong, and different credentials will not help — so the
//     message is explicit and carries the session id as a support reference.
//   - concurrency is a POLICY DENIAL, deliberately vague. The estate is healthy
//     and the answer is "no"; saying which cap was hit would tell a caller how
//     many of their colleagues are logged in.
//   - grant_context refuses nothing. It is carried onto the session's records
//     and read by nobody (internal/logging/grant.go).
//
// Both checks run BEFORE the target leg is dialled and before anything is
// provisioned, because a session that reached the target and then failed one of
// them has already happened.

// ErrCaptureUnavailable means a route that may only run if the session is
// recorded reached a proxy with no logging path at all.
//
// "No path at all" is the whole of it: PLAN §7's disk buffer is a RESILIENCE
// PATH and not a degraded mode, so a proxy spooling to disk while Hoplock
// Control is unreachable still satisfies the route. Refusing sessions during a
// Control outage on a proxy that is recording faithfully would be fail-closed
// against the wrong failure. It is the same rule, and the same predicate, as
// target.ErrNoLoggingPath — which PLAN §5.3 reaches from the other direction.
var ErrCaptureUnavailable = errors.New("proxy: this route requires the session to be recorded and this proxy has no logging path")

// concurrencyScope names which of D16's two independent ceilings refused a
// session. It is audit vocabulary: the record says which cap was hit and the
// user is told nothing (PLAN §4.3).
type concurrencyScope string

const (
	scopeSubject concurrencyScope = "subject"
	scopeTarget  concurrencyScope = "target"
)

// capExceeded is a concurrency refusal.
//
// It wraps control.ErrUnauthorized because that is exactly what it is — the
// server's own answer, arriving as a cap on the authorize response instead of as
// a 401 — so it renders as the same generic denial as every other policy answer
// and cannot accidentally be reported as an outage (user.FailureMessageFor).
type capExceeded struct {
	scope concurrencyScope
	limit int
	live  int
}

func (e *capExceeded) Error() string {
	return fmt.Sprintf("concurrency: the per-%s ceiling of %d live session(s) is reached (%d live): %v",
		e.scope, e.limit, e.live, control.ErrUnauthorized)
}

// Unwrap keeps the deny classification reachable for errors.Is, which is what
// decides that the user hears "access denied" and nothing more.
func (e *capExceeded) Unwrap() error { return control.ErrUnauthorized }

// requireCapture refuses a route that may only run recorded when this proxy has
// nowhere to put the records (D16, PLAN §6.5).
//
// A route without the field changes nothing here: absent means capture happens
// if it is configured and its absence stops nothing, which is what every v3
// server meant.
func (s *session) requireCapture(route *routing.Route) error {
	if !route.RequireSessionCapture {
		return nil
	}
	if s.rec.Deliverable() {
		return nil
	}
	return fmt.Errorf("%w (session %s)", ErrCaptureUnavailable, s.id)
}

// enforceConcurrency counts this session against the route's ceilings and, if
// both leave room, marks it live (D16).
//
// The subject and the target are read here, off the session, rather than inside
// the registry: the registry holds the server's lock and the subject is behind
// the session's own, and taking them in that order is how a lock cycle gets
// built by someone who was only adding a counter.
func (s *session) enforceConcurrency(route *routing.Route) error {
	return s.srv.admit(s.id, s.subjectID(), s.target,
		route.MaxSessionsPerSubject(), route.MaxSessionsPerTarget())
}

// liveSession is what the admitted registry knows about one session: the two
// scopes a cap is counted in, and nothing else.
type liveSession struct {
	subject string
	target  string
}

// admit counts the live sessions in each scope and records this one as live
// unless a cap refuses it.
//
// Counting happens against the proxy's OWN registry because that is the only
// place a live count exists (D16, PLAN §6.4) — and it is why the cap is
// per-proxy: a chained session is counted on every proxy it traverses, one slot
// each, so a cap of N is N sessions HERE and never an estate-wide ceiling. A
// fleet-wide count would have to be asked of Hoplock Control per connection,
// which is the round trip D2's decision cache exists to avoid.
//
// The count and the admission are one critical section. Two sessions arriving
// together would otherwise both count the other as absent and both be admitted,
// which is the only interesting thing that can go wrong with a ceiling of one.
//
// A session with NO caps is registered too: the cap counts live sessions, not
// capped ones, so an uncapped session still occupies the slot a capped one
// counts.
func (s *Server) admit(id, subject, tgt string, perSubject, perTarget int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	subjectLive, targetLive := 0, 0
	for liveID, live := range s.live {
		if liveID == id {
			continue
		}
		if subject != "" && live.subject == subject {
			subjectLive++
		}
		if tgt != "" && live.target == tgt {
			targetLive++
		}
	}
	if perSubject > 0 && subjectLive >= perSubject {
		return &capExceeded{scope: scopeSubject, limit: perSubject, live: subjectLive}
	}
	if perTarget > 0 && targetLive >= perTarget {
		return &capExceeded{scope: scopeTarget, limit: perTarget, live: targetLive}
	}
	s.live[id] = liveSession{subject: subject, target: tgt}
	return nil
}

// release frees a session's slot. It is called from the one place a session
// leaves the registry (Server.remove), so "a session that ends frees its slot"
// holds for every ending there is — a client hanging up, a revocation, a
// deadline, a panic in a channel goroutine.
func (s *Server) release(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.live, id)
}

// liveSessions is how many sessions this proxy currently holds past admission.
// It exists for tests and for an operator asking what a cap is counted against.
func (s *Server) liveSessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.live)
}
