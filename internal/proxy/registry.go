// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"context"
)

// DefaultKillReason is shown when Hoplock Control ordered a kill without
// saying why. PLAN §4.3 requires the user be told something: a session that
// vanishes silently is indistinguishable from a crash, and the difference
// decides whether they retry or call someone.
const DefaultKillReason = "your session was ended by Hoplock Control"

// The Server implements control.SessionRegistry, which is the half of the
// revocation mechanism phase 0003 left open (PLAN §6.4). It is what makes a
// cached authorize decision safe to hold: the server can withdraw access that is
// already in use, and can end a session that is already in flight.
//
// All three methods are best-effort by contract and return nil for sessions
// this proxy does not have. A kill for an unknown session is normal — the
// server broadcasts to a fleet and does not track which proxy holds which
// session — so treating it as an error would fill the revocation stream's logs
// with noise and tell the operator nothing.

// KillSession implements control.SessionRegistry.
func (s *Server) KillSession(_ context.Context, sessionID, reason string) error {
	s.mu.Lock()
	sess := s.sessions[sessionID]
	s.mu.Unlock()
	if sess == nil {
		return nil
	}
	sess.kill(killReason(reason))
	return nil
}

// KillSubject implements control.SessionRegistry.
//
// It matches on the identity's subject, never on the login: the login is what
// the user typed, while the subject is the stable id Hoplock Control
// revokes by. A revocation keyed on a typed name would miss the same person
// connecting under a different spelling.
func (s *Server) KillSubject(_ context.Context, subject, reason string) error {
	if subject == "" {
		return nil
	}
	for _, sess := range s.snapshot() {
		if sess.subjectID() == subject {
			sess.kill(killReason(reason))
		}
	}
	return nil
}

// KillAll implements control.SessionRegistry.
func (s *Server) KillAll(_ context.Context, reason string) error {
	for _, sess := range s.snapshot() {
		sess.kill(killReason(reason))
	}
	return nil
}

// Sessions reports the ids of the sessions currently proxied. It exists for
// tests and for a later status endpoint; it is a snapshot, not a lock on
// anything.
func (s *Server) Sessions() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.sessions))
	for id := range s.sessions {
		ids = append(ids, id)
	}
	return ids
}

func killReason(reason string) string {
	if reason == "" {
		return DefaultKillReason
	}
	return reason
}
