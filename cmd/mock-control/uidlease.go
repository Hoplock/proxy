// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"fmt"
	"net/http"

	"github.com/hoplock/proxy/internal/control"
)

// This file is the mock's half of phase 0035: the per-target allocation cursor
// that makes a uid-block lease mean anything.
//
// It is deliberately the whole server-side requirement, and it is small on
// purpose — the design claim the proxy makes is that Control needs ONE INTEGER
// PER TARGET, advanced under a lock on grant, with no per-session write and no
// read-modify-write on the session path. A mock that needed more than that would
// be evidence the claim is wrong.
//
// THE ONE INVARIANT A REAL CONTROL MUST ALSO KEEP: the cursor only ever
// advances. A uid inside a granted block is never inside another grant, for this
// proxy or any other, ever again — whether the block was used, abandoned, or
// allowed to expire. Everything the proxy relies on follows from that: two
// proxies cannot collide, a block is safe to hold through an outage, and an
// expired lease costs availability rather than the invariant. A server that
// "reclaimed" an unused block to save uids would silently reintroduce the
// cross-user file inheritance the whole mechanism exists to close.

// defaultUIDLeaseCount is the block size the mock grants when neither the
// fixture nor the proxy asks for one.
const defaultUIDLeaseCount = 4096

// fixtureUIDLeases configures the mock's uid-block grants (contract 4.3).
type fixtureUIDLeases struct {
	// UIDCount is the block size to grant, overriding whatever the proxy asks
	// for. Zero honours the proxy's request, and falls back to
	// defaultUIDLeaseCount when it asks for nothing.
	UIDCount int `yaml:"uid_count"`
	// TermSeconds is the lease term. Zero leaves it to the proxy's default.
	//
	// A fixture sets it to make the *outage* trade-off visible in a test: a
	// block ends when it is exhausted or when its term runs out, and both refuse
	// the session while this server is unreachable.
	TermSeconds int `yaml:"term_seconds"`
	// RangeMin and RangeMax bound the uids this server will allocate from, for
	// every target. Zero on either takes the bound from the proxy's own request
	// — which is what a Control with no opinion about a fleet's uid conventions
	// should do, and what makes the mock usable against any proxy config.
	RangeMin int `yaml:"range_min"`
	RangeMax int `yaml:"range_max"`
}

// handleLeaseUIDs grants an exclusive block of uids for one target (contract
// 4.3, phase 0035).
func (s *server) handleLeaseUIDs(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProxy(w, r) {
		return
	}
	var req control.UIDLeaseRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Target == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "target is required")
		return
	}
	if req.ProxyID == "" {
		// A block is granted TO a proxy. An unnamed one cannot be granted
		// anything, and a server that allowed it could not answer "whose block
		// was this uid in" for an incident.
		writeError(w, http.StatusBadRequest, "invalid_request", "proxy_id is required")
		return
	}

	resp, err := s.grantUIDBlock(&req)
	if err != nil {
		// The cursor has reached the top of the range. It is its own status
		// because it is the one refusal here an operator has to act on, and the
		// proxy treats it exactly as it treats an exhausted block.
		writeError(w, http.StatusConflict, "uid_range_exhausted", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// grantUIDBlock advances the target's cursor and returns the block it carved
// off, or refuses because the range is spent.
func (s *server) grantUIDBlock(req *control.UIDLeaseRequest) (control.UIDLeaseResponse, error) {
	cfg := s.fx.UIDLeases
	min, max := cfg.RangeMin, cfg.RangeMax
	if min == 0 {
		min = req.RangeMin
	}
	if max == 0 {
		max = req.RangeMax
	}
	if max <= min {
		return control.UIDLeaseResponse{}, fmt.Errorf("no uid range is configured for %s", req.Target)
	}
	count := cfg.UIDCount
	if count == 0 {
		count = req.UIDCount
	}
	if count <= 0 {
		count = defaultUIDLeaseCount
	}

	key := uidLeaseKey(req.Target, req.TargetPort)

	s.mu.Lock()
	defer s.mu.Unlock()
	cursor, ok := s.uidCursor[key]
	if !ok {
		cursor = min
	}
	// The proxy's observation may only RAISE the cursor. It is a target's word
	// relayed by a proxy, so it is honoured only upward and only inside the
	// range — which is what lets a server whose cursor sits below a mark left by
	// an earlier deployment catch up, at the cost a real Control should weigh:
	// root on a target can report a large floor and burn that target's range.
	if req.ObservedFloor >= cursor {
		cursor = req.ObservedFloor + 1
	}
	if cursor > max {
		return control.UIDLeaseResponse{}, fmt.Errorf("the uid range for %s is exhausted", req.Target)
	}
	to := cursor + count
	if to > max+1 {
		to = max + 1
	}
	s.uidCursor[key] = to
	s.uidLeases[key]++

	return control.UIDLeaseResponse{
		LeaseID:     fmt.Sprintf("lease-%s-%d", req.ProxyID, s.uidLeases[key]),
		UIDFrom:     cursor,
		UIDTo:       to,
		TermSeconds: cfg.TermSeconds,
	}, nil
}

// uidLeaseKey names a target the way the proxy's holder does.
func uidLeaseKey(target string, port int) string {
	if port <= 0 {
		return target
	}
	return fmt.Sprintf("%s:%d", target, port)
}

// uidLeaseCalls returns how many blocks have been granted for a target, for
// tests. "One call per block, not per session" is the claim the lease shape is
// justified by, so it has to be assertable.
func (s *server) uidLeaseCalls(target string, port int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.uidLeases[uidLeaseKey(target, port)]
}
