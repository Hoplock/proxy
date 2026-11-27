// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"net/http"
	"slices"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// Relay registrations (PLAN D11, §6.1, phase 0049).
//
// A hub reports the complete set of proxy ids registered with it, and the set
// replaces the previous one. The mock keeps the last report per reporting proxy
// with the time it arrived, so a test can see a registrant appear and drop, and
// decides nothing from it: a report grants nothing, and the mock's routes are
// fixtures, so no report can create or remove one.
//
// The contract's rule that a server attributes a report to the proxy its
// credential names, refusing another proxy's id with 401, applies "where that
// credential names a proxy". The mock's proxy_token is one shared bearer token
// that names none, so the path's proxy id is all it has to go on.

// pathDebugRelayRegistrations returns the last relay-registration report per
// reporting proxy.
const pathDebugRelayRegistrations = "/debug/relay-registrations"

// fixtureRelayRegistrations configures the relay-registration report endpoint.
type fixtureRelayRegistrations struct {
	// ReportAfterSeconds is answered as report_after_seconds. Absent or 0
	// answers none, leaving the proxy on its own 20-second ceiling.
	ReportAfterSeconds int32 `yaml:"report_after_seconds"`
}

// relayRegistrationReport is the last report one hub made, as the debug
// endpoint returns it.
type relayRegistrationReport struct {
	RegisteredProxyIDs []string  `json:"registered_proxy_ids"`
	ReceivedAt         time.Time `json:"received_at"`
}

// handleRelayRegistrationReport serves
// POST /v1/proxies/{proxy_id}/relay-registrations/report.
func (s *server) handleRelayRegistrationReport(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProxy(w, r) {
		return
	}
	id := r.PathValue("proxy_id")
	if !s.enrolled(id) {
		writeError(w, http.StatusNotFound, "not_enrolled", "no such proxy is enrolled")
		return
	}
	var rep control.RelayRegistrationReport
	if !decode(w, r, &rep) {
		return
	}
	// Absent and null both decode to nil; [] decodes to an empty slice. The
	// contract makes the list required and never null, so that "holds none"
	// and a malformed report cannot be confused.
	if rep.RegisteredProxyIDs == nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "registered_proxy_ids is required and must not be null")
		return
	}
	seen := make(map[string]bool, len(rep.RegisteredProxyIDs))
	for _, pid := range rep.RegisteredProxyIDs {
		switch {
		case pid == "":
			writeError(w, http.StatusBadRequest, "invalid_request", "registered_proxy_ids contains an empty id")
			return
		case seen[pid]:
			writeError(w, http.StatusBadRequest, "invalid_request", "registered_proxy_ids names an id twice")
			return
		}
		seen[pid] = true
	}
	s.mu.Lock()
	s.relayReports[id] = relayRegistrationReport{
		RegisteredProxyIDs: slices.Clone(rep.RegisteredProxyIDs),
		ReceivedAt:         s.now().UTC(),
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, control.RelayRegistrationReportResponse{
		Accepted:           true,
		ReportAfterSeconds: s.fx.RelayRegistrations.ReportAfterSeconds,
	})
}

// handleDebugRelayRegistrations returns the last report per reporting proxy.
func (s *server) handleDebugRelayRegistrations(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	out := make(map[string]relayRegistrationReport, len(s.relayReports))
	for k, v := range s.relayReports {
		out[k] = v
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

// relayReport returns the last report from one hub, for tests.
func (s *server) relayReport(id string) (relayRegistrationReport, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rep, ok := s.relayReports[id]
	return rep, ok
}
