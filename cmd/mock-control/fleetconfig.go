// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/hoplock/proxy/internal/control"
)

// Fleet configuration (PLAN D18, phase 0042).
//
// The mock holds ONE current document and serves it to every enrolled proxy.
// It cannot advertise a version it does not serve — 0039's standard — because
// there is exactly one way to publish: pathDebugConfig stores the document,
// derives its hash from the bytes it will serve, and emits the config_changed
// event from that same stored document. /debug/revoke refuses config_changed
// for the same reason: an event built by hand could name a document nobody
// serves.
const (
	// pathDebugConfig publishes a new document, standing in for Control's
	// publisher (its fleet.ConfigPublisher).
	pathDebugConfig = "/debug/config"
	// pathDebugConfigReports returns the last configuration report per proxy.
	pathDebugConfigReports = "/debug/config/reports"
)

// fixtureFleetConfig is the fleet-configuration fixture.
type fixtureFleetConfig struct {
	// Enrolled lists the proxy ids the mock treats as enrolled. Empty means
	// every proxy id is; a proxy not listed is answered 404 not_enrolled.
	Enrolled []string `yaml:"enrolled"`
	// Document is the document published at startup. Absent means nothing is
	// published, so the fetch answers 204.
	Document *fixtureConfigDocument `yaml:"document"`
}

// fixtureConfigDocument is one published document. Settings are passed through
// uninterpreted: validating them is the proxy's job, and a mock that refused a
// bad document could not be used to test the proxy refusing one.
type fixtureConfigDocument struct {
	Version  string         `json:"version" yaml:"version"`
	Settings map[string]any `json:"settings" yaml:"settings"`
}

// buildConfigDocument renders a document as the mock will serve it, with its
// hash derived from exactly those bytes.
func buildConfigDocument(d *fixtureConfigDocument) (*control.ProxyConfigDocument, error) {
	if d == nil {
		return nil, nil
	}
	if d.Version == "" {
		return nil, fmt.Errorf("fleet_config.document.version is required")
	}
	settings := make(map[string]json.RawMessage, len(d.Settings))
	for k, v := range d.Settings {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("fleet_config.document.settings[%q] is not JSON-encodable: %v", k, err)
		}
		settings[k] = raw
	}
	// json.Marshal orders map keys, so equal documents hash equally.
	body, err := json.Marshal(struct {
		Version  string                     `json:"version"`
		Settings map[string]json.RawMessage `json:"settings"`
	}{d.Version, settings})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	return &control.ProxyConfigDocument{
		Version:  d.Version,
		Hash:     "sha256:" + hex.EncodeToString(sum[:]),
		Settings: settings,
	}, nil
}

// enrolled reports whether id may fetch a document.
func (s *server) enrolled(id string) bool {
	return len(s.fx.FleetConfig.Enrolled) == 0 || slices.Contains(s.fx.FleetConfig.Enrolled, id)
}

// handleProxyConfig serves GET /v1/proxies/{proxy_id}/config.
func (s *server) handleProxyConfig(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProxy(w, r) {
		return
	}
	id := r.PathValue("proxy_id")
	if !s.enrolled(id) {
		writeError(w, http.StatusNotFound, "not_enrolled", "no such proxy is enrolled")
		return
	}
	s.mu.Lock()
	doc := s.fleetDoc
	s.mu.Unlock()
	if doc == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	etag := `"` + doc.Hash + `"`
	if inm := r.Header.Get("If-None-Match"); inm != "" && strings.TrimPrefix(inm, "W/") == etag {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, doc)
}

// handleProxyConfigReport serves POST /v1/proxies/{proxy_id}/config/report.
func (s *server) handleProxyConfigReport(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProxy(w, r) {
		return
	}
	id := r.PathValue("proxy_id")
	if !s.enrolled(id) {
		writeError(w, http.StatusNotFound, "not_enrolled", "no such proxy is enrolled")
		return
	}
	var rep control.ProxyConfigReport
	if !decode(w, r, &rep) {
		return
	}
	switch rep.State {
	case control.ConfigStateApplied, control.ConfigStatePendingRestart,
		control.ConfigStateRejected, control.ConfigStateFetchFailed:
	default:
		writeError(w, http.StatusBadRequest, "invalid_request", "state is not a known configuration state")
		return
	}
	if rep.ReportedAt.IsZero() {
		writeError(w, http.StatusBadRequest, "invalid_request", "reported_at is required")
		return
	}
	s.mu.Lock()
	s.configReports[id] = rep
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, control.ProxyConfigReportResponse{Accepted: true})
}

// debugConfigResponse says what was published and whom it reached.
type debugConfigResponse struct {
	EventID   string `json:"event_id"`
	Delivered int    `json:"delivered"`
	Version   string `json:"version"`
	Hash      string `json:"hash"`
}

// handleDebugConfig publishes a new document and announces it.
func (s *server) handleDebugConfig(w http.ResponseWriter, r *http.Request) {
	var in fixtureConfigDocument
	if !decode(w, r, &in) {
		return
	}
	doc, err := buildConfigDocument(&in)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	s.mu.Lock()
	s.fleetDoc = doc
	s.mu.Unlock()
	eventID, delivered := s.publishEvent(control.RevocationEvent{
		Type:          control.EventTypeConfigChanged,
		ConfigChanged: &control.ConfigChangedEvent{Version: doc.Version, Hash: doc.Hash},
	})
	writeJSON(w, http.StatusOK, debugConfigResponse{EventID: eventID, Delivered: delivered, Version: doc.Version, Hash: doc.Hash})
}

// handleDebugConfigReports returns the last report per proxy.
func (s *server) handleDebugConfigReports(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	out := make(map[string]control.ProxyConfigReport, len(s.configReports))
	for k, v := range s.configReports {
		out[k] = v
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

// configReport returns the last report from one proxy, for tests.
func (s *server) configReport(id string) (control.ProxyConfigReport, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rep, ok := s.configReports[id]
	return rep, ok
}
