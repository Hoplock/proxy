// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// controlServer is an instrumented, in-process stand-in for Hoplock Control.
//
// It is deliberately NOT cmd/mock-control. That server is fixture-driven and
// exists to make behaviour testable; this one exists to be COUNTED. It answers
// from the scenario rather than from a fixture file (a fixture with 300,000
// routes is a fixture nobody can read), records every call with its handling
// time, and can inject latency — none of which belongs in the behavioural mock.
// Both speak the same contract types from internal/control, so neither can
// drift from the wire format without the other failing to compile.
type controlServer struct {
	scenario *Scenario
	// targetHost and targetPort are where every authorize decision routes to:
	// one cheap in-process target standing in for the whole fleet. The FLEET is
	// the distinct target NAMES in the request, which is what the proxy's cache
	// keys on; where they actually resolve is not what is being measured.
	targetHost string
	targetPort int
	token      string

	ln  net.Listener
	srv *http.Server

	mu    sync.Mutex
	calls map[string]*callStat

	// hostKeysSeen tracks trust-on-first-use so the report can say whether the
	// host-key call is per connection or per target.
	hostKeys sync.Map

	eventSeq atomic.Uint64
}

// callStat accumulates what one control endpoint cost.
type callStat struct {
	Count      uint64
	TotalNanos int64
	MaxNanos   int64
}

// CallReport is one endpoint's share of the control load.
type CallReport struct {
	Path       string  `json:"path"`
	Count      uint64  `json:"count"`
	PerConn    float64 `json:"per_connection"`
	MeanMicros float64 `json:"mean_handling_micros"`
	MaxMicros  float64 `json:"max_handling_micros"`
}

func newControlServer(sc *Scenario, targetHost string, targetPort int, token string) *controlServer {
	return &controlServer{
		scenario:   sc,
		targetHost: targetHost,
		targetPort: targetPort,
		token:      token,
		calls:      make(map[string]*callStat),
	}
}

// start binds a loopback port and serves until stop is called.
func (c *controlServer) start() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("control: listen: %w", err)
	}
	c.ln = ln

	mux := http.NewServeMux()
	mux.HandleFunc("POST "+control.PathAuthenticateCert, c.instrument(control.PathAuthenticateCert, c.handleAuthCert))
	mux.HandleFunc("POST "+control.PathAuthorize, c.instrument(control.PathAuthorize, c.handleAuthorize))
	mux.HandleFunc("POST "+control.PathReportHostKey, c.instrument(control.PathReportHostKey, c.handleHostKey))
	mux.HandleFunc("POST "+control.PathIngestLogBatch, c.instrument(control.PathIngestLogBatch, c.handleLogBatch))
	mux.HandleFunc("POST "+control.PathIngestPriorityLog, c.instrument(control.PathIngestPriorityLog, c.handleLogPriority))
	mux.HandleFunc("POST "+control.PathReportCapabilities, c.instrument(control.PathReportCapabilities, c.handleCapabilities))
	mux.HandleFunc("GET "+control.PathProxyEvents, c.handleEvents)

	c.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = c.srv.Serve(ln) }()
	return nil
}

func (c *controlServer) baseURL() string {
	return "http://" + c.ln.Addr().String()
}

func (c *controlServer) stop() {
	if c.srv != nil {
		_ = c.srv.Close()
	}
}

// instrument counts a call and charges it the scenario's injected latency. The
// latency is applied BEFORE the handler so it lands on the proxy's critical
// path exactly as network distance would.
func (c *controlServer) instrument(path string, h func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if !c.authorized(w, r) {
			return
		}
		if d := c.scenario.Control.Latency; d > 0 {
			time.Sleep(d)
		}
		h(w, r)
		c.record(path, time.Since(start))
	}
}

func (c *controlServer) authorized(w http.ResponseWriter, r *http.Request) bool {
	if c.token == "" {
		return true
	}
	if r.Header.Get("Authorization") == "Bearer "+c.token {
		return true
	}
	http.Error(w, `{"error":{"code":"unauthorized","message":"bad token"}}`, http.StatusUnauthorized)
	return false
}

func (c *controlServer) record(path string, d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.calls[path]
	if st == nil {
		st = &callStat{}
		c.calls[path] = st
	}
	st.Count++
	st.TotalNanos += d.Nanoseconds()
	if n := d.Nanoseconds(); n > st.MaxNanos {
		st.MaxNanos = n
	}
}

// reset drops every counter. The driver calls it at the end of warmup so the
// reported per-connection call rate is a steady-state number.
func (c *controlServer) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = make(map[string]*callStat)
}

// snapshot returns the per-endpoint report, normalised by connections.
func (c *controlServer) snapshot(connections uint64) []CallReport {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]CallReport, 0, len(c.calls))
	for path, st := range c.calls {
		rep := CallReport{Path: path, Count: st.Count}
		if connections > 0 {
			rep.PerConn = float64(st.Count) / float64(connections)
		}
		if st.Count > 0 {
			rep.MeanMicros = float64(st.TotalNanos) / float64(st.Count) / 1000
		}
		rep.MaxMicros = float64(st.MaxNanos) / 1000
		out = append(out, rep)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// count returns one endpoint's current call count.
func (c *controlServer) count(path string) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if st := c.calls[path]; st != nil {
		return st.Count
	}
	return 0
}

func (c *controlServer) handleAuthCert(w http.ResponseWriter, r *http.Request) {
	var req control.AuthenticateCertRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	// Every key is accepted. Authenticating the load generator is not what is
	// being measured, and a fixture of 300,000 fingerprints would only add
	// a map lookup to the number this run reports.
	writeJSON(w, control.AuthenticateResponse{
		Status: control.AuthStatusAuthenticated,
		Identity: &control.Identity{
			Subject:     req.Login + "@load.invalid",
			Login:       req.Login,
			Source:      "loadgen",
			Principals:  []string{req.Login},
			DisplayName: req.Login,
		},
	})
}

func (c *controlServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	var req control.AuthorizeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	resp := control.AuthorizeResponse{
		RouteType:         control.RouteTypeDirect,
		Target:            c.targetHost,
		TargetPort:        c.targetPort,
		Permissions:       "loadgen",
		PermittedChannels: []string{"session"},
		// An empty blacklist filters nothing. The filter engine still compiles
		// and runs per exec, so what a rule costs is not what this run isolates
		// — a policy with rules would measure the rules, and D17's load
		// question is about connections rather than about pattern matching.
		FilterPolicy: control.FilterPolicy{Mode: control.FilterModeBlacklist},
	}
	if c.scenario.Control.CacheHint {
		resp.Cache = &control.CacheHint{
			Key:        c.cacheKey(&req),
			TTLSeconds: int(c.scenario.Control.CacheTTL / time.Second),
		}
	}
	writeJSON(w, resp)
}

// cacheKey is the SERVER's choice of sharing scope. The proxy never builds one
// (PLAN §6.4), which is why the widest scope the contract allows is a server
// setting here rather than a proxy setting in config.yaml.
func (c *controlServer) cacheKey(req *control.AuthorizeRequest) string {
	subject := ""
	if req.Identity != nil {
		subject = req.Identity.Subject
	}
	if c.scenario.Control.CacheScope == ScopePerSubject {
		return "subj:" + subject
	}
	return "st:" + subject + "|" + req.Target
}

func (c *controlServer) handleHostKey(w http.ResponseWriter, r *http.Request) {
	var req control.HostKeyReportRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	_, seen := c.hostKeys.LoadOrStore(req.Target+"|"+req.HostKey.Fingerprint, struct{}{})
	writeJSON(w, control.HostKeyReportResponse{Decision: control.HostKeyAccept, Known: seen})
}

func (c *controlServer) handleLogBatch(w http.ResponseWriter, r *http.Request) {
	var req control.LogBatchRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	// 202, not 200: internal/control/rest.go requires exactly this status for
	// the batch path, and a 200 here would make every batch fail, spill to the
	// proxy's resilience buffer, and turn "control calls per connection" into a
	// measurement of retry behaviour.
	writeJSONStatus(w, http.StatusAccepted, control.LogBatchResponse{Accepted: len(req.Records)})
}

func (c *controlServer) handleLogPriority(w http.ResponseWriter, r *http.Request) {
	var req control.LogPriorityRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	writeJSON(w, control.LogPriorityResponse{Accepted: true})
}

func (c *controlServer) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	var req control.CapabilityReportRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	writeJSON(w, control.CapabilityReportResponse{Accepted: true})
}

// handleEvents serves the revocation stream. It carries nothing but heartbeats:
// a run with no revocations still needs the stream ALIVE, because a proxy that
// cannot hear revocations stops serving cached decisions (PLAN §6.4's
// fail-closed rule) and every cache measurement here would silently become a
// measurement of that instead.
func (c *controlServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !c.authorized(w, r) {
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if rc.Flush() != nil {
		return
	}

	enc := json.NewEncoder(w)
	write := func(ev control.RevocationEvent) bool {
		if enc.Encode(ev) != nil {
			return false
		}
		return rc.Flush() == nil
	}

	ticker := time.NewTicker(c.scenario.Control.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if !write(c.newEvent(control.EventTypeHeartbeat)) {
				return
			}
		}
	}
}

func (c *controlServer) newEvent(t control.EventType) control.RevocationEvent {
	return control.RevocationEvent{
		EventID:   fmt.Sprintf("ev-%d", c.eventSeq.Add(1)),
		Type:      t,
		Timestamp: time.Now().UTC(),
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, `{"error":{"code":"invalid_request","message":"bad json"}}`, http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	writeJSONStatus(w, http.StatusOK, v)
}

func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// callName shortens a contract path for the report table.
func callName(path string) string {
	return strings.TrimPrefix(path, "/v1/")
}
