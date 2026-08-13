// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mauroasilva/securecommandproxy/internal/mgmt"
)

// Debug paths. They are deliberately outside the /v1 contract namespace: they
// exist so tests and the e2e topology can assert on what the bastion shipped,
// and no production server implements them.
const (
	pathDebugLogs  = "/debug/logs"
	pathDebugReset = "/debug/reset"
)

// serverOptions are the knobs main passes to the server.
type serverOptions struct {
	// LogDir, when set, mirrors every ingested record to JSONL files so a test
	// can inspect them after the process exits.
	LogDir string
	// Logger receives operational messages; nil discards them.
	Logger *log.Logger
	// Now overrides the clock (tests).
	Now func() time.Time
}

// server implements the management API from static fixtures. Everything it
// remembers — MFA challenges, seen host keys, ingested logs — lives here, in
// memory, for the lifetime of the process.
type server struct {
	fx     *fixtures
	logDir string
	logger *log.Logger
	now    func() time.Time

	mu        sync.Mutex
	mfa       map[string]*mfaChallenge
	hostKeys  map[string]bool // "target\x00fingerprint" -> seen
	batched   []mgmt.LogRecord
	priority  []mgmt.LogRecord
	seenLogs  map[string]bool // record_id -> stored, for de-duplication
	idCounter int
}

// mfaChallenge is one outstanding out-of-band factor.
type mfaChallenge struct {
	login          string
	remainingPolls int
	decision       string
	expiresAt      time.Time
	pollAfterMS    int
	prompt         string
}

func newServer(fx *fixtures, opts serverOptions) *server {
	s := &server{
		fx:       fx,
		logDir:   opts.LogDir,
		logger:   opts.Logger,
		now:      opts.Now,
		mfa:      make(map[string]*mfaChallenge),
		hostKeys: make(map[string]bool),
		seenLogs: make(map[string]bool),
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.logger == nil {
		s.logger = log.New(os.Stderr, "", 0)
	}
	for _, k := range fx.HostKeys.Known {
		s.hostKeys[hostKeyID(k.Target, k.Fingerprint)] = true
	}
	return s
}

// handler routes the contract endpoints plus the mock-only debug endpoints.
func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+mgmt.PathAuthenticateCert, s.handleAuthenticateCert)
	mux.HandleFunc("POST "+mgmt.PathAuthenticatePassword, s.handleAuthenticatePassword)
	mux.HandleFunc("POST "+mgmt.PathPollMFA, s.handlePollMFA)
	mux.HandleFunc("POST "+mgmt.PathAuthorize, s.handleAuthorize)
	mux.HandleFunc("POST "+mgmt.PathReportHostKey, s.handleReportHostKey)
	mux.HandleFunc("POST "+mgmt.PathIngestLogBatch, s.handleIngestLogBatch)
	mux.HandleFunc("POST "+mgmt.PathIngestPriorityLog, s.handleIngestPriorityLog)
	mux.HandleFunc("GET "+pathDebugLogs, s.handleDebugLogs)
	mux.HandleFunc("POST "+pathDebugReset, s.handleDebugReset)
	return mux
}

// --- contract handlers ------------------------------------------------------

func (s *server) handleAuthenticateCert(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeBastion(w, r) {
		return
	}
	var req mgmt.AuthenticateCertRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Login == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "login is required")
		return
	}
	if req.PublicKey.Fingerprint == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "public_key.fingerprint is required")
		return
	}

	user, ok := s.fx.user(req.Login)
	if !ok || !user.hasKeyFingerprint(req.PublicKey.Fingerprint) {
		// The message names neither the login nor the key: an unauthenticated
		// caller learns nothing about which half was wrong.
		writeError(w, http.StatusUnauthorized, "unauthorized", "no identity matches the offered key")
		return
	}
	writeJSON(w, http.StatusOK, mgmt.AuthenticateResponse{
		Status:   mgmt.AuthStatusAuthenticated,
		Identity: user.identity(),
	})
}

func (s *server) handleAuthenticatePassword(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeBastion(w, r) {
		return
	}
	var req mgmt.AuthenticatePasswordRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Login == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "login is required")
		return
	}

	user, ok := s.fx.user(req.Login)
	// The password is compared and then dropped: it is never logged, echoed, or
	// stored anywhere in this server (PLAN §7).
	if !ok || user.Password == "" || user.Password != req.Password {
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid credentials")
		return
	}

	if !user.MFA.Required {
		writeJSON(w, http.StatusOK, mgmt.AuthenticateResponse{
			Status:   mgmt.AuthStatusAuthenticated,
			Identity: user.identity(),
		})
		return
	}

	s.mu.Lock()
	s.idCounter++
	token := fmt.Sprintf("mfa-%d", s.idCounter)
	challenge := &mfaChallenge{
		login:          user.Login,
		remainingPolls: user.MFA.PendingPolls,
		decision:       user.MFA.Decision,
		expiresAt:      s.now().Add(time.Duration(user.MFA.TTLMS) * time.Millisecond),
		pollAfterMS:    user.MFA.PollAfterMS,
		prompt:         user.MFA.Prompt,
	}
	s.mfa[token] = challenge
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, mgmt.AuthenticateResponse{
		Status: mgmt.AuthStatusMFARequired,
		MFA:    challenge.wire(token),
	})
}

func (s *server) handlePollMFA(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeBastion(w, r) {
		return
	}
	var req mgmt.MFAPollRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}

	s.mu.Lock()
	challenge, ok := s.mfa[req.Token]
	switch {
	case !ok:
		s.mu.Unlock()
		writeError(w, http.StatusUnauthorized, "unauthorized", "unknown or spent MFA token")
		return
	case !s.now().Before(challenge.expiresAt):
		delete(s.mfa, req.Token)
		s.mu.Unlock()
		writeError(w, http.StatusUnauthorized, "unauthorized", "MFA challenge expired")
		return
	case challenge.remainingPolls > 0:
		challenge.remainingPolls--
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, mgmt.AuthenticateResponse{
			Status: mgmt.AuthStatusMFARequired,
			MFA:    challenge.wire(req.Token),
		})
		return
	}

	// The challenge resolves now; the token is single-use either way.
	delete(s.mfa, req.Token)
	login, decision := challenge.login, challenge.decision
	s.mu.Unlock()

	if decision != mfaApprove {
		writeError(w, http.StatusUnauthorized, "unauthorized", "MFA was denied")
		return
	}
	user, ok := s.fx.user(login)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "identity is no longer known")
		return
	}
	writeJSON(w, http.StatusOK, mgmt.AuthenticateResponse{
		Status:   mgmt.AuthStatusAuthenticated,
		Identity: user.identity(),
	})
}

func (s *server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeBastion(w, r) {
		return
	}
	var req mgmt.AuthorizeRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Identity == nil || req.Identity.Login == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "identity.login is required")
		return
	}
	if req.Target == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "target is required")
		return
	}

	route, ok := s.fx.route(req.Identity.Login, req.Target)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "no route permits this identity to reach the target")
		return
	}

	s.mu.Lock()
	s.idCounter++
	decisionID := fmt.Sprintf("decision-%d", s.idCounter)
	s.mu.Unlock()

	resp := mgmt.AuthorizeResponse{
		RouteType:         mgmt.RouteType(route.RouteType),
		Target:            req.Target,
		TargetPort:        route.TargetPort,
		Permissions:       route.Permissions,
		PermittedChannels: route.PermittedChannels,
		FilterPolicy: mgmt.FilterPolicy{
			Mode:     mgmt.FilterMode(route.FilterPolicy.Mode),
			Commands: route.FilterPolicy.Commands,
			Action:   mgmt.FilterAction(route.FilterPolicy.Action),
		},
		DecisionID: decisionID,
	}
	if resp.PermittedChannels == nil {
		// An absent allow-list must serialise as [] (deny all), not null.
		resp.PermittedChannels = []string{}
	}

	switch resp.RouteType {
	case mgmt.RouteTypeDirect:
		if route.ResolvedTarget != "" {
			resp.Target = route.ResolvedTarget
		}
	case mgmt.RouteTypeNextHop:
		// For a chain the target is the next bastion; the host the user asked
		// for travels in hop metadata so the next bastion re-runs the flow.
		resp.Target = route.NextHop
		resp.Hop = &mgmt.HopMetadata{
			FinalTarget: req.Target,
			MaxHops:     route.MaxHops,
			HopTrail:    append(append([]string{}, req.Conn.HopTrail...), req.Conn.BastionID),
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handleReportHostKey(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeBastion(w, r) {
		return
	}
	var req mgmt.HostKeyReportRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Target == "" || req.HostKey.Fingerprint == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "target and host_key.fingerprint are required")
		return
	}

	id := hostKeyID(req.Target, req.HostKey.Fingerprint)
	s.mu.Lock()
	known := s.hostKeys[id]
	// Trust on first use: record the key so the next report says known (D7).
	s.hostKeys[id] = true
	s.mu.Unlock()

	resp := mgmt.HostKeyReportResponse{
		Decision: mgmt.HostKeyDecision(s.fx.HostKeys.Decision),
		Known:    known,
		Reason:   "host key already trusted",
	}
	if !known {
		resp.Reason = "first sighting; recorded (trust-on-first-use)"
		if resp.Decision == mgmt.HostKeyReject {
			resp.Reason = "first sighting; policy rejects unknown host keys"
		}
	} else {
		// A key we already trust is always accepted, whatever the policy for
		// unknown keys is.
		resp.Decision = mgmt.HostKeyAccept
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handleIngestLogBatch(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeBastion(w, r) {
		return
	}
	var req mgmt.LogBatchRequest
	if !decode(w, r, &req) {
		return
	}
	if len(req.Records) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "records must not be empty")
		return
	}
	for i, rec := range req.Records {
		if rec.RecordID == "" || rec.SessionID == "" {
			writeError(w, http.StatusBadRequest, "invalid_request",
				fmt.Sprintf("records[%d] needs record_id and session_id", i))
			return
		}
	}

	accepted := 0
	s.mu.Lock()
	for _, rec := range req.Records {
		if s.seenLogs[rec.RecordID] {
			continue // a retried batch; the server de-duplicates
		}
		s.seenLogs[rec.RecordID] = true
		s.batched = append(s.batched, rec)
		accepted++
		s.mirror("batch.jsonl", rec)
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusAccepted, mgmt.LogBatchResponse{Accepted: accepted})
}

func (s *server) handleIngestPriorityLog(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeBastion(w, r) {
		return
	}
	var req mgmt.LogPriorityRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Record.RecordID == "" || req.Record.SessionID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "record needs record_id and session_id")
		return
	}

	s.mu.Lock()
	s.idCounter++
	receipt := fmt.Sprintf("receipt-%d", s.idCounter)
	if !s.seenLogs[req.Record.RecordID] {
		s.seenLogs[req.Record.RecordID] = true
		s.priority = append(s.priority, req.Record)
		s.mirror("priority.jsonl", req.Record)
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, mgmt.LogPriorityResponse{Accepted: true, ReceiptID: receipt})
}

// --- mock-only debug handlers ----------------------------------------------

// debugLogs is what GET /debug/logs returns.
type debugLogs struct {
	Batched  []mgmt.LogRecord `json:"batched"`
	Priority []mgmt.LogRecord `json:"priority"`
}

func (s *server) handleDebugLogs(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	out := debugLogs{
		Batched:  append([]mgmt.LogRecord{}, s.batched...),
		Priority: append([]mgmt.LogRecord{}, s.priority...),
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

func (s *server) handleDebugReset(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	s.batched = nil
	s.priority = nil
	s.seenLogs = make(map[string]bool)
	s.mfa = make(map[string]*mfaChallenge)
	s.hostKeys = make(map[string]bool)
	for _, k := range s.fx.HostKeys.Known {
		s.hostKeys[hostKeyID(k.Target, k.Fingerprint)] = true
	}
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ----------------------------------------------------------------

// authorizeBastion enforces the bearer token when the fixtures set one. It
// reports whether the request may proceed.
func (s *server) authorizeBastion(w http.ResponseWriter, r *http.Request) bool {
	if s.fx.BastionToken == "" {
		return true
	}
	const prefix = "Bearer "
	got := r.Header.Get("Authorization")
	if !strings.HasPrefix(got, prefix) || got[len(prefix):] != s.fx.BastionToken {
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid bastion token")
		return false
	}
	return true
}

// decode reads a JSON request body, rejecting unknown fields so a bastion that
// drifts from the contract is told loudly instead of being silently ignored.
func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		// The error may quote the offending body fragment, which for the
		// password endpoint could include the password: report the field only.
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid for this endpoint")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	var body errorEnvelope
	body.Error.Code = code
	body.Error.Message = message
	writeJSON(w, status, body)
}

// errorEnvelope is the contract's error body: {"error":{"code","message"}}.
type errorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// wire converts an internal challenge into its contract form.
func (c *mfaChallenge) wire(token string) *mgmt.MFAChallenge {
	return &mgmt.MFAChallenge{
		Token:       token,
		Prompt:      c.prompt,
		PollAfterMS: c.pollAfterMS,
		ExpiresAt:   c.expiresAt,
	}
}

func hostKeyID(target, fingerprint string) string { return target + "\x00" + fingerprint }

// mirror appends a record to a JSONL file when -log-dir is set. The caller
// holds s.mu. A mirroring failure is reported but never fails the request: the
// in-memory store is the source of truth for tests.
func (s *server) mirror(name string, rec mgmt.LogRecord) {
	if s.logDir == "" {
		return
	}
	line, err := json.Marshal(rec)
	if err != nil {
		s.logger.Printf("mock-management: encode record %s: %v", rec.RecordID, err)
		return
	}
	f, err := os.OpenFile(filepath.Join(s.logDir, name), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		s.logger.Printf("mock-management: open %s: %v", name, err)
		return
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(append(line, '\n')); err != nil {
		s.logger.Printf("mock-management: write %s: %v", name, err)
	}
}
