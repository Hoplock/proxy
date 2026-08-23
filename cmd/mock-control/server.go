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

	"github.com/hoplock/proxy/internal/control"
)

// Debug paths. They are deliberately outside the /v1 contract namespace: they
// exist so tests and the e2e topology can assert on what the proxy shipped,
// and no production server implements them.
const (
	pathDebugLogs   = "/debug/logs"
	pathDebugReset  = "/debug/reset"
	pathDebugRevoke = "/debug/revoke"
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

// server implements the Control API from static fixtures. Everything it
// remembers — MFA challenges, seen host keys, ingested logs — lives here, in
// memory, for the lifetime of the process.
type server struct {
	fx     *fixtures
	logDir string
	logger *log.Logger
	now    func() time.Time

	mu       sync.Mutex
	mfa      map[string]*mfaChallenge
	hostKeys map[string]bool // "target\x00fingerprint" -> seen
	batched  []control.LogRecord
	priority []control.LogRecord
	seenLogs map[string]bool // record_id -> stored, for de-duplication
	// subs are the open revocation streams; events are the retained history a
	// reconnecting proxy replays from, trimmed to the fixture's buffer size.
	subs           map[*subscriber]bool
	events         []control.RevocationEvent
	evictedThrough int
	idCounter      int
	// authorizations records every authorize call, so a test can assert that
	// each hop of a chain asked for its own decision rather than inheriting
	// one (D2, PLAN §6.1).
	authorizations []authorizeCall
}

// authorizeCall is one authorize request, reduced to what a test asserts on.
type authorizeCall struct {
	ProxyID   string
	SessionID string
	Login     string
	Subject   string
	Target    string
	HopTrail  []string
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
		subs:     make(map[*subscriber]bool),
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

// recordAuthorize remembers one authorize call.
func (s *server) recordAuthorize(req *control.AuthorizeRequest) {
	call := authorizeCall{
		ProxyID:   req.Conn.ProxyID,
		SessionID: req.Conn.SessionID,
		Target:    req.Target,
		HopTrail:  append([]string(nil), req.Conn.HopTrail...),
	}
	if req.Identity != nil {
		call.Login = req.Identity.Login
		call.Subject = req.Identity.Subject
	}
	s.mu.Lock()
	s.authorizations = append(s.authorizations, call)
	s.mu.Unlock()
}

// authorizeCalls returns the authorize calls seen so far, oldest first.
func (s *server) authorizeCalls() []authorizeCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]authorizeCall(nil), s.authorizations...)
}

// handler routes the contract endpoints plus the mock-only debug endpoints.
func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+control.PathAuthenticateCert, s.handleAuthenticateCert)
	mux.HandleFunc("POST "+control.PathAuthenticatePassword, s.handleAuthenticatePassword)
	mux.HandleFunc("POST "+control.PathPollMFA, s.handlePollMFA)
	mux.HandleFunc("POST "+control.PathAuthorize, s.handleAuthorize)
	mux.HandleFunc("POST "+control.PathReportHostKey, s.handleReportHostKey)
	mux.HandleFunc("POST "+control.PathIngestLogBatch, s.handleIngestLogBatch)
	mux.HandleFunc("POST "+control.PathIngestPriorityLog, s.handleIngestPriorityLog)
	// The path constant is already a net/http wildcard pattern, so the proxy
	// and the mock agree on the shape of the route as well as the string.
	mux.HandleFunc("GET "+control.PathProxyEvents, s.handleProxyEvents)
	mux.HandleFunc("GET "+pathDebugLogs, s.handleDebugLogs)
	mux.HandleFunc("POST "+pathDebugReset, s.handleDebugReset)
	mux.HandleFunc("POST "+pathDebugRevoke, s.handleDebugRevoke)
	return mux
}

// --- contract handlers ------------------------------------------------------

func (s *server) handleAuthenticateCert(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProxy(w, r) {
		return
	}
	var req control.AuthenticateCertRequest
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
	if !ok {
		// The message names neither the login nor the key: an unauthenticated
		// caller learns nothing about which half was wrong.
		writeError(w, http.StatusUnauthorized, "unauthorized", "no identity matches the offered key")
		return
	}

	// A chain leg presents the PREVIOUS HOP's key, not the user's (D11). The
	// server recognises the proxy and answers with the user's identity, which
	// it establishes itself: that is what makes each hop authenticate the hop
	// in front of it rather than trust what it was told (PLAN §6.1).
	if hop, isProxy := s.fx.proxyByKey(req.PublicKey.Fingerprint); isProxy {
		s.logger.Printf("mock: chain leg for %s authenticated as proxy %s", req.Login, hop.ID)
		writeJSON(w, http.StatusOK, control.AuthenticateResponse{
			Status:   control.AuthStatusAuthenticated,
			Identity: user.chainIdentity(hop.ID),
		})
		return
	}

	if !user.hasKeyFingerprint(req.PublicKey.Fingerprint) {
		writeError(w, http.StatusUnauthorized, "unauthorized", "no identity matches the offered key")
		return
	}
	writeJSON(w, http.StatusOK, control.AuthenticateResponse{
		Status:   control.AuthStatusAuthenticated,
		Identity: user.identity(),
	})
}

func (s *server) handleAuthenticatePassword(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProxy(w, r) {
		return
	}
	var req control.AuthenticatePasswordRequest
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
		writeJSON(w, http.StatusOK, control.AuthenticateResponse{
			Status:   control.AuthStatusAuthenticated,
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

	writeJSON(w, http.StatusOK, control.AuthenticateResponse{
		Status: control.AuthStatusMFARequired,
		MFA:    challenge.wire(token),
	})
}

func (s *server) handlePollMFA(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProxy(w, r) {
		return
	}
	var req control.MFAPollRequest
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
		writeJSON(w, http.StatusOK, control.AuthenticateResponse{
			Status: control.AuthStatusMFARequired,
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
	writeJSON(w, http.StatusOK, control.AuthenticateResponse{
		Status:   control.AuthStatusAuthenticated,
		Identity: user.identity(),
	})
}

func (s *server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProxy(w, r) {
		return
	}
	var req control.AuthorizeRequest
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

	s.recordAuthorize(&req)

	route, ok := s.fx.route(req.Identity.Login, req.Target, req.Conn.ProxyID)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "no route permits this identity to reach the target")
		return
	}

	s.mu.Lock()
	s.idCounter++
	decisionID := fmt.Sprintf("decision-%d", s.idCounter)
	s.mu.Unlock()

	// For a chain the target is the next proxy; the host the user asked for
	// travels in hop metadata so the next proxy re-runs the flow.
	hopTrail := append(append([]string{}, req.Conn.HopTrail...), req.Conn.ProxyID)
	resp := route.authorizeResponse(req.Target, hopTrail)
	resp.DecisionID = decisionID
	resp.Cache = cacheHint(route, req.Identity.Subject, req.Target)

	// A proxy declaring an older vocabulary must not be answered with fields it
	// cannot read: it fails such a response closed, by contract. A real server
	// would tailor the policy; the mock's fixtures are v2, so it says plainly
	// that it cannot serve this proxy rather than sending policy that will be
	// refused as a protocol error three lines later.
	if req.PolicyVersion > 0 && req.PolicyVersion < control.PolicyVersion && usesV2Vocabulary(resp) {
		writeError(w, http.StatusInternalServerError, "policy_version",
			fmt.Sprintf("this route needs policy vocabulary %d; the proxy declared %d",
				control.PolicyVersion, req.PolicyVersion))
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handleReportHostKey(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProxy(w, r) {
		return
	}
	var req control.HostKeyReportRequest
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

	resp := control.HostKeyReportResponse{
		Decision: control.HostKeyDecision(s.fx.HostKeys.Decision),
		Known:    known,
		Reason:   "host key already trusted",
	}
	if !known {
		resp.Reason = "first sighting; recorded (trust-on-first-use)"
		if resp.Decision == control.HostKeyReject {
			resp.Reason = "first sighting; policy rejects unknown host keys"
		}
	} else {
		// A key we already trust is always accepted, whatever the policy for
		// unknown keys is.
		resp.Decision = control.HostKeyAccept
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handleIngestLogBatch(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProxy(w, r) {
		return
	}
	var req control.LogBatchRequest
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

	writeJSON(w, http.StatusAccepted, control.LogBatchResponse{Accepted: accepted})
}

func (s *server) handleIngestPriorityLog(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProxy(w, r) {
		return
	}
	var req control.LogPriorityRequest
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

	writeJSON(w, http.StatusOK, control.LogPriorityResponse{Accepted: true, ReceiptID: receipt})
}

// --- mock-only debug handlers ----------------------------------------------

// debugLogs is what GET /debug/logs returns.
type debugLogs struct {
	Batched  []control.LogRecord `json:"batched"`
	Priority []control.LogRecord `json:"priority"`
}

func (s *server) handleDebugLogs(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	out := debugLogs{
		Batched:  append([]control.LogRecord{}, s.batched...),
		Priority: append([]control.LogRecord{}, s.priority...),
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

func (s *server) handleDebugReset(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	s.batched = nil
	s.priority = nil
	s.authorizations = nil
	s.seenLogs = make(map[string]bool)
	s.mfa = make(map[string]*mfaChallenge)
	s.hostKeys = make(map[string]bool)
	// Open subscriptions survive a reset; only the replayable history is
	// cleared, so a reconnect after this point starts from now.
	s.events = nil
	// Everything published so far is gone, so a proxy resuming from any of it
	// is told to resync rather than silently missing what it asked for.
	s.evictedThrough = s.idCounter
	for _, k := range s.fx.HostKeys.Known {
		s.hostKeys[hostKeyID(k.Target, k.Fingerprint)] = true
	}
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ----------------------------------------------------------------

// authorizeProxy enforces the bearer token when the fixtures set one. It
// reports whether the request may proceed.
func (s *server) authorizeProxy(w http.ResponseWriter, r *http.Request) bool {
	if s.fx.ProxyToken == "" {
		return true
	}
	const prefix = "Bearer "
	got := r.Header.Get("Authorization")
	if !strings.HasPrefix(got, prefix) || got[len(prefix):] != s.fx.ProxyToken {
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid proxy token")
		return false
	}
	return true
}

// decode reads a JSON request body, rejecting unknown fields so a proxy that
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
func (c *mfaChallenge) wire(token string) *control.MFAChallenge {
	return &control.MFAChallenge{
		Token:       token,
		Prompt:      c.prompt,
		PollAfterMS: c.pollAfterMS,
		ExpiresAt:   c.expiresAt,
	}
}

func hostKeyID(target, fingerprint string) string { return target + "\x00" + fingerprint }

// cacheHint converts a route's cache fixture into the contract's hint. A route
// without a ttl returns nil: no hint means "do not cache", which is the default
// for every route that does not opt in.
//
// The derived key is per (subject, target) — the narrowest scope, and never
// shared across identities, which the contract forbids. A fixture can set the
// key explicitly to model a server that shares one decision more widely.
func cacheHint(route *fixtureRoute, subject, target string) *control.CacheHint {
	if route.Cache.TTLSeconds <= 0 {
		return nil
	}
	key := route.Cache.Key
	if key == "" {
		key = "authz:" + subject + ":" + target
	}
	return &control.CacheHint{Key: key, TTLSeconds: route.Cache.TTLSeconds}
}

// filterRules converts fixture rules into their contract form, preserving order
// because the first match wins.
func filterRules(in []fixtureFilterRule) []control.FilterRule {
	if len(in) == 0 {
		return nil
	}
	out := make([]control.FilterRule, 0, len(in))
	for _, r := range in {
		out = append(out, control.FilterRule{
			Match:   r.Match,
			Action:  control.FilterAction(r.Action),
			Message: r.Message,
		})
	}
	return out
}

// mirror appends a record to a JSONL file when -log-dir is set. The caller
// holds s.mu. A mirroring failure is reported but never fails the request: the
// in-memory store is the source of truth for tests.
func (s *server) mirror(name string, rec control.LogRecord) {
	if s.logDir == "" {
		return
	}
	line, err := json.Marshal(rec)
	if err != nil {
		s.logger.Printf("mock-control: encode record %s: %v", rec.RecordID, err)
		return
	}
	f, err := os.OpenFile(filepath.Join(s.logDir, name), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		s.logger.Printf("mock-control: open %s: %v", name, err)
		return
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(append(line, '\n')); err != nil {
		s.logger.Printf("mock-control: write %s: %v", name, err)
	}
}
