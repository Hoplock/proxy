// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package user

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/mauroasilva/securecommandproxy/internal/mgmt"
)

// testMeta is the connection every test authenticates on. The login and target
// are distinctive strings so a test can assert that neither leaks into what the
// user is told.
func testMeta() ConnMeta {
	return ConnMeta{
		SessionID:     "sess-0001",
		BastionID:     "bastion-a",
		Login:         "alice",
		Target:        "db01.corp.example.com",
		ClientAddr:    "203.0.113.7:52344",
		ServerAddr:    "198.51.100.2:2222",
		ClientVersion: "SSH-2.0-OpenSSH_9.6",
	}
}

// recordingServer is a management server built per test from path handlers. It
// keeps every request body, so a test can prove what the bastion actually put
// on the wire — which is how the redaction test distinguishes "the password was
// sent" from "the password was logged".
type recordingServer struct {
	mu     sync.Mutex
	bodies map[string][]string
	server *httptest.Server
}

// newRecordingServer starts a server that answers the given paths and returns
// it together with a real mgmt.RESTClient pointed at it. Tests go through the
// real client on purpose: the contract, the client, and the authenticator are
// then all exercised by the same assertion.
func newRecordingServer(t *testing.T, handlers map[string]http.HandlerFunc) (*recordingServer, *mgmt.RESTClient) {
	t.Helper()

	rs := &recordingServer{bodies: make(map[string][]string)}
	mux := http.NewServeMux()
	for path, h := range handlers {
		path, h := path, h
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read body", http.StatusInternalServerError)
				return
			}
			rs.mu.Lock()
			rs.bodies[path] = append(rs.bodies[path], string(body))
			rs.mu.Unlock()

			r.Body = io.NopCloser(bytes.NewReader(body))
			h(w, r)
		})
	}
	rs.server = httptest.NewServer(mux)
	t.Cleanup(rs.server.Close)

	client, err := mgmt.NewRESTClient(mgmt.Options{BaseURL: rs.server.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewRESTClient returned error: %v", err)
	}
	return rs, client
}

// requests returns the number of requests recorded for a path.
func (rs *recordingServer) requests(path string) int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return len(rs.bodies[path])
}

// bodiesFor returns the recorded request bodies for a path.
func (rs *recordingServer) bodiesFor(path string) []string {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return append([]string(nil), rs.bodies[path]...)
}

// writeJSON answers with a JSON body and status.
func writeJSON(t *testing.T, w http.ResponseWriter, status int, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encoding response: %v", err)
	}
}

// writeDeny answers with the contract's 401, which is the ONLY response the
// bastion may treat as a deny decision.
func writeDeny(t *testing.T, w http.ResponseWriter, code, message string) {
	t.Helper()
	body := map[string]any{"error": map[string]string{"code": code, "message": message}}
	writeJSON(t, w, http.StatusUnauthorized, body)
}

// fakeClient is a mgmt.Client whose auth calls are supplied per test, for the
// failure modes an httptest server cannot produce conveniently (a dead
// connection, a response that violates the contract).
//
// The embedded interface is nil: a test that calls a method it did not set
// panics, which is louder and more useful than a silent zero value.
type fakeClient struct {
	mgmt.Client
	certFn     func(context.Context, *mgmt.AuthenticateCertRequest) (*mgmt.AuthenticateResponse, error)
	passwordFn func(context.Context, *mgmt.AuthenticatePasswordRequest) (*mgmt.AuthenticateResponse, error)
	pollFn     func(context.Context, *mgmt.MFAPollRequest) (*mgmt.AuthenticateResponse, error)
}

func (c *fakeClient) AuthenticateCert(ctx context.Context, req *mgmt.AuthenticateCertRequest) (*mgmt.AuthenticateResponse, error) {
	return c.certFn(ctx, req)
}

func (c *fakeClient) AuthenticatePassword(ctx context.Context, req *mgmt.AuthenticatePasswordRequest) (*mgmt.AuthenticateResponse, error) {
	return c.passwordFn(ctx, req)
}

func (c *fakeClient) PollMFA(ctx context.Context, req *mgmt.MFAPollRequest) (*mgmt.AuthenticateResponse, error) {
	return c.pollFn(ctx, req)
}

// transportError is what the client returns when it never reached the server:
// the "unknown decision" half of the error contract.
func transportError(op string) error {
	return &mgmt.APIError{Op: op, Cause: mgmt.ErrTransport}
}

// denyError is a deny decision as the client reports it.
func denyError(op string) error {
	return &mgmt.APIError{Op: op, StatusCode: http.StatusUnauthorized, Cause: mgmt.ErrUnauthorized}
}

// testLogger returns a logger and the buffer it writes to.
func testLogger() (*log.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return log.New(&buf, "", 0), &buf
}

// aliceIdentity is the authenticated identity the test servers return.
func aliceIdentity() *mgmt.Identity {
	return &mgmt.Identity{
		Subject:     "alice@example.com",
		Login:       "alice",
		DisplayName: "Alice Example",
		Source:      "fixture",
		Principals:  []string{"alice"},
		Groups:      []string{"engineering", "sre"},
		Claims:      map[string]string{"dept": "platform"},
	}
}

// recordingPrompter captures everything the user was told during an MFA wait.
type recordingPrompter struct {
	mu          sync.Mutex
	challenges  []string
	waits       []string
	err         error
	waitCounter int
}

func (p *recordingPrompter) Challenge(instruction string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.challenges = append(p.challenges, instruction)
	return p.err
}

func (p *recordingPrompter) Waiting(instruction string, _ time.Duration) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.waits = append(p.waits, instruction)
	p.waitCounter++
	return p.err
}

func (p *recordingPrompter) snapshot() (challenges, waits []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.challenges...), append([]string(nil), p.waits...)
}

// fastMFA polls and reports progress quickly, so a test that exercises the wait
// does not spend real seconds in it.
func fastMFA() PasswordMFAOptions {
	return PasswordMFAOptions{
		MinPollInterval:  time.Millisecond,
		ProgressInterval: time.Millisecond,
		MaxWait:          5 * time.Second,
	}
}
