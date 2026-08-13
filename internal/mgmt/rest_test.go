// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package mgmt

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testConn is the connection metadata every request in these tests carries.
func testConn() ConnMeta {
	return ConnMeta{
		SessionID:  "session-1",
		BastionID:  "bastion-test",
		ClientAddr: "203.0.113.7:52344",
		Timestamp:  time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC),
	}
}

// newTestClient starts an httptest server running h and returns a client for it.
func newTestClient(t *testing.T, h http.HandlerFunc) *RESTClient {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	c, err := NewRESTClient(Options{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewRESTClient: %v", err)
	}
	return c
}

// respondJSON writes status and body as the handler's whole response.
func respondJSON(t *testing.T, w http.ResponseWriter, status int, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

// denyBody is the contract's error envelope for a deny.
const denyBody = `{"error":{"code":"unauthorized","message":"denied by policy"}}`

func TestNewRESTClientRejectsBadOptions(t *testing.T) {
	tests := []struct {
		name string
		opts Options
	}{
		{name: "no base url", opts: Options{}},
		{name: "not a url", opts: Options{BaseURL: "://nope"}},
		{name: "wrong scheme", opts: Options{BaseURL: "ftp://mgmt.example.com"}},
		{name: "no host", opts: Options{BaseURL: "https://"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewRESTClient(tc.opts); err == nil {
				t.Fatal("NewRESTClient accepted invalid options")
			}
		})
	}
}

func TestAuthenticateCertSuccessSendsContractRequest(t *testing.T) {
	var gotPath, gotAuth, gotContentType string
	var gotBody AuthenticateCertRequest

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request: %v", err)
		}
		respondJSON(t, w, http.StatusOK, AuthenticateResponse{
			Status:   AuthStatusAuthenticated,
			Identity: &Identity{Subject: "alice@example.com", Login: "alice", Source: "fixture"},
		})
	})

	resp, err := c.AuthenticateCert(context.Background(), &AuthenticateCertRequest{
		Login:     "alice",
		Target:    "host.company.com",
		PublicKey: PublicKeyMaterial{Type: "ssh-ed25519", Blob: []byte{1, 2, 3}, Fingerprint: "SHA256:abc"},
		Conn:      testConn(),
	})
	if err != nil {
		t.Fatalf("AuthenticateCert: %v", err)
	}

	if gotPath != PathAuthenticateCert {
		t.Errorf("path = %q, want %q", gotPath, PathAuthenticateCert)
	}
	if want := "Bearer test-token"; gotAuth != want {
		t.Errorf("Authorization = %q, want %q", gotAuth, want)
	}
	if want := "application/json"; gotContentType != want {
		t.Errorf("Content-Type = %q, want %q", gotContentType, want)
	}
	if gotBody.PublicKey.Fingerprint != "SHA256:abc" {
		t.Errorf("fingerprint = %q, want %q", gotBody.PublicKey.Fingerprint, "SHA256:abc")
	}
	if string(gotBody.PublicKey.Blob) != "\x01\x02\x03" {
		t.Errorf("blob round-trip = %q, want the original bytes", gotBody.PublicKey.Blob)
	}
	if gotBody.Conn.SessionID != "session-1" {
		t.Errorf("conn.session_id = %q, want %q", gotBody.Conn.SessionID, "session-1")
	}
	if resp.Identity.Subject != "alice@example.com" {
		t.Errorf("subject = %q, want %q", resp.Identity.Subject, "alice@example.com")
	}
}

func TestDenyIsDistinctFromFailure(t *testing.T) {
	// A deny must be recognisable as a decision, and every other failure must
	// NOT look like one, or a caller could fail open.
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    error
		notWant error
	}{
		{
			name: "401 is a deny",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, denyBody)
			},
			want: ErrUnauthorized,
		},
		{
			name: "500 is a server error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			want:    ErrServer,
			notWant: ErrUnauthorized,
		},
		{
			name: "403 is a bad request",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			},
			want:    ErrBadRequest,
			notWant: ErrUnauthorized,
		},
		{
			name: "undecodable body is a protocol error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, "{not json")
			},
			want:    ErrProtocol,
			notWant: ErrUnauthorized,
		},
		{
			name: "unexpected 2xx is a protocol error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			},
			want:    ErrProtocol,
			notWant: ErrUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient(t, tc.handler)
			_, err := c.Authorize(context.Background(), &AuthorizeRequest{
				Identity: &Identity{Subject: "alice@example.com", Login: "alice"},
				Target:   "host.company.com",
				Conn:     testConn(),
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want one wrapping %v", err, tc.want)
			}
			if tc.notWant != nil && errors.Is(err, tc.notWant) {
				t.Fatalf("error = %v, must not wrap %v", err, tc.notWant)
			}
			if got, want := IsUnauthorized(err), errors.Is(err, ErrUnauthorized); got != want {
				t.Fatalf("IsUnauthorized = %v, want %v", got, want)
			}

			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("error %v is not an *APIError", err)
			}
			if apiErr.Op != "Authorize" {
				t.Errorf("APIError.Op = %q, want %q", apiErr.Op, "Authorize")
			}
		})
	}
}

func TestDenyCarriesServerErrorEnvelope(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, denyBody)
	})

	_, err := c.AuthenticatePassword(context.Background(), &AuthenticatePasswordRequest{
		Login: "alice", Password: "hunter2", Conn: testConn(),
	})

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error %v is not an *APIError", err)
	}
	if apiErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, http.StatusUnauthorized)
	}
	if apiErr.Code != "unauthorized" || apiErr.Message != "denied by policy" {
		t.Errorf("Code/Message = %q/%q, want %q/%q", apiErr.Code, apiErr.Message, "unauthorized", "denied by policy")
	}
	if strings.Contains(apiErr.Error(), "hunter2") {
		t.Error("error string leaked the password")
	}
}

func TestTransportFailureIsNotADeny(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	c, err := NewRESTClient(Options{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("NewRESTClient: %v", err)
	}
	srv.Close() // nothing is listening any more

	_, err = c.Authorize(context.Background(), &AuthorizeRequest{
		Identity: &Identity{Subject: "alice@example.com", Login: "alice"},
		Target:   "host.company.com",
		Conn:     testConn(),
	})
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("error = %v, want one wrapping ErrTransport", err)
	}
	if IsUnauthorized(err) {
		t.Fatal("an unreachable server must never look like a deny")
	}
}

// newBlockingTestClient returns a client for a server whose handler never
// responds until the test ends. The handler waits on a channel rather than on
// the request context: the server only notices a client disconnect once the
// request body has been read, which these handlers deliberately never do.
func newBlockingTestClient(t *testing.T, opts Options) *RESTClient {
	t.Helper()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})

	opts.BaseURL = srv.URL
	c, err := NewRESTClient(opts)
	if err != nil {
		t.Fatalf("NewRESTClient: %v", err)
	}
	return c
}

func TestCancelledContextIsATransportError(t *testing.T) {
	c := newBlockingTestClient(t, Options{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := c.ReportHostKey(ctx, &HostKeyReportRequest{
		Target:  "host.company.com",
		HostKey: PublicKeyMaterial{Type: "ssh-ed25519", Fingerprint: "SHA256:abc"},
		Conn:    testConn(),
	})
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("error = %v, want one wrapping ErrTransport", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want the context cause preserved", err)
	}
}

func TestTimeoutBoundsTheCall(t *testing.T) {
	c := newBlockingTestClient(t, Options{Timeout: 50 * time.Millisecond})

	start := time.Now()
	_, err := c.Authorize(context.Background(), &AuthorizeRequest{
		Identity: &Identity{Subject: "alice@example.com", Login: "alice"},
		Target:   "host.company.com",
		Conn:     testConn(),
	})
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("error = %v, want one wrapping ErrTransport", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want the deadline cause preserved so callers can retry on timeouts", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("call took %v; the client timeout did not apply", elapsed)
	}
}

func TestAuthenticateRejectsResponsesThatViolateTheContract(t *testing.T) {
	tests := []struct {
		name string
		body AuthenticateResponse
		call func(*RESTClient) error
	}{
		{
			name: "authenticated without identity",
			body: AuthenticateResponse{Status: AuthStatusAuthenticated},
			call: func(c *RESTClient) error {
				_, err := c.AuthenticateCert(context.Background(), &AuthenticateCertRequest{Login: "alice", Conn: testConn()})
				return err
			},
		},
		{
			name: "identity without subject",
			body: AuthenticateResponse{Status: AuthStatusAuthenticated, Identity: &Identity{Login: "alice"}},
			call: func(c *RESTClient) error {
				_, err := c.AuthenticateCert(context.Background(), &AuthenticateCertRequest{Login: "alice", Conn: testConn()})
				return err
			},
		},
		{
			name: "unknown status",
			body: AuthenticateResponse{Status: "maybe"},
			call: func(c *RESTClient) error {
				_, err := c.AuthenticatePassword(context.Background(), &AuthenticatePasswordRequest{Login: "alice", Conn: testConn()})
				return err
			},
		},
		{
			name: "mfa required without a token",
			body: AuthenticateResponse{Status: AuthStatusMFARequired, MFA: &MFAChallenge{}},
			call: func(c *RESTClient) error {
				_, err := c.PollMFA(context.Background(), &MFAPollRequest{Token: "mfa-1", Conn: testConn()})
				return err
			},
		},
		{
			name: "cert auth may not ask for mfa",
			body: AuthenticateResponse{Status: AuthStatusMFARequired, MFA: &MFAChallenge{Token: "mfa-1"}},
			call: func(c *RESTClient) error {
				_, err := c.AuthenticateCert(context.Background(), &AuthenticateCertRequest{Login: "alice", Conn: testConn()})
				return err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				respondJSON(t, w, http.StatusOK, tc.body)
			})
			if err := tc.call(c); !errors.Is(err, ErrProtocol) {
				t.Fatalf("error = %v, want one wrapping ErrProtocol", err)
			}
		})
	}
}

func TestAuthorizeRejectsUnknownEnumValues(t *testing.T) {
	valid := AuthorizeResponse{
		RouteType:         RouteTypeDirect,
		Target:            "host.company.com",
		PermittedChannels: []string{"session"},
		FilterPolicy:      FilterPolicy{Mode: FilterModeBlacklist, Action: FilterActionAllowAndLog},
	}

	tests := []struct {
		name  string
		patch func(*AuthorizeResponse)
	}{
		{name: "route type", patch: func(r *AuthorizeResponse) { r.RouteType = "teleport" }},
		{name: "missing target", patch: func(r *AuthorizeResponse) { r.Target = "" }},
		{name: "filter mode", patch: func(r *AuthorizeResponse) { r.FilterPolicy.Mode = "greylist" }},
		{name: "filter action", patch: func(r *AuthorizeResponse) { r.FilterPolicy.Action = "shrug" }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := valid
			tc.patch(&body)
			c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				respondJSON(t, w, http.StatusOK, body)
			})
			_, err := c.Authorize(context.Background(), &AuthorizeRequest{
				Identity: &Identity{Subject: "alice@example.com", Login: "alice"},
				Target:   "host.company.com",
				Conn:     testConn(),
			})
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("error = %v, want one wrapping ErrProtocol", err)
			}
		})
	}
}

func TestAuthorizeAcceptsANextHopRoute(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		respondJSON(t, w, http.StatusOK, AuthorizeResponse{
			RouteType:         RouteTypeNextHop,
			Target:            "bastion-2.company.com",
			PermittedChannels: []string{"session"},
			FilterPolicy:      FilterPolicy{Mode: FilterModeWhitelist, Action: FilterActionKillSession},
			Hop: &HopMetadata{
				FinalTarget: "deep.internal.company.com",
				MaxHops:     3,
				HopTrail:    []string{"bastion-1"},
			},
		})
	})

	resp, err := c.Authorize(context.Background(), &AuthorizeRequest{
		Identity: &Identity{Subject: "alice@example.com", Login: "alice"},
		Target:   "deep.internal.company.com",
		Conn:     testConn(),
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if resp.Hop == nil || resp.Hop.FinalTarget != "deep.internal.company.com" {
		t.Fatalf("hop metadata = %+v, want the final target preserved", resp.Hop)
	}
	if got, want := resp.Hop.HopTrail, []string{"bastion-1"}; len(got) != len(want) || got[0] != want[0] {
		t.Errorf("hop trail = %v, want %v", got, want)
	}
}

func TestIngestLogBatchExpects202(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PathIngestLogBatch {
			t.Errorf("path = %q, want %q", r.URL.Path, PathIngestLogBatch)
		}
		respondJSON(t, w, http.StatusAccepted, LogBatchResponse{Accepted: 2})
	})

	resp, err := c.IngestLogBatch(context.Background(), &LogBatchRequest{Records: []LogRecord{
		{RecordID: "r1", SessionID: "session-1", Kind: LogKindSessionStart, Severity: SeverityInfo},
		{RecordID: "r2", SessionID: "session-1", Kind: LogKindCommand, Severity: SeverityInfo},
	}})
	if err != nil {
		t.Fatalf("IngestLogBatch: %v", err)
	}
	if resp.Accepted != 2 {
		t.Errorf("accepted = %d, want 2", resp.Accepted)
	}
}

func TestIngestLogBatchRejectsAnEmptyBatchLocally(t *testing.T) {
	c := newTestClient(t, func(http.ResponseWriter, *http.Request) {
		t.Error("an empty batch must not reach the server")
	})
	if _, err := c.IngestLogBatch(context.Background(), &LogBatchRequest{}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("error = %v, want one wrapping ErrBadRequest", err)
	}
}

func TestIngestPriorityLogRequiresAcceptance(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		respondJSON(t, w, http.StatusOK, LogPriorityResponse{Accepted: false})
	})
	_, err := c.IngestPriorityLog(context.Background(), &LogPriorityRequest{Record: LogRecord{
		RecordID: "r1", SessionID: "session-1", Kind: LogKindPolicyDecision, Severity: SeverityCritical,
	}})
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("error = %v, want one wrapping ErrProtocol", err)
	}
}

func TestReportHostKeyRejectsAnUnknownDecision(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		respondJSON(t, w, http.StatusOK, HostKeyReportResponse{Decision: "maybe"})
	})
	_, err := c.ReportHostKey(context.Background(), &HostKeyReportRequest{
		Target:  "host.company.com",
		HostKey: PublicKeyMaterial{Type: "ssh-ed25519", Fingerprint: "SHA256:abc"},
		Conn:    testConn(),
	})
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("error = %v, want one wrapping ErrProtocol", err)
	}
}

func TestBaseURLPathPrefixIsPreserved(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		respondJSON(t, w, http.StatusOK, HostKeyReportResponse{Decision: HostKeyAccept, Known: true})
	}))
	t.Cleanup(srv.Close)

	// A trailing slash on the base URL must not double up in the request path.
	c, err := NewRESTClient(Options{BaseURL: srv.URL + "/mgmt/"})
	if err != nil {
		t.Fatalf("NewRESTClient: %v", err)
	}
	if _, err := c.ReportHostKey(context.Background(), &HostKeyReportRequest{
		Target:  "host.company.com",
		HostKey: PublicKeyMaterial{Fingerprint: "SHA256:abc"},
		Conn:    testConn(),
	}); err != nil {
		t.Fatalf("ReportHostKey: %v", err)
	}
	if want := "/mgmt" + PathReportHostKey; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
}

func TestNoAuthorizationHeaderWithoutAToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization = %q, want it unset", got)
		}
		respondJSON(t, w, http.StatusOK, HostKeyReportResponse{Decision: HostKeyAccept})
	}))
	t.Cleanup(srv.Close)

	c, err := NewRESTClient(Options{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("NewRESTClient: %v", err)
	}
	if _, err := c.ReportHostKey(context.Background(), &HostKeyReportRequest{
		Target:  "host.company.com",
		HostKey: PublicKeyMaterial{Fingerprint: "SHA256:abc"},
		Conn:    testConn(),
	}); err != nil {
		t.Fatalf("ReportHostKey: %v", err)
	}
}
