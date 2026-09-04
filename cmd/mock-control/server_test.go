// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// exampleFixturesPath is the fixture file that ships with the mock; it must
// always be valid and is what the e2e topology starts from.
const exampleFixturesPath = "fixtures.example.yaml"

// Credentials from fixtures.example.yaml.
const (
	proxyToken     = "dev-proxy-token"
	aliceKeyFP     = "SHA256:AAAA1111alice1111AAAA1111alice1111AAAA111111"
	alicePassword  = "alice-dev-password"
	knownHostKeyFP = "SHA256:CCCC3333hostkey3333CCCC3333hostkey3333CCCC"
)

// mock is a running mock server plus a client wired to it, so the tests drive
// the contract exactly as the proxy will.
type mock struct {
	srv    *httptest.Server
	client *control.RESTClient
	server *server
}

// startMock serves fx (or the shipped example fixtures when fx is nil).
func startMock(t *testing.T, fx *fixtures, opts serverOptions) *mock {
	t.Helper()
	if fx == nil {
		var err error
		fx, err = loadFixtures(exampleFixturesPath)
		if err != nil {
			t.Fatalf("loadFixtures(%s): %v", exampleFixturesPath, err)
		}
	}

	s := newServer(fx, opts)
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)

	client, err := control.NewRESTClient(control.Options{BaseURL: srv.URL, Token: fx.ProxyToken})
	if err != nil {
		t.Fatalf("NewRESTClient: %v", err)
	}
	return &mock{srv: srv, client: client, server: s}
}

func testConn() control.ConnMeta {
	return control.ConnMeta{
		SessionID:  "session-1",
		ProxyID:    "proxy-1",
		ClientAddr: "203.0.113.7:52344",
		Timestamp:  time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC),
	}
}

func TestExampleFixturesAreValid(t *testing.T) {
	fx, err := loadFixtures(exampleFixturesPath)
	if err != nil {
		t.Fatalf("loadFixtures(%s): %v", exampleFixturesPath, err)
	}
	if len(fx.Users) == 0 || len(fx.Routes) == 0 {
		t.Fatalf("example fixtures define %d users and %d routes; both must be non-empty",
			len(fx.Users), len(fx.Routes))
	}
	if fx.ProxyToken != proxyToken {
		t.Errorf("proxy_token = %q, want %q", fx.ProxyToken, proxyToken)
	}
}

func TestCertAuth(t *testing.T) {
	m := startMock(t, nil, serverOptions{})
	ctx := context.Background()

	t.Run("known key authenticates", func(t *testing.T) {
		resp, err := m.client.AuthenticateCert(ctx, &control.AuthenticateCertRequest{
			Login:     "alice",
			Target:    "host.company.com",
			PublicKey: control.PublicKeyMaterial{Type: "ssh-ed25519", Fingerprint: aliceKeyFP},
			Conn:      testConn(),
		})
		if err != nil {
			t.Fatalf("AuthenticateCert: %v", err)
		}
		if resp.Status != control.AuthStatusAuthenticated {
			t.Fatalf("status = %q, want %q", resp.Status, control.AuthStatusAuthenticated)
		}
		if got, want := resp.Identity.Subject, "alice@example.com"; got != want {
			t.Errorf("subject = %q, want %q", got, want)
		}
		if got, want := resp.Identity.Login, "alice"; got != want {
			t.Errorf("login = %q, want %q", got, want)
		}
		if len(resp.Identity.Groups) != 2 {
			t.Errorf("groups = %v, want the two from the fixture", resp.Identity.Groups)
		}
		if got := resp.Identity.Claims["department"]; got != "platform" {
			t.Errorf("claims[department] = %q, want %q", got, "platform")
		}
	})

	t.Run("unknown key is denied", func(t *testing.T) {
		_, err := m.client.AuthenticateCert(ctx, &control.AuthenticateCertRequest{
			Login:     "alice",
			PublicKey: control.PublicKeyMaterial{Type: "ssh-ed25519", Fingerprint: "SHA256:not-alices-key"},
			Conn:      testConn(),
		})
		if !control.IsUnauthorized(err) {
			t.Fatalf("error = %v, want a deny", err)
		}
	})

	t.Run("unknown login is denied", func(t *testing.T) {
		_, err := m.client.AuthenticateCert(ctx, &control.AuthenticateCertRequest{
			Login:     "nobody",
			PublicKey: control.PublicKeyMaterial{Type: "ssh-ed25519", Fingerprint: aliceKeyFP},
			Conn:      testConn(),
		})
		if !control.IsUnauthorized(err) {
			t.Fatalf("error = %v, want a deny", err)
		}
	})

	t.Run("password-only user cannot use a key", func(t *testing.T) {
		_, err := m.client.AuthenticateCert(ctx, &control.AuthenticateCertRequest{
			Login:     "mallory",
			PublicKey: control.PublicKeyMaterial{Type: "ssh-ed25519", Fingerprint: aliceKeyFP},
			Conn:      testConn(),
		})
		if !control.IsUnauthorized(err) {
			t.Fatalf("error = %v, want a deny", err)
		}
	})
}

func TestPasswordAuthWithMFAApproval(t *testing.T) {
	m := startMock(t, nil, serverOptions{})
	ctx := context.Background()

	resp, err := m.client.AuthenticatePassword(ctx, &control.AuthenticatePasswordRequest{
		Login:    "alice",
		Password: alicePassword,
		Conn:     testConn(),
	})
	if err != nil {
		t.Fatalf("AuthenticatePassword: %v", err)
	}
	if resp.Status != control.AuthStatusMFARequired {
		t.Fatalf("status = %q, want %q", resp.Status, control.AuthStatusMFARequired)
	}
	if resp.MFA.Token == "" {
		t.Fatal("challenge has no token")
	}
	if resp.MFA.PollAfter() <= 0 {
		t.Errorf("poll interval = %v, want a positive hint", resp.MFA.PollAfter())
	}

	// The fixture keeps the challenge pending for exactly one poll.
	pending, err := m.client.PollMFA(ctx, &control.MFAPollRequest{Token: resp.MFA.Token, Conn: testConn()})
	if err != nil {
		t.Fatalf("PollMFA (pending): %v", err)
	}
	if pending.Status != control.AuthStatusMFARequired {
		t.Fatalf("status = %q, want the challenge still pending", pending.Status)
	}

	approved, err := m.client.PollMFA(ctx, &control.MFAPollRequest{Token: resp.MFA.Token, Conn: testConn()})
	if err != nil {
		t.Fatalf("PollMFA (approve): %v", err)
	}
	if approved.Status != control.AuthStatusAuthenticated {
		t.Fatalf("status = %q, want %q", approved.Status, control.AuthStatusAuthenticated)
	}
	if got, want := approved.Identity.Subject, "alice@example.com"; got != want {
		t.Errorf("subject = %q, want %q", got, want)
	}

	// The token is single-use: polling a resolved challenge is a deny.
	if _, err := m.client.PollMFA(ctx, &control.MFAPollRequest{Token: resp.MFA.Token, Conn: testConn()}); !control.IsUnauthorized(err) {
		t.Fatalf("error = %v, want a deny for a spent token", err)
	}
}

func TestPasswordAuthDenials(t *testing.T) {
	m := startMock(t, nil, serverOptions{})
	ctx := context.Background()

	t.Run("wrong password", func(t *testing.T) {
		_, err := m.client.AuthenticatePassword(ctx, &control.AuthenticatePasswordRequest{
			Login: "alice", Password: "wrong", Conn: testConn(),
		})
		if !control.IsUnauthorized(err) {
			t.Fatalf("error = %v, want a deny", err)
		}
	})

	t.Run("key-only user has no password", func(t *testing.T) {
		_, err := m.client.AuthenticatePassword(ctx, &control.AuthenticatePasswordRequest{
			Login: "svc-deploy", Password: "", Conn: testConn(),
		})
		if !control.IsUnauthorized(err) {
			t.Fatalf("error = %v, want a deny", err)
		}
	})

	t.Run("mfa denied", func(t *testing.T) {
		resp, err := m.client.AuthenticatePassword(ctx, &control.AuthenticatePasswordRequest{
			Login: "mallory", Password: "mallory-dev-password", Conn: testConn(),
		})
		if err != nil {
			t.Fatalf("AuthenticatePassword: %v", err)
		}
		if resp.Status != control.AuthStatusMFARequired {
			t.Fatalf("status = %q, want %q", resp.Status, control.AuthStatusMFARequired)
		}
		_, err = m.client.PollMFA(ctx, &control.MFAPollRequest{Token: resp.MFA.Token, Conn: testConn()})
		if !control.IsUnauthorized(err) {
			t.Fatalf("error = %v, want a deny once MFA is refused", err)
		}
	})

	t.Run("unknown token", func(t *testing.T) {
		_, err := m.client.PollMFA(ctx, &control.MFAPollRequest{Token: "mfa-does-not-exist", Conn: testConn()})
		if !control.IsUnauthorized(err) {
			t.Fatalf("error = %v, want a deny", err)
		}
	})
}

func TestMFAChallengeExpires(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	fx := mustParseFixtures(t, `
users:
  - login: alice
    password: "pw"
    mfa:
      required: true
      decision: approve
      pending_polls: 5
      ttl_ms: 1000
`)
	m := startMock(t, fx, serverOptions{Now: func() time.Time { return now }})
	ctx := context.Background()

	resp, err := m.client.AuthenticatePassword(ctx, &control.AuthenticatePasswordRequest{
		Login: "alice", Password: "pw", Conn: testConn(),
	})
	if err != nil {
		t.Fatalf("AuthenticatePassword: %v", err)
	}

	now = now.Add(2 * time.Second) // past the 1s TTL
	if _, err := m.client.PollMFA(ctx, &control.MFAPollRequest{Token: resp.MFA.Token, Conn: testConn()}); !control.IsUnauthorized(err) {
		t.Fatalf("error = %v, want a deny for an expired challenge", err)
	}
}

func TestAuthorize(t *testing.T) {
	m := startMock(t, nil, serverOptions{})
	ctx := context.Background()
	alice := &control.Identity{Subject: "alice@example.com", Login: "alice", Source: "fixture"}

	t.Run("direct route carries the full policy", func(t *testing.T) {
		resp, err := m.client.Authorize(ctx, &control.AuthorizeRequest{
			Identity: alice, Target: "host.company.com", AuthMethod: control.AuthMethodCert, Conn: testConn(),
		})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		if resp.RouteType != control.RouteTypeDirect {
			t.Errorf("route_type = %q, want %q", resp.RouteType, control.RouteTypeDirect)
		}
		if resp.Target != "host.company.com" {
			t.Errorf("target = %q, want the requested host", resp.Target)
		}
		if resp.TargetPort != 22 {
			t.Errorf("target_port = %d, want 22", resp.TargetPort)
		}
		if resp.Permissions != "readOnlyGroup" {
			t.Errorf("permissions = %q, want %q", resp.Permissions, "readOnlyGroup")
		}
		if len(resp.PermittedChannels) != 1 || resp.PermittedChannels[0] != "session" {
			t.Errorf("permitted_channels = %v, want [session]", resp.PermittedChannels)
		}
		if resp.FilterPolicy.Mode != control.FilterModeBlacklist {
			t.Errorf("filter mode = %q, want %q", resp.FilterPolicy.Mode, control.FilterModeBlacklist)
		}
		// The whole point of per-rule actions: one policy, three severities, in
		// the fixture's order.
		wantRules := []control.FilterRule{
			{Match: "rm -rf /", Action: control.FilterActionKillSession},
			{Match: "shutdown", Action: control.FilterActionBlockCommand},
			{Match: "sudo *", Action: control.FilterActionWarnAndContinue},
		}
		if len(resp.FilterPolicy.Rules) != len(wantRules) {
			t.Fatalf("filter rules = %+v, want %d rules", resp.FilterPolicy.Rules, len(wantRules))
		}
		for i, want := range wantRules {
			got := resp.FilterPolicy.Rules[i]
			if got.Match != want.Match || got.Action != want.Action {
				t.Errorf("rule %d = %s→%s, want %s→%s (order is significant: first match wins)",
					i, got.Match, got.Action, want.Match, want.Action)
			}
			if got.Message == "" {
				t.Errorf("rule %d (%s) lost its operator message", i, got.Match)
			}
		}
		if resp.Hop != nil {
			t.Errorf("hop = %+v, want none on a direct route", resp.Hop)
		}
		if resp.DecisionID == "" {
			t.Error("decision_id is empty; audit correlation needs it")
		}
	})

	t.Run("nexthop route returns the next proxy and keeps the final target", func(t *testing.T) {
		conn := testConn()
		conn.HopTrail = []string{"proxy-0"}
		resp, err := m.client.Authorize(ctx, &control.AuthorizeRequest{
			Identity: alice, Target: "deep.internal.company.com", Conn: conn,
		})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		if resp.RouteType != control.RouteTypeNextHop {
			t.Fatalf("route_type = %q, want %q", resp.RouteType, control.RouteTypeNextHop)
		}
		if resp.Target != "proxy-2.company.com" {
			t.Errorf("target = %q, want the next proxy", resp.Target)
		}
		if resp.Hop == nil {
			t.Fatal("hop metadata is missing on a nexthop route")
		}
		if resp.Hop.FinalTarget != "deep.internal.company.com" {
			t.Errorf("final_target = %q, want the host the user asked for", resp.Hop.FinalTarget)
		}
		if resp.Hop.MaxHops != 3 {
			t.Errorf("max_hops = %d, want 3", resp.Hop.MaxHops)
		}
		want := []string{"proxy-0", "proxy-1"}
		if len(resp.Hop.HopTrail) != len(want) {
			t.Fatalf("hop_trail = %v, want %v", resp.Hop.HopTrail, want)
		}
		for i := range want {
			if resp.Hop.HopTrail[i] != want[i] {
				t.Fatalf("hop_trail = %v, want %v (this proxy appended)", resp.Hop.HopTrail, want)
			}
		}
	})

	t.Run("wildcard target route matches any host", func(t *testing.T) {
		svc := &control.Identity{Subject: "svc-deploy@example.com", Login: "svc-deploy", Source: "fixture"}
		resp, err := m.client.Authorize(ctx, &control.AuthorizeRequest{
			Identity: svc, Target: "anything.company.com", Conn: testConn(),
		})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		if resp.FilterPolicy.Mode != control.FilterModeWhitelist {
			t.Errorf("filter mode = %q, want %q", resp.FilterPolicy.Mode, control.FilterModeWhitelist)
		}
		if len(resp.FilterPolicy.Rules) != 3 {
			t.Fatalf("filter rules = %+v, want the three from the fixture", resp.FilterPolicy.Rules)
		}
		if last := resp.FilterPolicy.Rules[2]; last.Action != control.FilterActionKillSession {
			t.Errorf("last rule action = %q, want a whitelist that still escalates on %q",
				last.Action, last.Match)
		}
		if len(resp.PermittedChannels) != 2 {
			t.Errorf("permitted_channels = %v, want session and direct-tcpip", resp.PermittedChannels)
		}
	})

	t.Run("unmatched target is denied", func(t *testing.T) {
		_, err := m.client.Authorize(ctx, &control.AuthorizeRequest{
			Identity: alice, Target: "forbidden.company.com", Conn: testConn(),
		})
		if !control.IsUnauthorized(err) {
			t.Fatalf("error = %v, want a deny", err)
		}
	})

	t.Run("unknown identity is denied", func(t *testing.T) {
		_, err := m.client.Authorize(ctx, &control.AuthorizeRequest{
			Identity: &control.Identity{Subject: "eve@example.com", Login: "eve"},
			Target:   "host.company.com",
			Conn:     testConn(),
		})
		if !control.IsUnauthorized(err) {
			t.Fatalf("error = %v, want a deny", err)
		}
	})
}

func TestAuthorizeDeniesEveryChannelWhenTheAllowListIsEmpty(t *testing.T) {
	fx := mustParseFixtures(t, `
users:
  - login: alice
    password: "pw"
routes:
  - login: alice
    target: "*"
    route_type: direct
`)
	m := startMock(t, fx, serverOptions{})

	resp, err := m.client.Authorize(context.Background(), &control.AuthorizeRequest{
		Identity: &control.Identity{Subject: "alice", Login: "alice"},
		Target:   "host.company.com",
		Conn:     testConn(),
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if resp.PermittedChannels == nil {
		t.Fatal("permitted_channels decoded as nil; an absent allow-list must serialise as [] (deny all)")
	}
	if len(resp.PermittedChannels) != 0 {
		t.Errorf("permitted_channels = %v, want empty", resp.PermittedChannels)
	}
}

func TestReportHostKeyTrustsOnFirstUse(t *testing.T) {
	m := startMock(t, nil, serverOptions{})
	ctx := context.Background()

	report := func(target, fp string) *control.HostKeyReportResponse {
		t.Helper()
		resp, err := m.client.ReportHostKey(ctx, &control.HostKeyReportRequest{
			Target:  target,
			HostKey: control.PublicKeyMaterial{Type: "ssh-ed25519", Fingerprint: fp},
			Conn:    testConn(),
		})
		if err != nil {
			t.Fatalf("ReportHostKey: %v", err)
		}
		return resp
	}

	first := report("new.company.com", "SHA256:brand-new-key")
	if first.Known {
		t.Error("a key never seen before must report known=false")
	}
	if first.Decision != control.HostKeyAccept {
		t.Errorf("decision = %q, want %q (trust on first use)", first.Decision, control.HostKeyAccept)
	}

	second := report("new.company.com", "SHA256:brand-new-key")
	if !second.Known {
		t.Error("the second sighting of a key must report known=true")
	}

	seeded := report("host.company.com", knownHostKeyFP)
	if !seeded.Known {
		t.Error("a fixture-seeded key must report known=true on first report")
	}

	// A different key for a host we already know is still a first sighting.
	rotated := report("host.company.com", "SHA256:rotated-key")
	if rotated.Known {
		t.Error("a new key for a known host must report known=false")
	}
}

func TestReportHostKeyCanRejectUnknownKeys(t *testing.T) {
	fx := mustParseFixtures(t, `
users:
  - login: alice
    password: "pw"
host_keys:
  decision: reject
  known:
    - target: host.company.com
      fingerprint: "SHA256:trusted"
`)
	m := startMock(t, fx, serverOptions{})
	ctx := context.Background()

	unknown, err := m.client.ReportHostKey(ctx, &control.HostKeyReportRequest{
		Target:  "host.company.com",
		HostKey: control.PublicKeyMaterial{Fingerprint: "SHA256:unknown"},
		Conn:    testConn(),
	})
	if err != nil {
		t.Fatalf("ReportHostKey: %v", err)
	}
	if unknown.Decision != control.HostKeyReject {
		t.Errorf("decision = %q, want %q under a rejecting policy", unknown.Decision, control.HostKeyReject)
	}

	trusted, err := m.client.ReportHostKey(ctx, &control.HostKeyReportRequest{
		Target:  "host.company.com",
		HostKey: control.PublicKeyMaterial{Fingerprint: "SHA256:trusted"},
		Conn:    testConn(),
	})
	if err != nil {
		t.Fatalf("ReportHostKey: %v", err)
	}
	if trusted.Decision != control.HostKeyAccept || !trusted.Known {
		t.Errorf("decision/known = %q/%v, want an already-trusted key accepted", trusted.Decision, trusted.Known)
	}
}

func TestLogIngest(t *testing.T) {
	logDir := t.TempDir()
	m := startMock(t, nil, serverOptions{LogDir: logDir})
	ctx := context.Background()

	batch := &control.LogBatchRequest{Records: []control.LogRecord{
		{
			RecordID: "r1", SessionID: "session-1", Timestamp: testConn().Timestamp,
			Kind: control.LogKindSessionStart, Severity: control.SeverityInfo, Login: "alice",
		},
		{
			RecordID: "r2", SessionID: "session-1", Timestamp: testConn().Timestamp,
			Kind: control.LogKindCommand, Severity: control.SeverityInfo,
			Attributes: map[string]string{"command": "uptime"},
		},
	}}

	resp, err := m.client.IngestLogBatch(ctx, batch)
	if err != nil {
		t.Fatalf("IngestLogBatch: %v", err)
	}
	if resp.Accepted != 2 {
		t.Fatalf("accepted = %d, want 2", resp.Accepted)
	}

	// A retried batch must be de-duplicated by record id, not stored twice.
	retry, err := m.client.IngestLogBatch(ctx, batch)
	if err != nil {
		t.Fatalf("IngestLogBatch (retry): %v", err)
	}
	if retry.Accepted != 0 {
		t.Errorf("accepted = %d on a retried batch, want 0", retry.Accepted)
	}

	priority, err := m.client.IngestPriorityLog(ctx, &control.LogPriorityRequest{Record: control.LogRecord{
		RecordID: "r3", SessionID: "session-1", Timestamp: testConn().Timestamp,
		Kind: control.LogKindPolicyDecision, Severity: control.SeverityCritical,
		Message:    "blocked command",
		Attributes: map[string]string{"command": "rm -rf /", "action": string(control.FilterActionBlockCommand)},
	}})
	if err != nil {
		t.Fatalf("IngestPriorityLog: %v", err)
	}
	if !priority.Accepted || priority.ReceiptID == "" {
		t.Errorf("priority ack = %+v, want an accepted record with a receipt", priority)
	}

	stored := m.debugLogs(t)
	if len(stored.Batched) != 2 {
		t.Errorf("stored %d batched records, want 2", len(stored.Batched))
	}
	if len(stored.Priority) != 1 {
		t.Fatalf("stored %d priority records, want 1", len(stored.Priority))
	}
	if got := stored.Priority[0].Attributes["command"]; got != "rm -rf /" {
		t.Errorf("priority record attributes = %v, want the blocked command", stored.Priority[0].Attributes)
	}

	// -log-dir mirrors records to JSONL so a test can read them after exit.
	assertJSONLines(t, filepath.Join(logDir, "batch.jsonl"), 2)
	assertJSONLines(t, filepath.Join(logDir, "priority.jsonl"), 1)

	// Reset clears the store so a scenario can start from a clean slate.
	m.debugReset(t)
	if cleared := m.debugLogs(t); len(cleared.Batched) != 0 || len(cleared.Priority) != 0 {
		t.Errorf("after reset: %d batched, %d priority records, want none",
			len(cleared.Batched), len(cleared.Priority))
	}
}

func TestProxyTokenIsEnforced(t *testing.T) {
	m := startMock(t, nil, serverOptions{})

	wrong, err := control.NewRESTClient(control.Options{BaseURL: m.srv.URL, Token: "not-the-token"})
	if err != nil {
		t.Fatalf("NewRESTClient: %v", err)
	}
	_, err = wrong.ReportHostKey(context.Background(), &control.HostKeyReportRequest{
		Target:  "host.company.com",
		HostKey: control.PublicKeyMaterial{Fingerprint: "SHA256:whatever"},
		Conn:    testConn(),
	})
	if !control.IsUnauthorized(err) {
		t.Fatalf("error = %v, want a deny for a bad proxy token", err)
	}
}

func TestBadRequestsAreRejectedWithoutADeny(t *testing.T) {
	m := startMock(t, nil, serverOptions{})

	// A malformed body is a caller bug, not a policy decision: the server must
	// answer 400 so the proxy does not read it as "access denied".
	req, err := http.NewRequest(http.MethodPost, m.srv.URL+control.PathAuthorize, strings.NewReader(`{"target":`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+proxyToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestServerNeverStoresThePassword(t *testing.T) {
	m := startMock(t, nil, serverOptions{})

	if _, err := m.client.AuthenticatePassword(context.Background(), &control.AuthenticatePasswordRequest{
		Login: "alice", Password: alicePassword, Conn: testConn(),
	}); err != nil {
		t.Fatalf("AuthenticatePassword: %v", err)
	}

	// Nothing the server keeps about the session may contain the password.
	for _, rec := range m.debugLogs(t).Batched {
		if strings.Contains(rec.Message, alicePassword) {
			t.Errorf("a stored record contains the password: %s", rec.Message)
		}
	}
	m.server.mu.Lock()
	defer m.server.mu.Unlock()
	for token, challenge := range m.server.mfa {
		if strings.Contains(challenge.prompt, alicePassword) {
			t.Errorf("challenge %s retains the password", token)
		}
	}
}

func TestFixtureValidation(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantErrs []string
	}{
		{
			name:     "empty file",
			yaml:     "",
			wantErrs: []string{"empty"},
		},
		{
			name:     "unknown key",
			yaml:     "userz: []\n",
			wantErrs: []string{"malformed"},
		},
		{
			name:     "user without credentials",
			yaml:     "users:\n  - login: alice\n",
			wantErrs: []string{"neither key_fingerprints nor password"},
		},
		{
			name:     "duplicate login",
			yaml:     "users:\n  - login: alice\n    password: pw\n  - login: alice\n    password: pw\n",
			wantErrs: []string{"duplicated"},
		},
		{
			name: "nexthop without a next hop",
			yaml: "users:\n  - login: alice\n    password: pw\n" +
				"routes:\n  - target: h\n    route_type: nexthop\n",
			wantErrs: []string{"no next_hop"},
		},
		{
			name: "unknown filter action",
			yaml: "users:\n  - login: alice\n    password: pw\n" +
				"routes:\n  - target: h\n    filter_policy:\n      mode: blacklist\n" +
				"      rules:\n        - match: rm\n          action: shrug\n",
			wantErrs: []string{"not a known action"},
		},
		{
			name: "filter rule without a match pattern",
			yaml: "users:\n  - login: alice\n    password: pw\n" +
				"routes:\n  - target: h\n    filter_policy:\n      mode: whitelist\n" +
				"      rules:\n        - action: allow_and_log\n",
			wantErrs: []string{"has no match pattern"},
		},
		{
			name:     "unknown host key decision",
			yaml:     "users:\n  - login: alice\n    password: pw\nhost_keys:\n  decision: maybe\n",
			wantErrs: []string{"host_keys.decision"},
		},
		{
			// The rejection phase 0006 exists to make loudly: a guardrail and a
			// boundary cannot both decide the same command.
			name: "restricted exec beside a rule list",
			yaml: "users:\n  - login: alice\n    password: pw\n" +
				"routes:\n  - target: h\n    filter_policy:\n      mode: whitelist\n" +
				"      exec_mode: restricted\n      restricted_exec:\n        commands: []\n" +
				"      rules:\n        - match: rm\n          action: block_command\n",
			wantErrs: []string{"alternatives, not layers"},
		},
		{
			name: "restricted exec mode without a policy",
			yaml: "users:\n  - login: alice\n    password: pw\n" +
				"routes:\n  - target: h\n    filter_policy:\n      mode: whitelist\n" +
				"      exec_mode: restricted\n",
			wantErrs: []string{"restricted_exec is absent"},
		},
		{
			name: "restricted exec policy under the filtered tier",
			yaml: "users:\n  - login: alice\n    password: pw\n" +
				"routes:\n  - target: h\n    filter_policy:\n      mode: whitelist\n" +
				"      restricted_exec:\n        commands: []\n",
			wantErrs: []string{"alternatives, not layers"},
		},
		{
			name: "subsystem named as a request type",
			yaml: "users:\n  - login: alice\n    password: pw\n" +
				"routes:\n  - target: h\n    permitted_requests:\n      types: [shell, subsystem]\n",
			wantErrs: []string{"permitted_requests.subsystems"},
		},
		{
			name: "forward destination with both a port and a range",
			yaml: "users:\n  - login: alice\n    password: pw\n" +
				"routes:\n  - target: h\n    permitted_forwards:\n      direct_tcpip:\n" +
				"        - host: db\n          port: 5432\n          port_range:\n" +
				"            from: 1\n            to: 2\n",
			wantErrs: []string{"both port and port_range"},
		},
		{
			name: "relay hop with no proxy to relay through",
			yaml: "users:\n  - login: alice\n    password: pw\n" +
				"routes:\n  - target: h\n    route_type: nexthop\n    next_hop: p2\n" +
				"    hop_connection: relay\n",
			wantErrs: []string{"next_proxy_id"},
		},
		{
			name: "hop connection on a direct route",
			yaml: "users:\n  - login: alice\n    password: pw\n" +
				"routes:\n  - target: h\n    hop_connection: dial\n",
			wantErrs: []string{"hop_connection is set on a"},
		},
		{
			name: "unknown target auth method",
			yaml: "users:\n  - login: alice\n    password: pw\n" +
				"routes:\n  - target: h\n    target_auth:\n      method: telepathy\n",
			wantErrs: []string{"target_auth.method"},
		},
		{
			name: "empty prefix in an argument spec",
			yaml: "users:\n  - login: alice\n    password: pw\n" +
				"routes:\n  - target: h\n    filter_policy:\n      mode: whitelist\n" +
				"      exec_mode: restricted\n      restricted_exec:\n        commands:\n" +
				"          - executable: ls\n            form: positional\n            args:\n" +
				"              - kind: prefix\n",
			wantErrs: []string{"non-empty value"},
		},
		{
			name: "every problem is reported at once",
			yaml: "users:\n  - login: alice\n" +
				"routes:\n  - target: h\n    route_type: teleport\n",
			wantErrs: []string{"neither key_fingerprints nor password", "route_type"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseFixtures(strings.NewReader(tc.yaml))
			if err == nil {
				t.Fatal("parseFixtures accepted invalid fixtures")
			}
			for _, want := range tc.wantErrs {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
		})
	}
}

func TestFixtureDefaults(t *testing.T) {
	fx := mustParseFixtures(t, `
users:
  - login: alice
    password: "pw"
    mfa:
      required: true
routes:
  - target: host.company.com
`)
	u := fx.Users[0]
	if u.Identity.Subject != "alice" || u.Identity.Source != "fixture" {
		t.Errorf("identity defaults = %+v, want subject=alice source=fixture", u.Identity)
	}
	if u.MFA.Decision != mfaApprove || u.MFA.TTLMS == 0 || u.MFA.PollAfterMS == 0 {
		t.Errorf("mfa defaults = %+v, want an approving challenge with a TTL and poll hint", u.MFA)
	}

	r := fx.Routes[0]
	if r.Login != wildcard {
		t.Errorf("route login = %q, want the wildcard default", r.Login)
	}
	if r.RouteType != string(control.RouteTypeDirect) {
		t.Errorf("route_type = %q, want %q", r.RouteType, control.RouteTypeDirect)
	}
	if r.FilterPolicy.Mode != string(control.FilterModeBlacklist) {
		t.Errorf("filter mode default = %q, want %q", r.FilterPolicy.Mode, control.FilterModeBlacklist)
	}
	if len(r.FilterPolicy.Rules) != 0 {
		t.Errorf("filter rules = %+v, want none by default (a blacklist with no rules filters nothing)",
			r.FilterPolicy.Rules)
	}
	if fx.HostKeys.Decision != string(control.HostKeyAccept) {
		t.Errorf("host_keys.decision = %q, want %q", fx.HostKeys.Decision, control.HostKeyAccept)
	}
}

func TestRouteRulesAreEvaluatedInOrder(t *testing.T) {
	fx := mustParseFixtures(t, `
users:
  - login: alice
    password: "pw"
routes:
  - login: alice
    target: host.company.com
    permissions: specific
    permitted_channels: [session]
  - login: "*"
    target: "*"
    permissions: catch-all
    permitted_channels: [session]
`)
	m := startMock(t, fx, serverOptions{})
	ctx := context.Background()
	alice := &control.Identity{Subject: "alice", Login: "alice"}

	specific, err := m.client.Authorize(ctx, &control.AuthorizeRequest{
		Identity: alice, Target: "host.company.com", Conn: testConn(),
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if specific.Permissions != "specific" {
		t.Errorf("permissions = %q, want the first matching rule to win", specific.Permissions)
	}

	fallback, err := m.client.Authorize(ctx, &control.AuthorizeRequest{
		Identity: alice, Target: "other.company.com", Conn: testConn(),
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if fallback.Permissions != "catch-all" {
		t.Errorf("permissions = %q, want the catch-all rule", fallback.Permissions)
	}
}

func TestResolvedTargetOverridesADirectRoute(t *testing.T) {
	fx := mustParseFixtures(t, `
users:
  - login: alice
    password: "pw"
routes:
  - login: alice
    target: alias.company.com
    resolved_target: real.company.com
    permitted_channels: [session]
`)
	m := startMock(t, fx, serverOptions{})

	resp, err := m.client.Authorize(context.Background(), &control.AuthorizeRequest{
		Identity: &control.Identity{Subject: "alice", Login: "alice"},
		Target:   "alias.company.com",
		Conn:     testConn(),
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if resp.Target != "real.company.com" {
		t.Errorf("target = %q, want the resolved host", resp.Target)
	}
}

func TestNoProxyTokenServesEveryone(t *testing.T) {
	fx := mustParseFixtures(t, `
users:
  - login: alice
    key_fingerprints: ["SHA256:alice"]
`)
	m := startMock(t, fx, serverOptions{})

	anonymous, err := control.NewRESTClient(control.Options{BaseURL: m.srv.URL})
	if err != nil {
		t.Fatalf("NewRESTClient: %v", err)
	}
	if _, err := anonymous.AuthenticateCert(context.Background(), &control.AuthenticateCertRequest{
		Login:     "alice",
		PublicKey: control.PublicKeyMaterial{Fingerprint: "SHA256:alice"},
		Conn:      testConn(),
	}); err != nil {
		t.Fatalf("AuthenticateCert without a token: %v", err)
	}
}

// --- helpers ----------------------------------------------------------------

func mustParseFixtures(t *testing.T, yaml string) *fixtures {
	t.Helper()
	fx, err := parseFixtures(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("parseFixtures: %v", err)
	}
	return fx
}

// debugLogs reads the mock-only log store.
func (m *mock) debugLogs(t *testing.T) debugLogs {
	t.Helper()
	resp, err := http.Get(m.srv.URL + pathDebugLogs)
	if err != nil {
		t.Fatalf("GET %s: %v", pathDebugLogs, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", pathDebugLogs, resp.StatusCode)
	}
	var out debugLogs
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode debug logs: %v", err)
	}
	return out
}

// debugReset clears the mock's stored state.
func (m *mock) debugReset(t *testing.T) {
	t.Helper()
	resp, err := http.Post(m.srv.URL+pathDebugReset, "", nil)
	if err != nil {
		t.Fatalf("POST %s: %v", pathDebugReset, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST %s: status %d", pathDebugReset, resp.StatusCode)
	}
}

// assertJSONLines checks that path holds want decodable JSON lines.
func assertJSONLines(t *testing.T, path string, want int) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	dec := json.NewDecoder(f)
	got := 0
	for {
		var rec control.LogRecord
		err := dec.Decode(&rec)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		got++
	}
	if got != want {
		t.Errorf("%s holds %d records, want %d", path, got, want)
	}
}

// TestAuthorizeServesTheV2Vocabulary drives the phase 0006 fixture keys through
// the real client, which is the only way to know the mock and the contract agree
// about them: the client decodes the authorize response strictly and validates
// it, so a fixture key that serialises wrongly fails here rather than in 0009.
func TestAuthorizeServesTheV2Vocabulary(t *testing.T) {
	m := startMock(t, nil, serverOptions{})
	ctx := context.Background()
	alice := &control.Identity{Subject: "alice@example.com", Login: "alice", Source: "fixture"}
	deploy := &control.Identity{Subject: "svc-deploy@example.com", Login: "svc-deploy", Source: "fixture"}

	t.Run("in-channel requests and global requests", func(t *testing.T) {
		resp, err := m.client.Authorize(ctx, &control.AuthorizeRequest{
			Identity: alice, Target: "host.company.com", Conn: testConn(),
		})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		if resp.PermittedRequests == nil {
			t.Fatal("permitted_requests is absent; the fixture sets it")
		}
		if !resp.PermittedRequests.RequestPermitted(control.RequestShell) {
			t.Error("shell denied though the fixture permits it")
		}
		// The point of naming subsystems individually: sftp off, shell on.
		if resp.PermittedRequests.SubsystemPermitted("sftp") {
			t.Error("sftp permitted though the fixture's subsystem list is empty")
		}
		if resp.PermittedGlobalRequests == nil {
			t.Fatal("permitted_global_requests is absent; the fixture sets it")
		}
		if resp.PermittedGlobalRequests.Permitted(control.GlobalRequestTCPIPForward) {
			t.Error("tcpip-forward permitted though the fixture's list is empty")
		}
		if resp.TargetAuth == nil || resp.TargetAuth.Method != control.TargetAuthEphemeralUser {
			t.Errorf("target_auth = %+v, want the ephemeral-user method", resp.TargetAuth)
		}
	})

	t.Run("forwarding destinations", func(t *testing.T) {
		resp, err := m.client.Authorize(ctx, &control.AuthorizeRequest{
			Identity: deploy, Target: "app-01.company.com", Conn: testConn(),
		})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		dests, policed := resp.PermittedForwards.Destinations(control.ChannelDirectTCPIP)
		if !policed || len(dests) != 3 {
			t.Fatalf("direct_tcpip = %v (policed=%v), want the fixture's three entries", dests, policed)
		}
		if dests[0].Host != "postgres.prod.company.com" || dests[0].Port != 5432 {
			t.Errorf("first destination = %+v, want the exact host:port entry", dests[0])
		}
		if pr := dests[1].PortRange; pr == nil || pr.From != 9090 || pr.To != 9100 {
			t.Errorf("second destination port range = %+v, want 9090-9100", pr)
		}
		if rev, policed := resp.PermittedForwards.Destinations(control.ChannelForwardedTCPIP); !policed || len(rev) != 0 {
			t.Errorf("forwarded_tcpip = %v (policed=%v), want policed with none", rev, policed)
		}
		if resp.TargetAuth == nil || resp.TargetAuth.Params["credential_ref"] != "deploy-fleet-2026" {
			t.Errorf("target_auth = %+v, want the brokered-key credential reference", resp.TargetAuth)
		}
	})

	t.Run("restricted exec", func(t *testing.T) {
		resp, err := m.client.Authorize(ctx, &control.AuthorizeRequest{
			Identity: deploy, Target: "edge-fw-01.company.com", Conn: testConn(),
		})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		if got := resp.FilterPolicy.Exec(); got != control.ExecModeRestricted {
			t.Fatalf("exec_mode = %q, want %q", got, control.ExecModeRestricted)
		}
		if len(resp.FilterPolicy.Rules) != 0 {
			t.Error("a restricted policy must carry no rule list: the tiers are alternatives")
		}
		cmds := resp.FilterPolicy.RestrictedExec.Commands
		if len(cmds) != 3 {
			t.Fatalf("restricted_exec.commands = %d, want the fixture's three", len(cmds))
		}
		if cmds[2].Form != control.CommandFormPositional || len(cmds[2].Args) != 3 {
			t.Errorf("third command = %+v, want the positional form with three specs", cmds[2])
		}
		if cmds[2].Args[0].Kind != control.ArgumentPrefix || cmds[2].Args[0].Value != "--unit=" {
			t.Errorf("first arg spec = %+v, want the --unit= prefix", cmds[2].Args[0])
		}
	})

	t.Run("hop direction", func(t *testing.T) {
		resp, err := m.client.Authorize(ctx, &control.AuthorizeRequest{
			Identity: alice, Target: "deep.internal.company.com", Conn: testConn(),
		})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		if got := resp.Hop.Direction(); got != control.HopConnectionRelay {
			t.Errorf("hop.connection = %q, want %q", got, control.HopConnectionRelay)
		}
		if resp.Hop.NextProxyID != "proxy-2" {
			t.Errorf("hop.next_proxy_id = %q, want the registration to relay through", resp.Hop.NextProxyID)
		}
	})
}

// TestAuthorizeStillServesAV1Fixture is the compatibility criterion at the mock:
// a fixture written before phase 0006 sets none of the new keys, and must still
// produce a working, documented-default decision rather than a denial.
func TestAuthorizeStillServesAV1Fixture(t *testing.T) {
	fx := mustParseFixtures(t, `
users:
  - login: alice
    password: "pw"
routes:
  - login: alice
    target: "*"
    route_type: direct
    permitted_channels: [session]
    filter_policy:
      mode: blacklist
      rules:
        - match: shutdown
          action: block_command
`)
	m := startMock(t, fx, serverOptions{})

	resp, err := m.client.Authorize(context.Background(), &control.AuthorizeRequest{
		Identity: &control.Identity{Subject: "alice", Login: "alice"},
		Target:   "host.company.com",
		Conn:     testConn(),
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	for _, tc := range []struct {
		name string
		got  bool
	}{
		{"permitted_requests", resp.PermittedRequests != nil},
		{"permitted_forwards", resp.PermittedForwards != nil},
		{"permitted_global_requests", resp.PermittedGlobalRequests != nil},
		{"target_auth", resp.TargetAuth != nil},
		{"restricted_exec", resp.FilterPolicy.RestrictedExec != nil},
	} {
		if tc.got {
			t.Errorf("%s was invented for a fixture that never set it", tc.name)
		}
	}
	if got := resp.FilterPolicy.Exec(); got != control.ExecModeFiltered {
		t.Errorf("exec_mode = %q, want %q", got, control.ExecModeFiltered)
	}
	// And the v1 policy it did express is untouched.
	if !resp.PermittedRequests.RequestPermitted(control.RequestShell) {
		t.Error("a v1 fixture must not deny every shell")
	}
	if len(resp.FilterPolicy.Rules) != 1 {
		t.Errorf("filter rules = %v, want the fixture's one rule", resp.FilterPolicy.Rules)
	}
}

// TestAuthorizeRefusesAProxyThatCannotReadThePolicy covers the other half of the
// versioning rule. The proxy fails closed on a field it does not understand, so
// a server holding v2 policy for a proxy that declared v1 says so plainly
// instead of sending policy that will be refused as a protocol error.
func TestAuthorizeRefusesAProxyThatCannotReadThePolicy(t *testing.T) {
	m := startMock(t, nil, serverOptions{})

	body, err := json.Marshal(control.AuthorizeRequest{
		Identity:      &control.Identity{Subject: "alice@example.com", Login: "alice"},
		Target:        "host.company.com",
		PolicyVersion: 1,
		Conn:          testConn(),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, m.srv.URL+control.PathAuthorize, strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+proxyToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// An outage, not a deny: the proxy is not forbidden, the two ends disagree.
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
	payload, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(payload), "policy_version") {
		t.Errorf("body = %s, want it to name the version mismatch", payload)
	}
}

// TestAuthorizeServesTheV3Vocabulary drives the phase 0013 fixture keys through
// the real client, for the reason the v2 test exists: the client decodes the
// authorize response strictly and validates it, so a fixture key that
// serialises wrongly fails here rather than in 0014.
func TestAuthorizeServesTheV3Vocabulary(t *testing.T) {
	m := startMock(t, nil, serverOptions{})
	ctx := context.Background()
	deploy := &control.Identity{Subject: "svc-deploy@example.com", Login: "svc-deploy", Source: "fixture"}

	t.Run("a two-entry ladder, in the server's order", func(t *testing.T) {
		resp, err := m.client.Authorize(ctx, &control.AuthorizeRequest{
			Identity: deploy, Target: "core-fw-01.company.com", Conn: testConn(),
		})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		rungs, named := resp.Ladder()
		if !named || len(rungs) != 2 {
			t.Fatalf("ladder = %+v (named=%v), want the fixture's two rungs", rungs, named)
		}
		if rungs[0].Method != control.TargetAuthEphemeralAccount {
			t.Errorf("first rung = %q, want %q", rungs[0].Method, control.TargetAuthEphemeralAccount)
		}
		if got := rungs[0].Params[control.ParamPlatform]; got != "fortios" {
			t.Errorf("first rung platform = %q, want the driver the fixture names", got)
		}
		if got := control.ExpiryPosture(rungs[0].Params[control.ParamExpiryPosture]); got != control.ExpiryPostureTargetEnforced {
			t.Errorf("first rung expiry posture = %q, want %q", got, control.ExpiryPostureTargetEnforced)
		}
		if rungs[1].Method != control.TargetAuthBrokeredKey {
			t.Errorf("second rung = %q, want the weaker rung behind the device one", rungs[1].Method)
		}
		if resp.TargetAuth != nil {
			t.Error("target_auth was invented beside the ladder")
		}
		if got := resp.Profile(); got != control.AlgorithmProfileLegacyDevice {
			t.Errorf("algorithm_profile = %q, want %q", got, control.AlgorithmProfileLegacyDevice)
		}
	})

	t.Run("a one-entry ladder refuses degradation", func(t *testing.T) {
		resp, err := m.client.Authorize(ctx, &control.AuthorizeRequest{
			Identity: deploy, Target: "crown-fw-01.company.com", Conn: testConn(),
		})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		rungs, named := resp.Ladder()
		if !named || len(rungs) != 1 {
			t.Fatalf("ladder = %+v (named=%v), want exactly one rung", rungs, named)
		}
		if got := control.ExpiryPosture(rungs[0].Params[control.ParamExpiryPosture]); got != control.ExpiryPostureAcceptedRisk {
			t.Errorf("expiry posture = %q, want %q", got, control.ExpiryPostureAcceptedRisk)
		}
		if got := resp.Profile(); got != control.AlgorithmProfileLegacyRSASHA1 {
			t.Errorf("algorithm_profile = %q, want %q", got, control.AlgorithmProfileLegacyRSASHA1)
		}
	})

	t.Run("a v2 route still answers a v2 shape", func(t *testing.T) {
		alice := &control.Identity{Subject: "alice@example.com", Login: "alice", Source: "fixture"}
		resp, err := m.client.Authorize(ctx, &control.AuthorizeRequest{
			Identity: alice, Target: "host.company.com", Conn: testConn(),
		})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		if resp.TargetAuthLadder != nil {
			t.Fatal("a ladder was invented for a fixture that sets target_auth")
		}
		rungs, named := resp.Ladder()
		if !named || len(rungs) != 1 || rungs[0].Method != control.TargetAuthEphemeralUser {
			t.Errorf("Ladder() = %+v (named=%v), want the v2 object as one rung", rungs, named)
		}
		if resp.AlgorithmProfile != "" {
			t.Errorf("algorithm_profile = %q, want it absent on a route that never named one",
				resp.AlgorithmProfile)
		}
	})
}

// TestEmptyLadderFixtureIsADenialNotLocalConfig keeps the fixture layer honest
// about the distinction the contract is most likely to lose: a route whose
// ladder is written `[]` must reach the proxy as an empty ladder, not as an
// absent one, or the mock hands the session the very credential the fixture
// declined to name.
func TestEmptyLadderFixtureIsADenialNotLocalConfig(t *testing.T) {
	fx := mustParseFixtures(t, `
proxy_token: "`+proxyToken+`"
users:
  - login: alice
    password: pw
routes:
  - login: alice
    target: "*"
    route_type: direct
    permitted_channels: [session]
    target_auth_ladder: []
    filter_policy:
      mode: blacklist
`)
	m := startMock(t, fx, serverOptions{})

	resp, err := m.client.Authorize(context.Background(), &control.AuthorizeRequest{
		Identity: &control.Identity{Subject: "alice", Login: "alice"},
		Target:   "host.company.com",
		Conn:     testConn(),
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	rungs, named := resp.Ladder()
	if !named {
		t.Fatal("an empty ladder arrived as an absent one; the denial became local config")
	}
	if len(rungs) != 0 {
		t.Errorf("ladder = %+v, want no rungs to walk", rungs)
	}
}

// TestFixturesRefuseBothCredentialShapes proves the mock cannot start holding a
// policy the client would refuse. The check lives in the fixture layer as well
// as in the contract because a fixture file is where somebody writes the
// mistake.
func TestFixturesRefuseBothCredentialShapes(t *testing.T) {
	_, err := parseFixtures(strings.NewReader(`
users:
  - login: alice
    password: pw
routes:
  - login: alice
    target: h
    target_auth:
      method: static-key
      params:
        username: dev
    target_auth_ladder:
      - method: static-key
        params:
          username: dev
    filter_policy:
      mode: blacklist
`))
	if err == nil {
		t.Fatal("a fixture setting both credential shapes was accepted")
	}
	for _, want := range []string{"target_auth", "target_auth_ladder"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

// TestVersionGateAnswersPerRoute covers the half of the version gate that a
// vocabulary bump breaks most easily: raising PolicyVersion must not make every
// older route unservable to a proxy that declared an older vocabulary. The gate
// answers per ROUTE, not per build — a fixture using only the v2 vocabulary is
// still v2 however many revisions the contract has had since.
func TestVersionGateAnswersPerRoute(t *testing.T) {
	m := startMock(t, nil, serverOptions{})

	authorizeAs := func(t *testing.T, target string, version int) int {
		t.Helper()
		body, err := json.Marshal(control.AuthorizeRequest{
			Identity:      &control.Identity{Subject: "svc-deploy@example.com", Login: "svc-deploy"},
			Target:        target,
			PolicyVersion: version,
			Conn:          testConn(),
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		req, err := http.NewRequest(http.MethodPost, m.srv.URL+control.PathAuthorize, strings.NewReader(string(body)))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+proxyToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.ReadAll(resp.Body)
		return resp.StatusCode
	}

	// A v2 route (the wildcard rule: a single brokered-key target_auth and the
	// forwarding axis) to a proxy declaring 2.
	if got := authorizeAs(t, "anything.company.com", 2); got != http.StatusOK {
		t.Errorf("a v2 route to a v2 proxy = %d, want %d", got, http.StatusOK)
	}
	// A v3 route (a ladder, no enforcement object) to the same proxy: refused,
	// and refused as an outage rather than served with policy it would fail
	// closed on.
	if got := authorizeAs(t, "crown-fw-01.company.com", 2); got != http.StatusInternalServerError {
		t.Errorf("a v3 route to a v2 proxy = %d, want %d", got, http.StatusInternalServerError)
	}
	if got := authorizeAs(t, "crown-fw-01.company.com", 3); got != http.StatusOK {
		t.Errorf("a v3 route to a v3 proxy = %d, want %d", got, http.StatusOK)
	}
	// A v4 route (an enforcement rung) to a v3 proxy: same answer, one
	// vocabulary later. This is the case the gate exists for after phase 0018,
	// and the reason vocabularyVersion needs a case per contract revision.
	if got := authorizeAs(t, "edge-fw-01.company.com", 3); got != http.StatusInternalServerError {
		t.Errorf("a v4 route to a v3 proxy = %d, want %d", got, http.StatusInternalServerError)
	}
	if got := authorizeAs(t, "edge-fw-01.company.com", 4); got != http.StatusOK {
		t.Errorf("a v4 route to a v4 proxy = %d, want %d", got, http.StatusOK)
	}
}

// --- contract v4: enforcement points and session bounds ---------------------

// TestEnforcementRungsAreServedFromFixtures drives every rung on both axes
// through the real client, from the worked example. It is the fixture half of
// phase 0018's acceptance: a rung Control can name but the mock cannot serve is
// a rung phase 0019 cannot be built or tested against.
func TestEnforcementRungsAreServedFromFixtures(t *testing.T) {
	m := startMock(t, nil, serverOptions{})

	tests := []struct {
		name          string
		login, target string
		execution     control.ExecutionRung
		reach         control.ReachRung
		check         func(*testing.T, *control.AuthorizeResponse)
	}{
		{
			name: "the defaults, on a route that names no rung",
			// Every route written before phase 0018 lands here, which is the
			// compatibility property the whole revision rests on.
			login: "alice", target: "host.company.com",
			execution: control.ExecutionProxyInspected,
			reach:     control.ReachProxyChannelPolicy,
			check: func(t *testing.T, resp *control.AuthorizeResponse) {
				if resp.Enforcement != nil {
					t.Error("a pre-0018 route must carry no enforcement object at all")
				}
			},
		},
		{
			name:  "the free rung: no interactive shell",
			login: "svc-deploy", target: "automation-01.company.com",
			execution: control.ExecutionNoInteractiveShell,
			reach:     control.ReachProxyChannelPolicy,
			check: func(t *testing.T, resp *control.AuthorizeResponse) {
				if resp.PermittedRequests.RequestPermitted(control.RequestShell) {
					t.Error("the rung claims no interactive shell but the policy permits one")
				}
				if resp.Concurrency == nil || resp.Concurrency.PerSubject != 4 {
					t.Errorf("concurrency = %+v, want a per-subject cap of 4", resp.Concurrency)
				}
			},
		},
		{
			name:  "both applied rungs on an ephemeral-user route",
			login: "svc-deploy", target: "build-01.company.com",
			execution: control.ExecutionAccountRestricted,
			reach:     control.ReachAccountEgressRestricted,
			check: func(t *testing.T, resp *control.AuthorizeResponse) {
				if got := len(resp.Enforcement.PermittedDestinations); got != 2 {
					t.Errorf("permitted_destinations has %d entries, want 2", got)
				}
				if resp.FilterPolicy.Exec() != control.ExecModeRestricted {
					t.Error("account-restricted must ride restricted exec: it renders what that names")
				}
			},
		},
		{
			name:  "the strongest applied pair",
			login: "svc-deploy", target: "sensor-01.company.com",
			execution: control.ExecutionAccountConfined,
			reach:     control.ReachAccountNetworkIsolated,
		},
		{
			name:  "device RBAC, applied per session",
			login: "svc-deploy", target: "core-fw-01.company.com",
			execution: control.ExecutionPlatformAuthorized,
			reach:     control.ReachProxyChannelPolicy,
			check: func(t *testing.T, resp *control.AuthorizeResponse) {
				if resp.Enforcement.PlatformRole == "" {
					t.Error("platform-authorized carries no role; the role IS the rung")
				}
				// The applied rung is legal here only because the ladder's first
				// entry provisions the target. The brokered-key entry behind it
				// is a skipped rung, not a session without the rung.
				rungs, named := resp.Ladder()
				if !named || len(rungs) != 2 || !rungs[0].Method.Provisions() {
					t.Errorf("ladder = %+v, want a provisioning first entry", rungs)
				}
			},
		},
		{
			name: "an attested rung on a brokered-key route",
			// The case that makes the appliance estate reachable: the proxy
			// administers nothing, so no applied rung exists — and "none
			// available" would still be the wrong record.
			login: "svc-deploy", target: "edge-fw-01.company.com",
			execution: control.ExecutionPlatformAttested,
			reach:     control.ReachPlatformAttested,
			check: func(t *testing.T, resp *control.AuthorizeResponse) {
				att := resp.Enforcement.Attestation
				if att == nil || att.AssertedBy == "" || att.Reference == "" {
					t.Fatalf("attestation = %+v, want who asserts it and where that lives", att)
				}
				rungs, _ := resp.Ladder()
				for _, rung := range rungs {
					if rung.Method.Provisions() {
						t.Error("this route is meant to provision nothing")
					}
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := m.client.Authorize(context.Background(), &control.AuthorizeRequest{
				Identity: &control.Identity{Subject: tc.login + "@example.com", Login: tc.login},
				Target:   tc.target,
				Conn:     testConn(),
			})
			if err != nil {
				t.Fatalf("Authorize(%s): %v", tc.target, err)
			}
			if got := resp.EnforcedExecution(); got != tc.execution {
				t.Errorf("execution rung = %q, want %q", got, tc.execution)
			}
			if got := resp.EnforcedReach(); got != tc.reach {
				t.Errorf("reach rung = %q, want %q", got, tc.reach)
			}
			if tc.check != nil {
				tc.check(t, resp)
			}
		})
	}
}

// TestSessionBoundsAreServedFromFixtures covers D16's four fields on the UC3
// route, including the one shape a fixture cannot hold directly: the deadline
// is an absolute instant, anchored by the server at authorize time.
func TestSessionBoundsAreServedFromFixtures(t *testing.T) {
	now := time.Date(2026, 9, 4, 9, 0, 0, 0, time.UTC)
	m := startMock(t, nil, serverOptions{Now: func() time.Time { return now }})

	resp, err := m.client.Authorize(context.Background(), &control.AuthorizeRequest{
		Identity: &control.Identity{Subject: "alice@example.com", Login: "alice"},
		Target:   "scan-target-01.company.com",
		Conn:     testConn(),
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	if resp.SessionDeadline == nil {
		t.Fatal("the route carries no session_deadline")
	}
	if want := now.Add(time.Hour); !resp.SessionDeadline.Equal(want) {
		t.Errorf("session_deadline = %v, want %v (anchored at authorize time)", resp.SessionDeadline, want)
	}
	if !resp.RequireSessionCapture {
		t.Error("the route must require capture: it is what makes the grant defensible (D16)")
	}
	g := resp.GrantContext
	if g == nil || g.System != "qualys" || g.Reference == "" {
		t.Fatalf("grant_context = %+v, want the asserting system and its reference", g)
	}
	if g.WindowStart == nil || g.WindowEnd == nil || !g.WindowEnd.After(*g.WindowStart) {
		t.Errorf("grant_context window = %v..%v, want an ordered pair", g.WindowStart, g.WindowEnd)
	}
	if g.Additional == nil || g.Additional.Fields["scan_profile"] != "authenticated-linux" {
		t.Errorf("additional_context = %+v, want the object form intact", g.Additional)
	}
	if resp.Concurrency == nil || resp.Concurrency.PerTarget != 1 {
		t.Errorf("concurrency = %+v, want a per-target cap of 1", resp.Concurrency)
	}
	// This route deliberately names NO rung: a scanner's command set changes
	// with every content update, so every execution rung is worthless against
	// it and the honest policy says so (PLAN §13 UC3).
	if resp.Enforcement != nil {
		t.Error("the scanner route must claim no enforcement rung")
	}
}

// TestCapabilityReportIsRecorded drives the v4 endpoint through the real
// client. The server decides nothing — a capability report is an observation —
// so what is asserted is that it round-trips and is remembered.
func TestCapabilityReportIsRecorded(t *testing.T) {
	m := startMock(t, nil, serverOptions{})
	observed := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

	resp, err := m.client.ReportCapabilities(context.Background(), &control.CapabilityReportRequest{
		Target: "build-01.company.com",
		Capabilities: control.TargetCapabilities{
			Execution:  []control.ExecutionRung{control.ExecutionAccountRestricted},
			Reach:      []control.ReachRung{control.ReachAccountNetworkIsolated},
			ObservedAt: observed,
			Detail:     map[string]string{"init": "systemd-257"},
		},
		Conn: testConn(),
	})
	if err != nil {
		t.Fatalf("ReportCapabilities: %v", err)
	}
	if !resp.Accepted {
		t.Error("the server did not accept the report")
	}

	stored, ok := m.server.reportedCapabilities("build-01.company.com")
	if !ok {
		t.Fatal("the report was not recorded")
	}
	if !stored.Fresh(observed.Add(time.Minute), control.DefaultCapabilityTTL) {
		t.Error("the stored record is not fresh a minute after it was observed")
	}
	if !stored.ProvidesExecution(control.ExecutionAccountRestricted, observed, control.DefaultCapabilityTTL) {
		t.Error("the stored record does not provide what it reported")
	}
	if stored.ProvidesExecution(control.ExecutionAccountConfined, observed, control.DefaultCapabilityTTL) {
		t.Error("the stored record provides a rung it never reported")
	}

	// An undated record is a stale one by contract, so a server that stored it
	// would be storing something nobody may use.
	_, err = m.client.ReportCapabilities(context.Background(), &control.CapabilityReportRequest{
		Target:       "build-01.company.com",
		Capabilities: control.TargetCapabilities{Execution: []control.ExecutionRung{control.ExecutionAccountConfined}},
		Conn:         testConn(),
	})
	if err == nil {
		t.Error("an undated capability report was accepted")
	}
}

// TestInvalidV4FixturesAreRefusedAtStartup. Fixture decoding is strict and the
// route is checked against the CLIENT's own Validate, so a fixture describing a
// policy a real proxy would refuse must not start the mock — which is the only
// thing standing between a bad fixture and a scenario that fails three layers
// away from its cause.
func TestInvalidV4FixturesAreRefusedAtStartup(t *testing.T) {
	const preamble = "users:\n  - login: alice\n    password: pw\n" +
		"routes:\n  - target: h\n    filter_policy:\n      mode: blacklist\n"

	tests := []struct {
		name     string
		yaml     string
		wantErrs []string
	}{
		{
			name: "an applied rung on a brokered-key ladder",
			yaml: preamble +
				"    target_auth_ladder:\n      - method: brokered-key\n        params:\n" +
				"          username: monitor\n          credential_ref: fleet\n" +
				"    enforcement:\n      execution: platform-authorized\n" +
				"      platform_role: prof_admin\n",
			wantErrs: []string{"no credential method on this route provisions the target"},
		},
		{
			name:     "an unknown rung",
			yaml:     preamble + "    enforcement:\n      reach: firewalled\n",
			wantErrs: []string{"firewalled"},
		},
		{
			name:     "an attested rung with no attestation",
			yaml:     preamble + "    enforcement:\n      execution: platform-attested\n",
			wantErrs: []string{"carries no attestation"},
		},
		{
			name: "no-interactive-shell beside a permitted shell",
			yaml: preamble + "    permitted_requests:\n      types: [exec, shell]\n" +
				"    enforcement:\n      execution: no-interactive-shell\n",
			wantErrs: []string{"shell"},
		},
		{
			name: "both forms of additional context",
			yaml: preamble + "    grant_context:\n      system: qualys\n" +
				"      additional_context_text: hello\n" +
				"      additional_context_fields:\n        a: b\n",
			wantErrs: []string{"one or the other"},
		},
		{
			name:     "a malformed grant window",
			yaml:     preamble + "    grant_context:\n      window_end: \"yesterday\"\n",
			wantErrs: []string{"RFC 3339"},
		},
		{
			name:     "a negative deadline",
			yaml:     preamble + "    session_deadline_seconds: -1\n",
			wantErrs: []string{"session_deadline_seconds"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseFixtures(strings.NewReader(tc.yaml))
			if err == nil {
				t.Fatal("parseFixtures accepted a fixture the proxy would refuse")
			}
			for _, want := range tc.wantErrs {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
		})
	}
}
