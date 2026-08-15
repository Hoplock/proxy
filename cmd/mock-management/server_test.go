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

	"github.com/mauroasilva/securecommandproxy/internal/mgmt"
)

// exampleFixturesPath is the fixture file that ships with the mock; it must
// always be valid and is what the e2e topology starts from.
const exampleFixturesPath = "fixtures.example.yaml"

// Credentials from fixtures.example.yaml.
const (
	bastionToken   = "dev-bastion-token"
	aliceKeyFP     = "SHA256:AAAA1111alice1111AAAA1111alice1111AAAA111111"
	alicePassword  = "alice-dev-password"
	knownHostKeyFP = "SHA256:CCCC3333hostkey3333CCCC3333hostkey3333CCCC"
)

// mock is a running mock server plus a client wired to it, so the tests drive
// the contract exactly as the bastion will.
type mock struct {
	srv    *httptest.Server
	client *mgmt.RESTClient
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

	client, err := mgmt.NewRESTClient(mgmt.Options{BaseURL: srv.URL, Token: fx.BastionToken})
	if err != nil {
		t.Fatalf("NewRESTClient: %v", err)
	}
	return &mock{srv: srv, client: client, server: s}
}

func testConn() mgmt.ConnMeta {
	return mgmt.ConnMeta{
		SessionID:  "session-1",
		BastionID:  "bastion-1",
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
	if fx.BastionToken != bastionToken {
		t.Errorf("bastion_token = %q, want %q", fx.BastionToken, bastionToken)
	}
}

func TestCertAuth(t *testing.T) {
	m := startMock(t, nil, serverOptions{})
	ctx := context.Background()

	t.Run("known key authenticates", func(t *testing.T) {
		resp, err := m.client.AuthenticateCert(ctx, &mgmt.AuthenticateCertRequest{
			Login:     "alice",
			Target:    "host.company.com",
			PublicKey: mgmt.PublicKeyMaterial{Type: "ssh-ed25519", Fingerprint: aliceKeyFP},
			Conn:      testConn(),
		})
		if err != nil {
			t.Fatalf("AuthenticateCert: %v", err)
		}
		if resp.Status != mgmt.AuthStatusAuthenticated {
			t.Fatalf("status = %q, want %q", resp.Status, mgmt.AuthStatusAuthenticated)
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
		_, err := m.client.AuthenticateCert(ctx, &mgmt.AuthenticateCertRequest{
			Login:     "alice",
			PublicKey: mgmt.PublicKeyMaterial{Type: "ssh-ed25519", Fingerprint: "SHA256:not-alices-key"},
			Conn:      testConn(),
		})
		if !mgmt.IsUnauthorized(err) {
			t.Fatalf("error = %v, want a deny", err)
		}
	})

	t.Run("unknown login is denied", func(t *testing.T) {
		_, err := m.client.AuthenticateCert(ctx, &mgmt.AuthenticateCertRequest{
			Login:     "nobody",
			PublicKey: mgmt.PublicKeyMaterial{Type: "ssh-ed25519", Fingerprint: aliceKeyFP},
			Conn:      testConn(),
		})
		if !mgmt.IsUnauthorized(err) {
			t.Fatalf("error = %v, want a deny", err)
		}
	})

	t.Run("password-only user cannot use a key", func(t *testing.T) {
		_, err := m.client.AuthenticateCert(ctx, &mgmt.AuthenticateCertRequest{
			Login:     "mallory",
			PublicKey: mgmt.PublicKeyMaterial{Type: "ssh-ed25519", Fingerprint: aliceKeyFP},
			Conn:      testConn(),
		})
		if !mgmt.IsUnauthorized(err) {
			t.Fatalf("error = %v, want a deny", err)
		}
	})
}

func TestPasswordAuthWithMFAApproval(t *testing.T) {
	m := startMock(t, nil, serverOptions{})
	ctx := context.Background()

	resp, err := m.client.AuthenticatePassword(ctx, &mgmt.AuthenticatePasswordRequest{
		Login:    "alice",
		Password: alicePassword,
		Conn:     testConn(),
	})
	if err != nil {
		t.Fatalf("AuthenticatePassword: %v", err)
	}
	if resp.Status != mgmt.AuthStatusMFARequired {
		t.Fatalf("status = %q, want %q", resp.Status, mgmt.AuthStatusMFARequired)
	}
	if resp.MFA.Token == "" {
		t.Fatal("challenge has no token")
	}
	if resp.MFA.PollAfter() <= 0 {
		t.Errorf("poll interval = %v, want a positive hint", resp.MFA.PollAfter())
	}

	// The fixture keeps the challenge pending for exactly one poll.
	pending, err := m.client.PollMFA(ctx, &mgmt.MFAPollRequest{Token: resp.MFA.Token, Conn: testConn()})
	if err != nil {
		t.Fatalf("PollMFA (pending): %v", err)
	}
	if pending.Status != mgmt.AuthStatusMFARequired {
		t.Fatalf("status = %q, want the challenge still pending", pending.Status)
	}

	approved, err := m.client.PollMFA(ctx, &mgmt.MFAPollRequest{Token: resp.MFA.Token, Conn: testConn()})
	if err != nil {
		t.Fatalf("PollMFA (approve): %v", err)
	}
	if approved.Status != mgmt.AuthStatusAuthenticated {
		t.Fatalf("status = %q, want %q", approved.Status, mgmt.AuthStatusAuthenticated)
	}
	if got, want := approved.Identity.Subject, "alice@example.com"; got != want {
		t.Errorf("subject = %q, want %q", got, want)
	}

	// The token is single-use: polling a resolved challenge is a deny.
	if _, err := m.client.PollMFA(ctx, &mgmt.MFAPollRequest{Token: resp.MFA.Token, Conn: testConn()}); !mgmt.IsUnauthorized(err) {
		t.Fatalf("error = %v, want a deny for a spent token", err)
	}
}

func TestPasswordAuthDenials(t *testing.T) {
	m := startMock(t, nil, serverOptions{})
	ctx := context.Background()

	t.Run("wrong password", func(t *testing.T) {
		_, err := m.client.AuthenticatePassword(ctx, &mgmt.AuthenticatePasswordRequest{
			Login: "alice", Password: "wrong", Conn: testConn(),
		})
		if !mgmt.IsUnauthorized(err) {
			t.Fatalf("error = %v, want a deny", err)
		}
	})

	t.Run("key-only user has no password", func(t *testing.T) {
		_, err := m.client.AuthenticatePassword(ctx, &mgmt.AuthenticatePasswordRequest{
			Login: "svc-deploy", Password: "", Conn: testConn(),
		})
		if !mgmt.IsUnauthorized(err) {
			t.Fatalf("error = %v, want a deny", err)
		}
	})

	t.Run("mfa denied", func(t *testing.T) {
		resp, err := m.client.AuthenticatePassword(ctx, &mgmt.AuthenticatePasswordRequest{
			Login: "mallory", Password: "mallory-dev-password", Conn: testConn(),
		})
		if err != nil {
			t.Fatalf("AuthenticatePassword: %v", err)
		}
		if resp.Status != mgmt.AuthStatusMFARequired {
			t.Fatalf("status = %q, want %q", resp.Status, mgmt.AuthStatusMFARequired)
		}
		_, err = m.client.PollMFA(ctx, &mgmt.MFAPollRequest{Token: resp.MFA.Token, Conn: testConn()})
		if !mgmt.IsUnauthorized(err) {
			t.Fatalf("error = %v, want a deny once MFA is refused", err)
		}
	})

	t.Run("unknown token", func(t *testing.T) {
		_, err := m.client.PollMFA(ctx, &mgmt.MFAPollRequest{Token: "mfa-does-not-exist", Conn: testConn()})
		if !mgmt.IsUnauthorized(err) {
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

	resp, err := m.client.AuthenticatePassword(ctx, &mgmt.AuthenticatePasswordRequest{
		Login: "alice", Password: "pw", Conn: testConn(),
	})
	if err != nil {
		t.Fatalf("AuthenticatePassword: %v", err)
	}

	now = now.Add(2 * time.Second) // past the 1s TTL
	if _, err := m.client.PollMFA(ctx, &mgmt.MFAPollRequest{Token: resp.MFA.Token, Conn: testConn()}); !mgmt.IsUnauthorized(err) {
		t.Fatalf("error = %v, want a deny for an expired challenge", err)
	}
}

func TestAuthorize(t *testing.T) {
	m := startMock(t, nil, serverOptions{})
	ctx := context.Background()
	alice := &mgmt.Identity{Subject: "alice@example.com", Login: "alice", Source: "fixture"}

	t.Run("direct route carries the full policy", func(t *testing.T) {
		resp, err := m.client.Authorize(ctx, &mgmt.AuthorizeRequest{
			Identity: alice, Target: "host.company.com", AuthMethod: mgmt.AuthMethodCert, Conn: testConn(),
		})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		if resp.RouteType != mgmt.RouteTypeDirect {
			t.Errorf("route_type = %q, want %q", resp.RouteType, mgmt.RouteTypeDirect)
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
		if resp.FilterPolicy.Mode != mgmt.FilterModeBlacklist {
			t.Errorf("filter mode = %q, want %q", resp.FilterPolicy.Mode, mgmt.FilterModeBlacklist)
		}
		// The whole point of per-rule actions: one policy, three severities, in
		// the fixture's order.
		wantRules := []mgmt.FilterRule{
			{Match: "rm -rf /", Action: mgmt.FilterActionKillSession},
			{Match: "shutdown", Action: mgmt.FilterActionBlockCommand},
			{Match: "sudo *", Action: mgmt.FilterActionWarnAndContinue},
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

	t.Run("nexthop route returns the next bastion and keeps the final target", func(t *testing.T) {
		conn := testConn()
		conn.HopTrail = []string{"bastion-0"}
		resp, err := m.client.Authorize(ctx, &mgmt.AuthorizeRequest{
			Identity: alice, Target: "deep.internal.company.com", Conn: conn,
		})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		if resp.RouteType != mgmt.RouteTypeNextHop {
			t.Fatalf("route_type = %q, want %q", resp.RouteType, mgmt.RouteTypeNextHop)
		}
		if resp.Target != "bastion-2.company.com" {
			t.Errorf("target = %q, want the next bastion", resp.Target)
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
		want := []string{"bastion-0", "bastion-1"}
		if len(resp.Hop.HopTrail) != len(want) {
			t.Fatalf("hop_trail = %v, want %v", resp.Hop.HopTrail, want)
		}
		for i := range want {
			if resp.Hop.HopTrail[i] != want[i] {
				t.Fatalf("hop_trail = %v, want %v (this bastion appended)", resp.Hop.HopTrail, want)
			}
		}
	})

	t.Run("wildcard target route matches any host", func(t *testing.T) {
		svc := &mgmt.Identity{Subject: "svc-deploy@example.com", Login: "svc-deploy", Source: "fixture"}
		resp, err := m.client.Authorize(ctx, &mgmt.AuthorizeRequest{
			Identity: svc, Target: "anything.company.com", Conn: testConn(),
		})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		if resp.FilterPolicy.Mode != mgmt.FilterModeWhitelist {
			t.Errorf("filter mode = %q, want %q", resp.FilterPolicy.Mode, mgmt.FilterModeWhitelist)
		}
		if len(resp.FilterPolicy.Rules) != 3 {
			t.Fatalf("filter rules = %+v, want the three from the fixture", resp.FilterPolicy.Rules)
		}
		if last := resp.FilterPolicy.Rules[2]; last.Action != mgmt.FilterActionKillSession {
			t.Errorf("last rule action = %q, want a whitelist that still escalates on %q",
				last.Action, last.Match)
		}
		if len(resp.PermittedChannels) != 2 {
			t.Errorf("permitted_channels = %v, want session and direct-tcpip", resp.PermittedChannels)
		}
	})

	t.Run("unmatched target is denied", func(t *testing.T) {
		_, err := m.client.Authorize(ctx, &mgmt.AuthorizeRequest{
			Identity: alice, Target: "forbidden.company.com", Conn: testConn(),
		})
		if !mgmt.IsUnauthorized(err) {
			t.Fatalf("error = %v, want a deny", err)
		}
	})

	t.Run("unknown identity is denied", func(t *testing.T) {
		_, err := m.client.Authorize(ctx, &mgmt.AuthorizeRequest{
			Identity: &mgmt.Identity{Subject: "eve@example.com", Login: "eve"},
			Target:   "host.company.com",
			Conn:     testConn(),
		})
		if !mgmt.IsUnauthorized(err) {
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

	resp, err := m.client.Authorize(context.Background(), &mgmt.AuthorizeRequest{
		Identity: &mgmt.Identity{Subject: "alice", Login: "alice"},
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

	report := func(target, fp string) *mgmt.HostKeyReportResponse {
		t.Helper()
		resp, err := m.client.ReportHostKey(ctx, &mgmt.HostKeyReportRequest{
			Target:  target,
			HostKey: mgmt.PublicKeyMaterial{Type: "ssh-ed25519", Fingerprint: fp},
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
	if first.Decision != mgmt.HostKeyAccept {
		t.Errorf("decision = %q, want %q (trust on first use)", first.Decision, mgmt.HostKeyAccept)
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

	unknown, err := m.client.ReportHostKey(ctx, &mgmt.HostKeyReportRequest{
		Target:  "host.company.com",
		HostKey: mgmt.PublicKeyMaterial{Fingerprint: "SHA256:unknown"},
		Conn:    testConn(),
	})
	if err != nil {
		t.Fatalf("ReportHostKey: %v", err)
	}
	if unknown.Decision != mgmt.HostKeyReject {
		t.Errorf("decision = %q, want %q under a rejecting policy", unknown.Decision, mgmt.HostKeyReject)
	}

	trusted, err := m.client.ReportHostKey(ctx, &mgmt.HostKeyReportRequest{
		Target:  "host.company.com",
		HostKey: mgmt.PublicKeyMaterial{Fingerprint: "SHA256:trusted"},
		Conn:    testConn(),
	})
	if err != nil {
		t.Fatalf("ReportHostKey: %v", err)
	}
	if trusted.Decision != mgmt.HostKeyAccept || !trusted.Known {
		t.Errorf("decision/known = %q/%v, want an already-trusted key accepted", trusted.Decision, trusted.Known)
	}
}

func TestLogIngest(t *testing.T) {
	logDir := t.TempDir()
	m := startMock(t, nil, serverOptions{LogDir: logDir})
	ctx := context.Background()

	batch := &mgmt.LogBatchRequest{Records: []mgmt.LogRecord{
		{
			RecordID: "r1", SessionID: "session-1", Timestamp: testConn().Timestamp,
			Kind: mgmt.LogKindSessionStart, Severity: mgmt.SeverityInfo, Login: "alice",
		},
		{
			RecordID: "r2", SessionID: "session-1", Timestamp: testConn().Timestamp,
			Kind: mgmt.LogKindCommand, Severity: mgmt.SeverityInfo,
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

	priority, err := m.client.IngestPriorityLog(ctx, &mgmt.LogPriorityRequest{Record: mgmt.LogRecord{
		RecordID: "r3", SessionID: "session-1", Timestamp: testConn().Timestamp,
		Kind: mgmt.LogKindPolicyDecision, Severity: mgmt.SeverityCritical,
		Message:    "blocked command",
		Attributes: map[string]string{"command": "rm -rf /", "action": string(mgmt.FilterActionBlockCommand)},
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

func TestBastionTokenIsEnforced(t *testing.T) {
	m := startMock(t, nil, serverOptions{})

	wrong, err := mgmt.NewRESTClient(mgmt.Options{BaseURL: m.srv.URL, Token: "not-the-token"})
	if err != nil {
		t.Fatalf("NewRESTClient: %v", err)
	}
	_, err = wrong.ReportHostKey(context.Background(), &mgmt.HostKeyReportRequest{
		Target:  "host.company.com",
		HostKey: mgmt.PublicKeyMaterial{Fingerprint: "SHA256:whatever"},
		Conn:    testConn(),
	})
	if !mgmt.IsUnauthorized(err) {
		t.Fatalf("error = %v, want a deny for a bad bastion token", err)
	}
}

func TestBadRequestsAreRejectedWithoutADeny(t *testing.T) {
	m := startMock(t, nil, serverOptions{})

	// A malformed body is a caller bug, not a policy decision: the server must
	// answer 400 so the bastion does not read it as "access denied".
	req, err := http.NewRequest(http.MethodPost, m.srv.URL+mgmt.PathAuthorize, strings.NewReader(`{"target":`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bastionToken)

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

	if _, err := m.client.AuthenticatePassword(context.Background(), &mgmt.AuthenticatePasswordRequest{
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
	if r.RouteType != string(mgmt.RouteTypeDirect) {
		t.Errorf("route_type = %q, want %q", r.RouteType, mgmt.RouteTypeDirect)
	}
	if r.FilterPolicy.Mode != string(mgmt.FilterModeBlacklist) {
		t.Errorf("filter mode default = %q, want %q", r.FilterPolicy.Mode, mgmt.FilterModeBlacklist)
	}
	if len(r.FilterPolicy.Rules) != 0 {
		t.Errorf("filter rules = %+v, want none by default (a blacklist with no rules filters nothing)",
			r.FilterPolicy.Rules)
	}
	if fx.HostKeys.Decision != string(mgmt.HostKeyAccept) {
		t.Errorf("host_keys.decision = %q, want %q", fx.HostKeys.Decision, mgmt.HostKeyAccept)
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
	alice := &mgmt.Identity{Subject: "alice", Login: "alice"}

	specific, err := m.client.Authorize(ctx, &mgmt.AuthorizeRequest{
		Identity: alice, Target: "host.company.com", Conn: testConn(),
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if specific.Permissions != "specific" {
		t.Errorf("permissions = %q, want the first matching rule to win", specific.Permissions)
	}

	fallback, err := m.client.Authorize(ctx, &mgmt.AuthorizeRequest{
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

	resp, err := m.client.Authorize(context.Background(), &mgmt.AuthorizeRequest{
		Identity: &mgmt.Identity{Subject: "alice", Login: "alice"},
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

func TestNoBastionTokenServesEveryone(t *testing.T) {
	fx := mustParseFixtures(t, `
users:
  - login: alice
    key_fingerprints: ["SHA256:alice"]
`)
	m := startMock(t, fx, serverOptions{})

	anonymous, err := mgmt.NewRESTClient(mgmt.Options{BaseURL: m.srv.URL})
	if err != nil {
		t.Fatalf("NewRESTClient: %v", err)
	}
	if _, err := anonymous.AuthenticateCert(context.Background(), &mgmt.AuthenticateCertRequest{
		Login:     "alice",
		PublicKey: mgmt.PublicKeyMaterial{Fingerprint: "SHA256:alice"},
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
		var rec mgmt.LogRecord
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
