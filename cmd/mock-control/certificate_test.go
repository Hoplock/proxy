// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/auth/target"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/identity"
	"github.com/hoplock/proxy/internal/sshtest"
)

// writeCAKey writes a fresh ed25519 CA key where the fixtures will load it
// from, and returns its path and public half. Generated, never committed.
func writeCAKey(t *testing.T) (string, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	path := filepath.Join(t.TempDir(), "user_ca")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return path, signer.PublicKey()
}

// certificateFixtures is one user, one brokered-certificate route to target
// (resolved to itself), a second route on a brokered-key ladder, and an
// authority at keyPath (none when empty).
func certificateFixtures(t *testing.T, keyPath, fault string) *fixtures {
	t.Helper()
	faultLine := ""
	if fault != "" {
		faultLine = "    certificate_fault: " + fault + "\n"
	}
	doc := `
proxy_token: "` + proxyToken + `"
users:
  - login: svc
    identity: {subject: svc@example.com}
    key_fingerprints: ["SHA256:unused"]
routes:
  - login: svc
    target: pki.company.com
    route_type: direct
    permitted_channels: [session]
    target_auth_ladder:
      - method: brokered-certificate
        params: {username: monitor, lifetime_seconds: "600"}
` + faultLine + `
  - login: svc
    target: standing.company.com
    route_type: direct
    permitted_channels: [session]
    target_auth_ladder:
      - method: brokered-key
        params: {username: monitor}
certificate_authority:
  key_path: "` + keyPath + `"
  lifetime_seconds: 3600
`
	fx, err := parseFixtures(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("parseFixtures: %v", err)
	}
	return fx
}

// authorizeCertified is one authorize call for the certificate route, through
// the real client.
func authorizeCertified(t *testing.T, m *mock, sessionID string) *control.AuthorizeResponse {
	t.Helper()
	conn := testConn()
	conn.SessionID = sessionID
	resp, err := m.client.Authorize(context.Background(), &control.AuthorizeRequest{
		Identity: &control.Identity{Subject: "svc@example.com", Login: "svc"},
		Target:   "pki.company.com",
		Conn:     conn,
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	return resp
}

// certTargetFor is the route as the credential plane sees it: the decision's
// host and id, and its one rung.
func certTargetFor(resp *control.AuthorizeResponse, sessionID string, host *sshtest.Target) target.Target {
	rungs, _ := resp.Ladder()
	rung := rungs[0]
	tgt := target.Target{
		Host:       resp.Target,
		SessionID:  sessionID,
		DecisionID: resp.DecisionID,
		Auth:       &rung,
	}
	if host != nil {
		// The decision named pki.company.com; the stand-in listens on
		// loopback. The issuance has already been bound to the decision's
		// target by then, so only the dial is redirected.
		tgt.Port = host.Port()
		tgt.HostKeyCallback = ssh.FixedHostKey(host.HostKey())
	}
	return tgt
}

// TestTheMockIssuesACertificateAProxyCanLogInWith is the endpoint end to end:
// the real client, the real authenticator, and a target that trusts the mock's
// CA and nothing else. The certificate is over the submitted key, names the
// route's account as its only principal, stays inside the route's bound, and a
// second session gets a second serial.
func TestTheMockIssuesACertificateAProxyCanLogInWith(t *testing.T) {
	keyPath, caPub := writeCAKey(t)
	m := startMock(t, certificateFixtures(t, keyPath, ""), serverOptions{})
	host, err := sshtest.StartTarget(sshtest.Options{TrustedUserCAKeys: []ssh.PublicKey{caPub}})
	if err != nil {
		t.Fatalf("StartTarget: %v", err)
	}
	t.Cleanup(func() { _ = host.Close() })

	auth, err := target.NewBrokeredCertificateAuthenticator(target.BrokeredCertificateOptions{Issuer: m.client})
	if err != nil {
		t.Fatalf("NewBrokeredCertificateAuthenticator: %v", err)
	}

	var serials []string
	for _, session := range []string{"session-a", "session-b"} {
		resp := authorizeCertified(t, m, session)
		access, err := auth.Provision(context.Background(), &identity.Identity{Subject: "svc@example.com"},
			certTargetFor(resp, session, host))
		if err != nil {
			t.Fatalf("%s: Provision: %v", session, err)
		}
		cfg := *access.ClientConfig
		cfg.HostKeyCallback = ssh.FixedHostKey(host.HostKey())
		cfg.Timeout = 10 * time.Second
		client, err := ssh.Dial("tcp", host.Addr().String(), &cfg)
		if err != nil {
			t.Fatalf("%s: the mock's certificate did not log in: %v", session, err)
		}
		_ = client.Close()
		_ = access.Close(context.Background())
		serials = append(serials, access.CertificateSerial)
		if got := m.server.certificatesIssued(session); got != 1 {
			t.Errorf("%s: %d certificates issued, want one per session", session, got)
		}
	}
	if serials[0] == serials[1] {
		t.Errorf("two sessions were issued one serial %q", serials[0])
	}
	a, _ := strconv.ParseUint(serials[0], 10, 64)
	b, _ := strconv.ParseUint(serials[1], 10, 64)
	if b <= a {
		t.Errorf("serials %s then %s; a serial only ever rises", serials[0], serials[1])
	}

	// The certificate itself, read directly off the endpoint.
	signer := sshtest.MustGenerateSigner()
	resp := authorizeCertified(t, m, "session-c")
	issued, err := m.client.IssueCertificate(context.Background(), &control.CertificateRequest{
		SessionID: "session-c", DecisionID: resp.DecisionID, Target: resp.Target, Username: "monitor",
		PublicKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey())),
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(issued.Certificate))
	if err != nil {
		t.Fatalf("the issued certificate does not parse: %v", err)
	}
	cert := parsed.(*ssh.Certificate)
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "monitor" {
		t.Errorf("principals = %v, want only the route's account", cert.ValidPrincipals)
	}
	if bound := time.Now().Add(600 * time.Second); time.Unix(int64(cert.ValidBefore), 0).After(bound) {
		t.Errorf("valid before %v, past the route's 600s bound (the fixture's own 3600s must not win)",
			time.Unix(int64(cert.ValidBefore), 0))
	}
	if issued.ValidBefore.Unix() != int64(cert.ValidBefore) {
		t.Errorf("valid_before %v disagrees with the certificate's %d", issued.ValidBefore, cert.ValidBefore)
	}
	if len(issued.CAPublicKeys) != 1 || !strings.HasPrefix(issued.CAPublicKeys[0], caPub.Type()) {
		t.Errorf("ca_public_keys = %v, want the authority's key", issued.CAPublicKeys)
	}
}

// TestTheMocksDeliberatelyWrongCertificatesAreRefused proves each of the
// proxy's checks against a REAL server answer rather than a hand-built struct:
// every fault is an outage, names its check, and provisions nothing.
func TestTheMocksDeliberatelyWrongCertificatesAreRefused(t *testing.T) {
	keyPath, _ := writeCAKey(t)
	for fault, check := range map[string]string{
		certFaultExceedsLifetime: "valid for longer than the route's lifetime_seconds",
		certFaultWrongKey:        "does not certify the key this session submitted",
		certFaultExpired:         "already expired",
		certFaultMalformed:       "does not parse",
	} {
		t.Run(fault, func(t *testing.T) {
			m := startMock(t, certificateFixtures(t, keyPath, fault), serverOptions{})
			auth, err := target.NewBrokeredCertificateAuthenticator(target.BrokeredCertificateOptions{Issuer: m.client})
			if err != nil {
				t.Fatalf("NewBrokeredCertificateAuthenticator: %v", err)
			}
			resp := authorizeCertified(t, m, "session-f")
			_, err = auth.Provision(context.Background(), &identity.Identity{Subject: "svc@example.com"},
				certTargetFor(resp, "session-f", nil))
			if !errors.Is(err, target.ErrCertificateUnavailable) {
				t.Fatalf("error = %v, want ErrCertificateUnavailable", err)
			}
			if control.IsUnauthorized(err) {
				t.Errorf("error = %v reads as a denial", err)
			}
			if !strings.Contains(err.Error(), check) {
				t.Errorf("error = %q, want it to name %q", err, check)
			}
		})
	}
}

// TestTheMockRefusesAnIssuanceItCannotBind: an issuance is cross-checked
// against the decision it cites, never trusted — and a tenant with no
// authority answers 503. Every one of these reaches the proxy as an outage.
func TestTheMockRefusesAnIssuanceItCannotBind(t *testing.T) {
	keyPath, _ := writeCAKey(t)
	m := startMock(t, certificateFixtures(t, keyPath, ""), serverOptions{})
	resp := authorizeCertified(t, m, "session-x")
	key := string(ssh.MarshalAuthorizedKey(sshtest.MustGenerateSigner().PublicKey()))

	for name, tc := range map[string]struct {
		req  control.CertificateRequest
		want error
	}{
		"no decision id": {control.CertificateRequest{
			SessionID: "s", Target: resp.Target, Username: "monitor", PublicKey: key}, control.ErrUnauthorized},
		"a decision this server never made": {control.CertificateRequest{
			SessionID: "s", DecisionID: "decision-999", Target: resp.Target, Username: "monitor", PublicKey: key}, control.ErrUnauthorized},
		"another account than the decision named": {control.CertificateRequest{
			SessionID: "s", DecisionID: resp.DecisionID, Target: resp.Target, Username: "root", PublicKey: key}, control.ErrUnauthorized},
		"another target than the decision named": {control.CertificateRequest{
			SessionID: "s", DecisionID: resp.DecisionID, Target: "elsewhere", Username: "monitor", PublicKey: key}, control.ErrUnauthorized},
		"not a public key": {control.CertificateRequest{
			SessionID: "s", DecisionID: resp.DecisionID, Target: resp.Target, Username: "monitor", PublicKey: "nope"}, control.ErrBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			req := tc.req
			if _, err := m.client.IssueCertificate(context.Background(), &req); !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want %v", err, tc.want)
			}
		})
	}

	// A decision for a route that names no brokered-certificate rung licenses
	// no certificate either.
	standing, err := m.client.Authorize(context.Background(), &control.AuthorizeRequest{
		Identity: &control.Identity{Subject: "svc@example.com", Login: "svc"},
		Target:   "standing.company.com",
		Conn:     testConn(),
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if _, err := m.client.IssueCertificate(context.Background(), &control.CertificateRequest{
		SessionID: "s", DecisionID: standing.DecisionID, Target: standing.Target, Username: "monitor", PublicKey: key,
	}); !errors.Is(err, control.ErrUnauthorized) {
		t.Errorf("an issuance citing a brokered-key decision = %v, want a refusal", err)
	}

	t.Run("no authority", func(t *testing.T) {
		m := startMock(t, certificateFixtures(t, "", ""), serverOptions{})
		resp := authorizeCertified(t, m, "session-y")
		_, err := m.client.IssueCertificate(context.Background(), &control.CertificateRequest{
			SessionID: "s", DecisionID: resp.DecisionID, Target: resp.Target, Username: "monitor", PublicKey: key,
		})
		var apiErr *control.APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != 503 {
			t.Fatalf("error = %v, want a 503 from a tenant with no authority", err)
		}
		auth, err := target.NewBrokeredCertificateAuthenticator(target.BrokeredCertificateOptions{Issuer: m.client})
		if err != nil {
			t.Fatalf("NewBrokeredCertificateAuthenticator: %v", err)
		}
		if _, err := auth.Provision(context.Background(), &identity.Identity{Subject: "svc@example.com"},
			certTargetFor(resp, "session-y", nil)); !errors.Is(err, target.ErrCertificateUnavailable) {
			t.Errorf("Provision against a tenant with no authority = %v, want an outage", err)
		}
	})
}

// TestCertificateFixturesAreChecked: a fault on a route that cannot use it, a
// fault this mock cannot produce, and a key it cannot load all stop the mock
// at startup rather than at the first session.
func TestCertificateFixturesAreChecked(t *testing.T) {
	keyPath, _ := writeCAKey(t)
	for name, doc := range map[string]string{
		"a fault on a route with no certificate rung": `
routes:
  - login: svc
    target: standing.company.com
    target_auth_ladder:
      - method: brokered-key
        params: {username: monitor}
    certificate_fault: expired
`,
		"a fault the mock cannot produce": `
routes:
  - login: svc
    target: pki.company.com
    target_auth_ladder:
      - method: brokered-certificate
        params: {username: monitor}
    certificate_fault: slightly-wrong
certificate_authority: {key_path: "` + keyPath + `"}
`,
		"a key that is not there": `
certificate_authority: {key_path: "/nonexistent/user_ca"}
`,
		"a negative lifetime": `
certificate_authority: {key_path: "` + keyPath + `", lifetime_seconds: -1}
`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseFixtures(strings.NewReader(doc)); err == nil {
				t.Fatal("the fixtures were accepted")
			}
		})
	}
}
