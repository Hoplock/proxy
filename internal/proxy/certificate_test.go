// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/auth/target"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/logging"
	"github.com/hoplock/proxy/internal/routing"
	"github.com/hoplock/proxy/internal/sshtest"
)

// certificateHarness is a proxy whose route names brokered-certificate, in
// front of a target that trusts one CA and nothing else — so a session that
// runs at all ran on a certificate that CA minted.
func certificateHarness(t *testing.T, cache *control.CacheHint, options func(*Options)) (*harness, *sshtest.CertificateAuthority) {
	t.Helper()
	ca, err := sshtest.NewCertificateAuthority()
	if err != nil {
		t.Fatalf("NewCertificateAuthority: %v", err)
	}
	certAuth, err := target.NewBrokeredCertificateAuthenticator(target.BrokeredCertificateOptions{Issuer: ca})
	if err != nil {
		t.Fatalf("NewBrokeredCertificateAuthenticator: %v", err)
	}
	selector, err := target.NewSelector(map[string]target.TargetAuthenticator{
		target.MethodBrokeredCertificate: certAuth,
	}, target.MethodBrokeredCertificate, nil)
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}
	h := newHarness(t, harnessOptions{
		targetAuth:    selector,
		targetOptions: sshtest.Options{TrustedUserCAKeys: []ssh.PublicKey{ca.PublicKey()}},
		targetAuthLadder: &control.TargetAuthLadder{{
			Method: control.TargetAuthBrokeredCertificate,
			Params: map[string]string{target.ParamUsername: testTargetAccount, target.ParamLifetimeSeconds: "300"},
		}},
		cache:   cache,
		options: options,
	})
	return h, ca
}

// TestABrokeredCertificateSessionRecordsItsSerialAndNotItsCertificate is the
// proxy half of phase 0044: decision_id reaches the issuer, the session runs on
// the certificate, and the record names the method and the serial — the join
// key to Hoplock Control's own row — and nothing else about the credential.
func TestABrokeredCertificateSessionRecordsItsSerialAndNotItsCertificate(t *testing.T) {
	h, ca := certificateHarness(t, nil, nil)

	if out, status := runAndCollect(t, h, "uptime"); status != 0 {
		t.Fatalf("session status %d (%q), want the command to run on the certificate", status, out)
	}

	requests := ca.Requests()
	if len(requests) != 1 {
		t.Fatalf("%d issuance requests, want one", len(requests))
	}
	if got := requests[0]; got.DecisionID != "decision-1" || got.SessionID != testSessionID || got.Username != testTargetAccount {
		t.Errorf("issuance request = %+v; want the route's decision id, this session's id and the route's username", got)
	}

	accepted := h.target.CertificateSerials()
	if len(accepted) != 1 {
		t.Fatalf("the target accepted %d certificates, want one", len(accepted))
	}
	serial := strconv.FormatUint(accepted[0], 10)

	rec, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Kind == control.LogKindProvisioning && r.Attributes[logging.AttrCredentialMethod] != ""
	})
	if !ok {
		t.Fatal("no provisioning record named the credential method")
	}
	if got := rec.Attributes[logging.AttrCredentialMethod]; got != target.MethodBrokeredCertificate {
		t.Errorf("record %s = %q, want %q", logging.AttrCredentialMethod, got, target.MethodBrokeredCertificate)
	}
	if got := rec.Attributes[logging.AttrCredentialCertificateSerial]; got != serial {
		t.Errorf("record %s = %q, want the serial the target accepted, %q",
			logging.AttrCredentialCertificateSerial, got, serial)
	}

	// Nothing about the certificate but its serial reaches ANY record, nor the
	// proxy's own log.
	issued := ca.Issued()
	submitted := requests[0].PublicKey
	for _, r := range h.records() {
		encoded, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		for _, secretish := range []string{strings.Fields(issued[0])[1], strings.Fields(submitted)[1]} {
			if strings.Contains(string(encoded), secretish) {
				t.Errorf("a %s record carries the certificate or the session key", r.Kind)
			}
		}
	}
	for _, secretish := range []string{strings.Fields(issued[0])[1], strings.Fields(submitted)[1]} {
		if strings.Contains(h.logs.String(), secretish) {
			t.Error("the proxy's log carries the certificate or the session key")
		}
	}
}

// TestAReusedDecisionIsIssuedANewCertificatePerSession is the acceptance
// criterion the whole shape of phase 0044 exists for: an authorize decision
// Hoplock Control allowed to be reused serves two connections from ONE
// authorize call — and each connection still gets its own certificate, over
// its own key, under its own serial. A certificate carried on the decision
// would have been replayed; this one cannot be.
func TestAReusedDecisionIsIssuedANewCertificatePerSession(t *testing.T) {
	var cache *control.CachingClient
	h, ca := certificateHarness(t, &control.CacheHint{Key: "decision-reused", TTLSeconds: 300}, func(o *Options) {
		uniqueSessionIDs(o)
		cache = control.NewCachingClient(o.Client, control.CacheOptions{})
		cache.StreamAlive(time.Now())
		resolver, err := routing.NewResolver(routing.ResolverOptions{Client: cache})
		if err != nil {
			t.Fatalf("NewResolver: %v", err)
		}
		o.Resolver = resolver
	})

	for i := 0; i < 2; i++ {
		cache.StreamAlive(time.Now())
		if out, status := runAndCollect(t, h, "uptime"); status != 0 {
			t.Fatalf("session %d status %d (%q)", i+1, status, out)
		}
	}

	if n := len(h.client.authorizeRequests()); n != 1 {
		t.Fatalf("%d authorize calls, want one decision reused for both sessions", n)
	}
	if hits := cache.Stats().Hits; hits != 1 {
		t.Fatalf("cache hits = %d, want the second session served from the cached decision", hits)
	}
	requests := ca.Requests()
	if len(requests) != 2 {
		t.Fatalf("%d issuance requests, want one per session", len(requests))
	}
	if requests[0].SessionID == requests[1].SessionID || requests[0].PublicKey == requests[1].PublicKey {
		t.Error("the two issuances share a session id or a key; each session must be certified on its own")
	}
	if requests[0].DecisionID != requests[1].DecisionID {
		t.Error("the reused decision sent two different decision ids; it is one decision")
	}
	serials := h.target.CertificateSerials()
	if len(serials) != 2 || serials[0] == serials[1] {
		t.Fatalf("the target accepted serials %v, want two distinct ones", serials)
	}

	// And the records carry the two different serials.
	recorded := map[string]bool{}
	for _, r := range h.records() {
		if s := r.Attributes[logging.AttrCredentialCertificateSerial]; s != "" {
			recorded[s] = true
		}
	}
	for _, s := range serials {
		if !recorded[strconv.FormatUint(s, 10)] {
			t.Errorf("no record carries serial %d; recorded %v", s, recorded)
		}
	}
}

// TestARefusedCertificateIsAnOutageForTheUser: a certificate the proxy will not
// use ends the session as an outage — never "access denied", which would send
// the user to argue about a permission nobody withdrew.
func TestARefusedCertificateIsAnOutageForTheUser(t *testing.T) {
	h, ca := certificateHarness(t, nil, nil)
	ca.SetFault(sshtest.CertificateFaultTooLong)

	out, status := runAndCollect(t, h, "uptime")
	if status == 0 {
		t.Fatal("a session ran on a certificate that widened the route's lifetime bound")
	}
	if strings.Contains(out, "denied") {
		t.Errorf("the user was told %q; a refused certificate is an outage, not a denial", out)
	}
	if !strings.Contains(out, testSessionID) {
		t.Errorf("the outage message %q does not carry the session id as a support reference", out)
	}
	if n := len(h.target.Logins()); n != 0 {
		t.Errorf("the target saw %d login attempts; nothing may be dialled on a refused certificate", n)
	}
}
