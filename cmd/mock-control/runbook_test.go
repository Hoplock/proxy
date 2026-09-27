// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/auth/target"
	"github.com/hoplock/proxy/internal/auth/user"
	"github.com/hoplock/proxy/internal/config"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/logging"
	"github.com/hoplock/proxy/internal/proxy"
	"github.com/hoplock/proxy/internal/routing"
	"github.com/hoplock/proxy/internal/sshtest"
)

// This file runs the emergency runbook api/README.md writes down for the day an
// advisory lands (phase 0045), against the contract as the mock serves it and a
// real proxy with a real decision cache and revocation stream:
//
//  1. Control adds the ban to the route's policy;
//  2. Control sends cache_invalidate with all, because a cached decision keeps
//     the old policy until its TTL and the proxy never overrides a decision;
//  3. sessions already running keep what they negotiated, and Control ends
//     them with session_kill, found by the negotiated attributes.

// editRoute changes the route matching target while the server runs.
func (s *server) editRoute(t *testing.T, targetHost string, edit func(*fixtureRoute)) {
	t.Helper()
	s.routesMu.Lock()
	defer s.routesMu.Unlock()
	for i := range s.fx.Routes {
		if s.fx.Routes[i].Target == targetHost {
			edit(&s.fx.Routes[i])
			return
		}
	}
	t.Fatalf("no route for %s", targetHost)
}

func TestTheEmergencyRunbookWorksAsWritten(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The target offers two ciphers the default profile does; a route with no
	// ban negotiates the first, aes128-ctr.
	tgt, err := sshtest.StartTarget(sshtest.Options{Negotiation: sshtest.Negotiation{Ciphers: []string{"aes128-ctr", "aes256-ctr"}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tgt.Close() })
	clientKey := sshtest.MustGenerateSigner()

	fx := &fixtures{
		ProxyToken: "runbook-token",
		Users: []fixtureUser{{Login: "alice", Identity: fixtureIdentity{Subject: "alice@example.com", Source: "fixture"},
			KeyFingerprints: []string{ssh.FingerprintSHA256(clientKey.PublicKey())}}},
		Routes: []fixtureRoute{{
			Login: "alice", Target: tgt.Host(), RouteType: string(control.RouteTypeDirect), TargetPort: tgt.Port(),
			PermittedChannels: []string{"session"}, FilterPolicy: fixtureFilterPolicy{Mode: string(control.FilterModeBlacklist)},
			// A decision reused for five minutes: long enough that only step 2
			// can make the ban take effect.
			Cache: fixtureCacheHint{TTLSeconds: 300},
		}},
		HostKeys: fixtureHostKeys{Decision: string(control.HostKeyAccept)},
		Events:   fixtureEvents{HeartbeatMS: 20},
	}
	if err := fx.validate(); err != nil {
		t.Fatalf("fixtures: %v", err)
	}
	m := startMock(t, fx, serverOptions{})

	// The proxy: a server-authorised decision cache, and the revocation stream
	// that both invalidates it and ends sessions.
	cache := control.NewCachingClient(m.client, control.CacheOptions{})
	userAuth, err := user.NewFromConfig(config.UserAuth{Methods: []string{string(control.AuthMethodCert)}}, user.Options{Client: m.client})
	if err != nil {
		t.Fatal(err)
	}
	static, err := target.NewStaticKeyAuthenticator(target.StaticKeyOptions{Signer: sshtest.MustGenerateSigner(), Username: "svc-target"})
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := routing.NewResolver(routing.ResolverOptions{Client: cache, Capabilities: target.ProxyCapabilities()})
	if err != nil {
		t.Fatal(err)
	}
	recorder, err := logging.New(logging.Options{Client: m.client, BatchSize: 1, FlushInterval: 10 * time.Millisecond,
		BufferDir: t.TempDir(), Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeCtx, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_ = recorder.Close(closeCtx)
	})
	var sessions atomic.Int32
	server, err := proxy.New(proxy.Options{
		HostKey: sshtest.MustGenerateSigner(), Authenticator: userAuth, Resolver: resolver, TargetAuth: static,
		Client: cache, ProxyID: "proxy-runbook", TargetDelimiter: config.DefaultTargetDelimiter, Recorder: recorder,
		NewSessionID: func() string { return fmt.Sprintf("sess-runbook-%d", sessions.Add(1)) },
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(ctx, listener) }()
	stream := control.NewRevocationStream(m.client, cache, server, control.StreamOptions{HeartbeatTimeout: time.Second})
	go func() { _ = stream.Subscribe(ctx, "proxy-runbook") }()
	waitUntil(t, "the revocation stream to connect", func() bool { return !cache.StreamStale() })

	dial := func() *ssh.Client {
		t.Helper()
		client, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{
			User: "alice" + config.DefaultTargetDelimiter + tgt.Host(), Auth: []ssh.AuthMethod{ssh.PublicKeys(clientKey)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 10 * time.Second, //nolint:gosec // the proxy under test
		})
		if err != nil {
			t.Fatalf("dial the proxy: %v", err)
		}
		return client
	}
	runOne := func() {
		t.Helper()
		client := dial()
		defer func() { _ = client.Close() }()
		session, err := client.NewSession()
		if err != nil {
			t.Fatalf("new session: %v", err)
		}
		if err := session.Run("true"); err != nil {
			t.Fatalf("run: %v", err)
		}
	}
	// negotiated is the cipher the session's leg negotiated, from the records
	// Hoplock Control holds — the attribute the runbook finds sessions by.
	negotiated := func(sessionID string) (cipher string, bans string) {
		t.Helper()
		var rec *control.LogRecord
		waitUntil(t, "the negotiated record of "+sessionID, func() bool {
			for _, r := range m.debugLogs(t).Batched {
				if r.SessionID == sessionID && r.Attributes[logging.AttrEvent] == logging.EventAlgorithmsNegotiated {
					r := r
					rec = &r
					return true
				}
			}
			return false
		})
		return rec.Attributes[logging.AttrTargetCipherOut], rec.Attributes[logging.AttrAlgorithmBansPrefix+"ciphers"]
	}

	// A session opened BEFORE the advisory, and held open.
	held := dial()
	defer func() { _ = held.Close() }()
	heldSession, err := held.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := heldSession.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close() }()
	if err := heldSession.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}
	heldEnded := make(chan error, 1)
	go func() { heldEnded <- heldSession.Wait() }()
	if cipher, _ := negotiated("sess-runbook-1"); cipher != "aes128-ctr" {
		t.Fatalf("the held session negotiated %q, want aes128-ctr", cipher)
	}

	// A second session is served from the cached decision.
	runOne()
	if cipher, _ := negotiated("sess-runbook-2"); cipher != "aes128-ctr" {
		t.Fatalf("second session negotiated %q", cipher)
	}
	if cache.Stats().Hits == 0 {
		t.Fatal("the second session did not reuse the cached decision; the runbook's step 2 would prove nothing")
	}

	// Step 1: the advisory, and Control bans the cipher on the route.
	m.server.editRoute(t, tgt.Host(), func(r *fixtureRoute) {
		r.AlgorithmBans = &fixtureAlgorithmBans{Ciphers: []string{"aes128-ctr"}}
	})
	// Without step 2 the cached decision still carries the old policy.
	runOne()
	if cipher, _ := negotiated("sess-runbook-3"); cipher != "aes128-ctr" {
		t.Fatalf("before cache_invalidate the cached decision gave %q; the test's premise is wrong", cipher)
	}

	// Step 2: cache_invalidate all. The next connection runs under the ban.
	m.revoke(t, control.RevocationEvent{Type: control.EventTypeCacheInvalidate,
		CacheInvalidate: &control.CacheInvalidateEvent{All: true}})
	waitUntil(t, "the cache to be invalidated", func() bool { return cache.Stats().Entries == 0 })
	runOne()
	if cipher, bans := negotiated("sess-runbook-4"); cipher != "aes256-ctr" || bans != "aes128-ctr" {
		t.Fatalf("after cache_invalidate the session negotiated %q under bans %q, want aes256-ctr under the ban", cipher, bans)
	}

	// Step 3: the session opened before the ban still runs on what it
	// negotiated. Control finds every OPEN session whose target_cipher_out is
	// the banned cipher — negotiated records with no session_end — and ends it.
	select {
	case err := <-heldEnded:
		t.Fatalf("the held session ended before anyone killed it: %v", err)
	default:
	}
	logs := m.debugLogs(t)
	ended := map[string]bool{}
	for _, r := range append(logs.Batched, logs.Priority...) {
		if r.Kind == control.LogKindSessionEnd {
			ended[r.SessionID] = true
		}
	}
	var open []string
	for _, r := range logs.Batched {
		if r.Attributes[logging.AttrEvent] == logging.EventAlgorithmsNegotiated &&
			r.Attributes[logging.AttrTargetCipherOut] == "aes128-ctr" && !ended[r.SessionID] {
			open = append(open, r.SessionID)
		}
	}
	if len(open) != 1 || open[0] != "sess-runbook-1" {
		t.Fatalf("open sessions on the banned cipher = %q, want only the held one", open)
	}
	const reason = "Ended by the security team: aes128-ctr is subject to an advisory; reconnect to continue."
	m.revoke(t, control.RevocationEvent{Type: control.EventTypeSessionKill,
		SessionKill: &control.SessionKillEvent{SessionIDs: open, Reason: reason}})
	select {
	case <-heldEnded:
	case <-time.After(10 * time.Second):
		t.Fatal("session_kill did not end the session running on the banned cipher")
	}
	waitUntil(t, "the held session's end to be recorded", func() bool {
		for _, r := range m.debugLogs(t).Batched {
			if r.SessionID == "sess-runbook-1" && r.Kind == control.LogKindSessionEnd {
				return r.Attributes[logging.AttrEndReason] == logging.EndReasonRevoked
			}
		}
		return false
	})
}
