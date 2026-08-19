// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// eventFixtures is a minimal world with one cacheable route and a fast
// heartbeat, so a test can tell a live subscription from a hung one quickly.
const eventFixtures = `
proxy_token: "dev-proxy-token"
users:
  - login: alice
    identity:
      subject: alice@example.com
    password: "alice-dev-password"
routes:
  - login: alice
    target: host.company.com
    route_type: direct
    permissions: readOnlyGroup
    permitted_channels: [session]
    filter_policy:
      mode: blacklist
    cache:
      ttl_seconds: 600
events:
  heartbeat_ms: 20
  replay_buffer: 64
`

// recordingRegistry stands in for the proxy's session registry (phase 0005).
type recordingRegistry struct {
	mu    sync.Mutex
	kills []string
}

func (r *recordingRegistry) record(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.kills = append(r.kills, s)
}

func (r *recordingRegistry) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.kills...)
}

func (r *recordingRegistry) KillSession(_ context.Context, id, reason string) error {
	r.record("session:" + id + ":" + reason)
	return nil
}

func (r *recordingRegistry) KillSubject(_ context.Context, subject, reason string) error {
	r.record("subject:" + subject + ":" + reason)
	return nil
}

func (r *recordingRegistry) KillAll(_ context.Context, reason string) error {
	r.record("all:" + reason)
	return nil
}

// revoke publishes an event through the mock-only debug endpoint and returns
// how many subscribers it reached.
func (m *mock) revoke(t *testing.T, ev control.RevocationEvent) debugRevokeResponse {
	t.Helper()
	body, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("encode event: %v", err)
	}
	resp, err := http.Post(m.srv.URL+pathDebugRevoke, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", pathDebugRevoke, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s: status %d", pathDebugRevoke, resp.StatusCode)
	}
	var out debugRevokeResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode revoke response: %v", err)
	}
	return out
}

// waitUntil polls cond until it holds or the test gives up.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestAuthorizeCarriesTheFixtureCacheHint(t *testing.T) {
	m := startMock(t, nil, serverOptions{})
	ctx := context.Background()

	// fixtures.example.yaml opts alice's direct route into caching.
	resp, err := m.client.Authorize(ctx, &control.AuthorizeRequest{
		Identity: &control.Identity{Subject: "alice@example.com", Login: "alice"},
		Target:   "host.company.com",
		Conn:     testConn(),
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if resp.Cache == nil {
		t.Fatal("a route with a cache fixture returned no hint")
	}
	if resp.Cache.TTLSeconds != 60 {
		t.Errorf("ttl_seconds = %d, want 60", resp.Cache.TTLSeconds)
	}
	// The derived key is per (subject, target): a key is never shared across
	// identities.
	if want := "authz:alice@example.com:host.company.com"; resp.Cache.Key != want {
		t.Errorf("cache key = %q, want %q", resp.Cache.Key, want)
	}

	// A route with no cache fixture must not be cacheable at all.
	resp, err = m.client.Authorize(ctx, &control.AuthorizeRequest{
		Identity: &control.Identity{Subject: "svc-deploy@example.com", Login: "svc-deploy"},
		Target:   "build.company.com",
		Conn:     testConn(),
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if resp.Cache != nil {
		t.Errorf("cache = %+v, want no hint: a route must opt in", resp.Cache)
	}
}

// TestRevocationEndsACachedDecisionAndItsSessions is the end-to-end shape of
// phase 0003: a proxy holding a server-authorised cache, subscribed to the
// event stream, is told to kill a subject's sessions — and both halves happen.
func TestRevocationEndsACachedDecisionAndItsSessions(t *testing.T) {
	m := startMock(t, mustParseFixtures(t, eventFixtures), serverOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cache := control.NewCachingClient(m.client, control.CacheOptions{})
	registry := &recordingRegistry{}
	stream := control.NewRevocationStream(m.client, cache, registry, control.StreamOptions{
		HeartbeatTimeout: time.Second, // the fixture heartbeats every 20ms
	})
	subscribed := make(chan error, 1)
	go func() { subscribed <- stream.Subscribe(ctx, "proxy-1") }()

	// The cache is dead until the proxy can hear revocations, so a live
	// subscription is also the signal that the stream is up.
	waitUntil(t, "the revocation stream to connect", func() bool { return !cache.StreamStale() })

	req := &control.AuthorizeRequest{
		Identity: &control.Identity{Subject: "alice@example.com", Login: "alice"},
		Target:   "host.company.com",
		Conn:     testConn(),
	}
	first, err := cache.Authorize(ctx, req)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	cached, err := cache.Authorize(ctx, req)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	// Every fresh decision gets its own decision_id, so an identical one means
	// the second call never reached the server.
	if cached.DecisionID != first.DecisionID {
		t.Fatalf("decision_id = %q then %q; the second call should have been a cache hit",
			first.DecisionID, cached.DecisionID)
	}

	const reason = "Access withdrawn by the security team; contact #security."
	delivered := m.revoke(t, control.RevocationEvent{
		Type:        control.EventTypeSessionKill,
		SessionKill: &control.SessionKillEvent{Subject: "alice@example.com", Reason: reason},
	})
	if delivered.Delivered != 1 {
		t.Errorf("the event reached %d subscribers, want 1", delivered.Delivered)
	}
	if delivered.EventID == "" {
		t.Error("the server assigned no event id")
	}

	waitUntil(t, "the session kill to reach the registry", func() bool {
		return len(registry.all()) > 0
	})
	if got, want := registry.all()[0], "subject:alice@example.com:"+reason; got != want {
		t.Errorf("registry recorded %q, want %q — the operator's reason must arrive intact", got, want)
	}

	// The kill also dropped the cached decision, so a reconnecting user is
	// re-authorized rather than let straight back in.
	waitUntil(t, "the cached decision to be dropped", func() bool {
		return cache.Stats().Entries == 0
	})
	reauthorized, err := cache.Authorize(ctx, req)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if reauthorized.DecisionID == first.DecisionID {
		t.Errorf("decision_id = %q again; the revoked decision was served from cache", reauthorized.DecisionID)
	}

	cancel()
	if err := <-subscribed; err != nil {
		t.Errorf("Subscribe returned %v, want nil after cancellation", err)
	}
}

func TestEventStreamHeartbeats(t *testing.T) {
	m := startMock(t, mustParseFixtures(t, eventFixtures), serverOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream, err := m.client.StreamEvents(ctx, "proxy-1", "")
	if err != nil {
		t.Fatalf("StreamEvents: %v", err)
	}
	defer func() { _ = stream.Close() }()

	for i := 0; i < 2; i++ {
		ev, err := stream.Recv()
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		if ev.Type != control.EventTypeHeartbeat {
			t.Fatalf("event %d type = %q, want a heartbeat", i, ev.Type)
		}
		if ev.EventID == "" || ev.Timestamp.IsZero() {
			t.Errorf("heartbeat = %+v, want an id and a timestamp", ev)
		}
	}
}

// TestEventStreamReplaysTheGap covers the reconnect contract: the proxy sends
// the last id it processed, and the server replays what came after it.
func TestEventStreamReplaysTheGap(t *testing.T) {
	// Heartbeats off, so the stream carries exactly the replayed events.
	fx := mustParseFixtures(t, eventFixtures+"\n")
	fx.Events.HeartbeatMS = -1
	m := startMock(t, fx, serverOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	first := m.revoke(t, control.RevocationEvent{
		Type:            control.EventTypeCacheInvalidate,
		CacheInvalidate: &control.CacheInvalidateEvent{Keys: []string{"k1"}},
	})
	second := m.revoke(t, control.RevocationEvent{
		Type:            control.EventTypeCacheInvalidate,
		CacheInvalidate: &control.CacheInvalidateEvent{Keys: []string{"k2"}},
	})

	stream, err := m.client.StreamEvents(ctx, "proxy-1", first.EventID)
	if err != nil {
		t.Fatalf("StreamEvents: %v", err)
	}
	defer func() { _ = stream.Close() }()

	ev, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if ev.EventID != second.EventID {
		t.Errorf("replayed %q, want only what came after the last processed event (%q)",
			ev.EventID, second.EventID)
	}
	if ev.CacheInvalidate == nil || len(ev.CacheInvalidate.Keys) != 1 || ev.CacheInvalidate.Keys[0] != "k2" {
		t.Errorf("replayed payload = %+v, want the k2 invalidation", ev.CacheInvalidate)
	}
}

// TestEventStreamResyncsWhenTheGapIsTooOld is the other half of gap recovery:
// the server decides, and when it cannot replay it says so first.
func TestEventStreamResyncsWhenTheGapIsTooOld(t *testing.T) {
	fx := mustParseFixtures(t, eventFixtures+"\n")
	fx.Events.HeartbeatMS = -1
	fx.Events.ReplayBuffer = 1
	m := startMock(t, fx, serverOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var first debugRevokeResponse
	for i := 0; i < 3; i++ {
		ev := m.revoke(t, control.RevocationEvent{
			Type:            control.EventTypeCacheInvalidate,
			CacheInvalidate: &control.CacheInvalidateEvent{All: true},
		})
		if i == 0 {
			first = ev
		}
	}

	stream, err := m.client.StreamEvents(ctx, "proxy-1", first.EventID)
	if err != nil {
		t.Fatalf("StreamEvents: %v", err)
	}
	defer func() { _ = stream.Close() }()

	ev, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if ev.Type != control.EventTypeResync {
		t.Errorf("first event = %q, want a resync: the server cannot replay that far back", ev.Type)
	}

	// An id this server never issued is treated the same way.
	unknown, err := m.client.StreamEvents(ctx, "proxy-1", "not-an-event-id")
	if err != nil {
		t.Fatalf("StreamEvents: %v", err)
	}
	defer func() { _ = unknown.Close() }()
	ev, err = unknown.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if ev.Type != control.EventTypeResync {
		t.Errorf("first event = %q, want a resync for an unknown last_event_id", ev.Type)
	}
}

func TestEventStreamRequiresTheProxyToken(t *testing.T) {
	m := startMock(t, mustParseFixtures(t, eventFixtures), serverOptions{})
	client, err := control.NewRESTClient(control.Options{BaseURL: m.srv.URL, Token: "wrong-token"})
	if err != nil {
		t.Fatalf("NewRESTClient: %v", err)
	}

	_, err = client.StreamEvents(context.Background(), "proxy-1", "")
	if !control.IsUnauthorized(err) {
		t.Errorf("StreamEvents error = %v, want a deny", err)
	}
}

func TestDebugRevokeRejectsAnUnusableEvent(t *testing.T) {
	m := startMock(t, mustParseFixtures(t, eventFixtures), serverOptions{})

	tests := []struct {
		name string
		body string
	}{
		{"unknown type", `{"type":"explode"}`},
		{"session_kill without a payload", `{"type":"session_kill"}`},
		{"cache_invalidate without a payload", `{"type":"cache_invalidate"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Post(m.srv.URL+pathDebugRevoke, "application/json", bytes.NewReader([]byte(tc.body)))
			if err != nil {
				t.Fatalf("POST %s: %v", pathDebugRevoke, err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
		})
	}
}

func TestEventFixtureValidation(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "a cache key without a lifetime",
			yaml: "users:\n  - login: a\n    password: p\nroutes:\n  - login: a\n    cache:\n      key: k\n",
			want: "ttl_seconds is 0",
		},
		{
			name: "a negative cache lifetime",
			yaml: "users:\n  - login: a\n    password: p\nroutes:\n  - login: a\n    cache:\n      ttl_seconds: -5\n",
			want: "must not be negative",
		},
		{
			name: "a negative replay buffer",
			yaml: "users:\n  - login: a\n    password: p\nevents:\n  replay_buffer: -1\n",
			want: "replay_buffer must not be negative",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseFixtures(strings.NewReader(tc.yaml))
			if err == nil {
				t.Fatal("parseFixtures accepted an invalid fixture")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestEventFixtureDefaults(t *testing.T) {
	fx := mustParseFixtures(t, "users:\n  - login: a\n    password: p\nroutes:\n  - login: a\n")
	if fx.Events.HeartbeatMS != defaultHeartbeatMS {
		t.Errorf("heartbeat_ms = %d, want the default %d", fx.Events.HeartbeatMS, defaultHeartbeatMS)
	}
	if fx.Events.ReplayBuffer != defaultReplayBuffer {
		t.Errorf("replay_buffer = %d, want the default %d", fx.Events.ReplayBuffer, defaultReplayBuffer)
	}
	if fx.Routes[0].Cache.TTLSeconds != 0 {
		t.Errorf("cache ttl = %d, want 0: a route must opt into caching", fx.Routes[0].Cache.TTLSeconds)
	}
}
