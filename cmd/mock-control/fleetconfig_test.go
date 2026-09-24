// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/config"
	"github.com/hoplock/proxy/internal/control"
)

// publishConfig publishes a document through the mock-only debug endpoint.
func (m *mock) publishConfig(t *testing.T, version string, settings map[string]any) debugConfigResponse {
	t.Helper()
	body, err := json.Marshal(fixtureConfigDocument{Version: version, Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(m.srv.URL+pathDebugConfig, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", pathDebugConfig, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s: status %d", pathDebugConfig, resp.StatusCode)
	}
	var out debugConfigResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// recordingFleet is the proxy's real applier, recording the cache clamp of
// every document it actually applied — each test document sets a distinct one.
type recordingFleet struct {
	inner *config.Fleet
	mu    sync.Mutex
	ttls  []string
}

func (r *recordingFleet) ApplyConfig(s map[string]json.RawMessage) ([]string, error) {
	restart, err := r.inner.ApplyConfig(s)
	if err == nil && len(restart) == 0 {
		r.mu.Lock()
		r.ttls = append(r.ttls, r.inner.Current().Control.Cache.MaxTTL.String())
		r.mu.Unlock()
	}
	return restart, err
}

func (r *recordingFleet) applied() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.ttls)
}

// notifications wraps the sync to record every config_changed the stream
// delivered, so the test can prove the replay really happened.
type notifications struct {
	*control.ConfigSync
	mu     sync.Mutex
	hashes []string
}

func (n *notifications) ConfigChanged(ev *control.ConfigChangedEvent) {
	n.mu.Lock()
	n.hashes = append(n.hashes, ev.Hash)
	n.mu.Unlock()
	n.ConfigSync.ConfigChanged(ev)
}

func (n *notifications) seen() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.hashes)
}

// TestAReplayedConfigChangedDoesNotApplyAStaleDocument drives the real stream,
// the real sync and the real applier through the REPLAY path: the proxy is away
// while v1 and then v2 are published, reconnects from its last_event_id, and is
// replayed both notifications. It must end on v2 and never apply v1 — the
// notification names a document, and what is fetched is always the current one.
func TestAReplayedConfigChangedDoesNotApplyAStaleDocument(t *testing.T) {
	m := startMock(t, mustParseFixtures(t, eventFixtures), serverOptions{})
	boot, err := config.Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	fleet := &recordingFleet{inner: config.NewFleet(boot, boot, nil)}
	sync, err := control.NewConfigSync(control.ConfigSyncOptions{Source: m.client, Applier: fleet, ProxyID: "proxy-1"})
	if err != nil {
		t.Fatal(err)
	}
	notes := &notifications{ConfigSync: sync}
	stream := control.NewRevocationStream(m.client, nil, &recordingRegistry{}, control.StreamOptions{Config: notes})

	syncCtx, stopSync := context.WithCancel(context.Background())
	defer stopSync()
	go sync.Run(syncCtx)

	// First connection: establish a last_event_id, then go away.
	ctx1, cancel1 := context.WithCancel(context.Background())
	done1 := make(chan struct{})
	go func() { defer close(done1); _ = stream.Subscribe(ctx1, "proxy-1") }()
	waitUntil(t, "a live subscription", func() bool {
		return m.revoke(t, control.RevocationEvent{Type: control.EventTypeCacheInvalidate,
			CacheInvalidate: &control.CacheInvalidateEvent{All: true}}).Delivered > 0
	})
	waitUntil(t, "the first event to be processed", func() bool { return stream.LastEventID() != "" })
	cancel1()
	<-done1
	// The client has gone, but the server notices a closed stream only when it
	// next writes to it, so the subscription can outlive <-done1 by a moment —
	// long enough to receive the notification this test needs it to miss. A
	// probe that reaches nobody is the server agreeing the proxy is away. The
	// probe is itself replayed on resume, which is harmless: it is not a
	// configuration notification.
	waitUntil(t, "the first subscription to be gone", func() bool {
		return m.revoke(t, control.RevocationEvent{Type: control.EventTypeCacheInvalidate,
			CacheInvalidate: &control.CacheInvalidateEvent{All: true}}).Delivered == 0
	})
	resumeFrom := stream.LastEventID()

	// Published while the proxy cannot hear: two notifications to replay.
	v1 := m.publishConfig(t, "v1", map[string]any{"control.cache.max_ttl": "1m"})
	v2 := m.publishConfig(t, "v2", map[string]any{"control.cache.max_ttl": "2m"})
	if v1.Delivered != 0 || v2.Delivered != 0 {
		t.Fatal("a notification reached a proxy that was meant to be away")
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go func() { _ = stream.Subscribe(ctx2, "proxy-1") }()

	waitUntil(t, "both notifications replayed", func() bool { return len(notes.seen()) >= 2 })
	waitUntil(t, "v2 running", func() bool { return sync.Status().Running.Version == "v2" })
	waitUntil(t, "the report", func() bool {
		rep, ok := m.server.configReport("proxy-1")
		return ok && rep.RunningVersion == "v2" && rep.State == control.ConfigStateApplied
	})

	if got := notes.seen(); !slices.Equal(got[:2], []string{v1.Hash, v2.Hash}) {
		t.Errorf("replayed notifications = %v, want v1 then v2", got)
	}
	if stream.LastEventID() == resumeFrom {
		t.Error("the stream did not resume past its last event id")
	}
	for _, ttl := range fleet.applied() {
		if ttl == time.Minute.String() {
			t.Fatalf("applied %v: the stale v1 document was applied", fleet.applied())
		}
	}
	if got := fleet.applied(); len(got) == 0 || got[len(got)-1] != (2*time.Minute).String() {
		t.Errorf("applied %v, want to end on v2's clamp", got)
	}
}

func TestMockServesTheDocumentItAnnounces(t *testing.T) {
	fx := mustParseFixtures(t, eventFixtures+`
fleet_config:
  enrolled: [proxy-1]
`)
	m := startMock(t, fx, serverOptions{})
	ctx := context.Background()

	// Nothing published: 204, the unpublished document.
	doc, err := m.client.FetchProxyConfig(ctx, "proxy-1", "")
	if err != nil || doc.Published() {
		t.Fatalf("nothing published: %+v, %v", doc, err)
	}
	// Not enrolled: 404.
	if _, err := m.client.FetchProxyConfig(ctx, "proxy-9", ""); err == nil || !strings.Contains(err.Error(), "not_enrolled") {
		t.Errorf("unenrolled fetch: err = %v, want not_enrolled", err)
	}

	pub := m.publishConfig(t, "v1", map[string]any{"logging.batch_size": 128})
	doc, err = m.client.FetchProxyConfig(ctx, "proxy-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if doc.Version != pub.Version || doc.Hash != pub.Hash {
		t.Errorf("served %s/%s, announced %s/%s: the mock advertised a document it does not serve",
			doc.Version, doc.Hash, pub.Version, pub.Hash)
	}
	if string(doc.Settings["logging.batch_size"]) != "128" {
		t.Errorf("settings = %s", doc.Settings["logging.batch_size"])
	}
	if _, err := m.client.FetchProxyConfig(ctx, "proxy-1", doc.Hash); err == nil {
		t.Error("If-None-Match with the current hash was not answered 304")
	}

	// A config_changed cannot be published by hand.
	body, _ := json.Marshal(control.RevocationEvent{Type: control.EventTypeConfigChanged,
		ConfigChanged: &control.ConfigChangedEvent{Version: "v9", Hash: "made-up"}})
	resp, err := http.Post(m.srv.URL+pathDebugRevoke, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("/debug/revoke accepted a hand-built config_changed: status %d", resp.StatusCode)
	}

	// Reports are validated and kept.
	if _, err := m.client.ReportProxyConfig(ctx, "proxy-1", &control.ProxyConfigReport{
		State: control.ConfigStateRejected, DesiredVersion: "v1", DesiredHash: doc.Hash,
		LastError: "boom", ReportedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if rep, ok := m.server.configReport("proxy-1"); !ok || rep.State != control.ConfigStateRejected {
		t.Errorf("report kept = %+v, %v", rep, ok)
	}
	if _, err := m.client.ReportProxyConfig(ctx, "proxy-1", &control.ProxyConfigReport{
		State: "finished", ReportedAt: time.Now(),
	}); err == nil {
		t.Error("a report with an unknown state was accepted")
	}
}
