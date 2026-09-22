// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func testDoc(version string, settings map[string]string) *ProxyConfigDocument {
	raw := make(map[string]json.RawMessage, len(settings))
	for k, v := range settings {
		raw[k] = json.RawMessage(v)
	}
	return &ProxyConfigDocument{Version: version, Hash: "h-" + version, Settings: raw}
}

func TestRESTFetchProxyConfig(t *testing.T) {
	doc := testDoc("v7", map[string]string{"control.cache.max_ttl": `"5m"`})
	var status int
	var gotINM string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.EscapedPath() != ProxyConfigPath("proxy/1") {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		gotINM = r.Header.Get("If-None-Match")
		switch status {
		case http.StatusOK:
			w.Header().Set("ETag", `"`+doc.Hash+`"`)
			_ = json.NewEncoder(w).Encode(doc)
		case -1: // a 200 that is not a document
			_, _ = w.Write([]byte(`{"settings":{}}`))
		default:
			w.WriteHeader(status)
		}
	}))
	defer srv.Close()
	c, err := NewRESTClient(Options{BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	status = http.StatusOK
	got, err := c.FetchProxyConfig(ctx, "proxy/1", "")
	if err != nil {
		t.Fatalf("200: %v", err)
	}
	if got.Version != "v7" || got.Hash != "h-v7" || string(got.Settings["control.cache.max_ttl"]) != `"5m"` {
		t.Errorf("200 decoded as %+v", got)
	}
	if gotINM != "" {
		t.Errorf("If-None-Match = %q on a first fetch, want none", gotINM)
	}

	status = http.StatusNotModified
	if _, err := c.FetchProxyConfig(ctx, "proxy/1", "h-v7"); !errors.Is(err, ErrConfigNotModified) {
		t.Errorf("304: err = %v, want ErrConfigNotModified", err)
	}
	if gotINM != `"h-v7"` {
		t.Errorf("If-None-Match = %q, want the held hash as an entity tag", gotINM)
	}

	status = http.StatusNoContent
	got, err = c.FetchProxyConfig(ctx, "proxy/1", "")
	if err != nil || got.Published() {
		t.Errorf("204: got %+v, %v; want the unpublished zero document", got, err)
	}

	status = http.StatusNotFound
	if _, err := c.FetchProxyConfig(ctx, "proxy/1", ""); !errors.Is(err, ErrBadRequest) {
		t.Errorf("404 (not enrolled): err = %v, want ErrBadRequest", err)
	}

	status = -1
	if _, err := c.FetchProxyConfig(ctx, "proxy/1", ""); !errors.Is(err, ErrProtocol) {
		t.Errorf("unnamed document: err = %v, want ErrProtocol", err)
	}
}

func TestRESTReportProxyConfig(t *testing.T) {
	accepted := true
	var got ProxyConfigReport
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != ProxyConfigReportPath("p1") {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_ = json.NewEncoder(w).Encode(ProxyConfigReportResponse{Accepted: accepted})
	}))
	defer srv.Close()
	c, _ := NewRESTClient(Options{BaseURL: srv.URL})

	rep := &ProxyConfigReport{RunningVersion: "v1", RunningHash: "h1", State: ConfigStatePendingRestart,
		RestartRequired: []string{"logging.batch_size"}, ReportedAt: time.Now()}
	if _, err := c.ReportProxyConfig(context.Background(), "p1", rep); err != nil {
		t.Fatal(err)
	}
	if got.State != ConfigStatePendingRestart || got.RunningVersion != "v1" || len(got.RestartRequired) != 1 {
		t.Errorf("server received %+v", got)
	}
	accepted = false
	if _, err := c.ReportProxyConfig(context.Background(), "p1", rep); !errors.Is(err, ErrProtocol) {
		t.Errorf("unaccepted report: err = %v, want ErrProtocol", err)
	}
}

func TestValidateEventConfigChanged(t *testing.T) {
	ev := event("evt-1", EventTypeConfigChanged)
	if err := validateEvent(&ev); err == nil {
		t.Error("config_changed without a payload validated")
	}
	ev.ConfigChanged = &ConfigChangedEvent{Version: "v1"}
	if err := validateEvent(&ev); err == nil {
		t.Error("config_changed without a hash validated")
	}
	ev.ConfigChanged.Hash = "h1"
	if err := validateEvent(&ev); err != nil {
		t.Errorf("a complete config_changed failed validation: %v", err)
	}
}

// recordingNotifier is a ConfigNotifier that only records.
type recordingNotifier struct {
	j *journal
}

func (n *recordingNotifier) ConfigChanged(ev *ConfigChangedEvent) {
	n.j.add("config-changed:%s:%s", ev.Version, ev.Hash)
}
func (n *recordingNotifier) StreamConnected() { n.j.add("stream-connected") }

func configChanged(id, version string) RevocationEvent {
	ev := event(id, EventTypeConfigChanged)
	ev.ConfigChanged = &ConfigChangedEvent{Version: version, Hash: "h-" + version}
	return ev
}

// TestAProxyWithoutTheTypeIgnoresConfigChanged is the property the additive
// claim rests on: "a proxy ignores a type it does not recognise, so the server
// may add types without breaking older proxies". A stream with no configuration
// handler is exactly a proxy built before the type existed — it must drop the
// event, stay connected, and keep applying what follows.
func TestAProxyWithoutTheTypeIgnoresConfigChanged(t *testing.T) {
	kill := event("evt-2", EventTypeSessionKill)
	kill.SessionKill = &SessionKillEvent{All: true, Reason: "lockdown"}

	j := &journal{}
	src := newFakeSource(scriptedConn{events: []RevocationEvent{configChanged("evt-1", "v1"), kill}})
	stream := NewRevocationStream(src, &fakeCache{j: j}, &fakeRegistry{j: j}, StreamOptions{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startStream(t, stream, ctx)

	got := j.waitFor(t, 2)
	if len(got) != 2 || got[0] != "invalidate-all" || got[1] != "kill-all:lockdown" {
		t.Errorf("journal = %v, want only the kill that followed the ignored event", got)
	}
	if ids := src.lastEventIDs(); len(ids) != 1 {
		t.Errorf("the stream reconnected %d times over config_changed; want 0", len(ids)-1)
	}
	if id := stream.LastEventID(); id != "evt-2" {
		t.Errorf("LastEventID = %q, want evt-2: an ignored event is still consumed", id)
	}
}

// TestConfigChangedIsOnlyANotification: the stream hands the event to the
// configuration handler and does nothing else with it — no kill, no cache
// invalidation. Configuration is not on the data path. It also asks for a fetch
// on every connect and on resync, which is what covers a missed notification.
func TestConfigChangedIsOnlyANotification(t *testing.T) {
	j := &journal{}
	src := newFakeSource(scriptedConn{events: []RevocationEvent{
		configChanged("evt-1", "v1"),
		event("evt-2", EventTypeResync),
	}})
	stream := NewRevocationStream(src, &fakeCache{j: j}, &fakeRegistry{j: j},
		StreamOptions{Config: &recordingNotifier{j: j}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startStream(t, stream, ctx)

	want := []string{"stream-connected", "config-changed:v1:h-v1", "invalidate-all", "stream-connected"}
	got := j.waitFor(t, len(want))
	if !slices.Equal(got, want) {
		t.Errorf("journal = %v, want %v", got, want)
	}
}

// fakeFleetSource serves one current document the way a server honouring
// If-None-Match does, and records every call.
type fakeFleetSource struct {
	mu       sync.Mutex
	current  *ProxyConfigDocument // nil: nothing published
	fetchErr error
	fetches  []string // If-None-Match per fetch
	reports  []ProxyConfigReport
}

func (s *fakeFleetSource) FetchProxyConfig(_ context.Context, _, inm string) (*ProxyConfigDocument, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fetches = append(s.fetches, inm)
	if s.fetchErr != nil {
		return nil, s.fetchErr
	}
	if s.current == nil {
		return &ProxyConfigDocument{}, nil
	}
	if inm != "" && inm == s.current.Hash {
		return nil, ErrConfigNotModified
	}
	return s.current, nil
}

func (s *fakeFleetSource) ReportProxyConfig(_ context.Context, _ string, r *ProxyConfigReport) (*ProxyConfigReportResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reports = append(s.reports, *r)
	return &ProxyConfigReportResponse{Accepted: true}, nil
}

func (s *fakeFleetSource) set(doc *ProxyConfigDocument, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current, s.fetchErr = doc, err
}

func (s *fakeFleetSource) lastReport(t *testing.T) ProxyConfigReport {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reports) == 0 {
		t.Fatal("nothing was reported")
	}
	return s.reports[len(s.reports)-1]
}

// fakeApplier decides by the document's settings: a key "bad" rejects it, a
// key "restart" needs a restart. It records what it applied.
type fakeApplier struct {
	mu      sync.Mutex
	applied []string
}

func (a *fakeApplier) ApplyConfig(settings map[string]json.RawMessage) ([]string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := settings["bad"]; ok {
		return nil, errors.New(`"bad" is not a fleet-owned setting`)
	}
	if _, ok := settings["restart"]; ok {
		return []string{"restart"}, nil
	}
	keys := make([]string, 0, len(settings))
	for k := range settings {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	a.applied = append(a.applied, strings.Join(keys, ","))
	return nil, nil
}

func (a *fakeApplier) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.applied)
}

func newTestSync(t *testing.T, src *fakeFleetSource, app *fakeApplier) *ConfigSync {
	t.Helper()
	s, err := NewConfigSync(ConfigSyncOptions{Source: src, Applier: app, ProxyID: "proxy-1", RetryInterval: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestConfigSyncAppliesReportsAndDoesNotReapply(t *testing.T) {
	src := &fakeFleetSource{current: testDoc("v1", map[string]string{"live": `1`})}
	app := &fakeApplier{}
	s := newTestSync(t, src, app)
	ctx := context.Background()

	if !s.SyncOnce(ctx) {
		t.Fatal("SyncOnce failed")
	}
	rep := src.lastReport(t)
	if rep.State != ConfigStateApplied || rep.RunningVersion != "v1" || rep.RunningHash != "h-v1" || rep.DesiredVersion != "v1" {
		t.Errorf("report = %+v, want v1 applied and running", rep)
	}

	// A reconnect asks again, conditionally, and the answer is "unchanged".
	s.SyncOnce(ctx)
	if app.count() != 1 {
		t.Errorf("applied %d times, want once: an unchanged document is not re-applied", app.count())
	}
	if got := src.fetches[len(src.fetches)-1]; got != "h-v1" {
		t.Errorf("If-None-Match = %q, want the held hash", got)
	}

	// A notification naming the held document asks for nothing at all.
	s.ConfigChanged(&ConfigChangedEvent{Version: "v1", Hash: "h-v1"})
	select {
	case <-s.wake:
		t.Error("a notification for the held document asked for a fetch")
	default:
	}
}

func TestConfigSyncKeepsTheLastGoodDocument(t *testing.T) {
	src := &fakeFleetSource{current: testDoc("v1", map[string]string{"live": `1`})}
	app := &fakeApplier{}
	s := newTestSync(t, src, app)
	ctx := context.Background()
	s.SyncOnce(ctx)

	t.Run("unparseable or unapplicable", func(t *testing.T) {
		src.set(testDoc("v2", map[string]string{"bad": `1`}), nil)
		s.ConfigChanged(&ConfigChangedEvent{Version: "v2", Hash: "h-v2"})
		s.SyncOnce(ctx)
		rep := src.lastReport(t)
		if rep.State != ConfigStateRejected || rep.RunningVersion != "v1" || rep.DesiredVersion != "v2" {
			t.Errorf("report = %+v, want v2 rejected while v1 keeps running", rep)
		}
		if !strings.Contains(rep.LastError, "bad") {
			t.Errorf("last_error = %q, want the reason an operator can act on", rep.LastError)
		}
		// Not re-evaluated on every reconnect: the rejection is sticky until
		// the desired document moves.
		s.SyncOnce(ctx)
		if app.count() != 1 {
			t.Errorf("applied %d times, want 1", app.count())
		}
	})

	t.Run("unreachable", func(t *testing.T) {
		src.set(nil, &APIError{Op: "FetchProxyConfig", Cause: ErrTransport})
		s.ConfigChanged(&ConfigChangedEvent{Version: "v3", Hash: "h-v3"})
		if s.SyncOnce(ctx) {
			t.Error("SyncOnce reported success on a failed fetch")
		}
		rep := src.lastReport(t)
		if rep.State != ConfigStateFetchFailed || rep.RunningVersion != "v1" || rep.DesiredVersion != "v3" || rep.LastError == "" {
			t.Errorf("report = %+v, want fetch_failed naming the announced v3 while v1 keeps running", rep)
		}
	})

	t.Run("recovers", func(t *testing.T) {
		src.set(testDoc("v3", map[string]string{"live": `3`}), nil)
		s.SyncOnce(ctx)
		rep := src.lastReport(t)
		if rep.State != ConfigStateApplied || rep.RunningVersion != "v3" || rep.LastError != "" {
			t.Errorf("report = %+v, want v3 applied", rep)
		}
	})
}

// TestConfigSyncNeverReportsARestartAsRunning: a document whose settings need a
// restart is held, and the report keeps naming the document that is really in
// force — Control's drift view must not say the rollout finished.
func TestConfigSyncNeverReportsARestartAsRunning(t *testing.T) {
	src := &fakeFleetSource{current: testDoc("v1", map[string]string{"live": `1`})}
	app := &fakeApplier{}
	s := newTestSync(t, src, app)
	ctx := context.Background()
	s.SyncOnce(ctx)

	src.set(testDoc("v2", map[string]string{"live": `2`, "restart": `1`}), nil)
	s.SyncOnce(ctx)
	rep := src.lastReport(t)
	if rep.State != ConfigStatePendingRestart || rep.RunningVersion != "v1" || rep.DesiredVersion != "v2" {
		t.Errorf("report = %+v, want v2 pending while v1 runs", rep)
	}
	if !slices.Equal(rep.RestartRequired, []string{"restart"}) {
		t.Errorf("restart_required = %v", rep.RestartRequired)
	}
	if app.count() != 1 {
		t.Error("the live half of a pending document was applied; a process runs exactly one document")
	}
}

// TestConfigSyncStartedSeedsWhatTheProcessWasBuiltFrom: a document evaluated at
// startup is running without a restart, and is not re-applied on connect.
func TestConfigSyncStartedSeedsWhatTheProcessWasBuiltFrom(t *testing.T) {
	doc := testDoc("v1", map[string]string{"restart": `1`})
	src := &fakeFleetSource{current: doc}
	app := &fakeApplier{}
	s := newTestSync(t, src, app)
	s.Started(doc, nil, nil)
	s.SyncOnce(context.Background())
	rep := src.lastReport(t)
	if rep.State != ConfigStateApplied || rep.RunningVersion != "v1" {
		t.Errorf("report = %+v, want v1 running from startup", rep)
	}
	if app.count() != 0 {
		t.Error("the startup document was re-applied on connect")
	}

	rejected := newTestSync(t, src, app)
	rejected.Started(doc, nil, errors.New("proxy.id is not a fleet-owned setting"))
	if st := rejected.Status(); st.State != ConfigStateRejected || !st.Running.IsZero() {
		t.Errorf("status = %+v, want rejected and running on bootstrap", st)
	}
}

// TestConfigSyncRetriesAFailedFetch: the loop does not wedge on a failure and
// does not wait for the next notification to try again.
func TestConfigSyncRetriesAFailedFetch(t *testing.T) {
	src := &fakeFleetSource{fetchErr: &APIError{Op: "FetchProxyConfig", Cause: ErrServer}}
	app := &fakeApplier{}
	s := newTestSync(t, src, app)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()

	s.StreamConnected()
	deadline := time.Now().Add(2 * time.Second)
	for s.Status().State != ConfigStateFetchFailed {
		if time.Now().After(deadline) {
			t.Fatal("never reported the failed fetch")
		}
		time.Sleep(time.Millisecond)
	}
	src.set(testDoc("v1", map[string]string{"live": `1`}), nil)
	for s.Status().Running.Version != "v1" {
		if time.Now().After(deadline) {
			t.Fatalf("no retry applied v1; status %+v", s.Status())
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
}
