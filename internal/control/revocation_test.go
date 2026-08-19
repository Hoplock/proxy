// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// journal records what the stream did, in order, so a test can assert both the
// effects and their sequence (cache first, kill second).
type journal struct {
	mu      sync.Mutex
	entries []string
}

func (j *journal) add(format string, args ...any) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.entries = append(j.entries, fmt.Sprintf(format, args...))
}

func (j *journal) all() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]string(nil), j.entries...)
}

// waitFor blocks until the journal holds at least n entries.
func (j *journal) waitFor(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if got := j.all(); len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d journal entries; have %v", n, j.all())
		}
		time.Sleep(time.Millisecond)
	}
}

// fakeCache is a CacheController that only records.
type fakeCache struct {
	j     *journal
	mu    sync.Mutex
	alive int
}

func (c *fakeCache) Invalidate(keys ...string)  { c.j.add("invalidate:%s", strings.Join(keys, ",")) }
func (c *fakeCache) InvalidateSubject(s string) { c.j.add("invalidate-subject:%s", s) }
func (c *fakeCache) InvalidateAll()             { c.j.add("invalidate-all") }

func (c *fakeCache) StreamAlive(time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.alive++
}

func (c *fakeCache) aliveCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.alive
}

// fakeRegistry stands in for the proxy's session registry (phase 0005).
type fakeRegistry struct {
	j   *journal
	err error
}

func (r *fakeRegistry) KillSession(_ context.Context, id, reason string) error {
	r.j.add("kill-session:%s:%s", id, reason)
	return r.err
}

func (r *fakeRegistry) KillSubject(_ context.Context, subject, reason string) error {
	r.j.add("kill-subject:%s:%s", subject, reason)
	return r.err
}

func (r *fakeRegistry) KillAll(_ context.Context, reason string) error {
	r.j.add("kill-all:%s", reason)
	return r.err
}

// scriptedConn is one connection the fake source will hand out: the events it
// delivers, then how it ends.
type scriptedConn struct {
	openErr error
	events  []RevocationEvent
	// endErr is returned once the events run out. Nil means the connection is
	// held open until it is closed or the test ends, like a real idle stream.
	endErr error
}

// fakeSource is an EventStreamer driven by a script. Once the script runs out
// it holds the connection open, so Subscribe parks instead of spinning.
type fakeSource struct {
	mu        sync.Mutex
	script    []scriptedConn
	opened    []string // last_event_id per connection, in order
	connected chan struct{}
	streams   []*fakeStream
}

func newFakeSource(script ...scriptedConn) *fakeSource {
	return &fakeSource{script: script, connected: make(chan struct{}, 32)}
}

func (s *fakeSource) StreamEvents(_ context.Context, proxyID, lastEventID string) (EventStream, error) {
	s.mu.Lock()
	n := len(s.opened)
	s.opened = append(s.opened, lastEventID)
	var conn scriptedConn
	if n < len(s.script) {
		conn = s.script[n]
	}
	if proxyID == "" {
		s.mu.Unlock()
		return nil, errors.New("fakeSource: no proxy id")
	}
	if conn.openErr != nil {
		s.mu.Unlock()
		s.signal()
		return nil, conn.openErr
	}
	stream := &fakeStream{events: conn.events, endErr: conn.endErr, closed: make(chan struct{})}
	s.streams = append(s.streams, stream)
	s.mu.Unlock()
	s.signal()
	return stream, nil
}

func (s *fakeSource) signal() {
	select {
	case s.connected <- struct{}{}:
	default:
	}
}

// waitForConnections blocks until at least n connections have been opened.
func (s *fakeSource) waitForConnections(t *testing.T, n int) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		s.mu.Lock()
		got := len(s.opened)
		s.mu.Unlock()
		if got >= n {
			return
		}
		select {
		case <-s.connected:
		case <-deadline:
			t.Fatalf("timed out waiting for %d connections; got %d", n, got)
		}
	}
}

func (s *fakeSource) lastEventIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.opened...)
}

func (s *fakeSource) allClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.streams {
		if !st.isClosed() {
			return false
		}
	}
	return true
}

// fakeStream replays scripted events and then ends, or holds.
type fakeStream struct {
	mu     sync.Mutex
	events []RevocationEvent
	endErr error
	closed chan struct{}
	done   bool
}

func (s *fakeStream) Recv() (*RevocationEvent, error) {
	s.mu.Lock()
	if len(s.events) > 0 {
		ev := s.events[0]
		s.events = s.events[1:]
		s.mu.Unlock()
		return &ev, nil
	}
	endErr := s.endErr
	s.mu.Unlock()

	if endErr != nil {
		return nil, endErr
	}
	<-s.closed // an idle stream: nothing to read until it is torn down
	return nil, io.EOF
}

func (s *fakeStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.done {
		s.done = true
		close(s.closed)
	}
	return nil
}

func (s *fakeStream) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.done
}

func event(id string, t EventType) RevocationEvent {
	return RevocationEvent{EventID: id, Type: t, Timestamp: time.Now().UTC()}
}

// startStream subscribes in the background and returns the error channel.
func startStream(t *testing.T, s *RevocationStream, ctx context.Context) <-chan error {
	t.Helper()
	errCh := make(chan error, 1)
	go func() { errCh <- s.Subscribe(ctx, "proxy-1") }()
	return errCh
}

func TestRevocationStreamDispatchesEvents(t *testing.T) {
	kill := event("evt-1", EventTypeSessionKill)
	kill.SessionKill = &SessionKillEvent{
		SessionIDs: []string{"session-a", "session-b"},
		Reason:     "Access withdrawn by the security team.",
	}
	killSubject := event("evt-2", EventTypeSessionKill)
	killSubject.SessionKill = &SessionKillEvent{Subject: "alice@example.com", Reason: "offboarded"}
	killAll := event("evt-3", EventTypeSessionKill)
	killAll.SessionKill = &SessionKillEvent{All: true, Reason: "estate-wide lockdown"}
	invalidateKeys := event("evt-4", EventTypeCacheInvalidate)
	invalidateKeys.CacheInvalidate = &CacheInvalidateEvent{Keys: []string{"k1", "k2"}}
	invalidateSubject := event("evt-5", EventTypeCacheInvalidate)
	invalidateSubject.CacheInvalidate = &CacheInvalidateEvent{Subject: "bob@example.com"}
	invalidateAll := event("evt-6", EventTypeCacheInvalidate)
	invalidateAll.CacheInvalidate = &CacheInvalidateEvent{All: true}

	j := &journal{}
	src := newFakeSource(scriptedConn{events: []RevocationEvent{
		event("evt-0", EventTypeHeartbeat),
		kill, killSubject, killAll,
		invalidateKeys, invalidateSubject, invalidateAll,
		event("evt-7", EventTypeResync),
	}})
	cache := &fakeCache{j: j}
	stream := NewRevocationStream(src, cache, &fakeRegistry{j: j}, StreamOptions{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := startStream(t, stream, ctx)

	want := []string{
		// A kill by id says nothing about which cached decisions to drop.
		"kill-session:session-a:Access withdrawn by the security team.",
		"kill-session:session-b:Access withdrawn by the security team.",
		// Killing a subject's sessions also drops that subject's decisions, and
		// does so BEFORE the kill, so a reconnect cannot slip through.
		"invalidate-subject:alice@example.com",
		"kill-subject:alice@example.com:offboarded",
		"invalidate-all",
		"kill-all:estate-wide lockdown",
		"invalidate:k1,k2",
		"invalidate-subject:bob@example.com",
		"invalidate-all",
		// resync: nothing we hold can be trusted.
		"invalidate-all",
	}
	got := j.waitFor(t, len(want))
	if len(got) != len(want) {
		t.Fatalf("journal = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("journal[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if stream.LastEventID() != "evt-7" {
		t.Errorf("LastEventID = %q, want evt-7", stream.LastEventID())
	}
	if cache.aliveCount() == 0 {
		t.Error("the stream never marked the cache alive")
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("Subscribe returned %v, want nil after cancellation", err)
	}
}

func TestRevocationStreamSuppliesAReasonWhenTheServerDidNot(t *testing.T) {
	kill := event("evt-1", EventTypeSessionKill)
	kill.SessionKill = &SessionKillEvent{SessionIDs: []string{"session-a"}}

	j := &journal{}
	src := newFakeSource(scriptedConn{events: []RevocationEvent{kill}})
	stream := NewRevocationStream(src, &fakeCache{j: j}, &fakeRegistry{j: j}, StreamOptions{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startStream(t, stream, ctx)

	got := j.waitFor(t, 1)
	// PLAN §4.3: the user must be told something, so a killed session is never
	// mistaken for a crash.
	if want := "kill-session:session-a:" + defaultRevocationReason; got[0] != want {
		t.Errorf("journal[0] = %q, want %q", got[0], want)
	}
}

func TestRevocationStreamReconnectsWithBoundedBackoff(t *testing.T) {
	failing := scriptedConn{openErr: &APIError{Op: "StreamEvents", Cause: ErrTransport}}
	src := newFakeSource(failing, failing, failing, failing, failing)

	var mu sync.Mutex
	var delays []time.Duration
	stream := NewRevocationStream(src, nil, nil, StreamOptions{
		MinBackoff: time.Second,
		MaxBackoff: 4 * time.Second,
		Sleep: func(ctx context.Context, d time.Duration) error {
			mu.Lock()
			delays = append(delays, d)
			mu.Unlock()
			return ctx.Err() // no real sleeping: the schedule is what matters
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := startStream(t, stream, ctx)
	src.waitForConnections(t, 6) // the five failures, then the held connection

	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("Subscribe returned %v, want nil after cancellation", err)
	}

	mu.Lock()
	defer mu.Unlock()
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second, 4 * time.Second}
	if len(delays) < len(want) {
		t.Fatalf("backoff delays = %v, want at least %v", delays, want)
	}
	for i, d := range want {
		if delays[i] != d {
			t.Errorf("backoff[%d] = %s, want %s (doubling, capped at MaxBackoff)", i, delays[i], d)
		}
	}
}

func TestRevocationStreamResumesFromTheLastEventID(t *testing.T) {
	src := newFakeSource(
		scriptedConn{events: []RevocationEvent{event("evt-11", EventTypeHeartbeat)}, endErr: io.EOF},
		scriptedConn{events: []RevocationEvent{event("evt-12", EventTypeHeartbeat)}, endErr: io.EOF},
	)
	stream := NewRevocationStream(src, nil, nil, StreamOptions{
		Sleep: func(context.Context, time.Duration) error { return nil },
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := startStream(t, stream, ctx)
	src.waitForConnections(t, 3)
	cancel()
	<-errCh

	got := src.lastEventIDs()
	want := []string{"", "evt-11", "evt-12"}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("connection %d resumed from %q, want %q", i, got[i], w)
		}
	}
}

func TestRevocationStreamTreatsAMissedHeartbeatAsADeadStream(t *testing.T) {
	// Two connections that deliver nothing at all: a live socket that has gone
	// silent is indistinguishable from a healthy idle one without heartbeats.
	src := newFakeSource(scriptedConn{}, scriptedConn{})
	stream := NewRevocationStream(src, nil, nil, StreamOptions{
		HeartbeatTimeout: 20 * time.Millisecond,
		Sleep:            func(context.Context, time.Duration) error { return nil },
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := startStream(t, stream, ctx)
	src.waitForConnections(t, 2) // the first connection timed out and was replaced
	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("Subscribe returned %v, want nil", err)
	}
	if !src.allClosed() {
		t.Error("a stream abandoned for a missed heartbeat was left open")
	}
}

func TestRevocationStreamStopsOnADeny(t *testing.T) {
	denied := &APIError{Op: "StreamEvents", StatusCode: 401, Cause: ErrUnauthorized}
	src := newFakeSource(scriptedConn{openErr: denied})
	stream := NewRevocationStream(src, nil, nil, StreamOptions{
		Sleep: func(context.Context, time.Duration) error {
			t.Error("a rejected proxy credential must not be retried")
			return nil
		},
	})

	err := stream.Subscribe(context.Background(), "proxy-1")
	if !IsUnauthorized(err) {
		t.Errorf("Subscribe returned %v, want the deny", err)
	}
}

func TestRevocationStreamRejectsAnEmptyProxyID(t *testing.T) {
	stream := NewRevocationStream(newFakeSource(), nil, nil, StreamOptions{})
	err := stream.Subscribe(context.Background(), "")
	if !errors.Is(err, ErrBadRequest) {
		t.Errorf("Subscribe returned %v, want ErrBadRequest", err)
	}
}

func TestRevocationStreamEndsCleanlyOnCancellation(t *testing.T) {
	src := newFakeSource()
	stream := NewRevocationStream(src, nil, nil, StreamOptions{})

	ctx, cancel := context.WithCancel(context.Background())
	errCh := startStream(t, stream, ctx)
	src.waitForConnections(t, 1)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Subscribe returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Subscribe did not return after its context was cancelled")
	}
	if !src.allClosed() {
		t.Error("the stream was not closed on the way out")
	}
}

// TestRevocationStreamIgnoresUnknownEventTypes keeps a newer server from
// breaking an older proxy: the unknown event is skipped, the connection lives.
func TestRevocationStreamIgnoresUnknownEventTypes(t *testing.T) {
	kill := event("evt-2", EventTypeSessionKill)
	kill.SessionKill = &SessionKillEvent{All: true, Reason: "lockdown"}

	j := &journal{}
	src := newFakeSource(scriptedConn{events: []RevocationEvent{
		event("evt-1", EventType("quarantine_target")),
		kill,
	}})
	stream := NewRevocationStream(src, &fakeCache{j: j}, &fakeRegistry{j: j}, StreamOptions{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startStream(t, stream, ctx)

	got := j.waitFor(t, 2)
	if got[0] != "invalidate-all" || got[1] != "kill-all:lockdown" {
		t.Errorf("journal = %v, want the known event still applied", got)
	}
	if ids := src.lastEventIDs(); len(ids) != 1 {
		t.Errorf("the stream reconnected %d times over an unknown event type; want 0", len(ids)-1)
	}
}

// TestRevocationStreamSurvivesARegistryFailure: a kill for a session this
// proxy never had is normal and must not stop the rest of the stream.
func TestRevocationStreamSurvivesARegistryFailure(t *testing.T) {
	first := event("evt-1", EventTypeSessionKill)
	first.SessionKill = &SessionKillEvent{SessionIDs: []string{"gone"}, Reason: "revoked"}
	second := event("evt-2", EventTypeCacheInvalidate)
	second.CacheInvalidate = &CacheInvalidateEvent{All: true}

	j := &journal{}
	src := newFakeSource(scriptedConn{events: []RevocationEvent{first, second}})
	stream := NewRevocationStream(src, &fakeCache{j: j},
		&fakeRegistry{j: j, err: errors.New("no such session")}, StreamOptions{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startStream(t, stream, ctx)

	got := j.waitFor(t, 2)
	if got[1] != "invalidate-all" {
		t.Errorf("journal = %v, want the stream to carry on after a failed kill", got)
	}
}

// TestRevocationStreamDrivesTheRealCache is the wiring the proxy runs with:
// an event on the stream must actually drop the CachingClient's entry.
func TestRevocationStreamDrivesTheRealCache(t *testing.T) {
	cache, inner, _ := newTestCache(CacheOptions{})
	inner.authorize = func(req *AuthorizeRequest) (*AuthorizeResponse, error) {
		return testAuthorizeResponse("authz:"+req.Identity.Subject, 600), nil
	}
	req := testAuthorizeRequest("alice@example.com", "host.company.com")
	if _, err := cache.Authorize(context.Background(), req); err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	invalidate := event("evt-1", EventTypeCacheInvalidate)
	invalidate.CacheInvalidate = &CacheInvalidateEvent{Keys: []string{"authz:alice@example.com"}}
	src := newFakeSource(scriptedConn{events: []RevocationEvent{invalidate}}, scriptedConn{})
	stream := NewRevocationStream(src, cache, nil, StreamOptions{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startStream(t, stream, ctx)

	deadline := time.Now().Add(2 * time.Second)
	for cache.Stats().Entries != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the cached decision outlived the invalidation event")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := cache.Authorize(context.Background(), req); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if got := inner.calledFor("Authorize"); got != 2 {
		t.Errorf("server was asked %d times, want 2: the invalidated decision must not be served", got)
	}
}

func TestNopSessionRegistryAcceptsEverything(t *testing.T) {
	var reg SessionRegistry = NopSessionRegistry{}
	ctx := context.Background()
	if err := reg.KillSession(ctx, "s", "r"); err != nil {
		t.Errorf("KillSession: %v", err)
	}
	if err := reg.KillSubject(ctx, "s", "r"); err != nil {
		t.Errorf("KillSubject: %v", err)
	}
	if err := reg.KillAll(ctx, "r"); err != nil {
		t.Errorf("KillAll: %v", err)
	}
}
