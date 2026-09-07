// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// testClock is the injected clock: expiry is asserted by moving time, never by
// sleeping, so the tests are fast and cannot flake.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock {
	return &testClock{t: time.Date(2026, 8, 15, 9, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeClient counts calls and answers from a scripted function, so a test can
// tell "the cache answered" from "the server answered".
type fakeClient struct {
	authorize func(*AuthorizeRequest) (*AuthorizeResponse, error)
	hostKey   func(*HostKeyReportRequest) (*HostKeyReportResponse, error)

	mu    sync.Mutex
	calls map[string]int
}

func newFakeClient() *fakeClient {
	return &fakeClient{calls: map[string]int{}}
}

func (f *fakeClient) count(op string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[op]++
}

func (f *fakeClient) calledFor(op string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[op]
}

func (f *fakeClient) AuthenticateCert(context.Context, *AuthenticateCertRequest) (*AuthenticateResponse, error) {
	f.count("AuthenticateCert")
	return &AuthenticateResponse{Status: AuthStatusAuthenticated, Identity: &Identity{Subject: "alice@example.com"}}, nil
}

func (f *fakeClient) AuthenticatePassword(context.Context, *AuthenticatePasswordRequest) (*AuthenticateResponse, error) {
	f.count("AuthenticatePassword")
	return &AuthenticateResponse{Status: AuthStatusAuthenticated, Identity: &Identity{Subject: "alice@example.com"}}, nil
}

func (f *fakeClient) PollMFA(context.Context, *MFAPollRequest) (*AuthenticateResponse, error) {
	f.count("PollMFA")
	return &AuthenticateResponse{Status: AuthStatusAuthenticated, Identity: &Identity{Subject: "alice@example.com"}}, nil
}

func (f *fakeClient) Authorize(_ context.Context, req *AuthorizeRequest) (*AuthorizeResponse, error) {
	f.count("Authorize")
	if f.authorize != nil {
		return f.authorize(req)
	}
	return testAuthorizeResponse("authz:alice:host", 60), nil
}

func (f *fakeClient) ReportHostKey(_ context.Context, req *HostKeyReportRequest) (*HostKeyReportResponse, error) {
	f.count("ReportHostKey")
	if f.hostKey != nil {
		return f.hostKey(req)
	}
	// No hint: the default fake is a server that has not opted into reuse, so
	// every report reaches it. That is also the pre-0023 behaviour.
	return &HostKeyReportResponse{Decision: HostKeyAccept}, nil
}

func (f *fakeClient) IngestLogBatch(context.Context, *LogBatchRequest) (*LogBatchResponse, error) {
	f.count("IngestLogBatch")
	return &LogBatchResponse{Accepted: 1}, nil
}

func (f *fakeClient) IngestPriorityLog(context.Context, *LogPriorityRequest) (*LogPriorityResponse, error) {
	f.count("IngestPriorityLog")
	return &LogPriorityResponse{Accepted: true}, nil
}

var _ Client = (*fakeClient)(nil)

func testAuthorizeRequest(subject, target string) *AuthorizeRequest {
	return &AuthorizeRequest{
		Identity:   &Identity{Subject: subject, Login: "alice"},
		Target:     target,
		AuthMethod: AuthMethodCert,
		Conn:       testConn(),
	}
}

func testAuthorizeResponse(key string, ttlSeconds int) *AuthorizeResponse {
	resp := &AuthorizeResponse{
		RouteType:         RouteTypeDirect,
		Target:            "host.company.com",
		PermittedChannels: []string{"session"},
		FilterPolicy: FilterPolicy{
			Mode:  FilterModeBlacklist,
			Rules: []FilterRule{{Match: "shutdown", Action: FilterActionBlockCommand}},
		},
		DecisionID: "decision-1",
	}
	if ttlSeconds != 0 || key != "" {
		resp.Cache = &CacheHint{Key: key, TTLSeconds: ttlSeconds}
	}
	return resp
}

// newTestCache returns a caching client whose revocation stream is already
// healthy, which is the precondition for the cache being served at all.
func newTestCache(opts CacheOptions) (*CachingClient, *fakeClient, *testClock) {
	clock := newTestClock()
	opts.Now = clock.Now
	inner := newFakeClient()
	c := NewCachingClient(inner, opts)
	c.StreamAlive(clock.Now())
	return c, inner, clock
}

func TestCachingClientServesAHitWhileTheTTLLasts(t *testing.T) {
	c, inner, clock := newTestCache(CacheOptions{})
	ctx := context.Background()
	req := testAuthorizeRequest("alice@example.com", "host.company.com")

	first, err := c.Authorize(ctx, req)
	if err != nil {
		t.Fatalf("first Authorize: %v", err)
	}
	clock.Advance(30 * time.Second)
	second, err := c.Authorize(ctx, req)
	if err != nil {
		t.Fatalf("second Authorize: %v", err)
	}

	if got := inner.calledFor("Authorize"); got != 1 {
		t.Errorf("server was asked %d times, want 1: the second call must be a cache hit", got)
	}
	if second.DecisionID != first.DecisionID || second.Target != first.Target {
		t.Errorf("cached decision = %+v, want the first decision back", second)
	}
	stats := c.Stats()
	if stats.Hits != 1 || stats.Misses != 1 || stats.Stored != 1 || stats.Entries != 1 {
		t.Errorf("stats = %+v, want 1 hit, 1 miss, 1 stored, 1 entry", stats)
	}
}

func TestCachingClientNeverCachesWithoutTheServersPermission(t *testing.T) {
	tests := []struct {
		name string
		resp *AuthorizeResponse
	}{
		{"no cache hint at all", testAuthorizeResponse("", 0)},
		{"ttl_seconds is zero", testAuthorizeResponse("authz:alice:host", 0)},
		{"a key without a ttl", func() *AuthorizeResponse {
			r := testAuthorizeResponse("", 0)
			r.Cache = &CacheHint{Key: "authz:alice:host"}
			return r
		}()},
		{"a ttl without a key: the proxy never invents one", func() *AuthorizeResponse {
			r := testAuthorizeResponse("", 0)
			r.Cache = &CacheHint{TTLSeconds: 300}
			return r
		}()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, inner, _ := newTestCache(CacheOptions{})
			inner.authorize = func(*AuthorizeRequest) (*AuthorizeResponse, error) { return tc.resp, nil }
			req := testAuthorizeRequest("alice@example.com", "host.company.com")

			for i := 0; i < 3; i++ {
				if _, err := c.Authorize(context.Background(), req); err != nil {
					t.Fatalf("Authorize %d: %v", i, err)
				}
			}
			if got := inner.calledFor("Authorize"); got != 3 {
				t.Errorf("server was asked %d times, want 3: nothing may be cached here", got)
			}
			if stats := c.Stats(); stats.Entries != 0 || stats.Stored != 0 {
				t.Errorf("stats = %+v, want an empty cache", stats)
			}
		})
	}
}

func TestCachingClientExpiresAnEntryOnTheServersTTL(t *testing.T) {
	c, inner, clock := newTestCache(CacheOptions{})
	ctx := context.Background()
	req := testAuthorizeRequest("alice@example.com", "host.company.com")

	if _, err := c.Authorize(ctx, req); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	// The TTL from testAuthorizeResponse is 60s. Keep the stream fresh so this
	// is an expiry and not the stale-stream rule firing.
	clock.Advance(61 * time.Second)
	c.StreamAlive(clock.Now())

	if _, err := c.Authorize(ctx, req); err != nil {
		t.Fatalf("Authorize after expiry: %v", err)
	}
	if got := inner.calledFor("Authorize"); got != 2 {
		t.Errorf("server was asked %d times, want 2: an expired decision must not be served", got)
	}
	if stats := c.Stats(); stats.Expired != 1 {
		t.Errorf("stats = %+v, want 1 expiry", stats)
	}
}

func TestCachingClientClampsTheTTLDownwardOnly(t *testing.T) {
	tests := []struct {
		name       string
		maxTTL     time.Duration
		serverTTL  int
		stillFresh time.Duration
		nowExpired time.Duration
	}{
		{"operator is stricter than the server", 30 * time.Second, 300, 29 * time.Second, 31 * time.Second},
		{"operator is laxer: the server still wins", 10 * time.Minute, 5, 4 * time.Second, 6 * time.Second},
		{"no clamp configured", 0, 5, 4 * time.Second, 6 * time.Second},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, inner, clock := newTestCache(CacheOptions{MaxTTL: tc.maxTTL})
			inner.authorize = func(*AuthorizeRequest) (*AuthorizeResponse, error) {
				return testAuthorizeResponse("authz:alice:host", tc.serverTTL), nil
			}
			ctx := context.Background()
			req := testAuthorizeRequest("alice@example.com", "host.company.com")

			if _, err := c.Authorize(ctx, req); err != nil {
				t.Fatalf("Authorize: %v", err)
			}
			clock.Advance(tc.stillFresh)
			c.StreamAlive(clock.Now())
			if _, err := c.Authorize(ctx, req); err != nil {
				t.Fatalf("Authorize while fresh: %v", err)
			}
			if got := inner.calledFor("Authorize"); got != 1 {
				t.Fatalf("server was asked %d times before the lifetime ran out, want 1", got)
			}

			clock.Advance(tc.nowExpired - tc.stillFresh)
			c.StreamAlive(clock.Now())
			if _, err := c.Authorize(ctx, req); err != nil {
				t.Fatalf("Authorize after the lifetime: %v", err)
			}
			if got := inner.calledFor("Authorize"); got != 2 {
				t.Errorf("server was asked %d times after the lifetime, want 2", got)
			}
		})
	}
}

// TestCachingClientReportsAClamp: shortening the server's lifetime is the one
// place a local setting overrides the PDP, and a fleet where one proxy is
// configured differently is unexplainable from the outside if that is silent.
func TestCachingClientReportsAClamp(t *testing.T) {
	newCache := func(t *testing.T, maxTTL time.Duration, serverTTL int) (*CachingClient, *bytes.Buffer) {
		t.Helper()
		var logs bytes.Buffer
		clock := newTestClock()
		inner := newFakeClient()
		inner.authorize = func(*AuthorizeRequest) (*AuthorizeResponse, error) {
			return testAuthorizeResponse("authz:alice:host", serverTTL), nil
		}
		c := NewCachingClient(inner, CacheOptions{
			MaxTTL: maxTTL,
			Now:    clock.Now,
			Logger: log.New(&logs, "", 0),
		})
		c.StreamAlive(clock.Now())
		if _, err := c.Authorize(context.Background(), testAuthorizeRequest("alice@example.com", "host")); err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		return c, &logs
	}

	t.Run("a clamp that shortens is counted and logged", func(t *testing.T) {
		c, logs := newCache(t, 30*time.Second, 300)

		if got := c.Stats().Clamped; got != 1 {
			t.Errorf("Clamped = %d, want 1", got)
		}
		line := logs.String()
		for _, want := range []string{"authz:alice:host", "5m0s", "30s"} {
			if !strings.Contains(line, want) {
				t.Errorf("log %q does not mention %q; it must name the key and both lifetimes", line, want)
			}
		}
	})

	t.Run("a clamp longer than the server's changes nothing and says nothing", func(t *testing.T) {
		c, logs := newCache(t, 10*time.Minute, 60)

		if got := c.Stats().Clamped; got != 0 {
			t.Errorf("Clamped = %d, want 0: the server's lifetime already fitted", got)
		}
		if logs.Len() != 0 {
			t.Errorf("logged %q, want silence when nothing was overridden", logs.String())
		}
	})

	t.Run("no clamp configured is the default and stays quiet", func(t *testing.T) {
		c, logs := newCache(t, 0, 300)

		if got := c.Stats().Clamped; got != 0 {
			t.Errorf("Clamped = %d, want 0: the default honours the server exactly", got)
		}
		if logs.Len() != 0 {
			t.Errorf("logged %q, want silence", logs.String())
		}
	})

	t.Run("a decision that was not stored is not counted", func(t *testing.T) {
		// The stream is stale, so nothing is cached — and a clamp that applied
		// to nothing must not show up in the count.
		var logs bytes.Buffer
		clock := newTestClock()
		inner := newFakeClient()
		inner.authorize = func(*AuthorizeRequest) (*AuthorizeResponse, error) {
			return testAuthorizeResponse("authz:alice:host", 300), nil
		}
		c := NewCachingClient(inner, CacheOptions{
			MaxTTL: 30 * time.Second,
			Now:    clock.Now,
			Logger: log.New(&logs, "", 0),
		})
		if _, err := c.Authorize(context.Background(), testAuthorizeRequest("alice@example.com", "host")); err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		if got := c.Stats(); got.Clamped != 0 || got.Stored != 0 {
			t.Errorf("stats = %+v, want no store and no clamp", got)
		}
		if logs.Len() != 0 {
			t.Errorf("logged %q for a decision that was never cached", logs.String())
		}
	})
}

func TestCachingClientInvalidation(t *testing.T) {
	// Two subjects, two targets, so each invalidation can be shown to drop
	// exactly what it names and nothing else.
	seed := func(t *testing.T, c *CachingClient, inner *fakeClient) {
		t.Helper()
		inner.authorize = func(req *AuthorizeRequest) (*AuthorizeResponse, error) {
			return testAuthorizeResponse("authz:"+req.Identity.Subject+":"+req.Target, 600), nil
		}
		for _, req := range []*AuthorizeRequest{
			testAuthorizeRequest("alice@example.com", "host-a"),
			testAuthorizeRequest("alice@example.com", "host-b"),
			testAuthorizeRequest("bob@example.com", "host-a"),
		} {
			if _, err := c.Authorize(context.Background(), req); err != nil {
				t.Fatalf("seed Authorize: %v", err)
			}
		}
		if stats := c.Stats(); stats.Entries != 3 {
			t.Fatalf("seeded %d entries, want 3", stats.Entries)
		}
	}

	tests := []struct {
		name        string
		invalidate  func(*CachingClient)
		wantEntries int
		wantGone    *AuthorizeRequest
		wantKept    *AuthorizeRequest
	}{
		{
			name:        "by key",
			invalidate:  func(c *CachingClient) { c.Invalidate("authz:alice@example.com:host-a") },
			wantEntries: 2,
			wantGone:    testAuthorizeRequest("alice@example.com", "host-a"),
			wantKept:    testAuthorizeRequest("alice@example.com", "host-b"),
		},
		{
			name:        "by subject",
			invalidate:  func(c *CachingClient) { c.InvalidateSubject("alice@example.com") },
			wantEntries: 1,
			wantGone:    testAuthorizeRequest("alice@example.com", "host-b"),
			wantKept:    testAuthorizeRequest("bob@example.com", "host-a"),
		},
		{
			name:        "all",
			invalidate:  func(c *CachingClient) { c.InvalidateAll() },
			wantEntries: 0,
			wantGone:    testAuthorizeRequest("bob@example.com", "host-a"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, inner, _ := newTestCache(CacheOptions{})
			seed(t, c, inner)
			tc.invalidate(c)

			if got := c.Stats().Entries; got != tc.wantEntries {
				t.Errorf("cache holds %d entries, want %d", got, tc.wantEntries)
			}
			before := inner.calledFor("Authorize")
			if _, err := c.Authorize(context.Background(), tc.wantGone); err != nil {
				t.Fatalf("Authorize after invalidation: %v", err)
			}
			if got := inner.calledFor("Authorize"); got != before+1 {
				t.Errorf("an invalidated decision was served from cache")
			}
			if tc.wantKept != nil {
				before = inner.calledFor("Authorize")
				if _, err := c.Authorize(context.Background(), tc.wantKept); err != nil {
					t.Fatalf("Authorize of a kept entry: %v", err)
				}
				if got := inner.calledFor("Authorize"); got != before {
					t.Errorf("an unrelated decision was dropped too")
				}
			}
		})
	}
}

// TestCachingClientFailsClosedWhileTheStreamIsStale covers both halves of the
// rule in PLAN §6.4: no cache while revocations cannot be heard, and full use
// of it again once they can.
func TestCachingClientFailsClosedWhileTheStreamIsStale(t *testing.T) {
	clock := newTestClock()
	inner := newFakeClient()
	c := NewCachingClient(inner, CacheOptions{StaleAfter: 30 * time.Second, Now: clock.Now})
	ctx := context.Background()
	req := testAuthorizeRequest("alice@example.com", "host.company.com")

	// Before the stream has ever connected the cache is dead: nothing is stored
	// and nothing is served.
	if !c.StreamStale() {
		t.Error("a stream that never connected must count as stale")
	}
	for i := 0; i < 2; i++ {
		if _, err := c.Authorize(ctx, req); err != nil {
			t.Fatalf("Authorize %d: %v", i, err)
		}
	}
	if got := inner.calledFor("Authorize"); got != 2 {
		t.Errorf("server was asked %d times before the stream connected, want 2", got)
	}
	if stats := c.Stats(); stats.Entries != 0 || stats.StaleSkips != 2 {
		t.Errorf("stats = %+v, want no entries and 2 stale skips", stats)
	}

	// With the stream alive the cache works normally.
	c.StreamAlive(clock.Now())
	if _, err := c.Authorize(ctx, req); err != nil {
		t.Fatalf("Authorize with a live stream: %v", err)
	}
	if _, err := c.Authorize(ctx, req); err != nil {
		t.Fatalf("Authorize with a live stream: %v", err)
	}
	if got := inner.calledFor("Authorize"); got != 3 {
		t.Fatalf("server was asked %d times with a live stream, want 3 (one miss, one hit)", got)
	}

	// Let the stream go unheard for longer than StaleAfter: the entry is still
	// held (a resync may yet clear it) but must not be served.
	clock.Advance(31 * time.Second)
	if !c.StreamStale() {
		t.Fatal("the stream must be stale after StaleAfter has passed")
	}
	if _, err := c.Authorize(ctx, req); err != nil {
		t.Fatalf("Authorize with a stale stream: %v", err)
	}
	if got := inner.calledFor("Authorize"); got != 4 {
		t.Errorf("server was asked %d times, want 4: a stale stream must suspend the cache", got)
	}

	// A recovered stream may use what it still holds, within its unchanged TTL.
	c.StreamAlive(clock.Now())
	if _, err := c.Authorize(ctx, req); err != nil {
		t.Fatalf("Authorize after recovery: %v", err)
	}
	if got := inner.calledFor("Authorize"); got != 4 {
		t.Errorf("server was asked %d times after recovery, want 4: the entry was still valid", got)
	}
}

// TestCachingClientNeverCachesAuthentication guards the rule a future reader
// will be tempted to "optimise": an MFA approval is a per-session assertion and
// certificate validation is where revocation bites.
func TestCachingClientNeverCachesAuthentication(t *testing.T) {
	c, inner, _ := newTestCache(CacheOptions{})
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if _, err := c.AuthenticateCert(ctx, &AuthenticateCertRequest{Login: "alice"}); err != nil {
			t.Fatalf("AuthenticateCert: %v", err)
		}
		if _, err := c.AuthenticatePassword(ctx, &AuthenticatePasswordRequest{Login: "alice"}); err != nil {
			t.Fatalf("AuthenticatePassword: %v", err)
		}
		if _, err := c.PollMFA(ctx, &MFAPollRequest{Token: "mfa-1"}); err != nil {
			t.Fatalf("PollMFA: %v", err)
		}
		if _, err := c.ReportHostKey(ctx, &HostKeyReportRequest{Target: "host"}); err != nil {
			t.Fatalf("ReportHostKey: %v", err)
		}
		if _, err := c.IngestLogBatch(ctx, &LogBatchRequest{Records: []LogRecord{{RecordID: "r1"}}}); err != nil {
			t.Fatalf("IngestLogBatch: %v", err)
		}
		if _, err := c.IngestPriorityLog(ctx, &LogPriorityRequest{Record: LogRecord{RecordID: "r2"}}); err != nil {
			t.Fatalf("IngestPriorityLog: %v", err)
		}
	}

	for _, op := range []string{
		"AuthenticateCert", "AuthenticatePassword", "PollMFA",
		"IngestLogBatch", "IngestPriorityLog",
	} {
		if got := inner.calledFor(op); got != 2 {
			t.Errorf("%s reached the server %d times, want 2: authentication and log "+
				"shipping are never cached, whatever the server says", op, got)
		}
	}
	// ReportHostKey is cacheable since phase 0023, but only on a hint, and this
	// fake server sends none — so it too reaches the server every time.
	if got := inner.calledFor("ReportHostKey"); got != 2 {
		t.Errorf("ReportHostKey reached the server %d times, want 2: "+
			"no hint means report every connection", got)
	}
}

func TestCachingClientDoesNotCacheADeny(t *testing.T) {
	c, inner, _ := newTestCache(CacheOptions{})
	inner.authorize = func(*AuthorizeRequest) (*AuthorizeResponse, error) {
		return nil, &APIError{Op: "Authorize", StatusCode: 401, Cause: ErrUnauthorized}
	}
	req := testAuthorizeRequest("alice@example.com", "host.company.com")

	for i := 0; i < 2; i++ {
		_, err := c.Authorize(context.Background(), req)
		if !IsUnauthorized(err) {
			t.Fatalf("Authorize %d error = %v, want a deny", i, err)
		}
	}
	if got := inner.calledFor("Authorize"); got != 2 {
		t.Errorf("server was asked %d times, want 2: a deny is re-decided, never cached", got)
	}
}

// TestCachedDecisionIsIsolatedFromItsCaller stops one session's edits to its
// own policy from rewriting the policy handed to the next.
func TestCachedDecisionIsIsolatedFromItsCaller(t *testing.T) {
	c, _, _ := newTestCache(CacheOptions{})
	ctx := context.Background()
	req := testAuthorizeRequest("alice@example.com", "host.company.com")

	first, err := c.Authorize(ctx, req)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	first.PermittedChannels[0] = "direct-tcpip"
	first.PermittedChannels = append(first.PermittedChannels, "x11")
	first.FilterPolicy.Rules[0].Action = FilterActionAllowAndLog

	second, err := c.Authorize(ctx, req)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if len(second.PermittedChannels) != 1 || second.PermittedChannels[0] != "session" {
		t.Errorf("permitted channels = %v, want the policy the server sent", second.PermittedChannels)
	}
	if second.FilterPolicy.Rules[0].Action != FilterActionBlockCommand {
		t.Errorf("filter action = %q, want the policy the server sent", second.FilterPolicy.Rules[0].Action)
	}
}

// TestCachingClientRefusesAnEntryBelongingToAnotherSubject is defence against a
// server that breaks its own rule and reuses a key across identities.
func TestCachingClientRefusesAnEntryBelongingToAnotherSubject(t *testing.T) {
	c, inner, _ := newTestCache(CacheOptions{})
	inner.authorize = func(*AuthorizeRequest) (*AuthorizeResponse, error) {
		return testAuthorizeResponse("shared-key", 600), nil
	}
	ctx := context.Background()

	if _, err := c.Authorize(ctx, testAuthorizeRequest("alice@example.com", "host-a")); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	// Bob's request has a different shape, so it misses and re-asks; the shared
	// key then rebinds the entry to bob rather than serving him alice's policy.
	if _, err := c.Authorize(ctx, testAuthorizeRequest("bob@example.com", "host-a")); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if got := inner.calledFor("Authorize"); got != 2 {
		t.Fatalf("server was asked %d times, want 2", got)
	}
	if _, err := c.Authorize(ctx, testAuthorizeRequest("alice@example.com", "host-a")); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if got := inner.calledFor("Authorize"); got != 3 {
		t.Errorf("alice was served an entry that now belongs to bob")
	}
}

// TestCachingClientIgnoresRequestsItCannotKey covers the guard that a request
// with no authenticated subject is never cached — there would be nothing to
// invalidate it by.
func TestCachingClientIgnoresRequestsItCannotKey(t *testing.T) {
	c, inner, _ := newTestCache(CacheOptions{})
	req := &AuthorizeRequest{Target: "host.company.com", Conn: testConn()}

	for i := 0; i < 2; i++ {
		if _, err := c.Authorize(context.Background(), req); err != nil {
			t.Fatalf("Authorize %d: %v", i, err)
		}
	}
	if got := inner.calledFor("Authorize"); got != 2 {
		t.Errorf("server was asked %d times, want 2", got)
	}
	if stats := c.Stats(); stats.Entries != 0 {
		t.Errorf("cache holds %d entries, want 0", stats.Entries)
	}
}

func TestCachingClientBoundsItsSize(t *testing.T) {
	c, inner, _ := newTestCache(CacheOptions{MaxEntries: 2})
	inner.authorize = func(req *AuthorizeRequest) (*AuthorizeResponse, error) {
		return testAuthorizeResponse("authz:"+req.Target, 600), nil
	}
	for _, target := range []string{"host-a", "host-b", "host-c"} {
		if _, err := c.Authorize(context.Background(), testAuthorizeRequest("alice@example.com", target)); err != nil {
			t.Fatalf("Authorize %s: %v", target, err)
		}
	}
	if got := c.Stats().Entries; got != 2 {
		t.Errorf("cache holds %d entries, want at most 2", got)
	}
}

// TestCachingClientEvictsTheLeastRecentlyUsed pins the policy: a full cache
// makes room by dropping what has gone longest unused, and says it did.
func TestCachingClientEvictsTheLeastRecentlyUsed(t *testing.T) {
	c, inner, _ := newTestCache(CacheOptions{MaxEntries: 2})
	inner.authorize = func(req *AuthorizeRequest) (*AuthorizeResponse, error) {
		return testAuthorizeResponse("authz:"+req.Target, 600), nil
	}
	authorize := func(target string) {
		t.Helper()
		if _, err := c.Authorize(context.Background(), testAuthorizeRequest("alice@example.com", target)); err != nil {
			t.Fatalf("Authorize %s: %v", target, err)
		}
	}

	authorize("host-a")
	authorize("host-b")
	// Using host-a again makes host-b the least recently used, so the third
	// target must displace host-b and not host-a. Insertion order alone would
	// pick the other one, which is the difference this asserts.
	authorize("host-a")
	authorize("host-c")

	if got, want := c.Stats().Evicted, uint64(1); got != want {
		t.Errorf("Evicted = %d, want %d", got, want)
	}
	before := inner.calledFor("Authorize")
	authorize("host-a")
	if got := inner.calledFor("Authorize"); got != before {
		t.Error("host-a was evicted; the least recently used entry was host-b")
	}
	authorize("host-b")
	if got, want := inner.calledFor("Authorize"), before+1; got != want {
		t.Errorf("Authorize calls = %d, want %d — host-b should have been evicted", got, want)
	}
}

// TestCachingClientCachesAWorkingSetItMeetsAfterFilling is the regression test
// for the finding phase 0020 measured (PLAN §9.1): the cache used to hold the
// first MaxEntries shapes it ever saw and refuse every later decision, so a
// working set that turned up after a long cold sweep was never cached at all —
// a permanent 0% for the traffic that repeats. With eviction, the sweep is
// forgotten and the repeating set is served.
func TestCachingClientCachesAWorkingSetItMeetsAfterFilling(t *testing.T) {
	const bound = 64
	c, inner, _ := newTestCache(CacheOptions{MaxEntries: bound})
	inner.authorize = func(req *AuthorizeRequest) (*AuthorizeResponse, error) {
		return testAuthorizeResponse("authz:"+req.Target, 3600), nil
	}
	authorize := func(target string) {
		t.Helper()
		if _, err := c.Authorize(context.Background(), testAuthorizeRequest("svc@example.com", target)); err != nil {
			t.Fatalf("Authorize %s: %v", target, err)
		}
	}

	// A cold sweep four times the bound: every one of these is seen once and
	// never again, and together they more than fill the cache.
	for i := 0; i < bound*4; i++ {
		authorize(fmt.Sprintf("swept-%d.example.com", i))
	}
	if got := c.Stats().Evicted; got == 0 {
		t.Fatal("a sweep of four times the bound evicted nothing")
	}

	// Now the working set: eight targets, visited repeatedly, all of which fit.
	const working, rounds = 8, 10
	callsBefore := inner.calledFor("Authorize")
	for round := 0; round < rounds; round++ {
		for i := 0; i < working; i++ {
			authorize(fmt.Sprintf("polled-%d.example.com", i))
		}
	}
	// One miss each on the first round; every later visit is a hit.
	if got, want := inner.calledFor("Authorize")-callsBefore, working; got != want {
		t.Errorf("%d authorize calls for a working set of %d over %d rounds, want %d",
			got, working, rounds, want)
	}
	hits, total := c.Stats().Hits, working*rounds
	if wantHits := uint64(total - working); hits < wantHits {
		t.Errorf("Hits = %d, want at least %d (hit rate %.0f%%, want %.0f%%)",
			hits, wantHits, 100*float64(hits)/float64(total), 100*float64(wantHits)/float64(total))
	}
	if got := c.Stats().Shapes; got > bound {
		t.Errorf("cache holds %d shapes, want at most %d", got, bound)
	}
}

// TestCachingClientBoundsSharedShapes covers the other half of the bound. A
// server may answer every target of a subject with ONE key (PLAN §6.4), which
// stores one decision and one lookup path per target: it is the lookup paths
// that have to be bounded, and phase 0020 measured that a separate bound on
// them is what made the widest possible key sharing worth nothing.
func TestCachingClientBoundsSharedShapes(t *testing.T) {
	const bound = 16
	c, inner, _ := newTestCache(CacheOptions{MaxEntries: bound})
	inner.authorize = func(*AuthorizeRequest) (*AuthorizeResponse, error) {
		return testAuthorizeResponse("authz:one-key-for-everything", 3600), nil
	}
	for i := 0; i < bound*3; i++ {
		target := fmt.Sprintf("host-%d.example.com", i)
		if _, err := c.Authorize(context.Background(), testAuthorizeRequest("svc@example.com", target)); err != nil {
			t.Fatalf("Authorize %s: %v", target, err)
		}
	}

	stats := c.Stats()
	if stats.Shapes > bound {
		t.Errorf("cache holds %d shapes, want at most %d", stats.Shapes, bound)
	}
	// One key, so one decision — and it must still be there. An entry table
	// that filled with copies, or one wedged shut by the shape table, would
	// show up here.
	if stats.Entries != 1 {
		t.Errorf("cache holds %d decisions, want 1 (the server shared one key)", stats.Entries)
	}
	if stats.Evicted == 0 {
		t.Error("Evicted = 0 after three times the bound of distinct shapes")
	}
}

// TestCachingClientDropsADecisionWithItsLastShape checks the bookkeeping that
// keeps the two tables bounded by one number: a shared decision survives the
// eviction of one of the shapes naming it and goes when the last one does,
// rather than lingering unreachable.
func TestCachingClientDropsADecisionWithItsLastShape(t *testing.T) {
	c, inner, _ := newTestCache(CacheOptions{MaxEntries: 2})
	inner.authorize = func(req *AuthorizeRequest) (*AuthorizeResponse, error) {
		key := "authz:shared"
		if strings.HasPrefix(req.Target, "own-") {
			key = "authz:" + req.Target
		}
		return testAuthorizeResponse(key, 3600), nil
	}
	authorize := func(target string) {
		t.Helper()
		if _, err := c.Authorize(context.Background(), testAuthorizeRequest("svc@example.com", target)); err != nil {
			t.Fatalf("Authorize %s: %v", target, err)
		}
	}

	authorize("shared-a")
	authorize("shared-b")
	if got := c.Stats().Entries; got != 1 {
		t.Fatalf("two shapes under one key hold %d decisions, want 1", got)
	}

	// Evicts shared-a's shape; the decision stays, because shared-b names it.
	authorize("own-1")
	if got := c.Stats().Entries; got != 2 {
		t.Errorf("cache holds %d decisions, want 2 (the shared one and own-1)", got)
	}
	// Evicts shared-b's shape: the last one, so the shared decision goes too.
	authorize("own-2")
	stats := c.Stats()
	if stats.Entries != 2 {
		t.Errorf("cache holds %d decisions, want 2 (own-1 and own-2)", stats.Entries)
	}
	if stats.Shapes != 2 {
		t.Errorf("cache holds %d shapes, want 2", stats.Shapes)
	}
}

func TestCachingClientIsSafeUnderConcurrency(t *testing.T) {
	c, _, _ := newTestCache(CacheOptions{})
	req := testAuthorizeRequest("alice@example.com", "host.company.com")

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := c.Authorize(context.Background(), req); err != nil {
				t.Errorf("Authorize: %v", err)
			}
			switch i % 3 {
			case 0:
				c.Invalidate("authz:alice:host")
			case 1:
				c.InvalidateSubject("alice@example.com")
			default:
				c.StreamAlive(time.Now())
			}
			_ = c.Stats()
		}(i)
	}
	wg.Wait()
}

func TestCacheHintTTL(t *testing.T) {
	var absent *CacheHint
	if got := absent.TTL(); got != 0 {
		t.Errorf("a nil hint has TTL %s, want 0 (do not cache)", got)
	}
	if got := (&CacheHint{TTLSeconds: 90}).TTL(); got != 90*time.Second {
		t.Errorf("TTL = %s, want 90s", got)
	}
}

func TestAuthorizeRejectsAnUnusableCacheHint(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"ttl without a key", `{"route_type":"direct","target":"h","permitted_channels":[],` +
			`"filter_policy":{"mode":"blacklist"},"cache":{"ttl_seconds":60}}`},
		{"negative ttl", `{"route_type":"direct","target":"h","permitted_channels":[],` +
			`"filter_policy":{"mode":"blacklist"},"cache":{"key":"k","ttl_seconds":-1}}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, tc.body)
			})
			_, err := client.Authorize(context.Background(), testAuthorizeRequest("alice@example.com", "h"))
			if !errors.Is(err, ErrProtocol) {
				t.Errorf("error = %v, want ErrProtocol", err)
			}
		})
	}
}

// --- Host-key decision reuse (phase 0023) -----------------------------------

func testHostKeyRequest(target string, port int, fingerprint string) *HostKeyReportRequest {
	return &HostKeyReportRequest{
		Target:     target,
		TargetPort: port,
		HostKey: PublicKeyMaterial{
			Type:        "ssh-ed25519",
			Blob:        []byte(fingerprint),
			Fingerprint: fingerprint,
		},
		Conn: testConn(),
	}
}

// hostKeyServer answers like a server that has already ruled on every key it is
// shown and authorises reuse of the answer, keyed per (target, fingerprint).
func hostKeyServer(ttlSeconds int) func(*HostKeyReportRequest) (*HostKeyReportResponse, error) {
	return func(req *HostKeyReportRequest) (*HostKeyReportResponse, error) {
		return &HostKeyReportResponse{
			Decision: HostKeyAccept,
			Known:    true,
			Cache:    &CacheHint{Key: "hk:" + req.Target + "|" + req.HostKey.Fingerprint, TTLSeconds: ttlSeconds},
		}, nil
	}
}

func TestCachingClientReusesAHostKeyDecision(t *testing.T) {
	c, inner, clock := newTestCache(CacheOptions{})
	inner.hostKey = hostKeyServer(300)
	ctx := context.Background()
	req := testHostKeyRequest("host.company.com", 22, "SHA256:AAAA")

	first, err := c.ReportHostKey(ctx, req)
	if err != nil {
		t.Fatalf("first ReportHostKey: %v", err)
	}
	clock.Advance(10 * time.Second) // inside StaleAfter: the stream is still healthy
	second, err := c.ReportHostKey(ctx, req)
	if err != nil {
		t.Fatalf("second ReportHostKey: %v", err)
	}

	if got := inner.calledFor("ReportHostKey"); got != 1 {
		t.Errorf("server was asked %d times, want 1: the second report must be a cache hit", got)
	}
	if second.Decision != first.Decision || !second.Known {
		t.Errorf("cached decision = %+v, want the first decision back", second)
	}
	stats := c.Stats()
	if stats.HostKeyHits != 1 || stats.HostKeyMisses != 1 || stats.HostKeyStored != 1 {
		t.Errorf("stats = %+v, want 1 host-key hit, 1 miss, 1 stored", stats)
	}
	// The point of counting them apart: authorize reuse must be readable on its
	// own, or "which call is my Control load?" has no answer (PLAN §9.1).
	if stats.Hits != 0 || stats.Misses != 0 || stats.Stored != 0 {
		t.Errorf("stats = %+v, want the authorize counters untouched by a host-key report", stats)
	}
}

// TestCachingClientAlwaysReportsAChangedHostKey is the test this phase exists
// to make pass. A cached host-key decision must never answer for a key the
// server has not ruled on: that is the man-in-the-middle case, the key-rotation
// case, and the rebuilt-host case, and all three must reach Hoplock Control on
// the first connection that sees the new key (D7).
func TestCachingClientAlwaysReportsAChangedHostKey(t *testing.T) {
	c, inner, _ := newTestCache(CacheOptions{})
	inner.hostKey = hostKeyServer(3600)
	ctx := context.Background()

	original := testHostKeyRequest("host.company.com", 22, "SHA256:ORIGINAL")
	if _, err := c.ReportHostKey(ctx, original); err != nil {
		t.Fatalf("report the original key: %v", err)
	}
	if _, err := c.ReportHostKey(ctx, original); err != nil {
		t.Fatalf("re-report the original key: %v", err)
	}
	if got := inner.calledFor("ReportHostKey"); got != 1 {
		t.Fatalf("server was asked %d times for the original key, want 1", got)
	}

	// Same target, same port, DIFFERENT key.
	impostor := testHostKeyRequest("host.company.com", 22, "SHA256:IMPOSTOR")
	if _, err := c.ReportHostKey(ctx, impostor); err != nil {
		t.Fatalf("report the new key: %v", err)
	}
	if got := inner.calledFor("ReportHostKey"); got != 2 {
		t.Errorf("server was asked %d times, want 2: a key the server has not ruled on "+
			"must be reported, however long the decision for the old key is valid", got)
	}

	// The same target on a different port is a different endpoint and a
	// different question, so it is reported too.
	otherPort := testHostKeyRequest("host.company.com", 2222, "SHA256:ORIGINAL")
	if _, err := c.ReportHostKey(ctx, otherPort); err != nil {
		t.Fatalf("report on another port: %v", err)
	}
	if got := inner.calledFor("ReportHostKey"); got != 3 {
		t.Errorf("server was asked %d times, want 3: a different port is a different shape", got)
	}

	// And the original decision is still held: reporting a new key neither
	// replaced nor invalidated it.
	if _, err := c.ReportHostKey(ctx, original); err != nil {
		t.Fatalf("re-report the original key after the impostor: %v", err)
	}
	if got := inner.calledFor("ReportHostKey"); got != 3 {
		t.Errorf("server was asked %d times, want 3: the original key was still cached", got)
	}
}

func TestCachingClientNeverReusesAHostKeyDecisionItMayNot(t *testing.T) {
	tests := []struct {
		name string
		resp *HostKeyReportResponse
		why  string
	}{
		{
			name: "no hint",
			resp: &HostKeyReportResponse{Decision: HostKeyAccept, Known: true},
			why:  "absent cache means report every connection, as every server did before 4.1",
		},
		{
			name: "zero ttl",
			resp: &HostKeyReportResponse{Decision: HostKeyAccept, Known: true, Cache: &CacheHint{Key: "hk:1"}},
			why:  "a zero lifetime is the server saying no",
		},
		{
			name: "no key",
			resp: &HostKeyReportResponse{Decision: HostKeyAccept, Known: true, Cache: &CacheHint{TTLSeconds: 300}},
			why:  "without a key there is nothing to invalidate, so there is nothing to store",
		},
		{
			name: "reject",
			resp: &HostKeyReportResponse{Decision: HostKeyReject, Known: true, Cache: &CacheHint{Key: "hk:1", TTLSeconds: 300}},
			why:  "a rejected host key is a security event the server must keep seeing",
		},
		{
			name: "first sighting",
			resp: &HostKeyReportResponse{Decision: HostKeyAccept, Known: false, Cache: &CacheHint{Key: "hk:1", TTLSeconds: 300}},
			why:  "recording the key already changed the server's own answer",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, inner, _ := newTestCache(CacheOptions{})
			inner.hostKey = func(*HostKeyReportRequest) (*HostKeyReportResponse, error) { return tc.resp, nil }
			ctx := context.Background()
			req := testHostKeyRequest("host.company.com", 22, "SHA256:AAAA")

			for i := 0; i < 3; i++ {
				if _, err := c.ReportHostKey(ctx, req); err != nil {
					t.Fatalf("ReportHostKey: %v", err)
				}
			}
			if got := inner.calledFor("ReportHostKey"); got != 3 {
				t.Errorf("server was asked %d times, want 3: %s", got, tc.why)
			}
			if stats := c.Stats(); stats.HostKeyStored != 0 || stats.Entries != 0 {
				t.Errorf("stats = %+v, want nothing stored: %s", stats, tc.why)
			}
		})
	}
}

// A report the proxy cannot key safely is never cached. Keying on the target
// alone is precisely the reuse D7 forbids, so a missing fingerprint fails
// towards reporting rather than towards a weaker key.
func TestCachingClientNeverCachesAHostKeyReportItCannotKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  *HostKeyReportRequest
	}{
		{"no fingerprint", &HostKeyReportRequest{Target: "host.company.com", HostKey: PublicKeyMaterial{Type: "ssh-ed25519"}}},
		{"no target", &HostKeyReportRequest{HostKey: PublicKeyMaterial{Fingerprint: "SHA256:AAAA"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, inner, _ := newTestCache(CacheOptions{})
			inner.hostKey = hostKeyServer(300)
			ctx := context.Background()

			for i := 0; i < 2; i++ {
				if _, err := c.ReportHostKey(ctx, tc.req); err != nil {
					t.Fatalf("ReportHostKey: %v", err)
				}
			}
			if got := inner.calledFor("ReportHostKey"); got != 2 {
				t.Errorf("server was asked %d times, want 2: an unkeyable report is never cached", got)
			}
		})
	}
}

// cache_invalidate names the server's key, and it drops a host-key decision
// exactly as it drops an authorize one.
func TestHostKeyDecisionIsDroppedByCacheInvalidate(t *testing.T) {
	c, inner, _ := newTestCache(CacheOptions{})
	inner.hostKey = hostKeyServer(3600)
	ctx := context.Background()
	req := testHostKeyRequest("host.company.com", 22, "SHA256:AAAA")

	if _, err := c.ReportHostKey(ctx, req); err != nil {
		t.Fatalf("ReportHostKey: %v", err)
	}
	c.Invalidate("hk:host.company.com|SHA256:AAAA")
	if _, err := c.ReportHostKey(ctx, req); err != nil {
		t.Fatalf("ReportHostKey after invalidate: %v", err)
	}
	if got := inner.calledFor("ReportHostKey"); got != 2 {
		t.Errorf("server was asked %d times, want 2: the invalidated decision must not be served", got)
	}
	if stats := c.Stats(); stats.Invalidated != 1 {
		t.Errorf("stats = %+v, want 1 invalidated", stats)
	}
}

func TestHostKeyDecisionIsDroppedByInvalidateAll(t *testing.T) {
	c, inner, _ := newTestCache(CacheOptions{})
	inner.hostKey = hostKeyServer(3600)
	ctx := context.Background()
	req := testHostKeyRequest("host.company.com", 22, "SHA256:AAAA")

	if _, err := c.ReportHostKey(ctx, req); err != nil {
		t.Fatalf("ReportHostKey: %v", err)
	}
	c.InvalidateAll()
	if _, err := c.ReportHostKey(ctx, req); err != nil {
		t.Fatalf("ReportHostKey after resync: %v", err)
	}
	if got := inner.calledFor("ReportHostKey"); got != 2 {
		t.Errorf("server was asked %d times, want 2: a resync drops every kind of decision", got)
	}
}

// A subject-scoped invalidation means "this person's access changed". A
// host-key decision is not made for a person, so it is not what changed — see
// CachingClient.InvalidateSubject for why dropping it would protect nobody.
func TestInvalidateSubjectLeavesHostKeyDecisionsAlone(t *testing.T) {
	c, inner, _ := newTestCache(CacheOptions{})
	inner.hostKey = hostKeyServer(3600)
	ctx := context.Background()
	req := testHostKeyRequest("host.company.com", 22, "SHA256:AAAA")

	if _, err := c.Authorize(ctx, testAuthorizeRequest("alice@example.com", "host.company.com")); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if _, err := c.ReportHostKey(ctx, req); err != nil {
		t.Fatalf("ReportHostKey: %v", err)
	}

	c.InvalidateSubject("alice@example.com")

	if _, err := c.Authorize(ctx, testAuthorizeRequest("alice@example.com", "host.company.com")); err != nil {
		t.Fatalf("Authorize after invalidate: %v", err)
	}
	if got := inner.calledFor("Authorize"); got != 2 {
		t.Errorf("Authorize reached the server %d times, want 2: alice's decision was revoked", got)
	}
	if _, err := c.ReportHostKey(ctx, req); err != nil {
		t.Fatalf("ReportHostKey after invalidate: %v", err)
	}
	if got := inner.calledFor("ReportHostKey"); got != 1 {
		t.Errorf("ReportHostKey reached the server %d times, want 1: the host key is not "+
			"alice's, and revoking her access says nothing about the target's identity", got)
	}
}

// The fail-closed rule is one rule, not one per call: a proxy that cannot hear
// revocations must not serve a host-key accept it could no longer be told to
// withdraw.
func TestHostKeyDecisionIsNotServedWhileTheStreamIsStale(t *testing.T) {
	c, inner, clock := newTestCache(CacheOptions{StaleAfter: 30 * time.Second})
	inner.hostKey = hostKeyServer(3600)
	ctx := context.Background()
	req := testHostKeyRequest("host.company.com", 22, "SHA256:AAAA")

	if _, err := c.ReportHostKey(ctx, req); err != nil {
		t.Fatalf("ReportHostKey: %v", err)
	}
	clock.Advance(31 * time.Second)
	if _, err := c.ReportHostKey(ctx, req); err != nil {
		t.Fatalf("ReportHostKey while stale: %v", err)
	}
	if got := inner.calledFor("ReportHostKey"); got != 2 {
		t.Errorf("server was asked %d times, want 2: a stale stream stops the cache being served", got)
	}
	if stats := c.Stats(); stats.StaleSkips != 1 {
		t.Errorf("stats = %+v, want 1 stale skip", stats)
	}

	// And the decision is still there once the stream is heard again: staleness
	// suspends the cache, it does not empty it.
	c.StreamAlive(clock.Now())
	if _, err := c.ReportHostKey(ctx, req); err != nil {
		t.Fatalf("ReportHostKey after recovery: %v", err)
	}
	if got := inner.calledFor("ReportHostKey"); got != 2 {
		t.Errorf("server was asked %d times after recovery, want 2: the entry was still valid", got)
	}
}

func TestHostKeyDecisionExpiresOnTheServersTTL(t *testing.T) {
	c, inner, clock := newTestCache(CacheOptions{})
	inner.hostKey = hostKeyServer(60)
	ctx := context.Background()
	req := testHostKeyRequest("host.company.com", 22, "SHA256:AAAA")

	if _, err := c.ReportHostKey(ctx, req); err != nil {
		t.Fatalf("ReportHostKey: %v", err)
	}
	clock.Advance(61 * time.Second)
	c.StreamAlive(clock.Now())
	if _, err := c.ReportHostKey(ctx, req); err != nil {
		t.Fatalf("ReportHostKey after the TTL: %v", err)
	}
	if got := inner.calledFor("ReportHostKey"); got != 2 {
		t.Errorf("server was asked %d times, want 2: the server's lifetime had passed", got)
	}
	if stats := c.Stats(); stats.Expired != 1 {
		t.Errorf("stats = %+v, want 1 expired", stats)
	}
}

// A server that issues one key string for both an authorize decision and a
// host-key decision has made a mistake, and the proxy must never resolve it by
// serving one in answer to the other. Invalidating that key still drops both,
// which is the safe direction for the ambiguity to fall.
func TestOneKeyForTwoKindsIsNeverCrossServed(t *testing.T) {
	c, inner, _ := newTestCache(CacheOptions{})
	const shared = "same-key"
	inner.authorize = func(*AuthorizeRequest) (*AuthorizeResponse, error) {
		return testAuthorizeResponse(shared, 3600), nil
	}
	inner.hostKey = func(*HostKeyReportRequest) (*HostKeyReportResponse, error) {
		return &HostKeyReportResponse{
			Decision: HostKeyAccept,
			Known:    true,
			Reason:   "already trusted",
			Cache:    &CacheHint{Key: shared, TTLSeconds: 3600},
		}, nil
	}
	ctx := context.Background()
	authReq := testAuthorizeRequest("alice@example.com", "host.company.com")
	hkReq := testHostKeyRequest("host.company.com", 22, "SHA256:AAAA")

	if _, err := c.Authorize(ctx, authReq); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	hk, err := c.ReportHostKey(ctx, hkReq)
	if err != nil {
		t.Fatalf("ReportHostKey: %v", err)
	}
	if hk.Reason != "already trusted" {
		t.Fatalf("host-key response = %+v, want the server's own answer", hk)
	}
	authz, err := c.Authorize(ctx, authReq)
	if err != nil {
		t.Fatalf("second Authorize: %v", err)
	}
	if authz.DecisionID != "decision-1" {
		t.Fatalf("authorize response = %+v, want the authorize decision", authz)
	}
	if stats := c.Stats(); stats.Entries != 2 {
		t.Errorf("stats = %+v, want 2 entries: one key per kind, never one shared entry", stats)
	}

	c.Invalidate(shared)
	if stats := c.Stats(); stats.Entries != 0 {
		t.Errorf("stats = %+v, want 0 entries: one key names every decision issued under it", stats)
	}
}

// Both kinds of lookup path are bounded by the one setting, which is the fact an
// operator sizing control.cache.max_entries has to know: a server hinting both
// halves the number of targets a given bound covers.
func TestHostKeyShapesShareTheEntryBoundWithAuthorizeShapes(t *testing.T) {
	c, inner, _ := newTestCache(CacheOptions{MaxEntries: 2})
	inner.hostKey = hostKeyServer(3600)
	ctx := context.Background()

	if _, err := c.Authorize(ctx, testAuthorizeRequest("alice@example.com", "host.company.com")); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if _, err := c.ReportHostKey(ctx, testHostKeyRequest("host.company.com", 22, "SHA256:AAAA")); err != nil {
		t.Fatalf("ReportHostKey: %v", err)
	}
	if stats := c.Stats(); stats.Shapes != 2 || stats.Evicted != 0 {
		t.Fatalf("stats = %+v, want 2 shapes and no eviction: the bound is not reached yet", stats)
	}

	// One connection to a second target needs two more paths, and the bound is
	// two: the least recently used one gives way.
	if _, err := c.Authorize(ctx, testAuthorizeRequest("alice@example.com", "other.company.com")); err != nil {
		t.Fatalf("Authorize for the second target: %v", err)
	}
	stats := c.Stats()
	if stats.Shapes != 2 {
		t.Errorf("stats = %+v, want the bound held at 2 shapes across both kinds", stats)
	}
	if stats.Evicted != 1 {
		t.Errorf("stats = %+v, want 1 eviction", stats)
	}
}
