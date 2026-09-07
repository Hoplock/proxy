// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"
)

// BenchmarkCachedEntryFootprint measures what ONE cached lookup path costs in
// heap bytes, which is the number DefaultMaxEntries is derived from and the
// number an operator raising control.cache.max_entries pays per entry.
//
// It is a measurement rather than a throughput benchmark: b.N is the working
// set, the cache is filled once, and the reported metric is heap bytes per
// lookup path (`bytes/entry`). Run it as, e.g.:
//
//	go test ./internal/control -run XXX -bench CachedEntryFootprint -benchtime 20000x
//
// Two shapes are reported because the two bound the same table from different
// ends (PLAN §6.4): a server issuing a key per (subject, target) stores one
// decision per lookup path, and a server sharing one key across a subject's
// whole estate stores one decision for all of them and pays only for the
// shapes. The per-target figure is the one to size a default from — it is the
// larger, and it is what a server that says nothing about sharing produces.
func BenchmarkCachedEntryFootprint(b *testing.B) {
	b.Run("key-per-target", func(b *testing.B) {
		benchmarkCachedEntryFootprint(b, func(target string) string { return "authz:" + target })
	})
	b.Run("one-shared-key", func(b *testing.B) {
		benchmarkCachedEntryFootprint(b, func(string) string { return "authz:shared" })
	})
}

func benchmarkCachedEntryFootprint(b *testing.B, key func(target string) string) {
	ctx := context.Background()
	clock := newTestClock()
	inner := newFakeClient()
	inner.authorize = func(req *AuthorizeRequest) (*AuthorizeResponse, error) {
		return realisticAuthorizeResponse(key(req.Target)), nil
	}
	// The bound must not bite: this measures what an entry costs, not what
	// eviction does.
	c := NewCachingClient(inner, CacheOptions{MaxEntries: b.N + 1, Now: clock.Now})
	c.StreamAlive(clock.Now())

	// Target names are the real thing: a fully qualified host name is most of
	// what a shape string holds.
	targets := make([]string, b.N)
	for i := range targets {
		targets[i] = fmt.Sprintf("edge-switch-%06d.dc3.company.example.com", i)
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	b.ResetTimer()
	for _, target := range targets {
		if _, err := c.Authorize(ctx, testAuthorizeRequest("svc-netops@example.com", target)); err != nil {
			b.Fatalf("Authorize %s: %v", target, err)
		}
	}
	b.StopTimer()

	runtime.GC()
	runtime.ReadMemStats(&after)

	if got := c.Stats().Shapes; got != b.N {
		b.Fatalf("cache holds %d shapes, want %d — the run measured eviction, not footprint", got, b.N)
	}
	b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/float64(b.N), "bytes/entry")
	runtime.KeepAlive(c)
	runtime.KeepAlive(targets)
}

// realisticAuthorizeResponse is a decision of the size a real deployment
// caches: a direct route, a channel allow-list, a request policy, and a short
// command filter. It is deliberately not the minimal response the unit tests
// use — a default sized off an empty policy would be sized off nothing.
func realisticAuthorizeResponse(key string) *AuthorizeResponse {
	deadline := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	return &AuthorizeResponse{
		RouteType:         RouteTypeDirect,
		Target:            "edge-switch-000000.dc3.company.example.com",
		TargetPort:        22,
		Permissions:       "netops-readonly",
		PermittedChannels: []string{"session"},
		PermittedRequests: &RequestPolicy{Types: []string{"pty-req", "shell", "exec", "env"}},
		FilterPolicy: FilterPolicy{
			Mode: FilterModeBlacklist,
			Rules: []FilterRule{
				{Match: "shutdown*", Action: FilterActionBlockCommand, Message: "use the change window"},
				{Match: "reload*", Action: FilterActionBlockCommand, Message: "use the change window"},
				{Match: "config*", Action: FilterActionBlockCommand},
				{Match: "execute factoryreset*", Action: FilterActionBlockCommand},
			},
		},
		SessionDeadline: &deadline,
		DecisionID:      "dec-0f3a9c21-7b4e-4c6a-9f2d-1e8b5a0c7d64",
		Cache:           &CacheHint{Key: key, TTLSeconds: 3600},
	}
}
