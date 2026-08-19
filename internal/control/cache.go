// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"context"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Cache defaults.
const (
	// DefaultStaleAfter is how long the revocation stream may be silent before
	// the cache stops being served (PLAN §6.4). It is short on purpose: the
	// window in which a withdrawn authorization could still be honoured is
	// exactly this plus the remaining TTL of an entry.
	DefaultStaleAfter = 30 * time.Second
	// DefaultMaxEntries bounds the cache so a busy proxy cannot grow it
	// without limit. Reaching it costs cache hits, never correctness.
	DefaultMaxEntries = 4096
)

// CacheOptions configures a CachingClient.
type CacheOptions struct {
	// MaxTTL clamps the server's ttl_seconds DOWNWARD ONLY: an operator may be
	// more conservative than Hoplock Control, never more permissive.
	// Zero — the default — means "no local clamp": the server's lifetime is
	// honoured exactly.
	//
	// Setting it makes this proxy behave differently from its peers, which is
	// a real operational cost: the same policy is then reused for less time
	// here than there, and "why does this proxy re-authorize more often?"
	// becomes a per-host question. That divergence must never be silent, so a
	// clamp that actually shortens a lifetime is counted in CacheStats.Clamped
	// and reported to Logger.
	MaxTTL time.Duration
	// StaleAfter is how long the revocation stream may go unheard before cached
	// decisions stop being served. Zero means DefaultStaleAfter.
	StaleAfter time.Duration
	// MaxEntries bounds the number of cached decisions. Zero means
	// DefaultMaxEntries.
	MaxEntries int
	// Now overrides the clock, so expiry is testable without sleeping.
	Now func() time.Time
	// Logger receives notice when a local setting overrides what the server
	// asked for — today, only a MaxTTL clamp. Nil discards them. It is never
	// given policy contents, only the key and the two lifetimes.
	Logger *log.Logger
}

// CacheStats counts what the cache did, for metrics and tests.
type CacheStats struct {
	// Hits are Authorize calls answered from cache.
	Hits uint64
	// Misses are Authorize calls that reached the server.
	Misses uint64
	// Expired counts entries dropped because their TTL had passed.
	Expired uint64
	// Stored counts decisions the server let us cache.
	Stored uint64
	// Invalidated counts entries dropped by a revocation event.
	Invalidated uint64
	// StaleSkips counts lookups refused because the revocation stream was
	// unheard for longer than StaleAfter — the fail-closed rule firing.
	StaleSkips uint64
	// Clamped counts stored decisions whose server lifetime was shortened by
	// CacheOptions.MaxTTL. Anything but zero means this proxy is deliberately
	// caching for less time than Hoplock Control authorised: expect a
	// lower hit rate and more authorize calls here than on a peer without the
	// clamp. It is the number to look at before blaming the server or the
	// network for a proxy that re-authorizes "too often".
	Clamped uint64
	// Entries is the number of decisions held right now.
	Entries int
}

// CacheController is the part of a CachingClient that the revocation stream
// drives. It is an interface so RevocationStream can be tested without a cache,
// and so a deployment that caches nothing can pass nil.
type CacheController interface {
	// Invalidate drops the decisions cached under the given server keys.
	Invalidate(keys ...string)
	// InvalidateSubject drops every decision cached for one subject.
	InvalidateSubject(subject string)
	// InvalidateAll drops the whole cache.
	InvalidateAll()
	// StreamAlive records that the revocation stream was known good at t. The
	// cache is served only while this is recent (see CacheOptions.StaleAfter).
	StreamAlive(t time.Time)
}

// cacheEntry is one cached authorize decision.
type cacheEntry struct {
	// key is the server's opaque CacheHint.Key, the unit of invalidation.
	key string
	// subject is the identity the decision was made for. A decision is never
	// served to another subject, even if a server reused a key across them.
	subject   string
	expiresAt time.Time
	resp      *AuthorizeResponse
}

// CachingClient decorates a Client with the server-authorised reuse of
// authorize decisions (PLAN §6.4, D2).
//
// ONLY Authorize is cached. Authentication is deliberately never cached: an MFA
// approval is a per-session assertion, and certificate validation is where
// revocation bites — skipping either would defeat the second factor or keep a
// revoked credential alive. Every other method passes straight through, and
// this is not an oversight to be "fixed" later.
//
// Two rules make a cached allow safe to hold, and they only work together:
//
//   - the server owns the lifetime. A decision is cached only when the server
//     attached a CacheHint, only for the TTL it set, and only under the key it
//     chose. CacheOptions.MaxTTL may shorten that, never extend it, and the
//     proxy never invents a hint.
//   - the proxy must be able to hear revocations. While the revocation stream
//     has been unheard for longer than StaleAfter, nothing is served from cache
//     and nothing new is stored, so every connection is re-authorized. Live
//     sessions are NOT killed: losing the ability to hear about a revocation is
//     a reason to distrust the cache, not to drop users mid-command.
//
// A CachingClient is safe for concurrent use.
type CachingClient struct {
	inner      Client
	maxTTL     time.Duration
	staleAfter time.Duration
	maxEntries int
	now        func() time.Time
	logger     *log.Logger

	mu sync.Mutex
	// shapes maps a request shape to the server key its decision was returned
	// under. It is what lets the SERVER choose the sharing scope: if the server
	// answers two different requests with one key, both shapes point at one
	// entry and one invalidation drops both. The proxy never derives a key
	// itself, so it can never share a decision the server did not share.
	shapes map[string]string
	// entries holds the decisions, keyed by the server's cache key.
	entries   map[string]*cacheEntry
	lastAlive time.Time
	stats     CacheStats
}

var (
	_ Client          = (*CachingClient)(nil)
	_ CacheController = (*CachingClient)(nil)
)

// NewCachingClient wraps inner with an authorize-decision cache.
func NewCachingClient(inner Client, opts CacheOptions) *CachingClient {
	c := &CachingClient{
		inner:      inner,
		maxTTL:     opts.MaxTTL,
		staleAfter: opts.StaleAfter,
		maxEntries: opts.MaxEntries,
		now:        opts.Now,
		logger:     opts.Logger,
		shapes:     make(map[string]string),
		entries:    make(map[string]*cacheEntry),
	}
	if c.staleAfter <= 0 {
		c.staleAfter = DefaultStaleAfter
	}
	if c.maxEntries <= 0 {
		c.maxEntries = DefaultMaxEntries
	}
	if c.now == nil {
		c.now = time.Now
	}
	return c
}

// Authorize returns a cached decision when the server authorised reuse and the
// proxy can still hear revocations; otherwise it asks the server.
func (c *CachingClient) Authorize(ctx context.Context, req *AuthorizeRequest) (*AuthorizeResponse, error) {
	shape, subject, cacheable := authorizeShape(req)
	if cacheable {
		if resp, ok := c.lookup(shape, subject); ok {
			return resp, nil
		}
	}

	resp, err := c.inner.Authorize(ctx, req)
	if err != nil {
		// A deny is never cached either: it is as revocable as an allow, and the
		// server re-decides it for free.
		return nil, err
	}
	if cacheable {
		c.store(shape, subject, resp)
	}
	return resp, nil
}

// AuthenticateCert implements Client; authentication is never cached.
func (c *CachingClient) AuthenticateCert(ctx context.Context, req *AuthenticateCertRequest) (*AuthenticateResponse, error) {
	return c.inner.AuthenticateCert(ctx, req)
}

// AuthenticatePassword implements Client; authentication is never cached.
func (c *CachingClient) AuthenticatePassword(ctx context.Context, req *AuthenticatePasswordRequest) (*AuthenticateResponse, error) {
	return c.inner.AuthenticatePassword(ctx, req)
}

// PollMFA implements Client; an MFA result is per-session and never cached.
func (c *CachingClient) PollMFA(ctx context.Context, req *MFAPollRequest) (*AuthenticateResponse, error) {
	return c.inner.PollMFA(ctx, req)
}

// ReportHostKey implements Client; it passes through.
func (c *CachingClient) ReportHostKey(ctx context.Context, req *HostKeyReportRequest) (*HostKeyReportResponse, error) {
	return c.inner.ReportHostKey(ctx, req)
}

// IngestLogBatch implements Client; it passes through.
func (c *CachingClient) IngestLogBatch(ctx context.Context, req *LogBatchRequest) (*LogBatchResponse, error) {
	return c.inner.IngestLogBatch(ctx, req)
}

// IngestPriorityLog implements Client; it passes through.
func (c *CachingClient) IngestPriorityLog(ctx context.Context, req *LogPriorityRequest) (*LogPriorityResponse, error) {
	return c.inner.IngestPriorityLog(ctx, req)
}

// StreamAlive implements CacheController.
func (c *CachingClient) StreamAlive(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t.After(c.lastAlive) {
		c.lastAlive = t
	}
}

// StreamStale reports whether the revocation stream has been unheard for longer
// than StaleAfter, in which case the cache is not served. It is true before the
// stream has ever connected: a proxy that has never heard the server must not
// trust a decision it might have been told to forget.
func (c *CachingClient) StreamStale() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.streamStaleLocked()
}

func (c *CachingClient) streamStaleLocked() bool {
	return c.now().Sub(c.lastAlive) > c.staleAfter
}

// Invalidate implements CacheController.
func (c *CachingClient) Invalidate(keys ...string) {
	if len(keys) == 0 {
		return
	}
	drop := make(map[string]bool, len(keys))
	for _, k := range keys {
		drop[k] = true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.Invalidated += uint64(c.removeLocked(func(e *cacheEntry) bool { return drop[e.key] }))
}

// InvalidateSubject implements CacheController.
func (c *CachingClient) InvalidateSubject(subject string) {
	if subject == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.Invalidated += uint64(c.removeLocked(func(e *cacheEntry) bool { return e.subject == subject }))
}

// InvalidateAll implements CacheController.
func (c *CachingClient) InvalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.Invalidated += uint64(len(c.entries))
	c.shapes = make(map[string]string)
	c.entries = make(map[string]*cacheEntry)
}

// Stats returns a snapshot of the cache counters.
func (c *CachingClient) Stats() CacheStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.stats
	out.Entries = len(c.entries)
	return out
}

// lookup returns a cached decision for shape, if one may be served.
func (c *CachingClient) lookup(shape, subject string) (*AuthorizeResponse, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.streamStaleLocked() {
		// Fail closed: we cannot hear revocations, so we do not trust what we
		// were told earlier. The entries stay put — the stream may recover, and
		// a resync will clear them if the server says so.
		c.stats.StaleSkips++
		c.stats.Misses++
		return nil, false
	}

	key, ok := c.shapes[shape]
	if !ok {
		c.stats.Misses++
		return nil, false
	}
	entry, ok := c.entries[key]
	if !ok {
		// The entry was invalidated; the mapping is stale, so drop it.
		delete(c.shapes, shape)
		c.stats.Misses++
		return nil, false
	}
	if !c.now().Before(entry.expiresAt) {
		c.stats.Expired += uint64(c.removeLocked(func(e *cacheEntry) bool { return e == entry }))
		c.stats.Misses++
		return nil, false
	}
	if entry.subject != subject {
		// The server must never share a key across identities. If one did, we
		// re-ask rather than hand one user another user's policy.
		delete(c.shapes, shape)
		c.stats.Misses++
		return nil, false
	}

	c.stats.Hits++
	return entry.resp.clone(), true
}

// store caches resp when the server authorised it.
func (c *CachingClient) store(shape, subject string, resp *AuthorizeResponse) {
	hint := resp.Cache
	// No hint, no lifetime, or no key means: do not cache. The proxy never
	// supplies any of the three itself.
	if hint == nil || hint.TTLSeconds <= 0 || hint.Key == "" {
		return
	}
	serverTTL := hint.TTL()
	ttl := serverTTL
	clamped := c.maxTTL > 0 && ttl > c.maxTTL
	if clamped {
		ttl = c.maxTTL // clamp down; never up
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Storing while we cannot hear revocations would bank a decision we could
	// not be told to forget; the entry would only be usable once the stream is
	// back, and a reconnect may replay an invalidation for it.
	if c.streamStaleLocked() {
		return
	}
	now := c.now()
	if _, replacing := c.entries[hint.Key]; !replacing && len(c.entries) >= c.maxEntries {
		c.pruneExpiredLocked(now)
		if len(c.entries) >= c.maxEntries {
			return // bounded memory wins; the cost is a cache miss
		}
	}
	if _, mapped := c.shapes[shape]; !mapped && len(c.shapes) >= c.maxEntries {
		return
	}

	c.entries[hint.Key] = &cacheEntry{
		key:       hint.Key,
		subject:   subject,
		expiresAt: now.Add(ttl),
		resp:      resp.clone(),
	}
	c.shapes[shape] = hint.Key
	c.stats.Stored++
	if clamped {
		// Counted and said out loud only when the entry was actually stored, so
		// the number matches the decisions this really applied to. This is the
		// one place the proxy holds a decision for less time than the server
		// asked; leaving it silent would make a fleet where one proxy is
		// configured differently impossible to explain from the outside.
		c.stats.Clamped++
		c.logf("control: cache: local MaxTTL shortened the server's lifetime for key %q from %s to %s",
			hint.Key, serverTTL, ttl)
	}
}

func (c *CachingClient) logf(format string, args ...any) {
	if c.logger != nil {
		c.logger.Printf(format, args...)
	}
}

// removeLocked drops every entry match reports, plus the shape mappings that
// pointed at them, and returns how many entries went. It touches no counter:
// the caller knows whether this was an invalidation or an expiry. The caller
// holds c.mu.
func (c *CachingClient) removeLocked(match func(*cacheEntry) bool) int {
	dropped := make(map[string]bool)
	for key, entry := range c.entries {
		if match(entry) {
			delete(c.entries, key)
			dropped[key] = true
		}
	}
	if len(dropped) == 0 {
		return 0
	}
	for shape, key := range c.shapes {
		if dropped[key] {
			delete(c.shapes, shape)
		}
	}
	return len(dropped)
}

// pruneExpiredLocked drops entries whose TTL has passed. The caller holds c.mu.
func (c *CachingClient) pruneExpiredLocked(now time.Time) {
	c.stats.Expired += uint64(c.removeLocked(func(e *cacheEntry) bool {
		return !now.Before(e.expiresAt)
	}))
}

// authorizeShape derives the lookup key for a request: everything that could
// change the answer. It reports the subject, and whether the request may be
// cached at all — an unauthenticated or subject-less request never is.
//
// The shape is a proxy-side lookup key only. It is NOT the cache key: the
// server's opaque CacheHint.Key decides what a decision is shared with and
// invalidated by.
func authorizeShape(req *AuthorizeRequest) (shape, subject string, cacheable bool) {
	if req == nil || req.Identity == nil || req.Identity.Subject == "" {
		return "", "", false
	}
	subject = req.Identity.Subject
	shape = strings.Join([]string{
		subject,
		req.Identity.Login,
		req.Target,
		strconv.Itoa(req.TargetPort),
		string(req.AuthMethod),
		strings.Join(req.Conn.HopTrail, ","),
	}, "\x00")
	return shape, subject, true
}

// clone deep-copies a decision, so a cached policy cannot be mutated by a
// caller that was handed it — every session gets its own copy of the
// allow-list and the filter rules.
func (r *AuthorizeResponse) clone() *AuthorizeResponse {
	if r == nil {
		return nil
	}
	out := *r
	if r.PermittedChannels != nil {
		out.PermittedChannels = append([]string(nil), r.PermittedChannels...)
	}
	if r.FilterPolicy.Rules != nil {
		out.FilterPolicy.Rules = append([]FilterRule(nil), r.FilterPolicy.Rules...)
	}
	if r.Hop != nil {
		hop := *r.Hop
		if r.Hop.HopTrail != nil {
			hop.HopTrail = append([]string(nil), r.Hop.HopTrail...)
		}
		out.Hop = &hop
	}
	if r.Cache != nil {
		hint := *r.Cache
		out.Cache = &hint
	}
	return &out
}
