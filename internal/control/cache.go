// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"container/list"
	"context"
	"errors"
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
	//
	// DERIVED, and here is the arithmetic, in the terms PLAN §9.1 uses. One
	// cached lookup path — the shape string, its map entry, its place in the
	// recency list, and the decision it names — measures **1.0 KiB** on a
	// realistic policy (measured: BenchmarkCachedEntryFootprint, key per
	// (subject, target), 1,022–1,039 bytes across working sets from 20,000 to
	// 100,000). A server sharing one key across a subject's whole estate pays
	// 0.2 KiB instead, because the decision is stored once.
	//
	// So this bound costs about **32 MiB** of live heap when it is full, and
	// roughly **55 MiB of RSS** with the default GC pacing — the fan-out runs
	// measured the proxy process growing ~1.7 KiB per cached entry against the
	// 1.0 KiB it holds, the difference being GC headroom. That is the RSS of
	// ~470 live connections at §9.1's measured 118 KiB each, or 5% of a 1 GiB
	// proxy against the ~8,800 concurrent connections §9.1 derives for that
	// budget — and it is only paid by a proxy that has actually seen 32,000
	// distinct pairs. A proxy sized to serve sessions at all can afford that
	// without an operator being asked first, which is what a default has to be.
	//
	// What it assumes: a working set of at most ~32,000 distinct
	// (subject, login, target, port, method, hop trail) shapes between
	// restarts. UC2's fan-out is an order of magnitude past that — one
	// automation against 300,000 targets (§13 UC2) — and an estate like that
	// sets control.cache.max_entries to its own working set and pays ~1 KiB
	// per entry for it deliberately. What the default must NOT be is the old
	// 4,096: chosen in phase 0003 as a guard against unbounded growth, with no
	// fan-out figure in existence, and measured in 0020 to be smaller than the
	// working set of the use case the cache matters most for.
	DefaultMaxEntries = 32768
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
	// MaxEntries bounds the number of cached LOOKUP PATHS — request shapes —
	// which is the number an operator can size from, because it is the working
	// set: one per (subject, login, target, port, method, hop trail) the proxy
	// serves. Decisions are bounded by it too and are never the larger number,
	// since a decision is held only while some shape still points at it: a
	// server sharing one key across a thousand targets stores one decision and
	// a thousand shapes, and it is the thousand that has to fit.
	//
	// Reaching the bound evicts the least recently used shape rather than
	// refusing the new decision (counted in CacheStats.Evicted), so the hit
	// rate degrades with the working set instead of freezing on whatever the
	// proxy happened to see first.
	//
	// Zero means DefaultMaxEntries.
	MaxEntries int
	// Now overrides the clock, so expiry is testable without sleeping.
	Now func() time.Time
	// Logger receives notice when a local setting overrides what the server
	// asked for — today, only a MaxTTL clamp. Nil discards them. It is never
	// given policy contents, only the key and the two lifetimes.
	Logger *log.Logger
}

// CacheStats counts what the cache did, for metrics and tests.
//
// Reuse is counted PER KIND OF DECISION, because "which call is my Hoplock
// Control load?" is the question these numbers exist to answer and one figure
// mixing authorize with host-key reuse cannot answer it (PLAN §9.1). The
// table-wide counters below — Expired, Evicted, Invalidated, StaleSkips,
// Clamped, Entries, Shapes — span both kinds, since one table holds both and an
// operator sizing it is sizing it for the total.
type CacheStats struct {
	// Hits are Authorize calls answered from cache.
	Hits uint64
	// Misses are Authorize calls that reached the server.
	Misses uint64
	// HostKeyHits are ReportHostKey calls answered from cache (phase 0023).
	HostKeyHits uint64
	// HostKeyMisses are ReportHostKey calls that reached the server. A report
	// of a key this proxy has not seen on this target is always one of these,
	// which is the property D7 rests on.
	HostKeyMisses uint64
	// Expired counts entries dropped because their TTL had passed.
	Expired uint64
	// Evicted counts lookup paths dropped to make room for a newer decision
	// because the cache was full. Anything but zero means the working set is
	// larger than MaxEntries, and that is a DIFFERENT fix from a large
	// Expired: evictions say the cache is too small for the estate, expiries
	// say the server's TTLs are shorter than the interval at which this proxy
	// comes back to the same target. Both look like a miss from outside, which
	// is why they are counted apart.
	Evicted uint64
	// Stored counts authorize decisions the server let us cache.
	Stored uint64
	// HostKeyStored counts host-key decisions the server let us cache.
	HostKeyStored uint64
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
	// Entries is the number of decisions held right now, of both kinds. Under a
	// server that shares one key widely it is far smaller than Shapes, and it
	// is NOT the number MaxEntries bounds.
	Entries int
	// Shapes is the number of cached lookup paths held right now — the
	// quantity MaxEntries bounds. It is the one to compare against the setting
	// when deciding whether a proxy needs a larger cache, and since phase 0023
	// a proxy caching both kinds holds up to TWO shapes per connection: one
	// authorize path and one host-key path. An estate sizing
	// control.cache.max_entries to its target count under a server that hints
	// both must therefore double it, and the setting's name does not say so.
	Shapes int
}

// hit and miss route a lookup outcome to the counter for its kind, so the
// per-kind pairs stay coherent (hits + misses == calls of that kind).
func (s *CacheStats) hit(kind entryKind) {
	if kind == kindHostKey {
		s.HostKeyHits++
		return
	}
	s.Hits++
}

func (s *CacheStats) miss(kind entryKind) {
	if kind == kindHostKey {
		s.HostKeyMisses++
		return
	}
	s.Misses++
}

func (s *CacheStats) stored(kind entryKind) {
	if kind == kindHostKey {
		s.HostKeyStored++
		return
	}
	s.Stored++
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

// entryKind names which decision an entry holds (phase 0023).
//
// It namespaces the entries map, so a server that happened to issue the same
// opaque key string for an authorize decision and a host-key decision can never
// have one served in answer to the other. An Invalidate naming that key still
// drops both, which is the safe direction for the ambiguity to fall.
type entryKind string

const (
	kindAuthorize entryKind = "authorize"
	kindHostKey   entryKind = "hostkey"
)

// entryKey namespaces the server's opaque key by the kind of decision it came
// attached to. The unnamespaced key stays on the entry, because that is the
// form a cache_invalidate event carries.
func entryKey(kind entryKind, key string) string {
	return string(kind) + "\x00" + key
}

// cacheEntry is one cached decision. Exactly one of authorize and hostKey is
// set, and which one is fixed by kind.
type cacheEntry struct {
	kind entryKind
	// key is the server's opaque CacheHint.Key, the unit of invalidation.
	key string
	// subject is the identity the decision was made for. A decision is never
	// served to another subject, even if a server reused a key across them.
	//
	// It is EMPTY for a host-key decision, which is not made for an identity at
	// all: the server was asked whether a target presenting a given key may be
	// reached, and nothing in that answer depends on who is connecting. See
	// InvalidateSubject for what that means when a subject's access is revoked.
	subject   string
	expiresAt time.Time
	authorize *AuthorizeResponse
	hostKey   *HostKeyReportResponse
	// refs is how many shape mappings point at this decision. A decision the
	// server shared across many targets has many; one that reaches zero is
	// unreachable and goes with the last shape that named it, which is what
	// keeps the two tables bounded by one number instead of two.
	refs int
}

// shapeMapping is one lookup path: a request shape, the entries-map key its
// decision was returned under, and its place in the recency list.
type shapeMapping struct {
	// key is the entries-map key — entryKey(kind, the server's key) — not the
	// server's key on its own.
	key string
	// elem is this shape's element in CachingClient.lru, so a hit is a
	// constant-time move to the front and an eviction is a constant-time read
	// of the back.
	elem *list.Element
}

// CachingClient decorates a Client with the server-authorised reuse of
// decisions (PLAN §6.4, D2).
//
// TWO calls are cached, both on the one mechanism §6.4 defines — an opaque
// server key, a server-set lifetime, and the revocation stream that bounds
// both: Authorize (phase 0003) and ReportHostKey (phase 0023). They share one
// table, one bound and one fail-closed rule; what differs is only the lookup
// shape, and each method documents its own.
//
// AUTHENTICATION IS NEVER CACHED, and never will be: an MFA approval is a
// per-session assertion, and certificate validation is where revocation bites —
// skipping either would defeat the second factor or keep a revoked credential
// alive. Every other method passes straight through, and that is not an
// oversight to be "fixed" later.
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
	// shapes maps a request shape to the entries-map key its decision was
	// returned under. It is what lets the SERVER choose the sharing scope: if
	// the server answers two different requests with one key, both shapes point
	// at one entry and one invalidation drops both. The proxy never derives a
	// key itself, so it can never share a decision the server did not share.
	//
	// Both kinds of decision share this map — a shape is prefixed by its kind
	// and can never be confused with the other's — so CacheOptions.MaxEntries
	// bounds the two together (see CacheStats.Shapes).
	shapes map[string]*shapeMapping
	// lru orders the shapes by last use, most recent at the front. Its values
	// are shape strings. It is the eviction order: a full cache drops from the
	// back rather than refusing what it was just told.
	lru *list.List
	// entries holds the decisions, keyed by entryKey(kind, the server's key).
	entries   map[string]*cacheEntry
	lastAlive time.Time
	stats     CacheStats
}

var (
	_ Client             = (*CachingClient)(nil)
	_ CacheController    = (*CachingClient)(nil)
	_ CapabilityReporter = (*CachingClient)(nil)
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
		shapes:     make(map[string]*shapeMapping),
		lru:        list.New(),
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
		if cached, ok := c.cachedAuthorize(shape, subject); ok {
			return cached, nil
		}
	}

	resp, err := c.inner.Authorize(ctx, req)
	if err != nil {
		// A deny is never cached either: it is as revocable as an allow, and the
		// server re-decides it for free.
		return nil, err
	}
	if cacheable {
		c.store(shape, kindAuthorize, subject, resp.Cache, func(e *cacheEntry) {
			e.authorize = resp.Clone()
		})
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

// ReportHostKey returns a cached trust decision when the server authorised
// reuse of one for this exact (target, port, host key), and otherwise reports
// (phase 0023).
//
// The lookup shape INCLUDES THE KEY'S FINGERPRINT, and that clause is the whole
// security argument. A target presenting a key this proxy has not already had
// ruled on is a different shape, misses, and is reported — so the
// man-in-the-middle, the rotated key and the rebuilt host all still reach
// Hoplock Control on the first connection that sees the new key, which is the
// case D7 exists for.
//
// Two answers are deliberately never cached, however the server hints them:
//
//   - a REJECT. It is as revocable as an accept and the server re-decides it
//     for free, exactly as with an authorize deny; and a rejected host key is a
//     security event the server must keep seeing rather than one this proxy
//     silently stops reporting.
//   - a FIRST SIGHTING (known == false). The server's own answer to the same
//     question has already changed by recording the key, so reusing this one
//     would replay "trusted on first use" — into the audit log, not just a
//     console line — for every later connection. The first sighting is the one
//     report D7 is actually about; the connection after it establishes the
//     steady state that this phase makes free.
func (c *CachingClient) ReportHostKey(ctx context.Context, req *HostKeyReportRequest) (*HostKeyReportResponse, error) {
	shape, cacheable := hostKeyShape(req)
	if cacheable {
		if cached, ok := c.cachedHostKey(shape); ok {
			return cached, nil
		}
	}

	resp, err := c.inner.ReportHostKey(ctx, req)
	if err != nil {
		return nil, err
	}
	if cacheable && resp.Decision == HostKeyAccept && resp.Known {
		c.store(shape, kindHostKey, "", resp.Cache, func(e *cacheEntry) {
			e.hostKey = resp.Clone()
		})
	}
	return resp, nil
}

// IngestLogBatch implements Client; it passes through.
func (c *CachingClient) IngestLogBatch(ctx context.Context, req *LogBatchRequest) (*LogBatchResponse, error) {
	return c.inner.IngestLogBatch(ctx, req)
}

// IngestPriorityLog implements Client; it passes through.
func (c *CachingClient) IngestPriorityLog(ctx context.Context, req *LogPriorityRequest) (*LogPriorityResponse, error) {
	return c.inner.IngestPriorityLog(ctx, req)
}

// ReportCapabilities implements CapabilityReporter by forwarding to the wrapped
// client, so a proxy holding a CachingClient can still report what a target can
// enforce (contract v4).
//
// A capability report is an OBSERVATION and is never cached: it is the proxy
// telling the server what it just saw, and a decorator that answered from
// memory would be reporting the past. If the wrapped client cannot report — a
// test double, a transport that predates the endpoint — that is a contract
// failure and says so, rather than pretending the report was made.
func (c *CachingClient) ReportCapabilities(ctx context.Context, req *CapabilityReportRequest) (*CapabilityReportResponse, error) {
	reporter, ok := c.inner.(CapabilityReporter)
	if !ok {
		return nil, protocolError("ReportCapabilities",
			errors.New("the wrapped client cannot report target capabilities"))
	}
	return reporter.ReportCapabilities(ctx, req)
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

// Invalidate implements CacheController. It matches on the server's key as the
// server issued it, so one key drops every decision the server attached it to —
// an authorize decision and a host-key decision alike.
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
//
// It drops AUTHORIZE decisions only, and that is deliberate rather than an
// oversight of phase 0023. A host-key decision is not made for a subject: the
// server was asked whether a target presenting a given key may be reached, and
// the answer is the same for everyone. Dropping it when one user's access is
// withdrawn would neither withdraw anything nor protect anyone — it would only
// make the next connection by an unaffected user report a key the server has
// already ruled on.
//
// A server that wants to withdraw HOST-KEY trust says so with the key, via
// Invalidate (cache_invalidate), or clears everything with a resync. Those are
// the two mechanisms that mean "stop trusting what I told you", and this one
// means "this person's access changed".
func (c *CachingClient) InvalidateSubject(subject string) {
	if subject == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.Invalidated += uint64(c.removeLocked(func(e *cacheEntry) bool {
		return e.kind == kindAuthorize && e.subject == subject
	}))
}

// InvalidateAll implements CacheController.
func (c *CachingClient) InvalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.Invalidated += uint64(len(c.entries))
	c.shapes = make(map[string]*shapeMapping)
	c.lru = list.New()
	c.entries = make(map[string]*cacheEntry)
}

// Stats returns a snapshot of the cache counters.
func (c *CachingClient) Stats() CacheStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.stats
	out.Entries = len(c.entries)
	out.Shapes = len(c.shapes)
	return out
}

// cachedAuthorize and cachedHostKey are the two ways in. Each takes the lock,
// looks the shape up, and CLONES UNDER THE LOCK: a stored decision is refreshed
// in place when the server answers again under the same key, so a copy taken
// outside the lock would race with that write. Nothing outside this file ever
// holds a pointer into the cache.
func (c *CachingClient) cachedAuthorize(shape, subject string) (*AuthorizeResponse, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.lookupLocked(shape, kindAuthorize, subject)
	if !ok {
		return nil, false
	}
	return entry.authorize.Clone(), true
}

func (c *CachingClient) cachedHostKey(shape string) (*HostKeyReportResponse, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// A host-key decision is not made for an identity, so there is no subject
	// to match: "" is what store put on the entry.
	entry, ok := c.lookupLocked(shape, kindHostKey, "")
	if !ok {
		return nil, false
	}
	return entry.hostKey.Clone(), true
}

// lookupLocked returns the cached entry for shape, if one may be served.
//
// subject is the identity the answer is for, and is "" for a kind that is not
// made for an identity. It must match what was stored either way, so a decision
// made for one subject can never be served to another.
//
// The caller holds c.mu.
func (c *CachingClient) lookupLocked(shape string, kind entryKind, subject string) (*cacheEntry, bool) {
	if c.streamStaleLocked() {
		// Fail closed: we cannot hear revocations, so we do not trust what we
		// were told earlier. That covers host-key decisions too — an accept we
		// could not be told to withdraw is exactly what a compromised target
		// would want us to keep. The entries stay put: the stream may recover,
		// and a resync will clear them if the server says so.
		c.stats.StaleSkips++
		c.stats.miss(kind)
		return nil, false
	}

	mapping, ok := c.shapes[shape]
	if !ok {
		c.stats.miss(kind)
		return nil, false
	}
	entry, ok := c.entries[mapping.key]
	if !ok {
		// The entry was invalidated; the mapping is stale, so drop it.
		c.dropShapeLocked(shape)
		c.stats.miss(kind)
		return nil, false
	}
	if !c.now().Before(entry.expiresAt) {
		c.stats.Expired += uint64(c.removeLocked(func(e *cacheEntry) bool { return e == entry }))
		c.stats.miss(kind)
		return nil, false
	}
	if entry.subject != subject {
		// The server must never share a key across identities. If one did, we
		// re-ask rather than hand one user another user's policy.
		c.dropShapeLocked(shape)
		c.stats.miss(kind)
		return nil, false
	}

	// A hit is a use: it moves this shape to the front of the recency order,
	// which is what makes a working set smaller than the bound survive a long
	// tail of one-off targets sweeping past it.
	c.lru.MoveToFront(mapping.elem)
	c.stats.hit(kind)
	return entry, true
}

// store caches a decision when the server authorised it. fill sets the field
// on the entry that this kind holds, from a copy the caller owns.
func (c *CachingClient) store(shape string, kind entryKind, subject string, hint *CacheHint, fill func(*cacheEntry)) {
	// No hint, no lifetime, or no key means: do not cache. The proxy never
	// supplies any of the three itself.
	if hint == nil || hint.TTLSeconds <= 0 || hint.Key == "" {
		return
	}
	mapKey := entryKey(kind, hint.Key)
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

	// A shape already pointing at a DIFFERENT key is a key the server rotated;
	// the old decision loses this reference and goes if it was the last one.
	if mapping, mapped := c.shapes[shape]; mapped && mapping.key != mapKey {
		c.dropShapeLocked(shape)
	}

	if _, mapped := c.shapes[shape]; !mapped {
		// Room is made for the new lookup path, not refused to it. Expired
		// entries go first — they are free and nobody wanted them — and only
		// then does the least recently used shape give way. A full cache that
		// dropped the new decision instead would make the hit rate a function
		// of which targets this proxy happened to see first, and no amount of
		// server-side key sharing could reach it (PLAN §9.1).
		if len(c.shapes) >= c.maxEntries {
			c.pruneExpiredLocked(now)
		}
		for len(c.shapes) >= c.maxEntries && c.lru.Len() > 0 {
			c.evictOldestLocked()
		}
	}

	entry, held := c.entries[mapKey]
	if held {
		// The server answered under a key we already hold: refresh it in place
		// so the shapes already pointing at it keep pointing at it.
		entry.subject = subject
		entry.expiresAt = now.Add(ttl)
	} else {
		entry = &cacheEntry{
			kind:      kind,
			key:       hint.Key,
			subject:   subject,
			expiresAt: now.Add(ttl),
		}
		c.entries[mapKey] = entry
	}
	fill(entry)
	if mapping, mapped := c.shapes[shape]; mapped {
		c.lru.MoveToFront(mapping.elem)
	} else {
		c.shapes[shape] = &shapeMapping{key: mapKey, elem: c.lru.PushFront(shape)}
		entry.refs++
	}
	c.stats.stored(kind)
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
	for shape, mapping := range c.shapes {
		if dropped[mapping.key] {
			delete(c.shapes, shape)
			c.lru.Remove(mapping.elem)
		}
	}
	return len(dropped)
}

// dropShapeLocked removes one lookup path, and with it the decision it named
// if no other shape still points at that decision. It touches no counter: the
// caller knows why the shape was dropped. The caller holds c.mu.
func (c *CachingClient) dropShapeLocked(shape string) {
	mapping, ok := c.shapes[shape]
	if !ok {
		return
	}
	delete(c.shapes, shape)
	c.lru.Remove(mapping.elem)
	entry, held := c.entries[mapping.key]
	if !held {
		return
	}
	entry.refs--
	if entry.refs <= 0 {
		delete(c.entries, mapping.key)
	}
}

// evictOldestLocked drops the least recently used lookup path to make room.
// The caller holds c.mu and has checked that the list is not empty.
func (c *CachingClient) evictOldestLocked() {
	oldest := c.lru.Back()
	if oldest == nil {
		return
	}
	c.dropShapeLocked(oldest.Value.(string))
	c.stats.Evicted++
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
		string(kindAuthorize),
		subject,
		req.Identity.Login,
		req.Target,
		strconv.Itoa(req.TargetPort),
		string(req.AuthMethod),
		strings.Join(req.Conn.HopTrail, ","),
	}, "\x00")
	return shape, subject, true
}

// hostKeyShape derives the lookup key for a host-key report: the target, the
// port, and THE KEY ITSELF. Everything that could change the server's answer is
// in it, and the fingerprint is the part that matters — it is what makes a
// cache hit mean "the server has ruled on this exact pair" rather than "the
// server has ruled on this target".
//
// A report without a fingerprint is never cacheable. The proxy would then be
// keying on the target alone, which is precisely the reuse D7 forbids, so the
// absence fails towards reporting rather than towards a weaker key.
//
// The type is included alongside the fingerprint even though a SHA256 of the
// wire encoding already implies it, and the certificate flag likewise: it costs
// a few bytes and removes the need for anyone to reason about whether it does.
//
// Like authorizeShape this is a proxy-side lookup key only, never the cache
// key: the server's opaque CacheHint.Key still decides sharing scope and
// invalidation.
func hostKeyShape(req *HostKeyReportRequest) (shape string, cacheable bool) {
	if req == nil || req.Target == "" || req.HostKey.Fingerprint == "" {
		return "", false
	}
	isCert := "key"
	if req.HostKey.IsCertificate {
		isCert = "cert"
	}
	shape = strings.Join([]string{
		string(kindHostKey),
		req.Target,
		strconv.Itoa(req.TargetPort),
		req.HostKey.Type,
		isCert,
		req.HostKey.Fingerprint,
	}, "\x00")
	return shape, true
}
