// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// This file is phase 0035: where the floor under an ephemeral account's uid is
// held, and why it is not the target's and not any single proxy's.
//
// Phase 0027 made uid allocation non-reusing — strictly above everything a
// target has ever been given — and kept the high-water mark ON THE TARGET, which
// is the party this proxy does not trust. That is load-bearing in one situation
// no attacker is needed to reach: a proxy that has RESTARTED. Its in-process
// record is empty, so it has only the target's word for the floor, and a mark
// that has been lowered — deleted by root, lost with a reimaged host, never
// writable in the first place — puts a torn-down session's uid back in play.
//
// A LEASE is the shape that survives all of it. Hoplock Control grants this
// proxy an EXCLUSIVE block of uids for a target and the proxy allocates inside
// its own block locally. Every property falls out of exclusivity:
//
//   - two proxies holding two blocks cannot collide, so nothing reads a shared
//     counter on the session path;
//   - a granted block is safe to hold across a Control OUTAGE, because it
//     cannot have been granted to anybody else — which is what keeps
//     provisioning from being coupled to Control's availability, the way PLAN
//     §5.1's teardown and D16's deadline are deliberately not coupled;
//   - it costs one call per BLOCK, not per session, so the per-connection
//     budget phases 0022 and 0023 spent themselves reducing (PLAN §9.1) is
//     untouched;
//   - Control's whole storage requirement is a per-target allocation cursor it
//     advances on grant.
//
// THE FLOOR MUST NOT BE A FIELD ON THE AUTHORIZE RESPONSE, and that is the trap
// worth naming here rather than only in the plan. An authorize decision is
// CACHEABLE (§6.4) and CachingClient serves one while Control is unreachable, so
// a floor riding on it is replayed from whenever it was cached — and a stale
// floor is a LOWERED floor, which is the reuse this exists to prevent. Anything
// cacheable is disqualified the same way. A lease is not, because it is
// exclusive: replaying it grants the same block to the same proxy.
//
// Note what is deliberately absent below: CachingClient does not forward
// LeaseUIDs. A decorator that answered a lease from memory would be replaying a
// floor, so the shape of the interfaces makes that a compile error rather than a
// review comment.

// PathLeaseUIDs grants a proxy an exclusive block of ephemeral uids for one
// target (contract 4.3, phase 0035).
const PathLeaseUIDs = "/v1/uids/lease"

// DefaultUIDLeaseTerm is how long a block is used for when the server sets no
// term. A day is chosen against what the term actually costs: it is not what
// makes a uid non-reusable — Control's cursor only advances, so an expired block
// is never granted to anybody else — it is how long this proxy may keep
// provisioning on this target WITHOUT REACHING CONTROL. Shorter buys nothing and
// narrows the outage a proxy rides out.
const DefaultUIDLeaseTerm = 24 * time.Hour

// DefaultUIDLeaseRenewBefore is how far ahead of a block's end the holder renews
// in the background. Renewal is off the session path, so this is pure headroom:
// a Control outage has to start inside this window, on a target with a nearly
// spent block, to be felt at all.
const DefaultUIDLeaseRenewBefore = 1 * time.Hour

// uidLeaseRenewFraction is the share of a block that must be LEFT before the
// holder renews on space. A block renewed at one eighth remaining leaves enough
// to serve an outage that starts immediately afterwards, and wastes at most that
// eighth — uids the cursor has already burned either way.
const uidLeaseRenewFraction = 8

// uidLeaseCallTimeout bounds one lease call made in the background. The
// foreground ones are bounded by the session's own context.
const uidLeaseCallTimeout = 30 * time.Second

// UIDLeaseRequest asks for an exclusive block of uids for one target.
type UIDLeaseRequest struct {
	// ProxyID is the proxy the block is granted to. A lease is per proxy per
	// target and is NOT made on behalf of a session, which is why there is no
	// ConnMeta here.
	ProxyID string `json:"proxy_id"`
	// Target is the host the block is for.
	Target string `json:"target"`
	// TargetPort is the port, when it is not the default.
	TargetPort int `json:"target_port,omitempty"`
	// UIDCount is how many uids the proxy would like. It is a REQUEST: the
	// server grants what it chooses and the proxy uses what it is granted.
	UIDCount int `json:"uid_count,omitempty"`
	// RangeMin and RangeMax bound the range this proxy will accept a block
	// from. A server with no range of its own for the target may allocate from
	// them; one with its own ignores them. Either way the proxy refuses a block
	// outside them.
	RangeMin int `json:"range_min,omitempty"`
	RangeMax int `json:"range_max,omitempty"`
	// ObservedFloor is the highest uid the proxy has seen given out on this
	// target — the target's own high-water mark and account database.
	//
	// It is AN OBSERVATION FROM AN UNTRUSTED PARTY and the server's to clamp or
	// ignore. It may only ever raise a cursor, never lower one, which is the
	// same relationship a capability report has to a rung; it is sent so that a
	// server whose cursor sits below a mark left by an earlier deployment
	// catches up instead of granting blocks this proxy must discard.
	ObservedFloor int `json:"observed_floor,omitempty"`
}

// UIDLeaseResponse is one granted block.
type UIDLeaseResponse struct {
	// LeaseID names the grant. It goes on the provisioning record beside the
	// uid, so an incident can say which proxy's block a uid came from.
	LeaseID string `json:"lease_id"`
	// UIDFrom is the first uid in the block, inclusive.
	UIDFrom int `json:"uid_from"`
	// UIDTo is the end of the block, EXCLUSIVE.
	UIDTo int `json:"uid_to"`
	// TermSeconds is how long the proxy may keep allocating from the block.
	// Zero means DefaultUIDLeaseTerm. The proxy may stop sooner, never later.
	TermSeconds int `json:"term_seconds,omitempty"`
}

// Term returns TermSeconds as a duration, resolving the absent-value default.
func (r *UIDLeaseResponse) Term() time.Duration {
	if r == nil || r.TermSeconds <= 0 {
		return DefaultUIDLeaseTerm
	}
	return time.Duration(r.TermSeconds) * time.Second
}

// UIDLeaser is implemented by clients that can lease uid blocks. It is a
// SEPARATE, NARROWER INTERFACE rather than a method on Client for the reason
// CapabilityReporter is: the call is made by one caller on one path, and every
// other consumer of Client would only have to grow a stub.
type UIDLeaser interface {
	// LeaseUIDs grants an exclusive block of uids for a target. Its error
	// contract is Client's: only IsUnauthorized is a decision.
	LeaseUIDs(ctx context.Context, req *UIDLeaseRequest) (*UIDLeaseResponse, error)
}

// UIDBlock is a block of uids this proxy holds exclusively for one target.
// The range is half-open: From is the first uid, To is one past the last.
type UIDBlock struct {
	// LeaseID names the grant this block came from. Empty means the block was
	// not leased at all — see UIDLeaseSource for the one case that happens in.
	LeaseID string
	// From is the first uid in the block, inclusive.
	From int
	// To is the end of the block, exclusive.
	To int
	// Expires is when the proxy must stop allocating from the block. The zero
	// time means it never does.
	Expires time.Time
}

// Empty reports whether the block holds no uids at all.
func (b UIDBlock) Empty() bool { return b.To <= b.From }

// Live reports whether the block may still be allocated from.
//
// An expired block is one THIS PROXY stops using, never one the server hands to
// somebody else: Control's cursor only advances, so the uids inside it are
// retired whether or not they were ever issued. That is why expiry costs
// availability and never the invariant.
func (b UIDBlock) Live(now time.Time) bool {
	if b.Empty() {
		return false
	}
	return b.Expires.IsZero() || now.Before(b.Expires)
}

// UIDLeaseSource hands out the block a target's uids are allocated from. It is
// the interface the credential plane depends on; *UIDLeaseHolder is the
// implementation that talks to Hoplock Control.
type UIDLeaseSource interface {
	// Block returns the block currently held for a target, leasing one if there
	// is none or the held one has ended. floor is the highest uid the proxy has
	// observed given out there, which the holder passes on as an observation
	// and uses to decide whether the held block is nearly spent.
	Block(ctx context.Context, target string, port, floor int) (UIDBlock, error)
	// Replace leases a fresh block to take over from one that can no longer
	// serve an allocation. A spent block that has ALREADY been replaced — by a
	// concurrent session on the same target — yields the newer one instead of a
	// second call.
	Replace(ctx context.Context, target string, port, floor int, spent UIDBlock) (UIDBlock, error)
}

// UIDLeaseOptions configures a UIDLeaseHolder.
type UIDLeaseOptions struct {
	// Client makes the lease calls. Required.
	//
	// It is the REST client and never the caching one, which is not a
	// preference: see the note at the top of this file.
	Client UIDLeaser
	// ProxyID identifies this proxy to the server. Required — a block is
	// granted to a proxy, and an unnamed one cannot be granted anything.
	ProxyID string
	// UIDCount is how many uids to ask for per block. Zero asks for the
	// server's choice.
	UIDCount int
	// RangeMin and RangeMax bound the range this proxy accepts a block from.
	// Zero on either sends no bound and accepts whatever is granted.
	RangeMin int
	RangeMax int
	// RenewBefore is how far ahead of a block's term the holder renews in the
	// background. Zero means DefaultUIDLeaseRenewBefore.
	RenewBefore time.Duration
	// Logf receives renewal and refusal events; nil discards them.
	Logf func(format string, args ...any)
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// UIDLeaseHolder holds one leased block per target and renews it before it ends.
//
// The block is NOT persisted. A restarted proxy re-leases, and that is the
// simpler half of a choice worth recording: a fresh lease is a fresh block, and
// the cursor at Control is what makes it non-overlapping — so proxy-local
// durable state would buy nothing the cursor does not already give, while adding
// a file whose staleness would be indistinguishable from a lowered floor.
type UIDLeaseHolder struct {
	client      UIDLeaser
	proxyID     string
	count       int
	rangeMin    int
	rangeMax    int
	renewBefore time.Duration
	logf        func(string, ...any)
	now         func() time.Time

	mu     sync.Mutex
	byAddr map[string]*uidLeaseEntry
}

// uidLeaseEntry is one target's held block. Its own mutex is what keeps two
// sessions provisioning on one target from making two lease calls — and keeps a
// lease call for one target off the path of every other.
type uidLeaseEntry struct {
	mu       sync.Mutex
	block    UIDBlock
	renewing bool
}

var _ UIDLeaseSource = (*UIDLeaseHolder)(nil)

// NewUIDLeaseHolder returns a holder over the given client.
func NewUIDLeaseHolder(opts UIDLeaseOptions) (*UIDLeaseHolder, error) {
	if opts.Client == nil {
		return nil, fmt.Errorf("control: a uid lease holder needs a client")
	}
	if opts.ProxyID == "" {
		return nil, fmt.Errorf("control: a uid lease holder needs a proxy id")
	}
	if opts.UIDCount < 0 {
		return nil, fmt.Errorf("control: uid lease count %d is negative", opts.UIDCount)
	}
	h := &UIDLeaseHolder{
		client:      opts.Client,
		proxyID:     opts.ProxyID,
		count:       opts.UIDCount,
		rangeMin:    opts.RangeMin,
		rangeMax:    opts.RangeMax,
		renewBefore: opts.RenewBefore,
		logf:        opts.Logf,
		now:         opts.Now,
		byAddr:      map[string]*uidLeaseEntry{},
	}
	if h.renewBefore <= 0 {
		h.renewBefore = DefaultUIDLeaseRenewBefore
	}
	if h.now == nil {
		h.now = time.Now
	}
	if h.logf == nil {
		h.logf = func(string, ...any) {}
	}
	return h, nil
}

// Block implements UIDLeaseSource.
func (h *UIDLeaseHolder) Block(ctx context.Context, target string, port, floor int) (UIDBlock, error) {
	e := h.entry(target, port)
	e.mu.Lock()
	held := e.block
	if held.Live(h.now()) && held.To > floor {
		// The held block can still serve. Renewing it early is background work
		// and never this session's latency: the whole point of a lease is that
		// the session path makes no call.
		h.renewInBackground(e, target, port, floor)
		e.mu.Unlock()
		return held, nil
	}
	defer e.mu.Unlock()
	return h.lease(ctx, e, target, port, floor)
}

// Replace implements UIDLeaseSource.
func (h *UIDLeaseHolder) Replace(ctx context.Context, target string, port, floor int, spent UIDBlock) (UIDBlock, error) {
	e := h.entry(target, port)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.block.LeaseID != spent.LeaseID || e.block.To != spent.To {
		// Somebody else already replaced it. Taking a second block here would
		// burn one for nothing.
		return e.block, nil
	}
	return h.lease(ctx, e, target, port, floor)
}

// entry finds or creates the per-target holder state.
func (h *UIDLeaseHolder) entry(target string, port int) *uidLeaseEntry {
	key := uidLeaseKey(target, port)
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.byAddr[key]
	if !ok {
		e = &uidLeaseEntry{}
		h.byAddr[key] = e
	}
	return e
}

// lease calls the server and stores what it granted. The caller holds e.mu.
func (h *UIDLeaseHolder) lease(ctx context.Context, e *uidLeaseEntry, target string, port, floor int) (UIDBlock, error) {
	resp, err := h.client.LeaseUIDs(ctx, &UIDLeaseRequest{
		ProxyID:       h.proxyID,
		Target:        target,
		TargetPort:    port,
		UIDCount:      h.count,
		RangeMin:      h.rangeMin,
		RangeMax:      h.rangeMax,
		ObservedFloor: floor,
	})
	if err != nil {
		return UIDBlock{}, err
	}
	block, err := h.accept(resp)
	if err != nil {
		return UIDBlock{}, err
	}
	e.block = block
	h.logf("control: leased uids %d-%d for %s (lease %s, term %s)",
		block.From, block.To-1, uidLeaseKey(target, port), block.LeaseID, block.Expires.Sub(h.now()).Round(time.Second))
	return block, nil
}

// accept turns a granted block into one this proxy will allocate from, or
// refuses it.
//
// THE RANGE CHECK IS NOT A FORMALITY. RangeMin/RangeMax encode facts about the
// fleet the server has no way to know — above every distribution's own UID_MAX,
// above systemd's dynamic-user range, below 2^31 so a uid stays a positive
// int32 — and a block outside them would collide with the target's OWN accounts,
// which is a worse failure than the one the lease exists to prevent. So a block
// outside the configured range is refused rather than clamped: clamping would
// silently change what the server granted, and the two would then disagree about
// which uids are spent.
func (h *UIDLeaseHolder) accept(resp *UIDLeaseResponse) (UIDBlock, error) {
	if resp == nil {
		return UIDBlock{}, protocolError("LeaseUIDs", errors.New("the server granted no uid block"))
	}
	if resp.LeaseID == "" {
		return UIDBlock{}, protocolError("LeaseUIDs", errors.New("the server granted a uid block with no lease id"))
	}
	if resp.UIDTo <= resp.UIDFrom {
		return UIDBlock{}, protocolError("LeaseUIDs",
			fmt.Errorf("the server granted an empty uid block [%d,%d)", resp.UIDFrom, resp.UIDTo))
	}
	if h.rangeMin > 0 && resp.UIDFrom < h.rangeMin {
		return UIDBlock{}, protocolError("LeaseUIDs",
			fmt.Errorf("the server granted uids from %d, below the configured uid_min %d", resp.UIDFrom, h.rangeMin))
	}
	if h.rangeMax > 0 && resp.UIDTo-1 > h.rangeMax {
		return UIDBlock{}, protocolError("LeaseUIDs",
			fmt.Errorf("the server granted uids to %d, above the configured uid_max %d", resp.UIDTo-1, h.rangeMax))
	}
	return UIDBlock{
		LeaseID: resp.LeaseID,
		From:    resp.UIDFrom,
		To:      resp.UIDTo,
		Expires: h.now().Add(resp.Term()),
	}, nil
}

// renewInBackground takes a fresh block when the held one is close to its end,
// on a detached context. The caller holds e.mu.
//
// Nothing waits for it and its failure changes nothing: the held block still
// serves until it is spent or expires, and the session that finds it spent then
// leases in the foreground. That is the ordinary Control outage, and the
// headroom this renewal buys is exactly what keeps it from being felt.
func (h *UIDLeaseHolder) renewInBackground(e *uidLeaseEntry, target string, port, floor int) {
	if e.renewing || !h.nearlyDone(e.block, floor) {
		return
	}
	e.renewing = true
	spent := e.block
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), uidLeaseCallTimeout)
		defer cancel()
		e.mu.Lock()
		defer func() {
			e.renewing = false
			e.mu.Unlock()
		}()
		if e.block.LeaseID != spent.LeaseID {
			return
		}
		if _, err := h.lease(ctx, e, target, port, floor); err != nil {
			h.logf("control: could not renew the uid lease for %s ahead of time; the block in hand still serves: %v",
				uidLeaseKey(target, port), err)
		}
	}()
}

// nearlyDone reports whether a block is close enough to its end — in uids or in
// time — to be worth replacing before a session needs it to be.
func (h *UIDLeaseHolder) nearlyDone(b UIDBlock, floor int) bool {
	if b.Empty() {
		return true
	}
	if !b.Expires.IsZero() && h.now().Add(h.renewBefore).After(b.Expires) {
		return true
	}
	next := b.From
	if floor >= next {
		next = floor + 1
	}
	return b.To-next <= (b.To-b.From)/uidLeaseRenewFraction
}

// uidLeaseKey is how a target is named to the holder.
//
// It is host and port, which is how PLAN §5.1's mark, §6.4's host-key decisions
// and contract v4's capability reports are all keyed, and it carries the same
// known imprecision: several DNS names resolving to one host are several keys.
// That is a TARGET-IDENTITY question, it is phase 0029's, and it is deliberately
// not answered a second time here.
func uidLeaseKey(target string, port int) string {
	if port <= 0 {
		return target
	}
	return fmt.Sprintf("%s:%d", target, port)
}
