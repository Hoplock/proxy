// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/hoplock/proxy/internal/config"
	"github.com/hoplock/proxy/internal/control"
)

// This file is phase 0027: where an ephemeral account's NUMERIC identity comes
// from, and why it is not the target's to choose.
//
// The defect it closes is a cross-user information flow, not an untidiness.
// `useradd` with no `-u` allocates out of the fleet's own range, and shadow's
// allocator hands a torn-down account's uid straight back to the next caller —
// measured on shadow 4.13 (Debian/Ubuntu): create, delete, create, and the
// second account holds the first's uid. Teardown removes the account, its
// processes and its home (PLAN §5.1), and deliberately does NOT walk the
// filesystem, so every file the session wrote OUTSIDE its home keeps the bare
// number. The next session — a DIFFERENT PERSON — then owns those files.
//
// `-K UID_MIN=…`, the flag that looks like the fix, is not one. It moves the
// range the allocator searches and nothing else: with UID_MIN/UID_MAX set to a
// dedicated range, shadow still hands the freed uid back on the next call
// (measured: 2000002 → delete → 2000002). Reuse is a property of the ALLOCATOR,
// so the fix has to be an allocator — this one — and the uid has to travel to
// the target as an explicit `-u`.
//
// The invariant is: a uid this system has ever allocated on a target is never
// allocated there again. That needs a monotonic watermark, and the watermark has
// to survive teardown, this process, and this proxy.
//
// PHASE 0035 MOVED WHERE THAT WATERMARK IS HELD. 0027 put it on the target, in
// uidWatermarkName, which is the party this proxy does not trust and the only
// continuity a RESTARTED or REPLACED proxy had. It is now held by Hoplock
// Control, as an exclusive BLOCK of uids leased to this proxy for this target
// (internal/control/lease.go): allocation happens inside the block, two proxies
// holding two blocks cannot collide, and a block granted to this proxy is safe
// to keep using while Control is unreachable.
//
// The target-side mark is DEMOTED, not deleted. It is a corroborating signal
// that may only ever RAISE the floor and never lower it — the same relationship
// probeCache and 0023's host-key hint have with the server — so it still catches
// a lost lease record, and its absence is now a logged fact rather than an
// outage. That is what makes the method work on a target the proxy can write
// nothing to: a host with a read-only root filesystem, which can still run
// `useradd -m` and hold an authorized_keys in a writable /home.
//
// Nothing here CONFINES the account; that is phase 0019's filesystem rung, and
// the two halves meet: with a private home mounted noexec and nothing writable
// outside it there is nothing left to inherit, and this range is what makes the
// inheritance impossible even where a session could write outside.

// The default uid range. It is a deliberate choice rather than a discovered
// fact, and the reasoning is here because an operator who has to move it needs
// to know what the numbers were chosen against:
//
//   - ABOVE every `UID_MAX` a mainstream distribution ships (login.defs defaults
//     to 60000, and no distribution in this fleet's range ships above 65535), so
//     the target's own allocator never enters it and an ephemeral account can
//     never collide with one of the fleet's own;
//   - above systemd's dynamic-user range (61184–65519), `nobody` (65534), and
//     the 16-bit sentinels, none of which are safe to share;
//   - at the top of SSSD's default LDAP id-mapping range (`ldap_idmap_range_max`
//     is 2000000), so a domain-joined target's mapped users sit below it;
//   - far below 2^31, so every uid stays a positive int32 for NFSv3,
//     `iptables --uid-owner`, and anything that stores a uid in a signed field.
//
// One convention it cannot avoid is systemd-nspawn's container uid range
// (524288–1879048191), which straddles every candidate hole above 65535. That is
// exactly why allocation MEASURES rather than assumes: the census below reads the
// target's own account database and hands out only a uid nothing in the range
// holds, and a target it cannot read is refused.
// The numbers themselves are `internal/config`'s, because that is the surface an
// operator overrides them on and one source of truth is what keeps the validator
// and this allocator from disagreeing. The reasoning above is why they are those
// numbers; DefaultUIDMax gives one million uids, which at the 58
// provision/teardown cycles per second PLAN §9.1 measured is nearly five hours of
// continuously saturated provisioning before wrap-around, and years of ordinary
// use.
const (
	DefaultUIDMin = config.DefaultEphemeralUIDMin
	DefaultUIDMax = config.DefaultEphemeralUIDMax
	minAllowedUID = config.MinEphemeralUID
	maxAllowedUID = config.MaxEphemeralUID
)

// uidWatermarkName is the DIRECTORY on the target recording the highest uid this
// system has ever allocated there. Its entries are named after the uids
// themselves, and the watermark is the largest of them.
//
// SINCE PHASE 0035 IT IS CORROBORATION AND NOT THE FLOOR. The floor is the
// leased block; this may raise it and can never lower it, and a target that
// cannot hold it at all is served on the lease alone with the absence recorded.
// It is kept rather than dropped because it is what stops a lost lease record —
// a Control that forgot a cursor, a range an operator moved — from being the
// moment the invariant quietly weakens.
//
// A directory of names rather than a file holding a number, because two
// provisioners run on one target at the same time (PLAN §5.1): a file would be a
// read-modify-write between them, and two interleaved writers would move the
// mark BACKWARDS over a uid still in use — the reuse this phase closes,
// reintroduced by its own fix. Creating a file named after the uid reads nothing
// and is atomic, so the maximum only ever rises.
//
// It sits in the enforcement base (0019) because that directory already exists
// for exactly this kind of thing: root-owned, outside every account's home, and
// not writable by any session. Teardown removes `<base>/<principal>`, so this
// sibling survives it — which is the whole point, since the number has to outlive
// the account it describes.
const uidWatermarkName = "uid-watermark"

// uidCandidates is how many uids one allocation offers the target.
//
// The first is the allocation; the rest exist for one case only — another
// provisioner (another proxy, or another process sharing this proxy id) taking
// the same uid between this census and this `useradd`. The target tries them in
// order and reports which it used, so a lost race costs a retry inside one
// script instead of a refused session.
const uidCandidates = 8

// uidPressureNumerator/Denominator is the fraction of the range consumed at
// which every allocation starts warning.
//
// Wrap-around REFUSES (see allocate), which is a target-wide outage for this
// method, and an outage nobody was warned about is the version of this decision
// that is indefensible. Warning from nine tenths of the range turns it into a
// deadline an operator can act on — widening uid_max is a configuration change
// with nothing at risk.
const (
	uidPressureNumerator   = 9
	uidPressureDenominator = 10
)

// ErrUIDUnavailable means no uid can be allocated for an ephemeral account
// without risking reuse of one a previous account held.
//
// It is OUTAGE-class and never a denial (PLAN §4.3): no credential the user
// could offer changes it, and the estate is what has to change. Every path that
// cannot establish the invariant returns it — an unreadable census as much as an
// exhausted range — because "we could not tell" and "we know we would reuse" are
// the same answer here.
var ErrUIDUnavailable = errors.New("auth/target: no ephemeral uid is available that no previous account has held")

// uidCensus is what one target says about the ephemeral uid range.
type uidCensus struct {
	// inUse are the uids inside the range that an account holds right now,
	// whatever its name: an ephemeral account of this proxy's, one of another
	// proxy's, and a local account an operator put in the range all count.
	inUse map[int]bool
	// watermark is the highest uid this system has ever allocated on the
	// target, per its own marker file. Zero means there is no marker — a target
	// no proxy has provisioned on yet, which is not the same as a target whose
	// marker says zero, and both read the same here on purpose: a missing
	// marker leaves the census as the only evidence, and the census is enough
	// for a range nothing has been allocated from.
	watermark int
	// read says the census was actually obtained. A false here refuses the
	// session: an allocator with no census cannot promise anything.
	read bool
}

// parseUIDCensus reads the uid lines out of the discovery script's output
// (script.go's discoverScript, which the reaper reads for orphans).
//
// It is deliberately the same script and the same round trip. The provisioning
// path already pays for one discovery; asking the target the same question twice
// would add latency to every session to save nothing.
func parseUIDCensus(out []byte, min, max int) uidCensus {
	c := uidCensus{inUse: map[int]bool{}}
	for _, line := range strings.Split(string(out), "\n") {
		key, value, ok := strings.Cut(strings.TrimRight(line, "\r"), "\t")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || n < 0 {
			continue
		}
		switch strings.TrimSpace(key) {
		case uidKeyInUse:
			if n >= min && n <= max {
				c.inUse[n] = true
				c.read = true
			}
		case uidKeyWatermark:
			c.watermark = n
			c.read = true
		}
	}
	return c
}

// uidAllocator hands out ephemeral uids that nothing on a target has held.
//
// Its state is a per-target high-water mark, and it is a CACHE rather than the
// record: the durable one is the block Hoplock Control leased this proxy
// (phase 0035), which is what makes the invariant survive a restart, a replaced
// proxy and two proxies on one target. This one exists so that two sessions
// provisioning on one target inside this process cannot be handed the same uid
// by two censuses taken a microsecond apart.
//
// min and max are no longer where allocation happens — the block is. They are
// the range this proxy will ACCEPT a block from, and the range the pressure
// warning is measured against, because they are the only part of this an
// operator can widen locally.
type uidAllocator struct {
	min, max int

	mu   sync.Mutex
	high map[string]int
}

// newUIDAllocator validates the range and returns the allocator.
func newUIDAllocator(min, max int) (*uidAllocator, error) {
	if min == 0 {
		min = DefaultUIDMin
	}
	if max == 0 {
		max = DefaultUIDMax
	}
	switch {
	case min < minAllowedUID:
		return nil, fmt.Errorf("auth/target: ephemeral uid_min %d is inside the system uid range (below %d)", min, minAllowedUID)
	case max <= min:
		return nil, fmt.Errorf("auth/target: ephemeral uid_max %d must be above uid_min %d", max, min)
	case max > maxAllowedUID:
		return nil, fmt.Errorf("auth/target: ephemeral uid_max %d is above the largest usable uid %d", max, maxAllowedUID)
	}
	return &uidAllocator{min: min, max: max, high: map[string]int{}}, nil
}

// uidPlan is one allocation.
type uidPlan struct {
	// uid is the allocation: the uid the account will hold unless another
	// provisioner takes it first.
	uid int
	// candidates is uid followed by the fallbacks, in the order the target
	// tries them.
	candidates []int
	// lease names the block this allocation came out of. It goes on the
	// provisioning record beside the uid: without it an incident can see which
	// uid was used and not which proxy's block it came from, and those are
	// different questions once more than one proxy serves a target.
	lease string
	// remaining is how many uids are left in the configured RANGE above this
	// allocation. It is what the pressure warning is made of.
	remaining int
	// pressured says the configured range is more than uidPressureNumerator/
	// uidPressureDenominator consumed, so every allocation from here should say
	// so while widening it is still cheap.
	pressured bool
}

// errUIDBlockSpent means the leased block cannot serve this allocation: the
// floor has reached or passed its end.
//
// It is separate from ErrUIDUnavailable because it is RECOVERABLE — the caller
// takes a fresh block and asks again — where every other refusal here is not. It
// wraps ErrUIDUnavailable so that a caller which does not recover still reports
// the right class of failure (PLAN §4.3, outage).
var errUIDBlockSpent = fmt.Errorf("%w: the leased uid block is spent", ErrUIDUnavailable)

// observedFloor is the highest uid this system is known to have given out on a
// target: the target's mark, every in-range uid an account holds now, and this
// process's own record of what it has issued.
//
// EVERYTHING THE TARGET SAYS MAY ONLY RAISE THIS, NEVER LOWER IT, and that is a
// security property rather than an accident of taking a maximum. The census and
// the mark are both read off the target, which is the party this proxy does not
// trust; a.high[addr] is this process's own record. Because all three are
// maxima, a target that under-reports — a mark an attacker with root has
// deleted, a census missing an account, a target that can hold no mark at all —
// can only make this proxy SKIP uids, which is loud, and can never make it reuse
// one.
//
// What it can no longer do, and this is phase 0035's whole point, is leave a
// RESTARTED proxy with nothing: the leased block's own floor is below none of
// these and is held where neither the target nor this process can lower it.
func (a *uidAllocator) observedFloor(addr string, c uidCensus) (int, error) {
	if !c.read {
		return 0, fmt.Errorf("%w: the target's uid census could not be read", ErrUIDUnavailable)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	floor := c.watermark
	if h := a.high[addr]; h > floor {
		floor = h
	}
	for uid := range c.inUse {
		if uid > floor {
			floor = uid
		}
	}
	return floor, nil
}

// allocate picks the next uid for a target inside a leased block, or refuses.
//
// THE RULE: strictly above everything the target has ever handed out AND inside
// the block Control leased this proxy — the block's own floor, the marker file,
// every in-range uid an account holds now, and anything this process has handed
// out since. Never the lowest free one, which is what the target's own allocator
// would do and is the entire defect.
//
// AT THE TOP OF THE BLOCK IT REFUSES, and does not return to the bottom. The
// caller's remedy is a FRESH BLOCK (errUIDBlockSpent), which is a different
// thing from wrapping: Control's cursor only advances, so the next block is
// above this one and no uid is offered twice. At the top of the configured
// RANGE nothing can be granted at all, and that refusal is final. The reasoning
// against wrapping is unchanged from phase 0027 and is the reason a spent block
// is replaced rather than reused:
//
//   - Wrapping is the only moment reuse becomes possible again. A wrap that
//     "accepts with a recorded warning" reintroduces the exact cross-user flow
//     this file exists to close, silently, at the one moment nobody is looking —
//     and a warning in a log is not a boundary.
//   - Wrapping after a bounded check of the paths a session can write was the
//     serious alternative and it loses on completeness for the four reasons
//     PLAN §5.1 gives for not sweeping at teardown: unmounted filesystems,
//     snapshots and backups, ACLs and xattrs naming the uid, and files inside
//     containers. A check that can be wrong turns a hard, visible stop into a
//     soft, silent one precisely where the guarantee is at stake.
//   - The operator's remedy for the final refusal is cheap, local and risks
//     nothing: raise `uid_max`, and the server's own range with it. The pressure
//     warning above exists so they are told long before it.
//
// It is deliberately NOT configurable. A "wrap and accept" setting would have
// exactly one effect — reintroducing the defect — and the range is already the
// honest knob for an operator who needs more uids.
func (a *uidAllocator) allocate(addr string, c uidCensus, b control.UIDBlock) (uidPlan, error) {
	floor, err := a.observedFloor(addr, c)
	if err != nil {
		return uidPlan{}, err
	}
	if b.Empty() {
		return uidPlan{}, fmt.Errorf("%w: no uid block is held for this target", ErrUIDUnavailable)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	next := b.From
	if floor >= next {
		next = floor + 1
	}
	// THE RANGE IS CHECKED FIRST, and the order is what makes the two refusals
	// mean different things. Past uid_max nothing can help — accept() refuses a
	// block above it, so there is no fresh block to take — and the operator's
	// remedy is the one phase 0027 named. Past the end of the BLOCK but still
	// inside the range is recoverable, and says so.
	if next > a.max {
		return uidPlan{}, fmt.Errorf("%w: the range %d-%d is exhausted on this target, and allocation does not wrap",
			ErrUIDUnavailable, a.min, a.max)
	}
	if next >= b.To {
		return uidPlan{}, errUIDBlockSpent
	}

	plan := uidPlan{uid: next, lease: b.LeaseID, remaining: a.max - next}
	for uid := next; uid < b.To && len(plan.candidates) < uidCandidates; uid++ {
		if !c.inUse[uid] {
			plan.candidates = append(plan.candidates, uid)
		}
	}
	size := a.max - a.min + 1
	plan.pressured = (next-a.min)*uidPressureDenominator >= size*uidPressureNumerator
	// Only the ALLOCATION advances the cache, never the fallbacks: advancing by
	// the whole candidate list would burn eight uids per session and shrink the
	// range by a factor of eight for a race that almost never happens.
	a.high[addr] = next
	return plan, nil
}

// observe records the uid a target actually gave an account, which is not always
// the one that was allocated: an adopted account from a crashed session keeps
// the uid it already had, and a lost race lands on a fallback candidate.
func (a *uidAllocator) observe(addr string, uid int) {
	if uid <= 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if uid > a.high[addr] {
		a.high[addr] = uid
	}
}
