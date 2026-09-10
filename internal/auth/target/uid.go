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
// to survive both teardown and this process, so it lives ON THE TARGET beside
// the confinement material (uidWatermarkName). A proxy restart, a second proxy,
// and a crash all read the same number.
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
// record: the durable one is the marker file on the target, which is what makes
// the invariant survive a restart and hold across two proxies. This one exists
// so that two sessions provisioning on one target inside this process cannot be
// handed the same uid by two censuses taken a microsecond apart.
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
	// remaining is how many uids are left in the range above this allocation.
	// It is what the pressure warning is made of.
	remaining int
	// pressured says the range is more than uidPressureNumerator/
	// uidPressureDenominator consumed, so every allocation from here should say
	// so while widening the range is still cheap.
	pressured bool
}

// allocate picks the next uid for a target, or refuses.
//
// THE RULE: strictly above everything the target has ever handed out — the
// marker file, every in-range uid an account holds now, and anything this
// process has handed out since. Never the lowest free one, which is what the
// target's own allocator would do and is the entire defect.
//
// AT WRAP-AROUND IT REFUSES, and does not return to the bottom of the range.
// This is the one decision in the phase that trades availability for the
// invariant, so the reasoning is here rather than in a commit message:
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
//   - The operator's remedy for a refusal is cheap, local and risks nothing:
//     raise `uid_max`. The pressure warning above exists so they are told long
//     before the refusal, and an operator who decides reuse is acceptable on
//     their fleet can remove the target's marker file deliberately — which is
//     where that decision belongs, and is auditable as an act rather than
//     invisible as a default.
//
// It is deliberately NOT configurable. A "wrap and accept" setting would have
// exactly one effect — reintroducing the defect — and `uid_max` is already the
// honest knob for an operator who needs more uids.
func (a *uidAllocator) allocate(addr string, c uidCensus) (uidPlan, error) {
	if !c.read {
		return uidPlan{}, fmt.Errorf("%w: the target's uid census could not be read", ErrUIDUnavailable)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	next := a.min
	for _, floor := range []int{c.watermark, a.high[addr]} {
		if floor >= next {
			next = floor + 1
		}
	}
	for uid := range c.inUse {
		if uid >= next {
			next = uid + 1
		}
	}
	if next > a.max {
		return uidPlan{}, fmt.Errorf("%w: the range %d-%d is exhausted on this target, and allocation does not wrap",
			ErrUIDUnavailable, a.min, a.max)
	}

	plan := uidPlan{uid: next, remaining: a.max - next}
	for uid := next; uid <= a.max && len(plan.candidates) < uidCandidates; uid++ {
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
