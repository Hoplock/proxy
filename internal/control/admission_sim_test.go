// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"container/list"
	"flag"
	"fmt"
	"math"
	"math/rand/v2"
	"sort"
	"strings"
	"testing"
)

// This file is a STUDY, not a gate, and it changes no production behaviour.
//
// Phase 0022 gave the authorize cache LRU eviction and a settable bound. Below
// the bound that is a strict improvement. Above it the hit rate does not slope
// as a fleet outgrows the cache, it STEPS: a strict poll cycle is LRU's worst
// case, because every entry is evicted about one visit before it is wanted.
// PLAN §9.1 measures the step — 100% at 4,096 targets and 0% at 8,192 against
// a 4,096-entry bound, where the pre-0022 "refuse to store" behaviour gave 59%.
//
// Phase 0032 asks whether that step is worth an admission policy, and this is
// the evidence it is answered from. A simulation is two orders of magnitude
// cheaper than a load run, so the comparison is made here rather than by
// shipping five cache policies and measuring each.
//
// THE SIMULATOR IS NOT EVIDENCE UNTIL IT REPRODUCES THE MEASUREMENTS.
// TestAdmissionSimulationReproducesTheMeasuredPoints pins both measured points
// and runs on every `go test ./...`; the matrix below is gated behind its own
// -run because CI is a gate and this is a study. Run it with:
//
//	go test ./internal/control -run AdmissionSimulation -v
//
// What it deliberately does NOT model: TTL expiry (the load runs cache for an
// hour and measure for forty seconds, so nothing expires in them either),
// the shape→decision indirection (`MaxEntries` bounds lookup paths, and a
// lookup path is what every policy here holds), and wall-clock cost. The last
// is the one to keep in mind: this compares hit rates, and a policy that wins
// on hit rate can still lose on the code a future session has to read.

// ---------------------------------------------------------------------------
// The policy seam
// ---------------------------------------------------------------------------

// simPolicy is a cache of a fixed size under one replacement policy. The study
// asks it exactly one thing per connection: was this lookup path resident?
type simPolicy interface {
	name() string
	access(shape uint64) (hit bool)
}

// admission is the seam this phase exists to compare, and it is deliberately
// three things wide: a candidate, a victim, and a verdict. Everything shared —
// the table, the recency list, the sampling — lives in lruCore, so adding a
// policy is a function rather than a rewrite.
type admission interface {
	// record sees every access, hit or miss, before any verdict is asked.
	// Frequency-based policies build their estimate here; the others ignore it.
	record(shape uint64)
	// admit answers the only question a full cache has: may this candidate
	// displace this victim?
	admit(candidate, victim uint64) bool
}

// alwaysAdmit is what ships today: the newcomer always wins, and the policy is
// entirely in the choice of victim.
type alwaysAdmit struct{}

func (alwaysAdmit) record(uint64)          {}
func (alwaysAdmit) admit(_, _ uint64) bool { return true }

// neverAdmit is the pre-0022 behaviour: a full cache refuses new decisions.
// It is here as the baseline the cliff is measured against, not as a proposal —
// it holds whichever shapes arrived first for as long as their TTLs renew, so
// a cold sweep poisons it permanently. That is what 0022 removed.
type neverAdmit struct{}

func (neverAdmit) record(uint64)          {}
func (neverAdmit) admit(_, _ uint64) bool { return false }

// ---------------------------------------------------------------------------
// The shared cache core
// ---------------------------------------------------------------------------

// simResident is one resident lookup path. The recency list answers "which is
// oldest" for the LRU tail; the stamp answers it for a random sample, where
// walking the list is not an option; the slot makes removal from the sampling
// slice O(1).
type simResident struct {
	shape uint64
	stamp uint64
	el    *list.Element
	slot  int
}

// lruCore is the machinery every non-segmented policy here is built from.
// sampleK selects the victim: 0 or 1 takes the true LRU tail, k > 1 takes the
// least recently used of k randomly sampled residents.
type lruCore struct {
	label   string
	size    int
	sampleK int
	verdict admission

	table map[uint64]*simResident
	order *list.List // front = most recently used
	keys  []*simResident
	clock uint64
	rng   *rand.Rand
}

func newLRUCore(label string, size, sampleK int, verdict admission, seed uint64) *lruCore {
	return &lruCore{
		label:   label,
		size:    size,
		sampleK: sampleK,
		verdict: verdict,
		table:   make(map[uint64]*simResident, size),
		order:   list.New(),
		keys:    make([]*simResident, 0, size),
		rng:     rand.New(rand.NewPCG(seed, 0x9E3779B97F4A7C15)),
	}
}

func (c *lruCore) name() string { return c.label }

func (c *lruCore) access(shape uint64) bool {
	c.verdict.record(shape)
	c.clock++
	if r, resident := c.table[shape]; resident {
		r.stamp = c.clock
		c.order.MoveToFront(r.el)
		return true
	}
	// A miss. The proxy asks Hoplock Control, gets an answer, and offers it to
	// the cache; what happens next is the whole of the policy.
	if len(c.table) < c.size {
		c.insert(shape)
		return false
	}
	victim := c.victim()
	if c.verdict.admit(shape, victim.shape) {
		c.remove(victim)
		c.insert(shape)
	}
	return false
}

func (c *lruCore) insert(shape uint64) {
	r := &simResident{shape: shape, stamp: c.clock, slot: len(c.keys)}
	r.el = c.order.PushFront(r)
	c.table[shape] = r
	c.keys = append(c.keys, r)
}

func (c *lruCore) remove(r *simResident) {
	c.order.Remove(r.el)
	delete(c.table, r.shape)
	last := len(c.keys) - 1
	c.keys[r.slot] = c.keys[last]
	c.keys[r.slot].slot = r.slot
	c.keys = c.keys[:last]
}

// victim offers up the resident this policy would give away. The sampled
// variants are the cheap middle of the design space: no sketch, no segments,
// and in the real cache about ten lines — but the sample has to be taken from
// a slice, because the point of not walking to the LRU tail is not walking.
func (c *lruCore) victim() *simResident {
	if c.sampleK <= 1 {
		return c.order.Back().Value.(*simResident)
	}
	oldest := c.keys[c.rng.IntN(len(c.keys))]
	for i := 1; i < c.sampleK; i++ {
		if cand := c.keys[c.rng.IntN(len(c.keys))]; cand.stamp < oldest.stamp {
			oldest = cand
		}
	}
	return oldest
}

// ---------------------------------------------------------------------------
// Segmented LRU
// ---------------------------------------------------------------------------

// slruCache is segmented LRU: a probation segment new arrivals land in and a
// protected segment they are promoted into on a second hit. It is scan
// resistant without a sketch — a one-off target passes through probation and
// never displaces anything that has proved itself — at the cost of a second
// list and a promotion rule.
//
// The 20/80 probation/protected split is the conventional one.
type slruCache struct {
	label        string
	size         int
	protectedCap int
	probation    *list.List
	protected    *list.List
	where        map[uint64]*slruSlot
}

type slruSlot struct {
	el        *list.Element
	protected bool
}

func newSLRUCache(label string, size int) *slruCache {
	protected := size * 4 / 5
	if protected < 1 {
		protected = 1
	}
	return &slruCache{
		label:        label,
		size:         size,
		protectedCap: protected,
		probation:    list.New(),
		protected:    list.New(),
		where:        make(map[uint64]*slruSlot, size),
	}
}

func (c *slruCache) name() string { return c.label }

func (c *slruCache) access(shape uint64) bool {
	slot, resident := c.where[shape]
	if !resident {
		c.where[shape] = &slruSlot{el: c.probation.PushFront(shape)}
		c.evictToSize()
		return false
	}
	if slot.protected {
		c.protected.MoveToFront(slot.el)
		return true
	}
	// A second hit is what earns a place in the protected segment, and it is
	// the whole of the scan resistance: a one-off target is seen once, stays in
	// probation, and leaves without ever displacing something that has proved
	// itself.
	c.probation.Remove(slot.el)
	c.where[shape] = &slruSlot{el: c.protected.PushFront(shape), protected: true}
	c.demoteToCap()
	return true
}

// demoteToCap keeps the protected segment within its share. A demoted entry
// goes to the head of probation rather than out of the cache: having proved
// itself once, it is not thrown away for something that just did.
func (c *slruCache) demoteToCap() {
	for c.protected.Len() > c.protectedCap {
		oldest := c.protected.Back()
		c.protected.Remove(oldest)
		shape := oldest.Value.(uint64)
		c.where[shape] = &slruSlot{el: c.probation.PushFront(shape)}
	}
}

// evictToSize is the one place SLRU drops anything, and it triggers on the
// TOTAL rather than on either segment. Evicting at the probation segment's own
// cap instead would leave a cache that never fills: on a working set larger
// than probation nothing survives to a second hit, so the protected segment
// stays empty and 80% of the bound goes unused. The invariant that every policy
// is perfect below the bound is what catches that.
func (c *slruCache) evictToSize() {
	for c.probation.Len()+c.protected.Len() > c.size {
		victim := c.probation.Back()
		if victim != nil {
			c.probation.Remove(victim)
		} else {
			victim = c.protected.Back()
			c.protected.Remove(victim)
		}
		delete(c.where, victim.Value.(uint64))
	}
}

// ---------------------------------------------------------------------------
// TinyLFU
// ---------------------------------------------------------------------------

// tinyLFU is frequency-sketch admission over LRU eviction: a candidate takes
// the victim's place only if it has been seen more often. Under a uniform
// cycle every shape has the same frequency, the verdict is "no", and the cache
// holds its incumbents — which is the slope this phase is evaluating.
//
// Three moving parts, and each is a thing a future session would have to
// maintain in internal/control/cache.go:
//
//   - a count-min sketch of 4-bit saturating counters, four rows;
//   - a doorkeeper, so a shape seen exactly once costs a bloom bit rather than
//     four counter increments and never looks hot;
//   - a reset window, so the estimate ages and a formerly hot shape can lose.
//
// Ties go to the incumbent. Caffeine breaks them randomly to stop a sketch
// hash collision locking a candidate out forever; that is deliberately NOT
// done here, because a random tie-break degrades toward LRU under exactly the
// uniform cycle this study is about, and the study should show TinyLFU at its
// strongest on the trace it is proposed for.
type tinyLFU struct {
	counters   []uint8 // one 4-bit value per byte; the packed cost is noted below
	mask       uint64
	door       []uint64
	doorMask   uint64
	increments int
	sampleSize int
}

func newTinyLFU(size int, _ uint64) *tinyLFU {
	counters := nextPow2(uint64(4 * size))
	doorBits := nextPow2(uint64(8 * size))
	return &tinyLFU{
		counters:   make([]uint8, counters),
		mask:       counters - 1,
		door:       make([]uint64, doorBits/64),
		doorMask:   doorBits - 1,
		sampleSize: 10 * size,
	}
}

// sketchMemoryPerEntry reports what tinyLFU would cost the real cache per
// cached entry, in bytes, if the counters were packed two to a byte as they
// would be in production. It exists so the learnings can state the memory
// cost as a measured property of the sizing above rather than as an estimate.
func (s *tinyLFU) sketchMemoryPerEntry(size int) float64 {
	packedCounters := float64(len(s.counters)) / 2
	doorBytes := float64(len(s.door) * 8)
	return (packedCounters + doorBytes) / float64(size)
}

func (s *tinyLFU) record(shape uint64) {
	// First sighting goes to the doorkeeper only: the long tail of a cold
	// sweep is exactly the traffic that should not reach the sketch.
	if !s.doorTest(shape) {
		s.doorSet(shape)
		s.tick()
		return
	}
	for row := range 4 {
		i := s.index(row, shape)
		if s.counters[i] < 15 {
			s.counters[i]++
		}
	}
	s.tick()
}

func (s *tinyLFU) tick() {
	s.increments++
	if s.increments < s.sampleSize {
		return
	}
	// The reset window is what makes the estimate a rate rather than a total.
	// Without it nothing that was ever hot can cool, and the cache freezes.
	for i := range s.counters {
		s.counters[i] >>= 1
	}
	for i := range s.door {
		s.door[i] = 0
	}
	s.increments /= 2
}

func (s *tinyLFU) estimate(shape uint64) int {
	least := 15
	for row := range 4 {
		if c := int(s.counters[s.index(row, shape)]); c < least {
			least = c
		}
	}
	if s.doorTest(shape) {
		least++
	}
	return least
}

func (s *tinyLFU) admit(candidate, victim uint64) bool {
	return s.estimate(candidate) > s.estimate(victim)
}

func (s *tinyLFU) index(row int, shape uint64) uint64 {
	return splitmix64(shape+rowSeeds[row]) & s.mask
}

func (s *tinyLFU) doorTest(shape uint64) bool {
	for _, h := range s.doorBits(shape) {
		if s.door[h/64]&(1<<(h%64)) == 0 {
			return false
		}
	}
	return true
}

func (s *tinyLFU) doorSet(shape uint64) {
	for _, h := range s.doorBits(shape) {
		s.door[h/64] |= 1 << (h % 64)
	}
}

func (s *tinyLFU) doorBits(shape uint64) [2]uint64 {
	return [2]uint64{
		splitmix64(shape+rowSeeds[0]) & s.doorMask,
		splitmix64(shape+rowSeeds[3]) & s.doorMask,
	}
}

var rowSeeds = [4]uint64{
	0x9E3779B97F4A7C15, 0xBF58476D1CE4E5B9, 0x94D049BB133111EB, 0x2545F4914F6CDD1D,
}

func splitmix64(x uint64) uint64 {
	x += 0x9E3779B97F4A7C15
	x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9
	x = (x ^ (x >> 27)) * 0x94D049BB133111EB
	return x ^ (x >> 31)
}

func nextPow2(n uint64) uint64 {
	p := uint64(1)
	for p < n {
		p <<= 1
	}
	return p
}

// ---------------------------------------------------------------------------
// The policies under comparison
// ---------------------------------------------------------------------------

type policySpec struct {
	label string
	build func(size int, seed uint64) simPolicy
}

// simPolicies is ordered simplest first, which is also the order Step 3 of the
// prompt breaks a tie in: complexity here is paid forever by every future
// session reading internal/control/cache.go.
func simPolicies() []policySpec {
	return []policySpec{
		{"freeze", func(size int, seed uint64) simPolicy {
			return newLRUCore("freeze", size, 0, neverAdmit{}, seed)
		}},
		{"lru", func(size int, seed uint64) simPolicy {
			return newLRUCore("lru", size, 0, alwaysAdmit{}, seed)
		}},
		{"random-2", func(size int, seed uint64) simPolicy {
			return newLRUCore("random-2", size, 2, alwaysAdmit{}, seed)
		}},
		{"random-5", func(size int, seed uint64) simPolicy {
			return newLRUCore("random-5", size, 5, alwaysAdmit{}, seed)
		}},
		{"slru", func(size int, _ uint64) simPolicy {
			return newSLRUCache("slru", size)
		}},
		{"tinylfu", func(size int, seed uint64) simPolicy {
			return newLRUCore("tinylfu", size, 0, newTinyLFU(size, seed), seed)
		}},
	}
}

// ---------------------------------------------------------------------------
// Traces
// ---------------------------------------------------------------------------

// simTrace is one access pattern. warmup and measured come from ONE continuous
// stream, because a poller does not restart its cycle when a benchmark starts
// measuring — and that phase offset is why the harness reports 59% for a
// pattern whose steady state is 50%. See the reproduction test.
type simTrace struct {
	label    string
	bound    int // M, the cache bound
	warmup   int
	measured int
	stream   func(seed uint64) func() uint64
}

// uniformCycle is the poll shape scenarios 04/05/08 measure: a fixed sweep of
// n targets, in order, forever. It is LRU's worst case and it is what produces
// the cliff.
func uniformCycle(n int) func(uint64) func() uint64 {
	return func(uint64) func() uint64 {
		var i uint64
		return func() uint64 {
			v := i % uint64(n)
			i++
			return v
		}
	}
}

// hotAndCold is a small repeatedly-visited set plus a long tail of one-off
// targets: the pattern TestCachingClientCachesAWorkingSetItMeetsAfterFilling
// protects, and the one LRU is expected to win. A policy that loses badly here
// is disqualified however well it does elsewhere.
func hotAndCold(hot int, hotFraction float64) func(uint64) func() uint64 {
	return func(seed uint64) func() uint64 {
		rng := rand.New(rand.NewPCG(seed, 0x2545F4914F6CDD1D))
		var cold uint64
		return func() uint64 {
			if rng.Float64() < hotFraction {
				return uint64(rng.IntN(hot))
			}
			cold++
			return 1<<32 + cold
		}
	}
}

// zipf is the shape a real estate usually has when nobody has said which of
// the two above it is. Go's math/rand Zipf requires s > 1, and α = 0.9 is
// exactly the case this study wants, so the distribution is sampled from its
// own cumulative table instead.
func zipf(n int, alpha float64) func(uint64) func() uint64 {
	cum := make([]float64, n)
	total := 0.0
	for i := range n {
		total += 1 / math.Pow(float64(i+1), alpha)
		cum[i] = total
	}
	return func(seed uint64) func() uint64 {
		rng := rand.New(rand.NewPCG(seed, 0xBF58476D1CE4E5B9))
		return func() uint64 {
			return uint64(sort.SearchFloat64s(cum, rng.Float64()*total))
		}
	}
}

// churning is Q3 turned into a trace: a working set that drifts, replacing a
// fraction of its members every cycle. The cloud answer to Q3 ("ephemeral
// machines, very high churn") lives at the 10% row.
func churning(n int, rate float64) func(uint64) func() uint64 {
	return func(seed uint64) func() uint64 {
		rng := rand.New(rand.NewPCG(seed, 0x94D049BB133111EB))
		members := make([]uint64, n)
		for i := range members {
			members[i] = uint64(i)
		}
		next := uint64(n)
		var i int
		replace := int(float64(n)*rate + 0.5)
		if replace < 1 {
			replace = 1
		}
		return func() uint64 {
			if i == n {
				i = 0
				for r := 0; r < replace; r++ {
					members[rng.IntN(n)] = next
					next++
				}
			}
			v := members[i]
			i++
			return v
		}
	}
}

// zipfChurn is the trace that matches BOTH of this phase's operator answers at
// once, and it is the one criterion 2 is decided on. Q2 said the traffic is
// mixed — Zipf-like rather than a strict sweep — and Q3 said the working set's
// stability depends on the environment, churning hard on cloud and barely at
// all on-prem. Neither `zipf` (a fixed population) nor `churning` (a strict
// cycle that drifts) is that estate: the first has no churn and the second has
// no hot set, and a strict cycle is the one shape that pins LRU at zero.
//
// Members retire uniformly at random over ranks, because a machine being
// replaced does not know how often it was polled.
func zipfChurn(n int, alpha, rate float64) func(uint64) func() uint64 {
	cum := make([]float64, n)
	total := 0.0
	for i := range n {
		total += 1 / math.Pow(float64(i+1), alpha)
		cum[i] = total
	}
	return func(seed uint64) func() uint64 {
		rng := rand.New(rand.NewPCG(seed, 0x2545F4914F6CDD1D))
		members := make([]uint64, n)
		for i := range members {
			members[i] = uint64(i)
		}
		next := uint64(n)
		replace := int(float64(n)*rate + 0.5)
		if replace < 1 {
			replace = 1
		}
		var since int
		return func() uint64 {
			// One "cycle" is n accesses, so the churn rate is comparable with
			// the churning() trace above.
			if since == n {
				since = 0
				for r := 0; r < replace; r++ {
					members[rng.IntN(n)] = next
					next++
				}
			}
			since++
			return members[sort.SearchFloat64s(cum, rng.Float64()*total)]
		}
	}
}

// ---------------------------------------------------------------------------
// Running one (trace, policy) pair
// ---------------------------------------------------------------------------

const (
	// PLAN §9.1's measured call table: a cache hit removes the authorize call
	// and nothing else.
	callsPerHit  = 2.17
	callsPerMiss = 3.17
	// PLAN §9.1's five-minute row — the one the section says to size against.
	sizingConnectionsPerSec = 1167.0
)

type simResult struct {
	trace    string
	policy   string
	hitRate  float64 // percent
	calls    float64 // Hoplock Control calls per connection
	controlR float64 // Hoplock Control req/s at the five-minute row
}

func runSim(tr simTrace, p policySpec, seed uint64) simResult {
	cache := p.build(tr.bound, seed)
	next := tr.stream(seed)
	for range tr.warmup {
		cache.access(next())
	}
	hits := 0
	for range tr.measured {
		if cache.access(next()) {
			hits++
		}
	}
	rate := float64(hits) / float64(tr.measured)
	calls := callsPerMiss - rate*(callsPerMiss-callsPerHit)
	return simResult{
		trace:    tr.label,
		policy:   p.label,
		hitRate:  100 * rate,
		calls:    calls,
		controlR: calls * sizingConnectionsPerSec,
	}
}

// ---------------------------------------------------------------------------
// The measured points
// ---------------------------------------------------------------------------

// measuredBound and measuredTargets are scenario 08's second step, and the
// warmup/measured counts are that run's: 40 s of warmup and 9,999 measured
// connections at 250 conn/s. They are spelled out because the phase offset
// between the two matters — see the reproduction test.
const (
	measuredBound        = 4096
	measuredTargets      = 8192
	measuredWarmupConns  = 10000 // 40 s at 250 conn/s
	measuredWindowConns  = 9999  // load/results/08-uc2-fanout-evicting.json
	measuredFreezeHitPct = 59.0  // pre-0022, reproduced by phase 0020
	measuredLRUHitPct    = 0.0   // load/results/08-uc2-fanout-evicting.json
)

// TestAdmissionSimulationReproducesTheMeasuredPoints is the calibration check,
// and it is the reason anything else in this file may be believed. It runs on
// every `go test ./...` — unlike the matrix, which is gated — because a
// calibration check nobody runs is not a check, and the study it validates is
// meant to be re-run by a later session rather than re-derived.
//
// If this fails, the simulator is wrong. Fix it; do not reinterpret the load
// results.
func TestAdmissionSimulationReproducesTheMeasuredPoints(t *testing.T) {
	tr := simTrace{
		label:    "uniform-cycle N=8192 M=4096 (scenario 08)",
		bound:    measuredBound,
		warmup:   measuredWarmupConns,
		measured: measuredWindowConns,
		stream:   uniformCycle(measuredTargets),
	}

	for _, tc := range []struct {
		policy string
		want   float64
	}{
		{"freeze", measuredFreezeHitPct},
		{"lru", measuredLRUHitPct},
	} {
		var spec policySpec
		for _, p := range simPolicies() {
			if p.label == tc.policy {
				spec = p
			}
		}
		if spec.build == nil {
			t.Fatalf("no policy %q", tc.policy)
		}
		got := runSim(tr, spec, 1)
		// "Within a few points" of the load run, which is what the prompt asks
		// and all a simulation of a real proxy can honestly claim.
		if diff := got.hitRate - tc.want; diff < -3 || diff > 3 {
			t.Errorf("%s at N=%d/M=%d: hit rate %.1f%%, measured %.1f%% — the simulator does not reproduce the load run",
				tc.policy, measuredTargets, measuredBound, got.hitRate, tc.want)
		}
	}
}

// TestAdmissionSimulationCycleSteadyStateIsMOverN records the one thing the
// reproduction above hides. 59% is not `freeze`'s steady state: it is M/N plus
// the phase offset of the harness's finite window, because loadgen's
// connection index runs continuously across warmup (driver.nextIndex is not
// reset) and the measured window therefore starts partway through a sweep.
// The steady state of the same trace is M/N = 50%.
//
// It matters because the matrix below reports steady state, and a reader who
// only had the 59% would think the two disagreed.
func TestAdmissionSimulationCycleSteadyStateIsMOverN(t *testing.T) {
	tr := simTrace{
		label:    "uniform-cycle N=8192 M=4096, long window",
		bound:    measuredBound,
		warmup:   4 * measuredTargets,
		measured: 40 * measuredTargets,
		stream:   uniformCycle(measuredTargets),
	}
	var freeze policySpec
	for _, p := range simPolicies() {
		if p.label == "freeze" {
			freeze = p
		}
	}
	want := 100 * float64(measuredBound) / float64(measuredTargets)
	if got := runSim(tr, freeze, 1); got.hitRate < want-1 || got.hitRate > want+1 {
		t.Errorf("freeze steady state = %.1f%%, want M/N = %.1f%%", got.hitRate, want)
	}
}

// ---------------------------------------------------------------------------
// The matrix
// ---------------------------------------------------------------------------

// simCases is every (trace, bound) the study compares policies over. The bound
// is scenario 08's 4,096 throughout so that N/M is the only thing moving, and
// the windows are long enough for the phase artifact above to wash out.
func simCases() []simTrace {
	const m = measuredBound
	window := func(n int) (warmup, measured int) { return 5 * n, 20 * n }

	var cases []simTrace
	for _, ratio := range []float64{0.5, 0.9, 1.0, 1.1, 2, 4, 10} {
		n := int(ratio * m)
		w, d := window(n)
		cases = append(cases, simTrace{
			label: fmt.Sprintf("uniform-cycle N/M=%.2f", ratio),
			bound: m, warmup: w, measured: d, stream: uniformCycle(n),
		})
	}
	// The hot set is half the bound, so LRU can hold it comfortably; the tail
	// is one-off targets, which is what makes this a scan.
	for _, f := range []float64{0.50, 0.80, 0.95} {
		w, d := window(4 * m)
		cases = append(cases, simTrace{
			label: fmt.Sprintf("hot-set %d%% hot, one-off tail", int(f*100)),
			bound: m, warmup: w, measured: d, stream: hotAndCold(m/2, f),
		})
	}
	for _, alpha := range []float64{0.9, 1.2} {
		for _, ratio := range []float64{1.1, 2, 4} {
			n := int(ratio * m)
			w, d := window(n)
			cases = append(cases, simTrace{
				label: fmt.Sprintf("zipf a=%.1f N/M=%.1f", alpha, ratio),
				bound: m, warmup: w, measured: d, stream: zipf(n, alpha),
			})
		}
	}
	for _, rate := range []float64{0.01, 0.10} {
		for _, ratio := range []float64{1.1, 2} {
			n := int(ratio * m)
			w, d := window(n)
			cases = append(cases, simTrace{
				label: fmt.Sprintf("churn %d%%/cycle N/M=%.1f", int(rate*100), ratio),
				bound: m, warmup: w, measured: d, stream: churning(n, rate),
			})
		}
	}
	// The estate the operator actually described: Q2's mixed traffic over Q3's
	// drifting membership. Criterion 2 of the prompt's Step 3 is applied to
	// these rows, because these are the ones that match both answers.
	for _, alpha := range []float64{0.9, 1.2} {
		for _, rate := range []float64{0.01, 0.10} {
			n := 2 * m
			w, d := window(n)
			cases = append(cases, simTrace{
				label: fmt.Sprintf("zipf a=%.1f + churn %d%% N/M=2.0", alpha, int(rate*100)),
				bound: m, warmup: w, measured: d, stream: zipfChurn(n, alpha, rate),
			})
		}
	}
	return cases
}

// TestAdmissionSimulation prints the comparison matrix phase 0032 decides
// from, in the units the decision is made in: hit rate, the Hoplock Control
// calls per connection it implies (PLAN §9.1's measured 2.17 on a hit and 3.17
// on a miss), and the Control req/s that is worth at the five-minute row's
// 1,167 conn/s.
//
// It is gated behind its own -run: CI is a gate and this is a study.
//
//	go test ./internal/control -run AdmissionSimulation -v
func TestAdmissionSimulation(t *testing.T) {
	requireExplicitRun(t)

	results := make(map[string]map[string]simResult)
	var order []string
	for _, tr := range simCases() {
		row := make(map[string]simResult)
		for _, p := range simPolicies() {
			row[p.label] = runSim(tr, p, 1)
		}
		results[tr.label] = row
		order = append(order, tr.label)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "\nAdmission-policy comparison. Bound M = %d lookup paths throughout.\n", measuredBound)
	fmt.Fprintf(&b, "hit%% | Hoplock Control calls/conn | Control req/s at %.0f conn/s (PLAN §9.1)\n\n",
		sizingConnectionsPerSec)
	fmt.Fprintf(&b, "%-34s", "trace")
	for _, p := range simPolicies() {
		fmt.Fprintf(&b, "  %-22s", p.label)
	}
	b.WriteString("\n")
	for _, label := range order {
		fmt.Fprintf(&b, "%-34s", label)
		for _, p := range simPolicies() {
			r := results[label][p.label]
			fmt.Fprintf(&b, "  %5.1f %5.2f %7.0f     ", r.hitRate, r.calls, r.controlR)
		}
		b.WriteString("\n")
	}
	t.Log(b.String())

	sketch := newTinyLFU(measuredBound, 0)
	t.Logf("tinylfu sketch cost: %.2f bytes per cached entry (4-bit counters packed two per byte, plus doorkeeper), "+
		"against the ~1,024 bytes an entry already costs (BenchmarkCachedEntryFootprint)",
		sketch.sketchMemoryPerEntry(measuredBound))

	assertSimInvariants(t, results)
}

// assertSimInvariants is what makes this a test rather than a print. Each one
// is a property the study's conclusions rest on, so a change that breaks one
// invalidates the matrix above it.
func assertSimInvariants(t *testing.T, results map[string]map[string]simResult) {
	t.Helper()

	for trace, row := range results {
		for policy, r := range row {
			if r.hitRate < 0 || r.hitRate > 100 {
				t.Errorf("%s/%s: hit rate %.1f%% is not a rate", trace, policy, r.hitRate)
			}
		}
	}

	// Below the bound the working set fits and there is nothing to decide:
	// every policy must be perfect, or it is broken rather than interesting.
	for _, label := range []string{"uniform-cycle N/M=0.50", "uniform-cycle N/M=0.90", "uniform-cycle N/M=1.00"} {
		for policy, r := range results[label] {
			if r.hitRate < 99.9 {
				t.Errorf("%s/%s: %.1f%%, want 100%% — a working set that fits is never a policy question",
					label, policy, r.hitRate)
			}
		}
	}

	// The cliff itself: on a strict cycle LRU keeps nothing once the working
	// set exceeds the bound, however slightly. This is the finding the phase
	// evaluates, so it is asserted rather than trusted.
	for _, label := range []string{"uniform-cycle N/M=1.10", "uniform-cycle N/M=2.00", "uniform-cycle N/M=10.00"} {
		if r := results[label]["lru"]; r.hitRate > 1 {
			t.Errorf("%s/lru: %.1f%%, want ~0%% — a strict cycle is LRU's worst case", label, r.hitRate)
		}
	}

	// And the slope it is measured against: refusing to store degrades as M/N.
	for _, tc := range []struct {
		label string
		ratio float64
	}{
		{"uniform-cycle N/M=1.10", 1.1},
		{"uniform-cycle N/M=2.00", 2},
		{"uniform-cycle N/M=10.00", 10},
	} {
		want := 100 / tc.ratio
		if r := results[tc.label]["freeze"]; r.hitRate < want-2 || r.hitRate > want+2 {
			t.Errorf("%s/freeze: %.1f%%, want M/N = %.1f%%", tc.label, r.hitRate, want)
		}
	}
}

// requireExplicitRun keeps the study out of `go test ./...`, which this
// repository runs with -race as a merge gate. The matrix takes tens of seconds
// and asserts a comparison rather than a regression, so it runs when it is
// asked for by name and not otherwise.
func requireExplicitRun(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("admission simulation: a study, skipped in -short")
	}
	f := flag.Lookup("test.run")
	if f == nil || !strings.Contains(f.Value.String(), "AdmissionSimulation") {
		t.Skip("admission simulation: run it by name — go test ./internal/control -run AdmissionSimulation -v")
	}
}
