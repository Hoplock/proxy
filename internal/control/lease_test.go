// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// stubLeaser is a Hoplock Control that grants blocks from a monotonic cursor.
type stubLeaser struct {
	mu     sync.Mutex
	cursor int
	size   int
	term   int
	calls  int
	floors []int
	err    error
}

func (s *stubLeaser) LeaseUIDs(_ context.Context, req *UIDLeaseRequest) (*UIDLeaseResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.floors = append(s.floors, req.ObservedFloor)
	if s.err != nil {
		return nil, s.err
	}
	if s.cursor == 0 {
		s.cursor = 2000000
	}
	if req.ObservedFloor >= s.cursor {
		s.cursor = req.ObservedFloor + 1
	}
	size := s.size
	if size == 0 {
		size = 16
	}
	from := s.cursor
	s.cursor += size
	return &UIDLeaseResponse{
		LeaseID:     "lease-" + strings.Repeat("x", s.calls),
		UIDFrom:     from,
		UIDTo:       s.cursor,
		TermSeconds: s.term,
	}, nil
}

func testHolder(t *testing.T, client UIDLeaser, opts ...func(*UIDLeaseOptions)) *UIDLeaseHolder {
	t.Helper()
	o := UIDLeaseOptions{
		Client:   client,
		ProxyID:  "proxy-a",
		UIDCount: 16,
		RangeMin: 2000000,
		RangeMax: 2999999,
	}
	for _, f := range opts {
		f(&o)
	}
	h, err := NewUIDLeaseHolder(o)
	if err != nil {
		t.Fatalf("NewUIDLeaseHolder: %v", err)
	}
	return h
}

// TestOneCallPerBlockNotPerSession is the claim that justifies the lease shape
// over anything asked per session. Phases 0022 and 0023 spent themselves taking
// per-connection Control calls from 3.17 to 1.17 (PLAN §9.1); a floor fetched
// per session would give that back, so this is asserted rather than assumed.
func TestOneCallPerBlockNotPerSession(t *testing.T) {
	stub := &stubLeaser{size: 64}
	h := testHolder(t, stub)
	ctx := context.Background()

	first, err := h.Block(ctx, "host.example.com", 22, 0)
	if err != nil {
		t.Fatalf("Block: %v", err)
	}
	for i := 0; i < 32; i++ {
		got, err := h.Block(ctx, "host.example.com", 22, first.From+i)
		if err != nil {
			t.Fatalf("Block %d: %v", i, err)
		}
		if got.LeaseID != first.LeaseID {
			t.Fatalf("session %d got a different block; the held one still serves", i)
		}
	}
	if stub.calls != 1 {
		t.Errorf("%d lease calls for 33 allocations; the shape is one call per BLOCK", stub.calls)
	}
}

// TestAHeldBlockNeedsNoServer is the availability property: a block granted to
// this proxy cannot have been granted to anybody else, so it is safe to keep
// using while Control is unreachable.
func TestAHeldBlockNeedsNoServer(t *testing.T) {
	stub := &stubLeaser{size: 64}
	h := testHolder(t, stub)
	ctx := context.Background()

	first, err := h.Block(ctx, "host.example.com", 22, 0)
	if err != nil {
		t.Fatalf("Block: %v", err)
	}
	stub.mu.Lock()
	stub.err = errors.New("control unreachable")
	stub.mu.Unlock()

	got, err := h.Block(ctx, "host.example.com", 22, first.From)
	if err != nil {
		t.Fatalf("Block during an outage: %v", err)
	}
	if got.LeaseID != first.LeaseID {
		t.Error("a held block was replaced during an outage")
	}
}

// TestASpentBlockDuringAnOutageFailsClosed states the trade-off rather than
// hiding it: a Control outage plus a busy target becomes a provisioning outage
// for that target. Fail closed is the posture phase 0027 set, and the term and
// the block size are the operator's knobs against it.
func TestASpentBlockDuringAnOutageFailsClosed(t *testing.T) {
	stub := &stubLeaser{size: 4}
	h := testHolder(t, stub)
	ctx := context.Background()

	block, err := h.Block(ctx, "host.example.com", 22, 0)
	if err != nil {
		t.Fatalf("Block: %v", err)
	}
	stub.mu.Lock()
	stub.err = errors.New("control unreachable")
	stub.mu.Unlock()

	if _, err := h.Block(ctx, "host.example.com", 22, block.To); err == nil {
		t.Fatal("a spent block during an outage was served; it must fail closed")
	}
	if _, err := h.Replace(ctx, "host.example.com", 22, block.To, block); err == nil {
		t.Fatal("Replace during an outage succeeded")
	}
}

// TestAnExpiredBlockIsNotAllocatedFrom covers the other way a block ends. An
// expired one is a block THIS PROXY stops using; it is never granted to anybody
// else, because the server's cursor only advances — which is why expiry costs
// availability and never the invariant.
func TestAnExpiredBlockIsNotAllocatedFrom(t *testing.T) {
	stub := &stubLeaser{size: 64, term: 60}
	now := time.Now()
	h := testHolder(t, stub, func(o *UIDLeaseOptions) {
		o.RenewBefore = time.Second
		o.Now = func() time.Time { return now }
	})
	ctx := context.Background()

	first, err := h.Block(ctx, "host.example.com", 22, 0)
	if err != nil {
		t.Fatalf("Block: %v", err)
	}
	if first.Live(now.Add(2 * time.Minute)) {
		t.Error("a block with a 60s term is still live two minutes on")
	}

	now = now.Add(2 * time.Minute)
	second, err := h.Block(ctx, "host.example.com", 22, 0)
	if err != nil {
		t.Fatalf("Block after expiry: %v", err)
	}
	if second.LeaseID == first.LeaseID {
		t.Error("an expired block was served again")
	}
	if second.From < first.To {
		t.Errorf("the replacement block starts at %d, inside the expired one ending at %d; "+
			"the cursor only advances", second.From, first.To)
	}
}

// TestABlockOutsideTheConfiguredRangeIsRefused is a check that is not a
// formality: uid_min/uid_max encode facts about the fleet the server has no way
// to know, and a block below them would collide with the target's OWN accounts —
// a worse failure than the one the lease prevents.
func TestABlockOutsideTheConfiguredRangeIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		resp UIDLeaseResponse
		says string
	}{
		{"below uid_min", UIDLeaseResponse{LeaseID: "l", UIDFrom: 1000, UIDTo: 2000}, "below the configured uid_min"},
		{"above uid_max", UIDLeaseResponse{LeaseID: "l", UIDFrom: 2999000, UIDTo: 3100000}, "above the configured uid_max"},
		{"empty", UIDLeaseResponse{LeaseID: "l", UIDFrom: 2000000, UIDTo: 2000000}, "empty uid block"},
		{"unnamed", UIDLeaseResponse{UIDFrom: 2000000, UIDTo: 2000010}, "no lease id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := testHolder(t, &stubLeaser{})
			_, err := h.accept(&tc.resp)
			if err == nil {
				t.Fatalf("accept(%+v) was allowed", tc.resp)
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("the refusal reads %q, want it to name %q", err, tc.says)
			}
		})
	}
}

// TestTheObservedFloorIsPassedOnSoAServerCanCatchUp covers the migration case
// the target-side mark still exists for: a server whose cursor sits below a mark
// left by an earlier deployment would otherwise grant blocks the proxy must
// discard one after another.
func TestTheObservedFloorIsPassedOnSoAServerCanCatchUp(t *testing.T) {
	stub := &stubLeaser{size: 16}
	h := testHolder(t, stub)

	block, err := h.Block(context.Background(), "host.example.com", 22, 2000500)
	if err != nil {
		t.Fatalf("Block: %v", err)
	}
	if block.From <= 2000500 {
		t.Errorf("the granted block starts at %d, at or below the observed floor 2000500", block.From)
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if len(stub.floors) != 1 || stub.floors[0] != 2000500 {
		t.Errorf("the server saw floors %v, want the observation [2000500]", stub.floors)
	}
}

// TestTwoSessionsOnOneTargetMakeOneCall is the per-target lock doing its job: a
// stampede would burn one block per session, which is the cost the whole shape
// exists to avoid.
func TestTwoSessionsOnOneTargetMakeOneCall(t *testing.T) {
	stub := &stubLeaser{size: 1024}
	h := testHolder(t, stub)
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := h.Block(ctx, "host.example.com", 22, 0); err != nil {
				t.Errorf("Block: %v", err)
			}
		}()
	}
	wg.Wait()

	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.calls != 1 {
		t.Errorf("%d lease calls from 8 concurrent sessions on one target, want 1", stub.calls)
	}
}

// TestReplaceDoesNotBurnASecondBlock covers the race two sessions hit when they
// both find the block spent: the second must take the first's replacement rather
// than asking for one of its own.
func TestReplaceDoesNotBurnASecondBlock(t *testing.T) {
	stub := &stubLeaser{size: 4}
	h := testHolder(t, stub)
	ctx := context.Background()

	spent, err := h.Block(ctx, "host.example.com", 22, 0)
	if err != nil {
		t.Fatalf("Block: %v", err)
	}
	first, err := h.Replace(ctx, "host.example.com", 22, spent.To, spent)
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	second, err := h.Replace(ctx, "host.example.com", 22, spent.To, spent)
	if err != nil {
		t.Fatalf("Replace again: %v", err)
	}
	if second.LeaseID != first.LeaseID {
		t.Errorf("the second Replace took a new block %q over %q", second.LeaseID, first.LeaseID)
	}
	if stub.calls != 2 {
		t.Errorf("%d lease calls, want 2: the first block and one replacement", stub.calls)
	}
}

// TestACachingClientCannotLeaseUIDs is the trap phase 0035 is built around,
// asserted where it cannot rot: an authorize decision is cacheable and is served
// while Control is unreachable, so a floor that could be answered from memory
// would be replayed — and a stale floor is a LOWERED floor.
//
// The guarantee is structural rather than behavioural, so the test is a type
// assertion: CachingClient implements no UIDLeaser, and wiring one in is a
// compile error rather than a review comment.
func TestACachingClientCannotLeaseUIDs(t *testing.T) {
	var c any = NewCachingClient(nil, CacheOptions{})
	if _, ok := c.(UIDLeaser); ok {
		t.Fatal("CachingClient implements UIDLeaser; a lease answered from a cache is a replayed floor, " +
			"which is the uid reuse contract 4.3 exists to prevent")
	}
}
