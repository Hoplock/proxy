// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"context"
	"net/http"
	"testing"

	"github.com/hoplock/proxy/internal/control"
)

func leaseReq(proxyID, target string) *control.UIDLeaseRequest {
	return &control.UIDLeaseRequest{
		ProxyID:  proxyID,
		Target:   target,
		UIDCount: 16,
		RangeMin: 2000000,
		RangeMax: 2999999,
	}
}

// TestUIDBlocksNeverOverlap is the one invariant a real Control must keep, and
// everything the proxy relies on follows from it: the per-target cursor only
// ever advances, so a uid inside a granted block is never inside another grant,
// for this proxy or any other, ever again.
func TestUIDBlocksNeverOverlap(t *testing.T) {
	m := startMock(t, nil, serverOptions{})
	ctx := context.Background()

	seen := map[int]string{}
	var last int
	for _, proxyID := range []string{"proxy-a", "proxy-b", "proxy-a", "proxy-c"} {
		resp, err := m.client.LeaseUIDs(ctx, leaseReq(proxyID, "host.company.com"))
		if err != nil {
			t.Fatalf("LeaseUIDs(%s): %v", proxyID, err)
		}
		if resp.UIDTo <= resp.UIDFrom {
			t.Fatalf("%s was granted an empty block [%d,%d)", proxyID, resp.UIDFrom, resp.UIDTo)
		}
		if resp.UIDFrom < last {
			t.Errorf("%s was granted a block starting at %d, below the last block's end %d; "+
				"the cursor must only advance", proxyID, resp.UIDFrom, last)
		}
		for uid := resp.UIDFrom; uid < resp.UIDTo; uid++ {
			if other, dup := seen[uid]; dup {
				t.Fatalf("uid %d was granted to both %s and %s", uid, other, proxyID)
			}
			seen[uid] = proxyID
		}
		last = resp.UIDTo
	}
	if got := m.server.uidLeaseCalls("host.company.com", 0); got != 4 {
		t.Errorf("the server counted %d grants for this target, want 4; the count is what lets a "+
			"test assert one call per BLOCK rather than per session", got)
	}
	if other := m.server.uidLeaseCalls("host.company.com", 2222); other != 0 {
		t.Errorf("a target on another port shows %d grants; leases are keyed on host AND port", other)
	}
}

// TestUIDCursorsArePerTarget: a block burned on one target must not move another
// target's floor, or a busy host would exhaust the range for the whole fleet.
func TestUIDCursorsArePerTarget(t *testing.T) {
	m := startMock(t, nil, serverOptions{})
	ctx := context.Background()

	first, err := m.client.LeaseUIDs(ctx, leaseReq("proxy-a", "one.company.com"))
	if err != nil {
		t.Fatalf("LeaseUIDs: %v", err)
	}
	if _, err := m.client.LeaseUIDs(ctx, leaseReq("proxy-a", "one.company.com")); err != nil {
		t.Fatalf("LeaseUIDs: %v", err)
	}
	other, err := m.client.LeaseUIDs(ctx, leaseReq("proxy-a", "two.company.com"))
	if err != nil {
		t.Fatalf("LeaseUIDs: %v", err)
	}
	if other.UIDFrom != first.UIDFrom {
		t.Errorf("a second target's first block starts at %d, want %d: cursors are per target",
			other.UIDFrom, first.UIDFrom)
	}
}

// TestAnObservedFloorRaisesTheCursor covers the migration case the target-side
// mark still exists for — a server whose cursor sits below a mark an earlier
// deployment left. It may only ever raise, which is what makes honouring a
// target's word safe in this one direction.
func TestAnObservedFloorRaisesTheCursor(t *testing.T) {
	m := startMock(t, nil, serverOptions{})
	ctx := context.Background()

	req := leaseReq("proxy-a", "host.company.com")
	req.ObservedFloor = 2050000
	resp, err := m.client.LeaseUIDs(ctx, req)
	if err != nil {
		t.Fatalf("LeaseUIDs: %v", err)
	}
	if resp.UIDFrom <= 2050000 {
		t.Errorf("the block starts at %d, at or below the observed floor 2050000", resp.UIDFrom)
	}

	// And it may not LOWER it: a floor below the cursor changes nothing, which
	// is what stops a tampered mark from pulling the range back.
	back := leaseReq("proxy-a", "host.company.com")
	back.ObservedFloor = 1
	after, err := m.client.LeaseUIDs(ctx, back)
	if err != nil {
		t.Fatalf("LeaseUIDs: %v", err)
	}
	if after.UIDFrom < resp.UIDTo {
		t.Errorf("an observed floor of 1 pulled the cursor back to %d from %d",
			after.UIDFrom, resp.UIDTo)
	}
}

// TestAnExhaustedUIDRangeIsRefusedNotWrapped: at the top of the range the server
// refuses. Wrapping would hand back uids it has already granted, which is the
// reuse the whole mechanism exists to prevent.
func TestAnExhaustedUIDRangeIsRefusedNotWrapped(t *testing.T) {
	fx, err := loadFixtures(exampleFixturesPath)
	if err != nil {
		t.Fatalf("loadFixtures: %v", err)
	}
	fx.UIDLeases = fixtureUIDLeases{UIDCount: 8, RangeMin: 2000000, RangeMax: 2000015}
	m := startMock(t, fx, serverOptions{})
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if _, err := m.client.LeaseUIDs(ctx, leaseReq("proxy-a", "host.company.com")); err != nil {
			t.Fatalf("LeaseUIDs %d: %v", i, err)
		}
	}
	if _, err := m.client.LeaseUIDs(ctx, leaseReq("proxy-a", "host.company.com")); err == nil {
		t.Fatal("a third block was granted from a range with room for two")
	}
}

// TestALeaseNeedsANamedProxy: a block is granted TO a proxy, and a server that
// allowed an unnamed one could not answer "whose block was this uid in".
func TestALeaseNeedsANamedProxy(t *testing.T) {
	m := startMock(t, nil, serverOptions{})
	req := leaseReq("", "host.company.com")
	if _, err := m.client.LeaseUIDs(context.Background(), req); err == nil {
		t.Fatal("a lease with no proxy_id was granted")
	}
}

// TestTheUIDCursorSurvivesAReset is a claim about the MOCK rather than the
// contract, and it is here because the alternative is a subtle test-only defect:
// /debug/reset returns the mock to a clean state between e2e scenarios, and a
// cursor reset there would REWIND it — granting a block that overlaps one a proxy
// is still allocating from.
func TestTheUIDCursorSurvivesAReset(t *testing.T) {
	m := startMock(t, nil, serverOptions{})
	ctx := context.Background()

	first, err := m.client.LeaseUIDs(ctx, leaseReq("proxy-a", "host.company.com"))
	if err != nil {
		t.Fatalf("LeaseUIDs: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, m.srv.URL+pathDebugReset, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	_ = resp.Body.Close()

	after, err := m.client.LeaseUIDs(ctx, leaseReq("proxy-a", "host.company.com"))
	if err != nil {
		t.Fatalf("LeaseUIDs after reset: %v", err)
	}
	if after.UIDFrom < first.UIDTo {
		t.Errorf("the cursor rewound to %d across a reset, from %d; a rewound cursor grants a "+
			"block overlapping one a proxy is still allocating from", after.UIDFrom, first.UIDTo)
	}
}
