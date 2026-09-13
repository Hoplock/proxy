// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/hoplock/proxy/internal/control"
)

// fakeUIDLeases is a Hoplock Control that grants blocks from one monotonic
// cursor, which is the whole server-side requirement the contract states.
//
// It counts its calls because "one call per BLOCK, not per session" is the claim
// that justifies the lease shape over a per-session floor — phases 0022 and 0023
// spent themselves taking per-connection Control calls from 3.17 to 1.17
// (PLAN §9.1), and a shape that gave that back would not be worth having.
type fakeUIDLeases struct {
	mu     sync.Mutex
	from   int
	to     int
	calls  int
	fail   error
	closed bool
}

func (f *fakeUIDLeases) grant(floor int) (control.UIDBlock, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return control.UIDBlock{}, f.fail
	}
	if f.closed {
		return control.UIDBlock{}, errors.New("control unreachable")
	}
	size := f.to - f.from
	if f.calls > 0 {
		// The cursor only ever advances: the next block sits above the last,
		// whether or not the last was used up.
		f.from = f.to
		f.to = f.from + size
	}
	if floor >= f.from {
		f.from = floor + 1
		if f.to <= f.from {
			f.to = f.from + size
		}
	}
	f.calls++
	return control.UIDBlock{LeaseID: fmt.Sprintf("lease-test-%d", f.calls), From: f.from, To: f.to}, nil
}

// Block models the holder's rule: a block already in hand is served WITHOUT
// reaching the server, which is what makes a Control outage survivable.
func (f *fakeUIDLeases) Block(_ context.Context, _ string, _, floor int) (control.UIDBlock, error) {
	f.mu.Lock()
	held := f.calls > 0 && f.to > floor
	block := control.UIDBlock{LeaseID: fmt.Sprintf("lease-test-%d", f.calls), From: f.from, To: f.to}
	f.mu.Unlock()
	if held {
		return block, nil
	}
	return f.grant(floor)
}

func (f *fakeUIDLeases) Replace(_ context.Context, _ string, _, floor int, _ control.UIDBlock) (control.UIDBlock, error) {
	return f.grant(floor)
}

func (f *fakeUIDLeases) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeUIDLeases) unreachable() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
}

// TestARestartedProxyAllocatesAboveTheOldBlockWithNoMark is the defect phase
// 0035 exists to close, and it fails without the lease.
//
// A proxy that restarts loses a.high, so before this phase its only floor was
// the target's own mark — and a target that has no mark (deleted by root,
// reimaged, never writable) put a torn-down session's uid straight back in play.
// Here the target reports NOTHING: an empty census and no mark at all. The block
// is the only floor there is, and it has to be enough.
func TestARestartedProxyAllocatesAboveTheOldBlockWithNoMark(t *testing.T) {
	leases := &fakeUIDLeases{from: 2000000, to: 2000004}

	// The proxy before the restart: it spends its block.
	first := testAllocator(t, DefaultUIDMin, DefaultUIDMax)
	blockOne, err := leases.Block(context.Background(), "host", 22, 0)
	if err != nil {
		t.Fatalf("Block: %v", err)
	}
	var spent []int
	for {
		plan, err := first.allocate("host:22", census(0), blockOne)
		if errors.Is(err, errUIDBlockSpent) {
			break
		}
		if err != nil {
			t.Fatalf("allocate: %v", err)
		}
		spent = append(spent, plan.uid)
	}
	if len(spent) == 0 {
		t.Fatal("the first proxy allocated nothing")
	}

	// The restart. Everything this process knew is gone, and so is every trace
	// on the target: an empty account database and no mark.
	second := testAllocator(t, DefaultUIDMin, DefaultUIDMax)
	blockTwo, err := leases.Replace(context.Background(), "host", 22, 0, blockOne)
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	plan, err := second.allocate("host:22", census(0), blockTwo)
	if err != nil {
		t.Fatalf("allocate after restart: %v", err)
	}
	for _, uid := range spent {
		if plan.uid == uid {
			t.Fatalf("a restarted proxy was handed uid %d again, which a torn-down session held; "+
				"the leased block is the only floor a restart has left", uid)
		}
	}
	if plan.uid <= spent[len(spent)-1] {
		t.Errorf("allocated %d after %d; a block is granted ABOVE the cursor, never beside it",
			plan.uid, spent[len(spent)-1])
	}
}

// TestTwoProxiesOnOneTargetCannotCollide is the multi-proxy case, which
// exclusivity closes by construction rather than by both of them reading one
// shared counter on the session path.
func TestTwoProxiesOnOneTargetCannotCollide(t *testing.T) {
	leases := &fakeUIDLeases{from: 2000000, to: 2000008}
	ctx := context.Background()

	blockA, err := leases.Block(ctx, "host", 22, 0)
	if err != nil {
		t.Fatalf("Block: %v", err)
	}
	blockB, err := leases.Replace(ctx, "host", 22, 0, blockA)
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}

	a := testAllocator(t, DefaultUIDMin, DefaultUIDMax)
	b := testAllocator(t, DefaultUIDMin, DefaultUIDMax)
	seen := map[int]string{}
	for i := 0; i < 8; i++ {
		for name, pair := range map[string]struct {
			alloc *uidAllocator
			block control.UIDBlock
		}{"a": {a, blockA}, "b": {b, blockB}} {
			plan, err := pair.alloc.allocate("host:22", census(0), pair.block)
			if errors.Is(err, errUIDBlockSpent) {
				continue
			}
			if err != nil {
				t.Fatalf("proxy %s: %v", name, err)
			}
			if other, dup := seen[plan.uid]; dup {
				t.Fatalf("proxy %s was handed uid %d, which proxy %s already holds; "+
					"two blocks must not overlap", name, plan.uid, other)
			}
			seen[plan.uid] = name
		}
	}
	if len(seen) == 0 {
		t.Fatal("neither proxy allocated anything")
	}
}

// TestAMarkAboveTheBlockStillWins keeps the demoted mark doing the one job it
// still has: it may RAISE a floor the lease set, and never lower it.
func TestAMarkAboveTheBlockStillWins(t *testing.T) {
	a := testAllocator(t, DefaultUIDMin, DefaultUIDMax)
	block := control.UIDBlock{LeaseID: "l1", From: 2000000, To: 2000100}

	// A mark sitting above the block's floor — a previous deployment's, or a
	// server whose cursor was lost. The allocation must clear it.
	plan, err := a.allocate("host:22", census(2000050), block)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if plan.uid != 2000051 {
		t.Errorf("allocated %d; a mark above the block's floor must still raise it", plan.uid)
	}
}

// TestAMarkBelowWhatWasIssuedChangesNothing is phase 0027's trust boundary,
// re-asserted through the lease: everything the target says may only RAISE.
func TestAMarkBelowWhatWasIssuedChangesNothing(t *testing.T) {
	a := testAllocator(t, DefaultUIDMin, DefaultUIDMax)
	block := control.UIDBlock{LeaseID: "l1", From: 2000000, To: 2000100}

	first, err := a.allocate("host:22", census(2000010), block)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	// The mark is now wiped, which is what an attacker with root on the target
	// can do and is the only direction they can move it.
	second, err := a.allocate("host:22", census(0), block)
	if err != nil {
		t.Fatalf("allocate after the mark was wiped: %v", err)
	}
	if second.uid <= first.uid {
		t.Errorf("a wiped mark pulled the allocation back to %d after %d", second.uid, first.uid)
	}
}

// TestAnExhaustedBlockTakesAFreshOneRatherThanWrapping is the difference between
// a spent block and a spent range: one is recoverable and the other is the
// operator's.
func TestAnExhaustedBlockTakesAFreshOneRatherThanWrapping(t *testing.T) {
	a := testAllocator(t, DefaultUIDMin, DefaultUIDMax)
	block := control.UIDBlock{LeaseID: "l1", From: 2000000, To: 2000002}

	if _, err := a.allocate("host:22", census(0), block); err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if _, err := a.allocate("host:22", census(0), block); err != nil {
		t.Fatalf("allocate: %v", err)
	}
	_, err := a.allocate("host:22", census(0), block)
	if !errors.Is(err, errUIDBlockSpent) {
		t.Fatalf("a spent block = %v, want errUIDBlockSpent so the caller can take a fresh one", err)
	}
	if !errors.Is(err, ErrUIDUnavailable) {
		t.Error("errUIDBlockSpent must still be ErrUIDUnavailable: a caller that cannot " +
			"recover has to report the right class of failure")
	}
}

// TestTheTopOfTheConfiguredRangeIsFinal is the other half: past uid_max no block
// can help, because the holder refuses to accept one above it. The message has
// to be the operator's, not the recoverable one.
func TestTheTopOfTheConfiguredRangeIsFinal(t *testing.T) {
	a := testAllocator(t, 2000000, 2000010)
	block := control.UIDBlock{LeaseID: "l1", From: 2000000, To: 2000100}

	_, err := a.allocate("host:22", census(2000010), block)
	if !errors.Is(err, ErrUIDUnavailable) {
		t.Fatalf("past uid_max = %v, want ErrUIDUnavailable", err)
	}
	if errors.Is(err, errUIDBlockSpent) {
		t.Error("past uid_max reported a spent block; a fresh one cannot help and the " +
			"caller would burn the server's range asking for one")
	}
	if !strings.Contains(err.Error(), "does not wrap") {
		t.Errorf("the refusal reads %q; it must say the range does not wrap, because that is the operator's fix", err)
	}
}

// TestProvisioningSurvivesAControlOutageWhileTheBlockLasts is the availability
// claim that makes the lease shape defensible at all: a block granted to this
// proxy cannot have been granted to anybody else, so it is safe to keep using
// when Control is gone. PLAN §5.1's teardown and D16's deadline are deliberately
// uncoupled from Control for the same reason, and this keeps provisioning in
// that company.
func TestProvisioningSurvivesAControlOutageWhileTheBlockLasts(t *testing.T) {
	h := startFakeHost(t)
	auth := newTestEphemeral(t, h, "proxy-a")
	leases := &fakeUIDLeases{from: 5000, to: 5100}
	auth.leases = leases
	ctx := context.Background()
	tgt := h.tgt()
	tgt.Auth = ephemeralRoute(nil)

	first, err := auth.Provision(ctx, testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if err := first.Teardown(ctx); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	// Hoplock Control goes away. The block in hand is untouched by that.
	leases.unreachable()
	second, err := auth.Provision(ctx, testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision during a Control outage: %v; a held block must not need the server", err)
	}
	defer func() { _ = second.Teardown(ctx) }()

	if second.AccountUID == first.AccountUID {
		t.Errorf("both sessions were handed uid %d", second.AccountUID)
	}
	if got := leases.callCount(); got != 1 {
		t.Errorf("%d lease calls for two sessions; the shape is one call per BLOCK, not per session", got)
	}
}

// TestAnExhaustedBlockMidOutageIsAnOutageAndDisclosesNothing is the trade-off
// stated plainly: fail closed. A Control outage plus a busy target is a
// provisioning outage for that target, which is the posture phase 0027 set
// (PLAN §4.3) and is why the term and the block size are knobs an operator sizes
// against their own outages rather than hidden constants.
func TestAnExhaustedBlockMidOutageIsAnOutageAndDisclosesNothing(t *testing.T) {
	h := startFakeHost(t)
	auth := newTestEphemeral(t, h, "proxy-a")
	// A block of exactly one uid, so the second session needs a fresh one.
	leases := &fakeUIDLeases{from: 5000, to: 5001}
	auth.leases = leases
	ctx := context.Background()
	tgt := h.tgt()
	tgt.Auth = ephemeralRoute(nil)

	first, err := auth.Provision(ctx, testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	defer func() { _ = first.Teardown(ctx) }()

	leases.unreachable()
	_, err = auth.Provision(ctx, testIdentity(), tgt)
	if !errors.Is(err, ErrUIDUnavailable) {
		t.Fatalf("an exhausted block during an outage = %v, want ErrUIDUnavailable", err)
	}
	// It is an outage, so the engine says so (PLAN §4.3) — but the text it is
	// built from must still name nothing about the estate.
	for _, leak := range []string{h.tgt().Host, "5000", "5001"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("the refusal names %q: %v", leak, err)
		}
	}
	if accounts := h.ephemeralAccounts(t); len(accounts) != 1 {
		t.Errorf("the refused session left %v behind; it must provision nothing", accounts)
	}
}

// TestADeviceAdministratorInheritsNothingNumeric answers phase 0035's §3
// question in a test rather than by assumption, which is 0015's lesson: four
// documented facts about FortiOS turned out to be wrong, so "a device has no uid
// to recycle" is checked.
//
// The answer is NO, and it has two independent halves:
//
//   - the proxy allocates NOTHING numeric on a device. Every uid symbol in this
//     package is an EphemeralAuthenticator method, so ProvisionedAccess comes
//     back with no uid and no lease — asserted below, and it is what keeps a
//     device route working with no Control lease at all;
//   - the device's own objects are NAME-keyed, and the names carry a per-session
//     random token (principal.go). Every object the drivers create is
//     `edit "<name>"` — `config system admin` for the administrator, and 0017's
//     `config firewall schedule onetime` for its deadline — never a numbered
//     slot of the kind `config firewall policy` uses. So a freshly provisioned
//     administrator shares no identifier with a torn-down one, and there is
//     nothing for it to inherit.
//
// If a platform ever appears with a recycled admin index, a session id, or a
// numbered object slot, that is a finding for its own phase and not something
// this one quietly covers.
func TestADeviceAdministratorInheritsNothingNumeric(t *testing.T) {
	h := newDeviceHarness(t, deviceHarnessOptions{deliverable: true})
	ctx := context.Background()
	tgt := h.tgt
	tgt.Auth = deviceRouteAuth(nil)

	first, err := h.auth.Provision(ctx, deviceIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if first.AccountUID != 0 {
		t.Errorf("a device account reported uid %d; the proxy allocates no uid on a device, "+
			"and a non-zero one here would mean the ephemeral-user path had been entered",
			first.AccountUID)
	}
	if first.UIDLease != "" {
		t.Errorf("a device account carries uid lease %q; a device route must not need a lease, "+
			"or every device would be refused while Hoplock Control is unreachable", first.UIDLease)
	}
	name := first.ClientConfig.User
	if err := first.Close(ctx); err != nil {
		t.Fatalf("teardown: %v", err)
	}

	second, err := h.auth.Provision(ctx, deviceIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision after teardown: %v", err)
	}
	defer func() { _ = second.Close(ctx) }()
	if second.ClientConfig.User == name {
		t.Errorf("a freshly provisioned administrator reuses the torn-down one's name %q; "+
			"the per-session token is what makes it inherit nothing", name)
	}
}
