// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"errors"
	"strings"
	"testing"
)

// census is a uidCensus a test can write in one line. The `read` flag is set,
// because a census that was NOT read is its own case and has its own test below.
func census(watermark int, inUse ...int) uidCensus {
	c := uidCensus{inUse: map[int]bool{}, watermark: watermark, read: true}
	for _, uid := range inUse {
		c.inUse[uid] = true
	}
	return c
}

func testAllocator(t *testing.T, min, max int) *uidAllocator {
	t.Helper()
	a, err := newUIDAllocator(min, max)
	if err != nil {
		t.Fatalf("newUIDAllocator(%d, %d): %v", min, max, err)
	}
	return a
}

// TestUIDAllocatorAllocatesAboveTheHighWaterMark is the allocation rule itself:
// strictly above everything the target has ever handed out, never the lowest
// free uid — which is what the target's own allocator picks and is the whole
// defect (PLAN §5.1).
func TestUIDAllocatorAllocatesAboveTheHighWaterMark(t *testing.T) {
	for _, tc := range []struct {
		name   string
		census uidCensus
		want   int
	}{
		{"an untouched range starts at the bottom", census(0), 2000},
		{"the mark alone raises the floor", census(2010), 2011},
		{"a live account raises it too", census(0, 2003), 2004},
		{"the highest of the two wins", census(2010, 2003), 2011},
		{"and so does the highest account", census(2003, 2010), 2011},
		{
			// The case the defect is made of: an account was created and torn
			// down, so nothing holds the uid any more. The lowest free uid is
			// the bottom of the range; the answer must be above the mark.
			"a torn-down account's uid is not free again",
			census(2005),
			2006,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := testAllocator(t, 2000, 2999)
			plan, err := a.allocate("target:22", tc.census)
			if err != nil {
				t.Fatalf("allocate: %v", err)
			}
			if plan.uid != tc.want {
				t.Errorf("allocated uid %d, want %d", plan.uid, tc.want)
			}
			if len(plan.candidates) == 0 || plan.candidates[0] != plan.uid {
				t.Errorf("candidates = %v, want the allocation %d first", plan.candidates, plan.uid)
			}
		})
	}
}

// TestUIDAllocatorRefusesAtWrapAround is the wrap-around decision, and it is the
// one this phase had to make: at the top of the range allocation REFUSES rather
// than returning to the bottom.
//
// The bottom of the range is free in this test, and deliberately so — a uid
// being free is exactly the reasoning a wrapping allocator would use, and it is
// not sufficient. A uid the range has already handed out may own files a session
// wrote outside its home, and nothing on the target says so.
func TestUIDAllocatorRefusesAtWrapAround(t *testing.T) {
	a := testAllocator(t, 2000, 2002)

	plan, err := a.allocate("target:22", census(2001))
	if err != nil {
		t.Fatalf("allocate below the top of the range: %v", err)
	}
	if plan.uid != 2002 {
		t.Fatalf("allocated uid %d, want the last uid in the range, 2002", plan.uid)
	}

	// Nothing is in use at all now, so 2000, 2001 and 2002 are every one of them
	// free. The mark says all three have been handed out.
	_, err = a.allocate("target:22", census(2002))
	if !errors.Is(err, ErrUIDUnavailable) {
		t.Fatalf("allocate past the top of the range = %v, want ErrUIDUnavailable", err)
	}
	if !strings.Contains(err.Error(), "does not wrap") {
		t.Errorf("the refusal reads %q; it must say the range does not wrap, because that is the operator's fix", err)
	}
}

// TestUIDAllocatorWarnsBeforeItRefuses covers the other half of the wrap
// decision. A refusal is a target-wide outage for this method, and one nobody
// was warned about would be indefensible: from nine tenths of the range on,
// every allocation is flagged so that raising uid_max is still a cheap change.
func TestUIDAllocatorWarnsBeforeItRefuses(t *testing.T) {
	a := testAllocator(t, 1000, 1999)

	plan, err := a.allocate("target:22", census(1800))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if plan.pressured {
		t.Errorf("uid %d of 1000-1999 reported pressure; four fifths of a range is not a warning", plan.uid)
	}
	if plan.remaining != 1999-1801 {
		t.Errorf("remaining = %d, want %d", plan.remaining, 1999-1801)
	}

	plan, err = a.allocate("target:22", census(1950))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if !plan.pressured {
		t.Errorf("uid %d of 1000-1999 reported no pressure; the refusal must not be the first anyone hears of it", plan.uid)
	}
}

// TestUIDAllocatorRefusesWithoutACensus is the fail-closed rule (prompt 0027,
// §2). A target this proxy could not read is not a target with an empty range:
// assuming that is precisely how a fresh account lands on a departed one's uid.
func TestUIDAllocatorRefusesWithoutACensus(t *testing.T) {
	a := testAllocator(t, 2000, 2999)
	if _, err := a.allocate("target:22", uidCensus{inUse: map[int]bool{}}); !errors.Is(err, ErrUIDUnavailable) {
		t.Fatalf("allocate with no census = %v, want ErrUIDUnavailable", err)
	}
}

// TestUIDAllocatorSkipsWhatIsInUse covers a uid inside the range that something
// other than an ephemeral account holds — another proxy's session, or a local
// account an operator put there. It is not available, whatever its name.
func TestUIDAllocatorSkipsWhatIsInUse(t *testing.T) {
	a := testAllocator(t, 2000, 2999)
	plan, err := a.allocate("target:22", census(2000, 2001, 2002))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if plan.uid != 2003 {
		t.Errorf("allocated uid %d, want 2003 — 2001 and 2002 are held", plan.uid)
	}
	for _, uid := range plan.candidates {
		if uid <= 2002 {
			t.Errorf("candidates = %v, want nothing at or below the held uid 2002", plan.candidates)
			break
		}
	}
}

// TestUIDAllocatorDoesNotRepeatWithinTheProcess is why the allocator holds state
// at all. Two sessions provisioning on one target take their censuses
// independently, and a target's answer cannot mention an account that does not
// exist yet — so without this the two would be handed the same uid.
func TestUIDAllocatorDoesNotRepeatWithinTheProcess(t *testing.T) {
	a := testAllocator(t, 2000, 2999)
	first, err := a.allocate("target:22", census(0))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	second, err := a.allocate("target:22", census(0))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if first.uid == second.uid {
		t.Fatalf("two allocations on one target both got uid %d", first.uid)
	}

	// A different target is a different range: they share no account database,
	// so the second target starts at the bottom.
	other, err := a.allocate("other:22", census(0))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if other.uid != 2000 {
		t.Errorf("a second target allocated %d, want the bottom of its own range, 2000", other.uid)
	}
}

// TestUIDAllocatorObservesWhatTheTargetActuallyGave covers the account the
// target did not allocate: one adopted from a crashed session keeps the uid it
// already had, and a lost race lands on a fallback candidate. Either way the
// next allocation has to be above what happened, not above what was asked for.
func TestUIDAllocatorObservesWhatTheTargetActuallyGave(t *testing.T) {
	a := testAllocator(t, 2000, 2999)
	if _, err := a.allocate("target:22", census(0)); err != nil {
		t.Fatalf("allocate: %v", err)
	}
	a.observe("target:22", 2500)

	plan, err := a.allocate("target:22", census(0))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if plan.uid != 2501 {
		t.Errorf("allocated uid %d after observing 2500, want 2501", plan.uid)
	}
}

// TestUIDAllocatorRejectsAnUnusableRange keeps two misconfigurations out of a
// running proxy: a range reaching into the system uids, which would give an
// ephemeral session a service account's numeric identity, and an inverted one,
// which has no uids in it at all.
func TestUIDAllocatorRejectsAnUnusableRange(t *testing.T) {
	for _, tc := range []struct {
		name     string
		min, max int
	}{
		{"into the system range", 500, 2000},
		{"inverted", 3000, 2000},
		{"empty", 2000, 2000},
		{"above a positive int32", 2000, 1 << 31},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newUIDAllocator(tc.min, tc.max); err == nil {
				t.Fatalf("newUIDAllocator(%d, %d) was accepted", tc.min, tc.max)
			}
		})
	}
	a, err := newUIDAllocator(0, 0)
	if err != nil {
		t.Fatalf("newUIDAllocator(0, 0): %v", err)
	}
	if a.min != DefaultUIDMin || a.max != DefaultUIDMax {
		t.Errorf("an unset range = %d-%d, want the defaults %d-%d", a.min, a.max, DefaultUIDMin, DefaultUIDMax)
	}
}

// TestParseUIDCensusReadsTheDiscoveryOutput covers the parse against the shape
// discoverScript really prints, including the lines it must ignore: the reaper's
// own account, residue and clock lines share the stream.
func TestParseUIDCensusReadsTheDiscoveryOutput(t *testing.T) {
	out := strings.Join([]string{
		"now\t1700000000",
		"uid\t2000004",
		"uid\t1000", // outside the range: another account entirely
		"uid\t2000009",
		"hl-148d-alice-abcd1234\t1700000000\t/home/hl-148d-alice-abcd1234",
		"residue\thl-148d-bob-11112222\trule",
		"uidmark\t2000012",
	}, "\n")

	c := parseUIDCensus([]byte(out), 2000000, 2999999)
	if !c.read {
		t.Fatal("the census reads as unread, which would refuse every session on this target")
	}
	if c.watermark != 2000012 {
		t.Errorf("watermark = %d, want 2000012", c.watermark)
	}
	if !c.inUse[2000004] || !c.inUse[2000009] {
		t.Errorf("in-use = %v, want both in-range uids", c.inUse)
	}
	if c.inUse[1000] {
		t.Error("a uid outside the range was counted as in use")
	}
	if len(c.inUse) != 2 {
		t.Errorf("in-use = %v, want exactly the two in-range uids", c.inUse)
	}
}

// TestParseProvisionedUIDFailsClosed covers the other side of the same stream:
// the provisioning script has to report the uid the account ended up with, and
// output that does not is a failure rather than a zero. A record without the uid
// is a record whose join key back to the target is a deleted name (PLAN §5.1).
func TestParseProvisionedUIDFailsClosed(t *testing.T) {
	uid, err := parseProvisionedUID([]byte("uid\t2000004\n"))
	if err != nil {
		t.Fatalf("parseProvisionedUID: %v", err)
	}
	if uid != 2000004 {
		t.Errorf("uid = %d, want 2000004", uid)
	}
	if _, err := parseProvisionedUID([]byte("something else\n")); !errors.Is(err, ErrUIDUnavailable) {
		t.Fatalf("parseProvisionedUID with no uid line = %v, want ErrUIDUnavailable", err)
	}
}
