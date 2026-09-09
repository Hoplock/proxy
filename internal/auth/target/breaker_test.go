// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/config"
)

// clock is a hand-wound clock, so the breaker's windows are asserted rather
// than waited for.
type clock struct{ at time.Time }

func (c *clock) now() time.Time          { return c.at }
func (c *clock) advance(d time.Duration) { c.at = c.at.Add(d) }

func newTestBreaker(threshold int, window, cooldown time.Duration) (*RejectionBreaker, *clock) {
	c := &clock{at: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
	return NewRejectionBreaker(RejectionPolicy{
		Threshold: threshold,
		Window:    window,
		Cooldown:  cooldown,
		Now:       c.now,
	}), c
}

func brokeredKey(target, ref string) RejectionKey {
	return RejectionKey{Target: target, Method: MethodBrokeredKey, Handle: ref}
}

func TestBreakerOpensAtTheThreshold(t *testing.T) {
	b, _ := newTestBreaker(3, time.Minute, time.Minute)
	key := brokeredKey("target:22", "stale-fleet")

	for i := 1; i < 3; i++ {
		state := b.Reject(key)
		if state.Open {
			t.Fatalf("rejection %d opened the breaker; the threshold is 3", i)
		}
		if state.Consecutive != i {
			t.Fatalf("rejection %d reported %d consecutive", i, state.Consecutive)
		}
		if err := b.Check(key); err != nil {
			t.Fatalf("the credential was withheld after %d rejections: %v", i, err)
		}
	}

	state := b.Reject(key)
	if !state.Open || state.Consecutive != 3 {
		t.Fatalf("the third rejection produced %+v, want an open breaker at three", state)
	}

	err := b.Check(key)
	if !errors.Is(err, ErrCredentialWithheld) {
		t.Fatalf("Check returned %v, want ErrCredentialWithheld", err)
	}
	var withheld *WithheldError
	if !errors.As(err, &withheld) {
		t.Fatalf("Check returned %T, want a *WithheldError carrying the facts a record needs", err)
	}
	if withheld.Key != key || withheld.State.Consecutive != 3 || !withheld.State.Open {
		t.Errorf("the withheld error carries %+v for %v", withheld.State, withheld.Key)
	}
	// Nothing about the error may be material. The handle is a reference, and
	// the target and method are already in every other record.
	if msg := withheld.Error(); !strings.Contains(msg, "stale-fleet") || !strings.Contains(msg, "target:22") {
		t.Errorf("the withheld error does not name its own credential handle: %s", msg)
	}
}

// TestBreakerIsKeyedOnTheCredentialAndNotOnTheRoute is the assertion the whole
// design turns on: a wrong credential is wrong for everybody, and a right one
// must keep working while another is failing.
func TestBreakerIsKeyedOnTheCredentialAndNotOnTheRoute(t *testing.T) {
	b, _ := newTestBreaker(2, time.Minute, time.Minute)
	bad := brokeredKey("target:22", "stale-fleet")
	good := brokeredKey("target:22", "appliance-fleet")
	elsewhere := brokeredKey("other:22", "stale-fleet")
	otherMethod := RejectionKey{Target: "target:22", Method: MethodEphemeralUser, Handle: "stale-fleet"}

	b.Reject(bad)
	b.Reject(bad)
	if err := b.Check(bad); err == nil {
		t.Fatal("the refused credential is still being attempted")
	}
	for _, key := range []RejectionKey{good, elsewhere, otherMethod} {
		if err := b.Check(key); err != nil {
			t.Errorf("%v was withheld by another credential's failures: %v", key, err)
		}
	}
}

func TestBreakerSuccessResetsTheRun(t *testing.T) {
	b, _ := newTestBreaker(3, time.Minute, time.Minute)
	key := brokeredKey("target:22", "stale-fleet")

	b.Reject(key)
	b.Reject(key)
	b.Succeed(key)
	if state := b.State(key); state.Consecutive != 0 || state.Open {
		t.Fatalf("a success left %+v behind", state)
	}
	// Two more rejections must not reach a threshold of three.
	b.Reject(key)
	if state := b.Reject(key); state.Open || state.Consecutive != 2 {
		t.Fatalf("after a success the run continued: %+v", state)
	}
}

// TestBreakerSuccessClosesAnOpenBreaker covers the case an operator hits: the
// credential is fixed, the cooldown has not run out, and the next attempt that
// gets through must not be one rejection away from being withheld again.
func TestBreakerSuccessClosesAnOpenBreaker(t *testing.T) {
	b, c := newTestBreaker(2, time.Minute, 10*time.Minute)
	key := brokeredKey("target:22", "stale-fleet")

	b.Reject(key)
	b.Reject(key)
	if err := b.Check(key); err == nil {
		t.Fatal("the breaker did not open")
	}
	c.advance(11 * time.Minute)
	if err := b.Check(key); err != nil {
		t.Fatalf("the cooldown did not run out: %v", err)
	}
	b.Succeed(key)
	if state := b.Reject(key); state.Open {
		t.Fatalf("one rejection after a success reopened the breaker: %+v", state)
	}
}

func TestBreakerWindowBoundsTheRun(t *testing.T) {
	b, c := newTestBreaker(3, time.Minute, time.Minute)
	key := brokeredKey("target:22", "stale-fleet")

	b.Reject(key)
	b.Reject(key)
	// The next rejection falls outside the window the run started in, so it
	// starts a run of its own. A slow trickle of rejections spread over hours
	// is not the failure this contains.
	c.advance(2 * time.Minute)
	if state := b.Reject(key); state.Open || state.Consecutive != 1 {
		t.Fatalf("a rejection outside the window continued the run: %+v", state)
	}
}

func TestBreakerCooldownExpires(t *testing.T) {
	b, c := newTestBreaker(2, time.Minute, 5*time.Minute)
	key := brokeredKey("target:22", "stale-fleet")

	b.Reject(key)
	b.Reject(key)
	if err := b.Check(key); err == nil {
		t.Fatal("the breaker did not open")
	}
	c.advance(4 * time.Minute)
	if err := b.Check(key); err == nil {
		t.Fatal("the breaker closed before its cooldown ran out")
	}
	c.advance(2 * time.Minute)
	if err := b.Check(key); err != nil {
		t.Fatalf("the breaker stayed open past its cooldown: %v", err)
	}
	// The entry is judged fresh afterwards: one rejection must not re-open a
	// breaker whose cooldown has already been served.
	if state := b.Reject(key); state.Open {
		t.Errorf("the first rejection after a cooldown re-opened the breaker: %+v", state)
	}
}

// TestBreakerDisabledAndUnknownKeys covers the two ways containment is absent:
// the operator turned it off, and the method cannot name its credential.
func TestBreakerDisabledAndUnknownKeys(t *testing.T) {
	if b := NewRejectionBreaker(RejectionPolicy{Threshold: 0}); b != nil {
		t.Error("threshold 0 built a breaker; it is the escape hatch that disables containment")
	}

	var off *RejectionBreaker // the disabled breaker every caller may hold
	key := brokeredKey("target:22", "stale-fleet")
	for i := 0; i < 10; i++ {
		off.Reject(key)
	}
	if err := off.Check(key); err != nil {
		t.Errorf("a disabled breaker withheld a credential: %v", err)
	}
	off.Succeed(key)

	on, _ := newTestBreaker(1, time.Minute, time.Minute)
	partial := []RejectionKey{
		{Method: MethodBrokeredKey, Handle: "ref"},
		{Target: "target:22", Handle: "ref"},
		{Target: "target:22", Method: MethodBrokeredKey},
	}
	for _, k := range partial {
		if state := on.Reject(k); state.Consecutive != 0 {
			t.Errorf("%+v was scored; a key that does not identify a credential must not be", k)
		}
		if err := on.Check(k); err != nil {
			t.Errorf("%+v was withheld: %v", k, err)
		}
	}
}

// TestBreakerDefaults holds the documented defaults to the numbers
// config.example.yaml states.
func TestBreakerDefaults(t *testing.T) {
	b := NewRejectionBreaker(RejectionPolicy{Threshold: DefaultRejectionThreshold})
	if b.window != DefaultRejectionWindow || b.cooldown != DefaultRejectionCooldown {
		t.Errorf("zero durations resolved to %s/%s, want %s/%s",
			b.window, b.cooldown, DefaultRejectionWindow, DefaultRejectionCooldown)
	}
}

// TestBreakerPrunesIdleEntries keeps the map bounded by the estate rather than
// by how long the proxy has been running.
func TestBreakerPrunesIdleEntries(t *testing.T) {
	b, c := newTestBreaker(3, time.Minute, time.Minute)
	old := brokeredKey("target:22", "long-gone")
	b.Reject(old)

	c.advance(time.Hour)
	b.Reject(brokeredKey("target:22", "current"))

	b.mu.Lock()
	_, still := b.entries[old]
	b.mu.Unlock()
	if still {
		t.Error("an entry nothing could still be counting was kept")
	}
}

// TestRejectionPolicyFromConfig covers the translation the proxy actually runs
// on: an absent threshold takes the documented default, an explicit 0 disables
// containment, and the two durations pass straight through.
func TestRejectionPolicyFromConfig(t *testing.T) {
	if got := rejectionPolicy(config.RejectionAuth{}); got.Threshold != DefaultRejectionThreshold {
		t.Errorf("an absent threshold resolved to %d, want the default %d", got.Threshold, DefaultRejectionThreshold)
	}

	off := 0
	if got := rejectionPolicy(config.RejectionAuth{Threshold: &off}); got.Threshold != 0 {
		t.Errorf("an explicit 0 resolved to %d; it is the escape hatch that disables containment", got.Threshold)
	}
	if NewRejectionBreaker(rejectionPolicy(config.RejectionAuth{Threshold: &off})) != nil {
		t.Error("an explicit 0 still built a breaker")
	}

	three := 3
	got := rejectionPolicy(config.RejectionAuth{Threshold: &three, Window: time.Minute, Cooldown: 2 * time.Minute})
	if got.Threshold != 3 || got.Window != time.Minute || got.Cooldown != 2*time.Minute {
		t.Errorf("rejectionPolicy = %+v, want 3/1m/2m", got)
	}
}
