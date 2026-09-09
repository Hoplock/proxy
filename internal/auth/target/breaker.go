// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Defaults for the rejection breaker. They are deliberately unadventurous: the
// threshold is high enough that a single stale session or a race with a key
// rotation does not withhold a credential, and the two durations are long
// enough that a wrong credential stops being retried for a while and short
// enough that a fixed one is back in service without an operator restarting
// anything.
const (
	DefaultRejectionThreshold = 5
	DefaultRejectionWindow    = 5 * time.Minute
	DefaultRejectionCooldown  = 5 * time.Minute
)

// ErrCredentialWithheld is what a session gets while a credential's breaker is
// open: the proxy is not attempting the target with it at present.
//
// It is separate from every other target-leg failure because the operator's
// answer is different. Nothing is unreachable and nothing was denied — the
// proxy has stopped offering a credential that was refused over and over, and
// what fixes it is the credential.
var ErrCredentialWithheld = errors.New("auth/target: the proxy is not attempting this credential after repeated rejections")

// RejectionKey identifies the credential a rejection is scored against.
//
// The three fields are the whole design decision, so they are worth stating
// rather than reading off: a rejection is a fact about a CREDENTIAL on a
// TARGET, and about nothing else. It is never keyed on the user, the route, the
// permission set, or anything else derived from the authenticated subject — a
// wrong credential is wrong for everybody, and a right one has to keep working
// for everybody while another one is failing. Keying on the subject would also
// hand any user who can reach a target a way to withhold it from the next user,
// which is a denial of service with a login attached.
type RejectionKey struct {
	// Target is the "host:port" the proxy dials.
	Target string
	// Method is the credential method that produced the credential.
	Method string
	// Handle is the opaque name of the credential itself: a brokered route's
	// credential_ref, or the fingerprint of the management key an ephemeral
	// route provisions with. NEVER material — this value reaches audit records
	// and log lines.
	Handle string
}

// String renders the key for a log line. Every part of it is a handle.
func (k RejectionKey) String() string {
	return fmt.Sprintf("%s via %s/%s", k.Target, k.Method, k.Handle)
}

// known reports whether the key names a credential the breaker can score. A
// method that cannot name the credential it will dial with gets no containment
// rather than containment keyed on something that does not identify it.
func (k RejectionKey) known() bool {
	return k.Target != "" && k.Method != "" && k.Handle != ""
}

// RejectionState is what the breaker knows about one credential, as of the call
// that returned it. It is the audit half: every field belongs on the record
// that says a credential was refused.
type RejectionState struct {
	// Consecutive is how many rejections in a row this credential has had
	// inside the window.
	Consecutive int
	// Open is true while the proxy is withholding the credential.
	Open bool
	// Until is when an open breaker next allows an attempt. Zero when closed.
	Until time.Time
}

// Name renders the state for a record. Two values, because an operator reading
// an audit trail is asking exactly one question of this field: are we still
// trying?
func (s RejectionState) Name() string {
	if s.Open {
		return "open"
	}
	return "closed"
}

// WithheldError is ErrCredentialWithheld with the facts a record needs.
type WithheldError struct {
	Key   RejectionKey
	State RejectionState
}

func (e *WithheldError) Error() string {
	return fmt.Sprintf("%s: %s (%d consecutive rejections, next attempt after %s)",
		ErrCredentialWithheld, e.Key, e.State.Consecutive, e.State.Until.UTC().Format(time.RFC3339))
}

// Unwrap keeps the sentinel reachable, so the engine classifies this without
// knowing the type.
func (e *WithheldError) Unwrap() error { return ErrCredentialWithheld }

// RejectionPolicy is how much rejection a credential gets before the proxy
// stops offering it.
type RejectionPolicy struct {
	// Threshold is the number of consecutive rejections inside Window that
	// opens the breaker. Zero — or negative — disables containment entirely,
	// which is the escape hatch for an operator who would rather have every
	// session try.
	Threshold int
	// Window bounds how long a run of rejections counts as consecutive. Zero
	// means DefaultRejectionWindow.
	Window time.Duration
	// Cooldown is how long an open breaker withholds the credential. Zero means
	// DefaultRejectionCooldown.
	Cooldown time.Duration
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// RejectionBreaker bounds how often a refused proxy→target credential is
// retried (prompt 0025).
//
// Why this is self-protection and not policy, which is the first thing a
// reviewer asks about it: D2 says the proxy originates no policy, and the test
// that already licenses `chain.max_hops` and `control.cache.max_ttl` licenses
// this. It can only ever make the proxy attempt LESS than Hoplock Control
// authorised, never more; it never turns a denial into an allow; and it never
// widens, reorders, or substitutes a credential the server chose. A session it
// stops is an OUTAGE — the proxy's own problem, which no user can fix with
// different credentials — and never a denial (PLAN §4.3).
//
// What it is actually protecting against is a property of the deployment
// model rather than of any one target. A decrypting proxy is a SINGLE SOURCE
// ADDRESS to every target it fronts, so a target's per-source abuse defences
// (OpenSSH ≥ 9.8's PerSourcePenalties, on by default) score a refused
// credential against the proxy rather than against the user who triggered it.
// One route's stale key, retried at whatever rate users arrive, therefore ends
// with the target refusing to answer the proxy at all — and every other user of
// that target loses a working session to a credential that was never theirs.
//
// A nil *RejectionBreaker is a working disabled breaker, so a caller never has
// to check.
type RejectionBreaker struct {
	threshold int
	window    time.Duration
	cooldown  time.Duration
	now       func() time.Time

	mu      sync.Mutex
	entries map[RejectionKey]*rejectionEntry
}

// rejectionEntry is one credential's run of rejections.
type rejectionEntry struct {
	// consecutive counts the rejections in the current run, and first is when
	// that run started — the window is measured from it, so a slow trickle of
	// rejections spread over hours never accumulates into an open breaker.
	consecutive int
	first       time.Time
	// last is when anything happened to this entry, and exists only so idle
	// entries can be pruned.
	last time.Time
	// openUntil is when an open breaker next allows an attempt.
	openUntil time.Time
}

// NewRejectionBreaker returns a breaker for the policy, or nil when the policy
// disables containment.
//
// Returning nil rather than an inert value is deliberate: "this proxy is not
// containing rejections" is then visible at the one place that decides it,
// instead of being a threshold nobody notices is unreachable.
func NewRejectionBreaker(p RejectionPolicy) *RejectionBreaker {
	if p.Threshold <= 0 {
		return nil
	}
	b := &RejectionBreaker{
		threshold: p.Threshold,
		window:    p.Window,
		cooldown:  p.Cooldown,
		now:       p.Now,
		entries:   map[RejectionKey]*rejectionEntry{},
	}
	if b.window <= 0 {
		b.window = DefaultRejectionWindow
	}
	if b.cooldown <= 0 {
		b.cooldown = DefaultRejectionCooldown
	}
	if b.now == nil {
		b.now = time.Now
	}
	return b
}

// Check reports whether the credential may be attempted.
//
// A non-nil error is a *WithheldError wrapping ErrCredentialWithheld, and the
// caller must not open a connection to the target: not attempting the TCP
// connection at all is the entire point, because the connection is what the
// target's per-source defences count.
func (b *RejectionBreaker) Check(key RejectionKey) error {
	if b == nil || !key.known() {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	entry := b.entries[key]
	if entry == nil {
		return nil
	}
	if entry.openUntil.IsZero() {
		// Counting, but not open: the credential has been refused before and
		// has not reached the threshold. The run is what the entry is for, so
		// it stays — Check must never reset the count it is reading.
		return nil
	}
	now := b.now()
	if !now.Before(entry.openUntil) {
		// The cooldown has run out. The entry is dropped rather than half-reset
		// so the next attempt is judged on its own: a credential someone has
		// since fixed must not be one rejection away from being withheld again.
		delete(b.entries, key)
		return nil
	}
	return &WithheldError{Key: key, State: RejectionState{
		Consecutive: entry.consecutive,
		Open:        true,
		Until:       entry.openUntil,
	}}
}

// Reject scores one refused credential and returns the state that follows it.
func (b *RejectionBreaker) Reject(key RejectionKey) RejectionState {
	if b == nil || !key.known() {
		return RejectionState{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	b.prune(now)

	entry := b.entries[key]
	if entry == nil || now.Sub(entry.first) > b.window {
		// Either the first rejection this credential has had, or the first
		// outside the run the last one belonged to. Both start a new run.
		entry = &rejectionEntry{first: now}
		b.entries[key] = entry
	}
	entry.consecutive++
	entry.last = now
	if entry.consecutive >= b.threshold {
		entry.openUntil = now.Add(b.cooldown)
	}
	return RejectionState{
		Consecutive: entry.consecutive,
		Open:        !entry.openUntil.IsZero(),
		Until:       entry.openUntil,
	}
}

// Succeed clears everything known about a credential.
//
// One success closes the breaker and resets the count, with no partial credit
// and no decay: the run this counts is CONSECUTIVE rejections, and a credential
// that just worked has had none.
func (b *RejectionBreaker) Succeed(key RejectionKey) {
	if b == nil || !key.known() {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.entries, key)
}

// State reports what the breaker knows about a credential without changing it.
func (b *RejectionBreaker) State(key RejectionKey) RejectionState {
	if b == nil || !key.known() {
		return RejectionState{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	entry := b.entries[key]
	if entry == nil {
		return RejectionState{}
	}
	open := !entry.openUntil.IsZero() && b.now().Before(entry.openUntil)
	state := RejectionState{Consecutive: entry.consecutive, Open: open}
	if open {
		state.Until = entry.openUntil
	}
	return state
}

// prune drops entries nothing could still be counting.
//
// The map is bounded by the estate — one entry per (target, method, credential)
// that has ever been refused — and only ever grows on a rejection, which is
// rare by construction. Sweeping it on each rejection is therefore cheap, and
// it is the one moment the breaker is certainly holding the lock anyway.
func (b *RejectionBreaker) prune(now time.Time) {
	horizon := b.window + b.cooldown
	for key, entry := range b.entries {
		if now.Sub(entry.last) > horizon && (entry.openUntil.IsZero() || !now.Before(entry.openUntil)) {
			delete(b.entries, key)
		}
	}
}
