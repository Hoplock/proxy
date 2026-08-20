// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Reaper defaults.
const (
	// DefaultReaperInterval is how often the periodic sweep runs.
	DefaultReaperInterval = 10 * time.Minute
	// DefaultReaperGrace is how old an untracked ephemeral account must be
	// before a sweep removes it.
	//
	// It is not tidiness tuning. It is the window in which an account exists on
	// the target but this process does not yet know it does — between useradd
	// and the moment the session is tracked, and, more importantly, for a
	// session belonging to a DIFFERENT process using the same proxy id. Too
	// short and a sweep kills a live session; too long and an orphan holds a
	// login open. Minutes, not seconds and not hours.
	DefaultReaperGrace = 30 * time.Minute
	// sweepCooldown bounds how often one target is swept on the provisioning
	// path, so a busy target is not swept once per session.
	sweepCooldown = time.Minute
	// sweepTimeout bounds one target's sweep.
	sweepTimeout = 2 * time.Minute
)

// Lifecycle is implemented by target authenticators with background work.
// cmd/proxy starts and stops it; today the ephemeral method's orphan reaper is
// the only implementation.
type Lifecycle interface {
	// Start begins the background work. It returns immediately.
	Start(ctx context.Context)
	// Close ends it.
	Close() error
}

// Reaper removes ephemeral accounts that no live session owns (D6, PLAN §5.1).
//
// Guaranteed teardown has two halves. The first is the session's own: teardown
// runs on close, error, panic, and signal, and the engine's session.close is
// what makes that true. The second is this, and it exists because the first
// half assumes the process is alive to run it. A SIGKILL, an OOM kill, a
// hypervisor that vanishes — each one leaves an account with a working key on a
// production host and nothing left running that knows about it.
//
// It finds them by NAME (see principal.go): every account this proxy creates
// starts with a prefix derived from the proxy's id, and nothing else on the
// target does. That is why the sweep can be a default-remove rule over a listing
// instead of a registry the crash already destroyed.
//
// Two rules keep it from removing something it should not:
//
//   - an account tracked as live is never swept, however old it is, so a
//     week-long session is safe;
//   - an untracked account younger than the grace period is never swept, so a
//     session that is mid-provision — or one belonging to another process
//     sharing this proxy id — is safe.
//
// Sweeps happen at three moments: after each successful provisioning on that
// target (rate-limited, and the only way orphans from a crashed PROCESS are
// ever found, since a restarted proxy has no record of which targets it owes
// cleanup on), on the periodic tick, and whenever a test calls Sweep directly.
type Reaper struct {
	auth     *EphemeralAuthenticator
	interval time.Duration
	grace    time.Duration

	mu    sync.Mutex
	live  map[string]map[string]bool
	seen  map[string]*seenTarget
	stop  chan struct{}
	start sync.Once
	shut  sync.Once

	wg sync.WaitGroup
}

// seenTarget is a target this proxy has provisioned on, and the host key it
// presented when it did.
type seenTarget struct {
	tgt       Target
	hostKey   ssh.PublicKey
	lastSweep time.Time
}

// orphan is one candidate account read off a target.
type orphan struct {
	principal string
	home      string
	age       time.Duration
}

func newReaper(auth *EphemeralAuthenticator, interval, grace time.Duration) *Reaper {
	r := &Reaper{
		auth:     auth,
		interval: interval,
		grace:    grace,
		live:     map[string]map[string]bool{},
		seen:     map[string]*seenTarget{},
		stop:     make(chan struct{}),
	}
	if r.interval == 0 {
		r.interval = DefaultReaperInterval
	}
	if r.grace <= 0 {
		r.grace = DefaultReaperGrace
	}
	return r
}

// Start runs the periodic sweep until ctx is done or Close is called.
func (r *Reaper) Start(ctx context.Context) {
	if r.interval < 0 {
		r.auth.logf("auth/target: ephemeral-user orphan reaper is disabled")
		return
	}
	r.start.Do(func() {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.loop(ctx)
		}()
	})
}

// Close stops the periodic sweep and waits for it.
func (r *Reaper) Close() error {
	r.shut.Do(func() { close(r.stop) })
	r.wg.Wait()
	return nil
}

func (r *Reaper) loop(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stop:
			return
		case <-ticker.C:
			r.sweepAll(ctx)
		}
	}
}

// sweepAll sweeps every target this proxy has provisioned on.
func (r *Reaper) sweepAll(ctx context.Context) {
	for _, tgt := range r.targets() {
		select {
		case <-ctx.Done():
			return
		case <-r.stop:
			return
		default:
		}
		r.sweepOnce(ctx, tgt)
	}
}

// sweepInBackground sweeps a target off the session's critical path, at most
// once per cooldown.
func (r *Reaper) sweepInBackground(tgt Target) {
	if r.interval < 0 || !r.claimSweep(tgt) {
		return
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		// Deliberately detached from the session's context: the session that
		// triggered this sweep may end a millisecond later, and the orphans it
		// found belong to no session at all.
		ctx, cancel := context.WithTimeout(context.Background(), sweepTimeout)
		defer cancel()
		r.sweepOnce(ctx, tgt)
	}()
}

func (r *Reaper) sweepOnce(ctx context.Context, tgt Target) {
	ctx, cancel := context.WithTimeout(ctx, sweepTimeout)
	defer cancel()
	removed, err := r.Sweep(ctx, tgt)
	if err != nil {
		r.auth.logf("auth/target: ephemeral-user orphan sweep of %s failed: %v", tgt, err)
	}
	if len(removed) > 0 {
		r.auth.logf("auth/target: ephemeral-user orphan sweep of %s removed %d account(s): %s",
			tgt, len(removed), strings.Join(removed, ", "))
	}
}

// Sweep removes every orphaned ephemeral account on one target and returns
// what it removed.
//
// It is exported because it is the only way to assert the crash path in a test,
// and a cleanup guarantee nobody can test is a cleanup guarantee nobody has.
func (r *Reaper) Sweep(ctx context.Context, tgt Target) ([]string, error) {
	tgt = r.pinned(tgt)

	script, err := r.auth.discoverScript()
	if err != nil {
		return nil, err
	}
	admin, err := r.auth.dialer.Dial(ctx, tgt)
	if err != nil {
		return nil, err
	}
	defer func() { _ = admin.Close() }()

	out, err := admin.Run(ctx, script)
	if err != nil {
		return nil, stageErr("sweep", err)
	}

	var removed []string
	var failures []string
	for _, cand := range r.parseDiscovery(out) {
		if r.isLive(tgt, cand.principal) || cand.age < r.grace {
			continue
		}
		script, err := r.auth.teardownScript(cand.principal, cand.home)
		if err != nil {
			failures = append(failures, cand.principal)
			continue
		}
		if _, err := admin.Run(ctx, script); err != nil {
			r.auth.logf("auth/target: ephemeral-user could not remove orphan %s on %s: %v",
				cand.principal, tgt, err)
			failures = append(failures, cand.principal)
			continue
		}
		removed = append(removed, cand.principal)
	}
	if len(failures) > 0 {
		// Reported, not retried here: the next sweep tries again, and a target
		// that cannot delete accounts needs an operator rather than a loop.
		return removed, fmt.Errorf("auth/target: %d orphaned account(s) could not be removed: %s",
			len(failures), strings.Join(failures, ", "))
	}
	return removed, nil
}

// parseDiscovery reads the discovery script's output.
//
// Ages are measured against the TARGET's clock, which the script reports on its
// first line, because the proxy's clock and the target's are not the same
// clock. Skew of a few minutes between them is ordinary, and a grace period
// measured across it would either protect nothing or protect forever.
func (r *Reaper) parseDiscovery(out []byte) []orphan {
	now := r.auth.now().Unix()
	var orphans []orphan
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(fields) < 2 {
			continue
		}
		if fields[0] == "now" {
			if ts, err := strconv.ParseInt(fields[1], 10, 64); err == nil && ts > 0 {
				now = ts
			}
			continue
		}
		if !strings.HasPrefix(fields[0], r.auth.prefix) {
			continue
		}
		if err := validatePrincipal(fields[0]); err != nil {
			// A name that cannot be validated is a name that must not be
			// interpolated into a teardown script running as root.
			r.auth.logf("auth/target: ephemeral-user ignoring unusable account name %q: %v", fields[0], err)
			continue
		}
		created, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		home := r.auth.homeFor(fields[0])
		if len(fields) > 2 && validatePath(fields[2]) == nil {
			home = fields[2]
		}
		age := time.Duration(now-created) * time.Second
		orphans = append(orphans, orphan{principal: fields[0], home: home, age: age})
	}
	return orphans
}

// observe records a target and the host key it presented, so later sweeps can
// reach it without asking the policy service to re-approve a key it already
// approved.
func (r *Reaper) observe(tgt Target, hostKey ssh.PublicKey) {
	key := tgt.Addr()
	bare := Target{Host: tgt.Host, Port: tgt.Port}

	r.mu.Lock()
	defer r.mu.Unlock()
	if seen, ok := r.seen[key]; ok {
		if hostKey != nil {
			seen.hostKey = hostKey
		}
		return
	}
	r.seen[key] = &seenTarget{tgt: bare, hostKey: hostKey}
}

// track marks an account as belonging to a live session.
func (r *Reaper) track(tgt Target, principal string) {
	key := tgt.Addr()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.live[key] == nil {
		r.live[key] = map[string]bool{}
	}
	r.live[key][principal] = true
}

// release forgets an account, whether or not its teardown succeeded.
//
// A failed teardown deliberately releases too: the account then reads as an
// untracked orphan, which is exactly what it is, and the periodic sweep retries
// it once it is past the grace period. Keeping it "live" instead would protect
// the one thing that most needs removing.
func (r *Reaper) release(tgt Target, principal string) {
	key := tgt.Addr()
	r.mu.Lock()
	defer r.mu.Unlock()
	if live, ok := r.live[key]; ok {
		delete(live, principal)
		if len(live) == 0 {
			delete(r.live, key)
		}
	}
}

func (r *Reaper) isLive(tgt Target, principal string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.live[tgt.Addr()][principal]
}

// pinned returns tgt with the host key remembered for it, if any.
func (r *Reaper) pinned(tgt Target) Target {
	r.mu.Lock()
	defer r.mu.Unlock()
	if seen, ok := r.seen[tgt.Addr()]; ok && seen.hostKey != nil {
		return pin(tgt, seen.hostKey)
	}
	return tgt
}

// targets is every target seen this process lifetime, pinned to its host key.
func (r *Reaper) targets() []Target {
	r.mu.Lock()
	defer r.mu.Unlock()
	targets := make([]Target, 0, len(r.seen))
	for _, seen := range r.seen {
		targets = append(targets, pin(seen.tgt, seen.hostKey))
	}
	return targets
}

// claimSweep reports whether this caller may sweep the target now, and records
// that it did.
func (r *Reaper) claimSweep(tgt Target) bool {
	now := r.auth.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	seen, ok := r.seen[tgt.Addr()]
	if !ok {
		return false
	}
	if !seen.lastSweep.IsZero() && now.Sub(seen.lastSweep) < sweepCooldown {
		return false
	}
	seen.lastSweep = now
	return true
}
