// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/auth/target/device"
)

// deviceReaper removes device administrators that no live session owns
// (PLAN §5.1's reaper, extended over a driver's enumerate operation).
//
// Its guarantees are the POSIX reaper's and they are unchanged: the proxy-tag
// prefix scopes a sweep to this proxy's accounts, a live account is never swept
// however old it is, an untracked one is swept past a grace period, and the
// first successful provisioning on a device triggers a rate-limited background
// sweep of it — which is the only way a crashed PROCESS's leftovers are ever
// found, since a restarted proxy has no record of which devices it owes cleanup
// on.
//
// Two things are different here, and both are consequences of D13 rather than
// new policy.
//
// THE REAPER IS THE PRIMARY REMOVAL PATH, not a crash-recovery backstop. On
// Linux, OpenSSH's expiry-time makes the credential die whether or not this
// process is alive, and the reaper only tidies up. On a platform that cannot
// expire an account — which is every platform this repository ships a driver
// for — nothing else ever removes it. So the interval is tighter, and a sweep
// that fails is REPORTED rather than counted: a reaper that quietly fails on a
// device leaves a live privileged administrator on a firewall, and nobody finds
// out.
//
// AGE IS THIS PROCESS'S OBSERVATION, not the device's. The POSIX path reads a
// timestamp off the target and measures against the target's own clock. Most
// device platforms do not record when an administrator was created —
// device.Account.CreatedAt is zero and phase 0013 says that must be read as
// "age unknown" rather than "created at the epoch, sweep it now". So an account
// with no reported age is aged from WHEN THIS PROXY FIRST SAW IT, which means a
// restarted proxy waits one grace period before removing what it inherited.
// That is the safe direction: the alternative removes another proxy's live
// session, or its own, on the first sweep after a restart.
type deviceReaper struct {
	auth     *DeviceAccountAuthenticator
	interval time.Duration
	grace    time.Duration

	mu      sync.Mutex
	live    map[string]map[string]bool
	firstAt map[string]map[string]time.Time
	// firstResidueAt ages the objects a driver created BESIDE its accounts
	// (device.Residue), and it is a SEPARATE map from firstAt even though on
	// FortiOS the two share a name. They measure different things: firstAt
	// times an administrator from when this proxy first saw it, and a schedule
	// only becomes residue when its administrator is gone — which is often the
	// moment the same sweep removed it. Sharing one map would restart the
	// schedule's clock every time the account's entry was forgotten, and the
	// object that grants nothing would outlive the one that granted everything.
	firstResidueAt map[string]map[string]time.Time
	seen           map[string]*seenDevice
	timers         []*time.Timer
	stop           chan struct{}
	start          sync.Once
	shut           sync.Once

	wg sync.WaitGroup
}

// seenDevice is a device this proxy has provisioned on.
type seenDevice struct {
	ep        device.Endpoint
	route     *deviceRoute
	hostKey   ssh.PublicKey
	lastSweep time.Time
}

func newDeviceReaper(auth *DeviceAccountAuthenticator, interval, grace time.Duration) *deviceReaper {
	r := &deviceReaper{
		auth:           auth,
		interval:       interval,
		grace:          grace,
		live:           map[string]map[string]bool{},
		firstAt:        map[string]map[string]time.Time{},
		firstResidueAt: map[string]map[string]time.Time{},
		seen:           map[string]*seenDevice{},
		stop:           make(chan struct{}),
	}
	if r.interval == 0 {
		r.interval = DefaultDeviceReaperInterval
	}
	if r.grace <= 0 {
		r.grace = DefaultDeviceReaperGrace
	}
	return r
}

// Start runs the periodic sweep until ctx is done or Close is called.
func (r *deviceReaper) Start(ctx context.Context) {
	if r.interval < 0 {
		r.auth.logf("auth/target: ephemeral-account orphan reaper is disabled — on a platform that cannot expire an account, nothing else removes one")
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

// Close stops the sweep and any pending expiry timers, and waits for them.
func (r *deviceReaper) Close() error {
	r.shut.Do(func() { close(r.stop) })
	r.mu.Lock()
	timers := r.timers
	r.timers = nil
	r.mu.Unlock()
	for _, t := range timers {
		t.Stop()
	}
	r.wg.Wait()
	return nil
}

func (r *deviceReaper) loop(ctx context.Context) {
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

func (r *deviceReaper) sweepAll(ctx context.Context) {
	for _, d := range r.devices() {
		select {
		case <-ctx.Done():
			return
		case <-r.stop:
			return
		default:
		}
		r.sweepOnce(ctx, d.ep, d.route)
	}
}

// sweepInBackground sweeps a device off the session's critical path, at most
// once per cooldown.
func (r *deviceReaper) sweepInBackground(ep device.Endpoint, route *deviceRoute) {
	if r.interval < 0 || !r.claimSweep(ep) {
		return
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		// Detached from the session's context: the session that triggered this
		// sweep may end a millisecond later, and the orphans it finds belong to
		// no session at all.
		ctx, cancel := context.WithTimeout(context.Background(), sweepTimeout)
		defer cancel()
		r.sweepOnce(ctx, ep, route)
	}()
}

func (r *deviceReaper) sweepOnce(ctx context.Context, ep device.Endpoint, route *deviceRoute) {
	ctx, cancel := context.WithTimeout(ctx, sweepTimeout)
	defer cancel()
	removed, err := r.Sweep(ctx, ep, route)
	if err != nil {
		r.auth.logf("auth/target: ephemeral-account sweep of %s:%d failed: %v", ep.Host, ep.Port, err)
	}
	if len(removed) > 0 {
		r.auth.logf("auth/target: ephemeral-account sweep of %s:%d removed %d administrator(s): %s",
			ep.Host, ep.Port, len(removed), strings.Join(removed, ", "))
	}
}

// Sweep removes every orphaned administrator on one device and returns what it
// removed.
func (r *deviceReaper) Sweep(ctx context.Context, ep device.Endpoint, route *deviceRoute) ([]string, error) {
	ep = r.pin(ep)
	prefix := route.naming.prefix

	accounts, err := route.driver.ListAccounts(ctx, device.ListRequest{Endpoint: ep, Prefix: prefix})
	if err != nil {
		// A device that cannot be enumerated is the case D13 warns about: on a
		// platform with no expiry there is no other removal path, so this is
		// reported rather than logged and forgotten.
		r.auth.reportSweepFailure(SweepFailure{
			Target: addrOf(ep), Platform: route.platform,
			Reason: fmt.Sprintf("the device could not be enumerated: %v", err), At: r.auth.now(),
		})
		return nil, err
	}

	now := r.auth.now()
	var removed, failures []string
	for _, account := range accounts {
		if !strings.HasPrefix(account.Name, prefix) {
			// The driver was asked for a prefix; a driver that widened the
			// selection anyway must not be trusted with the consequence, which
			// is another proxy's live session.
			continue
		}
		if r.isLive(ep, account.Name) {
			continue
		}
		if !r.agedOut(ep, account, now) {
			continue
		}
		if err := route.driver.RemoveAccount(ctx, device.RemoveRequest{Endpoint: ep, Name: account.Name}); err != nil {
			failures = append(failures, account.Name)
			r.auth.reportSweepFailure(SweepFailure{
				Target: addrOf(ep), Platform: route.platform, Account: account.Name,
				Reason: err.Error(), At: now,
			})
			continue
		}
		r.forget(ep, account.Name)
		removed = append(removed, account.Name)
	}
	if len(failures) > 0 {
		// Reported, not retried here: the next sweep tries again, and a device
		// that cannot delete an administrator needs an operator rather than a
		// loop.
		return removed, fmt.Errorf("auth/target: %d orphaned administrator(s) could not be removed on %s: %s",
			len(failures), addrOf(ep), strings.Join(failures, ", "))
	}

	// The residue pass runs AFTER the account pass, in the same sweep, and the
	// order is the point: on a platform where the second object is referenced
	// by the first, an orphaned administrator removed a moment ago is what
	// makes its schedule unreferenced and therefore sweepable now rather than
	// on the next tick.
	sweptResidue, err := r.sweepResidue(ctx, ep, route)
	removed = append(removed, sweptResidue...)
	return removed, err
}

// sweepResidue removes the objects a driver created beside its accounts and no
// account references any more (device.ResidueSweeper, phase 0017).
//
// It is a SECOND LEAK CLASS and it is swept because it is one: a session that
// created a FortiGate's expiry schedule and then failed before the
// administrator existed leaves an object with this proxy's prefix on a
// customer's firewall that nothing else will ever look for. It grants access to
// nothing — which is why its failures are recorded as what they are rather than
// as an account left behind (SweepFailure.ObjectKind) — but "harmless litter
// this system cannot clean up" is not a sentence this product gets to say about
// objects it writes on other people's devices.
//
// A driver that creates no such objects does not implement the interface, and
// this returns immediately. That is the whole cost of the feature on every
// platform that does not need it.
func (r *deviceReaper) sweepResidue(ctx context.Context, ep device.Endpoint, route *deviceRoute) ([]string, error) {
	sweeper, ok := route.driver.(device.ResidueSweeper)
	if !ok {
		return nil, nil
	}
	prefix := route.naming.prefix

	residue, err := sweeper.ListResidue(ctx, device.ListRequest{Endpoint: ep, Prefix: prefix})
	if err != nil {
		r.auth.reportSweepFailure(SweepFailure{
			Target: addrOf(ep), Platform: route.platform,
			Reason: fmt.Sprintf("the device's leftover objects could not be enumerated: %v", err), At: r.auth.now(),
		})
		return nil, err
	}

	now := r.auth.now()
	var removed, failures []string
	for _, object := range residue {
		if !strings.HasPrefix(object.Name, prefix) {
			// The same distrust ListAccounts is treated with, for the same
			// reason: a driver that widened the selection it was given must not
			// be handed the consequence, which here is another proxy's object.
			continue
		}
		if r.isLive(ep, object.Name) {
			// Belt and braces over the driver's own "no account references it".
			// An object named after an account this process is currently using
			// is not residue whatever the device says, and the read that said
			// otherwise raced a session that had not finished creating it.
			continue
		}
		if !r.residueAgedOut(ep, object.Name, now) {
			continue
		}
		if err := sweeper.RemoveResidue(ctx, device.RemoveRequest{Endpoint: ep, Name: object.Name}); err != nil {
			failures = append(failures, object.Name)
			r.auth.reportSweepFailure(SweepFailure{
				Target: addrOf(ep), Platform: route.platform, Account: object.Name,
				ObjectKind: object.Kind, Reason: err.Error(), At: now,
			})
			continue
		}
		r.forgetResidue(ep, object.Name)
		removed = append(removed, fmt.Sprintf("%s (%s)", object.Name, object.Kind))
	}
	if len(failures) > 0 {
		return removed, fmt.Errorf("auth/target: %d leftover device object(s) could not be removed on %s: %s",
			len(failures), addrOf(ep), strings.Join(failures, ", "))
	}
	return removed, nil
}

// residueAgedOut reports whether a leftover object has been unreferenced long
// enough to remove.
//
// It exists because "no account references this" is true for a moment on the
// CREATE path too: a FortiGate's schedule is written one round trip before the
// administrator that names it, and a sweep landing in that window would delete
// another session's expiry object out from under it and fail that session's
// provisioning. The grace period is the same one an untracked account gets and
// it is measured the same way — from when THIS PROCESS first saw the object,
// because no platform here timestamps one.
func (r *deviceReaper) residueAgedOut(ep device.Endpoint, name string, now time.Time) bool {
	key := addrOf(ep)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.firstResidueAt[key] == nil {
		r.firstResidueAt[key] = map[string]time.Time{}
	}
	first, ok := r.firstResidueAt[key][name]
	if !ok {
		r.firstResidueAt[key][name] = now
		return false
	}
	return now.Sub(first) >= r.grace
}

// forgetResidue drops an object's first-seen record once it is gone.
func (r *deviceReaper) forgetResidue(ep device.Endpoint, name string) {
	key := addrOf(ep)
	r.mu.Lock()
	defer r.mu.Unlock()
	if seen, ok := r.firstResidueAt[key]; ok {
		delete(seen, name)
	}
}

// agedOut reports whether an untracked account is old enough to remove.
//
// It prefers the device's own timestamp where the platform records one. Where
// it does not — the common case, and the one device.Account documents — the age
// is measured from when THIS PROCESS first saw the account, so an account
// inherited at startup gets a full grace period before it is touched.
func (r *deviceReaper) agedOut(ep device.Endpoint, account device.Account, now time.Time) bool {
	if !account.CreatedAt.IsZero() {
		return now.Sub(account.CreatedAt) >= r.grace
	}
	key := addrOf(ep)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.firstAt[key] == nil {
		r.firstAt[key] = map[string]time.Time{}
	}
	first, ok := r.firstAt[key][account.Name]
	if !ok {
		r.firstAt[key][account.Name] = now
		return false
	}
	return now.Sub(first) >= r.grace
}

// observe records a device and the route that reached it, so later sweeps can
// enumerate it with the same driver and prefix.
func (r *deviceReaper) observe(ep device.Endpoint, route *deviceRoute) {
	key := addrOf(ep)
	bare := device.Endpoint{Host: ep.Host, Port: ep.Port, HostKeyCallback: ep.HostKeyCallback}

	r.mu.Lock()
	defer r.mu.Unlock()
	if seen, ok := r.seen[key]; ok {
		seen.route = route
		return
	}
	r.seen[key] = &seenDevice{ep: bare, route: route}
}

// pinHostKey remembers the key a device presented, so teardown and sweeps do
// not depend on the policy service being reachable.
func (r *deviceReaper) pinHostKey(ep device.Endpoint, key ssh.PublicKey) {
	if key == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if seen, ok := r.seen[addrOf(ep)]; ok {
		seen.hostKey = key
	}
}

// pin returns ep with the host key remembered for it, if any.
func (r *deviceReaper) pin(ep device.Endpoint) device.Endpoint {
	r.mu.Lock()
	defer r.mu.Unlock()
	if seen, ok := r.seen[addrOf(ep)]; ok && seen.hostKey != nil {
		ep.HostKeyCallback = ssh.FixedHostKey(seen.hostKey)
	}
	return ep
}

// track marks an account as belonging to a live session.
func (r *deviceReaper) track(ep device.Endpoint, name string) {
	key := addrOf(ep)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.live[key] == nil {
		r.live[key] = map[string]bool{}
	}
	r.live[key][name] = true
}

// release forgets an account, whether or not its teardown succeeded.
//
// A failed teardown deliberately releases too: the account then reads as an
// untracked orphan, which is exactly what it is, and the sweep retries it once
// it is past the grace period. Keeping it "live" would protect the one thing
// that most needs removing.
func (r *deviceReaper) release(ep device.Endpoint, name string) {
	key := addrOf(ep)
	r.mu.Lock()
	defer r.mu.Unlock()
	if live, ok := r.live[key]; ok {
		delete(live, name)
		if len(live) == 0 {
			delete(r.live, key)
		}
	}
}

// forget drops an account's first-seen record once it is gone.
func (r *deviceReaper) forget(ep device.Endpoint, name string) {
	key := addrOf(ep)
	r.mu.Lock()
	defer r.mu.Unlock()
	if seen, ok := r.firstAt[key]; ok {
		delete(seen, name)
	}
}

func (r *deviceReaper) isLive(ep device.Endpoint, name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.live[addrOf(ep)][name]
}

// devices is every device seen this process lifetime.
func (r *deviceReaper) devices() []*seenDevice {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*seenDevice, 0, len(r.seen))
	for _, seen := range r.seen {
		pinned := *seen
		if seen.hostKey != nil {
			pinned.ep.HostKeyCallback = ssh.FixedHostKey(seen.hostKey)
		}
		out = append(out, &pinned)
	}
	return out
}

// claimSweep reports whether this caller may sweep the device now.
func (r *deviceReaper) claimSweep(ep device.Endpoint) bool {
	now := r.auth.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	seen, ok := r.seen[addrOf(ep)]
	if !ok {
		return false
	}
	if !seen.lastSweep.IsZero() && now.Sub(seen.lastSweep) < sweepCooldown {
		return false
	}
	seen.lastSweep = now
	return true
}

// afterFunc schedules work and keeps the handle, so Close stops it rather than
// leaving a timer holding a reference to a closed provisioner.
func (r *deviceReaper) afterFunc(d time.Duration, f func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	select {
	case <-r.stop:
		return
	default:
	}
	r.timers = append(r.timers, time.AfterFunc(d, f))
}

func addrOf(ep device.Endpoint) string {
	return fmt.Sprintf("%s:%d", ep.Host, ep.Port)
}
