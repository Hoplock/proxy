// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/auth/target/device"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/sshtest"
)

// This file is the credential plane's half of phase 0045: every connection the
// session causes to its target — the POSIX management login, a driver's
// privileged CLI, and the reaper's sweep long after the session is gone — dials
// under the route's floor and bans, because a floor that held on the session
// leg while the proxy administered the target over a classical exchange would be
// the silent downgrade PLAN §6.5 forbids.

var classicalOnly = sshtest.Negotiation{KeyExchanges: []string{"curve25519-sha256", "ecdh-sha2-nistp256"}}

// withPolicy puts a whole algorithm policy on a target, as session.go does.
func withPolicy(tgt Target, p control.AlgorithmPolicy) Target {
	tgt.AlgorithmProfile = p.Profile.Resolve()
	tgt.AlgorithmFloor = p.Floor
	tgt.AlgorithmBans = p.Bans.Clone()
	tgt.Algorithms = p.Algorithms()
	return tgt
}

var pqFloor = control.AlgorithmPolicy{Floor: control.AlgorithmFloorPQHybridKEX}

// TestTheManagementLoginDialsUnderTheFloor: an ephemeral-user target whose sshd
// has no hybrid is refused at the provisioning login — as the algorithm-policy
// failure, caused by the floor — before any account exists; and the POSIX
// reaper keeps the floor on the target it sweeps from.
func TestTheManagementLoginDialsUnderTheFloor(t *testing.T) {
	ctx := context.Background()

	classical := startFakeHostNegotiating(t, classicalOnly)
	auth := newTestEphemeral(t, classical, "proxy-a")
	tgt := withPolicy(classical.tgt(), pqFloor)
	tgt.Auth = ephemeralRoute(nil)
	_, err := auth.Provision(ctx, testIdentity(), tgt)
	failure, ok := AlgorithmPolicyFailure(err, pqFloor)
	if !ok || failure.Axis != AlgorithmAxisKeyExchange || failure.Cause != control.AlgorithmPolicyCauseFloor {
		t.Fatalf("Provision under a floor the host cannot meet: %v (%+v), want a key-exchange floor failure", err, failure)
	}
	if accounts := classical.ephemeralAccounts(t); len(accounts) != 0 {
		t.Fatalf("an account was created over a login that should not have negotiated: %v", accounts)
	}

	// The same host with a hybrid is provisioned, and the reaper's own record
	// of it carries the floor for its sweeps.
	hybrid := startFakeHost(t)
	auth = newTestEphemeral(t, hybrid, "proxy-a")
	banned := control.AlgorithmPolicy{Floor: control.AlgorithmFloorPQHybridKEX, Bans: &control.AlgorithmBans{Ciphers: []string{"aes128-ctr"}}}
	tgt = withPolicy(hybrid.tgt(), banned)
	tgt.Auth = ephemeralRoute(nil)
	access, err := auth.Provision(ctx, testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision under a floor the host meets: %v", err)
	}
	defer func() { _ = access.Close(ctx) }()
	auth.reaper.mu.Lock()
	seen := auth.reaper.seen[tgt.Addr()]
	auth.reaper.mu.Unlock()
	if seen == nil {
		t.Fatal("the reaper did not record the target")
	}
	if seen.tgt.AlgorithmFloor != control.AlgorithmFloorPQHybridKEX || seen.tgt.AlgorithmBans.IsZero() ||
		!slices.Equal(seen.tgt.Algorithms.KeyExchanges, []string{control.KeyExchangeMLKEM768X25519}) ||
		slices.Contains(seen.tgt.Algorithms.Ciphers, "aes128-ctr") {
		t.Errorf("the reaper's record lost the policy: floor %q bans %+v lists %+v",
			seen.tgt.AlgorithmFloor, seen.tgt.AlgorithmBans, seen.tgt.Algorithms)
	}
}

// TestTheDriverAndTheSweepDialUnderTheFloor is phase 0043's sweep test with a
// floor: the driver's privileged CLI login is refused by a device the floor
// excludes, a device that meets it is provisioned and its mapping event names
// the floor and the exchange the driver's own connection negotiated, the
// reaper sweeps it from its own bare record under the floor — and a device that
// no longer meets the floor it was provisioned under is a sweep failure that
// says the device changed under the proxy.
func TestTheDriverAndTheSweepDialUnderTheFloor(t *testing.T) {
	ctx := context.Background()

	classical := newDeviceHarness(t, deviceHarnessOptions{fortios: sshtest.FortiOSOptions{Negotiation: classicalOnly}, deliverable: true})
	base := classical.tgt
	base.Auth = deviceRouteAuth(nil)
	if _, err := classical.auth.Provision(ctx, deviceIdentity(), withPolicy(base, pqFloor)); !IsAlgorithmPolicyUnmet(err) {
		t.Fatalf("a classical device under a pq floor: %v, want an algorithm-policy failure at the driver's login", err)
	}
	if len(classical.dev.Accounts()) != 0 {
		t.Fatal("something was created over a connection that should not have negotiated")
	}

	now := time.Now()
	h := newDeviceHarness(t, deviceHarnessOptions{deliverable: true, reaperGrace: time.Minute, now: func() time.Time { return now }})
	base = h.tgt
	base.Auth = deviceRouteAuth(nil)
	policy := control.AlgorithmPolicy{Floor: control.AlgorithmFloorPQHybridKEX, Bans: &control.AlgorithmBans{MACs: []string{"hmac-sha1"}}}
	access, err := h.auth.Provision(ctx, deviceIdentity(), withPolicy(base, policy))
	if err != nil {
		t.Fatalf("Provision under a floor the device meets: %v", err)
	}
	m := h.events.mapping()
	if len(m) != 1 {
		t.Fatalf("mapping events = %d", len(m))
	}
	if m[0].AlgorithmFloor != control.AlgorithmFloorPQHybridKEX || m[0].KexAlgorithm != control.KeyExchangeMLKEM768X25519 ||
		m[0].AlgorithmBans.IsZero() {
		t.Errorf("mapping event floor %q kex %q bans %+v, want the floor, the driver's negotiated hybrid and the ban",
			m[0].AlgorithmFloor, m[0].KexAlgorithm, m[0].AlgorithmBans)
	}

	// The reaper's OWN record of the device carries the floor's lists.
	h.auth.reaper.mu.Lock()
	seen := h.auth.reaper.seen[addrOf(device.Endpoint{Host: base.Host, Port: base.Port})]
	h.auth.reaper.mu.Unlock()
	if seen == nil || !slices.Equal(seen.ep.Algorithms.KeyExchanges, []string{control.KeyExchangeMLKEM768X25519}) ||
		slices.Contains(seen.ep.Algorithms.MACs, "hmac-sha1") {
		t.Fatalf("the reaper's endpoint does not carry the policy: %+v", seen)
	}

	// An orphan is swept from that record, under the floor.
	route, err := h.auth.resolve(base.Auth, nil)
	if err != nil {
		t.Fatal(err)
	}
	orphan := route.naming.prefix + "orphan-00000045"
	h.dev.AddAccount(sshtest.FortiOSAccount{Name: orphan, Profile: "prof_admin"})
	h.auth.reaper.sweepAll(ctx)
	now = now.Add(2 * time.Minute)
	h.auth.reaper.sweepAll(ctx)
	if _, still := h.dev.Accounts()[orphan]; still {
		t.Fatalf("the sweep under the floor did not remove the orphan (failures: %+v)", h.events.failures())
	}

	// A device that has since lost its hybrid: the sweep dials with the lists it
	// was provisioned under, cannot agree an exchange, and says the device
	// changed rather than blaming the route.
	changed, err := sshtest.StartFortiOS(sshtest.FortiOSOptions{Negotiation: classicalOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = changed.Close() }()
	stale := device.Endpoint{Host: changed.Host(), Port: changed.Port(), HostKeyCallback: ssh.FixedHostKey(changed.HostKey()),
		Algorithms: seen.ep.Algorithms.Clone()}
	if _, err := h.auth.reaper.Sweep(ctx, stale, route); err == nil {
		t.Fatal("a sweep under the floor reached a device without the hybrid")
	}
	var reported *SweepFailure
	for _, f := range h.events.failures() {
		if f.Target == addrOf(stale) {
			reported = &f
		}
	}
	if reported == nil {
		t.Fatal("the failed sweep was not reported")
	}
	if !strings.Contains(reported.Reason, "has changed under the proxy") || reported.AlgorithmAxis != AlgorithmAxisKeyExchange ||
		!slices.Contains(reported.AlgorithmsOffered, "curve25519-sha256") {
		t.Errorf("sweep failure = %+v, want it to say the device changed, on the key-exchange axis, with what it offers", reported)
	}

	if err := access.Close(ctx); err != nil {
		t.Fatalf("teardown under the floor: %v", err)
	}
}
