// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"context"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/auth/target/device"
	"github.com/hoplock/proxy/internal/auth/target/device/fortios"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/sshtest"
)

// This file is phase 0043 on the device path: the route's algorithm profile
// reaches the driver's privileged connection and the reaper's sweep, and every
// configuration change a driver reports becomes exactly one record.

// countingDriver wraps a real driver and keeps what each mutating call
// returned, in order — the ground truth the records are compared against.
type countingDriver struct {
	device.Driver
	mu      sync.Mutex
	calls   []string
	changes []device.Change
}

func (d *countingDriver) note(call string, changes []device.Change) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, call)
	d.changes = append(d.changes, changes...)
}

func (d *countingDriver) CreateAccount(ctx context.Context, req device.CreateRequest) (*device.Account, []device.Change, error) {
	a, c, err := d.Driver.CreateAccount(ctx, req)
	d.note("create", c)
	return a, c, err
}

func (d *countingDriver) InstallCredential(ctx context.Context, req device.CredentialRequest) ([]device.Change, error) {
	c, err := d.Driver.InstallCredential(ctx, req)
	d.note("install", c)
	return c, err
}

func (d *countingDriver) RemoveAccount(ctx context.Context, req device.RemoveRequest) ([]device.Change, error) {
	c, err := d.Driver.RemoveAccount(ctx, req)
	d.note("remove", c)
	return c, err
}

func (d *countingDriver) ListResidue(ctx context.Context, req device.ListRequest) ([]device.Residue, error) {
	return d.Driver.(device.ResidueSweeper).ListResidue(ctx, req)
}

func (d *countingDriver) RemoveResidue(ctx context.Context, req device.RemoveRequest) ([]device.Change, error) {
	c, err := d.Driver.(device.ResidueSweeper).RemoveResidue(ctx, req)
	d.note("remove-residue", c)
	return c, err
}

func (d *countingDriver) reported() ([]string, []device.Change) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.calls...), append([]device.Change(nil), d.changes...)
}

// countedHarness is newDeviceHarness with the FortiGate driver behind a
// countingDriver.
func countedHarness(t *testing.T, opts deviceHarnessOptions) (*deviceHarness, *countingDriver) {
	t.Helper()
	h := newDeviceHarness(t, opts)
	dialer, err := device.NewSSHShellDialer(device.SSHShellOptions{User: "hoplock-mgmt", Password: "mgmt-secret"})
	if err != nil {
		t.Fatal(err)
	}
	real, err := fortios.New(fortios.Options{Dialer: dialer})
	if err != nil {
		t.Fatal(err)
	}
	counting := &countingDriver{Driver: real}
	registry := device.NewRegistry()
	if err := registry.Register(counting); err != nil {
		t.Fatal(err)
	}
	h.auth.drivers = registry
	return h, counting
}

func changesOf(events []DeviceConfigChange) []device.Change {
	out := make([]device.Change, 0, len(events))
	for _, e := range events {
		out = append(out, device.Change{Op: e.Op, ObjectKind: e.ObjectKind, Name: e.Name})
	}
	return out
}

// TestOneRecordPerChangeOverAWholeDeviceSession: create, credential install,
// teardown — each change the driver reports is one record, none missing and
// none duplicated, and none that the driver did not report.
func TestOneRecordPerChangeOverAWholeDeviceSession(t *testing.T) {
	for _, posture := range []control.ExpiryPosture{control.ExpiryPostureProxyEnforced, control.ExpiryPostureTargetEnforced} {
		t.Run(string(posture), func(t *testing.T) {
			h, counting := countedHarness(t, deviceHarnessOptions{deliverable: true})
			ctx := context.Background()
			tgt := h.tgt
			tgt.Auth = deviceRouteAuth(map[string]string{
				control.ParamExpiryPosture:                         string(posture),
				control.ParamDeviceFieldPrefix + fortios.FieldVDOM: "",
			})
			access, err := h.auth.Provision(ctx, deviceIdentity(), tgt)
			if err != nil {
				t.Fatalf("Provision: %v", err)
			}
			name := access.ClientConfig.User
			if err := access.Close(ctx); err != nil {
				t.Fatalf("teardown: %v", err)
			}

			calls, driverSaid := counting.reported()
			if !slices.Equal(calls, []string{"create", "install", "remove"}) {
				t.Fatalf("driver calls = %q", calls)
			}
			want := []device.Change{{Op: device.ChangeCreate, Name: name}, {Op: device.ChangeModify, Name: name},
				{Op: device.ChangeDelete, Name: name}}
			if posture == control.ExpiryPostureTargetEnforced {
				// The schedule is created first and removed last (phase 0017).
				want = []device.Change{
					{Op: device.ChangeCreate, ObjectKind: "firewall schedule", Name: name},
					{Op: device.ChangeCreate, Name: name},
					{Op: device.ChangeModify, Name: name},
					{Op: device.ChangeDelete, Name: name},
					{Op: device.ChangeDelete, ObjectKind: "firewall schedule", Name: name},
				}
			}
			if !slices.Equal(driverSaid, want) {
				t.Fatalf("driver reported %+v, want %+v", driverSaid, want)
			}
			events := h.events.configChanges()
			if got := changesOf(events); !slices.Equal(got, driverSaid) {
				t.Fatalf("records %+v, driver reported %+v", got, driverSaid)
			}
			for _, e := range events {
				if e.SessionID != "sess-1" || e.Platform != fortios.PlatformFortiGate || e.Target != tgt.Addr() {
					t.Errorf("change record %+v lacks the session, platform or target", e)
				}
			}
		})
	}
}

// TestTheDeadlineRemovalAndAFailedProvisioningEmitToo covers the two removal
// paths a session does not drive itself: the proxy-enforced deadline, and the
// cleanup after a provisioning that failed half way.
func TestTheDeadlineRemovalAndAFailedProvisioningEmitToo(t *testing.T) {
	h, counting := countedHarness(t, deviceHarnessOptions{deliverable: true})
	ctx := context.Background()

	tgt := h.tgt
	tgt.Auth = deviceRouteAuth(map[string]string{control.ParamLifetimeSeconds: "1"})
	access, err := h.auth.Provision(ctx, deviceIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	name := access.ClientConfig.User
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, still := h.dev.Accounts()[name]; !still {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the proxy-enforced deadline did not remove the account")
		}
		time.Sleep(20 * time.Millisecond)
	}
	_, driverSaid := counting.reported()
	if got := changesOf(h.events.configChanges()); !slices.Equal(got, driverSaid) || len(got) != 3 ||
		got[2] != (device.Change{Op: device.ChangeDelete, Name: name}) {
		t.Fatalf("records after the deadline %+v, driver reported %+v", got, driverSaid)
	}
	_ = access.Close(ctx)

	// A credential the device refuses: the account was created, then removed
	// by the driver's own rollback, and removeQuietly finds nothing left.
	// Every change that happened is recorded, and nothing more.
	h2, counting2 := countedHarness(t, deviceHarnessOptions{deliverable: true,
		fortios: sshtest.FortiOSOptions{Faults: sshtest.FortiOSFaults{FailCommand: regexp.MustCompile(`^set ssh-public-key1`)}}})
	tgt2 := h2.tgt
	tgt2.Auth = deviceRouteAuth(map[string]string{control.ParamCredentialKind: string(control.CredentialKindPublicKey)})
	if _, err := h2.auth.Provision(ctx, deviceIdentity(), tgt2); err == nil {
		t.Fatal("provisioning against a device refusing passwords succeeded")
	}
	_, said := counting2.reported()
	if got := changesOf(h2.events.configChanges()); !slices.Equal(got, said) || len(got) != 2 ||
		got[0].Op != device.ChangeCreate || got[1].Op != device.ChangeDelete {
		t.Fatalf("records %+v, driver reported %+v; want the create and the rollback's delete", got, said)
	}
	if len(h2.dev.Accounts()) != 0 {
		t.Fatalf("a failed provisioning left %v", h2.dev.Accounts())
	}
}

// TestTheReaperEmitsItsRemovals: the account sweep and the residue sweep both
// report what they removed, and a sweep belongs to no session.
func TestTheReaperEmitsItsRemovals(t *testing.T) {
	now := time.Now()
	h, _ := countedHarness(t, deviceHarnessOptions{deliverable: true, reaperGrace: time.Minute, now: func() time.Time { return now }})
	ctx := context.Background()
	tgt := h.tgt
	tgt.Auth = deviceRouteAuth(nil)
	route, err := h.auth.resolve(tgt.Auth, nil)
	if err != nil {
		t.Fatal(err)
	}
	orphan := route.naming.prefix + "orphan-00000001"
	ghost := route.naming.prefix + "ghost-00000002"
	h.dev.AddAccount(sshtest.FortiOSAccount{Name: orphan, Profile: "prof_admin"})
	h.dev.AddSchedule(sshtest.FortiOSSchedule{Name: ghost})

	// A session's endpoint, as sweepInBackground passes it: the sweep must
	// not attribute its removals to that session.
	ep := device.Endpoint{Host: tgt.Host, Port: tgt.Port, SessionID: "sess-that-triggered-it", HostKeyCallback: tgt.HostKeyCallback}
	if _, err := h.auth.reaper.Sweep(ctx, ep, route); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := h.auth.reaper.Sweep(ctx, ep, route); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := h.auth.reaper.Sweep(ctx, ep, route); err != nil {
		t.Fatal(err)
	}

	got := changesOf(h.events.configChanges())
	want := []device.Change{{Op: device.ChangeDelete, Name: orphan}, {Op: device.ChangeDelete, ObjectKind: "firewall schedule", Name: ghost}}
	if !slices.Equal(got, want) {
		t.Fatalf("sweep records %+v, want %+v", got, want)
	}
	for _, e := range h.events.configChanges() {
		if e.SessionID != "" {
			t.Errorf("a sweep's removal is attributed to session %q", e.SessionID)
		}
	}
}

// legacyDevice is a FortiGate stand-in whose SSH server speaks only what the
// legacy-device profile adds: a DSA host key and a SHA-1 key exchange.
func legacyDevice(t *testing.T) sshtest.FortiOSOptions {
	t.Helper()
	key, err := sshtest.GenerateDSAHostKey()
	if err != nil {
		t.Fatal(err)
	}
	return sshtest.FortiOSOptions{HostKey: key, Negotiation: sshtest.Negotiation{KeyExchanges: []string{"diffie-hellman-group14-sha1"}}}
}

func withProfile(tgt Target, p control.AlgorithmProfile) Target {
	tgt.AlgorithmProfile = p.Resolve()
	tgt.Algorithms = p.Resolve().Algorithms()
	return tgt
}

// TestTheDriverAndTheSweepUseTheRoutesProfile is the connection that is easy
// to forget. The session leg is the engine's; the driver's privileged CLI
// login is dialled by a dialer built once at startup, and the reaper's sweep
// dials again from a bare endpoint long after the session is gone — and a
// sweep that cannot dial leaves a standing administrator behind.
func TestTheDriverAndTheSweepUseTheRoutesProfile(t *testing.T) {
	now := time.Now()
	h := newDeviceHarness(t, deviceHarnessOptions{fortios: legacyDevice(t), deliverable: true,
		reaperGrace: time.Minute, now: func() time.Time { return now }})
	ctx := context.Background()
	base := h.tgt
	base.Auth = deviceRouteAuth(nil)

	// The default profile cannot even log in to administer the device.
	if _, err := h.auth.Provision(ctx, deviceIdentity(), withProfile(base, control.AlgorithmProfileDefault)); err == nil ||
		!IsAlgorithmPolicyUnmet(err) {
		t.Fatalf("default profile against a legacy-only device: %v, want an algorithm-policy failure", err)
	}
	if len(h.dev.Accounts()) != 0 {
		t.Fatal("something was created over a connection that should not have negotiated")
	}

	access, err := h.auth.Provision(ctx, deviceIdentity(), withProfile(base, control.AlgorithmProfileLegacyDevice))
	if err != nil {
		t.Fatalf("legacy-device Provision: %v", err)
	}
	if m := h.events.mapping(); len(m) != 1 || m[0].AlgorithmProfile != control.AlgorithmProfileLegacyDevice {
		t.Fatalf("mapping event profile = %+v, want legacy-device", m)
	}

	// Leave an orphan and sweep from the reaper's OWN record of the device —
	// the bare endpoint it keeps, not the session's.
	route, err := h.auth.resolve(base.Auth, nil)
	if err != nil {
		t.Fatal(err)
	}
	orphan := route.naming.prefix + "orphan-00000009"
	h.dev.AddAccount(sshtest.FortiOSAccount{Name: orphan, Profile: "prof_admin"})
	h.auth.reaper.sweepAll(ctx)
	now = now.Add(2 * time.Minute)
	h.auth.reaper.sweepAll(ctx)
	if _, still := h.dev.Accounts()[orphan]; still {
		t.Fatalf("the reaper's sweep did not remove the orphan (failures: %+v)", h.events.failures())
	}

	// And the counterfactual: the same sweep from an endpoint that carries no
	// profile is refused by the device, which is the failure the copy exists
	// to prevent.
	bare := device.Endpoint{Host: base.Host, Port: base.Port, HostKeyCallback: base.HostKeyCallback}
	if _, err := h.auth.reaper.Sweep(ctx, bare, route); err == nil ||
		!strings.Contains(err.Error(), "no common algorithm") {
		t.Fatalf("a sweep with no profile against a legacy-only device: %v", err)
	}

	if err := access.Close(ctx); err != nil {
		t.Fatalf("teardown under legacy-device: %v", err)
	}
}

// TestTheDriftFeedDoesNotWidenTheFailClosedRule: ErrNoLoggingPath protects
// ATTRIBUTION, and a drift feed is not attribution. A proxy with no logging
// path at all must keep serving the readable-name device routes it serves
// today, provisioning and tearing down with no record to emit — only the
// constrained-naming refusal is unchanged (the test above).
func TestTheDriftFeedDoesNotWidenTheFailClosedRule(t *testing.T) {
	h := newDeviceHarness(t, deviceHarnessOptions{noEvents: true})
	ctx := context.Background()
	tgt := h.tgt
	tgt.Auth = deviceRouteAuth(map[string]string{control.ParamExpiryPosture: string(control.ExpiryPostureTargetEnforced)})
	access, err := h.auth.Provision(ctx, deviceIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision with no logging path: %v", err)
	}
	if err := access.Close(ctx); err != nil {
		t.Fatalf("teardown with no logging path: %v", err)
	}
	if len(h.dev.Accounts()) != 0 || len(h.dev.Schedules()) != 0 {
		t.Fatal("teardown left objects behind")
	}
}
