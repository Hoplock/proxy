// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package fortios

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/auth/target/device"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/sshtest"
)

// The device-enforced expiry tests (phase 0017).
//
// What they are all circling is one property: a session whose audit record says
// `target-enforced` must leave a device that actually holds the deadline, and
// must leave nothing behind when it ends. Everything below is one half of that
// or the other.

// deviceClock is the fake unit's clock, and it is deliberately NOT this
// process's.
//
// A driver that computed the window from its own clock would pass every test
// against a device that agreed with it, and then write a window hours out on a
// customer's unit in another timezone — in one direction an account that cannot
// log in, in the other an account the device honours past its deadline. The
// only way to fail that driver here is for the fake to keep a clock of its own.
func deviceClock() func() time.Time {
	at := time.Date(2031, 3, 4, 9, 30, 20, 0, time.UTC)
	return func() time.Time { return at }
}

const expiringAccount = "hl-a1b2-alice-0f0f0f0f"

// expiringHarness is a device whose clock is deviceClock's.
func expiringHarness(t *testing.T, opts sshtest.FortiOSOptions) *harness {
	t.Helper()
	if opts.Now == nil {
		opts.Now = deviceClock()
	}
	return newHarness(t, opts)
}

func createExpiring(t *testing.T, h *harness, lifetime time.Duration) {
	t.Helper()
	if _, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{
		Endpoint: h.ep,
		Name:     expiringAccount,
		Lifetime: lifetime,
	}); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
}

// TestALifetimeBecomesAScheduleOnTheDevice is the phase in one test: the second
// object exists, it carries the window, and the administrator names it.
//
// A driver that wrote `set schedule` without creating the schedule would pass a
// test that only looked at the administrator — and would leave every
// target-enforced session claiming a deadline that nothing holds. So the
// assertion is on both objects and on the reference between them.
func TestALifetimeBecomesAScheduleOnTheDevice(t *testing.T) {
	h := expiringHarness(t, sshtest.FortiOSOptions{})
	createExpiring(t, h, 45*time.Minute)

	sched, ok := h.dev.Schedules()[expiringAccount]
	if !ok {
		t.Fatalf("no one-time schedule was created; the device has %v", h.dev.Schedules())
	}
	// The window is the DEVICE's, not this process's: 09:30 (truncated from
	// 09:30:20) through 10:15.
	if sched.Start != "09:30 2031/03/04" {
		t.Errorf("schedule starts at %q, want the device's own clock truncated to the minute", sched.Start)
	}
	if sched.End != "10:15 2031/03/04" {
		t.Errorf("schedule ends at %q, want the device's clock plus the lifetime", sched.End)
	}
	if on := h.dev.Accounts()[expiringAccount]; on.Schedule != expiringAccount {
		t.Errorf("the administrator references schedule %q, want %q; a schedule nothing names bounds nothing",
			on.Schedule, expiringAccount)
	}
}

// TestTheScheduleIsCreatedBeforeTheAdministrator pins the ordering, which is
// load-bearing twice over.
//
// `set schedule` naming an entry that is not there is a dangling reference the
// device refuses — so the schedule has to exist first for the sequence to work
// at all. And that same ordering is what makes the driver's UNVERIFIED reading
// of which scope the schedule table lives in fail loudly instead of quietly: a
// schedule written where the administrator cannot see it fails the reference,
// rather than leaving an administrator whose deadline the device ignores.
func TestTheScheduleIsCreatedBeforeTheAdministrator(t *testing.T) {
	h := expiringHarness(t, sshtest.FortiOSOptions{})
	createExpiring(t, h, time.Hour)

	var scheduleAt, adminAt = -1, -1
	for i, cmd := range h.dev.Commands() {
		switch {
		case scheduleAt < 0 && cmd == "config firewall schedule onetime":
			scheduleAt = i
		case adminAt < 0 && strings.HasPrefix(cmd, "edit ") && strings.Contains(cmd, expiringAccount) && scheduleAt >= 0 && i > scheduleAt+3:
			adminAt = i
		}
	}
	if scheduleAt < 0 {
		t.Fatalf("the schedule table was never opened: %v", h.dev.Commands())
	}
	if adminAt < 0 || adminAt < scheduleAt {
		t.Errorf("the administrator was created before its schedule; `set schedule` would then name nothing: %v", h.dev.Commands())
	}
}

// TestTeardownRemovesBothObjects is the acceptance criterion, and it fails if
// EITHER object is left behind.
//
// The order matters as much as the outcome: the device refuses to delete a
// schedule an administrator still references (`object is in use`), so a driver
// that removed the schedule first would leave both on a unit that behaves that
// way and pass against one that does not.
func TestTeardownRemovesBothObjects(t *testing.T) {
	h := expiringHarness(t, sshtest.FortiOSOptions{})
	ctx := context.Background()
	createExpiring(t, h, time.Hour)

	if err := h.driver.RemoveAccount(ctx, device.RemoveRequest{Endpoint: h.ep, Name: expiringAccount}); err != nil {
		t.Fatalf("RemoveAccount: %v", err)
	}
	if _, ok := h.dev.Accounts()[expiringAccount]; ok {
		t.Error("the administrator is still on the device")
	}
	if _, ok := h.dev.Schedules()[expiringAccount]; ok {
		t.Error("the administrator is gone but its schedule is still on the device: a second object nothing else will remove")
	}

	// And removal stays idempotent with two objects, because teardown runs on
	// the normal path, on error, and from the reaper.
	if err := h.driver.RemoveAccount(ctx, device.RemoveRequest{Endpoint: h.ep, Name: expiringAccount}); err != nil {
		t.Errorf("removing an account whose objects are already gone: %v", err)
	}
}

// TestRemovalSweepsAScheduleFromAnAccountItNeverCreated is why removal always
// tries both tables.
//
// Teardown does not know which posture created the account it is removing, and
// the reaper knows less: the account may be the leftover of a session in a
// process that no longer exists. A driver that only removed what its current
// route implies would leave exactly the objects nobody is left to remember.
func TestRemovalSweepsAScheduleFromAnAccountItNeverCreated(t *testing.T) {
	h := expiringHarness(t, sshtest.FortiOSOptions{
		Accounts:  []sshtest.FortiOSAccount{{Name: expiringAccount, Profile: testAccessProfile, Schedule: expiringAccount}},
		Schedules: []sshtest.FortiOSSchedule{{Name: expiringAccount, Start: "09:00 2031/03/04", End: "17:00 2031/03/04"}},
	})
	if err := h.driver.RemoveAccount(context.Background(), device.RemoveRequest{Endpoint: h.ep, Name: expiringAccount}); err != nil {
		t.Fatalf("RemoveAccount: %v", err)
	}
	if _, ok := h.dev.Schedules()[expiringAccount]; ok {
		t.Error("a schedule left by an earlier process survived teardown")
	}
}

// TestAnOrphanedScheduleIsResidue is the leak class this phase created and had
// to close: a session that wrote the schedule and died before the administrator
// existed.
//
// The account sweep cannot see that object — there is no account — so without
// the residue sweep it stays on the customer's unit for good.
func TestAnOrphanedScheduleIsResidue(t *testing.T) {
	h := expiringHarness(t, sshtest.FortiOSOptions{
		Schedules: []sshtest.FortiOSSchedule{
			{Name: "hl-a1b2-ghost-11111111", Start: "09:00 2031/03/04", End: "10:00 2031/03/04"},
			{Name: "workdays", Start: "09:00 2031/03/04", End: "17:00 2031/03/04"},
		},
	})
	ctx := context.Background()

	residue, err := h.driver.ListResidue(ctx, device.ListRequest{Endpoint: h.ep, Prefix: "hl-a1b2-"})
	if err != nil {
		t.Fatalf("ListResidue: %v", err)
	}
	if len(residue) != 1 || residue[0].Name != "hl-a1b2-ghost-11111111" {
		t.Fatalf("ListResidue = %v, want the one orphan under this proxy's prefix", residue)
	}
	if residue[0].Kind == "" {
		t.Error("residue with no kind: an operator reading a failed sweep has to know which object is still on their firewall")
	}

	if err := h.driver.RemoveResidue(ctx, device.RemoveRequest{Endpoint: h.ep, Name: residue[0].Name}); err != nil {
		t.Fatalf("RemoveResidue: %v", err)
	}
	left := h.dev.Schedules()
	if _, ok := left["hl-a1b2-ghost-11111111"]; ok {
		t.Error("the orphaned schedule survived the sweep")
	}
	if _, ok := left["workdays"]; !ok {
		t.Error("the sweep removed a customer's own schedule; the prefix is the whole defence against that")
	}
}

// TestAReferencedScheduleIsNotResidue is the other half, and the more important
// one: a sweep that removed a schedule an administrator still names would
// disarm a live session's deadline — or fail, having tried.
func TestAReferencedScheduleIsNotResidue(t *testing.T) {
	h := expiringHarness(t, sshtest.FortiOSOptions{})
	ctx := context.Background()
	createExpiring(t, h, time.Hour)

	residue, err := h.driver.ListResidue(ctx, device.ListRequest{Endpoint: h.ep, Prefix: "hl-a1b2-"})
	if err != nil {
		t.Fatalf("ListResidue: %v", err)
	}
	if len(residue) != 0 {
		t.Errorf("ListResidue = %v, want nothing: the administrator that names this schedule is still on the device", residue)
	}
}

// TestResidueEnumerationNeedsAPrefix is ListAccounts' rule, and it is here for
// the same reason: on a shared device the prefix is the only thing keeping one
// proxy out of another's objects.
func TestResidueEnumerationNeedsAPrefix(t *testing.T) {
	h := expiringHarness(t, sshtest.FortiOSOptions{})
	if _, err := h.driver.ListResidue(context.Background(), device.ListRequest{Endpoint: h.ep}); err == nil {
		t.Error("ListResidue accepted an empty prefix, which selects objects this proxy does not own")
	}
}

// TestAnUnreadableDeviceClockRefusesTheExpiry is the fail-closed half of
// reading the window off the device.
//
// `set end` is an absolute datetime in the unit's own local time. A driver that
// fell back to the proxy's clock when it could not read the device's would
// write a window that is wrong by the offset between them, and the dangerous
// direction is silent: an account the device honours long past the deadline its
// audit record claims.
func TestAnUnreadableDeviceClockRefusesTheExpiry(t *testing.T) {
	h := expiringHarness(t, sshtest.FortiOSOptions{
		Faults: sshtest.FortiOSFaults{HideClock: true},
	})
	ctx := context.Background()

	_, err := h.driver.CreateAccount(ctx, device.CreateRequest{
		Endpoint: h.ep, Name: expiringAccount, Lifetime: time.Hour,
	})
	if err == nil {
		t.Fatal("an expiring account was created on a unit that would not say what time it is")
	}
	if errors.Is(err, device.ErrUnsupported) {
		// The platform can do this and so can this driver; THIS UNIT did not
		// answer. ErrUnsupported would walk the session down to a credential
		// the server ranked lower over a device's silence.
		t.Error("refusing over an unreadable clock must fail the attempt, not skip the ladder rung")
	}
	if len(h.dev.Accounts()) != 0 || len(h.dev.Schedules()) != 0 {
		t.Errorf("the refusal left objects behind: accounts=%v schedules=%v", h.dev.Accounts(), h.dev.Schedules())
	}

	// The same unit still serves a route that does not need a clock, because
	// nothing else in the driver depends on one.
	if _, err := h.driver.CreateAccount(ctx, device.CreateRequest{Endpoint: h.ep, Name: expiringAccount}); err != nil {
		t.Errorf("a route with no device-held deadline was refused over the same missing clock: %v", err)
	}
}

// TestALifetimeFinerThanTheScheduleIsRefused is the granularity decision.
//
// `hh:mm yyyy/mm/dd` has no seconds in it. Rounding a sub-minute lifetime UP
// would hand out time nobody authorised on a privileged account; the driver
// refuses instead, and refuses before it has dialled anything.
func TestALifetimeFinerThanTheScheduleIsRefused(t *testing.T) {
	h := expiringHarness(t, sshtest.FortiOSOptions{})
	_, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{
		Endpoint: h.ep, Name: expiringAccount, Lifetime: 30 * time.Second,
	})
	if err == nil {
		t.Fatal("a 30-second lifetime was accepted onto a schedule whose finest unit is a minute")
	}
	if len(h.dev.Accounts()) != 0 || len(h.dev.Schedules()) != 0 {
		t.Error("the refusal left an object on the device")
	}
}

// TestTheWindowNeverOutlivesTheLifetime is the rounding direction, stated as
// the property rather than as an example: whatever the second hand is doing,
// the device's window must not end after the deadline the route asked for.
func TestTheWindowNeverOutlivesTheLifetime(t *testing.T) {
	base := time.Date(2031, 3, 4, 9, 30, 0, 0, time.UTC)
	for _, offset := range []time.Duration{0, time.Second, 29 * time.Second, 59 * time.Second} {
		for _, lifetime := range []time.Duration{time.Minute, 90 * time.Second, time.Hour} {
			now := base.Add(offset)
			start, end, err := scheduleWindow(now, lifetime)
			if err != nil {
				t.Fatalf("scheduleWindow(%s, %s): %v", now, lifetime, err)
			}
			endAt, err := time.Parse(scheduleTimeLayout, end)
			if err != nil {
				t.Fatalf("parse %q: %v", end, err)
			}
			if endAt.After(now.Add(lifetime)) {
				t.Errorf("window ends at %s, past the deadline %s", endAt, now.Add(lifetime))
			}
			startAt, err := time.Parse(scheduleTimeLayout, start)
			if err != nil {
				t.Fatalf("parse %q: %v", start, err)
			}
			if startAt.After(now) {
				t.Errorf("window opens at %s, after now (%s): the account could not log in", startAt, now)
			}
		}
	}
}

// TestAnExistingScheduleIsACollisionNotAnAdoption extends the never-adopt rule
// to the second object.
//
// The two share a name, so a taken schedule means a taken token. Reported as
// device.ErrAccountExists, the provisioner draws another and retries — which is
// the one answer that neither adopts a stranger's object nor fails a session
// over a coincidence.
func TestAnExistingScheduleIsACollisionNotAnAdoption(t *testing.T) {
	h := expiringHarness(t, sshtest.FortiOSOptions{
		Schedules: []sshtest.FortiOSSchedule{{Name: expiringAccount, Start: "09:00 2031/03/04", End: "09:31 2031/03/04"}},
	})
	_, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{
		Endpoint: h.ep, Name: expiringAccount, Lifetime: time.Hour,
	})
	if !errors.Is(err, device.ErrAccountExists) {
		t.Fatalf("CreateAccount = %v, want ErrAccountExists so the provisioner retries with a fresh token", err)
	}
	if sched := h.dev.Schedules()[expiringAccount]; sched.End != "09:31 2031/03/04" {
		t.Error("the existing schedule was adopted and overwritten; another session's window would have moved")
	}
	if len(h.dev.Accounts()) != 0 {
		t.Error("an administrator was created against a schedule this session does not own")
	}
}

// TestNoLifetimeWritesNoSecondObject is what keeps this phase's cost on the
// routes that asked for it.
//
// Rendering expiry means a second object on a customer's firewall, with its own
// teardown and its own orphan class. A proxy-enforced route reaches the driver
// with a zero lifetime and must get exactly the single-object session phase
// 0014 shipped.
func TestNoLifetimeWritesNoSecondObject(t *testing.T) {
	h := expiringHarness(t, sshtest.FortiOSOptions{})
	if _, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{
		Endpoint: h.ep, Name: expiringAccount,
	}); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if len(h.dev.Schedules()) != 0 {
		t.Errorf("a route with no device-held deadline wrote %v onto the device", h.dev.Schedules())
	}
	if on := h.dev.Accounts()[expiringAccount]; on.Schedule != "" {
		t.Errorf("the administrator carries schedule %q on a route that never asked for one", on.Schedule)
	}
	for _, cmd := range h.dev.Commands() {
		if strings.HasPrefix(cmd, "config firewall schedule") {
			t.Errorf("the schedule table was opened on a route with no lifetime: %q", cmd)
		}
	}
}

// TestTheDeviceRefusesTheAccountOutsideItsWindow is the claim the declaration
// makes, exercised end to end rather than asserted about the configuration.
//
// The fake enforces the schedule at BOTH authentication callbacks — see
// sshtest.FakeFortiOS.scheduleAllows, and the unverified reading it records —
// so this is what `EnforcesExpiry: true` is worth against a device that behaves
// the way phase 0017 believes one does.
func TestTheDeviceRefusesTheAccountOutsideItsWindow(t *testing.T) {
	clock := deviceClock()
	h := expiringHarness(t, sshtest.FortiOSOptions{Now: clock})
	ctx := context.Background()
	createExpiring(t, h, 10*time.Minute)

	const secret = "not-the-placeholder-abcdefghij"
	if err := h.driver.InstallCredential(ctx, device.CredentialRequest{
		Endpoint: h.ep, Name: expiringAccount, Kind: control.CredentialKindPassword, Password: secret,
	}); err != nil {
		t.Fatalf("InstallCredential: %v", err)
	}

	dial := func() error {
		client, err := ssh.Dial("tcp", h.dev.Addr().String(), &ssh.ClientConfig{
			User:            expiringAccount,
			Auth:            []ssh.AuthMethod{ssh.Password(secret)},
			HostKeyCallback: ssh.FixedHostKey(h.dev.HostKey()),
			Timeout:         5 * time.Second,
		})
		if err != nil {
			return err
		}
		return client.Close()
	}
	if err := dial(); err != nil {
		t.Fatalf("the account could not log in inside its own window: %v", err)
	}

	// Move the unit's clock past the window. Nothing about the account changes:
	// the DEVICE is what stops honouring it, which is the whole content of the
	// declaration.
	past := time.Date(2031, 3, 4, 11, 0, 0, 0, time.UTC)
	h.dev.SetNow(func() time.Time { return past })
	if err := dial(); err == nil {
		t.Error("the device let the account log in after its window closed; `set schedule` is then decoration")
	}
	if _, ok := h.dev.Accounts()[expiringAccount]; !ok {
		t.Error("the account was removed by the deadline; FortiOS denies the login and leaves the object for the reaper")
	}
}

// TestAScheduleInUseIsNotDeletable is the fake's strict reading, asserted so
// that the teardown order stays deliberate rather than incidental.
func TestAScheduleInUseIsNotDeletable(t *testing.T) {
	h := expiringHarness(t, sshtest.FortiOSOptions{})
	ctx := context.Background()
	createExpiring(t, h, time.Hour)

	if err := h.driver.RemoveResidue(ctx, device.RemoveRequest{Endpoint: h.ep, Name: expiringAccount}); err == nil {
		t.Error("a schedule an administrator still references was deleted; the driver removes the administrator first for exactly this reason")
	}
	if _, ok := h.dev.Schedules()[expiringAccount]; !ok {
		t.Error("the referenced schedule is gone")
	}
}

// TestTheScheduleIsReachedThroughGlobalScopeOnAPartitionedUnit is the phase's
// most consequential unverified reading, asserted against a fake that enforces
// it (sshtest's schedule table refuses the top level on a partitioned unit).
//
// It cannot make the reading true. What it does is make it VISIBLE: if a real
// unit puts the one-time schedule table somewhere else, this is the test that
// changes, and the driver's create-then-reference ordering is what turns the
// wrong answer into a failed attempt rather than an administrator whose
// deadline the device ignores.
func TestTheScheduleIsReachedThroughGlobalScopeOnAPartitionedUnit(t *testing.T) {
	for _, mode := range []string{sshtest.FortiOSVDOMMultiple, sshtest.FortiOSVDOMSplitTask} {
		t.Run(mode, func(t *testing.T) {
			h := expiringHarness(t, sshtest.FortiOSOptions{VDOMMode: mode})
			ctx := context.Background()
			createExpiring(t, h, time.Hour)

			if _, ok := h.dev.Schedules()[expiringAccount]; !ok {
				t.Fatalf("no schedule was created on a %s unit", mode)
			}
			if on := h.dev.Accounts()[expiringAccount]; on.Schedule != expiringAccount {
				t.Errorf("the administrator references %q, want %q", on.Schedule, expiringAccount)
			}

			if err := h.driver.RemoveAccount(ctx, device.RemoveRequest{Endpoint: h.ep, Name: expiringAccount}); err != nil {
				t.Fatalf("RemoveAccount: %v", err)
			}
			if len(h.dev.Schedules()) != 0 || len(h.dev.Accounts()) != 0 {
				t.Error("teardown left an object behind on a partitioned unit")
			}
			// The nesting is one level deeper here, and a session that ends
			// inside a configuration block holds an object lock under workspace
			// mode — so the second table must unwind exactly like the first.
			if n := h.dev.StrandedSessions(); n != 0 {
				t.Errorf("%d session(s) ended inside a configuration block", n)
			}
		})
	}
}

// The verification pass's findings, as tests (phase 0017, post-verification).

// TestAScheduleNameOverTheObjectLimitIsRefusedBeforeAnythingIsCreated pins the
// number the verification pass corrected, and pins it at the boundary.
//
// A one-time schedule's own `name` is 31 characters — not the 32 this driver
// first took from the naming KB, and not the 35 of the `schedule` field that
// REFERENCES one. Since the schedule is named after the administrator, and an
// administrator name may be 64 characters as far as this driver's own
// validation is concerned, the gap has to fail before the first object exists
// rather than between the two.
func TestAScheduleNameOverTheObjectLimitIsRefusedBeforeAnythingIsCreated(t *testing.T) {
	h := expiringHarness(t, sshtest.FortiOSOptions{})
	const name32 = "hl-a1b2-abcdefghijklmn-0f0f0f0f0" // 32 characters

	if len(name32) != maxScheduleNameLen+1 {
		t.Fatalf("this test's fixture is %d characters, not %d", len(name32), maxScheduleNameLen+1)
	}
	_, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{
		Endpoint: h.ep, Name: name32, Lifetime: time.Hour,
	})
	if err == nil {
		t.Fatal("a 32-character name was accepted as a schedule name; the object's limit is 31")
	}
	if len(h.dev.Accounts()) != 0 || len(h.dev.Schedules()) != 0 {
		t.Error("the refusal left an object on the device")
	}

	// The same name is fine on a route with no device-held deadline, because
	// nothing there is named after it.
	if _, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{
		Endpoint: h.ep, Name: name32,
	}); err != nil {
		t.Errorf("a 32-character administrator was refused on a route that creates no schedule: %v", err)
	}
}

// TestTheClockComesFromTheDocumentedCommands is the verification pass's V3.
//
// `execute date` / `execute time` are documented in the Administration Guide in
// every supported release; the `System time` line in `get system status` is
// shown only in a community KB, so it is the fallback rather than the source.
// Both paths must produce the same window, and neither may read the clock off
// `execute time`'s second line — which is the last NTP SYNCHRONISATION, not the
// time now, and which this fake deliberately reports as hours stale.
func TestTheClockComesFromTheDocumentedCommands(t *testing.T) {
	t.Run("documented commands", func(t *testing.T) {
		h := expiringHarness(t, sshtest.FortiOSOptions{})
		createExpiring(t, h, 45*time.Minute)

		var asked bool
		for _, cmd := range h.dev.Commands() {
			if cmd == "execute date" {
				asked = true
			}
		}
		if !asked {
			t.Errorf("the driver never asked the unit for its date: %v", h.dev.Commands())
		}
		if sched := h.dev.Schedules()[expiringAccount]; sched.End != "10:15 2031/03/04" {
			t.Errorf("window ends at %q; the `last ntp sync` line is not the clock", sched.End)
		}
	})

	t.Run("falling back to the status line", func(t *testing.T) {
		h := expiringHarness(t, sshtest.FortiOSOptions{
			Faults: sshtest.FortiOSFaults{NoExecuteClock: true},
		})
		createExpiring(t, h, 45*time.Minute)

		sched, ok := h.dev.Schedules()[expiringAccount]
		if !ok {
			t.Fatal("a unit that answers only `get system status` was refused a schedule")
		}
		if sched.End != "10:15 2031/03/04" {
			t.Errorf("the fallback produced %q, want the same window the documented commands do", sched.End)
		}
	})
}

// TestThePreExpirationWarningIsSilenced is the verification pass's V5.
//
// `expiration-days` defaults to 3 and means "write an event log message this
// many days before the schedule expires". Every schedule this proxy creates is
// shorter than three days, so at the default every session earns the customer's
// unit a warning-severity event log for behaving exactly as intended. PLAN §5.3
// says Hoplock does not hide the configuration changes it makes; it does not
// follow that it may fill an event log with warnings about them.
func TestThePreExpirationWarningIsSilenced(t *testing.T) {
	h := expiringHarness(t, sshtest.FortiOSOptions{})
	createExpiring(t, h, time.Hour)

	sched := h.dev.Schedules()[expiringAccount]
	if sched.ExpirationDays != 0 {
		t.Errorf("expiration-days is %d, want 0: at the device's default of %d this schedule is born inside its own pre-expiration window",
			sched.ExpirationDays, sshtest.FortiOSDefaultExpirationDays)
	}
}
