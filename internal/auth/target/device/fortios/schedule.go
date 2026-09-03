// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package fortios

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hoplock/proxy/internal/auth/target/device"
)

// The second object (phase 0017).
//
// A FortiGate expires an administrator by REFERENCE: `set schedule <name>` on
// the administrator names an entry in `config firewall schedule onetime`, and
// that entry carries the absolute `set end` the device enforces at
// authentication. So a session provisioned under
// control.ExpiryPostureTargetEnforced writes two objects on a customer's
// firewall, and everything in this file exists because the second one can
// outlive the first.
//
// THE SCHEDULE TAKES THE ADMINISTRATOR'S OWN NAME. That is the design decision
// this file rests on and it buys three things at once. The schedule inherits
// the reaper prefix, so one proxy's sweep can never touch another's (PLAN
// §5.3's first non-negotiable). It inherits the uniqueness token, so two
// concurrent sessions cannot share a window whose first teardown closes the
// other's. And it needs no correlation table anywhere — the account a schedule
// belongs to is its name, which is what makes an orphan decidable from a device
// read alone rather than from proxy state a crash would have lost. The
// alternative, a second token, would have bought none of those and cost a
// second collision retry and a mapping to keep in step.
//
// It fits because the naming scheme in internal/auth/target never emits a name
// longer than 32 characters and 32 is the smaller of the two documented
// schedule-name limits (see maxScheduleNameLen). validateScheduleName is what
// says so at the boundary rather than in this comment.

const (
	// scheduleTableCommand opens the one-time schedule table.
	scheduleTableCommand = "config firewall schedule onetime"
	// scheduleShowCommand reads it.
	scheduleShowCommand = "show firewall schedule onetime"
)

// enterScheduleTable is the path to the one-time schedule table on this unit,
// and leaveScheduleTable is its exact inverse — the pair enterAdminTable and
// leaveAdminTable are, for the same reason and with the same rule: they are
// written next to each other so a sequence cannot open two levels and close one.
//
// UNVERIFIED, AND THE MOST CONSEQUENTIAL ASSUMPTION IN THIS FILE: that on a
// partitioned unit the one-time schedule table is reached through `config
// global`, like the administrator table. Phase 0017's prompt settles it that
// way — an object an administrator in the global table can reference is reached
// where that table is.
//
// The verification pass looked and found NOTHING EITHER WAY: the CLI reference
// carries no scope annotation on any command, and the Administration Guide's
// list of global settings does not mention firewall objects. What it did find
// are two indirect signals pointing the OTHER way — the guide's own multi-VDOM
// example configures firewall objects underneath `config vdom`, and the
// one-time schedule's expiry log message carries a Virtual Domain Name field.
// Neither is a statement about this table, and neither says what a GLOBAL
// administrator's `set schedule` resolves against when schedules are per-VDOM —
// which is the question a fix would have to answer, and cannot be answered from
// Fortinet's documentation today. So this stays as written, believed weaker
// than when it was written, and first on the hardware list for a partitioned
// unit.
//
// What makes being wrong SAFE rather than silent is the ORDER the create path
// uses, and it holds in both failure shapes. If the table cannot be entered in
// this scope at all, the sequence fails before anything exists. If it can, but
// the administrator cannot see what was written there, the administrator's
// `set schedule` fails on a dangling reference — `entry not found in
// datasource`, which cli.go already matches — and the attempt is rolled back.
// The failure this rules out is the one that would matter: an administrator
// created with a `set schedule` the device quietly ignored, on a session whose
// audit record says the device holds a deadline.
func (s *cliSession) enterScheduleTable() []step {
	steps := make([]step, 0, 2)
	if s.vdomMode.partitioned() {
		steps = append(steps, step{command: globalScopeCommand, label: "enter global configuration"})
	}
	return append(steps, step{command: scheduleTableCommand, label: "enter one-time schedule configuration"})
}

func (s *cliSession) leaveScheduleTable() []step {
	steps := []step{{command: "end", label: "leave one-time schedule configuration"}}
	if s.vdomMode.partitioned() {
		steps = append(steps, step{command: "end", label: "leave global configuration"})
	}
	return steps
}

// createSchedule writes this session's window into the schedule table.
//
// It runs BEFORE the administrator exists, which is the ordering the comment
// above argues for, and it is also the ordering the platform forces: `set
// schedule` naming an entry that is not there is a dangling reference and the
// device refuses it.
//
// The datetimes are sent UNQUOTED and everything else this driver sends is
// quoted; scheduleTimePattern in value.go carries why, and why that is safe.
func (d *Driver) createSchedule(ctx context.Context, s *cliSession, name, start, end string) error {
	steps := append(s.enterScheduleTable(),
		step{command: "edit " + quote(name), label: "create the expiry schedule"},
		step{command: "set start " + start, label: "set the expiry schedule's start"},
		step{command: "set end " + end, label: "set the expiry schedule's end"},
		// `expiration-days` DEFAULTS TO 3 and is not something this driver can
		// leave alone. It means "write an event log message this many days
		// before the schedule expires", so at its default every schedule
		// shorter than three days — which is every schedule this proxy creates
		// — is born already inside its own pre-expiration window and earns the
		// unit a warning-severity event log (message id 32048, "One time
		// schedule expiring") for a session that is behaving exactly as
		// intended. PLAN §5.3 is explicit that Hoplock does not hide the
		// configuration changes it makes; it is equally not entitled to fill a
		// customer's event log with warnings about them.
		//
		// Zero is the documented minimum. That it means "no message" rather
		// than "a message on the day" is the reading, not a quoted fact — but
		// both readings are quieter than the default, so this is the direction
		// to be wrong in.
		step{command: "set expiration-days 0", label: "silence the schedule's pre-expiration warning"},
		step{command: "next", label: "commit the expiry schedule"},
	)
	if err := d.run(ctx, s, append(steps, s.leaveScheduleTable()...)); err != nil && s.vdomMode.partitioned() {
		// The failure names the assumption, because on a partitioned unit this
		// is the sequence most likely to be wrong and the device's own error
		// will not say so (see enterScheduleTable).
		return fmt.Errorf("%w — on a unit running virtual domains this driver reaches `%s` through `%s`, "+
			"which is not documented either way and is the first thing to check on hardware",
			err, scheduleTableCommand, globalScopeCommand)
	} else if err != nil {
		return err
	}
	return nil
}

// removeSchedule deletes one schedule, and an absent one is a success.
//
// It is idempotent for RemoveAccount's reason and it is called on EVERY
// removal, including the removals of accounts that never had a schedule. That
// is deliberate: a teardown does not know which posture created the account it
// is removing, and neither does the reaper — the account may have been created
// by a session in another process, before a restart, under a route this one has
// never seen. Removal that only removed what the current route implies would
// leave exactly the objects nobody is left to remember.
func (d *Driver) removeSchedule(ctx context.Context, s *cliSession, name string) error {
	steps := append(s.enterScheduleTable(),
		step{command: "delete " + quote(name), label: "remove the expiry schedule", notFoundIsSuccess: true},
	)
	return d.run(ctx, s, append(steps, s.leaveScheduleTable()...))
}

// listSchedules reads the schedule table and returns the entries under a
// prefix, on ListAccounts' rules: the prefix is the caller's and is never
// widened, because on a shared device the prefix is the whole defence against
// one proxy deleting another's objects.
func (d *Driver) listSchedules(ctx context.Context, s *cliSession, prefix string) ([]string, error) {
	out, err := d.showGlobal(ctx, s, scheduleShowCommand, "list one-time schedules")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		m := editPattern.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil {
			continue
		}
		if prefix == "" || strings.HasPrefix(m[1], prefix) {
			names = append(names, m[1])
		}
	}
	return names, nil
}

// scheduleResidueKind is what an orphaned schedule is called in a log line and
// on a sweep-failure record. An operator reading that a sweep failed has to
// know which object is still on their firewall, and "account" would be wrong.
const scheduleResidueKind = "firewall schedule"

var _ device.ResidueSweeper = (*Driver)(nil)

// ListResidue implements device.ResidueSweeper.
//
// The orphan it exists for is narrow and real: a session that created the
// schedule and then failed, crashed, or lost the device before the
// administrator existed. The account sweep cannot see that object — there is no
// account — so without this it stays on the customer's unit until somebody
// notices a schedule named after an administrator that never was.
//
// UNREFERENCED IS DECIDED HERE, NOT IN THE REAPER, because only this driver
// knows what the reference is: an administrator of the same name. A schedule
// whose administrator still exists is left alone whether that administrator is
// live or itself an orphan — the account sweep removes the administrator first,
// and the schedule becomes residue on the pass after, which is the ordering
// that cannot delete the schedule out from under a live session.
//
// WHETHER TO REMOVE what this returns is the reaper's, and that split matters:
// a schedule can be unreferenced for one round trip on the create path, between
// createSchedule and the administrator's `set schedule`. The reaper ages it on
// the same first-seen grace it ages an untracked account by, so that window
// cannot become another session's failed provisioning.
func (d *Driver) ListResidue(ctx context.Context, req device.ListRequest) ([]device.Residue, error) {
	if req.Prefix == "" {
		return nil, errors.New("auth/target/device/fortios: enumerating without a prefix would select schedules this proxy does not own")
	}

	s, err := d.open(ctx, req.Endpoint)
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.Close() }()

	schedules, err := d.listSchedules(ctx, s, req.Prefix)
	if err != nil {
		return nil, err
	}
	if len(schedules) == 0 {
		return nil, nil
	}
	accounts, err := d.listAccounts(ctx, s, req.Prefix)
	if err != nil {
		return nil, err
	}
	referenced := make(map[string]bool, len(accounts))
	for _, a := range accounts {
		referenced[a.Name] = true
	}

	var residue []device.Residue
	for _, name := range schedules {
		if referenced[name] {
			continue
		}
		residue = append(residue, device.Residue{Name: name, Kind: scheduleResidueKind})
	}
	return residue, nil
}

// RemoveResidue implements device.ResidueSweeper.
//
// It removes the schedule and nothing else. An administrator of the same name
// is NOT removed here even though the two share one: RemoveAccount is where an
// account is removed, it is what the reaper's account pass calls, and an
// operation that quietly removed a privileged account as a side effect of
// tidying a schedule would be the reaper doing its most consequential work
// through the path nobody reviews.
func (d *Driver) RemoveResidue(ctx context.Context, req device.RemoveRequest) error {
	if err := validateScheduleName(req.Name); err != nil {
		return err
	}

	s, err := d.open(ctx, req.Endpoint)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()

	if err := d.removeSchedule(ctx, s, req.Name); err != nil {
		return fmt.Errorf("auth/target/device/fortios: remove the orphaned %s %q: %w", scheduleResidueKind, req.Name, err)
	}
	return nil
}
