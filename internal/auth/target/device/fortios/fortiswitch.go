// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package fortios

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/hoplock/proxy/internal/auth/target/device"
	"github.com/hoplock/proxy/internal/control"
)

// PlatformFortiSwitch is the value a route's `platform` parameter carries for a
// FortiSwitch (control.ParamPlatform). Like every platform name it is policy
// somebody else wrote, so it is stable across releases.
//
// It is ONE name for both management modes, and that is phase 0029's decision
// rather than an omission. See SwitchDriver.
const PlatformFortiSwitch = "fortiswitchos"

// SwitchDriver is the FortiSwitchOS implementation of device.Driver.
//
// # Why a FortiLink-managed switch is its own endpoint
//
// Phase 0029 was written expecting the opposite. Its premise was that a
// FortiLink-managed FortiSwitch "has no independent administrative plane the
// proxy can SSH into: it is administered THROUGH its managing FortiGate", and
// it asked for a driver that reached the switch as a field on the FortiGate's
// route — the shape phase 0016 established for a virtual domain, one level
// further out (docs/PLAN.md §5.3, "As extended (phase 0016)").
//
// Reading Fortinet's documentation rather than remembering it — which is what
// that prompt asked for, and what phases 0014 and 0015 established as the
// discipline here — does not support the premise. `config switch-controller
// security-policy local-access` on the FortiGate configures the "allowaccess
// list for mgmt and internal interfaces on managed FortiSwitch units", and
// `ssh` is in the DEFAULT for both (`https ping ssh`). A managed switch keeps
// its own SSH administrative plane and its own `config system admin` table;
// whether this proxy can reach that address is a routing and firewall-policy
// question in the customer's deployment, not a property of the platform.
//
// So the endpoint is the SWITCH, and FortiLink is a deployment fact rather than
// a target identity. That keeps 0016's answer intact rather than stretching it:
// 0016's rule is that the endpoint stays the DEVICE and a route field names a
// PARTITION of one device. A FortiSwitch is not a partition of its FortiGate —
// it is a separate device with its own host key, its own administrator table,
// its own configuration and its own serial number. Encoding it as a field on
// another device's route would have made `host:port` name a unit the account
// does not live on, which is the exact failure 0016 rejected `host/vdom` for.
//
// The alternatives were weighed and are recorded in docs/PLAN.md §5.3:
//
//   - the FortiGate as endpoint with `device_field.switch` naming the switch —
//     rejected once the switch turned out to be reachable, because it makes
//     every audit record, host-key pin and reaper sweep address a device the
//     administrator is not on, and buys nothing an estate that routes to its
//     switches needs;
//   - the switch as target with a field naming its managing FortiGate —
//     rejected because nothing in this driver needs to know the manager, so the
//     field would be an unverifiable fact in policy that goes stale the moment
//     a switch is re-homed;
//   - a platform name encoding the relationship (`fortiswitch-via-fortigate`) —
//     rejected because the management mode does not change the CLI this driver
//     speaks, and a switch moved between FortiGates, or out of FortiLink into
//     standalone, would otherwise change its PLATFORM in policy while remaining
//     the same device with the same administrator table.
//
// What is genuinely FortiLink-specific survives as declarations and refusals
// rather than as identity: the built-in profile set is smaller than FortiOS's
// (see checkSwitchProfile), the managing FortiGate can close SSH on the
// switch's interfaces through `local-access` — which this proxy sees as an
// ordinary unreachable device — and the FortiGate has NO VIEW of administrators
// created here, which is the leak class recorded on Capabilities and in the
// learnings.
//
// # Why it is a separate type from Driver
//
// The two platforms speak nearly the same CLI and this file reuses that: the
// prompt/response state machine (cli.go), the value validation (value.go) and
// the session-level helpers (run, showGlobal, listAccounts, accountExists) are
// the FortiGate driver's, moved onto cliSession by this phase rather than
// copied.
//
// What could not be shared is the TYPE. *Driver implements
// device.ResidueSweeper, and the reaper discovers that by type assertion — so a
// switch served by the same type would have its `config firewall schedule
// onetime` sweep run against a platform whose schedule table is `config system
// schedule onetime` and whose administrator has no verified schedule mechanism
// at all. Every sweep would report a failure on a customer's switch, every two
// minutes, for an object class that does not exist there. A separate type is
// what makes "this platform has no residue" expressible.
type SwitchDriver struct {
	dialer  device.ShellDialer
	profile string
}

var _ device.Driver = (*SwitchDriver)(nil)

// SwitchOptions configure a FortiSwitchOS driver.
type SwitchOptions struct {
	// Dialer opens the privileged CLI session. Required.
	Dialer device.ShellDialer
	// AccessProfile is the profile created administrators are given when the
	// route does not name one. As on FortiOS there is no default, and for a
	// sharper reason here: FortiSwitchOS documents exactly ONE built-in
	// profile and it is the all-access one (see checkSwitchProfile).
	AccessProfile string
}

// NewSwitch returns a FortiSwitchOS driver.
func NewSwitch(opts SwitchOptions) (*SwitchDriver, error) {
	if opts.Dialer == nil {
		return nil, errors.New("auth/target/device/fortios: a driver needs a way to reach the device")
	}
	d := &SwitchDriver{dialer: opts.Dialer, profile: opts.AccessProfile}
	// Empty is allowed here and refused at create time, exactly as on the
	// FortiGate driver: a proxy whose every route names its own profile is a
	// legitimate configuration, and refusing to build the driver would turn
	// that into a startup failure.
	if d.profile != "" {
		if err := validateProfile(d.profile); err != nil {
			return nil, err
		}
		if err := checkSwitchProfile(d.profile); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// Platform implements device.Driver.
func (d *SwitchDriver) Platform() string { return PlatformFortiSwitch }

// Capabilities implements device.Driver.
//
// Every value here was read directly from Fortinet's FortiSwitchOS
// documentation for 7.6.x; docs/FORTIOS-DOC-VERIFICATION.md carries the pages
// and the wording under "FortiSwitchOS (phase 0029)". Three are worth reading
// twice, because each is a place where this platform is NOT its FortiOS
// sibling and a driver that assumed otherwise would be wrong on a customer's
// switch.
//
// ENFORCESEXPIRY IS FALSE, and unlike FortiOS's true it rests on a
// contradiction in the vendor's own documentation rather than on a decision
// about what the bit means. `config system admin` on FortiSwitchOS does have
// `set schedule <schedule-name>`, and its description reads "Restrict times
// that an administrator can log in. Defined in config firewall schedule." But
// FortiSwitchOS HAS NO `config firewall schedule`: its CLI reference lists
// `config system schedule onetime`, `config system schedule recurring` and
// `config system schedule group` under `config system`, and no firewall
// schedule table anywhere. So the field exists and the table its own
// description names does not, and which table `set schedule` actually resolves
// against is unstated.
//
// Declaring true on that would be declaring a deadline this driver cannot
// establish the device honours — and the whole value of the bit, per phase
// 0017, is that it says the DEVICE ends the account's usefulness whether or not
// the proxy is alive. A route asking for control.ExpiryPostureTargetEnforced on
// this platform is therefore a SKIPPED LADDER RUNG (D14) rather than a session
// served with a window nobody can vouch for. Resolving the contradiction needs
// a real unit; it is queued rather than guessed at.
//
// The consequence is the one PLAN §5.3 describes for every platform that cannot
// expire an account: the orphan reaper is the PRIMARY removal path here, not a
// crash-recovery backstop.
//
// PERSISTSACROSSRELOAD IS TRUE, for FortiOS's reason and with the same
// evidence. `config system global` on FortiSwitchOS carries `set cfg-save
// {automatic | manual | revert}` exactly as FortiOS does, so under the default
// an administrator is written to flash when the block ends and the alternatives
// are device-wide settings governing every change on the unit. D13's amended
// rule — a shipped driver may declare persistence where the platform leaves it
// no choice, and must say which mechanism forces it — is what permits this.
//
// COMMANDAUTHORIZATION is declared because FortiSwitchOS has a real one, and
// its caveat is materially different from FortiOS's: the profile grouping is
// coarser and there is only one built-in.
func (d *SwitchDriver) Capabilities() device.Capabilities {
	return device.Capabilities{
		MaxAccountNameLen: maxSwitchAccountNameLen,
		// False, and see the type comment: the field exists, the table its
		// description names does not exist on this platform, and a deadline
		// this driver cannot establish the device honours is not one it will
		// claim. There is deliberately no ExpiryMechanism, which is what the
		// declaration means when EnforcesExpiry is false.
		EnforcesExpiry:       false,
		PersistsAcrossReload: true,
		PersistenceReason: "FortiSwitchOS has no runtime-only configuration plane, and the mechanism " +
			"is FortiOS's: `config system global` / `set cfg-save {automatic | manual | revert}` " +
			"writes the change to flash when the configuration block ends under the default, and " +
			"the alternatives are device-wide settings governing every change on the unit rather " +
			"than a per-command choice this driver could make. A created administrator therefore " +
			"survives a reload, and the orphan reaper — not a reload — is what removes it. On a " +
			"FortiLink-MANAGED switch there is a second reason to expect the account to outlive " +
			"this proxy's interest in it: the managing FortiGate has no view of the switch's " +
			"administrator table at all, so nothing on the FortiGate will ever reconcile one away.",
		CredentialKinds: []control.CredentialKind{
			control.CredentialKindPassword,
			control.CredentialKindPublicKey,
		},
		CommandAuthorization: "a FortiSwitchOS ACCESS PROFILE, named by `set accprofile` on the " +
			"administrator this proxy creates (`config system accprofile`). The switch's own " +
			"authorizer decides every command ahead of anything a proxy could parse, and it is " +
			"effective against a connection that never went through one.",
		AuthorizationCaveat: "FortiSwitchOS groups commands into TWELVE feature areas — `admingrp`, " +
			"`loggrp`, `mntgrp`, `netgrp`, `pktmongrp`, `routegrp`, `swcoregrp`, `swmonguardgrp`, " +
			"`sysgrp`, `utilgrp`, `exec-alias-grp` and the alias list — each set to `none`, `read` " +
			"or `read-write`, and the guarantee is exactly that grouping and no finer. Two facts " +
			"an operator has to know, and both differ from FortiOS: there is exactly ONE built-in " +
			"profile, `super_admin`, which cannot be deleted or modified and has access to " +
			"everything including adding and removing administrators — so any narrower scope is a " +
			"CUSTOM profile the customer builds, and the FortiOS built-ins `prof_admin` and " +
			"`super_admin_readonly` do not exist here at all. And creating administrators needs " +
			"`admingrp` read-write, so the privileged account this proxy logs in as must hold it: " +
			"Fortinet states only the default `admin` account, or an account with read-write " +
			"access control, can create a new administrator account.",
		PinsSourceAddress: true,
		// No Fields, and that is the phase's decision rather than an omission:
		// this platform is exactly one target. A FortiLink-managed switch is
		// still one device with one administrator table, so there is no
		// partition for a route to name — see the type comment.
		Fields: nil,
	}
}

// CreateAccount implements device.Driver.
//
// It is the FortiGate sequence minus everything that platform has and this one
// does not: no virtual domain to scope to, no `config global` wrapper, and no
// expiry schedule. What it keeps is the part that is about safety rather than
// about FortiOS — verify non-existence and NEVER adopt (D13, PLAN §5.3),
// because `edit` opens an existing entry as readily as it creates a new one and
// two sessions sharing an administrator means the first teardown removes the
// other's access.
func (d *SwitchDriver) CreateAccount(ctx context.Context, req device.CreateRequest) (*device.Account, error) {
	if err := validateAccountNameWithin(req.Name, maxSwitchAccountNameLen); err != nil {
		return nil, err
	}
	if len(req.Fields) > 0 {
		// The provisioner already checks a route's fields against
		// Capabilities.Fields and skips the rung when one is undeclared, so
		// this is belt and braces — the same duplication the FortiGate driver's
		// requestedVDOM keeps, and for the same reason: "the caller checked"
		// describes today's caller, and what is at stake is a configuration
		// command on somebody's switch.
		names := make([]string, 0, len(req.Fields))
		for name := range req.Fields {
			names = append(names, name)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("%w: this platform is one target and accepts no route fields, but the route carries %s",
			errInvalidValue, strings.Join(names, ", "))
	}
	if req.Lifetime > 0 {
		// Unreachable through the provisioner, which hands a lifetime only to
		// a driver declaring EnforcesExpiry. It is device.ErrUnsupported rather
		// than a plain error because that is exactly what it means — THIS
		// PLATFORM CANNOT, no retry and no different unit will change it — and
		// a driver that silently dropped the lifetime would leave an audit
		// record claiming a deadline the switch is not holding.
		return nil, device.Unsupported(PlatformFortiSwitch,
			"hold an administrator's deadline: `set schedule` exists but the `config firewall schedule` table its own documentation names does not exist on FortiSwitchOS")
	}

	profile := d.profile
	if req.Profile != "" {
		profile = req.Profile
	}
	if profile == "" {
		return nil, errors.New("auth/target/device/fortios: no access profile: " +
			"an administrator's scope must be named by the route or by " +
			"`auth.target.ephemeral_account.access_profile`, and FortiSwitchOS's only built-in " +
			"profile is `super_admin`, which has access to everything including administrator " +
			"management")
	}
	if err := validateProfile(profile); err != nil {
		return nil, err
	}
	if err := checkSwitchProfile(profile); err != nil {
		return nil, err
	}

	var trust string
	if req.SourceAddress != "" {
		var err error
		if trust, err = trustHost(req.SourceAddress); err != nil {
			return nil, err
		}
	}

	placeholder, err := randomSecret(placeholderSecretLen)
	if err != nil {
		return nil, err
	}

	s, err := d.open(ctx, req.Endpoint)
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.Close() }()

	exists, err := s.accountExists(ctx, req.Name)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("%w: %q is already an administrator on %s",
			device.ErrAccountExists, req.Name, req.Host)
	}

	steps := append(s.enterAdminTable(),
		step{command: "edit " + quote(req.Name), label: "create the administrator"},
		step{command: "set accprofile " + quote(profile), label: "set the access profile"},
	)
	if trust != "" {
		steps = append(steps,
			step{command: "set trusthost1 " + trust, label: "pin the administrator to the proxy's address"},
			// Both families, always. FortiSwitchOS has the same parallel pair
			// FortiOS does — `trusthost1`..`10` defaulting to `0.0.0.0
			// 0.0.0.0` and `ip6-trusthost1`..`10` defaulting to `::/0` — so a
			// pin that sets only the IPv4 field is not a pin.
			step{command: "set ip6-trusthost1 " + closedIPv6TrustHost, label: "close the administrator to IPv6"},
		)
	}
	steps = append(steps,
		// The account exists for a moment before InstallCredential runs, and
		// an administrator with no password can be logged into with an empty
		// one. See placeholderSecretLen.
		step{command: "set password " + quote(placeholder), label: "set a placeholder password", secret: true},
		step{command: "next", label: "commit the administrator"},
	)
	steps = append(steps, s.leaveAdminTable()...)

	if err := s.run(ctx, steps); err != nil {
		d.abandon(ctx, s, req.Name)
		return nil, err
	}

	return &device.Account{
		Name: req.Name,
		// FortiSwitchOS does not record when an administrator was created, so
		// this stays zero and the reaper reads it as "age unknown"
		// (device.Account).
		Profile: profile,
	}, nil
}

// InstallCredential implements device.Driver.
//
// Both kinds are served, and the public-key half is worth a note because the
// phase nearly lost it. Had the switch been reached THROUGH its FortiGate, the
// only path in would have been FortiOS's `execute switch-controller ssh`, whose
// client is documented as a "Simple SSH client" with no identity-file parameter
// and no client key store — so the credential would have had to be a password
// whatever FortiSwitchOS accepts. Connecting to the switch directly is what
// keeps `set ssh-public-key1` usable.
func (d *SwitchDriver) InstallCredential(ctx context.Context, req device.CredentialRequest) error {
	if err := validateAccountNameWithin(req.Name, maxSwitchAccountNameLen); err != nil {
		return err
	}

	var install step
	switch req.Kind {
	case control.CredentialKindPassword:
		if err := validateSecret(req.Password); err != nil {
			return err
		}
		install = step{command: "set password " + quote(req.Password), label: "set the administrator's password", secret: true}
	case control.CredentialKindPublicKey:
		key := strings.TrimSpace(req.PublicKey)
		if err := validatePublicKey(key); err != nil {
			return err
		}
		install = step{command: "set ssh-public-key1 " + quote(key), label: "install the administrator's public key"}
	default:
		// Never a substitution of the other kind: a password and a public key
		// have materially different exposure and the server chose (D13).
		return device.Unsupported(PlatformFortiSwitch, fmt.Sprintf("install a %q credential", req.Kind))
	}

	s, err := d.open(ctx, req.Endpoint)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()

	steps := append(s.enterAdminTable(),
		step{command: "edit " + quote(req.Name), label: "open the administrator"},
		install,
		step{command: "next", label: "commit the credential"},
	)
	steps = append(steps, s.leaveAdminTable()...)
	if err := s.run(ctx, steps); err != nil {
		d.abandon(ctx, s, req.Name)
		return err
	}
	return nil
}

// RemoveAccount implements device.Driver.
//
// One object, so one delete — and that is the whole difference from the
// FortiGate's removal, which has to unwind a schedule beside the administrator.
// It is IDEMPOTENT because teardown runs on the normal path, on error, on
// panic, on signal, and from the reaper (PLAN §5.1): an administrator that is
// already gone is the outcome this wanted. A device it cannot reach is a
// different answer — a retryable failure, which the reaper finds again.
func (d *SwitchDriver) RemoveAccount(ctx context.Context, req device.RemoveRequest) error {
	if err := validateAccountNameWithin(req.Name, maxSwitchAccountNameLen); err != nil {
		return err
	}

	s, err := d.open(ctx, req.Endpoint)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()

	steps := append(s.enterAdminTable(),
		step{command: "delete " + quote(req.Name), label: "remove the administrator", notFoundIsSuccess: true},
	)
	return s.run(ctx, append(steps, s.leaveAdminTable()...))
}

// ListAccounts implements device.Driver.
//
// The prefix is the caller's and is never widened: on a shared device, one
// proxy's sweep selecting another proxy's accounts kills live sessions, and this
// argument is the whole defence against it.
func (d *SwitchDriver) ListAccounts(ctx context.Context, req device.ListRequest) ([]device.Account, error) {
	if req.Prefix == "" {
		return nil, errors.New("auth/target/device/fortios: enumerating without a prefix would select accounts this proxy does not own")
	}

	s, err := d.open(ctx, req.Endpoint)
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.Close() }()

	return s.listAccounts(ctx, req.Prefix)
}

// ErrNotAFortiSwitch means the unit that answered is not one this driver may
// configure.
//
// It exists because the two platforms in this package speak NEARLY THE SAME
// CLI, which is the whole reason the switch driver could reuse the FortiGate's
// machinery — and is exactly what makes a misrouted session dangerous. `config
// system admin` / `edit` / `set accprofile` / `set password` are valid on both,
// so a route naming this platform against a FortiGate would create a
// privileged administrator on somebody's FIREWALL and report success. Nothing
// downstream would catch it: the account would exist, the credential would
// work, and the audit record would name a switch.
//
// So the identity is confirmed before anything is configured. Like ErrMultiVDOM
// this is deliberately NOT device.ErrUnsupported: the platform is capable and
// the driver is capable, and what is wrong is which device the route pointed
// at. Skipping the rung would answer a misrouted route by serving the session
// on a credential the server ranked lower, where D13's rule makes it an
// outage-class denial.
var ErrNotAFortiSwitch = errors.New("auth/target/device/fortios: the unit did not identify itself as a FortiSwitch")

// switchStatusCommand asks the unit what it is.
//
// Unlike its FortiGate counterpart this one is DOCUMENTED: Fortinet publishes
// `get system status`'s output for FortiSwitchOS, with an example beginning
// `Version: FortiSwitch-224E v7.4.0,build0752,230410`. (Phase 0017's
// verification found the opposite for FortiOS — no `get system status` page
// exists for FortiGate at all, and the "System time" line appears only in a
// community KB.)
const switchStatusCommand = "get system status"

// switchVersionPattern reads the model line.
//
// It matches the product word only. Fortinet's own example carries the model
// (`FortiSwitch-224E`) and the release after it, and pinning either would make
// this driver refuse next year's model or next quarter's firmware — a refusal
// that has nothing to do with the question being asked, which is only "is this
// a FortiSwitch and not a FortiGate".
var switchVersionPattern = regexp.MustCompile(`(?im)^\s*Version\s*:\s*FortiSwitch`)

// open dials the switch, reads past its login banner, and refuses a unit that
// is not one.
func (d *SwitchDriver) open(ctx context.Context, ep device.Endpoint) (*cliSession, error) {
	if d.dialer == nil {
		// The declaration registered in device.Shipped() (see init below) has
		// no way to reach a device. Refusing here rather than panicking keeps a
		// misconfiguration an error a proxy reports instead of a crash.
		return nil, errors.New("auth/target/device/fortios: this driver is a declaration only; build one with NewSwitch to reach a device")
	}
	shell, err := d.dialer.Shell(ctx, ep)
	if err != nil {
		return nil, err
	}
	s, err := openCLI(ctx, shell)
	if err != nil {
		_ = shell.Close()
		return nil, err
	}
	// FortiSwitchOS has no virtual domains, so cliSession.vdomMode stays at its
	// zero value and every table helper takes the unpartitioned path: no
	// `config global` wrapper to enter, and one level of nesting to unwind.
	// That is the correct shape here rather than a default that happens to
	// work — Fortinet's documented `get system status` output for a FortiSwitch
	// carries no "Virtual domain configuration" line at all.
	if err := d.confirmSwitch(ctx, s); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// confirmSwitch refuses a unit that did not say it is a FortiSwitch.
//
// It is read ONCE PER SESSION and before anything is configured, for the reason
// the FortiGate driver reads its VDOM mode there: every operation this driver
// performs is wrong on the wrong unit, and not only creation — `delete` and
// `show` on a FortiGate's administrator table are a sweep of somebody's
// firewall.
//
// An UNREADABLE answer is refused too. A unit that will not say what it is, is
// not a unit to create a privileged administrator on: the fail-closed direction
// costs a denial, and the other direction costs an account on the wrong device.
func (d *SwitchDriver) confirmSwitch(ctx context.Context, s *cliSession) error {
	out, err := s.send(ctx, switchStatusCommand)
	if err != nil {
		return fmt.Errorf("auth/target/device/fortios: read the unit's identity: %w", err)
	}
	if err := checkOutput("read the unit's identity", out); err != nil {
		return err
	}
	if !switchVersionPattern.MatchString(out) {
		return fmt.Errorf("%w: `%s` did not report a FortiSwitch version line, and this driver's commands "+
			"are valid on a FortiGate too — so a unit that will not identify itself is one an "+
			"administrator must not be created on", ErrNotAFortiSwitch, switchStatusCommand)
	}
	return nil
}

// abandon backs out of a failed sequence.
//
// It is the FortiGate's minus the schedule half, and it is a separate function
// rather than a shared one for exactly that reason: sending `config firewall
// schedule onetime` to a FortiSwitch is an unknown command, so a shared
// backstop would spend two refused commands per rollback pretending to clean up
// an object class this platform does not have.
func (d *SwitchDriver) abandon(ctx context.Context, s *cliSession, name string) {
	// `abort` discards an uncommitted configuration block outright. Its own
	// failure is swallowed: the session is being denied either way, and what it
	// could not undo is what the reaper is for.
	_, _ = s.send(ctx, "abort")
	_, _ = s.send(ctx, "end")
	for _, st := range s.enterAdminTable() {
		_, _ = s.send(ctx, st.command)
	}
	_, _ = s.send(ctx, "delete "+quote(name))
	for _, st := range s.leaveAdminTable() {
		_, _ = s.send(ctx, st.command)
	}
}

// switchBuiltinProfile is the only access profile FortiSwitchOS documents as
// built in.
//
// "The super_admin administrator is the administrative account that the primary
// administrator should have to log into the FortiSwitch unit. The profile
// cannot be deleted or modified to ensure there is always a method to
// administer the FortiSwitch unit. This user profile has access to all
// components of the system, including the ability to add and remove other
// system administrators."
const switchBuiltinProfile = builtinSuperAdmin

// SwitchAcceptsProfile reports whether an access profile can be used on a
// FortiSwitch, so a caller holding a FLEET-WIDE setting can tell before it
// hands one over.
//
// It exists for internal/auth/target's registry, which has exactly that
// problem: `auth.target.ephemeral_account.access_profile` is one value for
// every platform a proxy serves, and the FortiOS built-ins that most estates
// have configured do not exist here. See the call site for why the answer is
// to build this driver without a default rather than to refuse at startup.
func SwitchAcceptsProfile(profile string) error {
	if profile == "" {
		return nil
	}
	if err := validateProfile(profile); err != nil {
		return err
	}
	return checkSwitchProfile(profile)
}

// checkSwitchProfile refuses a FortiOS built-in on a FortiSwitch.
//
// `prof_admin` and `super_admin_readonly` are FortiOS profiles and appear in no
// FortiSwitchOS source. A proxy configured for a FortiGate estate that acquires
// its first switch will have one of them in
// `auth.target.ephemeral_account.access_profile`, and the failure without this
// check is the bad one: `set accprofile` is refused half way through a sequence
// that has already created the administrator entry, so a configuration mistake
// becomes a rollback to perform on a customer's switch.
//
// Only those two names are refused. A custom profile is the customer's to scope
// and this driver has no way to know what is in it — and a customer who has
// genuinely built a FortiSwitch profile named `prof_admin` gets a clear refusal
// naming why, which is better than the device's mid-sequence one.
func checkSwitchProfile(profile string) error {
	switch profile {
	case builtinProfAdmin, builtinSuperAdminReadOnly:
		return fmt.Errorf("%w: %q is a FortiOS access profile and FortiSwitchOS does not have it; "+
			"this platform documents one built-in, %q, and any narrower scope is a custom profile "+
			"built on the switch",
			errInvalidValue, profile, switchBuiltinProfile)
	default:
		return nil
	}
}

// RegisterSwitch adds the FortiSwitchOS driver to a registry.
func RegisterSwitch(r *device.Registry, opts SwitchOptions) error {
	d, err := NewSwitch(opts)
	if err != nil {
		return err
	}
	return r.Register(d)
}

// The declaration this repository ships, for device.CheckShipped. See the
// FortiGate driver's init for why a declaration with no dialer is the right
// thing to register.
func init() {
	if err := device.Shipped().Register(&SwitchDriver{}); err != nil {
		panic(err)
	}
}
