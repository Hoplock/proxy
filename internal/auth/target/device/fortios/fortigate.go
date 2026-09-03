// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package fortios

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/hoplock/proxy/internal/auth/target/device"
	"github.com/hoplock/proxy/internal/control"
)

// PlatformFortiGate is the value a route's `platform` parameter carries for a
// FortiGate (control.ParamPlatform). It is policy somebody else wrote, so it is
// stable across releases.
const PlatformFortiGate = "fortigate"

// FieldVDOM is the route field naming the virtual domain an administrator is
// scoped to (control.ParamDeviceFieldPrefix + "vdom", contract v3.1).
//
// It is a FIELD rather than part of the endpoint because a VDOM is a partition
// of one device and not a device: `fgt-edge-1:22` is what DNS resolves, what
// the host key is pinned to, and what the reaper sweeps, and one unit holding
// twelve virtual domains is still one unit to every one of those. What the
// field changes is the SCOPE of the administrator created on it, which is
// exactly what a route parameter is for.
//
// Absent, the administrator is created at global scope. That is the more
// privileged of the two and it is nobody's default by accident: it is what a
// proxy administering the whole unit — the shape phase 0014 was written for —
// keeps getting on a unit that has since been partitioned.
const FieldVDOM = "vdom"

// There is deliberately NO default access profile, and this comment is where
// the reasoning lives because the absence is the decision (phase 0015).
//
// Phase 0014 shipped `DefaultAccessProfile = "super_admin_readonly"` and
// defended it as "the most restrictive built-in that cannot be edited out from
// under us", ranked against `prof_admin_readonly` as the narrower-but-editable
// alternative. Verification removed the comparison: Fortinet documents THREE
// built-in profiles — `super_admin` (immutable), `prof_admin` (editable) and
// `super_admin_readonly` (immutable, assignable, and absent from the GUI's
// profile list, which is why it is easy to miss) — and no Fortinet source
// contains the string `prof_admin_readonly` at all. The default was chosen by
// comparing a real profile with one that appears not to exist.
//
// What is left of the old rationale is true and not enough. `super_admin_readonly`
// is immutable and reads everything, but:
//
//   - it is READ-ONLY, and a read-only account is wrong for most of PLAN §13's
//     UC1, whose whole point is changing the device;
//   - from FortiOS 7.4.x an administrator holding it CANNOT RUN `diagnose`
//     COMMANDS — disabled under CLI permits — so even the read-only
//     troubleshooting session it was meant to serve is narrower than it looks,
//     and Fortinet's own answer is a custom profile;
//   - it is the GLOBAL read-only profile. A per-VDOM administrator "must use
//     either the `prof_admin` administrator profile, or a custom profile", so
//     on a multi-VDOM unit it does not fit at all (see errMultiVDOM).
//
// A default that is wrong for the common case, quietly weaker than advertised
// on 7.4+, and inapplicable on a whole class of unit is not a safe default; it
// is a guess with a comment. So the profile is REQUIRED: it comes from the
// route (device.CreateRequest.Profile) or from proxy configuration
// (`auth.target.ephemeral_account.access_profile`), and an account is never
// created without one. WHICH profile a route gets is phase 0018's vocabulary
// and phase 0019's to apply; requiring one now is what stops that phase from
// inheriting a default nobody chose.

// placeholderSecretLen is the length of the throwaway password an account is
// created with.
//
// The account exists for a moment before InstallCredential runs, and a FortiOS
// administrator with NO password set can be logged into with an empty one. The
// device.Driver seam splits creation from the credential, so that moment is
// unavoidable; what is avoidable is it being a usable moment. The throwaway is
// generated here, never returned, never logged, and overwritten by the real
// credential a step later.
const placeholderSecretLen = 40

// Options configure a FortiOS driver.
type Options struct {
	// Platform overrides the platform name. Empty means PlatformFortiGate.
	// It exists because FortiSwitchOS speaks nearly the same CLI, and the
	// standalone switch driver is expected to be this driver under another
	// name (see the queued prompts).
	Platform string
	// Dialer opens the privileged CLI session. Required.
	Dialer device.ShellDialer
	// AccessProfile is the profile created administrators are given when the
	// route does not name one. There is no default (see above): a driver built
	// without it serves only routes that carry their own profile, and refuses
	// the rest rather than inventing a scope for a privileged account.
	AccessProfile string
}

// Driver is the FortiOS implementation of device.Driver.
type Driver struct {
	platform string
	dialer   device.ShellDialer
	profile  string
}

var _ device.Driver = (*Driver)(nil)

// New returns a FortiOS driver.
func New(opts Options) (*Driver, error) {
	if opts.Dialer == nil {
		return nil, errors.New("auth/target/device/fortios: a driver needs a way to reach the device")
	}
	d := &Driver{
		platform: opts.Platform,
		dialer:   opts.Dialer,
		profile:  opts.AccessProfile,
	}
	if d.platform == "" {
		d.platform = PlatformFortiGate
	}
	// An empty profile is allowed HERE and refused at create time. A proxy may
	// legitimately configure none because every route it serves names its own
	// (which is where phase 0019 takes this), and refusing to build the driver
	// would turn that into a startup failure. What must not happen is an
	// account created without one, and CreateAccount is where that is decided.
	if d.profile != "" {
		if err := validateProfile(d.profile); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// Platform implements device.Driver.
func (d *Driver) Platform() string { return d.platform }

// Capabilities implements device.Driver.
//
// Every value here was checked against Fortinet's own documentation — read
// directly, not summarised — and docs/FORTIOS-DOC-VERIFICATION.md carries the
// page, the versions and the wording behind each one. Two are worth reading
// twice.
//
// EnforcesExpiry is TRUE as of phase 0017, and what it rests on is a decision
// about what the bit MEANS rather than a new fact about the platform.
//
// The facts were settled in phase 0015 and are unchanged: `config system admin`
// has `set schedule {string}`; it names a `config firewall schedule onetime`
// entry carrying an absolute `set end {hh:mm yyyy/mm/dd}`; FortiOS enforces it
// at authentication, and Fortinet's KB shows the denial logged as
// `reason="out_of_schedule"`. Phase 0014 said none of that existed, phase 0015
// established that it does and declined to take it, and this phase takes it.
//
// WHY DENYING LOGIN MEETS THE BAR. The field says the DEVICE ends the account's
// usefulness whether or not this proxy is alive. The nearest thing in this
// system to compare it with is not a firewall at all: it is OpenSSH's
// `expiry-time` restriction in authorized_keys (PLAN §5.1), which is what
// `target-enforced` has meant on the POSIX path since D6. That also refuses new
// authentications, also leaves an established session running, and also leaves
// the credential object on the target for the reaper to remove. The contract is
// therefore already written around these semantics, and FortiOS's mechanism is
// the same shape as the one the posture was named for.
//
// WHAT IT DOES NOT DO, stated here because the bit alone would overstate it —
// and carried to the operator in ExpiryMechanism rather than left in this
// comment, because a declaration nobody can read from the audit record is a
// declaration nobody can check:
//
//   - It does not remove the account. The reaper is still the removal path and
//     PersistsAcrossReload is untouched.
//   - It is undocumented whether an ALREADY-ESTABLISHED session survives its
//     administrator's window closing. Nothing here models an answer; it is the
//     first item on this phase's hardware list. Ending the SESSION at its
//     deadline is a separate mechanism and a separate phase in any case.
//   - It is undocumented whether every authentication path honours the
//     schedule, and the verification pass narrowed this rather than closing it.
//     What is established: the field is defined ONCE PER ADMINISTRATOR, in the
//     same `config system admin` table that holds `password`,
//     `ssh-public-key1`..`3`, `remote-auth` and `two-factor`, with no
//     per-credential variant in any supported release — so there is nowhere for
//     a per-credential exception to be expressed. What is NOT established: the
//     only `reason="out_of_schedule"` denial Fortinet publishes is a GUI/HTTPS
//     login, not an SSH one of either kind. So the coverage this driver depends
//     on is an inference from the field's shape, and it is the DECISIVE item on
//     the hardware list: this declaration is worth what it says only if the
//     window closes every door into the account rather than one of them. The
//     inference is carried to the operator in ExpiryMechanism rather than left
//     here, because a caveat only the driver's source knows is a caveat nobody
//     acts on.
//
// The consequences are the ones the declaration implies. A route asking for
// control.ExpiryPostureTargetEnforced on FortiOS is now SERVED rather than
// skipped; CreateRequest.Lifetime is rendered rather than discarded; and a
// session that provisions under that posture writes TWO objects on the
// customer's unit, which is why teardown removes both and why the reaper
// carries a residue sweep (device.ResidueSweeper) for the one that can outlive
// the other.
//
// PersistsAcrossReload is TRUE, and D13 had to be amended for it. FortiOS has no
// runtime-only configuration plane: under the default `config system global` /
// `set cfg-save automatic`, `end` writes the change to flash immediately, and the
// alternatives (`manual`, `revert`) are DEVICE-WIDE settings that change how
// every other change on that unit behaves. D13's original wording assumed a
// Hoplock driver could always decline to persist — "a reload is then a free
// reaper" — and on the very platform D13 named as its example, it cannot. The
// honest declaration is the true one; docs/PLAN.md now says a shipped driver
// may declare persistence when the PLATFORM leaves it no choice, and the
// provisioner records it on every session this driver serves.
func (d *Driver) Capabilities() device.Capabilities {
	return device.Capabilities{
		MaxAccountNameLen: maxAccountNameLen,
		EnforcesExpiry:    true,
		ExpiryMechanism: "FortiOS refuses the administrator's next authentication once the window " +
			"closes: `set schedule` on the administrator names a `config firewall schedule onetime` " +
			"entry carrying an absolute `set end`, and the denial is logged as " +
			"`reason=\"out_of_schedule\"`. These are the semantics OpenSSH's `expiry-time` has on " +
			"the POSIX path. Three limits, stated because a posture of `target-enforced` would " +
			"otherwise be read as more than this is. It does NOT delete the account — the orphan " +
			"reaper is still what removes it. Fortinet documents nothing either way about a session " +
			"already established when the window closes, so a live session may outlive the deadline. " +
			"And the only denial Fortinet publishes is a GUI/HTTPS login: that the schedule also " +
			"covers SSH — with a password or a public key, which is how this proxy connects — " +
			"follows from the field being defined per-administrator rather than per-credential, and " +
			"is UNTESTED on hardware.",
		PersistsAcrossReload: true,
		PersistenceReason: "FortiOS has no runtime-only configuration plane: under the default " +
			"`config system global` / `set cfg-save automatic` an administrator is written to " +
			"flash when the configuration block ends, and the alternatives (`manual`, `revert`) " +
			"are device-wide settings governing every change on the unit rather than a per-command " +
			"choice this driver could make. A created administrator therefore survives a reload, " +
			"and the orphan reaper — not a reload — is what removes it.",
		CredentialKinds: []control.CredentialKind{
			control.CredentialKindPassword,
			control.CredentialKindPublicKey,
		},
		PinsSourceAddress: true,
		Fields: []device.Field{{
			Name: FieldVDOM,
			Description: "the virtual domain a VDOM-scoped administrator is created in; " +
				"absent, a unit running virtual domains gets a global administrator",
		}},
	}
}

// step is one line of a command sequence.
//
// The sequences below are TABLES rather than procedural code because D13 defers
// a declarative driver document that must eventually be able to express them.
// A format extracted from a table describes what the table already does; a
// format retrofitted against a function describes what somebody hoped it did.
type step struct {
	// command is the line sent to the device.
	command string
	// label names the step in an error message, because the command itself is
	// sometimes credential material.
	label string
	// secret says neither this command nor its output may reach a log or an
	// error under any circumstances.
	secret bool
	// notFoundIsSuccess says "there is nothing there" is what this step wanted,
	// which is how removal stays idempotent.
	notFoundIsSuccess bool
}

// CreateAccount implements device.Driver.
//
// It verifies non-existence first and NEVER adopts (D13, PLAN §5.3). FortiOS's
// `edit` is idempotent — it opens an existing entry as readily as it creates a
// new one — which is precisely the behaviour that must not be relied on here: on
// a constrained platform an existing name is plausibly another live session's,
// and adopting it means two sessions sharing an account whose first teardown
// removes the other's access.
func (d *Driver) CreateAccount(ctx context.Context, req device.CreateRequest) (*device.Account, error) {
	if err := validateAccountName(req.Name); err != nil {
		return nil, err
	}
	profile := d.profile
	if req.Profile != "" {
		profile = req.Profile
	}
	if profile == "" {
		// No default, and this is where that decision bites (see the comment
		// above DefaultAccessProfile's replacement). It is a plain error rather
		// than device.ErrUnsupported: the platform is perfectly capable of
		// scoping an administrator, this proxy was simply never told which
		// scope to use, and a rung skipped over a configuration gap would serve
		// the session on a credential the server ranked lower.
		return nil, errors.New("auth/target/device/fortios: no access profile: " +
			"an administrator's scope must be named by the route or by " +
			"`auth.target.ephemeral_account.access_profile`, because no FortiOS built-in " +
			"is a safe default (`super_admin_readonly` cannot run `diagnose` from 7.4.x " +
			"and does not fit a per-VDOM account)")
	}
	if err := validateProfile(profile); err != nil {
		return nil, err
	}
	vdom, err := requestedVDOM(req.Fields)
	if err != nil {
		return nil, err
	}
	if vdom != "" {
		if err := checkVDOMProfile(profile); err != nil {
			return nil, err
		}
	}

	var trust string
	if req.SourceAddress != "" {
		var err error
		if trust, err = trustHost(req.SourceAddress); err != nil {
			return nil, err
		}
	}
	// A lifetime means the DEVICE is to hold this account's deadline, and on
	// this platform that is a second object (schedule.go). The provisioner sets
	// it only for a route that asked for control.ExpiryPostureTargetEnforced,
	// so the test here is not "did anyone mention a lifetime" but "was this
	// driver asked to render one" — a proxy-enforced route reaches this line
	// with zero and gets exactly the single-object session phase 0014 shipped.
	//
	// The NAME is checked before anything is dialled, because the account and
	// its schedule share one and the schedule's limit is the shorter of the
	// two: a name this unit would take as an administrator and refuse as a
	// schedule must fail before the administrator exists, not between the two
	// objects.
	expiring := req.Lifetime > 0
	if expiring {
		if err := validateScheduleName(req.Name); err != nil {
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

	if vdom != "" {
		// Checked BEFORE anything is created, not read off a failed
		// `set vdom`. A VDOM the route names and the unit does not have is an
		// outage-class denial (D13) either way; the difference is whether the
		// denial leaves a half-created privileged administrator on a customer's
		// firewall for the rollback to catch. The check is not a guarantee —
		// the VDOM can be deleted between the read and the write — so
		// `set vdom` failing is still a failed attempt, and both paths are
		// closed.
		if err := d.checkVDOMExists(ctx, s, vdom); err != nil {
			return nil, err
		}
	}

	exists, err := d.accountExists(ctx, s, req.Name)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("%w: %q is already an administrator on %s",
			device.ErrAccountExists, req.Name, req.Host)
	}

	if expiring {
		// The schedule table is checked for the same name, and a hit is
		// reported as the SAME collision the administrator table would be.
		// The two objects share a name, so a taken schedule means a taken
		// token: the provisioner draws another and retries, which is the one
		// response that does not either adopt a stranger's object or fail a
		// session over a coincidence.
		taken, err := d.listSchedules(ctx, s, req.Name)
		if err != nil {
			return nil, err
		}
		for _, name := range taken {
			if name == req.Name {
				return nil, fmt.Errorf("%w: %q is already a one-time schedule on %s",
					device.ErrAccountExists, req.Name, req.Host)
			}
		}

		deviceNow, ok := d.readDeviceClock(ctx, s)
		if !ok {
			// Refused rather than computed from this proxy's clock, and this
			// is the fail-closed half of reading the window off the device
			// (see systemTimePattern). `set end` is an absolute LOCAL datetime
			// on the unit: writing one from a clock in another timezone either
			// locks the account out for hours or holds it open for hours past
			// its deadline, and the second failure is silent and is the audit
			// record claiming a deadline that does not exist. It is NOT
			// device.ErrUnsupported — the platform can do this and so can this
			// driver; this unit did not say what time it is, which fails the
			// attempt rather than walking the session down to a weaker rung.
			return nil, fmt.Errorf("%w: neither `%s`/`%s` nor `%s` reported a readable clock, and a one-time "+
				"schedule's end is an absolute datetime in the unit's own local time — "+
				"rendering one from this proxy's clock could hold the account open past its deadline",
				ErrDeviceRefused, executeDateCommand, executeTimeCommand, vdomStatusCommand)
		}
		start, end, err := scheduleWindow(deviceNow, req.Lifetime)
		if err != nil {
			return nil, err
		}
		if err := d.createSchedule(ctx, s, req.Name, start, end); err != nil {
			// Nothing has been created in the administrator table yet, and the
			// schedule's own sequence rolls itself back through run's
			// stop-at-first-failure plus the abandon below, so the unit is left
			// as it was found.
			d.abandon(ctx, s, req.Name)
			return nil, err
		}
	}

	steps := append(s.enterAdminTable(),
		step{command: "edit " + quote(req.Name), label: "create the administrator"},
	)
	if vdom != "" {
		// Fortinet's recipe sets the virtual domain first, before the profile
		// and the credential, and the order is kept: on a platform that reports
		// failure as text, a sequence that matches the published one is a
		// sequence whose failures somebody can look up.
		steps = append(steps, step{command: "set vdom " + quote(vdom), label: "scope the administrator to its virtual domain"})
	}
	steps = append(steps, step{command: "set accprofile " + quote(profile), label: "set the access profile"})
	if expiring {
		// The REFERENCE, and the reason the schedule is created first: naming
		// an entry that is not there is a dangling reference the device
		// refuses, which is also what makes a schedule written into a scope
		// this administrator cannot see fail loudly instead of silently
		// (schedule.go).
		steps = append(steps, step{command: "set schedule " + quote(req.Name), label: "bound the administrator to its expiry schedule"})
	}
	if trust != "" {
		steps = append(steps,
			step{command: "set trusthost1 " + trust, label: "pin the administrator to the proxy's address"},
			// Both families, always. `trusthost1` and `ip6-trusthost1` are
			// parallel restrictions with independent defaults, and the IPv6 one
			// defaults to `::/0`. Setting only the IPv4 field leaves the
			// account reachable from any IPv6 address on a unit with IPv6
			// management access — a pin the provisioner believes it applied and
			// the device does not have.
			step{command: "set ip6-trusthost1 " + closedIPv6TrustHost, label: "close the administrator to IPv6"},
		)
	}
	steps = append(steps,
		step{command: "set password " + quote(placeholder), label: "set a placeholder password", secret: true},
		step{command: "next", label: "commit the administrator"},
	)
	steps = append(steps, s.leaveAdminTable()...)

	if err := d.run(ctx, s, steps); err != nil {
		// `abort` leaves the configuration block WITHOUT applying it, so a
		// sequence that failed before `next` commits nothing at all. The
		// delete afterwards is for the case where it failed after: belt and
		// braces, on a device where a half-created administrator is a standing
		// privileged account.
		d.abandon(ctx, s, req.Name)
		return nil, err
	}

	return &device.Account{
		Name:    req.Name,
		Profile: profile,
		// FortiOS does not record when an administrator was created, so this
		// stays zero and the reaper reads it as "age unknown" (device.Account).
	}, nil
}

// InstallCredential implements device.Driver.
func (d *Driver) InstallCredential(ctx context.Context, req device.CredentialRequest) error {
	if err := validateAccountName(req.Name); err != nil {
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
		return device.Unsupported(d.platform, fmt.Sprintf("install a %q credential", req.Kind))
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
	if err := d.run(ctx, s, steps); err != nil {
		d.abandon(ctx, s, req.Name)
		return err
	}
	return nil
}

// RemoveAccount implements device.Driver, and removes BOTH objects a session
// can leave on the unit: the administrator, and the one-time schedule that
// carried its deadline (phase 0017).
//
// It is IDEMPOTENT because teardown runs on the normal path, on error, on
// panic, on signal, and from the reaper (PLAN §5.1): an administrator that is
// already gone is the outcome this wanted. A device it cannot reach is a
// different answer — a retryable failure, which the reaper finds again.
func (d *Driver) RemoveAccount(ctx context.Context, req device.RemoveRequest) error {
	if err := validateAccountName(req.Name); err != nil {
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
	if err := d.run(ctx, s, append(steps, s.leaveAdminTable()...)); err != nil {
		return err
	}

	// THE SECOND OBJECT, and it is removed second on purpose. Fortinet's
	// `object is in use` refusal — which cli.go already matches — suggests a
	// schedule an administrator still references may not be deletable, and
	// whether it actually is, is on this phase's hardware list. Removing the
	// administrator first makes the question moot: by the time the schedule is
	// deleted nothing references it. Getting the order the other way round
	// would leave a removal that works on some units and not others, and the
	// units it failed on would be the ones with a live privileged account still
	// on them.
	//
	// It runs for EVERY account, not only the ones this process created with a
	// schedule: teardown does not know which posture created what it is
	// removing, and the reaper knows even less — the account may be the
	// leftover of a session in a process that no longer exists. See
	// removeSchedule.
	if err := d.removeSchedule(ctx, s, req.Name); err != nil {
		// Named separately from the administrator, because the two outcomes
		// need different responses and one error would hide which happened:
		// the administrator IS gone, and what is left behind is a schedule that
		// grants no access to anything. The residue sweep is what finds it
		// again (schedule.go).
		return fmt.Errorf("auth/target/device/fortios: the administrator %q was removed but its %s was not: %w",
			req.Name, scheduleResidueKind, err)
	}
	return nil
}

// ListAccounts implements device.Driver.
//
// The prefix is the caller's and is never widened: on a shared device, one
// proxy's sweep selecting another proxy's accounts kills live sessions, and this
// argument is the whole defence against it.
func (d *Driver) ListAccounts(ctx context.Context, req device.ListRequest) ([]device.Account, error) {
	if req.Prefix == "" {
		return nil, errors.New("auth/target/device/fortios: enumerating without a prefix would select accounts this proxy does not own")
	}

	s, err := d.open(ctx, req.Endpoint)
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.Close() }()

	return d.listAccounts(ctx, s, req.Prefix)
}

// ErrMultiVDOM means the unit would not say which shape it is.
//
// The NAME is kept from phase 0015, when it meant "this unit is running virtual
// domains and this driver does not administer one" — a sentence that is no
// longer true, because phase 0016 administers those units. What survives is the
// narrower refusal 0015's fail-closed reasoning still earns: a `get system
// status` whose virtual-domain line cannot be parsed, or a configuration that
// is none of the three documented values. A version or model nobody has asked
// about is not a unit to guess at, and the direction that does not create
// privileged accounts on a hunch is refusal.
//
// It is NOT device.ErrUnsupported, and the distinction is the security half of
// this refusal. ErrUnsupported means the PLATFORM cannot, which makes the
// ladder rung unsatisfiable and walks the proxy down to a credential the server
// ranked lower — a silent downgrade triggered by the shape of one unit. This is
// an ATTEMPT that fails: the route is right, the platform is right, and this
// build cannot vouch for this device. D13's rule is that an unsupported
// configuration is an outage-class denial, never a best-effort attempt.
var ErrMultiVDOM = errors.New("auth/target/device/fortios: the unit did not report a virtual domain configuration this driver recognises")

// vdomStatusCommand asks the unit whether virtual domains are enabled.
//
// `get system status` is a READ. It is sent once per CLI session, before
// anything is configured, because every operation this driver performs is wrong
// on a multi-VDOM unit and not only creation: `config system admin` at the top
// level of such a unit is not the table Fortinet's own recipe edits, so `edit`,
// `delete` and `show` are all pointed at something this driver cannot vouch
// for.
const vdomStatusCommand = "get system status"

// vdomConfigurationPattern reads the answer.
//
// Fortinet documents exactly this line and exactly this way of reading it:
// "Enter the command 'get system status' or 'get sys status | grep -n Virtual'.
// The output will display the 'Virtual domain configuration' status", with
// `disable` meaning no VDOMs and `multiple` meaning multi-VDOM mode
// (community.fortinet.com, "How to check for VDOM Enablement on a FortiGate").
// Split-task mode reports its own value, which this driver also declines rather
// than assumes it can serve.
var vdomConfigurationPattern = regexp.MustCompile(`(?im)^\s*Virtual domain configuration\s*:\s*(\S+)\s*$`)

// vdomMode is the unit shape this session is talking to.
//
// Fortinet documents `disable` and `multiple` as the values of the "Virtual
// domain configuration" line, and the Administration Guide carries split-task
// mode as a third shape of the same feature — two fixed VDOMs, a management one
// and a traffic one, with its own "Create per-VDOM administrators" procedure
// identical to the multi-VDOM recipe. So the two VDOM shapes are served by one
// code path and the third value is "the unit is not partitioned".
type vdomMode string

const (
	vdomModeDisabled  vdomMode = "disable"
	vdomModeMultiple  vdomMode = "multiple"
	vdomModeSplitTask vdomMode = "split-task"
)

// partitioned reports whether the administrator table lives inside
// `config global` on this unit.
//
// This is the ONE question the rest of the driver asks about VDOM mode, and it
// is a method rather than a comparison scattered through the command tables so
// that a future third shape changes one line here instead of five sequences.
func (m vdomMode) partitioned() bool {
	return m == vdomModeMultiple || m == vdomModeSplitTask
}

// readStatus asks the unit which shape it is and what time it thinks it is,
// and refuses a shape this driver has not been written for.
//
// Phase 0014's command sequences were written from the single-VDOM recipe and
// are wrong on a unit with virtual domains in three ways at once, all
// documented: the administrator table lives inside `config global` there,
// `set vdom` is required for a VDOM-scoped account, and cliSession.Close's
// unwinding is one level shallower than that nesting needs. Phase 0015 refused
// the whole shape rather than mis-editing it; phase 0016 sends the documented
// sequence instead, and what is left of the refusal is narrower: a status line
// this pattern cannot read, or a virtual-domain configuration that is none of
// the three values above.
//
// An UNREADABLE answer stays refused, and stays refused for phase 0015's
// reason. The driver was once certain about a device shape it had never asked
// about; a version or model whose status output this pattern does not match is
// another shape nobody has asked about, and the fail-closed direction is the one
// that does not create privileged accounts on a hunch.
//
// It reads the unit's CLOCK from the same output, and the two answers are
// deliberately not held to the same standard. The VDOM mode decides which
// administrator table every command in the session addresses, so an unreadable
// one refuses the session. The clock is needed only by a route that asked the
// device to hold a deadline, so an unreadable one is remembered as absent and
// refuses THAT — a unit whose status output this driver cannot fully parse
// still serves every route that does not need a schedule.
func (d *Driver) readStatus(ctx context.Context, s *cliSession) error {
	readAt := time.Now()
	out, err := s.send(ctx, vdomStatusCommand)
	if err != nil {
		return fmt.Errorf("auth/target/device/fortios: read the unit's VDOM mode: %w", err)
	}
	if err := checkOutput("read the unit's VDOM mode", out); err != nil {
		return err
	}
	mode, err := parseVDOMMode(out)
	if err != nil {
		return err
	}
	s.vdomMode = mode
	if t, ok := parseDeviceTime(out); ok {
		s.deviceTime, s.readAt = t, readAt
	}
	return nil
}

// parseVDOMMode reads the virtual-domain line.
func parseVDOMMode(out string) (vdomMode, error) {
	m := vdomConfigurationPattern.FindStringSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("%w: `%s` did not report a virtual domain configuration, so this driver cannot tell which administrator table it would be editing",
			ErrMultiVDOM, vdomStatusCommand)
	}
	switch mode := vdomMode(strings.ToLower(m[1])); mode {
	case vdomModeDisabled, vdomModeMultiple, vdomModeSplitTask:
		return mode, nil
	default:
		return "", fmt.Errorf("%w: the unit reports virtual domain configuration %q, which is none of %q, %q or %q",
			ErrMultiVDOM, mode, vdomModeDisabled, vdomModeMultiple, vdomModeSplitTask)
	}
}

// systemTimePattern matches the unit's clock in `get system status` output.
//
// It is the FALLBACK, and it used to be the only source. Phase 0017 read the
// device clock here because `get system status` is already sent once per
// session and costs nothing extra; the verification pass found that choice
// weakly sourced — Fortinet publishes no `get system status` page for
// FortiGate at all, and the "System time" line appears only in a community KB,
// against two units, rendered in C `asctime` shape with no timezone or offset.
// So the primary source is now `execute date` / `execute time`, which the
// Administration Guide documents in every supported release (see
// executeDateCommand). This stays because it is free and because a unit that
// answers it and not the other is still a unit whose clock is known.
var systemTimePattern = regexp.MustCompile(`(?im)^\s*System time\s*:\s*(.+?)\s*$`)

// deviceTimeLayouts are the renderings this driver will read a device clock in.
//
// The first is the C `asctime` shape the KB shows `get system status` printing;
// the others are there because a clock is worth reading in whatever plausible
// form it arrives, and a driver that refuses over a separator has refused a
// device-enforced expiry on a unit that told it exactly what it needed to know.
//
// NONE of them carries a zone, and neither does any output FortiOS is
// documented to produce: the unit's timezone lives in `config system global` /
// `set timezone`, and the schedule is evaluated against that same local clock
// ("the configured schedule will be based on the firewall's local time
// configured under 'config system global'"). So the value IS the device's local
// wall clock; it is parsed into UTC and used only for arithmetic against
// itself, and no zone is ever derived from it.
var deviceTimeLayouts = []string{
	"Mon Jan 2 15:04:05 2006",
	"Jan 2 15:04:05 2006",
	"2006-01-02 15:04:05",
	"2006/01/02 15:04:05",
}

// The commands that read the unit's clock, and the shapes they answer in.
//
// `execute date` and `execute time` are documented in the Administration Guide
// in 7.0.17, 7.2.11, 7.4.9, 7.6.6 and 8.0.0 — the 7.6 and 8.0 pages print the
// output verbatim:
//
//	# execute date
//	current date is: 2024-07-23
//	# execute time
//	current time is: 14:17:00
//	last ntp sync:Tue Jul 23 13:25:21 2024
//
// They are two commands rather than one, and they are sent ON DEMAND rather
// than when the session opens: only a route that asked the device to hold a
// deadline needs a clock, and every other session should not pay two round
// trips for something it will not read.
//
// The `last ntp sync` line is deliberately ignored. It is the time of a
// SYNCHRONISATION, not the time now, and reading it as the clock would put a
// window minutes or days in the past on any unit whose NTP is unhealthy — which
// is exactly the unit whose clock is worth distrusting.
const (
	executeDateCommand = "execute date"
	executeTimeCommand = "execute time"
)

var (
	executeDatePattern = regexp.MustCompile(`(?im)^\s*current date is\s*:\s*(\d{4})[-/](\d{2})[-/](\d{2})\s*$`)
	executeTimePattern = regexp.MustCompile(`(?im)^\s*current time is\s*:\s*(\d{2}):(\d{2}):(\d{2})\s*$`)
)

// readDeviceClock asks the unit what time it is, preferring the documented
// commands and falling back to what `get system status` said when the session
// opened.
//
// It returns false when neither answered, and the caller refuses the route
// rather than reaching for this proxy's clock. That direction is the whole
// point: `set end` is an absolute datetime in the unit's local time, so a
// window computed from the wrong clock is wrong by the offset between them —
// in one direction an account that cannot log in, in the other an account the
// device honours long past the deadline its audit record claims.
func (d *Driver) readDeviceClock(ctx context.Context, s *cliSession) (time.Time, bool) {
	dateOut, dateErr := s.send(ctx, executeDateCommand)
	timeOut, timeErr := s.send(ctx, executeTimeCommand)
	if dateErr == nil && timeErr == nil {
		if t, ok := parseExecutedClock(dateOut, timeOut); ok {
			return t, true
		}
	}
	// The reading taken from `get system status` when the session opened,
	// carried forward by the elapsed time since (cliSession.deviceNow).
	return s.deviceNow()
}

// parseExecutedClock assembles the two answers into one wall clock.
func parseExecutedClock(dateOut, timeOut string) (time.Time, bool) {
	date := executeDatePattern.FindStringSubmatch(dateOut)
	clock := executeTimePattern.FindStringSubmatch(timeOut)
	if date == nil || clock == nil {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02 15:04:05",
		fmt.Sprintf("%s-%s-%s %s:%s:%s", date[1], date[2], date[3], clock[1], clock[2], clock[3]))
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// parseDeviceTime reads the unit's wall clock, and reports whether it could.
func parseDeviceTime(out string) (time.Time, bool) {
	m := systemTimePattern.FindStringSubmatch(out)
	if m == nil {
		return time.Time{}, false
	}
	// `date`'s day field is space-padded, so "Sep  3" arrives with two spaces
	// and Go's reference layout has one. Collapsing runs of whitespace is what
	// makes one layout read both.
	value := strings.Join(strings.Fields(m[1]), " ")
	for _, layout := range deviceTimeLayouts {
		if t, err := time.Parse(layout, value); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// globalScopeCommand enters the scope the administrator table lives in on a
// partitioned unit.
//
// Fortinet's own recipe for a per-VDOM administrator opens with it, and every
// document that shows `config system admin` on such a unit reaches it this way.
// On a unit that is NOT partitioned the command does not exist, which is why it
// is sent on the strength of what the unit reported rather than always.
const globalScopeCommand = "config global"

// enterAdminTable is the path to `config system admin` on this unit, and
// leaveAdminTable is its exact inverse.
//
// They are a pair on purpose. The nesting is what phase 0015 found the driver
// getting wrong, and a sequence that opens two levels and closes one leaves a
// configuration block open on a customer's firewall — so the two are written
// together, next to each other, rather than as an opening step in one table and
// a matching `end` somebody has to remember in five others.
func (s *cliSession) enterAdminTable() []step {
	steps := make([]step, 0, 2)
	if s.vdomMode.partitioned() {
		steps = append(steps, step{command: globalScopeCommand, label: "enter global configuration"})
	}
	return append(steps, step{command: adminTableCommand, label: "enter administrator configuration"})
}

func (s *cliSession) leaveAdminTable() []step {
	steps := []step{{command: "end", label: "leave administrator configuration"}}
	if s.vdomMode.partitioned() {
		steps = append(steps, step{command: "end", label: "leave global configuration"})
	}
	return steps
}

// adminTableCommand opens the administrator table itself.
const adminTableCommand = "config system admin"

// open dials the device, reads past its login banner, and refuses a unit this
// driver cannot administer.
func (d *Driver) open(ctx context.Context, ep device.Endpoint) (*cliSession, error) {
	if d.dialer == nil {
		// The declaration registered in device.Shipped() (see init below) has
		// no way to reach a device. Refusing here rather than panicking keeps a
		// misconfiguration an error a proxy reports instead of a crash.
		return nil, errors.New("auth/target/device/fortios: this driver is a declaration only; build one with New to reach a device")
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
	// The mode is read ONCE PER SESSION and before anything is configured,
	// because every operation this driver performs depends on it and not only
	// creation: on a partitioned unit `config system admin` at the top level is
	// not the table Fortinet's own recipe edits, so `edit`, `delete` and `show`
	// are all pointed at something the driver cannot vouch for.
	if err := d.readStatus(ctx, s); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// run executes a sequence, stopping at the first step the device refused.
func (d *Driver) run(ctx context.Context, s *cliSession, steps []step) error {
	for _, st := range steps {
		out, err := s.send(ctx, st.command)
		if err != nil {
			return fmt.Errorf("auth/target/device/fortios: %s: %w", st.label, err)
		}
		if st.secret {
			// The device echoes what it was given, and what it was given was a
			// password. The output is discarded rather than inspected for a
			// reason string, so the only thing that can escape this step is the
			// fact that it failed.
			if checkOutput(st.label, out) != nil {
				return fmt.Errorf("%w: %s", ErrDeviceRefused, st.label)
			}
			continue
		}
		if st.notFoundIsSuccess && isNotFound(out) {
			continue
		}
		if err := checkOutput(st.label, out); err != nil {
			return err
		}
	}
	return nil
}

// abandon backs out of a failed sequence.
//
// The unwinding follows the SAME nesting the sequence used, which on a
// partitioned unit is one level deeper: `abort` discards the uncommitted block
// wherever in it the session was, and the delete afterwards has to re-enter the
// table through `config global` again or it deletes nothing — quietly, on the
// one path whose whole job is to leave no administrator behind.
func (d *Driver) abandon(ctx context.Context, s *cliSession, name string) {
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
	// And the schedule of the same name, unconditionally. This path does not
	// know how far the sequence got before it failed — that is what makes it
	// the backstop rather than the plan — and deleting a schedule that was
	// never created costs one refused command that nobody reads, while leaving
	// one behind costs a sweep.
	for _, st := range s.enterScheduleTable() {
		_, _ = s.send(ctx, st.command)
	}
	_, _ = s.send(ctx, "delete "+quote(name))
	for _, st := range s.leaveScheduleTable() {
		_, _ = s.send(ctx, st.command)
	}
}

// accountExists reports whether an administrator of that name is on the device.
func (d *Driver) accountExists(ctx context.Context, s *cliSession, name string) (bool, error) {
	accounts, err := d.listAccounts(ctx, s, "")
	if err != nil {
		return false, err
	}
	for _, a := range accounts {
		if a.Name == name {
			return true, nil
		}
	}
	return false, nil
}

// editPattern matches an entry header in `show system admin` output.
var editPattern = regexp.MustCompile(`^\s*edit\s+"?([^"\s]+)"?\s*$`)

// accprofilePattern matches the access profile inside one entry.
var accprofilePattern = regexp.MustCompile(`^\s*set\s+accprofile\s+"?([^"\s]+)"?\s*$`)

// listAccounts reads the administrator table and returns the entries under a
// prefix. An empty prefix returns everything, which is only ever used by the
// non-existence check on the create path — the reaper always names one.
func (d *Driver) listAccounts(ctx context.Context, s *cliSession, prefix string) ([]device.Account, error) {
	out, err := d.showGlobal(ctx, s, adminShowCommand, "list administrators")
	if err != nil {
		return nil, err
	}

	var accounts []device.Account
	var current *device.Account
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if m := editPattern.FindStringSubmatch(line); m != nil {
			if current != nil {
				accounts = append(accounts, *current)
			}
			current = &device.Account{Name: m[1]}
			continue
		}
		if current == nil {
			continue
		}
		if m := accprofilePattern.FindStringSubmatch(line); m != nil {
			current.Profile = m[1]
			continue
		}
		if strings.TrimSpace(line) == "next" {
			accounts = append(accounts, *current)
			current = nil
		}
	}
	if current != nil {
		accounts = append(accounts, *current)
	}

	if prefix == "" {
		return accounts, nil
	}
	filtered := accounts[:0:0]
	for _, a := range accounts {
		if strings.HasPrefix(a.Name, prefix) {
			filtered = append(filtered, a)
		}
	}
	return filtered, nil
}

// adminShowCommand and vdomShowCommand read the two global tables this driver
// cares about.
//
// UNVERIFIED against hardware: that `show system admin` inside `config global`
// renders the SAME table this parser reads at the top level of a single-VDOM
// unit. Fortinet documents the table and documents that it lives in global
// scope on a partitioned unit; nothing found says the rendering differs, and
// nothing says it does not. It is on this phase's hardware list, and the fake
// device models them as one table because that is the reading the documentation
// supports — which is exactly the kind of assumption a fake can hide, so it is
// written down here rather than only there.
const (
	adminShowCommand = "show system admin"
	vdomShowCommand  = "show system vdom"
)

// showGlobal runs a read against a table that lives in global scope.
//
// On a unit that is not partitioned that is simply the top level and there is
// nothing to enter. On one that is, the scope has to be entered and left again,
// and leaving it is deferred rather than appended so that a read which fails
// half way does not leave the session in `config global` — the state that makes
// the NEXT command mean something other than what it says.
func (d *Driver) showGlobal(ctx context.Context, s *cliSession, command, label string) (string, error) {
	if s.vdomMode.partitioned() {
		out, err := s.send(ctx, globalScopeCommand)
		if err != nil {
			return "", fmt.Errorf("auth/target/device/fortios: enter global configuration: %w", err)
		}
		if err := checkOutput("enter global configuration", out); err != nil {
			return "", err
		}
		defer func() { _, _ = s.send(ctx, "end") }()
	}
	out, err := s.send(ctx, command)
	if err != nil {
		return "", fmt.Errorf("auth/target/device/fortios: %s: %w", label, err)
	}
	if err := checkOutput(label, out); err != nil {
		return "", err
	}
	return out, nil
}

// ErrUnknownVDOM means the route named a virtual domain this unit does not
// have — or has no virtual domains at all.
//
// Like ErrMultiVDOM it is deliberately NOT device.ErrUnsupported. The platform
// is capable, the driver is capable, and the route is the only thing that is
// wrong: answering it by skipping the rung would serve the session on a
// credential the server ranked lower because a policy author typed a VDOM name
// that has since been renamed. D13's rule makes that an outage-class denial.
var ErrUnknownVDOM = errors.New("auth/target/device/fortios: the unit does not have that virtual domain")

// requestedVDOM reads the route's virtual domain out of its device fields.
//
// An undeclared field is refused here as well as by the provisioner, which
// checks it against Capabilities.Fields before this driver is reached. The
// duplication is deliberate and it is the same belt-and-braces rule the value
// validation follows: "the caller checked" describes today's caller, and what
// is at stake is a configuration command on a firewall.
func requestedVDOM(fields map[string]string) (string, error) {
	for name := range fields {
		if name != FieldVDOM {
			return "", fmt.Errorf("%w: %q is not a field this driver accepts", errInvalidValue, name)
		}
	}
	vdom := strings.TrimSpace(fields[FieldVDOM])
	if vdom == "" {
		// Absent means global scope, which is a supported answer rather than a
		// missing one. An EMPTY value never reaches here — the contract refuses
		// it, because a route that names a field means to constrain something.
		return "", nil
	}
	if err := validateVDOM(vdom); err != nil {
		return "", err
	}
	return vdom, nil
}

// checkVDOMProfile refuses an access profile a per-VDOM administrator cannot
// hold.
//
// Fortinet is explicit about this, twice: a per-VDOM administrator "must use
// either the `prof_admin` administrator profile, or a custom profile", and
// "when creating an administrator at the VDOM level, the `super_admin`
// administrator profile cannot be used". `super_admin_readonly` is the GLOBAL
// read-only profile and falls on the same side of that line.
//
// It is checked here rather than left to the device because of what the device
// does with it: a refused `set accprofile` is a failure in the middle of a
// sequence that has already created the entry, so the difference between
// checking and not checking is whether a policy mistake leaves a rollback to
// perform on a customer's firewall. Only the two documented built-ins are
// refused — a custom profile the customer built is theirs to scope, and this
// driver has no way to know what is in it.
func checkVDOMProfile(profile string) error {
	switch profile {
	case builtinSuperAdmin, builtinSuperAdminReadOnly:
		return fmt.Errorf("%w: %q is a global access profile and a VDOM-scoped administrator cannot hold one; "+
			"FortiOS requires %q or a custom profile there",
			errInvalidValue, profile, builtinProfAdmin)
	default:
		return nil
	}
}

// The FortiOS built-in access profiles, as documented: three, not four (phase
// 0015). They are named here only to say which of them a per-VDOM administrator
// may not hold; this driver still has no default profile and does not want one.
const (
	builtinSuperAdmin         = "super_admin"
	builtinSuperAdminReadOnly = "super_admin_readonly"
	builtinProfAdmin          = "prof_admin"
)

// checkVDOMExists refuses a virtual domain the unit does not have.
func (d *Driver) checkVDOMExists(ctx context.Context, s *cliSession, vdom string) error {
	if !s.vdomMode.partitioned() {
		// A route asking for a VDOM on a unit that has none is not a smaller
		// version of the same request: whatever the policy author meant, this
		// unit cannot serve it, and creating a global administrator instead
		// would quietly hand out the WIDER scope the route was narrowing.
		return fmt.Errorf("%w: the route names virtual domain %q and the unit reports virtual domain configuration %q",
			ErrUnknownVDOM, vdom, s.vdomMode)
	}
	vdoms, err := d.listVDOMs(ctx, s)
	if err != nil {
		return err
	}
	for _, name := range vdoms {
		if name == vdom {
			return nil
		}
	}
	return fmt.Errorf("%w: the unit has no virtual domain %q", ErrUnknownVDOM, vdom)
}

// listVDOMs reads the unit's virtual domains.
//
// `config system vdom` is an ordinary configuration table with one `edit
// <name>` per virtual domain, so `show system vdom` renders in the same shape
// as the administrator table and is read by the same line matcher. The
// alternative every KB reaches for first is `diagnose sys vd list`, which is a
// DIAGNOSE command: from FortiOS 7.4 a read-only profile cannot run those at
// all, and this driver would then be unable to check a VDOM on exactly the
// units whose management account is most tightly scoped.
func (d *Driver) listVDOMs(ctx context.Context, s *cliSession) ([]string, error) {
	out, err := d.showGlobal(ctx, s, vdomShowCommand, "list virtual domains")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		if m := editPattern.FindStringSubmatch(strings.TrimRight(line, "\r")); m != nil {
			names = append(names, m[1])
		}
	}
	if len(names) == 0 {
		// A partitioned unit has at least the management VDOM, so an empty
		// answer means the read did not do what this driver thinks it did —
		// a different rendering, a truncated page, a profile that cannot see
		// the table. Refusing is fail-closed in the direction that does not
		// create a privileged account in a scope nobody confirmed.
		return nil, fmt.Errorf("%w: `%s` listed no virtual domains on a unit reporting %q",
			ErrUnknownVDOM, vdomShowCommand, s.vdomMode)
	}
	return names, nil
}

// secretAlphabet is what a generated password is drawn from.
//
// It excludes the quote and backslash characters the FortiOS parser treats
// specially, so that a generated password can never be the thing that ends a
// command early. That is a narrowing of the alphabet, not of the entropy: the
// length is what carries the entropy and it is set well above where the
// alphabet's size matters.
const secretAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.@%+=:,"

// randomSecret returns n characters of cryptographic randomness.
func randomSecret(n int) (string, error) {
	out := make([]byte, n)
	max := big.NewInt(int64(len(secretAlphabet)))
	for i := range out {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("auth/target/device/fortios: generate a password: %w", err)
		}
		out[i] = secretAlphabet[v.Int64()]
	}
	return string(out), nil
}

// Register adds this repository's FortiOS drivers to a registry, so a proxy
// builds them in one call rather than knowing each platform name.
func Register(r *device.Registry, opts Options) error {
	d, err := New(opts)
	if err != nil {
		return err
	}
	return r.Register(d)
}

// The declaration this repository ships.
//
// device.Shipped() exists so CheckShipped can hold Hoplock's own drivers to
// D13's rule, and that check reads Platform() and Capabilities() only — neither
// of which touches a device. So what is registered here is a DECLARATION: the
// same type with no way to reach anything. A proxy that serves routes builds a
// real driver with New and registers it in its own registry; this one exists to
// be checked, and open() refuses rather than panicking if anybody tries to use
// it for work.
func init() {
	if err := device.Shipped().Register(&Driver{platform: PlatformFortiGate}); err != nil {
		panic(err)
	}
}
