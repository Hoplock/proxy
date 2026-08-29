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
// EnforcesExpiry is FALSE, and it is false BY DECISION rather than by absence.
// Phase 0014 declared it false because "there is no `set expiry`, and `config
// system admin` has no schedule". The second half is flatly wrong: `config
// system admin` has `set schedule {string}`, it points at a `config firewall
// schedule onetime` entry carrying an absolute `set end {hh:mm yyyy/mm/dd}`,
// and FortiOS enforces it at authentication — Fortinet's own KB shows the
// denial logged as `reason="out_of_schedule"`. A FortiGate CAN time-bound an
// administrator by itself.
//
// It stays false anyway, and phase 0015 settled that with the user:
//
//   - The mechanism is a SECOND OBJECT per session. Taking it means creating a
//     schedule entry, naming it under PLAN §5.3's scheme (the field caps
//     schedule names at 35), referencing it, tearing it down, and teaching the
//     reaper to sweep an orphaned one. An orphaned schedule on a customer's
//     firewall is a smaller problem than an orphaned administrator and it is
//     not nothing — it is a new leak class, and a new leak class is a phase,
//     not a correction.
//   - It DENIES LOGIN; it does not remove the account. So it would not retire
//     the reaper or touch PersistsAcrossReload either way.
//   - Whether an ALREADY-ESTABLISHED session survives the window closing is
//     undocumented, and a target-enforced posture that cannot cut a live
//     session is not obviously the thing a PDP asking for one wants.
//
// The consequence is unchanged and the reasoning under it is not: a route
// demanding control.ExpiryPostureTargetEnforced is still a skipped ladder rung,
// and the reaper is still the removal path. What is no longer true is that
// FortiOS has nothing to offer here. Making the schedule mechanism real is a
// queued phase of its own, and until it lands this declaration says "this
// driver does not enforce expiry", not "this platform cannot".
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
		MaxAccountNameLen:    maxAccountNameLen,
		EnforcesExpiry:       false,
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
	// Lifetime is accepted and not rendered. FortiOS could carry it — `set
	// schedule` against a `config firewall schedule onetime` entry is a real
	// mechanism (see Capabilities) — and this driver does not, which is exactly
	// what Capabilities.EnforcesExpiry: false declares. The declaration is what
	// lets the provisioner decide whether that is acceptable for this route
	// BEFORE anything is created; silently ignoring a lifetime without it would
	// be the bug this is not.
	_ = req.Lifetime

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

// RemoveAccount implements device.Driver.
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
	return d.run(ctx, s, append(steps, s.leaveAdminTable()...))
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

// readVDOMMode asks the unit which shape it is, and refuses a shape this driver
// has not been written for.
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
func (d *Driver) readVDOMMode(ctx context.Context, s *cliSession) (vdomMode, error) {
	out, err := s.send(ctx, vdomStatusCommand)
	if err != nil {
		return "", fmt.Errorf("auth/target/device/fortios: read the unit's VDOM mode: %w", err)
	}
	if err := checkOutput("read the unit's VDOM mode", out); err != nil {
		return "", err
	}
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
	mode, err := d.readVDOMMode(ctx, s)
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	s.vdomMode = mode
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
