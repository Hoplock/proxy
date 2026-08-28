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

// DefaultAccessProfile is the access profile a created administrator is given
// when nothing else says otherwise.
//
// FortiOS ships four built-ins: `super_admin` and `prof_admin` (both
// read-write) and `super_admin_readonly` and `prof_admin_readonly`. This is the
// most restrictive one that can be relied on, and "relied on" is doing real
// work in that sentence:
//
//   - `prof_admin_readonly` is narrower — it excludes routing, system settings
//     and endpoint control — but it is EDITABLE, so an operator who widened it
//     once would silently widen what every Hoplock session on that unit can do,
//     and nothing here would notice.
//   - `super_admin_readonly` reads the whole configuration and can change none
//     of it, and Fortinet documents it as undeletable and unmodifiable. A
//     default that cannot drift is worth more than a default that is narrower
//     on a good day.
//
// It is a DEFAULT, not a policy, and a read-only one will be wrong for many
// real routes: an operator opening a session to change a firewall rule needs
// write access. WHICH profile a route gets is phase 0015's vocabulary and phase
// 0016's to apply, and until then an estate that needs more sets
// `auth.target.ephemeral_account.access_profile`. The default is deliberately
// the safe end of that choice rather than the convenient one.
const DefaultAccessProfile = "super_admin_readonly"

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
	// AccessProfile is the profile created administrators are given. Empty
	// means DefaultAccessProfile.
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
	if d.profile == "" {
		d.profile = DefaultAccessProfile
	}
	if err := validateProfile(d.profile); err != nil {
		return nil, err
	}
	return d, nil
}

// Platform implements device.Driver.
func (d *Driver) Platform() string { return d.platform }

// Capabilities implements device.Driver.
//
// Every value here was verified against Fortinet's current documentation rather
// than assumed; the package comment records what was checked and where the
// answers came from. Two of them are worth reading twice.
//
// EnforcesExpiry is FALSE. A FortiOS administrator has no expiry field: there is
// no `set expiry`, and `config system admin` has no schedule. So the device will
// never remove this account on its own, whatever happens to the proxy — which
// means the reaper is the PRIMARY removal path here rather than a crash-recovery
// backstop, and a route demanding control.ExpiryPostureTargetEnforced is a
// skipped ladder rung rather than a session served on a promise nobody keeps.
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
	if err := validateProfile(profile); err != nil {
		return nil, err
	}
	var trust string
	if req.SourceAddress != "" {
		var err error
		if trust, err = trustHost(req.SourceAddress); err != nil {
			return nil, err
		}
	}
	// Lifetime is accepted and not rendered: FortiOS has no expiry field, and
	// Capabilities.EnforcesExpiry says so, which is what lets the provisioner
	// decide whether that is acceptable for this route before anything is
	// created. Silently ignoring it here without that declaration would be the
	// bug this is not.
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

	exists, err := d.accountExists(ctx, s, req.Name)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("%w: %q is already an administrator on %s",
			device.ErrAccountExists, req.Name, req.Host)
	}

	steps := []step{
		{command: "config system admin", label: "enter administrator configuration"},
		{command: "edit " + quote(req.Name), label: "create the administrator"},
		{command: "set accprofile " + quote(profile), label: "set the access profile"},
	}
	if trust != "" {
		steps = append(steps, step{command: "set trusthost1 " + trust, label: "pin the administrator to the proxy's address"})
	}
	steps = append(steps,
		step{command: "set password " + quote(placeholder), label: "set a placeholder password", secret: true},
		step{command: "next", label: "commit the administrator"},
		step{command: "end", label: "leave administrator configuration"},
	)

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

	steps := []step{
		{command: "config system admin", label: "enter administrator configuration"},
		{command: "edit " + quote(req.Name), label: "open the administrator"},
		install,
		{command: "next", label: "commit the credential"},
		{command: "end", label: "leave administrator configuration"},
	}
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

	return d.run(ctx, s, []step{
		{command: "config system admin", label: "enter administrator configuration"},
		{command: "delete " + quote(req.Name), label: "remove the administrator", notFoundIsSuccess: true},
		{command: "end", label: "leave administrator configuration"},
	})
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

// open dials the device and reads past its login banner.
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
func (d *Driver) abandon(ctx context.Context, s *cliSession, name string) {
	// `abort` discards an uncommitted configuration block outright. Its own
	// failure is swallowed: the session is being denied either way, and what it
	// could not undo is what the reaper is for.
	_, _ = s.send(ctx, "abort")
	_, _ = s.send(ctx, "end")
	_, _ = s.send(ctx, "config system admin")
	_, _ = s.send(ctx, "delete "+quote(name))
	_, _ = s.send(ctx, "end")
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
	out, err := s.send(ctx, "show system admin")
	if err != nil {
		return nil, fmt.Errorf("auth/target/device/fortios: list administrators: %w", err)
	}
	if err := checkOutput("list administrators", out); err != nil {
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
	if err := device.Shipped().Register(&Driver{platform: PlatformFortiGate, profile: DefaultAccessProfile}); err != nil {
		panic(err)
	}
}
