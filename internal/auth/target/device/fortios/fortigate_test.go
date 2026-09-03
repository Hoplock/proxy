// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package fortios

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/auth/target/device"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/sshtest"
)

// harness is a driver wired to a fake device.
type harness struct {
	dev    *sshtest.FakeFortiOS
	driver *Driver
	ep     device.Endpoint
}

func newHarness(t *testing.T, opts sshtest.FortiOSOptions) *harness {
	t.Helper()
	dev, err := sshtest.StartFortiOS(opts)
	if err != nil {
		t.Fatalf("start fake device: %v", err)
	}
	t.Cleanup(func() { _ = dev.Close() })

	dialer, err := device.NewSSHShellDialer(device.SSHShellOptions{
		User:     firstNonEmpty(opts.AdminUser, "hoplock-mgmt"),
		Password: firstNonEmpty(opts.AdminPassword, "mgmt-secret"),
	})
	if err != nil {
		t.Fatalf("dialer: %v", err)
	}
	driver, err := New(Options{Dialer: dialer, AccessProfile: testAccessProfile})
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	return &harness{
		dev:    dev,
		driver: driver,
		ep: device.Endpoint{
			Host:            dev.Host(),
			Port:            dev.Port(),
			SessionID:       "sess-1",
			HostKeyCallback: ssh.FixedHostKey(dev.HostKey()),
		},
	}
}

// testAccessProfile is what these tests configure the driver with.
//
// There is no default any more (phase 0015), so a harness has to name one — and
// that is the point: an account's scope is a decision somebody makes, not one
// the driver carries. It is `super_admin_readonly` because that is a real,
// immutable FortiOS built-in, not because the driver prefers it.
const testAccessProfile = "super_admin_readonly"

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// TestLifecycleAgainstTheDevice is the whole driver in one pass: create,
// credential, enumerate, remove.
func TestLifecycleAgainstTheDevice(t *testing.T) {
	h := newHarness(t, sshtest.FortiOSOptions{
		Accounts: []sshtest.FortiOSAccount{{Name: "admin", Profile: "super_admin"}},
	})
	ctx := context.Background()
	const name = "hl-a1b2-alice-0f0f0f0f"

	acct, err := h.driver.CreateAccount(ctx, device.CreateRequest{
		Endpoint:      h.ep,
		Name:          name,
		SourceAddress: "198.51.100.7",
	})
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if acct.Name != name {
		t.Errorf("created %q, want %q", acct.Name, name)
	}
	if acct.Profile != testAccessProfile {
		t.Errorf("created with profile %q, want %q", acct.Profile, testAccessProfile)
	}
	if !acct.CreatedAt.IsZero() {
		t.Error("FortiOS does not record a creation time; a driver reporting one would have the reaper age accounts against a fiction")
	}

	on := h.dev.Accounts()[name]
	if on.Profile != testAccessProfile {
		t.Errorf("device has profile %q, want %q", on.Profile, testAccessProfile)
	}
	if on.TrustHost != "198.51.100.7 255.255.255.255" {
		t.Errorf("device has trusthost %q, want the proxy pinned as a /32", on.TrustHost)
	}
	// Both halves of the pin, because `ip6-trusthost1` defaults to `::/0`: an
	// account restricted only through `trusthost1` is reachable from any IPv6
	// address on a unit with IPv6 management access, which is a restriction the
	// provisioner believes it applied and the device does not have.
	if on.IP6TrustHost == sshtest.FortiOSOpenIPv6TrustHost {
		t.Error("the account is pinned on IPv4 and wide open on IPv6; ip6-trusthost1 was left at its `::/0` default")
	}
	// The window between create and credential must not be a usable one.
	if on.Password == "" {
		t.Error("the account was created with no password at all; a FortiOS administrator with no password can be logged into with an empty one")
	}
	placeholder := on.Password

	const secret = "correct-horse-battery-staple-42"
	if err := h.driver.InstallCredential(ctx, device.CredentialRequest{
		Endpoint: h.ep, Name: name,
		Kind: control.CredentialKindPassword, Password: secret,
	}); err != nil {
		t.Fatalf("InstallCredential: %v", err)
	}
	on = h.dev.Accounts()[name]
	if on.Password != secret {
		t.Errorf("device holds %q, want the session's password", on.Password)
	}
	if on.Password == placeholder {
		t.Error("the placeholder survived; the real credential never landed")
	}

	found, err := h.driver.ListAccounts(ctx, device.ListRequest{Endpoint: h.ep, Prefix: "hl-"})
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(found) != 1 || found[0].Name != name {
		t.Fatalf("ListAccounts returned %v, want just %q — the prefix is what keeps one proxy out of another's accounts", found, name)
	}

	if err := h.driver.RemoveAccount(ctx, device.RemoveRequest{Endpoint: h.ep, Name: name}); err != nil {
		t.Fatalf("RemoveAccount: %v", err)
	}
	if _, ok := h.dev.Accounts()[name]; ok {
		t.Error("the administrator survived removal")
	}
	if _, ok := h.dev.Accounts()["admin"]; !ok {
		t.Error("the device's own administrator was removed; the driver must only ever touch what it created")
	}
}

// TestRemovalIsIdempotent is the property teardown depends on: it runs on the
// normal path, on error, on panic, and from the reaper.
func TestRemovalIsIdempotent(t *testing.T) {
	h := newHarness(t, sshtest.FortiOSOptions{})
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := h.driver.RemoveAccount(ctx, device.RemoveRequest{Endpoint: h.ep, Name: "hl-a1b2-ghost-00000000"}); err != nil {
			t.Fatalf("removing an account that is already gone (attempt %d): %v", i+1, err)
		}
	}
}

// TestCreateNeverAdoptsAnExistingAccount is D13's rule, and the reason the
// device path differs from PLAN §5.1's idempotent POSIX one.
func TestCreateNeverAdoptsAnExistingAccount(t *testing.T) {
	const name = "hl-a1b2-alice-0f0f0f0f"
	h := newHarness(t, sshtest.FortiOSOptions{
		Accounts: []sshtest.FortiOSAccount{{Name: name, Profile: "super_admin", Password: "someone-elses"}},
	})

	_, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{Endpoint: h.ep, Name: name})
	if !errors.Is(err, device.ErrAccountExists) {
		t.Fatalf("CreateAccount over an existing name returned %v, want ErrAccountExists — adopting it would give two sessions one account, and the first teardown would remove the other's access", err)
	}
	if got := h.dev.Accounts()[name]; got.Password != "someone-elses" {
		t.Error("the existing account was modified; a collision must leave the other session untouched")
	}
}

// TestNameTooLongIsRefusedByTheDevice covers the error channel FortiOS actually
// has: text, with no exit status behind it.
func TestNameTooLongIsRefusedByTheDevice(t *testing.T) {
	h := newHarness(t, sshtest.FortiOSOptions{Faults: sshtest.FortiOSFaults{MaxNameLen: 12}})

	name := "hl-a1b2-" + strings.Repeat("z", 20)
	_, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{Endpoint: h.ep, Name: name})
	if err == nil {
		t.Fatal("a name the device rejected was reported as a successful creation")
	}
	if !errors.Is(err, ErrDeviceRefused) {
		t.Errorf("CreateAccount returned %v, want ErrDeviceRefused", err)
	}
	if _, ok := h.dev.Accounts()[name]; ok {
		t.Error("the refused account is on the device anyway")
	}
}

// TestConfigModeErrorLeavesNothingBehind is the failure-isolation rule: a
// denied session leaves the device as it found it.
func TestConfigModeErrorLeavesNothingBehind(t *testing.T) {
	h := newHarness(t, sshtest.FortiOSOptions{
		Faults: sshtest.FortiOSFaults{
			RejectProfile: true,
			FailCommand:   regexp.MustCompile(`set accprofile`),
		},
	})

	const name = "hl-a1b2-alice-0f0f0f0f"
	_, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{Endpoint: h.ep, Name: name})
	if err == nil {
		t.Fatal("a rejected access profile was reported as a successful creation")
	}
	if _, ok := h.dev.Accounts()[name]; ok {
		t.Fatal("a half-created administrator was left on the device; that is a standing privileged account nobody is tracking")
	}
}

// TestPagedOutputIsReadWhole covers `config system console`'s permanent default:
// the driver must page rather than turn paging off on a customer's device.
func TestPagedOutputIsReadWhole(t *testing.T) {
	var accounts []sshtest.FortiOSAccount
	for _, n := range []string{"admin", "hl-a1b2-a-00000001", "hl-a1b2-b-00000002", "hl-a1b2-c-00000003", "hl-a1b2-d-00000004"} {
		accounts = append(accounts, sshtest.FortiOSAccount{Name: n, Profile: "prof_admin"})
	}
	h := newHarness(t, sshtest.FortiOSOptions{
		Accounts: accounts,
		Faults:   sshtest.FortiOSFaults{PageEvery: 2},
	})

	found, err := h.driver.ListAccounts(context.Background(), device.ListRequest{Endpoint: h.ep, Prefix: "hl-a1b2-"})
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(found) != 4 {
		t.Fatalf("ListAccounts found %d accounts across a paged listing, want 4 — a sweep that stops at the first screen leaves live privileged accounts behind", len(found))
	}
}

// TestUnreachableDeviceIsARetryableFailure separates "gone" from "cannot be
// reached": the first is success on the removal path, the second is not.
func TestUnreachableDeviceIsARetryableFailure(t *testing.T) {
	h := newHarness(t, sshtest.FortiOSOptions{
		Accounts: []sshtest.FortiOSAccount{{Name: "hl-a1b2-alice-0f0f0f0f"}},
	})
	h.dev.SetUnreachable(true)

	err := h.driver.RemoveAccount(context.Background(), device.RemoveRequest{Endpoint: h.ep, Name: "hl-a1b2-alice-0f0f0f0f"})
	if err == nil {
		t.Fatal("removal against an unreachable device reported success; the account is still there and nothing will look for it again")
	}
	if errors.Is(err, device.ErrUnsupported) {
		t.Error("an unreachable device was reported as a permanent platform limitation, which would skip the ladder rung instead of failing the attempt")
	}
}

// TestPublicKeyIsInstalledAndPasswordIsNot covers D13's rule that the server's
// choice of credential kind is never substituted.
func TestPublicKeyIsInstalledAndPasswordIsNot(t *testing.T) {
	h := newHarness(t, sshtest.FortiOSOptions{})
	ctx := context.Background()
	const name = "hl-a1b2-alice-0f0f0f0f"

	if _, err := h.driver.CreateAccount(ctx, device.CreateRequest{Endpoint: h.ep, Name: name}); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterialForTests hoplock"
	if err := h.driver.InstallCredential(ctx, device.CredentialRequest{
		Endpoint: h.ep, Name: name,
		Kind: control.CredentialKindPublicKey, PublicKey: key,
	}); err != nil {
		t.Fatalf("InstallCredential: %v", err)
	}
	if got := h.dev.Accounts()[name].PublicKey; got != key {
		t.Errorf("device holds public key %q, want %q", got, key)
	}

	err := h.driver.InstallCredential(ctx, device.CredentialRequest{Endpoint: h.ep, Name: name, Kind: "certificate"})
	if !errors.Is(err, device.ErrUnsupported) {
		t.Errorf("an unknown credential kind returned %v, want ErrUnsupported so the rung is skipped rather than substituted", err)
	}
}

// TestNoCredentialReachesAnErrorOrACommandLog is the assertion the acceptance
// criteria ask for by name, rather than a promise to be careful.
func TestNoCredentialReachesAnErrorOrACommandLog(t *testing.T) {
	h := newHarness(t, sshtest.FortiOSOptions{
		Faults: sshtest.FortiOSFaults{FailCommand: regexp.MustCompile(`^next$`)},
	})
	ctx := context.Background()
	const name = "hl-a1b2-alice-0f0f0f0f"
	const secret = "S3cret-Never-Logged-Value"

	// The create path fails at `next`, which is after the placeholder password
	// was sent — so whatever the error says, it says it having seen one.
	_, createErr := h.driver.CreateAccount(ctx, device.CreateRequest{Endpoint: h.ep, Name: name})
	if createErr == nil {
		t.Fatal("expected the create sequence to fail at `next`")
	}
	if strings.Contains(createErr.Error(), "password") && strings.Contains(createErr.Error(), "set password") {
		t.Errorf("the error quotes the command that carried a password: %q", createErr)
	}

	h2 := newHarness(t, sshtest.FortiOSOptions{})
	if _, err := h2.driver.CreateAccount(ctx, device.CreateRequest{Endpoint: h2.ep, Name: name}); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	err := h2.driver.InstallCredential(ctx, device.CredentialRequest{
		Endpoint: h2.ep, Name: name, Kind: control.CredentialKindPassword, Password: secret,
	})
	if err != nil {
		t.Fatalf("InstallCredential: %v", err)
	}
	// The device is where the credential legitimately lands (it is the device's
	// own configuration and its own AAA record, and that is out of our
	// control). What must not happen is the secret appearing in anything this
	// process produces, so the check is on the error strings above and on the
	// account name, which is half of a password credential pair.
	for _, cmd := range h2.dev.Commands() {
		if strings.Contains(cmd, secret) && !strings.HasPrefix(cmd, "set password") {
			t.Errorf("the password reached the device outside the one command that installs it: %q", cmd)
		}
	}
}

// TestShippedDeclarationMeetsTheHoplockRule runs D13's invariant over the
// registry this repository actually ships, which is the only place it means
// anything: device.CheckShipped over an empty registry passes vacuously.
func TestShippedDeclarationMeetsTheHoplockRule(t *testing.T) {
	if _, err := device.Shipped().Lookup(PlatformFortiGate); err != nil {
		t.Fatalf("the FortiGate driver is not in the shipped registry: %v", err)
	}
	if err := device.CheckShipped(device.Shipped()); err != nil {
		t.Fatalf("CheckShipped over the shipped registry: %v", err)
	}

	caps := (&Driver{}).Capabilities()
	if !caps.PersistsAcrossReload {
		t.Error("FortiOS commits to flash on `end`; declaring otherwise would be a lie the reaper cannot cover")
	}
	if strings.TrimSpace(caps.PersistenceReason) == "" {
		t.Error("a shipped driver that persists must say which platform mechanism forces it")
	}
	if !caps.EnforcesExpiry {
		// Phase 0017 made this true, and it is only honest because the driver
		// now creates, references and tears down a `config firewall schedule
		// onetime` object and the reaper sweeps an orphaned one. The tests
		// below are what hold it to that: flipping the declaration back without
		// removing the mechanism, or removing the mechanism without flipping
		// the declaration, fails here or there.
		t.Error("EnforcesExpiry is false, but the driver renders a schedule onto the device")
	}
	if strings.TrimSpace(caps.ExpiryMechanism) == "" {
		// The declaration is one bit and the platforms behind it disagree about
		// what the bit buys. A shipped driver says which (device.CheckShipped).
		t.Error("a shipped driver that expires accounts must say what the device does at the deadline")
	}
	for _, want := range []string{"out_of_schedule", "reaper"} {
		if !strings.Contains(caps.ExpiryMechanism, want) {
			t.Errorf("ExpiryMechanism does not mention %q; it has to say what the device does and what it does not", want)
		}
	}
	if caps.MaxAccountNameLen != FortiOSMaxNameLenDeclared {
		t.Errorf("declared name limit %d, want %d", caps.MaxAccountNameLen, FortiOSMaxNameLenDeclared)
	}
}

// FortiOSMaxNameLenDeclared pins the verified limit in the test as well as the
// driver, so a change to one is a visible change to the other.
//
// 64 — `config system admin` / `name`, "Maximum length: 64", read directly from
// the CLI reference in phase 0015. It was 35 here, from a KB line about "most
// name fields".
const FortiOSMaxNameLenDeclared = 64

// TestAUserShellSessionReachesTheCLI is the shape an operator's session takes,
// and the shape the e2e topology drives: an SSH client asks for a SHELL and
// types, because an appliance is a CLI and not a command pipe.
//
// It is here rather than only in the e2e suite because the e2e suite needs
// Docker and this does not. The device scenario was written against `ssh host
// cmd` first, which the fake device refuses exactly as many real appliances
// refuse an exec request — a difference no unit test would have caught and CI
// found the slow way.
func TestAUserShellSessionReachesTheCLI(t *testing.T) {
	h := newHarness(t, sshtest.FortiOSOptions{
		Accounts: []sshtest.FortiOSAccount{{Name: "admin", Profile: "super_admin"}},
	})

	client, err := ssh.Dial("tcp", h.dev.Addr().String(), &ssh.ClientConfig{
		User:            "hoplock-mgmt",
		Auth:            []ssh.AuthMethod{ssh.Password("mgmt-secret")},
		HostKeyCallback: ssh.FixedHostKey(h.dev.HostKey()),
	})
	if err != nil {
		t.Fatalf("dial the device: %v", err)
	}
	defer func() { _ = client.Close() }()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("open a session: %v", err)
	}
	defer func() { _ = sess.Close() }()

	// Separate buffers: x/crypto copies stdout and stderr on their own
	// goroutines, so one buffer behind both is a data race.
	var out, errOut bytes.Buffer
	sess.Stdin = strings.NewReader("show system admin\nexit\n")
	sess.Stdout = &out
	sess.Stderr = &errOut
	if err := sess.Shell(); err != nil {
		t.Fatalf("request a shell: %v", err)
	}
	// Wait returns the session's exit status. Without one an OpenSSH client
	// reports 255, which would make every device session look like a
	// connection failure rather than a session that ran.
	if err := sess.Wait(); err != nil {
		t.Fatalf("shell session: %v (device said:\n%s)", err, out.String())
	}
	if !strings.Contains(out.String(), `edit "admin"`) {
		t.Errorf("the shell session did not reach the CLI; it said:\n%s", out.String())
	}
}

// TestAnExecRequestIsRefused pins the behaviour the driver is built around, so
// that a change making the fake device accept exec is a visible one: the driver
// asks for a shell because appliance SSH servers commonly answer an exec
// request with nothing at all.
func TestAnExecRequestIsRefused(t *testing.T) {
	h := newHarness(t, sshtest.FortiOSOptions{})

	client, err := ssh.Dial("tcp", h.dev.Addr().String(), &ssh.ClientConfig{
		User:            "hoplock-mgmt",
		Auth:            []ssh.AuthMethod{ssh.Password("mgmt-secret")},
		HostKeyCallback: ssh.FixedHostKey(h.dev.HostKey()),
	})
	if err != nil {
		t.Fatalf("dial the device: %v", err)
	}
	defer func() { _ = client.Close() }()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("open a session: %v", err)
	}
	defer func() { _ = sess.Close() }()

	if err := sess.Run("show system admin"); err == nil {
		t.Error("the device accepted an exec request; the driver's shell-channel design assumes it does not")
	}
}

// TestAPartitionedUnitIsServedThroughGlobalConfiguration replaces phase 0015's
// refusal test, and the replacement is this phase.
//
// 0015 asserted that a unit running virtual domains was DECLINED, because the
// sequence phase 0014 sent was written for a unit where the administrator table
// is not inside `config global`. The sequence is now the documented one, so
// what is asserted is that it is sent: the wrapper is there, it comes FIRST,
// and the table is never opened at the top level of such a unit — which is the
// command that edits something this driver cannot vouch for.
func TestAPartitionedUnitIsServedThroughGlobalConfiguration(t *testing.T) {
	for _, mode := range []string{sshtest.FortiOSVDOMMultiple, sshtest.FortiOSVDOMSplitTask} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, sshtest.FortiOSOptions{VDOMMode: mode})
			const name = "hl-a1b2-alice-0f0f0f0f"

			account, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{Endpoint: h.ep, Name: name})
			if err != nil {
				t.Fatalf("CreateAccount against a %s unit: %v", mode, err)
			}
			if account.Name != name {
				t.Errorf("CreateAccount returned %q, want %q", account.Name, name)
			}
			created, ok := h.dev.Accounts()[name]
			if !ok {
				t.Fatal("no administrator was created on the unit")
			}
			// No VDOM was named, so the account is GLOBAL — the shape a proxy
			// administering the whole unit gets, and the reason serving only
			// VDOM-scoped accounts would have been the smaller feature.
			if created.VDOM != "" {
				t.Errorf("the administrator was scoped to VDOM %q; no route field asked for one", created.VDOM)
			}
			assertAdminTableIsWrapped(t, h.dev.Commands())
		})
	}
}

// assertAdminTableIsWrapped checks the nesting on a partitioned unit: every
// `config system admin` is inside a `config global` that is still open.
//
// It is a transcript assertion rather than a state one because the state cannot
// tell the difference. An administrator created through the wrong scope and one
// created through the right scope look identical afterwards on a fake — which
// is exactly how phase 0014's sequence passed every test it had.
func assertAdminTableIsWrapped(t *testing.T, commands []string) {
	t.Helper()
	depth := 0
	sawWrapped := false
	for _, cmd := range commands {
		switch {
		case cmd == "config global":
			depth++
		case cmd == "abort":
			depth = 0
		case cmd == "end":
			if depth > 0 {
				depth--
			}
		case cmd == "config system admin", strings.HasPrefix(cmd, "show system admin"), strings.HasPrefix(cmd, "show system vdom"):
			if depth == 0 {
				t.Errorf("the driver sent %q at the top level of a partitioned unit; there the global tables are reached through `config global`", cmd)
				return
			}
			sawWrapped = true
		}
	}
	if !sawWrapped {
		t.Error("no global table was read or edited at all, so this assertion proved nothing")
	}
}

// TestAVDOMScopedAdministratorIsCreatedInItsVirtualDomain is the feature.
//
// The route names a virtual domain through the contract's device_field
// namespace, and the account is created inside it — which is what a policy
// author gets for writing `device_field.vdom`, and what the audit record then
// has to carry, because `host:port` names the unit and not the partition.
func TestAVDOMScopedAdministratorIsCreatedInItsVirtualDomain(t *testing.T) {
	h := newHarness(t, sshtest.FortiOSOptions{
		VDOMMode: sshtest.FortiOSVDOMMultiple,
		VDOMs:    []string{"root", "customer-a"},
	})
	const name = "hl-a1b2-alice-0f0f0f0f"

	if _, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{
		Endpoint: h.ep,
		Name:     name,
		// A per-VDOM administrator "must use either the `prof_admin`
		// administrator profile, or a custom profile", so the harness's global
		// read-only default cannot be used here — see checkVDOMProfile.
		Profile: "prof_admin",
		Fields:  map[string]string{FieldVDOM: "customer-a"},
	}); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}

	created, ok := h.dev.Accounts()[name]
	if !ok {
		t.Fatal("no administrator was created")
	}
	if created.VDOM != "customer-a" {
		t.Errorf("the administrator is scoped to %q, want %q", created.VDOM, "customer-a")
	}
	assertAdminTableIsWrapped(t, h.dev.Commands())
}

// TestAnUnknownVDOMIsRefusedBeforeAnythingIsCreated is decision 3 of this
// phase: the VDOM is checked against the unit BEFORE the administrator exists.
//
// Reading the failure off `set vdom` instead would leave a half-created
// privileged administrator to roll back on a customer's firewall every time a
// policy names a virtual domain that has been renamed.
func TestAnUnknownVDOMIsRefusedBeforeAnythingIsCreated(t *testing.T) {
	h := newHarness(t, sshtest.FortiOSOptions{
		VDOMMode: sshtest.FortiOSVDOMMultiple,
		VDOMs:    []string{"root"},
	})
	const name = "hl-a1b2-alice-0f0f0f0f"

	_, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{
		Endpoint: h.ep, Name: name, Profile: "prof_admin",
		Fields: map[string]string{FieldVDOM: "customer-a"},
	})
	if !errors.Is(err, ErrUnknownVDOM) {
		t.Fatalf("CreateAccount returned %v, want ErrUnknownVDOM", err)
	}
	// Not ErrUnsupported: skipping the rung would serve the session on a
	// credential the server ranked lower because a policy author typed a stale
	// VDOM name (D13, D14).
	if errors.Is(err, device.ErrUnsupported) {
		t.Error("a route naming a VDOM the unit does not have was reported as a platform limitation, which skips the ladder rung instead of failing the attempt")
	}
	if _, ok := h.dev.Accounts()[name]; ok {
		t.Error("an administrator was created for a route naming a virtual domain the unit does not have")
	}
	for _, cmd := range h.dev.Commands() {
		if strings.HasPrefix(cmd, "edit ") {
			t.Errorf("the driver sent %q before checking the virtual domain; the check exists so nothing is created", cmd)
		}
	}
}

// TestAVDOMOnAUnitWithoutVirtualDomainsIsRefused covers the other direction.
//
// A route narrowing a session to one virtual domain, sent to a unit that has
// none, must not quietly become a GLOBAL administrator: that is the widest
// scope on the unit, handed out because the narrowing could not be applied.
func TestAVDOMOnAUnitWithoutVirtualDomainsIsRefused(t *testing.T) {
	h := newHarness(t, sshtest.FortiOSOptions{})
	const name = "hl-a1b2-alice-0f0f0f0f"

	_, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{
		Endpoint: h.ep, Name: name, Profile: "prof_admin",
		Fields: map[string]string{FieldVDOM: "customer-a"},
	})
	if !errors.Is(err, ErrUnknownVDOM) {
		t.Fatalf("CreateAccount returned %v, want ErrUnknownVDOM", err)
	}
	if _, ok := h.dev.Accounts()[name]; ok {
		t.Error("an administrator was created on a unit that cannot serve the scope the route asked for")
	}
}

// TestAGlobalProfileIsRefusedForAVDOMScopedAdministrator pins the documented
// restriction: a per-VDOM administrator "must use either the `prof_admin`
// administrator profile, or a custom profile", and `super_admin` "cannot be
// used" at the VDOM level.
//
// The device would refuse it anyway, in the middle of a sequence that has
// already created the entry. Refusing first is what keeps a policy mistake from
// becoming a rollback on a firewall.
func TestAGlobalProfileIsRefusedForAVDOMScopedAdministrator(t *testing.T) {
	h := newHarness(t, sshtest.FortiOSOptions{
		VDOMMode: sshtest.FortiOSVDOMMultiple,
		VDOMs:    []string{"root"},
	})
	const name = "hl-a1b2-alice-0f0f0f0f"

	for _, profile := range []string{"super_admin", "super_admin_readonly"} {
		_, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{
			Endpoint: h.ep, Name: name, Profile: profile,
			Fields: map[string]string{FieldVDOM: "root"},
		})
		if err == nil {
			t.Fatalf("a VDOM-scoped administrator was created with the global profile %q", profile)
		}
		if _, ok := h.dev.Accounts()[name]; ok {
			t.Fatalf("an administrator was created with a profile a per-VDOM account cannot hold (%s)", profile)
		}
	}
}

// TestAnUndeclaredRouteFieldIsRefused is the driver's half of the namespace
// rule. The provisioner checks a field against Capabilities.Fields before this
// driver is reached; the driver checks it again, because "the caller checked"
// describes today's caller and the value ends up in a configuration command.
func TestAnUndeclaredRouteFieldIsRefused(t *testing.T) {
	h := newHarness(t, sshtest.FortiOSOptions{VDOMMode: sshtest.FortiOSVDOMMultiple})

	_, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{
		Endpoint: h.ep, Name: "hl-a1b2-alice-0f0f0f0f",
		Fields: map[string]string{"accprofile": "super_admin"},
	})
	if err == nil {
		t.Fatal("a route field this driver never declared was accepted")
	}
}

// TestTheDriverDeclaresTheVDOMField keeps the declaration and the behaviour
// together: the provisioner skips a rung naming a field the driver does not
// declare, so a driver that implements `vdom` without declaring it is a driver
// whose feature is unreachable through the contract.
func TestTheDriverDeclaresTheVDOMField(t *testing.T) {
	caps := (&Driver{platform: PlatformFortiGate}).Capabilities()
	if !caps.AcceptsField(FieldVDOM) {
		t.Fatalf("Capabilities().Fields = %v, want it to declare %q", caps.Fields, FieldVDOM)
	}
	for _, f := range caps.Fields {
		if f.Description == "" {
			t.Errorf("the %q field is declared with no description; an operator reading a skipped rung learns nothing", f.Name)
		}
	}
}

// TestEveryOperationAddressesTheGlobalAdminTable covers the rest of the
// surface on a partitioned unit.
//
// Creation is not the only sequence that moves: `delete` and `show system
// admin` reach the same global table, and a removal or a sweep that ran against
// whatever the current VDOM has would report success while leaving a live
// privileged administrator behind. The fake refuses those at the top level, so
// each of these passing IS the assertion that the driver wrapped them.
func TestEveryOperationAddressesTheGlobalAdminTable(t *testing.T) {
	h := newHarness(t, sshtest.FortiOSOptions{VDOMMode: sshtest.FortiOSVDOMMultiple})
	ctx := context.Background()
	const name = "hl-a1b2-alice-0f0f0f0f"

	if _, err := h.driver.CreateAccount(ctx, device.CreateRequest{Endpoint: h.ep, Name: name}); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if err := h.driver.InstallCredential(ctx, device.CredentialRequest{
		Endpoint: h.ep, Name: name, Kind: control.CredentialKindPassword, Password: "device-password-1",
	}); err != nil {
		t.Fatalf("InstallCredential: %v", err)
	}
	accounts, err := h.driver.ListAccounts(ctx, device.ListRequest{Endpoint: h.ep, Prefix: "hl-"})
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(accounts) != 1 || accounts[0].Name != name {
		t.Fatalf("ListAccounts = %v, want just %q", accounts, name)
	}
	if err := h.driver.RemoveAccount(ctx, device.RemoveRequest{Endpoint: h.ep, Name: name}); err != nil {
		t.Fatalf("RemoveAccount: %v", err)
	}
	if _, ok := h.dev.Accounts()[name]; ok {
		t.Error("the administrator survived removal on a partitioned unit")
	}
	assertAdminTableIsWrapped(t, h.dev.Commands())
}

// TestTheSessionIsNeverLeftInConfigurationMode is the unwinding half of the
// nesting, and it is a separate test because nothing else notices.
//
// Every command can succeed and the account can be correct while the session
// ends sitting inside `config global`, which on a unit running workspace mode
// holds an object lock the NEXT session trips over. The fake counts a session
// that ends inside a configuration block, and this asserts the count is zero
// across the whole surface on both unit shapes;
// TestTheFakeDeviceCountsAStrandedSession pins the counter itself, so that this
// staying green keeps meaning something.
func TestTheSessionIsNeverLeftInConfigurationMode(t *testing.T) {
	for _, mode := range []string{sshtest.FortiOSVDOMDisabled, sshtest.FortiOSVDOMMultiple} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, sshtest.FortiOSOptions{VDOMMode: mode, VDOMs: []string{"root"}})
			ctx := context.Background()
			const name = "hl-a1b2-alice-0f0f0f0f"

			if _, err := h.driver.CreateAccount(ctx, device.CreateRequest{Endpoint: h.ep, Name: name}); err != nil {
				t.Fatalf("CreateAccount: %v", err)
			}
			if err := h.driver.InstallCredential(ctx, device.CredentialRequest{
				Endpoint: h.ep, Name: name, Kind: control.CredentialKindPassword, Password: "device-password-1",
			}); err != nil {
				t.Fatalf("InstallCredential: %v", err)
			}
			if _, err := h.driver.ListAccounts(ctx, device.ListRequest{Endpoint: h.ep, Prefix: "hl-"}); err != nil {
				t.Fatalf("ListAccounts: %v", err)
			}
			if err := h.driver.RemoveAccount(ctx, device.RemoveRequest{Endpoint: h.ep, Name: name}); err != nil {
				t.Fatalf("RemoveAccount: %v", err)
			}
			if n := h.dev.StrandedSessions(); n != 0 {
				t.Errorf("%d CLI sessions ended inside a configuration block; the teardown did not unwind the nesting it opened", n)
			}
		})
	}
}

// TestTheFakeDeviceCountsAStrandedSession pins the FAKE, in the same spirit as
// TestTheFakeDeviceRejectsAnUnwrappedAdminTable.
//
// A driver that unwinds one level short leaves every command it sent looking
// successful, so the only thing that can catch it is the device noticing. This
// drives the fake by hand — the documented nesting, unwound one `end` short —
// and asserts it notices, so that the driver-level assertion above is not a
// counter that would read zero whatever happened.
func TestTheFakeDeviceCountsAStrandedSession(t *testing.T) {
	h := newHarness(t, sshtest.FortiOSOptions{VDOMMode: sshtest.FortiOSVDOMMultiple})

	client, err := ssh.Dial("tcp", h.dev.Addr().String(), &ssh.ClientConfig{
		User:            "hoplock-mgmt",
		Auth:            []ssh.AuthMethod{ssh.Password("mgmt-secret")},
		HostKeyCallback: ssh.FixedHostKey(h.dev.HostKey()),
	})
	if err != nil {
		t.Fatalf("dial the device: %v", err)
	}
	defer func() { _ = client.Close() }()

	run := func(t *testing.T, script string) {
		t.Helper()
		sess, err := client.NewSession()
		if err != nil {
			t.Fatalf("open a session: %v", err)
		}
		defer func() { _ = sess.Close() }()
		sess.Stdin = strings.NewReader(script)
		sess.Stdout = &bytes.Buffer{}
		if err := sess.Shell(); err != nil {
			t.Fatalf("request a shell: %v", err)
		}
		if err := sess.Wait(); err != nil {
			t.Fatalf("shell session: %v", err)
		}
	}

	// One `end` short of the two levels the documented sequence opens: phase
	// 0014's fixed teardown, on the unit shape this phase adds.
	run(t, "config global\nconfig system admin\nedit \"probe\"\nnext\nend\nexit\n")
	if n := h.dev.StrandedSessions(); n != 1 {
		t.Fatalf("StrandedSessions = %d after a session that left `config global` open, want 1", n)
	}

	// The same sequence unwound to the top costs nothing extra and is counted
	// as what it is.
	run(t, "config global\nconfig system admin\nedit \"probe2\"\nnext\nend\nend\nexit\n")
	if n := h.dev.StrandedSessions(); n != 1 {
		t.Errorf("StrandedSessions = %d after a fully unwound session, want it unchanged at 1", n)
	}
}

// TestAFailedSequenceIsUnwoundOnAPartitionedUnit is the same property on the
// path that matters most: the one where something went wrong.
//
// `abort` discards the block, and the rollback delete then has to re-enter the
// table through `config global` again — a rollback that ran at the top level
// would delete nothing, quietly, on the one path whose whole job is to leave no
// administrator behind.
func TestAFailedSequenceIsUnwoundOnAPartitionedUnit(t *testing.T) {
	h := newHarness(t, sshtest.FortiOSOptions{
		VDOMMode: sshtest.FortiOSVDOMMultiple,
		Faults:   sshtest.FortiOSFaults{FailCommand: regexp.MustCompile(`^set accprofile`)},
	})
	const name = "hl-a1b2-alice-0f0f0f0f"

	if _, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{Endpoint: h.ep, Name: name}); err == nil {
		t.Fatal("a create whose profile step the device refused was reported as a success")
	}
	if _, ok := h.dev.Accounts()[name]; ok {
		t.Error("a failed create left an administrator on the unit")
	}
	if n := h.dev.StrandedSessions(); n != 0 {
		t.Errorf("%d CLI sessions ended inside a configuration block after a failed sequence", n)
	}
}

// TestAnUnreadableVDOMModeIsStillRefused is what is LEFT of phase 0015's
// refusal, and the acceptance criterion for this phase is that what remains is
// narrower than "the unit is running virtual domains".
//
// A unit reporting a virtual domain configuration that is none of the three
// documented values is a shape nobody has asked about, and the fail-closed
// direction is the one that does not create privileged accounts on a hunch.
func TestAnUnreadableVDOMModeIsStillRefused(t *testing.T) {
	h := newHarness(t, sshtest.FortiOSOptions{VDOMMode: "enable"})

	_, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{
		Endpoint: h.ep, Name: "hl-a1b2-alice-0f0f0f0f",
	})
	if !errors.Is(err, ErrMultiVDOM) {
		t.Fatalf("CreateAccount against a unit reporting an unknown VDOM mode returned %v, want ErrMultiVDOM", err)
	}
	if errors.Is(err, device.ErrUnsupported) {
		t.Error("an unreadable unit shape was reported as a platform limitation, which skips the ladder rung")
	}
}

// TestAUnitThatWillNotSayIsRefused is the fail-closed half of the VDOM check.
//
// The failure this whole phase corrects is a driver that was certain about a
// device shape it had never asked about. A unit whose status output this driver
// cannot read is another shape nobody has asked about, and the direction that
// does not create privileged accounts on a hunch is refusal.
func TestAUnitThatWillNotSayIsRefused(t *testing.T) {
	h := newHarness(t, sshtest.FortiOSOptions{
		Faults: sshtest.FortiOSFaults{FailCommand: regexp.MustCompile(`^get system status$`)},
	})

	_, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{
		Endpoint: h.ep, Name: "hl-a1b2-alice-0f0f0f0f",
	})
	if err == nil {
		t.Fatal("a unit that would not report its VDOM mode was provisioned anyway")
	}
}

// TestTheFakeDeviceRejectsAnUnwrappedAdminTable pins the FAKE, not the driver.
//
// It is the test that would have caught phase 0014's gap, and it has to exist
// separately because this driver now declines a multi-VDOM unit rather than
// driving one: nothing else here would notice if the fake went back to
// accepting `config system admin` at the top level. Whichever phase adds
// multi-VDOM support inherits a device that refuses the sequence 0014 wrote.
func TestTheFakeDeviceRejectsAnUnwrappedAdminTable(t *testing.T) {
	h := newHarness(t, sshtest.FortiOSOptions{VDOMMode: sshtest.FortiOSVDOMMultiple})

	client, err := ssh.Dial("tcp", h.dev.Addr().String(), &ssh.ClientConfig{
		User:            "hoplock-mgmt",
		Auth:            []ssh.AuthMethod{ssh.Password("mgmt-secret")},
		HostKeyCallback: ssh.FixedHostKey(h.dev.HostKey()),
	})
	if err != nil {
		t.Fatalf("dial the device: %v", err)
	}
	defer func() { _ = client.Close() }()

	transcript := func(t *testing.T, script string) string {
		t.Helper()
		sess, err := client.NewSession()
		if err != nil {
			t.Fatalf("open a session: %v", err)
		}
		defer func() { _ = sess.Close() }()
		var out, errOut bytes.Buffer
		sess.Stdin = strings.NewReader(script)
		sess.Stdout = &out
		sess.Stderr = &errOut
		if err := sess.Shell(); err != nil {
			t.Fatalf("request a shell: %v", err)
		}
		if err := sess.Wait(); err != nil {
			t.Fatalf("shell session: %v", err)
		}
		return out.String()
	}

	unwrapped := transcript(t, "config system admin\nedit \"probe\"\nnext\nend\nexit\n")
	if !strings.Contains(unwrapped, "Command fail") {
		t.Errorf("the fake accepted `config system admin` at the top level of a multi-VDOM unit; a driver that drops the `config global` wrapper would pass its tests and edit the wrong scope. It said:\n%s", unwrapped)
	}

	wrapped := transcript(t, "config global\nconfig system admin\nedit \"probe\"\nnext\nend\nend\nexit\n")
	if strings.Contains(wrapped, "Command fail") {
		t.Errorf("the fake refused Fortinet's own documented multi-VDOM sequence, so it is strict in a way the device is not. It said:\n%s", wrapped)
	}
	if _, ok := h.dev.Accounts()["probe"]; !ok {
		t.Error("the documented sequence did not create an administrator; the fake is not modelling the wrapped table at all")
	}
}

// TestAnIPv6SourceAddressIsRefusedRatherThanMisrendered covers the other half
// of claim 9.
//
// `trusthost1` is an `ipv4-classnet` field. Phase 0014 rendered an IPv6 source
// as `<addr>/128` and wrote it there, so an IPv6-fronted proxy would have met a
// parse error from the device instead of a sentence naming the limitation.
func TestAnIPv6SourceAddressIsRefusedRatherThanMisrendered(t *testing.T) {
	h := newHarness(t, sshtest.FortiOSOptions{})
	const name = "hl-a1b2-alice-0f0f0f0f"

	_, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{
		Endpoint: h.ep, Name: name, SourceAddress: "2001:db8::7",
	})
	if err == nil {
		t.Fatal("an IPv6 source address was accepted; it would have been written into an IPv4 field")
	}
	if _, ok := h.dev.Accounts()[name]; ok {
		t.Error("an administrator was created despite the pin the route asked for not being applicable")
	}
	for _, cmd := range h.dev.Commands() {
		if strings.HasPrefix(cmd, "set trusthost1") {
			t.Errorf("the driver sent %q; an IPv6 address in an ipv4-classnet field is a device error, not a pin", cmd)
		}
	}
}

// TestAnUnnamedAccessProfileIsRefused is phase 0015's access-profile decision,
// as a test rather than as a comment.
//
// There is no default: `prof_admin_readonly` — the profile the old default was
// ranked against — appears in no Fortinet source, `super_admin_readonly` cannot
// run `diagnose` from 7.4.x, and neither fits a per-VDOM account. A privileged
// account's scope is named by somebody or the account is not created.
func TestAnUnnamedAccessProfileIsRefused(t *testing.T) {
	h := newHarness(t, sshtest.FortiOSOptions{})
	unconfigured, err := New(Options{Dialer: stubDialer{}})
	if err != nil {
		t.Fatalf("a driver with no access profile must still build, because a route may name its own: %v", err)
	}

	const name = "hl-a1b2-alice-0f0f0f0f"
	_, err = unconfigured.CreateAccount(context.Background(), device.CreateRequest{Endpoint: h.ep, Name: name})
	if err == nil {
		t.Fatal("an administrator was created with no access profile at all")
	}
	// Not ErrUnsupported: the platform scopes administrators perfectly well,
	// this proxy was simply never told which scope to use, and a skipped rung
	// would answer a configuration gap with a weaker credential.
	if errors.Is(err, device.ErrUnsupported) {
		t.Error("a missing access profile was reported as a platform limitation, which skips the ladder rung instead of failing the attempt")
	}
	if _, ok := h.dev.Accounts()[name]; ok {
		t.Error("the refused account is on the device anyway")
	}
}

// stubDialer stands in for a dialer that is never reached: the profile check
// happens before anything is opened, which is the point — refusing after
// dialling would mean a connection to a customer's firewall to discover a
// configuration mistake.
type stubDialer struct{}

func (stubDialer) Shell(context.Context, device.Endpoint) (device.Shell, error) {
	return nil, errors.New("the access-profile check must refuse before anything is dialled")
}

// TestTheDeclaredNameLimitIsTheDocumentedOne guards the correction in both
// directions: the driver's declaration and the fake device's enforcement have
// to move together, or one of them is quietly standing in for a device that
// does not exist.
func TestTheDeclaredNameLimitIsTheDocumentedOne(t *testing.T) {
	if sshtest.FortiOSMaxNameLen != FortiOSMaxNameLenDeclared {
		t.Fatalf("the fake device enforces %d characters and the driver declares %d; a fake more permissive than the device is how a driver bug becomes a green build",
			sshtest.FortiOSMaxNameLen, FortiOSMaxNameLenDeclared)
	}

	h := newHarness(t, sshtest.FortiOSOptions{})
	ctx := context.Background()

	atLimit := "hl-" + strings.Repeat("a", FortiOSMaxNameLenDeclared-3)
	if _, err := h.driver.CreateAccount(ctx, device.CreateRequest{Endpoint: h.ep, Name: atLimit}); err != nil {
		t.Errorf("a name of exactly %d characters was refused: %v", FortiOSMaxNameLenDeclared, err)
	}

	overLimit := atLimit + "a"
	if _, err := h.driver.CreateAccount(ctx, device.CreateRequest{Endpoint: h.ep, Name: overLimit}); err == nil {
		t.Errorf("a name of %d characters was accepted; the field stops at %d", len(overLimit), FortiOSMaxNameLenDeclared)
	}
}
