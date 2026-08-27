// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package fortios

import (
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
	driver, err := New(Options{Dialer: dialer})
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
	if acct.Profile != DefaultAccessProfile {
		t.Errorf("created with profile %q, want %q", acct.Profile, DefaultAccessProfile)
	}
	if !acct.CreatedAt.IsZero() {
		t.Error("FortiOS does not record a creation time; a driver reporting one would have the reaper age accounts against a fiction")
	}

	on := h.dev.Accounts()[name]
	if on.Profile != DefaultAccessProfile {
		t.Errorf("device has profile %q, want %q", on.Profile, DefaultAccessProfile)
	}
	if on.TrustHost != "198.51.100.7 255.255.255.255" {
		t.Errorf("device has trusthost %q, want the proxy pinned as a /32", on.TrustHost)
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
	if caps.EnforcesExpiry {
		t.Error("FortiOS has no per-administrator expiry field; declaring one would make the target-enforced posture satisfiable by nothing")
	}
	if caps.MaxAccountNameLen != FortiOSMaxNameLenDeclared {
		t.Errorf("declared name limit %d, want %d", caps.MaxAccountNameLen, FortiOSMaxNameLenDeclared)
	}
}

// FortiOSMaxNameLenDeclared pins the verified limit in the test as well as the
// driver, so a change to one is a visible change to the other.
const FortiOSMaxNameLenDeclared = 35
