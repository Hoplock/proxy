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

// switchHarness is a FortiSwitchOS driver wired to a fake switch.
type switchHarness struct {
	dev    *sshtest.FakeFortiOS
	driver *SwitchDriver
	ep     device.Endpoint
}

// testSwitchProfile is what these tests configure the switch driver with.
//
// `super_admin` because it is the ONLY profile FortiSwitchOS documents as
// built in — not because the driver prefers it, and not because an all-access
// profile is a good scope for a session. A narrower scope on this platform is
// a custom profile the customer builds, which is exactly what the capability's
// AuthorizationCaveat says.
const testSwitchProfile = "super_admin"

func newSwitchHarness(t *testing.T, opts sshtest.FortiOSOptions) *switchHarness {
	t.Helper()
	opts.Platform = sshtest.FortiOSPlatformFortiSwitch
	dev, err := sshtest.StartFortiOS(opts)
	if err != nil {
		t.Fatalf("start fake switch: %v", err)
	}
	t.Cleanup(func() { _ = dev.Close() })

	dialer, err := device.NewSSHShellDialer(device.SSHShellOptions{
		User:     firstNonEmpty(opts.AdminUser, "hoplock-mgmt"),
		Password: firstNonEmpty(opts.AdminPassword, "mgmt-secret"),
	})
	if err != nil {
		t.Fatalf("dialer: %v", err)
	}
	driver, err := NewSwitch(SwitchOptions{Dialer: dialer, AccessProfile: testSwitchProfile})
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	return &switchHarness{
		dev:    dev,
		driver: driver,
		ep: device.Endpoint{
			Host:            dev.Host(),
			Port:            dev.Port(),
			SessionID:       "sess-switch-1",
			HostKeyCallback: ssh.FixedHostKey(dev.HostKey()),
		},
	}
}

// TestSwitchLifecycleAgainstTheDevice is the whole driver in one pass: create,
// credential, enumerate, remove.
func TestSwitchLifecycleAgainstTheDevice(t *testing.T) {
	h := newSwitchHarness(t, sshtest.FortiOSOptions{
		Accounts: []sshtest.FortiOSAccount{{Name: "admin", Profile: "super_admin"}},
	})
	ctx := context.Background()
	const name = "hl-p1-alice-abc123"

	acct, err := h.driver.CreateAccount(ctx, device.CreateRequest{Endpoint: h.ep, Name: name})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if acct.Name != name || acct.Profile != testSwitchProfile {
		t.Fatalf("created %+v, want name %q profile %q", acct, name, testSwitchProfile)
	}

	if err := h.driver.InstallCredential(ctx, device.CredentialRequest{
		Endpoint: h.ep, Name: name,
		Kind: control.CredentialKindPassword, Password: "s3cret-value",
	}); err != nil {
		t.Fatalf("install credential: %v", err)
	}
	if got := h.dev.Accounts()[name].Password; got != "s3cret-value" {
		t.Fatalf("device holds password %q", got)
	}

	found, err := h.driver.ListAccounts(ctx, device.ListRequest{Endpoint: h.ep, Prefix: "hl-"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(found) != 1 || found[0].Name != name {
		t.Fatalf("listed %+v, want just %q", found, name)
	}

	if err := h.driver.RemoveAccount(ctx, device.RemoveRequest{Endpoint: h.ep, Name: name}); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, ok := h.dev.Accounts()[name]; ok {
		t.Fatal("the administrator is still on the switch after removal")
	}
	// Removal is idempotent because teardown runs on the normal path, on
	// error, and from the reaper.
	if err := h.driver.RemoveAccount(ctx, device.RemoveRequest{Endpoint: h.ep, Name: name}); err != nil {
		t.Fatalf("second remove: %v", err)
	}
	if n := h.dev.StrandedSessions(); n != 0 {
		t.Fatalf("%d session(s) ended inside a configuration block", n)
	}
}

// TestSwitchInstallsAPublicKey is the credential kind the phase nearly lost.
//
// Had the switch been administered through its FortiGate, the only way in
// would have been FortiOS's `execute switch-controller ssh`, whose client
// takes no identity file — so the credential would have had to be a password
// whatever FortiSwitchOS accepts. Connecting to the switch directly is what
// keeps `set ssh-public-key1` reachable, and this is the test that says so.
func TestSwitchInstallsAPublicKey(t *testing.T) {
	h := newSwitchHarness(t, sshtest.FortiOSOptions{})
	ctx := context.Background()
	const name = "hl-p1-bob-def456"

	if _, err := h.driver.CreateAccount(ctx, device.CreateRequest{Endpoint: h.ep, Name: name}); err != nil {
		t.Fatalf("create: %v", err)
	}
	signer, err := sshtest.GenerateSigner()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	authorized := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	if err := h.driver.InstallCredential(ctx, device.CredentialRequest{
		Endpoint: h.ep, Name: name,
		Kind: control.CredentialKindPublicKey, PublicKey: authorized,
	}); err != nil {
		t.Fatalf("install public key: %v", err)
	}

	// Asserting the switch HOLDS the key is not enough — that is the gap the
	// FortiGate fake was built to close. Log in as the account.
	client, err := ssh.Dial("tcp", h.dev.Addr().String(), &ssh.ClientConfig{
		User:            name,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(h.dev.HostKey()),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("the created administrator could not log in with its key: %v", err)
	}
	_ = client.Close()
}

// TestSwitchRefusesAUnitThatIsNotOne is the check that matters most on this
// platform, because the failure it prevents is silent.
//
// `config system admin` / `edit` / `set accprofile` / `set password` are valid
// on a FortiGate too, so a route naming this platform against a firewall would
// create a privileged administrator there and report success — with an audit
// record naming a switch.
func TestSwitchRefusesAUnitThatIsNotOne(t *testing.T) {
	t.Run("a FortiGate answering", func(t *testing.T) {
		// The fake in its DEFAULT platform: a FortiGate, which is exactly the
		// misrouted case.
		dev, err := sshtest.StartFortiOS(sshtest.FortiOSOptions{})
		if err != nil {
			t.Fatalf("start fake device: %v", err)
		}
		t.Cleanup(func() { _ = dev.Close() })
		dialer, err := device.NewSSHShellDialer(device.SSHShellOptions{User: "hoplock-mgmt", Password: "mgmt-secret"})
		if err != nil {
			t.Fatalf("dialer: %v", err)
		}
		driver, err := NewSwitch(SwitchOptions{Dialer: dialer, AccessProfile: testSwitchProfile})
		if err != nil {
			t.Fatalf("driver: %v", err)
		}
		_, err = driver.CreateAccount(context.Background(), device.CreateRequest{
			Endpoint: device.Endpoint{
				Host: dev.Host(), Port: dev.Port(), SessionID: "sess-1",
				HostKeyCallback: ssh.FixedHostKey(dev.HostKey()),
			},
			Name: "hl-p1-eve-aaa111",
		})
		if !errors.Is(err, ErrNotAFortiSwitch) {
			t.Fatalf("create against a FortiGate returned %v, want ErrNotAFortiSwitch", err)
		}
		if len(dev.Accounts()) != 0 {
			t.Fatalf("an administrator was created on the FortiGate: %+v", dev.Accounts())
		}
		// NOT ErrUnsupported: the platform and the driver are both capable and
		// the route pointed at the wrong device, so skipping the rung would
		// serve the session on a credential the server ranked lower.
		if errors.Is(err, device.ErrUnsupported) {
			t.Fatal("a misrouted route must be an outage-class denial, not a skipped ladder rung")
		}
	})

	t.Run("a unit that will not say what it is", func(t *testing.T) {
		h := newSwitchHarness(t, sshtest.FortiOSOptions{Faults: sshtest.FortiOSFaults{HideIdentity: true}})
		_, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{Endpoint: h.ep, Name: "hl-p1-eve-bbb222"})
		if !errors.Is(err, ErrNotAFortiSwitch) {
			t.Fatalf("create returned %v, want ErrNotAFortiSwitch", err)
		}
		if len(h.dev.Accounts()) != 0 {
			t.Fatalf("an administrator was created on an unidentified unit: %+v", h.dev.Accounts())
		}
	})
}

// TestSwitchRefusesFortiOSBuiltinProfiles covers the configuration mistake a
// FortiGate estate makes on the day it acquires its first switch.
func TestSwitchRefusesFortiOSBuiltinProfiles(t *testing.T) {
	for _, profile := range []string{"super_admin_readonly", "prof_admin"} {
		t.Run(profile, func(t *testing.T) {
			if err := SwitchAcceptsProfile(profile); err == nil {
				t.Fatalf("SwitchAcceptsProfile(%q) accepted a FortiOS-only built-in", profile)
			}
			if _, err := NewSwitch(SwitchOptions{Dialer: stubDialer{}, AccessProfile: profile}); err == nil {
				t.Fatalf("NewSwitch accepted %q", profile)
			}

			// And it is refused BEFORE anything is dialled, so the mistake
			// never leaves a half-created administrator behind.
			h := newSwitchHarness(t, sshtest.FortiOSOptions{})
			_, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{
				Endpoint: h.ep, Name: "hl-p1-carol-ccc333", Profile: profile,
			})
			if err == nil {
				t.Fatalf("create accepted route profile %q", profile)
			}
			if !strings.Contains(err.Error(), "super_admin") {
				t.Fatalf("the refusal does not name what FortiSwitchOS does have: %v", err)
			}
			if len(h.dev.Accounts()) != 0 {
				t.Fatalf("an administrator was created anyway: %+v", h.dev.Accounts())
			}
		})
	}

	// A custom profile is the customer's to scope, so only the two FortiOS
	// built-ins are refused.
	if err := SwitchAcceptsProfile("hoplock-session"); err != nil {
		t.Fatalf("SwitchAcceptsProfile refused a custom profile: %v", err)
	}
}

// TestSwitchDeclaresNoExpiryAndRefusesALifetime pins the contradiction this
// phase found rather than papering over it.
func TestSwitchDeclaresNoExpiryAndRefusesALifetime(t *testing.T) {
	caps := (&SwitchDriver{}).Capabilities()
	if caps.EnforcesExpiry {
		t.Fatal("FortiSwitchOS declares a deadline mechanism whose table its own documentation names does not exist there")
	}
	if caps.ExpiryMechanism != "" {
		t.Fatal("a driver that does not enforce expiry must not describe how it does")
	}

	h := newSwitchHarness(t, sshtest.FortiOSOptions{})
	_, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{
		Endpoint: h.ep, Name: "hl-p1-dave-ddd444", Lifetime: time.Hour,
	})
	// ErrUnsupported here and NOT on the misrouted-unit path above: this one
	// really is "the platform cannot", which is what makes the rung
	// unsatisfiable rather than the attempt failed.
	if !errors.Is(err, device.ErrUnsupported) {
		t.Fatalf("create with a lifetime returned %v, want device.ErrUnsupported", err)
	}
}

// TestSwitchIsNotAResidueSweeper is the reason SwitchDriver is its own type.
//
// The reaper discovers the residue sweep by type assertion, so a switch served
// by *Driver would have `config firewall schedule onetime` swept against a
// platform that has no such table — a reported sweep failure on a customer's
// switch every two minutes, for an object class that does not exist.
func TestSwitchIsNotAResidueSweeper(t *testing.T) {
	if _, ok := any(&SwitchDriver{}).(device.ResidueSweeper); ok {
		t.Fatal("the FortiSwitch driver claims a residue sweep for a table FortiSwitchOS does not have")
	}
	// The FortiGate driver still is one, so the assertion is discriminating.
	if _, ok := any(&Driver{}).(device.ResidueSweeper); !ok {
		t.Fatal("the FortiGate driver stopped being a residue sweeper")
	}
}

// TestSwitchRefusesRouteFields holds the target-identity decision in place.
//
// This platform is exactly one target: there is no partition for a route to
// name, so it declares no fields and refuses one that arrives anyway. If a
// later phase reintroduces a device-selecting field here, this test is what
// makes that a deliberate change rather than a drift.
func TestSwitchRefusesRouteFields(t *testing.T) {
	if fields := (&SwitchDriver{}).Capabilities().Fields; len(fields) != 0 {
		t.Fatalf("FortiSwitchOS declares route fields %+v", fields)
	}
	h := newSwitchHarness(t, sshtest.FortiOSOptions{})
	_, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{
		Endpoint: h.ep, Name: "hl-p1-erin-eee555",
		Fields: map[string]string{"switch": "S248EPTF19000001"},
	})
	if err == nil {
		t.Fatal("create accepted a route field on a platform that declares none")
	}
	if len(h.dev.Accounts()) != 0 {
		t.Fatalf("an administrator was created anyway: %+v", h.dev.Accounts())
	}
}

// TestSwitchNameLimitIsTheDeclaredOne checks the fake and the driver agree
// about the one figure Fortinet does not publish.
//
// They are deliberately the same number, so that a real unit proving the field
// wider or narrower moves both — see maxSwitchAccountNameLen.
func TestSwitchNameLimitIsTheDeclaredOne(t *testing.T) {
	if got := (&SwitchDriver{}).Capabilities().MaxAccountNameLen; got != sshtest.FortiSwitchMaxNameLen {
		t.Fatalf("the driver declares %d and the fake enforces %d", got, sshtest.FortiSwitchMaxNameLen)
	}
	// It still clears PLAN §5.3's threshold, so a switch administrator gets
	// the readable naming scheme and no behaviour turns on the difference.
	if sshtest.FortiSwitchMaxNameLen < 32 {
		t.Fatalf("%d would put FortiSwitchOS on the constrained naming scheme", sshtest.FortiSwitchMaxNameLen)
	}

	h := newSwitchHarness(t, sshtest.FortiOSOptions{})
	long := "hl-p1-" + strings.Repeat("z", sshtest.FortiSwitchMaxNameLen)
	if _, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{Endpoint: h.ep, Name: long}); err == nil {
		t.Fatal("create accepted a name longer than the platform's limit")
	}
}

// TestSwitchNeverAdopts is D13's rule on the platform where it bites hardest.
func TestSwitchNeverAdopts(t *testing.T) {
	const name = "hl-p1-frank-fff666"
	h := newSwitchHarness(t, sshtest.FortiOSOptions{
		Accounts: []sshtest.FortiOSAccount{{Name: name, Profile: "super_admin", Password: "somebody-elses"}},
	})
	_, err := h.driver.CreateAccount(context.Background(), device.CreateRequest{Endpoint: h.ep, Name: name})
	if !errors.Is(err, device.ErrAccountExists) {
		t.Fatalf("create returned %v, want device.ErrAccountExists", err)
	}
	// The other session's credential is untouched: adopting would have
	// overwritten it, and its teardown would then remove this session's access.
	if got := h.dev.Accounts()[name].Password; got != "somebody-elses" {
		t.Fatalf("the existing administrator's password became %q", got)
	}
}

// TestSwitchUnreachableIsRetryableAndNotASilentSuccess covers the failure a
// FortiLink deployment actually has: the managing FortiGate closing SSH on the
// switch's interfaces through `config switch-controller security-policy
// local-access`, which this proxy sees as an ordinary unreachable device.
func TestSwitchUnreachableIsRetryableAndNotASilentSuccess(t *testing.T) {
	h := newSwitchHarness(t, sshtest.FortiOSOptions{})
	ctx := context.Background()
	h.dev.SetUnreachable(true)

	if _, err := h.driver.CreateAccount(ctx, device.CreateRequest{Endpoint: h.ep, Name: "hl-p1-gina-ggg777"}); err == nil {
		t.Fatal("create against an unreachable switch reported success")
	} else if errors.Is(err, device.ErrUnsupported) {
		// A device that is down is a RETRYABLE failure. Reporting it as
		// ErrUnsupported would make the rung unsatisfiable and walk the
		// session down to a credential the server ranked lower — a silent
		// downgrade triggered by a reboot.
		t.Fatalf("an unreachable switch was reported as a permanent platform limitation: %v", err)
	}
	if _, err := h.driver.ListAccounts(ctx, device.ListRequest{Endpoint: h.ep, Prefix: "hl-"}); err == nil {
		// The sweep half, and the one that matters: an enumerate that returned
		// nothing would tell the reaper the switch is clean.
		t.Fatal("enumerating an unreachable switch reported an empty administrator table")
	}

	h.dev.SetUnreachable(false)
	if _, err := h.driver.CreateAccount(ctx, device.CreateRequest{Endpoint: h.ep, Name: "hl-p1-gina-ggg777"}); err != nil {
		t.Fatalf("create after the switch came back: %v", err)
	}
}
