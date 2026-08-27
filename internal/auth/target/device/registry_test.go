// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package device

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// fixtureDriver is a driver that does nothing, so that the registry and the
// shipped-driver invariant can be exercised without a device — and, more to the
// point, so that the invariant's own test can be shown to FAIL when a
// persisting driver is registered. A check that has never been seen to fail is
// a check nobody has evidence for.
type fixtureDriver struct {
	platform string
	caps     Capabilities
}

func (d fixtureDriver) Platform() string           { return d.platform }
func (d fixtureDriver) Capabilities() Capabilities { return d.caps }

func (d fixtureDriver) CreateAccount(context.Context, CreateRequest) (*Account, error) {
	return nil, Unsupported(d.platform, "create an account (fixture driver)")
}

func (d fixtureDriver) InstallCredential(context.Context, CredentialRequest) error {
	return Unsupported(d.platform, "install a credential (fixture driver)")
}

func (d fixtureDriver) RemoveAccount(context.Context, RemoveRequest) error { return nil }

func (d fixtureDriver) ListAccounts(context.Context, ListRequest) ([]Account, error) {
	return nil, nil
}

func wellBehaved(platform string) fixtureDriver {
	return fixtureDriver{
		platform: platform,
		caps: Capabilities{
			MaxAccountNameLen: 32,
			EnforcesExpiry:    true,
			CredentialKinds:   []control.CredentialKind{control.CredentialKindPublicKey},
			PinsSourceAddress: true,
		},
	}
}

// TestShippedDriversDoNotPersistAccounts is D13's invariant, expressed as a
// test over the registry rather than as a comment on the field.
//
// Phase 0013 ships no drivers, so the first half passes over an empty registry.
// The second half is what gives that any weight: the same check over a registry
// holding a persisting driver must fail, and its message must say why.
func TestShippedDriversDoNotPersistAccounts(t *testing.T) {
	if err := CheckShipped(Shipped()); err != nil {
		t.Fatalf("a driver this repository ships persists accounts across reload: %v", err)
	}

	// Prove the check can fail, or the assertion above is vacuous.
	reg := NewRegistry()
	if err := reg.Register(wellBehaved("compliant-platform")); err != nil {
		t.Fatalf("Register: %v", err)
	}
	persisting := fixtureDriver{
		platform: "persisting-platform",
		caps:     Capabilities{MaxAccountNameLen: 32, PersistsAcrossReload: true},
	}
	if err := reg.Register(persisting); err != nil {
		t.Fatalf("Register: %v", err)
	}

	err := CheckShipped(reg)
	if err == nil {
		t.Fatal("CheckShipped accepted a driver declaring PersistsAcrossReload")
	}
	for _, want := range []string{"persisting-platform", "PersistsAcrossReload", "D13", "CUSTOMER"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("CheckShipped error %q does not mention %q; the failure has to say why", err, want)
		}
	}
}

// TestUnknownPlatformIsRefusedNeverGuessed covers the registry's central
// promise: a platform with no driver is an outage-class denial, and never the
// nearest driver.
func TestUnknownPlatformIsRefusedNeverGuessed(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(wellBehaved("fortios")); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, err := reg.Lookup("fortios"); err != nil {
		t.Fatalf("Lookup of a registered platform: %v", err)
	}

	// "fortiswitch" is deliberately close to a registered platform: the one
	// answer that must not happen is the near neighbour being served.
	got, err := reg.Lookup("fortiswitch")
	if !errors.Is(err, ErrUnknownPlatform) {
		t.Fatalf("Lookup(unknown) error = %v, want ErrUnknownPlatform", err)
	}
	if got != nil {
		t.Errorf("Lookup(unknown) returned driver %v, want nothing at all", got)
	}
	if !strings.Contains(err.Error(), "fortios") {
		t.Errorf("error %q does not name the platforms this proxy has", err)
	}

	if _, err := (*Registry)(nil).Lookup("fortios"); !errors.Is(err, ErrUnknownPlatform) {
		t.Errorf("Lookup on a nil registry = %v, want ErrUnknownPlatform", err)
	}
}

// TestDuplicatePlatformIsRefusedAtRegistration keeps link order out of the
// question of which driver a route gets.
func TestDuplicatePlatformIsRefusedAtRegistration(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(wellBehaved("fortios")); err != nil {
		t.Fatalf("Register: %v", err)
	}
	err := reg.Register(fixtureDriver{platform: "fortios"})
	if !errors.Is(err, ErrDuplicatePlatform) {
		t.Fatalf("second Register = %v, want ErrDuplicatePlatform", err)
	}

	if err := reg.Register(nil); err == nil {
		t.Error("Register(nil) succeeded")
	}
	if err := reg.Register(fixtureDriver{}); err == nil {
		t.Error("Register of a driver with no platform name succeeded")
	}
}

// TestPlatformsIsWhatTheProxyAdvertises pins the ordering, because the list is
// what Hoplock Control is told this proxy can reach.
func TestPlatformsIsWhatTheProxyAdvertises(t *testing.T) {
	reg := NewRegistry()
	for _, p := range []string{"panos", "fortios", "ios-xe"} {
		if err := reg.Register(wellBehaved(p)); err != nil {
			t.Fatalf("Register(%s): %v", p, err)
		}
	}
	got := reg.Platforms()
	want := []string{"fortios", "ios-xe", "panos"}
	if len(got) != len(want) {
		t.Fatalf("Platforms() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Platforms() = %v, want %v", got, want)
		}
	}
	if len(reg.Drivers()) != len(want) {
		t.Errorf("Drivers() returned %d drivers, want %d", len(reg.Drivers()), len(want))
	}
	if len((*Registry)(nil).Platforms()) != 0 {
		t.Error("a nil registry advertises platforms")
	}
}

// TestCapabilitiesAreDataNotBehaviour is a compile-and-read assertion: a
// driver's declarations must be answerable without a device, because the
// provisioner reads them to decide whether a ladder rung is servable at all —
// including one it is about to skip, where there is nothing to connect to.
func TestCapabilitiesAreDataNotBehaviour(t *testing.T) {
	caps := wellBehaved("fortios").Capabilities()
	if !caps.Accepts(control.CredentialKindPublicKey) {
		t.Error("Accepts(publickey) = false on a driver declaring it")
	}
	if caps.Accepts(control.CredentialKindPassword) {
		t.Error("Accepts(password) = true on a driver that does not declare it")
	}
	if caps.MaxAccountNameLen == 0 {
		t.Error("MaxAccountNameLen is undeclared; zero is refused, never assumed generous")
	}
}

// TestUnsupportedIsDistinguishableFromAFailedAttempt guards the distinction
// phase 0014's provisioner and reaper both branch on. An unsupported operation
// skips the ladder rung; a failed attempt fails the session. Confusing the two
// turns a device outage into a silent downgrade, or a permanent limitation into
// a session that never connects.
func TestUnsupportedIsDistinguishableFromAFailedAttempt(t *testing.T) {
	d := wellBehaved("fortios")

	err := d.InstallCredential(context.Background(), CredentialRequest{
		Endpoint: Endpoint{Host: "fw-01", Port: 22, SessionID: "sess-1"},
		Name:     "hl-ab12-cd34",
		Kind:     control.CredentialKindPublicKey,
	})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("InstallCredential error = %v, want ErrUnsupported", err)
	}
	if !strings.Contains(err.Error(), "fortios") {
		t.Errorf("error %q does not name the driver that cannot do it", err)
	}

	attemptFailed := errors.New("device returned: command parse error")
	if errors.Is(attemptFailed, ErrUnsupported) {
		t.Error("a plain failure reads as ErrUnsupported")
	}
	if errors.Is(ErrAccountExists, ErrUnsupported) {
		t.Error("ErrAccountExists reads as ErrUnsupported; a name collision is retryable")
	}
}

// TestRequestsCarryTheEndpointNotTheDriver records why a driver holds no
// connection: the reaper reaches devices no session is using, so every
// operation names its own device.
func TestRequestsCarryTheEndpointNotTheDriver(t *testing.T) {
	req := CreateRequest{
		Endpoint: Endpoint{Host: "fw-01.example.net", Port: 22, SessionID: "sess-1"},
		Name:     "hl-ab12-cd34",
		Profile:  "hoplock-readonly",
		Lifetime: 15 * time.Minute,
	}
	if req.Host == "" || req.SessionID == "" {
		t.Error("CreateRequest does not carry its endpoint")
	}
	list := ListRequest{Endpoint: Endpoint{Host: "fw-01.example.net"}, Prefix: "hl-ab12-"}
	if list.Prefix == "" {
		t.Error("ListRequest does not carry the reaper prefix that scopes it to this proxy")
	}
}
