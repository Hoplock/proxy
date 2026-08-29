// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/auth/target/device"
	"github.com/hoplock/proxy/internal/auth/target/device/fortios"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/identity"
	"github.com/hoplock/proxy/internal/sshtest"
)

// deviceHarness is a device provisioner wired to a fake FortiOS device.
type deviceHarness struct {
	dev    *sshtest.FakeFortiOS
	auth   *DeviceAccountAuthenticator
	events *recordingSink
	tgt    Target
}

// recordingSink stands in for the telemetry pipeline.
type recordingSink struct {
	mu           sync.Mutex
	deliverable  bool
	mappings     []AccountMapping
	sweepFailure []SweepFailure
}

func (s *recordingSink) Deliverable() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deliverable
}

func (s *recordingSink) AccountMapping(ev AccountMapping) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mappings = append(s.mappings, ev)
}

func (s *recordingSink) SweepFailure(ev SweepFailure) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepFailure = append(s.sweepFailure, ev)
}

func (s *recordingSink) mapping() []AccountMapping {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AccountMapping(nil), s.mappings...)
}

func (s *recordingSink) failures() []SweepFailure {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]SweepFailure(nil), s.sweepFailure...)
}

// testDeviceAccessProfile is the scope these tests give a created
// administrator. It is a real FortiOS built-in, chosen by the test rather than
// by the driver.
const testDeviceAccessProfile = "super_admin_readonly"

type deviceHarnessOptions struct {
	fortios     sshtest.FortiOSOptions
	deliverable bool
	noEvents    bool
	proxyID     string
	reaperGrace time.Duration
	// nameLimit overrides the driver's declared limit, which is how the
	// constrained naming scheme is reached: FortiOS itself is above the
	// threshold, and the constrained path is every tighter platform's.
	nameLimit int
	now       func() time.Time
}

func newDeviceHarness(t *testing.T, opts deviceHarnessOptions) *deviceHarness {
	t.Helper()
	dev, err := sshtest.StartFortiOS(opts.fortios)
	if err != nil {
		t.Fatalf("start fake device: %v", err)
	}
	t.Cleanup(func() { _ = dev.Close() })

	dialer, err := device.NewSSHShellDialer(device.SSHShellOptions{
		User: "hoplock-mgmt", Password: "mgmt-secret",
	})
	if err != nil {
		t.Fatalf("dialer: %v", err)
	}
	registry := device.NewRegistry()
	driver, err := fortios.New(fortios.Options{Dialer: dialer})
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	// The proxy names the access profile, because since phase 0015 no driver
	// carries a default one: an administrator's scope on a customer's firewall
	// is a decision somebody makes.
	var toRegister device.Driver = driver
	if opts.nameLimit > 0 {
		toRegister = &limitedDriver{Driver: driver, limit: opts.nameLimit}
	}
	if err := registry.Register(toRegister); err != nil {
		t.Fatalf("register: %v", err)
	}

	sink := &recordingSink{deliverable: opts.deliverable}
	var events DeviceEventSink
	if !opts.noEvents {
		events = sink
	}
	proxyID := opts.proxyID
	if proxyID == "" {
		proxyID = "proxy-a"
	}
	auth, err := NewDeviceAccountAuthenticator(DeviceAccountOptions{
		ProxyID:        proxyID,
		Drivers:        registry,
		SourceAddress:  "198.51.100.7",
		AccessProfile:  testDeviceAccessProfile,
		Events:         events,
		ReaperInterval: -1, // no background sweeping; tests call Sweep directly
		ReaperGrace:    opts.reaperGrace,
		Now:            opts.now,
	})
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}

	return &deviceHarness{
		dev:    dev,
		auth:   auth,
		events: sink,
		tgt: Target{
			Host:            dev.Host(),
			Port:            dev.Port(),
			SessionID:       "sess-1",
			HostKeyCallback: ssh.FixedHostKey(dev.HostKey()),
		},
	}
}

// limitedDriver is a driver that declares a tighter name limit than it has, so
// the constrained naming scheme can be exercised against a real device.
type limitedDriver struct {
	device.Driver
	limit int
}

func (d *limitedDriver) Capabilities() device.Capabilities {
	caps := d.Driver.Capabilities()
	caps.MaxAccountNameLen = d.limit
	return caps
}

// deviceIdentity is the authenticated user a device session belongs to.
func deviceIdentity() *identity.Identity {
	return &identity.Identity{
		Subject: "u-1",
		Login:   "alice",
		Source:  "fixture",
		Method:  identity.MethodCert,
	}
}

func deviceRouteAuth(overrides map[string]string) *control.TargetAuth {
	params := map[string]string{
		control.ParamUsername:        "alice",
		control.ParamPlatform:        fortios.PlatformFortiGate,
		control.ParamCredentialKind:  string(control.CredentialKindPassword),
		control.ParamExpiryPosture:   string(control.ExpiryPostureProxyEnforced),
		control.ParamLifetimeSeconds: "3600",
	}
	for k, v := range overrides {
		if v == "" {
			delete(params, k)
			continue
		}
		params[k] = v
	}
	return &control.TargetAuth{Method: control.TargetAuthEphemeralAccount, Params: params}
}

// TestDeviceSessionProvisionsConnectsAndTearsDown is the whole lifecycle: an
// administrator that exists only for the session, and is gone afterwards.
func TestDeviceSessionProvisionsConnectsAndTearsDown(t *testing.T) {
	h := newDeviceHarness(t, deviceHarnessOptions{deliverable: true})
	ctx := context.Background()

	tgt := h.tgt
	tgt.Auth = deviceRouteAuth(nil)
	access, err := h.auth.Provision(ctx, deviceIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	name := access.ClientConfig.User
	if !strings.HasPrefix(name, principalPrefix) {
		t.Errorf("account %q does not carry the reaper's prefix", name)
	}
	if !strings.Contains(name, "alice") {
		t.Errorf("account %q drops the login segment, but FortiOS accepts 64 characters and should keep it", name)
	}
	on, ok := h.dev.Accounts()[name]
	if !ok {
		t.Fatalf("account %q was not created; the device has %v", name, h.dev.Accounts())
	}
	if on.TrustHost == "" {
		t.Error("the account was not pinned to the proxy's address, though the driver declares it can be")
	}

	if err := access.Close(ctx); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if _, ok := h.dev.Accounts()[name]; ok {
		t.Fatal("the administrator survived teardown; that is a standing privileged account on a firewall")
	}
	// Idempotent: teardown runs on the normal path, on error, on panic, and
	// from the reaper.
	if err := access.Close(ctx); err != nil {
		t.Fatalf("second teardown: %v", err)
	}
}

// TestMappingEventCarriesAttribution covers PLAN §5.3's load-bearing event.
func TestMappingEventCarriesAttribution(t *testing.T) {
	h := newDeviceHarness(t, deviceHarnessOptions{deliverable: true})
	tgt := h.tgt
	tgt.Auth = deviceRouteAuth(nil)
	tgt.Rung = 2

	access, err := h.auth.Provision(context.Background(), deviceIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = access.Close(context.Background()) })

	events := h.events.mapping()
	if len(events) != 1 {
		t.Fatalf("got %d mapping events, want exactly one", len(events))
	}
	ev := events[0]
	switch {
	case ev.Account != access.ClientConfig.User:
		t.Errorf("mapping names account %q, session connected as %q", ev.Account, access.ClientConfig.User)
	case ev.SessionID != "sess-1":
		t.Errorf("mapping has session %q; an event that cannot be joined to a session is not attribution", ev.SessionID)
	case ev.Subject != "u-1":
		t.Errorf("mapping has subject %q, want u-1", ev.Subject)
	case ev.Platform != fortios.PlatformFortiGate:
		t.Errorf("mapping has platform %q", ev.Platform)
	case ev.ExpiryPosture != string(control.ExpiryPostureProxyEnforced):
		t.Errorf("mapping has posture %q", ev.ExpiryPosture)
	case ev.Rung != 2:
		t.Errorf("mapping has rung %d, want the entry that was used", ev.Rung)
	case !ev.PersistsAcrossReload:
		t.Error("mapping does not record that FortiOS persists the account across a reload; the risk belongs where it is taken")
	case ev.PersistenceReason == "":
		t.Error("mapping records persistence with no reason, so nobody reading it can check the claim")
	}
}

// TestConstrainedNameRefusesWithoutALoggingPath is PLAN §5.3's fail-closed
// rule, and the two halves of it that must differ.
func TestConstrainedNameRefusesWithoutALoggingPath(t *testing.T) {
	t.Run("no logging path at all is a refusal", func(t *testing.T) {
		h := newDeviceHarness(t, deviceHarnessOptions{noEvents: true, nameLimit: 16})
		tgt := h.tgt
		tgt.Auth = deviceRouteAuth(nil)

		_, err := h.auth.Provision(context.Background(), deviceIdentity(), tgt)
		if !errors.Is(err, ErrNoLoggingPath) {
			t.Fatalf("Provision = %v, want ErrNoLoggingPath: on a constrained platform the mapping event is the only attribution there is", err)
		}
		if len(h.dev.Accounts()) != 0 {
			t.Error("an administrator was created anyway")
		}
	})

	t.Run("the disk buffer counts as a logging path", func(t *testing.T) {
		// deliverable is what a Shipper reports when the network is down but
		// records are spooling to disk: they are owed to the server, not lost.
		h := newDeviceHarness(t, deviceHarnessOptions{deliverable: true, nameLimit: 16})
		tgt := h.tgt
		tgt.Auth = deviceRouteAuth(nil)

		access, err := h.auth.Provision(context.Background(), deviceIdentity(), tgt)
		if err != nil {
			t.Fatalf("Provision: %v", err)
		}
		t.Cleanup(func() { _ = access.Close(context.Background()) })

		name := access.ClientConfig.User
		if len(name) > 16 {
			t.Errorf("account %q is longer than the declared limit of 16", name)
		}
		if strings.Contains(name, "alice") {
			t.Errorf("account %q kept the login segment under a constrained limit; a truncation that reads as attributable is worse than an absence", name)
		}
		if !strings.HasPrefix(name, principalPrefix) {
			t.Errorf("account %q lost the reaper prefix, which is the one part that must never go", name)
		}
		if got := h.events.mapping(); len(got) != 1 || !got[0].Constrained {
			t.Error("the mapping event does not record that this name carries no login")
		}
	})

	t.Run("an unservably short limit refuses the route", func(t *testing.T) {
		h := newDeviceHarness(t, deviceHarnessOptions{deliverable: true, nameLimit: 8})
		tgt := h.tgt
		tgt.Auth = deviceRouteAuth(nil)

		_, err := h.auth.Provision(context.Background(), deviceIdentity(), tgt)
		if !errors.Is(err, ErrNameLimit) {
			t.Fatalf("Provision = %v, want ErrNameLimit rather than a truncated name", err)
		}
	})
}

// TestConcurrentSessionsGetIndependentAccounts is why the name carries a token.
func TestConcurrentSessionsGetIndependentAccounts(t *testing.T) {
	h := newDeviceHarness(t, deviceHarnessOptions{deliverable: true})
	ctx := context.Background()

	var accesses []*ProvisionedAccess
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		tgt := h.tgt
		tgt.Auth = deviceRouteAuth(nil)
		tgt.SessionID = fmt.Sprintf("sess-%d", i)
		access, err := h.auth.Provision(ctx, deviceIdentity(), tgt)
		if err != nil {
			t.Fatalf("Provision %d: %v", i, err)
		}
		name := access.ClientConfig.User
		if seen[name] {
			t.Fatalf("two sessions for one login were given the same account %q", name)
		}
		seen[name] = true
		accesses = append(accesses, access)
	}

	first := accesses[0].ClientConfig.User
	second := accesses[1].ClientConfig.User
	if err := accesses[0].Close(ctx); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if _, ok := h.dev.Accounts()[first]; ok {
		t.Error("the first session's account survived its own teardown")
	}
	if _, ok := h.dev.Accounts()[second]; !ok {
		t.Fatal("one session's teardown removed the other session's account, which would end a live session's access")
	}
	if err := accesses[1].Close(ctx); err != nil {
		t.Fatalf("teardown: %v", err)
	}
}

// TestCollisionRetriesAndNeverAdopts covers §5.3's difference from the POSIX
// path.
func TestCollisionRetriesAndNeverAdopts(t *testing.T) {
	// A limit of 11 gives a four-character token, which is the tightest the
	// scheme allows and therefore where a collision is most plausible.
	h := newDeviceHarness(t, deviceHarnessOptions{deliverable: true, nameLimit: 11, proxyID: "proxy-a"})
	ctx := context.Background()

	// Occupy every name the scheme can produce but one, by taking the whole
	// four-character space is impractical — instead, take the name the next
	// draw would produce, by drawing it ourselves first.
	tgt := h.tgt
	tgt.Auth = deviceRouteAuth(nil)
	first, err := h.auth.Provision(ctx, deviceIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	taken := first.ClientConfig.User

	// A second session draws a different token, so the first account is left
	// exactly as it was: not adopted, not modified, not removed.
	second, err := h.auth.Provision(ctx, deviceIdentity(), tgt)
	if err != nil {
		t.Fatalf("second Provision: %v", err)
	}
	if second.ClientConfig.User == taken {
		t.Fatal("the second session adopted the first session's account")
	}
	if _, ok := h.dev.Accounts()[taken]; !ok {
		t.Error("the first session's account disappeared")
	}

	// And an occupied name is retried rather than adopted: staging one by hand
	// is how a collision is forced without relying on a draw.
	h.dev.AddAccount(sshtest.FortiOSAccount{Name: taken, Profile: "super_admin", Password: "someone-elses"})
	third, err := h.auth.Provision(ctx, deviceIdentity(), tgt)
	if err != nil {
		t.Fatalf("third Provision: %v", err)
	}
	if got := h.dev.Accounts()[taken]; got.Password != "someone-elses" {
		t.Error("an existing account was overwritten; a collision must leave the other session untouched")
	}
	for _, a := range []*ProvisionedAccess{first, second, third} {
		_ = a.Close(ctx)
	}
}

// TestReaperRemovesWhatACrashLeftBehind is the half of the guarantee that
// survives the process dying — and on a platform that cannot expire an account,
// the only removal path there is.
func TestReaperRemovesWhatACrashLeftBehind(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	h := newDeviceHarness(t, deviceHarnessOptions{
		deliverable: true, reaperGrace: 10 * time.Minute, now: clock,
	})
	ctx := context.Background()

	tgt := h.tgt
	tgt.Auth = deviceRouteAuth(nil)
	live, err := h.auth.Provision(ctx, deviceIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = live.Close(ctx) })
	liveName := live.ClientConfig.User

	// What a crashed process leaves: an account with this proxy's prefix that
	// no live session owns.
	route, err := h.auth.resolve(tgt.Auth)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	orphan := route.naming.prefix + "orphan-00000001"
	h.dev.AddAccount(sshtest.FortiOSAccount{Name: orphan, Profile: "prof_admin"})
	// And another proxy's account, which must never be touched.
	other, err := newNaming("proxy-b", 35)
	if err != nil {
		t.Fatalf("naming: %v", err)
	}
	foreign := other.prefix + "bob-00000002"
	h.dev.AddAccount(sshtest.FortiOSAccount{Name: foreign, Profile: "prof_admin"})

	ep := device.Endpoint{Host: h.tgt.Host, Port: h.tgt.Port, HostKeyCallback: h.tgt.HostKeyCallback}

	// FortiOS does not record when an administrator was created, so the first
	// sweep can only note that it has now seen it: removing on first sight
	// would kill a session that is mid-provision, or another process's.
	removed, err := h.auth.reaper.Sweep(ctx, ep, route)
	if err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	if len(removed) != 0 {
		t.Fatalf("the first sweep removed %v; an account of unknown age must get a full grace period", removed)
	}

	now = now.Add(11 * time.Minute)
	removed, err = h.auth.reaper.Sweep(ctx, ep, route)
	if err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	if len(removed) != 1 || removed[0] != orphan {
		t.Fatalf("sweep removed %v, want just %q", removed, orphan)
	}
	if _, ok := h.dev.Accounts()[liveName]; !ok {
		t.Error("the sweep removed a LIVE session's account")
	}
	if _, ok := h.dev.Accounts()[foreign]; !ok {
		t.Error("the sweep removed another proxy's account; at scale that ends someone else's sessions")
	}
}

// TestSweepFailureIsReported is D13's consequence: where the reaper is the only
// removal path, a sweep that fails quietly leaves a live privileged account.
func TestSweepFailureIsReported(t *testing.T) {
	h := newDeviceHarness(t, deviceHarnessOptions{deliverable: true})
	ctx := context.Background()

	tgt := h.tgt
	tgt.Auth = deviceRouteAuth(nil)
	route, err := h.auth.resolve(tgt.Auth)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ep := device.Endpoint{Host: h.tgt.Host, Port: h.tgt.Port, HostKeyCallback: h.tgt.HostKeyCallback}
	h.dev.SetUnreachable(true)

	if _, err := h.auth.reaper.Sweep(ctx, ep, route); err == nil {
		t.Fatal("a sweep of an unreachable device reported success")
	}
	if got := h.events.failures(); len(got) == 0 {
		t.Fatal("a device that could not be enumerated produced no reported failure; nobody would ever find out")
	}
}

// TestUnsatisfiablePostureIsASkippedRungNotADowngrade covers D14's walk and the
// distinction phase 0013's driver errors exist to carry.
func TestUnsatisfiablePostureIsASkippedRungNotADowngrade(t *testing.T) {
	h := newDeviceHarness(t, deviceHarnessOptions{deliverable: true})

	for _, tc := range []struct {
		name      string
		overrides map[string]string
	}{
		{"a platform this proxy has no driver for", map[string]string{control.ParamPlatform: "some-other-vendor"}},
		{"a posture the driver cannot satisfy", map[string]string{control.ParamExpiryPosture: string(control.ExpiryPostureTargetEnforced)}},
		{"a credential kind the platform does not accept", map[string]string{control.ParamCredentialKind: "certificate"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := h.auth.CanSatisfy(deviceRouteAuth(tc.overrides), h.tgt)
			if !errors.Is(err, ErrRungUnsatisfiable) {
				t.Fatalf("CanSatisfy = %v, want ErrRungUnsatisfiable so the ladder moves on", err)
			}
		})
	}
}

// TestRouteNeverFallsBackToTheTypedLogin is the defect prompt 0024 owns, and
// the one this method must not reopen.
func TestRouteNeverFallsBackToTheTypedLogin(t *testing.T) {
	h := newDeviceHarness(t, deviceHarnessOptions{deliverable: true})
	tgt := h.tgt
	tgt.Auth = deviceRouteAuth(map[string]string{control.ParamUsername: ""})

	_, err := h.auth.Provision(context.Background(), deviceIdentity(), tgt)
	if !errors.Is(err, ErrInvalidParam) {
		t.Fatalf("Provision = %v, want a refusal: identity.Login is what the user typed at their SSH client, and choosing an account name from it is an authorization decision", err)
	}
	if len(h.dev.Accounts()) != 0 {
		t.Error("an account was created from the typed login")
	}
}

// TestNoCredentialMaterialIsExposed is the assertion the acceptance criteria
// ask for by name.
func TestNoCredentialMaterialIsExposed(t *testing.T) {
	h := newDeviceHarness(t, deviceHarnessOptions{deliverable: true})
	ctx := context.Background()
	tgt := h.tgt
	tgt.Auth = deviceRouteAuth(nil)

	access, err := h.auth.Provision(ctx, deviceIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	name := access.ClientConfig.User
	secret := h.dev.Accounts()[name].Password
	if secret == "" {
		t.Fatal("no password reached the device at all")
	}

	// The mapping event is the richest thing this method emits, and it is the
	// one most likely to grow a field it should not have.
	for _, ev := range h.events.mapping() {
		rendered := fmt.Sprintf("%+v", ev)
		if strings.Contains(rendered, secret) {
			t.Error("the generated password appears in the account-mapping event")
		}
	}
	if err := access.Close(ctx); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	// Teardown zeroes the material, so what this process still holds is not a
	// working credential: the ClientConfig outlives the session in whatever
	// still references it, and a password sitting in it is a password sitting
	// in a heap dump.
	if strings.Contains(fmt.Sprintf("%+v", access.ClientConfig), secret) {
		t.Error("the generated password is still readable in the client configuration after teardown")
	}
}

// TestLadderFallsThroughToTheNextEntry is D14's walk end to end: a route that
// ranks a device method above a standing credential still connects on a proxy
// that cannot serve the device method, and the record names the entry it used.
func TestLadderFallsThroughToTheNextEntry(t *testing.T) {
	h := newDeviceHarness(t, deviceHarnessOptions{deliverable: true})
	fallback, err := NewStaticKeyAuthenticator(StaticKeyOptions{
		Signer: sshtest.MustGenerateSigner(), Username: "netadmin",
	})
	if err != nil {
		t.Fatalf("fallback: %v", err)
	}
	selector, err := NewSelector(map[string]TargetAuthenticator{
		MethodEphemeralAccount: h.auth,
		MethodStaticKey:        fallback,
	}, MethodStaticKey, nil)
	if err != nil {
		t.Fatalf("selector: %v", err)
	}

	// The first entry names a platform this proxy has no driver for, which is
	// unsatisfiable rather than an error. The second is servable.
	ladder := control.TargetAuthLadder{
		*deviceRouteAuth(map[string]string{control.ParamPlatform: "some-other-vendor"}),
		{Method: control.TargetAuthStaticKey, Params: map[string]string{control.ParamUsername: "netadmin"}},
	}
	tgt := h.tgt
	tgt.Ladder = &ladder

	access, err := selector.Provision(context.Background(), deviceIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if access.Method != MethodStaticKey {
		t.Errorf("session used %q, want the second entry", access.Method)
	}
	if access.Rung != 2 {
		t.Errorf("record names rung %d, want 2 — D14 makes the entry in force an audit fact", access.Rung)
	}
	if len(h.dev.Accounts()) != 0 {
		t.Error("the skipped entry created an administrator anyway")
	}
}

// TestEmptyLadderIsADenial keeps the absent/empty distinction alive on this
// side of the wire: an empty ladder is something the server WROTE.
func TestEmptyLadderIsADenial(t *testing.T) {
	fallback, err := NewStaticKeyAuthenticator(StaticKeyOptions{Signer: sshtest.MustGenerateSigner()})
	if err != nil {
		t.Fatalf("fallback: %v", err)
	}
	selector, err := NewSelector(map[string]TargetAuthenticator{MethodStaticKey: fallback}, MethodStaticKey, nil)
	if err != nil {
		t.Fatalf("selector: %v", err)
	}

	empty := control.TargetAuthLadder{}
	_, err = selector.Provision(context.Background(), deviceIdentity(), Target{Host: "h", Port: 22, Ladder: &empty})
	if !errors.Is(err, ErrLadderExhausted) {
		t.Fatalf("Provision = %v, want a denial: an empty ladder must never become a connection on the proxy's own credential", err)
	}
}

// TestFailedAttemptDoesNotDropToAWeakerRung is the other half of D14, and the
// one that would be a security bug to get wrong: a transient device failure
// must not become a silent downgrade.
func TestFailedAttemptDoesNotDropToAWeakerRung(t *testing.T) {
	h := newDeviceHarness(t, deviceHarnessOptions{deliverable: true})
	h.dev.SetUnreachable(true)

	fallback, err := NewStaticKeyAuthenticator(StaticKeyOptions{Signer: sshtest.MustGenerateSigner(), Username: "netadmin"})
	if err != nil {
		t.Fatalf("fallback: %v", err)
	}
	selector, err := NewSelector(map[string]TargetAuthenticator{
		MethodEphemeralAccount: h.auth,
		MethodStaticKey:        fallback,
	}, MethodStaticKey, nil)
	if err != nil {
		t.Fatalf("selector: %v", err)
	}

	ladder := control.TargetAuthLadder{
		*deviceRouteAuth(nil),
		{Method: control.TargetAuthStaticKey, Params: map[string]string{control.ParamUsername: "netadmin"}},
	}
	tgt := h.tgt
	tgt.Ladder = &ladder

	access, err := selector.Provision(context.Background(), deviceIdentity(), tgt)
	if err == nil {
		t.Fatalf("Provision succeeded on rung %d after the device was unreachable; an outage became a downgrade", access.Rung)
	}
	if errors.Is(err, ErrLadderExhausted) {
		t.Errorf("a reachable-but-failing device was treated as an unsatisfiable rung: %v", err)
	}
}

// TestTheProvisionedAccountCanActuallyLogIn is the "connects" half of the
// acceptance criteria, and it is a separate test because it was the half that
// went unproven: every other test here asserts the account EXISTS on the
// device, and existing is not the same as being usable.
//
// The gap was real and CI found it — the fake device accepted only the
// management login, so a driver could create an administrator it could never
// log in as, and nothing in this package noticed.
func TestTheProvisionedAccountCanActuallyLogIn(t *testing.T) {
	for _, kind := range []control.CredentialKind{control.CredentialKindPassword, control.CredentialKindPublicKey} {
		t.Run(string(kind), func(t *testing.T) {
			h := newDeviceHarness(t, deviceHarnessOptions{deliverable: true})
			ctx := context.Background()

			tgt := h.tgt
			tgt.Auth = deviceRouteAuth(map[string]string{control.ParamCredentialKind: string(kind)})
			access, err := h.auth.Provision(ctx, deviceIdentity(), tgt)
			if err != nil {
				t.Fatalf("Provision: %v", err)
			}
			t.Cleanup(func() { _ = access.Close(ctx) })

			// The proxy fills in host trust (D7); a session would carry its
			// own callback here.
			cfg := *access.ClientConfig
			cfg.HostKeyCallback = ssh.FixedHostKey(h.dev.HostKey())

			client, err := ssh.Dial("tcp", h.tgt.Addr(), &cfg)
			if err != nil {
				t.Fatalf("log into the device as the provisioned administrator %q: %v", cfg.User, err)
			}
			defer func() { _ = client.Close() }()

			sess, err := client.NewSession()
			if err != nil {
				t.Fatalf("open a CLI session: %v", err)
			}
			defer func() { _ = sess.Close() }()

			var out, errOut bytes.Buffer
			sess.Stdin = strings.NewReader("show system admin\nexit\n")
			sess.Stdout = &out
			sess.Stderr = &errOut
			if err := sess.Shell(); err != nil {
				t.Fatalf("request a shell: %v", err)
			}
			if err := sess.Wait(); err != nil {
				t.Fatalf("CLI session: %v", err)
			}
			if !strings.Contains(out.String(), cfg.User) {
				t.Errorf("the session did not reach the CLI as %q; it said:\n%s", cfg.User, out.String())
			}
		})
	}
}
