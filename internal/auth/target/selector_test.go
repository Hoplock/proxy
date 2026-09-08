// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/config"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/identity"
	"github.com/hoplock/proxy/internal/sshtest"
)

// recordingAuthenticator stands in for a credential method so a test can see
// which one a route reached.
type recordingAuthenticator struct {
	name  string
	calls int
}

func (a *recordingAuthenticator) Name() string { return a.name }

func (a *recordingAuthenticator) Provision(context.Context, *identity.Identity, Target) (*ProvisionedAccess, error) {
	a.calls++
	return &ProvisionedAccess{ClientConfig: &ssh.ClientConfig{User: a.name}}, nil
}

func newTestSelector(t *testing.T) (*Selector, map[string]*recordingAuthenticator) {
	t.Helper()
	methods := map[string]*recordingAuthenticator{
		MethodEphemeralUser: {name: MethodEphemeralUser},
		MethodStaticKey:     {name: MethodStaticKey},
	}
	built := map[string]TargetAuthenticator{}
	for name, method := range methods {
		built[name] = method
	}
	selector, err := NewSelector(built, MethodStaticKey, nil)
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}
	return selector, methods
}

// TestSelectorFollowsTheRoute is D6a's whole point: the method is the server's
// choice, per route, and one proxy serves both estates.
func TestSelectorFollowsTheRoute(t *testing.T) {
	selector, methods := newTestSelector(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		auth *control.TargetAuth
		want string
	}{
		{
			name: "the route names a method",
			auth: &control.TargetAuth{Method: control.TargetAuthEphemeralUser},
			want: MethodEphemeralUser,
		},
		{
			name: "the route names none",
			auth: nil,
			want: MethodStaticKey,
		},
		{
			name: "a v1 server sends an empty object",
			auth: &control.TargetAuth{},
			want: MethodStaticKey,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := methods[tc.want].calls
			access, err := selector.Provision(ctx, testIdentity(), Target{Host: "host", Port: 22, Auth: tc.auth})
			if err != nil {
				t.Fatalf("Provision: %v", err)
			}
			if got := access.ClientConfig.User; got != tc.want {
				t.Errorf("route was served by %q, want %q", got, tc.want)
			}
			if methods[tc.want].calls != before+1 {
				t.Errorf("%s was not called", tc.want)
			}
		})
	}
}

// TestSelectorNeverFallsBackToAnotherMethod is the property this type exists to
// hold. Serving a route with a method the server did not choose would mean
// connecting with credentials it did not authorise, on a target whose own audit
// trail would then attribute the session to the wrong thing.
func TestSelectorNeverFallsBackToAnotherMethod(t *testing.T) {
	selector, methods := newTestSelector(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name    string
		method  control.TargetAuthMethod
		wantErr error
	}{
		{
			name:    "a method this build does not have",
			method:  "control-minted",
			wantErr: ErrUnknownMethod,
		},
		{
			name:    "a method with no local material",
			method:  control.TargetAuthBrokeredKey,
			wantErr: ErrMethodUnavailable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := selector.Provision(ctx, testIdentity(), Target{
				Host: "host",
				Port: 22,
				Auth: &control.TargetAuth{Method: tc.method},
			})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Provision = %v, want errors.Is(..., %v)", err, tc.wantErr)
			}
			for name, method := range methods {
				if method.calls != 0 {
					t.Errorf("%s served a route naming %q", name, tc.method)
				}
			}
		})
	}
}

// TestSelectorBuildsEveryConfiguredMethod: a proxy fronting both estates
// configures both, and the fallback is only the answer to a server that names
// nothing.
func TestSelectorBuildsEveryConfiguredMethod(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "target_key")
	writeKey(t, keyPath)
	mgmtPath := filepath.Join(dir, "management_key")
	writeKey(t, mgmtPath)

	auth, err := NewFromConfig(config.TargetAuth{
		Method:    config.TargetAuthMethodStaticKey,
		StaticKey: config.StaticKeyAuth{KeyPath: keyPath},
		EphemeralUser: config.EphemeralUserAuth{
			ManagementKeyPath: mgmtPath,
			ProvisioningUser:  "hoplock-admin",
		},
		BrokeredKey: config.BrokeredKeyAuth{Dir: dir},
	}, Options{ProxyID: "proxy-a"})
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	selector, ok := auth.(*Selector)
	if !ok {
		t.Fatalf("NewFromConfig returned %T, want *Selector", auth)
	}
	t.Cleanup(func() { _ = selector.Close() })

	want := []string{MethodBrokeredKey, MethodEphemeralUser, MethodStaticKey}
	got := selector.available()
	if len(got) != len(want) {
		t.Fatalf("available methods = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("available methods = %v, want %v", got, want)
		}
	}

	// Lifecycle reaches the method that has background work.
	selector.Start(context.Background())
	if err := selector.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestSelectorRefusesAnEmptyPlane: a proxy that can log into nothing is a
// misconfiguration, caught at startup.
func TestSelectorRefusesAnEmptyPlane(t *testing.T) {
	if _, err := NewSelector(map[string]TargetAuthenticator{}, MethodStaticKey, nil); err == nil {
		t.Error("a selector with no methods was accepted")
	}
	if _, err := NewFromConfig(config.TargetAuth{Method: config.TargetAuthMethodStaticKey}, Options{}); err == nil {
		t.Error("a configuration with no local material was accepted")
	}
}

// TestSelectorNeedsAProxyIDForEphemeral: the account naming convention is
// derived from it, and the reaper's safety depends on that.
func TestSelectorNeedsAProxyIDForEphemeral(t *testing.T) {
	dir := t.TempDir()
	mgmtPath := filepath.Join(dir, "management_key")
	writeKey(t, mgmtPath)

	_, err := NewFromConfig(config.TargetAuth{
		Method: config.TargetAuthMethodEphemeralUser,
		EphemeralUser: config.EphemeralUserAuth{
			ManagementKeyPath: mgmtPath,
			ProvisioningUser:  "hoplock-admin",
		},
	}, Options{})
	if err == nil {
		t.Error("the ephemeral method was built without a proxy id")
	}
}

// TestAMethodThatProvisionsNothingCarriesOnlyAnAttestedRung is the out-of-scope
// half of phase 0019 stated as a test (PLAN §6.5, D6a).
//
// A brokered-key target is unmodifiable by definition, so an APPLIED rung on it
// is a contract violation and is refused before the method runs. An ATTESTED
// rung is the point of having the distinction: the session runs, nothing is
// provisioned, and the record carries the rung rather than "none".
func TestAMethodThatProvisionsNothingCarriesOnlyAnAttestedRung(t *testing.T) {
	brokered := &recordingAuth{name: MethodBrokeredKey}
	sel, err := NewSelector(map[string]TargetAuthenticator{MethodBrokeredKey: brokered}, MethodBrokeredKey, nil)
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}
	ctx := context.Background()
	id := &identity.Identity{Subject: "u-1", Login: "alice"}
	route := &control.TargetAuth{Method: control.TargetAuthBrokeredKey}

	t.Run("an attested rung runs and is recorded", func(t *testing.T) {
		brokered.calls = 0
		access, err := sel.Provision(ctx, id, Target{
			Host: "appliance", Port: 22, Auth: route,
			Enforcement: &Enforcement{
				Execution: control.ExecutionPlatformAttested,
				Reach:     control.ReachPlatformAttested,
				Attestation: &control.Attestation{
					AssertedBy: "network-engineering",
					Reference:  "baseline/edge@v3",
				},
			},
		})
		if err != nil {
			t.Fatalf("Provision: %v", err)
		}
		e := access.Enforcement
		switch {
		case e == nil:
			t.Fatal("no enforcement was recorded")
		case e.Execution != control.ExecutionPlatformAttested || e.Reach != control.ReachPlatformAttested:
			t.Errorf("rungs = %s/%s, want the attested pair", e.Execution, e.Reach)
		case e.Verified:
			t.Error("an attested rung is not verified by this system, and the record must say so")
		case e.AttestedBy != "network-engineering":
			t.Errorf("attested_by = %q, want the route's attestation", e.AttestedBy)
		}
	})

	t.Run("an applied rung is refused before the method runs", func(t *testing.T) {
		brokered.calls = 0
		_, err := sel.Provision(ctx, id, Target{
			Host: "appliance", Port: 22, Auth: route,
			Enforcement: &Enforcement{
				Execution:      control.ExecutionAccountRestricted,
				RestrictedExec: &control.RestrictedExecPolicy{Commands: []control.RestrictedCommand{{Executable: "cat"}}},
			},
		})
		if !errors.Is(err, ErrRungUnavailable) {
			t.Fatalf("Provision error = %v, want ErrRungUnavailable", err)
		}
		if brokered.calls != 0 {
			t.Error("the credential method ran for a route whose rung it can never carry")
		}
	})
}

// recordingAuth is a credential method that provisions nothing and counts its
// calls.
type recordingAuth struct {
	name  string
	calls int
}

func (a *recordingAuth) Name() string { return a.name }

func (a *recordingAuth) Provision(context.Context, *identity.Identity, Target) (*ProvisionedAccess, error) {
	a.calls++
	return &ProvisionedAccess{ClientConfig: &ssh.ClientConfig{User: "netadmin"}}, nil
}

// namedAuthenticator is a method that can name the credential it would dial
// with, which is what makes it eligible for containment.
type namedAuthenticator struct {
	name   string
	handle string
	calls  int
	err    error
}

func (a *namedAuthenticator) Name() string { return a.name }

func (a *namedAuthenticator) CredentialHandle(Target) string { return a.handle }

func (a *namedAuthenticator) Provision(context.Context, *identity.Identity, Target) (*ProvisionedAccess, error) {
	a.calls++
	if a.err != nil {
		return nil, a.err
	}
	return &ProvisionedAccess{ClientConfig: &ssh.ClientConfig{User: a.name}}, nil
}

// TestSelectorWithholdsAnOpenCredentialBeforeProvisioning is the containment
// property that matters most: an open breaker means the method never RUNS.
//
// Checking after provisioning would already have opened a connection to the
// target — on the ephemeral method, the management login — and the connection
// is precisely what a target's per-source defences count.
func TestSelectorWithholdsAnOpenCredentialBeforeProvisioning(t *testing.T) {
	method := &namedAuthenticator{name: MethodBrokeredKey, handle: "stale-fleet"}
	sel, err := NewSelector(map[string]TargetAuthenticator{MethodBrokeredKey: method}, MethodBrokeredKey, nil)
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}
	breaker := NewRejectionBreaker(RejectionPolicy{Threshold: 1, Window: time.Minute, Cooldown: time.Minute})
	sel = sel.WithRejectionBreaker(breaker)

	ctx := context.Background()
	id := &identity.Identity{Subject: "u-1", Login: "alice"}
	tgt := Target{Host: "appliance", Port: 22, Auth: &control.TargetAuth{Method: control.TargetAuthBrokeredKey}}

	access, err := sel.Provision(ctx, id, tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	want := RejectionKey{Target: "appliance:22", Method: MethodBrokeredKey, Handle: "stale-fleet"}
	if access.Credential != want {
		t.Fatalf("access.Credential = %+v, want %+v", access.Credential, want)
	}

	// The engine reports the handshake through the access, which is the seam a
	// device driver's own dial path adopts rather than reaching for the breaker.
	access.DialOutcome(errors.New(
		"ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain"))

	calls := method.calls
	_, err = sel.Provision(ctx, id, tgt)
	if !errors.Is(err, ErrCredentialWithheld) {
		t.Fatalf("Provision after the threshold returned %v, want ErrCredentialWithheld", err)
	}
	if method.calls != calls {
		t.Errorf("the method ran %d more times while its credential was withheld", method.calls-calls)
	}
}

// TestSelectorDoesNotFallThroughAWithheldRung: a withheld credential is not an
// unsatisfiable rung.
//
// D14's fall-through exists for rungs this proxy has no material for, which is
// a standing fact about the deployment. Containment is a transient local
// condition, and answering it by serving the session on the NEXT rung would be
// a quiet downgrade to a weaker credential than the one Hoplock Control put
// first — decided by the proxy, which is exactly what D2 forbids.
func TestSelectorDoesNotFallThroughAWithheldRung(t *testing.T) {
	first := &namedAuthenticator{name: MethodBrokeredKey, handle: "stale-fleet"}
	second := &recordingAuthenticator{name: MethodStaticKey}
	sel, err := NewSelector(map[string]TargetAuthenticator{
		MethodBrokeredKey: first,
		MethodStaticKey:   second,
	}, MethodStaticKey, nil)
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}
	breaker := NewRejectionBreaker(RejectionPolicy{Threshold: 1, Window: time.Minute, Cooldown: time.Minute})
	breaker.Reject(RejectionKey{Target: "appliance:22", Method: MethodBrokeredKey, Handle: "stale-fleet"})
	sel = sel.WithRejectionBreaker(breaker)

	_, err = sel.Provision(context.Background(), &identity.Identity{Subject: "u-1"}, Target{
		Host: "appliance", Port: 22,
		Ladder: &control.TargetAuthLadder{
			{Method: control.TargetAuthBrokeredKey},
			{Method: control.TargetAuthStaticKey},
		},
	})
	if !errors.Is(err, ErrCredentialWithheld) {
		t.Fatalf("Provision returned %v, want ErrCredentialWithheld", err)
	}
	if second.calls != 0 {
		t.Errorf("the session fell through to %s, which the server did not put first", second.name)
	}
}

// TestSelectorScoresNothingForAMethodThatCannotNameItsCredential: a method with
// no handle gets no containment, rather than containment keyed on something
// that does not identify what it dials with.
func TestSelectorScoresNothingForAMethodThatCannotNameItsCredential(t *testing.T) {
	method := &recordingAuthenticator{name: MethodBrokeredKey}
	sel, err := NewSelector(map[string]TargetAuthenticator{MethodBrokeredKey: method}, MethodBrokeredKey, nil)
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}
	sel = sel.WithRejectionBreaker(NewRejectionBreaker(RejectionPolicy{Threshold: 1, Window: time.Minute, Cooldown: time.Minute}))

	ctx := context.Background()
	id := &identity.Identity{Subject: "u-1"}
	tgt := Target{Host: "appliance", Port: 22, Auth: &control.TargetAuth{Method: control.TargetAuthBrokeredKey}}
	access, err := sel.Provision(ctx, id, tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if access.Credential != (RejectionKey{}) {
		t.Fatalf("access.Credential = %+v, want the zero key", access.Credential)
	}
	access.DialOutcome(errors.New(
		"ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain"))
	if _, err := sel.Provision(ctx, id, tgt); err != nil {
		t.Fatalf("a method with no credential handle was contained: %v", err)
	}
}

// TestCredentialHandlesAreHandlesAndNotMaterial holds each method's handle to
// being the identifier the audit record may carry.
func TestCredentialHandlesAreHandlesAndNotMaterial(t *testing.T) {
	signer := sshtest.MustGenerateSigner()

	static, err := NewStaticKeyAuthenticator(StaticKeyOptions{Signer: signer, Username: "netadmin"})
	if err != nil {
		t.Fatalf("NewStaticKeyAuthenticator: %v", err)
	}
	if got, want := static.CredentialHandle(Target{}), ssh.FingerprintSHA256(signer.PublicKey()); got != want {
		t.Errorf("static-key handle = %q, want the key's fingerprint %q", got, want)
	}

	brokered, err := NewBrokeredKeyAuthenticator(BrokeredKeyOptions{Source: &fakeCredentialSource{}})
	if err != nil {
		t.Fatalf("NewBrokeredKeyAuthenticator: %v", err)
	}
	named := Target{Auth: &control.TargetAuth{
		Method: control.TargetAuthBrokeredKey,
		Params: map[string]string{ParamCredentialRef: "appliance-fleet"},
	}}
	if got := brokered.CredentialHandle(named); got != "appliance-fleet" {
		t.Errorf("brokered-key handle = %q, want the route's credential_ref", got)
	}
	if got := brokered.CredentialHandle(Target{}); got == "" {
		t.Error("a route naming no credential_ref produced no handle; the source keys on the target instead")
	}
}

// fakeCredentialSource satisfies the brokered method's constructor; nothing
// here fetches a credential.
type fakeCredentialSource struct{}

func (*fakeCredentialSource) Name() string { return "fake" }

func (*fakeCredentialSource) Credential(context.Context, CredentialRequest) (*Credential, error) {
	return nil, ErrNoCredential
}
