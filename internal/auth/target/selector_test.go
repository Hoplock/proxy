// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/config"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/identity"
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
