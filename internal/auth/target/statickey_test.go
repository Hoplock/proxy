// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/hoplock/proxy/internal/config"
	"github.com/hoplock/proxy/internal/identity"
	"github.com/hoplock/proxy/internal/sshtest"
)

func testIdentity() *identity.Identity {
	return &identity.Identity{
		Subject: "alice@example.com",
		Login:   "alice",
		Source:  "fixture",
		Method:  identity.MethodCert,
	}
}

func TestStaticKeyProvisionUsesTheAuthenticatedLogin(t *testing.T) {
	auth, err := NewStaticKeyAuthenticator(StaticKeyOptions{Signer: sshtest.MustGenerateSigner()})
	if err != nil {
		t.Fatalf("NewStaticKeyAuthenticator: %v", err)
	}
	if got, want := auth.Name(), MethodStaticKey; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}

	access, err := auth.Provision(context.Background(), testIdentity(), Target{Host: "host.company.com", Port: 22})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if got, want := access.ClientConfig.User, "alice"; got != want {
		t.Errorf("ClientConfig.User = %q, want %q", got, want)
	}
	if len(access.ClientConfig.Auth) != 1 {
		t.Errorf("ClientConfig.Auth has %d methods, want 1", len(access.ClientConfig.Auth))
	}
	// The proxy owns host-key trust (D7); a credential provider that also
	// decided it would be a second policy in the wrong place.
	if access.ClientConfig.HostKeyCallback != nil {
		t.Error("the authenticator set a host key callback; that belongs to the proxy")
	}
}

func TestStaticKeyUsernameOverride(t *testing.T) {
	auth, err := NewStaticKeyAuthenticator(StaticKeyOptions{
		Signer:   sshtest.MustGenerateSigner(),
		Username: "testrunner",
	})
	if err != nil {
		t.Fatalf("NewStaticKeyAuthenticator: %v", err)
	}

	access, err := auth.Provision(context.Background(), testIdentity(), Target{Host: "host", Port: 22})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if got, want := access.ClientConfig.User, "testrunner"; got != want {
		t.Errorf("ClientConfig.User = %q, want %q", got, want)
	}
}

func TestStaticKeyRequiresAnIdentity(t *testing.T) {
	auth, _ := NewStaticKeyAuthenticator(StaticKeyOptions{Signer: sshtest.MustGenerateSigner()})
	if _, err := auth.Provision(context.Background(), nil, Target{Host: "host", Port: 22}); err == nil {
		t.Error("Provision accepted a nil identity")
	}
}

// TestTeardownRunsOnce is the property every target authenticator inherits from
// ProvisionedAccess: teardown happens on the normal path, on error, and from a
// reaper, so it must not delete twice what a later session may have recreated
// (PLAN §5).
func TestTeardownRunsOnce(t *testing.T) {
	calls := 0
	access := &ProvisionedAccess{Teardown: func(context.Context) error {
		calls++
		return errors.New("boom")
	}}

	first := access.Close(context.Background())
	second := access.Close(context.Background())

	if calls != 1 {
		t.Errorf("teardown ran %d times, want 1", calls)
	}
	if first == nil || second == nil || first.Error() != second.Error() {
		t.Errorf("Close returned %v then %v, want the same error both times", first, second)
	}
}

func TestCloseOnNilAccessIsSafe(t *testing.T) {
	var access *ProvisionedAccess
	if err := access.Close(context.Background()); err != nil {
		t.Errorf("Close on a nil access = %v, want nil", err)
	}
}

func TestNewFromConfig(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "target_key")
	writeKey(t, keyPath)

	auth, err := NewFromConfig(config.TargetAuth{
		Method:    config.TargetAuthMethodStaticKey,
		StaticKey: config.StaticKeyAuth{KeyPath: keyPath},
	}, Options{})
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	if got, want := auth.Name(), MethodStaticKey; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}

	if _, err := NewFromConfig(config.TargetAuth{Method: "ephemeral"}, Options{}); !errors.Is(err, ErrUnknownMethod) {
		t.Errorf("NewFromConfig with an unknown method = %v, want errors.Is(..., ErrUnknownMethod)", err)
	}
}

func TestNewStaticKeyAuthenticatorRejectsABadKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "not_a_key")
	if err := os.WriteFile(path, []byte("this is not a private key"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := NewStaticKeyAuthenticator(StaticKeyOptions{KeyPath: path}); err == nil {
		t.Error("a file that is not a private key was accepted")
	}
	if _, err := NewStaticKeyAuthenticator(StaticKeyOptions{}); err == nil {
		t.Error("options with neither a key path nor a signer were accepted")
	}
}

// writeKey writes a freshly generated private key in OpenSSH format.
func writeKey(t *testing.T, path string) {
	t.Helper()
	_, pemBytes, err := sshtest.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}
