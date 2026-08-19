// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/config"
	"github.com/hoplock/proxy/internal/identity"
)

// MethodStaticKey names the placeholder implementation below. It is the config
// package's constant so that the name an operator writes, the name this
// authenticator reports, and the name that appears in a log line cannot drift.
const MethodStaticKey = config.TargetAuthMethodStaticKey

// StaticKeyOptions configures a StaticKeyAuthenticator.
type StaticKeyOptions struct {
	// KeyPath is the PEM private key the proxy logs into targets with.
	// Required unless Signer is set.
	KeyPath string
	// Signer overrides KeyPath with an in-memory key. Tests use it; production
	// deployments load from disk.
	Signer ssh.Signer
	// Username logs into every target as this account instead of the
	// authenticated login. It exists for the development topology, where the
	// target has one pre-created test account and no user provisioning at all.
	// Empty means the authenticated login.
	Username string
	// Logger receives provisioning events; nil discards them.
	Logger *log.Logger
}

// StaticKeyAuthenticator logs into every target with one preloaded key.
//
// It is a PLACEHOLDER, deliberately, and it is the one implementation in this
// repository that does not do what D6 requires: it provisions nothing, its
// teardown removes nothing, and every session on every target uses the same
// long-lived credential. It exists so the proxy engine can be built and tested
// end to end before the ephemeral just-in-time provisioner lands in phase 0006,
// which replaces it behind this same interface — the proxy holds a
// TargetAuthenticator and will not change when it does.
//
// Do not ship it. A deployment running static-key has no per-session
// attribution on the target host and no credential that expires.
type StaticKeyAuthenticator struct {
	signer   ssh.Signer
	username string
	logger   *log.Logger
}

var _ TargetAuthenticator = (*StaticKeyAuthenticator)(nil)

// NewStaticKeyAuthenticator loads the configured key and returns the
// placeholder authenticator.
func NewStaticKeyAuthenticator(opts StaticKeyOptions) (*StaticKeyAuthenticator, error) {
	signer := opts.Signer
	if signer == nil {
		if opts.KeyPath == "" {
			return nil, errors.New("auth/target: static-key requires a key path")
		}
		pem, err := os.ReadFile(opts.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("auth/target: read static key: %w", err)
		}
		signer, err = ssh.ParsePrivateKey(pem)
		if err != nil {
			// The error from x/crypto names the file's problem, never its
			// contents, so it is safe to surface.
			return nil, fmt.Errorf("auth/target: parse static key %q: %w", opts.KeyPath, err)
		}
	}
	return &StaticKeyAuthenticator{
		signer:   signer,
		username: opts.Username,
		logger:   opts.Logger,
	}, nil
}

// Name implements TargetAuthenticator.
func (a *StaticKeyAuthenticator) Name() string { return MethodStaticKey }

// Provision implements TargetAuthenticator. It creates nothing, so its teardown
// is a no-op — which is exactly the property phase 0006 has to replace.
func (a *StaticKeyAuthenticator) Provision(_ context.Context, id *identity.Identity, tgt Target) (*ProvisionedAccess, error) {
	if id == nil {
		return nil, errors.New("auth/target: static-key requires an authenticated identity")
	}
	username := a.username
	if username == "" {
		username = id.Login
	}
	if username == "" {
		return nil, errors.New("auth/target: static-key has no username to log in as")
	}

	a.logf("auth/target: static-key provisioned subject=%s target=%s login=%s",
		id.Subject, tgt, username)

	return &ProvisionedAccess{
		ClientConfig: &ssh.ClientConfig{
			User: username,
			Auth: []ssh.AuthMethod{ssh.PublicKeys(a.signer)},
			// HostKeyCallback is intentionally nil: the proxy sets the
			// trust-on-first-use callback that reports keys to the management
			// server (D7). x/crypto refuses to dial without one, so forgetting
			// to set it fails the connection instead of trusting anything.
		},
		Teardown: func(context.Context) error { return nil },
	}, nil
}

func (a *StaticKeyAuthenticator) logf(format string, args ...any) {
	if a.logger == nil {
		return
	}
	a.logger.Printf(format, args...)
}
