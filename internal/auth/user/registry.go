// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package user

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/mauroasilva/securecommandproxy/internal/config"
	"github.com/mauroasilva/securecommandproxy/internal/identity"
)

// Registry is an ordered set of authenticators presented as a single
// UserAuthenticator. The order is the preference order, and it is fixed by the
// plan rather than by the operator: certificate first, password+MFA as the
// fallback (PLAN §4.1). Config decides which methods are *enabled*; it does not
// get to reorder them, because a deployment that tried password first would
// prompt every user for a password before ever looking at the key they already
// offered.
//
// Within one flow, the registry walks its authenticators and:
//   - skips any that returns ErrMethodNotSupported (a certificate authenticator
//     asked for a password is not a failure, it is the wrong shelf);
//   - returns the first identity that authenticates;
//   - if none authenticates, reports ErrUnavailable when *any* authenticator
//     could not reach a decision, and ErrDenied only when every one of them
//     actually decided to deny. An outage anywhere must not be presented to the
//     user as a permissions problem (PLAN §4.3).
type Registry struct {
	auths []UserAuthenticator
}

var _ UserAuthenticator = (*Registry)(nil)

// NewRegistry returns a registry over auths, in the given preference order.
func NewRegistry(auths ...UserAuthenticator) (*Registry, error) {
	if len(auths) == 0 {
		return nil, errors.New("auth/user: registry needs at least one authenticator")
	}
	seen := make(map[string]bool, len(auths))
	for _, a := range auths {
		if a == nil {
			return nil, errors.New("auth/user: registry given a nil authenticator")
		}
		if seen[a.Name()] {
			return nil, fmt.Errorf("auth/user: authenticator %q registered twice", a.Name())
		}
		seen[a.Name()] = true
	}
	return &Registry{auths: append([]UserAuthenticator(nil), auths...)}, nil
}

// NewFromConfig builds the registry described by cfg.
//
// cfg.Methods is a *set* of enabled methods; this function imposes the ordering.
// Validation of the method names themselves belongs to config.Validate, so a
// typo fails at startup rather than at the first login attempt; the check here
// is the backstop for a Config assembled in code.
func NewFromConfig(cfg config.UserAuth, opts Options) (*Registry, error) {
	enabled := make(map[identity.Method]bool, len(cfg.Methods))
	for _, name := range cfg.Methods {
		m := identity.Method(name)
		if !m.Valid() {
			return nil, fmt.Errorf("auth/user: unknown authentication method %q", name)
		}
		enabled[m] = true
	}

	var auths []UserAuthenticator
	// Certificate first, then password+MFA: the order is the plan's, not the
	// config file's.
	if enabled[identity.MethodCert] {
		a, err := NewCertAuthenticator(opts)
		if err != nil {
			return nil, err
		}
		auths = append(auths, a)
	}
	if enabled[identity.MethodPasswordMFA] {
		a, err := NewPasswordMFAAuthenticator(opts, PasswordMFAOptions{
			MinPollInterval:  cfg.MFA.MinPollInterval,
			ProgressInterval: cfg.MFA.ProgressInterval,
			MaxWait:          cfg.MFA.MaxWait,
		})
		if err != nil {
			return nil, err
		}
		auths = append(auths, a)
	}
	if len(auths) == 0 {
		return nil, errors.New("auth/user: no authentication methods enabled")
	}
	return NewRegistry(auths...)
}

// Name implements UserAuthenticator, naming the enabled methods in order.
func (r *Registry) Name() string {
	names := make([]string, 0, len(r.auths))
	for _, a := range r.auths {
		names = append(names, a.Name())
	}
	return strings.Join(names, ",")
}

// Authenticators returns the registered authenticators in preference order.
func (r *Registry) Authenticators() []UserAuthenticator {
	return append([]UserAuthenticator(nil), r.auths...)
}

// SupportsCert reports whether any authenticator implements the certificate
// flow, so the SSH layer can decide whether to offer public-key auth at all.
func (r *Registry) SupportsCert() bool {
	return r.supports(FlowSupport.SupportsCert)
}

// SupportsPassword reports whether any authenticator implements the password
// flow, so the SSH layer can decide whether to offer keyboard-interactive.
func (r *Registry) SupportsPassword() bool {
	return r.supports(FlowSupport.SupportsPassword)
}

// supports asks each authenticator whether it implements a flow. An
// authenticator that does not declare its flows is assumed to implement both:
// offering a method that then answers ErrMethodNotSupported costs one wasted
// round of the SSH auth conversation, whereas *not* offering a method the
// authenticator actually supports would lock users out.
func (r *Registry) supports(want func(FlowSupport) bool) bool {
	for _, a := range r.auths {
		f, ok := a.(FlowSupport)
		if !ok || want(f) {
			return true
		}
	}
	return false
}

// AuthenticateCert implements UserAuthenticator.
func (r *Registry) AuthenticateCert(ctx context.Context, meta ConnMeta, key ssh.PublicKey) (*identity.Identity, error) {
	return r.dispatch("cert", func(a UserAuthenticator) (*identity.Identity, error) {
		return a.AuthenticateCert(ctx, meta, key)
	})
}

// AuthenticatePassword implements UserAuthenticator.
func (r *Registry) AuthenticatePassword(ctx context.Context, meta ConnMeta, password string) (*identity.Identity, error) {
	return r.dispatch("password", func(a UserAuthenticator) (*identity.Identity, error) {
		return a.AuthenticatePassword(ctx, meta, password)
	})
}

// dispatch runs one flow across the registry and applies the precedence rule
// described on Registry.
func (r *Registry) dispatch(flow string, call func(UserAuthenticator) (*identity.Identity, error)) (*identity.Identity, error) {
	var (
		denied      error
		unavailable error
	)
	for _, a := range r.auths {
		id, err := call(a)
		switch {
		case err == nil:
			return id, nil
		case errors.Is(err, ErrMethodNotSupported):
			continue
		case errors.Is(err, ErrDenied):
			denied = err
		default:
			unavailable = err
		}
	}
	switch {
	case unavailable != nil:
		return nil, unavailable
	case denied != nil:
		return nil, denied
	default:
		return nil, fmt.Errorf("%s: %w", flow, ErrMethodNotSupported)
	}
}
