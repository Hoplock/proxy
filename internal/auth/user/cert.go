// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package user

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/mauroasilva/securecommandproxy/internal/identity"
	"github.com/mauroasilva/securecommandproxy/internal/mgmt"
)

// MethodCert is the registry/config name of the certificate authenticator. It
// is derived from identity.MethodCert so the name an operator writes in the
// config file, the name in a log line, and the method recorded on the
// authenticated identity can never drift apart.
const MethodCert = string(identity.MethodCert)

// CertAuthenticator authenticates a client by the public key or certificate it
// offers. It is tried first (PLAN §4.1): a key is offered without user
// interaction, so a successful certificate login costs one round trip and no
// prompt, and the password+MFA flow only ever runs for clients that have no
// acceptable key.
//
// It validates nothing locally. The offered material is relayed verbatim to the
// management server, which owns the trust roots, the principal rules, and
// revocation. That is also why certificate authentication is never cached
// (PLAN §6.4): this call is where revocation is enforced.
type CertAuthenticator struct {
	opts Options
}

var (
	_ UserAuthenticator = (*CertAuthenticator)(nil)
	_ FlowSupport       = (*CertAuthenticator)(nil)
)

// NewCertAuthenticator returns a certificate authenticator using opts.
func NewCertAuthenticator(opts Options) (*CertAuthenticator, error) {
	if opts.Client == nil {
		return nil, errors.New("auth/user: cert authenticator requires a management client")
	}
	return &CertAuthenticator{opts: opts}, nil
}

// Name implements UserAuthenticator.
func (a *CertAuthenticator) Name() string { return MethodCert }

// SupportsCert implements FlowSupport.
func (a *CertAuthenticator) SupportsCert() bool { return true }

// SupportsPassword implements FlowSupport.
func (a *CertAuthenticator) SupportsPassword() bool { return false }

// AuthenticateCert implements UserAuthenticator.
func (a *CertAuthenticator) AuthenticateCert(ctx context.Context, meta ConnMeta, key ssh.PublicKey) (*identity.Identity, error) {
	const op = "cert"
	if key == nil {
		return nil, fmt.Errorf("%s: %w: no public key offered", op, ErrDenied)
	}

	material := publicKeyMaterial(key)
	now := a.opts.now()
	req := &mgmt.AuthenticateCertRequest{
		Login:     meta.Login,
		Target:    meta.Target,
		PublicKey: material,
		Conn:      meta.wire(now),
	}

	a.opts.logf("auth: session=%s method=%s login=%q key=%s: asking management server",
		meta.SessionID, MethodCert, meta.Login, material.Fingerprint)

	resp, err := a.opts.Client.AuthenticateCert(ctx, req)
	if err != nil {
		outcome := classify(op, err)
		// The fingerprint is safe to log and is the only handle an operator has
		// on which key was refused; the key itself is public material anyway.
		a.opts.logf("auth: session=%s method=%s login=%q key=%s: %v",
			meta.SessionID, MethodCert, meta.Login, material.Fingerprint, outcome)
		return nil, outcome
	}

	// The client guarantees a cert response is AuthStatusAuthenticated with an
	// identity set, so there is no MFA branch here by design: certificate auth
	// that asks for a second factor is a contract violation, not a flow.
	id, err := identityFrom(op, resp.Identity, identity.MethodCert, now)
	if err != nil {
		a.opts.logf("auth: session=%s method=%s login=%q: %v",
			meta.SessionID, MethodCert, meta.Login, err)
		return nil, err
	}

	a.opts.logf("auth: session=%s method=%s login=%q key=%s: authenticated subject=%s source=%s",
		meta.SessionID, MethodCert, meta.Login, material.Fingerprint, id.Subject, id.Source)
	return id, nil
}

// AuthenticatePassword implements UserAuthenticator. The certificate
// authenticator has no password flow; the registry falls through to the next
// authenticator.
func (a *CertAuthenticator) AuthenticatePassword(context.Context, ConnMeta, string) (*identity.Identity, error) {
	return nil, fmt.Errorf("%s: %w", MethodCert, ErrMethodNotSupported)
}
