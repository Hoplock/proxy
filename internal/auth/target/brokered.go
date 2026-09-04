// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/identity"
)

// MethodBrokeredKey names the session-scoped credential method (D6a).
const MethodBrokeredKey = string(control.TargetAuthBrokeredKey)

// BrokeredKeyOptions configures the brokered-key authenticator.
type BrokeredKeyOptions struct {
	// Source yields the per-session credential. Required.
	Source CredentialSource
	// Username logs in as this account when the route names none. Empty falls
	// back to the authenticated login, which is what a target with matching
	// account names wants.
	Username string
	// Logger receives session events; nil discards them. It is NEVER given
	// credential material — see the note on Provision.
	Logger *log.Logger
}

// BrokeredKeyAuthenticator logs into a target with a credential it holds for
// the session and then forgets (D6a, PLAN §5.2).
//
// It exists because ephemeral-user, the stronger method, is also the most
// target-invasive one in the field: it needs a provisioning account and the
// right to create and delete OS users. A router, a firewall, a storage filer, a
// hypervisor, or an OT controller can do none of that — and those are exactly
// the devices that can never run an endpoint agent and gain the most from an
// inline enforcement point. An architecture that shipped only D6 would be
// closed to them.
//
// It changes NOTHING on the target. No account is created, no authorized_keys
// file is written, nothing is removed afterwards. That is the entire point:
// this is the method for a device the proxy cannot administer, and the honest
// consequence is that the account is standing and shared, so the audit trail
// belongs to the proxy rather than to the target (PLAN §5.2). Session capture
// is not optional on these routes.
//
// Teardown still exists and is still guaranteed. Here it zeroes the credential
// this process is holding, which is the only state there is to undo.
type BrokeredKeyAuthenticator struct {
	source   CredentialSource
	username string
	logger   *log.Logger
}

var _ TargetAuthenticator = (*BrokeredKeyAuthenticator)(nil)

// NewBrokeredKeyAuthenticator validates opts and returns the authenticator.
func NewBrokeredKeyAuthenticator(opts BrokeredKeyOptions) (*BrokeredKeyAuthenticator, error) {
	if opts.Source == nil {
		return nil, errors.New("auth/target: brokered-key requires a credential source")
	}
	return &BrokeredKeyAuthenticator{
		source:   opts.Source,
		username: opts.Username,
		logger:   opts.Logger,
	}, nil
}

// Name implements TargetAuthenticator.
func (a *BrokeredKeyAuthenticator) Name() string { return MethodBrokeredKey }

// Provision fetches this session's credential and builds the client
// configuration from it.
//
// Nothing here logs the credential, puts it in an error, or writes it anywhere.
// That is stated as a rule because it is not visible in a diff: the log line
// below names the credential's REFERENCE and its source, both of which are
// handles; a line that included the material would look exactly as ordinary.
func (a *BrokeredKeyAuthenticator) Provision(ctx context.Context, id *identity.Identity, tgt Target) (*ProvisionedAccess, error) {
	if id == nil {
		return nil, errors.New("auth/target: brokered-key requires an authenticated identity")
	}

	p := newParams(tgt.Auth)
	username := p.str(ParamUsername, a.username)
	ref := p.str(ParamCredentialRef, "")
	if err := p.rest(); err != nil {
		return nil, err
	}
	if username == "" {
		username = id.Login
	}
	if username == "" {
		return nil, errors.New("auth/target: brokered-key has no account to log in as")
	}

	// The target is UNMODIFIABLE by definition (D6a), so an applied rung on this
	// route is a contract violation and is refused before the credential is
	// even fetched. An ATTESTED rung is the point of the distinction — the
	// appliance enforces its own roles already — and the session runs, provisions
	// nothing, and is recorded at that rung rather than at "none" (PLAN §6.5).
	enforcement, err := resultForUnprovisioned(tgt.Enforcement, MethodBrokeredKey)
	if err != nil {
		return nil, err
	}

	cred, err := a.source.Credential(ctx, CredentialRequest{
		Target:   tgt,
		Ref:      ref,
		Username: username,
		Subject:  id.Subject,
	})
	if err != nil {
		return nil, err
	}

	held := &heldCredential{cred: cred}
	auth, err := authMethodFor(cred)
	if err != nil {
		held.zero()
		return nil, err
	}

	a.logf("auth/target: brokered-key provisioned subject=%s target=%s login=%s source=%s ref=%s",
		id.Subject, tgt, username, a.source.Name(), refForLog(ref))

	return &ProvisionedAccess{
		Enforcement: enforcement,
		ClientConfig: &ssh.ClientConfig{
			User: username,
			Auth: []ssh.AuthMethod{auth},
			// HostKeyCallback is the proxy's to set (D7).
		},
		Teardown: func(context.Context) error {
			held.zero()
			return nil
		},
	}, nil
}

// heldCredential is the session's copy of the material, and the thing teardown
// destroys. It is a type rather than a closure variable so that zeroing is
// idempotent and race-free: teardown runs from the session's normal path, its
// error path, and a panic unwind, and ProvisionedAccess.Close does not
// serialise anything a second caller might reach.
type heldCredential struct {
	once sync.Once
	cred *Credential
}

func (h *heldCredential) zero() {
	h.once.Do(func() {
		h.cred.Zero()
		h.cred = nil
	})
}

// authMethodFor turns credential material into an SSH authentication method.
//
// The private key's bytes are zeroed as soon as they are parsed, so the window
// in which the PEM exists in this process is the width of this function. What
// remains is the parsed key inside the signer, which x/crypto owns and which
// goes away with the session; a password has no parsed form and is held, and
// zeroed, by the caller's heldCredential.
func authMethodFor(cred *Credential) (ssh.AuthMethod, error) {
	switch {
	case len(cred.PrivateKey) > 0:
		var (
			signer ssh.Signer
			err    error
		)
		if len(cred.Passphrase) > 0 {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(cred.PrivateKey, cred.Passphrase)
		} else {
			signer, err = ssh.ParsePrivateKey(cred.PrivateKey)
		}
		zero(cred.PrivateKey)
		cred.PrivateKey = nil
		zero(cred.Passphrase)
		cred.Passphrase = nil
		if err != nil {
			// x/crypto's parse errors describe the encoding, never the key
			// material, which is what makes this safe to return.
			return nil, fmt.Errorf("auth/target: parse brokered credential: %w", err)
		}
		return ssh.PublicKeys(signer), nil
	case len(cred.Password) > 0:
		return ssh.PasswordCallback(func() (string, error) {
			if len(cred.Password) == 0 {
				return "", errors.New("auth/target: the brokered credential was already released")
			}
			return string(cred.Password), nil
		}), nil
	default:
		return nil, fmt.Errorf("%w: it carries neither a key nor a password", ErrNoCredential)
	}
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// refForLog renders a credential reference for a log line. The reference is a
// handle, never material (D6a), so it is safe; empty means the route named none
// and the source keyed on the target instead.
func refForLog(ref string) string {
	if ref == "" {
		return "(by target)"
	}
	return ref
}

func (a *BrokeredKeyAuthenticator) logf(format string, args ...any) {
	if a.logger == nil {
		return
	}
	a.logger.Printf(format, args...)
}
