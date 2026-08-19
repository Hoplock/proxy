// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package user

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/identity"
)

// UserAuthenticator decides whether an incoming SSH client is a known identity
// (PLAN §4.1). Implementations are stateless PEP shims: they hold no credential
// database and make no decision of their own, they relay the offered credential
// to Hoplock Control and translate the answer (D2).
//
// Both methods return an *identity.Identity rather than a bool so that AD/Okta
// claims flow through to routing and policy unchanged (D4).
//
// Error contract, which every caller and every implementation must honour:
//   - a deny decision from Hoplock Control is ErrDenied;
//   - anything that left the decision unknown — unreachable server, 5xx,
//     contract violation — is ErrUnavailable;
//   - a flow this authenticator does not implement is ErrMethodNotSupported.
//
// The split is not cosmetic: it is what lets the SSH layer tell the user
// "access denied" versus "this is an outage" (PLAN §4.3), and it is why an
// implementation must never collapse an unreachable server into a deny. Both
// outcomes refuse the connection — failing closed and failing silently are not
// the same thing.
//
// The name repeats the package name because it is fixed by PLAN §4.1 and names
// the *plane* (user→proxy) rather than the package: its counterpart in
// internal/auth/target is TargetAuthenticator.
type UserAuthenticator interface {
	// Name identifies the method for logging and metrics ("cert",
	// "password-mfa", ...).
	Name() string
	// AuthenticateCert is called when the client offers a public key or
	// certificate.
	AuthenticateCert(ctx context.Context, meta ConnMeta, key ssh.PublicKey) (*identity.Identity, error)
	// AuthenticatePassword is called for keyboard-interactive and password
	// flows. Implementations must never log, wrap, or store the password.
	AuthenticatePassword(ctx context.Context, meta ConnMeta, password string) (*identity.Identity, error)
}

// FlowSupport is an optional interface an authenticator implements to declare
// which flows it can actually serve. The SSH layer uses it to decide which auth
// methods to offer the client: a proxy with only certificate authentication
// enabled must not advertise keyboard-interactive, or every user without a key
// is prompted for a password that can never work.
//
// It is separate from UserAuthenticator because that interface is fixed by
// PLAN §4.1, and optional because "assume both" is the safe default — offering
// a method that turns out to be unsupported costs a wasted round trip, while
// withholding a supported one locks people out.
type FlowSupport interface {
	// SupportsCert reports whether AuthenticateCert does anything but return
	// ErrMethodNotSupported.
	SupportsCert() bool
	// SupportsPassword reports whether AuthenticatePassword does anything but
	// return ErrMethodNotSupported.
	SupportsPassword() bool
}

// Outcome sentinels. Callers classify with errors.Is; the concrete error wraps
// the management client's own error so the cause survives into the logs.
var (
	// ErrDenied is a deny decision: Hoplock Control refused this
	// credential. It is the ONLY error that may be reported to the user as a
	// permissions problem.
	ErrDenied = errors.New("authentication denied")
	// ErrUnavailable means no decision was obtained — Hoplock Control was
	// unreachable, failed, or answered off-contract. The connection is still
	// refused (fail closed, D2), but the user is told it is an outage.
	ErrUnavailable = errors.New("authentication unavailable")
	// ErrMethodNotSupported means this authenticator does not implement the
	// flow that was called. It is a routing condition inside the registry, not
	// an authentication outcome, and never reaches the user.
	ErrMethodNotSupported = errors.New("authentication method not supported by this authenticator")
)

// ConnMeta describes the SSH connection an authentication is performed for. It
// is the proxy-side view: the login and target have already been split out of
// the SSH username by the caller (D1), because the target segment must be
// stripped before the login is ever presented for authentication.
//
// The proxy (0005) builds one of these per connection and passes the same value
// to every authenticator, so that a fallback from certificate to password is
// visibly the same connection in the server's logs.
type ConnMeta struct {
	// SessionID is proxy-assigned, stable for the whole session, and the
	// support reference quoted to the user when setup fails (PLAN §4.3).
	SessionID string
	// ProxyID identifies this proxy to Hoplock Control.
	ProxyID string
	// Login is the SSH username with the target segment removed (D1).
	Login string
	// Target is the target parsed out of the SSH username. Authentication does
	// not decide on it — Authorize does — but it is sent so the server can
	// scope a credential to a target and log the attempt against it.
	Target string
	// ClientAddr is the SSH client's remote address ("host:port").
	ClientAddr string
	// ServerAddr is the local address the client connected to ("host:port").
	ServerAddr string
	// ClientVersion is the client identification string, as offered.
	ClientVersion string
	// HopTrail lists the proxy ids already traversed, oldest first (PLAN
	// §6.1). Empty on a user's first hop.
	HopTrail []string
}

// wire converts to the contract's connection metadata.
func (m ConnMeta) wire(now time.Time) control.ConnMeta {
	return control.ConnMeta{
		SessionID:     m.SessionID,
		ProxyID:       m.ProxyID,
		ClientAddr:    m.ClientAddr,
		ServerAddr:    m.ServerAddr,
		ClientVersion: m.ClientVersion,
		HopTrail:      m.HopTrail,
		Timestamp:     now,
	}
}

// Options are the dependencies every authenticator in this package shares.
type Options struct {
	// Client is the Control API client. Required: the proxy holds no
	// credential database, so an authenticator without a client cannot decide
	// anything (PLAN §3).
	Client control.Client
	// Logger receives authentication progress and outcomes. Nil discards them.
	// It is never given a password, and never a claim value.
	Logger *log.Logger
	// Now overrides the clock, for tests. Nil means time.Now.
	Now func() time.Time
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// logf writes an authentication log line. Callers pass only fields that are
// safe to persist: never the password, and never a credential of any kind.
func (o Options) logf(format string, args ...any) {
	if o.Logger == nil {
		return
	}
	o.Logger.Printf(format, args...)
}

// classify turns a management client error into this package's outcome
// contract. A deny is the server's decision; everything else is an outage, and
// the difference is preserved all the way to what the user is told (PLAN §4.3).
//
// The default arm is deliberately ErrUnavailable: a new or unrecognised failure
// mode must degrade to "unknown", never to "denied", because only "denied" is
// safe to present as a permissions answer.
func classify(op string, err error) error {
	if err == nil {
		return nil
	}
	if control.IsUnauthorized(err) {
		return fmt.Errorf("%s: %w: %w", op, ErrDenied, err)
	}
	return fmt.Errorf("%s: %w: %w", op, ErrUnavailable, err)
}

// identityFrom converts an authenticated response into the internal model. A
// response that claims success without a usable identity is an outage, not a
// deny: the proxy cannot audit a session it cannot attribute, and the server
// has violated the contract rather than made a decision.
func identityFrom(op string, w *control.Identity, method identity.Method, at time.Time) (*identity.Identity, error) {
	id, err := identity.FromWire(w, method, at)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %w", op, ErrUnavailable, err)
	}
	return id, nil
}

// publicKeyMaterial converts an offered SSH key or certificate into its wire
// form. The proxy validates nothing here — not the signature chain, not the
// principals, not the validity window: Hoplock Control is the decision
// point, and a local pre-validation would be a second, divergent policy (D2).
func publicKeyMaterial(key ssh.PublicKey) control.PublicKeyMaterial {
	_, isCert := key.(*ssh.Certificate)
	return control.PublicKeyMaterial{
		Type:          key.Type(),
		Blob:          key.Marshal(),
		Fingerprint:   ssh.FingerprintSHA256(key),
		IsCertificate: isCert,
	}
}
