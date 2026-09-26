// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/identity"
	"github.com/hoplock/proxy/internal/sshalg"
)

// MethodBrokeredCertificate names the per-session certificate method (PLAN
// §5.4, phase 0044).
const MethodBrokeredCertificate = string(control.TargetAuthBrokeredCertificate)

// CertificateClockSkew is how far a certificate's expiry may pass the route's
// lifetime_seconds bound before it is refused as a WIDENED bound.
//
// The bound is measured on this proxy's clock and the certificate is dated on
// Hoplock Control's, so a CA whose clock runs a second ahead would otherwise
// have every certificate it mints refused — an outage for a fleet whose only
// fault is ordinary NTP drift. Thirty seconds is far below any bound a route
// sets for a reason (a lifetime is minutes or hours) and far above the skew a
// synchronised estate shows; a certificate widening the route by more than
// that is refused.
const CertificateClockSkew = 30 * time.Second

// ErrCertificateUnavailable means no usable certificate was issued for this
// session: the issuance call failed, or the certificate it returned failed a
// check the proxy makes before using it.
//
// It is OUTAGE-CLASS and never a denial (PLAN §4.3), whatever Hoplock Control
// answered — a 401 from the issuance endpoint included, because the
// authorization decision was already made and answered allow. And it is never
// a SKIPPED rung: see Provision for why a failed issuance ends the session
// rather than walking down the ladder.
var ErrCertificateUnavailable = errors.New("auth/target: no usable certificate was issued for this session")

// certificateError names which check failed. Its text carries the cause for
// the operator's log, and it deliberately UNWRAPS TO THE SENTINEL ONLY: the
// issuer's error may be a control.ErrUnauthorized, and a caller asking
// errors.Is — which is how the deny/outage split is decided — must never find
// one here and tell the user "access denied" about a certificate authority
// that declined to sign.
//
// Nothing in it is, or is derived from, the certificate or the key.
type certificateError struct {
	check string
	cause error
}

func (e *certificateError) Error() string {
	if e.cause == nil {
		return fmt.Sprintf("%s: %s", ErrCertificateUnavailable, e.check)
	}
	return fmt.Sprintf("%s: %s: %v", ErrCertificateUnavailable, e.check, e.cause)
}

func (e *certificateError) Unwrap() error { return ErrCertificateUnavailable }

// BrokeredCertificateOptions configures the brokered-certificate authenticator.
type BrokeredCertificateOptions struct {
	// Issuer signs each session's public key. Required.
	//
	// It is the REST client and never the caching one — the caching client
	// does not implement control.CertificateIssuer, so wiring it here is a
	// compile error (internal/control/certificate.go).
	Issuer control.CertificateIssuer
	// Logger receives session events; nil discards them. It is never given the
	// certificate or either half of the key.
	Logger *log.Logger
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// BrokeredCertificateAuthenticator logs into a target with a certificate
// Hoplock Control minted for THIS session over a key pair this proxy generated
// for it (PLAN §5.4).
//
// The lifecycle is §5.2's, not §5.1's: nothing is created on the target and
// nothing is removed. The target already trusts the tenant's CA and already
// has the account, which is exactly why the method reaches devices the proxy
// cannot administer. What it adds over brokered-key is the credential's shape:
// minted for one session, expiring on its own, and — unlike a standing shared
// key — a credential the target's OWN audit trail can tell apart from the next
// session's. What a certificate asserts about the person is Hoplock Control's
// to decide; this type presents it and claims nothing about its content.
//
// The private half never leaves this process and is zeroed on teardown. The
// certificate and the public key are never logged either: the serial is the
// one fact about the credential that reaches a record.
type BrokeredCertificateAuthenticator struct {
	issuer control.CertificateIssuer
	logger *log.Logger
	now    func() time.Time
	// keys generates the session key pair. It is a field so a test can keep a
	// handle on the key and prove teardown destroyed it.
	keys func(keyType string) (*sessionKey, error)
}

var (
	_ TargetAuthenticator  = (*BrokeredCertificateAuthenticator)(nil)
	_ CredentialIdentifier = (*BrokeredCertificateAuthenticator)(nil)
)

// NewBrokeredCertificateAuthenticator validates opts and returns the
// authenticator.
func NewBrokeredCertificateAuthenticator(opts BrokeredCertificateOptions) (*BrokeredCertificateAuthenticator, error) {
	if opts.Issuer == nil {
		return nil, errors.New("auth/target: brokered-certificate requires a certificate issuer")
	}
	a := &BrokeredCertificateAuthenticator{
		issuer: opts.Issuer,
		logger: opts.Logger,
		now:    opts.Now,
		keys:   newSessionKey,
	}
	if a.now == nil {
		a.now = time.Now
	}
	return a, nil
}

// Name implements TargetAuthenticator.
func (a *BrokeredCertificateAuthenticator) Name() string { return MethodBrokeredCertificate }

// CredentialHandle implements CredentialIdentifier, for the rejection breaker
// and the rejection record (prompt 0025).
//
// Each session's certificate is different, so the certificate cannot be the
// handle. What a target accepts or refuses, session after session, is a
// certificate from this tenant's CA FOR THIS ACCOUNT — a target that does not
// trust the CA, or has no such account, refuses every one of them from the
// proxy's single source address, which is the run the breaker exists to cut
// short before it costs a Control issuance and a connection. So the handle is
// the principal the route names. It is policy, never material.
func (a *BrokeredCertificateAuthenticator) CredentialHandle(tgt Target) string {
	username := newParams(tgt.Auth).str(ParamUsername, "")
	if username == "" {
		return ""
	}
	return "principal:" + username
}

// Provision generates this session's key pair, has Hoplock Control sign its
// public half, checks what came back, and returns a client configuration that
// presents the certificate.
//
// THE FAILURE RULE is the one judgement this method makes, and it is made here
// rather than left to the ladder walk. A rung is SKIPPED only when this build
// structurally cannot satisfy it — the method is not implemented, or there is
// no local material; for this method that is a proxy built with no issuer, and
// NewFromConfig then does not construct it at all. A FAILED ISSUANCE IS NOT
// THAT. A transient Control failure, a refusal, and a certificate that fails a
// check below all end the session as an outage, with nothing provisioned: the
// selector returns this error as-is and never tries the next rung. Walking on
// would connect with a weaker, STANDING credential the server did not choose
// for this attempt — the silent downgrade D12-as-amended and D14 both forbid —
// and it would do so precisely when Control is unreachable and least able to
// say otherwise.
func (a *BrokeredCertificateAuthenticator) Provision(ctx context.Context, id *identity.Identity, tgt Target) (*ProvisionedAccess, error) {
	if id == nil {
		return nil, errors.New("auth/target: brokered-certificate requires an authenticated identity")
	}

	// Everything the route says is read, and refused if unreadable, BEFORE a
	// key exists: a route this method cannot serve must not cost a key pair or
	// a call to Control.
	p := newParams(tgt.Auth)
	username := p.str(ParamUsername, "")
	keyType := p.str(ParamKeyType, KeyTypeEd25519)
	bound, bounded, err := p.duration(ParamLifetimeSeconds)
	if err != nil {
		return nil, err
	}
	if err := p.rest(); err != nil {
		// Among what lands here: a route carrying the certificate, its serial
		// or a CA bundle as a PARAMETER — the artifacts of one issuance on a
		// decision that is cacheable. Refused, never used.
		return nil, err
	}
	if username == "" {
		// Required by the contract, so a served route always names one; this
		// is the locally configured path, and the method has no local default
		// on purpose. Like brokered-key it never consults identity.Principals:
		// the route names the principal the certificate is minted for.
		return nil, noAccountName(MethodBrokeredCertificate,
			"the method has no local default, so the route must name the account its certificate is minted for")
	}

	// The target is configured by nobody here (Provisions() is false), so an
	// applied rung is refused before anything is generated and an attested
	// one is recorded as such (PLAN §6.5).
	enforcement, err := resultForUnprovisioned(tgt.Enforcement, MethodBrokeredCertificate)
	if err != nil {
		return nil, err
	}

	key, err := a.keys(keyType)
	if err != nil {
		return nil, err
	}
	access, err := a.certify(ctx, tgt, username, key, bound, bounded)
	if err != nil {
		key.zero()
		return nil, err
	}
	access.Enforcement = enforcement

	a.logf("auth/target: brokered-certificate provisioned subject=%s target=%s login=%s key_type=%s serial=%s",
		id.Subject, tgt, username, keyType, access.CertificateSerial)
	return access, nil
}

// certify runs the issuance and the checks, and builds the access. The caller
// zeroes the key when it fails.
func (a *BrokeredCertificateAuthenticator) certify(ctx context.Context, tgt Target, username string, key *sessionKey,
	bound time.Duration, bounded bool,
) (*ProvisionedAccess, error) {
	public := key.signer.PublicKey()
	resp, err := a.issuer.IssueCertificate(ctx, &control.CertificateRequest{
		SessionID:  tgt.SessionID,
		DecisionID: tgt.DecisionID,
		Target:     tgt.Host,
		Username:   username,
		PublicKey:  strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public))) + " hoplock-session",
	})
	if err != nil {
		return nil, &certificateError{check: "issuance failed", cause: err}
	}
	cert, err := a.verify(resp, public, bound, bounded)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewCertSigner(cert, key.signer)
	if err != nil {
		// Unreachable once verify has compared the keys; kept because
		// x/crypto is the authority on what it will sign with.
		return nil, &certificateError{check: "the certificate cannot be used with the session key", cause: err}
	}
	return &ProvisionedAccess{
		ClientConfig: &ssh.ClientConfig{
			User: username,
			// Restricted to the route's profile like every session-leg signer
			// since phase 0043; a certificate signer is restricted by its
			// underlying key's algorithms.
			Auth: []ssh.AuthMethod{ssh.PublicKeys(sshalg.Signer(signer, tgt.Algorithms))},
			// HostKeyCallback is the proxy's to set (D7).
		},
		// There is no remote state to undo (PLAN §5.2): teardown destroys the
		// one thing this session holds. The proxy closes the leg.
		Teardown: func(context.Context) error {
			key.zero()
			return nil
		},
		CertificateSerial: resp.Serial,
	}, nil
}

// verify checks what Hoplock Control issued BEFORE it is used, because a
// credential the proxy cannot check is one it is trusting a network answer
// about. Each failure names its check and never the certificate or the key.
//
// It does NOT check the certificate's principals or extensions: what a
// certificate asserts is Hoplock Control's to decide, and the target enforces
// it. What it checks is that this is a credential this session can present
// and the route permits.
func (a *BrokeredCertificateAuthenticator) verify(resp *control.CertificateResponse, submitted ssh.PublicKey,
	bound time.Duration, bounded bool,
) (*ssh.Certificate, error) {
	if resp == nil {
		return nil, &certificateError{check: "the server issued nothing"}
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
	if err != nil {
		// x/crypto's parse errors describe the encoding, never the content.
		return nil, &certificateError{check: "the certificate does not parse", cause: err}
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		return nil, &certificateError{check: "the server returned a plain public key, not a certificate"}
	}
	if cert.CertType != ssh.UserCert {
		return nil, &certificateError{check: "the certificate is not a user certificate"}
	}
	if !bytes.Equal(cert.Key.Marshal(), submitted.Marshal()) {
		// Anything else means presenting a certificate for a key this proxy
		// does not hold — at best a failed login, at worst a certificate
		// meant for another session.
		return nil, &certificateError{check: "the certificate does not certify the key this session submitted"}
	}

	if cert.ValidBefore > maxCertTime {
		// OpenSSH's "forever" (CertTimeInfinity). A credential that never
		// expires is not a per-session one, whatever the route's bound says,
		// and the response has no instant it could honestly state for it.
		return nil, &certificateError{check: "the certificate never expires"}
	}
	now := a.now()
	expires := time.Unix(int64(cert.ValidBefore), 0)
	if !expires.After(now) {
		return nil, &certificateError{check: "the certificate has already expired"}
	}
	if resp.ValidBefore.Unix() != expires.Unix() {
		// The certificate's own field is the one the target enforces, and so
		// the one checked here; a response stating a different expiry is a
		// server answering some other question than the one it was asked.
		return nil, &certificateError{check: "valid_before does not match the certificate's own expiry"}
	}
	if bounded && expires.After(now.Add(bound).Add(CertificateClockSkew)) {
		// A server may SHORTEN the route's bound — it is an upper bound — and
		// may not widen it.
		return nil, &certificateError{check: fmt.Sprintf(
			"the certificate is valid for longer than the route's %s of %s", ParamLifetimeSeconds, bound)}
	}
	return cert, nil
}

// maxCertTime is the latest certificate expiry that is an instant rather than
// OpenSSH's "forever": anything above it does not fit a Unix time.
const maxCertTime = uint64(1<<63 - 1)

// sessionKey is one session's key pair, and the thing teardown destroys.
//
// It is generated per session and never written to disk; the public half goes
// to Hoplock Control to be signed, the private half nowhere. zero overwrites
// every private component this process can reach through the key's own API.
// What it cannot reach is the standard library's DERIVED form — the expanded
// key crypto/ed25519 caches for signing, the precomputed key crypto/rsa keeps
// — which is released with the session, exactly as brokered.go says of a
// parsed key inside a signer. The key's own bytes are the copy this package
// holds, and those are overwritten, not merely dropped.
type sessionKey struct {
	once   sync.Once
	signer ssh.Signer
	ed     ed25519.PrivateKey
	rsa    *rsa.PrivateKey
}

// newSessionKey generates a key pair of the route's key_type — the same
// vocabulary, and the same two values, as ephemeral-user's.
func newSessionKey(keyType string) (*sessionKey, error) {
	switch keyType {
	case KeyTypeEd25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("auth/target: generate session key: %w", err)
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			return nil, fmt.Errorf("auth/target: generate session key: %w", err)
		}
		return &sessionKey{signer: signer, ed: priv}, nil
	case KeyTypeRSA:
		priv, err := rsa.GenerateKey(rand.Reader, ephemeralRSABits)
		if err != nil {
			return nil, fmt.Errorf("auth/target: generate session key: %w", err)
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			return nil, fmt.Errorf("auth/target: generate session key: %w", err)
		}
		return &sessionKey{signer: signer, rsa: priv}, nil
	default:
		return nil, fmt.Errorf("%w: %s=%q", ErrInvalidParam, ParamKeyType, keyType)
	}
}

// zero destroys the private key. It is idempotent and safe from several
// goroutines, for heldCredential's reasons: teardown runs from the normal
// path, the error path and a panic unwind.
func (k *sessionKey) zero() {
	if k == nil {
		return
	}
	k.once.Do(func() {
		zero(k.ed)
		if k.rsa != nil {
			zeroInt(k.rsa.D)
			for _, prime := range k.rsa.Primes {
				zeroInt(prime)
			}
			zeroInt(k.rsa.Precomputed.Dp)
			zeroInt(k.rsa.Precomputed.Dq)
			zeroInt(k.rsa.Precomputed.Qinv)
		}
	})
}

// zeroInt overwrites a big.Int's words in place. SetInt64(0) alone would only
// shorten the slice and leave the digits in memory.
func zeroInt(x *big.Int) {
	if x == nil {
		return
	}
	words := x.Bits()
	for i := range words {
		words[i] = 0
	}
	x.SetInt64(0)
}

func (a *BrokeredCertificateAuthenticator) logf(format string, args ...any) {
	if a.logger == nil {
		return
	}
	a.logger.Printf(format, args...)
}
