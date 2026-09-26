// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// This file is phase 0044: how a certificate Hoplock Control mints for ONE
// session reaches the proxy, and why it does not ride the authorize decision.
//
// A brokered-certificate route (TargetAuthBrokeredCertificate) names POLICY —
// the account, the key algorithm, an upper bound on the lifetime. The proxy
// generates a key pair for the session, sends the public half here, and logs
// into the target with the certificate Control signs over it. The private half
// never leaves the proxy, so no private key crosses this API in either
// direction.
//
// THE CERTIFICATE MUST NOT BE A FIELD ON THE AUTHORIZE RESPONSE, and it is the
// same trap lease.go names for a uid floor, applied to a second per-session
// artifact. An authorize decision is CACHEABLE (PLAN §6.4) and CachingClient
// serves one to every connection it covers, including while Control is
// unreachable — so a certificate carried on it would be replayed: presented
// past its own valid_before, naming one serial in many sessions' records, and
// carrying a CA bundle from before a rotation. It could not be otherwise in any
// case: the certificate is signed over a key that does not exist when the
// authorize call is answered.
//
// Note what is deliberately absent below, exactly as for LeaseUIDs:
// CachingClient does not implement CertificateIssuer. A decorator that answered
// an issuance from memory would hand one session a certificate over ANOTHER
// session's key, so the shape of the interfaces makes that a compile error
// rather than a review comment.

// PathIssueCertificate signs a public key the proxy generated for one session
// (phase 0044). It is outside policy_version: the number governs /v1/authorize
// and nothing else.
const PathIssueCertificate = "/v1/credentials/certificate"

// CertificateRequest asks Hoplock Control to sign one session's public key.
type CertificateRequest struct {
	// SessionID is the proxy's session id — one issuance per session.
	SessionID string `json:"session_id"`
	// DecisionID is the authorize decision this session is served by, when the
	// decision carried one. It is optional on AuthorizeResponse, so the proxy
	// cannot promise it; a server that requires it refuses the call, and the
	// proxy treats that like every other refusal. A decision reused across
	// connections sends the same value from each, and each still gets its own
	// certificate.
	DecisionID string `json:"decision_id,omitempty"`
	// Target and Username are what the route named, so the server can bind the
	// certificate to them and cross-check them against its own decision.
	Target   string `json:"target"`
	Username string `json:"username"`
	// PublicKey is the public half of the session's key pair, in
	// authorized_keys form. It is a PUBLIC key and still never logged: the
	// serial is the one thing about a certificate that reaches a record.
	PublicKey string `json:"public_key"`
}

// CertificateResponse is one issued certificate.
//
// It is not cached, not shared between sessions, and therefore has no Clone:
// the one session that asked for it is the only one that ever holds it.
type CertificateResponse struct {
	// Certificate is one OpenSSH user certificate in authorized_keys form,
	// over the submitted public key.
	Certificate string `json:"certificate"`
	// Serial is the certificate's serial as a DECIMAL STRING. An SSH serial is
	// a uint64 and a JSON number is not safely integral above 2^53, so a
	// serial sent as a number can lose its low digits in any peer's parser —
	// and a serial that has lost digits is a join key that no longer joins.
	// Read it through SerialNumber.
	Serial string `json:"serial"`
	// ValidBefore is when the certificate stops being valid, RFC 3339 on the
	// wire (the same shape as session_deadline).
	ValidBefore time.Time `json:"valid_before"`
	// CAPublicKeys is the tenant's CA bundle, authorized_keys form, one per
	// element. Optional, carried, and acted on by nothing: a
	// brokered-certificate session administers nothing on the target (PLAN
	// §5.4).
	CAPublicKeys []string `json:"ca_public_keys,omitempty"`
}

// SerialNumber parses Serial as the uint64 an SSH certificate carries.
//
// It accepts decimal digits only — no sign, no base prefix, no separators —
// because the string is a join key and two spellings of one number would be
// two keys.
func (r *CertificateResponse) SerialNumber() (uint64, error) {
	if r == nil || r.Serial == "" {
		return 0, errors.New("the certificate carries no serial")
	}
	n, err := strconv.ParseUint(r.Serial, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != r.Serial {
		// Round-tripping refuses a leading zero, which ParseUint accepts: "010"
		// and "10" must not both name serial ten.
		return 0, fmt.Errorf("the certificate serial %q is not a canonical decimal uint64", r.Serial)
	}
	return n, nil
}

// CertificateIssuer is implemented by clients that can have a session's public
// key signed. It is a SEPARATE, NARROWER INTERFACE rather than a method on
// Client for UIDLeaser's reasons: one caller, one path — and a CachingClient
// that does not implement it cannot be wired in by mistake.
type CertificateIssuer interface {
	// IssueCertificate signs req.PublicKey for one session.
	//
	// Its error contract is Client's, with one difference in how the caller
	// uses it: the brokered-certificate authenticator treats EVERY error as an
	// outage, a 401 included, because the authorization decision was already
	// made and answered allow (PLAN §5.4). A refusal here is the server
	// declining to mint, not a denial of the route.
	IssueCertificate(ctx context.Context, req *CertificateRequest) (*CertificateResponse, error)
}

// checkIssued refuses a response that is not a certificate answer at all.
//
// It checks SHAPE only, and deliberately so: whether the certificate parses,
// is a user certificate, certifies the submitted key and fits the route's
// lifetime bound are all questions about SSH, answered by the authenticator in
// internal/auth/target — this package stays free of x/crypto/ssh, as
// AlgorithmProfile.Algorithms does.
func checkIssued(op string, resp *CertificateResponse) error {
	if resp == nil || resp.Certificate == "" {
		return protocolError(op, errors.New("the server issued no certificate"))
	}
	if _, err := resp.SerialNumber(); err != nil {
		return protocolError(op, err)
	}
	if resp.ValidBefore.IsZero() {
		return protocolError(op, errors.New("the server issued a certificate with no valid_before"))
	}
	return nil
}
