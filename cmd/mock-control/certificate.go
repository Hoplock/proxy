// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
)

// This file is the mock's half of phase 0044: a certificate authority minimal
// enough to read in one sitting and real enough that a proxy can log into a
// target with what it issues.
//
// It is a REFERENCE, not a second product. It signs the submitted public key
// with the route's username as the sole principal, a serial that only ever
// rises, and a validity bounded by the route's lifetime_seconds where the route
// set one. It does not revoke and does not rotate; Hoplock Control's own
// authority does both, and nothing on the proxy's side depends on either.
//
// What it does model, because a server author has to get it right:
//
//   - the certificate is issued against a DECISION this server made, and bound
//     to the target and account that decision named — an issuance request is
//     cross-checked, never trusted;
//   - one certificate per call. A decision reused across connections (PLAN
//     §6.4) produces one issuance per session, and each gets its own serial;
//   - the serial goes out as a decimal STRING, because a uint64 does not
//     survive a JSON number.

// defaultCertificateLifetime is how long a certificate is valid when neither
// the route nor the fixture bounds it.
const defaultCertificateLifetime = 5 * time.Minute

// certificateClockBackdate is how far before issuance a certificate's validity
// starts, so a target whose clock runs slightly behind this server still
// accepts it. It widens nothing at the far end, which is the end a route bounds.
const certificateClockBackdate = time.Minute

// Deliberately wrong certificates a route can ask for (routes[].certificate_fault),
// so a proxy's refusal is provable against a real server answer rather than a
// hand-built struct. Each is one check the proxy makes before using a
// certificate (PLAN §5.4).
const (
	// certFaultExceedsLifetime issues a certificate valid for longer than the
	// route's lifetime_seconds allows — a widened bound.
	certFaultExceedsLifetime = "exceeds-lifetime"
	// certFaultWrongKey certifies a key other than the one submitted.
	certFaultWrongKey = "wrong-key"
	// certFaultExpired issues a certificate whose validity has already ended.
	certFaultExpired = "expired"
	// certFaultMalformed answers a string that is not a certificate.
	certFaultMalformed = "malformed"
)

// fixtureCertificateAuthority configures the mock's certificate authority.
type fixtureCertificateAuthority struct {
	// KeyPath is the CA's ed25519 private key, OpenSSH format. It is loaded
	// once, at startup. Empty means this server has NO authority, and the
	// issuance endpoint answers 503 — which is what a tenant without one gets
	// from a real Control.
	KeyPath string `yaml:"key_path"`
	// LifetimeSeconds is how long a certificate is valid when the route sets no
	// lifetime_seconds. Zero means defaultCertificateLifetime. A route's bound,
	// where it set one, always wins when it is shorter.
	LifetimeSeconds int `yaml:"lifetime_seconds"`

	// signer is the loaded CA key.
	signer ssh.Signer
}

// load reads the CA key. It is called while the fixtures are validated, so a
// missing or unusable key stops the mock at startup rather than at the first
// session that needs it.
func (c *fixtureCertificateAuthority) load() error {
	if c.KeyPath == "" {
		return nil
	}
	pem, err := os.ReadFile(c.KeyPath)
	if err != nil {
		return fmt.Errorf("certificate_authority.key_path: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return fmt.Errorf("certificate_authority.key_path %q: %w", c.KeyPath, err)
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return fmt.Errorf("certificate_authority.key_path %q is a %s key; the mock's authority is ed25519",
			c.KeyPath, signer.PublicKey().Type())
	}
	c.signer = signer
	return nil
}

// certificateGrant is what an authorize decision naming brokered-certificate
// licensed: the target and account a certificate may be issued for, the
// route's bound, and any deliberate fault. It is remembered per decision id,
// because issuance is cross-checked against the decision it cites.
type certificateGrant struct {
	target   string
	username string
	bound    time.Duration
	fault    string
}

// grantFor extracts the certificate grant from a decision about to be
// answered, or reports that it names no brokered-certificate rung.
func grantFor(resp *control.AuthorizeResponse, fault string) (certificateGrant, bool) {
	rungs, _ := resp.Ladder()
	for _, rung := range rungs {
		if rung.Method != control.TargetAuthBrokeredCertificate {
			continue
		}
		grant := certificateGrant{
			target:   resp.Target,
			username: rung.Params[control.ParamUsername],
			fault:    fault,
		}
		if secs, err := strconv.Atoi(rung.Params[control.ParamLifetimeSeconds]); err == nil && secs > 0 {
			grant.bound = time.Duration(secs) * time.Second
		}
		return grant, true
	}
	return certificateGrant{}, false
}

// rememberCertificateGrant records what a decision licensed. The caller holds
// no lock.
func (s *server) rememberCertificateGrant(decisionID string, grant certificateGrant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certGrants[decisionID] = grant
}

// handleIssueCertificate signs one session's public key (phase 0044).
func (s *server) handleIssueCertificate(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProxy(w, r) {
		return
	}
	var req control.CertificateRequest
	if !decode(w, r, &req) {
		return
	}
	if req.SessionID == "" || req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "session_id and public_key are required")
		return
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "public_key is not an authorized_keys public key")
		return
	}
	if _, isCert := pub.(*ssh.Certificate); isCert {
		writeError(w, http.StatusBadRequest, "invalid_request", "public_key is a certificate, not a key")
		return
	}
	authority := s.fx.CertificateAuthority.signer
	if authority == nil {
		writeError(w, http.StatusServiceUnavailable, "no_authority",
			"no certificate authority is configured for this tenant")
		return
	}

	s.mu.Lock()
	grant, ok := s.certGrants[req.DecisionID]
	s.mu.Unlock()
	switch {
	case req.DecisionID == "" || !ok:
		// This server always sends a decision id, so an issuance citing none —
		// or one it never made — is not one it can bind to anything.
		writeError(w, http.StatusUnauthorized, "unknown_decision",
			"the decision this issuance cites is not one this server made for brokered-certificate")
		return
	case req.Target != grant.target || req.Username != grant.username:
		writeError(w, http.StatusUnauthorized, "decision_mismatch",
			"the target or account does not match the decision this issuance cites")
		return
	}

	resp, err := s.issueCertificate(authority, pub, &req, grant)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "issuance_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// issueCertificate mints the certificate, applying the grant's bound and any
// deliberate fault.
func (s *server) issueCertificate(authority ssh.Signer, pub ssh.PublicKey, req *control.CertificateRequest,
	grant certificateGrant,
) (*control.CertificateResponse, error) {
	lifetime := defaultCertificateLifetime
	if secs := s.fx.CertificateAuthority.LifetimeSeconds; secs > 0 {
		lifetime = time.Duration(secs) * time.Second
	}
	if grant.bound > 0 && grant.bound < lifetime {
		// The route's bound is an UPPER bound: a server may shorten it and may
		// not widen it (PLAN §5.4).
		lifetime = grant.bound
	}

	now := s.now().Truncate(time.Second)
	validBefore := now.Add(lifetime)
	switch grant.fault {
	case certFaultExceedsLifetime:
		validBefore = now.Add(lifetime + time.Hour)
	case certFaultExpired:
		validBefore = now.Add(-time.Hour)
	case certFaultWrongKey:
		other, err := newEd25519PublicKey()
		if err != nil {
			return nil, err
		}
		pub = other
	}

	s.mu.Lock()
	s.certSerial++
	serial := s.certSerial
	s.certIssued[req.SessionID]++
	s.mu.Unlock()

	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           "hoplock-session:" + req.SessionID,
		ValidPrincipals: []string{grant.username},
		ValidAfter:      uint64(now.Add(-certificateClockBackdate).Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
		// The permissions an interactive login needs. A real authority decides
		// these per tenant; the mock grants what OpenSSH's ssh-keygen does by
		// default, so the certificate behaves like one an operator would mint.
		Permissions: ssh.Permissions{Extensions: map[string]string{
			"permit-pty":              "",
			"permit-port-forwarding":  "",
			"permit-agent-forwarding": "",
			"permit-X11-forwarding":   "",
			"permit-user-rc":          "",
		}},
	}
	if err := cert.SignCert(rand.Reader, authority); err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	encoded := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
	if grant.fault == certFaultMalformed {
		encoded = ssh.CertAlgoED25519v01 + " bm90IGEgY2VydGlmaWNhdGU="
	}
	s.logger.Printf("mock-control: issued certificate serial %d for %s@%s (session %s, valid until %s)",
		serial, grant.username, grant.target, req.SessionID, validBefore.UTC().Format(time.RFC3339))
	return &control.CertificateResponse{
		Certificate:  encoded,
		Serial:       strconv.FormatUint(serial, 10),
		ValidBefore:  validBefore.UTC(),
		CAPublicKeys: []string{strings.TrimSpace(string(ssh.MarshalAuthorizedKey(authority.PublicKey())))},
	}, nil
}

// certificatesIssued is how many certificates were issued for one session, so
// a test can assert "one per session, never replayed".
func (s *server) certificatesIssued(sessionID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.certIssued[sessionID]
}

// validCertificateFault reports whether a fixture names a fault this mock can
// produce.
func validCertificateFault(fault string) error {
	switch fault {
	case "", certFaultExceedsLifetime, certFaultWrongKey, certFaultExpired, certFaultMalformed:
		return nil
	default:
		return errors.New("must be one of " + strings.Join([]string{
			certFaultExceedsLifetime, certFaultWrongKey, certFaultExpired, certFaultMalformed,
		}, ", "))
	}
}

// newEd25519PublicKey is a public key nobody submitted, for the wrong-key
// fault.
func newEd25519PublicKey() (ssh.PublicKey, error) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return ssh.NewPublicKey(pub)
}
