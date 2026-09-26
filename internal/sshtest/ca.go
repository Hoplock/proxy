// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package sshtest

import (
	"context"
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
)

// CertificateFault makes a CertificateAuthority answer deliberately wrongly, so
// a test can prove the proxy REFUSES what it was given rather than trusting a
// network answer (phase 0044). Each is one check in the brokered-certificate
// authenticator's list.
type CertificateFault string

const (
	// CertificateFaultWrongKey certifies a key other than the one submitted.
	CertificateFaultWrongKey CertificateFault = "wrong-key"
	// CertificateFaultMalformed answers a string that is not a certificate.
	CertificateFaultMalformed CertificateFault = "malformed"
	// CertificateFaultExpired answers a certificate whose validity has ended.
	CertificateFaultExpired CertificateFault = "expired"
	// CertificateFaultTooLong answers a certificate valid for a day — longer
	// than any bound a test route sets.
	CertificateFaultTooLong CertificateFault = "too-long"
	// CertificateFaultHostCertificate answers a HOST certificate.
	CertificateFaultHostCertificate CertificateFault = "host-certificate"
	// CertificateFaultMismatchedExpiry states a valid_before other than the
	// certificate's own.
	CertificateFaultMismatchedExpiry CertificateFault = "mismatched-expiry"
	// CertificateFaultForever answers a certificate that never expires
	// (OpenSSH's CertTimeInfinity).
	CertificateFaultForever CertificateFault = "forever"
	// CertificateFaultPlainKey answers the submitted public key itself, not a
	// certificate over it.
	CertificateFaultPlainKey CertificateFault = "plain-key"
)

// CertificateAuthority is an in-process certificate authority standing in for
// Hoplock Control's issuance endpoint: it implements control.CertificateIssuer
// by signing the submitted public key, with the request's username as the sole
// principal and a serial that only ever rises.
//
// It is test support, as everything in this package is. cmd/mock-control
// carries the reference implementation a server author reads; this one keeps
// unit tests off the network.
type CertificateAuthority struct {
	signer ssh.Signer

	mu       sync.Mutex
	lifetime time.Duration
	fault    CertificateFault
	err      error
	now      func() time.Time
	serial   uint64
	requests []control.CertificateRequest
	issued   []string
}

var _ control.CertificateIssuer = (*CertificateAuthority)(nil)

// NewCertificateAuthority generates a CA key and returns an authority that
// issues five-minute certificates.
func NewCertificateAuthority() (*CertificateAuthority, error) {
	signer, err := GenerateSigner()
	if err != nil {
		return nil, err
	}
	return &CertificateAuthority{signer: signer, lifetime: 5 * time.Minute, now: time.Now, serial: 1000}, nil
}

// PublicKey is the CA's public key — what a target trusts
// (Options.TrustedUserCAKeys).
func (ca *CertificateAuthority) PublicKey() ssh.PublicKey { return ca.signer.PublicKey() }

// SetLifetime changes how long certificates issued from now on are valid.
func (ca *CertificateAuthority) SetLifetime(d time.Duration) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.lifetime = d
}

// SetFault makes every issuance from now on deliberately wrong in one way; the
// empty fault restores correct answers.
func (ca *CertificateAuthority) SetFault(f CertificateFault) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.fault = f
}

// SetError makes every issuance from now on fail with err; nil restores it.
func (ca *CertificateAuthority) SetError(err error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.err = err
}

// Requests are the issuance requests received, in order.
func (ca *CertificateAuthority) Requests() []control.CertificateRequest {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return append([]control.CertificateRequest(nil), ca.requests...)
}

// Issued are the certificates answered, in authorized_keys form, in order — so
// a test can assert that none of them reached a record or a log line.
func (ca *CertificateAuthority) Issued() []string {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return append([]string(nil), ca.issued...)
}

// IssueCertificate implements control.CertificateIssuer.
func (ca *CertificateAuthority) IssueCertificate(_ context.Context, req *control.CertificateRequest) (*control.CertificateResponse, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.requests = append(ca.requests, *req)
	if ca.err != nil {
		return nil, ca.err
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("sshtest: the submitted public key does not parse: %w", err)
	}
	if ca.fault == CertificateFaultWrongKey {
		other, err := GenerateSigner()
		if err != nil {
			return nil, err
		}
		pub = other.PublicKey()
	}

	now := ca.now().Truncate(time.Second)
	validBefore := now.Add(ca.lifetime)
	switch ca.fault {
	case CertificateFaultExpired:
		validBefore = now.Add(-time.Hour)
	case CertificateFaultTooLong:
		validBefore = now.Add(24 * time.Hour)
	}
	certType := uint32(ssh.UserCert)
	if ca.fault == CertificateFaultHostCertificate {
		certType = ssh.HostCert
	}

	ca.serial++
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          ca.serial,
		CertType:        certType,
		KeyId:           "session:" + req.SessionID,
		ValidPrincipals: []string{req.Username},
		ValidAfter:      uint64(now.Add(-time.Minute).Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
	}
	if ca.fault == CertificateFaultForever {
		cert.ValidBefore = ssh.CertTimeInfinity
	}
	if err := cert.SignCert(rand.Reader, ca.signer); err != nil {
		return nil, fmt.Errorf("sshtest: sign certificate: %w", err)
	}
	encoded := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
	switch ca.fault {
	case CertificateFaultMalformed:
		encoded = ssh.CertAlgoED25519v01 + " bm90IGEgY2VydGlmaWNhdGU="
	case CertificateFaultPlainKey:
		encoded = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	}
	ca.issued = append(ca.issued, encoded)
	stated := validBefore
	if ca.fault == CertificateFaultMismatchedExpiry {
		stated = validBefore.Add(-time.Minute)
	}
	return &control.CertificateResponse{
		Certificate:  encoded,
		Serial:       strconv.FormatUint(cert.Serial, 10),
		ValidBefore:  stated,
		CAPublicKeys: []string{strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca.signer.PublicKey())))},
	}, nil
}
