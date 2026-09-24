// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

// Package sshalg applies a route's algorithm lists (control.Algorithms) to an
// SSH client connection (phase 0043).
//
// It exists because the expansion and its application live on opposite sides
// of an import rule. control.AlgorithmProfile.Algorithms is the one place a
// proxy→target connection's lists come from, and internal/control stays free of
// golang.org/x/crypto/ssh; the connections themselves are opened by
// internal/proxy (the session leg) and by internal/auth/target and its device
// subpackage (the management login, the driver's privileged CLI, the reaper's
// sweeps), which may not import each other. Every one of them calls Apply here,
// so "which algorithms did this connection offer" has one answer in code as it
// has in the record.
package sshalg

import (
	"io"
	"slices"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
)

// Apply sets every negotiated axis of cfg from a, filling an axis a leaves
// empty from the default profile.
//
// The fill is the property that matters: an empty field in an ssh.ClientConfig
// means "the library's client defaults", and those offer a SHA-1 key exchange,
// `hmac-sha1-96` and `ssh-rsa`/`ssh-dss` host keys — the set the default
// profile exists to replace. So no connection this proxy opens toward a target
// ever leaves one empty, whatever it was handed.
//
// The public-key axis is not a ClientConfig field on the client side; it is
// applied per signer by Signer, at the place the signer is wrapped into an
// auth method.
func Apply(cfg *ssh.ClientConfig, a control.Algorithms) {
	a = Complete(a)
	cfg.KeyExchanges = a.KeyExchanges
	cfg.Ciphers = a.Ciphers
	cfg.MACs = a.MACs
	cfg.HostKeyAlgorithms = a.HostKeys
}

// Complete returns a copy of a with every empty axis filled from the default
// profile's expansion.
func Complete(a control.Algorithms) control.Algorithms {
	def := control.AlgorithmProfileDefault.Algorithms()
	a = a.Clone()
	if len(a.KeyExchanges) == 0 {
		a.KeyExchanges = def.KeyExchanges
	}
	if len(a.Ciphers) == 0 {
		a.Ciphers = def.Ciphers
	}
	if len(a.MACs) == 0 {
		a.MACs = def.MACs
	}
	if len(a.HostKeys) == 0 {
		a.HostKeys = def.HostKeys
	}
	if len(a.PublicKeyAuths) == 0 {
		a.PublicKeyAuths = def.PublicKeyAuths
	}
	return a
}

// Signer restricts the signature algorithms s may authenticate with to those a
// permits, in a's preference order.
//
// It matters for RSA keys, which can sign with SHA-2 or SHA-1: left alone,
// x/crypto signs with SHA-1 (`ssh-rsa`) whenever a server does not advertise
// `server-sig-algs`, so a default route would still sign with SHA-1 against old
// firmware. Restricted, it signs with SHA-1 only where the route's profile says
// so. A key none of whose algorithms a permits gets an empty list — the
// handshake then fails for want of a signature algorithm — rather than being
// passed through unrestricted, which would widen the route one key at a time.
func Signer(s ssh.Signer, a control.Algorithms) ssh.Signer {
	if s == nil {
		return nil
	}
	allowed := Complete(a).PublicKeyAuths
	var permitted []string
	// Everything below is in the space of UNDERLYING signature algorithms:
	// that is what the auth list names, and what ssh.NewSignerWithAlgorithms
	// takes for a certificate signer as well as for a plain key.
	format := underlying(s.PublicKey().Type())
	for _, algo := range signatureAlgorithms(format) {
		if slices.Contains(allowed, algo) {
			permitted = append(permitted, algo)
		}
	}
	// Preference order is the route's, not the key format's.
	slices.SortStableFunc(permitted, func(x, y string) int {
		return slices.Index(allowed, x) - slices.Index(allowed, y)
	})
	if as, ok := s.(ssh.AlgorithmSigner); ok && len(permitted) > 0 {
		if restricted, err := ssh.NewSignerWithAlgorithms(as, permitted); err == nil {
			return restricted
		}
	}
	if len(permitted) == 1 && permitted[0] == format {
		// A signer that can only sign in its own format, and the format is
		// permitted: nothing to restrict.
		return s
	}
	return &refusingSigner{Signer: s}
}

// signatureAlgorithms is the set of signature algorithms a key of this
// (underlying) format can produce — x/crypto's algorithmsForKeyFormat, which it
// does not export.
func signatureAlgorithms(format string) []string {
	switch format {
	case ssh.KeyAlgoRSA:
		return []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSA}
	default:
		return []string{format}
	}
}

// underlying maps a certificate algorithm to the signature algorithm it
// carries, which is what the public-key auth list names.
func underlying(algo string) string {
	switch algo {
	case ssh.CertAlgoRSAv01:
		return ssh.KeyAlgoRSA
	case ssh.CertAlgoRSASHA256v01:
		return ssh.KeyAlgoRSASHA256
	case ssh.CertAlgoRSASHA512v01:
		return ssh.KeyAlgoRSASHA512
	case "ssh-dss-cert-v01@openssh.com": // spelled out: the library's constants for DSA are deprecated
		return "ssh-dss"
	case ssh.CertAlgoECDSA256v01:
		return ssh.KeyAlgoECDSA256
	case ssh.CertAlgoECDSA384v01:
		return ssh.KeyAlgoECDSA384
	case ssh.CertAlgoECDSA521v01:
		return ssh.KeyAlgoECDSA521
	case ssh.CertAlgoED25519v01:
		return ssh.KeyAlgoED25519
	case ssh.CertAlgoSKECDSA256v01:
		return ssh.KeyAlgoSKECDSA256
	case ssh.CertAlgoSKED25519v01:
		return ssh.KeyAlgoSKED25519
	}
	return algo
}

// refusingSigner is a key the route permits no signature algorithm for. It
// declares none, so x/crypto finds no algorithm to sign with and the
// authentication fails, which is the honest outcome.
type refusingSigner struct{ ssh.Signer }

func (r *refusingSigner) Algorithms() []string { return []string{} }

func (r *refusingSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	return nil, errNoPermittedAlgorithm
}

type sshalgError string

func (e sshalgError) Error() string { return string(e) }

const errNoPermittedAlgorithm = sshalgError("sshalg: the route's algorithm profile permits no signature algorithm for this key")

var _ ssh.MultiAlgorithmSigner = (*refusingSigner)(nil)
