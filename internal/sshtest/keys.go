// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package sshtest

import (
	"crypto/dsa" //nolint:staticcheck // a DSA-only device is what GenerateDSAHostKey stands in for
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// GenerateSigner returns a fresh ed25519 SSH key.
//
// Every key in a test is generated, never a fixture: a committed private key is
// a private key in a repository however loudly it is labelled a test key, and
// ed25519 generation is fast enough that there is nothing to save.
func GenerateSigner() (ssh.Signer, error) {
	signer, _, err := GenerateKeyPair()
	return signer, err
}

// GenerateKeyPair returns a fresh key as both a signer and an OpenSSH-format
// private key file, for the code paths that load a key from disk.
func GenerateKeyPair() (ssh.Signer, []byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("sshtest: generate key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("sshtest: sign with key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, nil, fmt.Errorf("sshtest: marshal key: %w", err)
	}
	return signer, pem.EncodeToMemory(block), nil
}

// MustGenerateSigner is GenerateSigner for callers with no error path, such as
// a test fixture built in a package-level helper.
func MustGenerateSigner() ssh.Signer {
	signer, err := GenerateSigner()
	if err != nil {
		panic(err)
	}
	return signer
}

// GenerateRSASHA1HostKey returns an RSA host key that signs ONLY with SHA-1
// (`ssh-rsa`), which is what a device too old for RSA-SHA2 presents.
//
// A plain RSA signer would also offer `rsa-sha2-256` and `rsa-sha2-512`, and a
// test of the legacy profiles against it would pass under the default profile
// too, proving nothing.
func GenerateRSASHA1HostKey() (ssh.Signer, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("sshtest: generate RSA key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("sshtest: sign with RSA key: %w", err)
	}
	as, ok := signer.(ssh.AlgorithmSigner)
	if !ok {
		return nil, fmt.Errorf("sshtest: RSA signer cannot choose its algorithm")
	}
	return ssh.NewSignerWithAlgorithms(as, []string{ssh.KeyAlgoRSA})
}

// GenerateDSAHostKey returns a DSA host key (`ssh-dss`), the only kind some
// appliance firmware of the SHA-1 era has. crypto/dsa is deprecated, and a
// DSA-only device is exactly what this stands in for.
//
//nolint:staticcheck // see above
func GenerateDSAHostKey() (ssh.Signer, error) {
	var priv dsa.PrivateKey
	if err := dsa.GenerateParameters(&priv.Parameters, rand.Reader, dsa.L1024N160); err != nil {
		return nil, fmt.Errorf("sshtest: generate DSA parameters: %w", err)
	}
	if err := dsa.GenerateKey(&priv, rand.Reader); err != nil {
		return nil, fmt.Errorf("sshtest: generate DSA key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(&priv)
	if err != nil {
		return nil, fmt.Errorf("sshtest: sign with DSA key: %w", err)
	}
	return signer, nil
}

// Negotiation restricts what an in-process server will negotiate, so a test
// can stand in for a target that speaks only legacy algorithms. An empty field
// leaves the library's server default for that axis.
type Negotiation struct {
	KeyExchanges []string
	Ciphers      []string
	MACs         []string
}

func (n Negotiation) apply(cfg *ssh.ServerConfig) {
	cfg.KeyExchanges = n.KeyExchanges
	cfg.Ciphers = n.Ciphers
	cfg.MACs = n.MACs
}
