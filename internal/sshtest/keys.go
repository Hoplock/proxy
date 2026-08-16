// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package sshtest

import (
	"crypto/ed25519"
	"crypto/rand"
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
