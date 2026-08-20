// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrNoCredential means the source holds nothing for this session.
//
// It is a distinct sentinel because "the reference names nothing here" is an
// outage the operator can fix — material is missing on this proxy — and not a
// policy denial. The user is told the same either way (PLAN §4.3); the operator
// is not.
var ErrNoCredential = errors.New("auth/target: no brokered credential for this target")

// CredentialSource yields the credential a brokered-key session logs into its
// target with (D6a, PLAN §5.2).
//
// THIS IS THE SEAM Hoplock Control's own plan expects to implement. Today the
// implementations in this file read local material — a directory of key files,
// or the process environment — selected by the route's opaque
// `credential_ref`. A future Control that MINTS a per-session credential
// implements this same interface and arrives as another `target_auth` method,
// not as another change to everything that touches a credential.
//
// Two rules bind every implementation, and both are the point of the method
// rather than hygiene:
//
//   - what it returns is held in memory for one session and zeroed by that
//     session's teardown;
//   - it never writes credential material anywhere, never logs it, and never
//     puts it in an error string. An error says which reference failed, never
//     what it held.
type CredentialSource interface {
	// Name identifies the source for logging ("dir", "env", ...).
	Name() string
	// Credential returns the material for one session, or ErrNoCredential.
	Credential(ctx context.Context, req CredentialRequest) (*Credential, error)
}

// CredentialRequest is what a source is told about the session asking.
//
// It carries no identity claims beyond the subject on purpose: a local store
// keyed by anything richer would be policy living on the proxy, and policy is
// the server's (D2). The subject is here for the future minting Control, which
// needs to know who the credential is being issued for.
type CredentialRequest struct {
	// Target is the host the session is being opened to.
	Target Target
	// Ref is the route's opaque credential_ref, or empty when it named none.
	Ref string
	// Username is the account the session will log in as.
	Username string
	// Subject is the authenticated user's subject.
	Subject string
}

// key is the lookup key for a source that stores material locally: the route's
// reference when it named one, and the target host otherwise.
func (r CredentialRequest) key() string {
	if r.Ref != "" {
		return r.Ref
	}
	return r.Target.Host
}

// Credential is one target credential, held in memory for a session only.
//
// It is bytes rather than a parsed key so that it can be zeroed. Exactly one of
// PrivateKey and Password is set.
type Credential struct {
	// PrivateKey is a PEM-encoded private key.
	PrivateKey []byte
	// Passphrase decrypts PrivateKey when it is encrypted.
	Passphrase []byte
	// Password is a password credential, for the appliances that offer nothing
	// else.
	Password []byte
}

// Zero overwrites every byte of the credential. It is safe to call more than
// once, because teardown is.
func (c *Credential) Zero() {
	if c == nil {
		return
	}
	for _, b := range [][]byte{c.PrivateKey, c.Passphrase, c.Password} {
		for i := range b {
			b[i] = 0
		}
	}
	c.PrivateKey, c.Passphrase, c.Password = nil, nil, nil
}

// validCredentialKey accepts the characters a reference may contain.
//
// The reference comes from the management server and is used to build a file
// name and an environment variable name, so it is validated before either: a
// reference of "../../etc/shadow" must be an error, not a read.
func validCredentialKey(key string) error {
	if key == "" {
		return fmt.Errorf("%w: empty reference", ErrInvalidParam)
	}
	for _, r := range key {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_':
		default:
			return fmt.Errorf("%w: reference %q contains %q", ErrInvalidParam, key, string(r))
		}
	}
	if strings.Contains(key, "..") {
		return fmt.Errorf("%w: reference %q contains %q", ErrInvalidParam, key, "..")
	}
	return nil
}

// DirCredentialSource reads brokered credentials from a directory, one file per
// reference, loaded on demand and never cached.
//
// On demand and uncached is the design, not an optimisation left undone: a
// credential this process is not currently using is a credential this process
// should not be holding. The file is read when a session starts and its bytes
// are zeroed when that session ends.
type DirCredentialSource struct {
	dir string
	ext string
}

var _ CredentialSource = (*DirCredentialSource)(nil)

// NewDirCredentialSource returns a source reading "<dir>/<ref><ext>".
func NewDirCredentialSource(dir, ext string) (*DirCredentialSource, error) {
	if dir == "" {
		return nil, errors.New("auth/target: the brokered-key directory source requires a directory")
	}
	if ext == "" {
		ext = ".key"
	}
	return &DirCredentialSource{dir: dir, ext: ext}, nil
}

// Name implements CredentialSource.
func (s *DirCredentialSource) Name() string { return "dir" }

// Credential implements CredentialSource.
func (s *DirCredentialSource) Credential(_ context.Context, req CredentialRequest) (*Credential, error) {
	key := req.key()
	if err := validCredentialKey(key); err != nil {
		return nil, err
	}
	path := filepath.Join(s.dir, key+s.ext)
	pem, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// The path is named because it is an operator's problem to fix and
			// contains no secret; the file's CONTENTS never appear in an error.
			return nil, fmt.Errorf("%w: %s", ErrNoCredential, path)
		}
		return nil, fmt.Errorf("auth/target: read brokered credential %s: %w", path, err)
	}
	return &Credential{PrivateKey: pem}, nil
}

// EnvCredentialSource reads brokered credentials from the process environment,
// which is how a container-scheduled proxy is usually given a secret.
type EnvCredentialSource struct {
	prefix string
	lookup func(string) (string, bool)
}

var _ CredentialSource = (*EnvCredentialSource)(nil)

// NewEnvCredentialSource returns a source reading "<prefix><REF>", with the
// reference upper-cased and its punctuation replaced by underscores.
func NewEnvCredentialSource(prefix string) (*EnvCredentialSource, error) {
	if prefix == "" {
		return nil, errors.New("auth/target: the brokered-key environment source requires a variable prefix")
	}
	return &EnvCredentialSource{prefix: prefix, lookup: os.LookupEnv}, nil
}

// Name implements CredentialSource.
func (s *EnvCredentialSource) Name() string { return "env" }

// Credential implements CredentialSource.
func (s *EnvCredentialSource) Credential(_ context.Context, req CredentialRequest) (*Credential, error) {
	key := req.key()
	if err := validCredentialKey(key); err != nil {
		return nil, err
	}
	name := s.prefix + envSuffix(key)
	value, ok := s.lookup(name)
	if !ok || value == "" {
		// The variable's NAME, never its value.
		return nil, fmt.Errorf("%w: %s is not set", ErrNoCredential, name)
	}
	return &Credential{PrivateKey: []byte(value)}, nil
}

// envSuffix renders a reference as an environment variable name suffix.
func envSuffix(key string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(key) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}
