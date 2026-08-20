// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// The ephemeral naming convention (D6, PLAN §5.1).
//
// Every account the ephemeral provisioner creates is named
//
//	hl-<proxy tag>-<login>-<token>
//
// and nothing else on the target starts with that prefix. The shape is not
// cosmetic: each of its three parts answers a robustness requirement that has
// no other answer.
//
//   - "hl-<proxy tag>-" is what the ORPHAN REAPER matches. The tag is derived
//     from this proxy's id, so two proxies provisioning on the same target
//     never see each other's accounts as orphans — a reaper that swept every
//     hl- account would kill live sessions belonging to another proxy, and it
//     would do it at exactly the moment an estate scaled out.
//   - "<login>" keeps the account attributable on the target itself. `who`, an
//     audit log, and a stray process list all name a person rather than a
//     random string, which is most of why D6 is worth its cost.
//   - "<token>" is what makes CONCURRENCY safe. Two sessions for the same login
//     on the same target get different accounts, so neither one's teardown can
//     remove the other's user, home, or keys. Coordinating on a shared account
//     instead would mean the second session waiting on the first, or the first
//     tearing down under the second — this repository chose unique principals,
//     and this token is that choice.
const (
	// principalPrefix marks an account as this system's to remove.
	principalPrefix = "hl-"
	// proxyTagLen is how much of the proxy id's digest scopes the prefix.
	proxyTagLen = 4
	// principalTokenLen is the per-session uniqueness token, in hex characters.
	principalTokenLen = 8
	// principalLoginLen caps the login part so the whole name fits in
	// maxPrincipalLen.
	principalLoginLen = 14
	// maxPrincipalLen is the portable limit on a POSIX user name (useradd
	// enforces 32 on Linux, and shorter elsewhere is rare enough to configure
	// around rather than design for).
	maxPrincipalLen = 32
)

// ErrInvalidPrincipal means a name could not be used as a target account.
var ErrInvalidPrincipal = errors.New("auth/target: invalid ephemeral principal")

// principalPrefixFor returns the account-name prefix belonging to one proxy.
//
// The tag is a digest of the proxy id rather than the id itself: ids are
// deployment-assigned and can be long, contain dots, or differ only in a
// suffix, none of which survives a 32-character account name.
func principalPrefixFor(proxyID string) string {
	sum := sha256.Sum256([]byte(proxyID))
	return principalPrefix + hex.EncodeToString(sum[:])[:proxyTagLen] + "-"
}

// newPrincipal derives this session's account name from the login it belongs
// to. The randomness is what makes it unique; the login is what makes it
// readable.
func newPrincipal(prefix, login string) (string, error) {
	base := sanitizeLogin(login)
	if base == "" {
		return "", fmt.Errorf("%w: login %q has no usable characters", ErrInvalidPrincipal, login)
	}
	token, err := randomToken(principalTokenLen)
	if err != nil {
		return "", err
	}
	name := prefix + base + "-" + token
	if len(name) > maxPrincipalLen {
		return "", fmt.Errorf("%w: %q is longer than %d characters", ErrInvalidPrincipal, name, maxPrincipalLen)
	}
	if err := validatePrincipal(name); err != nil {
		return "", err
	}
	return name, nil
}

// sanitizeLogin reduces a login to the portable POSIX account-name character
// set. It is deliberately lossy — two logins can reduce to the same base —
// because uniqueness comes from the token, not from here.
func sanitizeLogin(login string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(login) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_', r == '-':
			b.WriteRune(r)
		default:
			// Anything else — a dot, an @, a space, a non-ASCII rune — is
			// dropped rather than transliterated: a name that is *sometimes*
			// legal is the kind that fails on one host in a fleet.
		}
		if b.Len() >= principalLoginLen {
			break
		}
	}
	return strings.Trim(b.String(), "-_")
}

// validatePrincipal is the last gate before a name is interpolated into a shell
// script on the target. Everything that reaches a script goes through a check
// like this one; see shellQuote for why that is belt and braces rather than the
// only defence.
func validatePrincipal(name string) error {
	if name == "" {
		return fmt.Errorf("%w: empty", ErrInvalidPrincipal)
	}
	if len(name) > maxPrincipalLen {
		return fmt.Errorf("%w: %q is longer than %d characters", ErrInvalidPrincipal, name, maxPrincipalLen)
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-' || r == '_':
			if i == 0 {
				return fmt.Errorf("%w: %q must not start with %q", ErrInvalidPrincipal, name, string(r))
			}
		default:
			return fmt.Errorf("%w: %q contains %q", ErrInvalidPrincipal, name, string(r))
		}
	}
	return nil
}

// randomToken returns n hex characters of cryptographic randomness.
func randomToken(n int) (string, error) {
	buf := make([]byte, (n+1)/2)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("auth/target: generate principal token: %w", err)
	}
	return hex.EncodeToString(buf)[:n], nil
}
