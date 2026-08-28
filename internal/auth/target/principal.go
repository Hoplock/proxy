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
	return validatePrincipalChars(name)
}

// validatePrincipalChars is validatePrincipal without the length rule, so that
// a platform with its own declared limit can apply the same character set (see
// validatePrincipalLen). The character set itself is not negotiable: it is the
// intersection of what a POSIX useradd and a device configuration parser both
// accept without quoting, and widening it for one platform would widen it for
// the shell scripts too.
func validatePrincipalChars(name string) error {
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

// Naming under a DECLARED limit (PLAN §5.3, D13).
//
// Everything above is the POSIX scheme and it is unchanged: a Linux account is
// named exactly as phase 0007 named it, byte for byte, and the tests that pin
// that are the proof. What follows generalises the *choice* of scheme over a
// limit a device driver declares, because the three parts of the name above
// need 31 characters and a great many platforms cap an administrator name well
// below that.
//
// Which part gives way is the whole design. The reaper prefix cannot: without
// it one proxy's sweep deletes another proxy's live accounts. The uniqueness
// token cannot: without it two concurrent sessions share an account and the
// first teardown removes the other's access. So the READABLE LOGIN SEGMENT is
// what goes — a six-character truncation of "automation-disk-check" reads as
// attributable when it is not, and its absence is at least honest. Attribution
// then lives in the mapping event the provisioner emits (PLAN §5.3), which is
// why that event is load-bearing here in a way it never is on Linux.
const (
	// minAccountNameLen is the shortest declared limit that can be served. At
	// ten characters the token falls under four base36 characters, which is
	// both collision-prone and GUESSABLE — and on a password credential the
	// account name is half the credential pair.
	minAccountNameLen = 11
	// readableSchemeMin is the declared limit at or above which the POSIX
	// scheme is used unchanged.
	readableSchemeMin = 32
	// constrainedTagLen is how much of the proxy digest scopes a constrained
	// name. It is the reaper's whole selector there, so it is not negotiable
	// downwards.
	constrainedTagLen = 4
	// constrainedFixedLen is what the scheme spends before the token: "hl-"
	// plus the tag, plus the four characters PLAN §5.3 reserves so that the
	// token is (X-7) long.
	constrainedFixedLen = len(principalPrefix) + constrainedTagLen
	// base36Alphabet is the token alphabet under a constrained limit. Base36
	// rather than hex is not cosmetic: at X=12 the token is five characters,
	// worth ~26 bits in base36 against 20 in hex, and that difference lands
	// exactly where the budget is tightest.
	base36Alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
)

// ErrNameLimit means a platform's declared account-name limit cannot carry a
// name this system can safely reap.
//
// It is a REFUSAL, never a truncation. Truncating would shorten either the
// reaper prefix or the uniqueness token, and the caller cannot know which half
// it just destroyed — see the constants above for what each one is holding up.
var ErrNameLimit = errors.New("auth/target: the platform's account-name limit is too short to serve")

// naming renders one platform's account names under its declared limit.
//
// It is built once per provisioning and carries the reaper's prefix with it, so
// that the name a session gets and the prefix a sweep matches are decided by
// the same value in the same place. Two copies of that rule that disagree is a
// sweep that removes live accounts or one that finds none.
type naming struct {
	// limit is the platform's declared maximum, for the error message.
	limit int
	// prefix is what the reaper matches: every account this proxy creates on
	// this platform starts with it, and nothing else does.
	prefix string
	// readable says the login segment survives, which is true only at or above
	// readableSchemeMin.
	readable bool
	// tokenLen is the constrained scheme's token length, in base36 characters.
	tokenLen int
}

// newNaming selects the scheme for a declared limit.
//
// A limit of zero is UNDECLARED and is refused rather than assumed generous: a
// driver that forgot to declare one would otherwise get the POSIX scheme and
// discover the platform's real cap at the first `edit`, which is after the
// account may already exist.
func newNaming(proxyID string, limit int) (naming, error) {
	switch {
	case limit <= 0:
		return naming{}, fmt.Errorf("%w: the driver declares no maximum account-name length", ErrNameLimit)
	case limit < minAccountNameLen:
		return naming{}, fmt.Errorf("%w: %d characters, and %d is the shortest name that can carry both a reaper prefix and a token worth guessing at",
			ErrNameLimit, limit, minAccountNameLen)
	case limit >= readableSchemeMin:
		return naming{limit: limit, prefix: principalPrefixFor(proxyID), readable: true}, nil
	default:
		return naming{
			limit:    limit,
			prefix:   constrainedPrefixFor(proxyID),
			tokenLen: limit - constrainedFixedLen,
		}, nil
	}
}

// constrainedPrefixFor is the reaper prefix under a constrained limit: "hl-"
// and a base36 proxy tag, with no separator, because at eleven characters a
// separator costs a bit of token entropy for nothing.
//
// It is derived from the same digest as principalPrefixFor and rendered in
// base36 rather than hex, which buys the tag ~1.7M values instead of 65k. The
// tag's job is to keep two proxies out of each other's accounts, and that job
// gets harder as an estate scales out, which is exactly when the tags multiply.
func constrainedPrefixFor(proxyID string) string {
	sum := sha256.Sum256([]byte(proxyID))
	return principalPrefix + base36Encode(sum[:], constrainedTagLen)
}

// name derives one session's account name from the login it belongs to.
func (n naming) name(login string) (string, error) {
	if n.readable {
		// Byte-identical to what phase 0007 produces, deliberately: the POSIX
		// path's tests pass unmodified because this is the same function they
		// were written against.
		return newPrincipal(n.prefix, login)
	}
	token, err := randomBase36(n.tokenLen)
	if err != nil {
		return "", err
	}
	name := n.prefix + token
	if err := validatePrincipalLen(name, n.limit); err != nil {
		return "", err
	}
	return name, nil
}

// validatePrincipalLen is validatePrincipal against a platform's own limit.
func validatePrincipalLen(name string, limit int) error {
	if name == "" {
		return fmt.Errorf("%w: empty", ErrInvalidPrincipal)
	}
	if err := validatePrincipalChars(name); err != nil {
		return err
	}
	if len(name) > limit {
		return fmt.Errorf("%w: %q is longer than the %d characters this platform accepts", ErrInvalidPrincipal, name, limit)
	}
	return nil
}

// base36Encode renders the first bytes of a digest as n base36 characters. It
// is used for the proxy tag, where the input is already a digest and the only
// requirement is a stable, well-spread rendering.
func base36Encode(digest []byte, n int) string {
	out := make([]byte, n)
	var acc uint64
	for i := 0; i < 8 && i < len(digest); i++ {
		acc = acc<<8 | uint64(digest[i])
	}
	for i := range out {
		out[i] = base36Alphabet[acc%36]
		acc /= 36
	}
	return string(out)
}

// randomBase36 returns n base36 characters of cryptographic randomness.
//
// It rejects the tail of the byte range rather than taking a modulus of it: 256
// is not a multiple of 36, so a plain modulus would make the first four
// characters of the alphabet measurably likelier, and this token is the only
// thing standing between two concurrent sessions on a device.
func randomBase36(n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("%w: a token of %d characters", ErrNameLimit, n)
	}
	const limit = 256 - (256 % len(base36Alphabet))
	out := make([]byte, 0, n)
	buf := make([]byte, n)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("auth/target: generate account token: %w", err)
		}
		for _, b := range buf {
			if int(b) >= limit {
				continue
			}
			out = append(out, base36Alphabet[int(b)%len(base36Alphabet)])
			if len(out) == n {
				break
			}
		}
	}
	return string(out), nil
}
