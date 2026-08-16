// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package identity

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Method names how an identity was proven to the bastion. It travels with the
// identity because policy may legitimately care: a certificate and a
// password+MFA login are not the same assurance level, and an audit record that
// omits the method cannot answer "how did they get in?".
type Method string

const (
	// MethodCert is certificate/public-key authentication (tried first).
	MethodCert Method = "cert"
	// MethodPasswordMFA is password plus out-of-band MFA (the fallback).
	MethodPasswordMFA Method = "password-mfa"
)

// Valid reports whether m is a method this bastion knows how to produce.
func (m Method) Valid() bool {
	switch m {
	case MethodCert, MethodPasswordMFA:
		return true
	default:
		return false
	}
}

// SourceUnknown is used when an identity source did not name itself. It is a
// placeholder for a cosmetic field, never a stand-in for a missing decision.
const SourceUnknown = "unknown"

// ErrIncomplete is the cause of every validation failure on an Identity, so a
// caller classifies with errors.Is rather than by matching text.
var ErrIncomplete = errors.New("identity is incomplete")

// Claims carries source-specific attributes about the principal: everything an
// identity source knows that is not already a first-class field. It is a
// map[string]string rather than a richer tree because that is the shape the
// management API contract puts on the wire (mgmt.Identity.Claims); a claim with
// internal structure must be encoded into a string by its source, so adding a
// source never silently changes the contract.
//
// Keys are compared exactly. Normalising case or namespacing ("groups" vs
// "http://schemas.../groups") belongs to the identity source, not to consumers.
type Claims map[string]string

// Get returns the claim and whether it was present, so an empty claim is
// distinguishable from an absent one.
func (c Claims) Get(name string) (string, bool) {
	v, ok := c[name]
	return v, ok
}

// Value returns the claim, or "" when it is absent.
func (c Claims) Value(name string) string { return c[name] }

// Has reports whether the claim is present, whatever its value.
func (c Claims) Has(name string) bool {
	_, ok := c[name]
	return ok
}

// Clone returns a copy that shares no state with c. A nil Claims clones to nil.
func (c Claims) Clone() Claims {
	if c == nil {
		return nil
	}
	out := make(Claims, len(c))
	for k, v := range c {
		out[k] = v
	}
	return out
}

// Identity is an authenticated principal as the bastion understands it: the
// result of a user authenticator, and the input to routing, policy, and logging.
//
// It is a claims model rather than a username string so that AD, Okta, or any
// OIDC provider can be added behind the same authenticator interface without
// changing a single consumer (D4). Concretely, that means consumers must key
// their decisions on Subject, Groups, Principals, or Claims — never on Login,
// which is only the name the user happened to type at their SSH client.
//
// An Identity is immutable once returned by an authenticator. Nothing in the
// bastion may add a group, a principal, or a claim to it: the bastion is a
// policy *enforcement* point, and widening an identity locally would be
// originating policy (D2). Use Clone before handing it to code that might.
type Identity struct {
	// Subject is the stable unique id of the principal at its source
	// ("alice@example.com", an AD objectGUID, an OIDC sub). It is the only
	// field guaranteed to be stable across logins, so audit and revocation key
	// on it — not on Login.
	Subject string
	// Login is the SSH login name the client offered, with the target segment
	// already stripped (D1). It is what the user typed, so it is useful in logs
	// and prompts but must never be the basis of an authorization decision.
	Login string
	// DisplayName is a human-friendly name for logs and prompts. May be empty.
	DisplayName string
	// Source names the identity source that made the decision ("fixture", "ad",
	// "okta"). SourceUnknown when the server did not say.
	Source string
	// Principals are the principals this identity may assume on a target. The
	// target-side provisioner (0006) draws the ephemeral account name from here.
	Principals []string
	// Groups are the group memberships policy may key on.
	Groups []string
	// Claims carries everything else the source knows.
	Claims Claims
	// Method is how this identity was proven on this connection.
	Method Method
	// AuthenticatedAt is when the bastion accepted the identity. It is per
	// connection: authentication is never cached (PLAN §6.4), so this is always
	// the current session's own login, not a remembered one.
	AuthenticatedAt time.Time
}

// HasGroup reports whether the identity is a member of group. The comparison is
// exact: any case folding or domain-qualification belongs to the identity
// source, so that two sources cannot disagree about what "Engineering" means.
func (id *Identity) HasGroup(group string) bool {
	if id == nil {
		return false
	}
	return contains(id.Groups, group)
}

// HasPrincipal reports whether principal is one the identity may assume.
func (id *Identity) HasPrincipal(principal string) bool {
	if id == nil {
		return false
	}
	return contains(id.Principals, principal)
}

func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// Clone returns a deep copy, so a consumer that mutates what it was given
// cannot alter the identity the session was authenticated as.
func (id *Identity) Clone() *Identity {
	if id == nil {
		return nil
	}
	out := *id
	out.Principals = cloneStrings(id.Principals)
	out.Groups = cloneStrings(id.Groups)
	out.Claims = id.Claims.Clone()
	return &out
}

func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

// Validate reports whether the identity carries the fields every consumer
// depends on. It exists because an identity arrives from a remote decision: a
// server that answers "authenticated" with no subject has violated the contract,
// and the bastion must refuse the session rather than proceed with a principal
// it cannot name in an audit log.
func (id *Identity) Validate() error {
	switch {
	case id == nil:
		return fmt.Errorf("%w: identity is nil", ErrIncomplete)
	case strings.TrimSpace(id.Subject) == "":
		return fmt.Errorf("%w: subject is empty", ErrIncomplete)
	case strings.TrimSpace(id.Login) == "":
		return fmt.Errorf("%w: login is empty", ErrIncomplete)
	case !id.Method.Valid():
		return fmt.Errorf("%w: unknown authentication method %q", ErrIncomplete, id.Method)
	}
	return nil
}

// String renders the identity for logs. It names the subject, login, and
// method, and deliberately omits claims: claims are source-controlled and may
// carry attributes that do not belong in every log line.
func (id *Identity) String() string {
	if id == nil {
		return "identity.Identity(nil)"
	}
	return fmt.Sprintf("identity.Identity{Subject:%s, Login:%s, Source:%s, Method:%s}",
		id.Subject, id.Login, id.Source, id.Method)
}
