// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"errors"
	"fmt"

	"github.com/hoplock/proxy/internal/identity"
)

// ErrNoAccountName means the route named no account, the proxy's own
// configuration names none, and there is nothing server-established to draw one
// from — so the session is refused.
//
// It is an OUTAGE and not a denial (PLAN §4.3). Nobody decided this user may
// not reach this target: the estate could not say which account the proxy
// should log in as, which is a configuration fault whoever reads the audit
// record can fix. Nothing is provisioned and nothing is dialled before it is
// returned.
//
// What it replaces is a fallback to identity.Identity.Login — the name the user
// typed at their own SSH client. Choosing the account is an authorization
// decision, arguably the most consequential one this proxy makes: the account
// name is what the target's own audit trail, its file ownership, its
// authorized_keys and (on a password credential) half the credential pair are
// made of. internal/identity says in as many words that Login must never be the
// basis of one, and Login is not guaranteed stable across logins, so the same
// person could map to different accounts and different people to the same one.
// Refusing is the honest answer; guessing was never one.
var ErrNoAccountName = errors.New("auth/target: no account name is available for this route")

// noAccountName renders the refusal. remedy names the thing that would have
// answered the question, because the operator reading it is the one who has to
// supply it.
func noAccountName(method, remedy string) error {
	return fmt.Errorf("%w: %s named no %q parameter and %s", ErrNoAccountName, method, ParamUsername, remedy)
}

// accountFromPrincipals draws the account name from the identity's
// server-established principals, for a route that named none itself.
//
// Principals is the field that was designed for exactly this and never wired
// up: Hoplock Control puts it on the authenticate/authorize response, an
// Identity is immutable once returned (PLAN D2), and the proxy never adds to
// it. That is precisely the property Login lacks — it is server-established
// rather than client-typed — which is what makes it an answer rather than
// another guess.
//
// The multi-principal rule is deliberately strict. Exactly one principal is the
// identity's account and is used. SEVERAL is refused unless the route named
// one, because picking the first would make the order the server happened to
// serialise a list in into policy, and nothing about that order is contractual.
// NONE is refused because there is nothing to pick.
func accountFromPrincipals(id *identity.Identity, method string) (string, error) {
	switch {
	case id == nil || len(id.Principals) == 0:
		return "", noAccountName(method, "the identity carries no principal to draw one from")
	case len(id.Principals) > 1:
		return "", noAccountName(method, fmt.Sprintf(
			"the identity carries %d principals (%v), and which of them to assume is the server's decision to state, not this proxy's to pick",
			len(id.Principals), id.Principals))
	default:
		return id.Principals[0], nil
	}
}
