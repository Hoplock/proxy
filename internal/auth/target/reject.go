// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import "strings"

// This file is the whole coupling between this repository and the way
// golang.org/x/crypto/ssh renders a refused credential. It is one file, two
// constants, and one function on purpose: the library exports no typed error
// for "the target would not accept what we offered", so the classification has
// to read the text — and a text match that is spread across the tree is a text
// match nobody can find when it stops matching.

// The sentence x/crypto builds when every authentication method it had was
// refused (client_auth.go):
//
//	ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain
//
// Both halves are matched rather than one, because either alone appears in
// errors that are not this: the prefix also opens a partial-success error, and
// the suffix is generic enough to be reused. Matching the pair is what keeps a
// host-key failure or a dial timeout from being scored as a refused credential.
const (
	authRejectionPrefix = "ssh: unable to authenticate"
	authRejectionSuffix = "no supported methods remain"
)

// IsAuthRejection reports whether err is the TARGET refusing the credential the
// proxy offered it.
//
// This is a different failure from every other one the target leg can produce,
// and telling them apart is the point (PLAN §4.3): the host is reachable, the
// handshake got as far as authentication, and what failed is the proxy's own
// credential. Reported as a dial failure it reads as a network fault, and the
// operator who could fix it is sent to look at the one thing that is working.
//
// It is deliberately conservative. Anything it does not recognise stays a dial
// failure, which is the classification the proxy already had: a rejection
// mistaken for an outage costs an operator a wrong first guess, while an outage
// mistaken for a rejection would open a circuit breaker against a credential
// that was never refused.
func IsAuthRejection(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, authRejectionPrefix) && strings.Contains(msg, authRejectionSuffix)
}
