// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import "strings"

// This file is the whole coupling between this repository and the way
// golang.org/x/crypto/ssh renders a refused credential. It is one file, two
// constants, and one function on purpose: the library exports no typed error
// for "the far side would not accept what we offered", so the classification
// has to read the text — and a text match that is spread across the tree is a
// text match nobody can find when it stops matching.
//
// It lives in this package because the target leg was the first leg to need it
// (prompt 0025) and because moving it would move its tripwire test with it for
// no gain: `internal/proxy` already imports this package, and the chain leg's
// caller (prompt 0033) is one import away. What matters is that there is
// exactly ONE copy of the strings below, not which package holds it.

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

// IsAuthRejection reports whether err is the FAR SIDE of an SSH handshake
// refusing the credential the proxy offered it.
//
// This is a different failure from every other one such a leg can produce, and
// telling them apart is the point (PLAN §4.3): the host is reachable, the
// handshake got as far as authentication, and what failed is the proxy's own
// credential. Reported as a dial failure it reads as a network fault, and the
// operator who could fix it is sent to look at the one thing that is working.
//
// It has two callers, on the proxy's two outbound legs, and the wording it
// matches is the same on both because x/crypto builds it in one place. The
// target leg is this package's own (auth.go, prompt 0025). The chain leg is
// `internal/proxy`'s: a next hop refusing this proxy's chain identity key (D11)
// produces the identical error, and phase 0033 classified it here rather than
// copying the string. The function therefore says "far side" and not "target" —
// it is the one coupling point to x/crypto's rendering, and a second copy of it
// in the chain path is exactly what this file exists to prevent.
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
