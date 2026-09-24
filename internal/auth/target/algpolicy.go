// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"errors"

	"golang.org/x/crypto/ssh"
)

// This file is reject.go's sibling (phase 0043): the one place that knows how
// x/crypto reports a target that cannot negotiate anything the route's
// algorithm profile allows. Unlike a refused credential this failure HAS a
// typed error, so it is matched with errors.As and never by text.

// The negotiated axes, as the audit record names them (`algorithm_axis`). They
// are this repository's words rather than x/crypto's, because the library
// splits ciphers and MACs by direction and a route's profile does not — an
// operator choosing a profile needs to know WHICH list was short, not which way
// round the bytes were flowing.
const (
	AlgorithmAxisKeyExchange = "key_exchange"
	AlgorithmAxisHostKey     = "host_key"
	AlgorithmAxisCipher      = "cipher"
	AlgorithmAxisMAC         = "mac"
	AlgorithmAxisCompression = "compression"
)

// algorithmAxes maps AlgorithmNegotiationError.What — the strings x/crypto's
// findCommon is called with in common.go — to an axis. It is the whole
// coupling to the library's wording on this path; a What it does not know is
// still an algorithm-policy failure, reported under its own words.
var algorithmAxes = map[string]string{
	"key exchange":                 AlgorithmAxisKeyExchange,
	"host key":                     AlgorithmAxisHostKey,
	"client to server cipher":      AlgorithmAxisCipher,
	"server to client cipher":      AlgorithmAxisCipher,
	"client to server MAC":         AlgorithmAxisMAC,
	"server to client MAC":         AlgorithmAxisMAC,
	"client to server compression": AlgorithmAxisCompression,
	"server to client compression": AlgorithmAxisCompression,
}

// IsAlgorithmPolicyUnmet reports whether err is a target the proxy could not
// agree ANY algorithm with on some axis, under what the route allows.
//
// It is a different failure from a dial failure, and telling them apart is the
// point: the target answered and spoke SSH, and what failed is that the route's
// profile allows nothing the target offers. Reported as a dial failure it sends
// an operator to the network; reported as this, it sends them to the route's
// profile, which is the thing to change. It is never evidence about the
// credential — authentication was never reached — so it is never scored
// against one (phase 0025).
func IsAlgorithmPolicyUnmet(err error) bool {
	var neg *ssh.AlgorithmNegotiationError
	return errors.As(err, &neg)
}

// AlgorithmPolicyUnmet returns the axis that could not be agreed and the list
// the TARGET offered on it, from an error IsAlgorithmPolicyUnmet accepts.
//
// The offered list is what makes the record useful: it is what an operator
// reads to decide which legacy profile the route needs. It names algorithms,
// never material.
func AlgorithmPolicyUnmet(err error) (axis string, offered []string, ok bool) {
	var neg *ssh.AlgorithmNegotiationError
	if !errors.As(err, &neg) {
		return "", nil, false
	}
	axis, known := algorithmAxes[neg.What]
	if !known {
		axis = neg.What
	}
	// On a client connection RequestedAlgorithms is the PEER's list (x/crypto's
	// findCommon fills SupportedAlgorithms with ours).
	return axis, append([]string(nil), neg.RequestedAlgorithms...), true
}
