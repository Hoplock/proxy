// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/sshalg"
)

// This file is reject.go's sibling (phase 0043): the one place that knows how
// x/crypto reports a target that cannot negotiate anything the route's
// algorithm profile allows. Unlike a refused credential this failure HAS a
// typed error, so it is matched with errors.As and never by text.

// The negotiated axes, as the audit record names them (`algorithm_axis`). They
// are this repository's words rather than x/crypto's, because the library
// splits ciphers and MACs by direction and a route's profile does not — an
// operator choosing a profile needs to know WHICH list was short, not which way
// round the bytes were flowing. Since phase 0045 they are defined beside the
// expansion in internal/control, which has to pick a route's list by axis to
// say which step of it a target could not meet; these are the same constants.
const (
	AlgorithmAxisKeyExchange = control.AlgorithmAxisKeyExchange
	AlgorithmAxisHostKey     = control.AlgorithmAxisHostKey
	AlgorithmAxisCipher      = control.AlgorithmAxisCipher
	AlgorithmAxisMAC         = control.AlgorithmAxisMAC
	AlgorithmAxisCompression = control.AlgorithmAxisCompression
	// AlgorithmAxisPublicKeyAuth is the one axis a signature, not KEXINIT,
	// decides (phase 0045): see signatureUnmet.
	AlgorithmAxisPublicKeyAuth = control.AlgorithmAxisPublicKeyAuth
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
	if errors.As(err, &neg) {
		return true
	}
	_, unmet := signatureUnmet(err)
	return unmet
}

// signatureUnmet is sshalg.SignatureUnmet: the one algorithm failure x/crypto
// reports without a type, recognised in one place (phase 0045).
func signatureUnmet(err error) (keyType string, ok bool) { return sshalg.SignatureUnmet(err) }

// AlgorithmPolicyUnmet returns the axis that could not be agreed and the list
// the TARGET offered on it, from an error IsAlgorithmPolicyUnmet accepts.
//
// The offered list is what makes the record useful: it is what an operator
// reads to decide which legacy profile the route needs. It names algorithms,
// never material.
func AlgorithmPolicyUnmet(err error) (axis string, offered []string, ok bool) {
	var neg *ssh.AlgorithmNegotiationError
	if !errors.As(err, &neg) {
		if _, unmet := signatureUnmet(err); unmet {
			// Public-key signing is not negotiated in KEXINIT, and the library
			// does not say what the target accepts: the list is unknown.
			return AlgorithmAxisPublicKeyAuth, nil, true
		}
		return "", nil, false
	}
	axis, known := algorithmAxes[neg.What]
	if !known {
		axis = neg.What
	}
	// On a client connection RequestedAlgorithms is the PEER's list (x/crypto's
	// findCommon fills SupportedAlgorithms with ours).
	offered = slices.Clone(neg.RequestedAlgorithms)
	if axis == AlgorithmAxisKeyExchange {
		offered = withoutExtensionSignals(offered)
	}
	return axis, offered, true
}

// extensionSignals are names SSH carries in the KEY-EXCHANGE name-list that are
// not key exchanges: RFC 8308's extension-negotiation markers, and OpenSSH's
// strict key exchange (the Terrapin countermeasure). A target's list is
// reported so an operator can see which exchanges it has; these would only be
// noise in it, and no level could ever contain them.
var extensionSignals = []string{
	"ext-info-c", "ext-info-s",
	"kex-strict-c-v00@openssh.com", "kex-strict-s-v00@openssh.com",
}

func withoutExtensionSignals(list []string) []string {
	return slices.DeleteFunc(list, func(name string) bool {
		return slices.Contains(extensionSignals, name)
	})
}

// AlgorithmFailure is a target that could not meet the route's algorithm policy
// on one axis (phases 0043, 0045): one failure class, whichever part of the
// policy the target missed.
type AlgorithmFailure struct {
	// Axis is the axis that could not be agreed (algorithm_axis).
	Axis string
	// Offered is what the TARGET offered there, extension signals left out.
	Offered []string
	// Cause is which step of the expansion removed the last algorithm the
	// target offered: the profile, the floor, or a ban
	// (algorithm_policy_cause). It is what says which thing to change.
	Cause control.AlgorithmPolicyCause
}

// AlgorithmPolicyFailure classifies err against the policy the connection was
// dialled under. It is AlgorithmPolicyUnmet plus the one thing only the policy
// can answer: which part of it the target could not meet.
func AlgorithmPolicyFailure(err error, policy control.AlgorithmPolicy) (AlgorithmFailure, bool) {
	axis, offered, ok := AlgorithmPolicyUnmet(err)
	if !ok {
		return AlgorithmFailure{}, false
	}
	if keyType, signing := signatureUnmet(err); signing {
		// The step that left the proxy's key nothing to sign with; a key that
		// still had something is the target refusing it, the profile's case.
		cause := policy.CauseWhere(func(a control.Algorithms) bool {
			return keyType == "" || len(sshalg.Permitted(keyType, a)) > 0
		})
		return AlgorithmFailure{Axis: axis, Cause: cause}, true
	}
	return AlgorithmFailure{Axis: axis, Offered: offered, Cause: policy.Cause(axis, offered)}, true
}

// changedUnderTheProxy is what a SWEEP says when its connection to a target
// fails on algorithm policy (phase 0045). A sweep dials with the lists the
// target was provisioned under, so failing to agree an algorithm now means the
// target itself changed — an upgrade removed something, or a reconfiguration
// did — and the record says that rather than blaming the route. It is a sweep
// failure on the path sweep failures already take, not a session's stage.
func changedUnderTheProxy(err error) (reason, axis string, offered []string, ok bool) {
	axis, offered, ok = AlgorithmPolicyUnmet(err)
	if !ok {
		return "", "", nil, false
	}
	what := fmt.Sprintf("the target no longer offers any %s algorithm the route's algorithm policy allows (it offered: %s)",
		axis, strings.Join(offered, ","))
	if axis == AlgorithmAxisPublicKeyAuth {
		// No list to quote: the library does not say what the target accepts.
		what = "the target no longer accepts any signature algorithm the route's algorithm policy lets the proxy's key use"
	}
	return what + "; it was provisioned under the same policy, so the target has changed under the proxy", axis, offered, true
}
