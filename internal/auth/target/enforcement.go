// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"errors"
	"fmt"

	"github.com/hoplock/proxy/internal/control"
)

// This file is the credential plane's half of phase 0018's enforcement
// vocabulary (PLAN §6.5): the route's choice on the way in, and what was
// actually rendered on the way out.
//
// Two rules govern everything below and neither is negotiable:
//
//   - THE POLICY IS NOT RE-AUTHORED HERE. The allow-list a rung renders is the
//     one already in the authorize response (filter_policy.restricted_exec,
//     0006/0010). This package renders it; it never derives, widens, or
//     defaults it. Two places that each decide what may run is the bug the
//     whole architecture exists to avoid (D2).
//   - A RUNG THIS PROXY CANNOT PROVIDE ON THIS TARGET IS AN OUTAGE-CLASS
//     DENIAL and nothing is provisioned (PLAN §4.3). Never a silent downgrade:
//     the audit record would then claim a guarantee the session did not have.
//
// The distinction between a REFUSAL and a SKIPPED RUNG is the same one phase
// 0013 built into the driver errors, and it is decided by whether a connection
// was needed to find out. A rung a DECLARATION rules out — this build does not
// implement it, this driver's platform has no mechanism for it — is a skipped
// ladder entry (D14, ErrRungUnsatisfiable): the proxy walks on, and exhausting
// the ladder is the denial it already was. A rung the LIVE TARGET turns out not
// to support is ErrRungUnavailable, because by then the ladder has been walked,
// the entry was chosen, and the server's capability record was simply wrong —
// which it will sometimes be, since the proxy learns what a target supports
// only by touching it.

// ErrRungUnavailable means the target cannot provide the enforcement rung the
// route named. It is OUTAGE-CLASS (PLAN §4.3) and it is never a downgrade.
var ErrRungUnavailable = errors.New("auth/target: the target cannot provide the enforcement rung this route requires")

// Enforcement is the route's enforcement choice as the credential plane needs
// it: the two rungs, the parameters each requires, and the allow-list an
// execution rung renders.
//
// It is copied off the authorize response by the proxy rather than read from it
// here, for the reason every other field on Target is: a decision may be a
// cached one shared with other sessions, and a provisioner that mutated a slice
// it was handed would be rewriting their policy.
type Enforcement struct {
	// Execution and Reach are the rungs in force, already resolved through
	// EnforcementPolicy.ExecutionRung/ReachRung so no reader here has to decide
	// what an absent object meant.
	Execution control.ExecutionRung
	Reach     control.ReachRung
	// PlatformRole is the device role, access profile, or privilege level an
	// ExecutionPlatformAuthorized account is scoped to. It is the ROUTE's, and
	// it is what replaces the proxy-wide
	// auth.target.ephemeral_account.access_profile on the execution axis (0015,
	// 0018). Opaque to the contract and handed to the driver as data.
	PlatformRole string
	// PermittedDestinations are the destinations an
	// ReachAccountEgressRestricted session's own processes may open. It reuses
	// permitted_forwards' SHAPE and none of its meaning: that one is a rule
	// about SSH channels the proxy sees, this is a rule about sockets the
	// target's kernel sees, and one never widens the other.
	PermittedDestinations []control.ForwardDestination
	// Attestation names who asserts an attested rung and where the assertion
	// lives. Present exactly when one of the rungs is attested.
	Attestation *control.Attestation
	// RestrictedExec is the allow-list an account-restricted or
	// account-confined rung renders onto the target. It is the route's
	// filter_policy.restricted_exec, unchanged: the contract refuses either of
	// those rungs without it (0018's Validate), so a nil here on such a rung is
	// a locally-configured route rather than a served one, and it is refused
	// rather than defaulted.
	RestrictedExec *control.RestrictedExecPolicy
}

// EnforcementFrom copies the route's enforcement choice and the allow-list its
// execution rung would render.
//
// Both arguments come off one authorize response and neither is retained: the
// policy is deep-copied, exactly as internal/routing copies everything else out
// of a decision that may be shared.
func EnforcementFrom(policy *control.EnforcementPolicy, filter control.FilterPolicy) *Enforcement {
	e := &Enforcement{
		Execution: policy.ExecutionRung(),
		Reach:     policy.ReachRung(),
	}
	if policy != nil {
		clone := policy.Clone()
		e.PlatformRole = clone.PlatformRole
		e.PermittedDestinations = clone.PermittedDestinations
		e.Attestation = clone.Attestation
	}
	e.RestrictedExec = filter.Clone().RestrictedExec
	return e
}

// ExecutionRung resolves the absent-value default for a nil plan, so a caller
// that was handed no enforcement at all reads today's behaviour rather than an
// empty string.
func (e *Enforcement) ExecutionRung() control.ExecutionRung {
	if e == nil || e.Execution == "" {
		return control.ExecutionProxyInspected
	}
	return e.Execution
}

// ReachRung resolves the absent-value default on the second axis.
func (e *Enforcement) ReachRung() control.ReachRung {
	if e == nil || e.Reach == "" {
		return control.ReachProxyChannelPolicy
	}
	return e.Reach
}

// RequiresProvisioning reports whether either rung is one the proxy must apply
// ON the target.
func (e *Enforcement) RequiresProvisioning() bool {
	if e == nil {
		return false
	}
	return e.ExecutionRung().RequiresProvisioning() || e.ReachRung().RequiresProvisioning()
}

// EnforcementResult is what was ACTUALLY rendered, and it is what the audit
// record carries (0018's four fields).
//
// It exists as a separate type from Enforcement because the two are not the
// same claim and a record that confuses them is the one outcome here worse than
// not shipping the feature: one is what the route asked for, this is what the
// session stood on. Every field is filled in by whoever did the work, and a
// provisioner that rendered nothing says so rather than echoing the request.
type EnforcementResult struct {
	// Execution and Reach are the rungs IN FORCE.
	Execution control.ExecutionRung
	Reach     control.ReachRung
	// Verified says this system applied the rung itself and checked the target
	// took it. It is FALSE on an attested rung — the target enforces something
	// already, configured by somebody who is not this product, and an
	// unverified claim in an audit record is a liability unless it says so.
	Verified bool
	// AttestedBy and AttestationRef carry the attestation on an attested rung,
	// and are empty otherwise.
	AttestedBy     string
	AttestationRef string
	// ExecutionMechanism and ReachMechanism name what was actually done on the
	// target, in this repository's words rather than the contract's: the rung
	// vocabulary is named after guarantees so that an operator need not know
	// what rbash is, and these two are for the operator who does.
	ExecutionMechanism string
	ReachMechanism     string
	// Caveat is what the rung is ACTUALLY enforcing where that is narrower or
	// coarser than the guarantee's name — vendor RBAC groups commands the
	// vendor's way, so a profile permitting diagnostics may include a command
	// with a shell escape (PLAN §6.5). It is on the record because a record
	// naming only the guarantee cannot answer the one question anybody asks of
	// it afterwards.
	Caveat string
}

// ProxyCapabilities is what THIS BUILD can render, declared on every authorize
// request (contract v4).
//
// It answers "can this software do it" and never "can this target take it" —
// the second needs a login, and it is reported separately after one
// (control.CapabilityReporter). The list is deliberately written out here
// rather than derived from a registry: a build that grows a rung should have to
// say so in one obvious place, and a build that loses one should fail a test
// rather than quietly stop advertising it.
func ProxyCapabilities() *control.ProxyCapabilities {
	return &control.ProxyCapabilities{
		Execution: []control.ExecutionRung{
			// Enforced by the request axis that has shipped since 0006/0009:
			// a route naming it must deny shell and pty-req, and the session
			// re-checks that its policy actually does before it dials.
			control.ExecutionNoInteractiveShell,
			// Rendered onto the ephemeral account by confine.go.
			control.ExecutionAccountRestricted,
			control.ExecutionAccountConfined,
			// Rendered onto the device account by the driver.
			control.ExecutionPlatformAuthorized,
		},
		Reach: []control.ReachRung{
			control.ReachAccountEgressRestricted,
			control.ReachAccountNetworkIsolated,
		},
	}
}

// resultForUnprovisioned is the enforcement result for a credential method that
// touches nothing on the target — brokered-key (D6a) and the static-key
// placeholder.
//
// The two proxy-side rungs and an ATTESTED rung are all satisfiable there, and
// the attested one is the point of having the distinction: the appliance
// enforces its own roles already, this proxy configures nothing for it, and the
// record must say `platform-attested` rather than "none". What is not
// satisfiable is an APPLIED target rung, which is a contract violation the
// server's own Validate refuses (0018) — so reaching it here means a locally
// configured route, and it is refused rather than served without the rung.
func resultForUnprovisioned(e *Enforcement, method string) (*EnforcementResult, error) {
	exec, reach := e.ExecutionRung(), e.ReachRung()
	if exec.RequiresProvisioning() || reach.RequiresProvisioning() {
		return nil, fmt.Errorf("%w: %s provisions nothing on the target, and the route requires the applied rung %s/%s",
			ErrRungUnavailable, method, exec, reach)
	}
	return resultFor(e, "", ""), nil
}

// resultFor builds the record for a session whose rungs were satisfied,
// labelling the mechanisms the caller actually used.
//
// Verified is true unless a rung is attested. It is one bit for both axes
// because the contract has one field for it (0018) and because the combination
// it would otherwise have to describe cannot occur: the contract refuses an
// attestation beside an applied rung, so a response is either wholly attested
// on an axis or wholly applied.
func resultFor(e *Enforcement, execMechanism, reachMechanism string) *EnforcementResult {
	res := &EnforcementResult{
		Execution:          e.ExecutionRung(),
		Reach:              e.ReachRung(),
		Verified:           true,
		ExecutionMechanism: execMechanism,
		ReachMechanism:     reachMechanism,
	}
	if res.Execution.Attested() || res.Reach.Attested() {
		res.Verified = false
		if e != nil && e.Attestation != nil {
			res.AttestedBy = e.Attestation.AssertedBy
			res.AttestationRef = e.Attestation.Reference
		}
	}
	return res
}
