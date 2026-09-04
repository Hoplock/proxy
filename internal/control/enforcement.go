// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// This file carries the policy vocabulary added by phase 0018 (contract v4):
// WHERE a policy claim is enforced (D12 as amended, PLAN §6.5), and the bounds
// a session exists under (D16, PLAN §13 UC3).
//
// Nothing here is enforced by this package. Phase 0019 renders an enforcement
// rung onto an account; phase 0025 closes a session at its deadline. Each type
// names the phase that consumes it, and the absent-value default of every field
// is stated on the field — a policy field whose default is unwritten is a
// policy field that will eventually be guessed at.

// ExecutionRung says WHERE the limit on what a session may EXECUTE is enforced
// (PLAN §6.5, axis 1). It is named after what it GUARANTEES and never after its
// mechanism: an operator reading an audit record must not have to know what
// rbash is, and the mechanism a proxy reaches for is local to that proxy.
//
// D12 already says the quiet part: reliable interception of an unrestricted
// shell command is still an unrestricted shell. Both of its exec tiers are
// enforced in the proxy, at the exec request, so both stop meaning anything the
// moment a route permits an interactive shell. This type is how a server says
// that the same restricted_exec policy is to be enforced somewhere it survives
// that — and, on the last two rungs, somewhere it survives a connection that
// never went through a proxy at all.
type ExecutionRung string

const (
	// ExecutionProxyInspected is today's behaviour and the ABSENT-VALUE
	// DEFAULT: what the proxy sees at the exec request is what the proxy
	// decides (D12's two tiers, PLAN §6.3). It guarantees nothing about a
	// session that was permitted a shell, and nothing at all about a
	// connection made around the proxy.
	ExecutionProxyInspected ExecutionRung = "proxy-inspected"
	// ExecutionNoInteractiveShell guarantees that the session can obtain no
	// interactive shell or terminal, so every command it runs is one the proxy
	// decided. It turns restricted exec from "a boundary for the commands it
	// sees" into "a boundary, full stop".
	//
	// It is enforced by the proxy, on an axis that has shipped since phase 0006
	// (permitted_requests, D5a axis 2), which is why it is the cheapest strong
	// rung in the table: it needs nothing of the target and nothing installed.
	// The claim and the policy must agree, so a response naming it while
	// permitting shell or pty-req is refused (Validate).
	ExecutionNoInteractiveShell ExecutionRung = "no-interactive-shell"
	// ExecutionAccountRestricted guarantees that the ACCOUNT can execute only
	// the executables the policy names, for every login to it — including one
	// that never went through this proxy. The proxy creates the account, so it
	// chooses what that account can run (PLAN §5.1).
	//
	// What it does NOT guarantee is the strength of the list: an allow-list
	// containing an interpreter is not an allow-list (PLAN §6.5). The rung is a
	// claim about the mechanism, not about the policy author's judgement.
	ExecutionAccountRestricted ExecutionRung = "account-restricted"
	// ExecutionAccountConfined is ExecutionAccountRestricted plus a kernel- or
	// service-manager-enforced confinement of the session's processes: they
	// cannot gain privilege, and they cannot execute anything the session
	// itself wrote. It is the rung that survives an uploaded binary, which is
	// the hole every executable allow-list has on its own.
	ExecutionAccountConfined ExecutionRung = "account-confined"
	// ExecutionPlatformAuthorized guarantees that the DEVICE's own command
	// authorizer decides, for the account the proxy created, under the role the
	// route names (EnforcementPolicy.PlatformRole). It runs ahead of anything
	// the proxy could parse and it is effective against a connection that never
	// went through a proxy (D13, PLAN §5.3).
	//
	// Its failure mode has no Linux analogue and is recorded in PLAN §6.5:
	// vendor RBAC is COARSE AND NAMED, so the guarantee is only as good as the
	// vendor's grouping.
	ExecutionPlatformAuthorized ExecutionRung = "platform-authorized"
	// ExecutionPlatformAttested is the one ATTESTED rung on this axis: the
	// target already enforces its own command authorization on the account, and
	// the proxy configures NOTHING. It is how the appliance estate gets a real
	// enforcement claim instead of "none available", and it is the only kind of
	// rung a brokered-key route can carry.
	//
	// An attestation is worth exactly what its source is worth, so the response
	// must name who asserts it and where that assertion lives
	// (EnforcementPolicy.Attestation), and the audit record says the claim was
	// not verified by this system.
	ExecutionPlatformAttested ExecutionRung = "platform-attested"
)

// Attested reports whether the target already enforces this rung and the proxy
// configures nothing to provide it.
func (r ExecutionRung) Attested() bool { return r == ExecutionPlatformAttested }

// RequiresProvisioning reports whether providing this rung means the proxy
// configures something ON the target — which it can only do on a route whose
// credential method provisions the account (TargetAuthMethod.Provisions).
//
// The two proxy-side rungs need nothing of the target, and an attested rung is
// applied by nobody here, so neither couples to the credential method. That is
// what makes the coupling in D6a conditional rather than absolute since D14.
func (r ExecutionRung) RequiresProvisioning() bool {
	switch r {
	case ExecutionAccountRestricted, ExecutionAccountConfined, ExecutionPlatformAuthorized:
		return true
	default:
		return false
	}
}

// ReachRung says WHERE the limit on what a session may REACH is enforced
// (PLAN §6.5, axis 2).
//
// It is a second axis rather than a corner of the first because the two are
// separate questions with separate mechanisms: an account that can run exactly
// uptime and cat, and can also open a socket to anything in the estate, is a
// pivot point wearing an allow-list. And permitted_forwards does NOT answer
// this one — it governs what may be tunnelled through SSH CHANNELS, while a
// process the session starts on the target opens its own sockets and never
// touches a channel.
type ReachRung string

const (
	// ReachProxyChannelPolicy is today's behaviour and the ABSENT-VALUE
	// DEFAULT: permitted_forwards and permitted_global_requests decide, per
	// channel open and global request. It covers SSH-channel forwarding and
	// nothing else, which is the boundary PLAN §6.5 states in the text rather
	// than only in a table cell.
	ReachProxyChannelPolicy ReachRung = "proxy-channel-policy"
	// ReachAccountEgressRestricted guarantees that the session's own processes
	// reach only the destinations the policy names
	// (EnforcementPolicy.PermittedDestinations) — a connection anywhere else
	// fails on the target, whether or not it went through an SSH channel.
	ReachAccountEgressRestricted ReachRung = "account-egress-restricted"
	// ReachAccountNetworkIsolated guarantees that the session's processes reach
	// nothing off the host at all. It is the strongest reach rung and the
	// simplest to verify, and it is what an automation that only reads local
	// state should stand on.
	ReachAccountNetworkIsolated ReachRung = "account-network-isolated"
	// ReachPlatformAttested is the ATTESTED rung on this axis: the target
	// already constrains what the account can reach — a pre-provisioned ACL, a
	// role, a privilege level — and the proxy configures nothing. Like its
	// sibling on the execution axis it requires an attestation and it is the
	// only kind of reach rung a brokered-key route can carry.
	ReachPlatformAttested ReachRung = "platform-attested"
)

// Attested reports whether the target already enforces this rung and the proxy
// configures nothing to provide it.
func (r ReachRung) Attested() bool { return r == ReachPlatformAttested }

// RequiresProvisioning reports whether providing this rung means the proxy
// configures something ON the target.
func (r ReachRung) RequiresProvisioning() bool {
	switch r {
	case ReachAccountEgressRestricted, ReachAccountNetworkIsolated:
		return true
	default:
		return false
	}
}

// EnforcementPolicy is the server's choice of WHERE this connection's policy is
// enforced, on each of the two axes (contract v4, rendered by phase 0019).
//
// A nil policy means both axes take their absent-value default, which is
// exactly today's behaviour: the proxy decides at the exec request, and
// forwarding policy covers SSH channels only. A v3 server that never heard of
// this object therefore keeps working unchanged.
//
// It hangs at the top level of the response rather than on filter_policy, and
// the reasoning is in PLAN §6.5: the recommendation that it belongs on
// filter_policy is right about the execution axis — that rung really does
// select where the existing restricted_exec policy is enforced — and wrong
// about the reach axis, which has no policy object to attach to and must not be
// attached to permitted_forwards, because the survey's central finding is that
// permitted_forwards does NOT cover what a reach rung covers. Splitting one
// server decision across two places is how a session ends up with an audit
// record claiming a rung that was never applied, which is the failure this whole
// vocabulary exists to prevent.
type EnforcementPolicy struct {
	// Execution is the rung for what the session may execute. Empty means
	// ExecutionProxyInspected.
	Execution ExecutionRung `json:"execution,omitempty"`
	// Reach is the rung for what the session may reach. Empty means
	// ReachProxyChannelPolicy. The two axes are independent: a route may set
	// either, both, or neither.
	Reach ReachRung `json:"reach,omitempty"`
	// PlatformRole is the device role, access profile, or privilege level the
	// ephemeral account is scoped to. Required by ExecutionPlatformAuthorized
	// and forbidden otherwise.
	//
	// It is opaque to the contract and handed to the driver as data, for the
	// reason the platform vocabulary is open at all (D13): the set of role
	// names is as open as the set of platforms. It is deliberately not called
	// an access profile — that is one vendor's word for it.
	PlatformRole string `json:"platform_role,omitempty"`
	// PermittedDestinations are the destinations a ReachAccountEgressRestricted
	// session's own processes may open. Required and non-empty for that rung,
	// forbidden otherwise.
	//
	// It reuses ForwardDestination's SHAPE and shares none of its meaning:
	// permitted_forwards is a rule about SSH channels the proxy sees, this is a
	// rule about sockets the target's kernel sees. Naming a destination the
	// same way in both is the point — an operator writes one vocabulary — but
	// they are never merged, and one never widens the other.
	PermittedDestinations []ForwardDestination `json:"permitted_destinations,omitempty"`
	// Attestation names who asserts an attested rung and where that assertion
	// lives. Required when either axis is attested, forbidden otherwise.
	Attestation *Attestation `json:"attestation,omitempty"`
}

// ExecutionRung returns the execution rung in force, resolving the absent-value
// default so no caller has to decide what an empty policy meant.
func (p *EnforcementPolicy) ExecutionRung() ExecutionRung {
	if p == nil || p.Execution == "" {
		return ExecutionProxyInspected
	}
	return p.Execution
}

// ReachRung returns the reach rung in force, resolving the absent-value default.
func (p *EnforcementPolicy) ReachRung() ReachRung {
	if p == nil || p.Reach == "" {
		return ReachProxyChannelPolicy
	}
	return p.Reach
}

// RequiresProvisioning reports whether either rung is one the proxy must apply
// ON the target. It is what couples the enforcement choice to the credential
// ladder: a route whose every named method leaves the target untouched cannot
// carry an applied rung, and saying so is a contract violation rather than a
// surprise at connect time (Validate).
func (p *EnforcementPolicy) RequiresProvisioning() bool {
	if p == nil {
		return false
	}
	return p.Execution.RequiresProvisioning() || p.Reach.RequiresProvisioning()
}

// Attestation names the source of an ATTESTED enforcement rung.
//
// An attested rung is a claim this system does not verify: the target enforces
// something already, configured by somebody who is not this product, and the
// proxy applies nothing. An unverified claim in an audit record is a liability,
// so the contract's answer is not to pretend otherwise but to make the claim
// ATTRIBUTABLE — the record carries who asserted it and where the assertion
// lives, and says plainly that the proxy verified neither.
type Attestation struct {
	// AssertedBy names who makes the claim: the team, system, or role that
	// configured the target's own enforcement. Required.
	AssertedBy string `json:"asserted_by"`
	// Reference is where the assertion lives — a configuration baseline, a
	// standard, a ticket, a control id. Required, and required to be something
	// an auditor can follow: "trust us" and an empty string are the same
	// answer.
	Reference string `json:"reference"`
	// AssertedAt is when the claim was last affirmed. Optional; absent means
	// the assertion carries no date, which is itself worth recording.
	AssertedAt *time.Time `json:"asserted_at,omitempty"`
}

// GrantContext is WHY this access was granted, as an external system asserted it
// (D16, PLAN §13 UC3).
//
// THE PROXY TREATS ALL OF IT AS OPAQUE. It is copied to every log record for the
// session, never parsed, never matched against, and never the basis of a
// proxy-side decision — the next reader's instinct will be to make policy out of
// it, and D2 says that decision was already made upstream, by the PDP, before
// this response was written. It is also never shown to the user: a denial stays
// vague (PLAN §4.3), and this text is about the estate rather than about the
// user's own request.
//
// The type therefore carries no comparison, matching, or predicate helper, and
// a test asserts that it never grows one. Adding "just a Matches method" is how
// the proxy starts originating policy.
type GrantContext struct {
	// System names the external system that asserted the grant, e.g. the
	// scanner or the change-management product. Opaque.
	System string `json:"system,omitempty"`
	// Reference is that system's own handle for the assertion — a ticket, a
	// scan id, an incident number. Opaque.
	Reference string `json:"reference,omitempty"`
	// WindowStart and WindowEnd are the window the external system asserted.
	// They are RECORDED, not enforced: the bound the proxy enforces is
	// AuthorizeResponse.SessionDeadline, which the PDP sets having already
	// weighed this window. Two fields that look like a deadline and are not one
	// would be a trap, so the difference is stated here and in api/README.md.
	WindowStart *time.Time `json:"window_start,omitempty"`
	WindowEnd   *time.Time `json:"window_end,omitempty"`
	// Additional carries whatever else the integration wanted to record. It
	// accepts a JSON string or a JSON object, because the systems on the other
	// end differ more than a fixed schema can absorb.
	Additional *AdditionalContext `json:"additional_context,omitempty"`
}

// AdditionalContext is a JSON string or a JSON object, and nothing else.
//
// Exactly one of Text and Fields is set after decoding. Both forms exist
// because the systems D15 puts on the other end of a grant differ more than a
// fixed schema can absorb: one has a sentence, another has a bag of fields, and
// forcing either into the other's shape would make the record worse.
//
// Like the context it hangs on, it is opaque: it is carried and logged, never
// read for a decision.
type AdditionalContext struct {
	// Text is set when the server sent a JSON string.
	Text string
	// Fields is set when the server sent a JSON object.
	Fields map[string]any
}

// UnmarshalJSON accepts a string or an object and refuses everything else. A
// number, a list, or a boolean is a contract violation rather than something to
// coerce: the proxy is storing this verbatim for an auditor, and silently
// stringifying a shape the server did not choose would put words in its mouth.
func (c *AdditionalContext) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		c.Text, c.Fields = text, nil
		return nil
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err == nil {
		c.Text, c.Fields = "", fields
		return nil
	}
	return fmt.Errorf("additional_context must be a string or an object")
}

// MarshalJSON re-emits whichever form was received, so a decision that is
// re-encoded (a cached one, or one crossing a hop) reaches the next reader as
// the server wrote it.
func (c AdditionalContext) MarshalJSON() ([]byte, error) {
	if c.Fields != nil {
		return json.Marshal(c.Fields)
	}
	return json.Marshal(c.Text)
}

// ConcurrencyLimits caps how many sessions may be live at once (PLAN §13 UC2).
//
// It is a field here rather than something Control decides alone from ConnMeta
// because the live session count is knowable ONLY to the proxy, which holds the
// SessionRegistry. Exceeding a cap is a POLICY DENIAL and is disclosed as one —
// deliberately vague (PLAN §4.3) — never an outage: the estate is healthy and
// the answer is "no", which is exactly what a denial means.
//
// Both scopes are optional and independent. Absent (or zero) means uncapped,
// which is today's behaviour.
type ConcurrencyLimits struct {
	// PerSubject caps live sessions for one authenticated subject, across every
	// target. Zero means uncapped.
	PerSubject int `json:"max_sessions_per_subject,omitempty"`
	// PerTarget caps live sessions to one target, across every subject. Zero
	// means uncapped. It is the cap that protects the target — PLAN §5.1
	// records that useradd and userdel serialise on the target's account
	// database, so a per-target ceiling exists whether or not policy names one.
	PerTarget int `json:"max_sessions_per_target,omitempty"`
}

// ProxyCapabilities are the enforcement rungs a PROXY BUILD can provide at all,
// declared on AuthorizeRequest beside policy_version (0006's pattern).
//
// It answers only "can this software do it", never "can this target take it" —
// that is TargetCapabilities, which needs a login to find out. A server cannot
// sensibly choose a rung neither party can provide, and this is the half that
// needs no probe.
type ProxyCapabilities struct {
	// Execution are the execution-axis rungs this build implements.
	Execution []ExecutionRung `json:"execution,omitempty"`
	// Reach are the reach-axis rungs this build implements.
	Reach []ReachRung `json:"reach,omitempty"`
}

// ProvidesExecution reports whether this build can provide an execution rung.
//
// A rung that needs nothing of the build is always provided: the two
// proxy-side defaults are what the proxy already does, and an ATTESTED rung is
// applied by nobody — the target enforces it already. Everything else must be
// declared, and a nil ProxyCapabilities declares nothing, which is the fail-safe
// answer for a proxy that predates this field.
func (c *ProxyCapabilities) ProvidesExecution(rung ExecutionRung) bool {
	if rung == "" || rung == ExecutionProxyInspected || rung.Attested() {
		return true
	}
	if c == nil {
		return false
	}
	for _, have := range c.Execution {
		if have == rung {
			return true
		}
	}
	return false
}

// ProvidesReach reports whether this build can provide a reach rung, on the same
// rules as ProvidesExecution.
func (c *ProxyCapabilities) ProvidesReach(rung ReachRung) bool {
	if rung == "" || rung == ReachProxyChannelPolicy || rung.Attested() {
		return true
	}
	if c == nil {
		return false
	}
	for _, have := range c.Reach {
		if have == rung {
			return true
		}
	}
	return false
}

// TargetCapabilities are the enforcement rungs one TARGET can take, as the proxy
// found them by connecting to it (contract v4, probed by phase 0019).
//
// What is available depends on the target far more than on the proxy — whether
// it runs systemd, whether cgroup v2 is mounted, whether SELinux is enforcing,
// whether netfilter is reachable, whether it is a Linux host at all — and the
// proxy is the only party positioned to find out, because it is the only one
// that logs in. Authorize happens BEFORE the proxy has ever touched the target,
// so this cannot ride on AuthorizeRequest for a first-ever connection: it takes
// the shape /v1/hostkeys/report already established (D7), where the proxy learns
// something by connecting and reports it, and the server accumulates it.
//
// It is OBSERVATIONAL AND GRANTS NOTHING. The authority for a rung is the
// authorize response; this record only lets a server avoid choosing one that
// cannot be provided. That is what makes a stale or absent record safe: the
// proxy re-checks the rung against the live target at provisioning time and
// fails the session as an outage if it cannot provide it (PLAN §4.3), so the
// worst a stale record can cause is a refused session — never a session running
// below the rung its own audit record claims.
type TargetCapabilities struct {
	// Execution are the execution-axis rungs this target can take.
	Execution []ExecutionRung `json:"execution,omitempty"`
	// Reach are the reach-axis rungs this target can take.
	Reach []ReachRung `json:"reach,omitempty"`
	// ObservedAt is when the proxy probed. A record with no observation time is
	// treated as stale, because a capability with no date is a capability with
	// no shelf life.
	ObservedAt time.Time `json:"observed_at"`
	// Detail is free-form observation for an operator reading the console —
	// which init the target runs, which module was missing. It is never parsed
	// and never the basis of a decision.
	Detail map[string]string `json:"detail,omitempty"`
}

// DefaultCapabilityTTL is how long a target capability record stays usable
// before it must be re-observed. A target's enforcement surface changes with a
// package upgrade or a kernel boot, neither of which announces itself here, so
// the window is short enough that a stale record is a re-probe rather than a
// belief.
const DefaultCapabilityTTL = 15 * time.Minute

// Fresh reports whether the record was observed recently enough to be used.
// A NIL RECORD AND AN UNDATED ONE ARE BOTH STALE, which is the fail-safe answer:
// "we have not looked" and "we looked too long ago" both mean the same thing to
// anyone choosing a rung from it.
func (c *TargetCapabilities) Fresh(now time.Time, ttl time.Duration) bool {
	if c == nil || c.ObservedAt.IsZero() || ttl <= 0 {
		return false
	}
	return !now.After(c.ObservedAt.Add(ttl))
}

// ProvidesExecution reports whether this target can take an execution rung.
//
// A stale or absent record provides nothing that has to be applied — that is the
// fail-safe half. The rungs that need nothing OF THE TARGET are unaffected by
// staleness for the same reason they are unaffected by the record's absence: the
// two proxy-side defaults are the proxy's own behaviour, and an ATTESTED rung is
// applied by nobody, which is precisely how an appliance nobody can probe still
// carries a real enforcement claim.
func (c *TargetCapabilities) ProvidesExecution(rung ExecutionRung, now time.Time, ttl time.Duration) bool {
	if rung == "" || rung == ExecutionProxyInspected || rung.Attested() {
		return true
	}
	if !c.Fresh(now, ttl) {
		return false
	}
	for _, have := range c.Execution {
		if have == rung {
			return true
		}
	}
	return false
}

// ProvidesReach reports whether this target can take a reach rung, on the same
// rules as ProvidesExecution.
func (c *TargetCapabilities) ProvidesReach(rung ReachRung, now time.Time, ttl time.Duration) bool {
	if rung == "" || rung == ReachProxyChannelPolicy || rung.Attested() {
		return true
	}
	if !c.Fresh(now, ttl) {
		return false
	}
	for _, have := range c.Reach {
		if have == rung {
			return true
		}
	}
	return false
}

// CapabilityReportRequest reports what one target can take (contract v4).
//
// It is deliberately the same shape as HostKeyReportRequest: the proxy learned
// something by connecting, and it tells the server, which accumulates it. The
// server answers with nothing the proxy must obey — a capability report is an
// observation, not a request for a decision.
type CapabilityReportRequest struct {
	// Target is the host the capabilities were observed on.
	Target string `json:"target"`
	// TargetPort is the port, when it is not the default.
	TargetPort int `json:"target_port,omitempty"`
	// Platform names the device driver that observed them, for an
	// ephemeral-account target. Empty for a POSIX host.
	Platform string `json:"platform,omitempty"`
	// Capabilities is what was observed.
	Capabilities TargetCapabilities `json:"capabilities"`
	// Conn is the connection the observation was made on.
	Conn ConnMeta `json:"conn"`
}

// CapabilityReportResponse acknowledges a capability report.
type CapabilityReportResponse struct {
	// Accepted is true when the server recorded the report.
	Accepted bool `json:"accepted"`
	// ReportAfterSeconds is when the server would like the next observation, in
	// seconds. Zero leaves the interval to the proxy (DefaultCapabilityTTL).
	// The server owns the freshness of its own record, on the same reasoning as
	// CacheHint.TTLSeconds: a proxy may re-observe sooner, never later.
	ReportAfterSeconds int `json:"report_after_seconds,omitempty"`
}

// ReportAfter returns ReportAfterSeconds as a duration, resolving the
// absent-value default.
func (r *CapabilityReportResponse) ReportAfter() time.Duration {
	if r == nil || r.ReportAfterSeconds <= 0 {
		return DefaultCapabilityTTL
	}
	return time.Duration(r.ReportAfterSeconds) * time.Second
}

// CapabilityReporter is implemented by clients that can report what a target can
// enforce. It is a SEPARATE, NARROWER INTERFACE rather than a method on Client
// on purpose: the report is made by phase 0019 after a target leg is up, and
// every other caller in the tree — the router, the user authenticator, the log
// shipper — has no business with it and would only have to grow a stub.
type CapabilityReporter interface {
	// ReportCapabilities records what a target can enforce. Its error contract
	// is Client's: only IsUnauthorized is a decision.
	ReportCapabilities(ctx context.Context, req *CapabilityReportRequest) (*CapabilityReportResponse, error)
}
