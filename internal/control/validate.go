// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"errors"
	"fmt"
	"sort"
)

// Validate checks an authorize response against the contract in
// api/control.yaml. It is the proxy's fail-closed gate: a response it cannot
// read exactly is refused, never approximated. The client wraps the error as
// ErrProtocol, so the session fails as an outage rather than a denial
// (PLAN §4.3).
//
// It is exported so the mock server and any future transport validate against
// the same rules the REST client does, rather than each growing its own
// almost-correct copy.
func (r *AuthorizeResponse) Validate() error {
	if r == nil {
		return errors.New("authorize response is empty")
	}
	switch r.RouteType {
	case RouteTypeDirect, RouteTypeNextHop:
	default:
		return fmt.Errorf("unknown route_type %q", r.RouteType)
	}
	if r.Target == "" {
		return errors.New("route has no target")
	}
	if err := r.PermittedRequests.validate(); err != nil {
		return err
	}
	if err := r.PermittedForwards.validate(); err != nil {
		return err
	}
	if err := r.validateTargetAuth(); err != nil {
		return err
	}
	if err := r.AlgorithmProfile.validate(); err != nil {
		return err
	}
	if err := r.FilterPolicy.validate(); err != nil {
		return err
	}
	if err := r.validateEnforcement(); err != nil {
		return err
	}
	if err := r.validateSessionBounds(); err != nil {
		return err
	}
	if err := r.Hop.validate(r.RouteType); err != nil {
		return err
	}
	if c := r.Cache; c != nil {
		// A cache hint the proxy cannot honour exactly is refused rather than
		// guessed at: it may not invent a key, and a negative lifetime has no
		// meaning. Either would put the PEP in charge of the decision's
		// lifetime, which is what the server-set TTL exists to prevent.
		if c.TTLSeconds < 0 {
			return fmt.Errorf("cache.ttl_seconds %d is negative", c.TTLSeconds)
		}
		if c.TTLSeconds > 0 && c.Key == "" {
			return errors.New("cache.ttl_seconds is set but cache.key is empty")
		}
	}
	return nil
}

// knownRequestTypes are the values permitted_requests.types may hold. The
// subsystem request is absent on purpose: it is permitted by name.
var knownRequestTypes = map[string]bool{
	RequestPTY:       true,
	RequestShell:     true,
	RequestExec:      true,
	RequestEnv:       true,
	RequestX11:       true,
	RequestAuthAgent: true,
}

func (p *RequestPolicy) validate() error {
	if p == nil {
		return nil
	}
	for i, t := range p.Types {
		if knownRequestTypes[t] {
			continue
		}
		if t == RequestSubsystem {
			// Accepting it would be worse than refusing it: a server writing
			// "subsystem" means "sftp and scp and everything else", and this
			// policy has no way to say that. Name the fix in the error.
			return fmt.Errorf(
				"permitted_requests.types[%d]: %q is permitted by name in permitted_requests.subsystems, not as a type",
				i, t)
		}
		return fmt.Errorf("permitted_requests.types[%d]: unknown request type %q", i, t)
	}
	for i, name := range p.Subsystems {
		if name == "" {
			return fmt.Errorf("permitted_requests.subsystems[%d] is empty", i)
		}
	}
	return nil
}

func (p *ForwardPolicy) validate() error {
	if p == nil {
		return nil
	}
	if err := validateDestinations("permitted_forwards.direct_tcpip", p.DirectTCPIP); err != nil {
		return err
	}
	return validateDestinations("permitted_forwards.forwarded_tcpip", p.ForwardedTCPIP)
}

func validateDestinations(field string, dests []ForwardDestination) error {
	for i, d := range dests {
		where := fmt.Sprintf("%s[%d]", field, i)
		if d.Host == "" {
			return fmt.Errorf("%s has no host", where)
		}
		if d.Port != 0 && d.PortRange != nil {
			// Both set has no single meaning, and picking one would be the
			// proxy deciding policy.
			return fmt.Errorf("%s sets both port and port_range", where)
		}
		if d.Port != 0 && !validPort(d.Port) {
			return fmt.Errorf("%s.port %d is out of range", where, d.Port)
		}
		if pr := d.PortRange; pr != nil {
			if !validPort(pr.From) || !validPort(pr.To) {
				return fmt.Errorf("%s.port_range %d-%d is out of range", where, pr.From, pr.To)
			}
			if pr.From > pr.To {
				return fmt.Errorf("%s.port_range %d-%d is inverted", where, pr.From, pr.To)
			}
		}
	}
	return nil
}

func validPort(p int) bool { return p >= 1 && p <= 65535 }

// validateTargetAuth checks the route's credential selection in either shape
// the contract allows, and refuses a response that states it twice.
func (r *AuthorizeResponse) validateTargetAuth() error {
	if r.TargetAuth != nil && r.TargetAuthLadder != nil {
		// The one rejection contract v3 exists to make loudly, on phase 0010's
		// precedent (restricted_exec beside a non-empty rule list): two
		// statements of which credential to use, disagreeing, have no
		// defensible resolution. Preferring either one would make the proxy the
		// author of a policy the server wrote twice.
		return errors.New(
			"authorize response sets both target_auth and target_auth_ladder: " +
				"the ladder supersedes the single object, they are not layers (D14)")
	}
	if err := r.TargetAuth.validate("target_auth"); err != nil {
		return err
	}
	if r.TargetAuthLadder == nil {
		return nil
	}
	// An entry the proxy cannot READ is a contract violation and refuses the
	// whole response; an entry the proxy cannot SATISFY is a skipped rung
	// (D14). Keeping the two apart is what stops a server hiding a constraint
	// in a rung the proxy would silently drop.
	for i := range *r.TargetAuthLadder {
		entry := (*r.TargetAuthLadder)[i]
		if err := entry.validate(fmt.Sprintf("target_auth_ladder[%d]", i)); err != nil {
			return err
		}
	}
	return nil
}

func (a *TargetAuth) validate(where string) error {
	if a == nil {
		return nil
	}
	switch a.Method {
	case TargetAuthEphemeralUser, TargetAuthBrokeredKey, TargetAuthStaticKey:
	case TargetAuthEphemeralAccount:
		if err := a.validateEphemeralAccount(where); err != nil {
			return err
		}
	default:
		// An unknown method is refused here rather than at provisioning time so
		// the failure is one clean outage-class denial (PLAN §4.3) instead of a
		// half-set-up session. It is never a fallback to a method the server
		// did not choose, and in a ladder it is not a rung to skip either: the
		// proxy cannot tell an unimplemented method from a mistyped one.
		return fmt.Errorf("%s.method %q is not a method this proxy knows", where, a.Method)
	}
	if a.Method.requiresUsername() && a.Params[ParamUsername] == "" {
		// Contract v3. Before it, this defaulted to the identity's login — a
		// client-typed string internal/identity says must never be the basis of
		// an authorization decision. The account name is what the target's own
		// audit trail is made of, so the server names it or there is no route.
		return fmt.Errorf("%s.params.%s is required for method %q (contract v3)",
			where, ParamUsername, a.Method)
	}
	return nil
}

// validateEphemeralAccount checks the device-provisioning vocabulary (D13).
//
// Only the CONTRACT's own vocabulary is checked here — the values this document
// enumerates, and the parameters it requires. Whether a driver for the named
// platform exists is deliberately not asked: D13 makes customer-written drivers
// a first-class case, so the set of platforms is open and the registry in
// internal/auth/target/device is what refuses an unknown one (outage-class,
// PLAN §4.3). What this can still do is refuse a platform value that is not a
// platform name at all, before it is used to select anything.
func (a *TargetAuth) validateEphemeralAccount(where string) error {
	platform := a.Params[ParamPlatform]
	if platform == "" {
		// Never inferred from a banner: guessing wrong means running
		// configuration commands against the wrong parser (D13).
		return fmt.Errorf("%s.params.%s is required for method %q and is never inferred",
			where, ParamPlatform, TargetAuthEphemeralAccount)
	}
	if !validPlatformName(platform) {
		return fmt.Errorf("%s.params.%s %q is not a platform name "+
			"(lowercase letters, digits and single hyphens, %d characters or fewer)",
			where, ParamPlatform, platform, maxPlatformNameLen)
	}
	switch CredentialKind(a.Params[ParamCredentialKind]) {
	case CredentialKindPassword, CredentialKindPublicKey:
	default:
		// Required rather than defaulted: a password is a reusable secret that
		// lands in the device's running configuration, a public key is not, and
		// a default would hand out the weaker one to a policy that never said
		// so.
		return fmt.Errorf("%s.params.%s %q must be %q or %q",
			where, ParamCredentialKind, a.Params[ParamCredentialKind],
			CredentialKindPassword, CredentialKindPublicKey)
	}
	posture := ExpiryPosture(a.Params[ParamExpiryPosture])
	switch posture {
	case ExpiryPostureTargetEnforced, ExpiryPostureProxyEnforced, ExpiryPostureAcceptedRisk:
	default:
		// "The risk was accepted" is a sentence somebody writes down, never one
		// a proxy infers from an omission (D13).
		return fmt.Errorf("%s.params.%s %q must be %q, %q or %q",
			where, ParamExpiryPosture, a.Params[ParamExpiryPosture],
			ExpiryPostureTargetEnforced, ExpiryPostureProxyEnforced, ExpiryPostureAcceptedRisk)
	}
	if err := a.validateDeviceFields(where); err != nil {
		return err
	}
	if posture != ExpiryPostureAcceptedRisk && a.Params[ParamLifetimeSeconds] == "" {
		// A posture that enforces an expiry with no expiry to enforce is a
		// statement with no content.
		return fmt.Errorf("%s.params.%s is required when %s is %q",
			where, ParamLifetimeSeconds, ParamExpiryPosture, posture)
	}
	return nil
}

// validateDeviceFields checks the SHAPE of the device_field namespace, and only
// the shape (contract v3.1, phase 0016).
//
// What a field MEANS is the driver's business, and which fields exist is the
// driver's to declare — the set is as open as the set of platforms, and for the
// same reason (D13). So this refuses what cannot be a field at all: an empty
// name, a name that is not an identifier, an empty value, and a bag so large it
// is no longer policy metadata. A field the named driver does not accept is a
// SKIPPED RUNG at provisioning time (D14), not a contract violation, because
// the server may legitimately name a field for a proxy build that carries a
// driver this one does not.
func (a *TargetAuth) validateDeviceFields(where string) error {
	fields := a.DeviceFields()
	if len(fields) > maxDeviceFields {
		return fmt.Errorf("%s.params carries %d %s* fields, more than the %d a route may name",
			where, len(fields), ParamDeviceFieldPrefix, maxDeviceFields)
	}
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	// Sorted so that a response with two bad fields is refused with the same
	// message every time; map order would make the failure irreproducible.
	sort.Strings(names)
	for _, name := range names {
		if !validDeviceFieldName(name) {
			return fmt.Errorf("%s.params.%s%s is not a device field name "+
				"(lowercase letters, digits, hyphens and underscores, %d characters or fewer)",
				where, ParamDeviceFieldPrefix, name, maxDeviceFieldNameLen)
		}
		value := fields[name]
		if value == "" {
			// An empty field is not an absent one. Absent means "the driver's
			// own default" — a global administrator, where the field is a
			// VDOM — and a route that names a field means to constrain
			// something, so an empty value is a policy author's mistake rather
			// than a way of saying nothing.
			return fmt.Errorf("%s.params.%s%s is empty; omit the field to leave the driver's default",
				where, ParamDeviceFieldPrefix, name)
		}
		if len(value) > maxDeviceFieldValueLen {
			// The value is echoed nowhere: it is policy metadata rather than
			// credential material, but it is also unbounded text from another
			// system, and its length is the only thing wrong with it here.
			return fmt.Errorf("%s.params.%s%s is longer than the %d characters a device field may carry",
				where, ParamDeviceFieldPrefix, name, maxDeviceFieldValueLen)
		}
	}
	return nil
}

// The bounds on the device_field namespace. They exist to keep an OPEN
// namespace from becoming an unbounded payload; they are not an opinion about
// what a platform's fields are called.
const (
	maxDeviceFields        = 16
	maxDeviceFieldNameLen  = 64
	maxDeviceFieldValueLen = 256
)

// validDeviceFieldName reports whether s is shaped like a field name:
// lowercase letters and digits, with hyphens and underscores between them and
// at neither end. It is the platform-name rule plus the underscore, because
// device vocabularies are full of them (`short_name`, `ip6-trusthost1`) and
// this names a field rather than a driver.
func validDeviceFieldName(s string) bool {
	if s == "" || len(s) > maxDeviceFieldNameLen {
		return false
	}
	prevSeparator := true // a leading separator is as invalid as a doubled one
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			prevSeparator = false
		case r == '-', r == '_':
			if prevSeparator {
				return false
			}
			prevSeparator = true
		default:
			return false
		}
	}
	return !prevSeparator
}

// maxPlatformNameLen bounds a platform name. It is generous on purpose: the
// check exists to reject something that is not a name, not to curate the set of
// platforms, which belongs to whoever writes the drivers.
const maxPlatformNameLen = 64

// validPlatformName reports whether s is shaped like a platform identifier:
// lowercase letters and digits, single hyphens between them, no leading or
// trailing hyphen.
func validPlatformName(s string) bool {
	if s == "" || len(s) > maxPlatformNameLen {
		return false
	}
	prevHyphen := true // a leading hyphen is as invalid as a doubled one
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			prevHyphen = false
		case r == '-':
			if prevHyphen {
				return false
			}
			prevHyphen = true
		default:
			return false
		}
	}
	return !prevHyphen
}

// validateEnforcement checks the enforcement vocabulary (contract v4, PLAN
// §6.5): that each rung is one this proxy knows, that the parameters a rung
// needs are present and the ones it does not are absent, that the rung's claim
// agrees with the rest of the response, and that an APPLIED rung was not asked
// for on a route where no named credential method could ever apply it.
//
// Every one of those is refused rather than approximated, for the reason this
// whole vocabulary exists: a session running at a weaker rung than its audit
// record claims is worse than a session that does not run.
func (r *AuthorizeResponse) validateEnforcement() error {
	p := r.Enforcement
	if p == nil {
		return nil
	}
	switch p.Execution {
	case "", ExecutionProxyInspected, ExecutionNoInteractiveShell,
		ExecutionAccountRestricted, ExecutionAccountConfined,
		ExecutionPlatformAuthorized, ExecutionPlatformAttested:
	default:
		// Never coerced to the default: coercing DOWN would run the session at a
		// weaker rung than the policy names, and there is nothing to coerce up
		// to.
		return fmt.Errorf("enforcement.execution %q is not a rung this proxy knows", p.Execution)
	}
	switch p.Reach {
	case "", ReachProxyChannelPolicy, ReachAccountEgressRestricted,
		ReachAccountNetworkIsolated, ReachPlatformAttested:
	default:
		return fmt.Errorf("enforcement.reach %q is not a rung this proxy knows", p.Reach)
	}

	// An attested rung is a claim this system does not verify, so the response
	// must at least say who makes it and where it is written down. An
	// attestation on a rung the proxy APPLIES is refused for the mirror-image
	// reason: it would put an unverified sentence next to a rung this proxy
	// rendered itself, and a reader could not tell which half the record meant.
	attested := p.Execution.Attested() || p.Reach.Attested()
	switch {
	case attested && p.Attestation == nil:
		return fmt.Errorf("enforcement names an attested rung but carries no attestation "+
			"(who asserts it, and where that assertion lives): execution %q, reach %q",
			p.ExecutionRung(), p.ReachRung())
	case !attested && p.Attestation != nil:
		return errors.New("enforcement carries an attestation but names no attested rung")
	case attested:
		if p.Attestation.AssertedBy == "" {
			return errors.New("enforcement.attestation.asserted_by is required for an attested rung")
		}
		if p.Attestation.Reference == "" {
			// "Trust us" and an empty string are the same answer, and neither is
			// something an auditor can follow.
			return errors.New("enforcement.attestation.reference is required for an attested rung")
		}
	}

	// platform_role is the device's own word for what the account may do, and it
	// is the whole content of the platform-authorized rung.
	if got := p.PlatformRole != ""; got != (p.Execution == ExecutionPlatformAuthorized) {
		if got {
			return fmt.Errorf("enforcement.platform_role is set but execution is %q, not %q",
				p.ExecutionRung(), ExecutionPlatformAuthorized)
		}
		return fmt.Errorf("enforcement.platform_role is required for execution %q",
			ExecutionPlatformAuthorized)
	}

	// The destination list is the whole content of the egress rung; on every
	// other rung it would be a constraint nothing reads, which is the shape a
	// dropped restriction takes.
	if p.Reach == ReachAccountEgressRestricted {
		if len(p.PermittedDestinations) == 0 {
			return fmt.Errorf("enforcement.permitted_destinations is required and must not be empty for reach %q",
				ReachAccountEgressRestricted)
		}
	} else if len(p.PermittedDestinations) > 0 {
		return fmt.Errorf("enforcement.permitted_destinations is set but reach is %q, not %q",
			p.ReachRung(), ReachAccountEgressRestricted)
	}
	if err := validateDestinations("enforcement.permitted_destinations", p.PermittedDestinations); err != nil {
		return err
	}

	if err := r.validateRungAgreesWithPolicy(); err != nil {
		return err
	}
	return r.validateRungIsReachable()
}

// validateRungAgreesWithPolicy refuses a response whose enforcement claim
// contradicts the policy in the same response.
//
// Both checks below are the same rule seen twice: a rung names WHERE something
// is enforced, so there has to be something to enforce, and the response must
// not simultaneously permit what the rung says is impossible. A response that
// disagreed with itself would be resolved by the proxy, and the proxy resolving
// a policy conflict is the thing D2 exists to prevent.
func (r *AuthorizeResponse) validateRungAgreesWithPolicy() error {
	switch r.Enforcement.ExecutionRung() {
	case ExecutionNoInteractiveShell:
		// The rung's guarantee IS the request axis (D5a axis 2), so the claim is
		// only true if the policy that carries it says so. Absent
		// permitted_requests means "not policed", which permits every request —
		// including the two this rung says cannot happen.
		p := r.PermittedRequests
		if p == nil {
			return fmt.Errorf("enforcement.execution %q needs permitted_requests to deny %q and %q, "+
				"but permitted_requests is absent, which polices nothing",
				ExecutionNoInteractiveShell, RequestShell, RequestPTY)
		}
		for _, name := range []string{RequestShell, RequestPTY} {
			if contains(p.Types, name) {
				return fmt.Errorf("enforcement.execution %q but permitted_requests.types permits %q",
					ExecutionNoInteractiveShell, name)
			}
		}
	case ExecutionAccountRestricted, ExecutionAccountConfined:
		// These rungs render the permitted executables onto the account, and the
		// only place the contract names an executable is restricted_exec. A
		// pattern rule list (the filtered tier) has patterns, not executables:
		// there is nothing to render, and a rung rendered from nothing would
		// claim a boundary that is an empty set or a wildcard depending on who
		// guessed.
		if r.FilterPolicy.Exec() != ExecModeRestricted {
			return fmt.Errorf("enforcement.execution %q needs filter_policy.exec_mode %q "+
				"(it is where the executables it renders are named), but the mode is %q",
				r.Enforcement.ExecutionRung(), ExecModeRestricted, r.FilterPolicy.Exec())
		}
	}
	return nil
}

// validateRungIsReachable refuses an APPLIED rung on a route where no credential
// method the server named could ever apply it.
//
// This is the conditional form of D6a's coupling, as D14 left it. brokered-key
// changes nothing on the target by definition, so no rung the proxy applies is
// available on it — but a route now names an ORDERED LADDER, so the coupling is
// per entry: a ladder of [ephemeral-user, brokered-key] reaches an applied rung
// on its first entry and not on its second, and the entry that cannot carry the
// route's rung is a SKIPPED RUNG (D14) at provisioning time, never a session
// that quietly runs without it.
//
// What is refused here is the case where that skipping could only ever exhaust
// the ladder: every named method leaves the target untouched. Such a policy can
// only fail at connect time, in front of a user, and a policy that can only fail
// at connect time is one Control should never have been able to author.
//
// An ABSENT ladder is not refused: it means the proxy uses its locally
// configured method, which this response cannot see. That is resolved at
// provisioning time, on the same outage-class rule.
func (r *AuthorizeResponse) validateRungIsReachable() error {
	if !r.Enforcement.RequiresProvisioning() {
		return nil
	}
	rungs, named := r.Ladder()
	if !named || len(rungs) == 0 {
		return nil
	}
	for _, entry := range rungs {
		if entry.Method.Provisions() {
			return nil
		}
	}
	return fmt.Errorf("enforcement names an applied rung (execution %q, reach %q) but no credential "+
		"method on this route provisions the target, so nothing could ever apply it "+
		"(an attested rung is what a %q route may carry)",
		r.Enforcement.ExecutionRung(), r.Enforcement.ReachRung(), TargetAuthBrokeredKey)
}

// validateSessionBounds checks the fields that bound how long and on what
// grounds a session exists (contract v4, D16).
//
// The grant context is checked for SHAPE and nothing else, deliberately. The
// proxy never reads its content for a decision, so there is nothing here that
// could become policy by accident — what is refused is a record that cannot be
// true of any window.
func (r *AuthorizeResponse) validateSessionBounds() error {
	if d := r.SessionDeadline; d != nil && d.IsZero() {
		// The zero instant is what an absent or unparsed timestamp decodes to,
		// and enforcing it literally would close every session the moment it
		// opened. Absent means "no deadline"; there is no third reading.
		return errors.New("session_deadline is present but zero; omit it to leave the session unbounded")
	}
	if c := r.Concurrency; c != nil {
		if c.PerSubject < 0 {
			return fmt.Errorf("concurrency.max_sessions_per_subject %d is negative", c.PerSubject)
		}
		if c.PerTarget < 0 {
			return fmt.Errorf("concurrency.max_sessions_per_target %d is negative", c.PerTarget)
		}
	}
	if g := r.GrantContext; g != nil {
		if g.WindowStart != nil && g.WindowEnd != nil && g.WindowEnd.Before(*g.WindowStart) {
			return errors.New("grant_context.window_end is before grant_context.window_start")
		}
	}
	return nil
}

func (p AlgorithmProfile) validate() error {
	switch p {
	case "", AlgorithmProfileDefault, AlgorithmProfileLegacyRSASHA1, AlgorithmProfileLegacyDevice:
		return nil
	default:
		// Coercing an unknown profile to the default would deny every route on
		// the estate this vocabulary exists for; coercing it to the widest
		// would weaken a leg nobody asked to weaken. Neither is the proxy's to
		// choose.
		return fmt.Errorf("algorithm_profile %q is not a profile this proxy knows", p)
	}
}

func (p FilterPolicy) validate() error {
	switch p.Mode {
	case FilterModeWhitelist, FilterModeBlacklist:
	default:
		return fmt.Errorf("unknown filter mode %q", p.Mode)
	}
	for i, rule := range p.Rules {
		if rule.Match == "" {
			return fmt.Errorf("filter rule %d has no match pattern", i)
		}
		switch rule.Action {
		case FilterActionAllowAndLog, FilterActionBlockCommand,
			FilterActionWarnAndContinue, FilterActionKillSession:
		default:
			return fmt.Errorf("filter rule %d (%q): unknown action %q", i, rule.Match, rule.Action)
		}
	}

	switch p.Exec() {
	case ExecModeFiltered:
		if p.RestrictedExec != nil {
			return errors.New(
				"filter_policy sets restricted_exec but exec_mode is filtered: " +
					"the two tiers are alternatives, not layers (D12)")
		}
	case ExecModeRestricted:
		if p.RestrictedExec == nil {
			return errors.New("filter_policy.exec_mode is restricted but restricted_exec is absent")
		}
		if len(p.Rules) > 0 {
			// The one rejection this phase exists to make loudly: a guardrail
			// and a boundary disagreeing about the same command have no
			// defensible resolution, so the response is refused rather than
			// resolved.
			return errors.New(
				"filter_policy sets both restricted_exec and a rule list: " +
					"the two tiers are alternatives, not layers (D12)")
		}
		if err := p.RestrictedExec.validate(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown filter_policy.exec_mode %q", p.ExecMode)
	}
	return nil
}

func (p *RestrictedExecPolicy) validate() error {
	for i, c := range p.Commands {
		where := fmt.Sprintf("restricted_exec.commands[%d]", i)
		if c.Executable == "" {
			return fmt.Errorf("%s has no executable", where)
		}
		switch c.Form {
		case CommandFormExact:
			if len(c.Args) > 0 {
				return fmt.Errorf("%s (%s) is form exact but sets args", where, c.Executable)
			}
		case CommandFormPositional:
			if len(c.Argv) > 0 {
				return fmt.Errorf("%s (%s) is form positional but sets argv", where, c.Executable)
			}
			if err := validateArgs(where+".args", c.Args); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s (%s): unknown form %q", where, c.Executable, c.Form)
		}
	}
	return nil
}

func validateArgs(field string, args []ArgumentSpec) error {
	optionalSeen := false
	for i, a := range args {
		where := fmt.Sprintf("%s[%d]", field, i)
		switch a.Kind {
		case ArgumentLiteral, ArgumentPrefix:
			if a.Value == "" {
				// An empty prefix is "any" wearing a disguise, and the whole
				// point of naming ArgumentAny is that it stays visible.
				return fmt.Errorf("%s: kind %q needs a non-empty value", where, a.Kind)
			}
			if len(a.Values) > 0 {
				return fmt.Errorf("%s: kind %q must not set values", where, a.Kind)
			}
		case ArgumentOneOf:
			if len(a.Values) == 0 {
				return fmt.Errorf("%s: kind %q needs at least one value", where, a.Kind)
			}
			if a.Value != "" {
				return fmt.Errorf("%s: kind %q must not set value", where, a.Kind)
			}
		case ArgumentAny:
			if a.Value != "" || len(a.Values) > 0 {
				return fmt.Errorf("%s: kind %q takes no value", where, a.Kind)
			}
		default:
			return fmt.Errorf("%s: unknown kind %q", where, a.Kind)
		}
		if a.Optional {
			optionalSeen = true
			continue
		}
		if optionalSeen {
			// A required position after an optional one has no well-defined
			// place in the vector: the argument at that index could belong to
			// either spec.
			return fmt.Errorf("%s is required but follows an optional argument", where)
		}
	}
	return nil
}

func (h *HopMetadata) validate(routeType RouteType) error {
	if h == nil {
		return nil
	}
	switch h.Direction() {
	case HopConnectionDial:
	case HopConnectionRelay:
		if h.NextProxyID == "" {
			// Without it the upstream cannot select a registration, and the one
			// thing it must never do instead is dial.
			return errors.New("hop.connection is relay but hop.next_proxy_id is empty")
		}
	default:
		return fmt.Errorf("unknown hop.connection %q", h.Connection)
	}
	if h.MaxHops < 0 {
		return fmt.Errorf("hop.max_hops %d is negative", h.MaxHops)
	}
	if routeType != RouteTypeNextHop && h.Connection != "" {
		return fmt.Errorf("hop.connection is set on a %q route", routeType)
	}
	return nil
}
