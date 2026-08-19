// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"errors"
	"fmt"
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
	if err := r.TargetAuth.validate(); err != nil {
		return err
	}
	if err := r.FilterPolicy.validate(); err != nil {
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

func (a *TargetAuth) validate() error {
	if a == nil {
		return nil
	}
	switch a.Method {
	case TargetAuthEphemeralUser, TargetAuthBrokeredKey, TargetAuthStaticKey:
	default:
		// An unknown method is refused here rather than at provisioning time so
		// the failure is one clean outage-class denial (PLAN §4.3) instead of a
		// half-set-up session. It is never a fallback to a method the server
		// did not choose.
		return fmt.Errorf("target_auth.method %q is not a method this proxy knows", a.Method)
	}
	return nil
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
