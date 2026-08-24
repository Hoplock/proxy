// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package filter

import (
	"fmt"
	"strings"

	"github.com/hoplock/proxy/internal/control"
)

// Tier names which of PLAN §6.3's three tiers decided a command. It is carried
// in every audit event because a later review has to be able to tell a boundary
// from a guardrail without re-reading the policy.
type Tier string

const (
	// TierRestricted is the enforced tier: parsed argv against a default-deny
	// list of approved shapes (D12).
	TierRestricted Tier = "restricted_exec"
	// TierFiltered is the guardrail: the ordered rule list against the whole
	// exec string.
	TierFiltered Tier = "filtered_exec"
	// TierInteractive is the best-effort inspection of an interactive stream.
	TierInteractive Tier = "interactive"
)

// Guarantee is what a tier is allowed to claim. The words are D12's, and they
// are the same words used in the documentation and in the audit record, on
// purpose: a product that lets "seen reliably" and "cannot be evaded" blur has
// already sold the wrong thing.
type Guarantee string

const (
	// GuaranteeEnforcement is a boundary: default-deny, defensible under
	// adversarial review.
	GuaranteeEnforcement Guarantee = "enforcement"
	// GuaranteeGuardrail is a rule list: every command is seen, and a pattern
	// is still a pattern.
	GuaranteeGuardrail Guarantee = "guardrail"
	// GuaranteeAuditSignal is best-effort observation: it reports, it never
	// enforces.
	GuaranteeAuditSignal Guarantee = "audit_signal"
)

// Guarantee is what this tier may claim.
func (t Tier) Guarantee() Guarantee {
	switch t {
	case TierRestricted:
		return GuaranteeEnforcement
	case TierFiltered:
		return GuaranteeGuardrail
	default:
		return GuaranteeAuditSignal
	}
}

// Decision is the policy's answer about one command.
//
// It carries two texts and they are not interchangeable. Message is the
// operator's own words and is the only part a user may see; Detail names what
// decided — the pattern, the rule's position, the parse error — and belongs to
// the audit record alone. PLAN §4.3: the user learns THAT policy stopped them,
// never the policy's contents.
type Decision struct {
	// Tier is which tier decided.
	Tier Tier
	// Action is the policy action to apply.
	Action control.FilterAction
	// Message is the operator-authored text attached to the rule that matched,
	// empty when there was none. It is shown to the user verbatim.
	Message string
	// Matched says a rule or a permitted-command entry decided, as opposed to
	// the mode's default for a command nothing matched.
	Matched bool
	// RuleIndex is the position of the rule that decided, -1 when none did.
	// Operator-only: the position of a rule is the policy's contents.
	RuleIndex int
	// Detail explains the decision for the operator. Operator-only.
	Detail string
	// Command is the command the decision was made about.
	Command string
}

// Blocks reports whether the command must not run.
func (d Decision) Blocks() bool {
	return d.Action == control.FilterActionBlockCommand || d.Action == control.FilterActionKillSession
}

// Kills reports whether the whole session ends.
func (d Decision) Kills() bool { return d.Action == control.FilterActionKillSession }

// Warns reports whether the user is warned and the command runs anyway.
func (d Decision) Warns() bool { return d.Action == control.FilterActionWarnAndContinue }

// Reportable says whether this decision is worth an audit event.
//
// Everything a policy actually did is: a rule matched (allow_and_log says so in
// its name), or the command was blocked, warned about, or killed the session. A
// command that matched nothing under a blacklist is the one case that is not —
// the policy had no opinion, and an event per command belongs to session
// capture (0011), not to command policy.
func (d Decision) Reportable() bool {
	return d.Matched || d.Action != control.FilterActionAllowAndLog
}

// Guarantee is what the deciding tier may claim.
func (d Decision) Guarantee() Guarantee { return d.Tier.Guarantee() }

// Engine is one connection's compiled command policy.
//
// It is immutable once built and safe for concurrent use: a connection's
// policy is fetched once and enforced for that connection's lifetime (D2), and
// every channel on it asks the same engine.
type Engine struct {
	mode       control.FilterMode
	tier       Tier
	rules      []control.FilterRule
	restricted *control.RestrictedExecPolicy
}

// New compiles a policy into an engine, or refuses it.
//
// It validates through the contract's own rules rather than a second almost-
// correct copy of them, so the tier-alternatives violation (both restricted_exec
// and a rule list) is refused here exactly as the client refuses it on the
// wire. A policy that does not compile fails the session closed: there is no
// reading of "the policy could not be understood" that permits a command.
func New(p control.FilterPolicy) (*Engine, error) {
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("filter: %w", err)
	}
	e := &Engine{mode: p.Mode, restricted: p.RestrictedExec}
	if len(p.Rules) > 0 {
		e.rules = append([]control.FilterRule(nil), p.Rules...)
	}
	if p.Exec() == control.ExecModeRestricted {
		e.tier = TierRestricted
	} else {
		e.tier = TierFiltered
	}
	return e, nil
}

// Tier is the exec tier this policy selects.
func (e *Engine) Tier() Tier { return e.tier }

// Mode is the fallback for a command no rule matched.
func (e *Engine) Mode() control.FilterMode { return e.mode }

// Filters reports whether this policy can ever say no.
//
// A blacklist with no rules filters nothing, which is a policy a server is
// entitled to send; the caller uses this to leave such a session on the
// pass-through path instead of inspecting every command to always answer yes.
func (e *Engine) Filters() bool {
	return e.tier == TierRestricted || e.mode == control.FilterModeWhitelist || len(e.rules) > 0
}

// Exec decides one exec request's command. It is the reliable interception
// point: the whole command is available before anything runs (PLAN §6.3).
func (e *Engine) Exec(command string) Decision {
	if e.tier == TierRestricted {
		return e.decideRestricted(command)
	}
	return e.decideFiltered(TierFiltered, command)
}

// Interactive decides one line read out of an interactive stream, best-effort.
//
// The tier is always TierInteractive, whatever the exec mode is, because what
// decided is not what makes this reliable: the line was reconstructed from a
// keystroke stream, and line editing, encodings, and shell escapes defeat that
// by construction. The caller reports the answer and never enforces it — with
// the single exception D12's audit-signal tier still allows, ending a session,
// which cannot corrupt a stream it is ending.
//
// The second result says whether there is anything to report; a shell session
// under a blacklist that matched nothing produces no event per line.
func (e *Engine) Interactive(line string) (Decision, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Decision{Tier: TierInteractive, RuleIndex: -1}, false
	}
	var d Decision
	if e.tier == TierRestricted {
		d = e.decideRestricted(line)
	} else {
		d = e.decideFiltered(TierFiltered, line)
	}
	d.Tier = TierInteractive
	return d, d.Reportable()
}

// decideFiltered applies the ordered rule list: FIRST MATCH WINS, and the mode
// answers for a command nothing matched.
func (e *Engine) decideFiltered(tier Tier, command string) Decision {
	subject := strings.TrimSpace(command)
	for i, rule := range e.rules {
		if !matchPattern(rule.Match, subject) {
			continue
		}
		return Decision{
			Tier:      tier,
			Action:    rule.Action,
			Message:   rule.Message,
			Matched:   true,
			RuleIndex: i,
			Detail:    fmt.Sprintf("rule %d %q matched", i, rule.Match),
			Command:   command,
		}
	}
	return e.modeDefault(tier, command)
}

// modeDefault is the answer for a command no rule matched. Mode is required by
// the contract precisely so that this answer always exists.
func (e *Engine) modeDefault(tier Tier, command string) Decision {
	d := Decision{Tier: tier, Matched: false, RuleIndex: -1, Command: command}
	if e.mode == control.FilterModeWhitelist {
		d.Action = control.FilterActionBlockCommand
		d.Detail = "no rule matched and the policy is a whitelist"
		return d
	}
	d.Action = control.FilterActionAllowAndLog
	d.Detail = "no rule matched and the policy is a blacklist"
	return d
}
