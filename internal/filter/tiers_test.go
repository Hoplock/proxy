// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package filter

import (
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// TestTheShellWrapperGetsPastTheGuardrailAndNotPastTheBoundary is D12 in
// executable form, and it is written to fail loudly in both directions.
//
// One command, one policy sentence — "you may not read /etc/shadow" — and two
// tiers. The guardrail sees the command and a shell wrapper defeats it; the
// boundary parses the command and refuses it because nobody named "sh". If the
// first half ever starts passing, the guardrail has begun making a promise it
// cannot keep and the documentation is now a lie. If the second half ever
// starts failing, the boundary is broken. Neither half may be softened: the
// honest limit of a pattern is the whole reason the restricted tier exists.
func TestTheShellWrapperGetsPastTheGuardrailAndNotPastTheBoundary(t *testing.T) {
	const (
		blocked = "cat /etc/shadow"
		wrapper = `sh -c 'cat /etc/shadow'`
	)

	guardrail := mustEngine(t, control.FilterPolicy{
		Mode:  control.FilterModeBlacklist,
		Rules: []control.FilterRule{{Match: blocked, Action: control.FilterActionBlockCommand}},
	})
	if got := guardrail.Exec(blocked); !got.Blocks() {
		t.Fatalf("the guardrail let %q through: it must at least see the command it was given", blocked)
	}
	if got := guardrail.Exec(wrapper); got.Blocks() {
		t.Fatalf("the guardrail blocked %q. That is not a fix — a pattern cannot stop a shell, "+
			"and a test asserting otherwise would document a boundary this tier does not have (D12)", wrapper)
	}
	if guardrail.Tier().Guarantee() != GuaranteeGuardrail {
		t.Errorf("the filtered tier claims %q, want %q", guardrail.Tier().Guarantee(), GuaranteeGuardrail)
	}

	// The same sentence as a boundary: only "cat" is named, so the shell that
	// would have re-expanded the command is not a command that runs.
	boundary := mustEngine(t, restrictedPolicy(control.RestrictedCommand{
		Executable: "cat",
		Form:       control.CommandFormPositional,
		Args:       []control.ArgumentSpec{{Kind: control.ArgumentPrefix, Value: "/var/log/"}},
	}))
	if got := boundary.Exec(wrapper); !got.Blocks() {
		t.Fatalf("the boundary let %q through: an executable nobody named must be denied", wrapper)
	}
	if got := boundary.Exec("cat /etc/shadow"); !got.Blocks() {
		t.Errorf("the boundary let an argument outside its shape through")
	}
	if got := boundary.Exec("cat /var/log/app.log"); got.Blocks() {
		t.Errorf("the boundary denied the shape it was told to permit: %s", got.Detail)
	}
	if boundary.Tier().Guarantee() != GuaranteeEnforcement {
		t.Errorf("the restricted tier claims %q, want %q", boundary.Tier().Guarantee(), GuaranteeEnforcement)
	}
}

// TestTheInteractiveTierReportsAndNeverEnforces holds the third row of §6.3's
// table: the same policy, read off a keystroke stream, is an audit signal.
func TestTheInteractiveTierReportsAndNeverEnforces(t *testing.T) {
	e := mustEngine(t, control.FilterPolicy{
		Mode: control.FilterModeBlacklist,
		Rules: []control.FilterRule{
			{Match: "rm -rf /", Action: control.FilterActionKillSession},
			{Match: "ls*", Action: control.FilterActionAllowAndLog},
		},
	})

	d, report := e.Interactive("rm -rf /")
	if !report {
		t.Fatal("a matched command produced nothing to report")
	}
	if d.Tier != TierInteractive {
		t.Errorf("tier = %q, want %q whatever the exec mode is", d.Tier, TierInteractive)
	}
	if d.Guarantee() != GuaranteeAuditSignal {
		t.Errorf("guarantee = %q, want %q", d.Guarantee(), GuaranteeAuditSignal)
	}

	// The event says the action was NOT applied. That field is the whole
	// difference between a report and a claim.
	ev := d.Event(time.Unix(0, 0), false)
	if ev.Enforced {
		t.Error("an interactive event claims it was enforced")
	}
	if ev.Outcome != OutcomeObserved {
		t.Errorf("outcome = %q, want %q", ev.Outcome, OutcomeObserved)
	}
	if ev.Action != control.FilterActionKillSession {
		t.Errorf("action = %q, want the action the policy named to survive into the record", ev.Action)
	}

	// A blacklist that matched nothing has nothing to say: an event per typed
	// line belongs to session capture, not to command policy.
	if _, report := e.Interactive("cat /etc/hosts"); report {
		t.Error("an unmatched line under a blacklist produced an event")
	}
	if _, report := e.Interactive("   "); report {
		t.Error("a blank line produced an event")
	}
	// A whitelist's default is a denial, so the same line is worth reporting.
	strict := mustEngine(t, control.FilterPolicy{Mode: control.FilterModeWhitelist})
	if _, report := strict.Interactive("cat /etc/hosts"); !report {
		t.Error("a line the policy would have blocked produced no event")
	}
}
