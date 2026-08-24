// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package filter

import (
	"testing"

	"github.com/hoplock/proxy/internal/control"
)

// mustEngine compiles a policy or fails the test.
func mustEngine(t *testing.T, p control.FilterPolicy) *Engine {
	t.Helper()
	e, err := New(p)
	if err != nil {
		t.Fatalf("New(%+v): %v", p, err)
	}
	return e
}

// TestOnePolicyAppliesEachRuleItsOwnAction is the sentence a single action for
// a whole list cannot say: warn on sudo, block shutdown, kill the session on
// "rm -rf /" — three severities in one policy (PLAN §6.3).
func TestOnePolicyAppliesEachRuleItsOwnAction(t *testing.T) {
	e := mustEngine(t, control.FilterPolicy{
		Mode: control.FilterModeBlacklist,
		Rules: []control.FilterRule{
			{Match: "rm -rf /", Action: control.FilterActionKillSession, Message: "call the on-call."},
			{Match: "shutdown*", Action: control.FilterActionBlockCommand},
			{Match: "sudo *", Action: control.FilterActionWarnAndContinue},
			{Match: "systemctl status *", Action: control.FilterActionAllowAndLog},
		},
	})

	for _, tc := range []struct {
		command string
		want    control.FilterAction
	}{
		{"rm -rf /", control.FilterActionKillSession},
		{"shutdown -h now", control.FilterActionBlockCommand},
		{"sudo systemctl restart nginx", control.FilterActionWarnAndContinue},
		{"systemctl status nginx", control.FilterActionAllowAndLog},
		{"ls -l", control.FilterActionAllowAndLog}, // no rule, blacklist
	} {
		got := e.Exec(tc.command)
		if got.Action != tc.want {
			t.Errorf("Exec(%q).Action = %q, want %q (%s)", tc.command, got.Action, tc.want, got.Detail)
		}
		if got.Tier != TierFiltered {
			t.Errorf("Exec(%q).Tier = %q, want %q", tc.command, got.Tier, TierFiltered)
		}
	}

	// The operator's message rides with the rule that carried it, and only
	// with that rule.
	if got := e.Exec("rm -rf /"); got.Message != "call the on-call." {
		t.Errorf("message = %q, want the rule's own message", got.Message)
	}
	if got := e.Exec("shutdown -h now"); got.Message != "" {
		t.Errorf("message = %q, want none: that rule carries no message", got.Message)
	}
}

// TestTheFirstMatchingRuleWins is the ordering the contract promises: a
// specific rule placed before a broad one decides, so "rm -rf /" can kill the
// session while "rm *" only warns.
func TestTheFirstMatchingRuleWins(t *testing.T) {
	ordered := mustEngine(t, control.FilterPolicy{
		Mode: control.FilterModeBlacklist,
		Rules: []control.FilterRule{
			{Match: "rm -rf /", Action: control.FilterActionKillSession},
			{Match: "rm *", Action: control.FilterActionWarnAndContinue},
		},
	})
	if got := ordered.Exec("rm -rf /"); got.Action != control.FilterActionKillSession || got.RuleIndex != 0 {
		t.Errorf("Exec(rm -rf /) = %q rule %d, want kill_session from rule 0", got.Action, got.RuleIndex)
	}
	if got := ordered.Exec("rm /tmp/scratch"); got.Action != control.FilterActionWarnAndContinue || got.RuleIndex != 1 {
		t.Errorf("Exec(rm /tmp/scratch) = %q rule %d, want warn_and_continue from rule 1", got.Action, got.RuleIndex)
	}

	// Reversed, the broad rule decides both — which is why evaluation order is
	// part of the contract rather than an implementation detail.
	reversed := mustEngine(t, control.FilterPolicy{
		Mode: control.FilterModeBlacklist,
		Rules: []control.FilterRule{
			{Match: "rm *", Action: control.FilterActionWarnAndContinue},
			{Match: "rm -rf /", Action: control.FilterActionKillSession},
		},
	})
	if got := reversed.Exec("rm -rf /"); got.Action != control.FilterActionWarnAndContinue || got.RuleIndex != 0 {
		t.Errorf("Exec(rm -rf /) = %q rule %d, want the broad rule in front to decide", got.Action, got.RuleIndex)
	}
}

// TestAnUnmatchedCommandFallsToTheMode covers the reason Mode is required:
// there is always a defined answer for a command no rule matched.
func TestAnUnmatchedCommandFallsToTheMode(t *testing.T) {
	rules := []control.FilterRule{{Match: "uptime", Action: control.FilterActionAllowAndLog}}

	whitelist := mustEngine(t, control.FilterPolicy{Mode: control.FilterModeWhitelist, Rules: rules})
	if got := whitelist.Exec("cat /etc/shadow"); !got.Blocks() || got.Matched {
		t.Errorf("whitelist unmatched = %+v, want an unmatched block", got)
	}
	if got := whitelist.Exec("uptime"); got.Action != control.FilterActionAllowAndLog || !got.Matched {
		t.Errorf("whitelist matched = %+v, want the rule to permit it", got)
	}

	blacklist := mustEngine(t, control.FilterPolicy{Mode: control.FilterModeBlacklist, Rules: rules})
	if got := blacklist.Exec("cat /etc/shadow"); got.Blocks() || got.Matched {
		t.Errorf("blacklist unmatched = %+v, want it allowed by the mode", got)
	}

	// The two degenerate lists the contract calls out by name.
	emptyWhitelist := mustEngine(t, control.FilterPolicy{Mode: control.FilterModeWhitelist})
	if got := emptyWhitelist.Exec("uptime"); !got.Blocks() {
		t.Errorf("empty whitelist allowed %+v, want everything blocked", got)
	}
	emptyBlacklist := mustEngine(t, control.FilterPolicy{Mode: control.FilterModeBlacklist})
	if got := emptyBlacklist.Exec("rm -rf /"); got.Blocks() {
		t.Errorf("empty blacklist blocked %+v, want nothing filtered", got)
	}
	if emptyBlacklist.Filters() {
		t.Error("an empty blacklist reports that it filters; a session with it must stay on the pass-through path")
	}
	if !emptyWhitelist.Filters() {
		t.Error("an empty whitelist reports that it filters nothing, but it blocks everything")
	}
}

// TestPatternsAreAnchoredAndWildcarded pins the matching semantics the contract
// leaves to this engine.
func TestPatternsAreAnchoredAndWildcarded(t *testing.T) {
	for _, tc := range []struct {
		pattern, command string
		want             bool
	}{
		{"cat /etc/shadow", "cat /etc/shadow", true},
		{"cat /etc/shadow", "sh -c 'cat /etc/shadow'", false},
		{"cat /etc/shadow", "cat /etc/shadow.bak", false},
		{"rm *", "rm -rf /home/data", true}, // "/" is not a separator here
		{"rm *", "rm", false},
		{"rm*", "rm", true},
		{"*shadow*", "sh -c 'cat /etc/shadow'", true},
		{"cat /etc/pass??", "cat /etc/passwd", true},
		{"CAT *", "cat /etc/shadow", false}, // case-sensitive
		{"*", "anything at all", true},
	} {
		if got := matchPattern(tc.pattern, tc.command); got != tc.want {
			t.Errorf("matchPattern(%q, %q) = %t, want %t", tc.pattern, tc.command, got, tc.want)
		}
	}

	// The engine compares the command less the whitespace around it, so a rule
	// is not evaded by a leading space.
	e := mustEngine(t, control.FilterPolicy{
		Mode:  control.FilterModeBlacklist,
		Rules: []control.FilterRule{{Match: "cat /etc/shadow", Action: control.FilterActionBlockCommand}},
	})
	if got := e.Exec("  cat /etc/shadow  "); !got.Blocks() {
		t.Errorf("Exec with surrounding whitespace = %+v, want the rule to still match", got)
	}
}

// TestAPolicyThatDoesNotCompileIsRefused keeps the fail-closed gate: the engine
// refuses what the wire refuses, rather than approximating it.
func TestAPolicyThatDoesNotCompileIsRefused(t *testing.T) {
	for name, p := range map[string]control.FilterPolicy{
		"no mode": {Rules: []control.FilterRule{{Match: "x", Action: control.FilterActionBlockCommand}}},
		"unknown action": {Mode: control.FilterModeBlacklist,
			Rules: []control.FilterRule{{Match: "x", Action: "log_it_somewhere"}}},
		"both tiers": {
			Mode:           control.FilterModeBlacklist,
			ExecMode:       control.ExecModeRestricted,
			Rules:          []control.FilterRule{{Match: "x", Action: control.FilterActionBlockCommand}},
			RestrictedExec: &control.RestrictedExecPolicy{},
		},
		"restricted without a list": {Mode: control.FilterModeBlacklist, ExecMode: control.ExecModeRestricted},
		"restricted list without the mode": {Mode: control.FilterModeBlacklist,
			RestrictedExec: &control.RestrictedExecPolicy{}},
	} {
		if _, err := New(p); err == nil {
			t.Errorf("%s: New accepted a policy the contract refuses", name)
		}
	}
}
