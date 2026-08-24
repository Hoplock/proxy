// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package inspect

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/channel"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/filter"
)

// recorder collects the audit events an inspector produces.
type recorder struct{ events []filter.AuditEvent }

func (r *recorder) Record(ev filter.AuditEvent) { r.events = append(r.events, ev) }

func (r *recorder) last(t *testing.T) filter.AuditEvent {
	t.Helper()
	if len(r.events) == 0 {
		t.Fatal("no audit event was recorded")
	}
	return r.events[len(r.events)-1]
}

func mustEngine(t *testing.T, p control.FilterPolicy) *filter.Engine {
	t.Helper()
	e, err := filter.New(p)
	if err != nil {
		t.Fatalf("filter.New: %v", err)
	}
	return e
}

// execRequest is one client exec request on a session channel.
func execRequest(command string) *channel.RequestEvent {
	return &channel.RequestEvent{
		Channel: channel.Info{
			SessionID: "sess-1",
			ChannelID: "sess-1/1",
			Type:      SessionChannel,
		},
		Direction: channel.FromClient,
		Type:      control.RequestExec,
		Command:   command,
	}
}

func newExec(t *testing.T, p control.FilterPolicy, audit filter.Sink) *Exec {
	t.Helper()
	return NewExec(Options{
		Engine: mustEngine(t, p),
		Audit:  audit,
		Now:    func() time.Time { return time.Unix(1, 0).UTC() },
	})
}

// TestEachActionReachesTheUserAsItsOwnThing covers the four actions at the SSH
// boundary: what is refused, what ends the session, what runs with a warning,
// and what runs silently.
func TestEachActionReachesTheUserAsItsOwnThing(t *testing.T) {
	audit := &recorder{}
	insp := newExec(t, control.FilterPolicy{
		Mode: control.FilterModeBlacklist,
		Rules: []control.FilterRule{
			{Match: "rm -rf /", Action: control.FilterActionKillSession, Message: "Call the on-call engineer."},
			{Match: "shutdown*", Action: control.FilterActionBlockCommand, Message: "Use the maintenance window."},
			{Match: "sudo *", Action: control.FilterActionWarnAndContinue},
			{Match: "systemctl status *", Action: control.FilterActionAllowAndLog},
		},
	}, audit)
	ctx := context.Background()

	killed := insp.InspectRequest(ctx, execRequest("rm -rf /"))
	if !killed.Terminates() {
		t.Errorf("kill_session produced %v, want a terminating decision", killed.Action)
	}
	if !killed.Denied() {
		t.Error("a terminating decision must also read as a denial: the command must not run")
	}
	if !strings.Contains(killed.Reason, "terminated by policy") ||
		!strings.Contains(killed.Reason, "Call the on-call engineer.") {
		t.Errorf("user sees %q, want the termination plus the operator's message", killed.Reason)
	}

	blocked := insp.InspectRequest(ctx, execRequest("shutdown -h now"))
	if blocked.Action != channel.ActionDeny {
		t.Errorf("block_command produced %v, want a denial", blocked.Action)
	}
	if !strings.Contains(blocked.Reason, "blocked by policy") ||
		!strings.Contains(blocked.Reason, "Use the maintenance window.") {
		t.Errorf("user sees %q, want the block plus the operator's message", blocked.Reason)
	}

	warned := insp.InspectRequest(ctx, execRequest("sudo systemctl restart nginx"))
	if warned.Denied() {
		t.Error("warn_and_continue refused the command; it must run")
	}
	if warned.Notice == "" || !strings.Contains(warned.Notice, "flagged by policy") {
		t.Errorf("warn_and_continue notice = %q, want the user warned", warned.Notice)
	}

	allowed := insp.InspectRequest(ctx, execRequest("systemctl status nginx"))
	if allowed.Denied() || allowed.Notice != "" {
		t.Errorf("allow_and_log produced %+v, want a silent allow with an audit event", allowed)
	}

	// Four decisions, four events, all on the priority path.
	if len(audit.events) != 4 {
		t.Fatalf("recorded %d events, want one per decision", len(audit.events))
	}
	for _, ev := range audit.events {
		if ev.Priority != filter.PriorityImmediate || !ev.Enforced {
			t.Errorf("event %+v: want an enforced event on the priority path", ev)
		}
		if ev.Tier != filter.TierFiltered || ev.Guarantee != filter.GuaranteeGuardrail {
			t.Errorf("event %+v: want the deciding tier recorded", ev)
		}
		if ev.SessionID != "sess-1" || ev.ChannelID != "sess-1/1" || ev.Request != control.RequestExec {
			t.Errorf("event %+v: want the SSH context filled in", ev)
		}
		if ev.Inspector != ExecName {
			t.Errorf("event inspector = %q, want %q", ev.Inspector, ExecName)
		}
	}

	// A command the policy had no opinion about is not a security event.
	before := len(audit.events)
	if d := insp.InspectRequest(ctx, execRequest("uptime")); d.Denied() {
		t.Error("an unmatched command under a blacklist was refused")
	}
	if len(audit.events) != before {
		t.Error("an unmatched command under a blacklist produced an audit event")
	}
}

// TestTheUserLearnsThatPolicyStoppedThemAndNothingElse is PLAN §4.3 applied to
// command policy: the terminal gets the fact, the audit record gets the policy.
func TestTheUserLearnsThatPolicyStoppedThemAndNothingElse(t *testing.T) {
	audit := &recorder{}
	insp := newExec(t, control.FilterPolicy{
		Mode: control.FilterModeWhitelist,
		Rules: []control.FilterRule{
			{Match: "uptime", Action: control.FilterActionAllowAndLog},
			{Match: "cat /etc/shadow*", Action: control.FilterActionBlockCommand},
		},
	}, audit)

	for _, command := range []string{"cat /etc/shadow", "curl http://evil.example"} {
		d := insp.InspectRequest(context.Background(), execRequest(command))
		if !d.Denied() {
			t.Fatalf("%q was permitted", command)
		}
		for _, leak := range []string{
			"cat /etc/shadow*", // the pattern that matched
			"uptime",           // another rule's pattern
			"whitelist", "blacklist", "mode",
			"rule", "pattern",
		} {
			if strings.Contains(strings.ToLower(d.Reason), strings.ToLower(leak)) {
				t.Errorf("the user is shown %q, which discloses %q", d.Reason, leak)
			}
		}
		// The operator's copy is allowed to say all of it.
		if d.Detail == "" {
			t.Error("the operator detail is empty; the audit trail needs what the user may not see")
		}
	}

	ev := audit.last(t)
	if ev.Detail == "" || ev.Command != "curl http://evil.example" {
		t.Errorf("audit event %+v, want the command and the reason it was refused", ev)
	}
}

// TestRestrictedExecDeniesLikeABlockAndRecordsLikeABoundary is the presentation
// half of D12: the user cannot tell the tiers apart, and the audit record
// cannot confuse them.
func TestRestrictedExecDeniesLikeABlockAndRecordsLikeABoundary(t *testing.T) {
	audit := &recorder{}
	insp := newExec(t, control.FilterPolicy{
		Mode:     control.FilterModeWhitelist,
		ExecMode: control.ExecModeRestricted,
		RestrictedExec: &control.RestrictedExecPolicy{
			Commands: []control.RestrictedCommand{{
				Executable: "/usr/bin/uptime",
				Form:       control.CommandFormExact,
			}},
		},
	}, audit)
	ctx := context.Background()

	if d := insp.InspectRequest(ctx, execRequest("/usr/bin/uptime")); d.Denied() {
		t.Fatalf("the approved command was denied: %s", d.Detail)
	}
	d := insp.InspectRequest(ctx, execRequest("sh -c '/usr/bin/uptime'"))
	if d.Action != channel.ActionDeny {
		t.Fatalf("the boundary produced %v for an unnamed executable, want a denial", d.Action)
	}
	if !strings.Contains(d.Reason, "blocked by policy") {
		t.Errorf("user sees %q, want the same presentation a blocked command gets", d.Reason)
	}
	if strings.Contains(d.Reason, "/usr/bin/uptime") || strings.Contains(d.Reason, "sh") {
		t.Errorf("user sees %q, which names the permitted executables", d.Reason)
	}

	ev := audit.last(t)
	if ev.Tier != filter.TierRestricted || ev.Guarantee != filter.GuaranteeEnforcement {
		t.Errorf("audit event %+v, want the boundary recorded as enforcement", ev)
	}
	if ev.Outcome != filter.OutcomeBlocked {
		t.Errorf("outcome = %q, want %q", ev.Outcome, filter.OutcomeBlocked)
	}
}

// TestOnlyTheClientsExecRequestsAreFiltered keeps the inspector inside its own
// axis: a target does not run commands on the user, and a pty request is not a
// command.
func TestOnlyTheClientsExecRequestsAreFiltered(t *testing.T) {
	audit := &recorder{}
	insp := newExec(t, control.FilterPolicy{Mode: control.FilterModeWhitelist}, audit)
	ctx := context.Background()

	fromTarget := execRequest("rm -rf /")
	fromTarget.Direction = channel.FromTarget
	if d := insp.InspectRequest(ctx, fromTarget); d.Denied() {
		t.Error("a request travelling the other way was filtered as a user command")
	}

	pty := execRequest("")
	pty.Type = control.RequestPTY
	if d := insp.InspectRequest(ctx, pty); d.Denied() {
		t.Error("a pty request was decided by command policy")
	}
	if len(audit.events) != 0 {
		t.Errorf("recorded %d events for requests that carry no command", len(audit.events))
	}
}
