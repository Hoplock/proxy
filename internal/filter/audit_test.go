// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package filter

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// TestTheAuditEventCarriesTheTierAndThePriority pins the shape phase 0011
// consumes. The field names are what a security team's queries are written
// against; changing them is a contract change, not a refactor.
func TestTheAuditEventCarriesTheTierAndThePriority(t *testing.T) {
	e := mustEngine(t, control.FilterPolicy{
		Mode:  control.FilterModeBlacklist,
		Rules: []control.FilterRule{{Match: "shutdown*", Action: control.FilterActionBlockCommand}},
	})
	d := e.Exec("shutdown -h now")
	ev := d.Event(time.Unix(1, 0).UTC(), true)
	ev.SessionID = "sess-1"

	if ev.Event != EventCommandPolicy {
		t.Errorf("event = %q, want %q", ev.Event, EventCommandPolicy)
	}
	if ev.Priority != PriorityImmediate {
		t.Errorf("priority = %q, want %q: a policy that fired must not wait in a batch (D8)", ev.Priority, PriorityImmediate)
	}
	if ev.Tier != TierFiltered || ev.Guarantee != GuaranteeGuardrail {
		t.Errorf("tier/guarantee = %q/%q, want the deciding tier recorded", ev.Tier, ev.Guarantee)
	}
	if ev.Outcome != OutcomeBlocked || !ev.Enforced {
		t.Errorf("outcome/enforced = %q/%t, want blocked and enforced", ev.Outcome, ev.Enforced)
	}
	if ev.RuleIndex != 0 || !ev.Matched {
		t.Errorf("rule = %d matched = %t, want the rule that decided", ev.RuleIndex, ev.Matched)
	}

	var wire map[string]any
	encoded, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, key := range []string{
		"event", "priority", "timestamp", "session_id", "tier", "guarantee",
		"action", "outcome", "enforced", "command", "matched", "rule_index",
	} {
		if _, ok := wire[key]; !ok {
			t.Errorf("the wire shape has no %q; 0011 consumes these names", key)
		}
	}

	// The mode-default decision is reportable too, and names no rule.
	strict := mustEngine(t, control.FilterPolicy{Mode: control.FilterModeWhitelist})
	blocked := strict.Exec("uptime").Event(time.Unix(1, 0), true)
	if blocked.RuleIndex != -1 || blocked.Matched {
		t.Errorf("an unmatched decision claims rule %d matched=%t", blocked.RuleIndex, blocked.Matched)
	}
}

// TestTheLogSinkMarksThePriorityAndTheTier is the interim delivery this phase
// ships: until 0011's transport exists, the event is a log line an operator can
// already alert on.
func TestTheLogSinkMarksThePriorityAndTheTier(t *testing.T) {
	var lines []string
	sink := LogSink(func(format string, args ...any) {
		lines = append(lines, strings.TrimSpace(fmt.Sprintf(format, args...)))
	})

	e := mustEngine(t, restrictedPolicy(exactUptime))
	d := e.Exec("rm -rf /")
	ev := d.Event(time.Unix(1, 0), true)
	ev.SessionID = "sess-1"
	sink.Record(ev)

	if len(lines) != 1 {
		t.Fatalf("sink wrote %d lines, want 1", len(lines))
	}
	for _, want := range []string{
		"priority=immediate",
		"event=" + EventCommandPolicy,
		"session=sess-1",
		"tier=" + string(TierRestricted),
		"guarantee=" + string(GuaranteeEnforcement),
		"action=" + string(control.FilterActionBlockCommand),
		"outcome=" + string(OutcomeBlocked),
	} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("log line %q is missing %q", lines[0], want)
		}
	}

	// A nil logger is not a special case at the call site.
	LogSink(nil).Record(ev)
}
