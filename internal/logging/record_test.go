// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/filter"
)

// TestEveryRecordCarriesTheSessionItBelongsTo is the schema's first rule: a
// record that cannot be attributed to a session cannot be part of a session's
// reconstruction.
func TestEveryRecordCarriesTheSessionItBelongsTo(t *testing.T) {
	shipper, server := newTestShipper(t, func(o *Options) { o.BatchSize = 1000 })
	rec := shipper.Session(SessionInfo{SessionID: "sess-1", ProxyID: "proxy-1"})
	rec.Identify("alice@example.com", "alice", "host.example.com")

	rec.Start(Attrs{}.Set(AttrClientAddr, "10.0.0.1:2222"))
	rec.Request("request exec", Attrs{}.Set(AttrCommand, "uptime"))
	rec.End(nil)
	flush(t, shipper)

	delivered := server.delivered()
	if len(delivered) != 3 {
		t.Fatalf("delivered %d records, want 3", len(delivered))
	}
	seen := map[string]bool{}
	for _, r := range delivered {
		if r.SessionID != "sess-1" || r.Subject != "alice@example.com" ||
			r.Login != "alice" || r.Target != "host.example.com" {
			t.Errorf("record %s is not attributed: %+v", r.Kind, r)
		}
		if r.RecordID == "" {
			t.Errorf("record %s has no id; the server cannot de-duplicate a retry", r.Kind)
		}
		if r.Timestamp.IsZero() {
			t.Errorf("record %s has no timestamp", r.Kind)
		}
		if seen[r.RecordID] {
			t.Errorf("record id %s was reused", r.RecordID)
		}
		seen[r.RecordID] = true
		if r.Attributes[AttrProxyID] != "proxy-1" {
			t.Errorf("record %s does not name the proxy that made it", r.Kind)
		}
	}
}

// TestASessionEndCarriesItsDuration keeps the field a report groups by.
func TestASessionEndCarriesItsDuration(t *testing.T) {
	shipper, server := newTestShipper(t, func(o *Options) { o.BatchSize = 1000 })
	rec := shipper.Session(SessionInfo{SessionID: "sess-1"})
	rec.End(nil)
	flush(t, shipper)

	end := server.delivered()[0]
	if end.Kind != control.LogKindSessionEnd {
		t.Fatalf("kind = %q, want %q", end.Kind, control.LogKindSessionEnd)
	}
	if _, ok := end.Attributes[AttrDuration]; !ok {
		t.Errorf("the session end record has no %s", AttrDuration)
	}
}

// TestACriticalRecordTakesThePriorityPath is the recorder's half of D8: the
// severity decides the endpoint, so no capture point has to remember to.
func TestACriticalRecordTakesThePriorityPath(t *testing.T) {
	shipper, server := newTestShipper(t, func(o *Options) {
		o.BatchSize = 1000
		o.FlushInterval = -1
	})
	rec := shipper.Session(SessionInfo{SessionID: "sess-1"})

	rec.Denied("channel direct-tcpip refused", Attrs{}.Set(AttrReason, "not permitted"))

	eventually(t, func() bool { return len(server.priorityRecords()) == 1 }, "the refusal")
	got := server.priorityRecords()[0]
	if got.Kind != control.LogKindPolicyDecision || got.Severity != control.SeverityCritical {
		t.Errorf("refusal recorded as %s/%s, want policy_decision/critical", got.Kind, got.Severity)
	}
}

// TestANilRecorderRecordsNothing is what lets every capture point call through
// without asking whether telemetry is configured.
func TestANilRecorderRecordsNothing(t *testing.T) {
	var rec *SessionRecorder
	rec.Identify("alice", "alice", "host")
	rec.Start(nil)
	rec.Denied("refused", nil)
	rec.Stream([]byte("bytes"), time.Now(), nil)
	rec.End(nil)
	if got := rec.Records(); got != 0 {
		t.Errorf("a nil recorder recorded %d records", got)
	}
	if sink := rec.AuditSink(); sink == nil {
		t.Error("a nil recorder returned no audit sink; callers would have to branch")
	}
}

// TestAStreamRecordMarshalsItsPayload keeps capture round-trippable: the bytes
// come back as the bytes, which is what a replay concatenates.
func TestAStreamRecordMarshalsItsPayload(t *testing.T) {
	shipper, server := newTestShipper(t, func(o *Options) { o.BatchSize = 1000 })
	rec := shipper.Session(SessionInfo{SessionID: "sess-1"})

	payload := []byte("\x1b[32mready\x1b[0m\r\n\x00\xff")
	rec.Stream(payload, time.Now(), Attrs{}.Set(AttrStream, "stdout"))
	flush(t, shipper)

	encoded, err := json.Marshal(server.delivered()[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back control.LogRecord
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(back.Payload) != string(payload) {
		t.Errorf("payload round-tripped as %q, want %q", back.Payload, payload)
	}
}

// TestTheCommandPolicySeveritiesMatchTheOutcome pins the mapping AuditSink
// documents, because it is what decides which endpoint an event leaves on.
func TestTheCommandPolicySeveritiesMatchTheOutcome(t *testing.T) {
	tests := []struct {
		action control.FilterAction
		want   control.Severity
	}{
		{control.FilterActionBlockCommand, control.SeverityCritical},
		{control.FilterActionKillSession, control.SeverityCritical},
		{control.FilterActionWarnAndContinue, control.SeverityWarn},
		{control.FilterActionAllowAndLog, control.SeverityInfo},
	}
	for _, tt := range tests {
		t.Run(string(tt.action), func(t *testing.T) {
			got := auditSeverity(filter.AuditEvent{Action: tt.action})
			if got != tt.want {
				t.Errorf("severity for %s = %q, want %q", tt.action, got, tt.want)
			}
		})
	}
}

// TestAnObservedBlockIsStillCritical is the D12 reading of the mapping: the
// interactive tier enforces nothing, and "someone typed the thing that would
// have been blocked" is exactly the signal a security team wants now.
func TestAnObservedBlockIsStillCritical(t *testing.T) {
	shipper, server := newTestShipper(t, func(o *Options) {
		o.BatchSize = 1000
		o.FlushInterval = -1
	})
	rec := shipper.Session(SessionInfo{SessionID: "sess-1"})

	rec.AuditSink().Record(filter.AuditEvent{
		Event:     filter.EventCommandPolicy,
		Priority:  filter.PriorityImmediate,
		Timestamp: time.Now(),
		Tier:      filter.TierInteractive,
		Guarantee: filter.GuaranteeAuditSignal,
		Action:    control.FilterActionKillSession,
		Outcome:   filter.OutcomeObserved,
		Enforced:  false,
		Command:   "rm -rf /",
		RuleIndex: 3,
	})

	eventually(t, func() bool { return len(server.priorityRecords()) == 1 }, "the observed match")
	got := server.priorityRecords()[0]
	if got.Attributes[AttrEnforced] != "false" {
		t.Errorf("enforced = %q, want false: the record must not claim it stopped anything",
			got.Attributes[AttrEnforced])
	}
	if got.Attributes[AttrTier] != string(filter.TierInteractive) ||
		got.Attributes[AttrCommand] != "rm -rf /" ||
		got.Attributes[AttrRuleIndex] != "3" {
		t.Errorf("the record lost fields 0010 pinned: %v", got.Attributes)
	}
}
