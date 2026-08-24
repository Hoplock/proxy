// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
	"strconv"

	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/filter"
)

// This file is where phase 0010's command-policy audit event meets D8's
// transport. 0010 fixed the SHAPE of the event and shipped it to the proxy's
// log as a placeholder; this is the sink that was always meant to replace that,
// and it changes where the event goes, not what any field is called.

// AuditSink returns the filter.Sink that routes command-policy events into the
// telemetry pipeline.
//
// The mapping it applies is the one D8 describes, made explicit:
//
//   - A policy that named block_command or kill_session is CRITICAL, and a
//     critical record takes the priority endpoint. That holds whether or not
//     the action was enforced — an interactive-tier match that only observed a
//     command someone would have been blocked for is exactly the signal a
//     security team is watching for, and "enforced=false" is on the record for
//     them to read (D12).
//   - warn_and_continue is WARN and rides the batch. The user was told, the
//     command ran, and nothing is waiting on the record.
//   - allow_and_log is INFO and rides the batch.
//
// The event's own priority marker is preserved verbatim in the record's
// attributes, so the producer's intent survives even where this mapping and it
// disagree.
func (r *SessionRecorder) AuditSink() filter.Sink {
	if r == nil {
		return filter.DiscardSink
	}
	return filter.SinkFunc(func(ev filter.AuditEvent) { r.CommandPolicy(ev) })
}

// CommandPolicy records one command-policy decision.
func (r *SessionRecorder) CommandPolicy(ev filter.AuditEvent) {
	if r == nil {
		return
	}
	attrs := Attrs{}.
		Set(AttrEvent, ev.Event).
		Set(AttrPriority, string(ev.Priority)).
		Set(AttrChannelID, ev.ChannelID).
		Set(AttrChannelType, ev.ChannelType).
		Set(AttrRequest, ev.Request).
		Set(AttrTier, string(ev.Tier)).
		Set(AttrGuarantee, string(ev.Guarantee)).
		Set(AttrAction, string(ev.Action)).
		Set(AttrOutcome, string(ev.Outcome)).
		Set(AttrCommand, ev.Command).
		Set(AttrDetail, ev.Detail).
		Set(AttrInspector, ev.Inspector).
		SetBool(AttrEnforced, ev.Enforced).
		SetBool(AttrMatched, ev.Matched).
		Set(AttrRuleIndex, strconv.Itoa(ev.RuleIndex))

	r.Record(Event{
		Kind:     control.LogKindPolicyDecision,
		Severity: auditSeverity(ev),
		Message:  commandPolicyMessage(ev),
		Attrs:    attrs,
		At:       ev.Timestamp,
	})
}

// auditSeverity ranks a command-policy event. See AuditSink for why the action
// the policy NAMED decides it rather than the outcome that followed.
func auditSeverity(ev filter.AuditEvent) control.Severity {
	switch ev.Action {
	case control.FilterActionBlockCommand, control.FilterActionKillSession:
		return control.SeverityCritical
	case control.FilterActionWarnAndContinue:
		return control.SeverityWarn
	default:
		return control.SeverityInfo
	}
}

// commandPolicyMessage is the human-readable half. It says what happened, not
// which rule said so: the rule is in the attributes, where a report can group
// by it (PLAN §4.3 keeps policy contents off the user's terminal; this record
// is not the user's terminal, but a message field is read by people scanning,
// and the structured fields are what queries are written against).
func commandPolicyMessage(ev filter.AuditEvent) string {
	switch ev.Outcome {
	case filter.OutcomeBlocked:
		return "command blocked by policy"
	case filter.OutcomeKilled:
		return "session terminated by policy"
	case filter.OutcomeWarned:
		return "command warned by policy"
	case filter.OutcomeObserved:
		return "command observed by policy"
	default:
		return "command allowed by policy"
	}
}
