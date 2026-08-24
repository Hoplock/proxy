// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package filter

import (
	"fmt"
	"strings"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// This file defines the audit event command policy produces, and the temporary
// sink it goes to until phase 0011 builds the log pipeline.
//
// The SHAPE is the durable part. 0011 changes where these events go and how
// they are batched; it does not get to change what a blocked command is called,
// because the field names below are what a security team's queries are written
// against and what a report about "boundary versus guardrail" is grouped by.

// EventCommandPolicy is the stable event type name. Every event this package
// produces carries it.
const EventCommandPolicy = "command.policy"

// Priority is D8's delivery class.
type Priority string

const (
	// PriorityImmediate is D8's "blocked commands and other critical security
	// events are sent immediately": flush the in-flight batch or use the
	// dedicated priority path. Every command-policy event carries it — a
	// policy that fired is exactly the event that must not wait in a buffer
	// for a session that may be about to be killed.
	PriorityImmediate Priority = "immediate"
	// PriorityBatch is ordinary telemetry. Nothing in this package emits it;
	// it exists so the field has a defined other value for 0011.
	PriorityBatch Priority = "batch"
)

// Outcome is what actually happened to the command, which is not the same as
// the action the policy named: the interactive tier reports actions it did not
// apply, and Enforced is how an auditor tells the two apart.
type Outcome string

const (
	// OutcomeAllowed means the command ran.
	OutcomeAllowed Outcome = "allowed"
	// OutcomeWarned means the user was warned and the command ran.
	OutcomeWarned Outcome = "warned"
	// OutcomeBlocked means the command did not run.
	OutcomeBlocked Outcome = "blocked"
	// OutcomeKilled means the session was terminated.
	OutcomeKilled Outcome = "killed"
	// OutcomeObserved means the policy matched on the best-effort interactive
	// tier and nothing was enforced.
	OutcomeObserved Outcome = "observed"
)

// AuditEvent is one command-policy decision, ready for D8's priority path.
//
// The JSON tags are the wire shape 0011 consumes. Two fields carry policy
// contents — Detail and RuleIndex — and they are the reason this record exists
// separately from what the user is shown: the terminal learns THAT policy
// stopped a command, and this record learns which rule, in which tier, with
// which guarantee (PLAN §4.3, §6.3).
type AuditEvent struct {
	// Event is always EventCommandPolicy.
	Event string `json:"event"`
	// Priority is the delivery class: always PriorityImmediate here.
	Priority Priority `json:"priority"`
	// Timestamp is when the decision was made.
	Timestamp time.Time `json:"timestamp"`
	// SessionID is the proxy session, and the support reference the user was
	// given for anything that failed (PLAN §4.3).
	SessionID string `json:"session_id"`
	// ChannelID identifies the channel within the session.
	ChannelID string `json:"channel_id,omitempty"`
	// ChannelType is the SSH channel type the command arrived on.
	ChannelType string `json:"channel_type,omitempty"`
	// Request is the SSH request the command came from ("exec"), or "shell"
	// for a line reconstructed from an interactive stream.
	Request string `json:"request,omitempty"`
	// Tier is which of PLAN §6.3's three tiers decided.
	Tier Tier `json:"tier"`
	// Guarantee is what that tier may claim. It is stored rather than derived
	// so that a stored event stays readable if the tiers are ever renamed.
	Guarantee Guarantee `json:"guarantee"`
	// Action is the policy action the decision named.
	Action control.FilterAction `json:"action"`
	// Outcome is what actually happened.
	Outcome Outcome `json:"outcome"`
	// Enforced says whether Action was applied. It is false for everything the
	// interactive tier merely observed.
	Enforced bool `json:"enforced"`
	// Command is the command as it arrived, or the line reconstructed from the
	// interactive stream.
	Command string `json:"command"`
	// Matched says a rule or permitted-command entry decided, rather than the
	// mode's default.
	Matched bool `json:"matched"`
	// RuleIndex is the position of the rule that decided, -1 when none did.
	RuleIndex int `json:"rule_index"`
	// Detail explains the decision for the operator: which pattern matched,
	// why a parse was refused. It is never shown to the user.
	Detail string `json:"detail,omitempty"`
	// Inspector names the inspector that produced the event.
	Inspector string `json:"inspector,omitempty"`
}

// Sink receives audit events. It is deliberately tiny: phase 0011 owns
// batching, buffering, and the priority path, and everything this package needs
// to know about them is that an event goes somewhere and does not block a
// command decision on the network.
type Sink interface {
	Record(AuditEvent)
}

// SinkFunc adapts a function to Sink.
type SinkFunc func(AuditEvent)

// Record implements Sink.
func (f SinkFunc) Record(ev AuditEvent) { f(ev) }

// DiscardSink drops events. It exists so a caller without a sink is not a
// special case at every call site.
var DiscardSink Sink = SinkFunc(func(AuditEvent) {})

// LogSink writes events to the proxy's log as one line each, until 0011 ships
// the pipeline that ships them.
//
// The line leads with the priority and the event name so that an operator
// running today's proxy can already alert on it, and so that the field names
// are the same ones 0011 will send: the marker is "priority=immediate", and it
// means what D8 says it means.
func LogSink(logf func(format string, args ...any)) Sink {
	if logf == nil {
		return DiscardSink
	}
	return SinkFunc(func(ev AuditEvent) { logf("%s", ev.LogLine()) })
}

// LogLine renders an event as one structured log line.
func (ev AuditEvent) LogLine() string {
	var b strings.Builder
	fmt.Fprintf(&b, "filter: priority=%s event=%s session=%s", ev.Priority, ev.Event, ev.SessionID)
	if ev.ChannelID != "" {
		fmt.Fprintf(&b, " channel=%s", ev.ChannelID)
	}
	if ev.Request != "" {
		fmt.Fprintf(&b, " request=%s", ev.Request)
	}
	fmt.Fprintf(&b, " tier=%s guarantee=%s action=%s outcome=%s enforced=%t matched=%t rule=%d command=%q",
		ev.Tier, ev.Guarantee, ev.Action, ev.Outcome, ev.Enforced, ev.Matched, ev.RuleIndex, ev.Command)
	if ev.Detail != "" {
		fmt.Fprintf(&b, " detail=%q", ev.Detail)
	}
	if ev.Inspector != "" {
		fmt.Fprintf(&b, " by=%s", ev.Inspector)
	}
	return b.String()
}

// Event turns a decision into the audit event for it.
//
// enforced says whether the caller applied the action or only observed it,
// which is the difference between the two exec tiers and the interactive one.
func (d Decision) Event(now time.Time, enforced bool) AuditEvent {
	return AuditEvent{
		Event:     EventCommandPolicy,
		Priority:  PriorityImmediate,
		Timestamp: now,
		Tier:      d.Tier,
		Guarantee: d.Guarantee(),
		Action:    d.Action,
		Outcome:   d.outcome(enforced),
		Enforced:  enforced,
		Command:   d.Command,
		Matched:   d.Matched,
		RuleIndex: d.RuleIndex,
		Detail:    d.Detail,
	}
}

// outcome is what happened to the command.
func (d Decision) outcome(enforced bool) Outcome {
	if !enforced {
		return OutcomeObserved
	}
	switch d.Action {
	case control.FilterActionKillSession:
		return OutcomeKilled
	case control.FilterActionBlockCommand:
		return OutcomeBlocked
	case control.FilterActionWarnAndContinue:
		return OutcomeWarned
	default:
		return OutcomeAllowed
	}
}
