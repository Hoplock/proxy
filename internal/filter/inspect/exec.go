// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package inspect

import (
	"context"
	"time"

	"github.com/hoplock/proxy/internal/channel"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/filter"
)

// ExecName identifies the exec inspector in logs, decisions, and audit events.
const ExecName = "command-filter/exec"

// Options configure the inspectors in this package.
type Options struct {
	// Engine is the connection's compiled policy. Required.
	Engine *filter.Engine
	// Audit receives an event for every decision worth recording. Nil
	// discards them, which no production caller wants and every focused test
	// does.
	Audit filter.Sink
	// Now supplies event timestamps. Nil means time.Now.
	Now func() time.Time
}

func (o Options) now() time.Time {
	if o.Now == nil {
		return time.Now()
	}
	return o.Now()
}

func (o Options) sink() filter.Sink {
	if o.Audit == nil {
		return filter.DiscardSink
	}
	return o.Audit
}

// Exec applies command policy to "exec" requests, before the request reaches
// the target.
//
// This is the enforcing inspector. Which tier it enforces — the parsed-argv
// boundary or the pattern guardrail — is the engine's business and the audit
// record's; the user is told the same thing either way, because what the user
// may learn is THAT policy stopped them and never the policy's contents
// (PLAN §4.3).
type Exec struct {
	opts Options
}

// NewExec returns the exec inspector for a connection's policy.
func NewExec(opts Options) *Exec { return &Exec{opts: opts} }

// Name implements channel.Inspector.
func (e *Exec) Name() string { return ExecName }

// InspectRequest implements channel.RequestInspector.
func (e *Exec) InspectRequest(_ context.Context, ev *channel.RequestEvent) channel.Decision {
	// Only the client's own exec requests carry this policy. A target does not
	// run commands on the user, and the pipeline hands both directions here.
	if ev.Type != control.RequestExec || ev.Direction != channel.FromClient {
		return channel.Allow()
	}

	d := e.opts.Engine.Exec(ev.Command)
	if d.Reportable() {
		e.opts.sink().Record(auditEvent(d, e.opts.now(), true, ev.Channel, control.RequestExec, ExecName))
	}

	switch {
	case d.Kills():
		// The user is told the session is ending before it ends: a revoked or
		// filtered session must never look like a crash (PLAN §4.3).
		return channel.TerminateWithDetail(killedText(d.Message), d.Detail).AsCommandFailure()
	case d.Blocks():
		// Restricted-exec denial uses this same presentation. The tier that
		// decided is in the audit event, not on the terminal.
		//
		// The refusal is delivered as the command's own failure — stderr plus a
		// non-zero exit status — because that is what a blocked command is:
		// something the user asked to run, which did not run, and said why.
		return channel.DenyWithDetail(blockedText(d.Message), d.Detail).AsCommandFailure()
	case d.Warns():
		return channel.Warn(warningText(d.Message), d.Detail)
	default:
		return channel.Allow()
	}
}

// blockedText is what a user sees for a blocked command: that policy stopped
// it, plus the operator's own words when the rule carried any.
//
// It names no pattern, no mode, no permitted executable, and not even which
// tier refused. Every one of those would let a client map the policy one probe
// at a time, and the audit record already has them (PLAN §4.3).
func blockedText(message string) string {
	return withMessage("That command was blocked by policy.", message)
}

// killedText is what a user sees when a command ends the session. It is a full
// sentence rather than a clause because the transport renders it as the
// session's own last words, not behind the generic denial.
func killedText(message string) string {
	return withMessage("This session has been terminated by policy.", message)
}

// warningText is what a user sees when a command is permitted but flagged.
func warningText(message string) string {
	return withMessage("Warning: this command is flagged by policy and has been recorded.", message)
}

// withMessage appends the operator-authored message, which the contract says is
// displayed verbatim — the server is the one that must keep policy internals
// out of it.
func withMessage(text, message string) string {
	if message == "" {
		return text
	}
	return text + " " + message
}

// auditEvent fills in the SSH-side fields the engine has no way to know.
func auditEvent(d filter.Decision, now time.Time, enforced bool, info channel.Info, request, inspector string) filter.AuditEvent {
	ev := d.Event(now, enforced)
	ev.SessionID = info.SessionID
	ev.ChannelID = info.ChannelID
	ev.ChannelType = info.Type
	ev.Request = request
	ev.Inspector = inspector
	return ev
}
