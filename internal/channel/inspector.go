// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package channel

import (
	"context"
	"io"
)

// Direction names which end of a proxied session something came from.
//
// It is the axis that makes "in both directions" (PLAN §6.2) expressible: a
// channel the session may not open is not one the target may hand it, and the
// pipeline has to be able to say which of the two it is looking at.
type Direction int

const (
	// FromClient is the user's side: a channel the client opened, or bytes
	// travelling client → target.
	FromClient Direction = iota
	// FromTarget is the far side: a channel the target opened back
	// (forwarded-tcpip, x11, auth-agent), or bytes travelling target → client.
	FromTarget
)

// String names the direction for a log line.
func (d Direction) String() string {
	if d == FromTarget {
		return "target"
	}
	return "client"
}

// Opposite is the direction data flows the other way down the same channel.
func (d Direction) Opposite() Direction {
	if d == FromTarget {
		return FromClient
	}
	return FromTarget
}

// Action is what an inspector says about one event.
//
// ActionAllow is the zero value on purpose: an inspector that looked at an
// event and had nothing to say returns the empty Decision, and a Decision
// nobody filled in must not deny a session by accident. Nothing is fail-open
// as a result — the three policy axes are enforced by the pipeline itself,
// before any inspector runs, and an inspector can only ever narrow what policy
// already allowed.
type Action int

const (
	// ActionAllow lets the event through untouched.
	ActionAllow Action = iota
	// ActionFlag lets the event through and records it. It is how an inspector
	// says "this happened and someone should know" without ending a session
	// over it — the shape 0011's audit events and 0010's warn_and_continue
	// both need.
	ActionFlag
	// ActionMutate lets the event through with Decision.Payload in place of the
	// payload it carried. Inspectors later in the chain see the replacement,
	// which is what makes a chain a pipeline rather than a poll.
	ActionMutate
	// ActionDeny refuses the event. The first denial in a chain wins and the
	// rest of the chain does not run: a decision that has already been made
	// cannot be widened by whatever comes next.
	ActionDeny
	// ActionTerminate refuses the event AND ends the session. It is a denial
	// first — everything that treats ActionDeny as "this does not happen"
	// treats this the same way — and the session teardown is the transport's
	// to perform, because session lifecycle is not an inspector's to reach
	// into.
	//
	// It exists for phase 0010's kill_session action (PLAN §6.3): a policy
	// that can only refuse the command in front of it cannot express "this
	// user is done", and an inspector that killed the session itself would be
	// a decider holding a connection handle.
	ActionTerminate
)

// String names the action for a log line.
func (a Action) String() string {
	switch a {
	case ActionFlag:
		return "flag"
	case ActionMutate:
		return "mutate"
	case ActionDeny:
		return "deny"
	case ActionTerminate:
		return "terminate"
	default:
		return "allow"
	}
}

// Decision is one inspector's — or the pipeline's own — answer about an event.
type Decision struct {
	// Action is the answer itself.
	Action Action
	// Reason is the clause the user is shown for a denial. It is a clause, not
	// a message: internal/proxy renders it behind the generic denial from
	// PLAN §4.3, so that the deny/outage split has exactly one implementation.
	// It must therefore disclose nothing the client did not already say.
	Reason string
	// Detail is for the operator's log and the audit trail. It may name what
	// Reason may not, because it never reaches the user.
	Detail string
	// Payload replaces the event's payload when Action is ActionMutate.
	Payload []byte
	// Notice is text shown to the user alongside an event that was NOT
	// refused: the warn-and-continue half of a command policy, where the point
	// is that the command runs and the user hears about it (PLAN §6.3).
	//
	// It is separate from Reason because the two are read at opposite ends of
	// a decision, and a single field would eventually be written by an
	// inspector that meant the other one. Like Reason it is user-visible, so
	// it discloses nothing about the policy that produced it.
	Notice string
	// CommandFailure marks a denial for delivery as the CHANNEL's own failure —
	// an affirmative reply to the request, the reason on the channel's stderr,
	// and a non-zero exit status — rather than as a protocol-level refusal of
	// the request itself.
	//
	// What was refused is the difference. A request the session may never make
	// (D5a axis 2) is refused as a request, and the client's own "request
	// failed" is then accurate. A command policy refuses the COMMAND that a
	// permitted request carried (PLAN §6.3): the exec was allowed to happen and
	// what it produced is a refusal, so it is reported the way every other
	// command failure is. An SSH client that gets a false reply prints its own
	// generic error and stops reading, which would lose the sentence the user
	// needs — and PLAN §4.3 is explicit that a blocked command says it was
	// blocked.
	CommandFailure bool
	// By names the inspector that decided, empty when the pipeline's own
	// policy did.
	By string
}

// Allow is the empty decision: the event proceeds untouched.
func Allow() Decision { return Decision{} }

// Deny refuses the event, with the clause the user is shown.
func Deny(reason string) Decision { return Decision{Action: ActionDeny, Reason: reason} }

// DenyWithDetail refuses the event, adding an operator-only detail that the
// user never sees.
func DenyWithDetail(reason, detail string) Decision {
	return Decision{Action: ActionDeny, Reason: reason, Detail: detail}
}

// Flag lets the event through and records detail against it.
func Flag(detail string) Decision { return Decision{Action: ActionFlag, Detail: detail} }

// Mutate lets the event through with a replacement payload.
func Mutate(payload []byte) Decision { return Decision{Action: ActionMutate, Payload: payload} }

// Terminate refuses the event and ends the session, with the clause the user is
// shown.
func Terminate(reason string) Decision { return Decision{Action: ActionTerminate, Reason: reason} }

// TerminateWithDetail refuses the event and ends the session, adding an
// operator-only detail the user never sees.
func TerminateWithDetail(reason, detail string) Decision {
	return Decision{Action: ActionTerminate, Reason: reason, Detail: detail}
}

// Warn lets the event through and shows the user a notice about it.
func Warn(notice, detail string) Decision {
	return Decision{Action: ActionFlag, Notice: notice, Detail: detail}
}

// AsCommandFailure marks a denial for delivery as the channel's own failure.
// See Decision.CommandFailure.
func (d Decision) AsCommandFailure() Decision {
	d.CommandFailure = true
	return d
}

// Denied reports whether the event was refused. A terminating decision refuses
// the event too: ending the session is what happens *in addition*, and a caller
// that only asks "may this proceed" must never read it as a yes.
func (d Decision) Denied() bool { return d.Action == ActionDeny || d.Action == ActionTerminate }

// Terminates reports whether the session must end. Only the transport acts on
// it; the pipeline treats it as the denial it also is.
func (d Decision) Terminates() bool { return d.Action == ActionTerminate }

// PayloadOr returns the decision's replacement payload, or fallback when the
// decision left the payload alone.
func (d Decision) PayloadOr(fallback []byte) []byte {
	if d.Action == ActionMutate {
		return d.Payload
	}
	return fallback
}

// Info identifies the channel an event belongs to.
type Info struct {
	// SessionID is the proxy session the channel belongs to, and the support
	// reference a user is given for a failure (PLAN §4.3).
	SessionID string
	// ChannelID names this channel within the session, assigned by the
	// pipeline when the channel is opened. It is what lets an inspector
	// correlate its own events across the calls it gets for one channel — the
	// request that turned a session channel into an interactive shell, and the
	// stream that then carries the keystrokes — and what names the channel in
	// an audit record.
	ChannelID string
	// Type is the SSH channel type.
	Type string
	// Opener is the side that opened the channel.
	Opener Direction
	// Forward is the parsed destination of a forwarding channel, nil for
	// every other channel type.
	Forward *Forward
}

// OpenEvent is a channel open, before the far side has been asked for it.
type OpenEvent struct {
	// SessionID is the proxy session the channel would belong to.
	SessionID string
	// ChannelType is the type being opened.
	ChannelType string
	// Direction is the side asking.
	Direction Direction
	// Payload is the channel-open extra data, as it arrived. It is
	// attacker-controlled on both sides.
	Payload []byte
	// Forward is the destination the pipeline parsed out of Payload for a
	// forwarding channel type, nil for everything else. It is filled in before
	// any inspector runs, so an inspector never re-parses the wire.
	Forward *Forward
}

// RequestEvent is one in-channel request.
type RequestEvent struct {
	// Channel identifies the channel the request arrived on.
	Channel Info
	// Direction is the side making the request.
	Direction Direction
	// Type is the request type ("pty-req", "exec", "subsystem", …).
	Type string
	// WantReply is whether the requester is waiting for an answer.
	WantReply bool
	// Payload is the request payload, as it arrived.
	Payload []byte
	// Subsystem is the subsystem name the pipeline parsed out of Payload when
	// Type is "subsystem", empty otherwise.
	Subsystem string
	// Command is the command the pipeline parsed out of Payload when Type is
	// "exec", empty otherwise. Phase 0010's command filter reads it here
	// rather than unmarshalling the payload a second time.
	Command string
}

// StreamEvent is one direction of an open channel's byte stream, handed to an
// inspector so it can wrap it.
type StreamEvent struct {
	// Channel identifies the channel the bytes belong to.
	Channel Info
	// Direction is the way the bytes are travelling.
	Direction Direction
	// Stderr is whether this is the channel's extended-data stream rather than
	// its main one.
	Stderr bool
	// Source is the stream to read from.
	Source io.Reader
}

// Inspector is the base of everything registered in a chain. What an inspector
// actually inspects is decided by which of the three capability interfaces
// below it also implements, so a filter that only cares about exec requests
// does not have to carry no-op stream and open methods — and, more to the
// point, a channel with no stream inspectors can skip stream wrapping entirely
// instead of copying bytes through a chain of no-ops.
type Inspector interface {
	// Name identifies the inspector in logs and audit events.
	Name() string
}

// OpenInspector is consulted once per channel, before the far side is asked to
// open it. Denying here refuses the channel outright.
type OpenInspector interface {
	Inspector
	InspectOpen(ctx context.Context, ev *OpenEvent) Decision
}

// RequestInspector is consulted for every in-channel request that carries
// policy. This is where phase 0010's command filter attaches: "exec" arrives
// with Command already parsed, and "shell" is the request that turns the
// channel into the interactive stream its keystroke inspection reads.
type RequestInspector interface {
	Inspector
	InspectRequest(ctx context.Context, ev *RequestEvent) Decision
}

// StreamInspector wraps one direction of a channel's byte stream.
//
// It returns the reader the pump will copy from. Returning ev.Source unchanged
// (or nil, which means the same) leaves the direction alone; returning a
// wrapper is how an inspector observes or transforms the bytes. A wrapper that
// returns an error ends that direction, which closes the channel — that is how
// a stream inspector refuses, and it is deliberately the only way, because
// policy is decided at open and request time and never per byte.
type StreamInspector interface {
	Inspector
	InspectStream(ctx context.Context, ev *StreamEvent) io.Reader
}
