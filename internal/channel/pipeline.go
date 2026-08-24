// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package channel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync/atomic"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
)

// Policy is the connection's policy as the pipeline needs it: the three axes of
// D5a, and nothing else. *routing.Route implements it — the route is what
// carries Hoplock Control's answer — and the interface exists so this package
// depends on the decision rather than on where the decision came from, which is
// also what lets a test state a policy in one literal.
type Policy interface {
	// ChannelPermitted is axis 1: which channel types may exist.
	ChannelPermitted(channelType string) bool
	// RequestPermitted is axis 2, for everything but a subsystem.
	RequestPermitted(name string) bool
	// SubsystemPermitted is axis 2 for a subsystem, decided by name.
	SubsystemPermitted(name string) bool
	// GlobalRequestPermitted is axis 3b: connection-level requests.
	GlobalRequestPermitted(name string) bool
	// ForwardDestinations is axis 3a: the destinations permitted for a
	// forwarding channel type, and whether that axis is policed at all.
	ForwardDestinations(channelType string) ([]control.ForwardDestination, bool)
}

// Options configure a Pipeline.
type Options struct {
	// Policy is the connection's policy. Required.
	Policy Policy
	// Inspectors is the chain registry. Nil registers nothing, which is the
	// pure pass-through this phase ships with.
	Inspectors *Registry
	// SessionID tags every event and every log line with the session it
	// belongs to.
	SessionID string
	// Logf records denials and flags. Nil discards them.
	Logf func(format string, args ...any)
}

// Pipeline is one connection's inspection pipeline.
//
// Every channel and every connection-level request on that connection goes
// through it. Policy runs first and always; inspectors run after, and only for
// what policy already allowed.
type Pipeline struct {
	policy    Policy
	registry  *Registry
	sessionID string
	logf      func(format string, args ...any)
	// channels numbers the channels opened on this connection, so each one can
	// be named in an audit record and correlated across the calls an inspector
	// gets for it.
	channels atomic.Uint64
}

// New returns a pipeline for one connection.
func New(opts Options) (*Pipeline, error) {
	if opts.Policy == nil {
		return nil, errors.New("channel: a policy is required")
	}
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Pipeline{
		policy:    opts.Policy,
		registry:  opts.Inspectors,
		sessionID: opts.SessionID,
		logf:      logf,
	}, nil
}

// Inspection is the pipeline bound to one open channel: the object the
// transport consults for every request and every stream on that channel.
//
// A nil *Inspection is usable and inspects nothing, so a caller that has not
// opened a channel through the pipeline is not a special case.
type Inspection struct {
	pipe     *Pipeline
	info     Info
	requests []RequestInspector
	streams  []StreamInspector
}

// Open applies the axes SSH decides at channel-open time — the channel type in
// whichever direction it was asked for, and, for a forwarding channel, the
// destination inside its payload — then runs the open inspectors.
//
// It returns the Inspection to drive the channel with, and the decision. On a
// denial the Inspection is nil and the decision carries the clause to refuse
// with; on anything else the caller opens the far side with
// decision.PayloadOr(ev.Payload), so that a mutating inspector is not silently
// ignored.
func (p *Pipeline) Open(ctx context.Context, ev OpenEvent) (*Inspection, Decision) {
	ev.SessionID = p.sessionID

	// Axis 1, both directions: a channel the session may not open is not one
	// the target may hand it.
	if !p.policy.ChannelPermitted(ev.ChannelType) {
		return nil, p.denied(Deny(channelTypeReason(ev.ChannelType)),
			"channel %s %s: not on the channel allow-list", ev.Direction, ev.ChannelType)
	}

	// Axis 3a: a port forward's whole meaning is the destination in its
	// payload, so the type alone deciding it would be a toggle, not a firewall.
	if IsForwardChannel(ev.ChannelType) {
		forward, err := ParseForward(ev.ChannelType, ev.Payload)
		if err != nil {
			return nil, p.denied(Deny(malformedForwardReason),
				"channel %s %s: %v", ev.Direction, ev.ChannelType, err)
		}
		ev.Forward = &forward
		if dests, policed := p.policy.ForwardDestinations(ev.ChannelType); policed && !MatchForward(dests, forward) {
			return nil, p.denied(Deny(forwardReason(forward)),
				"channel %s %s: destination %s not permitted", ev.Direction, ev.ChannelType, forward)
		}
	}

	decision := Allow()
	for _, inspector := range p.registry.Inspectors(ev.ChannelType) {
		opener, ok := inspector.(OpenInspector)
		if !ok {
			continue
		}
		d := p.attribute(inspector, opener.InspectOpen(ctx, &ev))
		switch d.Action {
		case ActionDeny, ActionTerminate:
			return nil, p.denied(d, "channel %s %s: %s denied it", ev.Direction, ev.ChannelType, d.By)
		case ActionMutate:
			ev.Payload = d.Payload
			decision = d
		case ActionFlag:
			p.flagged(d, "channel %s %s", ev.Direction, ev.ChannelType)
		case ActionAllow:
		}
	}

	insp := &Inspection{
		pipe: p,
		info: Info{
			SessionID: p.sessionID,
			ChannelID: p.nextChannelID(),
			Type:      ev.ChannelType,
			Opener:    ev.Direction,
			Forward:   ev.Forward,
		},
	}
	for _, inspector := range p.registry.Inspectors(ev.ChannelType) {
		if r, ok := inspector.(RequestInspector); ok {
			insp.requests = append(insp.requests, r)
		}
		if s, ok := inspector.(StreamInspector); ok {
			insp.streams = append(insp.streams, s)
		}
	}
	return insp, decision
}

// GlobalRequest applies axis 3b to a connection-level request.
//
// Remote forwarding is asked for here, not by opening a channel, so a
// channel-type allow-list never sees it — and denying the forwarded-tcpip
// channel that results is not the same thing, because the listener is created
// on the target either way and only the connections through it fail
// (PLAN §6.2). A denied request is answered false by the caller; it is never
// relayed.
func (p *Pipeline) GlobalRequest(_ context.Context, name string) Decision {
	if p.policy.GlobalRequestPermitted(name) {
		return Allow()
	}
	// No clause: a global request is not attached to a channel, so there is
	// nowhere to write to and nothing but the false reply to say it with.
	return p.denied(Deny(""), "global request %s: not on the allow-list", name)
}

// Request applies the in-channel request axis and then the chain's request
// inspectors.
//
// The axis is enforced here, at the request, rather than at the open, because
// that is where SSH decides what a session channel is: the same channel becomes
// an interactive login, a one-shot command, or a file transfer depending on
// which request follows it (PLAN §6.2, D5a).
func (i *Inspection) Request(ctx context.Context, ev RequestEvent) Decision {
	if i == nil {
		return Allow()
	}
	ev.Channel = i.info

	// A resize, a signal, or an exit status decides nothing, so it is outside
	// the policy and always relayed. Inspectors still see it — a recorder needs
	// the resize to replay a session — but a denial from one is downgraded to a
	// flag, because "always relayed" is the contract these requests have.
	ancillary := control.IsAncillaryChannelRequest(ev.Type)

	if !ancillary {
		if d, ok := i.pipe.policeRequest(&ev); !ok {
			return d
		}
	}

	decision := Allow()
	for _, inspector := range i.requests {
		d := i.pipe.attribute(inspector, inspector.InspectRequest(ctx, &ev))
		switch d.Action {
		case ActionDeny, ActionTerminate:
			if ancillary {
				i.pipe.flagged(d, "request %s on %s: denial downgraded, the request carries no policy",
					ev.Type, ev.Channel.Type)
				continue
			}
			return i.pipe.denied(d, "request %s on %s: %s denied it", ev.Type, ev.Channel.Type, d.By)
		case ActionMutate:
			ev.Payload = d.Payload
			if d.Notice == "" {
				// A replacement payload does not withdraw an earlier
				// inspector's notice to the user.
				d.Notice = decision.Notice
			}
			decision = d
		case ActionFlag:
			i.pipe.flagged(d, "request %s on %s", ev.Type, ev.Channel.Type)
			// A flag with a notice is the warn-and-continue shape: the event
			// proceeds and the caller shows the user the notice, so the
			// decision has to survive rather than be dropped for an Allow.
			if d.Notice != "" && decision.Action == ActionAllow {
				decision = d
			}
		case ActionAllow:
		}
	}
	return decision
}

// nextChannelID names the next channel opened on this connection. The id is
// scoped to the session, which is what an audit record needs: a channel is only
// ever discussed alongside the session it belongs to.
func (p *Pipeline) nextChannelID() string {
	return p.sessionID + "/" + strconv.FormatUint(p.channels.Add(1), 10)
}

// policeRequest applies axis 2 to one request, filling in the parsed subsystem
// name or command as it goes so that no inspector has to unmarshal the payload
// a second time. It reports the denial and false when the request is refused.
func (p *Pipeline) policeRequest(ev *RequestEvent) (Decision, bool) {
	switch ev.Type {
	case control.RequestSubsystem:
		var payload struct{ Name string }
		if err := ssh.Unmarshal(ev.Payload, &payload); err != nil {
			return p.denied(Deny(malformedRequestReason),
				"request subsystem on %s: malformed payload: %v", ev.Channel.Type, err), false
		}
		ev.Subsystem = payload.Name
		// Subsystems are named individually, not covered by a "subsystem"
		// entry in the type list, so that sftp is deniable while shell stays.
		if !p.policy.SubsystemPermitted(payload.Name) {
			return p.denied(Deny(subsystemReason(payload.Name)),
				"request subsystem %q on %s: not permitted", payload.Name, ev.Channel.Type), false
		}
	case control.RequestExec:
		var payload struct{ Command string }
		if err := ssh.Unmarshal(ev.Payload, &payload); err != nil {
			return p.denied(Deny(malformedRequestReason),
				"request exec on %s: malformed payload: %v", ev.Channel.Type, err), false
		}
		ev.Command = payload.Command
		if !p.policy.RequestPermitted(ev.Type) {
			return p.denied(Deny(requestReason(ev.Type)),
				"request exec on %s: not permitted", ev.Channel.Type), false
		}
	default:
		if !p.policy.RequestPermitted(ev.Type) {
			return p.denied(Deny(requestReason(ev.Type)),
				"request %s on %s: not permitted", ev.Type, ev.Channel.Type), false
		}
	}
	return Allow(), true
}

// Reader returns the reader the pump should copy one direction from.
//
// When no stream inspector is registered for this channel it returns src
// itself, so an un-inspected channel is the same straight io.Copy phase 0005
// shipped: no wrapper, no buffer, no allocation. That is the property
// BenchmarkStreamCopy exists to hold onto.
func (i *Inspection) Reader(ctx context.Context, dir Direction, stderr bool, src io.Reader) io.Reader {
	if i == nil || len(i.streams) == 0 {
		return src
	}
	for _, inspector := range i.streams {
		wrapped := inspector.InspectStream(ctx, &StreamEvent{
			Channel:   i.info,
			Direction: dir,
			Stderr:    stderr,
			Source:    src,
		})
		if wrapped != nil {
			src = wrapped
		}
	}
	return src
}

// Inspected reports whether anything is attached to this channel. It is what
// lets the transport keep the un-inspected path visibly separate.
func (i *Inspection) Inspected() bool {
	return i != nil && (len(i.requests) > 0 || len(i.streams) > 0)
}

// Opener reports which side opened the channel: the direction data travels on
// its near half, and the side whose requests carry policy.
func (i *Inspection) Opener() Direction {
	if i == nil {
		return FromClient
	}
	return i.info.Opener
}

// Info identifies the channel this inspection is bound to.
func (i *Inspection) Info() Info {
	if i == nil {
		return Info{}
	}
	return i.info
}

// RequestStartsExecution reports whether a request is the one that puts the
// channel to work.
//
// It is what tells a denial apart from an ending: refusing a pty leaves a
// channel that can still run a command ("CI may run commands but never gets an
// interactive terminal"), while refusing the shell, the command, or the
// subsystem leaves a channel with nothing left to do, and holding it open would
// be the silent failure PLAN §4.3 forbids.
func RequestStartsExecution(name string) bool {
	switch name {
	case control.RequestShell, control.RequestExec, control.RequestSubsystem:
		return true
	default:
		return false
	}
}

// attribute stamps an inspector's name onto its decision, so a log line and an
// audit event can name who decided without every inspector remembering to.
func (p *Pipeline) attribute(inspector Inspector, d Decision) Decision {
	if d.By == "" {
		d.By = inspector.Name()
	}
	return d
}

// denied logs a refusal and returns it. Every denial in this package goes
// through here, so no axis can be enforced without leaving a trace.
func (p *Pipeline) denied(d Decision, format string, args ...any) Decision {
	p.logf("channel: session=%s denied %s%s", p.sessionID, fmt.Sprintf(format, args...), detailSuffix(d))
	return d
}

// flagged logs an inspector's flag. The event proceeds.
func (p *Pipeline) flagged(d Decision, format string, args ...any) {
	p.logf("channel: session=%s flagged %s by=%s%s", p.sessionID, fmt.Sprintf(format, args...), d.By, detailSuffix(d))
}

func detailSuffix(d Decision) string {
	if d.Detail == "" {
		return ""
	}
	return ": " + d.Detail
}
