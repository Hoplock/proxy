// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/auth/target"
	"github.com/hoplock/proxy/internal/channel"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/logging"
	"github.com/hoplock/proxy/internal/routing"
)

// This file is the telemetry side of the engine: every capture point PLAN §7
// asks for, in one place, so that reading "what does a session record" does not
// mean reading the transport.
//
// The transport calls these; none of them can fail, block, or change what the
// session does. A nil recorder — a proxy built without a Shipper — makes every
// one of them a no-op, which is what keeps the capture points out of the
// engine's error handling.

// recordStart captures the beginning of a session: who connected, from where,
// how they authenticated, and whether the "who" is a user or the proxy in front
// of this one (D11).
func (s *session) recordStart() {
	id := s.identity
	if id == nil {
		return
	}
	s.rec.Identify(id.Subject, s.login, s.target)
	attrs := logging.Attrs{}.
		Set(logging.AttrClientAddr, s.conn.RemoteAddr().String()).
		Set(logging.AttrServerAddr, s.conn.LocalAddr().String()).
		Set(logging.AttrClientVersion, string(s.conn.ClientVersion())).
		Set(logging.AttrAuthMethod, string(id.Method)).
		Set(logging.AttrIdentitySource, id.Source).
		Set(logging.AttrHopTrail, s.chain().Trail.String()).
		SetBool(logging.AttrHopPeer, s.hopPeer)
	s.rec.Start(attrs)

	// The authentication record is separate from the session record because
	// they answer different questions and a later phase may produce several of
	// the second. What it does NOT carry is the credential: the authenticator
	// hands the engine an identity, never a password, so there is nothing here
	// to redact (PLAN §7).
	s.rec.Auth(fmt.Sprintf("authenticated by %s", id.Method), logging.Attrs{}.
		Set(logging.AttrAuthMethod, string(id.Method)).
		Set(logging.AttrIdentitySource, id.Source))
}

// recordAuthorize captures Hoplock Control's decision: the route, the policy
// that will be enforced on it, and the credential method chosen for the target
// leg (D6a).
func (s *session) recordAuthorize(route *routing.Route) {
	attrs := logging.Attrs{}.
		Set(logging.AttrRouteType, string(route.Type)).
		Set(logging.AttrPermissions, route.Permissions).
		Set(logging.AttrDecisionID, route.DecisionID).
		Set(logging.AttrFinalTarget, route.FinalTarget()).
		Set(logging.AttrExecMode, string(route.ExecMode())).
		Set(logging.AttrFilterMode, string(route.Filter.Mode)).
		Set(logging.AttrPermittedChannels, strings.Join(route.PermittedChannels, ",")).
		SetInt(logging.AttrTargetPort, route.Port)
	if route.TargetAuth != nil {
		attrs.Set(logging.AttrCredentialMethod, string(route.TargetAuth.Method))
	}
	if route.IsNextHop() {
		// D11: a hop's connection direction is part of the route, so it is part
		// of the record. Reconstructing a chained session means knowing not
		// just which proxies it crossed but which way each leg was opened.
		attrs.Set(logging.AttrHopConnection, string(route.HopDirection()))
		if route.Hop != nil {
			attrs.Set(logging.AttrHopNextProxy, route.Hop.NextProxyID)
		}
	}
	s.rec.Authorize(fmt.Sprintf("authorized to %s route %s", route.Type, route.Addr()), attrs)
}

// recordHopLeg captures a chain leg coming up, with the direction it travelled.
func (s *session) recordHopLeg(plan *routing.HopPlan) {
	s.rec.Authorize(fmt.Sprintf("hop leg up to %s", hopName(plan)), logging.Attrs{}.
		Set(logging.AttrRouteType, string(control.RouteTypeNextHop)).
		Set(logging.AttrHopConnection, string(plan.Direction)).
		Set(logging.AttrHopNextProxy, plan.NextProxyID).
		Set(logging.AttrHopTrail, plan.Chain.Trail.String()).
		Set(logging.AttrFinalTarget, plan.FinalTarget))
}

// recordCredential captures which target-credential method actually provisioned
// this session's access, and the account it provisioned (D6a).
//
// The method is the server's choice where it made one and the proxy's local
// configuration otherwise, which is the same precedence Provision itself
// applies — so the record says what happened rather than what was asked for.
func (s *session) recordCredential(route *routing.Route, access *target.ProvisionedAccess) {
	// Since contract v3 the server sends a LADDER, so "which method" is a
	// question with more than one possible answer and the record must name the
	// one that was USED (D14). The provisioner reports it; the route's first
	// entry is only the fallback for a method that does not.
	method := access.Method
	if method == "" {
		method = s.srv.targetAuth.Name()
		if route.TargetAuth != nil && route.TargetAuth.Method != "" {
			method = string(route.TargetAuth.Method)
		}
	}
	account := ""
	if access.ClientConfig != nil {
		account = access.ClientConfig.User
	}
	attrs := logging.Attrs{}.
		Set(logging.AttrCredentialMethod, method).
		Set(logging.AttrTargetAccount, account)
	if access.Rung > 0 {
		// The rung in force is an AUDIT fact and never a user-facing one (D14):
		// "you got the weaker credential" tells an attacker which targets are
		// softest and tells an honest user nothing they can act on.
		attrs = attrs.Set(logging.AttrCredentialRung, strconv.Itoa(access.Rung))
	}
	s.rec.Provisioning(fmt.Sprintf("target access provisioned by %s", method), attrs)
}

// recordEnforcement captures the enforcement rung the session actually stood
// on, per axis (contract v4, PLAN §6.5).
//
// It is a record of its own rather than four more attributes on the
// provisioning event because it answers a different question. The provisioning
// event says which credential got the proxy in; this says what bounds the
// session once it is in, on both axes, together with what was actually done to
// deliver it. A reviewer asking "what was this session allowed to run, and what
// could it reach" reads one record.
//
// The rung named here is the one IN FORCE. Everything that could have made it
// weaker than the route asked for has already failed the session by this point:
// a rung the target could not provide is an outage-class denial with nothing
// provisioned, never a downgrade.
func (s *session) recordEnforcement(access *target.ProvisionedAccess) {
	if access == nil || access.Enforcement == nil {
		return
	}
	e := access.Enforcement
	attrs := logging.EnforcementAttrs(logging.Attrs{}.Set(logging.AttrEvent, "enforcement.applied"), e)
	message := fmt.Sprintf("session enforcement: execution=%s reach=%s", e.Execution, e.Reach)
	if !e.Verified {
		// Said in the message and not only in a field: an attested rung is a
		// claim this system did not check, and a reader skimming messages must
		// not take it for one it did.
		message += " (attested, not verified by this proxy)"
	}
	s.rec.Provisioning(message, attrs)
}

// recordHostKey captures a target host key the proxy accepted (D7).
func (s *session) recordHostKey(key ssh.PublicKey, known bool) {
	message := "target host key trusted on first use"
	if known {
		message = "target host key recognised"
	}
	s.rec.HostKey(message, logging.Attrs{}.
		Set(logging.AttrHostKeyType, key.Type()).
		Set(logging.AttrHostKeyFingerprint, ssh.FingerprintSHA256(key)).
		SetBool(logging.AttrHostKeyKnown, known))
}

// recordChannel captures a channel the pipeline allowed, or the refusal it
// produced. A refusal is critical and therefore immediate (D8).
func (s *session) recordChannel(channelType string, dir channel.Direction, payload []byte, insp *channel.Inspection, d channel.Decision) {
	attrs := logging.Attrs{}.
		Set(logging.AttrChannelType, channelType).
		Set(logging.AttrDirection, dir.String()).
		Set(logging.AttrChannelID, insp.Info().ChannelID)
	// The destination is read from the payload rather than from the
	// inspection, because a REFUSED channel has no inspection — and a refused
	// forward is precisely the one whose destination has to be in the record
	// (D5a axis 3a).
	if channel.IsForwardChannel(channelType) {
		if fwd, err := channel.ParseForward(channelType, payload); err == nil {
			attrs.Set(logging.AttrForwardHost, fwd.Host).SetInt(logging.AttrForwardPort, fwd.Port)
		}
	}
	if d.Denied() {
		s.rec.Denied(fmt.Sprintf("channel %s refused", channelType), denialAttrs(attrs, d))
		return
	}
	s.rec.ChannelOpen(attrs)
}

// recordChannelClose captures the end of a channel.
func (s *session) recordChannelClose(insp *channel.Inspection, exitStatus int, haveStatus bool) {
	info := insp.Info()
	if info.ChannelID == "" {
		return
	}
	attrs := logging.Attrs{}.
		Set(logging.AttrChannelID, info.ChannelID).
		Set(logging.AttrChannelType, info.Type).
		Set(logging.AttrDirection, info.Opener.String())
	if haveStatus {
		attrs.Set(logging.AttrExitStatus, strconv.Itoa(exitStatus))
	}
	s.rec.ChannelClose(attrs)
}

// recordRequest captures one in-channel request and what policy said about it
// (D5a axis 2). This is where sftp becomes visible as itself, and where an exec
// command enters the record.
func (s *session) recordRequest(insp *channel.Inspection, req *ssh.Request, d channel.Decision) {
	info := insp.Info()
	attrs := logging.Attrs{}.
		Set(logging.AttrChannelID, info.ChannelID).
		Set(logging.AttrChannelType, info.Type).
		Set(logging.AttrDirection, channel.FromClient.String()).
		Set(logging.AttrRequest, req.Type).
		Set(logging.AttrScope, "channel")

	switch req.Type {
	case control.RequestExec:
		attrs.Set(logging.AttrCommand, execCommand(req.Payload))
	case control.RequestSubsystem:
		attrs.Set(logging.AttrSubsystem, subsystemName(req.Payload))
	case control.RequestPTY:
		// A pty is the replay header: everything captured on this channel after
		// it is terminal output of this size (PLAN §7).
		if term, width, height, ok := parsePTYRequest(req.Payload); ok {
			attrs.Set(logging.AttrTerm, term).SetInt(logging.AttrWidth, width).SetInt(logging.AttrHeight, height)
			s.rec.Stream(nil, s.srv.now(), logging.Attrs{}.
				Set(logging.AttrCapture, logging.CaptureHeader).
				Set(logging.AttrCaptureFormat, logging.CaptureFormatRawChunk).
				Set(logging.AttrChannelID, info.ChannelID).
				Set(logging.AttrChannelType, info.Type).
				Set(logging.AttrTerm, term).
				SetInt(logging.AttrWidth, width).
				SetInt(logging.AttrHeight, height))
		}
	}

	if d.Denied() {
		s.rec.Denied(fmt.Sprintf("request %s refused", req.Type), denialAttrs(attrs, d))
		return
	}
	s.rec.Request(fmt.Sprintf("request %s", req.Type), attrs)
}

// recordGlobalRequest captures a connection-level request and its decision
// (D5a axis 3b).
func (s *session) recordGlobalRequest(name string, denied bool, d channel.Decision) {
	attrs := logging.Attrs{}.
		Set(logging.AttrRequest, name).
		Set(logging.AttrScope, "connection")
	if denied {
		s.rec.Denied(fmt.Sprintf("global request %s refused", name), denialAttrs(attrs, d))
		return
	}
	s.rec.Request(fmt.Sprintf("global request %s", name), attrs)
}

// recordKill captures a session ended on someone else's orders — a revocation
// from Hoplock Control, a kill_session rule, a shutdown. It is critical, and
// therefore immediate: a session that is about to stop existing must not leave
// its last record in a batch.
func (s *session) recordKill(reason string) {
	s.rec.Denied("session terminated", logging.Attrs{}.
		Set(logging.AttrReason, reason).
		Set(logging.AttrAction, string(control.FilterActionKillSession)))
}

// recordFailure captures a setup failure, classified by the stage it happened
// in — the same classification the user's message is built from (PLAN §4.3).
func (s *session) recordFailure(err error) {
	var setupErr *setupError
	stage := ""
	if errors.As(err, &setupErr) {
		stage = string(setupErr.stage)
	}
	s.rec.Failure("session setup failed", logging.Attrs{}.
		Set(logging.AttrStage, stage).
		Set(logging.AttrError, err.Error()))
}

// recordEnd captures the close of a session.
func (s *session) recordEnd() {
	s.rec.End(logging.Attrs{}.Set(logging.AttrHopTrail, s.chain().Trail.String()))
}

// denialAttrs adds the decision's own fields to a record. Reason is what the
// user was shown; Detail is the operator's half and never reaches a terminal.
func denialAttrs(attrs logging.Attrs, d channel.Decision) logging.Attrs {
	return attrs.
		Set(logging.AttrAction, d.Action.String()).
		Set(logging.AttrReason, d.Reason).
		Set(logging.AttrDetail, d.Detail).
		Set(logging.AttrInspector, d.By)
}

// execCommand, subsystemName, and ptyRequest read the fields the record needs
// out of a request payload. They are lenient on purpose: a payload that does
// not parse is attacker-controlled input, and losing one attribute is better
// than losing the record it belongs to.
func execCommand(payload []byte) string {
	var msg struct{ Command string }
	if err := ssh.Unmarshal(payload, &msg); err != nil {
		return ""
	}
	return msg.Command
}

func subsystemName(payload []byte) string {
	var msg struct{ Subsystem string }
	if err := ssh.Unmarshal(payload, &msg); err != nil {
		return ""
	}
	return msg.Subsystem
}

func parsePTYRequest(payload []byte) (term string, width, height int, ok bool) {
	var msg struct {
		Term          string
		Columns, Rows uint32
		Width, Height uint32
		Modes         string
	}
	if err := ssh.Unmarshal(payload, &msg); err != nil {
		return "", 0, 0, false
	}
	return msg.Term, int(msg.Columns), int(msg.Rows), true
}
