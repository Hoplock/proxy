// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/auth/user"
	"github.com/hoplock/proxy/internal/control"
)

// This file owns everything the user is told after they have authenticated
// (PLAN §4.3). The rule itself is not implemented here: user.FailureMessageFor
// is the single implementation of the deny/outage split, and this file only
// decides which non-disclosing detail describes the failure at hand. Two copies
// of that rule would eventually disagree, and the branch that leaks is the one
// nobody is looking at.

// bannerPrefix marks a line as coming from the proxy rather than from the
// target's program, which is the difference between "your command printed
// this" and "your session was ended".
const bannerPrefix = "Hoplock Proxy: "

// exitProxyFailure is the exit status the proxy reports when it, rather
// than a program on the target, ended the channel. It is deliberately not 0
// (which would tell a script the command succeeded) and not 255 (which is what
// the SSH client itself reports for its own errors), so a non-zero status that
// came from the proxy is distinguishable in a pipeline.
//
// A session that reached its deadline reports exitSessionExpired instead, so
// "time ran out" is distinguishable from "policy stopped you" — see
// deadline.go.
const exitProxyFailure = 254

// stage names the part of session setup that failed. It exists to pick the
// user-facing detail: "the policy service is unavailable" is a lie when the
// target is simply down, and a user who is told the wrong thing raises the
// wrong ticket — which is what PLAN §4.3 exists to prevent.
type stage string

const (
	stageIdentity  stage = "identity"
	stageUsername  stage = "username"
	stageAuthorize stage = "authorize"
	stageRoute     stage = "route"
	stageProvision stage = "provision"
	stageDial      stage = "dial"
	// stageTargetAuth is the target refusing the proxy's OWN credential, and it
	// is separate from stageDial because the two send an operator to opposite
	// places. The host answered, the handshake reached authentication, and what
	// failed is a credential this proxy holds — reported as a dial failure it
	// reads as a network fault, which is the one thing that is working
	// (prompt 0025).
	stageTargetAuth stage = "target-auth"
	// stageTargetWithheld is that credential having been refused often enough
	// that the proxy has stopped offering it. It is deliberately its own stage
	// rather than a flavour of the one above: "we tried just now and were
	// refused" and "we are not currently trying" are different facts about the
	// estate, and only the second one explains why nothing appears in the
	// target's logs.
	stageTargetWithheld stage = "target-auth-withheld"
	stageHop            stage = "hop"
	stageHopDial        stage = "hop-dial"
	stageRelay          stage = "relay"
	stageHostKey        stage = "hostkey"
	stageChannel        stage = "channel"
)

// setupError is a session-setup failure tagged with the stage it happened in.
// It wraps the underlying error, so control.IsUnauthorized — and therefore the
// deny/outage split — still classifies it after the tagging.
type setupError struct {
	stage stage
	err   error
}

func (e *setupError) Error() string { return string(e.stage) + ": " + e.err.Error() }

// Unwrap keeps the cause reachable for errors.Is, which is what decides whether
// the user sees a denial or an outage.
func (e *setupError) Unwrap() error { return e.err }

// outageDetail describes a failure in terms safe to show anyone.
//
// None of these name the target, say whether it exists, or reveal which policy
// applied: the split is deny-versus-outage, and an outage message that leaked
// estate details would just be a slower oracle.
func outageDetail(err error) string {
	var se *setupError
	if !errors.As(err, &se) {
		return user.OutageDetailPolicyService
	}
	switch se.stage {
	case stageAuthorize, stageIdentity:
		return user.OutageDetailPolicyService
	case stageUsername:
		return "the connection did not name a target the proxy could read"
	case stageRoute:
		return "reaching this target needs a route this proxy cannot serve yet"
	case stageProvision:
		return "credentials for the target could not be provisioned"
	case stageDial:
		return "the target could not be reached"
	case stageTargetAuth:
		// Says which SIDE the credential belongs to and nothing else. Not the
		// method, not the reference, not the account, and not whether the
		// target exists — a user who could learn which credential was refused
		// could map the estate one refused session at a time (PLAN §4.3). What
		// it does say is the part that is actionable for whoever reads the
		// ticket: this is the proxy's credential, so it is not the user's to
		// fix and a different key of theirs will not help.
		return "the proxy's own credential for this target was refused"
	case stageTargetWithheld:
		// The same non-disclosure, plus the one thing that distinguishes it:
		// nothing was attempted. An operator who reads "refused" and finds no
		// matching entry in the target's log is looking for a bug; this wording
		// tells them there is nothing to find.
		return "the proxy's own credential for this target was refused repeatedly, so it is not attempting the connection at present"
	case stageHop:
		// Deliberately vague about WHY the chain could not be extended: a loop,
		// an exceeded hop count, and a missing chain key are all faults in the
		// estate's own routing, and the operator reads them in the audit log
		// against the session id the user is given (PLAN §4.3).
		return "the chain of proxies to this target could not be extended"
	case stageHopDial:
		return "the next proxy in the chain could not be reached"
	case stageRelay:
		// Named separately from a dial failure because the fix is different:
		// nothing is unreachable, the next proxy is simply not connected to
		// this one, and that is what an operator needs to be told.
		return "the next proxy in the chain is not currently connected"
	case stageHostKey:
		return "the target's host key was not accepted"
	case stageChannel:
		return "the target refused to open the session"
	default:
		return user.OutageDetailPolicyService
	}
}

// failureText renders what the user is shown for a failed session.
func (s *session) failureText(err error) string {
	return user.FailureMessageFor(err, outageDetail(err), s.id)
}

// usernameHelp explains the one failure the user can actually fix themselves.
// It is appended to the malformed-username message because the encoded target
// is this proxy's own convention (D1) and a user who typed a bare hostname
// has no way to guess it. It discloses nothing: the delimiter is in the
// client-side configuration they were given.
func (s *session) usernameHelp() string {
	return fmt.Sprintf("%sConnect as \"login%starget\", for example \"alice%sserver.example.com\".",
		bannerPrefix, s.srv.delimiter, s.srv.delimiter)
}

// connectingText is the progress line written while the target leg is coming
// up. It names the target because the user typed it: repeating it back reveals
// nothing they did not already know, and it is what makes a slow connection
// legible instead of looking like a hang.
func connectingText(target string) string {
	return bannerPrefix + "connecting to " + target + "..."
}

// deniedText renders a pipeline denial for the user: the generic denial from
// PLAN §4.3, followed by the clause internal/channel supplied for what was
// refused.
//
// The split is the point. The deny/outage rule has one implementation
// (user.FailureMessageFor and DenyMessage); the pipeline contributes only the
// clause naming the thing the client asked for, and never the permitted set —
// which would let a client map the policy one probe at a time.
func deniedText(reason string) string {
	if reason == "" {
		return user.DenyMessage
	}
	return user.DenyMessage + " " + reason
}

// noticeText renders a notice attached to an event that was allowed: a warning
// about a command that is about to run, rather than a refusal.
//
// It carries the proxy's own prefix because that is the whole point of a
// warning — the user has to be able to tell a line the proxy wrote from output
// of the command they ran.
func noticeText(notice string) string {
	return bannerPrefix + notice
}

// deadlineWarningText warns that the session is about to reach its deadline.
//
// PLAN §4.3 splits what a user is told into a denial and an outage, and this is
// neither: nothing was refused and nothing is broken. It therefore gets its own
// wording, and the wording is the deliverable — a session that vanished at its
// deadline with an outage message would send its user to file a ticket against
// a service that did exactly what it was asked to.
//
// It discloses only the time left. Not the policy, not who set the deadline,
// not how long the route allows — a user learning "you were given four hours"
// learns the shape of the policy one session at a time (§4.3).
func deadlineWarningText(remaining time.Duration) string {
	if remaining < time.Second {
		remaining = time.Second
	}
	return fmt.Sprintf("%sThis session reaches its authorized end in %s and will then be closed. "+
		"Finish up and save your work; reconnecting starts a new session.",
		bannerPrefix, remaining.Round(time.Second))
}

// deadlineExpiredText is what the user is told as the session ends.
//
// Three things and nothing else: that the session reached its authorized end —
// which is a statement about time, not about permission — that reconnecting is
// the remedy, which is true here and is the opposite of what an outage message
// says, and the session id as the support reference §4.3 promises everywhere
// else. It names no policy and no target.
func deadlineExpiredText(sessionID string) string {
	text := bannerPrefix + "This session has reached its authorized end and is now closing. " +
		"Nothing is wrong and nothing was denied; reconnect to start a new session."
	if sessionID != "" {
		text += fmt.Sprintf(" Session %s.", sessionID)
	}
	return text
}

// deniedChannelReason is the clause for a channel refused before the pipeline
// could speak for itself. It exists only for the unreachable nil-pipeline
// guard: with a pipeline, every clause comes from internal/channel.
func deniedChannelReason(channelType string) string {
	return "Channel type " + channelType + " is not available on this session."
}

// errChannelNotPermitted is the allow-list refusing a channel. It wraps the
// management client's deny sentinel because that is exactly what it is — the
// server's decision, arriving in the authorize response rather than in a 401 —
// so it renders as the same generic denial as every other policy answer.
func errChannelNotPermitted(channelType string) error {
	return fmt.Errorf("channel type %q is not permitted by policy: %w", channelType, control.ErrUnauthorized)
}

// failChannel reports a setup failure on an already-open session channel and
// ends it: stderr, a non-zero exit status, then a clean close (PLAN §4.3).
func (s *session) failChannel(ch ssh.Channel, queued []*ssh.Request, err error) {
	// Answer the requests that were waiting. Replying false would make the
	// client print its own generic "request failed" instead of the reason that
	// is about to arrive on stderr, so they are acknowledged and answered by
	// the exit status below.
	for _, req := range queued {
		if req.WantReply {
			_ = req.Reply(true, nil)
		}
	}

	writeUser(ch, s.failureText(err))
	if failedAt(err, stageUsername) {
		writeUser(ch, s.usernameHelp())
	}
	sendExitStatus(ch, exitProxyFailure)
	_ = ch.Close()
	s.failureDelivered()
}

// rejectChannel refuses a channel the engine could not open, carrying the
// reason in the rejection message — the only place there is to say anything
// when the channel itself never came into existence.
func (s *session) rejectChannel(nc ssh.NewChannel, reason ssh.RejectionReason, err error) {
	_ = nc.Reject(reason, s.failureText(err))
	s.failureDelivered()
}

// writeUser writes one line of proxy-authored text to a channel's stderr.
//
// stderr, never stdout: a session's stdout belongs to the program the user ran,
// and scp and sftp parse it as a protocol. Lines end CRLF because a channel
// with a pty is in raw mode, where a bare LF steps down without returning to
// column zero.
func writeUser(ch ssh.Channel, text string) {
	writeUserTo(ch.Stderr(), text)
}

func writeUserTo(w io.Writer, text string) {
	_, _ = io.WriteString(w, text+"\r\n")
}

// sendExitStatus ends a channel with an exit status, so a script sees a failure
// rather than an empty success.
func sendExitStatus(ch ssh.Channel, status uint32) {
	payload := ssh.Marshal(struct{ Status uint32 }{Status: status})
	_, _ = ch.SendRequest(requestExitStatus, false, payload)
}

// failedAt reports whether err came from the named setup stage.
func failedAt(err error, want stage) bool {
	var se *setupError
	return errors.As(err, &se) && se.stage == want
}
