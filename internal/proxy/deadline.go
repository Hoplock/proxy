// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/logging"
)

// This file enforces the route's session deadline (contract v4, D16, PLAN
// §6.5). A route carries three lifetimes and they bound three different things.
// Two of them are NOT this one, and the difference is the reason this file
// exists:
//
//   - `lifetime_seconds` is an AUTHENTICATION bound. It becomes OpenSSH's
//     `expiry-time` restriction in the ephemeral account's `authorized_keys`
//     (PLAN §5.1), so it stops the key opening a NEW connection. It does not
//     end an established session.
//   - `CacheHint.ttl_seconds` bounds decision REUSE (PLAN §6.4) — how long this
//     proxy may serve another connection from a decision it already has. It
//     says nothing about how long any session runs.
//
// So before this phase an established session had no upper bound at all except
// revocation (§6.4), and revocation needs the event stream to be up — which is
// exactly when an immortal privileged session is least acceptable. That is the
// hole `session_deadline` describes and the timer below closes. Do not
// "simplify" it into either of the two lifetimes above.
//
// The timer is LOCAL: nothing here asks Hoplock Control anything, so it holds
// with Control unreachable. Expiry ends the session through the engine's normal
// teardown — the same path a user's own close takes — so credential removal,
// the reaper's bookkeeping, and the telemetry flush all behave identically.

// DefaultDeadlineWarning is how long before the deadline the user is warned.
//
// A minute is chosen to be actionable rather than tidy: it is long enough to
// finish a sentence in an editor, write a file out, or let a short command
// complete, and short enough that a person who has stepped away does not come
// back to a warning that has scrolled past. Deployments that want a different
// lead time set `session.deadline_warning`; a negative value turns the warning
// off entirely.
const DefaultDeadlineWarning = time.Minute

// exitSessionExpired is the exit status a channel ends with when the session
// reached its deadline.
//
// It is deliberately distinct from exitProxyFailure (254): a script that was cut
// short because its session ran out of time did not fail policy, and an operator
// reading a pipeline's exit status should not have to guess which happened. Not
// 0 (that would report success), not 255 (the SSH client's own code).
const exitSessionExpired = 253

// armDeadline starts this session's local deadline timer.
//
// It is called from setup with the deadline the chain resolved — the earlier of
// what this hop's authorize returned and what the session arrived carrying — so
// on a chained route every hop ends on the same instant and no hop can extend
// one (routing.ShortenDeadline).
//
// No deadline means no timer: absent is not zero (contract v4), and a session
// the server set no bound on is left unbounded exactly as a v3 server left it.
func (s *session) armDeadline(deadline *time.Time) {
	if deadline == nil {
		return
	}
	at := *deadline

	// A lead time longer than the session's whole deadline warns nobody rather
	// than warning at once. It is PLAN §4.3's rule about explaining too early:
	// a message written before the client has opened a channel and asked for
	// something goes into a stream nobody is reading, so an immediate "warning"
	// is indistinguishable from no warning at all. The expiry message still
	// arrives, and it is the one §4.3 actually requires.
	lead := s.srv.deadlineWarning
	warnAt := at.Add(-lead)
	warn := lead > 0 && warnAt.After(s.srv.now())
	s.logf("proxy: session=%s deadline armed at=%s in=%s warn_at=%s",
		s.id, at.UTC().Format(time.RFC3339), at.Sub(s.srv.now()).Round(time.Second),
		warnAtText(warn, warnAt))

	go func() {
		defer s.recoverPanic("session deadline")
		if warn {
			if !s.waitUntil(warnAt) {
				return
			}
			s.warnDeadline(at)
		}
		if !s.waitUntil(at) {
			return
		}
		s.expire(at)
	}()
}

// waitUntil sleeps until an instant, reporting false if the session ended first.
//
// The remaining time is measured against the server's clock rather than counted
// down from arming, so a deadline is an instant throughout: the same value this
// hop declared to the next one is the value it waits for itself.
func (s *session) waitUntil(at time.Time) bool {
	d := at.Sub(s.srv.now())
	if d <= 0 {
		return true
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-s.ctx.Done():
		return false
	}
}

// warnDeadline tells the user their session is about to end, while they can
// still do something about it.
//
// A session with no channel open is told nothing — there is nowhere to write —
// which is the limitation PLAN §4.3 already records for a client that opens no
// channel, not a new one.
func (s *session) warnDeadline(at time.Time) {
	channels := s.openChannels()
	if len(channels) == 0 {
		return
	}
	remaining := at.Sub(s.srv.now())
	text := deadlineWarningText(remaining)
	for _, ch := range channels {
		writeUser(ch, text)
	}
	s.logf("proxy: session=%s deadline warning delivered channels=%d remaining=%s",
		s.id, len(channels), remaining.Round(time.Second))
}

// expire ends the session because it reached its deadline.
//
// It is kill's sibling and deliberately not kill itself: what the user is told
// differs, the exit status differs, and the telemetry differs, because an
// expiry is neither a denial nor an outage nor a revocation — it is a session
// ending exactly as it was authorized to (PLAN §4.3). What it shares with kill
// is the ending: channels closed, the client connection closed, and then the
// engine's ordinary teardown in session.close.
func (s *session) expire(at time.Time) {
	s.mu.Lock()
	if s.killed {
		// Already ending on someone else's orders. Whoever got here first owns
		// the explanation; a second one would contradict it.
		s.mu.Unlock()
		return
	}
	s.killed = true
	s.endedBy = logging.EndReasonDeadline
	channels := s.channelsLocked()
	s.mu.Unlock()

	s.logf("proxy: session=%s deadline reached at=%s overshoot=%s channels=%d",
		s.id, at.UTC().Format(time.RFC3339), s.srv.now().Sub(at).Round(time.Millisecond), len(channels))
	s.recordDeadlineExpiry(at)

	text := deadlineExpiredText(s.id)
	for _, ch := range channels {
		writeUser(ch, text)
		sendExitStatus(ch, exitSessionExpired)
		_ = ch.Close()
	}
	// Let the client read the exit status and hang up before the connection
	// goes. Unlike a policy kill, the status here is the point — it is what
	// distinguishes an expiry from every other ending in a pipeline — and
	// pulling the socket out from under a client that has not read it yet
	// would waste it.
	if len(channels) > 0 {
		s.lingerUntilClosed()
	}
	s.disconnect(text)
}

// openChannels is the session's currently open channels.
func (s *session) openChannels() []ssh.Channel {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.channelsLocked()
}

func (s *session) channelsLocked() []ssh.Channel {
	channels := make([]ssh.Channel, 0, len(s.channels))
	for ch := range s.channels {
		channels = append(channels, ch)
	}
	return channels
}

// warnAtText renders the warning instant for the arming log line, saying so
// when there will be no warning at all.
func warnAtText(warn bool, at time.Time) string {
	if !warn {
		return "never"
	}
	return at.UTC().Format(time.RFC3339)
}
