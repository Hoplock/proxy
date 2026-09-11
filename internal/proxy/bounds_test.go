// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/auth/user"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/logging"
	"github.com/hoplock/proxy/internal/sshtest"
)

// The three session bounds that are not the deadline (contract v4, D16,
// PLAN §6.5, bounds.go). Each one is tested against the class PLAN §4.3 puts it
// in, because the class is the deliverable: a capture refusal that read as a
// denial would send a user to ask for permissions they already have, and a
// concurrency refusal that read as an outage would tell them the estate is
// broken when it is simply busy.

// --- require_session_capture -------------------------------------------------

// noRecorder builds the proxy without a telemetry pipeline, which is the only
// way to have no logging path at all: with a pipeline there is a disk buffer,
// and a disk buffer is a logging path (PLAN §7).
func noRecorder(o *Options) { o.Recorder = nil }

// TestARouteThatMustBeRecordedIsRefusedAsAnOutageWhenNothingCanRecord is the
// capture bound's refusal, in the class it belongs to.
//
// Outage, not denial: the user asked for nothing they are not allowed, the estate
// cannot record, and no other credential of theirs would change the answer. So
// the message says plainly that this is not a permissions problem and carries the
// session id as the support reference §4.3 promises.
func TestARouteThatMustBeRecordedIsRefusedAsAnOutageWhenNothingCanRecord(t *testing.T) {
	h := newHarness(t, harnessOptions{
		requireSessionCapture: true,
		options:               noRecorder,
	})

	text, status := runAndCollect(t, h, "uptime")

	if strings.Contains(text, user.DenyMessage) {
		t.Errorf("user saw %q, which reads as a denial; an unrecordable session is an outage", text)
	}
	if !strings.Contains(text, "not a permissions problem") {
		t.Errorf("user saw %q, want it to say this is not a permissions problem", text)
	}
	if !strings.Contains(text, testSessionID) {
		t.Errorf("user saw %q, want the session id as a support reference", text)
	}
	if status == 0 {
		t.Error("a refused session exited 0; a failure must not look like success")
	}
	// Checked before the target leg is dialled (PLAN §6.5): a session that
	// reached the target and then failed this check has already happened, which
	// is what the bound exists to prevent.
	if logins := h.target.Logins(); len(logins) != 0 {
		t.Errorf("the target was logged into as %v; the check must run before the target leg", logins)
	}
}

// TestARouteThatMustBeRecordedRunsWhileOnlyTheNetworkIsDown is the other half,
// and the one the bound would be wrong without.
//
// PLAN §7's buffer is a RESILIENCE path, not a degraded mode. A proxy spooling to
// disk while Hoplock Control is unreachable is recording, so refusing its
// sessions would be failing closed against the wrong failure — and would turn
// every Control outage into an outage of the estate for exactly the routes that
// are watched most closely.
func TestARouteThatMustBeRecordedRunsWhileOnlyTheNetworkIsDown(t *testing.T) {
	h := newHarness(t, harnessOptions{requireSessionCapture: true})
	// Both log endpoints refuse from here on. The shipper's disk buffer keeps
	// what it cannot deliver, which is what Deliverable reports on.
	h.client.ingestDown.Store(true)

	text, status := runAndCollect(t, h, "uptime")

	if status != 0 {
		t.Errorf("the session failed with %q (exit %d); a buffering proxy satisfies the capture bound", text, status)
	}
	if strings.Contains(text, "could not be recorded") {
		t.Errorf("user saw %q; the session WAS recorded, to disk", text)
	}
	if logins := h.target.Logins(); len(logins) != 1 {
		t.Errorf("the target was logged into as %v, want exactly one login", logins)
	}
}

// TestARouteWithoutTheCaptureBoundIsUnaffected keeps the absent-value default
// honest: a v3 server's route on a proxy with no pipeline at all behaves exactly
// as it did before this phase.
func TestARouteWithoutTheCaptureBoundIsUnaffected(t *testing.T) {
	h := newHarness(t, harnessOptions{options: noRecorder})

	text, status := runAndCollect(t, h, "uptime")

	if status != 0 {
		t.Errorf("an unbounded route failed with %q (exit %d) on a proxy that records nothing", text, status)
	}
}

// --- concurrency -------------------------------------------------------------

// capped builds a harness whose route carries the two ceilings, with unique
// session ids because more than one session is live at a time.
func capped(t *testing.T, perSubject, perTarget int) *harness {
	t.Helper()
	return newHarness(t, harnessOptions{
		concurrency: &control.ConcurrencyLimits{PerSubject: perSubject, PerTarget: perTarget},
		options:     uniqueSessionIDs,
	})
}

// holdOneSession opens a session that stays up and returns the CLIENT
// connection, because ending a session means ending that: closing the SSH
// session closes a channel, and the proxy session — and therefore its
// concurrency slot — lives as long as the connection does.
//
// It waits for the session to be ADMITTED rather than merely registered: a
// session enters the engine's registry at the handshake, long before it has been
// counted against anything, and a test that raced that would be asserting about
// the wrong moment.
func holdOneSession(t *testing.T, h *harness) *ssh.Client {
	t.Helper()
	before := h.server.liveSessions()
	client := h.mustDial(h.username())
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}
	if _, err := io.WriteString(stdin, "ping\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitFor(t, func() bool { return h.server.liveSessions() > before }, "the held session to be admitted")
	return client
}

// TestASubjectAtItsCeilingIsDeniedAndTheRecordNamesTheCap is the concurrency
// bound's headline claim, and the disclosure half is as much of it as the
// counting half: exceeding a cap is a POLICY DENIAL (PLAN §4.3, D16), so the user
// is told "access denied" and nothing else, and the cap that was hit exists only
// on the audit record.
func TestASubjectAtItsCeilingIsDeniedAndTheRecordNamesTheCap(t *testing.T) {
	h := capped(t, 1, 0)
	held := holdOneSession(t, h)
	defer func() { _ = held.Close() }()

	text, status := runAndCollect(t, h, "uptime")

	if !strings.Contains(text, user.DenyMessage) {
		t.Errorf("user saw %q, want the generic denial %q", text, user.DenyMessage)
	}
	if strings.Contains(text, "not a permissions problem") {
		t.Errorf("user saw %q, which reads as an outage; a full ceiling is the estate answering no", text)
	}
	// Nothing about the cap, how many sessions are live, or whose they are: a
	// user who learns "you are at your limit of 1" learns the policy, and one who
	// learns the TARGET is full learns that the target exists.
	for _, leak := range []string{"ceiling", "concurren", "limit", "1 live", h.targetName()} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(leak)) {
			t.Errorf("denial text %q discloses %q", text, leak)
		}
	}
	if status == 0 {
		t.Error("a denied session exited 0; a denial must not look like success")
	}

	rec, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Attributes[logging.AttrEvent] == "session.concurrency_exceeded"
	})
	if !ok {
		t.Fatalf("no record names the ceiling that refused the session; the record is the only place it exists")
	}
	for key, want := range map[string]string{
		logging.AttrConcurrencyScope: "subject",
		logging.AttrConcurrencyLimit: "1",
		logging.AttrConcurrencyLive:  "1",
	} {
		if got := rec.Attributes[key]; got != want {
			t.Errorf("the refusal record carries %s=%q, want %q", key, got, want)
		}
	}
	if rec.Kind != control.LogKindPolicyDecision {
		t.Errorf("the refusal was recorded as %s, want %s: it is a policy answer, not a fault",
			rec.Kind, control.LogKindPolicyDecision)
	}
	if !recordedOnPriorityPath(h, rec.RecordID) {
		t.Error("the refusal waited in a batch; a refusal takes D8's immediate path")
	}
}

// TestAnEndedSessionFreesItsSlot is the other half of a ceiling: a cap that never
// gave a slot back would turn the first N connections of a proxy's life into its
// only ones.
func TestAnEndedSessionFreesItsSlot(t *testing.T) {
	h := capped(t, 1, 0)
	held := holdOneSession(t, h)

	if _, status := runAndCollect(t, h, "uptime"); status == 0 {
		t.Fatal("a second session succeeded while the subject was at its ceiling of one")
	}

	// Closing the client's connection is the ordinary ending, and teardown is
	// asynchronous: the slot is freed where the session leaves the registry.
	_ = held.Close()
	waitFor(t, func() bool { return h.server.liveSessions() == 0 }, "the held session to free its slot")

	if text, status := runAndCollect(t, h, "uptime"); status != 0 {
		t.Errorf("the next session was refused with %q (exit %d) after the slot was freed", text, status)
	}
}

// TestATargetAtItsCeilingIsDeniedAcrossSubjects is the second scope, which is
// not reachable through the first: the subject here is under its own cap and is
// refused anyway, because what is full is the target.
func TestATargetAtItsCeilingIsDeniedAcrossSubjects(t *testing.T) {
	h := capped(t, 0, 1)
	held := holdOneSession(t, h)
	defer func() { _ = held.Close() }()

	// A different login is a different subject (fakeClient.AuthenticateCert), and
	// it has no session of its own anywhere.
	other := "bob" + testDelimiter + h.targetName()
	text, status := runAndCollectAs(t, h, other, "uptime")

	if !strings.Contains(text, user.DenyMessage) {
		t.Errorf("user saw %q, want the generic denial", text)
	}
	if status == 0 {
		t.Error("a second subject reached a target that was at its ceiling")
	}
	rec, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Attributes[logging.AttrConcurrencyScope] == "target"
	})
	if !ok {
		t.Fatal("no record names the per-target ceiling")
	}
	if got := rec.Attributes[logging.AttrConcurrencyLimit]; got != "1" {
		t.Errorf("the refusal record carries a limit of %q, want 1", got)
	}
	if rec.Subject != "bob"+subjectDomain {
		t.Errorf("the refusal is attributed to %q, want the subject that was refused", rec.Subject)
	}
}

// TestAnUncappedRouteIsCountedButNeverRefused states what "uncapped" means on
// both sides. A route with no ceilings refuses nothing — and its sessions are
// still counted, because a cap counts the sessions a proxy holds and not the ones
// that happen to carry a cap of their own.
func TestAnUncappedRouteIsCountedButNeverRefused(t *testing.T) {
	h := newHarness(t, harnessOptions{options: uniqueSessionIDs})
	held := holdOneSession(t, h)
	defer func() { _ = held.Close() }()

	if text, status := runAndCollect(t, h, "uptime"); status != 0 {
		t.Errorf("an uncapped route refused a second session with %q (exit %d)", text, status)
	}
	if got := h.server.liveSessions(); got == 0 {
		t.Error("an uncapped session occupies no slot; a capped session beside it would count nothing")
	}
}

// TestTwoSessionsArrivingTogetherCannotBothTakeTheLastSlot is the only
// interesting way a ceiling can be wrong: the count and the admission have to be
// one critical section, or two sessions each see the other as absent.
//
// The overlap is made CERTAIN rather than likely. The stand-in target blocks
// inside the exec it was handed until this test releases it, so whichever
// attempt wins the slot is provably still holding it while the other five are
// answered — an earlier version of this test raced six clients against a session
// that had already finished (the fake target runs no command and returns at
// once), which admitted two of them for entirely correct reasons.
func TestTwoSessionsArrivingTogetherCannotBothTakeTheLastSlot(t *testing.T) {
	const attempts = 6
	reached := make(chan string, attempts)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseAll)

	h := newHarness(t, harnessOptions{
		concurrency: &control.ConcurrencyLimits{PerSubject: 1},
		options:     uniqueSessionIDs,
		targetOptions: sshtest.Options{Exec: func(command string) ([]byte, []byte, uint32) {
			reached <- command
			<-release
			return nil, nil, 0
		}},
	})

	type outcome struct {
		text   string
		status int
	}
	results := make(chan outcome, attempts)
	for range attempts {
		go func() {
			text, status := runAndCollect(t, h, "uptime")
			results <- outcome{text: text, status: status}
		}()
	}

	// One attempt is through to the target and is holding the only slot. Every
	// answer below is therefore an answer given while it was live.
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("no session reached the target; the ceiling was never under contention")
	}

	for refused := 0; refused < attempts-1; refused++ {
		select {
		case got := <-results:
			if got.status == 0 {
				t.Fatalf("a second session was admitted past a ceiling of one: %q", got.text)
			}
			if !strings.Contains(got.text, user.DenyMessage) {
				t.Errorf("a refused attempt was told %q, want the generic denial", got.text)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of %d overlapping attempts were refused; the rest are still "+
				"running, which means they were admitted past a ceiling of one", refused, attempts-1)
		}
	}

	releaseAll()
	select {
	case got := <-results:
		if got.status != 0 {
			t.Errorf("the admitted session failed with %q (exit %d)", got.text, got.status)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the admitted session never finished")
	}
	if extra := len(reached); extra != 0 {
		t.Errorf("%d sessions reached the target under a ceiling of one, want 1", extra+1)
	}
}

// TestAChainedSessionIsCountedOnThisProxyToo is the decision D16 leaves to the
// implementation, stated as a test: a cap is counted on EVERY proxy a session
// traverses, because the registry a proxy counts against is its own (PLAN §6.5).
//
// So a next-hop session is admitted, counted and refusable exactly like a direct
// one, and the consequence is that a cap of N is N sessions HERE rather than an
// estate-wide ceiling. The refusal below happens before the route types diverge,
// which is what the absence of the hop machinery's own message proves.
func TestAChainedSessionIsCountedOnThisProxyToo(t *testing.T) {
	h := capped(t, 1, 0)
	// The first session takes the only slot on a direct route; the second is
	// answered with a chain leg to a proxy that does not exist, so if the cap
	// were not counted first the hop would be attempted and say so.
	var answered atomic.Int32
	h.client.authorize = func(*control.AuthorizeRequest) (*control.AuthorizeResponse, error) {
		host, port := h.targetHostPort()
		resp := &control.AuthorizeResponse{
			RouteType:         control.RouteTypeDirect,
			Target:            host,
			TargetPort:        port,
			Permissions:       "testGroup",
			PermittedChannels: []string{channelSession},
			FilterPolicy:      control.FilterPolicy{Mode: control.FilterModeBlacklist},
			Concurrency:       &control.ConcurrencyLimits{PerSubject: 1},
			DecisionID:        "decision-1",
		}
		if answered.Add(1) > 1 {
			resp.RouteType = control.RouteTypeNextHop
			resp.Target = "next-proxy.invalid"
			resp.Hop = &control.HopMetadata{
				Connection:  control.HopConnectionRelay,
				NextProxyID: "proxy-enclave",
				FinalTarget: "deep.internal.example.com",
			}
		}
		return resp, nil
	}

	held := holdOneSession(t, h)
	defer func() { _ = held.Close() }()

	text, status := runAndCollect(t, h, "uptime")

	if !strings.Contains(text, user.DenyMessage) {
		t.Errorf("user saw %q, want the chain leg refused by the ceiling", text)
	}
	if status == 0 {
		t.Error("a chained session was admitted past a full ceiling")
	}
	// The hop was never attempted: the cap is counted before the route types
	// diverge, exactly as the deadline is armed for both of them.
	if strings.Contains(text, "not currently connected") || strings.Contains(text, "chain") {
		t.Errorf("user saw %q; the hop machinery ran before the ceiling was counted", text)
	}
}

// --- grant_context -----------------------------------------------------------

// TestTheGrantContextIsOnTheSessionsRecordsAndNowhereElse is D16's third bound,
// which refuses nothing and is therefore only ever right or wrong about two
// things: that it reaches the records intact, and that it reaches the user never.
func TestTheGrantContextIsOnTheSessionsRecordsAndNowhereElse(t *testing.T) {
	window := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	h := newHarness(t, harnessOptions{grantContext: &control.GrantContext{
		System:      "change-management",
		Reference:   "CHG-1234",
		WindowStart: &window,
		Additional:  &control.AdditionalContext{Text: "approved by the Tuesday CAB"},
	}})

	text, status := runAndCollect(t, h, "uptime")
	if status != 0 {
		t.Fatalf("the session failed with %q (exit %d); a grant context decides nothing", text, status)
	}
	// Never shown to the user, on any path: the grant context is about the
	// estate's reasons, not about the user's own request, and a denial stays
	// vague (PLAN §4.3).
	for _, secret := range []string{"change-management", "CHG-1234", "Tuesday CAB"} {
		if strings.Contains(text, secret) {
			t.Errorf("the user was shown %q out of the grant context:\n%s", secret, text)
		}
	}

	// Every record the session made after the decision carries it. The records
	// before the decision — the handshake's and the authentication's — carry
	// less, because nothing knew it yet.
	var carried, checked int
	for _, rec := range h.records() {
		if rec.Kind == control.LogKindSessionStart || rec.Kind == control.LogKindAuth {
			continue
		}
		checked++
		if rec.Attributes[logging.AttrGrantReference] != "CHG-1234" ||
			rec.Attributes[logging.AttrGrantSystem] != "change-management" ||
			rec.Attributes[logging.AttrGrantWindowStart] != "2026-03-01T09:00:00Z" ||
			rec.Attributes[logging.AttrGrantAdditional] != "approved by the Tuesday CAB" {
			t.Errorf("%s record does not carry the grant context verbatim: %v", rec.Kind, rec.Attributes)
			continue
		}
		carried++
	}
	if checked == 0 || carried != checked {
		t.Errorf("%d of %d records after the decision carry the grant context", carried, checked)
	}
}

// TestTheObjectFormOfAdditionalContextSurvivesTheEngine is the same claim for
// the other shape the field takes. It is here as well as in internal/logging
// because the route is what carries it across the engine, and a field that
// arrived as an object must not reach a record as one flattened string.
func TestTheObjectFormOfAdditionalContextSurvivesTheEngine(t *testing.T) {
	h := newHarness(t, harnessOptions{grantContext: &control.GrantContext{
		System: "scanner",
		Additional: &control.AdditionalContext{Fields: map[string]any{
			"scan_id":  "s-99",
			"severity": float64(7),
		}},
	}})

	if text, status := runAndCollect(t, h, "uptime"); status != 0 {
		t.Fatalf("the session failed with %q (exit %d)", text, status)
	}

	rec := h.recordOfKind(control.LogKindAuthorize)
	for key, want := range map[string]string{
		logging.AttrGrantAdditionalPrefix + "scan_id":  "s-99",
		logging.AttrGrantAdditionalPrefix + "severity": "7",
	} {
		if got := rec.Attributes[key]; got != want {
			t.Errorf("the authorize record carries %s=%q, want %q", key, got, want)
		}
	}
	if _, ok := rec.Attributes[logging.AttrGrantAdditional]; ok {
		t.Error("the object form also arrived as the string form; a reader cannot tell which the server sent")
	}
}

// TestTheBoundsAreOnTheAuthorizeRecord keeps the two bounds that can refuse a
// session visible on the sessions they did NOT refuse. A session that ran under a
// ceiling of two is a different fact from one that ran under none, and only the
// record can say which.
func TestTheBoundsAreOnTheAuthorizeRecord(t *testing.T) {
	h := newHarness(t, harnessOptions{
		requireSessionCapture: true,
		concurrency:           &control.ConcurrencyLimits{PerSubject: 2, PerTarget: 3},
	})

	if text, status := runAndCollect(t, h, "uptime"); status != 0 {
		t.Fatalf("the session failed with %q (exit %d)", text, status)
	}

	rec := h.recordOfKind(control.LogKindAuthorize)
	for key, want := range map[string]string{
		logging.AttrCaptureRequired:         "true",
		logging.AttrConcurrencyLimitSubject: "2",
		logging.AttrConcurrencyLimitTarget:  "3",
	} {
		if got := rec.Attributes[key]; got != want {
			t.Errorf("the authorize record carries %s=%q, want %q", key, got, want)
		}
	}
}
