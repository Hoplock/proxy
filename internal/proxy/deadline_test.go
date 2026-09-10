// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/auth/target"
	"github.com/hoplock/proxy/internal/auth/user"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/identity"
	"github.com/hoplock/proxy/internal/logging"
	"github.com/hoplock/proxy/internal/routing"
	"github.com/hoplock/proxy/internal/sshtest"
)

// The deadlines here are short on purpose. They are real durations rather than
// a faked clock because what is under test is the engine's own timer and the
// order the user is told things in, and a fake clock would prove neither.

const (
	testDeadline = 500 * time.Millisecond
	testWarning  = 250 * time.Millisecond
)

// heldSession opens a shell through the proxy and returns it once the target
// leg is definitely up, so a deadline cannot be raced by session setup.
func heldSession(t *testing.T, h *harness) (*ssh.Session, *syncBuffer) {
	t.Helper()
	client := h.mustDial(h.username())

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	stderr := &syncBuffer{}
	session.Stderr = stderr
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
	waitFor(t, func() bool { return len(h.server.Sessions()) == 1 }, "the session to register")
	return session, stderr
}

// clientExitStatus reads the status a channel ended with, or -1 when the client was
// given no status at all.
func clientExitStatus(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitStatus()
	}
	return -1
}

// TestSessionEndsAtItsDeadline is the phase's headline claim: an established
// session is bounded, the user is warned before it ends, told plainly why when
// it does, and the exit status says which ending this was.
func TestSessionEndsAtItsDeadline(t *testing.T) {
	h := newHarness(t, harnessOptions{
		sessionDeadline: testDeadline,
		options:         func(o *Options) { o.DeadlineWarning = testWarning },
	})
	session, stderr := heldSession(t, h)

	started := time.Now()
	err := session.Wait()
	elapsed := time.Since(started)

	if elapsed > 5*time.Second {
		t.Fatalf("the session ran for %s past its deadline; the timer did not fire", elapsed)
	}
	text := stderr.String()

	// Both messages, in order. The warning is only useful before the fact, so
	// "the user was told twice" is not the same claim as "the user was warned".
	warned := strings.Index(text, "reaches its authorized end in")
	expired := strings.Index(text, "has reached its authorized end")
	switch {
	case warned < 0:
		t.Errorf("user saw %q, want a warning before the deadline", text)
	case expired < 0:
		t.Errorf("user saw %q, want the expiry message", text)
	case warned > expired:
		t.Errorf("user saw %q, want the warning before the expiry message", text)
	}
	if !strings.Contains(text, testSessionID) {
		t.Errorf("user saw %q, want the session id as a support reference", text)
	}
	if !strings.Contains(text, bannerPrefix) {
		t.Errorf("user saw %q, want the proxy's own prefix so it is not read as program output", text)
	}
	if !strings.Contains(text, "reconnect") && !strings.Contains(text, "Reconnect") {
		t.Errorf("user saw %q, want it to say reconnecting is the remedy", text)
	}

	// Neither of PLAN §4.3's two branches. An expiry is not a denial — nothing
	// was refused — and not an outage — nothing is broken — and wording it as
	// either sends the user to solve a problem that does not exist.
	if strings.Contains(text, user.DenyMessage) {
		t.Errorf("user saw %q, which reads as a denial", text)
	}
	if strings.Contains(text, "not a permissions problem") || strings.Contains(text, "service problem") {
		t.Errorf("user saw %q, which reads as an outage", text)
	}
	// Nothing about the policy that set the bound.
	for _, leak := range []string{"testGroup", "decision-1", h.targetName()} {
		if strings.Contains(text, leak) {
			t.Errorf("user saw %q, which discloses %q", text, leak)
		}
	}

	if got := clientExitStatus(err); got != exitSessionExpired {
		t.Errorf("exit status = %d, want %d; %d is a policy kill and 0 would read as success",
			got, exitSessionExpired, exitProxyFailure)
	}
}

// TestSessionWithoutADeadlineIsNotBounded keeps absent from becoming zero: a
// route that names no deadline leaves the session alone, exactly as a v3
// server left it (contract v4's absent-value rule).
func TestSessionWithoutADeadlineIsNotBounded(t *testing.T) {
	h := newHarness(t, harnessOptions{
		options: func(o *Options) { o.DeadlineWarning = testWarning },
	})
	client := h.mustDial(h.username())

	time.Sleep(4 * testDeadline)

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = session.Close() }()
	if _, err := session.Output("uptime"); err != nil {
		t.Fatalf("a session with no deadline was ended anyway: %v", err)
	}
}

// TestDeadlineWarningIsSkippedWhenItsLeadHasPassed covers the rule that a
// warning nobody could read is not sent: with a lead time longer than the whole
// deadline, warning "immediately" would write into a channel the client has not
// asked anything on yet (PLAN §4.3). The expiry message still arrives.
func TestDeadlineWarningIsSkippedWhenItsLeadHasPassed(t *testing.T) {
	h := newHarness(t, harnessOptions{
		sessionDeadline: testDeadline,
		options:         func(o *Options) { o.DeadlineWarning = time.Hour },
	})
	session, stderr := heldSession(t, h)
	_ = session.Wait()

	text := stderr.String()
	if strings.Contains(text, "reaches its authorized end in") {
		t.Errorf("user saw %q, want no warning when its lead time had already passed", text)
	}
	if !strings.Contains(text, "has reached its authorized end") {
		t.Errorf("user saw %q, want the expiry message regardless", text)
	}
}

// TestDeadlineWarningCanBeTurnedOff is the negative lead time: only the message
// at expiry, which is the minimum PLAN §4.3 requires.
func TestDeadlineWarningCanBeTurnedOff(t *testing.T) {
	h := newHarness(t, harnessOptions{
		sessionDeadline: testDeadline,
		options:         func(o *Options) { o.DeadlineWarning = -1 },
	})
	session, stderr := heldSession(t, h)
	_ = session.Wait()

	text := stderr.String()
	if strings.Contains(text, "reaches its authorized end in") {
		t.Errorf("user saw %q, want no warning when the lead time is configured off", text)
	}
	if !strings.Contains(text, "has reached its authorized end") {
		t.Errorf("user saw %q, want the expiry message", text)
	}
}

// countingAuthenticator wraps a credential plane and counts teardowns, so a
// test can assert that an expiry ran the ORDINARY one rather than a second
// path of its own (PLAN §5.1).
type countingAuthenticator struct {
	inner     target.TargetAuthenticator
	teardowns atomic.Int64
}

func (a *countingAuthenticator) Name() string { return a.inner.Name() }

func (a *countingAuthenticator) Provision(ctx context.Context, id *identity.Identity, tgt target.Target) (*target.ProvisionedAccess, error) {
	access, err := a.inner.Provision(ctx, id, tgt)
	if err != nil {
		return nil, err
	}
	inner := access.Teardown
	access.Teardown = func(ctx context.Context) error {
		a.teardowns.Add(1)
		if inner == nil {
			return nil
		}
		return inner(ctx)
	}
	return access, nil
}

// TestDeadlineExpiryTearsDownThroughTheNormalPath is why expiry does not get a
// teardown route of its own: the credentials a session was provisioned must be
// removed on the way out however it ended (D6, PLAN §5.1). A second path would
// be a second place for that to be forgotten.
func TestDeadlineExpiryTearsDownThroughTheNormalPath(t *testing.T) {
	staticKey, err := target.NewStaticKeyAuthenticator(target.StaticKeyOptions{Signer: sshtest.MustGenerateSigner(), Username: testTargetAccount})
	if err != nil {
		t.Fatalf("NewStaticKeyAuthenticator: %v", err)
	}
	counting := &countingAuthenticator{inner: staticKey}
	h := newHarness(t, harnessOptions{
		sessionDeadline: testDeadline,
		targetAuth:      counting,
		options:         func(o *Options) { o.DeadlineWarning = testWarning },
	})
	session, _ := heldSession(t, h)
	_ = session.Wait()

	waitFor(t, func() bool { return counting.teardowns.Load() == 1 }, "the session's credentials to be torn down")
	waitFor(t, func() bool { return len(h.server.Sessions()) == 0 }, "the session to be deregistered")
}

// TestDeadlineExpiryIsItsOwnOutcomeInTheRecord is §4 of the phase: an operator
// asking "why did this session stop" reads the answer rather than inferring it
// from the absence of everything else.
func TestDeadlineExpiryIsItsOwnOutcomeInTheRecord(t *testing.T) {
	h := newHarness(t, harnessOptions{
		sessionDeadline: testDeadline,
		options:         func(o *Options) { o.DeadlineWarning = testWarning },
	})
	session, _ := heldSession(t, h)
	_ = session.Wait()

	end, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Kind == control.LogKindSessionEnd
	})
	if !ok {
		t.Fatal("no session_end record was produced")
	}
	if got := end.Attributes[logging.AttrEndReason]; got != logging.EndReasonDeadline {
		t.Errorf("session_end %s = %q, want %q", logging.AttrEndReason, got, logging.EndReasonDeadline)
	}

	expiry, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Attributes[logging.AttrEvent] == "session.deadline_reached"
	})
	if !ok {
		t.Fatal("no record named the moment the deadline was reached")
	}
	// Not a refusal and not an error: an expiry on a security team's denial
	// dashboard, or on an outage one, is a false alarm every time it fires.
	if expiry.Severity == control.SeverityCritical {
		t.Errorf("the expiry record is %s severity; an expiry is not a refusal", expiry.Severity)
	}
	if expiry.Kind == control.LogKindError {
		t.Error("the expiry record is an error record; an expiry is not a failure")
	}
	if expiry.Attributes[logging.AttrSessionDeadline] == "" {
		t.Errorf("the expiry record carries no %s", logging.AttrSessionDeadline)
	}

	// The bound is on the authorize record too, so a session whose proxy died
	// before it expired still shows an auditor what it was given.
	authorized, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Kind == control.LogKindAuthorize && r.Attributes[logging.AttrRouteType] != ""
	})
	if !ok {
		t.Fatal("no authorize record was produced")
	}
	if authorized.Attributes[logging.AttrSessionDeadline] == "" {
		t.Errorf("the authorize record carries no %s; the bound is invisible until it fires",
			logging.AttrSessionDeadline)
	}
}

// TestOrdinaryEndingsAreRecordedAsThemselves is the other half of the claim
// above: the new attribute is only worth reading if the ordinary case says
// something different.
func TestOrdinaryEndingsAreRecordedAsThemselves(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	runSession(t, h)

	end, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Kind == control.LogKindSessionEnd
	})
	if !ok {
		t.Fatal("no session_end record was produced")
	}
	if got := end.Attributes[logging.AttrEndReason]; got != logging.EndReasonClientClose {
		t.Errorf("session_end %s = %q, want %q", logging.AttrEndReason, got, logging.EndReasonClientClose)
	}
}

// TestRevokedSessionsAreRecordedAsRevoked keeps the two proxy-initiated endings
// apart: a kill and an expiry share the teardown path and nothing else, and an
// operator must not have to tell them apart by timestamp.
func TestRevokedSessionsAreRecordedAsRevoked(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	session, _ := heldSession(t, h)

	if err := h.server.KillSubject(context.Background(), testSubject, "revoked by the security team"); err != nil {
		t.Fatalf("KillSubject: %v", err)
	}
	_ = session.Wait()

	end, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Kind == control.LogKindSessionEnd
	})
	if !ok {
		t.Fatal("no session_end record was produced")
	}
	if got := end.Attributes[logging.AttrEndReason]; got != logging.EndReasonRevoked {
		t.Errorf("session_end %s = %q, want %q", logging.AttrEndReason, got, logging.EndReasonRevoked)
	}
}

// TestAChainedSessionCannotExtendItsDeadline is the failure mode an absolute
// instant was chosen to avoid, at the level where it actually happens: this hop
// authorizes independently and is answered a LATER deadline than the session
// arrived carrying, and must still end at the earlier one.
//
// It is invisible without a chain — every hop would serve the answer it was
// given — and by three hops it would be a session outliving its bound by
// multiples of it.
func TestAChainedSessionCannotExtendItsDeadline(t *testing.T) {
	h := newHarness(t, harnessOptions{
		// This hop's own answer: an hour away, and not what should be enforced.
		sessionDeadline: time.Hour,
		options:         func(o *Options) { o.DeadlineWarning = -1 },
	})

	key, err := sshtest.GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	client, err := ssh.Dial("tcp", h.addr, &ssh.ClientConfig{
		User:            h.username(),
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		// What makes this connection a chain leg rather than a user's client
		// (D11): the proxy expects a hop trail before it authorizes anything.
		ClientVersion: routing.HopClientVersion,
		Timeout:       10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial as a hop peer: %v", err)
	}
	defer func() { _ = client.Close() }()

	inherited := time.Now().Add(testDeadline)
	ok, _, err := client.SendRequest(routing.RequestHopTrail, true, routing.MarshalChain(routing.Chain{
		Trail:       routing.HopTrail{"proxy-upstream"},
		FinalTarget: h.targetName(),
		Deadline:    &inherited,
	}))
	if err != nil || !ok {
		t.Fatalf("declare the hop trail: ok=%t err=%v", ok, err)
	}

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	stderr := &syncBuffer{}
	session.Stderr = stderr
	// Stdin stays open, or the stand-in target's shell reaches EOF and exits
	// before there is a session for the deadline to end.
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

	started := time.Now()
	waitErr := session.Wait()
	elapsed := time.Since(started)

	if elapsed > 30*time.Second {
		t.Fatalf("the chained session ran for %s; it took this hop's later deadline", elapsed)
	}
	if !strings.Contains(stderr.String(), "has reached its authorized end") {
		t.Errorf("user saw %q, want the expiry message", stderr.String())
	}
	if got := clientExitStatus(waitErr); got != exitSessionExpired {
		t.Errorf("exit status = %d, want %d", got, exitSessionExpired)
	}
}

// TestDeadlineTearsDownWhileTheRemoteCommandIsStillRunning is the regression
// test for the defect the e2e topology caught: the deadline fired on time and
// the user was told, but the session's teardown did not run until the remote
// program exited two minutes later — so the ephemeral account, and anything it
// had backgrounded, outlived the deadline by however long the command ran.
//
// The cause is that teardown waits for the channel pumps and one of them is
// blocked reading the TARGET leg, which nothing had closed. A deadline is
// precisely the case where a session ends while a long command is still
// running, which is why the ordinary close path never showed it.
func TestDeadlineTearsDownWhileTheRemoteCommandIsStillRunning(t *testing.T) {
	staticKey, err := target.NewStaticKeyAuthenticator(target.StaticKeyOptions{Signer: sshtest.MustGenerateSigner(), Username: testTargetAccount})
	if err != nil {
		t.Fatalf("NewStaticKeyAuthenticator: %v", err)
	}
	counting := &countingAuthenticator{inner: staticKey}

	// A shell that never returns on its own, standing in for the `sleep 120`
	// the topology runs. It is released only when the test is over, so a
	// teardown that happens is a teardown the expiry caused.
	release := make(chan struct{})

	h := newHarness(t, harnessOptions{
		sessionDeadline: testDeadline,
		targetAuth:      counting,
		options:         func(o *Options) { o.DeadlineWarning = -1 },
		targetOptions: sshtest.Options{
			Shell: func(io.ReadWriter) uint32 {
				<-release
				return 0
			},
		},
	})
	// Registered AFTER the harness so it runs BEFORE the harness's cleanups
	// (t.Cleanup is LIFO): the stand-in target cannot shut down while one of
	// its shells is still blocked.
	t.Cleanup(func() { close(release) })

	session, _ := heldSession(t, h)
	_ = session.Wait()

	waitFor(t, func() bool { return counting.teardowns.Load() == 1 },
		"the credentials to be torn down while the remote command is still running")
	waitFor(t, func() bool { return len(h.server.Sessions()) == 0 }, "the session to be deregistered")
}

// TestRevokedSessionTearsDownWhileTheRemoteCommandIsStillRunning is the same
// claim for the other proxy-initiated ending.
//
// The defect above was latent in the kill path too — a revoked session held its
// ephemeral account for as long as the command it was revoked in the middle of
// kept running — and only never showed because every kill scenario until now
// used a command that exits at once. PLAN §6.4 says "the session was killed"
// must mean the connection is gone; it has to mean the account is gone too.
func TestRevokedSessionTearsDownWhileTheRemoteCommandIsStillRunning(t *testing.T) {
	staticKey, err := target.NewStaticKeyAuthenticator(target.StaticKeyOptions{Signer: sshtest.MustGenerateSigner(), Username: testTargetAccount})
	if err != nil {
		t.Fatalf("NewStaticKeyAuthenticator: %v", err)
	}
	counting := &countingAuthenticator{inner: staticKey}
	release := make(chan struct{})

	h := newHarness(t, harnessOptions{
		targetAuth: counting,
		targetOptions: sshtest.Options{
			Shell: func(io.ReadWriter) uint32 {
				<-release
				return 0
			},
		},
	})
	t.Cleanup(func() { close(release) })

	session, _ := heldSession(t, h)
	if err := h.server.KillSubject(context.Background(), testSubject, "revoked by the security team"); err != nil {
		t.Fatalf("KillSubject: %v", err)
	}
	_ = session.Wait()

	waitFor(t, func() bool { return counting.teardowns.Load() == 1 },
		"the revoked session's credentials to be torn down while the remote command is still running")
	waitFor(t, func() bool { return len(h.server.Sessions()) == 0 }, "the session to be deregistered")
}
