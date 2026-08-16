// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mauroasilva/securecommandproxy/internal/auth/user"
	"github.com/mauroasilva/securecommandproxy/internal/mgmt"
	"github.com/mauroasilva/securecommandproxy/internal/sshtest"
)

// TestExecEndToEnd is the phase's headline claim: a user authenticates to the
// bastion, is authorized to a direct target, runs a command, and gets that
// command's output and exit status back.
func TestExecEndToEnd(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	client := h.mustDial(h.username())

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = session.Close() }()

	var stderr bytes.Buffer
	session.Stderr = &stderr
	out, err := session.Output("uptime")
	if err != nil {
		t.Fatalf("Output: %v (stderr %q)", err, stderr.String())
	}
	if got, want := string(out), "ran: uptime\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
	if got := h.target.Commands(); len(got) != 1 || got[0] != "uptime" {
		t.Errorf("target saw commands %v, want [uptime]", got)
	}
	if got := h.target.Logins(); len(got) != 1 || got[0] != testLogin {
		t.Errorf("target saw logins %v, want [%s]", got, testLogin)
	}

	// The authorize call carries the identity and the parsed target, not the
	// raw username.
	calls := h.client.authorizeRequests()
	if len(calls) != 1 {
		t.Fatalf("authorize called %d times, want 1", len(calls))
	}
	if got, want := calls[0].Target, h.targetName(); got != want {
		t.Errorf("authorize target = %q, want %q", got, want)
	}
	if got, want := calls[0].Identity.Subject, testSubject; got != want {
		t.Errorf("authorize subject = %q, want %q", got, want)
	}
	if got, want := calls[0].Conn.BastionID, testBastionID; got != want {
		t.Errorf("authorize bastion id = %q, want %q", got, want)
	}
}

// TestExecExitStatusIsPreserved checks the status the program exited with
// survives the proxy, because a script on the far side of a bastion has to be
// able to tell success from failure.
func TestExecExitStatusIsPreserved(t *testing.T) {
	h := newHarness(t, harnessOptions{targetOptions: sshtest.Options{
		Exec: func(command string) ([]byte, []byte, uint32) {
			return []byte("out\n"), []byte("err\n"), 7
		},
	}})
	client := h.mustDial(h.username())

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = session.Close() }()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	err = session.Run("failing-command")
	var exitErr *ssh.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("Run error = %v (%T), want *ssh.ExitError", err, err)
	}
	if got, want := exitErr.ExitStatus(), 7; got != want {
		t.Errorf("exit status = %d, want %d", got, want)
	}
	if got, want := stdout.String(), "out\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
	if got, want := stderr.String(), "err\n"; got != want {
		t.Errorf("stderr = %q, want %q", got, want)
	}
}

// TestInteractiveShell exercises the other half of the channel surface: a pty,
// a shell, and data in both directions.
//
// It also proves the requests the engine holds while the target leg comes up
// are really replayed — the pty the client asked for before the target existed
// reaches the target.
func TestInteractiveShell(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	client := h.mustDial(h.username())

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = session.Close() }()

	if err := session.Setenv("SCP_TEST", "1"); err != nil {
		t.Fatalf("Setenv: %v", err)
	}
	if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		t.Fatalf("RequestPty: %v", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}

	if _, err := io.WriteString(stdin, "hello bastion\n"); err != nil {
		t.Fatalf("write to shell: %v", err)
	}
	got, err := readN(stdout, len("hello bastion\n"))
	if err != nil {
		t.Fatalf("read from shell: %v", err)
	}
	if want := "hello bastion\n"; got != want {
		t.Errorf("shell echoed %q, want %q", got, want)
	}

	_ = stdin.Close()
	if err := session.Wait(); err != nil {
		t.Errorf("Wait: %v", err)
	}

	if got := h.target.PTYs(); got != 1 {
		t.Errorf("target received %d pty requests, want 1 (held requests must be replayed)", got)
	}
	if got := h.target.Envs(); len(got) != 1 || got[0] != "SCP_TEST=1" {
		t.Errorf("target received envs %v, want [SCP_TEST=1]", got)
	}
}

// TestAuthorizeDenyIsGenericAndNamesNothing is the disclosure rule's first
// branch (PLAN §4.3): a denial says only that access was denied. It must not
// name the target, the login, or which of them was the problem, because a
// precise denial is an oracle for probing the estate one attempt at a time.
func TestAuthorizeDenyIsGenericAndNamesNothing(t *testing.T) {
	h := newHarness(t, harnessOptions{
		authorize: func(*mgmt.AuthorizeRequest) (*mgmt.AuthorizeResponse, error) {
			return nil, denyError("Authorize")
		},
	})

	text, status := runAndCollect(t, h, "uptime")

	if !strings.Contains(text, user.DenyMessage) {
		t.Errorf("user saw %q, want it to contain %q", text, user.DenyMessage)
	}
	if strings.Contains(text, h.targetName()) {
		t.Errorf("deny text %q names the target", text)
	}
	if strings.Contains(text, testLogin) {
		t.Errorf("deny text %q names the login", text)
	}
	if strings.Contains(strings.ToLower(text), "unavailable") ||
		strings.Contains(strings.ToLower(text), "service problem") {
		t.Errorf("deny text %q reads as an outage", text)
	}
	if status == 0 {
		t.Error("a denied session exited 0; a failure must not look like success")
	}
}

// TestManagementOutageIsExplicitAndCarriesTheSessionID is the second branch: a
// failure that is not a decision is said to be an outage, and carries the
// session id so the disconnect becomes a ticket the logs can answer.
func TestManagementOutageIsExplicitAndCarriesTheSessionID(t *testing.T) {
	h := newHarness(t, harnessOptions{
		authorize: func(*mgmt.AuthorizeRequest) (*mgmt.AuthorizeResponse, error) {
			return nil, outageError("Authorize")
		},
	})

	text, status := runAndCollect(t, h, "uptime")

	if strings.Contains(text, user.DenyMessage) {
		t.Errorf("outage text %q reads as a denial", text)
	}
	if !strings.Contains(text, "not a permissions problem") {
		t.Errorf("outage text %q does not say it is not a permissions problem", text)
	}
	if !strings.Contains(text, testSessionID) {
		t.Errorf("outage text %q does not carry the session id %q", text, testSessionID)
	}
	if status == 0 {
		t.Error("a failed session exited 0; a failure must not look like success")
	}
}

// TestFailureAfterChannelOpenIsNotASilentClose states the property both tests
// above depend on, on its own: once the session channel exists, a failure is
// stderr plus a non-zero exit status, never a dropped connection.
func TestFailureAfterChannelOpenIsNotASilentClose(t *testing.T) {
	h := newHarness(t, harnessOptions{
		authorize: func(*mgmt.AuthorizeRequest) (*mgmt.AuthorizeResponse, error) {
			return nil, outageError("Authorize")
		},
	})
	client := h.mustDial(h.username())

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = session.Close() }()

	var stderr bytes.Buffer
	session.Stderr = &stderr

	err = session.Run("uptime")
	var exitErr *ssh.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("Run error = %v (%T), want an *ssh.ExitError rather than a dropped connection", err, err)
	}
	if got := exitErr.ExitStatus(); got != exitBastionFailure {
		t.Errorf("exit status = %d, want %d", got, exitBastionFailure)
	}
	if stderr.Len() == 0 {
		t.Error("the session ended with nothing written to stderr")
	}
}

// TestTargetDialFailureSaysTheTargetIsUnreachable checks the outage branch
// names the right dependency: telling a user the policy service is down when
// their target is down sends them to the wrong team.
func TestTargetDialFailureSaysTheTargetIsUnreachable(t *testing.T) {
	h := newHarness(t, harnessOptions{noTarget: true})

	text, _ := runAndCollect(t, h, "uptime")

	if !strings.Contains(text, "target could not be reached") {
		t.Errorf("user saw %q, want it to say the target could not be reached", text)
	}
	if !strings.Contains(text, testSessionID) {
		t.Errorf("outage text %q does not carry the session id", text)
	}
}

// TestHostKeyIsReportedAndTrustedOnFirstUse covers D7: the bastion keeps no
// local trust store, it reports the key it saw and does what the server says.
func TestHostKeyIsReportedAndTrustedOnFirstUse(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	client := h.mustDial(h.username())

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = session.Close() }()
	if _, err := session.Output("uptime"); err != nil {
		t.Fatalf("Output: %v", err)
	}

	reports := h.client.hostKeyReports()
	if len(reports) != 1 {
		t.Fatalf("host key reported %d times, want 1", len(reports))
	}
	if got, want := reports[0].Target, h.targetName(); got != want {
		t.Errorf("reported target = %q, want %q", got, want)
	}
	if got, want := reports[0].TargetPort, h.target.Port(); got != want {
		t.Errorf("reported port = %d, want %d", got, want)
	}
	if got, want := reports[0].HostKey.Fingerprint, ssh.FingerprintSHA256(h.target.HostKey()); got != want {
		t.Errorf("reported fingerprint = %q, want %q", got, want)
	}
	if got, want := reports[0].Conn.SessionID, testSessionID; got != want {
		t.Errorf("reported session id = %q, want %q", got, want)
	}
}

// TestHostKeyRejectionEndsTheSessionWithAReason covers the other half of D7: a
// key the server refuses aborts the target leg, and the user is told what
// failed without being told they lack permission.
func TestHostKeyRejectionEndsTheSessionWithAReason(t *testing.T) {
	h := newHarness(t, harnessOptions{
		hostKey: func(*mgmt.HostKeyReportRequest) (*mgmt.HostKeyReportResponse, error) {
			return &mgmt.HostKeyReportResponse{Decision: mgmt.HostKeyReject, Known: false, Reason: "unknown key"}, nil
		},
	})

	text, status := runAndCollect(t, h, "uptime")

	if !strings.Contains(text, "host key was not accepted") {
		t.Errorf("user saw %q, want it to name the host key", text)
	}
	if strings.Contains(text, user.DenyMessage) {
		t.Errorf("host-key failure %q reads as a permissions denial", text)
	}
	if status == 0 {
		t.Error("a session that never reached its target exited 0")
	}
}

// TestChannelNotPermittedIsRefused covers the allow-list (D5) for a channel the
// engine can refuse before it exists.
func TestChannelNotPermittedIsRefused(t *testing.T) {
	h := newHarness(t, harnessOptions{permittedChannels: []string{channelSession}})
	client := h.mustDial(h.username())

	// A session channel is permitted, so the connection works at all.
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	_ = session.Close()

	_, _, err = client.OpenChannel("direct-tcpip", nil)
	var openErr *ssh.OpenChannelError
	if !errors.As(err, &openErr) {
		t.Fatalf("OpenChannel error = %v (%T), want *ssh.OpenChannelError", err, err)
	}
	if openErr.Reason != ssh.Prohibited {
		t.Errorf("rejection reason = %v, want %v", openErr.Reason, ssh.Prohibited)
	}
	if !strings.Contains(openErr.Message, user.DenyMessage) {
		t.Errorf("rejection message = %q, want the generic denial", openErr.Message)
	}
}

// TestPermittedChannelOtherThanSessionIsProxied is the same allow-list from the
// other side: a permitted non-session channel is forwarded generically, without
// the engine knowing anything about what it carries (D5).
func TestPermittedChannelOtherThanSessionIsProxied(t *testing.T) {
	h := newHarness(t, harnessOptions{permittedChannels: []string{channelSession, "direct-tcpip"}})
	client := h.mustDial(h.username())

	ch, reqs, err := client.OpenChannel("direct-tcpip", nil)
	if err != nil {
		t.Fatalf("OpenChannel: %v", err)
	}
	go ssh.DiscardRequests(reqs)
	defer func() { _ = ch.Close() }()

	if _, err := io.WriteString(ch, "tunnelled"); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readN(ch, len("tunnelled"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if want := "tunnelled"; got != want {
		t.Errorf("channel echoed %q, want %q", got, want)
	}
}

// TestEmptyChannelAllowListDeniesTheSession checks the deliberate reading of an
// empty allow-list: it denies everything rather than meaning "unset".
//
// The session channel is accepted before the policy is known — that ordering is
// what gives the bastion somewhere to write — so the refusal arrives as an
// explained close on the channel rather than as an open failure.
func TestEmptyChannelAllowListDeniesTheSession(t *testing.T) {
	h := newHarness(t, harnessOptions{permittedChannels: []string{}})

	text, status := runAndCollect(t, h, "uptime")

	if !strings.Contains(text, user.DenyMessage) {
		t.Errorf("user saw %q, want the generic denial", text)
	}
	if status == 0 {
		t.Error("a session with no permitted channels exited 0")
	}
}

// TestNextHopRouteIsRefusedAsAnOutage covers the 0007 seam: the route is
// understood, cannot be served yet, and says so as a service limitation rather
// than as a denial.
func TestNextHopRouteIsRefusedAsAnOutage(t *testing.T) {
	h := newHarness(t, harnessOptions{routeType: mgmt.RouteTypeNextHop})

	text, _ := runAndCollect(t, h, "uptime")

	if strings.Contains(text, user.DenyMessage) {
		t.Errorf("next-hop refusal %q reads as a denial", text)
	}
	if !strings.Contains(text, "route this bastion cannot serve yet") {
		t.Errorf("user saw %q, want it to name the unsupported route", text)
	}
}

// TestMalformedUsernameExplainsTheEncoding covers the one failure the user can
// fix themselves: the target rides in the username (D1), and a user who typed a
// bare login cannot guess that.
func TestMalformedUsernameExplainsTheEncoding(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	text, status := runAndCollectAs(t, h, testLogin, "uptime")

	if !strings.Contains(text, "did not name a target") {
		t.Errorf("user saw %q, want it to say the target was missing", text)
	}
	if !strings.Contains(text, testDelimiter) {
		t.Errorf("user saw %q, want it to show the login%starget form", text, testDelimiter)
	}
	if status == 0 {
		t.Error("a session with no target exited 0")
	}
}

// TestKillSubjectTellsTheUserAndEndsTheSession covers the SessionRegistry half
// of PLAN §6.4 that phase 0003 left for this engine: the management server can
// end a session already in flight, and the user is told why before it goes.
func TestKillSubjectTellsTheUserAndEndsTheSession(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	client := h.mustDial(h.username())

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	var stderr syncBuffer
	session.Stderr = &stderr
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}
	// Make sure the session is up before revoking it: a kill that raced the
	// channel open would pass for the wrong reason.
	if _, err := io.WriteString(stdin, "ping\n"); err != nil {
		t.Fatalf("write: %v", err)
	}

	const reason = "credentials revoked by the security team"
	waitFor(t, func() bool { return len(h.server.Sessions()) == 1 }, "the session to register")
	if err := h.server.KillSubject(context.Background(), testSubject, reason); err != nil {
		t.Fatalf("KillSubject: %v", err)
	}

	_ = session.Wait()
	if got := stderr.String(); !strings.Contains(got, reason) {
		t.Errorf("user saw %q, want the operator's reason %q", got, reason)
	}
}

// TestKillSubjectIgnoresOtherSubjects checks a kill is scoped: revocation names
// a subject, and every other session keeps running.
func TestKillSubjectIgnoresOtherSubjects(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	client := h.mustDial(h.username())

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = session.Close() }()

	if err := h.server.KillSubject(context.Background(), "someone-else@example.com", "not you"); err != nil {
		t.Fatalf("KillSubject: %v", err)
	}
	if _, err := session.Output("uptime"); err != nil {
		t.Fatalf("the session was killed for another subject: %v", err)
	}
}

// TestSessionsDoNotLeakGoroutines is the acceptance criterion that both legs
// close cleanly. A proxy that forgets one pump per session looks perfectly
// healthy until the process runs out of memory a week later.
func TestSessionsDoNotLeakGoroutines(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	// One warm-up session, so lazily started machinery is not counted as a leak.
	runSession(t, h)
	settle()
	before := runtime.NumGoroutine()

	for range 5 {
		runSession(t, h)
	}

	deadline := time.Now().Add(5 * time.Second)
	var after int
	for time.Now().Before(deadline) {
		settle()
		if after = runtime.NumGoroutine(); after <= before+2 {
			return
		}
	}
	t.Errorf("goroutines after 5 sessions = %d, before = %d", after, before)
}

// runSession opens a connection, runs a command, and closes everything.
func runSession(t *testing.T, h *harness) {
	t.Helper()
	client, err := h.dial(h.username())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if _, err := session.Output("uptime"); err != nil {
		t.Fatalf("Output: %v", err)
	}
	_ = session.Close()
}

// runAndCollect runs a command that is expected to fail and returns what the
// user was shown plus the exit status they were given.
func runAndCollect(t *testing.T, h *harness, command string) (string, int) {
	t.Helper()
	return runAndCollectAs(t, h, h.username(), command)
}

func runAndCollectAs(t *testing.T, h *harness, username, command string) (string, int) {
	t.Helper()
	client, err := h.dial(username)
	if err != nil {
		t.Fatalf("dial as %q: %v", username, err)
	}
	defer func() { _ = client.Close() }()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = session.Close() }()

	var stderr bytes.Buffer
	session.Stderr = &stderr
	err = session.Run(command)

	status := 0
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		status = exitErr.ExitStatus()
	} else if err != nil {
		// Anything other than an exit status means the user was told nothing
		// useful; report it with whatever did reach stderr.
		t.Logf("Run returned %v (%T)", err, err)
		status = -1
	}
	return stderr.String(), status
}

// readN reads exactly n bytes or fails.
func readN(r io.Reader, n int) (string, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// waitFor polls cond until it holds or the test times out.
func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// settle gives finished goroutines a chance to exit before they are counted.
func settle() {
	for range 3 {
		runtime.Gosched()
		time.Sleep(50 * time.Millisecond)
		runtime.GC()
	}
}
