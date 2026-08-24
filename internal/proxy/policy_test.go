// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/auth/user"
	"github.com/hoplock/proxy/internal/control"
)

// This file states phase 0009's claims the way a customer would: one test per
// policy sentence, each proved end to end through a real SSH client. The unit
// tests for the pipeline itself live in internal/channel; what is asserted here
// is that the three axes reach the wire, and that a refusal is something the
// user can read.

// TestMayOpenAShellButMayNotCopyFilesOffTheBox is the sentence a channel-type
// allow-list cannot say: scp, sftp, a login shell, and a one-shot command all
// ride the same "session" channel, so only the request axis can separate them.
func TestMayOpenAShellButMayNotCopyFilesOffTheBox(t *testing.T) {
	h := newHarness(t, harnessOptions{
		// A present-but-empty Subsystems list denies every subsystem while
		// Types leaves the shell alone. Absent would have meant "not policed".
		permittedRequests: &control.RequestPolicy{
			Types: []string{control.RequestPTY, control.RequestShell},
		},
	})
	client := h.mustDial(h.username())

	// The shell still works.
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
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
	if _, err := io.WriteString(stdin, "hello\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got, err := readN(stdout, len("hello\n")); err != nil || got != "hello\n" {
		t.Fatalf("shell echoed %q, %v; want %q", got, err, "hello\n")
	}
	_ = stdin.Close()
	_ = session.Close()

	// sftp does not, and says so.
	ch := openSessionChannel(t, client)
	ok, err := ch.SendRequest(control.RequestSubsystem, true, ssh.Marshal(struct{ Name string }{"sftp"}))
	if err != nil {
		t.Fatalf("subsystem request: %v", err)
	}
	if ok {
		t.Error("the sftp subsystem was permitted")
	}
	if text := proxyMessage(t, ch); !strings.Contains(text, user.DenyMessage) || !strings.Contains(text, "sftp") {
		t.Errorf("user saw %q, want the generic denial naming sftp", text)
	}
	if got := h.target.Subsystems(); len(got) != 0 {
		t.Errorf("target started subsystems %v, want none: the refusal must happen at the proxy", got)
	}

	// Nor does scp, which is an exec rather than a subsystem — the same
	// sentence, enforced on the other request.
	ch = openSessionChannel(t, client)
	ok, err = ch.SendRequest(control.RequestExec, true, ssh.Marshal(struct{ Command string }{"scp -f /etc/shadow"}))
	if err != nil {
		t.Fatalf("exec request: %v", err)
	}
	if ok {
		t.Error("scp was permitted")
	}
	if text := proxyMessage(t, ch); !strings.Contains(text, user.DenyMessage) {
		t.Errorf("user saw %q, want the generic denial", text)
	}
	if got := h.target.Commands(); len(got) != 0 {
		t.Errorf("target ran %v, want nothing", got)
	}
}

// TestCIMayRunCommandsButNeverGetsATerminal is the other half of the request
// axis, and the reason a denial is not a close: the channel that was refused a
// pty is the same channel that then runs the command.
func TestCIMayRunCommandsButNeverGetsATerminal(t *testing.T) {
	h := newHarness(t, harnessOptions{
		permittedRequests: &control.RequestPolicy{Types: []string{control.RequestExec}},
	})
	client := h.mustDial(h.username())
	ch := openSessionChannel(t, client)

	ok, err := ch.SendRequest(control.RequestPTY, true, ptyRequest())
	if err != nil {
		t.Fatalf("pty request: %v", err)
	}
	if ok {
		t.Error("a pty was granted on a session that may not have one")
	}
	if text := proxyMessage(t, ch); !strings.Contains(text, user.DenyMessage) ||
		!strings.Contains(text, "terminal") {
		t.Errorf("user saw %q, want the denial to name the terminal", text)
	}
	if got := h.target.PTYs(); got != 0 {
		t.Errorf("target allocated %d ptys, want 0", got)
	}

	ok, err = ch.SendRequest(control.RequestExec, true, ssh.Marshal(struct{ Command string }{"uptime"}))
	if err != nil {
		t.Fatalf("exec request: %v", err)
	}
	if !ok {
		t.Fatal("exec was refused on a session that may run commands")
	}
	if got, err := readN(ch, len("ran: uptime\n")); err != nil || got != "ran: uptime\n" {
		t.Errorf("command output = %q, %v; want %q", got, err, "ran: uptime\n")
	}
}

// TestMayTunnelToTheDatabaseAndNowhereElse is the destination axis: allowing
// direct-tcpip wholesale is a toggle, and the whole meaning of a forward is the
// host and port inside its payload.
func TestMayTunnelToTheDatabaseAndNowhereElse(t *testing.T) {
	h := newHarness(t, harnessOptions{
		permittedChannels: []string{channelSession, control.ChannelDirectTCPIP},
		permittedForwards: &control.ForwardPolicy{
			DirectTCPIP: []control.ForwardDestination{{Host: "db.internal", Port: 5432}},
		},
	})
	client := h.mustDial(h.username())

	ch, reqs, err := client.OpenChannel(control.ChannelDirectTCPIP, directTCPIP("db.internal", 5432))
	if err != nil {
		t.Fatalf("OpenChannel to the permitted destination: %v", err)
	}
	go ssh.DiscardRequests(reqs)
	defer func() { _ = ch.Close() }()
	if _, err := io.WriteString(ch, "select 1"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got, err := readN(ch, len("select 1")); err != nil || got != "select 1" {
		t.Fatalf("tunnel echoed %q, %v; want %q", got, err, "select 1")
	}

	for _, tc := range []struct {
		name string
		host string
		port int
	}{
		{"another host", "web.internal", 5432},
		{"another port on the same host", "db.internal", 22},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := client.OpenChannel(control.ChannelDirectTCPIP, directTCPIP(tc.host, tc.port))
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
		})
	}
}

// TestMayNeverOpenAListener is the axis a channel allow-list structurally
// cannot reach: remote forwarding is asked for on the connection, and denying
// the forwarded-tcpip channels it produces would leave the listener standing.
func TestMayNeverOpenAListener(t *testing.T) {
	h := newHarness(t, harnessOptions{
		permittedGlobalRequests: &control.GlobalRequestPolicy{},
	})
	client := h.mustDial(h.username())

	// Run something first, so the target leg is up: a tcpip-forward that was
	// going to be relayed would have reached the target by the time we look.
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if _, err := session.Output("uptime"); err != nil {
		t.Fatalf("Output: %v", err)
	}
	_ = session.Close()

	if listener, err := client.Listen("tcp", "127.0.0.1:0"); err == nil {
		_ = listener.Close()
		t.Error("tcpip-forward was permitted on a session that may never open a listener")
	}
	for _, name := range h.target.GlobalRequests() {
		if name == control.GlobalRequestTCPIPForward {
			t.Error("tcpip-forward reached the target: the listener exists even though the client was refused")
		}
	}
}

// TestUnpolicedGlobalRequestsStillReachTheTarget is the boundary of the same
// axis: transport hygiene is not policy, and denying a keepalive breaks a
// healthy session rather than securing one.
func TestUnpolicedGlobalRequestsStillReachTheTarget(t *testing.T) {
	h := newHarness(t, harnessOptions{
		permittedGlobalRequests: &control.GlobalRequestPolicy{},
	})
	client := h.mustDial(h.username())

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if _, err := session.Output("uptime"); err != nil {
		t.Fatalf("Output: %v", err)
	}
	_ = session.Close()

	if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
		t.Fatalf("keepalive: %v", err)
	}
	waitFor(t, func() bool {
		for _, name := range h.target.GlobalRequests() {
			if name == "keepalive@openssh.com" {
				return true
			}
		}
		return false
	}, "the keepalive to reach the target")
}

// TestMalformedForwardingPayloadIsDenied covers the payload the pipeline is
// handed by whoever opened the channel: it is attacker-controlled, so an
// unreadable one is a denial and never a panic — and never a pass, because a
// destination the proxy cannot read is one it cannot police.
func TestMalformedForwardingPayloadIsDenied(t *testing.T) {
	h := newHarness(t, harnessOptions{
		permittedChannels: []string{channelSession, control.ChannelDirectTCPIP},
	})
	client := h.mustDial(h.username())

	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{"empty", nil},
		{"truncated length prefix", []byte{0x00, 0x00, 0x01}},
		{"host length beyond the payload", []byte{0x00, 0x00, 0xff, 0xff, 'd', 'b'}},
		{"trailing junk", append(directTCPIP("db.internal", 5432), 'x')},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := client.OpenChannel(control.ChannelDirectTCPIP, tc.payload)
			var openErr *ssh.OpenChannelError
			if !errors.As(err, &openErr) {
				t.Fatalf("OpenChannel error = %v (%T), want *ssh.OpenChannelError", err, err)
			}
			if openErr.Reason != ssh.Prohibited {
				t.Errorf("rejection reason = %v, want %v", openErr.Reason, ssh.Prohibited)
			}
		})
	}

	// The connection survived every one of them.
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession after malformed opens: %v", err)
	}
	defer func() { _ = session.Close() }()
	if _, err := session.Output("uptime"); err != nil {
		t.Fatalf("Output after malformed opens: %v", err)
	}
}

// TestAncillaryRequestsAreNeverPoliced checks the deliberate hole in the
// request axis: a terminal resize decides nothing, so an allow-list that named
// only "shell" must not turn a working session into a broken one.
func TestAncillaryRequestsAreNeverPoliced(t *testing.T) {
	h := newHarness(t, harnessOptions{
		permittedRequests: &control.RequestPolicy{Types: []string{control.RequestShell}},
	})
	client := h.mustDial(h.username())
	ch := openSessionChannel(t, client)

	ok, err := ch.SendRequest(control.RequestShell, true, nil)
	if err != nil {
		t.Fatalf("shell request: %v", err)
	}
	if !ok {
		t.Fatal("shell was refused on a session that may have one")
	}
	ok, err = ch.SendRequest("window-change", true, ssh.Marshal(struct {
		Columns, Rows, Width, Height uint32
	}{100, 40, 800, 600}))
	if err != nil {
		t.Fatalf("window-change: %v", err)
	}
	if !ok {
		t.Error("a terminal resize was refused; ancillary requests carry no policy")
	}
}

// openSessionChannel opens a raw session channel.
//
// Tests that expect a request to be refused need this rather than ssh.Session:
// a Session only starts copying stderr once a command has started, and a
// refused request never starts one, so the explanation would be lost.
func openSessionChannel(t *testing.T, client *ssh.Client) ssh.Channel {
	t.Helper()
	ch, reqs, err := client.OpenChannel(channelSession, nil)
	if err != nil {
		t.Fatalf("OpenChannel(session): %v", err)
	}
	go ssh.DiscardRequests(reqs)
	t.Cleanup(func() { _ = ch.Close() })
	return ch
}

// proxyMessage reads one line of proxy-authored text off a channel's stderr.
func proxyMessage(t *testing.T, ch ssh.Channel) string {
	t.Helper()
	type result struct {
		line string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		line, err := bufio.NewReader(ch.Stderr()).ReadString('\n')
		done <- result{line, err}
	}()
	select {
	case got := <-done:
		if got.err != nil && got.line == "" {
			t.Fatalf("reading the proxy's message: %v", got.err)
		}
		return strings.TrimRight(got.line, "\r\n")
	case <-time.After(5 * time.Second):
		t.Fatal("the proxy said nothing before closing the channel")
		return ""
	}
}

// directTCPIP builds a direct-tcpip channel-open payload the way a client's
// port forward does (RFC 4254 §7.2).
func directTCPIP(host string, port int) []byte {
	return ssh.Marshal(struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}{host, uint32(port), "127.0.0.1", 51000})
}

// ptyRequest builds a pty-req payload.
func ptyRequest() []byte {
	return ssh.Marshal(struct {
		Term                         string
		Columns, Rows, Width, Height uint32
		Modes                        string
	}{"xterm", 80, 24, 640, 480, ""})
}
