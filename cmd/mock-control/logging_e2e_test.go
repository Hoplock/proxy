// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/filter"
	"github.com/hoplock/proxy/internal/logging"
)

// This file is phase 0011's end-to-end test: a real SSH client, a real proxy
// with a real telemetry pipeline, and the real ingest contract spoken over HTTP
// to the mock server in this package.
//
// It asserts the four things PLAN §7 and D8 promise and nothing else can:
// a session can be reconstructed from what arrives, a batch leaves on a flush,
// a blocked command does NOT wait for one, and an outage costs latency rather
// than records.

// controlGate makes Hoplock Control unreachable on demand.
//
// It closes the connection rather than answering an error status, because that
// is what an unreachable server does: the proxy has to survive a transport
// failure mid-request, not a polite refusal.
type controlGate struct {
	down atomic.Bool
	next http.Handler
}

func (g *controlGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only the contract endpoints go down. /debug is the test's window into
	// what the server stored, not something the proxy talks to, and closing it
	// would blind the test to the outage it is asserting about.
	if g.down.Load() && strings.HasPrefix(r.URL.Path, "/v1/") {
		if hijacker, ok := w.(http.Hijacker); ok {
			if conn, _, err := hijacker.Hijack(); err == nil {
				_ = conn.Close()
				return
			}
		}
		http.Error(w, "unreachable", http.StatusServiceUnavailable)
		return
	}
	g.next.ServeHTTP(w, r)
}

// startGatedMock is startMock with the gate in front of it.
func startGatedMock(t *testing.T, fx *fixtures, gate *controlGate) *mock {
	t.Helper()
	s := newServer(fx, serverOptions{})
	gate.next = s.handler()
	srv := httptest.NewServer(gate)
	t.Cleanup(srv.Close)

	client, err := control.NewRESTClient(control.Options{BaseURL: srv.URL, Token: fx.ProxyToken})
	if err != nil {
		t.Fatalf("NewRESTClient: %v", err)
	}
	return &mock{srv: srv, client: client, server: s}
}

// --- assertions on what the mock stored ------------------------------------

// storedLogs is everything the mock has ingested, on both paths.
func (s *e2eStack) storedLogs(t *testing.T) debugLogs {
	t.Helper()
	resp, err := http.Get(s.mock.srv.URL + pathDebugLogs) //nolint:noctx // test helper against a local server
	if err != nil {
		t.Fatalf("GET %s: %v", pathDebugLogs, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out debugLogs
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode %s: %v", pathDebugLogs, err)
	}
	return out
}

// flushLogs delivers everything the sessions queued.
func (s *e2eStack) flushLogs(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.recorder.Flush(ctx); err != nil {
		t.Fatalf("flush telemetry: %v", err)
	}
}

// awaitLogs polls the mock until want is satisfied, flushing on each attempt.
func (s *e2eStack) awaitLogs(t *testing.T, want func(debugLogs) bool, what string) debugLogs {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		s.flushLogs(t)
		logs := s.storedLogs(t)
		if want(logs) {
			return logs
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// awaitStat polls a condition on the shipper's own counters.
func awaitStat(t *testing.T, want func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if want() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// kinds counts the records of each kind.
func kinds(recs []control.LogRecord) map[control.LogKind]int {
	out := map[control.LogKind]int{}
	for _, rec := range recs {
		out[rec.Kind]++
	}
	return out
}

// findRecord returns the first record matching want.
func findRecord(recs []control.LogRecord, want func(control.LogRecord) bool) (control.LogRecord, bool) {
	for _, rec := range recs {
		if want(rec) {
			return rec, true
		}
	}
	return control.LogRecord{}, false
}

// TestASessionCanBeReconstructedFromWhatArrives is PLAN §7's headline
// requirement: everything a security team needs to say what happened in a
// session is at Hoplock Control, keyed by the session id.
func TestASessionCanBeReconstructedFromWhatArrives(t *testing.T) {
	stack := startE2E(t, e2eOptions{})
	client := stack.dial(t)

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
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
	const typed = "whoami\r\n"
	if _, err := io.WriteString(stdin, typed); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := io.ReadFull(stdout, make([]byte, len(typed))); err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = stdin.Close()
	_ = session.Wait()
	_ = client.Close()

	logs := stack.awaitLogs(t, func(l debugLogs) bool {
		return kinds(append(l.Batched, l.Priority...))[control.LogKindSessionEnd] > 0
	}, "the session to be recorded end to end")

	all := append(append([]control.LogRecord{}, logs.Batched...), logs.Priority...)
	for _, rec := range all {
		if rec.SessionID != e2eSessionID {
			t.Errorf("record %s belongs to session %q, want %q", rec.Kind, rec.SessionID, e2eSessionID)
		}
	}

	// The metadata PLAN §7 enumerates, each in the record that owns it.
	counts := kinds(all)
	for _, kind := range []control.LogKind{
		control.LogKindSessionStart,
		control.LogKindAuth,
		control.LogKindAuthorize,
		control.LogKindHostKey,
		control.LogKindProvisioning,
		control.LogKindChannelOpen,
		control.LogKindCommand,
		control.LogKindStream,
		control.LogKindChannelClose,
		control.LogKindSessionEnd,
	} {
		if counts[kind] == 0 {
			t.Errorf("no %s record: the session cannot be reconstructed without it", kind)
		}
	}

	start, _ := findRecord(all, func(r control.LogRecord) bool { return r.Kind == control.LogKindSessionStart })
	if start.Subject == "" || start.Attributes[logging.AttrClientAddr] == "" ||
		start.Attributes[logging.AttrAuthMethod] == "" {
		t.Errorf("session start does not say who connected from where and how: %v", start.Attributes)
	}

	authz, _ := findRecord(all, func(r control.LogRecord) bool { return r.Kind == control.LogKindAuthorize })
	if authz.Attributes[logging.AttrRouteType] != string(control.RouteTypeDirect) ||
		authz.Attributes[logging.AttrPermissions] != "deployGroup" {
		t.Errorf("authorize record does not carry the route and permission set: %v", authz.Attributes)
	}

	// The in-channel requests, including the pty that makes the capture
	// replayable (D5a axis 2, PLAN §7).
	if _, ok := findRecord(all, func(r control.LogRecord) bool {
		return r.Kind == control.LogKindCommand && r.Attributes[logging.AttrRequest] == control.RequestPTY
	}); !ok {
		t.Error("no record of the pty request")
	}
	header, ok := findRecord(all, func(r control.LogRecord) bool {
		return r.Kind == control.LogKindStream && r.Attributes[logging.AttrCapture] == logging.CaptureHeader
	})
	if !ok {
		t.Fatal("no replay header was recorded for the pty session")
	}
	if header.Attributes[logging.AttrTerm] != "xterm" ||
		header.Attributes[logging.AttrWidth] != "80" || header.Attributes[logging.AttrHeight] != "24" {
		t.Errorf("replay header = %v, want the terminal the client asked for", header.Attributes)
	}

	// And the stream itself: the keystrokes are in the capture, in order.
	var captured bytes.Buffer
	for _, rec := range all {
		if rec.Kind == control.LogKindStream && rec.Attributes[logging.AttrCapture] == logging.CaptureChunk &&
			rec.Attributes[logging.AttrStream] == "stdin" {
			captured.Write(rec.Payload)
		}
	}
	if !strings.Contains(captured.String(), "whoami") {
		t.Errorf("the captured input stream is %q, want the keystrokes the user typed", captured.String())
	}
	if _, err := strconv.Atoi(header.Attributes[logging.AttrWidth]); err != nil {
		t.Errorf("replay header width is not a number: %v", err)
	}
}

// TestABatchIsDeliveredOnFlush is D8's throughput path against the real
// contract endpoint: records accumulate and arrive as batches, on 202.
func TestABatchIsDeliveredOnFlush(t *testing.T) {
	stack := startE2E(t, e2eOptions{})
	client := stack.dial(t)

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if _, err := session.Output("deploy"); err != nil {
		t.Fatalf("Output: %v", err)
	}
	_ = session.Close()

	// Nothing is critical here and the flush interval is a minute, so nothing
	// has left yet.
	if got := stack.storedLogs(t); len(got.Batched) != 0 {
		t.Fatalf("%d records arrived before any flush; the batch is not batching", len(got.Batched))
	}

	stack.flushLogs(t)
	logs := stack.storedLogs(t)
	if len(logs.Batched) == 0 {
		t.Fatal("the flush delivered no records on the batch endpoint")
	}
	if len(logs.Priority) != 0 {
		t.Errorf("%d ordinary records took the priority endpoint", len(logs.Priority))
	}
}

// TestABlockedCommandArrivesImmediately is the acceptance criterion for D8's
// priority path, stated as timing and ordering.
//
// The flush interval is a minute and the batch is nowhere near full, so nothing
// ordinary can arrive on its own. What the test asserts is that the blocked
// command arrives anyway, on the dedicated endpoint, WITH the records that
// preceded it — because a critical event flushes the batch in front of it.
func TestABlockedCommandArrivesImmediately(t *testing.T) {
	stack := startE2E(t, e2eOptions{
		filterPolicy: &fixtureFilterPolicy{
			Mode: string(control.FilterModeBlacklist),
			Rules: []fixtureFilterRule{{
				Match:  "cat /etc/shadow*",
				Action: string(control.FilterActionBlockCommand),
			}},
		},
	})
	client := stack.dial(t)

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	var stderr bytes.Buffer
	session.Stderr = &stderr
	started := time.Now()
	if err := session.Run("cat /etc/shadow"); err == nil {
		t.Fatal("the blocked command succeeded")
	}
	_ = session.Close()

	// No flush: if the record arrives, it arrived because it was critical.
	deadline := time.Now().Add(10 * time.Second)
	var logs debugLogs
	for time.Now().Before(deadline) {
		logs = stack.storedLogs(t)
		if len(logs.Priority) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(logs.Priority) == 0 {
		t.Fatal("the blocked command did not reach the priority endpoint on its own")
	}
	if elapsed := time.Since(started); elapsed >= e2eFlushInterval {
		t.Fatalf("the blocked command took %s, which is not sooner than the %s flush interval",
			elapsed, e2eFlushInterval)
	}

	blocked, ok := findRecord(logs.Priority, func(r control.LogRecord) bool {
		return r.Attributes[logging.AttrEvent] == filter.EventCommandPolicy &&
			r.Attributes[logging.AttrOutcome] == string(filter.OutcomeBlocked)
	})
	if !ok {
		t.Fatalf("the priority endpoint holds %v, not the blocked command", logs.Priority)
	}
	if blocked.Severity != control.SeverityCritical {
		t.Errorf("the blocked command is severity %q, want critical", blocked.Severity)
	}
	if blocked.Attributes[logging.AttrCommand] != "cat /etc/shadow" {
		t.Errorf("the record names command %q", blocked.Attributes[logging.AttrCommand])
	}

	// Ordering: the batch in front of the critical record was flushed with it,
	// so the session that produced the blocked command is already at the
	// server rather than arriving a minute later.
	if len(logs.Batched) == 0 {
		t.Error("the critical record did not flush the in-flight batch: its context is still queued")
	}
	if _, ok := findRecord(logs.Batched, func(r control.LogRecord) bool {
		return r.Kind == control.LogKindSessionStart
	}); !ok {
		t.Error("the session that ran the blocked command was not delivered with it")
	}
}

// TestAnOutageBuffersToDiskAndLosesNothing is PLAN §7's resilience requirement
// against the real endpoints: with Hoplock Control unreachable the records go
// to the proxy's local buffer, and when it returns every one of them arrives.
func TestAnOutageBuffersToDiskAndLosesNothing(t *testing.T) {
	stack := startE2E(t, e2eOptions{
		filterPolicy: &fixtureFilterPolicy{
			Mode: string(control.FilterModeBlacklist),
			Rules: []fixtureFilterRule{{
				Match:  "rollback",
				Action: string(control.FilterActionBlockCommand),
			}},
		},
	})
	client := stack.dial(t)

	// One command first, so the session's setup — authorize, provisioning, the
	// target dial and its host-key report — is finished before the link goes.
	// The outage under test is a TELEMETRY outage: what is being asserted is
	// that losing Hoplock Control costs records their latency and nothing
	// else, not that a session can be set up without a PDP (it cannot, D2).
	warmup, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if _, err := warmup.Output("deploy"); err != nil {
		t.Fatalf("warm-up command: %v", err)
	}
	_ = warmup.Close()

	stack.gate.down.Store(true)

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if out, err := session.Output("deploy"); err != nil || string(out) != "deployed\n" {
		t.Fatalf("the session broke while telemetry was down: %v (%q)", err, out)
	}
	_ = session.Close()

	blocked, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	blocked.Stderr = io.Discard
	if err := blocked.Run("rollback"); err == nil {
		t.Fatal("the blocked command succeeded during the outage")
	}
	_ = blocked.Close()

	// The records are on disk, in the proxy's buffer, under this session.
	awaitStat(t, func() bool { return stack.recorder.Stats().Buffered > 0 }, "the records to reach the disk buffer")
	if _, err := os.Stat(filepath.Join(stack.bufferDir, e2eSessionID)); err != nil {
		t.Errorf("no per-session buffer area during the outage: %v", err)
	}
	if got := stack.storedLogs(t); len(got.Batched)+len(got.Priority) != 0 {
		t.Fatalf("%d records reached an unreachable server", len(got.Batched)+len(got.Priority))
	}

	buffered := stack.recorder.Stats().Buffered
	stack.gate.down.Store(false)

	logs := stack.awaitLogs(t, func(l debugLogs) bool {
		return uint64(len(l.Batched)+len(l.Priority)) >= buffered && stack.recorder.Stats().Segments == 0
	}, "the buffer to drain")

	if got := stack.recorder.Stats().Dropped; got != 0 {
		t.Errorf("%d records were dropped across the outage, want none", got)
	}
	// The blocked command survived as a priority record: an outage does not
	// downgrade a critical event to ordinary telemetry.
	if _, ok := findRecord(logs.Priority, func(r control.LogRecord) bool {
		return r.Attributes[logging.AttrOutcome] == string(filter.OutcomeBlocked) &&
			r.Attributes[logging.AttrCommand] == "rollback"
	}); !ok {
		t.Error("the command blocked during the outage did not drain to the priority endpoint")
	}
	// And the buffer is empty again: it is a buffer, not a destination.
	entries, err := os.ReadDir(stack.bufferDir)
	if err != nil {
		t.Fatalf("read buffer dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("the buffer still holds %d entries after draining", len(entries))
	}
}

// TestTheInitialAuthPasswordIsNeverWritten is PLAN §7's redaction rule, tested
// where it can actually fail: end to end, over the password plane, against
// every record the server stored AND every byte the proxy wrote to disk.
//
// It is a structural property rather than a filter — no capture point is ever
// handed the password — and this test is what keeps it structural.
func TestTheInitialAuthPasswordIsNeverWritten(t *testing.T) {
	const password = "correct-horse-battery-staple"

	stack := startE2E(t, e2eOptions{password: password})

	client, err := ssh.Dial("tcp", stack.addr, &ssh.ClientConfig{
		User: "alice" + "#" + stack.target.Host(),
		// The password plane is served over keyboard-interactive, because that
		// is the flow an out-of-band second factor needs (PLAN §4.1).
		Auth: []ssh.AuthMethod{ssh.KeyboardInteractive(
			func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = password
				}
				return answers, nil
			},
		)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial the proxy with a password: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if _, err := session.Output("deploy"); err != nil {
		t.Fatalf("Output: %v", err)
	}
	_ = session.Close()
	_ = client.Close()

	logs := stack.awaitLogs(t, func(l debugLogs) bool {
		return kinds(append(l.Batched, l.Priority...))[control.LogKindAuth] > 0
	}, "the authentication record")

	all := append(append([]control.LogRecord{}, logs.Batched...), logs.Priority...)
	if len(all) == 0 {
		t.Fatal("no records at all; the test would pass vacuously")
	}
	for _, rec := range all {
		encoded, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		if bytes.Contains(encoded, []byte(password)) {
			t.Fatalf("the initial-auth password is in a %s record: %s", rec.Kind, encoded)
		}
	}

	// The authentication record exists and says how the user authenticated,
	// which is the point: redaction is not the same as recording nothing.
	auth, _ := findRecord(all, func(r control.LogRecord) bool { return r.Kind == control.LogKindAuth })
	if auth.Attributes[logging.AttrAuthMethod] != string(control.AuthMethodPasswordMFA) {
		t.Errorf("auth record method = %q, want %q",
			auth.Attributes[logging.AttrAuthMethod], control.AuthMethodPasswordMFA)
	}

	// And nothing the proxy wrote to its own disk carries it either. The
	// buffer normally drains to nothing; this walks whatever is there.
	if err := filepath.WalkDir(stack.bufferDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(content, []byte(password)) {
			t.Fatalf("the initial-auth password is in the disk buffer file %s", path)
		}
		return nil
	}); err != nil {
		t.Fatalf("walk the buffer directory: %v", err)
	}
}
