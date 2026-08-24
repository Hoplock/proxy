// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/logging"
)

// This file states what the ENGINE records (PLAN §7). The pipeline's own
// behaviour — batching, the priority endpoint, the disk buffer — is tested in
// internal/logging; what is asserted here is that the transport reaches every
// capture point and puts the right thing in each record.

// TestASessionRecordsItsWholeLifecycle walks one ordinary session and checks
// that each stage left the record an auditor would look for.
func TestASessionRecordsItsWholeLifecycle(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	if _, status := runAndCollect(t, h, "uptime"); status != 0 {
		t.Fatalf("the command exited %d", status)
	}

	start := h.recordOfKind(control.LogKindSessionStart)
	if start.Subject != testSubject || start.Login != testLogin {
		t.Errorf("session start = %+v, want it attributed to the authenticated user", start)
	}
	if start.Attributes[logging.AttrAuthMethod] == "" || start.Attributes[logging.AttrClientAddr] == "" {
		t.Errorf("session start does not say how or from where: %v", start.Attributes)
	}
	if start.Attributes[logging.AttrProxyID] != testProxyID {
		t.Errorf("session start does not name the proxy: %v", start.Attributes)
	}

	authz := h.recordOfKind(control.LogKindAuthorize)
	if authz.Attributes[logging.AttrRouteType] != string(control.RouteTypeDirect) ||
		authz.Attributes[logging.AttrPermissions] != "testGroup" ||
		authz.Attributes[logging.AttrDecisionID] != "decision-1" {
		t.Errorf("authorize record = %v, want the route, the permission set, and the decision id", authz.Attributes)
	}

	hostKey := h.recordOfKind(control.LogKindHostKey)
	if hostKey.Attributes[logging.AttrHostKeyFingerprint] == "" ||
		hostKey.Attributes[logging.AttrHostKeyKnown] != "false" {
		t.Errorf("host key record = %v, want a fingerprint and its first sighting (D7)", hostKey.Attributes)
	}

	cred := h.recordOfKind(control.LogKindProvisioning)
	if cred.Attributes[logging.AttrCredentialMethod] == "" {
		t.Errorf("provisioning record = %v, want the credential method (D6a)", cred.Attributes)
	}

	open := h.recordOfKind(control.LogKindChannelOpen)
	if open.Attributes[logging.AttrChannelType] != channelSession ||
		open.Attributes[logging.AttrChannelID] == "" {
		t.Errorf("channel open = %v, want the type and the id that correlates it", open.Attributes)
	}

	exec, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Kind == control.LogKindCommand && r.Attributes[logging.AttrRequest] == control.RequestExec
	})
	if !ok {
		t.Fatal("the exec request was not recorded")
	}
	if exec.Attributes[logging.AttrCommand] != "uptime" {
		t.Errorf("exec record command = %q, want %q", exec.Attributes[logging.AttrCommand], "uptime")
	}
	if exec.Attributes[logging.AttrChannelID] != open.Attributes[logging.AttrChannelID] {
		t.Error("the exec record does not correlate with the channel it ran on")
	}

	closed := h.recordOfKind(control.LogKindChannelClose)
	if closed.Attributes[logging.AttrChannelID] != open.Attributes[logging.AttrChannelID] {
		t.Error("the channel close does not name the channel that opened")
	}
	if closed.Attributes[logging.AttrExitStatus] != "0" {
		t.Errorf("channel close exit status = %q, want 0", closed.Attributes[logging.AttrExitStatus])
	}

	end := h.recordOfKind(control.LogKindSessionEnd)
	if _, ok := end.Attributes[logging.AttrDuration]; !ok {
		t.Error("the session end record has no duration")
	}
}

// TestTheOutputOfACommandIsCaptured is the replay half of PLAN §7 at the
// transport level: what the target printed is in the record, and what the
// client received is unchanged.
func TestTheOutputOfACommandIsCaptured(t *testing.T) {
	// The stand-in target echoes the command back, so what it printed is known
	// exactly and the capture can be compared against it.
	h := newHarness(t, harnessOptions{})
	if _, status := runAndCollect(t, h, "uptime"); status != 0 {
		t.Fatalf("the command exited %d", status)
	}

	captured, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Kind == control.LogKindStream &&
			r.Attributes[logging.AttrStream] == "stdout" &&
			len(r.Payload) > 0
	})
	if !ok {
		t.Fatal("the command's output was not captured")
	}
	if captured.Attributes[logging.AttrCaptureFormat] != logging.CaptureFormatRawChunk {
		t.Errorf("stream record does not say how to read its payload: %v", captured.Attributes)
	}
	if captured.Attributes[logging.AttrChannelID] == "" || captured.Attributes[logging.AttrOffsetMS] == "" {
		t.Errorf("stream record = %v, want the channel and the offset a replay needs", captured.Attributes)
	}
	if !strings.Contains(string(captured.Payload), "uptime") {
		t.Errorf("captured %q, want the output the target produced", captured.Payload)
	}
}

// TestARefusedChannelIsRecordedAsACriticalDecision is D8's other half at the
// transport: a refusal is the event, and it does not wait in a batch.
func TestARefusedChannelIsRecordedAsACriticalDecision(t *testing.T) {
	h := newHarness(t, harnessOptions{permittedChannels: []string{channelSession}})
	client := h.mustDial(h.username())

	// A channel type the route does not permit (D5a axis 1).
	_, _, err := client.OpenChannel("direct-tcpip", directTCPIP("10.0.0.1", 5432))
	if err == nil {
		t.Fatal("an unpermitted channel was opened")
	}

	rec, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Kind == control.LogKindPolicyDecision &&
			r.Attributes[logging.AttrChannelType] == "direct-tcpip"
	})
	if !ok {
		t.Fatal("the refused channel produced no policy_decision record")
	}
	if rec.Severity != control.SeverityCritical {
		t.Errorf("a refusal was recorded as %q, want critical", rec.Severity)
	}
	if !recordedOnPriorityPath(h, rec.RecordID) {
		t.Error("a refusal did not take the priority path")
	}
}

// TestADeniedForwardRecordsTheDestination keeps the axis that makes a port
// forward auditable: what it MEANT is inside the payload, and the record has
// it (D5a axis 3a).
func TestADeniedForwardRecordsTheDestination(t *testing.T) {
	h := newHarness(t, harnessOptions{
		permittedChannels: []string{channelSession, "direct-tcpip"},
		permittedForwards: &control.ForwardPolicy{
			DirectTCPIP: []control.ForwardDestination{{Host: "db.internal", Port: 5432}},
		},
	})
	client := h.mustDial(h.username())

	if _, _, err := client.OpenChannel("direct-tcpip", directTCPIP("10.0.0.9", 22)); err == nil {
		t.Fatal("a destination outside the allow-list was opened")
	}

	rec, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Kind == control.LogKindPolicyDecision &&
			r.Attributes[logging.AttrForwardHost] == "10.0.0.9"
	})
	if !ok {
		t.Fatal("the refused forward did not record its destination")
	}
	if rec.Attributes[logging.AttrForwardPort] != "22" {
		t.Errorf("forward port = %q, want 22", rec.Attributes[logging.AttrForwardPort])
	}
}

// TestAPTYRequestRecordsTheReplayHeader keeps a captured pty session
// reconstructable: the geometry the bytes were written for is recorded before
// them.
func TestAPTYRequestRecordsTheReplayHeader(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	client := h.mustDial(h.username())
	ch := openSessionChannel(t, client)

	if _, err := ch.SendRequest(control.RequestPTY, true, ptyRequest()); err != nil {
		t.Fatalf("pty request: %v", err)
	}
	// Then something the target finishes, so the channel ends on its own
	// rather than leaving a pty session open for the test's teardown to
	// unwind.
	if _, err := ch.SendRequest(control.RequestExec, true,
		ssh.Marshal(struct{ Command string }{"uptime"})); err != nil {
		t.Fatalf("exec request: %v", err)
	}

	header, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Kind == control.LogKindStream && r.Attributes[logging.AttrCapture] == logging.CaptureHeader
	})
	if !ok {
		t.Fatal("no replay header was recorded for the pty")
	}
	if header.Attributes[logging.AttrTerm] != "xterm" ||
		header.Attributes[logging.AttrWidth] != "80" ||
		header.Attributes[logging.AttrHeight] != "24" {
		t.Errorf("replay header = %v, want the terminal the client asked for", header.Attributes)
	}
	_ = ch.Close()
	_ = client.Close()
}

// TestASetupFailureIsRecordedWithItsStage keeps an outage distinguishable from
// a denial in the record, the same way it is in what the user is told
// (PLAN §4.3).
func TestASetupFailureIsRecordedWithItsStage(t *testing.T) {
	h := newHarness(t, harnessOptions{
		authorize: func(*control.AuthorizeRequest) (*control.AuthorizeResponse, error) {
			return nil, outageError("Authorize")
		},
	})
	client, err := h.dial(h.username())
	if err == nil {
		defer func() { _ = client.Close() }()
		session, sessionErr := client.NewSession()
		if sessionErr == nil {
			_ = session.Run("uptime")
			_ = session.Close()
		}
	}

	rec, ok := h.awaitRecord(func(r control.LogRecord) bool { return r.Kind == control.LogKindError })
	if !ok {
		t.Fatal("a failed session produced no error record")
	}
	if rec.Attributes[logging.AttrStage] != string(stageAuthorize) {
		t.Errorf("failure stage = %q, want %q", rec.Attributes[logging.AttrStage], stageAuthorize)
	}
	if rec.Severity != control.SeverityWarn {
		t.Errorf("a service outage was recorded as %q, want warn: it is not a security event", rec.Severity)
	}
}

// TestAKilledSessionSaysSoImmediately keeps a revocation from looking like a
// crash in the record, the way it does not on the terminal (PLAN §4.3, §6.4).
func TestAKilledSessionSaysSoImmediately(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	client := h.mustDial(h.username())
	defer func() { _ = client.Close() }()

	waitFor(t, func() bool { return len(h.server.Sessions()) == 1 }, "the session to register")
	h.server.KillSession(context.Background(), testSessionID, "access was revoked")

	rec, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Kind == control.LogKindPolicyDecision &&
			r.Attributes[logging.AttrReason] == "access was revoked"
	})
	if !ok {
		t.Fatal("a killed session produced no record of why")
	}
	if !recordedOnPriorityPath(h, rec.RecordID) {
		t.Error("a session kill did not take the priority path")
	}
}

// TestNoRecorderIsNotASpecialCase keeps every capture point safe on a proxy
// built without a telemetry pipeline.
func TestNoRecorderIsNotASpecialCase(t *testing.T) {
	h := newHarness(t, harnessOptions{options: func(o *Options) { o.Recorder = nil }})
	if _, status := runAndCollect(t, h, "uptime"); status != 0 {
		t.Errorf("the command exited %d with no recorder attached", status)
	}
	if got := len(h.client.records()); got != 0 {
		t.Errorf("%d records were shipped by a proxy with no recorder", got)
	}
}
