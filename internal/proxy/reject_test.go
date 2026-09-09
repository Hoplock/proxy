// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/auth/target"
	"github.com/hoplock/proxy/internal/auth/user"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/logging"
	"github.com/hoplock/proxy/internal/sshtest"
)

// This file is the engine's half of prompt 0025: a target that refuses the
// proxy's OWN credential is classified as its own failure, told to the user as
// an outage that discloses nothing about the credential, and recorded as a
// critical event.

// refusingOptions describe a topology where the target accepts one key and the
// proxy holds another, so the target leg fails on a REAL rejection rather than
// on a stubbed error. That is the whole reason these tests are worth having:
// the classification is a text match on what x/crypto produces, and a stub
// would be asserting on our own copy of it.
func refusingOptions(t *testing.T, breaker *target.RejectionBreaker) harnessOptions {
	t.Helper()
	accepted := sshtest.MustGenerateSigner()
	held := sshtest.MustGenerateSigner()

	placeholder, err := target.NewStaticKeyAuthenticator(target.StaticKeyOptions{Signer: held})
	if err != nil {
		t.Fatalf("NewStaticKeyAuthenticator: %v", err)
	}
	selector, err := target.NewSelector(
		map[string]target.TargetAuthenticator{target.MethodStaticKey: placeholder},
		target.MethodStaticKey,
		nil,
	)
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}
	return harnessOptions{
		targetAuth:    selector.WithRejectionBreaker(breaker),
		targetOptions: sshtest.Options{AuthorizedKeys: []ssh.PublicKey{accepted.PublicKey()}},
	}
}

func refusingHarness(t *testing.T, breaker *target.RejectionBreaker) *harness {
	t.Helper()
	return newHarness(t, refusingOptions(t, breaker))
}

// TestARefusedTargetCredentialIsNotReportedAsAnUnreachableTarget is the defect
// phase 0012 found, stated as a test.
//
// The target is up and answering; what it refused is a credential this proxy
// holds. Told "the target could not be reached", the operator reading the audit
// log is sent to look at the network — the one part of the system that is
// working.
func TestARefusedTargetCredentialIsNotReportedAsAnUnreachableTarget(t *testing.T) {
	h := refusingHarness(t, nil)

	text, status := runAndCollect(t, h, "uptime")

	if status == 0 {
		t.Error("a session whose credential was refused exited 0")
	}
	if strings.Contains(text, user.DenyMessage) {
		t.Errorf("user saw %q; a refused PROXY credential is an outage, not the user's permissions", text)
	}
	if strings.Contains(text, "the target could not be reached") {
		t.Errorf("user saw %q; the target was reached and refused us", text)
	}
	if !strings.Contains(text, "credential for this target was refused") {
		t.Errorf("user saw %q, want it to name a refused credential", text)
	}
	if !strings.Contains(text, testSessionID) {
		t.Errorf("user saw %q, want the session id as the support reference (PLAN §4.3)", text)
	}
}

// TestARefusedTargetCredentialIsRecordedCritically covers the audit half: the
// event a security team watches for does not wait in a batch, and it names the
// credential by HANDLE and by nothing else.
func TestARefusedTargetCredentialIsRecordedCritically(t *testing.T) {
	h := refusingHarness(t, nil)
	runAndCollect(t, h, "uptime")

	rec, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Attributes[logging.AttrEvent] == "target.credential_rejected"
	})
	if !ok {
		t.Fatal("a refused proxy credential produced no record")
	}
	if rec.Kind != control.LogKindError {
		t.Errorf("record kind = %s, want %s", rec.Kind, control.LogKindError)
	}
	if rec.Severity != control.SeverityCritical {
		t.Errorf("record severity = %s, want critical so it takes D8's immediate path", rec.Severity)
	}
	host, port := h.targetHostPort()
	wantAddr := net.JoinHostPort(host, strconv.Itoa(port))
	if rec.Attributes[logging.AttrTargetAddr] != wantAddr {
		t.Errorf("record target = %q, want %q", rec.Attributes[logging.AttrTargetAddr], wantAddr)
	}
	if rec.Attributes[logging.AttrCredentialMethod] != target.MethodStaticKey {
		t.Errorf("record method = %q, want %q",
			rec.Attributes[logging.AttrCredentialMethod], target.MethodStaticKey)
	}
	if handle := rec.Attributes[logging.AttrCredentialHandle]; !strings.HasPrefix(handle, "SHA256:") {
		t.Errorf("record credential handle = %q, want a key fingerprint", handle)
	}
	if rec.Attributes[logging.AttrStage] != string(stageTargetAuth) {
		t.Errorf("record stage = %q, want %q", rec.Attributes[logging.AttrStage], stageTargetAuth)
	}
}

// TestRepeatedRejectionsStopReachingTheTarget is containment, asserted where it
// is observable: the target's own record of who tried to log in.
//
// Timing proves nothing here and a count does. The target records every key it
// was offered, so "the proxy stopped trying" is the assertion that the number
// of offers stops going up while sessions keep arriving.
func TestRepeatedRejectionsStopReachingTheTarget(t *testing.T) {
	breaker := target.NewRejectionBreaker(target.RejectionPolicy{
		Threshold: 2,
		Window:    time.Minute,
		Cooldown:  time.Minute,
	})
	h := refusingHarness(t, breaker)

	for i := 0; i < 2; i++ {
		if _, status := runAndCollect(t, h, "uptime"); status == 0 {
			t.Fatalf("session %d succeeded against a target that refuses this credential", i+1)
		}
	}
	attempts := len(h.target.Keys())
	if attempts < 2 {
		t.Fatalf("the target saw %d login attempts, want one per session", attempts)
	}

	text, status := runAndCollect(t, h, "uptime")
	if status == 0 {
		t.Error("a session on a withheld credential succeeded")
	}
	if got := len(h.target.Keys()); got != attempts {
		t.Errorf("the target saw %d more login attempts after the breaker opened; it must see none", got-attempts)
	}
	if !strings.Contains(text, "is not attempting the connection at present") {
		t.Errorf("user saw %q, want the wording that says nothing was attempted", text)
	}
	if strings.Contains(text, user.DenyMessage) {
		t.Errorf("user saw %q; a withheld credential is the proxy's problem, not the user's", text)
	}

	rec, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Attributes[logging.AttrEvent] == "target.credential_withheld"
	})
	if !ok {
		t.Fatal("a withheld credential produced no record")
	}
	if rec.Severity != control.SeverityCritical || rec.Kind != control.LogKindError {
		t.Errorf("withheld record = %s/%s, want a critical error record", rec.Kind, rec.Severity)
	}
	if rec.Attributes[logging.AttrRejectionState] != "open" ||
		rec.Attributes[logging.AttrRejectionCount] != "2" {
		t.Errorf("withheld record = %v, want an open breaker at two consecutive rejections", rec.Attributes)
	}
}

// TestNoRecordCarriesCredentialMaterial is the rule that is invisible in a
// diff: everything these records name is a handle.
func TestNoRecordCarriesCredentialMaterial(t *testing.T) {
	breaker := target.NewRejectionBreaker(target.RejectionPolicy{
		Threshold: 1, Window: time.Minute, Cooldown: time.Minute,
	})
	h := refusingHarness(t, breaker)
	runAndCollect(t, h, "uptime")
	runAndCollect(t, h, "uptime")

	h.flushRecords()
	for _, rec := range h.records() {
		for key, value := range rec.Attributes {
			if strings.Contains(value, "PRIVATE KEY") || strings.Contains(value, "BEGIN OPENSSH") {
				t.Errorf("record attribute %s carries key material", key)
			}
		}
		if strings.Contains(rec.Message, "PRIVATE KEY") {
			t.Errorf("record message carries key material: %s", rec.Message)
		}
	}
}

// TestAHostKeyFailureStillWinsOverTheRejectionBranch keeps the ordering the
// prompt calls out: a host key the proxy would not accept also surfaces as a
// handshake error, and it is a different failure with a different fix.
func TestAHostKeyFailureStillWinsOverTheRejectionBranch(t *testing.T) {
	// Both failures are live at once: the target would refuse this credential
	// AND the server refuses its host key. Ordered the other way round, the
	// session would be reported as a refused credential and the breaker would
	// score a rejection against a credential the target never even saw.
	opts := refusingOptions(t, target.NewRejectionBreaker(target.RejectionPolicy{
		Threshold: 1, Window: time.Minute, Cooldown: time.Minute,
	}))
	opts.hostKey = func(*control.HostKeyReportRequest) (*control.HostKeyReportResponse, error) {
		return &control.HostKeyReportResponse{Decision: control.HostKeyReject, Reason: "unknown key"}, nil
	}
	h := newHarness(t, opts)

	text, _ := runAndCollect(t, h, "uptime")
	if !strings.Contains(text, "host key was not accepted") {
		t.Errorf("user saw %q, want the host-key failure", text)
	}
	if strings.Contains(text, "credential for this target was refused") {
		t.Errorf("user saw %q; a host-key failure was classified as a refused credential", text)
	}

	// And nothing was scored: the next session must still be attempted.
	text, _ = runAndCollect(t, h, "uptime")
	if strings.Contains(text, "is not attempting the connection at present") {
		t.Errorf("user saw %q; a host-key failure opened the credential breaker", text)
	}
}
