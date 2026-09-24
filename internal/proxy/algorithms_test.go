// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"strings"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/auth/target"
	"github.com/hoplock/proxy/internal/auth/user"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/logging"
	"github.com/hoplock/proxy/internal/sshtest"
)

// This file is the engine's half of phase 0043: the route's algorithm profile
// is APPLIED to the session leg, the default is the library's secure set, a
// target the profile strands fails as its own stage, and the record names the
// profile the handshake used. Every target here is a real in-process SSH server
// negotiating for real, because what is under test is what goes on the wire.

// Stand-ins for appliance firmware, by what they are limited to.
func dsaOnlyTarget(t *testing.T) sshtest.Options {
	t.Helper()
	key, err := sshtest.GenerateDSAHostKey()
	if err != nil {
		t.Fatal(err)
	}
	return sshtest.Options{HostKey: key}
}

func rsaSHA1OnlyTarget(t *testing.T) sshtest.Options {
	t.Helper()
	key, err := sshtest.GenerateRSASHA1HostKey()
	if err != nil {
		t.Fatal(err)
	}
	return sshtest.Options{HostKey: key}
}

func sha1KexOnlyTarget() sshtest.Options {
	return sshtest.Options{Negotiation: sshtest.Negotiation{KeyExchanges: []string{"diffie-hellman-group14-sha1"}}}
}

// legacyOnlyTarget offers ONLY what legacy-device adds, on every axis.
func legacyOnlyTarget(t *testing.T) sshtest.Options {
	t.Helper()
	opts := dsaOnlyTarget(t)
	opts.Negotiation = sshtest.Negotiation{
		KeyExchanges: []string{"diffie-hellman-group14-sha1"},
		Ciphers:      []string{"aes128-cbc"},
		MACs:         []string{"hmac-sha1-96"},
	}
	return opts
}

func profileHarness(t *testing.T, target sshtest.Options, profile control.AlgorithmProfile) *harness {
	t.Helper()
	return newHarness(t, harnessOptions{targetOptions: target, algorithmProfile: profile})
}

// assertAlgorithmPolicyUnmet checks every half of the stage: what the user is
// told, and the warn record an operator reads.
func assertAlgorithmPolicyUnmet(t *testing.T, h *harness, text string, status int, axis, profile, offered string) {
	t.Helper()
	if status == 0 {
		t.Fatalf("session exited 0; want the handshake to fail (output %q)", text)
	}
	if strings.Contains(text, user.DenyMessage) {
		t.Errorf("user saw %q; an unmet algorithm policy is an outage, not a denial", text)
	}
	if strings.Contains(text, "the target could not be reached") {
		t.Errorf("user saw %q; the target was reached and spoke SSH", text)
	}
	if !strings.Contains(text, "the target does not support the algorithms this route allows") {
		t.Errorf("user saw %q, want the algorithm-policy outage text", text)
	}
	if !strings.Contains(text, testSessionID) {
		t.Errorf("user saw %q, want the session id (PLAN §4.3)", text)
	}

	rec, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Attributes[logging.AttrEvent] == logging.EventAlgorithmPolicyUnmet
	})
	if !ok {
		t.Fatal("no target.algorithm_policy_unmet record")
	}
	if rec.Severity != control.SeverityWarn || rec.Kind != control.LogKindError {
		t.Errorf("record %s/%s, want error/warn — an outage on the batch path, not a security event", rec.Kind, rec.Severity)
	}
	if got := rec.Attributes[logging.AttrAlgorithmAxis]; got != axis {
		t.Errorf("algorithm_axis = %q, want %q", got, axis)
	}
	if got := rec.Attributes[logging.AttrAlgorithmProfile]; got != profile {
		t.Errorf("algorithm_profile = %q, want %q", got, profile)
	}
	if got := rec.Attributes[logging.AttrTargetAlgorithmsOffered]; !strings.Contains(got, offered) {
		t.Errorf("target_algorithms_offered = %q, want it to name %q", got, offered)
	}
	if rec.Attributes[logging.AttrStage] != string(stageAlgorithmPolicy) {
		t.Errorf("stage = %q, want %q", rec.Attributes[logging.AttrStage], stageAlgorithmPolicy)
	}
	for _, r := range h.records() {
		if r.Attributes[logging.AttrEvent] == "target.credential_rejected" {
			t.Error("an algorithm failure was recorded as a refused credential")
		}
	}
}

func TestADSAOnlyTargetNeedsLegacyDevice(t *testing.T) {
	opts := dsaOnlyTarget(t)
	for _, profile := range []control.AlgorithmProfile{"", control.AlgorithmProfileLegacyRSASHA1} {
		h := profileHarness(t, opts, profile)
		text, status := runAndCollect(t, h, "uptime")
		assertAlgorithmPolicyUnmet(t, h, text, status, target.AlgorithmAxisHostKey, string(profile.Resolve()), "ssh-dss")
	}

	// runSession fails the test unless the command runs to completion.
	runSession(t, profileHarness(t, opts, control.AlgorithmProfileLegacyDevice))
}

func TestAnRSASHA1OnlyTargetNeedsLegacyRSASHA1(t *testing.T) {
	opts := rsaSHA1OnlyTarget(t)
	h := profileHarness(t, opts, control.AlgorithmProfileDefault)
	text, status := runAndCollect(t, h, "uptime")
	assertAlgorithmPolicyUnmet(t, h, text, status, target.AlgorithmAxisHostKey, "default", "ssh-rsa")

	runSession(t, profileHarness(t, opts, control.AlgorithmProfileLegacyRSASHA1))
}

// TestASHA1KeyExchangeTargetFailsUnderDefault is the break this phase
// announces, made visible: a target that only speaks SHA-1 key exchange no
// longer connects on the default profile, the operator is told which axis and
// what the target offered, and the 0025 breaker never hears about it.
func TestASHA1KeyExchangeTargetFailsUnderDefault(t *testing.T) {
	// A breaker that would withhold the credential after ONE rejection: if the
	// algorithm failure were scored against it, the second session would be
	// withheld rather than failing on the same stage.
	breaker := target.NewRejectionBreaker(target.RejectionPolicy{Threshold: 1, Window: time.Minute, Cooldown: time.Minute})
	signer := sshtest.MustGenerateSigner()
	static, err := target.NewStaticKeyAuthenticator(target.StaticKeyOptions{Signer: signer, Username: testTargetAccount})
	if err != nil {
		t.Fatal(err)
	}
	selector, err := target.NewSelector(map[string]target.TargetAuthenticator{target.MethodStaticKey: static}, target.MethodStaticKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, harnessOptions{targetOptions: sha1KexOnlyTarget(), targetAuth: selector.WithRejectionBreaker(breaker)})

	for i := 0; i < 2; i++ {
		text, status := runAndCollect(t, h, "uptime")
		assertAlgorithmPolicyUnmet(t, h, text, status, target.AlgorithmAxisKeyExchange, "default", "diffie-hellman-group14-sha1")
	}
	host, port := h.targetHostPort()
	key := target.RejectionKey{Target: target.Target{Host: host, Port: port}.Addr(), Method: target.MethodStaticKey, Handle: static.CredentialHandle(target.Target{})}
	if st := breaker.State(key); st.Consecutive != 0 || st.Open {
		t.Fatalf("breaker state after algorithm failures = %+v, want untouched", st)
	}

	runSession(t, profileHarness(t, sha1KexOnlyTarget(), control.AlgorithmProfileLegacyDevice))
}

// TestLegacyDeviceIsScopedToTheRoute is the positive and the negative half
// together, and the negative half is the one that proves something: the same
// target, the same proxy build, and the default route still does not
// handshake — the weakening belongs to the route, not to the fleet.
//
// It is also where the record and the handshake are held together. Both are
// read from the same route, and a route naming a non-default profile must show
// that profile on its provisioning record AND have used it on the wire.
func TestLegacyDeviceIsScopedToTheRoute(t *testing.T) {
	opts := legacyOnlyTarget(t)

	legacy := profileHarness(t, opts, control.AlgorithmProfileLegacyDevice)
	runSession(t, legacy)
	if cmds := legacy.target.Commands(); len(cmds) != 1 {
		t.Fatalf("the legacy-only target ran %q, want the one command", cmds)
	}
	rec, ok := legacy.awaitRecord(func(r control.LogRecord) bool { return r.Kind == control.LogKindProvisioning })
	if !ok {
		t.Fatal("no provisioning record")
	}
	if got := rec.Attributes[logging.AttrAlgorithmProfile]; got != string(control.AlgorithmProfileLegacyDevice) {
		t.Errorf("provisioning record algorithm_profile = %q, want legacy-device", got)
	}

	def := profileHarness(t, opts, "")
	text, status := runAndCollect(t, def, "uptime")
	if status == 0 {
		t.Fatalf("the default route handshook with a legacy-only target: %q", text)
	}
	if !strings.Contains(text, "the target does not support the algorithms this route allows") {
		t.Errorf("default route against a legacy-only target: user saw %q", text)
	}
}

// TestDefaultIsStampedNotOmitted pins the rule PLAN §7 states: the profile is
// always on the provisioning record, so absence never has to be read as a
// value.
func TestDefaultIsStampedNotOmitted(t *testing.T) {
	h := profileHarness(t, sshtest.Options{}, "")
	runSession(t, h)
	rec, ok := h.awaitRecord(func(r control.LogRecord) bool { return r.Kind == control.LogKindProvisioning })
	if !ok {
		t.Fatal("no provisioning record")
	}
	if got := rec.Attributes[logging.AttrAlgorithmProfile]; got != "default" {
		t.Errorf("provisioning record algorithm_profile = %q, want default", got)
	}
}

// TestEverySessionRecordUsesOneNamePerField scans every attribute a whole
// session emits for the naming verdict (phase 0043): the method and the rung
// leave this proxy as credential_method and credential_rung, and never also as
// Hoplock Control's target_auth_method / target_auth_rung.
func TestEverySessionRecordUsesOneNamePerField(t *testing.T) {
	h := profileHarness(t, sshtest.Options{}, control.AlgorithmProfileLegacyRSASHA1)
	runSession(t, h)
	sawMethod := false
	for _, rec := range h.records() {
		for key := range rec.Attributes {
			if key == "target_auth_method" || key == "target_auth_rung" {
				t.Errorf("%s record carries %q", rec.Kind, key)
			}
			if key == logging.AttrCredentialMethod {
				sawMethod = true
			}
		}
	}
	if !sawMethod {
		t.Error("no record named the credential method at all")
	}
}
