// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/auth/target"
	"github.com/hoplock/proxy/internal/auth/user"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/identity"
	"github.com/hoplock/proxy/internal/logging"
	"github.com/hoplock/proxy/internal/sshtest"
)

// This file is the engine's half of phase 0045: a floor and a ban are applied
// to the session leg, an unmet one fails the session as the algorithm-policy
// outage with its cause on the record — never a deny, never a fallback, never
// scored against the credential — every leg that comes up records what it
// negotiated, and every handshake feeds the target's key-exchange report.
// Every target here negotiates for real.

// Stand-ins, by the key exchanges they offer.
func classicalOnlyTarget() sshtest.Options {
	return sshtest.Options{Negotiation: sshtest.Negotiation{KeyExchanges: []string{"curve25519-sha256", "ecdh-sha2-nistp256"}}}
}

// sntrupTarget offers OpenSSH 9.0–9.8's default hybrid and classical exchanges
// — the population Correction 1 exists for. x/crypto cannot serve sntrup761,
// so this target only advertises (sshtest.KexInitTarget).
var sntrupTarget = sshtest.KexInitOptions{KeyExchanges: []string{
	"sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com", "curve25519-sha256", "ecdh-sha2-nistp256",
	"kex-strict-s-v00@openssh.com",
}}

// kexObservations records what the engine hands its key-exchange observer.
type kexObservations struct {
	mu   sync.Mutex
	seen []control.KexObservation
}

func (k *kexObservations) ObserveKex(_ string, _ int, o *control.KexObservation) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.seen = append(k.seen, *o)
}

func (k *kexObservations) all() []control.KexObservation {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]control.KexObservation(nil), k.seen...)
}

func withObserver(o KexObserver) func(*Options) {
	return func(opts *Options) { opts.KexObserver = o }
}

// countingAuth counts how often the engine asks for credentials, which is how a
// test sees that nothing retried with another rung.
type countingAuth struct {
	target.TargetAuthenticator
	calls atomic.Int32
}

func (c *countingAuth) Provision(ctx context.Context, id *identity.Identity, tgt target.Target) (*target.ProvisionedAccess, error) {
	c.calls.Add(1)
	return c.TargetAuthenticator.Provision(ctx, id, tgt)
}

// breakerAuth is a static-key credential plane behind a breaker that withholds
// the credential after ONE rejection, on a two-rung ladder: if an algorithm
// failure were scored, or walked on, the next session would show it.
func breakerAuth(t *testing.T) (*countingAuth, *target.RejectionBreaker, *target.StaticKeyAuthenticator, *control.TargetAuthLadder) {
	t.Helper()
	breaker := target.NewRejectionBreaker(target.RejectionPolicy{Threshold: 1, Window: time.Minute, Cooldown: time.Minute})
	static, err := target.NewStaticKeyAuthenticator(target.StaticKeyOptions{Signer: sshtest.MustGenerateSigner(), Username: testTargetAccount})
	if err != nil {
		t.Fatal(err)
	}
	selector, err := target.NewSelector(map[string]target.TargetAuthenticator{target.MethodStaticKey: static}, target.MethodStaticKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	rung := control.TargetAuth{Method: control.TargetAuthStaticKey, Params: map[string]string{control.ParamUsername: testTargetAccount}}
	ladder := &control.TargetAuthLadder{rung, rung}
	return &countingAuth{TargetAuthenticator: selector.WithRejectionBreaker(breaker)}, breaker, static, ladder
}

func negotiatedRecord(t *testing.T, h *harness) control.LogRecord {
	t.Helper()
	rec, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Attributes[logging.AttrEvent] == logging.EventAlgorithmsNegotiated
	})
	if !ok {
		t.Fatal("no target.algorithms_negotiated record")
	}
	if rec.Kind != control.LogKindProvisioning || rec.Severity != control.SeverityInfo {
		t.Errorf("negotiated record %s/%s, want provisioning/info on the batch path", rec.Kind, rec.Severity)
	}
	return rec
}

// assertPolicyUnmet checks every half of the stage for a floor or ban failure:
// what the user is told, and the warn record an operator reads.
func assertPolicyUnmet(t *testing.T, h *harness, text string, status int, userText, axis, cause, offered string) control.LogRecord {
	t.Helper()
	if status == 0 {
		t.Fatalf("session exited 0; want the handshake to fail (output %q)", text)
	}
	if strings.Contains(text, user.DenyMessage) {
		t.Errorf("user saw %q; an unmet algorithm policy is an outage, not a denial", text)
	}
	if !strings.Contains(text, userText) {
		t.Errorf("user saw %q, want %q", text, userText)
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
		t.Errorf("record %s/%s, want error/warn — an outage on the batch path", rec.Kind, rec.Severity)
	}
	for key, want := range map[string]string{
		logging.AttrAlgorithmAxis:        axis,
		logging.AttrAlgorithmPolicyCause: cause,
		logging.AttrStage:                string(stageAlgorithmPolicy),
	} {
		if got := rec.Attributes[key]; got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if got := rec.Attributes[logging.AttrTargetAlgorithmsOffered]; !strings.Contains(got, offered) {
		t.Errorf("target_algorithms_offered = %q, want it to name %q", got, offered)
	}
	for _, r := range h.records() {
		if r.Attributes[logging.AttrEvent] == "target.credential_rejected" {
			t.Error("an algorithm failure was recorded as a refused credential")
		}
	}
	return rec
}

const pqFloorText = "this route requires a post-quantum key exchange, and the target does not support one"

// TestAPostQuantumFloorConnectsToAnMLKEMTarget: the floor is met, the session
// runs, and the record carries what was negotiated beside the floor in force.
func TestAPostQuantumFloorConnectsToAnMLKEMTarget(t *testing.T) {
	h := newHarness(t, harnessOptions{algorithmFloor: control.AlgorithmFloorPQHybridKEX})
	runSession(t, h)

	rec := negotiatedRecord(t, h)
	for key, want := range map[string]string{
		logging.AttrTargetKexAlgorithm: control.KeyExchangeMLKEM768X25519,
		logging.AttrAlgorithmFloor:     "pq-hybrid-kex",
		logging.AttrAlgorithmProfile:   "default",
	} {
		if got := rec.Attributes[key]; got != want {
			t.Errorf("negotiated record %s = %q, want %q", key, got, want)
		}
	}
	for _, key := range []string{logging.AttrTargetHostKeyAlgorithm, logging.AttrTargetCipherOut,
		logging.AttrTargetCipherIn, logging.AttrTargetPublicKeyAlgorithmsOffered} {
		if rec.Attributes[key] == "" {
			t.Errorf("negotiated record has no %s", key)
		}
	}
	// The provisioning record names the floor where it names the profile.
	prov, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Kind == control.LogKindProvisioning && r.Attributes[logging.AttrCredentialMethod] != ""
	})
	if !ok || prov.Attributes[logging.AttrAlgorithmFloor] != "pq-hybrid-kex" {
		t.Errorf("provisioning record algorithm_floor = %q, want pq-hybrid-kex", prov.Attributes[logging.AttrAlgorithmFloor])
	}
}

// TestAPostQuantumFloorRefusesAClassicalTarget: the outage, specific and with
// the session id; the warn record with the target's list; the breaker never
// hears of it; and no second rung is tried.
func TestAPostQuantumFloorRefusesAClassicalTarget(t *testing.T) {
	auth, breaker, static, ladder := breakerAuth(t)
	h := newHarness(t, harnessOptions{targetOptions: classicalOnlyTarget(), algorithmFloor: control.AlgorithmFloorPQHybridKEX,
		targetAuth: auth, targetAuthLadder: ladder})

	for i := 1; i <= 2; i++ {
		text, status := runAndCollect(t, h, "uptime")
		rec := assertPolicyUnmet(t, h, text, status, pqFloorText, target.AlgorithmAxisKeyExchange, "floor", "curve25519-sha256")
		if rec.Attributes[logging.AttrAlgorithmFloor] != "pq-hybrid-kex" {
			t.Errorf("unmet record algorithm_floor = %q", rec.Attributes[logging.AttrAlgorithmFloor])
		}
		if got := auth.calls.Load(); got != int32(i) {
			t.Fatalf("after %d sessions the credential plane was asked %d times: something retried", i, got)
		}
	}
	// The rung in force was the first; nothing walked on to the second.
	prov, ok := h.awaitRecord(func(r control.LogRecord) bool { return r.Attributes[logging.AttrCredentialRung] != "" })
	if !ok || prov.Attributes[logging.AttrCredentialRung] != "1" {
		t.Errorf("credential_rung = %q, want 1: an algorithm failure is not a rung failure", prov.Attributes[logging.AttrCredentialRung])
	}
	host, port := h.targetHostPort()
	key := target.RejectionKey{Target: target.Target{Host: host, Port: port}.Addr(), Method: target.MethodStaticKey,
		Handle: static.CredentialHandle(target.Target{})}
	if st := breaker.State(key); st.Consecutive != 0 || st.Open {
		t.Fatalf("breaker state after floor failures = %+v, want untouched", st)
	}
}

// TestAPostQuantumFloorRefusesAnSntrup761Target is Correction 1 made concrete:
// OpenSSH's own hybrid is not one this proxy implements, so a target offering
// only it does not meet the level.
func TestAPostQuantumFloorRefusesAnSntrup761Target(t *testing.T) {
	auth, breaker, static, ladder := breakerAuth(t)
	obs := &kexObservations{}
	h := newHarness(t, harnessOptions{kexInitTarget: &sntrupTarget, algorithmFloor: control.AlgorithmFloorPQHybridKEX,
		targetAuth: auth, targetAuthLadder: ladder, options: withObserver(obs)})

	text, status := runAndCollect(t, h, "uptime")
	rec := assertPolicyUnmet(t, h, text, status, pqFloorText, target.AlgorithmAxisKeyExchange, "floor", "sntrup761x25519-sha512")
	if strings.Contains(rec.Attributes[logging.AttrTargetAlgorithmsOffered], "kex-strict") {
		t.Errorf("the offered list carries an extension signal: %q", rec.Attributes[logging.AttrTargetAlgorithmsOffered])
	}
	host, port := h.targetHostPort()
	key := target.RejectionKey{Target: target.Target{Host: host, Port: port}.Addr(), Method: target.MethodStaticKey,
		Handle: static.CredentialHandle(target.Target{})}
	if st := breaker.State(key); st.Consecutive != 0 || st.Open {
		t.Fatalf("breaker state = %+v, want untouched", st)
	}
	if auth.calls.Load() != 1 {
		t.Errorf("the credential plane was asked %d times", auth.calls.Load())
	}
	// The failure reveals the target's whole list: an exact observation that
	// it meets modern-kex and not the hybrid level.
	seen := obs.all()
	if len(seen) != 1 || seen[0].FloorMet != "modern-kex" || seen[0].Negotiated != "" ||
		len(seen[0].Offered) != 4 {
		t.Errorf("key-exchange observations = %+v, want one: modern-kex from the target's four exchanges", seen)
	}
}

// TestWithoutAFloorTheClassicalTargetStillConnects: nothing that connected
// before this phase stops connecting, and the record names the classical
// exchange it used.
func TestWithoutAFloorTheClassicalTargetStillConnects(t *testing.T) {
	h := newHarness(t, harnessOptions{targetOptions: classicalOnlyTarget()})
	runSession(t, h)
	rec := negotiatedRecord(t, h)
	if got := rec.Attributes[logging.AttrTargetKexAlgorithm]; got != "curve25519-sha256" {
		t.Errorf("target_kex_algorithm = %q, want the classical exchange", got)
	}
	if _, present := rec.Attributes[logging.AttrAlgorithmFloor]; present {
		t.Error("a route with no floor stamped algorithm_floor; absence is the one spelling of no floor")
	}
}

// TestTheFloorIsTurnedByTheDecisionAlone: the same route moved DOWN to
// modern-kex connects to a classical-only modern target, and moved UP again it
// fails with the floor stage. Nothing about the proxy changed but the decision.
func TestTheFloorIsTurnedByTheDecisionAlone(t *testing.T) {
	var floor atomic.Value
	floor.Store(control.AlgorithmFloorPQHybridKEX)
	h := newHarness(t, harnessOptions{targetOptions: classicalOnlyTarget()})
	h.client.authorize = func(*control.AuthorizeRequest) (*control.AuthorizeResponse, error) {
		host, port := h.targetHostPort()
		return &control.AuthorizeResponse{
			RouteType: control.RouteTypeDirect, Target: host, TargetPort: port,
			PermittedChannels: []string{channelSession}, FilterPolicy: control.FilterPolicy{Mode: control.FilterModeBlacklist},
			AlgorithmFloor: floor.Load().(control.AlgorithmFloor),
		}, nil
	}

	text, status := runAndCollect(t, h, "uptime")
	if status == 0 || !strings.Contains(text, pqFloorText) {
		t.Fatalf("at pq-hybrid-kex: status %d, %q", status, text)
	}
	floor.Store(control.AlgorithmFloorModernKEX)
	runSession(t, h)
	floor.Store(control.AlgorithmFloorPQHybridKEX)
	if text, status := runAndCollect(t, h, "uptime"); status == 0 || !strings.Contains(text, pqFloorText) {
		t.Fatalf("raised again: status %d, %q", status, text)
	}
}

// TestABannedCipherIsNegotiatedAround: a target that offers another cipher is
// reached on it, and the record says which, in both directions.
func TestABannedCipherIsNegotiatedAround(t *testing.T) {
	obs := &kexObservations{}
	h := newHarness(t, harnessOptions{
		targetOptions: sshtest.Options{Negotiation: sshtest.Negotiation{Ciphers: []string{"aes128-ctr", "aes256-ctr"}}},
		algorithmBans: &control.AlgorithmBans{Ciphers: []string{"aes128-ctr"}},
		options:       withObserver(obs),
	})
	runSession(t, h)
	rec := negotiatedRecord(t, h)
	if rec.Attributes[logging.AttrTargetCipherOut] != "aes256-ctr" || rec.Attributes[logging.AttrTargetCipherIn] != "aes256-ctr" {
		t.Errorf("target_cipher_out/in = %q/%q, want aes256-ctr both ways",
			rec.Attributes[logging.AttrTargetCipherOut], rec.Attributes[logging.AttrTargetCipherIn])
	}
	if rec.Attributes[logging.AttrAlgorithmBansPrefix+"ciphers"] != "aes128-ctr" {
		t.Errorf("algorithm_bans.ciphers = %q", rec.Attributes[logging.AttrAlgorithmBansPrefix+"ciphers"])
	}
	// A non-AEAD cipher negotiates a MAC, and the record names it.
	if rec.Attributes[logging.AttrTargetMACOut] == "" || rec.Attributes[logging.AttrTargetMACIn] == "" {
		t.Error("a CTR cipher's MAC is missing from the record")
	}
	// A cipher ban does not reduce the key-exchange offer: still an observation.
	if seen := obs.all(); len(seen) != 1 || seen[0].FloorMet != "pq-hybrid-kex" {
		t.Errorf("observations = %+v, want pq-hybrid-kex", seen)
	}
}

// TestBanningTheOnlyCommonCipherFailsTheSession: the algorithm-policy stage on
// the cipher axis, caused by the ban, naming the target's ciphers — and the
// breaker untouched.
func TestBanningTheOnlyCommonCipherFailsTheSession(t *testing.T) {
	auth, breaker, static, ladder := breakerAuth(t)
	h := newHarness(t, harnessOptions{
		targetOptions:    sshtest.Options{Negotiation: sshtest.Negotiation{Ciphers: []string{"aes128-ctr"}}},
		algorithmBans:    &control.AlgorithmBans{Ciphers: []string{"aes128-ctr"}},
		targetAuth:       auth,
		targetAuthLadder: ladder,
	})
	text, status := runAndCollect(t, h, "uptime")
	rec := assertPolicyUnmet(t, h, text, status, "the target offers no cipher this route permits",
		target.AlgorithmAxisCipher, "ban", "aes128-ctr")
	if rec.Attributes[logging.AttrAlgorithmBansPrefix+"ciphers"] != "aes128-ctr" {
		t.Errorf("unmet record algorithm_bans.ciphers = %q", rec.Attributes[logging.AttrAlgorithmBansPrefix+"ciphers"])
	}
	if strings.Contains(text, "aes128-ctr") {
		t.Errorf("the user was told which algorithm is banned: %q", text)
	}
	host, port := h.targetHostPort()
	key := target.RejectionKey{Target: target.Target{Host: host, Port: port}.Addr(), Method: target.MethodStaticKey,
		Handle: static.CredentialHandle(target.Target{})}
	if st := breaker.State(key); st.Consecutive != 0 || st.Open {
		t.Fatalf("breaker state = %+v, want untouched", st)
	}
}

// TestAnUnmatchedBanIsNamedOnTheRecord: a ban on a name this build cannot
// offer is accepted and changes nothing — and is never silent.
func TestAnUnmatchedBanIsNamedOnTheRecord(t *testing.T) {
	h := newHarness(t, harnessOptions{algorithmBans: &control.AlgorithmBans{
		KeyExchanges: []string{"sntrup761x25519-sha512"}, MACs: []string{"hmac-sha1"}}})
	runSession(t, h)
	prov, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Kind == control.LogKindProvisioning && r.Attributes[logging.AttrCredentialMethod] != ""
	})
	if !ok {
		t.Fatal("no provisioning record")
	}
	if got := prov.Attributes[logging.AttrAlgorithmBansUnmatched]; got != "key_exchanges:sntrup761x25519-sha512" {
		t.Errorf("algorithm_bans_unmatched = %q, want the one name no build offers", got)
	}
	for key, want := range map[string]string{
		logging.AttrAlgorithmBansPrefix + "key_exchanges": "sntrup761x25519-sha512",
		logging.AttrAlgorithmBansPrefix + "macs":          "hmac-sha1",
	} {
		if got := prov.Attributes[key]; got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if _, present := prov.Attributes[logging.AttrAlgorithmBansPrefix+"ciphers"]; present {
		t.Error("an axis with no ban has an attribute")
	}
}

// TestEveryHandshakeFeedsTheKeyExchangeReport: what the engine observes on a
// success, on a failed negotiation, and under a key-exchange ban — where a
// success is NOT an observation and a failure still is.
func TestEveryHandshakeFeedsTheKeyExchangeReport(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		obs := &kexObservations{}
		runSession(t, newHarness(t, harnessOptions{targetOptions: classicalOnlyTarget(), options: withObserver(obs)}))
		if seen := obs.all(); len(seen) != 1 || seen[0].FloorMet != "modern-kex" ||
			seen[0].Negotiated != "curve25519-sha256" || seen[0].Offered != nil || seen[0].ObservedAt.IsZero() {
			t.Errorf("observations = %+v, want modern-kex negotiated on curve25519-sha256", seen)
		}
	})
	t.Run("failure", func(t *testing.T) {
		obs := &kexObservations{}
		h := newHarness(t, harnessOptions{targetOptions: classicalOnlyTarget(),
			algorithmFloor: control.AlgorithmFloorPQHybridKEX, options: withObserver(obs)})
		if _, status := runAndCollect(t, h, "uptime"); status == 0 {
			t.Fatal("the session ran")
		}
		if seen := obs.all(); len(seen) != 1 || seen[0].FloorMet != "modern-kex" || seen[0].Negotiated != "" ||
			len(seen[0].Offered) == 0 {
			t.Errorf("observations = %+v, want modern-kex from the target's list", seen)
		}
	})
	t.Run("success under a key-exchange ban", func(t *testing.T) {
		obs := &kexObservations{}
		runSession(t, newHarness(t, harnessOptions{options: withObserver(obs),
			algorithmBans: &control.AlgorithmBans{KeyExchanges: []string{control.KeyExchangeMLKEM768X25519}}}))
		if seen := obs.all(); len(seen) != 0 {
			t.Errorf("a success under a key-exchange ban was reported: %+v", seen)
		}
	})
	t.Run("failure under a key-exchange ban", func(t *testing.T) {
		obs := &kexObservations{}
		h := newHarness(t, harnessOptions{targetOptions: classicalOnlyTarget(), options: withObserver(obs),
			algorithmBans: &control.AlgorithmBans{KeyExchanges: []string{"curve25519-sha256", "ecdh-sha2-nistp256"}}})
		if _, status := runAndCollect(t, h, "uptime"); status == 0 {
			t.Fatal("the session ran")
		}
		if seen := obs.all(); len(seen) != 1 || seen[0].FloorMet != "modern-kex" {
			t.Errorf("observations = %+v, want the failure's exact modern-kex", seen)
		}
	})
}

// failingReporter answers every report late and with an error.
type failingReporter struct{ calls atomic.Int32 }

func (f *failingReporter) ReportCapabilities(ctx context.Context, _ *control.CapabilityReportRequest) (*control.CapabilityReportResponse, error) {
	f.calls.Add(1)
	select {
	case <-time.After(2 * time.Second):
	case <-ctx.Done():
	}
	return nil, errors.New("control is unreachable")
}

// TestAKeyExchangeReportIsNeverOnTheSessionPath: with the real reporter behind a
// Hoplock Control that answers slowly and then fails, the session is set up and
// runs without waiting for it, and nothing about the failure reaches the user.
func TestAKeyExchangeReportIsNeverOnTheSessionPath(t *testing.T) {
	slow := &failingReporter{}
	reports := target.NewKexReporter(target.KexReporterOptions{Reporter: slow})
	h := newHarness(t, harnessOptions{options: withObserver(reports)})

	start := time.Now()
	runSession(t, h)
	if elapsed := time.Since(start); elapsed >= 2*time.Second {
		t.Errorf("the session took %v: it waited on the report", elapsed)
	}
	reports.Wait()
	if slow.calls.Load() != 1 {
		t.Errorf("the reporter was called %d times, want 1", slow.calls.Load())
	}
}

// TestAKeyExchangeReportGoesOutForABrokeredRoute: the observation is made where
// the session leg is dialled, which every credential method shares — here a
// brokered-key route, reported through the real reporter once, and not again
// for a second session inside the freshness window.
func TestAKeyExchangeReportGoesOutForABrokeredRoute(t *testing.T) {
	reporter := &recordingReporter{}
	reports := target.NewKexReporter(target.KexReporterOptions{Reporter: reporter})
	h := brokeredHarness(t, withObserver(reports))

	runSession(t, h)
	runSession(t, h)
	reports.Wait()
	sent := reporter.all()
	if len(sent) != 1 {
		t.Fatalf("two brokered-key sessions sent %d reports, want 1", len(sent))
	}
	if k := sent[0].Capabilities.Kex; k == nil || k.FloorMet != "pq-hybrid-kex" {
		t.Errorf("report = %+v, want the target's pq-hybrid-kex", sent[0].Capabilities)
	}
}

// recordingReporter records capability reports and accepts them.
type recordingReporter struct {
	mu   sync.Mutex
	sent []*control.CapabilityReportRequest
}

func (r *recordingReporter) ReportCapabilities(_ context.Context, req *control.CapabilityReportRequest) (*control.CapabilityReportResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, req)
	return &control.CapabilityReportResponse{Accepted: true}, nil
}

func (r *recordingReporter) all() []*control.CapabilityReportRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*control.CapabilityReportRequest(nil), r.sent...)
}

// brokeredHarness is a route on the brokered-key method (D6a): a standing
// account and a credential held in memory for the session.
func brokeredHarness(t *testing.T, options func(*Options)) *harness {
	t.Helper()
	_, pem, err := sshtest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	store := t.TempDir()
	if err := os.WriteFile(filepath.Join(store, "core-switch.key"), pem, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := target.NewDirCredentialSource(store, "")
	if err != nil {
		t.Fatal(err)
	}
	brokered, err := target.NewBrokeredKeyAuthenticator(target.BrokeredKeyOptions{Source: source, Username: "netadmin"})
	if err != nil {
		t.Fatal(err)
	}
	selector, err := target.NewSelector(map[string]target.TargetAuthenticator{target.MethodBrokeredKey: brokered},
		target.MethodBrokeredKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	return newHarness(t, harnessOptions{targetAuth: selector, options: options,
		targetAuthLadder: &control.TargetAuthLadder{{
			Method: control.TargetAuthBrokeredKey,
			Params: map[string]string{control.ParamUsername: "netadmin", "credential_ref": "core-switch"},
		}}})
}

// TestAPublicKeyBanIsTheAlgorithmPolicyOutage: a ban that leaves the proxy's
// key no signature algorithm fails as the same stage and record as every other
// axis — not as "the target could not be reached" — and is never scored
// against the credential it could not use.
func TestAPublicKeyBanIsTheAlgorithmPolicyOutage(t *testing.T) {
	auth, breaker, static, ladder := breakerAuth(t)
	h := newHarness(t, harnessOptions{
		// The static key is ed25519; the ban leaves it nothing to sign with.
		algorithmBans:    &control.AlgorithmBans{PublicKeyAuths: []string{"ssh-ed25519"}},
		targetAuth:       auth,
		targetAuthLadder: ladder,
	})
	for i := 0; i < 2; i++ {
		text, status := runAndCollect(t, h, "uptime")
		rec := assertPolicyUnmet(t, h, text, status,
			"this route permits no signature algorithm the proxy's key for this target can use",
			target.AlgorithmAxisPublicKeyAuth, "ban", "")
		if strings.Contains(text, "could not be reached") {
			t.Errorf("user saw %q; the target answered", text)
		}
		if rec.Attributes[logging.AttrAlgorithmBansPrefix+"public_key_auth"] != "ssh-ed25519" {
			t.Errorf("algorithm_bans.public_key_auth = %q", rec.Attributes[logging.AttrAlgorithmBansPrefix+"public_key_auth"])
		}
	}
	host, port := h.targetHostPort()
	key := target.RejectionKey{Target: target.Target{Host: host, Port: port}.Addr(), Method: target.MethodStaticKey,
		Handle: static.CredentialHandle(target.Target{})}
	if st := breaker.State(key); st.Consecutive != 0 || st.Open {
		t.Fatalf("breaker state = %+v, want untouched", st)
	}
}
