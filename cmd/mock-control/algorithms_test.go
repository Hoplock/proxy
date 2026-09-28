// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// This file is the server half of phase 0045: the mock refuses what the client
// refuses in a floor or a ban, serves either only to a proxy that can read and
// enforce it, and merges capability reports exactly as the contract says a
// server must. Phase 0047 adds one thing a server must do and the mock does:
// accept the per-profile declaration. The mock authors no policy, so it judges
// nothing against it.

// TestFloorAndBanFixturesAreCheckedLikeTheClientChecksThem: a fixture the proxy
// would refuse as a contract violation must not start the mock — the refused
// profile × floor pair and every ban refusal — while a ban on a name no build
// implements is accepted, as the client accepts it.
func TestFloorAndBanFixturesAreCheckedLikeTheClientChecksThem(t *testing.T) {
	const head = "users:\n  - login: alice\n    password: pw\n" +
		"routes:\n  - target: h\n    filter_policy:\n      mode: blacklist\n"
	refused := map[string]struct {
		yaml, want string
	}{
		"legacy-device with a floor": {head + "    algorithm_profile: legacy-device\n    algorithm_floor: modern-kex\n",
			"widens the key-exchange axis"},
		"an unknown floor": {head + "    algorithm_floor: fips-kex\n", "not a level this proxy enforces"},
		"a ban that empties the floor's level": {head + "    algorithm_floor: pq-hybrid-kex\n" +
			"    algorithm_bans:\n      key_exchanges: [mlkem768x25519-sha256]\n", "removes every key exchange"},
		"a ban that empties an axis": {head + "    algorithm_bans:\n      macs: [hmac-sha2-256-etm@openssh.com, " +
			"hmac-sha2-512-etm@openssh.com, hmac-sha2-256, hmac-sha2-512, hmac-sha1]\n", "nothing to offer"},
		"an empty identifier": {head + "    algorithm_bans:\n      ciphers: [\"\"]\n", "is empty"},
		"a duplicate":         {head + "    algorithm_bans:\n      host_keys: [ssh-rsa, ssh-rsa]\n", "twice"},
	}
	for name, c := range refused {
		_, err := parseFixtures(strings.NewReader(c.yaml))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: parseFixtures = %v, want an error naming %q", name, err, c.want)
		}
	}

	accepted := map[string]string{
		"legacy-rsa-sha1 with a floor": head + "    algorithm_profile: legacy-rsa-sha1\n    algorithm_floor: pq-hybrid-kex\n",
		"a name no build implements":   head + "    algorithm_bans:\n      key_exchanges: [sntrup761x25519-sha512]\n",
		"an empty ban object":          head + "    algorithm_bans: {}\n",
	}
	for name, yaml := range accepted {
		if _, err := parseFixtures(strings.NewReader(yaml)); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
}

// authorizeWith posts an authorize request declaring version and caps, and
// returns the status and body.
func authorizeWith(t *testing.T, m *mock, login, target string, version int, caps *control.ProxyCapabilities) (int, []byte) {
	t.Helper()
	body, err := json.Marshal(control.AuthorizeRequest{
		Identity:      &control.Identity{Subject: login + "@example.com", Login: login},
		Target:        target,
		PolicyVersion: version,
		Capabilities:  caps,
		Conn:          testConn(),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, m.srv.URL+control.PathAuthorize, strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+proxyToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, payload
}

// declaring is a proxy that declares the given floor levels, as this build
// would declare them.
func declaring(levels ...control.AlgorithmFloor) *control.ProxyCapabilities {
	caps := &control.ProxyCapabilities{}
	for _, c := range control.AlgorithmFloorCapabilities() {
		for _, level := range levels {
			if c.Level == level {
				caps.AlgorithmFloors = append(caps.AlgorithmFloors, c)
			}
		}
	}
	return caps
}

// TestAFloorOrABanIsServedOnlyToAProxyThatReadsIt: a route whose policy carries
// a floor or a ban is never served to a proxy declaring an older vocabulary
// with either omitted, and a floor level is never sent to a proxy that did not
// declare it. Both refusals are 500s — an outage, never a deny, and never a
// thinned policy.
func TestAFloorOrABanIsServedOnlyToAProxyThatReadsIt(t *testing.T) {
	m := startMock(t, nil, serverOptions{})
	const pq = "pq-host.company.com"

	// A proxy one vocabulary behind: refused, and told why.
	status, body := authorizeWith(t, m, "alice", pq, control.PolicyVersion-1, declaring(control.AlgorithmFloors()...))
	if status != http.StatusInternalServerError || !strings.Contains(string(body), "policy_version") {
		t.Errorf("a route with a floor and a ban to a proxy on vocabulary %d = %d %s, want a 500 naming the version",
			control.PolicyVersion-1, status, body)
	}
	// The current vocabulary, but the level undeclared — by a proxy declaring
	// nothing, and by one declaring only a lower level.
	for name, caps := range map[string]*control.ProxyCapabilities{
		"no declaration":       nil,
		"a lower level only":   declaring(control.AlgorithmFloorModernKEX),
		"an empty declaration": {},
	} {
		status, body := authorizeWith(t, m, "alice", pq, control.PolicyVersion, caps)
		if status != http.StatusInternalServerError || !strings.Contains(string(body), "algorithm_floor") {
			t.Errorf("%s: %d %s, want a 500 naming the undeclared level", name, status, body)
		}
	}
	// Declared and current: served, with the floor and the ban on the wire.
	status, body = authorizeWith(t, m, "alice", pq, control.PolicyVersion, declaring(control.AlgorithmFloorPQHybridKEX))
	if status != http.StatusOK {
		t.Fatalf("a proxy reading and declaring the floor = %d %s, want 200", status, body)
	}
	var resp control.AuthorizeResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if err := resp.Validate(); err != nil {
		t.Fatalf("the served policy is one the proxy refuses: %v", err)
	}
	if resp.AlgorithmFloor != control.AlgorithmFloorPQHybridKEX || resp.AlgorithmBans == nil ||
		len(resp.AlgorithmBans.Ciphers) != 2 || len(resp.AlgorithmBans.MACs) != 1 {
		t.Errorf("served floor %q bans %+v, want the fixture's", resp.AlgorithmFloor, resp.AlgorithmBans)
	}

	// A route with neither is served to a proxy declaring nothing, one
	// vocabulary behind: the gate is per route.
	if status, body := authorizeWith(t, m, "alice", "host.company.com", control.PolicyVersion-1, nil); status != http.StatusOK {
		t.Errorf("a route with no floor to an older proxy = %d %s, want 200", status, body)
	}
}

// TestAnAuthorizeDeclaringProfilesIsServedAsBefore: a proxy that declares what
// each algorithm profile offers (phase 0047) is served exactly what it is served
// without that declaration, on a plain route and on one with a floor and a ban.
// The declaration grants nothing and gates nothing, so the mock refuses nothing
// new. What this pins is that the strict decoder knows the field, where it
// answers a 400 to one it does not.
func TestAnAuthorizeDeclaringProfilesIsServedAsBefore(t *testing.T) {
	m := startMock(t, nil, serverOptions{})
	offerable := control.OfferableAlgorithms()
	withProfiles := &control.ProxyCapabilities{
		AlgorithmFloors:   control.AlgorithmFloorCapabilities(),
		AlgorithmProfiles: control.AlgorithmProfileCapabilities(),
		Algorithms:        &offerable,
	}
	withoutProfiles := withProfiles.Clone()
	withoutProfiles.AlgorithmProfiles = nil

	// served is one authorize answer, with the two fields that differ per call
	// by design set aside: the decision id, and a deadline anchored at now.
	served := func(target string, caps *control.ProxyCapabilities) control.AuthorizeResponse {
		t.Helper()
		status, body := authorizeWith(t, m, "alice", target, control.PolicyVersion, caps)
		if status != http.StatusOK {
			t.Fatalf("%s: %d %s, want 200", target, status, body)
		}
		var resp control.AuthorizeResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatal(err)
		}
		resp.DecisionID, resp.SessionDeadline = "", nil
		return resp
	}
	for _, target := range []string{"host.company.com", "pq-host.company.com"} {
		if got, want := served(target, withProfiles), served(target, withoutProfiles); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: declaring the profiles changed what was served:\n got %+v\nwant %+v", target, got, want)
		}
	}

	// The field was on the wire, spelled as the contract spells it, and the
	// decoder that took it is strict: the same request with the key misspelled
	// is refused.
	body, err := json.Marshal(control.AuthorizeRequest{
		Identity:      &control.Identity{Subject: "alice@example.com", Login: "alice"},
		Target:        "host.company.com",
		PolicyVersion: control.PolicyVersion,
		Capabilities:  withProfiles,
		Conn:          testConn(),
	})
	if err != nil {
		t.Fatal(err)
	}
	const field = `"algorithm_profiles":[{"profile":"default","key_exchanges":[`
	if !strings.Contains(string(body), field) {
		t.Fatalf("the request does not carry %s: %s", field, body)
	}
	misspelled := strings.Replace(string(body), `"algorithm_profiles"`, `"algorithm_profilez"`, 1)
	req, err := http.NewRequest(http.MethodPost, m.srv.URL+control.PathAuthorize, strings.NewReader(misspelled))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+proxyToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("an unknown capabilities field = %d, want 400: the acceptance above proves nothing about a lax decoder", resp.StatusCode)
	}
}

// TestACapabilityReportMergesPerObservation drives the merge rule through the
// real client: the rung observation and the key-exchange observation are each
// replaced only by a report that carries it, so neither kind of report erases
// the other.
func TestACapabilityReportMergesPerObservation(t *testing.T) {
	m := startMock(t, nil, serverOptions{})
	ctx := context.Background()
	at := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	report := func(caps control.TargetCapabilities) error {
		_, err := m.client.ReportCapabilities(ctx, &control.CapabilityReportRequest{
			Target: "merge.company.com", Capabilities: caps, Conn: testConn()})
		return err
	}
	stored := func() *control.TargetCapabilities {
		t.Helper()
		c, ok := m.server.reportedCapabilities("merge.company.com")
		if !ok {
			t.Fatal("nothing stored")
		}
		return c
	}

	// The probe's rung observation first.
	if err := report(control.TargetCapabilities{Execution: []control.ExecutionRung{control.ExecutionAccountRestricted},
		ObservedAt: at}); err != nil {
		t.Fatalf("rung report: %v", err)
	}
	// Then a key-exchange report: the rungs survive.
	kex := &control.KexObservation{FloorMet: "modern-kex", Negotiated: "curve25519-sha256", ObservedAt: at.Add(time.Minute)}
	if err := report(control.TargetCapabilities{Kex: kex}); err != nil {
		t.Fatalf("key-exchange report: %v", err)
	}
	got := stored()
	if len(got.Execution) != 1 || !got.ObservedAt.Equal(at) {
		t.Errorf("a key-exchange report clobbered the rung observation: %+v", got)
	}
	if got.Kex == nil || got.Kex.FloorMet != "modern-kex" {
		t.Errorf("the key-exchange observation was not stored: %+v", got.Kex)
	}

	// And the reverse: a fresh rung report, which says the target can now take
	// nothing, replaces the rungs and leaves the key exchange alone.
	if err := report(control.TargetCapabilities{ObservedAt: at.Add(2 * time.Minute)}); err != nil {
		t.Fatalf("second rung report: %v", err)
	}
	got = stored()
	if len(got.Execution) != 0 || !got.ObservedAt.Equal(at.Add(2*time.Minute)) {
		t.Errorf("a dated rung report did not replace the rung observation: %+v", got)
	}
	if got.Kex == nil || got.Kex.FloorMet != "modern-kex" {
		t.Errorf("a rung report clobbered the key-exchange observation: %+v", got.Kex)
	}

	// What is refused: rungs with no date, and a report carrying nothing.
	for name, caps := range map[string]control.TargetCapabilities{
		"undated rungs":   {Execution: []control.ExecutionRung{control.ExecutionAccountRestricted}},
		"no observation":  {},
		"an undated kex":  {Kex: &control.KexObservation{FloorMet: "none"}},
		"a kex, no level": {Kex: &control.KexObservation{ObservedAt: at}},
	} {
		if err := report(caps); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// TestEveryMethodsTargetReachesControlWithItsKeyExchange drives the report end
// to end — a real proxy, the real reporter, the contract as the mock serves it —
// for an ephemeral-account DEVICE route and a static-key route: the observation
// is made where the session leg is dialled, which every credential method
// shares, and it is merged into what Control holds about the target.
func TestEveryMethodsTargetReachesControlWithItsKeyExchange(t *testing.T) {
	const password = "alice-e2e-password"
	stack := startE2E(t, e2eOptions{password: password, device: true, kexReports: true})

	runDeviceSession(t, stack, password)
	client := stack.dial(t)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Run("deploy"); err != nil {
		t.Fatalf("run on the static-key route: %v", err)
	}
	stack.kexReports.Wait()

	for _, host := range []string{
		capabilityKey("localhost", stack.device.Port()),
		capabilityKey(stack.target.Host(), stack.target.Port()),
	} {
		caps, ok := stack.mock.server.reportedCapabilities(host)
		if !ok || caps.Kex == nil {
			t.Fatalf("Control holds no key-exchange observation of %s", host)
		}
		// Both stand-ins are x/crypto servers, which offer the ML-KEM hybrid;
		// neither route has a ban, so a success is an exact observation.
		if caps.Kex.FloorMet != string(control.AlgorithmFloorPQHybridKEX) ||
			caps.Kex.Negotiated != control.KeyExchangeMLKEM768X25519 || caps.Kex.ObservedAt.IsZero() {
			t.Errorf("%s: key-exchange observation %+v, want pq-hybrid-kex negotiated on the hybrid", host, caps.Kex)
		}
		if caps.CarriesRungs() {
			t.Errorf("%s: a key-exchange report was stored as a rung observation: %+v", host, caps)
		}
	}
}

// TestABanAloneNeedsTheNewVocabulary: a route with a ban and no floor is refused
// to a proxy one vocabulary behind — an omitted ban is a dropped restriction —
// and served, ban intact, to one that reads it with no floor declared at all.
func TestABanAloneNeedsTheNewVocabulary(t *testing.T) {
	fx, err := parseFixtures(strings.NewReader("proxy_token: " + proxyToken + "\n" +
		"users:\n  - login: alice\n    password: pw\n" +
		"routes:\n  - login: alice\n    target: banned.company.com\n    permitted_channels: [session]\n" +
		"    filter_policy:\n      mode: blacklist\n    algorithm_bans:\n      ciphers: [aes128-cbc]\n"))
	if err != nil {
		t.Fatalf("fixtures: %v", err)
	}
	m := startMock(t, fx, serverOptions{})

	if status, body := authorizeWith(t, m, "alice", "banned.company.com", control.PolicyVersion-1, nil); status != http.StatusInternalServerError ||
		!strings.Contains(string(body), "policy_version") {
		t.Errorf("a ban to a proxy on vocabulary %d = %d %s, want a 500 naming the version", control.PolicyVersion-1, status, body)
	}
	status, body := authorizeWith(t, m, "alice", "banned.company.com", control.PolicyVersion, nil)
	if status != http.StatusOK {
		t.Fatalf("a ban to a proxy that reads it = %d %s, want 200", status, body)
	}
	var resp control.AuthorizeResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.AlgorithmBans == nil || len(resp.AlgorithmBans.Ciphers) != 1 || resp.AlgorithmFloor != "" {
		t.Errorf("served bans %+v floor %q", resp.AlgorithmBans, resp.AlgorithmFloor)
	}
}
