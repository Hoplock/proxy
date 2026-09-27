// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// testAlgorithmFloor is phase 0045 through the real binaries and a real
// OpenSSH: a route with a post-quantum floor against the target's own sshd,
// which offers ML-KEM hybrid, and against a second sshd on the same host that
// offers classical exchanges only (deploy/target/entrypoint.sh); the same
// classical sshd with no floor; and a route with a cipher ban. Then what
// Hoplock Control holds about each target: its key-exchange level, merged
// beside the rungs the ephemeral-user probe reported, never over them.
func testAlgorithmFloor(t *testing.T) {
	t.Run("a post-quantum floor the target meets connects, and the record names the hybrid", func(t *testing.T) {
		const marker = "floor-met-0045"
		s := aliceOn(proxyDirect, "pq.company.com")
		s.command = "/bin/echo " + marker
		r := ssh(t, s)
		wantExit(t, r, "pq floor", 0)
		wantContains(t, r, "pq floor", marker)

		rec := negotiatedRecordOf(t, marker)
		if got := rec.Attributes["target_kex_algorithm"]; got != "mlkem768x25519-sha256" {
			t.Errorf("target_kex_algorithm = %q, want mlkem768x25519-sha256 — does the target's OpenSSH (>= 9.9) offer it?", got)
		}
		if got := rec.Attributes["algorithm_floor"]; got != "pq-hybrid-kex" {
			t.Errorf("algorithm_floor = %q, want pq-hybrid-kex on the record beside what was negotiated", got)
		}
	})

	t.Run("the same floor against a classical target is an outage naming the requirement", func(t *testing.T) {
		s := aliceOn(proxyDirect, "pq-classical.company.com")
		s.command = "/bin/true"
		r := ssh(t, s)
		wantFailure(t, r, "pq floor, classical target")
		wantContains(t, r, "pq floor, classical target",
			"this route requires a post-quantum key exchange, and the target does not support one")
		// The outage branch and never the deny: nothing was refused to the
		// user; the target could not meet the route's policy.
		wantNotContains(t, r, "pq floor, classical target", "Access denied.")
		wantNotContains(t, r, "pq floor, classical target", "could not be reached")
		id := sessionIDOf(r)
		if id == "" {
			t.Fatalf("the outage carries no session id\n%s", r)
		}

		var unmet logRecord
		waitFor(t, "the target.algorithm_policy_unmet record", func() bool {
			for _, rec := range recordsOfSession(t, id) {
				if rec.Attributes["event"] == "target.algorithm_policy_unmet" {
					unmet = rec
					return true
				}
			}
			return false
		})
		if unmet.Severity != "warn" {
			t.Errorf("unmet-policy record severity %q, want warn — an outage on the batch path", unmet.Severity)
		}
		for key, want := range map[string]string{
			"algorithm_axis":         "key_exchange",
			"algorithm_policy_cause": "floor",
			"algorithm_floor":        "pq-hybrid-kex",
		} {
			if got := unmet.Attributes[key]; got != want {
				t.Errorf("%s = %q, want %q", key, got, want)
			}
		}
		offered := unmet.Attributes["target_algorithms_offered"]
		if !strings.Contains(offered, "curve25519-sha256") || strings.Contains(offered, "mlkem") {
			t.Errorf("target_algorithms_offered = %q, want the classical sshd's list", offered)
		}
		// It failed at the provisioning login, so nothing was created.
		for _, rec := range recordsOfSession(t, id) {
			if rec.Kind == "provisioning" && rec.Attributes["credential_method"] != "" {
				t.Errorf("a credential was provisioned for a session whose floor could not be met: %+v", rec)
			}
		}
	})

	t.Run("without a floor the same classical target still connects", func(t *testing.T) {
		const marker = "classical-0045"
		s := aliceOn(proxyDirect, "classical.company.com")
		s.command = "/bin/echo " + marker
		r := ssh(t, s)
		wantExit(t, r, "classical, no floor", 0)
		rec := negotiatedRecordOf(t, marker)
		if got := rec.Attributes["target_kex_algorithm"]; got != "curve25519-sha256" {
			t.Errorf("target_kex_algorithm = %q, want the classical curve25519-sha256", got)
		}
		if _, present := rec.Attributes["algorithm_floor"]; present {
			t.Error("a route with no floor stamped algorithm_floor")
		}
	})

	t.Run("a banned cipher is negotiated around", func(t *testing.T) {
		const marker = "banned-0045"
		s := aliceOn(proxyDirect, "banned.company.com")
		s.command = "/bin/echo " + marker
		r := ssh(t, s)
		wantExit(t, r, "cipher ban", 0)
		rec := negotiatedRecordOf(t, marker)
		for _, key := range []string{"target_cipher_out", "target_cipher_in"} {
			if got := rec.Attributes[key]; got == "" || got == "aes128-gcm@openssh.com" {
				t.Errorf("%s = %q, want a cipher other than the banned one", key, got)
			}
		}
		if got := rec.Attributes["algorithm_bans.ciphers"]; got != "aes128-gcm@openssh.com" {
			t.Errorf("algorithm_bans.ciphers = %q, want the ban on the record", got)
		}
	})

	t.Run("Control holds each target's key-exchange level beside its rungs", func(t *testing.T) {
		waitFor(t, "both targets' key-exchange reports", func() bool {
			caps := fetchCapabilities(t)
			return caps["target"].Kex != nil && caps["target:2222"].Kex != nil
		})
		caps := fetchCapabilities(t)
		// The ephemeral-user probe's rung observation and the key-exchange
		// report were sent separately; the merge kept both.
		main := caps["target"]
		if main.Kex.FloorMet != "pq-hybrid-kex" {
			t.Errorf("the target's sshd floor_met = %q, want pq-hybrid-kex", main.Kex.FloorMet)
		}
		if main.ObservedAt == "" || len(main.Execution) == 0 {
			t.Errorf("the key-exchange report clobbered the probe's rung observation: %+v", main)
		}
		// Observed from the failed negotiation, whose list is exact.
		if got := caps["target:2222"].Kex.FloorMet; got != "modern-kex" {
			t.Errorf("the classical sshd floor_met = %q, want modern-kex", got)
		}
	})
}

// negotiatedRecordOf is the target.algorithms_negotiated record of the session
// that ran a command naming marker.
func negotiatedRecordOf(t *testing.T, marker string) logRecord {
	t.Helper()
	var rec logRecord
	waitFor(t, "the negotiated record of the session running "+marker, func() bool {
		id := sessionOfRecord(t, marker)
		if id == "" {
			return false
		}
		for _, r := range recordsOfSession(t, id) {
			if r.Attributes["event"] == "target.algorithms_negotiated" {
				rec = r
				return true
			}
		}
		return false
	})
	return rec
}

// targetCapabilities is the subset of what the mock holds per target that the
// scenarios assert on (cmd/mock-control, GET /debug/capabilities).
type targetCapabilities struct {
	Execution  []string `json:"execution"`
	ObservedAt string   `json:"observed_at"`
	Kex        *struct {
		FloorMet   string   `json:"floor_met"`
		Negotiated string   `json:"negotiated"`
		Offered    []string `json:"offered"`
	} `json:"kex"`
}

// fetchCapabilities reads what Hoplock Control holds about every target.
func fetchCapabilities(t *testing.T) map[string]targetCapabilities {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+controlAddr+"/debug/capabilities", nil)
	if err != nil {
		t.Fatalf("build the capabilities request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /debug/capabilities: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /debug/capabilities: %s", resp.Status)
	}
	out := map[string]targetCapabilities{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode /debug/capabilities: %v", err)
	}
	return out
}
