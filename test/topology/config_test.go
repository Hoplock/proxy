// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

// Package topology_test checks the e2e topology's static configuration with the
// same loader the proxy uses.
//
// It runs in the ordinary `go test ./...` — no Docker, no network. A typo in a
// deploy config is otherwise found only when a container fails to start several
// minutes into the e2e job, and bootstrap config decoding is strict (an unknown
// key is an error), so the failure mode this guards against is common and its
// feedback loop is otherwise slow.
package topology_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/config"
)

// deployDir is this repo's deploy/ directory, relative to this test.
const deployDir = "../../deploy"

func TestProxyConfigsLoad(t *testing.T) {
	t.Parallel()

	want := map[string]struct {
		id          string
		listenAddr  string
		registers   bool
		acceptsRegs bool
	}{
		"proxy-direct.yaml":  {id: "proxy-direct", listenAddr: "0.0.0.0:2222"},
		"proxy-nexthop.yaml": {id: "proxy-nexthop", listenAddr: "0.0.0.0:2222", acceptsRegs: true},
		// The loopback bind is the topology's claim that nothing can connect
		// inbound to the zone proxy (D11). It is asserted here as well as in
		// the scenario suite: a config change that quietly published the
		// listener would make that scenario pass for the wrong reason.
		"proxy-zone.yaml": {id: "proxy-zone", listenAddr: "127.0.0.1:2222", registers: true},
	}

	for name, w := range want {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := config.Load(filepath.Join(deployDir, "proxy", name))
			if err != nil {
				t.Fatalf("load %s: %v", name, err)
			}
			if cfg.Proxy.ID != w.id {
				t.Errorf("proxy.id = %q, want %q", cfg.Proxy.ID, w.id)
			}
			if cfg.Proxy.ListenAddr != w.listenAddr {
				t.Errorf("proxy.listen_addr = %q, want %q", cfg.Proxy.ListenAddr, w.listenAddr)
			}
			if got := cfg.Chain.Registers(); got != w.registers {
				t.Errorf("chain registers an upstream relay = %v, want %v", got, w.registers)
			}
			if got := cfg.Chain.AcceptsRegistrations(); got != w.acceptsRegs {
				t.Errorf("chain accepts relay registrations = %v, want %v", got, w.acceptsRegs)
			}
		})
	}
}

// TestFixtureTemplateHasPlaceholders keeps the rendered fixtures honest: every
// fingerprint deploy/gen-material.sh substitutes must still have somewhere to
// go, and no placeholder may survive into a rendered file.
func TestFixtureTemplateHasPlaceholders(t *testing.T) {
	t.Parallel()

	body, err := os.ReadFile(filepath.Join(deployDir, "control", "fixtures.template.yaml"))
	if err != nil {
		t.Fatalf("read the fixture template: %v", err)
	}
	script, err := os.ReadFile(filepath.Join(deployDir, "gen-material.sh"))
	if err != nil {
		t.Fatalf("read gen-material.sh: %v", err)
	}

	for _, placeholder := range []string{
		"@@FP_USER_ALICE@@", "@@FP_USER_SVC@@",
		"@@FP_CHAIN_DIRECT@@", "@@FP_CHAIN_NEXTHOP@@", "@@FP_CHAIN_ZONE@@",
	} {
		if !bytes.Contains(body, []byte(placeholder)) {
			t.Errorf("the fixture template no longer uses %s", placeholder)
		}
		if !bytes.Contains(script, []byte(placeholder)) {
			t.Errorf("gen-material.sh no longer substitutes %s", placeholder)
		}
	}
}

// TestContainmentSettingsTheScenariosDependOn pins the two numbers the
// credential-rejection scenarios are written against.
//
// They are not the defaults, deliberately: the threshold is low enough that a
// scenario reaches it in two sessions, and the cooldown is long enough that no
// assertion in the run can be overtaken by it. Both are load-bearing, and a
// change to either turns a scenario into one that passes for the wrong reason
// — or one that fails minutes into the e2e job for a reason nobody reads.
func TestContainmentSettingsTheScenariosDependOn(t *testing.T) {
	t.Parallel()

	cfg, err := config.Load(filepath.Join(deployDir, "proxy", "proxy-direct.yaml"))
	if err != nil {
		t.Fatalf("load proxy-direct.yaml: %v", err)
	}
	r := cfg.Auth.Target.Rejection
	if r.Threshold == nil || *r.Threshold != 2 {
		t.Errorf("auth.target.rejection.threshold = %v, want 2 (test/e2e reaches it in two sessions)", r.Threshold)
	}
	if r.Cooldown < 10*time.Minute {
		t.Errorf("auth.target.rejection.cooldown = %s, want at least 10m so no assertion outlives it", r.Cooldown)
	}
	if r.Window < r.Cooldown {
		t.Errorf("auth.target.rejection.window = %s, shorter than the cooldown %s", r.Window, r.Cooldown)
	}
}

// TestPasswordMFASettingsTheScenariosDependOn pins what makes the password+MFA
// scenarios (phase 0026) able to see what they assert on.
//
// Three settings, each of which turns a scenario into one that passes for the
// wrong reason — or fails minutes into the e2e job — if it moves:
//
//   - `proxy-direct` must offer BOTH methods, or there is no fallback to drive;
//   - the other two proxies must offer NEITHER password method, because the
//     fallback ORDER (PLAN §4.1) is only observable while a proxy exists that
//     gives a client with no acceptable key no second chance;
//   - the progress interval must be short enough that the "still waiting" line
//     appears inside a sub-second approval. At the shipped 5s default it never
//     would, and the scenario asserting on it — the whole reason the flow is
//     keyboard-interactive rather than plain password auth (PLAN §4.3) — would
//     pass against a proxy that had no such line to print.
func TestPasswordMFASettingsTheScenariosDependOn(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		file       string
		wantMethod bool
	}{
		{"proxy-direct.yaml", true},
		{"proxy-nexthop.yaml", false},
		{"proxy-zone.yaml", false},
	} {
		cfg, err := config.Load(filepath.Join(deployDir, "proxy", tc.file))
		if err != nil {
			t.Fatalf("load %s: %v", tc.file, err)
		}
		if got := contains(cfg.Auth.User.Methods, "password-mfa"); got != tc.wantMethod {
			t.Errorf("%s: auth.user.methods = %v; password-mfa enabled = %v, want %v",
				tc.file, cfg.Auth.User.Methods, got, tc.wantMethod)
		}
		if !contains(cfg.Auth.User.Methods, "cert") {
			t.Errorf("%s: auth.user.methods = %v, want cert on every proxy", tc.file, cfg.Auth.User.Methods)
		}
	}

	cfg, err := config.Load(filepath.Join(deployDir, "proxy", "proxy-direct.yaml"))
	if err != nil {
		t.Fatalf("load proxy-direct.yaml: %v", err)
	}
	if d := cfg.Auth.User.MFA.ProgressInterval; d <= 0 || d > time.Second {
		t.Errorf("auth.user.mfa.progress_interval = %s, want a positive value no longer than 1s "+
			"(zero means the 5s package default, which no scenario's approval lasts)", d)
	}
}

// TestTheReaperLeavesAHeldSessionAlone pins the other half of what the
// concurrency scenarios (phase 0026) rest on.
//
// Those scenarios hold two sessions open on one target for fifteen seconds and
// then assert on the accounts the target is carrying. The reaper never sweeps an
// account it knows is live, so this is belt and braces — but the grace period is
// exactly what protects a session the proxy does not know about yet (PLAN §5.1),
// and a grace shorter than a held session would make the scenarios flaky in a
// way that reads as a provisioning bug rather than as a setting.
func TestTheReaperLeavesAHeldSessionAlone(t *testing.T) {
	t.Parallel()

	cfg, err := config.Load(filepath.Join(deployDir, "proxy", "proxy-direct.yaml"))
	if err != nil {
		t.Fatalf("load proxy-direct.yaml: %v", err)
	}
	if g := cfg.Auth.Target.EphemeralUser.Reaper.Grace; g < time.Minute {
		t.Errorf("auth.target.ephemeral_user.reaper.grace = %s, want at least 1m so it outlives "+
			"a held session in test/e2e", g)
	}
}

// TestTheRefusedRouteNamesACredentialNothingElseUses is the property that keeps
// the containment scenarios from breaking every route after them: they leave a
// breaker OPEN for the rest of the run, and that is safe only while exactly one
// route names the credential it is scored against.
func TestTheRefusedRouteNamesACredentialNothingElseUses(t *testing.T) {
	t.Parallel()

	body, err := os.ReadFile(filepath.Join(deployDir, "control", "fixtures.template.yaml"))
	if err != nil {
		t.Fatalf("read the fixture template: %v", err)
	}
	if got := bytes.Count(body, []byte("credential_ref: stale-fleet")); got != 1 {
		t.Errorf("%d routes name credential_ref stale-fleet, want exactly 1", got)
	}

	script, err := os.ReadFile(filepath.Join(deployDir, "gen-material.sh"))
	if err != nil {
		t.Fatalf("read gen-material.sh: %v", err)
	}
	if !bytes.Contains(script, []byte("stale-fleet.key")) {
		t.Error("gen-material.sh no longer generates the stale brokered credential")
	}
	// Its public half must never be installed on the target, or the route it
	// backs would simply work and every containment scenario would pass
	// vacuously.
	entrypoint, err := os.ReadFile(filepath.Join(deployDir, "target", "entrypoint.sh"))
	if err != nil {
		t.Fatalf("read the target entrypoint: %v", err)
	}
	if bytes.Contains(entrypoint, []byte("stale_key")) {
		t.Error("the target installs the stale credential; the route it backs must be refused")
	}
}

// contains reports whether list holds want.
func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
