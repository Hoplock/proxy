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
	"slices"
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

// TestTheUIDRangeTheScenariosDependOn pins what phase 0027's scenarios read.
//
// The uid scenarios assert that a session's uid lands inside the DEDICATED range
// and that consecutive sessions never share one. Both are only observable while
// the topology leaves the range at its default: a proxy configured onto the
// fleet's own range would still allocate non-reusing uids, and the scenario
// asserting they are outside the fleet's range would fail for a reason that is
// nothing to do with allocation.
//
// It also pins the route the cross-login scenario needs. That claim is about TWO
// PEOPLE on one target, so a second login has to reach it — and with no
// enforcement rung, because a confined session cannot write the file the first
// half of the scenario leaves behind.
func TestTheUIDRangeTheScenariosDependOn(t *testing.T) {
	t.Parallel()

	cfg, err := config.Load(filepath.Join(deployDir, "proxy", "proxy-direct.yaml"))
	if err != nil {
		t.Fatalf("load proxy-direct.yaml: %v", err)
	}
	e := cfg.Auth.Target.EphemeralUser
	if e.UIDMin != 0 || e.UIDMax != 0 {
		t.Errorf("auth.target.ephemeral_user.uid_min/uid_max = %d/%d, want the defaults (0/0): "+
			"test/e2e asserts a session's uid is inside %d-%d",
			e.UIDMin, e.UIDMax, config.DefaultEphemeralUIDMin, config.DefaultEphemeralUIDMax)
	}
	// The mark that makes allocation non-reusing lives under this directory, so
	// a session's uid outliving its account depends on it being somewhere the
	// provisioning account can write on the target image.
	if base := e.EnforcementBase; base != "" && base != "/var/lib/hoplock" {
		t.Errorf("auth.target.ephemeral_user.enforcement_base = %q; the uid mark lives there and "+
			"deploy/target must be able to write it", base)
	}

	body, err := os.ReadFile(filepath.Join(deployDir, "control", "fixtures.template.yaml"))
	if err != nil {
		t.Fatalf("read the fixture template: %v", err)
	}
	if !bytes.Contains(body, []byte("target: inherit.company.com")) {
		t.Error("the fixtures no longer carry the inherit.company.com route, which is the second " +
			"login the cross-login uid scenario needs")
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

// TestTheUnnamedAccountRouteIsTheOnlyOneWithNoAccountName pins the arrangement
// the phase-0028 scenario depends on, which is spread across two files and is
// invisible in either one alone.
//
// The scenario asserts that a session with NO account name available anywhere
// is refused as an outage. Since contract v4.2 every credential method requires
// a `username` on its route, so the only way to reach that state is a route
// naming no `target_auth` at all, served by a proxy that also configures no
// account for its local method. Break either half — add a username to
// proxy-nexthop, or a target_auth to the route — and the scenario passes
// vacuously against a proxy that had an account all along.
func TestTheUnnamedAccountRouteIsTheOnlyOneWithNoAccountName(t *testing.T) {
	t.Parallel()

	// Half one: proxy-nexthop configures no fallback account, and the other two
	// proxies still do — this is a deliberate single exception, not a drift.
	want := map[string]string{
		"proxy-direct.yaml":  "netadmin",
		"proxy-nexthop.yaml": "",
		"proxy-zone.yaml":    "netadmin",
	}
	for file, account := range want {
		cfg, err := config.Load(filepath.Join(deployDir, "proxy", file))
		if err != nil {
			t.Fatalf("load %s: %v", file, err)
		}
		if got := cfg.Auth.Target.BrokeredKey.Username; got != account {
			t.Errorf("%s: auth.target.brokered_key.username = %q, want %q", file, got, account)
		}
	}

	// Half two: the route exists, is scoped to that proxy, and names no
	// credential method of its own.
	body, err := os.ReadFile(filepath.Join(deployDir, "control", "fixtures.template.yaml"))
	if err != nil {
		t.Fatalf("read the fixture template: %v", err)
	}
	const route = "  - login: alice\n    target: unnamed.company.com\n    proxy_id: proxy-nexthop\n"
	if !bytes.Contains(body, []byte(route)) {
		t.Fatal("the unnamed.company.com route is gone or is no longer scoped to proxy-nexthop")
	}
	rest := body[bytes.Index(body, []byte(route))+len(route):]
	if end := bytes.Index(rest, []byte("\n  - login:")); end >= 0 {
		rest = rest[:end]
	}
	if bytes.Contains(rest, []byte("target_auth")) {
		t.Error("the unnamed.company.com route now names a target_auth; it must name none")
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

// TestEveryRoutedPlatformHasADriverOnItsProxy is the check phase 0029 needed
// and did not have.
//
// The FortiSwitch scenario failed in CI three minutes into the e2e job with
// `no driver for this platform: "fortiswitchos" (this proxy has: [fortigate])`
// — a route naming a platform its serving proxy does not register. That is
// correct behaviour on the proxy's side and D13 requires it (an unregistered
// platform is an outage-class denial, never the nearest driver), so the bug is
// entirely in the topology: two files that have to agree, in different
// directories, with nothing checking that they do.
//
// The whole class is cheap to close here. `platforms:` is an ALLOW-LIST — an
// empty one means every driver the build ships, and a non-empty one silently
// excludes the rest — so adding a driver to the code is not enough to make a
// proxy serve it, and adding a route is not enough either.
func TestEveryRoutedPlatformHasADriverOnItsProxy(t *testing.T) {
	t.Parallel()

	body, err := os.ReadFile(filepath.Join(deployDir, "control", "fixtures.template.yaml"))
	if err != nil {
		t.Fatalf("read the fixture template: %v", err)
	}

	// Walk the fixture's routes, pairing each `platform:` parameter with the
	// `proxy_id:` above it. A regex is enough and a YAML decode is not
	// obviously better: the fixture's own schema lives in cmd/mock-control,
	// which this package deliberately does not import.
	var proxyID string
	seen := map[string]map[string]bool{}
	for _, line := range bytes.Split(body, []byte("\n")) {
		trimmed := bytes.TrimSpace(line)
		if rest, ok := bytes.CutPrefix(trimmed, []byte("proxy_id:")); ok {
			proxyID = string(bytes.Trim(bytes.TrimSpace(rest), `"`))
			continue
		}
		rest, ok := bytes.CutPrefix(trimmed, []byte("platform:"))
		if !ok {
			continue
		}
		platform := string(bytes.Trim(bytes.TrimSpace(rest), `"`))
		if platform == "" || proxyID == "" {
			continue
		}
		if seen[proxyID] == nil {
			seen[proxyID] = map[string]bool{}
		}
		seen[proxyID][platform] = true
	}
	if len(seen) == 0 {
		t.Fatal("no route in the fixture template names a device platform; this test has stopped checking anything")
	}

	// One platform is deliberately unserved, and it is the whole point of the
	// route that names it: D14's ladder fall-through needs a first entry this
	// proxy CANNOT satisfy, so that the second one is what serves the session.
	// The exemption is tied to that one name, and the assertion below keeps it
	// tied — if the fall-through route is ever removed or renamed, this stops
	// being an exemption and starts being a hole.
	const deliberatelyUnserved = "some-other-vendor"
	if got := bytes.Count(body, []byte("platform: "+deliberatelyUnserved)); got != 1 {
		t.Errorf("%d routes name platform %q, want exactly 1 (D14's ladder fall-through); "+
			"this test exempts that name from needing a driver", got, deliberatelyUnserved)
	}

	for id, platforms := range seen {
		delete(platforms, deliberatelyUnserved)
		cfg, err := config.Load(filepath.Join(deployDir, "proxy", id+".yaml"))
		if err != nil {
			t.Errorf("load the config for %s: %v", id, err)
			continue
		}
		allowed := cfg.Auth.Target.EphemeralAccount.Platforms
		if len(allowed) == 0 {
			// Empty means every driver this build ships, so nothing to check.
			continue
		}
		for platform := range platforms {
			if !slices.Contains(allowed, platform) {
				t.Errorf("a route served by %s names platform %q, but %s.yaml's "+
					"auth.target.ephemeral_account.platforms is %v — the proxy will refuse the "+
					"session as an outage (D13: an unregistered platform is never the nearest driver)",
					id, platform, id, allowed)
			}
		}
	}
}

// TestTheFakeDeviceServesEveryPortTheFixturesRoute is the other half of the
// same class: a route can name a platform the proxy serves and still point at
// a port nothing listens on.
func TestTheFakeDeviceServesEveryPortTheFixturesRoute(t *testing.T) {
	t.Parallel()

	compose, err := os.ReadFile(filepath.Join(deployDir, "compose.yaml"))
	if err != nil {
		t.Fatalf("read compose.yaml: %v", err)
	}
	for _, listener := range []string{"0.0.0.0:22", "0.0.0.0:2222", "0.0.0.0:2223"} {
		if !bytes.Contains(compose, []byte(`"`+listener+`"`)) {
			t.Errorf("the device node no longer serves %s; a fixture route points at it", listener)
		}
	}
}

// TestTheSessionBoundRoutesTheScenariosDependOn pins the fixture routes phase
// 0031's scenarios are written against (D16, docs/PLAN.md §6.5).
//
// Each one carries exactly one bound, and two of them carry a ceiling of ONE —
// which is load-bearing rather than tidy: a scenario holds one session open and
// asserts the next is refused, so a cap of two would pass for the wrong reason
// and a missing route would fail minutes into the e2e job with a denial nobody
// can attribute.
func TestTheSessionBoundRoutesTheScenariosDependOn(t *testing.T) {
	t.Parallel()

	body, err := os.ReadFile(filepath.Join(deployDir, "control", "fixtures.template.yaml"))
	if err != nil {
		t.Fatalf("read the fixture template: %v", err)
	}
	for _, want := range []string{
		"target: recorded.company.com",
		"require_session_capture: true",
		"target: capped.company.com",
		"max_sessions_per_subject: 1",
		"target: granted.company.com",
		"additional_context_text:",
		"target: granted-fields.company.com",
		"additional_context_fields:",
	} {
		if !bytes.Contains(body, []byte(want)) {
			t.Errorf("the fixtures no longer carry %q, which a session-bounds scenario needs", want)
		}
	}
	// Two routes to the capped target, one per login: the per-target ceiling is
	// only being tested if the second session belongs to a DIFFERENT subject,
	// and that subject needs a route of its own to be refused on.
	if got := bytes.Count(body, []byte("target: capped-target.company.com")); got != 2 {
		t.Errorf("%d routes name capped-target.company.com, want 2 (one per login)", got)
	}
	if got := bytes.Count(body, []byte("max_sessions_per_target: 1")); got != 2 {
		t.Errorf("%d routes cap capped-target.company.com at one live session, want 2", got)
	}
}
