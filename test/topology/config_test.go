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
