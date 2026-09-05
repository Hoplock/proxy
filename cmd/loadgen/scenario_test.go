// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadScenarioAppliesDefaults(t *testing.T) {
	sc := decode(t, `
name: defaults
run:
  mode: rate
  rate: 10
  duration: 5s
`)
	if sc.Kind != KindConnection {
		t.Errorf("kind = %q, want %q", sc.Kind, KindConnection)
	}
	if sc.Run.Session != SessionExec {
		t.Errorf("session = %q, want %q", sc.Run.Session, SessionExec)
	}
	if sc.Workload.Subjects != 1 || sc.Workload.Targets != 1 {
		t.Errorf("workload = %d subjects x %d targets, want 1 x 1", sc.Workload.Subjects, sc.Workload.Targets)
	}
	if sc.Workload.Order != OrderCycle {
		t.Errorf("order = %q, want %q", sc.Workload.Order, OrderCycle)
	}
	if sc.Proxy.CacheStaleAfter != 30*time.Second {
		t.Errorf("stale_after = %s, want 30s", sc.Proxy.CacheStaleAfter)
	}
	// MaxInflight must leave headroom above the offered rate, or the generator
	// caps itself and the shortfall is read as proxy saturation.
	if sc.Run.MaxInflight < int(sc.Run.Rate) {
		t.Errorf("max_inflight = %d, want at least the offered rate", sc.Run.MaxInflight)
	}
}

func TestLoadScenarioRejectsUnknownKeys(t *testing.T) {
	// A misspelt knob that silently does nothing is a measurement of the wrong
	// thing, and nothing downstream would ever notice.
	_, err := decodeScenario(strings.NewReader("name: x\nkind: connection\nrun:\n  mode: rate\n  rate: 1\n  duration: 1s\n  ratee: 5\n"))
	if err == nil {
		t.Fatal("decodeScenario accepted an unknown key")
	}
}

func TestScenarioValidation(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "no name",
			yaml: "kind: connection\nrun:\n  mode: rate\n  rate: 1\n  duration: 1s\n",
			want: "name is required",
		},
		{
			name: "unknown kind",
			yaml: "name: x\nkind: wat\n",
			want: "unknown kind",
		},
		{
			name: "rate mode without a rate",
			yaml: "name: x\nrun:\n  mode: rate\n  duration: 1s\n",
			want: "run.rate or run.rate_steps",
		},
		{
			name: "hold mode without concurrency",
			yaml: "name: x\nrun:\n  mode: hold\n  duration: 1s\n",
			want: "run.concurrency",
		},
		{
			name: "ttl shorter than the run",
			yaml: "name: x\nrun:\n  mode: rate\n  rate: 1\n  duration: 60s\ncontrol:\n  cache_hint: true\n  cache_ttl: 5s\n",
			want: "measure expiry",
		},
		{
			name: "both sweeps",
			yaml: "name: x\nrun:\n  mode: rate\n  rate_steps: [1, 2]\n  duration: 1s\nworkload:\n  target_steps: [1, 2]\n",
			want: "cannot both be set",
		},
		{
			name: "target sweep without a restart",
			yaml: "name: x\nrun:\n  mode: rate\n  rate: 1\n  duration: 1s\nworkload:\n  target_steps: [1, 2]\n",
			want: "restart_between_steps",
		},
		{
			name: "authorized_keys without a home",
			yaml: "name: x\nkind: provisioning\nprovisioning:\n  authorized_keys: true\n",
			want: "provisioning.home",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeScenario(strings.NewReader(tc.yaml))
			if err == nil {
				t.Fatalf("decodeScenario accepted %q", tc.yaml)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestScenarioSteps(t *testing.T) {
	t.Run("single", func(t *testing.T) {
		sc := decode(t, "name: x\nrun:\n  mode: rate\n  rate: 7\n  duration: 1s\nworkload:\n  targets: 5\n")
		steps := sc.steps()
		if len(steps) != 1 || steps[0].Rate != 7 || steps[0].Targets != 5 {
			t.Fatalf("steps = %+v, want one step of 7 conn/s x 5 targets", steps)
		}
	})
	t.Run("rate sweep keeps the working set fixed", func(t *testing.T) {
		sc := decode(t, "name: x\nrun:\n  mode: rate\n  rate_steps: [1, 2]\n  duration: 1s\nworkload:\n  targets: 9\n")
		steps := sc.steps()
		if len(steps) != 2 {
			t.Fatalf("len(steps) = %d, want 2", len(steps))
		}
		for _, s := range steps {
			if s.Targets != 9 || s.NameOffset != 0 {
				t.Errorf("step %+v, want 9 targets at offset 0", s)
			}
		}
	})
	t.Run("target sweep gives each step a disjoint working set", func(t *testing.T) {
		sc := decode(t, "name: x\nrun:\n  mode: rate\n  rate: 1\n  duration: 1s\n  restart_between_steps: true\nworkload:\n  target_steps: [4, 8]\n")
		steps := sc.steps()
		if len(steps) != 2 {
			t.Fatalf("len(steps) = %d, want 2", len(steps))
		}
		// Without the offset the second step would find the first step's names
		// already cached and report a hit rate that belongs to another run.
		if steps[0].NameOffset != 0 || steps[1].NameOffset != 4 {
			t.Errorf("offsets = %d, %d; want 0, 4", steps[0].NameOffset, steps[1].NameOffset)
		}
	})
}

func TestCommittedScenariosAreValid(t *testing.T) {
	// The scenario files are the reproducibility promise: a result nobody can
	// re-run is an anecdote. This is what keeps them loadable as the schema
	// moves.
	paths, err := filepath.Glob(filepath.Join("..", "..", "load", "scenarios", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no committed scenarios found under load/scenarios/")
	}
	for _, p := range paths {
		t.Run(filepath.Base(p), func(t *testing.T) {
			sc, err := LoadScenario(p)
			if err != nil {
				t.Fatalf("LoadScenario(%s): %v", p, err)
			}
			if want := strings.TrimSuffix(filepath.Base(p), ".yaml"); sc.Name != want {
				t.Errorf("name = %q, want %q so the result file matches the scenario file", sc.Name, want)
			}
		})
	}
}

func decode(t *testing.T, yaml string) *Scenario {
	t.Helper()
	sc, err := decodeScenario(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("decodeScenario: %v", err)
	}
	return sc
}
