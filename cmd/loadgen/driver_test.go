// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"strings"
	"testing"

	"github.com/hoplock/proxy/internal/routing"
)

func TestUsernameSplitsAsD1Requires(t *testing.T) {
	// The generator's usernames go through the proxy's own parser. If they did
	// not split the way D1 says, every connection in a run would fail at
	// routing and the harness would be measuring denial.
	sc := decode(t, "name: x\nrun:\n  mode: rate\n  rate: 1\n  duration: 1s\nworkload:\n  subjects: 3\n  targets: 5\n")
	d := newDriver(sc, stepPlan{Rate: 1, Targets: 5}, "127.0.0.1:1", nil, nil)

	logins := map[string]bool{}
	targets := map[string]bool{}
	for i := range uint64(15) {
		login, target, err := routing.ParseUsername(d.username(i), "#")
		if err != nil {
			t.Fatalf("ParseUsername(%q): %v", d.username(i), err)
		}
		logins[login] = true
		targets[target] = true
	}
	if len(logins) != 3 {
		t.Errorf("distinct logins = %d, want the scenario's 3 subjects", len(logins))
	}
	if len(targets) != 5 {
		t.Errorf("distinct targets = %d, want the scenario's 5", len(targets))
	}
}

func TestUsernameHonoursTheStepOffset(t *testing.T) {
	sc := decode(t, "name: x\nrun:\n  mode: rate\n  rate: 1\n  duration: 1s\n")
	first := newDriver(sc, stepPlan{Targets: 4}, "127.0.0.1:1", nil, nil)
	second := newDriver(sc, stepPlan{Targets: 4, NameOffset: 4}, "127.0.0.1:1", nil, nil)
	seen := map[string]bool{}
	for i := range uint64(4) {
		seen[first.username(i)] = true
	}
	for i := range uint64(4) {
		if seen[second.username(i)] {
			t.Fatalf("step 2 reused %q from step 1: its cache measurement would not be its own", second.username(i))
		}
	}
}

func TestFirstLine(t *testing.T) {
	if got := firstLine([]byte("\n\n  denied: nope\nmore\n")); got != "denied: nope" {
		t.Errorf("firstLine = %q", got)
	}
	if got := firstLine(nil); got != "" {
		t.Errorf("firstLine(nil) = %q, want empty", got)
	}
}

func TestClassifyBoundsTheErrorText(t *testing.T) {
	// Ten thousand identical failures are noise; their shape is the finding,
	// and an unbounded key would make the error table unreadable.
	long := strings.Repeat("x", 500)
	if got := classify(errString(long)); len(got) > 120 {
		t.Errorf("classify returned %d chars, want it bounded", len(got))
	}
}

type errString string

func (e errString) Error() string { return string(e) }
