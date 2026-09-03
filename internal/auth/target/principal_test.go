// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"errors"
	"strings"
	"testing"
)

// TestReadableSchemeIsUnchangedByTheGeneralisation is the proof phase 0014's
// acceptance criteria ask for: generalising the naming over a DECLARED limit
// must not change one byte of what the POSIX path produces.
//
// The ephemeral tests already assert the Linux path end to end and pass
// unmodified, which is the stronger evidence. This is the direct statement of
// the same thing, so that a future change to the constrained scheme fails here
// rather than somewhere three packages away.
func TestReadableSchemeIsUnchangedByTheGeneralisation(t *testing.T) {
	const proxyID = "proxy-a"
	prefix := principalPrefixFor(proxyID)

	for _, limit := range []int{32, 35, 64, 255} {
		n, err := newNaming(proxyID, limit)
		if err != nil {
			t.Fatalf("newNaming(%d): %v", limit, err)
		}
		if !n.readable {
			t.Fatalf("a limit of %d dropped the login segment; PLAN §5.3 keeps it at 32 and above", limit)
		}
		if n.prefix != prefix {
			t.Errorf("limit %d uses prefix %q, want the POSIX prefix %q — the reaper matches on this", limit, n.prefix, prefix)
		}
		name, err := n.name("alice")
		if err != nil {
			t.Fatalf("name: %v", err)
		}
		if !strings.HasPrefix(name, prefix+"alice-") {
			t.Errorf("name %q is not the §5.1 scheme", name)
		}
		if len(name) != len(prefix)+len("alice-")+principalTokenLen {
			t.Errorf("name %q is not the §5.1 shape", name)
		}
		if err := validatePrincipal(name); err != nil {
			t.Errorf("name %q would not pass the POSIX gate: %v", name, err)
		}
	}
}

// TestConstrainedSchemeKeepsWhatCannotBeGivenUp covers PLAN §5.3's trade: the
// login segment goes, the reaper prefix and the uniqueness token stay.
func TestConstrainedSchemeKeepsWhatCannotBeGivenUp(t *testing.T) {
	const proxyID = "proxy-a"
	for _, limit := range []int{11, 12, 16, 24, 31} {
		n, err := newNaming(proxyID, limit)
		if err != nil {
			t.Fatalf("newNaming(%d): %v", limit, err)
		}
		if n.readable {
			t.Fatalf("a limit of %d kept the login segment", limit)
		}
		name, err := n.name("automation-disk-check")
		if err != nil {
			t.Fatalf("name: %v", err)
		}
		switch {
		case len(name) != limit:
			t.Errorf("limit %d produced %q (%d characters); the scheme spends the whole budget on the token", limit, name, len(name))
		case !strings.HasPrefix(name, principalPrefix):
			t.Errorf("name %q lost the reaper prefix; without it one proxy's sweep removes another's live accounts", name)
		case !strings.HasPrefix(name, n.prefix):
			t.Errorf("name %q does not carry the proxy tag the reaper will match", name)
		case strings.Contains(name, "automation"):
			t.Errorf("name %q kept part of the login; a truncation that reads as attributable is worse than an absence", name)
		}
		if got := len(name) - len(n.prefix); got != limit-constrainedFixedLen {
			t.Errorf("limit %d gave the token %d characters, want %d", limit, got, limit-constrainedFixedLen)
		}
	}
}

// TestTokensDoNotRepeat is the property two concurrent sessions depend on.
func TestTokensDoNotRepeat(t *testing.T) {
	n, err := newNaming("proxy-a", 12)
	if err != nil {
		t.Fatalf("newNaming: %v", err)
	}
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		name, err := n.name("alice")
		if err != nil {
			t.Fatalf("name: %v", err)
		}
		seen[name] = true
	}
	// Five base36 characters is ~26 bits; 200 draws colliding more than a
	// handful of times would mean the token is not what it claims to be.
	if len(seen) < 195 {
		t.Errorf("200 draws produced only %d distinct names", len(seen))
	}
}

// TestUnservableLimitsAreRefusedNotTruncated is the refusal PLAN §5.3 requires
// below eleven characters, and the one for a driver that declares nothing.
func TestUnservableLimitsAreRefusedNotTruncated(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit int
	}{
		{"undeclared", 0},
		{"negative", -1},
		{"one character short", minAccountNameLen - 1},
		{"far too short", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newNaming("proxy-a", tc.limit); !errors.Is(err, ErrNameLimit) {
				t.Fatalf("newNaming(%d) = %v, want ErrNameLimit", tc.limit, err)
			}
		})
	}
}

// TestProxyTagsDifferBetweenProxies is what keeps one proxy's reaper out of
// another's accounts, under both schemes.
func TestProxyTagsDifferBetweenProxies(t *testing.T) {
	for _, limit := range []int{12, 35} {
		a, err := newNaming("proxy-a", limit)
		if err != nil {
			t.Fatalf("newNaming: %v", err)
		}
		b, err := newNaming("proxy-b", limit)
		if err != nil {
			t.Fatalf("newNaming: %v", err)
		}
		if a.prefix == b.prefix {
			t.Errorf("two proxies share the prefix %q at limit %d; each would sweep the other's live sessions", a.prefix, limit)
		}
	}
}

// TestTheNamingSchemeFitsAFortiOSScheduleName is a cross-package invariant, and
// it is here rather than in the driver because this is the file that can break
// it (phase 0017, after verification).
//
// A FortiGate carries an account's deadline in a `config firewall schedule
// onetime` entry NAMED AFTER THE ACCOUNT, and that table's own `name` field
// accepts 31 characters. This scheme happens to produce exactly 31 at its
// longest — 8 for `hl-<tag>-`, 14 for the login, 9 for `-<token>` — so it fits
// with nothing to spare. Widen principalLoginLen or principalTokenLen by one
// and every device-enforced FortiOS route starts failing at schedule creation,
// which is a failure nothing in this package would otherwise show.
func TestTheNamingSchemeFitsAFortiOSScheduleName(t *testing.T) {
	// fortiOSScheduleNameLen is duplicated deliberately rather than imported:
	// internal/auth/target must not depend on one driver, and a number that
	// two files have to agree on is exactly the kind that drifts silently.
	// If it changes there, this test is the thing that fails.
	const fortiOSScheduleNameLen = 31

	for _, limit := range []int{minAccountNameLen, 20, 31, readableSchemeMin, 64, 255} {
		n, err := newNaming("proxy-a", limit)
		if err != nil {
			t.Fatalf("newNaming(%d): %v", limit, err)
		}
		for i := 0; i < 64; i++ {
			name, err := n.name("a-very-long-login-name-indeed")
			if err != nil {
				t.Fatalf("name(limit %d): %v", limit, err)
			}
			if len(name) > fortiOSScheduleNameLen {
				t.Fatalf("limit %d produced %q (%d characters), which cannot name a FortiOS one-time schedule (%d)",
					limit, name, len(name), fortiOSScheduleNameLen)
			}
		}
	}
}
