// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hoplock/proxy/internal/auth/target/device"
	"github.com/hoplock/proxy/internal/auth/target/device/fortios"
	"github.com/hoplock/proxy/internal/config"
)

// profileDialer is a ShellDialer that refuses to reach anything.
//
// Every check in this file is answered from a DECLARATION, which is the
// property being tested: a proxy learns that its access profile is wrong for a
// platform without dialling a customer's device, so it learns it at startup
// rather than one session at a time. A dialer that would panic if used is how
// that stays true when somebody adds a check that connects.
type profileDialer struct{}

func (profileDialer) Shell(context.Context, device.Endpoint) (device.Shell, error) {
	return nil, errors.New("a startup check must not dial a device")
}

// TestTheAccessProfileIsResolvedPerPlatform is phase 0036's answer to the
// question the setting could not previously express: a proxy fronting two
// platforms whose profile vocabularies do not overlap has a correct value for
// each, and a route naming no scope of its own is served on both.
func TestTheAccessProfileIsResolvedPerPlatform(t *testing.T) {
	t.Parallel()
	cfg := config.EphemeralAccountAuth{
		AccessProfile: config.AccessProfilePerPlatform(map[string]string{
			fortios.PlatformFortiGate:   "prof_admin",
			fortios.PlatformFortiSwitch: "super_admin",
		}),
	}
	registry, err := newDriverRegistry(cfg, profileDialer{})
	if err != nil {
		t.Fatalf("a scope named for each platform was refused: %v", err)
	}

	profiles := accessProfilesFor(registry, cfg.AccessProfile)
	for platform, want := range map[string]string{
		fortios.PlatformFortiGate:   "prof_admin",
		fortios.PlatformFortiSwitch: "super_admin",
	} {
		if got := profiles[platform]; got != want {
			t.Errorf("the scope for %s resolved to %q, want %q", platform, got, want)
		}
	}
}

// TestAFortiOSProfileOnASwitchIsRefusedAtStartup is the failure this phase
// exists to move.
//
// It is the configuration a FortiGate estate has on the day it acquires its
// first switch: one string, valid on the platform it was written for, naming
// nothing at all on the other. Phase 0029 answered it per session — the switch
// driver was built with no default and refused a route relying on one — and the
// operator's only signal was an outage. It is now a boot error, and the message
// has to carry enough for an operator to act on: which platform, which profile,
// and what the platform does have.
func TestAFortiOSProfileOnASwitchIsRefusedAtStartup(t *testing.T) {
	t.Parallel()
	for _, profile := range []string{"prof_admin", "super_admin_readonly"} {
		t.Run(profile, func(t *testing.T) {
			t.Parallel()
			_, err := newDriverRegistry(config.EphemeralAccountAuth{
				AccessProfile: config.AccessProfileEverywhere(profile),
			}, profileDialer{})
			if err == nil {
				t.Fatalf("a proxy serving both platforms started with %q for every platform", profile)
			}
			for _, want := range []string{
				"access_profile", fortios.PlatformFortiSwitch, profile,
				"FortiSwitchOS does not have it",
			} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal does not name %q: %v", want, err)
				}
			}
		})
	}
}

// TestAFortiGateOnlyProxyKeepsTheScalarForm is the other half of the same
// change, and it is why the scalar shape is kept rather than migrated.
//
// The scalar is not a legacy form: it is how an operator says "every platform
// this proxy serves takes the same scope", which is the truth for a
// single-platform estate. Phase 0029's argument against refusing at startup was
// that a FortiGate-only deployment must not stop booting the day a second
// driver ships — that argument is answered by `platforms:` naming what the
// proxy fronts, not by weakening the check.
func TestAFortiGateOnlyProxyKeepsTheScalarForm(t *testing.T) {
	t.Parallel()
	registry, err := newDriverRegistry(config.EphemeralAccountAuth{
		Platforms:     []string{fortios.PlatformFortiGate},
		AccessProfile: config.AccessProfileEverywhere("prof_admin"),
	}, profileDialer{})
	if err != nil {
		t.Fatalf("a FortiGate-only proxy was refused: %v", err)
	}
	if got := registry.Platforms(); len(got) != 1 || got[0] != fortios.PlatformFortiGate {
		t.Fatalf("registered %v, want only %s", got, fortios.PlatformFortiGate)
	}
}

// TestAPlatformWithNoScopeIsRefusedAtStartup covers the mapping form's own
// mistake: an entry for one platform and none for another the proxy serves.
//
// There is deliberately no fleet-wide fallback under the mapping form. A
// fallback would put the scope of a platform the operator DID think about onto
// one they did not, which is exactly the substitution this phase removes.
func TestAPlatformWithNoScopeIsRefusedAtStartup(t *testing.T) {
	t.Parallel()
	_, err := newDriverRegistry(config.EphemeralAccountAuth{
		AccessProfile: config.AccessProfilePerPlatform(map[string]string{
			fortios.PlatformFortiGate: "prof_admin",
		}),
	}, profileDialer{})
	if err == nil {
		t.Fatal("a proxy started with no scope for a platform it serves")
	}
	if !strings.Contains(err.Error(), fortios.PlatformFortiSwitch) {
		t.Errorf("the refusal does not name the uncovered platform: %v", err)
	}
	if !strings.Contains(err.Error(), "platforms") {
		t.Errorf("the refusal does not offer narrowing `platforms:` as the other remedy: %v", err)
	}
}

// TestAScopeForAnUnservedPlatformIsRefused keeps the two halves of one error
// together.
//
// An operator who narrows `platforms:` and forgets to remove the entry, or who
// misspells a platform name, is otherwise told only that a DIFFERENT platform
// has no scope — and the reason it has none is sitting two lines above in their
// own file.
func TestAScopeForAnUnservedPlatformIsRefused(t *testing.T) {
	t.Parallel()
	_, err := newDriverRegistry(config.EphemeralAccountAuth{
		Platforms: []string{fortios.PlatformFortiGate},
		AccessProfile: config.AccessProfilePerPlatform(map[string]string{
			fortios.PlatformFortiGate: "prof_admin",
			"fortigatte":              "prof_admin",
		}),
	}, profileDialer{})
	if err == nil {
		t.Fatal("a scope named for a platform this proxy does not serve was accepted")
	}
	if !strings.Contains(err.Error(), "fortigatte") {
		t.Errorf("the refusal does not name the entry: %v", err)
	}
}

// TestEveryShippedDriverAnswersForItsOwnScope is the seam property, and it is
// what stops phase 0036 from being a two-driver special case.
//
// device.ValidateRole answers nil for a driver that declares no rule, which is
// the right answer and also an easy one to reach by forgetting to implement the
// interface. The check that a platform cannot hold the profile named for it is
// only as good as the drivers that answer it, so a shipped driver is required
// to have an opinion — a third platform with a fourth profile vocabulary
// repeats this whole argument otherwise, which is what the prompt for this
// phase said it was trying to stop.
func TestEveryShippedDriverAnswersForItsOwnScope(t *testing.T) {
	t.Parallel()
	for _, d := range device.Shipped().Drivers() {
		if _, ok := d.(device.RoleValidator); !ok {
			t.Errorf("shipped driver %q declares no device.RoleValidator, so a proxy cannot be told at startup "+
				"that its access profile is wrong for this platform", d.Platform())
			continue
		}
		if err := device.ValidateRole(d, ""); err == nil {
			t.Errorf("shipped driver %q accepts an empty scope, which is no scope at all", d.Platform())
		}
	}
}
