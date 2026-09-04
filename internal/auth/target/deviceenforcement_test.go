// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hoplock/proxy/internal/auth/target/device"
	"github.com/hoplock/proxy/internal/control"
)

// Phase 0019's device half (PLAN §6.5, §5.3): the rung a device can carry is
// the PLATFORM's own authorizer, the scope it is given is the ROUTE's, and what
// the record says is what the platform is actually enforcing.

// TestPlatformAuthorizedUsesTheRoutesRoleRatherThanTheProxysProfile is the
// replacement 0015 asked for: `enforcement.platform_role` is what a route names,
// and `auth.target.ephemeral_account.access_profile` becomes the setting for the
// routes that name none.
func TestPlatformAuthorizedUsesTheRoutesRoleRatherThanTheProxysProfile(t *testing.T) {
	h := newDeviceHarness(t, deviceHarnessOptions{deliverable: true})
	tgt := h.tgt
	tgt.Auth = deviceRouteAuth(nil)
	tgt.Enforcement = &Enforcement{
		Execution:    control.ExecutionPlatformAuthorized,
		PlatformRole: "prof_admin",
	}

	access, err := h.auth.Provision(context.Background(), deviceIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = access.Close(context.Background()) })

	on, ok := h.dev.Accounts()[access.ClientConfig.User]
	if !ok {
		t.Fatalf("the administrator was not created; the device has %v", h.dev.Accounts())
	}
	if on.Profile != "prof_admin" {
		t.Errorf("access profile = %q, want the route's platform_role rather than the proxy's %q",
			on.Profile, testDeviceAccessProfile)
	}

	e := access.Enforcement
	if e == nil || e.Execution != control.ExecutionPlatformAuthorized || !e.Verified {
		t.Fatalf("Enforcement = %+v, want an applied, verified platform-authorized rung", e)
	}
	if !strings.Contains(e.ExecutionMechanism, "prof_admin") {
		t.Errorf("mechanism = %q, want it to name the scope the account actually got", e.ExecutionMechanism)
	}
	// The coarseness is recorded rather than glossed: vendor RBAC groups
	// commands the vendor's way, and the record has to say what the rung is
	// actually enforcing.
	if !strings.Contains(e.Caveat, "super_admin_readonly") {
		t.Errorf("caveat = %q, want the driver's declaration of how its authorizer leaks by grouping", e.Caveat)
	}
	events := h.events.mapping()
	if len(events) != 1 || events[0].Enforcement == nil {
		t.Fatalf("the mapping event carries no enforcement: %+v", events)
	}
	if events[0].Enforcement.Caveat != e.Caveat {
		t.Error("the mapping event and the session record disagree about what the rung enforces")
	}
}

// TestARouteWithNoRoleIsRefused: the contract requires platform_role beside the
// rung, so falling back to the proxy-wide profile would put a scope the route
// did not name behind a record saying the route chose one.
func TestPlatformAuthorizedWithNoRoleIsRefused(t *testing.T) {
	h := newDeviceHarness(t, deviceHarnessOptions{deliverable: true})
	tgt := h.tgt
	tgt.Auth = deviceRouteAuth(nil)
	tgt.Enforcement = &Enforcement{Execution: control.ExecutionPlatformAuthorized}

	_, err := h.auth.Provision(context.Background(), deviceIdentity(), tgt)
	if !errors.Is(err, ErrInvalidParam) {
		t.Fatalf("Provision error = %v, want ErrInvalidParam", err)
	}
	if len(h.dev.Accounts()) != 0 {
		t.Error("an administrator was created for a route whose rung could not be rendered")
	}
}

// TestARungThePlatformCannotDeliverIsASkippedRung. 0018 fixed the class: a rung
// a DECLARATION rules out is a skipped ladder entry, so the proxy may walk on,
// and exhausting the ladder is the outage-class denial it already was.
func TestARungThePlatformCannotDeliverIsASkippedRung(t *testing.T) {
	for _, tc := range []struct {
		name string
		e    *Enforcement
	}{
		{"a POSIX execution rung", &Enforcement{
			Execution:      control.ExecutionAccountRestricted,
			RestrictedExec: catOnly(),
		}},
		{"a POSIX reach rung", &Enforcement{
			Reach:                 control.ReachAccountEgressRestricted,
			PermittedDestinations: []control.ForwardDestination{{Host: "10.0.0.1", Port: 443}},
		}},
		{"network isolation", &Enforcement{Reach: control.ReachAccountNetworkIsolated}},
		{"an unknown execution rung", &Enforcement{Execution: "account-hardened"}},
		{"an unknown reach rung", &Enforcement{Reach: "account-firewalled"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newDeviceHarness(t, deviceHarnessOptions{deliverable: true})
			tgt := h.tgt
			tgt.Auth = deviceRouteAuth(nil)
			tgt.Enforcement = tc.e

			// It is answerable without connecting, which is what lets the
			// ladder walk past it.
			if err := h.auth.CanSatisfy(tgt.Auth, tgt); !errors.Is(err, ErrRungUnsatisfiable) {
				t.Fatalf("CanSatisfy = %v, want ErrRungUnsatisfiable", err)
			}
			if _, err := h.auth.Provision(context.Background(), deviceIdentity(), tgt); !errors.Is(err, ErrRungUnsatisfiable) {
				t.Fatalf("Provision = %v, want ErrRungUnsatisfiable", err)
			}
			if len(h.dev.Accounts()) != 0 {
				t.Error("an administrator was created anyway")
			}
		})
	}
}

// TestAnAttestedRungOnADeviceAppliesNothingAndIsRecorded. Pre-provisioned rungs
// stay pre-provisioned: the customer defined the scope, this phase configures
// nothing for it, and the record says the claim was not verified here.
func TestAnAttestedRungOnADeviceAppliesNothingAndIsRecorded(t *testing.T) {
	h := newDeviceHarness(t, deviceHarnessOptions{deliverable: true})
	tgt := h.tgt
	tgt.Auth = deviceRouteAuth(nil)
	tgt.Enforcement = &Enforcement{
		Execution: control.ExecutionPlatformAttested,
		Reach:     control.ReachPlatformAttested,
		Attestation: &control.Attestation{
			AssertedBy: "network-engineering",
			Reference:  "baseline/fgt-edge-readonly@v7",
		},
	}

	access, err := h.auth.Provision(context.Background(), deviceIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = access.Close(context.Background()) })

	e := access.Enforcement
	switch {
	case e == nil:
		t.Fatal("no enforcement was recorded")
	case e.Verified:
		t.Error("an attested rung must be recorded as unverified: nobody here checked it")
	case e.AttestedBy != "network-engineering":
		t.Errorf("attested_by = %q, want the route's attestation", e.AttestedBy)
	case e.AttestationRef != "baseline/fgt-edge-readonly@v7":
		t.Errorf("attestation reference = %q, want the route's", e.AttestationRef)
	case e.ExecutionMechanism != "":
		t.Errorf("mechanism = %q, want nothing: an attested rung applies nothing", e.ExecutionMechanism)
	}
	// The account still needs a scope, and with no role named it is the
	// proxy-wide setting.
	if on := h.dev.Accounts()[access.ClientConfig.User]; on.Profile != testDeviceAccessProfile {
		t.Errorf("access profile = %q, want the proxy-wide setting %q", on.Profile, testDeviceAccessProfile)
	}
}

// TestADriverDeclaringNoAuthorizerCannotCarryTheRung.
func TestADriverDeclaringNoAuthorizerCannotCarryTheRung(t *testing.T) {
	h := newDeviceHarness(t, deviceHarnessOptions{deliverable: true})
	tgt := h.tgt
	tgt.Auth = deviceRouteAuth(map[string]string{control.ParamPlatform: unexpiringPlatform})
	tgt.Enforcement = &Enforcement{
		Execution:    control.ExecutionPlatformAuthorized,
		PlatformRole: "prof_admin",
	}
	// The stand-in platform declares no command authorizer, which is the
	// honest answer for most platforms until somebody writes the mapping.
	if err := h.auth.CanSatisfy(tgt.Auth, tgt); !errors.Is(err, ErrRungUnsatisfiable) {
		t.Fatalf("CanSatisfy = %v, want ErrRungUnsatisfiable for a platform with no authorizer", err)
	}
}

// TestShippedDriversMustSayHowTheirAuthorizerLeaks is D13's rule applied to the
// new declaration: a bit flipped with nothing to review is what CheckShipped
// exists to fail.
func TestShippedDriversMustSayHowTheirAuthorizerLeaks(t *testing.T) {
	if err := device.CheckShipped(device.Shipped()); err != nil {
		t.Fatalf("the shipped drivers do not meet D13's rules: %v", err)
	}
	registry := device.NewRegistry()
	if err := registry.Register(&silentAuthorizer{}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := device.CheckShipped(registry); err == nil {
		t.Fatal("a shipped driver may not declare a command authorizer without saying how it leaks by grouping")
	}
}

// silentAuthorizer declares an authorizer and says nothing about its grouping.
type silentAuthorizer struct{ device.Driver }

func (d *silentAuthorizer) Platform() string { return "silent-authorizer" }

func (d *silentAuthorizer) Capabilities() device.Capabilities {
	return device.Capabilities{
		MaxAccountNameLen:    32,
		CredentialKinds:      []control.CredentialKind{control.CredentialKindPassword},
		CommandAuthorization: "a role",
	}
}
