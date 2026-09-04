// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// enforcedResponse is a v4 authorize response standing on an APPLIED rung of
// each axis, over a ladder whose first entry provisions the target. It is the
// shape phase 0019 renders, and every rule below is checked against it.
func enforcedResponse() *AuthorizeResponse {
	deadline := time.Date(2026, 9, 4, 17, 30, 0, 0, time.UTC)
	windowStart := time.Date(2026, 9, 4, 9, 0, 0, 0, time.UTC)
	windowEnd := time.Date(2026, 9, 4, 17, 0, 0, 0, time.UTC)
	return &AuthorizeResponse{
		RouteType:         RouteTypeDirect,
		Target:            "build-01.company.com",
		PermittedChannels: []string{"session"},
		PermittedRequests: &RequestPolicy{Types: []string{RequestExec}},
		TargetAuthLadder: ladderOf(TargetAuth{
			Method: TargetAuthEphemeralUser,
			Params: map[string]string{ParamUsername: "svc-build", ParamLifetimeSeconds: "900"},
		}),
		FilterPolicy: FilterPolicy{
			Mode:     FilterModeWhitelist,
			ExecMode: ExecModeRestricted,
			RestrictedExec: &RestrictedExecPolicy{Commands: []RestrictedCommand{
				{Executable: "/bin/uptime", Form: CommandFormExact},
			}},
		},
		Enforcement: &EnforcementPolicy{
			Execution: ExecutionAccountRestricted,
			Reach:     ReachAccountEgressRestricted,
			PermittedDestinations: []ForwardDestination{
				{Host: "artifacts.company.com", Port: 443},
				{Host: "10.9.0.0/16", PortRange: &PortRange{From: 8080, To: 8090}},
			},
		},
		SessionDeadline:       &deadline,
		RequireSessionCapture: true,
		GrantContext: &GrantContext{
			System:      "qualys",
			Reference:   "SCAN-2026-09-04-1183",
			WindowStart: &windowStart,
			WindowEnd:   &windowEnd,
			Additional: &AdditionalContext{Fields: map[string]any{
				"scan_profile": "authenticated-linux",
				"tags":         []any{"prod", "linux"},
			}},
		},
		Concurrency: &ConcurrencyLimits{PerSubject: 4, PerTarget: 10},
	}
}

// attestedResponse is the other kind of rung: a brokered-key route, where the
// proxy administers nothing and the enforcement claim is the target's own.
// Calling that "none available" would be false, which is why the vocabulary
// distinguishes attested from applied at all.
func attestedResponse() *AuthorizeResponse {
	return &AuthorizeResponse{
		RouteType:         RouteTypeDirect,
		Target:            "edge-fw-01.company.com",
		PermittedChannels: []string{"session"},
		TargetAuthLadder: ladderOf(TargetAuth{
			Method: TargetAuthBrokeredKey,
			Params: map[string]string{ParamUsername: "monitor", ParamCredentialRef: "edge-fleet-2026"},
		}),
		FilterPolicy: FilterPolicy{Mode: FilterModeBlacklist},
		Enforcement: &EnforcementPolicy{
			Execution: ExecutionPlatformAttested,
			Reach:     ReachPlatformAttested,
			Attestation: &Attestation{
				AssertedBy: "network-engineering",
				Reference:  "NET-BASELINE-7.2 §4",
			},
		},
	}
}

// TestEnforcementRoundTrips is the v4 smoke test: every field survives the wire
// intact, under the JSON names the contract documents.
func TestEnforcementRoundTrips(t *testing.T) {
	want := enforcedResponse()
	if err := want.Validate(); err != nil {
		t.Fatalf("the fixture itself violates the contract: %v", err)
	}

	body, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, name := range []string{
		`"enforcement"`, `"execution"`, `"reach"`, `"permitted_destinations"`,
		`"session_deadline"`, `"require_session_capture"`, `"grant_context"`,
		`"additional_context"`, `"concurrency"`, `"max_sessions_per_subject"`,
	} {
		if !strings.Contains(string(body), name) {
			t.Errorf("marshalled response does not carry %s: %s", name, body)
		}
	}

	var got AuthorizeResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(&got, want) {
		t.Errorf("round trip changed the response:\n got %+v\nwant %+v", got.Enforcement, want.Enforcement)
	}
	if got.EnforcedExecution() != ExecutionAccountRestricted {
		t.Errorf("EnforcedExecution = %q, want %q", got.EnforcedExecution(), ExecutionAccountRestricted)
	}
	if got.EnforcedReach() != ReachAccountEgressRestricted {
		t.Errorf("EnforcedReach = %q, want %q", got.EnforcedReach(), ReachAccountEgressRestricted)
	}
}

// TestAbsentEnforcementIsTodaysBehaviour is the compatibility rule the whole
// revision rests on: a v3 server that never heard of any of these fields keeps
// working, and every default is what it already produced.
func TestAbsentEnforcementIsTodaysBehaviour(t *testing.T) {
	var resp AuthorizeResponse
	if err := json.Unmarshal([]byte(`{
		"route_type": "direct",
		"target": "host.company.com",
		"permitted_channels": ["session"],
		"filter_policy": {"mode": "blacklist"}
	}`), &resp); err != nil {
		t.Fatalf("unmarshal a v3 response: %v", err)
	}
	if err := resp.Validate(); err != nil {
		t.Fatalf("a v3 response must stay valid: %v", err)
	}

	if got := resp.EnforcedExecution(); got != ExecutionProxyInspected {
		t.Errorf("absent enforcement.execution = %q, want %q", got, ExecutionProxyInspected)
	}
	if got := resp.EnforcedReach(); got != ReachProxyChannelPolicy {
		t.Errorf("absent enforcement.reach = %q, want %q", got, ReachProxyChannelPolicy)
	}
	if resp.SessionDeadline != nil {
		t.Error("absent session_deadline must mean no deadline")
	}
	if resp.RequireSessionCapture {
		t.Error("absent require_session_capture must mean capture is not required")
	}
	if resp.GrantContext != nil {
		t.Error("absent grant_context must mean no grant context")
	}
	if resp.Concurrency != nil {
		t.Error("absent concurrency must mean uncapped")
	}
	// The nil receivers matter as much as the absent fields: 0019 reads these
	// through the accessors on a response that may carry nothing.
	var nilPolicy *EnforcementPolicy
	if nilPolicy.ExecutionRung() != ExecutionProxyInspected || nilPolicy.ReachRung() != ReachProxyChannelPolicy {
		t.Error("a nil EnforcementPolicy must read as both defaults")
	}
	if nilPolicy.RequiresProvisioning() {
		t.Error("a nil EnforcementPolicy must require no provisioning")
	}
}

// TestEachAxisIsIndependent guards the property the two-ladder finding rests
// on: what a session may run and what it may reach are separate questions, and
// a route may answer either without answering the other.
func TestEachAxisIsIndependent(t *testing.T) {
	t.Run("execution only", func(t *testing.T) {
		resp := enforcedResponse()
		resp.Enforcement = &EnforcementPolicy{Execution: ExecutionAccountConfined}
		if err := resp.Validate(); err != nil {
			t.Fatalf("an execution rung alone must be valid: %v", err)
		}
		if got := resp.EnforcedReach(); got != ReachProxyChannelPolicy {
			t.Errorf("reach = %q, want the default %q", got, ReachProxyChannelPolicy)
		}
	})
	t.Run("reach only", func(t *testing.T) {
		resp := enforcedResponse()
		resp.Enforcement = &EnforcementPolicy{Reach: ReachAccountNetworkIsolated}
		if err := resp.Validate(); err != nil {
			t.Fatalf("a reach rung alone must be valid: %v", err)
		}
		if got := resp.EnforcedExecution(); got != ExecutionProxyInspected {
			t.Errorf("execution = %q, want the default %q", got, ExecutionProxyInspected)
		}
	})
}

// TestUnknownRungIsRefused: an unknown rung is never coerced. Coercing down
// would run the session at a weaker rung than the policy names — the silent
// downgrade this whole vocabulary exists to prevent — and there is nothing to
// coerce up to.
func TestUnknownRungIsRefused(t *testing.T) {
	t.Run("execution", func(t *testing.T) {
		resp := enforcedResponse()
		resp.Enforcement = &EnforcementPolicy{Execution: ExecutionRung("account-hardened")}
		assertRefused(t, resp, "account-hardened")
	})
	t.Run("reach", func(t *testing.T) {
		resp := enforcedResponse()
		resp.Enforcement = &EnforcementPolicy{Reach: ReachRung("firewalled")}
		assertRefused(t, resp, "firewalled")
	})
	t.Run("a rung from the other axis", func(t *testing.T) {
		// The two attested values are spelled the same on purpose, but nothing
		// else crosses: naming an execution rung on the reach axis is a policy
		// author's mistake and must not be read as anything.
		resp := enforcedResponse()
		resp.Enforcement = &EnforcementPolicy{Reach: ReachRung(ExecutionAccountRestricted)}
		assertRefused(t, resp, string(ExecutionAccountRestricted))
	})
}

// TestAppliedRungOnABrokeredKeyRouteIsRefused is the coupling D6a stated and
// D14 made conditional. brokered-key changes nothing on the target, so an
// applied rung could never be rendered on such a route: the policy can only
// fail at connect time, in front of a user, which is why it is refused here
// instead.
func TestAppliedRungOnABrokeredKeyRouteIsRefused(t *testing.T) {
	brokered := TargetAuth{
		Method: TargetAuthBrokeredKey,
		Params: map[string]string{ParamUsername: "monitor", ParamCredentialRef: "edge-fleet-2026"},
	}
	provisioning := TargetAuth{
		Method: TargetAuthEphemeralUser,
		Params: map[string]string{ParamUsername: "svc-build", ParamLifetimeSeconds: "900"},
	}

	t.Run("every entry is brokered-key", func(t *testing.T) {
		resp := enforcedResponse()
		resp.TargetAuthLadder = ladderOf(brokered)
		assertRefused(t, resp, "no credential method on this route provisions the target")
	})
	t.Run("the single v2 object is brokered-key", func(t *testing.T) {
		resp := enforcedResponse()
		resp.TargetAuthLadder = nil
		resp.TargetAuth = &brokered
		assertRefused(t, resp, "no credential method on this route provisions the target")
	})
	t.Run("some entry provisions the target", func(t *testing.T) {
		// The rung is a property of the ROUTE, and the entry that cannot carry
		// it is a skipped rung (D14) rather than a refusal: refusing here would
		// forfeit the whole argument for a ladder.
		resp := enforcedResponse()
		resp.TargetAuthLadder = ladderOf(provisioning, brokered)
		if err := resp.Validate(); err != nil {
			t.Fatalf("a ladder whose first entry provisions must be accepted: %v", err)
		}
	})
	t.Run("no ladder at all", func(t *testing.T) {
		// The proxy's locally configured method is invisible to this response,
		// so the question is resolved at provisioning time instead.
		resp := enforcedResponse()
		resp.TargetAuthLadder = nil
		if err := resp.Validate(); err != nil {
			t.Fatalf("an absent ladder must not be refused here: %v", err)
		}
	})
	t.Run("an attested rung is fine on brokered-key", func(t *testing.T) {
		// This is the point of having the distinction at all: the appliance
		// estate gets a real enforcement claim instead of "none available".
		if err := attestedResponse().Validate(); err != nil {
			t.Fatalf("an attested rung on a brokered-key route must be accepted: %v", err)
		}
	})
}

// TestAttestationIsRequiredAndAttributable: an attested rung is a claim nothing
// here verifies, so the contract's answer is to make it attributable. "Trust
// us" and an empty string are the same answer.
func TestAttestationIsRequiredAndAttributable(t *testing.T) {
	t.Run("missing entirely", func(t *testing.T) {
		resp := attestedResponse()
		resp.Enforcement.Attestation = nil
		assertRefused(t, resp, "carries no attestation")
	})
	t.Run("no asserter", func(t *testing.T) {
		resp := attestedResponse()
		resp.Enforcement.Attestation.AssertedBy = ""
		assertRefused(t, resp, "asserted_by")
	})
	t.Run("no reference", func(t *testing.T) {
		resp := attestedResponse()
		resp.Enforcement.Attestation.Reference = ""
		assertRefused(t, resp, "reference")
	})
	t.Run("attestation beside an applied rung", func(t *testing.T) {
		// A sentence nobody verified, next to a rung this proxy rendered
		// itself, leaves a reader unable to tell which half the record meant.
		resp := enforcedResponse()
		resp.Enforcement.Attestation = &Attestation{AssertedBy: "someone", Reference: "somewhere"}
		assertRefused(t, resp, "names no attested rung")
	})
}

// TestRungParametersAreRequiredWhereTheyAreTheRung: each of these parameters is
// the whole content of its rung, and on any other rung it is a constraint
// nothing reads — which is the shape a dropped restriction takes.
func TestRungParametersAreRequiredWhereTheyAreTheRung(t *testing.T) {
	t.Run("platform_role is required by platform-authorized", func(t *testing.T) {
		resp := enforcedResponse()
		resp.Enforcement = &EnforcementPolicy{Execution: ExecutionPlatformAuthorized}
		assertRefused(t, resp, "platform_role is required")
	})
	t.Run("platform_role is forbidden elsewhere", func(t *testing.T) {
		resp := enforcedResponse()
		resp.Enforcement.PlatformRole = "prof_admin"
		assertRefused(t, resp, "platform_role is set")
	})
	t.Run("platform-authorized with a role", func(t *testing.T) {
		resp := enforcedResponse()
		resp.Enforcement = &EnforcementPolicy{
			Execution:    ExecutionPlatformAuthorized,
			PlatformRole: "prof_admin",
		}
		if err := resp.Validate(); err != nil {
			t.Fatalf("platform-authorized with a role must be valid: %v", err)
		}
	})
	t.Run("destinations are required by account-egress-restricted", func(t *testing.T) {
		resp := enforcedResponse()
		resp.Enforcement.PermittedDestinations = nil
		assertRefused(t, resp, "permitted_destinations is required")
	})
	t.Run("destinations are forbidden elsewhere", func(t *testing.T) {
		resp := enforcedResponse()
		resp.Enforcement.Reach = ReachAccountNetworkIsolated
		assertRefused(t, resp, "permitted_destinations is set")
	})
	t.Run("destinations are checked like any other", func(t *testing.T) {
		resp := enforcedResponse()
		resp.Enforcement.PermittedDestinations = []ForwardDestination{
			{Host: "db.company.com", Port: 5432, PortRange: &PortRange{From: 1, To: 2}},
		}
		assertRefused(t, resp, "sets both port and port_range")
	})
}

// TestRungMustAgreeWithTheRestOfTheResponse. A response that contradicts itself
// would have to be resolved by the proxy, and the proxy resolving a policy
// conflict is exactly what D2 forbids.
func TestRungMustAgreeWithTheRestOfTheResponse(t *testing.T) {
	t.Run("no-interactive-shell needs permitted_requests", func(t *testing.T) {
		resp := enforcedResponse()
		resp.Enforcement = &EnforcementPolicy{Execution: ExecutionNoInteractiveShell}
		resp.PermittedRequests = nil
		assertRefused(t, resp, "polices nothing")
	})
	for _, permitted := range []string{RequestShell, RequestPTY} {
		t.Run("no-interactive-shell versus "+permitted, func(t *testing.T) {
			resp := enforcedResponse()
			resp.Enforcement = &EnforcementPolicy{Execution: ExecutionNoInteractiveShell}
			resp.PermittedRequests = &RequestPolicy{Types: []string{RequestExec, permitted}}
			assertRefused(t, resp, permitted)
		})
	}
	t.Run("no-interactive-shell when the policy agrees", func(t *testing.T) {
		resp := enforcedResponse()
		resp.Enforcement = &EnforcementPolicy{Execution: ExecutionNoInteractiveShell}
		resp.PermittedRequests = &RequestPolicy{Types: []string{RequestExec, RequestEnv}}
		if err := resp.Validate(); err != nil {
			t.Fatalf("the claim and the policy agree here: %v", err)
		}
	})
	for _, rung := range []ExecutionRung{ExecutionAccountRestricted, ExecutionAccountConfined} {
		t.Run(string(rung)+" needs restricted exec", func(t *testing.T) {
			// restricted_exec is the only place the contract names an
			// executable; a pattern rule list has nothing to render.
			resp := enforcedResponse()
			resp.Enforcement = &EnforcementPolicy{Execution: rung}
			resp.FilterPolicy = FilterPolicy{Mode: FilterModeBlacklist}
			assertRefused(t, resp, "exec_mode")
		})
	}
}

// TestSessionBoundsAreValidated covers the shapes that cannot be true of any
// session. The grant context is checked for SHAPE and nothing else, because the
// proxy never reads its content for a decision.
func TestSessionBoundsAreValidated(t *testing.T) {
	t.Run("a zero deadline is refused", func(t *testing.T) {
		// The zero instant is what an absent or unparsed timestamp decodes to,
		// and enforcing it literally would close every session as it opened.
		resp := enforcedResponse()
		zero := time.Time{}
		resp.SessionDeadline = &zero
		assertRefused(t, resp, "session_deadline is present but zero")
	})
	t.Run("a negative concurrency cap is refused", func(t *testing.T) {
		resp := enforcedResponse()
		resp.Concurrency = &ConcurrencyLimits{PerSubject: -1}
		assertRefused(t, resp, "max_sessions_per_subject")
	})
	t.Run("an inverted grant window is refused", func(t *testing.T) {
		resp := enforcedResponse()
		start := time.Date(2026, 9, 4, 17, 0, 0, 0, time.UTC)
		end := time.Date(2026, 9, 4, 9, 0, 0, 0, time.UTC)
		resp.GrantContext = &GrantContext{WindowStart: &start, WindowEnd: &end}
		assertRefused(t, resp, "window_end is before")
	})
}

// TestAdditionalContextTakesEitherForm. The systems on the other end of a grant
// differ more than a fixed schema can absorb: one has a sentence, another has a
// bag of fields. Anything else is refused rather than coerced, because the
// proxy stores this verbatim for an auditor.
func TestAdditionalContextTakesEitherForm(t *testing.T) {
	t.Run("a string", func(t *testing.T) {
		var c AdditionalContext
		if err := json.Unmarshal([]byte(`"approved by the change board"`), &c); err != nil {
			t.Fatalf("a string must decode: %v", err)
		}
		if c.Text != "approved by the change board" || c.Fields != nil {
			t.Errorf("decoded a string as %+v", c)
		}
		body, err := json.Marshal(c)
		if err != nil || string(body) != `"approved by the change board"` {
			t.Errorf("re-encoding a string gave %s (%v)", body, err)
		}
	})
	t.Run("an object", func(t *testing.T) {
		var c AdditionalContext
		if err := json.Unmarshal([]byte(`{"ticket":"CHG-9","depth":2}`), &c); err != nil {
			t.Fatalf("an object must decode: %v", err)
		}
		if c.Text != "" || c.Fields["ticket"] != "CHG-9" {
			t.Errorf("decoded an object as %+v", c)
		}
	})
	for name, payload := range map[string]string{
		"a number": `7`, "a list": `["a"]`, "a boolean": `true`,
	} {
		t.Run(name+" is refused", func(t *testing.T) {
			var c AdditionalContext
			if err := json.Unmarshal([]byte(payload), &c); err == nil {
				t.Errorf("%s decoded as %+v; the contract admits a string or an object only", name, c)
			}
		})
	}
}

// TestCloneIsolatesTheV4Vocabulary. A decision is handed to many sessions, and
// a cached one is shared: nothing a session holds may share backing memory with
// what the cache holds. For the grant context this matters even though nothing
// decides from it — one session mutating what another is logging corrupts the
// one record in this system that cannot be reconstructed afterwards.
func TestCloneIsolatesTheV4Vocabulary(t *testing.T) {
	original := enforcedResponse()
	clone := original.Clone()

	mutations := map[string]func(*AuthorizeResponse){
		"enforcement object": func(r *AuthorizeResponse) {
			r.Enforcement.Execution = ExecutionProxyInspected
		},
		"permitted destination": func(r *AuthorizeResponse) {
			r.Enforcement.PermittedDestinations[0].Host = "evil.company.com"
		},
		"destination port range": func(r *AuthorizeResponse) {
			r.Enforcement.PermittedDestinations[1].PortRange.To = 65535
		},
		"session deadline": func(r *AuthorizeResponse) {
			*r.SessionDeadline = r.SessionDeadline.Add(24 * time.Hour)
		},
		"grant context window": func(r *AuthorizeResponse) {
			*r.GrantContext.WindowEnd = r.GrantContext.WindowEnd.Add(24 * time.Hour)
		},
		"grant context fields": func(r *AuthorizeResponse) {
			r.GrantContext.Additional.Fields["scan_profile"] = "rewritten"
		},
		"grant context nested list": func(r *AuthorizeResponse) {
			r.GrantContext.Additional.Fields["tags"].([]any)[0] = "rewritten"
		},
		"concurrency caps": func(r *AuthorizeResponse) {
			r.Concurrency.PerSubject = 9999
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			fresh := enforcedResponse()
			copied := fresh.Clone()
			mutate(copied)
			if reflect.DeepEqual(fresh, copied) {
				t.Fatalf("mutating the clone's %s did not change it; the test proves nothing", name)
			}
			if !reflect.DeepEqual(fresh, enforcedResponse()) {
				t.Errorf("mutating the clone's %s reached back into the original", name)
			}
		})
	}

	// The attestation hangs off the enforcement object and is easy to miss.
	att := attestedResponse()
	attClone := att.Clone()
	attClone.Enforcement.Attestation.AssertedBy = "rewritten"
	if att.Enforcement.Attestation.AssertedBy != "network-engineering" {
		t.Error("mutating the clone's attestation reached back into the original")
	}

	// And the whole thing must still be equal when nothing is touched.
	if !reflect.DeepEqual(original, clone) {
		t.Error("Clone did not reproduce the response")
	}
}

// TestAdditionalContextCloneDoesNotAlias is the same rule at the one place a
// shallow copy would look right: the object form is arbitrary and nested.
func TestAdditionalContextCloneDoesNotAlias(t *testing.T) {
	c := &AdditionalContext{Fields: map[string]any{
		"outer": map[string]any{"inner": "original"},
	}}
	clone := c.Clone()
	clone.Fields["outer"].(map[string]any)["inner"] = "rewritten"
	if got := c.Fields["outer"].(map[string]any)["inner"]; got != "original" {
		t.Errorf("the nested map aliased: inner = %q", got)
	}
}

// TestProxyCapabilitiesFailSafe: an undeclared rung is not provided, and a
// proxy that declares nothing — which is what a v3 proxy implies — provides only
// what needs no capability at all.
func TestProxyCapabilitiesFailSafe(t *testing.T) {
	declared := &ProxyCapabilities{
		Execution: []ExecutionRung{ExecutionNoInteractiveShell, ExecutionAccountRestricted},
		Reach:     []ReachRung{ReachAccountNetworkIsolated},
	}
	for rung, want := range map[ExecutionRung]bool{
		ExecutionAccountRestricted:  true,
		ExecutionNoInteractiveShell: true,
		ExecutionAccountConfined:    false,
		ExecutionPlatformAuthorized: false,
		// Needs nothing of the build: it is what the proxy already does.
		ExecutionProxyInspected: true,
		// Applied by nobody here, so no capability gates it.
		ExecutionPlatformAttested: true,
	} {
		if got := declared.ProvidesExecution(rung); got != want {
			t.Errorf("declared.ProvidesExecution(%q) = %v, want %v", rung, got, want)
		}
	}
	if !declared.ProvidesReach(ReachAccountNetworkIsolated) ||
		declared.ProvidesReach(ReachAccountEgressRestricted) {
		t.Error("ProvidesReach did not answer from the declaration")
	}

	var absent *ProxyCapabilities
	for _, rung := range []ExecutionRung{ExecutionAccountRestricted, ExecutionAccountConfined} {
		if absent.ProvidesExecution(rung) {
			t.Errorf("a proxy declaring nothing must not provide %q", rung)
		}
	}
	if !absent.ProvidesExecution(ExecutionProxyInspected) ||
		!absent.ProvidesExecution(ExecutionPlatformAttested) ||
		!absent.ProvidesReach(ReachProxyChannelPolicy) ||
		!absent.ProvidesReach(ReachPlatformAttested) {
		t.Error("a proxy declaring nothing must still provide the rungs that need nothing of it")
	}
}

// TestTargetCapabilitiesAbsentAndStaleFailSafe is the answer to "what does a
// stale or absent capability record mean". The three cases — no record, an
// undated one, and one past its TTL — are treated identically, because they mean
// the same thing to anyone choosing a rung from one.
func TestTargetCapabilitiesAbsentAndStaleFailSafe(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	fresh := &TargetCapabilities{
		Execution:  []ExecutionRung{ExecutionAccountRestricted, ExecutionAccountConfined},
		Reach:      []ReachRung{ReachAccountEgressRestricted},
		ObservedAt: now.Add(-time.Minute),
	}
	stale := fresh.Clone()
	stale.ObservedAt = now.Add(-2 * DefaultCapabilityTTL)
	undated := fresh.Clone()
	undated.ObservedAt = time.Time{}

	cases := map[string]*TargetCapabilities{"absent": nil, "stale": stale, "undated": undated}

	if !fresh.Fresh(now, DefaultCapabilityTTL) {
		t.Fatal("a record observed a minute ago must be fresh")
	}
	if !fresh.ProvidesExecution(ExecutionAccountRestricted, now, DefaultCapabilityTTL) {
		t.Fatal("a fresh record must provide what it lists")
	}
	if fresh.ProvidesExecution(ExecutionPlatformAuthorized, now, DefaultCapabilityTTL) {
		t.Error("a fresh record must not provide what it does not list")
	}

	for name, record := range cases {
		t.Run(name, func(t *testing.T) {
			if record.Fresh(now, DefaultCapabilityTTL) {
				t.Error("must not be fresh")
			}
			for _, rung := range []ExecutionRung{ExecutionAccountRestricted, ExecutionAccountConfined} {
				if record.ProvidesExecution(rung, now, DefaultCapabilityTTL) {
					t.Errorf("provided the applied rung %q", rung)
				}
			}
			if record.ProvidesReach(ReachAccountEgressRestricted, now, DefaultCapabilityTTL) {
				t.Error("provided an applied reach rung")
			}
			// The half that must NOT fail safe, or an appliance nobody can
			// probe would carry no enforcement claim at all: nothing here is
			// applied to the target, so no observation of it is needed.
			if !record.ProvidesExecution(ExecutionProxyInspected, now, DefaultCapabilityTTL) ||
				!record.ProvidesExecution(ExecutionPlatformAttested, now, DefaultCapabilityTTL) ||
				!record.ProvidesReach(ReachProxyChannelPolicy, now, DefaultCapabilityTTL) ||
				!record.ProvidesReach(ReachPlatformAttested, now, DefaultCapabilityTTL) {
				t.Error("withheld a rung that needs nothing of the target")
			}
		})
	}

	// A record exactly at its TTL is still usable; one past it is not.
	if !fresh.Fresh(fresh.ObservedAt.Add(DefaultCapabilityTTL), DefaultCapabilityTTL) {
		t.Error("a record exactly at its TTL must still be fresh")
	}
	if fresh.Fresh(fresh.ObservedAt.Add(DefaultCapabilityTTL+time.Nanosecond), DefaultCapabilityTTL) {
		t.Error("a record past its TTL must be stale")
	}
	// A nonsensical TTL is not a licence to use anything.
	if fresh.Fresh(now, 0) || fresh.Fresh(now, -time.Hour) {
		t.Error("a non-positive TTL must make every record stale")
	}
}

// TestCapabilityReportAfterDefaults: the server owns the freshness of its own
// record, on the same reasoning as the cache TTL — a proxy may re-observe
// sooner, never later.
func TestCapabilityReportAfterDefaults(t *testing.T) {
	var absent *CapabilityReportResponse
	if got := absent.ReportAfter(); got != DefaultCapabilityTTL {
		t.Errorf("nil ReportAfter = %v, want %v", got, DefaultCapabilityTTL)
	}
	if got := (&CapabilityReportResponse{}).ReportAfter(); got != DefaultCapabilityTTL {
		t.Errorf("zero ReportAfter = %v, want %v", got, DefaultCapabilityTTL)
	}
	if got := (&CapabilityReportResponse{ReportAfterSeconds: 900}).ReportAfter(); got != 15*time.Minute {
		t.Errorf("ReportAfter = %v, want 15m", got)
	}
}

// TestGrantContextIsNotConsultedByAnyDecisionPath.
//
// D16 gives the proxy a structured reason for a grant and D2 says the proxy
// originates no policy, so the grant context is carried and logged and nothing
// else. The next reader's instinct will be to make policy out of it — "just a
// Matches method" — and by the time that has happened the proxy is deciding
// from a field an external system wrote.
//
// The test is therefore structural rather than behavioural, in two halves: the
// type carries no comparison or matching helper, and no package outside this
// one reads its fields.
func TestGrantContextIsNotConsultedByAnyDecisionPath(t *testing.T) {
	// Half one: the method set. Clone is the only thing a policy payload needs;
	// anything shaped like a question is what this test exists to catch.
	allowed := map[string]bool{"Clone": true}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(&GrantContext{}), reflect.TypeOf(GrantContext{}),
	} {
		for i := range typ.NumMethod() {
			name := typ.Method(i).Name
			if !allowed[name] {
				t.Errorf("%s has a method %q; the grant context is carried and logged, never consulted",
					typ, name)
			}
		}
	}
	// AdditionalContext needs its two JSON methods and nothing else.
	allowedAdditional := map[string]bool{"Clone": true, "MarshalJSON": true, "UnmarshalJSON": true}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(&AdditionalContext{}), reflect.TypeOf(AdditionalContext{}),
	} {
		for i := range typ.NumMethod() {
			name := typ.Method(i).Name
			if !allowedAdditional[name] {
				t.Errorf("%s has a method %q; additional context is opaque", typ, name)
			}
		}
	}

	// Half two: who reads it. internal/logging is the one package that may,
	// when it comes to build the record — everything else reading GrantContext
	// is a decision path by definition, because a policy payload is only ever
	// read to decide something or to record it.
	readers := packagesReferencing(t, "../..", "GrantContext")
	for pkg := range readers {
		switch pkg {
		// internal/control defines it; internal/logging is the one package that
		// may READ it, when it builds a record. cmd/mock-control is a SERVER —
		// it authors the field rather than consuming it, which is the opposite
		// direction and the only reason a PDP exists.
		case "internal/control", "internal/logging", "cmd/mock-control":
		default:
			t.Errorf("package %s references GrantContext; only internal/logging's record "+
				"construction may read it (D2, D16)", pkg)
		}
	}
}

// packagesReferencing returns the repository-relative directories of the
// non-test Go files mentioning ident. It is a coarse instrument on purpose:
// what it is guarding is a rule about which packages may touch a type at all,
// and that is answerable from the identifier alone.
func packagesReferencing(t *testing.T, root, ident string) map[string]bool {
	t.Helper()
	found := map[string]bool{}
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("resolve %s: %v", root, err)
	}
	err = filepath.WalkDir(abs, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == "deploy" || name == "docs" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			// A file this package cannot parse is not one it can vouch for.
			t.Errorf("parse %s: %v", path, err)
			return nil
		}
		ast.Inspect(file, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if ok && id.Name == ident {
				rel, _ := filepath.Rel(abs, filepath.Dir(path))
				found[filepath.ToSlash(rel)] = true
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", abs, err)
	}
	return found
}

// assertRefused checks that Validate rejects a response and says why.
func assertRefused(t *testing.T, resp *AuthorizeResponse, want string) {
	t.Helper()
	err := resp.Validate()
	if err == nil {
		t.Fatalf("the response was accepted; it must be refused as a contract violation")
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("refusal %q does not mention %q; an operator has to be able to fix it", err, want)
	}
}
