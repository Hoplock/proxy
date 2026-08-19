// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// fullV2Response is an authorize response that sets EVERY field the phase 0006
// vocabulary added, including the nested pointers and slices. The round-trip,
// isolation, and clone tests all run against it, so a field added to the
// contract without a line in Clone has one place to be caught.
func fullV2Response() *AuthorizeResponse {
	return &AuthorizeResponse{
		RouteType:         RouteTypeNextHop,
		Target:            "proxy-2.company.com",
		TargetPort:        2222,
		Permissions:       "readOnlyGroup",
		PermittedChannels: []string{"session", ChannelDirectTCPIP},
		PermittedRequests: &RequestPolicy{
			Types:      []string{RequestPTY, RequestShell, RequestExec},
			Subsystems: []string{"sftp"},
		},
		PermittedForwards: &ForwardPolicy{
			DirectTCPIP: []ForwardDestination{
				{Host: "postgres.prod", Port: 5432},
				{Host: "*.metrics.company.com", PortRange: &PortRange{From: 9090, To: 9100}},
			},
			ForwardedTCPIP: []ForwardDestination{{Host: "10.4.0.0/16"}},
		},
		PermittedGlobalRequests: &GlobalRequestPolicy{
			Types: []string{GlobalRequestTCPIPForward, GlobalRequestCancelTCPIPForward},
		},
		TargetAuth: &TargetAuth{
			Method: TargetAuthBrokeredKey,
			Params: map[string]string{"username": "svc-net", "credential_ref": "fleet-2026"},
		},
		FilterPolicy: FilterPolicy{
			Mode:     FilterModeWhitelist,
			ExecMode: ExecModeRestricted,
			RestrictedExec: &RestrictedExecPolicy{
				Commands: []RestrictedCommand{
					// No argv at all: an exact form with no arguments. Absent
					// and empty mean the same thing, so the fixture uses the
					// form that survives a round trip unchanged.
					{Executable: "/bin/uptime", Form: CommandFormExact},
					{Executable: "show", Form: CommandFormExact, Argv: []string{"version"}},
					{
						Executable: "/usr/bin/journalctl",
						Form:       CommandFormPositional,
						Args: []ArgumentSpec{
							{Kind: ArgumentPrefix, Value: "--unit="},
							{Kind: ArgumentOneOf, Values: []string{"-n", "--lines"}, Optional: true},
							{Kind: ArgumentAny, Optional: true},
						},
					},
				},
			},
		},
		Hop: &HopMetadata{
			Connection:  HopConnectionRelay,
			NextProxyID: "proxy-2",
			FinalTarget: "deep.internal.company.com",
			MaxHops:     3,
			HopTrail:    []string{"proxy-1"},
		},
		DecisionID: "decision-1",
		Cache:      &CacheHint{Key: "authz:alice:deep", TTLSeconds: 60},
	}
}

// TestFullV2ResponseSurvivesARoundTrip is the contract's own smoke test: the
// whole vocabulary has to reach the proxy through JSON with nothing lost and
// nothing renamed, or a policy field silently stops arriving.
func TestFullV2ResponseSurvivesARoundTrip(t *testing.T) {
	want := fullV2Response()
	if err := want.Validate(); err != nil {
		t.Fatalf("the fixture itself violates the contract: %v", err)
	}

	body, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got AuthorizeResponse
	dec := json.NewDecoder(strings.NewReader(string(body)))
	// Strict, exactly as the client decodes it: a tag that does not round-trip
	// shows up here as an unknown field rather than as a silently dropped one.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !reflect.DeepEqual(&got, want) {
		t.Errorf("round trip lost or changed policy:\n got %+v\nwant %+v", &got, want)
	}
}

// TestCloneIsolatesEveryMutableField mutates every slice, map, and pointer the
// v2 vocabulary added and proves the original is untouched. A cached decision is
// handed to many sessions, so a shallow copy anywhere here lets one connection
// rewrite another's policy.
func TestCloneIsolatesEveryMutableField(t *testing.T) {
	original := fullV2Response()
	pristine := fullV2Response()

	c := original.Clone()

	c.PermittedChannels[0] = "mutated"
	c.PermittedRequests.Types[0] = "mutated"
	c.PermittedRequests.Subsystems[0] = "mutated"
	c.PermittedForwards.DirectTCPIP[0].Host = "mutated"
	c.PermittedForwards.DirectTCPIP[1].PortRange.From = 1
	c.PermittedForwards.ForwardedTCPIP[0].Host = "mutated"
	c.PermittedGlobalRequests.Types[0] = "mutated"
	c.TargetAuth.Params["username"] = "mutated"
	c.TargetAuth.Params["added"] = "mutated"
	c.FilterPolicy.RestrictedExec.Commands[1].Argv[0] = "mutated"
	c.FilterPolicy.RestrictedExec.Commands[2].Args[0].Value = "mutated"
	c.FilterPolicy.RestrictedExec.Commands[2].Args[1].Values[0] = "mutated"
	c.Hop.HopTrail[0] = "mutated"
	c.Hop.NextProxyID = "mutated"
	c.Cache.Key = "mutated"

	if !reflect.DeepEqual(original, pristine) {
		t.Errorf("mutating the clone changed the original:\n got %+v\nwant %+v", original, pristine)
	}
}

// TestCloneAlsoCoversTheFilterRuleList keeps the v1 fields honest alongside the
// new ones, since FilterPolicy.Clone now owns both tiers.
func TestCloneAlsoCoversTheFilterRuleList(t *testing.T) {
	original := &AuthorizeResponse{
		RouteType:         RouteTypeDirect,
		Target:            "host.company.com",
		PermittedChannels: []string{"session"},
		FilterPolicy: FilterPolicy{
			Mode:  FilterModeBlacklist,
			Rules: []FilterRule{{Match: "shutdown", Action: FilterActionBlockCommand}},
		},
	}
	c := original.Clone()
	c.FilterPolicy.Rules[0].Action = FilterActionAllowAndLog
	if original.FilterPolicy.Rules[0].Action != FilterActionBlockCommand {
		t.Errorf("filter rule action = %q, want the original untouched",
			original.FilterPolicy.Rules[0].Action)
	}
}

// TestAbsentPolicyIsTheV1Default is the compatibility guarantee written down:
// a response from a server that never heard of the phase 0006 vocabulary must
// still be a working decision, and no field may become "deny everything" or
// "allow everything" by accident.
func TestAbsentPolicyIsTheV1Default(t *testing.T) {
	v1 := &AuthorizeResponse{
		RouteType:         RouteTypeDirect,
		Target:            "host.company.com",
		PermittedChannels: []string{"session"},
		FilterPolicy:      FilterPolicy{Mode: FilterModeBlacklist},
	}
	if err := v1.Validate(); err != nil {
		t.Fatalf("a v1 response must stay valid: %v", err)
	}

	// Axis 2 and 3 are not policed: a v1 server never expressed them, so
	// reading its silence as a denial would break every shell it authorised.
	for _, req := range []string{RequestPTY, RequestShell, RequestExec, RequestEnv} {
		if !v1.PermittedRequests.RequestPermitted(req) {
			t.Errorf("request %q denied by an absent request policy", req)
		}
	}
	if !v1.PermittedRequests.SubsystemPermitted("sftp") {
		t.Error("subsystem denied by an absent request policy")
	}
	if !v1.PermittedGlobalRequests.Permitted(GlobalRequestTCPIPForward) {
		t.Error("global request denied by an absent global request policy")
	}
	if _, policed := v1.PermittedForwards.Destinations(ChannelDirectTCPIP); policed {
		t.Error("an absent forward policy must not police destinations")
	}

	// The axis a v1 server DID express keeps its meaning: still an allow-list.
	if v1.PermittedChannels == nil || len(v1.PermittedChannels) != 1 {
		t.Errorf("permitted channels = %v, want the v1 allow-list intact", v1.PermittedChannels)
	}

	// And the defaults that must resolve to something, resolve to v1 behaviour.
	if got := v1.FilterPolicy.Exec(); got != ExecModeFiltered {
		t.Errorf("exec mode = %q, want %q for a v1 policy", got, ExecModeFiltered)
	}
	if got := v1.Hop.Direction(); got != HopConnectionDial {
		t.Errorf("hop direction = %q, want %q for an absent hop", got, HopConnectionDial)
	}
	if v1.TargetAuth != nil {
		t.Error("target auth must stay absent so the proxy uses its local method")
	}
}

// TestPresentButEmptyPolicyDenies is the other half of the default: absence is
// "not policed", but an empty object is a decision to permit nothing, exactly
// as permitted_channels: [] denies every channel.
func TestPresentButEmptyPolicyDenies(t *testing.T) {
	empty := &RequestPolicy{}
	for _, req := range []string{RequestPTY, RequestShell, RequestExec} {
		if empty.RequestPermitted(req) {
			t.Errorf("request %q permitted by an empty request policy", req)
		}
	}
	if empty.SubsystemPermitted("sftp") {
		t.Error("sftp permitted by an empty request policy")
	}
	// Ancillary requests are outside the policy in both directions: denying a
	// terminal resize is a broken session, not an enforced one.
	if !empty.RequestPermitted("window-change") {
		t.Error("window-change must never be policed")
	}

	if (&GlobalRequestPolicy{}).Permitted(GlobalRequestTCPIPForward) {
		t.Error("tcpip-forward permitted by an empty global request policy")
	}
	if !(&GlobalRequestPolicy{}).Permitted("keepalive@openssh.com") {
		t.Error("a keepalive must never be policed")
	}

	fwd := &ForwardPolicy{}
	dests, policed := fwd.Destinations(ChannelDirectTCPIP)
	if !policed || len(dests) != 0 {
		t.Errorf("empty forward policy: dests=%v policed=%v, want policed with none", dests, policed)
	}
	if _, policed := fwd.Destinations("some-future-channel"); !policed {
		t.Error("a present forward policy must police channel types it does not name")
	}
}

// TestAuthAgentRequestSpellings pins the one request whose wire name has two
// forms: a policy naming it must not be evaded by asking for the other.
func TestAuthAgentRequestSpellings(t *testing.T) {
	p := &RequestPolicy{Types: []string{RequestAuthAgent}}
	for _, name := range []string{RequestAuthAgent, "auth-agent-req@openssh.com"} {
		if !p.RequestPermitted(name) {
			t.Errorf("%q denied though the policy names auth-agent-req", name)
		}
	}
	denied := &RequestPolicy{Types: []string{RequestShell}}
	if denied.RequestPermitted("auth-agent-req@openssh.com") {
		t.Error("agent forwarding permitted by a policy that never named it")
	}
}

// TestValidateRejectsAContractViolation covers every shape the client refuses
// rather than resolves. Each one is a place where guessing would mean the proxy
// deciding policy it was not given.
func TestValidateRejectsAContractViolation(t *testing.T) {
	tests := []struct {
		name  string
		patch func(*AuthorizeResponse)
		want  string
	}{{
		name: "restricted exec beside a rule list",
		patch: func(r *AuthorizeResponse) {
			r.FilterPolicy.Rules = []FilterRule{{Match: "rm", Action: FilterActionBlockCommand}}
		},
		want: "alternatives, not layers",
	}, {
		name:  "restricted exec without a policy",
		patch: func(r *AuthorizeResponse) { r.FilterPolicy.RestrictedExec = nil },
		want:  "restricted_exec is absent",
	}, {
		name:  "restricted exec policy under the filtered tier",
		patch: func(r *AuthorizeResponse) { r.FilterPolicy.ExecMode = ExecModeFiltered },
		want:  "alternatives, not layers",
	}, {
		name:  "unknown exec mode",
		patch: func(r *AuthorizeResponse) { r.FilterPolicy.ExecMode = "advisory" },
		want:  "exec_mode",
	}, {
		name: "unknown command form",
		patch: func(r *AuthorizeResponse) {
			r.FilterPolicy.RestrictedExec.Commands[0].Form = "regex"
		},
		want: "unknown form",
	}, {
		name: "exact form carrying positional args",
		patch: func(r *AuthorizeResponse) {
			r.FilterPolicy.RestrictedExec.Commands[0].Args = []ArgumentSpec{{Kind: ArgumentAny}}
		},
		want: "form exact but sets args",
	}, {
		name: "positional form carrying an exact argv",
		patch: func(r *AuthorizeResponse) {
			r.FilterPolicy.RestrictedExec.Commands[2].Argv = []string{"x"}
		},
		want: "form positional but sets argv",
	}, {
		name: "command with no executable",
		patch: func(r *AuthorizeResponse) {
			r.FilterPolicy.RestrictedExec.Commands[0].Executable = ""
		},
		want: "no executable",
	}, {
		name: "empty prefix, which is `any` in disguise",
		patch: func(r *AuthorizeResponse) {
			r.FilterPolicy.RestrictedExec.Commands[2].Args[0] = ArgumentSpec{Kind: ArgumentPrefix}
		},
		want: "non-empty value",
	}, {
		name: "oneof with no values",
		patch: func(r *AuthorizeResponse) {
			r.FilterPolicy.RestrictedExec.Commands[2].Args[1] = ArgumentSpec{Kind: ArgumentOneOf}
		},
		want: "at least one value",
	}, {
		name: "unknown argument kind",
		patch: func(r *AuthorizeResponse) {
			r.FilterPolicy.RestrictedExec.Commands[2].Args[0].Kind = "glob"
		},
		want: "unknown kind",
	}, {
		name: "required argument after an optional one",
		patch: func(r *AuthorizeResponse) {
			r.FilterPolicy.RestrictedExec.Commands[2].Args[2].Optional = false
		},
		want: "follows an optional argument",
	}, {
		name: "subsystem named as a request type",
		patch: func(r *AuthorizeResponse) {
			r.PermittedRequests.Types = append(r.PermittedRequests.Types, RequestSubsystem)
		},
		want: "permitted_requests.subsystems",
	}, {
		name: "unknown request type",
		patch: func(r *AuthorizeResponse) {
			r.PermittedRequests.Types = []string{"shell-but-cooler"}
		},
		want: "unknown request type",
	}, {
		name: "destination with no host",
		patch: func(r *AuthorizeResponse) {
			r.PermittedForwards.DirectTCPIP[0].Host = ""
		},
		want: "no host",
	}, {
		name: "destination with both a port and a range",
		patch: func(r *AuthorizeResponse) {
			r.PermittedForwards.DirectTCPIP[0].PortRange = &PortRange{From: 1, To: 2}
		},
		want: "both port and port_range",
	}, {
		name: "inverted port range",
		patch: func(r *AuthorizeResponse) {
			r.PermittedForwards.DirectTCPIP[1].PortRange = &PortRange{From: 9100, To: 9090}
		},
		want: "inverted",
	}, {
		name:  "port out of range",
		patch: func(r *AuthorizeResponse) { r.PermittedForwards.DirectTCPIP[0].Port = 70000 },
		want:  "out of range",
	}, {
		name:  "unknown target auth method",
		patch: func(r *AuthorizeResponse) { r.TargetAuth.Method = "magic" },
		want:  "target_auth.method",
	}, {
		name:  "relay hop with no proxy to relay through",
		patch: func(r *AuthorizeResponse) { r.Hop.NextProxyID = "" },
		want:  "next_proxy_id",
	}, {
		name:  "unknown hop connection",
		patch: func(r *AuthorizeResponse) { r.Hop.Connection = "teleport" },
		want:  "hop.connection",
	}, {
		name: "hop connection on a direct route",
		patch: func(r *AuthorizeResponse) {
			r.RouteType = RouteTypeDirect
			r.Target = "host.company.com"
		},
		want: "direct",
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := fullV2Response()
			tc.patch(resp)
			err := resp.Validate()
			if err == nil {
				t.Fatal("Validate accepted a contract violation")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestAuthorizeRejectsBothExecTiers is the acceptance criterion in its
// end-to-end form: a server answering with a guardrail and a boundary at once
// fails the session closed, as a protocol error, rather than the proxy picking
// one.
func TestAuthorizeRejectsBothExecTiers(t *testing.T) {
	resp := fullV2Response()
	resp.FilterPolicy.Rules = []FilterRule{{Match: "rm -rf /", Action: FilterActionKillSession}}

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		respondJSON(t, w, http.StatusOK, resp)
	})
	_, err := c.Authorize(context.Background(), &AuthorizeRequest{
		Identity: &Identity{Subject: "alice@example.com"}, Target: "host", Conn: testConn(),
	})
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("error = %v, want one wrapping ErrProtocol", err)
	}
	if errors.Is(err, ErrUnauthorized) {
		t.Fatal("a contract violation must never read as a deny (PLAN §4.3)")
	}
}

// TestAuthorizeFailsClosedOnAnUnknownField is the versioning rule enforced:
// the proxy refuses policy it cannot read rather than dropping the part it does
// not recognise, because an unknown field may be a restriction.
func TestAuthorizeFailsClosedOnAnUnknownField(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"route_type": "direct",
			"target": "host.company.com",
			"permitted_channels": ["session"],
			"filter_policy": {"mode": "blacklist"},
			"permitted_sorcery": {"types": ["levitation"]}
		}`))
	})
	_, err := c.Authorize(context.Background(), &AuthorizeRequest{
		Identity: &Identity{Subject: "alice@example.com"}, Target: "host", Conn: testConn(),
	})
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("error = %v, want one wrapping ErrProtocol", err)
	}
}

// TestAuthorizeDeclaresItsPolicyVersion proves the other half of that rule: the
// strict decode is only safe because the server is told which vocabulary the
// proxy can read.
func TestAuthorizeDeclaresItsPolicyVersion(t *testing.T) {
	var got AuthorizeRequest
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode request: %v", err)
		}
		respondJSON(t, w, http.StatusOK, &AuthorizeResponse{
			RouteType:         RouteTypeDirect,
			Target:            "host.company.com",
			PermittedChannels: []string{"session"},
			FilterPolicy:      FilterPolicy{Mode: FilterModeBlacklist},
		})
	})
	if _, err := c.Authorize(context.Background(), &AuthorizeRequest{
		Identity: &Identity{Subject: "alice@example.com"}, Target: "host", Conn: testConn(),
	}); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if got.PolicyVersion != PolicyVersion {
		t.Errorf("policy_version = %d, want %d", got.PolicyVersion, PolicyVersion)
	}
}
