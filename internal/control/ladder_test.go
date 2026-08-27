// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// ladderOf builds a *TargetAuthLadder from entries, so a test can say "present
// and empty" without the pointer noise obscuring which state it means.
func ladderOf(entries ...TargetAuth) *TargetAuthLadder {
	l := TargetAuthLadder(entries)
	if l == nil {
		l = TargetAuthLadder{}
	}
	return &l
}

func deviceRung(overrides map[string]string) TargetAuth {
	params := map[string]string{
		ParamUsername:        "hoplock",
		ParamPlatform:        "fortios",
		ParamCredentialKind:  string(CredentialKindPublicKey),
		ParamExpiryPosture:   string(ExpiryPostureTargetEnforced),
		ParamLifetimeSeconds: "900",
	}
	for k, v := range overrides {
		if v == "" {
			delete(params, k)
			continue
		}
		params[k] = v
	}
	return TargetAuth{Method: TargetAuthEphemeralAccount, Params: params}
}

// ladderResponse is a v3 authorize response carrying a two-entry ladder: the
// strong device rung first, the weaker standing credential behind it. That
// ordering is the whole point of D14 — the PDP authors the degradation, the
// proxy never invents it.
func ladderResponse() *AuthorizeResponse {
	return &AuthorizeResponse{
		RouteType:         RouteTypeDirect,
		Target:            "edge-fw-01.company.com",
		PermittedChannels: []string{"session"},
		TargetAuthLadder: ladderOf(
			deviceRung(nil),
			TargetAuth{
				Method: TargetAuthBrokeredKey,
				Params: map[string]string{ParamUsername: "netadmin", ParamCredentialRef: "edge-fleet-2026"},
			},
		),
		AlgorithmProfile: AlgorithmProfileLegacyDevice,
		FilterPolicy:     FilterPolicy{Mode: FilterModeBlacklist},
	}
}

// TestLadderRoundTripsAndPreservesOrder is the contract's smoke test for D14.
// Order IS the policy: a ladder that arrives reordered is a different decision,
// and the one it silently becomes is always the weaker one.
func TestLadderRoundTripsAndPreservesOrder(t *testing.T) {
	want := ladderResponse()
	if err := want.Validate(); err != nil {
		t.Fatalf("the fixture itself violates the contract: %v", err)
	}

	body, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(body), `"target_auth_ladder"`) {
		t.Fatalf("marshalled response does not carry target_auth_ladder: %s", body)
	}

	var got AuthorizeResponse
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !reflect.DeepEqual(&got, want) {
		t.Fatalf("round trip lost or changed policy:\n got %+v\nwant %+v", &got, want)
	}

	rungs, named := got.Ladder()
	if !named || len(rungs) != 2 {
		t.Fatalf("Ladder() = %v, %v; want the two rungs the server named", rungs, named)
	}
	if rungs[0].Method != TargetAuthEphemeralAccount || rungs[1].Method != TargetAuthBrokeredKey {
		t.Errorf("ladder order = %q then %q, want the server's order preserved",
			rungs[0].Method, rungs[1].Method)
	}
	if got.Profile() != AlgorithmProfileLegacyDevice {
		t.Errorf("Profile() = %q, want the profile the server named", got.Profile())
	}
}

// TestV2SingleObjectReadsAsAOneEntryLadder is the compatibility half. A v2
// server sends one object and keeps working, and the shape it maps onto is
// exactly the one-entry ladder a PDP writes when it refuses degradation — which
// is D6a's original behaviour, unchanged.
func TestV2SingleObjectReadsAsAOneEntryLadder(t *testing.T) {
	resp := &AuthorizeResponse{
		RouteType:         RouteTypeDirect,
		Target:            "host.company.com",
		PermittedChannels: []string{"session"},
		TargetAuth: &TargetAuth{
			Method: TargetAuthEphemeralUser,
			Params: map[string]string{ParamUsername: "alice", ParamKeyType: "ed25519"},
		},
		FilterPolicy: FilterPolicy{Mode: FilterModeBlacklist},
	}
	if err := resp.Validate(); err != nil {
		t.Fatalf("a v2 response is refused by a v3 proxy: %v", err)
	}

	rungs, named := resp.Ladder()
	if !named {
		t.Fatal("Ladder() reports the server named nothing; it named one method")
	}
	if len(rungs) != 1 || rungs[0].Method != TargetAuthEphemeralUser {
		t.Fatalf("Ladder() = %+v, want a one-entry ladder holding the v2 object", rungs)
	}
	if rungs[0].Params[ParamUsername] != "alice" {
		t.Errorf("the entry lost its params: %+v", rungs[0].Params)
	}
}

// TestBothShapesTogetherIsRefused covers the contract violation this revision
// exists to make loudly, on phase 0010's precedent: two statements of which
// credential to use, disagreeing, have no defensible resolution, so neither is
// preferred.
func TestBothShapesTogetherIsRefused(t *testing.T) {
	resp := ladderResponse()
	resp.TargetAuth = &TargetAuth{
		Method: TargetAuthStaticKey,
		Params: map[string]string{ParamUsername: "dev"},
	}

	err := resp.Validate()
	if err == nil {
		t.Fatal("a response setting both target_auth and target_auth_ladder was accepted")
	}
	for _, want := range []string{"target_auth", "target_auth_ladder"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

// TestEmptyLadderIsADenialNotLocalConfig is the absent-versus-empty rule at the
// point where getting it wrong is worst: an empty ladder read as "absent" hands
// the session the proxy's locally configured credential, which is precisely the
// method the server declined to name.
func TestEmptyLadderIsADenialNotLocalConfig(t *testing.T) {
	denied := &AuthorizeResponse{
		RouteType:         RouteTypeDirect,
		Target:            "host.company.com",
		PermittedChannels: []string{"session"},
		TargetAuthLadder:  ladderOf(),
		FilterPolicy:      FilterPolicy{Mode: FilterModeBlacklist},
	}
	if err := denied.Validate(); err != nil {
		t.Fatalf("an empty ladder is a coherent policy, not a malformed one: %v", err)
	}
	rungs, named := denied.Ladder()
	if !named {
		t.Fatal("an empty ladder reads as 'the server named nothing'; it is a denial")
	}
	if len(rungs) != 0 {
		t.Fatalf("Ladder() = %+v, want no rungs to walk", rungs)
	}

	absent := &AuthorizeResponse{
		RouteType:         RouteTypeDirect,
		Target:            "host.company.com",
		PermittedChannels: []string{"session"},
		FilterPolicy:      FilterPolicy{Mode: FilterModeBlacklist},
	}
	if _, named := absent.Ladder(); named {
		t.Error("an absent ladder reads as named; absent means the proxy's local method")
	}

	// The wire has to carry the difference too, or the distinction dies in
	// transit: an empty ladder must not serialise as an absent one.
	body, err := json.Marshal(denied)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(body), `"target_auth_ladder":[]`) {
		t.Fatalf("an empty ladder did not survive marshalling as an empty ladder: %s", body)
	}
	var got AuthorizeResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rungs, named := got.Ladder(); !named || len(rungs) != 0 {
		t.Errorf("after a round trip the denial became %v/%v", rungs, named)
	}
}

// TestCloneIsolatesTheLadder extends the mutation test to D14's field. A cached
// decision is handed to many sessions; one that shared the ladder's backing
// array would let a session reorder — or rewrite the parameters of — another
// session's credentials.
func TestCloneIsolatesTheLadder(t *testing.T) {
	original := ladderResponse()
	pristine := ladderResponse()

	c := original.Clone()
	(*c.TargetAuthLadder)[0].Method = TargetAuthStaticKey
	(*c.TargetAuthLadder)[0].Params[ParamUsername] = "mutated"
	(*c.TargetAuthLadder)[0].Params["added"] = "mutated"
	(*c.TargetAuthLadder)[1].Params[ParamCredentialRef] = "mutated"

	if !reflect.DeepEqual(original, pristine) {
		t.Errorf("mutating the clone changed the original:\n got %+v\nwant %+v", original, pristine)
	}

	// Cloning must keep the three states apart as carefully as the wire does.
	if (*AuthorizeResponse)(nil).Clone() != nil {
		t.Error("cloning a nil response produced something")
	}
	empty := ladderOf().Clone()
	if empty == nil {
		t.Fatal("cloning an empty ladder produced an absent one, turning a denial into local config")
	}
	if len(*empty) != 0 {
		t.Errorf("cloned empty ladder has %d rungs", len(*empty))
	}
	if (*TargetAuthLadder)(nil).Clone() != nil {
		t.Error("cloning an absent ladder produced an empty one, turning local config into a denial")
	}
}

// TestLadderVocabularyIsRefusedNeverCoerced walks every value the v3 vocabulary
// closes. Each of these could be "helpfully" defaulted, and each default would
// be a policy the server did not write.
func TestLadderVocabularyIsRefusedNeverCoerced(t *testing.T) {
	tests := []struct {
		name  string
		entry TargetAuth
		want  string
	}{
		{
			name:  "unknown method",
			entry: TargetAuth{Method: "telepathy", Params: map[string]string{ParamUsername: "x"}},
			want:  "telepathy",
		},
		{
			name:  "ephemeral-user without a username",
			entry: TargetAuth{Method: TargetAuthEphemeralUser, Params: map[string]string{ParamKeyType: "ed25519"}},
			want:  ParamUsername,
		},
		{
			name:  "static-key without a username",
			entry: TargetAuth{Method: TargetAuthStaticKey},
			want:  ParamUsername,
		},
		{
			name:  "ephemeral-account without a username",
			entry: deviceRung(map[string]string{ParamUsername: ""}),
			want:  ParamUsername,
		},
		{
			name:  "ephemeral-account without a platform",
			entry: deviceRung(map[string]string{ParamPlatform: ""}),
			want:  ParamPlatform,
		},
		{
			name:  "ephemeral-account with a platform that is not a name",
			entry: deviceRung(map[string]string{ParamPlatform: "FortiOS 7.4"}),
			want:  ParamPlatform,
		},
		{
			name:  "ephemeral-account with an unknown credential kind",
			entry: deviceRung(map[string]string{ParamCredentialKind: "smartcard"}),
			want:  ParamCredentialKind,
		},
		{
			name:  "ephemeral-account with no credential kind",
			entry: deviceRung(map[string]string{ParamCredentialKind: ""}),
			want:  ParamCredentialKind,
		},
		{
			name:  "ephemeral-account with an unknown expiry posture",
			entry: deviceRung(map[string]string{ParamExpiryPosture: "eventually"}),
			want:  ParamExpiryPosture,
		},
		{
			name:  "ephemeral-account with no expiry posture",
			entry: deviceRung(map[string]string{ParamExpiryPosture: ""}),
			want:  ParamExpiryPosture,
		},
		{
			name:  "an enforcing posture with no lifetime to enforce",
			entry: deviceRung(map[string]string{ParamLifetimeSeconds: ""}),
			want:  ParamLifetimeSeconds,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Once as a single v2-shaped object...
			single := ladderResponse()
			single.TargetAuthLadder = nil
			entry := tc.entry
			single.TargetAuth = &entry
			if err := single.Validate(); err == nil {
				t.Errorf("target_auth accepted %+v", tc.entry)
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %q", err, tc.want)
			}

			// ...and once buried in a ladder behind a rung that is fine. A rung
			// the proxy cannot READ refuses the whole response; only a rung it
			// cannot SATISFY is skipped, and that is what stops a server hiding
			// a constraint in an entry nobody validates.
			ladder := ladderResponse()
			ladder.TargetAuthLadder = ladderOf(deviceRung(nil), tc.entry)
			err := ladder.Validate()
			if err == nil {
				t.Fatalf("a ladder carrying %+v was accepted", tc.entry)
			}
			if !strings.Contains(err.Error(), "target_auth_ladder[1]") {
				t.Errorf("error %q does not say which rung is wrong", err)
			}
		})
	}
}

// TestAcceptedRiskNeedsNoLifetime is the other side of the lifetime rule: the
// posture that enforces nothing is the one posture with nothing to enforce.
func TestAcceptedRiskNeedsNoLifetime(t *testing.T) {
	resp := ladderResponse()
	resp.TargetAuthLadder = ladderOf(deviceRung(map[string]string{
		ParamExpiryPosture:   string(ExpiryPostureAcceptedRisk),
		ParamLifetimeSeconds: "",
	}))
	if err := resp.Validate(); err != nil {
		t.Fatalf("accepted-risk with no lifetime was refused: %v", err)
	}
}

// TestAlgorithmProfileDefaultsToTheStrongestAndRefusesTheUnknown pins both ends
// of the profile field. Absent is the only value that is not a weakening, and
// an unknown one is refused rather than coerced in either direction.
func TestAlgorithmProfileDefaultsToTheStrongestAndRefusesTheUnknown(t *testing.T) {
	resp := ladderResponse()
	resp.AlgorithmProfile = ""
	if err := resp.Validate(); err != nil {
		t.Fatalf("an absent algorithm_profile was refused: %v", err)
	}
	if got := resp.Profile(); got != AlgorithmProfileDefault {
		t.Errorf("Profile() = %q, want %q", got, AlgorithmProfileDefault)
	}
	// Absent must stay absent on the wire, or every v3 response starts telling
	// a v2 server's audit trail about a profile nobody chose.
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(body), "algorithm_profile") {
		t.Errorf("an absent profile was serialised: %s", body)
	}

	for _, p := range []AlgorithmProfile{
		AlgorithmProfileDefault, AlgorithmProfileLegacyRSASHA1, AlgorithmProfileLegacyDevice,
	} {
		resp.AlgorithmProfile = p
		if err := resp.Validate(); err != nil {
			t.Errorf("profile %q was refused: %v", p, err)
		}
	}

	resp.AlgorithmProfile = "anything-goes"
	err = resp.Validate()
	if err == nil {
		t.Fatal("an unknown algorithm_profile was accepted")
	}
	if !strings.Contains(err.Error(), "anything-goes") {
		t.Errorf("error %q does not name the profile it refused", err)
	}
}

// TestBrokeredKeyKeepsItsV2Username records a deliberate limit of this phase.
// The username requirement is scoped to the methods where the PROXY names the
// account it creates; brokered-key logs into an account an operator already
// chose, and phase 0007's behaviour for it is unchanged.
func TestBrokeredKeyKeepsItsV2Username(t *testing.T) {
	resp := ladderResponse()
	resp.TargetAuthLadder = ladderOf(TargetAuth{
		Method: TargetAuthBrokeredKey,
		Params: map[string]string{ParamCredentialRef: "edge-fleet-2026"},
	})
	if err := resp.Validate(); err != nil {
		t.Fatalf("brokered-key without a username was refused: %v", err)
	}
}
