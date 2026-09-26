// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// certRung is a brokered-certificate ladder entry carrying the three documented
// parameters, with overrides applied the way deviceRung applies them: an empty
// value removes the parameter.
func certRung(overrides map[string]string) TargetAuth {
	params := map[string]string{
		ParamUsername:        "netadmin",
		ParamKeyType:         "ed25519",
		ParamLifetimeSeconds: "300",
	}
	for k, v := range overrides {
		if v == "" {
			delete(params, k)
			continue
		}
		params[k] = v
	}
	return TargetAuth{Method: TargetAuthBrokeredCertificate, Params: params}
}

// TestBrokeredCertificateIsAMethodThatNamesItsAccountAndProvisionsNothing pins
// the two answers phase 0044 declares for the method rather than inheriting.
//
// requiresUsername: the account is the principal the certificate is minted
// for, so the server names it or there is no route. Provisions: the target
// already trusts the CA and already has the account, so nothing is configured
// on it and only an ATTESTED rung is reachable on such a route (PLAN §6.5).
func TestBrokeredCertificateIsAMethodThatNamesItsAccountAndProvisionsNothing(t *testing.T) {
	if !TargetAuthBrokeredCertificate.requiresUsername() {
		t.Error("brokered-certificate does not require a username; it would be defaulted to a client-typed login")
	}
	if TargetAuthBrokeredCertificate.Provisions() {
		t.Error("brokered-certificate claims to provision the target; an applied rung would be reachable on a route that renders nothing")
	}
	// The siblings keep their answers: this phase changes none of them.
	for method, provisions := range map[TargetAuthMethod]bool{
		TargetAuthEphemeralUser:    true,
		TargetAuthEphemeralAccount: true,
		TargetAuthBrokeredKey:      false,
		TargetAuthStaticKey:        false,
	} {
		if got := method.Provisions(); got != provisions {
			t.Errorf("%s.Provisions() = %v, want %v", method, got, provisions)
		}
		if !method.requiresUsername() {
			t.Errorf("%s no longer requires a username", method)
		}
	}
}

// TestBrokeredCertificateParamsAreValidated covers the contract half of the
// method: username is required, key_type and lifetime_seconds are permitted.
//
// What the contract does NOT check is as much the test as what it does: a
// parameter it does not define is the AUTHENTICATOR's to refuse at provisioning
// time (ErrUnknownParam), and a value's shape is the authenticator's to parse.
// Checking either here too would be a second copy of one rule (policy.go).
func TestBrokeredCertificateParamsAreValidated(t *testing.T) {
	validates := func(t *testing.T, entry TargetAuth) error {
		t.Helper()
		resp := ladderResponse()
		resp.TargetAuthLadder = ladderOf(entry)
		return resp.Validate()
	}

	t.Run("all three documented params", func(t *testing.T) {
		if err := validates(t, certRung(nil)); err != nil {
			t.Fatalf("a brokered-certificate rung with username, key_type and lifetime_seconds was refused: %v", err)
		}
	})
	t.Run("username alone", func(t *testing.T) {
		entry := certRung(map[string]string{ParamKeyType: "", ParamLifetimeSeconds: ""})
		if err := validates(t, entry); err != nil {
			t.Fatalf("key_type and lifetime_seconds are optional, and a rung without them was refused: %v", err)
		}
	})
	t.Run("no username", func(t *testing.T) {
		err := validates(t, certRung(map[string]string{ParamUsername: ""}))
		if err == nil {
			t.Fatal("a brokered-certificate rung with no username was accepted")
		}
		for _, want := range []string{"target_auth_ladder[0]", ParamUsername, string(TargetAuthBrokeredCertificate)} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("Validate() = %q, want it to name %q", err, want)
			}
		}
	})
	t.Run("an undocumented param is the authenticator's to refuse, not the contract's", func(t *testing.T) {
		// A certificate smuggled into the route is exactly the shape this
		// phase refused; it is refused, but by internal/auth/target, which
		// owns unknown parameters.
		entry := certRung(map[string]string{"certificate": "ssh-ed25519-cert-v01@openssh.com AAAA"})
		if err := validates(t, entry); err != nil {
			t.Fatalf("the contract refused an unknown parameter itself (%v); that check lives in internal/auth/target", err)
		}
	})
}

// TestAnAppliedRungIsUnreachableOnABrokeredCertificateRoute: the method
// provisions nothing, so an applied rung on a ladder of only this method is the
// same contract violation as on brokered-key — and an attested one is fine.
func TestAnAppliedRungIsUnreachableOnABrokeredCertificateRoute(t *testing.T) {
	resp := enforcedResponse()
	resp.TargetAuthLadder = ladderOf(certRung(nil))
	assertRefused(t, resp, "no credential method on this route provisions the target")

	attested := attestedResponse()
	attested.TargetAuthLadder = ladderOf(certRung(nil))
	if err := attested.Validate(); err != nil {
		t.Fatalf("an attested rung on a brokered-certificate route must be accepted: %v", err)
	}
}

// TestACachingClientCannotIssueCertificates is lease_test.go's trap, asserted
// for the second per-session artifact that must never be answered from memory:
// a cached issuance is a certificate over ANOTHER session's key, replayed.
// The guarantee is structural, so the test is a type assertion.
func TestACachingClientCannotIssueCertificates(t *testing.T) {
	var c any = NewCachingClient(nil, CacheOptions{})
	if _, ok := c.(CertificateIssuer); ok {
		t.Fatal("CachingClient implements CertificateIssuer; an issuance answered from a cache is a " +
			"certificate replayed into a session whose key it does not certify")
	}
	var rest any = &RESTClient{}
	if _, ok := rest.(CertificateIssuer); !ok {
		t.Fatal("RESTClient does not implement CertificateIssuer; nothing could issue a certificate")
	}
}

// TestIssueCertificateSendsTheContractRequest drives the call through the real
// client: the path, the body a server receives, and the answer decoded.
func TestIssueCertificateSendsTheContractRequest(t *testing.T) {
	validBefore := time.Date(2026, 9, 22, 11, 4, 0, 0, time.UTC)
	var got map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PathIssueCertificate || r.Method != http.MethodPost {
			t.Errorf("request = %s %s, want POST %s", r.Method, r.URL.Path, PathIssueCertificate)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode request: %v", err)
		}
		respondJSON(t, w, http.StatusOK, map[string]any{
			"certificate":    "ssh-ed25519-cert-v01@openssh.com AAAA",
			"serial":         "18446744073709551615",
			"valid_before":   validBefore.Format(time.RFC3339),
			"ca_public_keys": []string{"ssh-ed25519 AAAA ca"},
		})
	})

	resp, err := c.IssueCertificate(context.Background(), &CertificateRequest{
		SessionID:  "session-1",
		DecisionID: "decision-7",
		Target:     "host.company.com",
		Username:   "netadmin",
		PublicKey:  "ssh-ed25519 AAAA hoplock-session",
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	for field, want := range map[string]string{
		"session_id":  "session-1",
		"decision_id": "decision-7",
		"target":      "host.company.com",
		"username":    "netadmin",
		"public_key":  "ssh-ed25519 AAAA hoplock-session",
	} {
		if got[field] != want {
			t.Errorf("request %s = %v, want %q", field, got[field], want)
		}
	}
	// The largest serial an SSH certificate can carry survives the trip —
	// which is exactly what a JSON number would not have done.
	serial, err := resp.SerialNumber()
	if err != nil || serial != 18446744073709551615 {
		t.Errorf("SerialNumber() = %d, %v; want the maximum uint64", serial, err)
	}
	if !resp.ValidBefore.Equal(validBefore) {
		t.Errorf("ValidBefore = %v, want %v", resp.ValidBefore, validBefore)
	}
	if len(resp.CAPublicKeys) != 1 {
		t.Errorf("CAPublicKeys = %v, want the one key the server sent", resp.CAPublicKeys)
	}
}

// TestIssueCertificateOmitsAnAbsentDecisionID: decision_id is optional on the
// authorize response, so the proxy cannot always send one, and an empty string
// on the wire would be a correlation value that correlates nothing.
func TestIssueCertificateOmitsAnAbsentDecisionID(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "decision_id") {
			t.Errorf("request = %s, want no decision_id when the decision carried none", body)
		}
		respondJSON(t, w, http.StatusOK, map[string]any{
			"certificate": "c", "serial": "1", "valid_before": "2026-09-22T11:04:00Z",
		})
	})
	if _, err := c.IssueCertificate(context.Background(), &CertificateRequest{
		SessionID: "session-1", PublicKey: "ssh-ed25519 AAAA",
	}); err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
}

// TestIssueCertificateRequiresASessionAndAKey refuses locally, before any call:
// an issuance for no session is one no record could ever be joined to.
func TestIssueCertificateRequiresASessionAndAKey(t *testing.T) {
	called := false
	c := newTestClient(t, func(http.ResponseWriter, *http.Request) { called = true })
	for name, req := range map[string]*CertificateRequest{
		"nil":           nil,
		"no session id": {PublicKey: "ssh-ed25519 AAAA"},
		"no public key": {SessionID: "session-1"},
	} {
		if _, err := c.IssueCertificate(context.Background(), req); !errors.Is(err, ErrBadRequest) {
			t.Errorf("%s: error = %v, want ErrBadRequest", name, err)
		}
	}
	if called {
		t.Error("an invalid request reached the server")
	}
}

// TestIssueCertificateRefusesAnAnswerThatIsNotACertificate: the shape checks
// this package can make without x/crypto/ssh. Every one is a protocol error,
// and so an outage, never a deny.
func TestIssueCertificateRefusesAnAnswerThatIsNotACertificate(t *testing.T) {
	for name, body := range map[string]string{
		"no certificate":         `{"serial":"1","valid_before":"2026-09-22T11:04:00Z"}`,
		"no serial":              `{"certificate":"c","valid_before":"2026-09-22T11:04:00Z"}`,
		"a serial as a number":   `{"certificate":"c","serial":10427,"valid_before":"2026-09-22T11:04:00Z"}`,
		"a non-canonical serial": `{"certificate":"c","serial":"010427","valid_before":"2026-09-22T11:04:00Z"}`,
		"no valid_before":        `{"certificate":"c","serial":"1"}`,
	} {
		t.Run(name, func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, body)
			})
			_, err := c.IssueCertificate(context.Background(), &CertificateRequest{
				SessionID: "session-1", PublicKey: "ssh-ed25519 AAAA",
			})
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("error = %v, want ErrProtocol", err)
			}
			if IsUnauthorized(err) {
				t.Fatalf("error = %v reads as a deny", err)
			}
		})
	}
}

// TestIssueCertificateKeepsTheClientErrorClasses: at this layer a refusal is
// classified exactly as Client classifies it. It is the AUTHENTICATOR that
// treats every one of them as an outage (PLAN §5.4) — so the classes must
// arrive intact for the operator's log, and the conversion is tested there.
func TestIssueCertificateKeepsTheClientErrorClasses(t *testing.T) {
	for status, want := range map[int]error{
		http.StatusUnauthorized:        ErrUnauthorized,
		http.StatusBadRequest:          ErrBadRequest,
		http.StatusInternalServerError: ErrServer,
		http.StatusServiceUnavailable:  ErrServer,
	} {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"error":{"code":"no_authority","message":"no CA for this tenant"}}`)
		})
		_, err := c.IssueCertificate(context.Background(), &CertificateRequest{
			SessionID: "session-1", PublicKey: "ssh-ed25519 AAAA",
		})
		if !errors.Is(err, want) {
			t.Errorf("status %d: error = %v, want %v", status, err, want)
		}
	}
}

// TestCertificateSerialIsACanonicalDecimalUint64 pins the join key's spelling.
// Two spellings of one number would be two keys, and a number past 2^64 is not
// a serial an SSH certificate can carry.
func TestCertificateSerialIsACanonicalDecimalUint64(t *testing.T) {
	for serial, want := range map[string]uint64{
		"0":                    0,
		"10427":                10427,
		"9007199254740993":     9007199254740993, // 2^53+1: the first a float64 loses
		"18446744073709551615": 18446744073709551615,
	} {
		got, err := (&CertificateResponse{Serial: serial}).SerialNumber()
		if err != nil || got != want {
			t.Errorf("SerialNumber(%q) = %d, %v; want %d", serial, got, err, want)
		}
	}
	for _, serial := range []string{"", "010", "+1", "-1", "1e3", "0x10", "1_000", " 1", "18446744073709551616"} {
		if _, err := (&CertificateResponse{Serial: serial}).SerialNumber(); err == nil {
			t.Errorf("SerialNumber(%q) was accepted", serial)
		}
	}
	if _, err := (*CertificateResponse)(nil).SerialNumber(); err == nil {
		t.Error("a nil response yielded a serial")
	}
}

// TestCloneIsolatesABrokeredCertificateRung extends the ladder's mutation test
// to the new method. Phase 0044 adds no field to AuthorizeResponse — the method
// is an enum value, and its policy rides the params map clone.go already
// copies — so what there is to prove is that a cached decision naming it still
// hands every session its own copy of the route's bound.
func TestCloneIsolatesABrokeredCertificateRung(t *testing.T) {
	original := ladderResponse()
	original.TargetAuthLadder = ladderOf(certRung(nil))
	c := original.Clone()
	(*c.TargetAuthLadder)[0].Params[ParamLifetimeSeconds] = "86400"
	(*c.TargetAuthLadder)[0].Params["certificate"] = "mutated"
	if got := (*original.TargetAuthLadder)[0].Params; got[ParamLifetimeSeconds] != "300" || got["certificate"] != "" {
		t.Errorf("mutating a clone rewrote the cached rung: %v", got)
	}
}

// TestTheCertificateMethodMovedTheVocabularyAndTheEndpointDidNot is phase
// 0044's version decision, asserted in both halves because it is easy to get
// backwards.
//
// The METHOD moved policy_version: it is an enum value inside the strictly
// decoded authorize response, and an unknown method refuses the whole response
// (it is not a rung to skip) — so a proxy that does not know it must never be
// sent it, and only the number can tell a server so. The ENDPOINT did not: the
// number governs /v1/authorize and nothing else.
func TestTheCertificateMethodMovedTheVocabularyAndTheEndpointDidNot(t *testing.T) {
	if PolicyVersion != 5 {
		t.Errorf("PolicyVersion = %d, want 5: brokered-certificate is vocabulary, and it is the revision that made it 5", PolicyVersion)
	}
	// A proxy one vocabulary behind refuses the method outright, which is the
	// failure the bump prevents a server from causing.
	resp := ladderResponse()
	resp.TargetAuthLadder = ladderOf(TargetAuth{Method: "brokered-certificate-v2", Params: map[string]string{ParamUsername: "x"}})
	if err := resp.Validate(); err == nil || !strings.Contains(err.Error(), "not a method this proxy knows") {
		t.Errorf("an unknown method was not refused as unreadable vocabulary: %v", err)
	}
	// And the endpoint's payloads are nowhere on the strictly decoded response.
	encoded, err := json.Marshal(&AuthorizeResponse{})
	if err != nil {
		t.Fatalf("marshal AuthorizeResponse: %v", err)
	}
	for _, field := range []string{"certificate", "serial", "valid_before", "ca_public_keys", "certificate_serial"} {
		if strings.Contains(string(encoded), `"`+field+`"`) {
			t.Errorf("AuthorizeResponse carries %q; a per-session artifact on a cacheable decision is a replayed credential", field)
		}
	}
}
