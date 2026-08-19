// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package identity

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

func TestMethodValid(t *testing.T) {
	for _, tt := range []struct {
		method Method
		want   bool
	}{
		{MethodCert, true},
		{MethodPasswordMFA, true},
		{Method(""), false},
		{Method("kerberos"), false},
	} {
		if got := tt.method.Valid(); got != tt.want {
			t.Errorf("Method(%q).Valid() = %v, want %v", tt.method, got, tt.want)
		}
	}
}

func TestMethodWireMethod(t *testing.T) {
	if got, want := MethodCert.WireMethod(), control.AuthMethodCert; got != want {
		t.Errorf("MethodCert.WireMethod() = %q, want %q", got, want)
	}
	if got, want := MethodPasswordMFA.WireMethod(), control.AuthMethodPasswordMFA; got != want {
		t.Errorf("MethodPasswordMFA.WireMethod() = %q, want %q", got, want)
	}
	if got := Method("kerberos").WireMethod(); got != "" {
		t.Errorf("unknown method WireMethod() = %q, want \"\"", got)
	}
}

func TestClaims(t *testing.T) {
	c := Claims{"email": "alice@example.com", "empty": ""}

	if v, ok := c.Get("email"); !ok || v != "alice@example.com" {
		t.Errorf("Get(email) = %q, %v", v, ok)
	}
	// An empty claim is present; that is not the same as absent, and policy may
	// legitimately care about the difference.
	if v, ok := c.Get("empty"); !ok || v != "" {
		t.Errorf("Get(empty) = %q, %v; want \"\", true", v, ok)
	}
	if _, ok := c.Get("absent"); ok {
		t.Error("Get(absent) reported present")
	}
	if !c.Has("empty") || c.Has("absent") {
		t.Error("Has disagrees with Get")
	}
	if got := c.Value("absent"); got != "" {
		t.Errorf("Value(absent) = %q, want \"\"", got)
	}

	clone := c.Clone()
	clone["email"] = "mallory@example.com"
	if c["email"] != "alice@example.com" {
		t.Error("Clone shares state with the original")
	}
	if Claims(nil).Clone() != nil {
		t.Error("nil Claims cloned to non-nil")
	}
}

func TestIdentityCloneIsDeep(t *testing.T) {
	id := &Identity{
		Subject:    "alice@example.com",
		Login:      "alice",
		Source:     "fixture",
		Principals: []string{"alice"},
		Groups:     []string{"engineering"},
		Claims:     Claims{"dept": "sre"},
		Method:     MethodCert,
	}

	clone := id.Clone()
	clone.Groups[0] = "admins"
	clone.Principals[0] = "root"
	clone.Claims["dept"] = "finance"

	if id.Groups[0] != "engineering" || id.Principals[0] != "alice" || id.Claims["dept"] != "sre" {
		t.Errorf("Clone shares state with the original: %+v", id)
	}
	if (*Identity)(nil).Clone() != nil {
		t.Error("nil identity cloned to non-nil")
	}
}

func TestIdentityMembership(t *testing.T) {
	id := &Identity{Groups: []string{"engineering", "sre"}, Principals: []string{"alice"}}

	if !id.HasGroup("sre") || !id.HasPrincipal("alice") {
		t.Error("membership not found for a group/principal that is present")
	}
	// Exact comparison: normalisation is the identity source's job, so that two
	// sources cannot disagree about what a group name means.
	if id.HasGroup("SRE") {
		t.Error("HasGroup matched a differently-cased group")
	}
	if id.HasGroup("admins") || id.HasPrincipal("root") {
		t.Error("membership found for something absent")
	}
	if (*Identity)(nil).HasGroup("sre") {
		t.Error("nil identity reported a group membership")
	}
}

func TestIdentityValidate(t *testing.T) {
	valid := func() *Identity {
		return &Identity{Subject: "alice@example.com", Login: "alice", Source: "fixture", Method: MethodCert}
	}

	for _, tt := range []struct {
		name    string
		id      *Identity
		wantErr bool
	}{
		{name: "valid", id: valid()},
		{name: "nil", id: nil, wantErr: true},
		{name: "no subject", id: func() *Identity { id := valid(); id.Subject = ""; return id }(), wantErr: true},
		{name: "blank subject", id: func() *Identity { id := valid(); id.Subject = "  "; return id }(), wantErr: true},
		{name: "no login", id: func() *Identity { id := valid(); id.Login = ""; return id }(), wantErr: true},
		{name: "unknown method", id: func() *Identity { id := valid(); id.Method = "kerberos"; return id }(), wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.id.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatal("Validate() = nil, want error")
				}
				if !errors.Is(err, ErrIncomplete) {
					t.Errorf("Validate() = %v, want errors.Is(..., ErrIncomplete)", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}

// TestIdentityStringOmitsClaims keeps source-controlled attributes out of every
// log line that formats an identity.
func TestIdentityStringOmitsClaims(t *testing.T) {
	id := &Identity{
		Subject: "alice@example.com",
		Login:   "alice",
		Source:  "fixture",
		Method:  MethodCert,
		Claims:  Claims{"phone": "+1-555-0100"},
	}

	got := id.String()
	if strings.Contains(got, "555-0100") || strings.Contains(got, "phone") {
		t.Errorf("String() = %q, want it to omit claims", got)
	}
	for _, want := range []string{"alice@example.com", "alice", "fixture", "cert"} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, want it to contain %q", got, want)
		}
	}
	if got := (*Identity)(nil).String(); got == "" {
		t.Error("nil identity String() = \"\", want something printable")
	}
}

func TestFromWire(t *testing.T) {
	at := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	wire := &control.Identity{
		Subject:     "alice@example.com",
		Login:       "alice",
		DisplayName: "Alice Example",
		Source:      "fixture",
		Principals:  []string{"alice"},
		Groups:      []string{"engineering", "sre"},
		Claims:      map[string]string{"dept": "platform"},
	}

	id, err := FromWire(wire, MethodPasswordMFA, at)
	if err != nil {
		t.Fatalf("FromWire returned error: %v", err)
	}
	want := &Identity{
		Subject:         "alice@example.com",
		Login:           "alice",
		DisplayName:     "Alice Example",
		Source:          "fixture",
		Principals:      []string{"alice"},
		Groups:          []string{"engineering", "sre"},
		Claims:          Claims{"dept": "platform"},
		Method:          MethodPasswordMFA,
		AuthenticatedAt: at,
	}
	if !reflect.DeepEqual(id, want) {
		t.Errorf("FromWire() = %+v, want %+v", id, want)
	}

	// The conversion must copy: a later mutation of the wire value cannot
	// change what the session was authenticated as.
	wire.Groups[0] = "admins"
	wire.Claims["dept"] = "finance"
	if id.Groups[0] != "engineering" || id.Claims["dept"] != "platform" {
		t.Errorf("FromWire aliased the wire value: %+v", id)
	}
}

func TestFromWireRejectsUnusableIdentities(t *testing.T) {
	at := time.Now()

	for _, tt := range []struct {
		name string
		wire *control.Identity
	}{
		{name: "nil", wire: nil},
		{name: "no subject", wire: &control.Identity{Login: "alice"}},
		{name: "no login", wire: &control.Identity{Subject: "alice@example.com"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			id, err := FromWire(tt.wire, MethodCert, at)
			if err == nil {
				t.Fatalf("FromWire() = %+v, want an error", id)
			}
			if !errors.Is(err, ErrIncomplete) {
				t.Errorf("FromWire() = %v, want errors.Is(..., ErrIncomplete)", err)
			}
		})
	}
}

// TestFromWireDefaultsSource keeps a cosmetic omission from failing a session:
// the source name is for humans, unlike the subject, which is not.
func TestFromWireDefaultsSource(t *testing.T) {
	id, err := FromWire(&control.Identity{Subject: "alice@example.com", Login: "alice"}, MethodCert, time.Now())
	if err != nil {
		t.Fatalf("FromWire returned error: %v", err)
	}
	if got, want := id.Source, SourceUnknown; got != want {
		t.Errorf("Source = %q, want %q", got, want)
	}
}

func TestToWireRoundTrip(t *testing.T) {
	at := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	original := &Identity{
		Subject:         "alice@example.com",
		Login:           "alice",
		DisplayName:     "Alice Example",
		Source:          "fixture",
		Principals:      []string{"alice"},
		Groups:          []string{"engineering"},
		Claims:          Claims{"dept": "platform"},
		Method:          MethodCert,
		AuthenticatedAt: at,
	}

	back, err := FromWire(original.ToWire(), original.Method, at)
	if err != nil {
		t.Fatalf("FromWire returned error: %v", err)
	}
	if !reflect.DeepEqual(back, original) {
		t.Errorf("round trip = %+v, want %+v", back, original)
	}

	if (*Identity)(nil).ToWire() != nil {
		t.Error("nil identity converted to a non-nil wire identity")
	}
}

// TestToWireDoesNotAlias guards the same immutability property in the other
// direction: handing an identity to the control client must not give that client a
// handle on the session's identity.
func TestToWireDoesNotAlias(t *testing.T) {
	id := &Identity{
		Subject: "alice@example.com",
		Login:   "alice",
		Groups:  []string{"engineering"},
		Claims:  Claims{"dept": "platform"},
		Method:  MethodCert,
	}

	w := id.ToWire()
	w.Groups[0] = "admins"
	w.Claims["dept"] = "finance"

	if id.Groups[0] != "engineering" || id.Claims["dept"] != "platform" {
		t.Errorf("ToWire aliased the identity: %+v", id)
	}
}
