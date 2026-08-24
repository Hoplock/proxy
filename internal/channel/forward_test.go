// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package channel

import (
	"errors"
	"testing"

	"github.com/hoplock/proxy/internal/control"
)

func TestParseForward(t *testing.T) {
	got, err := ParseForward(control.ChannelDirectTCPIP, marshalForward("db.internal", 5432))
	if err != nil {
		t.Fatalf("ParseForward: %v", err)
	}
	want := Forward{Host: "db.internal", Port: 5432, OriginHost: "127.0.0.1", OriginPort: 51000}
	if got != want {
		t.Errorf("parsed %+v, want %+v", got, want)
	}
	if got.String() != "db.internal:5432" {
		t.Errorf("String() = %q, want %q", got.String(), "db.internal:5432")
	}
}

func TestParseForwardRejectsANonForwardingChannel(t *testing.T) {
	_, err := ParseForward("session", marshalForward("db.internal", 5432))
	if !errors.Is(err, ErrMalformedForward) {
		t.Errorf("error = %v, want ErrMalformedForward", err)
	}
}

// TestMatchHost is where the two naming worlds are kept apart: the proxy never
// resolves a name to decide policy, so a CIDR matches only IP literals and a
// wildcard matches only names.
func TestMatchHost(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		host    string
		want    bool
	}{
		{"db.internal", "db.internal", true},
		{"db.internal", "DB.Internal", true},
		{"db.internal", "db.internal.", true},
		{"db.internal", "other.internal", false},
		{"db.internal", "xdb.internal", false},

		{"*", "anything.at.all", true},
		{"*", "10.0.0.1", true},

		{"*.internal", "db.internal", true},
		{"*.internal", "a.b.internal", true},
		{"*.internal", "internal", false},
		{"*.internal", "db.external", false},
		// A wildcard is a statement about names. Letting it match an IP
		// literal would make "*.internal" a wildcard over the estate.
		{"*.internal", "10.0.0.1", false},

		{"10.0.0.0/8", "10.1.2.3", true},
		{"10.0.0.0/8", "11.1.2.3", false},
		// A CIDR never matches a name: deciding otherwise would mean
		// resolving it, and a DNS answer is not a decision the PDP made.
		{"10.0.0.0/8", "db.internal", false},
		{"2001:db8::/32", "2001:db8::1", true},
		{"2001:db8::/32", "2001:dba::1", false},

		{"10.0.0.1", "10.0.0.1", true},
		{"::1", "0:0:0:0:0:0:0:1", true},
		{"10.0.0.1", "10.0.0.2", false},

		{"", "db.internal", false},
		{"db.internal", "", false},
	} {
		if got := matchHost(tc.pattern, tc.host); got != tc.want {
			t.Errorf("matchHost(%q, %q) = %t, want %t", tc.pattern, tc.host, got, tc.want)
		}
	}
}

func TestMatchPort(t *testing.T) {
	for _, tc := range []struct {
		name string
		dest control.ForwardDestination
		port int
		want bool
	}{
		{"an exact port", control.ForwardDestination{Port: 5432}, 5432, true},
		{"another port", control.ForwardDestination{Port: 5432}, 5433, false},
		{"no constraint permits any port", control.ForwardDestination{}, 1, true},
		{"inside an inclusive range", control.ForwardDestination{
			PortRange: &control.PortRange{From: 5000, To: 6000}}, 5432, true},
		{"the bottom of the range", control.ForwardDestination{
			PortRange: &control.PortRange{From: 5000, To: 6000}}, 5000, true},
		{"the top of the range", control.ForwardDestination{
			PortRange: &control.PortRange{From: 5000, To: 6000}}, 6000, true},
		{"outside the range", control.ForwardDestination{
			PortRange: &control.PortRange{From: 5000, To: 6000}}, 4999, false},
		// Both, and an inverted range, are contract violations. Matching
		// nothing is the only reading of a malformed entry that cannot widen
		// a policy by being written wrong.
		{"both a port and a range", control.ForwardDestination{
			Port: 5432, PortRange: &control.PortRange{From: 1, To: 65535}}, 5432, false},
		{"an inverted range", control.ForwardDestination{
			PortRange: &control.PortRange{From: 6000, To: 5000}}, 5432, false},
	} {
		if got := matchPort(tc.dest, tc.port); got != tc.want {
			t.Errorf("%s: matchPort = %t, want %t", tc.name, got, tc.want)
		}
	}
}

func TestMatchForwardTakesAnyEntry(t *testing.T) {
	dests := []control.ForwardDestination{
		{Host: "db.internal", Port: 5432},
		{Host: "*.cache.internal", PortRange: &control.PortRange{From: 6379, To: 6380}},
	}
	for _, tc := range []struct {
		host string
		port int
		want bool
	}{
		{"db.internal", 5432, true},
		{"a.cache.internal", 6379, true},
		{"a.cache.internal", 6381, false},
		{"db.internal", 6379, false},
	} {
		got := MatchForward(dests, Forward{Host: tc.host, Port: tc.port})
		if got != tc.want {
			t.Errorf("MatchForward(%s:%d) = %t, want %t", tc.host, tc.port, got, tc.want)
		}
	}
	// An empty list permits nothing: present-but-empty means "permit nothing",
	// exactly as it does for the channel allow-list.
	if MatchForward(nil, Forward{Host: "db.internal", Port: 5432}) {
		t.Error("an empty destination list permitted a forward")
	}
}
