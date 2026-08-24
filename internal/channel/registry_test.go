// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package channel

import (
	"strings"
	"testing"
)

func TestRegistryOrdersSpecificChainsBeforeTheWildcard(t *testing.T) {
	reg := NewRegistry()
	reg.Register("session", &stub{name: "first"}, &stub{name: "second"})
	reg.Register(AnyChannel, &stub{name: "everywhere"})
	reg.Register("x11", &stub{name: "x11-only"})

	for _, tc := range []struct {
		channelType string
		want        string
	}{
		{"session", "first,second,everywhere"},
		{"x11", "x11-only,everywhere"},
		{"direct-tcpip", "everywhere"},
	} {
		var names []string
		for _, inspector := range reg.Inspectors(tc.channelType) {
			names = append(names, inspector.Name())
		}
		if got := strings.Join(names, ","); got != tc.want {
			t.Errorf("Inspectors(%q) = %q, want %q", tc.channelType, got, tc.want)
		}
	}
}

func TestRegistryWithNothingRegisteredReturnsNil(t *testing.T) {
	if got := NewRegistry().Inspectors("session"); got != nil {
		t.Errorf("Inspectors on an empty registry = %v, want nil", got)
	}
	// A nil registry is what a proxy with no inspectors configured passes in.
	var none *Registry
	none.Register("session", &stub{name: "ignored"})
	if got := none.Inspectors("session"); got != nil {
		t.Errorf("Inspectors on a nil registry = %v, want nil", got)
	}
}

func TestRegistryDoesNotListTheWildcardChainTwice(t *testing.T) {
	reg := NewRegistry()
	reg.Register(AnyChannel, &stub{name: "everywhere"})
	if got := len(reg.Inspectors(AnyChannel)); got != 1 {
		t.Errorf("Inspectors(AnyChannel) returned %d inspectors, want 1", got)
	}
}
