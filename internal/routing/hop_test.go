// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package routing

import (
	"errors"
	"testing"

	"github.com/hoplock/proxy/internal/control"
)

func nextHop(hop *control.HopMetadata) *Route {
	return &Route{
		Type: control.RouteTypeNextHop,
		Host: "proxy-b.example.com",
		Port: 22,
		Hop:  hop,
	}
}

func TestIsHopPeer(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{HopClientVersion, true},
		{HopClientVersion + "_1.4", true},
		{"SSH-2.0-OpenSSH_9.6", false},
		{"", false},
		// A user's client cannot become a hop by looking like one: the trail it
		// would then owe can only ever refuse its own session.
		{"SSH-2.0-Hoplock Proxy", false},
	}
	for _, tt := range tests {
		if got := IsHopPeer(tt.version); got != tt.want {
			t.Errorf("IsHopPeer(%q) = %t, want %t", tt.version, got, tt.want)
		}
	}
}

func TestChainRoundTrip(t *testing.T) {
	want := Chain{
		Trail:       HopTrail{"proxy-edge", "proxy-zone"},
		FinalTarget: "deep.internal.example.com",
		MaxHops:     3,
	}
	got, err := ParseChain(MarshalChain(want))
	if err != nil {
		t.Fatalf("ParseChain: %v", err)
	}
	if got.Trail.String() != want.Trail.String() {
		t.Errorf("trail = %v, want %v", got.Trail, want.Trail)
	}
	if got.FinalTarget != want.FinalTarget {
		t.Errorf("final target = %q, want %q", got.FinalTarget, want.FinalTarget)
	}
	if got.MaxHops != want.MaxHops {
		t.Errorf("max hops = %d, want %d", got.MaxHops, want.MaxHops)
	}
}

// TestParseChainRejectsAnEmptyTrail keeps a hop from resetting the chain state
// it is supposed to be carrying: an empty trail would silently restart loop
// detection and the hop count.
func TestParseChainRejectsAnEmptyTrail(t *testing.T) {
	if _, err := ParseChain(MarshalChain(Chain{FinalTarget: "host.example.com"})); err == nil {
		t.Error("ParseChain accepted a hop trail with no proxies in it")
	}
	if _, err := ParseChain([]byte("not an ssh payload")); err == nil {
		t.Error("ParseChain accepted a malformed payload")
	}
}

func TestPlanHopDial(t *testing.T) {
	plan, err := PlanHop("proxy-a", Chain{}, nextHop(&control.HopMetadata{
		NextProxyID: "proxy-b",
		FinalTarget: "deep.internal.example.com",
	}), 0)
	if err != nil {
		t.Fatalf("PlanHop: %v", err)
	}
	if got, want := plan.Direction, control.HopConnectionDial; got != want {
		t.Errorf("direction = %q, want %q (absent means dial)", got, want)
	}
	if got, want := plan.Addr, "proxy-b.example.com:22"; got != want {
		t.Errorf("addr = %q, want %q", got, want)
	}
	if got, want := plan.Chain.Trail.String(), "proxy-a"; got != want {
		t.Errorf("trail = %q, want %q", got, want)
	}
	if got, want := plan.Chain.MaxHops, DefaultMaxHops; got != want {
		t.Errorf("max hops = %d, want the package default %d", got, want)
	}
}

// TestPlanHopRelayNeedsAProxyID: a relay hop names the registration it travels
// over, and there is nothing to guess if it does not.
func TestPlanHopRelayNeedsAProxyID(t *testing.T) {
	plan, err := PlanHop("proxy-a", Chain{}, nextHop(&control.HopMetadata{
		Connection:  control.HopConnectionRelay,
		NextProxyID: "proxy-b",
		FinalTarget: "deep.internal.example.com",
	}), 0)
	if err != nil {
		t.Fatalf("PlanHop: %v", err)
	}
	if plan.Addr != "" {
		t.Errorf("a relay hop planned a dial address %q", plan.Addr)
	}
	if got, want := plan.NextProxyID, "proxy-b"; got != want {
		t.Errorf("next proxy = %q, want %q", got, want)
	}

	_, err = PlanHop("proxy-a", Chain{}, nextHop(&control.HopMetadata{
		Connection:  control.HopConnectionRelay,
		FinalTarget: "deep.internal.example.com",
	}), 0)
	if !errors.Is(err, ErrHopContract) {
		t.Errorf("a relay hop with no proxy id gave %v, want ErrHopContract", err)
	}
}

func TestPlanHopDetectsLoops(t *testing.T) {
	tests := []struct {
		name     string
		self     string
		incoming Chain
		hop      *control.HopMetadata
	}{
		{
			name:     "this proxy is already in the trail",
			self:     "proxy-a",
			incoming: Chain{Trail: HopTrail{"proxy-a", "proxy-b"}},
			hop:      &control.HopMetadata{NextProxyID: "proxy-c", FinalTarget: "host.example.com"},
		},
		{
			name:     "the next hop is already in the trail",
			self:     "proxy-b",
			incoming: Chain{Trail: HopTrail{"proxy-a"}},
			hop:      &control.HopMetadata{NextProxyID: "proxy-a", FinalTarget: "host.example.com"},
		},
		{
			name: "the route points back at this proxy",
			self: "proxy-a",
			hop:  &control.HopMetadata{NextProxyID: "proxy-a", FinalTarget: "host.example.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PlanHop(tt.self, tt.incoming, nextHop(tt.hop), 0)
			if !errors.Is(err, ErrHopLoop) {
				t.Errorf("PlanHop = %v, want ErrHopLoop", err)
			}
		})
	}
}

func TestPlanHopEnforcesTheStrictestCap(t *testing.T) {
	hop := &control.HopMetadata{NextProxyID: "proxy-c", FinalTarget: "host.example.com", MaxHops: 4}
	incoming := Chain{Trail: HopTrail{"proxy-a"}, MaxHops: 4}

	// Three proxies in the chain, and every cap allows four.
	plan, err := PlanHop("proxy-b", incoming, nextHop(hop), 0)
	if err != nil {
		t.Fatalf("PlanHop: %v", err)
	}
	if got, want := plan.Chain.Trail.String(), "proxy-a>proxy-b"; got != want {
		t.Errorf("trail = %q, want %q", got, want)
	}

	// The local cap is the strictest, and a proxy may always be stricter than
	// the server told it to be.
	if _, err := PlanHop("proxy-b", incoming, nextHop(hop), 2); !errors.Is(err, ErrHopLimit) {
		t.Errorf("PlanHop with a local cap of 2 = %v, want ErrHopLimit", err)
	}
	// A cap inherited from further up the chain binds this hop too.
	tight := Chain{Trail: HopTrail{"proxy-a"}, MaxHops: 2}
	if _, err := PlanHop("proxy-b", tight, nextHop(hop), 0); !errors.Is(err, ErrHopLimit) {
		t.Errorf("PlanHop with an inherited cap of 2 = %v, want ErrHopLimit", err)
	}
	// And the server's own cap on the route.
	if _, err := PlanHop("proxy-b", Chain{Trail: HopTrail{"proxy-a"}}, nextHop(
		&control.HopMetadata{NextProxyID: "proxy-c", FinalTarget: "host.example.com", MaxHops: 2},
	), 0); !errors.Is(err, ErrHopLimit) {
		t.Errorf("PlanHop with a route cap of 2 = %v, want ErrHopLimit", err)
	}
}

func TestPlanHopRejectsWhatItCannotActOn(t *testing.T) {
	tests := []struct {
		name  string
		route *Route
		want  error
	}{
		{
			name:  "a direct route is not a hop",
			route: &Route{Type: control.RouteTypeDirect, Host: "host.example.com", Port: 22},
			want:  ErrUnsupportedRoute,
		},
		{
			name:  "no hop metadata at all",
			route: nextHop(nil),
			want:  ErrHopContract,
		},
		{
			name:  "no final target to ask the next hop for",
			route: nextHop(&control.HopMetadata{NextProxyID: "proxy-b"}),
			want:  ErrHopContract,
		},
		{
			name: "an unknown connection direction",
			route: nextHop(&control.HopMetadata{
				Connection:  control.HopConnection("carrier-pigeon"),
				NextProxyID: "proxy-b",
				FinalTarget: "host.example.com",
			}),
			want: ErrHopContract,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := PlanHop("proxy-a", Chain{}, tt.route, 0); !errors.Is(err, tt.want) {
				t.Errorf("PlanHop = %v, want %v", err, tt.want)
			}
		})
	}
}
