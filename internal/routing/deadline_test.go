// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package routing

import (
	"context"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

func TestShortenDeadlineTakesTheEarlier(t *testing.T) {
	early := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	late := early.Add(time.Hour)

	tests := []struct {
		name           string
		inherited, own *time.Time
		want           *time.Time
	}{
		{"neither", nil, nil, nil},
		{"only the chain's", &early, nil, &early},
		{"only this hop's", nil, &late, &late},
		{"this hop is stricter", &late, &early, &early},
		{"this hop would extend", &early, &late, &early},
		{"the same instant", &early, &early, &early},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShortenDeadline(tt.inherited, tt.own)
			switch {
			case tt.want == nil && got != nil:
				t.Fatalf("deadline = %v, want none", got)
			case tt.want == nil:
				return
			case got == nil:
				t.Fatalf("deadline = none, want %v", tt.want)
			case !got.Equal(*tt.want):
				t.Errorf("deadline = %v, want %v", got, tt.want)
			}
			// The result must never alias either input: a cached decision is
			// handed to more than one session (PLAN §6.4).
			if got == tt.inherited || got == tt.own {
				t.Error("ShortenDeadline returned a pointer into its input")
			}
		})
	}
}

// TestPlanHopNeverExtendsTheDeadline is the chain rule (D11, D16): a hop whose
// own authorize call answers with a LATER deadline than the session arrived
// carrying must declare the earlier one to the next hop, so the whole chain
// ends on one instant.
//
// It is invisible until a session crosses three proxies — each hop would
// happily serve the answer it was given — which is why it is asserted here
// rather than left to the topology.
func TestPlanHopNeverExtendsTheDeadline(t *testing.T) {
	inherited := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	later := inherited.Add(30 * time.Minute)

	route := nextHop(&control.HopMetadata{
		NextProxyID: "proxy-c",
		FinalTarget: "deep.internal.example.com",
	})
	route.SessionDeadline = &later

	plan, err := PlanHop("proxy-b", Chain{Trail: HopTrail{"proxy-a"}, Deadline: &inherited}, route, 0)
	if err != nil {
		t.Fatalf("PlanHop: %v", err)
	}
	if plan.Chain.Deadline == nil {
		t.Fatal("the declared chain carries no deadline; the next hop would run unbounded")
	}
	if got := *plan.Chain.Deadline; !got.Equal(inherited) {
		t.Errorf("declared deadline = %v, want the inherited %v — a hop may only shorten", got, inherited)
	}
}

// TestPlanHopShortensTheDeadline is the other direction: this hop's own answer
// is stricter than the chain's, so it is what travels on.
func TestPlanHopShortensTheDeadline(t *testing.T) {
	inherited := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	earlier := inherited.Add(-10 * time.Minute)

	route := nextHop(&control.HopMetadata{
		NextProxyID: "proxy-c",
		FinalTarget: "deep.internal.example.com",
	})
	route.SessionDeadline = &earlier

	plan, err := PlanHop("proxy-b", Chain{Trail: HopTrail{"proxy-a"}, Deadline: &inherited}, route, 0)
	if err != nil {
		t.Fatalf("PlanHop: %v", err)
	}
	if plan.Chain.Deadline == nil || !plan.Chain.Deadline.Equal(earlier) {
		t.Errorf("declared deadline = %v, want this hop's stricter %v", plan.Chain.Deadline, earlier)
	}
}

// TestPlanHopWithoutADeadlineDeclaresNone keeps absent from becoming zero: a
// chain nobody bounded stays unbounded rather than acquiring an instant in the
// year 1 (contract v4's absent-value rule).
func TestPlanHopWithoutADeadlineDeclaresNone(t *testing.T) {
	plan, err := PlanHop("proxy-b", Chain{Trail: HopTrail{"proxy-a"}}, nextHop(&control.HopMetadata{
		NextProxyID: "proxy-c",
		FinalTarget: "deep.internal.example.com",
	}), 0)
	if err != nil {
		t.Fatalf("PlanHop: %v", err)
	}
	if plan.Chain.Deadline != nil {
		t.Errorf("declared deadline = %v, want none", plan.Chain.Deadline)
	}
}

// TestChainDeadlineSurvivesTheWire covers the half of the rule that is not
// arithmetic: the resolved instant has to reach the next proxy, and it travels
// on the hop-trail request beside the trail and the hop cap.
func TestChainDeadlineSurvivesTheWire(t *testing.T) {
	// Millisecond precision is what the payload carries; the instant is
	// truncated to it deliberately, so the test states the same truncation.
	deadline := time.UnixMilli(time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC).UnixMilli()).UTC()
	want := Chain{
		Trail:       HopTrail{"proxy-edge", "proxy-zone"},
		FinalTarget: "deep.internal.example.com",
		MaxHops:     3,
		Deadline:    &deadline,
	}
	got, err := ParseChain(MarshalChain(want))
	if err != nil {
		t.Fatalf("ParseChain: %v", err)
	}
	if got.Deadline == nil {
		t.Fatal("the deadline did not survive the hop-trail payload")
	}
	if !got.Deadline.Equal(deadline) {
		t.Errorf("deadline = %v, want %v", got.Deadline, deadline)
	}

	unbounded, err := ParseChain(MarshalChain(Chain{Trail: HopTrail{"proxy-edge"}}))
	if err != nil {
		t.Fatalf("ParseChain: %v", err)
	}
	if unbounded.Deadline != nil {
		t.Errorf("deadline = %v, want none for a chain nobody bounded", unbounded.Deadline)
	}
}

// TestResolveCopiesTheSessionDeadline checks the field survives the wire→Route
// conversion, and is COPIED rather than aliased: the response may be a cached
// decision another session is also being served (PLAN §6.4).
func TestResolveCopiesTheSessionDeadline(t *testing.T) {
	deadline := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	resp := &control.AuthorizeResponse{
		RouteType:         control.RouteTypeDirect,
		Target:            "host.company.com",
		TargetPort:        22,
		PermittedChannels: []string{"session"},
		SessionDeadline:   &deadline,
	}
	client := &fakeClient{resp: resp}
	resolver, err := NewResolver(ResolverOptions{Client: client})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	route, err := resolver.Resolve(context.Background(), Request{
		Identity: testIdentity(),
		Target:   "host.company.com",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.SessionDeadline == nil {
		t.Fatal("the route carries no session deadline; the session would run unbounded")
	}
	if !route.SessionDeadline.Equal(deadline) {
		t.Errorf("session deadline = %v, want %v", route.SessionDeadline, deadline)
	}
	if route.SessionDeadline == resp.SessionDeadline {
		t.Error("the route aliases the response's deadline; a session could rewrite a cached decision")
	}

	client.resp = &control.AuthorizeResponse{
		RouteType:         control.RouteTypeDirect,
		Target:            "host.company.com",
		TargetPort:        22,
		PermittedChannels: []string{"session"},
	}
	route, err = resolver.Resolve(context.Background(), Request{
		Identity: testIdentity(),
		Target:   "host.company.com",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.SessionDeadline != nil {
		t.Errorf("session deadline = %v, want none — absent is not zero", route.SessionDeadline)
	}
}
