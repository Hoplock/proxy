// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package routing

import (
	"context"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/identity"
)

// fakeClient answers Authorize and nothing else: the resolver is the only
// caller under test, and a fake that implemented the rest would invite tests
// that quietly exercise something else.
type fakeClient struct {
	resp *control.AuthorizeResponse
	err  error
	last *control.AuthorizeRequest
}

var _ control.Client = (*fakeClient)(nil)

func (c *fakeClient) Authorize(_ context.Context, req *control.AuthorizeRequest) (*control.AuthorizeResponse, error) {
	c.last = req
	return c.resp, c.err
}

func (c *fakeClient) AuthenticateCert(context.Context, *control.AuthenticateCertRequest) (*control.AuthenticateResponse, error) {
	panic("not called")
}

func (c *fakeClient) AuthenticatePassword(context.Context, *control.AuthenticatePasswordRequest) (*control.AuthenticateResponse, error) {
	panic("not called")
}

func (c *fakeClient) PollMFA(context.Context, *control.MFAPollRequest) (*control.AuthenticateResponse, error) {
	panic("not called")
}

func (c *fakeClient) ReportHostKey(context.Context, *control.HostKeyReportRequest) (*control.HostKeyReportResponse, error) {
	panic("not called")
}

func (c *fakeClient) IngestLogBatch(context.Context, *control.LogBatchRequest) (*control.LogBatchResponse, error) {
	panic("not called")
}

func (c *fakeClient) IngestPriorityLog(context.Context, *control.LogPriorityRequest) (*control.LogPriorityResponse, error) {
	panic("not called")
}

func testIdentity() *identity.Identity {
	return &identity.Identity{
		Subject:         "alice@example.com",
		Login:           "alice",
		Source:          "fixture",
		Groups:          []string{"engineering"},
		Method:          identity.MethodCert,
		AuthenticatedAt: time.Unix(0, 0).UTC(),
	}
}

func TestResolveDirect(t *testing.T) {
	client := &fakeClient{resp: &control.AuthorizeResponse{
		RouteType:         control.RouteTypeDirect,
		Target:            "host.company.com",
		TargetPort:        2222,
		Permissions:       "readOnlyGroup",
		PermittedChannels: []string{"session"},
		FilterPolicy:      control.FilterPolicy{Mode: control.FilterModeBlacklist},
		DecisionID:        "decision-1",
	}}
	r, err := NewResolver(ResolverOptions{Client: client})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	route, err := r.Resolve(context.Background(), Request{
		Identity: testIdentity(),
		Target:   "host.company.com",
		Conn:     control.ConnMeta{SessionID: "sess-1", ProxyID: "proxy-1"},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !route.IsDirect() {
		t.Errorf("route type = %q, want direct", route.Type)
	}
	if got, want := route.Addr(), "host.company.com:2222"; got != want {
		t.Errorf("Addr() = %q, want %q", got, want)
	}
	if !route.ChannelPermitted("session") {
		t.Error("session channel is not permitted, but the route permits it")
	}
	if route.ChannelPermitted("direct-tcpip") {
		t.Error("direct-tcpip is permitted, but the route does not list it")
	}

	// The identity travels as claims, and the method the connection was proven
	// with is on the request — both are what policy keys on.
	if got, want := client.last.Identity.Subject, "alice@example.com"; got != want {
		t.Errorf("request subject = %q, want %q", got, want)
	}
	if got, want := client.last.AuthMethod, control.AuthMethodCert; got != want {
		t.Errorf("request auth method = %q, want %q", got, want)
	}
}

// TestResolveDefaultsThePort covers a route that names no port: the fallback is
// the proxy's, the choice is still the server's whenever it makes one.
func TestResolveDefaultsThePort(t *testing.T) {
	client := &fakeClient{resp: &control.AuthorizeResponse{
		RouteType:         control.RouteTypeDirect,
		Target:            "host.company.com",
		PermittedChannels: []string{"session"},
	}}
	r, _ := NewResolver(ResolverOptions{Client: client})

	route, err := r.Resolve(context.Background(), Request{Identity: testIdentity(), Target: "host.company.com"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got, want := route.Port, DefaultTargetPort; got != want {
		t.Errorf("Port = %d, want %d", got, want)
	}
}

// TestResolveDenyStaysADeny is the property everything user-facing rests on: a
// 401 must still classify as a deny after the resolver has wrapped it, or the
// user is told the wrong thing (PLAN §4.3).
func TestResolveDenyStaysADeny(t *testing.T) {
	client := &fakeClient{err: &control.APIError{Op: "Authorize", StatusCode: 401, Cause: control.ErrUnauthorized}}
	r, _ := NewResolver(ResolverOptions{Client: client})

	_, err := r.Resolve(context.Background(), Request{Identity: testIdentity(), Target: "host.company.com"})
	if err == nil {
		t.Fatal("Resolve returned no error for a deny")
	}
	if !control.IsUnauthorized(err) {
		t.Errorf("error %v does not classify as a deny", err)
	}
}

// TestResolveOutageIsNotADeny is the same property from the other side: an
// unreachable server must never be reported as a permissions answer.
func TestResolveOutageIsNotADeny(t *testing.T) {
	client := &fakeClient{err: &control.APIError{Op: "Authorize", StatusCode: 503, Cause: control.ErrServer}}
	r, _ := NewResolver(ResolverOptions{Client: client})

	_, err := r.Resolve(context.Background(), Request{Identity: testIdentity(), Target: "host.company.com"})
	if err == nil {
		t.Fatal("Resolve returned no error for a server failure")
	}
	if control.IsUnauthorized(err) {
		t.Errorf("error %v classifies a server failure as a deny", err)
	}
}

// TestResolveNextHopIsReturnedIntact keeps the chaining seam honest: the route
// is resolved and handed back whole, hop metadata included, because the engine
// dispatches on the type and PlanHop needs everything the server said about the
// hop (D11).
func TestResolveNextHopIsReturnedIntact(t *testing.T) {
	client := &fakeClient{resp: &control.AuthorizeResponse{
		RouteType:         control.RouteTypeNextHop,
		Target:            "proxy-2.company.com",
		PermittedChannels: []string{"session"},
		Hop: &control.HopMetadata{
			FinalTarget: "deep.internal.company.com",
			NextProxyID: "proxy-2",
			MaxHops:     3,
		},
	}}
	r, err := NewResolver(ResolverOptions{Client: client})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	route, err := r.Resolve(context.Background(), Request{
		Identity: testIdentity(),
		Target:   "deep.internal.company.com",
		Conn:     control.ConnMeta{SessionID: "sess-1", ProxyID: "proxy-1"},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.IsDirect() {
		t.Error("a nexthop route reported itself as direct")
	}
	if !route.IsNextHop() {
		t.Error("a nexthop route did not report itself as a next hop")
	}
	if route.Hop == nil || route.Hop.FinalTarget != "deep.internal.company.com" {
		t.Errorf("hop metadata = %+v, want the final target preserved", route.Hop)
	}
	if got, want := route.FinalTarget(), "deep.internal.company.com"; got != want {
		t.Errorf("FinalTarget() = %q, want %q", got, want)
	}
	if got, want := route.MaxHops(), 3; got != want {
		t.Errorf("MaxHops() = %d, want %d", got, want)
	}
	if got, want := route.HopDirection(), control.HopConnectionDial; got != want {
		t.Errorf("HopDirection() = %q, want %q (an absent direction is a dial)", got, want)
	}
}

// TestResolveCopiesTheResponse keeps a session from editing the policy the next
// one is served: the caching client hands out decisions that outlive a session.
func TestResolveCopiesTheResponse(t *testing.T) {
	resp := &control.AuthorizeResponse{
		RouteType:         control.RouteTypeDirect,
		Target:            "host.company.com",
		PermittedChannels: []string{"session"},
		FilterPolicy: control.FilterPolicy{
			Mode:  control.FilterModeBlacklist,
			Rules: []control.FilterRule{{Match: "rm -rf /", Action: control.FilterActionKillSession}},
		},
	}
	client := &fakeClient{resp: resp}
	r, _ := NewResolver(ResolverOptions{Client: client})

	route, err := r.Resolve(context.Background(), Request{Identity: testIdentity(), Target: "host.company.com"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	route.PermittedChannels[0] = "everything"
	route.Filter.Rules[0].Action = control.FilterActionAllowAndLog

	if resp.PermittedChannels[0] != "session" {
		t.Error("mutating the route rewrote the response's channel allow-list")
	}
	if resp.FilterPolicy.Rules[0].Action != control.FilterActionKillSession {
		t.Error("mutating the route rewrote the response's filter policy")
	}
}

func TestResolveRequiresIdentityAndTarget(t *testing.T) {
	client := &fakeClient{resp: &control.AuthorizeResponse{RouteType: control.RouteTypeDirect, Target: "host"}}
	r, _ := NewResolver(ResolverOptions{Client: client})

	if _, err := r.Resolve(context.Background(), Request{Target: "host.company.com"}); err == nil {
		t.Error("Resolve accepted a request with no identity")
	}
	if _, err := r.Resolve(context.Background(), Request{Identity: testIdentity()}); err == nil {
		t.Error("Resolve accepted a request with no target")
	}
}

func TestNewResolverRequiresAClient(t *testing.T) {
	if _, err := NewResolver(ResolverOptions{}); err == nil {
		t.Error("NewResolver accepted options with no management client")
	}
}

// v2Response is an authorize response using the whole phase 0006 vocabulary
// (D5a, D6a, D11, D12). The tests below prove the route carries every part of
// it to phases 0007–0010 and shares memory with none of it.
func v2Response() *control.AuthorizeResponse {
	return &control.AuthorizeResponse{
		RouteType:         control.RouteTypeNextHop,
		Target:            "proxy-2.company.com",
		PermittedChannels: []string{"session", control.ChannelDirectTCPIP},
		PermittedRequests: &control.RequestPolicy{
			Types:      []string{control.RequestPTY, control.RequestShell, control.RequestExec},
			Subsystems: []string{"sftp"},
		},
		PermittedForwards: &control.ForwardPolicy{
			DirectTCPIP: []control.ForwardDestination{{Host: "postgres.prod", Port: 5432}},
		},
		PermittedGlobalRequests: &control.GlobalRequestPolicy{
			Types: []string{control.GlobalRequestTCPIPForward},
		},
		TargetAuth: &control.TargetAuth{
			Method: control.TargetAuthBrokeredKey,
			Params: map[string]string{"username": "svc-net"},
		},
		FilterPolicy: control.FilterPolicy{
			Mode:     control.FilterModeWhitelist,
			ExecMode: control.ExecModeRestricted,
			RestrictedExec: &control.RestrictedExecPolicy{
				Commands: []control.RestrictedCommand{
					{Executable: "show", Form: control.CommandFormExact, Argv: []string{"version"}},
				},
			},
		},
		Hop: &control.HopMetadata{
			Connection:  control.HopConnectionRelay,
			NextProxyID: "proxy-2",
			FinalTarget: "deep.internal.company.com",
			MaxHops:     3,
			HopTrail:    []string{"proxy-1"},
		},
	}
}

// TestResolveCarriesTheV2Vocabulary is the hand-off to phases 0007–0010: this
// phase enforces none of it, so the only thing that can go wrong here is the
// route dropping a field on the floor.
func TestResolveCarriesTheV2Vocabulary(t *testing.T) {
	client := &fakeClient{resp: v2Response()}
	r, _ := NewResolver(ResolverOptions{Client: client})

	route, err := r.Resolve(context.Background(), Request{
		Identity: testIdentity(), Target: "deep.internal.company.com",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// Axis 2: in-channel requests, with subsystems named individually.
	if !route.RequestPermitted(control.RequestShell) {
		t.Error("shell denied though the policy names it")
	}
	if route.RequestPermitted(control.RequestX11) {
		t.Error("x11-req permitted though the policy never named it")
	}
	if !route.SubsystemPermitted("sftp") {
		t.Error("sftp denied though the policy names it")
	}
	if route.SubsystemPermitted("netconf") {
		t.Error("an unnamed subsystem was permitted")
	}

	// Axis 2, forwarding: the destinations travel; matching them is 0009's job.
	dests, policed := route.ForwardDestinations(control.ChannelDirectTCPIP)
	if !policed || len(dests) != 1 || dests[0].Host != "postgres.prod" || dests[0].Port != 5432 {
		t.Errorf("direct-tcpip destinations = %v (policed=%v), want the server's list", dests, policed)
	}
	// The other direction has no list in a present policy, which is a deny.
	if reverse, policed := route.ForwardDestinations(control.ChannelForwardedTCPIP); !policed || len(reverse) != 0 {
		t.Errorf("forwarded-tcpip destinations = %v (policed=%v), want policed with none", reverse, policed)
	}

	// Axis 3: connection-level requests.
	if !route.GlobalRequestPermitted(control.GlobalRequestTCPIPForward) {
		t.Error("tcpip-forward denied though the policy names it")
	}
	if route.GlobalRequestPermitted(control.GlobalRequestStreamLocalForward) {
		t.Error("an unnamed global request was permitted")
	}

	// D6a: the credential method is the server's choice, carried to 0007.
	if route.TargetAuth == nil || route.TargetAuth.Method != control.TargetAuthBrokeredKey {
		t.Errorf("target auth = %+v, want the brokered-key method the server chose", route.TargetAuth)
	}
	if got := route.TargetAuth.Params["username"]; got != "svc-net" {
		t.Errorf("target auth username = %q, want the server's parameter", got)
	}

	// D12: the exec tier, carried to 0010.
	if got := route.ExecMode(); got != control.ExecModeRestricted {
		t.Errorf("exec mode = %q, want %q", got, control.ExecModeRestricted)
	}
	if route.Filter.RestrictedExec == nil || len(route.Filter.RestrictedExec.Commands) != 1 {
		t.Errorf("restricted exec = %+v, want the server's command list", route.Filter.RestrictedExec)
	}

	// D11: the hop direction, carried to 0008.
	if got := route.HopDirection(); got != control.HopConnectionRelay {
		t.Errorf("hop direction = %q, want %q", got, control.HopConnectionRelay)
	}
	if route.Hop.NextProxyID != "proxy-2" {
		t.Errorf("next proxy id = %q, want the registration to relay through", route.Hop.NextProxyID)
	}
}

// TestResolveCopiesTheWholeV2Policy extends the isolation guarantee to
// everything phase 0006 added: a cached decision is shared, so a session that
// mutated what it was handed would be rewriting another session's policy.
func TestResolveCopiesTheWholeV2Policy(t *testing.T) {
	resp := v2Response()
	client := &fakeClient{resp: resp}
	r, _ := NewResolver(ResolverOptions{Client: client})

	route, err := r.Resolve(context.Background(), Request{
		Identity: testIdentity(), Target: "deep.internal.company.com",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	route.PermittedRequests.Types[0] = "mutated"
	route.PermittedRequests.Subsystems[0] = "mutated"
	route.PermittedForwards.DirectTCPIP[0].Host = "mutated"
	route.PermittedGlobalRequests.Types[0] = "mutated"
	route.TargetAuth.Params["username"] = "mutated"
	route.Filter.RestrictedExec.Commands[0].Argv[0] = "mutated"
	route.Hop.HopTrail[0] = "mutated"

	pristine := v2Response()
	for _, tc := range []struct {
		name string
		got  any
		want any
	}{
		{"request types", resp.PermittedRequests.Types[0], pristine.PermittedRequests.Types[0]},
		{"subsystems", resp.PermittedRequests.Subsystems[0], pristine.PermittedRequests.Subsystems[0]},
		{"forward host", resp.PermittedForwards.DirectTCPIP[0].Host, pristine.PermittedForwards.DirectTCPIP[0].Host},
		{"global requests", resp.PermittedGlobalRequests.Types[0], pristine.PermittedGlobalRequests.Types[0]},
		{"target auth params", resp.TargetAuth.Params["username"], pristine.TargetAuth.Params["username"]},
		{"restricted argv", resp.FilterPolicy.RestrictedExec.Commands[0].Argv[0], pristine.FilterPolicy.RestrictedExec.Commands[0].Argv[0]},
		{"hop trail", resp.Hop.HopTrail[0], pristine.Hop.HopTrail[0]},
	} {
		if tc.got != tc.want {
			t.Errorf("mutating the route rewrote the response's %s: got %v, want %v", tc.name, tc.got, tc.want)
		}
	}
}

// TestRouteFromAV1ServerIsUnpoliced is the compatibility guarantee at the layer
// the proxy actually reads: a server that never heard of the phase 0006
// vocabulary still yields a working route, and no axis silently becomes a deny.
func TestRouteFromAV1ServerIsUnpoliced(t *testing.T) {
	client := &fakeClient{resp: &control.AuthorizeResponse{
		RouteType:         control.RouteTypeDirect,
		Target:            "host.company.com",
		PermittedChannels: []string{"session"},
		FilterPolicy:      control.FilterPolicy{Mode: control.FilterModeBlacklist},
	}}
	r, _ := NewResolver(ResolverOptions{Client: client})

	route, err := r.Resolve(context.Background(), Request{Identity: testIdentity(), Target: "host.company.com"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if !route.ChannelPermitted("session") || route.ChannelPermitted("direct-tcpip") {
		t.Error("the channel allow-list must keep meaning exactly what it meant")
	}
	for _, name := range []string{control.RequestPTY, control.RequestShell, control.RequestExec} {
		if !route.RequestPermitted(name) {
			t.Errorf("request %q denied by a v1 route: an absent axis is not a deny", name)
		}
	}
	if !route.SubsystemPermitted("sftp") {
		t.Error("sftp denied by a v1 route")
	}
	if !route.GlobalRequestPermitted(control.GlobalRequestTCPIPForward) {
		t.Error("tcpip-forward denied by a v1 route")
	}
	if _, policed := route.ForwardDestinations(control.ChannelDirectTCPIP); policed {
		t.Error("a v1 route must not police forwarding destinations")
	}
	if route.TargetAuth != nil {
		t.Error("a v1 route must leave the proxy on its locally configured method")
	}
	if got := route.ExecMode(); got != control.ExecModeFiltered {
		t.Errorf("exec mode = %q, want %q", got, control.ExecModeFiltered)
	}
	if got := route.HopDirection(); got != control.HopConnectionDial {
		t.Errorf("hop direction = %q, want %q", got, control.HopConnectionDial)
	}
}

// TestResolveCarriesTheEnforcementChoice: the rung is read through the
// accessors and never off the field, because an absent enforcement object is a
// v3 server saying "proxy-inspected" rather than a server saying nothing.
func TestResolveCarriesTheEnforcementChoice(t *testing.T) {
	client := &fakeClient{resp: &control.AuthorizeResponse{
		RouteType:         control.RouteTypeDirect,
		Target:            "db-1",
		TargetPort:        22,
		PermittedChannels: []string{"session"},
		Enforcement: &control.EnforcementPolicy{
			Execution:             control.ExecutionAccountConfined,
			Reach:                 control.ReachAccountEgressRestricted,
			PermittedDestinations: []control.ForwardDestination{{Host: "10.1.2.3", Port: 5432}},
		},
	}}
	resolver, err := NewResolver(ResolverOptions{Client: client})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	route, err := resolver.Resolve(context.Background(), Request{Identity: testIdentity(), Target: "db-1"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.EnforcedExecution() != control.ExecutionAccountConfined {
		t.Errorf("execution rung = %q, want the server's", route.EnforcedExecution())
	}
	if route.EnforcedReach() != control.ReachAccountEgressRestricted {
		t.Errorf("reach rung = %q, want the server's", route.EnforcedReach())
	}
	// Deep-copied: the decision may be a cached one shared with other sessions,
	// and a session that mutated a slice it was handed would rewrite their
	// policy (PLAN §6.4).
	route.Enforcement.PermittedDestinations[0].Host = "0.0.0.0/0"
	if client.resp.Enforcement.PermittedDestinations[0].Host != "10.1.2.3" {
		t.Error("the route shares its destination list with the authorize response")
	}
}

// TestResolveDefaultsTheEnforcementChoice: a v3 server that never heard of the
// object keeps working, and both axes read as today's behaviour.
func TestResolveDefaultsTheEnforcementChoice(t *testing.T) {
	client := &fakeClient{resp: &control.AuthorizeResponse{
		RouteType: control.RouteTypeDirect, Target: "db-1", TargetPort: 22,
	}}
	resolver, err := NewResolver(ResolverOptions{Client: client})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	route, err := resolver.Resolve(context.Background(), Request{Identity: testIdentity(), Target: "db-1"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.EnforcedExecution() != control.ExecutionProxyInspected {
		t.Errorf("execution rung = %q, want the absent-value default", route.EnforcedExecution())
	}
	if route.EnforcedReach() != control.ReachProxyChannelPolicy {
		t.Errorf("reach rung = %q, want the absent-value default", route.EnforcedReach())
	}
}

// TestResolveAdvertisesTheProxysCapabilities: the half of capability
// advertisement that needs no probe rides on every authorize request.
func TestResolveAdvertisesTheProxysCapabilities(t *testing.T) {
	client := &fakeClient{resp: &control.AuthorizeResponse{
		RouteType: control.RouteTypeDirect, Target: "db-1", TargetPort: 22,
	}}
	caps := &control.ProxyCapabilities{
		Execution: []control.ExecutionRung{control.ExecutionAccountRestricted},
		Reach:     []control.ReachRung{control.ReachAccountNetworkIsolated},
	}
	resolver, err := NewResolver(ResolverOptions{Client: client, Capabilities: caps})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if _, err := resolver.Resolve(context.Background(), Request{Identity: testIdentity(), Target: "db-1"}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	sent := client.last.Capabilities
	if sent == nil || len(sent.Execution) != 1 || sent.Execution[0] != control.ExecutionAccountRestricted {
		t.Fatalf("capabilities = %+v, want the build's declaration", sent)
	}
	// Cloned per request, so one session's request cannot rewrite another's.
	sent.Execution[0] = "account-confined"
	if caps.Execution[0] != control.ExecutionAccountRestricted {
		t.Error("the request shares the resolver's capability slice")
	}
}
