// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package routing

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mauroasilva/securecommandproxy/internal/identity"
	"github.com/mauroasilva/securecommandproxy/internal/mgmt"
)

// fakeClient answers Authorize and nothing else: the resolver is the only
// caller under test, and a fake that implemented the rest would invite tests
// that quietly exercise something else.
type fakeClient struct {
	resp *mgmt.AuthorizeResponse
	err  error
	last *mgmt.AuthorizeRequest
}

var _ mgmt.Client = (*fakeClient)(nil)

func (c *fakeClient) Authorize(_ context.Context, req *mgmt.AuthorizeRequest) (*mgmt.AuthorizeResponse, error) {
	c.last = req
	return c.resp, c.err
}

func (c *fakeClient) AuthenticateCert(context.Context, *mgmt.AuthenticateCertRequest) (*mgmt.AuthenticateResponse, error) {
	panic("not called")
}

func (c *fakeClient) AuthenticatePassword(context.Context, *mgmt.AuthenticatePasswordRequest) (*mgmt.AuthenticateResponse, error) {
	panic("not called")
}

func (c *fakeClient) PollMFA(context.Context, *mgmt.MFAPollRequest) (*mgmt.AuthenticateResponse, error) {
	panic("not called")
}

func (c *fakeClient) ReportHostKey(context.Context, *mgmt.HostKeyReportRequest) (*mgmt.HostKeyReportResponse, error) {
	panic("not called")
}

func (c *fakeClient) IngestLogBatch(context.Context, *mgmt.LogBatchRequest) (*mgmt.LogBatchResponse, error) {
	panic("not called")
}

func (c *fakeClient) IngestPriorityLog(context.Context, *mgmt.LogPriorityRequest) (*mgmt.LogPriorityResponse, error) {
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
	client := &fakeClient{resp: &mgmt.AuthorizeResponse{
		RouteType:         mgmt.RouteTypeDirect,
		Target:            "host.company.com",
		TargetPort:        2222,
		Permissions:       "readOnlyGroup",
		PermittedChannels: []string{"session"},
		FilterPolicy:      mgmt.FilterPolicy{Mode: mgmt.FilterModeBlacklist},
		DecisionID:        "decision-1",
	}}
	r, err := NewResolver(ResolverOptions{Client: client})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	route, err := r.Resolve(context.Background(), Request{
		Identity: testIdentity(),
		Target:   "host.company.com",
		Conn:     mgmt.ConnMeta{SessionID: "sess-1", BastionID: "bastion-1"},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if err := route.RequireDirect(); err != nil {
		t.Errorf("RequireDirect: %v", err)
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
	if got, want := client.last.AuthMethod, mgmt.AuthMethodCert; got != want {
		t.Errorf("request auth method = %q, want %q", got, want)
	}
}

// TestResolveDefaultsThePort covers a route that names no port: the fallback is
// the bastion's, the choice is still the server's whenever it makes one.
func TestResolveDefaultsThePort(t *testing.T) {
	client := &fakeClient{resp: &mgmt.AuthorizeResponse{
		RouteType:         mgmt.RouteTypeDirect,
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
	client := &fakeClient{err: &mgmt.APIError{Op: "Authorize", StatusCode: 401, Cause: mgmt.ErrUnauthorized}}
	r, _ := NewResolver(ResolverOptions{Client: client})

	_, err := r.Resolve(context.Background(), Request{Identity: testIdentity(), Target: "host.company.com"})
	if err == nil {
		t.Fatal("Resolve returned no error for a deny")
	}
	if !mgmt.IsUnauthorized(err) {
		t.Errorf("error %v does not classify as a deny", err)
	}
}

// TestResolveOutageIsNotADeny is the same property from the other side: an
// unreachable server must never be reported as a permissions answer.
func TestResolveOutageIsNotADeny(t *testing.T) {
	client := &fakeClient{err: &mgmt.APIError{Op: "Authorize", StatusCode: 503, Cause: mgmt.ErrServer}}
	r, _ := NewResolver(ResolverOptions{Client: client})

	_, err := r.Resolve(context.Background(), Request{Identity: testIdentity(), Target: "host.company.com"})
	if err == nil {
		t.Fatal("Resolve returned no error for a server failure")
	}
	if mgmt.IsUnauthorized(err) {
		t.Errorf("error %v classifies a server failure as a deny", err)
	}
}

// TestResolveNextHopIsReturnedIntact records the phase-0007 seam: the route is
// resolved and handed back whole, and only the caller's RequireDirect refuses
// it. Dropping it here would make chaining a rewrite rather than a plug-in.
func TestResolveNextHopIsReturnedIntact(t *testing.T) {
	client := &fakeClient{resp: &mgmt.AuthorizeResponse{
		RouteType:         mgmt.RouteTypeNextHop,
		Target:            "bastion-2.company.com",
		PermittedChannels: []string{"session"},
		Hop: &mgmt.HopMetadata{
			FinalTarget: "deep.internal.company.com",
			MaxHops:     3,
			HopTrail:    []string{"bastion-1"},
		},
	}}
	r, _ := NewResolver(ResolverOptions{Client: client})

	route, err := r.Resolve(context.Background(), Request{Identity: testIdentity(), Target: "deep.internal.company.com"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if route.IsDirect() {
		t.Error("a nexthop route reported itself as direct")
	}
	if err := route.RequireDirect(); !errors.Is(err, ErrUnsupportedRoute) {
		t.Errorf("RequireDirect() = %v, want errors.Is(..., ErrUnsupportedRoute)", err)
	}
	if route.Hop == nil || route.Hop.FinalTarget != "deep.internal.company.com" {
		t.Errorf("hop metadata = %+v, want the final target preserved", route.Hop)
	}
	if mgmt.IsUnauthorized(route.RequireDirect()) {
		t.Error("an unsupported route classifies as a deny; it is a bastion limitation")
	}
}

// TestResolveCopiesTheResponse keeps a session from editing the policy the next
// one is served: the caching client hands out decisions that outlive a session.
func TestResolveCopiesTheResponse(t *testing.T) {
	resp := &mgmt.AuthorizeResponse{
		RouteType:         mgmt.RouteTypeDirect,
		Target:            "host.company.com",
		PermittedChannels: []string{"session"},
		FilterPolicy: mgmt.FilterPolicy{
			Mode:  mgmt.FilterModeBlacklist,
			Rules: []mgmt.FilterRule{{Match: "rm -rf /", Action: mgmt.FilterActionKillSession}},
		},
	}
	client := &fakeClient{resp: resp}
	r, _ := NewResolver(ResolverOptions{Client: client})

	route, err := r.Resolve(context.Background(), Request{Identity: testIdentity(), Target: "host.company.com"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	route.PermittedChannels[0] = "everything"
	route.Filter.Rules[0].Action = mgmt.FilterActionAllowAndLog

	if resp.PermittedChannels[0] != "session" {
		t.Error("mutating the route rewrote the response's channel allow-list")
	}
	if resp.FilterPolicy.Rules[0].Action != mgmt.FilterActionKillSession {
		t.Error("mutating the route rewrote the response's filter policy")
	}
}

func TestResolveRequiresIdentityAndTarget(t *testing.T) {
	client := &fakeClient{resp: &mgmt.AuthorizeResponse{RouteType: mgmt.RouteTypeDirect, Target: "host"}}
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
