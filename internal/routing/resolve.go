// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package routing

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"

	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/identity"
)

// ErrUnsupportedRoute means Hoplock Control returned a route this proxy
// cannot serve. Today that is only "nexthop", which phase 0007 implements; it is
// an outage from the user's point of view (the proxy is incomplete, they are
// not forbidden), never a denial.
var ErrUnsupportedRoute = errors.New("routing: route type is not supported by this proxy")

// Request is everything Hoplock Control needs to decide a route for one
// connection.
type Request struct {
	// Identity is the authenticated user. Required: an unauthenticated
	// connection has nothing to authorize.
	Identity *identity.Identity
	// Target is the normalised target the user asked for, as ParseUsername
	// returned it.
	Target string
	// Conn is the connection metadata carried on every management call.
	Conn control.ConnMeta
}

// Route is Hoplock Control's answer: the per-connection policy snapshot
// (PLAN §6.4). It is the whole decision — where to connect, which channels are
// allowed, and which command filter applies — so nothing on the data path has to
// ask the server anything (D2).
//
// The proxy never widens it. Fields are copied out of the wire response so a
// session cannot mutate a cached decision that another session will be served
// (the caching client also deep-copies; this is the second half of that
// guarantee).
type Route struct {
	// Type is "direct" (Host is the end host) or "nexthop" (Host is the next
	// proxy in the chain).
	Type control.RouteType
	// Host and Port are what the proxy dials.
	Host string
	Port int
	// Permissions is the opaque permission-set name, carried into logs.
	Permissions string
	// PermittedChannels is the SSH channel allow-list (D5). Empty denies every
	// channel — that is a decision, not a default.
	PermittedChannels []string
	// Filter is the command filter policy enforced by phase 0009.
	Filter control.FilterPolicy
	// Hop carries the chaining constraints of a next-hop route (phase 0007).
	Hop *control.HopMetadata
	// DecisionID correlates this decision with the server's audit trail.
	DecisionID string
}

// Addr is the "host:port" the proxy dials for this route.
func (r *Route) Addr() string {
	return net.JoinHostPort(r.Host, strconv.Itoa(r.Port))
}

// IsDirect reports whether Host is the end host rather than the next proxy.
func (r *Route) IsDirect() bool { return r.Type == control.RouteTypeDirect }

// RequireDirect is the seam phase 0007 replaces. A proxy that can only serve
// direct routes calls it before dialling; when chaining lands, the caller
// dispatches on Type instead and hands a next-hop route to the chain dialler,
// which is why the route is returned intact rather than dropped here.
func (r *Route) RequireDirect() error {
	if r.IsDirect() {
		return nil
	}
	return fmt.Errorf("%w: %q", ErrUnsupportedRoute, r.Type)
}

// ChannelPermitted reports whether the connection may open a channel of this
// type (D5).
//
// The comparison is exact and the empty list denies everything: an allow-list
// that fell back to "allow all" when the server said nothing would turn a
// truncated or misunderstood response into a wide-open session. Phase 0008 adds
// the inspection pipeline around this; the check itself stays here because the
// route is what carries the answer.
func (r *Route) ChannelPermitted(channelType string) bool {
	for _, permitted := range r.PermittedChannels {
		if permitted == channelType {
			return true
		}
	}
	return false
}

// ResolverOptions configures a Resolver.
type ResolverOptions struct {
	// Client is the Control API client. Required.
	Client control.Client
	// DefaultTargetPort is used when the server's route names no port. Zero
	// means DefaultTargetPort.
	DefaultTargetPort int
	// Logger receives route decisions; nil discards them.
	Logger *log.Logger
}

// Resolver turns an authenticated identity plus a requested target into the
// connection's policy, by asking Hoplock Control (D2). It originates no
// policy of its own: it does not decide, cache, or second-guess, it converts.
type Resolver struct {
	client      control.Client
	defaultPort int
	logger      *log.Logger
}

// NewResolver validates opts and returns a Resolver.
func NewResolver(opts ResolverOptions) (*Resolver, error) {
	if opts.Client == nil {
		return nil, errors.New("routing: Resolver requires a management client")
	}
	r := &Resolver{
		client:      opts.Client,
		defaultPort: opts.DefaultTargetPort,
		logger:      opts.Logger,
	}
	if r.defaultPort <= 0 {
		r.defaultPort = DefaultTargetPort
	}
	return r, nil
}

// Resolve asks Hoplock Control to authorize the connection and returns
// the route it answered with.
//
// The error it returns wraps the management client's error unchanged, so
// control.IsUnauthorized still classifies a deny after the wrap. That matters:
// what the user is told depends entirely on that classification (PLAN §4.3),
// and a caller must never see an outage as a denial.
func (r *Resolver) Resolve(ctx context.Context, req Request) (*Route, error) {
	if req.Identity == nil {
		return nil, errors.New("routing: Resolve requires an authenticated identity")
	}
	if req.Target == "" {
		return nil, fmt.Errorf("%w: no target to authorize", ErrMalformedUsername)
	}

	resp, err := r.client.Authorize(ctx, &control.AuthorizeRequest{
		Identity:   req.Identity.ToWire(),
		Target:     req.Target,
		AuthMethod: req.Identity.Method.WireMethod(),
		Conn:       req.Conn,
	})
	if err != nil {
		return nil, fmt.Errorf("authorize: %w", err)
	}

	route := &Route{
		Type:              resp.RouteType,
		Host:              resp.Target,
		Port:              resp.TargetPort,
		Permissions:       resp.Permissions,
		PermittedChannels: append([]string(nil), resp.PermittedChannels...),
		Filter:            cloneFilter(resp.FilterPolicy),
		DecisionID:        resp.DecisionID,
	}
	if route.Port <= 0 {
		route.Port = r.defaultPort
	}
	if resp.Hop != nil {
		hop := *resp.Hop
		hop.HopTrail = append([]string(nil), resp.Hop.HopTrail...)
		route.Hop = &hop
	}

	r.logf("routing: session=%s subject=%s target=%s route=%s permissions=%s channels=%v decision=%s",
		req.Conn.SessionID, req.Identity.Subject, req.Target, route.Type,
		route.Permissions, route.PermittedChannels, route.DecisionID)
	return route, nil
}

func cloneFilter(p control.FilterPolicy) control.FilterPolicy {
	return control.FilterPolicy{Mode: p.Mode, Rules: append([]control.FilterRule(nil), p.Rules...)}
}

func (r *Resolver) logf(format string, args ...any) {
	if r.logger == nil {
		return
	}
	r.logger.Printf(format, args...)
}
