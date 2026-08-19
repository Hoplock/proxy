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
// cannot serve. Today that is only "nexthop", which phase 0008 implements; it is
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
	// channel — that is a decision, not a default. It is the coarsest of the
	// three policy axes (D5a) and never the whole answer; see the two below.
	PermittedChannels []string
	// PermittedRequests is the in-channel request policy (D5a, enforced by
	// phase 0009). NIL MEANS NOT POLICED, which is what a v1 server means; a
	// non-nil policy denies anything it does not name.
	PermittedRequests *control.RequestPolicy
	// PermittedForwards is the forwarding destination policy (D5a, enforced by
	// phase 0009). Nil means destinations are not policed.
	PermittedForwards *control.ForwardPolicy
	// PermittedGlobalRequests is the connection-level request policy (D5a,
	// enforced by phase 0009). Nil means global requests are relayed unpoliced,
	// which is what internal/proxy does today.
	PermittedGlobalRequests *control.GlobalRequestPolicy
	// TargetAuth is the credential method the server chose for this route (D6a,
	// consumed by phase 0007). Nil means the proxy's locally configured method.
	TargetAuth *control.TargetAuth
	// Filter is the command filter policy enforced by phase 0010, including
	// which exec tier applies (D12).
	Filter control.FilterPolicy
	// Hop carries the chaining constraints of a next-hop route, connection
	// direction included (D11, phase 0008).
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

// RequireDirect is the seam phase 0008 replaces. A proxy that can only serve
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
// truncated or misunderstood response into a wide-open session. Phase 0009 adds
// the inspection pipeline around this; the check itself stays here because the
// route is what carries the answer.
//
// It is the first of three axes, not the whole policy (D5a): see
// RequestPermitted, SubsystemPermitted, ForwardDestinations, and
// GlobalRequestPermitted.
func (r *Route) ChannelPermitted(channelType string) bool {
	for _, permitted := range r.PermittedChannels {
		if permitted == channelType {
			return true
		}
	}
	return false
}

// RequestPermitted reports whether the connection may make this in-channel
// request (D5a). It is ChannelPermitted's sibling on the second axis: a nil
// policy is the v1 default and permits everything, a non-nil one permits only
// what it names, and ancillary requests (a terminal resize, an exit status) are
// never policy. Phase 0009 enforces it at the request, because that is where
// SSH decides what a session channel is.
//
// Subsystem requests are decided by SubsystemPermitted, by name.
func (r *Route) RequestPermitted(name string) bool {
	return r.PermittedRequests.RequestPermitted(name)
}

// SubsystemPermitted reports whether the connection may start this subsystem
// (D5a). Subsystems are named individually so sftp is deniable while shell
// stays — the whole reason the request axis exists.
func (r *Route) SubsystemPermitted(name string) bool {
	return r.PermittedRequests.SubsystemPermitted(name)
}

// GlobalRequestPermitted reports whether a connection-level request may be
// relayed (D5a axis 3). A nil policy relays everything, which is what the proxy
// does today; transport hygiene requests are relayed regardless.
func (r *Route) GlobalRequestPermitted(name string) bool {
	return r.PermittedGlobalRequests.Permitted(name)
}

// ForwardDestinations returns the destinations permitted for a forwarding
// channel type and whether that axis is policed at all (D5a). Matching a
// payload against them is phase 0009's job — the host patterns and port ranges
// are policy the route only carries.
func (r *Route) ForwardDestinations(channelType string) ([]control.ForwardDestination, bool) {
	return r.PermittedForwards.Destinations(channelType)
}

// ExecMode reports which tier decides an exec request on this connection (D12,
// enforced by phase 0010), resolving the absent-value default to
// control.ExecModeFiltered.
func (r *Route) ExecMode() control.ExecMode { return r.Filter.Exec() }

// HopDirection reports how the next proxy is reached (D11, consumed by phase
// 0008). A direct route, or a hop that says nothing, reads as
// control.HopConnectionDial.
func (r *Route) HopDirection() control.HopConnection { return r.Hop.Direction() }

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

	// Everything is deep-copied out of the response: the decision may be a
	// cached one shared with other sessions, and a session that mutated a slice
	// it was handed would be rewriting their policy. control.Clone is the single
	// implementation, so a field added to the contract cannot be copied
	// correctly here and shallowly there.
	route := &Route{
		Type:                    resp.RouteType,
		Host:                    resp.Target,
		Port:                    resp.TargetPort,
		Permissions:             resp.Permissions,
		PermittedChannels:       append([]string(nil), resp.PermittedChannels...),
		PermittedRequests:       resp.PermittedRequests.Clone(),
		PermittedForwards:       resp.PermittedForwards.Clone(),
		PermittedGlobalRequests: resp.PermittedGlobalRequests.Clone(),
		TargetAuth:              resp.TargetAuth.Clone(),
		Filter:                  resp.FilterPolicy.Clone(),
		Hop:                     resp.Hop.Clone(),
		DecisionID:              resp.DecisionID,
	}
	if route.Port <= 0 {
		route.Port = r.defaultPort
	}

	r.logf("routing: session=%s subject=%s target=%s route=%s permissions=%s channels=%v exec=%s hop=%s decision=%s",
		req.Conn.SessionID, req.Identity.Subject, req.Target, route.Type,
		route.Permissions, route.PermittedChannels, route.ExecMode(),
		route.HopDirection(), route.DecisionID)
	return route, nil
}

func (r *Resolver) logf(format string, args ...any) {
	if r.logger == nil {
		return
	}
	r.logger.Printf(format, args...)
}
