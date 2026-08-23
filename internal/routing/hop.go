// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package routing

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
)

// DefaultMaxHops caps how many proxies one session may traverse when neither
// Hoplock Control nor the local config says otherwise.
//
// It exists because a chain is built one decision at a time: no single proxy
// sees the whole path, so nothing but a cap stops a mistaken policy from
// building an arbitrarily long one. Four is generous for the topologies D11
// describes (an edge proxy, a zone proxy, an enclave proxy) and still bounds
// the setup latency a user waits through, since every hop costs its own
// authenticate + authorize + host-key round trips (PLAN §6.4).
const DefaultMaxHops = 4

// HopClientVersion is the SSH identification string a proxy presents when it
// opens a leg to another proxy, in either connection direction (D11).
//
// It is how the receiving proxy knows to expect the hop trail below before it
// authorizes: SSH offers no other pre-authentication field a peer controls, and
// waiting for a trail on every connection would stall every ordinary user who
// never sends one. It is an expectation, never a credential — see HopTrail.
const HopClientVersion = "SSH-2.0-Hoplock_Proxy_hop"

// RequestHopTrail is the connection-level request an upstream proxy sends to
// the next hop, immediately after authenticating and before it opens any
// channel, to declare the chain the session has already travelled.
//
// It is an extension name (RFC 4253 §4.6.1), so a proxy that does not implement
// it answers false rather than failing the connection.
const RequestHopTrail = "hop-trail@hoplock.io"

// Chain and hop failures. All three are refusals this proxy makes locally,
// about a route Hoplock Control gave it, so none of them is a denial: the
// user is told an outage with the session id (PLAN §4.3) and the proxy writes
// an audit line naming the trail.
var (
	// ErrHopLoop means the chain would revisit a proxy it has already been
	// through, which never terminates and never reaches anything new.
	ErrHopLoop = errors.New("routing: next-hop route revisits a proxy already in the chain")
	// ErrHopLimit means extending the chain would exceed the hop cap.
	ErrHopLimit = errors.New("routing: next-hop route exceeds the maximum hop count")
	// ErrHopContract means the hop metadata cannot be acted on: a relay hop
	// with no proxy id names no registration to open a channel over, and
	// guessing one would be inventing a route.
	ErrHopContract = errors.New("routing: next-hop route is missing hop metadata")
)

// IsHopPeer reports whether an SSH peer identified itself as a Hoplock proxy
// extending a chain, and therefore owes a RequestHopTrail before its session
// can be authorized.
func IsHopPeer(clientVersion string) bool {
	return strings.HasPrefix(clientVersion, HopClientVersion)
}

// HopTrail is the chain a session has already travelled, oldest proxy first.
//
// It is deliberately NOT a credential and carries no authority. Every entry it
// holds can only ever cause a refusal — a loop, or the hop cap — so a client
// that forged one would be restricting itself. What authorises a chain leg is
// the previous hop's key, which the next hop's authenticator relays to Hoplock
// Control like any other credential (PLAN §6.1): no proxy takes an upstream's
// word for who the user is.
type HopTrail []string

// Contains reports whether the trail already includes a proxy id.
func (t HopTrail) Contains(proxyID string) bool {
	for _, id := range t {
		if id == proxyID {
			return true
		}
	}
	return false
}

// String renders the trail for logs and audit lines.
func (t HopTrail) String() string { return strings.Join(t, ">") }

// Chain is what an upstream proxy declared about the session it is handing on.
// The zero value is a user's first hop: no proxies traversed, no inherited cap.
type Chain struct {
	// Trail is the proxies the session has already been through, oldest first.
	Trail HopTrail
	// FinalTarget is the host the chain is being built toward, as the first
	// proxy in the chain was told. It is informational here: this proxy
	// authorizes the target it was asked for, not the one it was told about.
	FinalTarget string
	// MaxHops is the cap the chain has been carrying. Zero means none was
	// declared.
	MaxHops int
}

// hopTrailPayload is the SSH wire form of RequestHopTrail. []string marshals as
// a comma-separated name-list, which is why a proxy id may not contain a comma.
type hopTrailPayload struct {
	Trail       []string
	FinalTarget string
	MaxHops     uint32
}

// MarshalChain encodes a chain as a RequestHopTrail payload.
func MarshalChain(c Chain) []byte {
	limit := c.MaxHops
	if limit < 0 {
		limit = 0
	}
	return ssh.Marshal(hopTrailPayload{
		Trail:       []string(c.Trail),
		FinalTarget: c.FinalTarget,
		MaxHops:     uint32(limit),
	})
}

// ParseChain decodes a RequestHopTrail payload.
//
// It rejects an empty trail: a peer announcing itself as a hop has been
// somewhere, and an empty trail from one would silently reset the loop
// detection and the hop count that the trail exists to carry.
func ParseChain(payload []byte) (Chain, error) {
	var p hopTrailPayload
	if err := ssh.Unmarshal(payload, &p); err != nil {
		return Chain{}, fmt.Errorf("routing: malformed %s payload: %w", RequestHopTrail, err)
	}
	trail := make(HopTrail, 0, len(p.Trail))
	for _, id := range p.Trail {
		if id == "" {
			return Chain{}, fmt.Errorf("routing: %s payload has an empty proxy id", RequestHopTrail)
		}
		trail = append(trail, id)
	}
	if len(trail) == 0 {
		return Chain{}, fmt.Errorf("routing: %s payload carries no proxy ids", RequestHopTrail)
	}
	return Chain{Trail: trail, FinalTarget: p.FinalTarget, MaxHops: int(p.MaxHops)}, nil
}

// HopPlan is everything the engine needs to extend the chain by one leg. It is
// derived from the route and the incoming chain, and every check that can
// refuse the hop has already run by the time one exists.
type HopPlan struct {
	// Direction is how the next proxy is reached (D11).
	Direction control.HopConnection
	// NextProxyID names the next proxy. Required for a relay hop, because it
	// selects the registration to open a channel over; informational on a dial
	// hop, where it is also what loop detection matches on when the server
	// supplies it.
	NextProxyID string
	// Addr is the "host:port" a dial hop connects to. Empty for a relay hop,
	// which reaches the next proxy over a connection it did not open.
	Addr string
	// FinalTarget is the host to ask the next hop for.
	FinalTarget string
	// Chain is what this proxy declares to the next hop: the incoming trail
	// with this proxy appended, and the cap that survived MaxHops resolution.
	Chain Chain
}

// PlanHop validates a next-hop route against the chain the session arrived on
// and returns the leg to open (PLAN §6.1).
//
// self is this proxy's id, incoming is what the upstream hop declared (the zero
// Chain for a user's first hop), and localMax is the proxy's own hop cap, which
// can only ever make the chain shorter than the server allowed: a proxy may
// refuse to extend a chain it was told to extend, never the reverse (D2). A
// localMax of zero means DefaultMaxHops, so a chain is always capped by
// something even when neither the config nor the server said anything.
func PlanHop(self string, incoming Chain, route *Route, localMax int) (*HopPlan, error) {
	if self == "" {
		return nil, errors.New("routing: planning a hop requires this proxy's id")
	}
	if route == nil || route.Type != control.RouteTypeNextHop {
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedRoute, routeType(route))
	}
	if localMax <= 0 {
		localMax = DefaultMaxHops
	}
	if strings.Contains(self, ",") {
		// The trail travels as an SSH name-list, so a comma in an id would
		// split it into two proxies that were never in the chain.
		return nil, fmt.Errorf("routing: proxy id %q contains a comma", self)
	}
	// Been here before: whatever the route says next, this session has already
	// passed through this proxy and is going in circles.
	if incoming.Trail.Contains(self) {
		return nil, fmt.Errorf("%w: %s is already in %s", ErrHopLoop, self, incoming.Trail)
	}

	trail := make(HopTrail, 0, len(incoming.Trail)+1)
	trail = append(trail, incoming.Trail...)
	trail = append(trail, self)

	plan := &HopPlan{
		Direction:   route.HopDirection(),
		FinalTarget: route.FinalTarget(),
		Chain:       Chain{Trail: trail, MaxHops: resolveMaxHops(incoming.MaxHops, route.MaxHops(), localMax)},
	}
	if route.Hop != nil {
		plan.NextProxyID = route.Hop.NextProxyID
	}
	if plan.FinalTarget == "" {
		return nil, fmt.Errorf("%w: the route names no final target", ErrHopContract)
	}
	plan.Chain.FinalTarget = plan.FinalTarget

	if plan.NextProxyID != "" && trail.Contains(plan.NextProxyID) {
		return nil, fmt.Errorf("%w: %s is already in %s", ErrHopLoop, plan.NextProxyID, trail)
	}
	if limit := plan.Chain.MaxHops; limit > 0 && len(trail)+1 > limit {
		return nil, fmt.Errorf("%w: %s plus %s would be %d hops, the limit is %d",
			ErrHopLimit, trail, hopLabel(plan), len(trail)+1, limit)
	}

	switch plan.Direction {
	case control.HopConnectionRelay:
		if plan.NextProxyID == "" {
			return nil, fmt.Errorf("%w: a relay hop must name next_proxy_id", ErrHopContract)
		}
	case control.HopConnectionDial:
		if route.Host == "" {
			return nil, fmt.Errorf("%w: a dial hop must name the next proxy's host", ErrHopContract)
		}
		plan.Addr = route.Addr()
	default:
		return nil, fmt.Errorf("%w: unknown connection direction %q", ErrHopContract, plan.Direction)
	}
	return plan, nil
}

// resolveMaxHops takes the strictest cap on offer. The inherited and route caps
// come from the server, the local one from this proxy's config; a zero on any
// of them means "no opinion", and the smallest opinion wins.
func resolveMaxHops(inherited, route, local int) int {
	strictest := 0
	for _, candidate := range []int{inherited, route, local} {
		if candidate > 0 && (strictest == 0 || candidate < strictest) {
			strictest = candidate
		}
	}
	return strictest
}

func hopLabel(plan *HopPlan) string {
	if plan.NextProxyID != "" {
		return plan.NextProxyID
	}
	if plan.Addr != "" {
		return plan.Addr
	}
	return "the next hop"
}

func routeType(route *Route) control.RouteType {
	if route == nil {
		return ""
	}
	return route.Type
}
