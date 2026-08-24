// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package channel

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
)

// ErrMalformedForward is a forwarding channel-open payload the proxy could not
// read. It is a denial, never a panic and never a pass: the payload is written
// by whichever side opened the channel, so "I could not parse your destination"
// can only ever mean "you do not get this channel".
var ErrMalformedForward = errors.New("channel: malformed forwarding payload")

// maxPort is the largest port number the wire can legally carry. The payload
// field is a uint32, so a value above this is malformed rather than merely
// unmatched — and clamping it instead would silently turn 65536 into a port
// that a policy might permit.
const maxPort = 65535

// Forward is a forwarding channel's destination, parsed out of its
// channel-open payload (RFC 4254 §7.2).
//
// For direct-tcpip it is the address the client asked to reach. For
// forwarded-tcpip it is the listening address the connection arrived on, which
// is the same thing seen from the other end: in both cases it is the address
// policy is written about, not the originator.
type Forward struct {
	// Host is the destination host, exactly as the wire spelled it. The proxy
	// never resolves it: a DNS answer is not a decision the PDP made.
	Host string
	// Port is the destination port.
	Port int
	// OriginHost is the originating address the peer declared. It is
	// unverified and carries no policy; it is here for the audit trail.
	OriginHost string
	// OriginPort is the originating port, on the same terms.
	OriginPort int
}

// String renders the destination as host:port.
func (f Forward) String() string { return net.JoinHostPort(f.Host, strconv.Itoa(f.Port)) }

// IsForwardChannel reports whether a channel type carries a destination in its
// open payload, and therefore has a destination axis at all (D5a).
func IsForwardChannel(channelType string) bool {
	return channelType == control.ChannelDirectTCPIP || channelType == control.ChannelForwardedTCPIP
}

// tcpipForwardPayload is the channel-open extra data both forwarding channel
// types carry: destination address and port, then originator address and port.
type tcpipForwardPayload struct {
	Host       string
	Port       uint32
	OriginHost string
	OriginPort uint32
}

// ParseForward reads the destination out of a forwarding channel's open
// payload.
//
// It is deliberately strict — ssh.Unmarshal rejects a short payload and a long
// one alike — because a payload the proxy only half understands is a payload
// it cannot police. Every failure is ErrMalformedForward, which the pipeline
// turns into a denial.
func ParseForward(channelType string, payload []byte) (Forward, error) {
	if !IsForwardChannel(channelType) {
		return Forward{}, fmt.Errorf("%w: %q carries no destination", ErrMalformedForward, channelType)
	}
	var parsed tcpipForwardPayload
	if err := ssh.Unmarshal(payload, &parsed); err != nil {
		return Forward{}, fmt.Errorf("%w: %v", ErrMalformedForward, err)
	}
	if parsed.Port > maxPort || parsed.OriginPort > maxPort {
		return Forward{}, fmt.Errorf("%w: port out of range", ErrMalformedForward)
	}
	if parsed.Host == "" {
		return Forward{}, fmt.Errorf("%w: empty destination host", ErrMalformedForward)
	}
	return Forward{
		Host:       parsed.Host,
		Port:       int(parsed.Port),
		OriginHost: parsed.OriginHost,
		OriginPort: int(parsed.OriginPort),
	}, nil
}

// MatchForward reports whether a destination is permitted by any entry in the
// list. An empty list permits nothing, which is what a present-but-empty
// direction on the contract's forward policy means (PLAN §6.2).
func MatchForward(dests []control.ForwardDestination, f Forward) bool {
	for _, dest := range dests {
		if matchHost(dest.Host, f.Host) && matchPort(dest, f.Port) {
			return true
		}
	}
	return false
}

// matchHost applies one host pattern: a bare "*", a "*."-prefixed suffix
// wildcard, a CIDR, or an exact host.
//
// The two kinds of name never cross. A CIDR matches only an IP literal,
// because matching a hostname against one would require resolving it, and a
// wildcard matches only a name, because "*.example.com" is a DNS statement and
// an IP literal is not a DNS name. Anything else would let a policy be widened
// by whatever a resolver happened to answer.
func matchHost(pattern, host string) bool {
	if pattern == "" || host == "" {
		return false
	}
	if pattern == "*" {
		return true
	}

	if prefix, err := netip.ParsePrefix(pattern); err == nil {
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return false
		}
		return prefix.Contains(addr.Unmap())
	}

	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		if _, err := netip.ParseAddr(host); err == nil {
			return false
		}
		name := strings.ToLower(strings.TrimSuffix(host, "."))
		suffix = strings.ToLower(strings.TrimSuffix(suffix, "."))
		return suffix != "" && strings.HasSuffix(name, "."+suffix)
	}

	// Exact. Two IP literals are compared as addresses so that the many
	// spellings of one IPv6 address are one host, and everything else is
	// compared as a case-insensitive name.
	if want, err := netip.ParseAddr(pattern); err == nil {
		got, err := netip.ParseAddr(host)
		return err == nil && want.Unmap() == got.Unmap()
	}
	return strings.EqualFold(strings.TrimSuffix(pattern, "."), strings.TrimSuffix(host, "."))
}

// matchPort applies one destination's port constraint: an exact port, an
// inclusive range, or neither, which permits any port on a matching host.
//
// A destination that names both, or an inverted range, matches nothing. Such
// an entry is a contract violation (the two are documented as mutually
// exclusive), and the fail-closed reading is the only one that cannot be used
// to widen a policy by writing it wrong.
func matchPort(dest control.ForwardDestination, port int) bool {
	switch {
	case dest.Port != 0 && dest.PortRange != nil:
		return false
	case dest.Port != 0:
		return dest.Port == port
	case dest.PortRange != nil:
		r := dest.PortRange
		return r.From <= r.To && port >= r.From && port <= r.To
	default:
		return true
	}
}
