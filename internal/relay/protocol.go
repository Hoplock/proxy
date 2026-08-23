// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package relay

import "time"

// The proxy↔proxy relay protocol. It is ordinary SSH: the registration is an
// SSH connection the downstream proxy opens to the upstream, and a relayed
// session is a channel the upstream opens back over it. Reusing SSH rather than
// inventing a framing is what lets the registration be authenticated with the
// same key and certificate machinery as everything else in the fleet.
const (
	// ChannelSession is the channel type the upstream opens on a registration
	// to hand a session to the downstream proxy. Its byte stream is the
	// downstream proxy's inbound connection: the next SSH handshake on it is
	// the chain leg itself.
	ChannelSession = "relay-session@hoplock.io"
	// RequestKeepalive is the connection-level ping both ends send. A TCP
	// connection that has silently gone away looks exactly like an idle one,
	// and an idle registration is the normal state of an enclave proxy, so
	// only an unanswered ping can tell them apart.
	RequestKeepalive = "keepalive@hoplock.io"
	// ServerVersion identifies the upstream's registration listener. It is not
	// the proxy's own SSH listener: a client that reaches this port has found
	// the fleet's plumbing, not a way in.
	ServerVersion = "SSH-2.0-Hoplock_Relay_hub"
	// ClientVersion identifies a registering downstream proxy.
	ClientVersion = "SSH-2.0-Hoplock_Relay_registration"
)

// Timing defaults. None of these decides anything; they bound how long a dead
// link goes unnoticed and how hard a disconnected proxy retries.
const (
	// DefaultKeepaliveInterval is how often each end pings the other.
	DefaultKeepaliveInterval = 10 * time.Second
	// DefaultKeepaliveTimeout is how long a ping may go unanswered before the
	// link is treated as dead.
	DefaultKeepaliveTimeout = 20 * time.Second
	// DefaultDialTimeout bounds one registration attempt, TCP connect plus SSH
	// handshake.
	DefaultDialTimeout = 15 * time.Second
	// DefaultMinBackoff is the first delay after a lost registration.
	DefaultMinBackoff = time.Second
	// DefaultMaxBackoff caps the reconnect delay, so a proxy keeps trying at a
	// steady rate instead of drifting into hours. The same bounds as the
	// revocation stream (control.DefaultMaxBackoff), for the same reason.
	DefaultMaxBackoff = 30 * time.Second
)
