// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package relay

import (
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Addr names one end of a relayed connection. A relayed session has no socket
// of its own, so its addresses describe the hop instead: they exist to make
// logs and ConnMeta legible, and are never parsed.
type Addr struct {
	// ProxyID is the peer proxy the channel runs to or from.
	ProxyID string
	// Transport is the registration's own address, so an operator can still
	// find the TCP connection the session actually travelled over.
	Transport net.Addr
}

// Network reports the pseudo-network name of a relayed connection.
func (a Addr) Network() string { return "hoplock-relay" }

func (a Addr) String() string {
	if a.Transport == nil {
		return a.Network() + "/" + a.ProxyID
	}
	return a.Network() + "/" + a.ProxyID + "@" + a.Transport.String()
}

// channelConn presents an SSH channel as a net.Conn, so a relayed session can
// be handed to the same engine code that serves an accepted socket.
//
// Deadlines are the one place the adaptation is not exact. An SSH channel has
// no deadline of its own, so a deadline here is a watchdog that CLOSES the
// channel when it expires rather than making the next Read return a timeout.
// Both callers in this codebase use deadlines the same way — to stop an
// unauthenticated connection or a stalled handshake from living forever — and
// for that a close is the intended outcome anyway.
type channelConn struct {
	ssh.Channel
	local  Addr
	remote Addr

	mu    sync.Mutex
	timer *time.Timer
}

var _ net.Conn = (*channelConn)(nil)

func newChannelConn(ch ssh.Channel, local, remote Addr) *channelConn {
	return &channelConn{Channel: ch, local: local, remote: remote}
}

func (c *channelConn) LocalAddr() net.Addr  { return c.local }
func (c *channelConn) RemoteAddr() net.Addr { return c.remote }

// SetDeadline arms (or with the zero time disarms) the watchdog described on
// channelConn.
func (c *channelConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if t.IsZero() {
		return nil
	}
	d := time.Until(t)
	if d <= 0 {
		return c.Channel.Close()
	}
	c.timer = time.AfterFunc(d, func() { _ = c.Channel.Close() })
	return nil
}

// SetReadDeadline and SetWriteDeadline share the one watchdog: the channel
// cannot fail a read without failing the write half with it.
func (c *channelConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *channelConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

// Close stops the watchdog and closes the channel.
func (c *channelConn) Close() error {
	c.mu.Lock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.mu.Unlock()
	return c.Channel.Close()
}
