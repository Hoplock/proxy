// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package relay

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// ErrNoRegistration means no downstream proxy is currently registered under
// the id a relay hop named.
//
// It is deliberately terminal. A relay hop is never downgraded to a dial: the
// route said relay because the next proxy sits behind a boundary with no
// inbound rule, and dialling it anyway would either fail or — worse, if some
// path did exist — quietly use the one the mode exists to avoid. The session
// fails as an outage instead (PLAN §4.3).
var ErrNoRegistration = errors.New("relay: no proxy is registered under that id")

// HubOptions configures the upstream half of the relay.
type HubOptions struct {
	// HostKey is the key the registration listener presents. Registering
	// proxies pin it, so it is what stops a downstream proxy from handing its
	// registration — and every session that would travel over it — to an
	// impostor. Required.
	HostKey ssh.Signer
	// Authorizer decides which proxy ids a registering key may claim.
	// Required: an unauthenticated registration is a way to receive other
	// people's sessions.
	Authorizer *Authorizer
	// KeepaliveInterval is how often the hub pings a registration. Zero means
	// DefaultKeepaliveInterval; negative disables the ping.
	KeepaliveInterval time.Duration
	// KeepaliveTimeout is how long a ping may go unanswered before the
	// registration is dropped. Zero means DefaultKeepaliveTimeout.
	KeepaliveTimeout time.Duration
	// ServerVersion overrides the SSH identification string.
	ServerVersion string
	// Logger receives registration lifecycle events; nil discards them.
	Logger *log.Logger
}

// Hub accepts relay registrations and opens sessions over them (D11).
//
// It keeps at most one registration per proxy id. A second registration for an
// id replaces the first, because that is what a reconnect after an unnoticed
// network death looks like from here, and refusing it would leave the id
// unreachable until a dead connection timed out.
type Hub struct {
	hostKey    ssh.Signer
	authorizer *Authorizer
	keepalive  time.Duration
	timeout    time.Duration
	version    string
	logger     *log.Logger

	mu    sync.Mutex
	regs  map[string]*registration
	conns sync.WaitGroup
}

// registration is one downstream proxy's live outbound connection.
type registration struct {
	proxyID    string
	conn       ssh.Conn
	remoteAddr net.Addr
	localAddr  net.Addr
	since      time.Time
}

// NewHub validates opts and returns a Hub.
func NewHub(opts HubOptions) (*Hub, error) {
	switch {
	case opts.HostKey == nil:
		return nil, errors.New("relay: the registration listener needs a host key")
	case opts.Authorizer == nil:
		return nil, errors.New("relay: the registration listener needs an authorizer")
	}
	h := &Hub{
		hostKey:    opts.HostKey,
		authorizer: opts.Authorizer,
		keepalive:  opts.KeepaliveInterval,
		timeout:    opts.KeepaliveTimeout,
		version:    opts.ServerVersion,
		logger:     opts.Logger,
		regs:       make(map[string]*registration),
	}
	if h.keepalive == 0 {
		h.keepalive = DefaultKeepaliveInterval
	}
	if h.timeout <= 0 {
		h.timeout = DefaultKeepaliveTimeout
	}
	if h.version == "" {
		h.version = ServerVersion
	}
	return h, nil
}

// Serve accepts registrations until ctx ends or the listener fails. It closes
// every registration on the way out, so a downstream proxy learns immediately
// that its upstream is gone rather than waiting for a keepalive to lapse.
func (h *Hub) Serve(ctx context.Context, l net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}
		_ = l.Close()
	}()

	var serveErr error
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() == nil {
				serveErr = fmt.Errorf("relay: accept: %w", err)
			}
			break
		}
		h.conns.Add(1)
		go func() {
			defer h.conns.Done()
			h.handleRegistration(ctx, conn)
		}()
	}

	h.closeAll()
	h.conns.Wait()
	return serveErr
}

// Open opens a session channel over the registration held for proxyID and
// returns it as a net.Conn. It answers ErrNoRegistration when there is none.
func (h *Hub) Open(ctx context.Context, proxyID string) (net.Conn, error) {
	h.mu.Lock()
	reg := h.regs[proxyID]
	h.mu.Unlock()
	if reg == nil {
		return nil, fmt.Errorf("%w: %q", ErrNoRegistration, proxyID)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	ch, reqs, err := reg.conn.OpenChannel(ChannelSession, nil)
	if err != nil {
		// A registration that cannot carry a channel is dead; drop it so the
		// next session is refused promptly instead of waiting on the same
		// corpse, and so the downstream proxy's reconnect can replace it.
		h.drop(reg, fmt.Sprintf("opening a session failed: %v", err))
		return nil, fmt.Errorf("relay: open a session to %q: %w", proxyID, err)
	}
	go ssh.DiscardRequests(reqs)

	local := Addr{ProxyID: proxyID, Transport: reg.localAddr}
	remote := Addr{ProxyID: proxyID, Transport: reg.remoteAddr}
	return newChannelConn(ch, local, remote), nil
}

// Registered reports whether a proxy id currently has a live registration.
func (h *Hub) Registered(proxyID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.regs[proxyID] != nil
}

// Registrations lists the proxy ids with a live registration, for logs and
// operational checks.
func (h *Hub) Registrations() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	ids := make([]string, 0, len(h.regs))
	for id := range h.regs {
		ids = append(ids, id)
	}
	return ids
}

// Drop closes the registration held for proxyID, if any, and reports whether
// there was one. The downstream proxy re-registers on its own backoff.
func (h *Hub) Drop(proxyID string) bool {
	h.mu.Lock()
	reg := h.regs[proxyID]
	h.mu.Unlock()
	if reg == nil {
		return false
	}
	h.drop(reg, "closed by the upstream proxy")
	return true
}

// handleRegistration authenticates one registering proxy and holds its
// connection open until it dies.
func (h *Hub) handleRegistration(ctx context.Context, nc net.Conn) {
	cfg := &ssh.ServerConfig{
		ServerVersion:     h.version,
		PublicKeyCallback: h.authorizer.Authenticate,
	}
	cfg.AddHostKey(h.hostKey)

	// An unauthenticated socket must not be able to sit on the listener
	// forever; the deadline is cleared once the handshake succeeds.
	_ = nc.SetDeadline(time.Now().Add(DefaultDialTimeout))
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		h.logf("relay: registration from %s refused: %v", nc.RemoteAddr(), err)
		_ = nc.Close()
		return
	}
	_ = nc.SetDeadline(time.Time{})

	// The id is the one the authorizer proved, not the one the connection
	// claimed: they are equal by construction today, and keeping the proven
	// value is what makes that stay true if a future authorizer maps them.
	proxyID := ProxyIDOf(conn.Permissions)
	if proxyID == "" {
		proxyID = conn.User()
	}

	reg := &registration{
		proxyID:    proxyID,
		conn:       conn,
		remoteAddr: conn.RemoteAddr(),
		localAddr:  conn.LocalAddr(),
		since:      time.Now(),
	}
	h.register(reg)
	h.logf("relay: proxy %s registered from %s", proxyID, reg.remoteAddr)

	// A registrant opens nothing and asks for nothing: the channels run the
	// other way. Anything it does send is refused rather than ignored, so a
	// misconfigured peer fails loudly instead of hanging.
	go func() {
		for nch := range chans {
			_ = nch.Reject(ssh.Prohibited, "a relay registration carries no client channels")
		}
	}()
	go h.serveRequests(reqs)

	closed := make(chan struct{})
	go func() {
		_ = conn.Wait()
		close(closed)
	}()
	h.keepaliveLoop(ctx, reg, closed)

	<-closed
	h.deregister(reg)
	h.logf("relay: proxy %s registration ended after %s", proxyID, time.Since(reg.since).Round(time.Second))
}

// serveRequests answers a registrant's connection-level requests. Keepalives
// get a true reply; everything else is refused, because a registration is
// plumbing and carries no session-level traffic of its own.
func (h *Hub) serveRequests(in <-chan *ssh.Request) {
	for req := range in {
		if req.WantReply {
			_ = req.Reply(req.Type == RequestKeepalive, nil)
		}
	}
}

// keepaliveLoop pings the registrant until the connection dies or ctx ends.
func (h *Hub) keepaliveLoop(ctx context.Context, reg *registration, closed <-chan struct{}) {
	if h.keepalive < 0 {
		return
	}
	ticker := time.NewTicker(h.keepalive)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			h.drop(reg, "the upstream proxy is shutting down")
			return
		case <-closed:
			return
		case <-ticker.C:
			if !h.ping(reg) {
				h.drop(reg, "no answer to a keepalive")
				return
			}
		}
	}
}

// ping sends one keepalive and reports whether the registrant answered inside
// the timeout. SendRequest blocks until the peer replies, so the timeout is
// enforced by racing it rather than by the call itself.
func (h *Hub) ping(reg *registration) bool {
	answered := make(chan bool, 1)
	go func() {
		_, _, err := reg.conn.SendRequest(RequestKeepalive, true, nil)
		answered <- err == nil
	}()
	timer := time.NewTimer(h.timeout)
	defer timer.Stop()
	select {
	case ok := <-answered:
		return ok
	case <-timer.C:
		return false
	}
}

func (h *Hub) register(reg *registration) {
	h.mu.Lock()
	previous := h.regs[reg.proxyID]
	h.regs[reg.proxyID] = reg
	h.mu.Unlock()
	if previous != nil {
		h.logf("relay: proxy %s re-registered; closing the previous registration from %s",
			reg.proxyID, previous.remoteAddr)
		_ = previous.conn.Close()
	}
}

// deregister removes reg only if it is still the current registration, so a
// dying connection cannot evict the reconnect that replaced it.
func (h *Hub) deregister(reg *registration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.regs[reg.proxyID] == reg {
		delete(h.regs, reg.proxyID)
	}
}

func (h *Hub) drop(reg *registration, reason string) {
	h.deregister(reg)
	h.logf("relay: dropping proxy %s registration: %s", reg.proxyID, reason)
	_ = reg.conn.Close()
}

func (h *Hub) closeAll() {
	h.mu.Lock()
	regs := make([]*registration, 0, len(h.regs))
	for _, reg := range h.regs {
		regs = append(regs, reg)
	}
	h.regs = make(map[string]*registration)
	h.mu.Unlock()
	for _, reg := range regs {
		_ = reg.conn.Close()
	}
}

func (h *Hub) logf(format string, args ...any) {
	if h.logger == nil {
		return
	}
	h.logger.Printf(format, args...)
}
