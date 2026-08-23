// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package relay

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// RegistrarOptions configures the downstream half of the relay.
type RegistrarOptions struct {
	// UpstreamAddr is the "host:port" of the upstream proxy's registration
	// listener. Required.
	UpstreamAddr string
	// ProxyID is this proxy's id, presented as the SSH username and used by
	// the upstream to select this registration for a relay hop. Required.
	ProxyID string
	// Signer is this proxy's identity key, or a certificate signer whose
	// certificate names ProxyID as a principal. Required.
	Signer ssh.Signer
	// HostKeyCallback verifies the upstream's host key. Required: an
	// unverified upstream is one that can be impersonated, and this
	// registration is an inbound path for sessions.
	HostKeyCallback ssh.HostKeyCallback
	// Handle serves one relayed connection. It is called on its own goroutine
	// and owns closing the connection. Required.
	Handle func(context.Context, net.Conn)
	// DialTimeout bounds one registration attempt. Zero means
	// DefaultDialTimeout.
	DialTimeout time.Duration
	// KeepaliveInterval is how often the registrar pings the upstream. Zero
	// means DefaultKeepaliveInterval; negative disables the ping.
	KeepaliveInterval time.Duration
	// KeepaliveTimeout is how long a ping may go unanswered before the link is
	// treated as dead. Zero means DefaultKeepaliveTimeout.
	KeepaliveTimeout time.Duration
	// MinBackoff and MaxBackoff bound the exponential reconnect delay. Zero
	// means DefaultMinBackoff / DefaultMaxBackoff.
	MinBackoff, MaxBackoff time.Duration
	// ClientVersion overrides the SSH identification string.
	ClientVersion string
	// Logger receives registration lifecycle events; nil discards them.
	Logger *log.Logger
	// Dial overrides how the TCP connection is made (tests). Nil uses a
	// net.Dialer bounded by DialTimeout.
	Dial func(ctx context.Context, addr string) (net.Conn, error)
	// Sleep waits for d or until ctx ends, returning ctx.Err() if it did.
	// Tests replace it to make backoff instant and observable.
	Sleep func(ctx context.Context, d time.Duration) error
}

// Registrar keeps this proxy's outbound relay registration open (D11).
//
// It is modelled on the revocation stream (PLAN §6.4) because it is the same
// problem one layer down: a long-lived connection this proxy must open outbound
// because nothing may dial in, that has to come back on its own after every
// network event. It reconnects for as long as it is asked to, and never gives
// up on a transport failure.
//
// A lost registration does not touch the sessions already flowing over it
// beyond what the transport forces: those sessions are channels on the old SSH
// connection, so they die with it, and nothing here closes them early or
// cancels the work they are doing. The replacement registration carries new
// sessions only.
type Registrar struct {
	addr      string
	proxyID   string
	signer    ssh.Signer
	hostKey   ssh.HostKeyCallback
	handle    func(context.Context, net.Conn)
	dialTO    time.Duration
	keepalive time.Duration
	timeout   time.Duration
	minBackoff,
	maxBackoff time.Duration
	version string
	logger  *log.Logger
	dial    func(ctx context.Context, addr string) (net.Conn, error)
	sleep   func(context.Context, time.Duration) error

	sessions sync.WaitGroup

	mu         sync.Mutex
	registered bool
}

// NewRegistrar validates opts and returns a Registrar.
func NewRegistrar(opts RegistrarOptions) (*Registrar, error) {
	switch {
	case opts.UpstreamAddr == "":
		return nil, errors.New("relay: registering needs an upstream address")
	case opts.ProxyID == "":
		return nil, errors.New("relay: registering needs this proxy's id")
	case opts.Signer == nil:
		return nil, errors.New("relay: registering needs this proxy's identity key")
	case opts.HostKeyCallback == nil:
		return nil, errors.New("relay: registering needs a host key callback for the upstream")
	case opts.Handle == nil:
		return nil, errors.New("relay: registering needs a handler for relayed connections")
	}
	r := &Registrar{
		addr:       opts.UpstreamAddr,
		proxyID:    opts.ProxyID,
		signer:     opts.Signer,
		hostKey:    opts.HostKeyCallback,
		handle:     opts.Handle,
		dialTO:     opts.DialTimeout,
		keepalive:  opts.KeepaliveInterval,
		timeout:    opts.KeepaliveTimeout,
		minBackoff: opts.MinBackoff,
		maxBackoff: opts.MaxBackoff,
		version:    opts.ClientVersion,
		logger:     opts.Logger,
		dial:       opts.Dial,
		sleep:      opts.Sleep,
	}
	if r.dialTO <= 0 {
		r.dialTO = DefaultDialTimeout
	}
	if r.keepalive == 0 {
		r.keepalive = DefaultKeepaliveInterval
	}
	if r.timeout <= 0 {
		r.timeout = DefaultKeepaliveTimeout
	}
	if r.minBackoff <= 0 {
		r.minBackoff = DefaultMinBackoff
	}
	if r.maxBackoff <= 0 {
		r.maxBackoff = DefaultMaxBackoff
	}
	if r.maxBackoff < r.minBackoff {
		r.maxBackoff = r.minBackoff
	}
	if r.version == "" {
		r.version = ClientVersion
	}
	if r.dial == nil {
		r.dial = r.dialTCP
	}
	if r.sleep == nil {
		r.sleep = sleepCtx
	}
	return r, nil
}

// Run holds the registration open until ctx ends, reconnecting with bounded
// exponential backoff after every failure.
//
// It returns nil when ctx ends — the normal way to stop — and an error only
// when reconnecting cannot help: the upstream rejected this proxy's own key.
// That is a configuration fault, and a retry loop would only hide it.
func (r *Registrar) Run(ctx context.Context) error {
	backoff := r.minBackoff
	for {
		fatal, err := r.runOnce(ctx)
		if ctx.Err() != nil {
			r.sessions.Wait()
			return nil
		}
		if fatal {
			r.sessions.Wait()
			return err
		}
		if err != nil {
			r.logf("relay: registration with %s ended: %v; retrying in %s", r.addr, err, backoff)
		}
		if err := r.sleep(ctx, backoff); err != nil {
			r.sessions.Wait()
			return nil
		}
		backoff *= 2
		if backoff > r.maxBackoff {
			backoff = r.maxBackoff
		}
	}
}

// Registered reports whether the registration is currently up. It is what an
// operator (and a test) asks after a reconnect.
func (r *Registrar) Registered() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.registered
}

// runOnce holds one registration open. It reports whether the failure is one
// that retrying cannot fix.
func (r *Registrar) runOnce(ctx context.Context) (fatal bool, err error) {
	dialCtx, cancel := context.WithTimeout(ctx, r.dialTO)
	nc, err := r.dial(dialCtx, r.addr)
	cancel()
	if err != nil {
		return false, fmt.Errorf("dial upstream %s: %w", r.addr, err)
	}

	_ = nc.SetDeadline(time.Now().Add(r.dialTO))
	conn, chans, reqs, err := ssh.NewClientConn(nc, r.addr, &ssh.ClientConfig{
		User:            r.proxyID,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(r.signer)},
		HostKeyCallback: r.hostKey,
		ClientVersion:   r.version,
		Timeout:         r.dialTO,
	})
	if err != nil {
		_ = nc.Close()
		// A key the upstream will not accept is not a transient failure, and
		// hammering the listener with it helps nobody. The host key not
		// matching is the same kind of answer: it is either the wrong upstream
		// or an impostor, and neither improves with retries.
		if isFatalHandshake(err) {
			return true, fmt.Errorf("relay: the upstream %s refused this proxy's registration: %w", r.addr, err)
		}
		return false, fmt.Errorf("register with %s: %w", r.addr, err)
	}
	_ = nc.SetDeadline(time.Time{})

	r.setRegistered(true)
	defer r.setRegistered(false)
	r.logf("relay: registered with %s as %s", r.addr, r.proxyID)

	go r.serveRequests(reqs)
	go r.serveChannels(ctx, conn, chans)

	closed := make(chan struct{})
	go func() {
		_ = conn.Wait()
		close(closed)
	}()
	r.keepaliveLoop(ctx, conn, closed)
	<-closed
	return false, nil
}

// serveChannels accepts the sessions the upstream sends down the registration.
//
// The handler gets the Run context, not one scoped to this registration: a
// reconnect must not cancel work that is already in flight. The transport will
// take those sessions with it when it dies, and that is the only thing that
// should.
func (r *Registrar) serveChannels(ctx context.Context, conn ssh.Conn, chans <-chan ssh.NewChannel) {
	local := Addr{ProxyID: r.proxyID, Transport: conn.LocalAddr()}
	remote := Addr{ProxyID: r.proxyID, Transport: conn.RemoteAddr()}
	for nch := range chans {
		if nch.ChannelType() != ChannelSession {
			_ = nch.Reject(ssh.UnknownChannelType, "only relayed sessions travel over a registration")
			continue
		}
		ch, reqs, err := nch.Accept()
		if err != nil {
			r.logf("relay: accepting a relayed session failed: %v", err)
			continue
		}
		go ssh.DiscardRequests(reqs)
		r.sessions.Add(1)
		go func() {
			defer r.sessions.Done()
			r.handle(ctx, newChannelConn(ch, local, remote))
		}()
	}
}

// serveRequests answers the upstream's keepalives.
func (r *Registrar) serveRequests(in <-chan *ssh.Request) {
	for req := range in {
		if req.WantReply {
			_ = req.Reply(req.Type == RequestKeepalive, nil)
		}
	}
}

// keepaliveLoop pings the upstream so a silently dead link is noticed and
// replaced, instead of leaving this proxy unreachable while it believes it is
// registered.
func (r *Registrar) keepaliveLoop(ctx context.Context, conn ssh.Conn, closed <-chan struct{}) {
	if r.keepalive < 0 {
		return
	}
	ticker := time.NewTicker(r.keepalive)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = conn.Close()
			return
		case <-closed:
			return
		case <-ticker.C:
			if !r.ping(conn) {
				r.logf("relay: upstream %s did not answer a keepalive; reconnecting", r.addr)
				_ = conn.Close()
				return
			}
		}
	}
}

func (r *Registrar) ping(conn ssh.Conn) bool {
	answered := make(chan bool, 1)
	go func() {
		_, _, err := conn.SendRequest(RequestKeepalive, true, nil)
		answered <- err == nil
	}()
	timer := time.NewTimer(r.timeout)
	defer timer.Stop()
	select {
	case ok := <-answered:
		return ok
	case <-timer.C:
		return false
	}
}

func (r *Registrar) dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: r.dialTO}
	return d.DialContext(ctx, "tcp", addr)
}

func (r *Registrar) setRegistered(up bool) {
	r.mu.Lock()
	r.registered = up
	r.mu.Unlock()
}

func (r *Registrar) logf(format string, args ...any) {
	if r.logger == nil {
		return
	}
	r.logger.Printf(format, args...)
}

// isFatalHandshake reports whether a handshake failure is a configuration
// fault rather than a transient one.
//
// x/crypto reports both a rejected credential and a refused host key as plain
// errors, so the message is the only signal there is. It is matched narrowly:
// anything not recognised stays retryable, because treating a transient failure
// as fatal would take a healthy proxy offline until someone restarted it.
func isFatalHandshake(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, fatal := range []string{
		"unable to authenticate",
		"no supported methods remain",
		"host key mismatch",
		"knownhosts",
	} {
		if strings.Contains(msg, fatal) {
			return true
		}
	}
	return false
}

// sleepCtx waits for d, or until ctx ends.
func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
