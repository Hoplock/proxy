// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package mgmt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"
)

// Revocation stream defaults.
const (
	// DefaultHeartbeatTimeout is how long the stream may be silent before it is
	// treated as dead. The server heartbeats well inside this; a TCP connection
	// that has silently gone away looks exactly like an idle one, so only the
	// absence of heartbeats can tell them apart.
	DefaultHeartbeatTimeout = 20 * time.Second
	// DefaultMinBackoff is the first reconnect delay.
	DefaultMinBackoff = time.Second
	// DefaultMaxBackoff caps the reconnect delay, so a bastion keeps trying at a
	// steady rate instead of drifting into hours.
	DefaultMaxBackoff = 30 * time.Second
	// defaultRevocationReason is shown to the user when the server killed a
	// session without saying why. PLAN §4.3: a revoked session must never look
	// like a crash, so there is always something to display.
	defaultRevocationReason = "your session was ended by the management server"
)

// errHeartbeatMissed ends a connection whose heartbeats stopped arriving.
var errHeartbeatMissed = errors.New("no heartbeat within the timeout")

// StreamOptions configures a RevocationStream.
type StreamOptions struct {
	// HeartbeatTimeout is how long the stream may be silent before it is
	// reconnected. Zero means DefaultHeartbeatTimeout.
	HeartbeatTimeout time.Duration
	// MinBackoff and MaxBackoff bound the exponential reconnect delay. Zero
	// means DefaultMinBackoff / DefaultMaxBackoff.
	MinBackoff, MaxBackoff time.Duration
	// Now overrides the clock used to mark the stream alive (tests).
	Now func() time.Time
	// Sleep waits for d or until ctx ends, returning ctx.Err() if it did. Tests
	// replace it to make backoff instant and observable. Nil uses a timer.
	Sleep func(ctx context.Context, d time.Duration) error
	// Logger receives reconnects and unexpected events; nil discards them. It
	// must never be given event contents beyond ids and types.
	Logger *log.Logger
}

// RevocationStream keeps the bastion's outbound subscription to the management
// server open and routes what arrives (PLAN §6.4).
//
// The subscription is outbound because bastions sit behind firewalls and must
// not need an inbound listener: this stream is the server's only way to reach a
// running bastion, which makes it both the kill switch for live sessions and
// the thing that makes a cached authorize decision safe to hold.
//
// It reconnects for as long as it is asked to, resuming from the last event it
// processed so the server can replay the gap. It never gives up on a transport
// failure — while it is down, the cache goes stale on its own (CachingClient)
// and every connection is re-authorized, but live sessions keep running.
type RevocationStream struct {
	src      EventStreamer
	cache    CacheController
	registry SessionRegistry

	heartbeatTimeout time.Duration
	minBackoff       time.Duration
	maxBackoff       time.Duration
	now              func() time.Time
	sleep            func(context.Context, time.Duration) error
	logger           *log.Logger

	mu          sync.Mutex
	lastEventID string
}

// NewRevocationStream wires a stream source to the cache and the session
// registry. cache may be nil when the deployment caches nothing; registry may
// be NopSessionRegistry until the proxy implements one (phase 0005), but a
// deployment that runs with the no-op silently drops kills.
func NewRevocationStream(src EventStreamer, cache CacheController, registry SessionRegistry, opts StreamOptions) *RevocationStream {
	s := &RevocationStream{
		src:              src,
		cache:            cache,
		registry:         registry,
		heartbeatTimeout: opts.HeartbeatTimeout,
		minBackoff:       opts.MinBackoff,
		maxBackoff:       opts.MaxBackoff,
		now:              opts.Now,
		sleep:            opts.Sleep,
		logger:           opts.Logger,
	}
	if s.registry == nil {
		s.registry = NopSessionRegistry{}
	}
	if s.heartbeatTimeout <= 0 {
		s.heartbeatTimeout = DefaultHeartbeatTimeout
	}
	if s.minBackoff <= 0 {
		s.minBackoff = DefaultMinBackoff
	}
	if s.maxBackoff <= 0 {
		s.maxBackoff = DefaultMaxBackoff
	}
	if s.maxBackoff < s.minBackoff {
		s.maxBackoff = s.minBackoff
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.sleep == nil {
		s.sleep = sleepCtx
	}
	return s
}

// Subscribe holds the subscription open until ctx ends, reconnecting with
// bounded exponential backoff after any transport or protocol failure.
//
// It returns nil when ctx ends — that is the normal way to stop — and an error
// only when reconnecting cannot help: the server rejected the bastion's own
// credential (a deny), or rejected the request as malformed. Both are
// configuration faults that a retry loop would only hide.
func (s *RevocationStream) Subscribe(ctx context.Context, bastionID string) error {
	if bastionID == "" {
		return &APIError{Op: "Subscribe", Cause: fmt.Errorf("%w: bastion id is required", ErrBadRequest)}
	}

	backoff := s.minBackoff
	for {
		err := s.runOnce(ctx, bastionID)
		if ctx.Err() != nil {
			return nil
		}
		switch {
		case err == nil, errors.Is(err, io.EOF):
			// The server closed the stream cleanly; reconnect from the start of
			// the backoff, since nothing is known to be wrong.
			backoff = s.minBackoff
			s.logf("mgmt: revocation stream closed by the server; reconnecting")
		case IsUnauthorized(err) || errors.Is(err, ErrBadRequest):
			return err
		default:
			s.logf("mgmt: revocation stream failed (%v); reconnecting in %s", err, backoff)
		}

		if err := s.sleep(ctx, backoff); err != nil {
			return nil
		}
		backoff = min(backoff*2, s.maxBackoff)
	}
}

// LastEventID returns the id of the last event processed. It is what a
// reconnect resumes from, and it is opaque to the bastion.
func (s *RevocationStream) LastEventID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastEventID
}

// runOnce holds one connection open until it fails or ctx ends.
func (s *RevocationStream) runOnce(ctx context.Context, bastionID string) error {
	stream, err := s.src.StreamEvents(ctx, bastionID, s.LastEventID())
	if err != nil {
		return err
	}
	// A connected stream is itself proof the server is reachable, so the cache
	// may be served from here even before the first heartbeat.
	s.markAlive()

	done := make(chan struct{})
	defer func() {
		close(done)
		_ = stream.Close()
	}()

	events := make(chan *RevocationEvent)
	failures := make(chan error, 1)
	go func() {
		for {
			ev, err := stream.Recv()
			if err != nil {
				failures <- err // buffered: never blocks, even after done
				return
			}
			select {
			case events <- ev:
			case <-done:
				return
			}
		}
	}()

	// Silence beyond the heartbeat timeout means the connection is dead even
	// though the socket still looks open. Closing it (via the deferred Close,
	// which also unblocks the reader) is the only way to find out.
	timer := time.NewTimer(s.heartbeatTimeout)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-failures:
			return err
		case ev := <-events:
			s.handle(ctx, ev)
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(s.heartbeatTimeout)
		case <-timer.C:
			return fmt.Errorf("%w: %w", ErrTransport, errHeartbeatMissed)
		}
	}
}

// handle applies one event. Cache invalidation always happens before the kill,
// so a connection racing the teardown cannot be authorized from a decision the
// server has just withdrawn.
func (s *RevocationStream) handle(ctx context.Context, ev *RevocationEvent) {
	s.mu.Lock()
	s.lastEventID = ev.EventID
	s.mu.Unlock()
	s.markAlive()

	switch ev.Type {
	case EventTypeHeartbeat:
		// Liveness only, already recorded above.
	case EventTypeResync:
		// The server cannot tell us what we missed, so nothing we hold can be
		// trusted: drop it all and re-authorize from scratch.
		s.invalidateAll()
	case EventTypeCacheInvalidate:
		inv := ev.CacheInvalidate
		switch {
		case inv.All:
			s.invalidateAll()
		case inv.Subject != "":
			if s.cache != nil {
				s.cache.InvalidateSubject(inv.Subject)
			}
		default:
			if s.cache != nil {
				s.cache.Invalidate(inv.Keys...)
			}
		}
	case EventTypeSessionKill:
		s.handleKill(ctx, ev.SessionKill)
	default:
		// A newer server may know event types this bastion does not. Ignoring
		// them keeps the stream alive rather than reconnecting in a loop.
		s.logf("mgmt: ignoring unknown revocation event type %q (event %s)", ev.Type, ev.EventID)
	}
}

// handleKill ends the sessions the server named and drops any cached decision
// that could let them straight back in.
func (s *RevocationStream) handleKill(ctx context.Context, kill *SessionKillEvent) {
	reason := kill.Reason
	if reason == "" {
		reason = defaultRevocationReason
	}
	switch {
	case kill.All:
		s.invalidateAll()
		s.report("KillAll", s.registry.KillAll(ctx, reason))
	case kill.Subject != "":
		if s.cache != nil {
			s.cache.InvalidateSubject(kill.Subject)
		}
		s.report("KillSubject", s.registry.KillSubject(ctx, kill.Subject, reason))
	default:
		// Session ids say nothing about which cached decisions to drop; a server
		// that wants those gone sends a cache_invalidate too.
		for _, id := range kill.SessionIDs {
			s.report("KillSession", s.registry.KillSession(ctx, id, reason))
		}
	}
}

func (s *RevocationStream) invalidateAll() {
	if s.cache != nil {
		s.cache.InvalidateAll()
	}
}

func (s *RevocationStream) markAlive() {
	if s.cache != nil {
		s.cache.StreamAlive(s.now())
	}
}

// report logs a registry failure. It is never fatal: a kill for a session this
// bastion does not have is normal, and one that failed must not stop the rest
// of the stream from being applied.
func (s *RevocationStream) report(op string, err error) {
	if err != nil {
		s.logf("mgmt: revocation %s: %v", op, err)
	}
}

func (s *RevocationStream) logf(format string, args ...any) {
	if s.logger != nil {
		s.logger.Printf(format, args...)
	}
}

// sleepCtx waits for d, or returns ctx.Err() if ctx ends first.
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
