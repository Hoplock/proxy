// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package mgmt

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// contentTypeNDJSON is the media type of the revocation stream: one JSON event
// per line, delivered as the response body arrives.
const contentTypeNDJSON = "application/x-ndjson"

// maxEventLineBytes caps one event line, so a misbehaving or hostile server
// cannot make the bastion buffer without bound.
const maxEventLineBytes = 1 << 20

// EventStreamer opens the server→bastion revocation stream. It is separate from
// Client because it is the one call that is long-lived rather than
// request/response: a decorator around Client (see CachingClient) has nothing
// to add to it, and a fake Client in a test should not have to implement it.
// RESTClient implements both.
type EventStreamer interface {
	// StreamEvents subscribes to the events for one bastion, resuming after
	// lastEventID when it is non-empty. The returned stream stays open until it
	// fails, is closed, or ctx ends.
	StreamEvents(ctx context.Context, bastionID, lastEventID string) (EventStream, error)
}

// EventStream delivers revocation events in the order the server sent them.
type EventStream interface {
	// Recv blocks until the next event arrives. It returns io.EOF when the
	// server closed the stream cleanly, and an *APIError wrapping ErrTransport
	// or ErrProtocol otherwise. Every error is terminal for this stream: the
	// caller closes it and reconnects.
	Recv() (*RevocationEvent, error)
	// Close releases the stream. It is safe to call concurrently with Recv,
	// which is how a caller aborts a blocked read (e.g. a missed heartbeat).
	Close() error
}

// ndjsonEventStream reads newline-delimited events from a response body.
type ndjsonEventStream struct {
	body    io.ReadCloser
	scanner *bufio.Scanner
}

func newNDJSONEventStream(body io.ReadCloser) *ndjsonEventStream {
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 0, 4096), maxEventLineBytes)
	return &ndjsonEventStream{body: body, scanner: sc}
}

// Recv implements EventStream.
func (s *ndjsonEventStream) Recv() (*RevocationEvent, error) {
	const op = "StreamEvents"
	for {
		if !s.scanner.Scan() {
			if err := s.scanner.Err(); err != nil {
				return nil, &APIError{Op: op, Cause: fmt.Errorf("%w: %w", ErrTransport, err)}
			}
			return nil, io.EOF
		}
		line := bytes.TrimSpace(s.scanner.Bytes())
		if len(line) == 0 {
			continue // tolerate blank separator lines
		}
		var ev RevocationEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, protocolError(op, fmt.Errorf("decode event: %v", err))
		}
		if err := validateEvent(&ev); err != nil {
			return nil, protocolError(op, err)
		}
		return &ev, nil
	}
}

// Close implements EventStream.
func (s *ndjsonEventStream) Close() error { return s.body.Close() }

// validateEvent enforces "the payload named by type is present and selects
// something", so a dispatcher can act on an event without re-checking the
// contract. An unrecognised type is deliberately not an error: a newer server
// must be able to add an event type without breaking older bastions, which then
// ignore it (see RevocationStream.dispatch).
func validateEvent(ev *RevocationEvent) error {
	if ev.EventID == "" {
		return errors.New("event has no event_id")
	}
	switch ev.Type {
	case "":
		return errors.New("event has no type")
	case EventTypeSessionKill:
		if ev.SessionKill == nil {
			return errors.New("session_kill event has no session_kill payload")
		}
		k := ev.SessionKill
		if len(k.SessionIDs) == 0 && k.Subject == "" && !k.All {
			return errors.New("session_kill names no session_ids, subject, or all")
		}
	case EventTypeCacheInvalidate:
		if ev.CacheInvalidate == nil {
			return errors.New("cache_invalidate event has no cache_invalidate payload")
		}
		i := ev.CacheInvalidate
		if len(i.Keys) == 0 && i.Subject == "" && !i.All {
			return errors.New("cache_invalidate names no keys, subject, or all")
		}
	}
	return nil
}

// SessionRegistry is how the revocation stream reaches live SSH sessions. It is
// implemented by the proxy in phase 0005; this package only routes to it.
//
// An implementation MUST deliver reason to the user before closing the
// connection (PLAN §4.3): a session the server revoked must not be
// indistinguishable from a crash. This phase's job is to carry the reason to
// the implementation intact.
//
// A kill for a session, subject, or bastion the registry knows nothing about is
// not an error — the server may be addressing sessions this bastion never had,
// or has already lost. Implementations are called from the stream's goroutine,
// so they must not block for long.
type SessionRegistry interface {
	// KillSession tears down the named session.
	KillSession(ctx context.Context, sessionID, reason string) error
	// KillSubject tears down every session belonging to a subject.
	KillSubject(ctx context.Context, subject, reason string) error
	// KillAll tears down every session on this bastion.
	KillAll(ctx context.Context, reason string) error
}

// NopSessionRegistry accepts and discards every kill. It exists so the
// revocation stream is usable before the proxy implements the real registry in
// 0005; a deployment must never run with it, because a kill would be silently
// dropped.
type NopSessionRegistry struct{}

var _ SessionRegistry = NopSessionRegistry{}

// KillSession implements SessionRegistry.
func (NopSessionRegistry) KillSession(context.Context, string, string) error { return nil }

// KillSubject implements SessionRegistry.
func (NopSessionRegistry) KillSubject(context.Context, string, string) error { return nil }

// KillAll implements SessionRegistry.
func (NopSessionRegistry) KillAll(context.Context, string) error { return nil }
