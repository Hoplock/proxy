// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// subscriberBuffer is how many events one subscriber may fall behind by before
// the mock drops its connection. A dropped subscriber reconnects and replays
// from its last event id, so lagging costs a reconnect, never an event.
const subscriberBuffer = 64

// eventIDPrefix labels the ids this server assigns. Only the server may parse
// them: to the proxy an event id is opaque (api/README.md).
const eventIDPrefix = "evt-"

// subscriber is one open revocation stream.
type subscriber struct {
	ch chan control.RevocationEvent
	// kick is closed to end the connection from the server side.
	kick   chan struct{}
	kicked bool
}

// handleProxyEvents serves the long-lived revocation stream.
func (s *server) handleProxyEvents(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProxy(w, r) {
		return
	}
	if r.PathValue("proxy_id") == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "proxy_id is required")
		return
	}

	sub := &subscriber{
		ch:   make(chan control.RevocationEvent, subscriberBuffer),
		kick: make(chan struct{}),
	}
	backlog, resync := s.subscribe(sub, r.URL.Query().Get(control.QueryLastEventID))
	defer s.unsubscribe(sub)

	// The stream outlives the server's read and write timeouts by design, so
	// both deadlines are cleared for this connection only.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if rc.Flush() != nil {
		return
	}

	enc := json.NewEncoder(w)
	write := func(ev control.RevocationEvent) bool {
		if err := enc.Encode(ev); err != nil {
			return false
		}
		return rc.Flush() == nil
	}

	// Gap recovery: replay what the proxy missed, or tell it up front that we
	// cannot, in which case it drops its cache and starts over.
	if resync {
		if !write(s.newEvent(control.EventTypeResync)) {
			return
		}
	}
	for _, ev := range backlog {
		if !write(ev) {
			return
		}
	}

	// Heartbeats prove the stream is alive; a proxy that stops hearing them
	// reconnects. A negative interval disables them, which is how a test drives
	// the proxy's heartbeat timeout.
	var heartbeats <-chan time.Time
	if ms := s.fx.Events.HeartbeatMS; ms > 0 {
		ticker := time.NewTicker(time.Duration(ms) * time.Millisecond)
		defer ticker.Stop()
		heartbeats = ticker.C
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case <-sub.kick:
			return
		case ev := <-sub.ch:
			if !write(ev) {
				return
			}
		case <-heartbeats:
			if !write(s.newEvent(control.EventTypeHeartbeat)) {
				return
			}
		}
	}
}

// handleDebugRevoke publishes an event to every subscriber. It is mock-only:
// on a real server these events come from an operator action or a policy
// change, and this endpoint is how a test or the e2e topology stands in for one.
func (s *server) handleDebugRevoke(w http.ResponseWriter, r *http.Request) {
	var ev control.RevocationEvent
	if !decode(w, r, &ev) {
		return
	}
	switch ev.Type {
	case control.EventTypeSessionKill:
		if ev.SessionKill == nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "session_kill payload is required")
			return
		}
	case control.EventTypeCacheInvalidate:
		if ev.CacheInvalidate == nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "cache_invalidate payload is required")
			return
		}
	case control.EventTypeHeartbeat, control.EventTypeResync:
	default:
		writeError(w, http.StatusBadRequest, "invalid_request", "unknown event type")
		return
	}

	eventID, delivered := s.publishEvent(ev)
	writeJSON(w, http.StatusOK, debugRevokeResponse{EventID: eventID, Delivered: delivered})
}

// debugRevokeResponse tells the caller which event was published and how many
// subscribers it reached, so a test can wait for a subscription to be live.
type debugRevokeResponse struct {
	EventID   string `json:"event_id"`
	Delivered int    `json:"delivered"`
}

// subscribe registers sub and returns what it missed since lastEventID. It
// reports resync when the gap cannot be replayed — an unparseable id, or one
// older than everything still retained.
func (s *server) subscribe(sub *subscriber, lastEventID string) (backlog []control.RevocationEvent, resync bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subs[sub] = true

	if lastEventID == "" {
		return nil, false // a fresh subscription starts from now
	}
	num, ok := eventNum(lastEventID)
	if !ok || num < s.evictedThrough {
		return nil, true
	}
	for _, ev := range s.events {
		if n, ok := eventNum(ev.EventID); ok && n > num {
			backlog = append(backlog, ev)
		}
	}
	return backlog, false
}

func (s *server) unsubscribe(sub *subscriber) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.subs, sub)
}

// publishEvent assigns an id, retains the event for replay, and fans it out.
func (s *server) publishEvent(ev control.RevocationEvent) (eventID string, delivered int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ev.EventID = s.nextEventIDLocked()
	if ev.Timestamp.IsZero() {
		ev.Timestamp = s.now().UTC()
	}

	s.events = append(s.events, ev)
	if over := len(s.events) - s.fx.Events.ReplayBuffer; over > 0 {
		// Remember how far the history was trimmed: a proxy asking to resume
		// from before this point is told to resync instead.
		if n, ok := eventNum(s.events[over-1].EventID); ok {
			s.evictedThrough = n
		}
		s.events = append([]control.RevocationEvent{}, s.events[over:]...)
	}

	for sub := range s.subs {
		select {
		case sub.ch <- ev:
			delivered++
		default:
			// Too far behind to catch up: end the connection. The proxy
			// reconnects with its last event id and replays the gap.
			if !sub.kicked {
				sub.kicked = true
				close(sub.kick)
			}
		}
	}
	return ev.EventID, delivered
}

// newEvent builds a bare event of the given type. Heartbeats and resyncs are
// per-connection and are deliberately not retained for replay: they carry no
// state, and heartbeats would otherwise evict real events from the history.
func (s *server) newEvent(t control.EventType) control.RevocationEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return control.RevocationEvent{
		EventID:   s.nextEventIDLocked(),
		Type:      t,
		Timestamp: s.now().UTC(),
	}
}

// nextEventIDLocked assigns the next id. Ids are monotonic, which is what makes
// replay-after-an-id possible; the caller holds s.mu.
func (s *server) nextEventIDLocked() string {
	s.idCounter++
	return eventIDPrefix + strconv.Itoa(s.idCounter)
}

// eventNum parses an id this server assigned.
func eventNum(id string) (int, bool) {
	rest, ok := strings.CutPrefix(id, eventIDPrefix)
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(rest)
	if err != nil {
		return 0, false
	}
	return n, true
}
