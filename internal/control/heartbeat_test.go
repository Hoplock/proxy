// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// This file is about one field: RevocationEvent.heartbeat_interval_seconds.
//
// The contract has always required heartbeats "at a steady interval", but
// nothing on the stream said which interval, so a conformance harness could
// only grade a number a human typed into its configuration. The field makes the
// obligation a claim the SERVER makes on the wire, and the tests below are the
// two assertions that claim is worth: a server must keep the interval it
// advertises, AND that interval must be inside the ceiling. Neither half is
// sufficient alone — a server advertising 600s and keeping to it passes the
// first and breaks every proxy in the fleet.

// heartbeatConformance is the check a conformance harness makes from the wire,
// written here to prove it is expressible from what the contract now carries.
// advertised is what the server said (zero when it said nothing); gaps are the
// intervals between the heartbeats that actually arrived.
//
// It deliberately does NOT live in the package's production surface: consuming
// the field is a separate phase (a proxy may tighten its own detection with it,
// never loosen it), and this is a grader, not an enforcement point.
func heartbeatConformance(advertised time.Duration, gaps []time.Duration) error {
	ceiling := MaxHeartbeatIntervalSeconds * time.Second
	if advertised > ceiling {
		return fmt.Errorf("server advertises %s, above the %s ceiling", advertised, ceiling)
	}
	if advertised == 0 {
		return nil // the server claims nothing, so there is nothing to grade
	}
	for i, gap := range gaps {
		if gap > advertised {
			return fmt.Errorf("heartbeat %d arrived after %s, later than the advertised %s",
				i+1, gap, advertised)
		}
	}
	return nil
}

// heartbeatServer serves the revocation stream, emitting one heartbeat per
// receive on emit and advertising advertise seconds on each. It stands in for a
// server whose claim may or may not match what it does.
func heartbeatServer(t *testing.T, advertise int32, emit <-chan struct{}) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentTypeNDJSON)
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		_ = rc.Flush()
		enc := json.NewEncoder(w)
		for n := 1; ; n++ {
			select {
			case <-r.Context().Done():
				return
			case _, ok := <-emit:
				if !ok {
					return
				}
				ev := RevocationEvent{
					EventID:                  fmt.Sprintf("evt-%d", n),
					Type:                     EventTypeHeartbeat,
					Timestamp:                time.Now().UTC(),
					HeartbeatIntervalSeconds: advertise,
				}
				if enc.Encode(ev) != nil || rc.Flush() != nil {
					return
				}
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// observeHeartbeats reads count heartbeats off a real stream and returns what
// the server advertised together with the gaps between arrivals.
//
// Arrival times come from the caller's clock rather than from time.Now: the
// handshake through emit already fixes the ORDER of events, so simulating their
// spacing costs the test nothing real and saves it from sleeping for seconds.
// What is not simulated is the part under test — the advertised interval is
// read off the wire, through the real client, exactly as a harness would read
// it.
func observeHeartbeats(t *testing.T, stream EventStream, emit chan<- struct{}, count int, spacing time.Duration) (advertised time.Duration, gaps []time.Duration) {
	t.Helper()
	for i := 0; i < count; i++ {
		emit <- struct{}{}
		ev, err := stream.Recv()
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		if ev.Type != EventTypeHeartbeat {
			t.Fatalf("event type = %q, want %q", ev.Type, EventTypeHeartbeat)
		}
		if d, ok := ev.AdvertisedHeartbeatInterval(); ok {
			advertised = d
		}
		if i > 0 {
			gaps = append(gaps, spacing)
		}
	}
	return advertised, gaps
}

// openHeartbeatStream dials the test server through the real client.
func openHeartbeatStream(t *testing.T, srv *httptest.Server) EventStream {
	t.Helper()
	client, err := NewRESTClient(Options{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("NewRESTClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stream, err := client.StreamEvents(ctx, "proxy-1", "")
	if err != nil {
		t.Fatalf("StreamEvents: %v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	return stream
}

// TestAdvertisedHeartbeatIntervalIsGradedFromTheWire is why the field exists: a
// server cannot satisfy the liveness obligation by advertising an interval it
// does not keep, because the claim and the behaviour are both observable and
// the harness compares them to each other rather than to its own configuration.
func TestAdvertisedHeartbeatIntervalIsGradedFromTheWire(t *testing.T) {
	t.Run("a server that keeps what it advertises passes", func(t *testing.T) {
		emit := make(chan struct{})
		stream := openHeartbeatStream(t, heartbeatServer(t, 5, emit))

		advertised, gaps := observeHeartbeats(t, stream, emit, 3, 4*time.Second)
		if advertised != 5*time.Second {
			t.Fatalf("advertised = %s, want 5s read off the stream", advertised)
		}
		if err := heartbeatConformance(advertised, gaps); err != nil {
			t.Errorf("a conformant server was graded as failing: %v", err)
		}
	})

	t.Run("a server that advertises more often than it heartbeats fails", func(t *testing.T) {
		emit := make(chan struct{})
		// Claims every 2s, delivers every 6s. Before this field the suite had
		// no way to notice: it would have compared 6s against whatever interval
		// its own expectation file named.
		stream := openHeartbeatStream(t, heartbeatServer(t, 2, emit))

		advertised, gaps := observeHeartbeats(t, stream, emit, 3, 6*time.Second)
		if advertised != 2*time.Second {
			t.Fatalf("advertised = %s, want 2s read off the stream", advertised)
		}
		err := heartbeatConformance(advertised, gaps)
		if err == nil {
			t.Fatal("a server emitting slower than it advertised was graded as conformant")
		}
		t.Logf("detected: %v", err)
	})

	t.Run("keeping a huge advertised interval still fails the ceiling", func(t *testing.T) {
		emit := make(chan struct{})
		// 600s, kept exactly. The first half of the requirement holds and the
		// stream is still dead as far as every proxy in the fleet is concerned,
		// which is why the ceiling is a requirement of its own.
		stream := openHeartbeatStream(t, heartbeatServer(t, 600, emit))

		advertised, gaps := observeHeartbeats(t, stream, emit, 2, 600*time.Second)
		if err := heartbeatConformance(advertised, gaps); err == nil {
			t.Error("a server advertising 600s was graded as conformant")
		}
	})
}

// TestAbsentHeartbeatIntervalMeansTheProxyKeepsItsOwnTimers pins the
// absent-value default. A server that says nothing must behave exactly as every
// server did before the field existed.
func TestAbsentHeartbeatIntervalMeansTheProxyKeepsItsOwnTimers(t *testing.T) {
	emit := make(chan struct{})
	stream := openHeartbeatStream(t, heartbeatServer(t, 0, emit))

	advertised, gaps := observeHeartbeats(t, stream, emit, 2, time.Hour)
	if advertised != 0 {
		t.Fatalf("advertised = %s, want nothing: the server set no field", advertised)
	}
	// Nothing is claimed, so nothing is graded — the proxy is on its own
	// timers and the stream above is judged by DefaultHeartbeatTimeout alone.
	if err := heartbeatConformance(advertised, gaps); err != nil {
		t.Errorf("an absent interval was graded: %v", err)
	}

	var absent *RevocationEvent
	if d, ok := absent.AdvertisedHeartbeatInterval(); ok || d != 0 {
		t.Errorf("nil event resolved to (%s, %v), want (0s, false)", d, ok)
	}
	zero := &RevocationEvent{Type: EventTypeHeartbeat}
	if d, ok := zero.AdvertisedHeartbeatInterval(); ok || d != 0 {
		t.Errorf("unset field resolved to (%s, %v), want (0s, false)", d, ok)
	}
}

// TestHeartbeatCeilingLeavesRoomForALostHeartbeat is the reasoning behind the
// ceiling's value, kept as an assertion so the two constants cannot drift apart
// silently: two consecutive intervals at the ceiling must still fit inside the
// proxy's reconnect timeout, or one delayed heartbeat looks like a dead stream.
func TestHeartbeatCeilingLeavesRoomForALostHeartbeat(t *testing.T) {
	ceiling := MaxHeartbeatIntervalSeconds * time.Second
	if 2*ceiling > DefaultHeartbeatTimeout {
		t.Errorf("ceiling %s leaves no room inside the %s reconnect timeout for a lost heartbeat",
			ceiling, DefaultHeartbeatTimeout)
	}
}

// TestHeartbeatIntervalDidNotMoveThePolicyVersion records why this contract
// change is not a vocabulary revision.
//
// PolicyVersion governs POST /v1/authorize and nothing else, because that is
// the response the proxy decodes STRICTLY — the only place an unknown field
// could be a dropped restriction. heartbeat_interval_seconds is on
// RevocationEvent, on another endpoint, and the event stream already requires a
// proxy to ignore what it does not recognise. So the field reaches an older
// peer harmlessly, exactly as HostKeyReportResponse.cache does, and bumping the
// number would force a fleet-wide upgrade for nothing.
func TestHeartbeatIntervalDidNotMoveThePolicyVersion(t *testing.T) {
	if PolicyVersion != 4 {
		t.Errorf("PolicyVersion = %d, want 4: adding heartbeat_interval_seconds is not a vocabulary revision", PolicyVersion)
	}

	// The structural half of the same claim: the field is not on the strictly
	// decoded response, nor on anything it contains.
	encoded, err := json.Marshal(&AuthorizeResponse{})
	if err != nil {
		t.Fatalf("marshal AuthorizeResponse: %v", err)
	}
	var shape map[string]any
	if err := json.Unmarshal(encoded, &shape); err != nil {
		t.Fatalf("decode AuthorizeResponse shape: %v", err)
	}
	if _, found := shape["heartbeat_interval_seconds"]; found {
		t.Error("heartbeat_interval_seconds is on AuthorizeResponse; that WOULD be a vocabulary revision")
	}
}
