// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/auth/target"
	"github.com/hoplock/proxy/internal/control"
)

// Pinning (phase 0046): what keeps D16's "recorded, not even to its disk
// buffer" and PLAN §5.3's "attribution is the log" true under a bounded buffer.

// TestPinningNeedsAPipeline: a proxy with no pipeline cannot pin — as it
// cannot record — and one with no buffer has nothing to make durable, so its
// pin succeeds and Deliverable goes on meaning what it always meant there.
func TestPinningNeedsAPipeline(t *testing.T) {
	var none *SessionRecorder
	if err := none.Pin(); err == nil {
		t.Error("a nil recorder's Pin succeeded; it must fail as its Deliverable answers false")
	}

	server := &fakeControl{}
	shipper, err := New(Options{Client: server, FlushInterval: -1, Logf: t.Logf})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shipper.Close(ctx)
	})
	rec := shipper.Session(SessionInfo{SessionID: "held"})
	if err := rec.Pin(); err != nil {
		t.Errorf("Pin with no buffer configured: %v", err)
	}
	if !rec.Deliverable() {
		t.Error("a buffer-less proxy that has dropped nothing reports no logging path")
	}
}

// TestAnUnsetWindowIsAGibibyte: zero means the default, as it does for every
// other logging knob, and the default is the one the configuration documents.
func TestAnUnsetWindowIsAGibibyte(t *testing.T) {
	if DefaultBufferMaxBytes != 1<<30 {
		t.Errorf("DefaultBufferMaxBytes = %d, want 1 GiB", DefaultBufferMaxBytes)
	}
	shipper, _ := newTestShipper(t, nil)
	if got := shipper.buffer.window; got != DefaultBufferMaxBytes {
		t.Errorf("a shipper with no window set has a window of %d, want %d", got, DefaultBufferMaxBytes)
	}
}

// TestDeliverableGoesFalseWhenPinnedRecordsFillTheWindow: a buffer full of
// records it may not evict cannot promise a new pinned session its record, so
// D16 routes and constrained device routes are refused — and every other route
// keeps running, its records still accepted.
func TestDeliverableGoesFalseWhenPinnedRecordsFillTheWindow(t *testing.T) {
	const window = 32 << 10
	shipper, server := newTestShipper(t, func(o *Options) {
		o.BatchSize = 1
		o.BufferMaxBytes = window
		o.RetryMin = time.Hour
	})
	server.setDown(true)

	held := shipper.Session(SessionInfo{SessionID: "held", ProxyID: "p"})
	if !held.Deliverable() {
		t.Fatal("an empty buffer does not promise a pinned session its record")
	}
	if err := held.Pin(); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	for i := 0; shipper.Stats().PinnedBytes < window; i++ {
		if i > 100 {
			t.Fatal("the pinned records never reached the window")
		}
		held.Stream(make([]byte, 3000), testEpoch, Attrs{AttrSequence: "x"})
		handled(t, shipper)
	}
	if held.Deliverable() {
		t.Errorf("pinned bytes %d reached the window %d and a new pinned session is still promised its record",
			shipper.Stats().PinnedBytes, window)
	}

	// Everybody else keeps running: an unpinned session's records are
	// accepted — evicted, when there is no room, and reported.
	other := shipper.Session(SessionInfo{SessionID: "other", ProxyID: "p"})
	other.Stream(make([]byte, 3000), testEpoch, nil)
	handled(t, shipper)
	if got := shipper.Stats().Dropped; got != 0 {
		t.Errorf("Stats.Dropped = %d: an unpinned session's records were lost rather than accounted for", got)
	}

	// And when the server comes back, every pinned record arrives in full.
	madeHeld := held.Records()
	server.setDown(false)
	flush(t, shipper)
	var arrived uint64
	for _, rec := range server.delivered() {
		if rec.SessionID == "held" {
			arrived++
		}
	}
	if arrived != madeHeld {
		t.Errorf("%d of the pinned session's %d records arrived", arrived, madeHeld)
	}
}

// TestAPinGoesOnceItsSessionHasEndedAndShipped: a pin must not outlive what it
// protects — the marker and the directory go once the session's end has been
// shipped and nothing of it is left on disk — and must not go sooner.
func TestAPinGoesOnceItsSessionHasEndedAndShipped(t *testing.T) {
	shipper, server := newTestShipper(t, func(o *Options) { o.RetryMin = time.Hour })
	dir := shipper.buffer.dir
	marker := filepath.Join(dir, "held", pinMarker)

	held := shipper.Session(SessionInfo{SessionID: "held", ProxyID: "p"})
	if err := held.Pin(); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("Pin returned before the pin was on disk: %v", err)
	}

	// Ended during an outage: the session's records are on disk, pinned, and
	// the pin stays with them.
	server.setDown(true)
	held.Record(Event{Kind: control.LogKindCommand, Message: "last command"})
	held.End(nil)
	handled(t, shipper)
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the pin went while the ended session's records were still on disk: %v", err)
	}

	// Delivered: nothing of it is left, and neither is the pin.
	server.setDown(false)
	flush(t, shipper)
	eventually(t, func() bool {
		_, err := os.Stat(filepath.Join(dir, "held"))
		return os.IsNotExist(err)
	}, "the ended session's pin and directory to go")
}

// TestAConstrainedMappingEventPinsItsSession is PLAN §5.3's half: on a
// platform whose account name carries no login, the mapping event is the only
// attribution there is, so its session is pinned before the event is written.
func TestAConstrainedMappingEventPinsItsSession(t *testing.T) {
	shipper, server := newTestShipper(t, func(o *Options) {
		o.BatchSize = 1
		o.BufferMaxBytes = 16 << 10
		o.RetryMin = time.Hour
	})
	server.setDown(true)
	sink := shipper.DeviceSink()

	sink.AccountMapping(target.AccountMapping{
		Account: "hl-ab12xy7q9w", SessionID: "constrained", Subject: "alice@example.com",
		Target: "fw-1:22", Platform: "fortios", Constrained: true, At: testEpoch,
	})
	sink.AccountMapping(target.AccountMapping{
		Account: "hl-ab12-alice-7q9w", SessionID: "readable", Subject: "bob@example.com",
		Target: "fw-2:22", Platform: "fortios", Constrained: false, At: testEpoch,
	})
	handled(t, shipper)
	if _, err := os.Stat(filepath.Join(shipper.buffer.dir, "constrained", pinMarker)); err != nil {
		t.Fatalf("a constrained session's mapping event did not pin it: %v", err)
	}
	if _, err := os.Stat(filepath.Join(shipper.buffer.dir, "readable", pinMarker)); !os.IsNotExist(err) {
		t.Errorf("a readable account name pinned its session (err=%v); its attribution is the name itself", err)
	}

	// A flood cannot push the only attribution there is out of the buffer.
	for i := range 40 {
		shipper.Record(capture("flood", i, 3000))
	}
	handled(t, shipper)
	if got := tagged(t, shipper.buffer.dir, "constrained", tagPriority); len(got) != 1 {
		t.Fatalf("the constrained mapping event was evicted: %v", got)
	}
}
