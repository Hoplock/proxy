// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// record is one ordinary record for a shipper test.
func record(sessionID, message string) control.LogRecord {
	return control.LogRecord{
		SessionID: sessionID,
		Timestamp: time.Now().UTC(),
		Kind:      control.LogKindCommand,
		Severity:  control.SeverityInfo,
		Message:   message,
	}
}

func critical(sessionID, message string) control.LogRecord {
	rec := record(sessionID, message)
	rec.Kind = control.LogKindPolicyDecision
	rec.Severity = control.SeverityCritical
	return rec
}

// TestABatchIsSentWhenItFills is D8's throughput path: records accumulate and
// leave as one request, not as one request each.
func TestABatchIsSentWhenItFills(t *testing.T) {
	shipper, server := newTestShipper(t, nil) // BatchSize 4, no interval

	for i := range 3 {
		shipper.Record(record("sess-1", fmt.Sprintf("record %d", i)))
	}
	// Three records is not a batch, and nothing else is going to trigger one.
	time.Sleep(50 * time.Millisecond)
	if got := server.batchCount(); got != 0 {
		t.Fatalf("%d batches sent before the batch was full, want 0", got)
	}

	shipper.Record(record("sess-1", "record 3"))
	eventually(t, func() bool { return server.batchCount() == 1 }, "the full batch to be sent")

	if got, want := len(server.batchedRecords()), 4; got != want {
		t.Errorf("delivered %d records, want %d", got, want)
	}
	if got := shipper.Stats().Batched; got != 4 {
		t.Errorf("Stats().Batched = %d, want 4", got)
	}
}

// TestAPartialBatchLeavesOnTheFlushInterval is the other trigger: an idle
// session's records must not sit forever waiting for a batch to fill.
func TestAPartialBatchLeavesOnTheFlushInterval(t *testing.T) {
	shipper, server := newTestShipper(t, func(o *Options) {
		o.FlushInterval = 20 * time.Millisecond
		o.BatchSize = 1000
	})

	shipper.Record(record("sess-1", "lonely"))
	eventually(t, func() bool { return len(server.batchedRecords()) == 1 }, "the interval flush")
}

// TestACriticalRecordDoesNotWaitForTheBatch is the acceptance criterion for
// D8's priority path, stated as timing: with interval flushing off and the
// batch nowhere near full, a critical record still reaches the server.
func TestACriticalRecordDoesNotWaitForTheBatch(t *testing.T) {
	shipper, server := newTestShipper(t, func(o *Options) {
		o.BatchSize = 1000   // a batch that will never fill
		o.FlushInterval = -1 // and no interval to fall back on
	})

	shipper.Record(record("sess-1", "context"))
	shipper.RecordPriority(critical("sess-1", "command blocked by policy"))

	eventually(t, func() bool { return len(server.priorityRecords()) == 1 }, "the priority record")
	if got := server.priorityRecords()[0].Message; got != "command blocked by policy" {
		t.Errorf("priority record = %q, want the blocked command", got)
	}
	if got := shipper.Stats().Priority; got != 1 {
		t.Errorf("Stats().Priority = %d, want 1", got)
	}
}

// TestACriticalRecordFlushesWhatCameBeforeIt is the ordering half of D8's
// "flush the in-flight batch OR use a dedicated priority path": this shipper
// does both, so the context of a blocked command is never delivered after the
// block itself.
func TestACriticalRecordFlushesWhatCameBeforeIt(t *testing.T) {
	shipper, server := newTestShipper(t, func(o *Options) {
		o.BatchSize = 1000
		o.FlushInterval = -1
	})

	shipper.Record(record("sess-1", "the user opened a shell"))
	shipper.Record(record("sess-1", "the user ran a command"))
	shipper.RecordPriority(critical("sess-1", "and it was blocked"))

	eventually(t, func() bool { return len(server.priorityRecords()) == 1 }, "the priority record")

	// The batch went first, and it was complete: both records that preceded
	// the block are at the server by the time the block is.
	if got, want := messages(server.batchedRecords()),
		[]string{"the user opened a shell", "the user ran a command"}; !equalStrings(got, want) {
		t.Errorf("batched %v, want %v delivered before the critical record", got, want)
	}
}

// TestFlushDeliversEverythingQueued is what shutdown and the tests rely on.
func TestFlushDeliversEverythingQueued(t *testing.T) {
	shipper, server := newTestShipper(t, func(o *Options) { o.BatchSize = 1000 })

	for i := range 5 {
		shipper.Record(record("sess-1", fmt.Sprintf("record %d", i)))
	}
	flush(t, shipper)

	if got, want := len(server.batchedRecords()), 5; got != want {
		t.Errorf("flush delivered %d records, want %d", got, want)
	}
}

// TestCloseShipsWhatIsStillQueued is the shutdown guarantee: the last session's
// records are not abandoned because the process is stopping.
func TestCloseShipsWhatIsStillQueued(t *testing.T) {
	server := &fakeControl{}
	shipper, err := New(Options{
		Client:        server,
		BatchSize:     1000,
		FlushInterval: -1,
		BufferDir:     t.TempDir(),
		Logf:          t.Logf,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	shipper.Record(record("sess-1", "last words"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := shipper.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got, want := len(server.batchedRecords()), 1; got != want {
		t.Errorf("Close delivered %d records, want %d", got, want)
	}
}

// TestAFullQueueBuffersRatherThanBlocking states the rule that keeps telemetry
// off a session's critical path: a capture point never waits, and never loses
// a record either.
func TestAFullQueueBuffersRatherThanBlocking(t *testing.T) {
	server := &fakeControl{}
	server.setDown(true) // nothing drains, so the queue is the only sink
	dir := t.TempDir()
	shipper, err := New(Options{
		Client:        server,
		QueueSize:     1,
		BatchSize:     1000,
		FlushInterval: -1,
		RetryMin:      time.Hour, // no drain attempt during the test
		BufferDir:     dir,
		Logf:          t.Logf,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shipper.Close(ctx)
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 200 {
			shipper.Record(record("sess-1", fmt.Sprintf("record %d", i)))
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Record blocked on a full queue; a capture point must never wait on telemetry")
	}

	eventually(t, func() bool {
		stats := shipper.Stats()
		return stats.Buffered > 0 && stats.Dropped == 0
	}, "the overflow to reach the disk buffer")
}

// TestAShipperWithoutABufferCountsWhatItLoses keeps the honest reading of "no
// buffer configured": records are lost, and the number is visible rather than
// pretended away.
func TestAShipperWithoutABufferCountsWhatItLoses(t *testing.T) {
	server := &fakeControl{}
	server.setDown(true)
	shipper, err := New(Options{Client: server, BatchSize: 1, FlushInterval: -1, Logf: t.Logf})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shipper.Close(ctx)
	})

	shipper.Record(record("sess-1", "lost"))
	eventually(t, func() bool { return shipper.Stats().Dropped == 1 }, "the drop to be counted")
	if got := shipper.Stats().Buffered; got != 0 {
		t.Errorf("Stats().Buffered = %d with no buffer configured, want 0", got)
	}
}

// TestNewRejectsAShipperWithNoClient keeps the one required option required.
func TestNewRejectsAShipperWithNoClient(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("New accepted a shipper with no management client")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
