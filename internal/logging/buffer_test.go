// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// TestAnOutageBuffersToDiskAndDrainsOnRecovery is PLAN §7's resilience
// requirement end to end: with Hoplock Control down the records go to disk,
// and when it returns every one of them arrives — in order, on the endpoint it
// was owed to, and with nothing left behind.
func TestAnOutageBuffersToDiskAndDrainsOnRecovery(t *testing.T) {
	dir := t.TempDir()
	shipper, server := newTestShipper(t, func(o *Options) {
		o.BufferDir = dir
		o.BatchSize = 2
	})

	server.setDown(true)
	for i := range 4 {
		shipper.Record(record("sess-1", fmt.Sprintf("record %d", i)))
	}
	shipper.RecordPriority(critical("sess-1", "blocked during the outage"))

	eventually(t, func() bool { return shipper.Stats().Buffered >= 5 }, "the records to reach the buffer")
	if got := len(server.delivered()); got != 0 {
		t.Fatalf("%d records reached a server that is down", got)
	}
	if !shipper.Stats().Degraded {
		t.Error("the shipper does not report itself degraded while records are on disk")
	}
	// The buffer is a directory per session (PLAN §7).
	if _, err := os.Stat(filepath.Join(dir, "sess-1")); err != nil {
		t.Errorf("no per-session buffer area: %v", err)
	}

	server.setDown(false)
	eventually(t, func() bool { return shipper.Stats().Drained >= 5 }, "the buffer to drain")

	// Nothing lost: every record arrives, in the order it was made.
	if got, want := messages(server.batchedRecords()),
		[]string{"record 0", "record 1", "record 2", "record 3"}; !equalStrings(got, want) {
		t.Errorf("drained batch records %v, want %v", got, want)
	}
	// And the critical one is still critical: an outage does not downgrade a
	// blocked command to ordinary telemetry.
	if got := server.priorityRecords(); len(got) != 1 || got[0].Message != "blocked during the outage" {
		t.Errorf("priority records after the drain = %v, want the blocked command", messages(got))
	}
	if got := shipper.Stats().Dropped; got != 0 {
		t.Errorf("Stats().Dropped = %d after a recovered outage, want 0", got)
	}

	// The buffer is empty again: it is a buffer, not a destination.
	eventually(t, func() bool { return shipper.Stats().Segments == 0 }, "the buffer to empty")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read buffer dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("buffer directory still holds %d entries after draining", len(entries))
	}
}

// TestRecordsMadeDuringAnOutageDoNotOvertakeBufferedOnes is the ordering rule
// the buffer exists to keep: while anything is owed to the server, new records
// join the back of the queue on disk rather than being sent ahead of it.
func TestRecordsMadeDuringAnOutageDoNotOvertakeBufferedOnes(t *testing.T) {
	shipper, server := newTestShipper(t, func(o *Options) { o.BatchSize = 1 })

	server.setDown(true)
	shipper.Record(record("sess-1", "first"))
	eventually(t, func() bool { return shipper.Stats().Buffered == 1 }, "the first record to buffer")

	// The server is up again, but the buffer still holds the first record.
	// The second must not be delivered before it.
	server.setDown(false)
	shipper.Record(record("sess-1", "second"))

	eventually(t, func() bool { return len(server.batchedRecords()) == 2 }, "both records")
	if got, want := messages(server.batchedRecords()), []string{"first", "second"}; !equalStrings(got, want) {
		t.Errorf("delivered %v, want %v", got, want)
	}
}

// TestAPreviousRunsBufferIsAdoptedAndDrained is the crash case: a proxy that
// died mid-outage left records nobody else will ship, and the next run ships
// them.
func TestAPreviousRunsBufferIsAdoptedAndDrained(t *testing.T) {
	dir := t.TempDir()

	// A run that buffered and then stopped without recovering.
	first := &fakeControl{}
	first.setDown(true)
	shipper, err := New(Options{Client: first, BatchSize: 1, FlushInterval: -1, RetryMin: time.Hour, BufferDir: dir, Logf: t.Logf})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	shipper.Record(record("sess-1", "from the previous run"))
	eventually(t, func() bool { return shipper.Stats().Buffered == 1 }, "the record to buffer")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = shipper.Close(ctx)

	// The next run, against a server that is up.
	second := &fakeControl{}
	next, err := New(Options{
		Client: second, BatchSize: 1, FlushInterval: -1,
		RetryMin: 10 * time.Millisecond, RetryMax: 20 * time.Millisecond,
		BufferDir: dir, Logf: t.Logf,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = next.Close(ctx) })

	eventually(t, func() bool { return len(second.batchedRecords()) == 1 }, "the adopted record to drain")
	if got := second.batchedRecords()[0].Message; got != "from the previous run" {
		t.Errorf("drained %q, want the previous run's record", got)
	}
}

// TestABufferedBatchIsSplitPerSession keeps the "one area per session" layout
// true for a batch that carried several sessions' records.
func TestABufferedBatchIsSplitPerSession(t *testing.T) {
	dir := t.TempDir()
	shipper, server := newTestShipper(t, func(o *Options) {
		o.BufferDir = dir
		o.BatchSize = 2
		o.RetryMin = time.Hour
	})

	server.setDown(true)
	shipper.Record(record("sess-a", "from a"))
	shipper.Record(record("sess-b", "from b"))
	eventually(t, func() bool { return shipper.Stats().Buffered == 2 }, "both records to buffer")

	for _, session := range []string{"sess-a", "sess-b"} {
		if _, err := os.Stat(filepath.Join(dir, session)); err != nil {
			t.Errorf("no buffer area for %s: %v", session, err)
		}
	}
}

// TestAnUnreadableSegmentIsDiscardedRatherThanBlockingTheDrain keeps a corrupt
// file from stopping every later record forever. The loss is counted, because
// silently losing an audit record is the failure this whole file exists to
// avoid.
func TestAnUnreadableSegmentIsDiscardedRatherThanBlockingTheDrain(t *testing.T) {
	dir := t.TempDir()
	sessionDir := filepath.Join(dir, "sess-1")
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	name := fmt.Sprintf("%0*d.%s%s", segmentSeqWidth, 0, kindBatch, segmentSuffix)
	if err := os.WriteFile(filepath.Join(sessionDir, name), []byte("{not json\n"), 0o600); err != nil {
		t.Fatalf("write segment: %v", err)
	}

	server := &fakeControl{}
	shipper, err := New(Options{
		Client: server, BatchSize: 1, FlushInterval: -1,
		RetryMin: 10 * time.Millisecond, RetryMax: 20 * time.Millisecond,
		BufferDir: dir, Logf: t.Logf,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	t.Cleanup(func() { _ = shipper.Close(ctx) })

	eventually(t, func() bool { return shipper.Stats().Dropped == 1 }, "the corrupt segment to be discarded")

	// And the drain keeps working afterwards.
	shipper.Record(record("sess-1", "after the corruption"))
	eventually(t, func() bool { return len(server.batchedRecords()) == 1 }, "delivery to resume")
}

// TestSegmentsSortIntoTheOrderTheyWereWritten pins the property the file names
// carry: lexical order is delivery order, across sessions as well as within
// one.
func TestSegmentsSortIntoTheOrderTheyWereWritten(t *testing.T) {
	buffer, err := newDiskBuffer(t.TempDir())
	if err != nil {
		t.Fatalf("newDiskBuffer: %v", err)
	}
	for i := range 12 {
		session := fmt.Sprintf("sess-%d", i%3)
		if err := buffer.append(session, kindBatch, []control.LogRecord{record(session, fmt.Sprintf("%d", i))}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	segs, err := buffer.segments()
	if err != nil {
		t.Fatalf("segments: %v", err)
	}
	if len(segs) != 12 {
		t.Fatalf("got %d segments, want 12", len(segs))
	}
	for i, seg := range segs {
		if seg.seq != uint64(i) {
			t.Fatalf("segment %d has sequence %d, want %d: the drain order is wrong", i, seg.seq, i)
		}
	}
}

// TestASessionIDNeverEscapesTheBufferDirectory is the rule a telemetry buffer
// must not break, whatever it is handed.
func TestASessionIDNeverEscapesTheBufferDirectory(t *testing.T) {
	for _, id := range []string{"../../etc", "a/b", "", strings.Repeat("x", 300)} {
		name := sessionDirName(id)
		if name == "" || strings.Contains(name, "/") || strings.Contains(name, "..") {
			t.Errorf("sessionDirName(%q) = %q, which is not a safe directory name", id, name)
		}
	}
	// Two ids that sanitise to the same characters must not share a directory:
	// one session's records must never land in another's area.
	if sessionDirName("a/b") == sessionDirName("a:b") {
		t.Error("two different session ids collided into one buffer directory")
	}
}
