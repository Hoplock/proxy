// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// The bounded buffer (phase 0046, buffer.go): the window, the classes it evicts
// in, what it never evicts, and the report every eviction leaves.

// testEpoch keeps every record's encoding — and so every file's size — the same
// from run to run.
var testEpoch = time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

// capture is a stream-capture record carrying n bytes of payload.
func capture(sessionID string, i, n int) control.LogRecord {
	return control.LogRecord{
		RecordID:  fmt.Sprintf("%s-%05d", sessionID, i),
		SessionID: sessionID,
		Timestamp: testEpoch.Add(time.Duration(i) * time.Millisecond),
		Kind:      control.LogKindStream,
		Severity:  control.SeverityInfo,
		Payload:   bytes.Repeat([]byte{'x'}, n),
	}
}

// metadata is a record of the given kind and severity, padded to about n bytes
// so that files of every class can be made the same size.
func metadata(sessionID string, i int, kind control.LogKind, severity control.Severity, n int) control.LogRecord {
	return control.LogRecord{
		RecordID:  fmt.Sprintf("%s-%05d", sessionID, i),
		SessionID: sessionID,
		Timestamp: testEpoch.Add(time.Duration(i) * time.Millisecond),
		Kind:      kind,
		Severity:  severity,
		Message:   strings.Repeat("m", n),
	}
}

// handled waits until every record handed to the shipper so far has been
// delivered, spilled or evicted: a flush processes the queue before it drains,
// and its drain error — the server is often down on purpose — is not the point.
func handled(t *testing.T, s *Shipper) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.Flush(ctx)
}

func newTestBuffer(t *testing.T, dir string, window int64) *diskBuffer {
	t.Helper()
	b, err := newDiskBuffer(bufferOptions{dir: dir, window: window, now: func() time.Time { return testEpoch }, logf: t.Logf})
	if err != nil {
		t.Fatalf("newDiskBuffer: %v", err)
	}
	return b
}

func mustAppend(t *testing.T, b *diskBuffer, sessionID string, tag fileTag, recs ...control.LogRecord) bool {
	t.Helper()
	evicted, err := b.appendSegment(sessionID, tag, recs)
	if err != nil {
		t.Fatalf("appendSegment: %v", err)
	}
	return evicted
}

// sessionFiles is what an operator's ls of one session's directory shows,
// minus the directory's own dot-files.
func sessionFiles(t *testing.T, dir, sessionID string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, sessionDirName(sessionID)))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read session buffer: %v", err)
	}
	var names []string
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") {
			names = append(names, e.Name())
		}
	}
	return names
}

// tagged is the files of one tag, by their records' ids — which is what says
// which records survived.
func tagged(t *testing.T, dir, sessionID string, tag fileTag) []string {
	t.Helper()
	var ids []string
	for _, name := range sessionFiles(t, dir, sessionID) {
		if _, got, ok := parseFileName(name); ok && got == tag {
			recs, err := loadRecords(filepath.Join(dir, sessionDirName(sessionID), name))
			if err != nil {
				t.Fatalf("load %s: %v", name, err)
			}
			for _, rec := range recs {
				ids = append(ids, rec.RecordID)
			}
		}
	}
	return ids
}

// diskBytes is every byte of every file under dir: what the buffer's own count
// has to match.
func diskBytes(t *testing.T, dir string) int64 {
	t.Helper()
	var total int64
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	})
	if err != nil {
		t.Fatalf("walk buffer: %v", err)
	}
	return total
}

// gapRecords reads every logging.gap record a session's directory holds.
func gapRecords(t *testing.T, dir, sessionID string) []control.LogRecord {
	t.Helper()
	var out []control.LogRecord
	for _, name := range sessionFiles(t, dir, sessionID) {
		if _, tag, ok := parseFileName(name); ok && tag.isGap() {
			recs, err := loadRecords(filepath.Join(dir, sessionDirName(sessionID), name))
			if err != nil {
				t.Fatalf("load %s: %v", name, err)
			}
			out = append(out, recs...)
		}
	}
	return out
}

func encodedLen(t *testing.T, recs ...control.LogRecord) int64 {
	t.Helper()
	data, _, err := encodeRecords(recs)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return int64(len(data))
}

func gapInt(t *testing.T, rec control.LogRecord, key string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(rec.Attributes[key], 10, 64)
	if err != nil {
		t.Fatalf("gap record %s=%q is not a number", key, rec.Attributes[key])
	}
	return n
}

// TestTheBufferCountsEveryByteItHolds is the window's unit of account: every
// file counts — segments of every class, set-aside records, gap records — and
// the count is the disk's, before a restart and after one.
func TestTheBufferCountsEveryByteItHolds(t *testing.T) {
	dir := t.TempDir()
	b := newTestBuffer(t, dir, 1<<30)

	mustAppend(t, b, "sess-a", tagBatch, metadata("sess-a", 0, control.LogKindAuth, control.SeverityInfo, 10))
	mustAppend(t, b, "sess-a", tagStream, capture("sess-a", 1, 100), capture("sess-a", 2, 300))
	mustAppend(t, b, "sess-a", tagPriority, metadata("sess-a", 3, control.LogKindPolicyDecision, control.SeverityCritical, 20))
	mustAppend(t, b, "sess-b", tagRefused, metadata("sess-b", 4, control.LogKindCommand, control.SeverityInfo, 30))
	report := newGapTally("gap-1", GapCauseRefused, "sess-b")
	report.add(metadata("sess-b", 4, control.LogKindCommand, control.SeverityInfo, 30), 100)
	if err := b.putGap(report.record(testEpoch), false); err != nil {
		t.Fatalf("putGap: %v", err)
	}

	if got, want := b.stats().bytes, diskBytes(t, dir); got != want {
		t.Fatalf("the buffer counts %d bytes; the disk holds %d", got, want)
	}

	// Delivering one file takes exactly its bytes off the count.
	records, _ := b.owedFiles()
	c, ok := b.claim(records[0])
	if !ok {
		t.Fatal("could not claim the oldest file")
	}
	if err := b.settle(c, nil, 1); err != nil {
		t.Fatalf("settle: %v", err)
	}
	if got, want := b.stats().bytes, diskBytes(t, dir); got != want {
		t.Fatalf("after a delivery the buffer counts %d bytes; the disk holds %d", got, want)
	}

	// And a new run recomputes it from the disk, not from anything it was told.
	adopted := newTestBuffer(t, dir, 1<<30)
	if got, want := adopted.stats().bytes, diskBytes(t, dir); got != want {
		t.Fatalf("an adopted buffer counts %d bytes; the disk holds %d", got, want)
	}
	// A set-aside record is kept but owed nothing; everything else is owed.
	if got := adopted.stats().owed; got != 3 {
		t.Errorf("the adopted buffer owes %d files, want 3 (stream, priority, the report)", got)
	}
}

// TestEvictionTakesTheLowestClassOldestFirst is the order the window evicts
// in: set-aside records, then stream capture, then other batch records, then
// priority records, oldest first within each — and an append ranked below
// everything left is evicted itself rather than displacing anything above it.
func TestEvictionTakesTheLowestClassOldestFirst(t *testing.T) {
	const pad = 4000 // every file is one record of about this size
	var i int
	next := func(kind control.LogKind, severity control.Severity) control.LogRecord {
		i++
		if kind == control.LogKindStream {
			return capture("sess-a", i, pad*3/4) // base64 makes it pad long
		}
		return metadata("sess-a", i, kind, severity, pad)
	}
	set := []struct {
		tag fileTag
		rec control.LogRecord
	}{
		{tagRefused, next(control.LogKindCommand, control.SeverityInfo)},             // A1
		{tagStream, next(control.LogKindStream, control.SeverityInfo)},               // S1
		{tagStream, next(control.LogKindStream, control.SeverityInfo)},               // S2
		{tagBatch, next(control.LogKindCommand, control.SeverityInfo)},               // B1
		{tagBatch, next(control.LogKindCommand, control.SeverityInfo)},               // B2
		{tagPriority, next(control.LogKindPolicyDecision, control.SeverityCritical)}, // P1
	}
	var window int64 = 2048 // room for the report, never for another file
	for _, f := range set {
		window += encodedLen(t, f.rec)
	}

	dir := t.TempDir()
	b := newTestBuffer(t, dir, window)
	for _, f := range set {
		if mustAppend(t, b, "sess-a", f.tag, f.rec) {
			t.Fatalf("an append into an empty window was evicted")
		}
	}
	id := func(n int) string { return set[n].rec.RecordID }

	steps := []struct {
		what    string
		tag     fileTag
		rec     control.LogRecord
		evicted string // which record the append costs, "" for the append itself
	}{
		{"a batch record evicts the set-aside record", tagBatch, next(control.LogKindCommand, control.SeverityInfo), id(0)},
		{"then the oldest stream capture", tagBatch, next(control.LogKindCommand, control.SeverityInfo), id(1)},
		{"then the next", tagBatch, next(control.LogKindCommand, control.SeverityInfo), id(2)},
		{"then the oldest batch record", tagBatch, next(control.LogKindCommand, control.SeverityInfo), id(3)},
		{"a priority record evicts batch records before priority ones", tagPriority,
			next(control.LogKindPolicyDecision, control.SeverityCritical), id(4)},
		{"stream capture ranked below everything left is evicted itself", tagStream, next(control.LogKindStream, control.SeverityInfo), ""},
		{"so is a set-aside record", tagRefused, next(control.LogKindCommand, control.SeverityInfo), ""},
	}
	held := map[string]bool{}
	for _, f := range set {
		held[f.rec.RecordID] = true
	}
	for _, step := range steps {
		before := b.stats().evicted
		selfEvicted := mustAppend(t, b, "sess-a", step.tag, step.rec)
		if got := b.stats().evicted - before; got != 1 {
			t.Fatalf("%s: %d records evicted, want exactly 1", step.what, got)
		}
		if step.evicted == "" {
			if !selfEvicted {
				t.Fatalf("%s: the append was written, displacing a record ranked above it", step.what)
			}
			continue
		}
		if selfEvicted {
			t.Fatalf("%s: the append itself was evicted", step.what)
		}
		delete(held, step.evicted)
		held[step.rec.RecordID] = true
		var present []string
		for _, tag := range []fileTag{tagRefused, tagStream, tagBatch, tagPriority} {
			present = append(present, tagged(t, dir, "sess-a", tag)...)
		}
		for rid := range held {
			if !slices.Contains(present, rid) {
				t.Fatalf("%s: %s was evicted, want %s", step.what, rid, step.evicted)
			}
		}
		if slices.Contains(present, step.evicted) {
			t.Fatalf("%s: %s is still there", step.what, step.evicted)
		}
	}
	if got, window := b.stats().bytes, b.window; got > window {
		t.Errorf("the buffer holds %d bytes over a window of %d with nothing pinned", got, window)
	}

	// One report for the whole run, counting every record the run evicted.
	gaps := gapRecords(t, dir, "sess-a")
	if len(gaps) != 1 {
		t.Fatalf("%d gap records for one session and one cause, want 1", len(gaps))
	}
	gap := gaps[0]
	if got, want := gapInt(t, gap, AttrGapRecords), int64(b.stats().evicted); got != want || want != 7 {
		t.Errorf("the report counts %d records, the buffer evicted %d; want 7", got, want)
	}
	if got := gap.Attributes[AttrGapKinds]; got != "command,stream" {
		t.Errorf("gap_kinds = %q, want %q", got, "command,stream")
	}
	if got := gap.Attributes[AttrGapCritical]; got != "0" {
		t.Errorf("gap_critical = %q with no critical record evicted", got)
	}
	if gap.Severity != control.SeverityWarn || gap.Kind != control.LogKindError {
		t.Errorf("the report is %s/%s, want error/warn", gap.Kind, gap.Severity)
	}
}

// TestAPinnedSessionIsNeverEvicted is D16's claim surviving a bounded buffer: a
// session whose record is a bound keeps every record it spilled — the ones made
// before the pin included — while another session's flood evicts everything
// else, and a pinned append is written even over the window.
func TestAPinnedSessionIsNeverEvicted(t *testing.T) {
	dir := t.TempDir()
	const window = 64 << 10
	b := newTestBuffer(t, dir, window)

	// The handshake and the authentication, spilled before anyone knew the
	// route would require capture.
	mustAppend(t, b, "held", tagBatch, metadata("held", 0, control.LogKindSessionStart, control.SeverityInfo, 200))
	mustAppend(t, b, "held", tagBatch, metadata("held", 1, control.LogKindAuth, control.SeverityInfo, 200))
	if err := b.pin("held"); err != nil {
		t.Fatalf("pin: %v", err)
	}
	mustAppend(t, b, "held", tagStream, capture("held", 2, 1000))
	heldBefore := sessionFiles(t, dir, "held")

	// A flood many windows deep from somebody else.
	for i := range 100 {
		mustAppend(t, b, "flood", tagStream, capture("flood", i, 4000))
	}
	if got := sessionFiles(t, dir, "held"); !slices.Equal(got, heldBefore) {
		t.Fatalf("the pinned session's files went from %v to %v", heldBefore, got)
	}
	if got := b.stats().bytes; got > window {
		t.Errorf("the buffer holds %d bytes over a window of %d while only its own records were pinned", got, window)
	}

	// A pinned append bigger than everything evictable is written anyway.
	big := capture("held", 3, window)
	if mustAppend(t, b, "held", tagStream, big) {
		t.Fatal("a pinned append was evicted")
	}
	if got := tagged(t, dir, "held", tagStream); !slices.Contains(got, big.RecordID) {
		t.Fatalf("the pinned append is not on disk: %v", got)
	}
	if got := tagged(t, dir, "flood", tagStream); len(got) != 0 {
		t.Errorf("the flood still holds %d records the pinned append should have displaced", len(got))
	}
	if b.hasRoomForPin() {
		t.Errorf("pinned bytes %d reached the window %d and a new pin is still promised room",
			b.stats().pinned, int64(window))
	}
}

// TestPinsSurviveARestart is the crash the buffer exists for, with pins: a new
// run adopts a pinned session pinned, and an adopted buffer over a lowered
// window is evicted down to it at start — pinned files excepted, and reported.
func TestPinsSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	first := newTestBuffer(t, dir, 1<<30)
	for i := range 4 {
		mustAppend(t, first, "held", tagStream, capture("held", i, 4000))
		mustAppend(t, first, "other", tagStream, capture("other", i, 4000))
	}
	if err := first.pin("held"); err != nil {
		t.Fatalf("pin: %v", err)
	}
	heldFiles := sessionFiles(t, dir, "held")

	// The next run, with the window lowered to less than the pinned session alone.
	next := newTestBuffer(t, dir, 8000)
	if got := sessionFiles(t, dir, "held"); !slices.Equal(got, heldFiles) {
		t.Fatalf("the pinned session's files went from %v to %v across the restart", heldFiles, got)
	}
	if got := tagged(t, dir, "other", tagStream); len(got) != 0 {
		t.Errorf("an unpinned session kept %v over a lowered window", got)
	}
	gaps := gapRecords(t, dir, "other")
	if len(gaps) != 1 || gapInt(t, gaps[0], AttrGapRecords) != 4 {
		t.Fatalf("the eviction at start was reported as %v, want one report of 4 records", gaps)
	}
	// Everything left is pinned: the pinned session's files, and the report,
	// which is never evicted either.
	if got, want := next.stats().pinned, diskBytes(t, dir); got != want {
		t.Errorf("adopted pinned bytes = %d, want %d: the pinned session's files and the report", got, want)
	}
	if next.hasRoomForPin() {
		t.Error("a window full of adopted pinned records still promises a new pin room")
	}
}

// TestAnEndedSessionsPinGoesWithItsLastRecord keeps pins from accumulating: once
// the session has ended and nothing of it is left on disk, the marker and the
// directory go.
func TestAnEndedSessionsPinGoesWithItsLastRecord(t *testing.T) {
	dir := t.TempDir()
	b := newTestBuffer(t, dir, 1<<30)
	if err := b.pin("held"); err != nil {
		t.Fatalf("pin: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "held", pinMarker)); err != nil {
		t.Fatalf("no durable pin marker: %v", err)
	}
	mustAppend(t, b, "held", tagBatch, metadata("held", 0, control.LogKindSessionEnd, control.SeverityInfo, 10))

	// Ended, but its last record is still owed: the pin stays with it.
	b.release("held")
	if _, err := os.Stat(filepath.Join(dir, "held", pinMarker)); err != nil {
		t.Fatalf("the pin went while the session's record was still on disk: %v", err)
	}
	records, _ := b.owedFiles()
	c, ok := b.claim(records[0])
	if !ok {
		t.Fatal("claim")
	}
	if err := b.settle(c, nil, 1); err != nil {
		t.Fatalf("settle: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "held")); !os.IsNotExist(err) {
		t.Errorf("the ended session's directory outlived its last record (err=%v)", err)
	}
}

// TestGapRecordsCoalesceOverALongEvictionRun is what bounds the reports by the
// sessions affected rather than by the length of the outage.
func TestGapRecordsCoalesceOverALongEvictionRun(t *testing.T) {
	shipper, server := newTestShipper(t, func(o *Options) {
		o.BatchSize = 1
		o.BufferMaxBytes = 32 << 10
		o.RetryMin = time.Hour
	})
	server.setDown(true)
	for i := range 200 {
		shipper.Record(capture("sess-a", i, 2000))
	}
	handled(t, shipper)

	gaps := gapRecords(t, shipper.buffer.dir, "sess-a")
	if len(gaps) != 1 {
		t.Fatalf("%d undelivered gap records for one session and cause after a long eviction run, want 1", len(gaps))
	}
	if got, want := gapInt(t, gaps[0], AttrGapRecords), int64(shipper.Stats().Evicted); got != want {
		t.Errorf("the report counts %d records; %d were evicted", got, want)
	}
}

// TestTheWindowHoldsAndTheNewestRecordsArrive is the window end to end on the
// shipper: an outage and a session producing far more capture than the window
// leave the buffer within it, and recovery delivers the newest records plus one
// report whose numbers are the evicted records' own.
func TestTheWindowHoldsAndTheNewestRecordsArrive(t *testing.T) {
	const window = 48 << 10
	shipper, server := newTestShipper(t, func(o *Options) {
		o.BatchSize = 4
		o.BufferMaxBytes = window
		o.RetryMin = time.Hour // recovery is the explicit flush below
	})
	server.setDown(true)
	var made []control.LogRecord
	for i := range 160 {
		rec := capture("sess-a", i, 1500)
		if i%40 == 7 {
			rec = metadata("sess-a", i, control.LogKindPolicyDecision, control.SeverityInfo, 100)
		}
		made = append(made, rec)
		shipper.Record(rec)
	}
	handled(t, shipper)

	if got := shipper.Stats().BufferedBytes; got > window {
		t.Fatalf("the buffer holds %d bytes over its window of %d with nothing pinned", got, window)
	}
	if got, want := shipper.Stats().BufferedBytes, diskBytes(t, shipper.buffer.dir); got != want {
		t.Fatalf("the buffer counts %d bytes; the disk holds %d", got, want)
	}

	server.setDown(false)
	flush(t, shipper)

	delivered := map[string]bool{}
	var gaps []control.LogRecord
	for _, rec := range server.delivered() {
		if isGapRecord(rec) {
			gaps = append(gaps, rec)
			continue
		}
		delivered[rec.RecordID] = true
	}
	if !delivered[made[len(made)-1].RecordID] {
		t.Error("the newest record did not arrive; the window must evict the oldest")
	}
	var missing []control.LogRecord
	for _, rec := range made {
		if !delivered[rec.RecordID] {
			missing = append(missing, rec)
		}
	}
	if len(gaps) != 1 {
		t.Fatalf("%d gap records arrived for one affected session, want 1", len(gaps))
	}
	gap := gaps[0]
	if gap.SessionID != "sess-a" || gap.Attributes[AttrGapCause] != GapCauseEvicted {
		t.Errorf("the report is for session %q, cause %q", gap.SessionID, gap.Attributes[AttrGapCause])
	}
	if got := gapInt(t, gap, AttrGapRecords); got != int64(len(missing)) {
		t.Errorf("gap_records = %d; %d records did not arrive", got, len(missing))
	}
	if got, want := uint64(gapInt(t, gap, AttrGapRecords)), shipper.Stats().Evicted; got != want {
		t.Errorf("Stats.Evicted = %d, but the report counts %d", want, got)
	}
	var wantBytes int64
	for _, rec := range missing {
		wantBytes += encodedLen(t, rec)
	}
	if got := gapInt(t, gap, AttrGapBytes); got != wantBytes {
		t.Errorf("gap_bytes = %d, want %d: the missing records' size on disk", got, wantBytes)
	}
	if got, want := gap.Attributes[AttrGapFirstAt], missing[0].Timestamp.Format(time.RFC3339Nano); got != want {
		t.Errorf("gap_first_at = %s, want %s", got, want)
	}
	if got, want := gap.Attributes[AttrGapLastAt], missing[len(missing)-1].Timestamp.Format(time.RFC3339Nano); got != want {
		t.Errorf("gap_last_at = %s, want %s", got, want)
	}
	// The flood was capture, and capture is all it cost: every metadata
	// record survived it, which is the attack the classes exist for.
	if got := gap.Attributes[AttrGapKinds]; got != string(control.LogKindStream) {
		t.Errorf("gap_kinds = %q: a capture flood evicted something other than capture", got)
	}
	for _, rec := range made {
		if rec.Kind != control.LogKindStream && !delivered[rec.RecordID] {
			t.Errorf("metadata record %s was evicted by a capture flood", rec.RecordID)
		}
	}
	if got := shipper.Stats().Dropped; got != 0 {
		t.Errorf("Stats.Dropped = %d: an eviction is reported, never a drop", got)
	}
}

// TestEvictionsSurviveACrash: a report written in the same critical section as
// the eviction reaches the server even when the run that evicted never
// recovered, and the next run's byte count is the disk's.
func TestEvictionsSurviveACrash(t *testing.T) {
	dir := t.TempDir()
	down := &fakeControl{}
	down.setDown(true)
	first, err := New(Options{Client: down, BatchSize: 1, FlushInterval: -1, RetryMin: time.Hour,
		BufferDir: dir, BufferMaxBytes: 16 << 10, Logf: t.Logf})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := range 40 {
		first.Record(capture("sess-a", i, 1500))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = first.Close(ctx) // cannot drain: the server is still down
	evicted := first.Stats().Evicted
	if evicted == 0 {
		t.Fatal("nothing was evicted; the test needs an eviction to lose")
	}

	up := &fakeControl{}
	next, err := New(Options{Client: up, BatchSize: 64, FlushInterval: -1, RetryMin: time.Hour,
		BufferDir: dir, BufferMaxBytes: 16 << 10, Logf: t.Logf})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = next.Close(ctx) })
	if got, want := next.Stats().BufferedBytes, diskBytes(t, dir); got != want {
		t.Fatalf("the adopted buffer counts %d bytes; the disk holds %d", got, want)
	}
	flush(t, next)

	var reported int64
	for _, rec := range up.delivered() {
		if isGapRecord(rec) {
			reported += gapInt(t, rec, AttrGapRecords)
		}
	}
	if reported != int64(evicted) {
		t.Errorf("after the restart the reports count %d evicted records; the crashed run evicted %d", reported, evicted)
	}
}

// TestTheDrainNeverEvictsTheFileItIsDelivering: eviction runs on whichever
// goroutine appends — a capture point spilling past a full queue included — so
// it has to leave alone the one file the drain has in flight. Run with -race.
func TestTheDrainNeverEvictsTheFileItIsDelivering(t *testing.T) {
	release := make(chan struct{})
	blocked := make(chan struct{})
	var once sync.Once
	shipper, server := newTestShipper(t, func(o *Options) {
		o.BatchSize = 1
		o.QueueSize = 1
		o.BufferMaxBytes = 24 << 10
		o.RetryMin = time.Hour
	})
	server.setDown(true)
	first := capture("first", 0, 4000)
	shipper.Record(first)
	eventually(t, func() bool { return shipper.Stats().Buffered == 1 }, "the first record to buffer")
	records, _ := shipper.buffer.owedFiles()
	inFlight := filepath.Join(shipper.buffer.dir, "first", fileName(records[0], tagStream))

	server.mu.Lock()
	server.down = false
	server.failBatch = func(int, []control.LogRecord) error {
		once.Do(func() { close(blocked); <-release })
		return nil
	}
	server.mu.Unlock()

	flushed := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		flushed <- shipper.Flush(ctx)
	}()
	<-blocked // the drain is delivering the first file, and waiting

	// Enough capture to evict the first file many times over, spilled from
	// this goroutine past the full queue.
	var wg sync.WaitGroup
	for g := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 20 {
				shipper.Record(capture(fmt.Sprintf("flood-%d", g), i, 4000))
			}
		}()
	}
	wg.Wait()
	if shipper.Stats().Evicted == 0 {
		t.Fatal("nothing was evicted; the window was never under pressure")
	}
	if _, err := os.Stat(inFlight); err != nil {
		t.Fatalf("the file the drain was delivering was evicted: %v", err)
	}

	close(release)
	if err := <-flushed; err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := server.batchedRecords(); len(got) == 0 || got[0].RecordID != first.RecordID {
		t.Fatalf("the record in flight was not delivered first: %v", got)
	}
}

// TestASentReportIsNeverRewritten: a report the drain has sent may already be
// on the server, which de-duplicates on record_id, so a later eviction must not
// change it under that id — the change would be dropped without a trace.
func TestASentReportIsNeverRewritten(t *testing.T) {
	dir := t.TempDir()
	b := newTestBuffer(t, dir, 16<<10)
	for i := range 8 {
		mustAppend(t, b, "sess-a", tagStream, capture("sess-a", i, 4000))
	}
	gaps := gapRecords(t, dir, "sess-a")
	if len(gaps) != 1 {
		t.Fatalf("%d reports, want 1", len(gaps))
	}
	_, reports := b.owedFiles()
	if len(reports) != 1 {
		t.Fatalf("%d reports owed, want 1", len(reports))
	}
	c, ok := b.claim(reports[0])
	if !ok {
		t.Fatal("could not claim the report")
	}
	sent, err := os.ReadFile(c.path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// The send timed out after the server may have stored it.
	if err := b.settle(c, gaps, 1); err != nil {
		t.Fatalf("settle: %v", err)
	}

	for i := 8; i < 12; i++ {
		mustAppend(t, b, "sess-a", tagStream, capture("sess-a", i, 4000))
	}
	now, err := os.ReadFile(c.path)
	if err != nil {
		t.Fatalf("the sent report is gone: %v", err)
	}
	if !bytes.Equal(now, sent) {
		t.Error("a report that was sent was rewritten under the same record_id")
	}
	after := gapRecords(t, dir, "sess-a")
	if len(after) != 2 {
		t.Fatalf("%d reports after more evictions, want the sent one and a new one", len(after))
	}
	var total int64
	for _, rec := range after {
		total += gapInt(t, rec, AttrGapRecords)
	}
	if total != int64(b.stats().evicted) {
		t.Errorf("the reports count %d records; %d were evicted", total, b.stats().evicted)
	}
	if after[0].RecordID == after[1].RecordID {
		t.Error("the new report reuses the sent one's record_id")
	}
}

// TestAGapRecordNeverBegetsAnother: a report that is itself evicted — one the
// server refused, sitting in the set-aside area — is counted and reported by
// nothing.
func TestAGapRecordNeverBegetsAnother(t *testing.T) {
	dir := t.TempDir()
	b := newTestBuffer(t, dir, 8<<10)
	refusedReport := newGapTally("gap-refused-1", GapCauseRefused, "sess-a")
	refusedReport.add(metadata("sess-a", 0, control.LogKindCommand, control.SeverityInfo, 10), 50)
	mustAppend(t, b, "sess-a", tagRefused, refusedReport.record(testEpoch))
	// Enough priority records to push the set-aside report out.
	for i := 1; i < 4; i++ {
		mustAppend(t, b, "sess-a", tagPriority, metadata("sess-a", i, control.LogKindPolicyDecision, control.SeverityCritical, 3000))
	}
	if got := tagged(t, dir, "sess-a", tagRefused); len(got) != 0 {
		t.Fatalf("the set-aside report was not evicted: %v", got)
	}
	// Counted as evicted, like anything else the window pushed out...
	evicted := int64(b.stats().evicted)
	if evicted < 1 {
		t.Fatal("the eviction was not counted")
	}
	// ...and reported by nothing: whatever else went is in a report, and the
	// report of the evicted report is the one that does not exist.
	var reported int64
	for _, gap := range gapRecords(t, dir, "sess-a") {
		if strings.Contains(gap.Attributes[AttrGapKinds], string(control.LogKindError)) {
			t.Errorf("an evicted gap record begot another: %v", gap.Attributes)
		}
		reported += gapInt(t, gap, AttrGapRecords)
	}
	if reported != evicted-1 {
		t.Errorf("the reports count %d records; %d were evicted, one of them a gap record", reported, evicted)
	}
}

// jsonLines decodes a buffer file, for tests that inspect one directly.
func jsonLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		out = append(out, m)
	}
	return out
}
