// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// A refused record costs exactly itself (phase 0046, refusal.go): it is set
// aside, counted and reported, and nothing behind it waits.

func command(sessionID string, i int) control.LogRecord {
	return metadata(sessionID, i, control.LogKindCommand, control.SeverityInfo, 10)
}

// deliveredCount is how many times each record id reached the server, on
// either path.
func deliveredCount(server *fakeControl) map[string]int {
	counts := map[string]int{}
	for _, rec := range server.delivered() {
		counts[rec.RecordID]++
	}
	return counts
}

func gapsOf(recs []control.LogRecord) []control.LogRecord {
	var out []control.LogRecord
	for _, rec := range recs {
		if isGapRecord(rec) {
			out = append(out, rec)
		}
	}
	return out
}

// TestOnlyA400OrA413IsARefusal is the classification, through the real REST
// client against a real HTTP server, for every status the client can meet.
// ErrBadRequest would have been the trap: it covers every 4xx but 401, and
// reading a 404 from a wrong base URL as "discard these records" would set the
// whole audit stream aside.
func TestOnlyA400OrA413IsARefusal(t *testing.T) {
	cases := []struct {
		status  int
		refusal bool
	}{
		{http.StatusBadRequest, true},
		{http.StatusRequestEntityTooLarge, true},
		{http.StatusUnauthorized, false},
		{http.StatusForbidden, false},
		{http.StatusNotFound, false},
		{http.StatusRequestTimeout, false},
		{http.StatusConflict, false},
		{http.StatusUnprocessableEntity, false},
		{http.StatusTooManyRequests, false},
		{http.StatusInternalServerError, false},
		{http.StatusBadGateway, false},
		{http.StatusServiceUnavailable, false},
		{http.StatusGatewayTimeout, false},
		{http.StatusOK, false}, // not the documented 202: a contract violation, not a refusal
	}
	for _, tc := range cases {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			rec := command("sess-a", 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req control.LogBatchRequest
				_ = json.NewDecoder(r.Body).Decode(&req)
				w.Header().Set("Content-Type", "application/json")
				// The record under test gets the status; anything else — the
				// report of a refusal — is taken, so what is counted is the
				// record's fate alone.
				if len(req.Records) == 1 && req.Records[0].RecordID == rec.RecordID {
					w.WriteHeader(tc.status)
					_, _ = io.WriteString(w, `{"error":{"code":"invalid_record","message":"records[0] (record_id `+rec.RecordID+`) is refused"}}`)
					return
				}
				w.WriteHeader(http.StatusAccepted)
				_, _ = fmt.Fprintf(w, `{"accepted":%d}`, len(req.Records))
			}))
			defer server.Close()
			client, err := control.NewRESTClient(control.Options{BaseURL: server.URL, Token: "t"})
			if err != nil {
				t.Fatalf("NewRESTClient: %v", err)
			}

			_, err = client.IngestLogBatch(context.Background(), &control.LogBatchRequest{Records: []control.LogRecord{rec}})
			if got := isRefusal(err); got != tc.refusal {
				t.Fatalf("isRefusal(%v) = %t, want %t", err, got, tc.refusal)
			}

			// And what the shipper does with it.
			shipper := newRESTShipper(t, client)
			shipper.Record(rec)
			handled(t, shipper)
			stats := shipper.Stats()
			if tc.refusal {
				if stats.Refused != 1 || stats.Segments != 0 || stats.Buffered != 0 {
					t.Errorf("a %d was not set aside: %+v", tc.status, stats)
				}
				return
			}
			if stats.Refused != 0 || stats.Buffered != 1 || stats.Segments != 1 {
				t.Errorf("a %d did not keep the record for the retry: %+v", tc.status, stats)
			}
		})
	}

	t.Run("transport", func(t *testing.T) {
		server := httptest.NewServer(http.NotFoundHandler())
		url := server.URL
		server.Close() // nothing listens there now
		client, err := control.NewRESTClient(control.Options{BaseURL: url, Token: "t"})
		if err != nil {
			t.Fatalf("NewRESTClient: %v", err)
		}
		_, err = client.IngestLogBatch(context.Background(), &control.LogBatchRequest{Records: []control.LogRecord{command("s", 1)}})
		if err == nil || isRefusal(err) {
			t.Fatalf("a transport failure (%v) is not a refusal", err)
		}
	})
}

func newRESTShipper(t *testing.T, client control.Client) *Shipper {
	t.Helper()
	shipper, err := New(Options{Client: client, BatchSize: 1, FlushInterval: -1, BufferDir: t.TempDir(),
		RetryMin: time.Hour, Logf: t.Logf})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shipper.Close(ctx)
	})
	return shipper
}

// TestOneBadRecordInABatchOf64IsIsolated is bisection's bound, and its promise:
// every other record delivered exactly once, the bad one set aside and named.
func TestOneBadRecordInABatchOf64IsIsolated(t *testing.T) {
	shipper, server := newTestShipper(t, func(o *Options) { o.BatchSize = 64 })
	var made []control.LogRecord
	for i := range 64 {
		made = append(made, command("sess-a", i))
	}
	bad := made[37]
	server.setRefuse(func(r control.LogRecord) bool { return r.RecordID == bad.RecordID })

	for _, rec := range made {
		shipper.Record(rec)
	}
	eventually(t, func() bool { return shipper.Stats().Refused == 1 }, "the isolation to finish")

	requests, _ := server.requests()
	if bound := 2*int(math.Ceil(math.Log2(64))) + 1; requests > bound {
		t.Errorf("isolating one bad record in 64 took %d requests, want at most %d", requests, bound)
	}
	counts := deliveredCount(server)
	for _, rec := range made {
		want := 1
		if rec.RecordID == bad.RecordID {
			want = 0
		}
		if counts[rec.RecordID] != want {
			t.Errorf("record %s was delivered %d times, want %d", rec.RecordID, counts[rec.RecordID], want)
		}
	}
	if got := tagged(t, shipper.buffer.dir, "sess-a", tagRefused); len(got) != 1 || got[0] != bad.RecordID {
		t.Errorf("the set-aside area holds %v, want only the refused record", got)
	}

	flush(t, shipper)
	gaps := gapsOf(server.batchedRecords())
	if len(gaps) != 1 {
		t.Fatalf("%d reports of the refusal, want 1", len(gaps))
	}
	gap := gaps[0]
	for key, want := range map[string]string{
		AttrGapCause:     GapCauseRefused,
		AttrGapRecords:   "1",
		AttrGapRecordIDs: bad.RecordID,
		AttrRefusalCode:  "invalid_record",
		AttrGapKinds:     string(control.LogKindCommand),
		AttrGapCritical:  "0",
	} {
		if got := gap.Attributes[key]; got != want {
			t.Errorf("the report carries %s=%q, want %q", key, got, want)
		}
	}
	if !strings.Contains(gap.Attributes[AttrRefusalMessage], bad.RecordID) {
		t.Errorf("refusal_message %q is not the server's own words", gap.Attributes[AttrRefusalMessage])
	}
	if gap.SessionID != "sess-a" || gap.Severity != control.SeverityWarn {
		t.Errorf("the report is session %q at %s, want sess-a at warn", gap.SessionID, gap.Severity)
	}
	if got := shipper.Stats(); got.Segments != 0 || got.Dropped != 0 {
		t.Errorf("after the refusal: %+v, want nothing owed and nothing dropped", got)
	}
}

// TestEveryRecordRefusedIsSetAside is bisection's worst case: 2n−1 requests,
// and nothing resent.
func TestEveryRecordRefusedIsSetAside(t *testing.T) {
	const n = 70 // more ids than a report names
	shipper, server := newTestShipper(t, func(o *Options) { o.BatchSize = n })
	server.setRefuse(func(r control.LogRecord) bool { return !isGapRecord(r) })
	for i := range n {
		shipper.Record(command("sess-a", i))
	}
	eventually(t, func() bool { return shipper.Stats().Refused == n }, "every record to be set aside")
	if requests, _ := server.requests(); requests != 2*n-1 {
		t.Errorf("%d requests to set aside %d records, want %d", requests, n, 2*n-1)
	}
	if got := len(tagged(t, shipper.buffer.dir, "sess-a", tagRefused)); got != n {
		t.Errorf("%d records set aside, want %d", got, n)
	}

	flush(t, shipper)
	gaps := gapsOf(server.batchedRecords())
	if len(gaps) != 1 {
		t.Fatalf("%d reports, want 1", len(gaps))
	}
	if got := len(strings.Split(gaps[0].Attributes[AttrGapRecordIDs], ",")); got != maxGapRecordIDs {
		t.Errorf("the report names %d ids, want %d", got, maxGapRecordIDs)
	}
	if got := gaps[0].Attributes[AttrGapRecordIDsTruncated]; got != "true" {
		t.Errorf("gap_record_ids_truncated = %q with more than %d ids", got, maxGapRecordIDs)
	}
	if got := gaps[0].Attributes[AttrGapRecords]; got != strconv.Itoa(n) {
		t.Errorf("gap_records = %s, want %d", got, n)
	}
	// Set aside means never resent: a second flush sends nothing.
	before, _ := server.requests()
	flush(t, shipper)
	if after, _ := server.requests(); after != before {
		t.Errorf("a flush resent something: %d requests became %d", before, after)
	}
}

// TestAFailurePartwayThroughAnIsolationKeepsTheRest: a half that meets a 5xx
// stops the isolation, and what it had not reached goes to disk — nothing the
// server took, and nothing counted twice.
func TestAFailurePartwayThroughAnIsolationKeepsTheRest(t *testing.T) {
	shipper, server := newTestShipper(t, func(o *Options) {
		o.BatchSize = 8
		o.RetryMin = time.Hour
	})
	var made []control.LogRecord
	for i := range 8 {
		made = append(made, command("sess-a", i))
	}
	server.setRefuse(func(r control.LogRecord) bool { return r.RecordID == made[6].RecordID })
	server.mu.Lock()
	// all 8 refused → [0..3] taken → [4..7] refused → [4,5] taken → [6,7] fails
	server.failBatch = func(n int, _ []control.LogRecord) error {
		if n == 5 {
			return statusError("IngestLogBatch", http.StatusServiceUnavailable)
		}
		return nil
	}
	server.mu.Unlock()

	for _, rec := range made {
		shipper.Record(rec)
	}
	eventually(t, func() bool { return shipper.Stats().Buffered == 2 }, "the rest to go to disk")
	if got := tagged(t, shipper.buffer.dir, "sess-a", tagBatch); len(got) != 2 || got[0] != made[6].RecordID || got[1] != made[7].RecordID {
		t.Fatalf("the buffer holds %v, want the two records the isolation had not reached", got)
	}

	server.mu.Lock()
	server.failBatch = nil
	server.mu.Unlock()
	flush(t, shipper)

	counts := deliveredCount(server)
	for i, rec := range made {
		want := 1
		if i == 6 {
			want = 0
		}
		if counts[rec.RecordID] != want {
			t.Errorf("record %d was delivered %d times, want %d", i, counts[rec.RecordID], want)
		}
	}
	if got := tagged(t, shipper.buffer.dir, "sess-a", tagRefused); len(got) != 1 || got[0] != made[6].RecordID {
		t.Errorf("the set-aside area holds %v, want the refused record once", got)
	}
	if got := shipper.Stats(); got.Refused != 1 || got.Segments != 0 {
		t.Errorf("after recovery: %+v, want one refusal and nothing owed", got)
	}
}

// TestAFailurePartwayThroughTheDrainRewritesTheSegment: in the drain, what is
// still owed after a 5xx stays in the segment — rewritten to hold exactly that,
// under the same name, so it keeps its place in the drain order.
func TestAFailurePartwayThroughTheDrainRewritesTheSegment(t *testing.T) {
	shipper, server := newTestShipper(t, func(o *Options) {
		o.BatchSize = 8
		o.RetryMin = time.Hour
	})
	var made []control.LogRecord
	for i := range 8 {
		made = append(made, command("sess-a", i))
	}
	server.setDown(true)
	for _, rec := range made {
		shipper.Record(rec)
	}
	handled(t, shipper)
	records, _ := shipper.buffer.owedFiles()
	if len(records) != 1 {
		t.Fatalf("%d segments on disk, want 1", len(records))
	}
	segment := filepath.Join(shipper.buffer.dir, "sess-a", fileName(records[0], tagBatch))

	server.mu.Lock()
	server.down = false
	base := server.batchRequests
	// all 8 refused → [0..3] taken → [4..7] fails
	server.failBatch = func(n int, _ []control.LogRecord) error {
		if n == base+3 {
			return statusError("IngestLogBatch", http.StatusBadGateway)
		}
		return nil
	}
	server.mu.Unlock()
	server.setRefuse(func(r control.LogRecord) bool { return r.RecordID == made[6].RecordID })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := shipper.Flush(ctx); err == nil {
		t.Fatal("the drain met a 502 and reported success")
	}
	lines := jsonLines(t, segment)
	if len(lines) != 4 || lines[0]["record_id"] != made[4].RecordID {
		t.Fatalf("the segment holds %d records starting %v, want exactly the 4 still owed", len(lines), lines[0]["record_id"])
	}
	if got := shipper.Stats().Drained; got != 4 {
		t.Errorf("Stats.Drained = %d, want 4", got)
	}

	server.mu.Lock()
	server.failBatch = nil
	server.mu.Unlock()
	flush(t, shipper)
	counts := deliveredCount(server)
	for i, rec := range made {
		want := 1
		if i == 6 {
			want = 0
		}
		if counts[rec.RecordID] != want {
			t.Errorf("record %d was delivered %d times, want %d", i, counts[rec.RecordID], want)
		}
	}
	if got := shipper.Stats(); got.Refused != 1 || got.Segments != 0 || got.Drained != 7 {
		t.Errorf("after the drain: %+v, want 7 drained, 1 refused, nothing owed", got)
	}
}

// TestTheDrainGoesOnPastARefusedSegment is the defect this phase exists for:
// before it the drain stopped at the first segment the server would not take,
// and every segment behind it waited forever.
func TestTheDrainGoesOnPastARefusedSegment(t *testing.T) {
	shipper, server := newTestShipper(t, func(o *Options) {
		o.BatchSize = 2
		o.RetryMin = time.Hour
	})
	server.setDown(true)
	first := []control.LogRecord{command("sess-a", 0), command("sess-a", 1)}
	later := []control.LogRecord{command("sess-b", 2), command("sess-b", 3)}
	for _, rec := range append(first, later...) {
		shipper.Record(rec)
	}
	handled(t, shipper)
	server.setDown(false)
	server.setRefuse(func(r control.LogRecord) bool { return r.RecordID == first[0].RecordID })
	flush(t, shipper)

	counts := deliveredCount(server)
	for _, rec := range []control.LogRecord{first[1], later[0], later[1]} {
		if counts[rec.RecordID] != 1 {
			t.Errorf("record %s was delivered %d times, want 1", rec.RecordID, counts[rec.RecordID])
		}
	}
	if got := shipper.Stats(); got.Segments != 0 || got.Refused != 1 {
		t.Errorf("after the drain: %+v, want nothing owed and one refusal", got)
	}
}

// TestAPrioritySegmentIsDeliveredOneRecordAtATime: in the drain a priority
// segment goes one record at a time, a refused one is set aside, and the rest
// still arrive — on the priority endpoint.
func TestAPrioritySegmentIsDeliveredOneRecordAtATime(t *testing.T) {
	shipper, server := newTestShipper(t, func(o *Options) { o.RetryMin = time.Hour })
	recs := []control.LogRecord{critical("sess-a", "one"), critical("sess-a", "two"), critical("sess-a", "three")}
	for i := range recs {
		recs[i].RecordID = fmt.Sprintf("crit-%d", i)
	}
	shipper.spill(kindPriority, recs, false)
	server.setRefuse(func(r control.LogRecord) bool { return r.RecordID == "crit-1" })
	flush(t, shipper)

	var got []string
	for _, rec := range server.priorityRecords() {
		if !isGapRecord(rec) {
			got = append(got, rec.RecordID)
		}
	}
	if strings.Join(got, ",") != "crit-0,crit-2" {
		t.Errorf("the priority endpoint received %v, want crit-0 and crit-2", got)
	}
	if ids := tagged(t, shipper.buffer.dir, "sess-a", tagRefused); len(ids) != 1 || ids[0] != "crit-1" {
		t.Errorf("the set-aside area holds %v", ids)
	}
}

// TestARefusedCriticalRecordIsReportedCritically: a blocked command the server
// refused is a security event missing from its store, and the report of it
// takes the priority path.
func TestARefusedCriticalRecordIsReportedCritically(t *testing.T) {
	shipper, server := newTestShipper(t, nil)
	rec := critical("sess-a", "command blocked by policy")
	rec.RecordID = "crit-1"
	server.setRefuse(func(r control.LogRecord) bool { return r.RecordID == "crit-1" })

	shipper.RecordPriority(rec)
	eventually(t, func() bool { return len(gapsOf(server.priorityRecords())) == 1 }, "the report on the priority path")

	gap := gapsOf(server.priorityRecords())[0]
	if gap.Severity != control.SeverityCritical || gap.Attributes[AttrGapCritical] != "1" {
		t.Errorf("the report of a refused critical record is %s with gap_critical=%s", gap.Severity, gap.Attributes[AttrGapCritical])
	}
	if got := gap.Attributes[AttrGapRecordIDs]; got != "crit-1" {
		t.Errorf("the report names %q", got)
	}
	if ids := tagged(t, shipper.buffer.dir, "sess-a", tagRefused); len(ids) != 1 || ids[0] != "crit-1" {
		t.Errorf("the set-aside area holds %v", ids)
	}
}

// TestARefusedReportBegetsNoOther: a server that refuses the report of a
// refusal gets the report set aside and counted, and nothing more — otherwise
// every report would be the next thing to report.
func TestARefusedReportBegetsNoOther(t *testing.T) {
	shipper, server := newTestShipper(t, func(o *Options) { o.BatchSize = 2 })
	server.setRefuse(func(control.LogRecord) bool { return true })
	shipper.Record(command("sess-a", 0))
	shipper.Record(command("sess-a", 1))
	eventually(t, func() bool { return shipper.Stats().Refused == 2 }, "both records to be set aside")
	flush(t, shipper)
	if got := shipper.Stats().Refused; got != 3 {
		t.Fatalf("Stats.Refused = %d, want the two records and their report", got)
	}
	before, _ := server.requests()
	flush(t, shipper)
	if after, _ := server.requests(); after != before {
		t.Errorf("a refused report produced more traffic: %d requests became %d", before, after)
	}
	if got := len(tagged(t, shipper.buffer.dir, "sess-a", tagRefused)); got != 3 {
		t.Errorf("%d records set aside, want 3", got)
	}
}

// TestARefusalWithNoBufferIsCountedAndReportedNotDropped: with nowhere to keep
// it, a refused record is still accounted for — before phase 0046 the whole
// batch would have been dropped with it.
func TestARefusalWithNoBufferIsCountedAndReportedNotDropped(t *testing.T) {
	server := &fakeControl{}
	shipper, err := New(Options{Client: server, BatchSize: 2, FlushInterval: -1, Logf: t.Logf})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shipper.Close(ctx)
	})
	bad, good := command("sess-a", 0), command("sess-a", 1)
	server.setRefuse(func(r control.LogRecord) bool { return r.RecordID == bad.RecordID })
	shipper.Record(bad)
	shipper.Record(good)
	flush(t, shipper)

	stats := shipper.Stats()
	if stats.Refused != 1 || stats.Dropped != 0 {
		t.Errorf("stats = %+v, want one refusal and nothing dropped", stats)
	}
	if counts := deliveredCount(server); counts[good.RecordID] != 1 {
		t.Error("the good record in the refused batch did not arrive")
	}
	if len(gapsOf(server.batchedRecords())) != 1 {
		t.Error("the refusal was not reported")
	}
	if !shipper.Deliverable() {
		t.Error("a refusal made a buffer-less proxy report no logging path")
	}
}
