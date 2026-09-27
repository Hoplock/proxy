// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// fakeControl is Hoplock Control as far as the shipper is concerned: it records
// what arrived on each endpoint and can be told to refuse, which is the whole
// of the outage story.
type fakeControl struct {
	mu       sync.Mutex
	batches  [][]control.LogRecord
	priority []control.LogRecord
	down     bool
	batchErr error
	// refuse makes the server refuse a request carrying any record it
	// matches, with a 400 that stores none of the request — the contract's
	// answer to a record it will not take (phase 0046).
	refuse func(control.LogRecord) bool
	// failBatch, when it returns an error, answers that batch request with it
	// instead: a 5xx partway through an isolation, say. n counts the batch
	// requests so far, this one included.
	failBatch func(n int, recs []control.LogRecord) error
	// batchRequests and priorityRequests count every request received,
	// answered or not.
	batchRequests    int
	priorityRequests int
}

var _ control.Client = (*fakeControl)(nil)

// errDown is what an unreachable Hoplock Control looks like from here.
var errDown = errors.New("hoplock control is unreachable")

func (f *fakeControl) setDown(down bool) {
	f.mu.Lock()
	f.down = down
	f.mu.Unlock()
}

func (f *fakeControl) setRefuse(refuse func(control.LogRecord) bool) {
	f.mu.Lock()
	f.refuse = refuse
	f.mu.Unlock()
}

// refusedError is the error the real REST client returns for a 400, carrying
// the server's code and a message naming the record, as Control's does.
func refusedError(op string, index int, rec control.LogRecord) error {
	return &control.APIError{
		Op: op, StatusCode: http.StatusBadRequest, Code: "invalid_record",
		Message: fmt.Sprintf("records[%d] (record_id %s) is not accepted", index, rec.RecordID),
		Cause:   control.ErrBadRequest,
	}
}

// statusError is the error the real REST client returns for any other status.
func statusError(op string, status int) error {
	cause := control.ErrBadRequest
	switch {
	case status == http.StatusUnauthorized:
		cause = control.ErrUnauthorized
	case status >= 500:
		cause = control.ErrServer
	}
	return &control.APIError{Op: op, StatusCode: status, Code: "status", Message: http.StatusText(status), Cause: cause}
}

func (f *fakeControl) IngestLogBatch(_ context.Context, req *control.LogBatchRequest) (*control.LogBatchResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batchRequests++
	if f.down {
		return nil, errDown
	}
	if f.batchErr != nil {
		return nil, f.batchErr
	}
	if f.failBatch != nil {
		if err := f.failBatch(f.batchRequests, req.Records); err != nil {
			return nil, err
		}
	}
	for i, rec := range req.Records {
		if f.refuse != nil && f.refuse(rec) {
			return nil, refusedError("IngestLogBatch", i, rec)
		}
	}
	f.batches = append(f.batches, append([]control.LogRecord(nil), req.Records...))
	return &control.LogBatchResponse{Accepted: len(req.Records)}, nil
}

func (f *fakeControl) IngestPriorityLog(_ context.Context, req *control.LogPriorityRequest) (*control.LogPriorityResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.priorityRequests++
	if f.down {
		return nil, errDown
	}
	if f.refuse != nil && f.refuse(req.Record) {
		return nil, refusedError("IngestPriorityLog", 0, req.Record)
	}
	f.priority = append(f.priority, req.Record)
	return &control.LogPriorityResponse{Accepted: true, ReceiptID: "receipt"}, nil
}

func (f *fakeControl) requests() (batch, priority int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.batchRequests, f.priorityRequests
}

// delivered is every record the server holds, batch records first, in the order
// each path received them.
func (f *fakeControl) delivered() []control.LogRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []control.LogRecord
	for _, batch := range f.batches {
		out = append(out, batch...)
	}
	return append(out, f.priority...)
}

func (f *fakeControl) batchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.batches)
}

func (f *fakeControl) priorityRecords() []control.LogRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]control.LogRecord(nil), f.priority...)
}

func (f *fakeControl) batchedRecords() []control.LogRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []control.LogRecord
	for _, batch := range f.batches {
		out = append(out, batch...)
	}
	return out
}

// The rest of the contract is not this package's business; a shipper only ever
// calls the two ingest endpoints.
func (f *fakeControl) AuthenticateCert(context.Context, *control.AuthenticateCertRequest) (*control.AuthenticateResponse, error) {
	return nil, errors.New("not used")
}

func (f *fakeControl) AuthenticatePassword(context.Context, *control.AuthenticatePasswordRequest) (*control.AuthenticateResponse, error) {
	return nil, errors.New("not used")
}

func (f *fakeControl) PollMFA(context.Context, *control.MFAPollRequest) (*control.AuthenticateResponse, error) {
	return nil, errors.New("not used")
}

func (f *fakeControl) Authorize(context.Context, *control.AuthorizeRequest) (*control.AuthorizeResponse, error) {
	return nil, errors.New("not used")
}

func (f *fakeControl) ReportHostKey(context.Context, *control.HostKeyReportRequest) (*control.HostKeyReportResponse, error) {
	return nil, errors.New("not used")
}

// newTestShipper returns a started shipper wired to a fake server, with a
// buffer directory and no interval flushing: a test that sees a batch saw it
// because something triggered it, not because a tick fired.
func newTestShipper(t *testing.T, adjust func(*Options)) (*Shipper, *fakeControl) {
	t.Helper()
	server := &fakeControl{}
	opts := Options{
		Client:        server,
		BatchSize:     4,
		FlushInterval: -1,
		BufferDir:     t.TempDir(),
		RetryMin:      10 * time.Millisecond,
		RetryMax:      20 * time.Millisecond,
		Logf:          t.Logf,
	}
	if adjust != nil {
		adjust(&opts)
	}
	shipper, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shipper.Close(ctx)
	})
	return shipper, server
}

// flush delivers everything queued and fails the test if it cannot.
func flush(t *testing.T, s *Shipper) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
}

// eventually polls until want is true, or fails.
func eventually(t *testing.T, want func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if want() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// messages is the Message field of each record, which is enough to assert
// ordering without spelling out whole records.
func messages(recs []control.LogRecord) []string {
	out := make([]string, len(recs))
	for i, rec := range recs {
		out[i] = rec.Message
	}
	return out
}
