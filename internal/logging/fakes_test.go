// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
	"context"
	"errors"
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
}

var _ control.Client = (*fakeControl)(nil)

// errDown is what an unreachable Hoplock Control looks like from here.
var errDown = errors.New("hoplock control is unreachable")

func (f *fakeControl) setDown(down bool) {
	f.mu.Lock()
	f.down = down
	f.mu.Unlock()
}

func (f *fakeControl) IngestLogBatch(_ context.Context, req *control.LogBatchRequest) (*control.LogBatchResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errDown
	}
	if f.batchErr != nil {
		return nil, f.batchErr
	}
	f.batches = append(f.batches, append([]control.LogRecord(nil), req.Records...))
	return &control.LogBatchResponse{Accepted: len(req.Records)}, nil
}

func (f *fakeControl) IngestPriorityLog(_ context.Context, req *control.LogPriorityRequest) (*control.LogPriorityResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errDown
	}
	f.priority = append(f.priority, req.Record)
	return &control.LogPriorityResponse{Accepted: true, ReceiptID: "receipt"}, nil
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
