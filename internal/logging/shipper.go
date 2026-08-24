// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// Defaults for a Shipper. They are sized for a proxy carrying interactive
// sessions: a batch large enough to amortise a round trip, an interval short
// enough that an idle session's records are not hours old, and a queue deep
// enough to absorb a burst of stream chunks without any session goroutine ever
// waiting on the network.
const (
	// DefaultBatchSize is how many records accumulate before a batch is sent.
	DefaultBatchSize = 64
	// DefaultFlushInterval is how long a partial batch waits.
	DefaultFlushInterval = 5 * time.Second
	// DefaultQueueSize bounds the records in flight between the capture points
	// and the shipping goroutine.
	DefaultQueueSize = 4096
	// DefaultSendTimeout bounds one delivery attempt.
	DefaultSendTimeout = 10 * time.Second
	// DefaultRetryMin and DefaultRetryMax bound the drain backoff after an
	// outage.
	DefaultRetryMin = time.Second
	DefaultRetryMax = 30 * time.Second
	// DefaultMaxPayloadBytes caps one stream-capture record's payload. Larger
	// reads are split across records, which the capture format is built for:
	// chunks are concatenated in sequence order.
	DefaultMaxPayloadBytes = 32 << 10
)

// Options configure a Shipper.
type Options struct {
	// Client is the Hoplock Control client. Required.
	Client control.Client
	// BatchSize is how many records trigger a send. Zero means
	// DefaultBatchSize.
	BatchSize int
	// FlushInterval is how long a partial batch waits. Zero means
	// DefaultFlushInterval; negative disables interval flushing, leaving size
	// and priority as the only triggers.
	FlushInterval time.Duration
	// QueueSize bounds the in-flight records. Zero means DefaultQueueSize.
	QueueSize int
	// BufferDir is the local resilience buffer's directory (PLAN §7). Empty
	// disables buffering, and records that cannot be delivered are then
	// counted in Stats.Dropped rather than kept.
	BufferDir string
	// SendTimeout bounds one delivery attempt. Zero means DefaultSendTimeout.
	SendTimeout time.Duration
	// RetryMin and RetryMax bound the drain backoff. Zero means the defaults.
	RetryMin time.Duration
	RetryMax time.Duration
	// MaxPayloadBytes caps a stream record's payload. Zero means
	// DefaultMaxPayloadBytes.
	MaxPayloadBytes int
	// Logf records the shipper's own operational events — an outage, a drain,
	// a dropped record. It never receives a captured byte. Nil discards them.
	Logf func(format string, args ...any)
	// Now overrides the clock, for tests.
	Now func() time.Time
	// NewRecordID overrides record id generation, for tests.
	NewRecordID func() string
}

// Stats is what a Shipper has done. It exists for tests and for an operator
// asking whether telemetry is actually leaving the box.
type Stats struct {
	// Queued is records accepted from capture points.
	Queued uint64
	// Batched and Priority are records delivered on each path.
	Batched  uint64
	Priority uint64
	// Batches is how many batch requests were sent.
	Batches uint64
	// Buffered is records written to the disk buffer, Drained is records the
	// buffer later delivered.
	Buffered uint64
	Drained  uint64
	// Dropped is records lost: no buffer configured, or the buffer itself
	// failed. It is the number that must stay zero.
	Dropped uint64
	// Segments is how many buffer segments are still owed to the server.
	Segments int
	// Degraded reports whether delivery is currently going to disk.
	Degraded bool
}

// Shipper delivers log records to Hoplock Control (D8).
//
// One goroutine owns delivery. Capture points hand it records over a channel
// and never block on the network, which is what lets a recorder sit in the path
// of a command decision. The goroutine batches ordinary records, flushes and
// then takes the dedicated endpoint for a critical one, and falls back to the
// disk buffer whenever the server will not take either.
type Shipper struct {
	client          control.Client
	batchSize       int
	flushInterval   time.Duration
	sendTimeout     time.Duration
	retryMin        time.Duration
	retryMax        time.Duration
	maxPayloadBytes int
	logf            func(format string, args ...any)
	clock           func() time.Time
	newID           func() string

	buffer *diskBuffer

	queue chan control.LogRecord
	prio  chan control.LogRecord
	flush chan chan error

	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}

	// stopped gates the send channels: once delivery has stopped, a capture
	// point that is still winding down must not block on a channel nobody
	// reads.
	stopped atomic.Bool

	queued   atomic.Uint64
	batched  atomic.Uint64
	priority atomic.Uint64
	batches  atomic.Uint64
	buffered atomic.Uint64
	drained  atomic.Uint64
	dropped  atomic.Uint64
}

// New returns a started Shipper. Close stops it.
func New(opts Options) (*Shipper, error) {
	if opts.Client == nil {
		return nil, errors.New("logging: a management client is required")
	}
	buffer, err := newDiskBuffer(opts.BufferDir)
	if err != nil {
		return nil, err
	}

	s := &Shipper{
		client:          opts.Client,
		batchSize:       opts.BatchSize,
		flushInterval:   opts.FlushInterval,
		sendTimeout:     opts.SendTimeout,
		retryMin:        opts.RetryMin,
		retryMax:        opts.RetryMax,
		maxPayloadBytes: opts.MaxPayloadBytes,
		logf:            opts.Logf,
		clock:           opts.Now,
		newID:           opts.NewRecordID,
		buffer:          buffer,
		prio:            make(chan control.LogRecord, 64),
		flush:           make(chan chan error),
		stop:            make(chan struct{}),
		done:            make(chan struct{}),
	}
	if s.batchSize <= 0 {
		s.batchSize = DefaultBatchSize
	}
	if s.flushInterval == 0 {
		s.flushInterval = DefaultFlushInterval
	}
	if s.sendTimeout <= 0 {
		s.sendTimeout = DefaultSendTimeout
	}
	if s.retryMin <= 0 {
		s.retryMin = DefaultRetryMin
	}
	if s.retryMax < s.retryMin {
		s.retryMax = maxDuration(DefaultRetryMax, s.retryMin)
	}
	if s.maxPayloadBytes <= 0 {
		s.maxPayloadBytes = DefaultMaxPayloadBytes
	}
	if s.logf == nil {
		s.logf = func(string, ...any) {}
	}
	if s.clock == nil {
		s.clock = time.Now
	}
	if s.newID == nil {
		s.newID = newRecordID
	}
	queueSize := opts.QueueSize
	if queueSize <= 0 {
		queueSize = DefaultQueueSize
	}
	s.queue = make(chan control.LogRecord, queueSize)

	go s.run()
	return s, nil
}

func (s *Shipper) now() time.Time {
	if s == nil || s.clock == nil {
		return time.Now()
	}
	return s.clock()
}

func (s *Shipper) newRecordID() string {
	if s == nil || s.newID == nil {
		return newRecordID()
	}
	return s.newID()
}

// MaxPayloadBytes is the largest payload one stream record may carry.
func (s *Shipper) MaxPayloadBytes() int {
	if s == nil {
		return DefaultMaxPayloadBytes
	}
	return s.maxPayloadBytes
}

// Record queues a record for batched delivery. It never blocks: a full queue
// spills straight to the disk buffer, because a telemetry pipeline that can
// stall a session is worse than one that writes to disk.
func (s *Shipper) Record(rec control.LogRecord) {
	if s == nil {
		return
	}
	s.queued.Add(1)
	if s.stopped.Load() {
		s.spill(kindBatch, []control.LogRecord{rec})
		return
	}
	select {
	case s.queue <- rec:
	default:
		s.logf("logging: record queue full, buffering session=%s kind=%s", rec.SessionID, rec.Kind)
		s.spill(kindBatch, []control.LogRecord{rec})
	}
}

// RecordPriority queues a critical record for immediate delivery (D8).
//
// "Immediate" is bounded rather than synchronous: the call hands the record to
// the delivery goroutine and returns, and that goroutine flushes the in-flight
// batch and posts the record to the priority endpoint before it does anything
// else. The added latency is one channel handoff, which is what lets a blocked
// command be recorded from inside the decision that blocked it.
func (s *Shipper) RecordPriority(rec control.LogRecord) {
	if s == nil {
		return
	}
	s.queued.Add(1)
	if s.stopped.Load() {
		s.spill(kindPriority, []control.LogRecord{rec})
		return
	}
	select {
	case s.prio <- rec:
	default:
		// The priority channel is full only if the server is taking longer per
		// record than the proxy is producing them. Buffering keeps the record;
		// it stays a priority record and drains to the priority endpoint.
		s.logf("logging: priority queue full, buffering session=%s kind=%s", rec.SessionID, rec.Kind)
		s.spill(kindPriority, []control.LogRecord{rec})
	}
}

// Flush delivers everything queued and then tries to drain the disk buffer. It
// is what tests wait on, and what a shutdown uses to avoid abandoning records
// that were one interval away from being sent.
func (s *Shipper) Flush(ctx context.Context) error {
	if s == nil {
		return nil
	}
	reply := make(chan error, 1)
	select {
	case s.flush <- reply:
	case <-s.done:
		return errors.New("logging: shipper is closed")
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-reply:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close flushes what is queued and stops the delivery goroutine. Records that
// still cannot be delivered are buffered to disk for the next run.
func (s *Shipper) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	err := s.Flush(ctx)
	s.stopOnce.Do(func() {
		s.stopped.Store(true)
		close(s.stop)
	})
	select {
	case <-s.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return err
}

// Stats reports what has been delivered.
func (s *Shipper) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	return Stats{
		Queued:   s.queued.Load(),
		Batched:  s.batched.Load(),
		Priority: s.priority.Load(),
		Batches:  s.batches.Load(),
		Buffered: s.buffered.Load(),
		Drained:  s.drained.Load(),
		Dropped:  s.dropped.Load(),
		Segments: s.buffer.pending(),
		Degraded: s.degraded(),
	}
}

// degraded reports whether delivery is currently going to disk. It is true
// exactly while the buffer holds something: new records join the queue on disk
// rather than overtaking it, which is what keeps a drained session in order.
func (s *Shipper) degraded() bool { return s.buffer.pending() > 0 }

// run is the delivery goroutine.
func (s *Shipper) run() {
	defer close(s.done)

	var (
		batch      = make([]control.LogRecord, 0, s.batchSize)
		ticker     *time.Ticker
		tickC      <-chan time.Time
		retryTimer *time.Timer
		retryC     <-chan time.Time
		backoff    time.Duration
	)
	if s.flushInterval > 0 {
		ticker = time.NewTicker(s.flushInterval)
		tickC = ticker.C
		defer ticker.Stop()
	}
	defer func() {
		if retryTimer != nil {
			retryTimer.Stop()
		}
	}()

	for {
		// Arm the drain retry whenever anything is owed to the server, and
		// disarm it the moment nothing is. The backoff resets on a clean
		// drain, so a second outage does not start where the first left off.
		switch {
		case s.degraded() && retryC == nil:
			backoff = nextBackoff(backoff, s.retryMin, s.retryMax)
			retryTimer = time.NewTimer(backoff)
			retryC = retryTimer.C
		case !s.degraded() && retryC != nil:
			retryTimer.Stop()
			retryTimer, retryC = nil, nil
			backoff = 0
		}

		select {
		case rec := <-s.prio:
			// D8, in this order on purpose: whatever accumulated before the
			// critical event goes first, so the context of a blocked command
			// reaches the server no later than the block itself does.
			s.drainQueue(&batch)
			s.sendBatch(&batch)
			s.sendPriority(rec)

		case rec := <-s.queue:
			batch = append(batch, rec)
			if len(batch) >= s.batchSize {
				s.sendBatch(&batch)
			}

		case <-tickC:
			s.sendBatch(&batch)

		case reply := <-s.flush:
			s.drainQueue(&batch)
			s.drainPriority()
			s.sendBatch(&batch)
			reply <- s.drainBuffer()

		case <-retryC:
			retryC = nil
			if err := s.drainBuffer(); err == nil {
				backoff = 0
			}

		case <-s.stop:
			s.drainQueue(&batch)
			s.drainPriority()
			s.sendBatch(&batch)
			_ = s.drainBuffer()
			return
		}
	}
}

// drainQueue moves everything already queued into the batch without waiting.
// It is what keeps ordering intact when a priority record arrives: the select
// above picks a ready case at random, so the batch has to be topped up before
// it is flushed rather than trusted to be complete.
func (s *Shipper) drainQueue(batch *[]control.LogRecord) {
	for {
		select {
		case rec := <-s.queue:
			*batch = append(*batch, rec)
		default:
			return
		}
	}
}

// drainPriority delivers every queued critical record. Only shutdown and Flush
// use it; the steady-state path takes them one at a time so each one flushes
// the batch in front of it.
func (s *Shipper) drainPriority() {
	for {
		select {
		case rec := <-s.prio:
			s.sendPriority(rec)
		default:
			return
		}
	}
}

// sendBatch delivers the accumulated records, emptying the batch either way:
// what the server would not take goes to disk, and a record is never in both
// places.
func (s *Shipper) sendBatch(batch *[]control.LogRecord) {
	if len(*batch) == 0 {
		return
	}
	recs := make([]control.LogRecord, len(*batch))
	copy(recs, *batch)
	*batch = (*batch)[:0]

	if s.degraded() {
		// Something is already owed to the server. Joining the back of that
		// queue keeps the session's records in order.
		s.spill(kindBatch, recs)
		return
	}
	if err := s.postBatch(recs); err != nil {
		s.logf("logging: batch of %d records not delivered, buffering: %v", len(recs), err)
		s.spill(kindBatch, recs)
		return
	}
	s.batched.Add(uint64(len(recs)))
	s.batches.Add(1)
}

// sendPriority delivers one critical record.
func (s *Shipper) sendPriority(rec control.LogRecord) {
	if s.degraded() {
		s.spill(kindPriority, []control.LogRecord{rec})
		return
	}
	if err := s.postPriority(rec); err != nil {
		s.logf("logging: priority record not delivered, buffering: session=%s kind=%s: %v",
			rec.SessionID, rec.Kind, err)
		s.spill(kindPriority, []control.LogRecord{rec})
		return
	}
	s.priority.Add(1)
}

func (s *Shipper) postBatch(recs []control.LogRecord) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.sendTimeout)
	defer cancel()
	_, err := s.client.IngestLogBatch(ctx, &control.LogBatchRequest{Records: recs})
	return err
}

func (s *Shipper) postPriority(rec control.LogRecord) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.sendTimeout)
	defer cancel()
	_, err := s.client.IngestPriorityLog(ctx, &control.LogPriorityRequest{Record: rec})
	return err
}

// spill writes records to the disk buffer, one segment per session because the
// buffer's layout is one area per session (PLAN §7).
func (s *Shipper) spill(kind deliveryKind, recs []control.LogRecord) {
	if s.buffer == nil {
		s.dropped.Add(uint64(len(recs)))
		s.logf("logging: %d records dropped: no buffer directory configured", len(recs))
		return
	}
	for _, group := range groupBySession(recs) {
		if err := s.buffer.append(group.sessionID, kind, group.records); err != nil {
			s.dropped.Add(uint64(len(group.records)))
			s.logf("logging: %d records dropped: %v", len(group.records), err)
			continue
		}
		s.buffered.Add(uint64(len(group.records)))
	}
}

// sessionGroup is one session's slice of a spilled batch.
type sessionGroup struct {
	sessionID string
	records   []control.LogRecord
}

// groupBySession splits records by session, preserving order within each and
// the order the sessions first appear.
func groupBySession(recs []control.LogRecord) []sessionGroup {
	var groups []sessionGroup
	index := make(map[string]int, len(recs))
	for _, rec := range recs {
		i, ok := index[rec.SessionID]
		if !ok {
			index[rec.SessionID] = len(groups)
			groups = append(groups, sessionGroup{sessionID: rec.SessionID})
			i = len(groups) - 1
		}
		groups[i].records = append(groups[i].records, rec)
	}
	return groups
}

// drainBuffer ships what the outage left on disk, oldest first, stopping at the
// first segment the server still will not take.
//
// Stopping matters: draining past a failure would deliver a session's later
// records before its earlier ones, and the whole point of the buffer is that an
// outage costs latency rather than fidelity.
func (s *Shipper) drainBuffer() error {
	if s.buffer == nil {
		return nil
	}
	segs, err := s.buffer.segments()
	if err != nil {
		return err
	}
	for _, seg := range segs {
		recs, err := s.buffer.load(seg)
		if err != nil {
			// A segment that cannot be read will never become readable.
			// Removing it is the only way the drain makes progress, and it is
			// counted as the loss it is rather than retried forever.
			s.logf("logging: discarding unreadable buffer segment %s: %v", seg.path, err)
			s.dropped.Add(1)
			_ = s.buffer.remove(seg)
			continue
		}
		if len(recs) == 0 {
			_ = s.buffer.remove(seg)
			continue
		}
		if err := s.deliverSegment(seg, recs); err != nil {
			return err
		}
		s.drained.Add(uint64(len(recs)))
		if err := s.buffer.remove(seg); err != nil {
			return err
		}
	}
	return nil
}

// deliverSegment sends one buffered segment to the endpoint it was owed to.
func (s *Shipper) deliverSegment(seg segment, recs []control.LogRecord) error {
	if seg.kind == kindPriority {
		for _, rec := range recs {
			if err := s.postPriority(rec); err != nil {
				return err
			}
			s.priority.Add(1)
		}
		return nil
	}
	if err := s.postBatch(recs); err != nil {
		return err
	}
	s.batched.Add(uint64(len(recs)))
	s.batches.Add(1)
	return nil
}

// nextBackoff doubles towards max, starting at min.
func nextBackoff(current, min, max time.Duration) time.Duration {
	if current <= 0 {
		return min
	}
	next := current * 2
	if next > max {
		return max
	}
	return next
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// newRecordID is the client-assigned unique id the server de-duplicates
// retried batches by (control.LogRecord.RecordID). It has to be unique across
// proxies and across restarts, because a drained buffer replays records a
// crashed run had already queued.
func newRecordID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail in practice; a time-based id keeps the
		// record rather than losing it to a panic in a logging path.
		return fmt.Sprintf("rec-%d", time.Now().UnixNano())
	}
	return "rec-" + hex.EncodeToString(b[:])
}
