// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
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
	// DefaultBufferMaxBytes is the disk buffer's window: the most it holds
	// before it evicts (phase 0046, buffer.go). A gibibyte is hours of an
	// ordinary estate's metadata and several of its busiest sessions' capture.
	DefaultBufferMaxBytes int64 = 1 << 30
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
	// BufferMaxBytes is the buffer's window: every byte it holds on disk
	// counts, and past it the oldest records that are not pinned are evicted,
	// in class order, and reported (buffer.go). Zero means
	// DefaultBufferMaxBytes. It has no floor here — the configuration's minimum
	// protects operators, and a test needs a window of a few segments.
	BufferMaxBytes int64
	// SendTimeout bounds one delivery attempt. Zero means DefaultSendTimeout.
	SendTimeout time.Duration
	// RetryMin and RetryMax bound the drain backoff. Zero means the defaults.
	RetryMin time.Duration
	RetryMax time.Duration
	// MaxPayloadBytes caps a stream record's payload. Zero means
	// DefaultMaxPayloadBytes.
	MaxPayloadBytes int
	// Logf records the shipper's own operational events — an outage, a drain,
	// a dropped record, a refusal. It never receives a captured byte. Nil
	// discards them.
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
	// Batches is how many batch requests the server took.
	Batches uint64
	// Buffered is records written to the disk buffer, Drained is records the
	// buffer later delivered.
	Buffered uint64
	Drained  uint64
	// Dropped is records lost WITHOUT a report: no buffer configured, a write
	// that failed, a file that could not be read. It is the number that must
	// stay zero. An evicted or a refused record is not dropped — it is
	// accounted for and reported.
	Dropped uint64
	// Evicted and EvictedBytes are records the buffer's window pushed out,
	// each one reported in a logging.gap record — except a gap record itself,
	// which is counted here and reported by nothing (gap.go).
	Evicted      uint64
	EvictedBytes uint64
	// Refused is records the server refused and the proxy set aside rather
	// than resend (refusal.go).
	Refused uint64
	// Segments is how many buffer files are still owed to the server.
	Segments int
	// BufferedBytes is every byte the buffer holds on disk; PinnedBytes is the
	// part of it the window may not evict. Once PinnedBytes reaches the window
	// the proxy stops promising a new pinned session its record
	// (Deliverable).
	BufferedBytes int64
	PinnedBytes   int64
	// Degraded reports whether delivery is currently going to disk.
	Degraded bool
}

// Shipper delivers log records to Hoplock Control (D8).
//
// One goroutine owns delivery. Capture points hand it records over a channel
// and never block on the network, which is what lets a recorder sit in the path
// of a command decision. The goroutine batches ordinary records, flushes and
// then takes the dedicated endpoint for a critical one, and falls back to the
// disk buffer whenever the server will not take either — except for a record
// the server refuses outright, which is set aside instead of retried
// (refusal.go).
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

	// ending holds the pinned sessions whose session_end record has been
	// shipped, waiting for the moment nothing else they made can still be on
	// its way to disk (releaseEnded). The value is whether the end went
	// straight to disk past a full queue, which also has to wait for the queue.
	endMu       sync.Mutex
	ending      map[string]bool
	endingCount atomic.Int64

	queued   atomic.Uint64
	batched  atomic.Uint64
	priority atomic.Uint64
	batches  atomic.Uint64
	buffered atomic.Uint64
	drained  atomic.Uint64
	dropped  atomic.Uint64
	refused  atomic.Uint64
}

// New returns a started Shipper. Close stops it.
func New(opts Options) (*Shipper, error) {
	if opts.Client == nil {
		return nil, errors.New("logging: a management client is required")
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

	window := opts.BufferMaxBytes
	if window <= 0 {
		window = DefaultBufferMaxBytes
	}
	// The buffer reports evictions in records of its own, so it is built with
	// the shipper's clock and record ids — and after them.
	buffer, err := newDiskBuffer(bufferOptions{
		dir: opts.BufferDir, window: window, now: s.now, newID: s.newRecordID, logf: s.logf,
	})
	if err != nil {
		return nil, err
	}
	s.buffer = buffer

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
	s.enqueue(rec, false)
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
	s.enqueue(rec, true)
}

// enqueue hands a record to the delivery goroutine, or to disk when it cannot
// take one — never blocking. It is Record and RecordPriority without the
// count, and it is how the shipper's own reports (refusal.go) take the
// ordinary path.
func (s *Shipper) enqueue(rec control.LogRecord, priority bool) {
	kind, ch := kindBatch, s.queue
	if priority {
		kind, ch = kindPriority, s.prio
	}
	if s.stopped.Load() {
		s.spill(kind, []control.LogRecord{rec}, false)
		return
	}
	select {
	case ch <- rec:
	default:
		if priority {
			// The priority channel is full only if the server is taking longer
			// per record than the proxy is producing them. Buffering keeps the
			// record; it stays a priority record and drains to the priority
			// endpoint.
			s.logf("logging: priority queue full, buffering session=%s kind=%s", rec.SessionID, rec.Kind)
		} else {
			s.logf("logging: record queue full, buffering session=%s kind=%s", rec.SessionID, rec.Kind)
		}
		s.spill(kind, []control.LogRecord{rec}, false)
		// Past a full queue, ahead of records still in it.
		s.noteEnded([]control.LogRecord{rec}, true)
	}
}

// Deliverable reports whether a record emitted now has somewhere to go — and,
// since phase 0046, whether a session pinned now can be promised its record.
//
// It is not "is Hoplock Control reachable". A DISK BUFFER IS A LOGGING PATH
// WHILE ITS WINDOW HAS ROOM FOR A PINNED SESSION: a record written to it is
// owed to the server rather than lost, and PLAN §5.3's fail-closed rule and
// D16's required capture both turn on exactly that distinction — a route whose
// record is a bound, or whose attribution exists only in one record, is refused
// when there is nowhere to put it, and served when only the network
// destination is down. A buffer whose window is full of records it may not
// evict cannot promise a new pinned session its record, so it answers false,
// and every route that does not need the promise keeps running.
//
// With no buffer configured the network is the only path, and a record already
// counted as dropped is the proof that it is not there.
func (s *Shipper) Deliverable() bool {
	if s == nil || s.client == nil {
		return false
	}
	if s.buffer != nil {
		return s.buffer.hasRoomForPin()
	}
	return s.dropped.Load() == 0
}

// pin makes a session's records ones the buffer never evicts
// (SessionRecorder.Pin). With no buffer there is nothing to make durable and
// nothing that could be evicted, so it succeeds: Deliverable is what refuses a
// proxy with no path at all.
func (s *Shipper) pin(sessionID string) error {
	if s == nil {
		return errors.New("logging: this proxy has no telemetry pipeline to pin a session in")
	}
	if s.buffer == nil {
		return nil
	}
	return s.buffer.pin(sessionID)
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
	bs := s.buffer.stats()
	return Stats{
		Queued:        s.queued.Load(),
		Batched:       s.batched.Load(),
		Priority:      s.priority.Load(),
		Batches:       s.batches.Load(),
		Buffered:      s.buffered.Load(),
		Drained:       s.drained.Load(),
		Dropped:       s.dropped.Load() + bs.dropped,
		Evicted:       bs.evicted,
		EvictedBytes:  bs.evictedBytes,
		Refused:       s.refused.Load(),
		Segments:      bs.owed,
		BufferedBytes: bs.bytes,
		PinnedBytes:   bs.pinned,
		Degraded:      bs.owed > 0,
	}
}

// degraded reports whether delivery is currently going to disk. It is true
// exactly while the buffer holds something owed to the server: new records join
// it on disk rather than overtaking it, which is what keeps a drained session in
// order. A set-aside record is owed nothing and degrades nothing.
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
		s.releaseEnded(len(batch) == 0)

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
			err := s.drainBuffer()
			// What the drain refused was reported through the queue. Ship
			// that too, so a flush leaves nothing it caused behind it.
			s.drainQueue(&batch)
			s.drainPriority()
			s.sendBatch(&batch)
			reply <- err

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
			s.drainQueue(&batch)
			s.drainPriority()
			s.sendBatch(&batch)
			s.releaseEnded(true)
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
// what the server would not take YET goes to disk, what it refused is set
// aside, and a record is never in two of those places.
func (s *Shipper) sendBatch(batch *[]control.LogRecord) {
	if len(*batch) == 0 {
		return
	}
	recs := make([]control.LogRecord, len(*batch))
	copy(recs, *batch)
	*batch = (*batch)[:0]
	// However the batch goes, it has gone once this returns — and a session's
	// end going with it is what starts that session's pin on its way out.
	defer s.noteEnded(recs, false)

	if s.degraded() {
		// Something is already owed to the server. Joining the back of that
		// queue keeps the session's records in order.
		s.spill(kindBatch, recs, false)
		return
	}
	res := s.deliverBatch(recs)
	s.batched.Add(uint64(res.delivered))
	s.batches.Add(uint64(res.requests))
	s.refuse("on the batch path", res.delivered, res.refused)
	if res.err != nil {
		// Nothing the server has already taken goes to disk.
		s.logf("logging: %d of a batch of %d records not delivered, buffering: %v", len(res.owed), len(recs), res.err)
		s.spill(kindBatch, res.owed, true)
	}
}

// sendPriority delivers one critical record.
func (s *Shipper) sendPriority(rec control.LogRecord) {
	if s.degraded() {
		s.spill(kindPriority, []control.LogRecord{rec}, false)
		return
	}
	err := s.postPriority(rec)
	switch {
	case err == nil:
		s.priority.Add(1)
	case isRefusal(err):
		// The request is one record, so the refusal is already isolated.
		s.refuse("on the priority path", 0, []refusal{refusalOf(rec, err)})
	default:
		s.logf("logging: priority record not delivered, buffering: session=%s kind=%s: %v",
			rec.SessionID, rec.Kind, err)
		s.spill(kindPriority, []control.LogRecord{rec}, true)
	}
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

// spill writes records the server is still owed to the disk buffer: one file
// per session and class, because the buffer's layout is one area per session
// (PLAN §7) and eviction goes by class.
//
// A gap record is not spilled as a record at all: it goes to the buffer's gap
// store (putGap), which coalesces one that was never sent into the session's
// report for its cause and keeps one that was sent — which the server may hold
// already — exactly as it is. sent says which these records are.
func (s *Shipper) spill(kind deliveryKind, recs []control.LogRecord, sent bool) {
	if len(recs) == 0 {
		return
	}
	if s.buffer == nil {
		s.dropped.Add(uint64(len(recs)))
		s.logf("logging: %d records dropped: no buffer directory configured", len(recs))
		return
	}
	ordinary := make([]control.LogRecord, 0, len(recs))
	for _, rec := range recs {
		if !isGapRecord(rec) {
			ordinary = append(ordinary, rec)
			continue
		}
		if err := s.buffer.putGap(rec, sent); err != nil {
			s.dropped.Add(1)
			s.logf("logging: a logging.gap record was dropped: %v", err)
			continue
		}
		s.buffered.Add(1)
	}
	for _, group := range groupForSpill(kind, ordinary) {
		// A file is the unit of eviction, so none is bigger than a batch: a
		// flush or a critical record drains the whole queue into one batch,
		// and one file of all of it could outgrow the window and be evicted
		// whole, newest records included.
		for chunk := range slices.Chunk(group.records, s.batchSize) {
			evicted, err := s.buffer.appendSegment(group.sessionID, group.tag, chunk)
			switch {
			case err != nil:
				s.dropped.Add(uint64(len(chunk)))
				s.logf("logging: %d records dropped: %v", len(chunk), err)
			case evicted:
				// Counted and reported by the buffer, like any other eviction.
			default:
				s.buffered.Add(uint64(len(chunk)))
			}
		}
	}
}

// spillGroup is one session's records of one class, from a spilled batch.
type spillGroup struct {
	sessionID string
	tag       fileTag
	records   []control.LogRecord
}

// groupForSpill splits records by session and — on the batch path — by whether
// they are stream capture, preserving order within each group and the order
// the groups first appear.
//
// No file mixes stream capture with anything else, because the window evicts
// capture before metadata and a file of both would belong to neither class. A
// session's two files are written in the order their first records appeared,
// which gives up ordering BETWEEN the two classes within one spill, and only
// there: a chunk's position is its seq and offset_ms, and a metadata record's
// is its timestamp (PLAN §7).
func groupForSpill(kind deliveryKind, recs []control.LogRecord) []spillGroup {
	type key struct {
		sessionID string
		tag       fileTag
	}
	var groups []spillGroup
	index := map[key]int{}
	for _, rec := range recs {
		k := key{rec.SessionID, segmentTag(kind, rec.Kind == control.LogKindStream)}
		i, ok := index[k]
		if !ok {
			i = len(groups)
			index[k] = i
			groups = append(groups, spillGroup{sessionID: k.sessionID, tag: k.tag})
		}
		groups[i].records = append(groups[i].records, rec)
	}
	return groups
}

// sessionGroup is one session's slice of a set of records.
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
// first file the server will not take YET.
//
// Stopping matters: draining past an outage would deliver a session's later
// records before its earlier ones, and the whole point of the buffer is that an
// outage costs latency rather than fidelity. A refusal is not an outage: the
// refused records are set aside and the drain goes on to the next file, which
// is what keeps one record the server will never take from holding up every
// record behind it.
//
// The gap records go last, once every other file in the pass was delivered —
// after the surviving records they report on, which is the report arriving
// "once delivery resumes". Going last also keeps a report from ever being the
// probe that finds out whether the server is back: a report sent is a report
// frozen (buffer.go), and one sent into every retry of an outage would freeze
// once per retry, bounding the reports by the outage's length instead of by the
// sessions it touched.
func (s *Shipper) drainBuffer() error {
	if s.buffer == nil {
		return nil
	}
	records, reports := s.buffer.owedFiles()
	for _, seq := range append(records, reports...) {
		if err := s.drainFile(seq); err != nil {
			return err
		}
	}
	return nil
}

// drainFile delivers one buffered file, if it is still there to claim.
func (s *Shipper) drainFile(seq uint64) error {
	c, ok := s.buffer.claim(seq)
	if !ok {
		return nil // evicted since the snapshot
	}
	recs, err := s.buffer.load(c)
	if err != nil {
		// A file that cannot be read will never become readable. Removing it
		// is the only way the drain makes progress, and it is counted as the
		// loss it is rather than retried forever.
		s.logf("logging: discarding unreadable buffer segment %s: %v", c.path, err)
		s.dropped.Add(1)
		s.buffer.discard(c)
		return nil
	}
	var owed []control.LogRecord
	if len(recs) > 0 {
		owed, err = s.deliverFile(c, recs)
	}
	if serr := s.buffer.settle(c, owed, len(recs)); serr != nil {
		s.logf("logging: settle buffer segment %s: %v", c.path, serr)
		if err == nil {
			err = serr
		}
	}
	return err
}

// deliverFile sends one buffered file to the endpoint it is owed to, and
// returns what the server has still not taken: nothing once every record was
// delivered or refused, and — when a failure that is not a refusal stopped it —
// the rest, which the buffer keeps owed in place.
func (s *Shipper) deliverFile(c claim, recs []control.LogRecord) ([]control.LogRecord, error) {
	switch {
	case c.tag.isGap():
		return s.deliverEach(recs, "draining a logging.gap record", func(rec control.LogRecord) error {
			// A report is owed by its own severity, which a later eviction
			// can have raised since it was written.
			if rec.Severity == control.SeverityCritical {
				return s.postCounted(rec)
			}
			if err := s.postBatch([]control.LogRecord{rec}); err != nil {
				return err
			}
			s.batched.Add(1)
			s.batches.Add(1)
			return nil
		})
	case c.tag == tagPriority:
		// One record at a time, as a priority record always is: the endpoint
		// takes one, and a critical record is never folded into a batch.
		return s.deliverEach(recs, "draining a priority segment", s.postCounted)
	}
	res := s.deliverBatch(recs)
	s.batched.Add(uint64(res.delivered))
	s.batches.Add(uint64(res.requests))
	s.drained.Add(uint64(res.delivered))
	s.refuse("draining a batch segment", res.delivered, res.refused)
	return res.owed, res.err
}

// deliverEach delivers records one at a time with post, setting aside what the
// server refuses and stopping at the first failure that is not a refusal.
func (s *Shipper) deliverEach(recs []control.LogRecord, where string, post func(control.LogRecord) error) ([]control.LogRecord, error) {
	var refused []refusal
	delivered := 0
	for i, rec := range recs {
		err := post(rec)
		switch {
		case err == nil:
			delivered++
			s.drained.Add(1)
		case isRefusal(err):
			refused = append(refused, refusalOf(rec, err))
		default:
			s.refuse(where, delivered, refused)
			return recs[i:], err
		}
	}
	s.refuse(where, delivered, refused)
	return nil, nil
}

// postCounted posts one record to the priority endpoint and counts it.
func (s *Shipper) postCounted(rec control.LogRecord) error {
	if err := s.postPriority(rec); err != nil {
		return err
	}
	s.priority.Add(1)
	return nil
}

// noteEnded starts a pinned session's pin on its way out once its session_end
// record has been shipped — delivered, or spilled.
//
// session_end is the last record a session's recorder makes: internal/proxy
// records it after teardown, so after every other record of that session has
// been handed over. What can still be in transit then is a critical record
// waiting in the priority queue — the delivery goroutine picks among ready
// channels at random — and, when the end went straight to disk past a full
// queue, the records still in that queue. releaseEnded waits for both.
func (s *Shipper) noteEnded(recs []control.LogRecord, overflow bool) {
	if s.buffer == nil {
		return
	}
	for _, rec := range recs {
		if rec.Kind != control.LogKindSessionEnd || !s.buffer.livePinned(rec.SessionID) {
			continue
		}
		s.endMu.Lock()
		if s.ending == nil {
			s.ending = map[string]bool{}
		}
		s.ending[rec.SessionID] = s.ending[rec.SessionID] || overflow
		s.endingCount.Store(int64(len(s.ending)))
		s.endMu.Unlock()
	}
}

// releaseEnded lets go of the pins noteEnded armed, once nothing their sessions
// made can still reach the disk unpinned: the priority queue is empty, and for
// an end that overtook a full queue, the queue and the batch are too. What such
// a session left on disk stays pinned until it is delivered (buffer.release).
func (s *Shipper) releaseEnded(batchEmpty bool) {
	if s.endingCount.Load() == 0 || len(s.prio) > 0 {
		return
	}
	queueIdle := batchEmpty && len(s.queue) == 0
	var ready []string
	s.endMu.Lock()
	for sessionID, overflow := range s.ending {
		if overflow && !queueIdle {
			continue
		}
		ready = append(ready, sessionID)
		delete(s.ending, sessionID)
	}
	s.endingCount.Store(int64(len(s.ending)))
	s.endMu.Unlock()
	for _, sessionID := range ready {
		s.buffer.release(sessionID)
	}
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
