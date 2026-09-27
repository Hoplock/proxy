// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
	"bufio"
	"bytes"
	"container/list"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// The disk buffer is PLAN §7's resilience layer: when Hoplock Control is
// unreachable, records go here instead of being lost, and drain in order once
// it answers again. It is a buffer and never a destination — nothing reads it
// but the drain loop, and a segment is removed the moment the server has it.
//
// LAYOUT. One directory per session, which is what PLAN §7 asks for and also
// what makes an operator's "what happened to session X while the link was
// down" answerable with ls:
//
//	<dir>/<session>/<seq>.batch.jsonl        records owed to /v1/logs/batch
//	<dir>/<session>/<seq>.stream.jsonl       stream capture owed to /v1/logs/batch
//	<dir>/<session>/<seq>.priority.jsonl     records owed to /v1/logs/priority
//	<dir>/<session>/<seq>.gap-evicted.jsonl  a logging.gap record: what the window evicted
//	<dir>/<session>/<seq>.gap-refused.jsonl  a logging.gap record: a refusal not yet reported
//	<dir>/<session>/<seq>.refused.jsonl      set aside: refused by the server, never resent
//	<dir>/<session>/.pinned                  this session's records are never evicted
//
// Every file but .pinned is one control.LogRecord per line, as JSON, so
// `jq . <dir>/*/*.refused.jsonl` is everything the server refused. seq is a
// zero-padded global counter, so sorting file names across every session
// directory replays them in the order they were written — the property that
// makes "nothing is lost" also mean "nothing is reordered". A file is written
// under a .partial name and renamed into place, so nothing reads half a record.
//
// A segment never mixes stream capture with any other record, because eviction
// goes by class (below) and a segment of two classes would have none, and it
// holds at most a batch: a file is the unit of eviction, and one bigger than
// the window would go whole. A gap record is owed by its own severity —
// critical to the priority endpoint, anything else to the batch one — because a
// later eviction can make an undelivered report critical, and the drain sends
// the reports last in each pass, after the records they report on
// (Shipper.drainBuffer). <session> is sessionDirName, which never begins with a
// dot, so .pinned can never be one of a session's files.
//
// COMPATIBILITY. An older binary delivers batch and priority segments exactly as
// it always did and ignores every other file here. It never mis-delivers one: a
// set-aside record it resent would be refused again and stall its whole drain,
// which is the defect this layout exists to end. A segment written before this
// layout may mix stream capture with other records; it is read as batch, the
// class that loses nothing by the mistake.
//
// THE WINDOW (phase 0046, D8 as amended). The buffer holds at most window bytes
// — every file counts: segments of every class, set-aside records and gap
// records. An append that would take it over evicts WHOLE files, taking the
// first class that has one and the oldest (lowest seq) within that class:
//
//  1. set-aside records: refused, kept only for an operator to inspect;
//  2. stream capture: bulky, and serving replay only;
//  3. other batch records: who, where, which command, which decision;
//  4. priority records, last, because D8 exists to keep them.
//
// NEVER EVICTED: a file in a pinned session's directory, a gap record, and the
// file the drain is delivering at that moment. The append itself counts as the
// newest file of its class, so when everything ranked below it cannot make the
// room it is evicted instead — counted and reported like any other eviction —
// and nothing ranked above it is touched. A pinned append (a pinned session's,
// or a gap record) is written even over the window once nothing evictable is
// left; how far over is bounded by the sessions admitted while there was room
// (PLAN §7). A gap record an eviction creates is written the same way — the
// next append makes room for it.
//
// PINNING. A session whose record is a bound (D16's require_session_capture) or
// the only attribution there is (PLAN §5.3's constrained naming) is pinned: its
// directory gets a .pinned marker, written and synced before Pin returns, and
// nothing under it is evicted — what it spilled before the pin, its set-aside
// records, and everything after. The marker is what makes a pin survive a
// restart. It goes when the session has ended and nothing of it is left on
// disk.
//
// EVICTIONS ARE ACCOUNTED DURABLY. The gap record reporting an eviction is
// written and synced before the files it counts are removed, in the same
// critical section. A crash between the two can leave a report of records that
// are then delivered after all; the other order could leave records gone with
// no report, which is the failure this rule exists to prevent.
//
// Each session has one undelivered gap record per cause that later evictions
// rewrite in place, so reports are bounded by the sessions affected and not by
// how long the outage lasted — until that record is first SENT. A record the
// server may already hold is never changed under its record_id: the server
// de-duplicates on it, so the change would be silently dropped. A report that
// has been sent (and is being retried) or was adopted from a previous run stays
// byte-for-byte as it is, and the next eviction starts another, which bounds a
// session at two undelivered reports per cause rather than one.

// deliveryKind is which endpoint a record is owed to. A priority record that
// fell back to disk must still reach the priority endpoint when it drains: an
// outage does not downgrade a blocked command to ordinary telemetry.
type deliveryKind string

const (
	kindBatch    deliveryKind = "batch"
	kindPriority deliveryKind = "priority"
)

// fileTag is the middle of a buffer file's name: what the file holds, and so
// where it is owed and when it may be evicted.
type fileTag string

const (
	tagBatch      fileTag = "batch"
	tagStream     fileTag = "stream"
	tagPriority   fileTag = "priority"
	tagRefused    fileTag = "refused"
	tagGapEvicted fileTag = "gap-evicted"
	tagGapRefused fileTag = "gap-refused"
)

// The eviction classes, in the order they go.
const (
	classRefused = iota
	classStream
	classBatch
	classPriority
	numClasses
)

// class is the tag's eviction class, or -1 for a gap record, which is never
// evicted.
func (t fileTag) class() int {
	switch t {
	case tagRefused:
		return classRefused
	case tagStream:
		return classStream
	case tagBatch:
		return classBatch
	case tagPriority:
		return classPriority
	}
	return -1
}

func (t fileTag) known() bool { return t.class() >= 0 || t.isGap() }

func (t fileTag) isGap() bool { return t == tagGapEvicted || t == tagGapRefused }

// owed reports whether the server is still owed the file. A set-aside record
// is not: the server refused it, and it is kept only for an operator.
func (t fileTag) owed() bool { return t != tagRefused }

func (t fileTag) gapCause() string {
	if t == tagGapRefused {
		return GapCauseRefused
	}
	return GapCauseEvicted
}

func gapTag(cause string) fileTag {
	if cause == GapCauseRefused {
		return tagGapRefused
	}
	return tagGapEvicted
}

// segmentTag is the tag a spilled group of records is written under.
func segmentTag(kind deliveryKind, stream bool) fileTag {
	switch {
	case kind == kindPriority:
		return tagPriority
	case stream:
		return tagStream
	}
	return tagBatch
}

// segmentSeqWidth zero-pads the sequence so that lexical order is numeric
// order. Twenty digits covers uint64.
const segmentSeqWidth = 20

const (
	segmentSuffix = ".jsonl"
	stagingSuffix = ".partial"
	pinMarker     = ".pinned"
)

func fileName(seq uint64, tag fileTag) string {
	return fmt.Sprintf("%0*d.%s%s", segmentSeqWidth, seq, tag, segmentSuffix)
}

// parseFileName reads a buffer file's sequence and tag back out of its name.
func parseFileName(name string) (uint64, fileTag, bool) {
	base, ok := strings.CutSuffix(name, segmentSuffix)
	if !ok {
		return 0, "", false
	}
	seqText, tagText, ok := strings.Cut(base, ".")
	if !ok {
		return 0, "", false
	}
	tag := fileTag(tagText)
	if !tag.known() {
		return 0, "", false
	}
	seq, err := strconv.ParseUint(seqText, 10, 64)
	if err != nil {
		return 0, "", false
	}
	return seq, tag, true
}

// bufEntry is one file the buffer holds.
type bufEntry struct {
	seq  uint64
	tag  fileTag
	size int64
	area *sessionArea
	// elem is the file's place in its eviction class, and nil while it cannot
	// be evicted: a gap record, or a file under a pinned session.
	elem *list.Element
	// inFlight marks the file the drain is delivering. It is never evicted and
	// never rewritten by anything else until the drain settles it.
	inFlight bool
	// gap is the tally of a gap record that later reports may still be
	// coalesced into: one this process wrote and has never sent. It is nil for
	// every other file, a sent or adopted report included.
	gap *gapTally
}

// sessionArea is one session's directory.
type sessionArea struct {
	name  string
	files map[uint64]*bufEntry
	// pinned is whether the .pinned marker is on disk. live is whether a
	// session still running holds the pin, which keeps the marker while the
	// directory is empty: the session's next record is pinned too.
	pinned bool
	live   bool
}

// gapKey names the one undelivered gap record per session and cause.
type gapKey struct {
	area  string
	cause string
}

// bufferOptions configure a diskBuffer.
type bufferOptions struct {
	dir    string
	window int64
	now    func() time.Time
	newID  func() string
	logf   func(format string, args ...any)
}

// diskBuffer is the local resilience buffer.
//
// A nil *diskBuffer is usable and buffers nothing, which is what a proxy
// configured without a buffer directory gets: records it cannot deliver are
// counted as dropped rather than silently pretended to be safe.
type diskBuffer struct {
	dir    string
	window int64
	now    func() time.Time
	newID  func() string
	logf   func(format string, args ...any)

	// mu is held across every file operation that changes what the buffer
	// holds. Eviction runs on whichever goroutine appends — a capture point can
	// spill straight to disk — and the drain claims and settles under it, so
	// the two never meet on one file.
	mu      sync.Mutex
	seq     uint64
	areas   map[string]*sessionArea
	entries map[uint64]*bufEntry
	classes [numClasses]*list.List
	// gaps is the gap record per session and cause that later reports are
	// coalesced into. Only a record never sent is here: the drain takes one out
	// as it claims it, and it does not come back.
	gaps map[gapKey]*bufEntry

	bytes  int64 // every byte of every file
	pinned int64 // the bytes that may not be evicted: pinned sessions' files and gap records
	owed   int   // files still owed to the server

	evicted      uint64
	evictedBytes uint64
	dropped      uint64
	// evicting is whether an eviction episode has been logged; the drain
	// emptying the buffer ends it.
	evicting bool
}

// newDiskBuffer prepares the buffer directory and adopts whatever a previous
// run left behind.
//
// Adoption is the point: a proxy that crashed mid-outage has records on disk
// that nobody else will ever ship, and starting the sequence at zero would
// interleave the new run's records with the old run's on drain. The byte count
// is recomputed from what is actually there, and a window lowered since the
// last run is enforced at once, by the same rules as any other eviction.
func newDiskBuffer(opts bufferOptions) (*diskBuffer, error) {
	if opts.dir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(opts.dir, 0o700); err != nil {
		return nil, fmt.Errorf("logging: create buffer directory: %w", err)
	}
	b := &diskBuffer{
		dir:     opts.dir,
		window:  opts.window,
		now:     opts.now,
		newID:   opts.newID,
		logf:    opts.logf,
		areas:   map[string]*sessionArea{},
		entries: map[uint64]*bufEntry{},
		gaps:    map[gapKey]*bufEntry{},
	}
	if b.window <= 0 {
		b.window = DefaultBufferMaxBytes
	}
	if b.now == nil {
		b.now = time.Now
	}
	if b.newID == nil {
		b.newID = newRecordID
	}
	if b.logf == nil {
		b.logf = func(string, ...any) {}
	}
	for i := range b.classes {
		b.classes[i] = list.New()
	}
	// Staging files are the remains of a write that did not finish. They were
	// never complete records, so removing them is the only safe reading.
	b.sweepStaging()

	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.adoptLocked(); err != nil {
		return nil, err
	}
	if _, err := b.makeRoomLocked(nil); err != nil {
		b.logf("logging: the adopted buffer is over its window and could not be evicted down to it: %v", err)
	}
	return b, nil
}

// adoptLocked indexes what a previous run left on disk.
func (b *diskBuffer) adoptLocked() error {
	top, err := os.ReadDir(b.dir)
	if err != nil {
		return fmt.Errorf("logging: read buffer directory: %w", err)
	}
	var adopted []*bufEntry
	for _, d := range top {
		if !d.IsDir() {
			continue
		}
		area := &sessionArea{name: d.Name(), files: map[uint64]*bufEntry{}}
		names, err := os.ReadDir(filepath.Join(b.dir, area.name))
		if err != nil {
			return fmt.Errorf("logging: read session buffer: %w", err)
		}
		for _, f := range names {
			if f.Name() == pinMarker {
				area.pinned = true
				continue
			}
			seq, tag, ok := parseFileName(f.Name())
			if !ok {
				continue
			}
			info, err := f.Info()
			if err != nil {
				continue // gone since the listing
			}
			e := &bufEntry{seq: seq, tag: tag, size: info.Size(), area: area}
			area.files[seq] = e
			adopted = append(adopted, e)
		}
		b.areas[area.name] = area
		// A pin with nothing left under it belonged to a session that ended
		// before the previous run did.
		b.gcAreaLocked(area)
	}
	slices.SortFunc(adopted, func(x, y *bufEntry) int { return compareSeq(x.seq, y.seq) })
	for _, e := range adopted {
		if e.seq >= b.seq {
			b.seq = e.seq + 1
		}
		b.indexLocked(e)
	}
	return nil
}

func compareSeq(x, y uint64) int {
	switch {
	case x < y:
		return -1
	case x > y:
		return 1
	}
	return 0
}

// --- appending ---------------------------------------------------------------

// appendSegment writes one session's records as a new file of the given tag,
// making room for it under the window first.
//
// evicted reports that the records were themselves evicted instead of written:
// everything ranked below them could not make the room. They are then counted
// and reported exactly like any other eviction — and are not on disk.
func (b *diskBuffer) appendSegment(sessionID string, tag fileTag, recs []control.LogRecord) (evicted bool, err error) {
	if b == nil || len(recs) == 0 {
		return false, errors.New("logging: no disk buffer configured")
	}
	data, sizes, err := encodeRecords(recs)
	if err != nil {
		return false, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	name := sessionDirName(sessionID)
	dropped, err := b.makeRoomLocked(&incoming{
		area: b.areaLocked(name), tag: tag, size: int64(len(data)), recs: recs, sizes: sizes,
	})
	if err != nil {
		b.gcAreaLocked(b.areaLocked(name))
		return false, err
	}
	if dropped {
		return true, nil
	}
	// Looked up again: making room can have emptied, and so forgotten, the
	// session's own directory.
	area := b.areaLocked(name)
	if _, err := b.writeLocked(area, tag, data, false); err != nil {
		b.gcAreaLocked(area)
		return false, err
	}
	return false, nil
}

// putGap keeps a logging.gap record that could not be delivered live.
//
// One that was never sent is coalesced into the session's report for the same
// cause, or becomes it, so a report spilled behind an outage never makes one
// report per session two. One that WAS sent is kept exactly as it is: the
// server may hold it already (a timeout after it committed), and it
// de-duplicates on record_id, so it must arrive again byte for byte or not at
// all — coalescing into it would change it under an id the server would then
// ignore, and merging it into another would count it twice.
//
// A gap record is never evicted, so this is a pinned append: it makes room if
// it can, and is written over the window if it cannot.
func (b *diskBuffer) putGap(rec control.LogRecord, sent bool) error {
	if b == nil {
		return errors.New("logging: no disk buffer configured")
	}
	cause := rec.Attributes[AttrGapCause]
	if !isGapRecord(rec) || (cause != GapCauseEvicted && cause != GapCauseRefused) {
		return errors.New("logging: not a logging.gap record")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	name := sessionDirName(rec.SessionID)
	key := gapKey{name, cause}
	t, parsed := gapFromRecord(rec)
	coalesce := !sent && parsed
	if base := b.gaps[key]; coalesce && base != nil {
		// The report's growth is room to make first. Making it can rewrite
		// this very report — an eviction coalesces into it too — so the merge
		// is done against whatever it holds once the room is made.
		grown := base.gap.clone()
		grown.merge(t)
		if _, err := b.makeRoomLocked(&incoming{area: b.areaLocked(name), tag: base.tag,
			size: max(encodedSize(grown.record(b.now()))-base.size, 0)}); err != nil {
			return err
		}
		merged := base.gap.clone()
		merged.merge(t)
		data, _, err := encodeRecords([]control.LogRecord{merged.record(b.now())})
		if err != nil {
			return err
		}
		if err := b.rewriteLocked(base, data, true); err != nil {
			return err
		}
		base.gap = merged
		return nil
	}

	data, _, err := encodeRecords([]control.LogRecord{rec})
	if err != nil {
		return err
	}
	if _, err := b.makeRoomLocked(&incoming{area: b.areaLocked(name), tag: gapTag(cause), size: int64(len(data))}); err != nil {
		return err
	}
	e, err := b.writeLocked(b.areaLocked(name), gapTag(cause), data, true)
	if err != nil {
		return err
	}
	if coalesce && b.gaps[key] == nil {
		e.gap = t
		b.gaps[key] = e
	}
	return nil
}

// --- pinning -----------------------------------------------------------------

// pin makes a session's records unevictable, durably: the marker is written and
// synced before it returns, so a pin survives the crash the buffer exists for.
// It never refuses on window grounds; Shipper.Deliverable is the gate.
func (b *diskBuffer) pin(sessionID string) error {
	if b == nil {
		return nil
	}
	if sessionID == "" {
		return errors.New("logging: a record that belongs to no session cannot be pinned")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	area := b.areaLocked(sessionDirName(sessionID))
	if !area.pinned {
		if err := b.writeMarkerLocked(area); err != nil {
			b.gcAreaLocked(area)
			return fmt.Errorf("logging: pin session %s: %w", sessionID, err)
		}
		area.pinned = true
		// Everything the session spilled before anyone knew it needed pinning
		// — its handshake, its authentication — is pinned with it.
		for _, e := range area.files {
			if e.elem != nil {
				b.classes[e.tag.class()].Remove(e.elem)
				e.elem = nil
				b.pinned += e.size
			}
		}
	}
	area.live = true
	return nil
}

// release lets a pin go once its session has ended and everything it made has
// been shipped or spilled (Shipper.releaseEnded). What the session left on disk
// stays pinned until it is delivered; the marker goes with the last of it.
func (b *diskBuffer) release(sessionID string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if area := b.areas[sessionDirName(sessionID)]; area != nil {
		area.live = false
		b.gcAreaLocked(area)
	}
}

// livePinned reports whether a running session holds a pin.
func (b *diskBuffer) livePinned(sessionID string) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	area := b.areas[sessionDirName(sessionID)]
	return area != nil && area.live
}

// hasRoomForPin reports whether the pinned bytes are still below the window:
// whether a new pinned session can be promised its record (Deliverable).
func (b *diskBuffer) hasRoomForPin() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pinned < b.window
}

func (b *diskBuffer) writeMarkerLocked(area *sessionArea) error {
	dir, created, err := b.ensureAreaDirLocked(area)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, pinMarker)
	if err := writeFileSync(path, nil); err != nil {
		_ = os.Remove(path)
		return err
	}
	if err := syncDirs(dir, created, b.dir); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

// --- eviction ----------------------------------------------------------------

// incoming is an append the window has to make room for.
type incoming struct {
	area *sessionArea
	tag  fileTag
	size int64
	// recs and sizes are what a report counts if the append is itself evicted.
	recs  []control.LogRecord
	sizes []int
}

// evictable reports whether the append could be evicted in place of what is
// already there: it is neither pinned nor a gap record.
func (inc *incoming) evictable() bool {
	return inc != nil && inc.tag.class() >= 0 && !inc.area.pinned
}

// makeRoomLocked evicts what has to go for inc to fit under the window, in
// class order, and reports whether inc must itself be evicted. inc is nil when
// there is no append — an adopted buffer over a lowered window.
func (b *diskBuffer) makeRoomLocked(inc *incoming) (dropped bool, err error) {
	var size int64
	if inc != nil {
		size = inc.size
	}
	if b.bytes+size <= b.window {
		return false, nil
	}
	at := b.now()

	if inc.evictable() {
		// Kept, if what ranks below it — a lower class, or older in its own —
		// can make the room.
		plan := b.newPlanLocked(at)
		if b.fillLocked(plan, size, inc.tag.class()) {
			return false, b.applyLocked(plan)
		}
		// It cannot, so keeping the append would cost a record ranked above
		// it. The append goes instead, and takes nothing with it: dropping it
		// frees all the room it needed.
		plan = b.newPlanLocked(at)
		plan.dropIncoming(inc)
		b.fillLocked(plan, 0, numClasses-1)
		return true, b.applyLocked(plan)
	}

	// A pinned append, or none: evict in class order until it fits. With
	// nothing evictable left, a pinned append is written over the window.
	plan := b.newPlanLocked(at)
	b.fillLocked(plan, size, numClasses-1)
	return false, b.applyLocked(plan)
}

// fillLocked adds victims to plan, class by class up to maxClass and oldest
// first within each, until an append of extra bytes fits. It reports whether
// it does.
func (b *diskBuffer) fillLocked(plan *evictionPlan, extra int64, maxClass int) bool {
	for c := 0; c <= maxClass; c++ {
		for el := b.classes[c].Front(); el != nil; el = el.Next() {
			if plan.fits(extra) {
				return true
			}
			if e := el.Value.(*bufEntry); !e.inFlight {
				plan.add(e)
			}
		}
	}
	return plan.fits(extra)
}

// evictionPlan is one eviction, worked out before any file is touched: the
// victims, and the report each affected session gets.
type evictionPlan struct {
	b  *diskBuffer
	at time.Time
	// reports holds one report per session directory, in the order the plan
	// first touched them.
	reports []*planReport
	byArea  map[string]*planReport
	freed   int64
	// growth is how much the undelivered reports being rewritten grow. A
	// report the plan creates is written like any pinned append, and the next
	// append makes room for it; counting it here would evict records to make
	// room for the report of their own eviction.
	growth     int64
	unreadable []unreadableFile
}

// unreadableFile is a victim that cannot be read, and so cannot be reported.
type unreadableFile struct {
	entry *bufEntry
	err   error
}

// planReport is one session's share of an eviction.
type planReport struct {
	area    string
	base    *bufEntry // the undelivered report being rewritten, nil if the plan creates one
	tally   *gapTally
	size    int64 // the rewritten report's encoded size
	victims []*bufEntry
	records uint64
	bytes   uint64
	// incoming marks the report of an append that is itself evicted. It is
	// applied last, so a failure leaves the append unreported only when it
	// also leaves it unevicted.
	incoming bool
}

func (b *diskBuffer) newPlanLocked(at time.Time) *evictionPlan {
	return &evictionPlan{b: b, at: at, byArea: map[string]*planReport{}}
}

func (p *evictionPlan) fits(extra int64) bool {
	return p.b.bytes-p.freed+p.growth+extra <= p.b.window
}

// report is the session's report in this plan, starting from its undelivered
// one when there is one.
func (p *evictionPlan) report(area string) *planReport {
	if r := p.byArea[area]; r != nil {
		return r
	}
	r := &planReport{area: area}
	if base := p.b.gaps[gapKey{area, GapCauseEvicted}]; base != nil {
		r.base, r.tally, r.size = base, base.gap.clone(), base.size
	} else {
		r.tally = newGapTally(p.b.newID(), GapCauseEvicted, "")
	}
	p.byArea[area] = r
	p.reports = append(p.reports, r)
	return r
}

// add makes e a victim, reading it for its report.
func (p *evictionPlan) add(e *bufEntry) {
	p.freed += e.size
	recs, sizes, err := readForReport(p.b.pathLocked(e))
	if err != nil {
		// A file that cannot be read can only be lost, not reported: it is
		// counted as dropped, the one number that must stay zero.
		p.unreadable = append(p.unreadable, unreadableFile{entry: e, err: err})
		return
	}
	r := p.report(e.area.name)
	r.victims = append(r.victims, e)
	r.bytes += uint64(e.size)
	p.count(r, recs, sizes)
}

// dropIncoming makes the append itself a victim.
func (p *evictionPlan) dropIncoming(inc *incoming) {
	r := p.report(inc.area.name)
	r.incoming = true
	r.bytes += uint64(inc.size)
	p.count(r, inc.recs, inc.sizes)
}

// count folds evicted records into a report. A gap record that is itself
// evicted — one the server refused, sitting in the set-aside area — is counted
// as evicted and reported by nothing: a gap record never begets another.
func (p *evictionPlan) count(r *planReport, recs []control.LogRecord, sizes []int) {
	for i, rec := range recs {
		r.records++
		if isGapRecord(rec) {
			continue
		}
		if r.base == nil && r.tally.records == 0 {
			r.tally.sessionID = rec.SessionID
		}
		r.tally.add(rec, int64(sizes[i]))
	}
	if r.base != nil {
		size := encodedSize(r.tally.record(p.at))
		p.growth += size - r.size
		r.size = size
	}
}

// applyLocked carries the plan out, one session at a time: its report is
// written and synced, and only then are the files it counts removed.
func (b *diskBuffer) applyLocked(p *evictionPlan) error {
	reports := slices.Clone(p.reports)
	slices.SortStableFunc(reports, func(x, y *planReport) int {
		switch {
		case x.incoming == y.incoming:
			return 0
		case x.incoming:
			return 1
		}
		return -1
	})
	for _, r := range reports {
		if r.tally.records > 0 {
			if err := b.writeReportLocked(r, p.at); err != nil {
				return fmt.Errorf("logging: write the report of an eviction: %w", err)
			}
		}
		for _, v := range r.victims {
			if err := b.removeLocked(v); err != nil {
				b.logf("logging: evicted buffer file could not be removed: %v", err)
			}
		}
		b.evicted += r.records
		b.evictedBytes += r.bytes
		if r.records > 0 && !b.evicting {
			// Once per episode: every eviction is reported to the server, and
			// the operator's log needs to say only that it has started.
			b.evicting = true
			b.logf("logging: the disk buffer's window of %d bytes is full: evicting the oldest records that are not pinned, "+
				"in class order, each reported in a %s record", b.window, EventLoggingGap)
		}
	}
	for _, u := range p.unreadable {
		b.logf("logging: discarding unreadable buffer file %s to make room: %v", b.pathLocked(u.entry), u.err)
		if err := b.removeLocked(u.entry); err != nil {
			b.logf("logging: unreadable buffer file could not be removed: %v", err)
		}
		b.dropped++
	}
	return nil
}

// writeReportLocked rewrites a session's undelivered report in place, or
// writes its first.
func (b *diskBuffer) writeReportLocked(r *planReport, at time.Time) error {
	data, _, err := encodeRecords([]control.LogRecord{r.tally.record(at)})
	if err != nil {
		return err
	}
	if r.base != nil {
		if err := b.rewriteLocked(r.base, data, true); err != nil {
			return err
		}
		r.base.gap = r.tally
		return nil
	}
	e, err := b.writeLocked(b.areaLocked(r.area), tagGapEvicted, data, true)
	if err != nil {
		return err
	}
	// Never sent, so the session's next eviction is coalesced into it.
	e.gap = r.tally
	b.gaps[gapKey{r.area, GapCauseEvicted}] = e
	return nil
}

// --- draining ----------------------------------------------------------------

// claim is a file the drain is delivering.
type claim struct {
	seq  uint64
	tag  fileTag
	path string
}

// owedFiles is every file still owed to the server, oldest first: the drain's
// work list, with the gap records apart from the records they report on. It is
// a snapshot; a file evicted since is simply not claimable.
func (b *diskBuffer) owedFiles() (records, reports []uint64) {
	if b == nil {
		return nil, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for seq, e := range b.entries {
		switch {
		case e.tag.isGap():
			reports = append(reports, seq)
		case e.tag.owed():
			records = append(records, seq)
		}
	}
	slices.Sort(records)
	slices.Sort(reports)
	return records, reports
}

// claim marks a file in flight: from here until settle, nothing evicts it and
// nothing rewrites it. A gap record claimed is a gap record sent — the server
// may hold it from here on — so it leaves the coalescing index for good, and a
// later eviction starts a new report rather than changing this one under an id
// the server would ignore.
func (b *diskBuffer) claim(seq uint64) (claim, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.entries[seq]
	if e == nil || e.inFlight || !e.tag.owed() {
		return claim{}, false
	}
	e.inFlight = true
	if e.tag.isGap() {
		if key := (gapKey{e.area.name, e.tag.gapCause()}); b.gaps[key] == e {
			delete(b.gaps, key)
		}
		e.gap = nil
	}
	return claim{seq: seq, tag: e.tag, path: b.pathLocked(e)}, true
}

// settle ends a claim. owed is what the server still has not taken: none of
// it, and the file goes; all of it, and the file stays as it was; part of it,
// and the file is rewritten atomically to hold exactly that part — nothing the
// server took is sent again, and nothing is sent to an endpoint it was not owed
// to.
func (b *diskBuffer) settle(c claim, owed []control.LogRecord, total int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.entries[c.seq]
	if e == nil {
		return nil
	}
	e.inFlight = false
	switch {
	case len(owed) == 0:
		err := b.removeLocked(e)
		if b.owed == 0 {
			b.evicting = false
		}
		return err
	case len(owed) >= total:
		return nil
	}
	data, _, err := encodeRecords(owed)
	if err != nil {
		return err
	}
	return b.rewriteLocked(e, data, false)
}

// discard removes a claimed file that cannot be read. It will never become
// readable, and removing it is the only way the drain makes progress.
func (b *diskBuffer) discard(c claim) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.entries[c.seq]; e != nil {
		_ = b.removeLocked(e)
	}
}

// load reads a claimed file's records back.
func (b *diskBuffer) load(c claim) ([]control.LogRecord, error) {
	return loadRecords(c.path)
}

// --- what the buffer holds ---------------------------------------------------

// bufferStats is the buffer's half of Shipper.Stats.
type bufferStats struct {
	bytes, pinned                  int64
	owed                           int
	evicted, evictedBytes, dropped uint64
}

func (b *diskBuffer) stats() bufferStats {
	if b == nil {
		return bufferStats{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return bufferStats{
		bytes: b.bytes, pinned: b.pinned, owed: b.owed,
		evicted: b.evicted, evictedBytes: b.evictedBytes, dropped: b.dropped,
	}
}

// pending is how many files are still owed to the server. It is what makes the
// shipper "degraded": while anything is owed, new records join it on disk
// rather than overtaking it. A set-aside record is not owed and does not count.
func (b *diskBuffer) pending() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.owed
}

// --- the index and the files behind it ---------------------------------------

func (b *diskBuffer) areaLocked(name string) *sessionArea {
	area := b.areas[name]
	if area == nil {
		area = &sessionArea{name: name, files: map[uint64]*bufEntry{}}
		b.areas[name] = area
	}
	return area
}

// gcAreaLocked forgets a session directory with nothing left in it, removing
// its marker and the directory itself — unless a running session still holds
// the pin, whose next record must find the marker there.
func (b *diskBuffer) gcAreaLocked(area *sessionArea) {
	if len(area.files) > 0 || area.live {
		return
	}
	dir := filepath.Join(b.dir, area.name)
	if area.pinned {
		if err := os.Remove(filepath.Join(dir, pinMarker)); err != nil && !errors.Is(err, os.ErrNotExist) {
			// The marker stays, and the next run adopts an empty pinned
			// directory and removes it: the safe way to be wrong.
			b.logf("logging: remove the pin of an empty session buffer: %v", err)
		}
	}
	_ = os.Remove(dir) // best effort: a directory holding anything else stays
	delete(b.areas, area.name)
}

func (b *diskBuffer) pathLocked(e *bufEntry) string {
	return filepath.Join(b.dir, e.area.name, fileName(e.seq, e.tag))
}

// indexLocked accounts for a file now on disk.
func (b *diskBuffer) indexLocked(e *bufEntry) {
	e.area.files[e.seq] = e
	b.entries[e.seq] = e
	b.bytes += e.size
	if e.tag.owed() {
		b.owed++
	}
	switch {
	case e.tag.isGap(), e.area.pinned:
		b.pinned += e.size
	default:
		e.elem = b.classes[e.tag.class()].PushBack(e)
	}
}

// removeLocked deletes a file and everything the index knew about it.
func (b *diskBuffer) removeLocked(e *bufEntry) error {
	err := os.Remove(b.pathLocked(e))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("logging: remove buffered file: %w", err)
	}
	delete(e.area.files, e.seq)
	delete(b.entries, e.seq)
	b.bytes -= e.size
	if e.tag.owed() {
		b.owed--
	}
	if e.elem != nil {
		b.classes[e.tag.class()].Remove(e.elem)
		e.elem = nil
	} else {
		b.pinned -= e.size
	}
	if e.tag.isGap() {
		if key := (gapKey{e.area.name, e.tag.gapCause()}); b.gaps[key] == e {
			delete(b.gaps, key)
		}
	}
	b.gcAreaLocked(e.area)
	return nil
}

// writeLocked writes data as a new file of the given tag under area. A durable
// write also syncs the directories that name it: a report or a pin that a crash
// can undo is not accounted for.
func (b *diskBuffer) writeLocked(area *sessionArea, tag fileTag, data []byte, durable bool) (*bufEntry, error) {
	dir, created, err := b.ensureAreaDirLocked(area)
	if err != nil {
		return nil, err
	}
	seq := b.seq
	b.seq++
	final := filepath.Join(dir, fileName(seq, tag))
	staging := final + stagingSuffix
	if err := writeFileSync(staging, data); err != nil {
		_ = os.Remove(staging)
		return nil, err
	}
	if err := os.Rename(staging, final); err != nil {
		_ = os.Remove(staging)
		return nil, fmt.Errorf("logging: publish buffered file: %w", err)
	}
	if durable {
		if err := syncDirs(dir, created, b.dir); err != nil {
			_ = os.Remove(final)
			return nil, err
		}
	}
	e := &bufEntry{seq: seq, tag: tag, size: int64(len(data)), area: area}
	b.indexLocked(e)
	return e, nil
}

// rewriteLocked replaces a file's content atomically, keeping its name — and
// so its place in the drain order.
func (b *diskBuffer) rewriteLocked(e *bufEntry, data []byte, durable bool) error {
	final := b.pathLocked(e)
	staging := final + stagingSuffix
	if err := writeFileSync(staging, data); err != nil {
		_ = os.Remove(staging)
		return err
	}
	if err := os.Rename(staging, final); err != nil {
		_ = os.Remove(staging)
		return fmt.Errorf("logging: rewrite buffered file: %w", err)
	}
	if durable {
		if err := syncDirs(filepath.Dir(final), false, b.dir); err != nil {
			return err
		}
	}
	delta := int64(len(data)) - e.size
	b.bytes += delta
	if e.elem == nil {
		b.pinned += delta
	}
	e.size = int64(len(data))
	return nil
}

// ensureAreaDirLocked creates a session's directory when it does not exist,
// and says whether it did.
func (b *diskBuffer) ensureAreaDirLocked(area *sessionArea) (string, bool, error) {
	dir := filepath.Join(b.dir, area.name)
	if _, err := os.Lstat(dir); err == nil {
		return dir, false, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", false, fmt.Errorf("logging: create session buffer: %w", err)
	}
	return dir, true, nil
}

// sweepStaging removes incomplete writes left by a previous run.
func (b *diskBuffer) sweepStaging() {
	sessions, err := os.ReadDir(b.dir)
	if err != nil {
		return
	}
	for _, session := range sessions {
		if !session.IsDir() {
			continue
		}
		sessionDir := filepath.Join(b.dir, session.Name())
		entries, err := os.ReadDir(sessionDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), stagingSuffix) {
				_ = os.Remove(filepath.Join(sessionDir, entry.Name()))
			}
		}
	}
}

// --- encoding ----------------------------------------------------------------

// encodeRecords renders records as JSON lines, with each line's size: a
// report counts the bytes a record occupied, not the file it shared.
func encodeRecords(recs []control.LogRecord) ([]byte, []int, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	sizes := make([]int, len(recs))
	for i := range recs {
		before := buf.Len()
		if err := enc.Encode(&recs[i]); err != nil {
			return nil, nil, fmt.Errorf("logging: encode buffered record: %w", err)
		}
		sizes[i] = buf.Len() - before
	}
	return buf.Bytes(), sizes, nil
}

func encodedSize(rec control.LogRecord) int64 {
	data, _, err := encodeRecords([]control.LogRecord{rec})
	if err != nil {
		return 0
	}
	return int64(len(data))
}

// writeFileSync writes and fsyncs, because a buffer that does not survive the
// crash it exists for is decoration.
func writeFileSync(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("logging: open buffered file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("logging: write buffered file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("logging: sync buffered file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("logging: close buffered file: %w", err)
	}
	return nil
}

// syncDirs syncs a directory whose entries changed, and its parent too when the
// directory itself is new: a rename is durable only once the directory holding
// it is.
func syncDirs(dir string, created bool, parent string) error {
	if err := syncDir(dir); err != nil {
		return err
	}
	if created {
		return syncDir(parent)
	}
	return nil
}

func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("logging: open buffer directory: %w", err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("logging: sync buffer directory: %w", err)
	}
	return nil
}

// loadRecords reads a file's records back in full.
func loadRecords(path string) ([]control.LogRecord, error) {
	var recs []control.LogRecord
	err := scanLines(path, func(line []byte) error {
		var rec control.LogRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return fmt.Errorf("logging: decode buffered record: %w", err)
		}
		recs = append(recs, rec)
		return nil
	})
	return recs, err
}

// reportFields is what a gap record needs from a record being evicted. Decoding
// only these skips the payload a stream chunk carries.
type reportFields struct {
	RecordID   string           `json:"record_id"`
	SessionID  string           `json:"session_id"`
	Timestamp  time.Time        `json:"timestamp"`
	Kind       control.LogKind  `json:"kind"`
	Severity   control.Severity `json:"severity"`
	Subject    string           `json:"subject"`
	Login      string           `json:"login"`
	Target     string           `json:"target"`
	Attributes struct {
		Event string `json:"event"`
	} `json:"attributes"`
}

// readForReport reads what a report needs from a file about to be evicted, with
// each record's size on disk.
func readForReport(path string) ([]control.LogRecord, []int, error) {
	var (
		recs  []control.LogRecord
		sizes []int
	)
	err := scanLines(path, func(line []byte) error {
		var f reportFields
		if err := json.Unmarshal(line, &f); err != nil {
			return fmt.Errorf("logging: decode buffered record: %w", err)
		}
		rec := control.LogRecord{
			RecordID: f.RecordID, SessionID: f.SessionID, Timestamp: f.Timestamp,
			Kind: f.Kind, Severity: f.Severity, Subject: f.Subject, Login: f.Login, Target: f.Target,
		}
		if f.Attributes.Event != "" {
			rec.Attributes = map[string]string{AttrEvent: f.Attributes.Event}
		}
		recs = append(recs, rec)
		sizes = append(sizes, len(line)+1) // and its newline
		return nil
	})
	return recs, sizes, err
}

// maxBufferedRecordBytes bounds one buffered line. A stream chunk is capped far
// below this by the shipper's payload limit; the headroom is for the JSON and
// base64 expansion around it.
const maxBufferedRecordBytes = 4 << 20

func scanLines(path string, each func(line []byte) error) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("logging: open buffered file: %w", err)
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), maxBufferedRecordBytes)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		if err := each(line); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("logging: read buffered file: %w", err)
	}
	return nil
}

// sessionDirName makes a session id safe to use as a directory name.
//
// Session ids are generated by the proxy and are already safe; the sanitising
// exists because the id also arrives from configuration and tests, and a
// telemetry buffer must never be the thing that writes outside its own
// directory. Anything outside the safe set becomes an underscore, and a name
// that changed keeps a short digest of the original so two sanitised ids
// cannot collide into one directory. The result never begins with a dot, which
// is what leaves .pinned free to mean something.
func sessionDirName(sessionID string) string {
	if sessionID == "" {
		return "unknown"
	}
	var b strings.Builder
	changed := false
	for _, r := range sessionID {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
			changed = true
		}
	}
	name := b.String()
	if len(name) > 96 {
		name = name[:96]
		changed = true
	}
	if !changed {
		return name
	}
	return name + "-" + shortDigest(sessionID)
}

// shortDigest is a cheap non-cryptographic tag; it disambiguates directory
// names and nothing else depends on it.
func shortDigest(s string) string {
	const (
		offset = 14695981039346656037
		prime  = 1099511628211
	)
	h := uint64(offset)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime
	}
	return strconv.FormatUint(h, 36)
}
