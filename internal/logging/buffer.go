// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/hoplock/proxy/internal/control"
)

// The disk buffer is PLAN §7's resilience layer: when Hoplock Control is
// unreachable, records go here instead of being lost, and drain in order once
// it answers again. It is a buffer and never a destination — nothing reads it
// but the drain loop, and a segment is removed the moment the server has it.
//
// Layout is one directory per session, which is what PLAN §7 asks for and also
// what makes an operator's "what happened to session X while the link was
// down" answerable with ls:
//
//	<dir>/<session-id>/<seq>.batch.jsonl
//	<dir>/<session-id>/<seq>.priority.jsonl
//
// A segment file is one delivery attempt's worth of records, one JSON object
// per line. seq is a zero-padded global counter, so sorting segment names
// across every session directory replays them in the order they were written —
// the property that makes "nothing is lost" also mean "nothing is reordered".

// deliveryKind is which endpoint a buffered segment is owed to. It is part of
// the file name because a priority record that fell back to disk must still
// reach the priority endpoint when it drains: an outage does not downgrade a
// blocked command to ordinary telemetry.
type deliveryKind string

const (
	kindBatch    deliveryKind = "batch"
	kindPriority deliveryKind = "priority"
)

// segmentSeqWidth zero-pads the sequence so that lexical order is numeric
// order. Twenty digits covers uint64.
const segmentSeqWidth = 20

// segmentSuffix is what marks a complete segment. A partially written file is
// staged under a different suffix and renamed into place, so the drain loop
// can never read half a record.
const (
	segmentSuffix = ".jsonl"
	stagingSuffix = ".partial"
)

// segment is one buffered delivery attempt on disk.
type segment struct {
	path      string
	seq       uint64
	kind      deliveryKind
	sessionID string
}

// diskBuffer is the local resilience buffer.
//
// A nil *diskBuffer is usable and buffers nothing, which is what a proxy
// configured without a buffer directory gets: records it cannot deliver are
// counted as dropped rather than silently pretended to be safe.
type diskBuffer struct {
	dir string

	mu     sync.Mutex
	seq    uint64
	unsent int
}

// newDiskBuffer prepares the buffer directory and adopts whatever a previous
// run left behind.
//
// Adoption is the point: a proxy that crashed mid-outage has segments on disk
// that nobody else will ever ship, and starting the sequence at zero would
// interleave the new run's records with the old run's on drain.
func newDiskBuffer(dir string) (*diskBuffer, error) {
	if dir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("logging: create buffer directory: %w", err)
	}
	b := &diskBuffer{dir: dir}
	segs, err := b.segments()
	if err != nil {
		return nil, err
	}
	b.unsent = len(segs)
	for _, seg := range segs {
		if seg.seq >= b.seq {
			b.seq = seg.seq + 1
		}
	}
	// Staging files are the remains of a write that did not finish. They were
	// never complete records, so removing them is the only safe reading.
	_ = b.sweepStaging()
	return b, nil
}

// append writes one delivery attempt's records as a new segment.
func (b *diskBuffer) append(sessionID string, kind deliveryKind, recs []control.LogRecord) error {
	if b == nil || len(recs) == 0 {
		return errors.New("logging: no disk buffer configured")
	}

	b.mu.Lock()
	seq := b.seq
	b.seq++
	b.mu.Unlock()

	sessionDir := filepath.Join(b.dir, sessionDirName(sessionID))
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		return fmt.Errorf("logging: create session buffer: %w", err)
	}

	name := fmt.Sprintf("%0*d.%s%s", segmentSeqWidth, seq, kind, segmentSuffix)
	final := filepath.Join(sessionDir, name)
	staging := final + stagingSuffix

	if err := writeSegment(staging, recs); err != nil {
		_ = os.Remove(staging)
		return err
	}
	if err := os.Rename(staging, final); err != nil {
		_ = os.Remove(staging)
		return fmt.Errorf("logging: publish buffer segment: %w", err)
	}

	b.mu.Lock()
	b.unsent++
	b.mu.Unlock()
	return nil
}

// writeSegment writes the records as JSON lines and fsyncs, because a buffer
// that does not survive the crash it exists for is decoration.
func writeSegment(path string, recs []control.LogRecord) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("logging: open buffer segment: %w", err)
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for i := range recs {
		if err := enc.Encode(&recs[i]); err != nil {
			_ = f.Close()
			return fmt.Errorf("logging: encode buffered record: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		return fmt.Errorf("logging: write buffer segment: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("logging: sync buffer segment: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("logging: close buffer segment: %w", err)
	}
	return nil
}

// segments lists every complete segment, oldest first across all sessions.
func (b *diskBuffer) segments() ([]segment, error) {
	if b == nil {
		return nil, nil
	}
	sessions, err := os.ReadDir(b.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("logging: read buffer directory: %w", err)
	}

	var segs []segment
	for _, session := range sessions {
		if !session.IsDir() {
			continue
		}
		sessionDir := filepath.Join(b.dir, session.Name())
		entries, err := os.ReadDir(sessionDir)
		if err != nil {
			return nil, fmt.Errorf("logging: read session buffer: %w", err)
		}
		for _, entry := range entries {
			seg, ok := parseSegment(sessionDir, session.Name(), entry.Name())
			if ok {
				segs = append(segs, seg)
			}
		}
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i].seq < segs[j].seq })
	return segs, nil
}

// parseSegment reads a segment's sequence and delivery kind back out of its
// file name.
func parseSegment(dir, sessionID, name string) (segment, bool) {
	if !strings.HasSuffix(name, segmentSuffix) {
		return segment{}, false
	}
	base := strings.TrimSuffix(name, segmentSuffix)
	seqText, kindText, ok := strings.Cut(base, ".")
	if !ok {
		return segment{}, false
	}
	kind := deliveryKind(kindText)
	if kind != kindBatch && kind != kindPriority {
		return segment{}, false
	}
	seq, err := strconv.ParseUint(seqText, 10, 64)
	if err != nil {
		return segment{}, false
	}
	return segment{path: filepath.Join(dir, name), seq: seq, kind: kind, sessionID: sessionID}, true
}

// load reads a segment's records back.
func (b *diskBuffer) load(seg segment) ([]control.LogRecord, error) {
	f, err := os.Open(seg.path)
	if err != nil {
		return nil, fmt.Errorf("logging: open buffered segment: %w", err)
	}
	defer func() { _ = f.Close() }()

	var recs []control.LogRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), maxBufferedRecordBytes)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec control.LogRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("logging: decode buffered record: %w", err)
		}
		recs = append(recs, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("logging: read buffered segment: %w", err)
	}
	return recs, nil
}

// maxBufferedRecordBytes bounds one buffered line. A stream chunk is capped far
// below this by the shipper's payload limit; the headroom is for the JSON and
// base64 expansion around it.
const maxBufferedRecordBytes = 4 << 20

// remove deletes a segment the server has taken, and the session directory
// with it once it holds nothing else.
func (b *diskBuffer) remove(seg segment) error {
	if err := os.Remove(seg.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("logging: remove buffered segment: %w", err)
	}
	b.mu.Lock()
	if b.unsent > 0 {
		b.unsent--
	}
	b.mu.Unlock()
	// Best effort: a non-empty directory simply stays.
	_ = os.Remove(filepath.Dir(seg.path))
	return nil
}

// pending is how many segments are still owed to the server. It is what makes
// the shipper "degraded": while anything is on disk, new records join it rather
// than overtaking it.
func (b *diskBuffer) pending() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.unsent
}

// sweepStaging removes incomplete writes left by a previous run.
func (b *diskBuffer) sweepStaging() error {
	sessions, err := os.ReadDir(b.dir)
	if err != nil {
		return err
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
	return nil
}

// sessionDirName makes a session id safe to use as a directory name.
//
// Session ids are generated by the proxy and are already safe; the sanitising
// exists because the id also arrives from configuration and tests, and a
// telemetry buffer must never be the thing that writes outside its own
// directory. Anything outside the safe set becomes an underscore, and a name
// that changed keeps a short digest of the original so two sanitised ids
// cannot collide into one directory.
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
