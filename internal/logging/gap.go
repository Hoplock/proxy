// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// A logging.gap record is how the pipeline says what it could not deliver
// (phase 0046, D8 as amended). There are two causes and one record shape:
//
//   - EVICTED: the disk buffer's window pushed records out before Hoplock
//     Control could have them (buffer.go). The server never saw them.
//   - REFUSED: the server received records and refused them with a 400
//     (refusal.go). The proxy set them aside instead of resending them.
//
// The record goes into the affected SESSION's own timeline — its session_id is
// that session's — so "what happened to session X" returns "N records evicted
// between T1 and T2" from an ordinary session query, rather than from a
// pipeline log somebody has to know to look in. Records that belonged to no
// session (a sweep's) get a gap record with session_id "", which the contract
// requires a server to accept on any kind.
//
// It is `kind: error` on purpose: Hoplock Control refuses a kind it does not
// know, so a new kind would be refused by the very server this record reports
// to — and a refused gap record reports nothing.
//
// A gap record never begets another. Refused, it is set aside and counted like
// any refused record; evicted from the set-aside area, it is counted like any
// evicted record — and in neither case does it produce a further gap record.
// Without that rule a server that refuses gap records would turn every report
// into the next thing to report.

// maxGapRecordIDs bounds AttrGapRecordIDs. A refusal is usually one bad record
// or one bad kind; sixty-four ids is enough to find either, and a server that
// refuses everything must not make one gap record grow without bound.
const maxGapRecordIDs = 64

// gapTally accumulates the records one gap record reports: one per session and
// cause. It is the record's content before it is a record, so the buffer can
// coalesce a later eviction into an undelivered report instead of writing a
// second one.
type gapTally struct {
	// id is the gap record's own record_id. It is fixed when the tally is
	// created and kept across updates, so a report rewritten in place is still
	// one record to a server de-duplicating on it.
	id        string
	cause     string
	sessionID string
	// subject, login and target come from the first missing record that
	// carries each, so the report is attributable in the same terms as the
	// records it replaces.
	subject string
	login   string
	target  string

	records     int
	bytes       int64
	first, last time.Time
	kinds       map[control.LogKind]struct{}
	critical    int

	// Refused only.
	ids       []string
	truncated bool
	code      string
	message   string
}

func newGapTally(id, cause, sessionID string) *gapTally {
	return &gapTally{id: id, cause: cause, sessionID: sessionID, kinds: map[control.LogKind]struct{}{}}
}

// isGapRecord reports whether rec is itself a logging.gap record — the one
// kind of record that is never reported on (the no-recursion rule above).
func isGapRecord(rec control.LogRecord) bool {
	return rec.Attributes[AttrEvent] == EventLoggingGap
}

// add counts one missing record, size bytes of it on the proxy's disk.
func (t *gapTally) add(rec control.LogRecord, size int64) {
	t.records++
	t.bytes += size
	ts := rec.Timestamp.UTC()
	if !ts.IsZero() {
		if t.first.IsZero() || ts.Before(t.first) {
			t.first = ts
		}
		if ts.After(t.last) {
			t.last = ts
		}
	}
	if rec.Kind != "" {
		t.kinds[rec.Kind] = struct{}{}
	}
	if rec.Severity == control.SeverityCritical {
		t.critical++
	}
	if t.subject == "" {
		t.subject = rec.Subject
	}
	if t.login == "" {
		t.login = rec.Login
	}
	if t.target == "" {
		t.target = rec.Target
	}
	if t.cause == GapCauseRefused && rec.RecordID != "" {
		t.addID(rec.RecordID)
	}
}

func (t *gapTally) addID(id string) {
	if len(t.ids) >= maxGapRecordIDs {
		t.truncated = true
		return
	}
	t.ids = append(t.ids, id)
}

// refusal records the server's answer to a single-record refusal. The last
// one wins: it is the one an operator reading the report should act on.
func (t *gapTally) refusal(code, message string) {
	if code != "" || message != "" {
		t.code, t.message = code, message
	}
}

// merge folds another tally for the same session and cause into this one: a
// later eviction, or a report that could not be delivered live.
func (t *gapTally) merge(o *gapTally) {
	t.records += o.records
	t.bytes += o.bytes
	if !o.first.IsZero() && (t.first.IsZero() || o.first.Before(t.first)) {
		t.first = o.first
	}
	if o.last.After(t.last) {
		t.last = o.last
	}
	for k := range o.kinds {
		t.kinds[k] = struct{}{}
	}
	t.critical += o.critical
	if t.subject == "" {
		t.subject = o.subject
	}
	if t.login == "" {
		t.login = o.login
	}
	if t.target == "" {
		t.target = o.target
	}
	for _, id := range o.ids {
		t.addID(id)
	}
	t.truncated = t.truncated || o.truncated
	t.refusal(o.code, o.message)
}

func (t *gapTally) clone() *gapTally {
	c := *t
	c.kinds = maps.Clone(t.kinds)
	c.ids = slices.Clone(t.ids)
	return &c
}

// record renders the tally as the logging.gap record, stamped at.
//
// Severity decides the endpoint, unchanged (PLAN §7): the report is critical
// when anything it reports was critical — a blocked command, a kill, a mapping
// event is then missing from the server's store, and that is itself a security
// fact — and warn otherwise, on §7's rule that losing telemetry is
// outage-class.
func (t *gapTally) record(at time.Time) control.LogRecord {
	attrs := Attrs{}.
		Set(AttrEvent, EventLoggingGap).
		Set(AttrGapCause, t.cause).
		Set(AttrGapRecords, strconv.Itoa(t.records)).
		Set(AttrGapBytes, strconv.FormatInt(t.bytes, 10)).
		Set(AttrGapKinds, t.kindList()).
		Set(AttrGapCritical, strconv.Itoa(t.critical))
	if !t.first.IsZero() {
		attrs = attrs.
			Set(AttrGapFirstAt, t.first.Format(time.RFC3339Nano)).
			Set(AttrGapLastAt, t.last.Format(time.RFC3339Nano))
	}
	if t.cause == GapCauseRefused {
		attrs = attrs.
			Set(AttrGapRecordIDs, strings.Join(t.ids, ",")).
			Set(AttrRefusalCode, t.code).
			Set(AttrRefusalMessage, t.message)
		if t.truncated {
			attrs = attrs.SetBool(AttrGapRecordIDsTruncated, true)
		}
	}

	severity := control.SeverityWarn
	if t.critical > 0 {
		severity = control.SeverityCritical
	}
	message := "records were evicted from the proxy's disk buffer before Hoplock Control received them"
	if t.cause == GapCauseRefused {
		message = "records were refused by Hoplock Control and set aside by the proxy"
	}
	return control.LogRecord{
		RecordID:   t.id,
		SessionID:  t.sessionID,
		Timestamp:  at.UTC(),
		Kind:       control.LogKindError,
		Severity:   severity,
		Message:    message,
		Subject:    t.subject,
		Login:      t.login,
		Target:     t.target,
		Attributes: attrs,
	}
}

func (t *gapTally) kindList() string {
	kinds := make([]string, 0, len(t.kinds))
	for k := range t.kinds {
		kinds = append(kinds, string(k))
	}
	slices.Sort(kinds)
	return strings.Join(kinds, ",")
}

// gapFromRecord reads a logging.gap record back into a tally: an undelivered
// report adopted from a previous run, or one the live path could not deliver.
// Both are coalesced into, so a restart or a failed send never turns one report
// per session into two.
func gapFromRecord(rec control.LogRecord) (*gapTally, bool) {
	if !isGapRecord(rec) {
		return nil, false
	}
	a := rec.Attributes
	cause := a[AttrGapCause]
	if cause != GapCauseEvicted && cause != GapCauseRefused {
		return nil, false
	}
	t := newGapTally(rec.RecordID, cause, rec.SessionID)
	t.subject, t.login, t.target = rec.Subject, rec.Login, rec.Target

	var err error
	if t.records, err = strconv.Atoi(a[AttrGapRecords]); err != nil {
		return nil, false
	}
	if t.bytes, err = strconv.ParseInt(a[AttrGapBytes], 10, 64); err != nil {
		return nil, false
	}
	if t.critical, err = strconv.Atoi(a[AttrGapCritical]); err != nil {
		return nil, false
	}
	if s := a[AttrGapFirstAt]; s != "" {
		if t.first, err = time.Parse(time.RFC3339Nano, s); err != nil {
			return nil, false
		}
		if t.last, err = time.Parse(time.RFC3339Nano, a[AttrGapLastAt]); err != nil {
			return nil, false
		}
	}
	for _, k := range strings.Split(a[AttrGapKinds], ",") {
		if k != "" {
			t.kinds[control.LogKind(k)] = struct{}{}
		}
	}
	for _, id := range strings.Split(a[AttrGapRecordIDs], ",") {
		if id != "" {
			t.ids = append(t.ids, id)
		}
	}
	t.truncated = a[AttrGapRecordIDsTruncated] == "true"
	t.code, t.message = a[AttrRefusalCode], a[AttrRefusalMessage]
	return t, true
}
