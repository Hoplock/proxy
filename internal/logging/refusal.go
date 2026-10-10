// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
	"errors"
	"net/http"

	"github.com/hoplock/proxy/internal/control"
)

// A refusal is the server saying "never" about a record, where every other
// failure says "not now" (phase 0046, D8 as amended). Telling the two apart is
// this file's whole job. Before it the shipper had one failure branch: any
// error spilled to disk and the drain retried the oldest segment until the
// server took it, so one record the server would never take was resent
// unchanged forever, and every record behind it — critical ones included —
// waited behind it while the disk filled.
//
// Now a refused record costs exactly itself. It is set aside (buffer.go), never
// resent, counted in Stats.Refused, and reported in a logging.gap record in its
// session's own timeline (gap.go); everything else in the batch is delivered.

// isRefusal reports whether err is the server refusing the records themselves.
//
// Exactly two statuses mean that. 400 is the contract's answer to a request it
// will not store, and it stores none of a batch it answers 400 to. 413 is not a
// contract response: it is what a middlebox in front of Hoplock Control answers
// to a body that is too large, and splitting the batch is exactly what cures it
// — a single record still refused on its own is set aside like any other.
//
// It is deliberately NOT errors.Is(err, control.ErrBadRequest). That sentinel
// covers every 4xx but 401, so a 404 from a wrong base URL, a 408, a 409 or a
// 429 would each read as "discard these records", and a misconfiguration would
// quietly set aside the whole audit stream. Everything else — those, every 5xx,
// every transport failure — keeps the records and retries, and 401 is
// unchanged.
func isRefusal(err error) bool {
	var apiErr *control.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == http.StatusBadRequest || apiErr.StatusCode == http.StatusRequestEntityTooLarge
}

// refusal is one record the server refused on its own, with what it said.
type refusal struct {
	rec     control.LogRecord
	code    string
	message string
}

func refusalOf(rec control.LogRecord, err error) refusal {
	r := refusal{rec: rec}
	var apiErr *control.APIError
	if errors.As(err, &apiErr) {
		r.code, r.message = apiErr.Code, apiErr.Message
	}
	return r
}

// isolation is what delivering one batch came to.
type isolation struct {
	delivered int
	// requests is how many batch requests the server took.
	requests int
	refused  []refusal
	// owed is what was neither delivered nor refused when a failure that is
	// not a refusal stopped the isolation, in its original order.
	owed []control.LogRecord
	// err is that failure, nil when every record was delivered or refused.
	err error
}

// deliverBatch posts records to the batch endpoint and, on a refusal, isolates
// the records the server refuses by resending halves until each refusal is down
// to one record.
//
// There is no contract field naming the refused record, and this repository
// adds none. A proxy has to bisect anyway for a server that does not send one;
// bisection sets aside only a record the server has refused ON ITS OWN, so a
// server bug in an index field could never make the proxy discard a record the
// server would have taken; and it needs no contract revision. The cost is at
// most 2n−1 requests for n records, and 2·log2(n)+1 for one bad record —
// thirteen for a batch of 64.
//
// It relies on a 400 storing nothing, which the contract states. Even a server
// that stored part of a batch loses nothing when the rest is resent, because it
// de-duplicates on record_id; the rule matters only for the accepted count.
func (s *Shipper) deliverBatch(recs []control.LogRecord) isolation {
	var out isolation
	pending := [][]control.LogRecord{recs}
	for len(pending) > 0 {
		chunk := pending[0]
		pending = pending[1:]
		err := s.postBatch(chunk)
		switch {
		case err == nil:
			out.delivered += len(chunk)
			out.requests++
		case !isRefusal(err):
			// Not now, rather than never: what was delivered stays delivered,
			// what was refused stays refused, and the rest is still owed.
			out.err = err
			out.owed = append(out.owed, chunk...)
			for _, rest := range pending {
				out.owed = append(out.owed, rest...)
			}
			return out
		case len(chunk) == 1:
			out.refused = append(out.refused, refusalOf(chunk[0], err))
		default:
			half := len(chunk) / 2
			pending = append([][]control.LogRecord{chunk[:half], chunk[half:]}, pending...)
		}
	}
	return out
}

// refuse sets refused records aside and reports them, and names the isolation
// in the operational log: where it happened, what was delivered, what was set
// aside, and what the server said.
func (s *Shipper) refuse(where string, delivered int, refused []refusal) {
	if len(refused) == 0 {
		return
	}
	last := refused[len(refused)-1]
	s.logf("logging: Hoplock Control refused records %s: %d delivered, %d set aside (code %q: %s)",
		where, delivered, len(refused), last.code, last.message)
	s.setAside(refused)
	s.reportRefusals(refused)
	// Counted last, as spill counts Buffered after the write: whoever sees the
	// count sees the records kept and their report queued.
	s.refused.Add(uint64(len(refused)))
}

// setAside keeps refused records in the buffer's set-aside area, never to be
// resent: the first class the window evicts, unless their session is pinned.
// With no buffer they are counted and reported but not kept — before phase 0046
// the whole batch they arrived in would have been dropped with them.
func (s *Shipper) setAside(refused []refusal) {
	recs := make([]control.LogRecord, len(refused))
	for i, r := range refused {
		recs[i] = r.rec
	}
	if s.buffer == nil {
		s.logf("logging: %d refused records not kept: no buffer directory configured", len(recs))
		return
	}
	for _, group := range groupBySession(recs) {
		if _, err := s.buffer.appendSegment(group.sessionID, tagRefused, group.records); err != nil {
			s.logf("logging: %d refused records not kept: %v", len(group.records), err)
		}
	}
}

// reportRefusals sends one logging.gap record for each session the refusals
// touched, through the ordinary path — delivery is working at this moment, the
// server having just answered. A refused gap record is counted and reported by
// nothing: a gap record never begets another.
func (s *Shipper) reportRefusals(refused []refusal) {
	var order []string
	tallies := map[string]*gapTally{}
	for _, r := range refused {
		if isGapRecord(r.rec) {
			continue
		}
		t := tallies[r.rec.SessionID]
		if t == nil {
			t = newGapTally(s.newRecordID(), GapCauseRefused, r.rec.SessionID)
			tallies[r.rec.SessionID] = t
			order = append(order, r.rec.SessionID)
		}
		t.add(r.rec, encodedSize(r.rec))
		t.refusal(r.code, r.message)
	}
	for _, sessionID := range order {
		rec := tallies[sessionID].record(s.now())
		s.enqueue(rec, rec.Severity == control.SeverityCritical)
	}
}
