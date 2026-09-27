// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/auth/target"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/logging"
)

// The bounded buffer and the refused record (phase 0046), end to end: the real
// proxy, the real REST client, the real mock — its /debug/logs/sink to take the
// log destination down and its /debug/logs/refuse to make it refuse.

// runOn runs one command on a fresh session channel and closes the
// connection — which is what ends the proxy's session — returning the
// command's error.
func runOn(t *testing.T, client *ssh.Client, command string) error {
	t.Helper()
	defer func() { _ = client.Close() }()
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	session.Stdout, session.Stderr = io.Discard, io.Discard
	err = session.Run(command)
	_ = session.Close()
	return err
}

// ended waits until the proxy holds no session, so every record the sessions
// made — their session_end included — has been handed to the pipeline.
func (s *e2eStack) ended(t *testing.T) {
	t.Helper()
	awaitStat(t, func() bool { return len(s.proxy.Sessions()) == 0 }, "every session to end")
}

// handled waits until everything handed to the pipeline has been delivered,
// spilled or evicted. The drain's own error is not the point: the sink is
// often down on purpose.
func (s *e2eStack) handled(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = s.recorder.Flush(ctx)
}

func ofSession(recs []control.LogRecord, sessionID string) []control.LogRecord {
	var out []control.LogRecord
	for _, rec := range recs {
		if rec.SessionID == sessionID {
			out = append(out, rec)
		}
	}
	return out
}

func gapReports(recs []control.LogRecord) []control.LogRecord {
	var out []control.LogRecord
	for _, rec := range recs {
		if rec.Attributes[logging.AttrEvent] == logging.EventLoggingGap {
			out = append(out, rec)
		}
	}
	return out
}

func hasKind(recs []control.LogRecord, kind control.LogKind) bool {
	return slices.ContainsFunc(recs, func(r control.LogRecord) bool { return r.Kind == kind })
}

// setAside reads the record ids the proxy set aside for a session.
func (s *e2eStack) setAside(t *testing.T, sessionID string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(s.bufferDir, sessionID, "*.refused.jsonl"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	var ids []string
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
			var rec control.LogRecord
			if err := json.Unmarshal(line, &rec); err != nil {
				t.Fatalf("decode %s: %v", path, err)
			}
			ids = append(ids, rec.RecordID)
		}
	}
	sort.Strings(ids)
	return ids
}

// TestARefusedKindNoLongerStallsTheStream is the phase's headline: with the
// server refusing one kind, a session's other records all arrive, the refused
// ones are set aside and named in a report in the session's own timeline, and
// a LATER session's records arrive too. Before this phase the first refusal
// stopped all of the proxy's delivery for good.
func TestARefusedKindNoLongerStallsTheStream(t *testing.T) {
	stack := startE2E(t, e2eOptions{uniqueSessionIDs: true})
	stack.mock.debugLogRefuse(t, `{"kinds":["command"]}`)

	if err := runOn(t, stack.dialAs(t, stack.target.Host()), "deploy"); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	stack.ended(t)
	first := e2eSessionID + "-1"
	logs := stack.awaitLogs(t, func(l debugLogs) bool {
		mine := ofSession(append(l.Batched, l.Priority...), first)
		return hasKind(mine, control.LogKindSessionEnd) && len(gapReports(mine)) == 1
	}, "the first session's records and its report")

	mine := ofSession(append(logs.Batched, logs.Priority...), first)
	for _, kind := range []control.LogKind{
		control.LogKindSessionStart, control.LogKindAuth, control.LogKindAuthorize,
		control.LogKindChannelOpen, control.LogKindStream, control.LogKindChannelClose, control.LogKindSessionEnd,
	} {
		if !hasKind(mine, kind) {
			t.Errorf("the session's %s record did not arrive behind the refusal", kind)
		}
	}
	if hasKind(mine, control.LogKindCommand) {
		t.Error("a refused command record was stored")
	}

	gap := gapReports(mine)[0]
	if gap.Severity != control.SeverityWarn || gap.Kind != control.LogKindError {
		t.Errorf("the report is %s/%s, want error/warn", gap.Kind, gap.Severity)
	}
	if got := gap.Attributes[logging.AttrGapCause]; got != logging.GapCauseRefused {
		t.Errorf("gap_cause = %q", got)
	}
	if got := gap.Attributes[logging.AttrRefusalCode]; got != "invalid_record" {
		t.Errorf("refusal_code = %q, want the server's own", got)
	}
	named := strings.Split(gap.Attributes[logging.AttrGapRecordIDs], ",")
	sort.Strings(named)
	if kept := stack.setAside(t, first); len(kept) == 0 || !slices.Equal(named, kept) {
		t.Errorf("the report names %v; the proxy set aside %v", named, kept)
	}

	// A later session is not held up by the first one's refusal.
	if err := runOn(t, stack.dialAs(t, stack.target.Host()), "deploy"); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	stack.ended(t)
	second := e2eSessionID + "-2"
	logs = stack.awaitLogs(t, func(l debugLogs) bool {
		return hasKind(ofSession(l.Batched, second), control.LogKindSessionEnd)
	}, "the later session's records")
	if hasKind(ofSession(logs.Batched, second), control.LogKindCommand) {
		t.Error("the later session's refused command record was stored")
	}
	if got := stack.recorder.Stats(); got.Segments != 0 || got.Dropped != 0 {
		t.Errorf("after both sessions: %+v, want no segment owed and nothing dropped", got)
	}
}

// TestTheDrainSetsARefusalAsideAndGoesOn: the same refusal met in the drain.
// Every other segment is delivered — before this phase the drain stopped at the
// first segment the server would not take, and everything behind it waited.
func TestTheDrainSetsARefusalAsideAndGoesOn(t *testing.T) {
	stack := startE2E(t, e2eOptions{uniqueSessionIDs: true})
	stack.mock.debugLogSink(t, false)
	for range 2 {
		if err := runOn(t, stack.dialAs(t, stack.target.Host()), "deploy"); err != nil {
			t.Fatalf("deploy while the sink was down: %v", err)
		}
		stack.ended(t)
	}
	stack.handled(t)
	if got := stack.recorder.Stats().Segments; got == 0 {
		t.Fatal("nothing reached the disk buffer; the drain has nothing to prove")
	}

	stack.mock.debugLogRefuse(t, `{"kinds":["command"]}`)
	stack.mock.debugLogSink(t, true)
	logs := stack.awaitLogs(t, func(l debugLogs) bool {
		all := append(l.Batched, l.Priority...)
		return hasKind(ofSession(all, e2eSessionID+"-1"), control.LogKindSessionEnd) &&
			hasKind(ofSession(all, e2eSessionID+"-2"), control.LogKindSessionEnd) &&
			len(gapReports(all)) == 2
	}, "both sessions' records and a report each")

	for _, id := range []string{e2eSessionID + "-1", e2eSessionID + "-2"} {
		mine := ofSession(append(logs.Batched, logs.Priority...), id)
		if hasKind(mine, control.LogKindCommand) {
			t.Errorf("session %s: a refused record was stored", id)
		}
		if !hasKind(mine, control.LogKindStream) || !hasKind(mine, control.LogKindAuthorize) {
			t.Errorf("session %s: the records around the refused one did not arrive", id)
		}
		if len(stack.setAside(t, id)) == 0 {
			t.Errorf("session %s: nothing was set aside", id)
		}
	}
	if got := stack.recorder.Stats(); got.Segments != 0 {
		t.Errorf("%d segments still owed after the drain", got.Segments)
	}
}

// TestARefusedBlockIsReportedOnThePriorityPath: a blocked command the server
// refused is a security event missing from its store, and that is itself a
// security fact — so its report is critical, and arrives on the priority
// endpoint.
func TestARefusedBlockIsReportedOnThePriorityPath(t *testing.T) {
	stack := startE2E(t, e2eOptions{filterPolicy: &fixtureFilterPolicy{
		Mode:  string(control.FilterModeBlacklist),
		Rules: []fixtureFilterRule{{Match: "rollback", Action: string(control.FilterActionBlockCommand)}},
	}})
	stack.mock.debugLogRefuse(t, `{"kinds":["policy_decision"]}`)
	if err := runOn(t, stack.dial(t), "rollback"); err == nil {
		t.Fatal("the blocked command succeeded")
	}
	stack.ended(t)
	stack.flushLogs(t)
	// A priority request is one record, so each refused critical record is
	// its own isolation and gets its own report (a block can make more than
	// one: the policy decision, and the refusal the channel reports).
	refused := stack.recorder.Stats().Refused
	if refused == 0 {
		t.Fatal("nothing was refused; the scenario never ran")
	}
	logs := stack.awaitLogs(t, func(l debugLogs) bool { return uint64(len(gapReports(l.Priority))) == refused },
		"a report of each refused block on the priority path")

	for _, gap := range gapReports(logs.Priority) {
		if gap.Severity != control.SeverityCritical || gap.Attributes[logging.AttrGapCritical] != "1" {
			t.Errorf("the report of a refused block is %s with gap_critical=%s", gap.Severity, gap.Attributes[logging.AttrGapCritical])
		}
		if got := gap.Attributes[logging.AttrGapKinds]; got != string(control.LogKindPolicyDecision) {
			t.Errorf("gap_kinds = %q", got)
		}
	}
	if len(gapReports(logs.Batched)) != 0 {
		t.Error("a report of a refused critical record took the batch path")
	}
	if hasKind(logs.Priority, control.LogKindPolicyDecision) {
		t.Error("the refused block was stored")
	}
}

// TestTheWindowEvictsCaptureAndReportsIt: an outage and a session producing
// far more capture than the window. The buffer stays within it, the capture
// flood costs only capture — oldest first — and recovery delivers the newest
// records and one report counting exactly what went.
func TestTheWindowEvictsCaptureAndReportsIt(t *testing.T) {
	const window = 1 << 20
	stack := startE2E(t, e2eOptions{
		uniqueSessionIDs: true,
		logging:          func(o *logging.Options) { o.BufferMaxBytes = window },
	})
	stack.mock.debugLogSink(t, false)
	if err := runOn(t, stack.dialAs(t, stack.target.Host()), floodCommand); err != nil {
		t.Fatalf("flood: %v", err)
	}
	stack.ended(t)
	stack.handled(t)

	stats := stack.recorder.Stats()
	if stats.Evicted == 0 {
		t.Fatal("nothing was evicted; the flood never outgrew the window")
	}
	if stats.BufferedBytes > window {
		t.Fatalf("the buffer holds %d bytes over its window of %d with nothing pinned", stats.BufferedBytes, window)
	}

	stack.mock.debugLogSink(t, true)
	session := e2eSessionID + "-1"
	logs := stack.awaitLogs(t, func(l debugLogs) bool {
		mine := ofSession(append(l.Batched, l.Priority...), session)
		return hasKind(mine, control.LogKindSessionEnd) && len(gapReports(mine)) == 1
	}, "the session's surviving records and its report")
	mine := ofSession(append(logs.Batched, logs.Priority...), session)

	// Capture is all the flood cost: every metadata record arrived.
	for _, kind := range []control.LogKind{
		control.LogKindSessionStart, control.LogKindAuth, control.LogKindAuthorize, control.LogKindCommand,
		control.LogKindChannelOpen, control.LogKindChannelClose, control.LogKindSessionEnd,
	} {
		if !hasKind(mine, kind) {
			t.Errorf("the session's %s record was lost to a capture flood", kind)
		}
	}
	// Oldest first: what arrived is the newest capture, a run of chunks with
	// no hole in it, and the report counts exactly the chunks before it.
	var seqs []int
	for _, rec := range mine {
		if rec.Kind == control.LogKindStream {
			n, err := strconv.Atoi(rec.Attributes[logging.AttrSequence])
			if err != nil {
				t.Fatalf("stream record without a sequence: %v", rec.Attributes)
			}
			seqs = append(seqs, n)
		}
	}
	sort.Ints(seqs)
	if len(seqs) == 0 {
		t.Fatal("no capture arrived at all; the window must keep the newest")
	}
	for i := 1; i < len(seqs); i++ {
		if seqs[i] != seqs[i-1]+1 {
			t.Fatalf("the capture that arrived has a hole between chunks %d and %d: eviction was not oldest first", seqs[i-1], seqs[i])
		}
	}
	gap := gapReports(mine)[0]
	if got := gap.Attributes[logging.AttrGapCause]; got != logging.GapCauseEvicted {
		t.Errorf("gap_cause = %q", got)
	}
	if got, want := gap.Attributes[logging.AttrGapRecords], strconv.Itoa(seqs[0]); got != want {
		t.Errorf("gap_records = %s, want %s: every chunk before the first that arrived", got, want)
	}
	if got := gap.Attributes[logging.AttrGapKinds]; got != string(control.LogKindStream) {
		t.Errorf("gap_kinds = %q, want only capture", got)
	}
	if got, want := gap.Attributes[logging.AttrGapRecords], strconv.FormatUint(stack.recorder.Stats().Evicted, 10); got != want {
		t.Errorf("the report counts %s records; Stats.Evicted is %s", got, want)
	}
}

// TestAPinnedSessionSurvivesAFlood is D16's claim under a bounded buffer: a
// session on a route that requires capture keeps every record while another
// session's flood evicts everything else; once pinned records fill the window a
// new capture-bound session is refused as an outage while unbound routes keep
// running; and when the sink returns every pinned record arrives in full.
func TestAPinnedSessionSurvivesAFlood(t *testing.T) {
	const window = 1 << 20
	stack := startE2E(t, e2eOptions{
		uniqueSessionIDs: true,
		captureRoute:     true,
		logging:          func(o *logging.Options) { o.BufferMaxBytes = window },
	})
	stack.mock.debugLogSink(t, false)

	// Pinned first, then flooded around.
	if err := runOn(t, stack.dialAs(t, "localhost"), "deploy"); err != nil {
		t.Fatalf("the capture-bound session failed while the buffer had room: %v", err)
	}
	stack.ended(t)
	pinned := e2eSessionID + "-1"
	if err := runOn(t, stack.dialAs(t, stack.target.Host()), floodCommand); err != nil {
		t.Fatalf("flood: %v", err)
	}
	stack.ended(t)
	stack.handled(t)
	if stack.recorder.Stats().Evicted == 0 {
		t.Fatal("the flood evicted nothing; the pin was never tested")
	}
	if _, err := os.Stat(filepath.Join(stack.bufferDir, pinned, ".pinned")); err != nil {
		t.Fatalf("the capture-bound session is not pinned: %v", err)
	}

	stack.mock.debugLogSink(t, true)
	logs := stack.awaitLogs(t, func(l debugLogs) bool {
		all := append(l.Batched, l.Priority...)
		return hasKind(ofSession(all, pinned), control.LogKindSessionEnd) &&
			hasKind(ofSession(all, e2eSessionID+"-2"), control.LogKindSessionEnd)
	}, "both sessions' records")
	all := append(logs.Batched, logs.Priority...)
	mine := ofSession(all, pinned)
	for _, kind := range []control.LogKind{
		control.LogKindSessionStart, control.LogKindAuth, control.LogKindAuthorize, control.LogKindChannelOpen,
		control.LogKindCommand, control.LogKindStream, control.LogKindChannelClose, control.LogKindSessionEnd,
	} {
		if !hasKind(mine, kind) {
			t.Errorf("the pinned session's %s record did not survive the flood", kind)
		}
	}
	for _, gap := range gapReports(all) {
		if gap.SessionID == pinned {
			t.Errorf("a pinned session lost records: %v", gap.Attributes)
		}
	}

	// A pinned session bigger than the window: it is written anyway, and from
	// then on the proxy cannot promise another pinned session its record.
	stack.mock.debugLogSink(t, false)
	if err := runOn(t, stack.dialAs(t, "localhost"), floodCommand); err != nil {
		t.Fatalf("a pinned flood admitted while there was room failed: %v", err)
	}
	stack.ended(t)
	stack.handled(t)
	if got := stack.recorder.Stats().PinnedBytes; got < window {
		t.Fatalf("pinned bytes %d did not reach the window %d", got, window)
	}
	refused := stack.dialAs(t, "localhost")
	session, err := refused.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	var stderr bytes.Buffer
	session.Stderr = &stderr
	if err := session.Run("deploy"); err == nil {
		t.Fatal("a capture-bound session was admitted with the window full of pinned records")
	}
	if text := stderr.String(); !strings.Contains(text, "not a permissions problem") {
		t.Errorf("the refusal read %q; it is an outage, not a denial", text)
	}
	_ = refused.Close()
	stack.ended(t)
	if err := runOn(t, stack.dialAs(t, stack.target.Host()), "deploy"); err != nil {
		t.Errorf("an unbound route failed while the window was full of pinned records: %v", err)
	}
	stack.ended(t)

	// And every record of the pinned flood arrives, in full.
	stack.mock.debugLogSink(t, true)
	flood := e2eSessionID + "-3"
	logs = stack.awaitLogs(t, func(l debugLogs) bool {
		return hasKind(ofSession(append(l.Batched, l.Priority...), flood), control.LogKindSessionEnd)
	}, "the pinned flood's records")
	var chunks, captured int
	for _, rec := range ofSession(logs.Batched, flood) {
		if rec.Kind == control.LogKindStream {
			chunks++
			captured += len(rec.Payload)
		}
	}
	if captured != floodBytes {
		t.Errorf("the pinned flood's capture arrived as %d bytes in %d chunks, want all %d", captured, chunks, floodBytes)
	}
}

// TestSessionLessRecordsArrive is the regression test for both triggers the
// request could and could not see: a sweep's device.config.change and a
// device.account.sweep_failed carry session_id "", and the contract now
// requires a server to accept that on any kind — this repository's own mock
// refused both before.
func TestSessionLessRecordsArrive(t *testing.T) {
	stack := startE2E(t, e2eOptions{})
	sink := stack.recorder.DeviceSink()
	sink.ConfigChange(target.DeviceConfigChange{
		Target: "fw-1:22", Platform: "fortios", Op: "delete", Name: "hl-ab12-alice-7q9w",
	})
	sink.SweepFailure(target.SweepFailure{
		Target: "fw-1:22", Platform: "fortios", Account: "hl-ab12-bob-3k8p", Reason: "the device refused the delete",
	})
	logs := stack.awaitLogs(t, func(l debugLogs) bool {
		return len(ofSession(l.Batched, "")) == 1 && len(ofSession(l.Priority, "")) == 1
	}, "both session-less records to be stored")
	if got := ofSession(logs.Batched, "")[0].Attributes[logging.AttrEvent]; got != logging.EventDeviceConfigChange {
		t.Errorf("the session-less batch record is %q", got)
	}
	if got := ofSession(logs.Priority, "")[0].Attributes[logging.AttrEvent]; got != "device.account.sweep_failed" {
		t.Errorf("the session-less priority record is %q", got)
	}
	if got := stack.recorder.Stats(); got.Refused != 0 || got.Segments != 0 {
		t.Errorf("session-less records were refused or held back: %+v", got)
	}
}
