// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"context"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// This file is the second half of what the proxy reports about a TARGET (phase
// 0045), beside probe.go's rung observation: which algorithm-floor level the
// target's key exchange was seen to meet.
//
// It exists so that an administrator can raise a route's floor SAFELY — see,
// before raising it, which targets it would break. Nobody but the proxy sees a
// target's key exchange, and it sees one on every handshake, for every
// credential method. So the engine hands each handshake's observation here, and
// this decides whether it is news.
//
// It shares probe.go's pattern, and for the same reasons: a per-target record
// kept while it is fresh, the server owning the freshness (report_after_seconds),
// and the report made fire-and-forget on a detached context, NEVER on the
// session path. Phase 0023 cut Hoplock Control calls per connection to one
// authentication, and a report per handshake would put one back; a report only
// when there is news does not.
//
// Like every capability report it is an observation and grants nothing: the
// authorize response is the authority for a floor, and the live handshake
// re-checks it every time.

// KexReporter keeps one key-exchange observation per target and reports it to
// Hoplock Control when it is news: when there is no fresh observation of the
// target, or when the level it met CHANGED — a target whose level dropped is
// news a security team wants now, not in fifteen minutes.
type KexReporter struct {
	reporter control.CapabilityReporter
	logger   *log.Logger
	now      func() time.Time

	mu sync.Mutex
	by map[string]*kexRecord
	// seq orders reports, so an answer that arrives after a newer observation
	// was already sent cannot overwrite the newer one's freshness.
	seq uint64
	// inFlight is every report not yet answered, so a test (and a shutdown)
	// can wait for them.
	inFlight sync.WaitGroup
}

// kexRecord is what the reporter holds for one target.
type kexRecord struct {
	// floorMet is the level last REPORTED, which is what "changed" compares.
	floorMet string
	// freshUntil is when the server would like the next observation. Zero
	// means the server holds no fresh observation from this proxy — the last
	// report failed — so the next handshake reports again.
	freshUntil time.Time
	seq        uint64
}

// KexReporterOptions configures a KexReporter.
type KexReporterOptions struct {
	// Reporter is where reports go. Nil makes the reporter observe nothing,
	// which is what a proxy with no Hoplock Control to report to runs with.
	Reporter control.CapabilityReporter
	// Logger receives failed reports; nil discards them.
	Logger *log.Logger
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// NewKexReporter returns a reporter.
func NewKexReporter(opts KexReporterOptions) *KexReporter {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &KexReporter{reporter: opts.Reporter, logger: opts.Logger, now: now, by: map[string]*kexRecord{}}
}

// ObserveKex takes one handshake's observation of the target at host:port and
// reports it if it is news. It never blocks on the network: the report, when
// there is one, is sent on its own goroutine with its own deadline, so neither
// a slow Hoplock Control nor a failing one can reach the session that made the
// observation.
func (r *KexReporter) ObserveKex(host string, port int, observation *control.KexObservation) {
	if r == nil || r.reporter == nil || observation == nil {
		return
	}
	key := net.JoinHostPort(host, strconv.Itoa(port))
	now := r.now()

	r.mu.Lock()
	held, known := r.by[key]
	fresh := known && now.Before(held.freshUntil)
	changed := known && held.floorMet != observation.FloorMet
	if fresh && !changed {
		r.mu.Unlock()
		return
	}
	// Claimed before the report is sent, provisionally fresh for the default
	// interval: a second session to the same target meanwhile has nothing new
	// to say, and saying it twice is the per-connection call this reporter
	// exists not to make.
	r.seq++
	seq := r.seq
	r.by[key] = &kexRecord{floorMet: observation.FloorMet, freshUntil: now.Add(control.DefaultCapabilityTTL), seq: seq}
	r.inFlight.Add(1)
	r.mu.Unlock()

	req := &control.CapabilityReportRequest{
		Target:     host,
		TargetPort: port,
		// The key-exchange observation ALONE, and no observed_at: this report
		// carries no rung observation, and the server's merge rule leaves the
		// one it holds untouched (TargetCapabilities).
		Capabilities: control.TargetCapabilities{Kex: observation.Clone()},
	}
	go r.send(key, seq, now, req)
}

// send makes one report on a detached context and records what the server
// said about freshness.
func (r *KexReporter) send(key string, seq uint64, sentAt time.Time, req *control.CapabilityReportRequest) {
	defer r.inFlight.Done()
	ctx, cancel := context.WithTimeout(context.Background(), capabilityReportTimeout)
	defer cancel()
	resp, err := r.reporter.ReportCapabilities(ctx, req)

	r.mu.Lock()
	defer r.mu.Unlock()
	held := r.by[key]
	if held == nil || held.seq != seq {
		// A newer observation has been sent since; its answer decides.
		return
	}
	if err != nil {
		// The server holds no fresh observation from this proxy, so the next
		// handshake to this target reports again. A report that failed changes
		// nothing about the session that made it.
		held.freshUntil = time.Time{}
		r.logf("auth/target: could not report %s's key exchange: %v", req.Target, err)
		return
	}
	// The server owns the freshness of its own record: the proxy re-observes
	// when it asks, never later.
	held.freshUntil = sentAt.Add(resp.ReportAfter())
}

// Wait blocks until every report sent so far has been answered or has failed.
// Nothing on a session's path calls it; it is for tests and for an orderly
// shutdown.
func (r *KexReporter) Wait() {
	if r == nil {
		return
	}
	r.inFlight.Wait()
}

func (r *KexReporter) logf(format string, args ...any) {
	if r.logger != nil {
		r.logger.Printf(format, args...)
	}
}
