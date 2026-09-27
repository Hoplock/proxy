// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// scriptedReporter records every capability report and answers as scripted.
type scriptedReporter struct {
	mu       sync.Mutex
	requests []*control.CapabilityReportRequest
	// fail answers the next report with an error; after is the server's
	// report_after_seconds; block, when set, holds every report until closed.
	fail  bool
	after int
	block chan struct{}
}

func (r *scriptedReporter) ReportCapabilities(ctx context.Context, req *control.CapabilityReportRequest) (*control.CapabilityReportResponse, error) {
	if r.block != nil {
		select {
		case <-r.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req)
	if r.fail {
		r.fail = false
		return nil, errors.New("control is unreachable")
	}
	return &control.CapabilityReportResponse{Accepted: true, ReportAfterSeconds: r.after}, nil
}

func (r *scriptedReporter) sent() []*control.CapabilityReportRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*control.CapabilityReportRequest(nil), r.requests...)
}

func kexObservation(floorMet string, at time.Time) *control.KexObservation {
	return &control.KexObservation{FloorMet: floorMet, Negotiated: "curve25519-sha256", ObservedAt: at}
}

// TestAKexReportIsMadeOnlyWhenItIsNews is the whole policy of the reporter: the
// first observation of a target goes out, a second one inside the freshness
// window does not, a CHANGED level goes out at once, and the server's
// report_after_seconds decides when the window ends.
func TestAKexReportIsMadeOnlyWhenItIsNews(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	fake := &scriptedReporter{after: 60}
	r := NewKexReporter(KexReporterOptions{Reporter: fake, Now: func() time.Time { return now }})

	r.ObserveKex("host.company.com", 22, kexObservation("modern-kex", now))
	r.Wait()
	sent := fake.sent()
	if len(sent) != 1 {
		t.Fatalf("first observation sent %d reports, want 1", len(sent))
	}
	req := sent[0]
	if req.Target != "host.company.com" || req.TargetPort != 22 || req.Capabilities.Kex == nil ||
		req.Capabilities.Kex.FloorMet != "modern-kex" {
		t.Fatalf("report = %+v, want the target's key-exchange observation", req)
	}
	// The report carries NO rung observation, so the server's merge rule
	// leaves the probe's untouched.
	if req.Capabilities.CarriesRungs() || req.Capabilities.UndatedRungs() {
		t.Fatalf("a key-exchange report carries a rung observation: %+v", req.Capabilities)
	}

	// A second session to the same target inside the window: nothing.
	now = now.Add(30 * time.Second)
	r.ObserveKex("host.company.com", 22, kexObservation("modern-kex", now))
	r.Wait()
	if n := len(fake.sent()); n != 1 {
		t.Fatalf("a second observation inside the window sent %d reports in all, want 1", n)
	}

	// Another target is its own record.
	r.ObserveKex("other.company.com", 22, kexObservation("modern-kex", now))
	r.Wait()
	if n := len(fake.sent()); n != 2 {
		t.Fatalf("another target's first observation: %d reports in all, want 2", n)
	}

	// The level changed: news, reported at once, inside the window.
	now = now.Add(time.Second)
	r.ObserveKex("host.company.com", 22, kexObservation("pq-hybrid-kex", now))
	r.Wait()
	if sent := fake.sent(); len(sent) != 3 || sent[2].Capabilities.Kex.FloorMet != "pq-hybrid-kex" {
		t.Fatalf("a changed level was not reported at once: %d reports", len(sent))
	}

	// The server asked for the next observation after 60s: honoured exactly.
	now = now.Add(59 * time.Second)
	r.ObserveKex("host.company.com", 22, kexObservation("pq-hybrid-kex", now))
	r.Wait()
	if n := len(fake.sent()); n != 3 {
		t.Fatalf("an observation before report_after_seconds elapsed was reported (%d in all)", n)
	}
	now = now.Add(2 * time.Second)
	r.ObserveKex("host.company.com", 22, kexObservation("pq-hybrid-kex", now))
	r.Wait()
	if n := len(fake.sent()); n != 4 {
		t.Fatalf("an observation after report_after_seconds elapsed was not reported (%d in all)", n)
	}
}

// TestAFailedKexReportIsRetriedByTheNextHandshake: a report the server never
// recorded leaves it with no fresh observation, so the next handshake reports.
func TestAFailedKexReportIsRetriedByTheNextHandshake(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	fake := &scriptedReporter{fail: true}
	r := NewKexReporter(KexReporterOptions{Reporter: fake, Now: func() time.Time { return now }})

	r.ObserveKex("host.company.com", 22, kexObservation("none", now))
	r.Wait()
	now = now.Add(time.Second)
	r.ObserveKex("host.company.com", 22, kexObservation("none", now))
	r.Wait()
	if n := len(fake.sent()); n != 2 {
		t.Fatalf("after a failed report the next observation sent %d reports in all, want 2", n)
	}
	now = now.Add(time.Second)
	r.ObserveKex("host.company.com", 22, kexObservation("none", now))
	r.Wait()
	if n := len(fake.sent()); n != 2 {
		t.Fatalf("after a successful report the next observation was reported again (%d in all)", n)
	}
}

// TestAKexReportNeverBlocksTheCaller: the observation is made on a session's
// path and the report is not. A server that never answers must not hold the
// caller, and a second observation meanwhile is not a second report.
func TestAKexReportNeverBlocksTheCaller(t *testing.T) {
	fake := &scriptedReporter{block: make(chan struct{})}
	r := NewKexReporter(KexReporterOptions{Reporter: fake})

	returned := make(chan struct{})
	go func() {
		r.ObserveKex("host.company.com", 22, kexObservation("modern-kex", time.Now()))
		r.ObserveKex("host.company.com", 22, kexObservation("modern-kex", time.Now()))
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("ObserveKex blocked on an unanswered report")
	}
	close(fake.block)
	r.Wait()
	if n := len(fake.sent()); n != 1 {
		t.Fatalf("two observations while the first report was in flight sent %d reports, want 1", n)
	}
}

// TestANilReporterObservesNothing: a proxy with nowhere to report runs with it.
func TestANilReporterObservesNothing(t *testing.T) {
	var nilReporter *KexReporter
	nilReporter.ObserveKex("h", 22, kexObservation("none", time.Now()))
	nilReporter.Wait()
	NewKexReporter(KexReporterOptions{}).ObserveKex("h", 22, kexObservation("none", time.Now()))
}
