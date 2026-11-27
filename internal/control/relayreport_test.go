// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- fakes -------------------------------------------------------------------

// relayWait is one wait the reporter asked its clock for.
type relayWait struct {
	d    time.Duration
	fire chan time.Time
}

// fakeRelayClock records every wait and fires one only when a test says so, so
// "no report happened" means the reporter chose not to send one rather than
// that the test was quick.
type fakeRelayClock struct{ waits chan relayWait }

func newFakeRelayClock() *fakeRelayClock { return &fakeRelayClock{waits: make(chan relayWait, 256)} }

func (c *fakeRelayClock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	c.waits <- relayWait{d: d, fire: ch}
	return ch
}

// next is the next wait the reporter asked for.
func (c *fakeRelayClock) next(t *testing.T) relayWait {
	t.Helper()
	select {
	case w := <-c.waits:
		return w
	case <-time.After(5 * time.Second):
		t.Fatal("the reporter asked for no wait")
		return relayWait{}
	}
}

// relayCall is one report as the sink received it.
type relayCall struct {
	ids    []string
	wasNil bool
}

// fakeRelaySink records each report as it is SENT, before answering, so a test
// can see a report in flight.
type fakeRelaySink struct {
	calls chan relayCall

	mu     sync.Mutex
	n      int
	answer func(n int) (*RelayRegistrationReportResponse, error)
	// gate, when set, holds every call until a value arrives on it or the
	// call's context ends.
	gate chan struct{}
	// hangAfter, when positive, makes every call after the first hangAfter
	// ignore its context and never return until the test ends — a sink that
	// does not honour its context.
	hangAfter int
	hang      chan struct{}
}

func newFakeRelaySink() *fakeRelaySink {
	return &fakeRelaySink{calls: make(chan relayCall, 256), hang: make(chan struct{})}
}

func (s *fakeRelaySink) ReportRelayRegistrations(ctx context.Context, proxyID string, rep *RelayRegistrationReport) (*RelayRegistrationReportResponse, error) {
	s.mu.Lock()
	s.n++
	n, answer, gate, hangAfter := s.n, s.answer, s.gate, s.hangAfter
	s.mu.Unlock()

	s.calls <- relayCall{ids: slices.Clone(rep.RegisteredProxyIDs), wasNil: rep.RegisteredProxyIDs == nil}
	if hangAfter > 0 && n > hangAfter {
		<-s.hang
		return nil, errors.New("released at the end of the test")
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if answer != nil {
		return answer(n)
	}
	return &RelayRegistrationReportResponse{Accepted: true}, nil
}

func (s *fakeRelaySink) set(f func(*fakeRelaySink)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s)
}

// next is the next report the sink received.
func (s *fakeRelaySink) next(t *testing.T) relayCall {
	t.Helper()
	select {
	case c := <-s.calls:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("no report was made")
		return relayCall{}
	}
}

// none asserts that no report arrives for a while.
func (s *fakeRelaySink) none(t *testing.T, why string) {
	t.Helper()
	select {
	case c := <-s.calls:
		t.Fatalf("%s: an unexpected report was made: %v", why, c.ids)
	case <-time.After(100 * time.Millisecond):
	}
}

// relaySet is a registration set a test changes under the reporter.
type relaySet struct {
	mu  sync.Mutex
	ids []string
}

func (s *relaySet) set(ids ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ids = ids
}

func (s *relaySet) get() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.ids)
}

// syncBuffer is a log destination a test can read while the reporter writes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) lines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.FieldsFunc(b.buf.String(), func(r rune) bool { return r == '\n' })
}

// runningReporter is a reporter under test.
type runningReporter struct {
	*RelayReporter
	cancel context.CancelFunc
	done   chan struct{}
}

func startRelayReporter(t *testing.T, sink RelayReportSink, regs *relaySet, clock *fakeRelayClock, tweak func(*RelayReporterOptions)) *runningReporter {
	t.Helper()
	opts := RelayReporterOptions{
		Sink:          sink,
		ProxyID:       "proxy-hub",
		Registrations: regs.get,
	}
	if clock != nil {
		opts.After = clock.After
	}
	if tweak != nil {
		tweak(&opts)
	}
	r, err := NewRelayReporter(opts)
	if err != nil {
		t.Fatalf("NewRelayReporter: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Run(ctx)
	}()
	rr := &runningReporter{RelayReporter: r, cancel: cancel, done: done}
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after its context ended")
		}
	})
	return rr
}

func wantIDs(t *testing.T, what string, got relayCall, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if got.wasNil || !slices.Equal(got.ids, want) {
		t.Fatalf("%s: reported %v (nil %v), want %v", what, got.ids, got.wasNil, want)
	}
}

// --- the wire ----------------------------------------------------------------

func TestRelayRegistrationReportMarshalsAnEmptySetAsAnArray(t *testing.T) {
	for _, rep := range []any{RelayRegistrationReport{}, &RelayRegistrationReport{}, &RelayRegistrationReport{RegisteredProxyIDs: []string{}}} {
		raw, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := string(raw), `{"registered_proxy_ids":[]}`; got != want {
			t.Errorf("%T marshals as %s, want %s", rep, got, want)
		}
	}
	raw, _ := json.Marshal(&RelayRegistrationReport{RegisteredProxyIDs: []string{"a", "b"}})
	if got, want := string(raw), `{"registered_proxy_ids":["a","b"]}`; got != want {
		t.Errorf("a set marshals as %s, want %s", got, want)
	}
}

func TestRelayRegistrationReportPathEscapesTheProxyID(t *testing.T) {
	if got, want := RelayRegistrationReportPath("hub/1 a"), "/v1/proxies/hub%2F1%20a/relay-registrations/report"; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
	if got, want := RelayRegistrationReportPath("proxy-nexthop"), "/v1/proxies/proxy-nexthop/relay-registrations/report"; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
}

func TestRESTReportRelayRegistrations(t *testing.T) {
	const id = "hub/1 a"
	var status int
	var body string
	var gotBody []byte
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.EscapedPath() != RelayRegistrationReportPath(id) {
			t.Errorf("request = %s %s", r.Method, r.URL.EscapedPath())
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q; the report is authenticated by the proxy's own credential", got)
		}
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	ctx := context.Background()

	// Accepted, with an interval and a field this build does not know: the
	// decoding is lenient, because this is not the authorize response.
	status, body = http.StatusOK, `{"accepted":true,"report_after_seconds":5,"from_a_later_build":1}`
	resp, err := c.ReportRelayRegistrations(ctx, id, &RelayRegistrationReport{})
	if err != nil {
		t.Fatalf("200: %v", err)
	}
	if resp.ReportAfter() != 5*time.Second {
		t.Errorf("ReportAfter = %v, want 5s", resp.ReportAfter())
	}
	if got, want := string(gotBody), `{"registered_proxy_ids":[]}`; got != want {
		t.Errorf("an empty set was sent as %s, want %s", got, want)
	}

	status, body = http.StatusOK, `{"accepted":false}`
	if _, err := c.ReportRelayRegistrations(ctx, id, &RelayRegistrationReport{RegisteredProxyIDs: []string{"proxy-zone"}}); !errors.Is(err, ErrProtocol) {
		t.Errorf("accepted:false = %v, want ErrProtocol", err)
	}

	status, body = http.StatusNotFound, `{"error":{"code":"not_enrolled","message":"no such proxy is enrolled"}}`
	_, err = c.ReportRelayRegistrations(ctx, id, &RelayRegistrationReport{})
	var apiErr *APIError
	if !errors.Is(err, ErrBadRequest) || !errors.As(err, &apiErr) || apiErr.Code != "not_enrolled" {
		t.Errorf("404 = %v, want ErrBadRequest carrying not_enrolled", err)
	}

	status, body = http.StatusUnauthorized, `{"error":{"code":"unauthorized","message":"no"}}`
	if _, err := c.ReportRelayRegistrations(ctx, id, &RelayRegistrationReport{}); !IsUnauthorized(err) {
		t.Errorf("401 = %v, want ErrUnauthorized", err)
	}

	if _, err := c.ReportRelayRegistrations(ctx, "", &RelayRegistrationReport{}); !errors.Is(err, ErrBadRequest) {
		t.Errorf("an empty proxy id = %v, want ErrBadRequest", err)
	}
	if _, err := c.ReportRelayRegistrations(ctx, id, nil); !errors.Is(err, ErrBadRequest) {
		t.Errorf("a nil report = %v, want ErrBadRequest", err)
	}
}

func TestRelayReportResponseAfter(t *testing.T) {
	for _, tc := range []struct {
		resp *RelayRegistrationReportResponse
		want time.Duration
	}{
		{nil, 0},
		{&RelayRegistrationReportResponse{}, 0},
		{&RelayRegistrationReportResponse{ReportAfterSeconds: -3}, 0},
		{&RelayRegistrationReportResponse{ReportAfterSeconds: 5}, 5 * time.Second},
	} {
		if got := tc.resp.ReportAfter(); got != tc.want {
			t.Errorf("%+v.ReportAfter() = %v, want %v", tc.resp, got, tc.want)
		}
	}
}

func TestNewRelayReporterRequiresItsInputs(t *testing.T) {
	regs := func() []string { return nil }
	for name, opts := range map[string]RelayReporterOptions{
		"no sink":          {ProxyID: "p", Registrations: regs},
		"no proxy id":      {Sink: newFakeRelaySink(), Registrations: regs},
		"no registrations": {Sink: newFakeRelaySink(), ProxyID: "p"},
	} {
		if _, err := NewRelayReporter(opts); err == nil {
			t.Errorf("%s: NewRelayReporter accepted it", name)
		}
	}
}

// --- the reporter ------------------------------------------------------------

// TestRelayReporterStartsWithTheEmptySet: a restarted hub clears what its
// previous process reported, so the first report goes out at once and carries
// [] when nothing is registered.
func TestRelayReporterStartsWithTheEmptySet(t *testing.T) {
	sink, clock := newFakeRelaySink(), newFakeRelayClock()
	startRelayReporter(t, sink, &relaySet{}, clock, nil)
	wantIDs(t, "the start report", sink.next(t))
	clock.next(t) // the interval wait, never fired
	sink.none(t, "nothing changed and no interval passed")
}

// TestRelayReporterReportsEachChangeAtOnce: an arrival and a departure are each
// reported without waiting for the interval, and the set is sorted and
// de-duplicated.
func TestRelayReporterReportsEachChangeAtOnce(t *testing.T) {
	sink, clock, regs := newFakeRelaySink(), newFakeRelayClock(), &relaySet{}
	r := startRelayReporter(t, sink, regs, clock, nil)
	wantIDs(t, "the start report", sink.next(t))
	clock.next(t)

	regs.set("proxy-zone")
	r.Changed()
	wantIDs(t, "a registration arriving", sink.next(t), "proxy-zone")
	clock.next(t)

	regs.set("proxy-zone", "", "proxy-b", "proxy-zone")
	r.Changed()
	wantIDs(t, "a second registration arriving", sink.next(t), "proxy-b", "proxy-zone")
	clock.next(t)

	regs.set("proxy-b")
	r.Changed()
	wantIDs(t, "a registration dropping", sink.next(t), "proxy-b")
}

// TestRelayReporterCoalescesPokesDuringAReport: at most one report is in
// flight, and any number of changes during it cause exactly one more, carrying
// the set as it is when that one is sent.
func TestRelayReporterCoalescesPokesDuringAReport(t *testing.T) {
	sink, clock, regs := newFakeRelaySink(), newFakeRelayClock(), &relaySet{}
	gate := make(chan struct{})
	sink.set(func(s *fakeRelaySink) { s.gate = gate })
	r := startRelayReporter(t, sink, regs, clock, nil)

	wantIDs(t, "the start report", sink.next(t)) // now in flight, held by the gate
	for i := range 20 {
		regs.set("proxy-" + string(rune('a'+i)))
		r.Changed()
	}
	regs.set("proxy-late")
	sink.none(t, "a second report while the first is in flight")

	gate <- struct{}{} // the start report answers
	wantIDs(t, "the coalesced report", sink.next(t), "proxy-late")
	gate <- struct{}{}
	clock.next(t)
	sink.none(t, "twenty changes during one report")
}

// TestRelayReporterInterval: with nothing changing, a report goes out every
// interval; the server can shorten it and never lengthen it.
func TestRelayReporterInterval(t *testing.T) {
	for _, tc := range []struct {
		name     string
		interval time.Duration
		after    int32
		want     time.Duration
	}{
		{name: "the default", want: 20 * time.Second},
		{name: "a configured interval", interval: 7 * time.Second, want: 7 * time.Second},
		{name: "the server shortens it", after: 5, want: 5 * time.Second},
		{name: "the server cannot lengthen it", after: 300, want: 20 * time.Second},
		{name: "the server cannot lengthen a configured one", interval: 3 * time.Second, after: 5, want: 3 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink, clock := newFakeRelaySink(), newFakeRelayClock()
			sink.set(func(s *fakeRelaySink) {
				s.answer = func(int) (*RelayRegistrationReportResponse, error) {
					return &RelayRegistrationReportResponse{Accepted: true, ReportAfterSeconds: tc.after}, nil
				}
			})
			startRelayReporter(t, sink, &relaySet{ids: []string{"proxy-zone"}}, clock, func(o *RelayReporterOptions) { o.Interval = tc.interval })
			for i := range 3 {
				wantIDs(t, "a report", sink.next(t), "proxy-zone")
				w := clock.next(t)
				if w.d != tc.want {
					t.Fatalf("report %d: the next report waits %v, want %v", i, w.d, tc.want)
				}
				w.fire <- time.Now()
			}
		})
	}
}

// TestRelayReporterBacksOff: a failed report is retried after 1s, doubling,
// capped at the effective interval — including one the server shortened.
func TestRelayReporterBacksOff(t *testing.T) {
	failing := func(int) (*RelayRegistrationReportResponse, error) {
		return nil, &APIError{Op: "test", StatusCode: 500, Cause: ErrServer}
	}
	t.Run("up to the interval", func(t *testing.T) {
		sink, clock := newFakeRelaySink(), newFakeRelayClock()
		sink.set(func(s *fakeRelaySink) { s.answer = failing })
		startRelayReporter(t, sink, &relaySet{}, clock, nil)
		for _, want := range []time.Duration{1, 2, 4, 8, 16, 20, 20} {
			sink.next(t)
			w := clock.next(t)
			if w.d != want*time.Second {
				t.Fatalf("backoff = %v, want %v", w.d, want*time.Second)
			}
			w.fire <- time.Now()
		}
	})
	t.Run("up to the interval the server asked for", func(t *testing.T) {
		sink, clock := newFakeRelaySink(), newFakeRelayClock()
		sink.set(func(s *fakeRelaySink) {
			s.answer = func(n int) (*RelayRegistrationReportResponse, error) {
				if n == 1 {
					return &RelayRegistrationReportResponse{Accepted: true, ReportAfterSeconds: 5}, nil
				}
				return failing(n)
			}
		})
		startRelayReporter(t, sink, &relaySet{}, clock, nil)
		for _, want := range []time.Duration{5, 1, 2, 4, 5, 5} {
			sink.next(t)
			w := clock.next(t)
			if w.d != want*time.Second {
				t.Fatalf("wait = %v, want %v", w.d, want*time.Second)
			}
			w.fire <- time.Now()
		}
	})
	t.Run("a change is reported at once, whatever the backoff says", func(t *testing.T) {
		sink, clock, regs := newFakeRelaySink(), newFakeRelayClock(), &relaySet{}
		sink.set(func(s *fakeRelaySink) { s.answer = failing })
		r := startRelayReporter(t, sink, regs, clock, nil)
		sink.next(t)
		clock.next(t).fire <- time.Now()
		sink.next(t)
		if w := clock.next(t); w.d != 2*time.Second {
			t.Fatalf("second backoff = %v, want 2s", w.d)
		}
		regs.set("proxy-zone")
		r.Changed() // neither wait was fired
		wantIDs(t, "a change during backoff", sink.next(t), "proxy-zone")
	})
}

// TestRelayReporterKeepsReportingThroughEveryFailureClass: whatever the server
// answers, the reporter keeps going — it never returns, and it never does
// anything but report again. (That no session or registration is touched is
// structural: the reporter holds neither. cmd/mock-control's chain test proves
// it end to end.) Each class logs once, naming the proxy and the class.
func TestRelayReporterKeepsReportingThroughEveryFailureClass(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()

	for _, tc := range []struct {
		name   string
		status int
		body   string
		url    string
		class  string
	}{
		{name: "transport", url: deadURL, class: "unreachable"},
		{name: "401", status: 401, body: `{"error":{"code":"unauthorized","message":"no"}}`, class: "unauthorized, HTTP 401 unauthorized"},
		{name: "404", status: 404, body: `{"error":{"code":"not_enrolled","message":"no"}}`, class: "refused, HTTP 404 not_enrolled"},
		{name: "500", status: 500, body: `{"error":{"code":"internal","message":"no"}}`, class: "server failure, HTTP 500 internal"},
		{name: "accepted false", status: 200, body: `{"accepted":false}`, class: "contract violation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := tc.url
			if base == "" {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tc.status)
					_, _ = w.Write([]byte(tc.body))
				}))
				t.Cleanup(srv.Close)
				base = srv.URL
			}
			rest, err := NewRESTClient(Options{BaseURL: base, Token: "t"})
			if err != nil {
				t.Fatal(err)
			}
			sink := &countingRelaySink{inner: rest, calls: make(chan struct{}, 16)}
			clock, logs := newFakeRelayClock(), &syncBuffer{}
			r := startRelayReporter(t, sink, &relaySet{ids: []string{"proxy-zone"}}, clock, func(o *RelayReporterOptions) {
				o.Logger = log.New(logs, "", 0)
			})
			for range 3 {
				<-sink.calls
				clock.next(t).fire <- time.Now()
			}
			<-sink.calls
			select {
			case <-r.done:
				t.Fatal("Run returned on a failed report")
			default:
			}
			lines := logs.lines()
			if len(lines) != 1 {
				t.Fatalf("four failures logged %d lines, want 1: %q", len(lines), lines)
			}
			if !strings.Contains(lines[0], "proxy-hub") || !strings.Contains(lines[0], "("+tc.class+")") {
				t.Errorf("log line %q does not name the proxy and the class %q", lines[0], tc.class)
			}
		})
	}
}

// countingRelaySink passes reports through and counts them.
type countingRelaySink struct {
	inner RelayReportSink
	calls chan struct{}
}

func (s *countingRelaySink) ReportRelayRegistrations(ctx context.Context, proxyID string, rep *RelayRegistrationReport) (*RelayRegistrationReportResponse, error) {
	resp, err := s.inner.ReportRelayRegistrations(ctx, proxyID, rep)
	s.calls <- struct{}{}
	return resp, err
}

// TestRelayReporterLogsOncePerTransition: the first failure after a success
// and the first success after a failure each log one line; the retries in
// between do not.
func TestRelayReporterLogsOncePerTransition(t *testing.T) {
	sink, clock, logs := newFakeRelaySink(), newFakeRelayClock(), &syncBuffer{}
	var mu sync.Mutex
	fail := true
	sink.set(func(s *fakeRelaySink) {
		s.answer = func(int) (*RelayRegistrationReportResponse, error) {
			mu.Lock()
			defer mu.Unlock()
			if fail {
				return nil, &APIError{Op: "test", Cause: ErrTransport}
			}
			return &RelayRegistrationReportResponse{Accepted: true}, nil
		}
	})
	setFail := func(v bool) {
		mu.Lock()
		defer mu.Unlock()
		fail = v
	}
	startRelayReporter(t, sink, &relaySet{}, clock, func(o *RelayReporterOptions) { o.Logger = log.New(logs, "", 0) })

	step := func() {
		sink.next(t)
		clock.next(t).fire <- time.Now()
	}
	for range 3 {
		step()
	}
	setFail(false)
	for range 3 {
		step()
	}
	setFail(true)
	for range 3 {
		step()
	}
	sink.next(t) // the last attempt has been made; its line, if any, is written

	lines := logs.lines()
	if len(lines) != 3 {
		t.Fatalf("logged %d lines, want 3 (fail, recover, fail): %q", len(lines), lines)
	}
	for i, want := range []string{"failed (unreachable)", "delivered again", "failed (unreachable)"} {
		if !strings.Contains(lines[i], want) || !strings.Contains(lines[i], "proxy-hub") {
			t.Errorf("line %d = %q, want it to say %q and name the proxy", i, lines[i], want)
		}
	}
}

// TestRelayReporterSendsAFinalEmptySet: the hub has closed every registration
// when the reporter stops, and one last [] saves Control waiting out three
// intervals.
func TestRelayReporterSendsAFinalEmptySet(t *testing.T) {
	sink, clock := newFakeRelaySink(), newFakeRelayClock()
	r := startRelayReporter(t, sink, &relaySet{ids: []string{"proxy-zone"}}, clock, nil)
	wantIDs(t, "the start report", sink.next(t), "proxy-zone")
	clock.next(t)

	r.cancel()
	wantIDs(t, "the final report", sink.next(t))
	select {
	case <-r.done:
	case <-time.After(RelayFinalReportTimeout):
		t.Fatal("Run did not return after the final report")
	}
	sink.none(t, "after the final report")
}

// TestRelayReporterFinalReportIsBounded: neither a report hanging when the
// reporter stops nor a final report that hangs delays shutdown past
// RelayFinalReportTimeout — even against a sink that ignores its context.
func TestRelayReporterFinalReportIsBounded(t *testing.T) {
	sink, clock, regs := newFakeRelaySink(), newFakeRelayClock(), &relaySet{}
	sink.set(func(s *fakeRelaySink) { s.hangAfter = 1 })
	t.Cleanup(func() { close(sink.hang) })
	r := startRelayReporter(t, sink, regs, clock, nil)
	sink.next(t)
	clock.next(t)

	regs.set("proxy-zone")
	r.Changed()
	wantIDs(t, "the report that will hang", sink.next(t), "proxy-zone")

	start := time.Now()
	r.cancel()
	wantIDs(t, "the final report, sent although the previous one never answered", sink.next(t))
	select {
	case <-r.done:
	case <-time.After(RelayFinalReportTimeout + time.Second):
		t.Fatal("a hanging sink held Run past the final report's bound")
	}
	if took := time.Since(start); took > RelayFinalReportTimeout+500*time.Millisecond {
		t.Errorf("Run took %v to return, bound is %v", took, RelayFinalReportTimeout)
	}
}
