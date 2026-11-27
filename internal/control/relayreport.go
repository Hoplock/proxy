// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"time"
)

// This file is phase 0049: a relay hub telling Hoplock Control which proxies
// hold a registration with it (PLAN D11, §6.1 "What Control is told").
//
// D11 has Control choose `relay`, and Control can only choose it correctly over
// a registration it knows to be live. The only party that knows is the proxy
// that ACCEPTED the registration — the one that opens the relay channel when a
// route says relay — so that proxy reports, and nothing else does.
//
// Three rules shape it, and each is a reason something is NOT done here:
//
//   - The report is an observation and grants nothing. The proxy goes on
//     refusing a relay hop it holds no registration for as an outage, whatever
//     Control believes, and never dials it instead.
//   - It is not on the data path. No answer and no failure ends a session,
//     drops a registration, refuses a connection or touches a cached decision.
//   - The interval's ceiling is the proxy's. The server may shorten it and
//     never lengthen it: a broken server announcing a long interval would
//     otherwise age every relay out of its own routing with no error raised.

// PathRelayRegistrationReport is where a relay hub reports the registrations it
// holds, templated on the proxy id. Build a concrete path with
// RelayRegistrationReportPath.
const PathRelayRegistrationReport = "/v1/proxies/{proxy_id}/relay-registrations/report"

// RelayRegistrationReportPath returns the relay-registration report path for
// one proxy.
func RelayRegistrationReportPath(proxyID string) string {
	return "/v1/proxies/" + url.PathEscape(proxyID) + "/relay-registrations/report"
}

// DefaultRelayReportInterval is the longest a hub goes without reporting its
// registrations. It is a ceiling: the server may shorten it with
// report_after_seconds and can never lengthen it.
const DefaultRelayReportInterval = 20 * time.Second

// RelayFinalReportTimeout bounds the best-effort report of an empty set made
// when the reporter stops. Shutdown is never delayed past it.
const RelayFinalReportTimeout = 2 * time.Second

const (
	// relayReportMinBackoff is the first retry after a failed report; each
	// further failure doubles it, up to the effective interval.
	relayReportMinBackoff = time.Second
	// relayReportCallTimeout bounds one report. A report slower than this has
	// been overtaken by the next one anyway.
	relayReportCallTimeout = 10 * time.Second
)

// RelayRegistrationReport is the body of
// POST /v1/proxies/{proxy_id}/relay-registrations/report.
type RelayRegistrationReport struct {
	// RegisteredProxyIDs is the COMPLETE set of proxy ids with a live
	// registration at the reporting proxy — each the id its registrant was
	// authenticated as, which is the id a relay hop's next_proxy_id names. It
	// replaces the previous set, so an id it no longer names has dropped.
	RegisteredProxyIDs []string `json:"registered_proxy_ids"`
}

// MarshalJSON renders an empty set as [] and never as null: the contract makes
// the list required and non-null, so that "holds none" and a malformed report
// cannot be confused.
func (r RelayRegistrationReport) MarshalJSON() ([]byte, error) {
	type wire RelayRegistrationReport
	if r.RegisteredProxyIDs == nil {
		r.RegisteredProxyIDs = []string{}
	}
	return json.Marshal(wire(r))
}

// RelayRegistrationReportResponse acknowledges a report.
type RelayRegistrationReportResponse struct {
	// Accepted is true when the server recorded the report. Anything else is a
	// contract violation.
	Accepted bool `json:"accepted"`
	// ReportAfterSeconds is how soon the server would like the next report.
	// It can only shorten DefaultRelayReportInterval; absent or 0 leaves it.
	ReportAfterSeconds int32 `json:"report_after_seconds,omitempty"`
}

// ReportAfter returns ReportAfterSeconds as a duration, and 0 when the server
// asked for nothing.
func (r *RelayRegistrationReportResponse) ReportAfter() time.Duration {
	if r == nil || r.ReportAfterSeconds <= 0 {
		return 0
	}
	return time.Duration(r.ReportAfterSeconds) * time.Second
}

// RelayReportSink receives relay-registration reports. It is the one method
// RelayReporter depends on, so the reporter can be tested without HTTP. It is
// not on Client for the reason CapabilityReporter is not: one caller, and every
// other holder of a Client would only grow a stub.
type RelayReportSink interface {
	ReportRelayRegistrations(ctx context.Context, proxyID string, report *RelayRegistrationReport) (*RelayRegistrationReportResponse, error)
}

var _ RelayReportSink = (*RESTClient)(nil)

// ReportRelayRegistrations implements RelayReportSink.
func (c *RESTClient) ReportRelayRegistrations(ctx context.Context, proxyID string, report *RelayRegistrationReport) (*RelayRegistrationReportResponse, error) {
	const op = "ReportRelayRegistrations"
	if proxyID == "" {
		return nil, &APIError{Op: op, Cause: fmt.Errorf("%w: proxy id is required", ErrBadRequest)}
	}
	if report == nil {
		return nil, &APIError{Op: op, Cause: fmt.Errorf("%w: a report is required", ErrBadRequest)}
	}
	// Lenient decoding: this is not the authorize response, so a field this
	// build does not know is one it may ignore.
	resp, err := post[RelayRegistrationReportResponse](ctx, c, op, RelayRegistrationReportPath(proxyID), report, http.StatusOK)
	if err != nil {
		return nil, err
	}
	if !resp.Accepted {
		return nil, protocolError(op, errors.New("server did not accept the relay-registration report"))
	}
	return resp, nil
}

// RelayReporterOptions configures a RelayReporter.
type RelayReporterOptions struct {
	// Sink receives the reports. Required.
	Sink RelayReportSink
	// ProxyID is this proxy — the hub. Required.
	ProxyID string
	// Registrations returns the proxy ids registered right now. It is read at
	// send time, for every report. Required.
	Registrations func() []string
	// Interval is the longest the reporter goes without reporting. Zero means
	// DefaultRelayReportInterval. The server's report_after_seconds can shorten
	// it and never lengthen it.
	Interval time.Duration
	// Logger receives one line per transition between delivering and failing;
	// nil discards them. Nothing here is an audit record: this is fleet
	// plumbing, not a session event (D8).
	Logger *log.Logger
	// After overrides time.After, so a test can drive the reporter's clock.
	After func(time.Duration) <-chan time.Time
}

// RelayReporter tells Hoplock Control which proxies hold a relay registration
// with this one (PLAN D11, phase 0049).
//
// It reports when Run starts — so a restarted proxy clears what its previous
// process reported — then on every Changed, and otherwise whenever the
// effective interval has passed since the last successful report. At most one
// report is in flight, which is what keeps a slow older report from landing
// after a newer one without a sequence number on the wire.
//
// Nothing it does, delivered or not, touches a session or a registration.
type RelayReporter struct {
	sink          RelayReportSink
	proxyID       string
	registrations func() []string
	interval      time.Duration
	logger        *log.Logger
	after         func(time.Duration) <-chan time.Time
	finalTimeout  time.Duration

	wake chan struct{}

	// failing is the logging state, owned by Run's goroutine: true from the
	// first failure until the next success.
	failing bool
}

// NewRelayReporter validates opts and returns a reporter. Run it for the life
// of the registration listener.
func NewRelayReporter(opts RelayReporterOptions) (*RelayReporter, error) {
	switch {
	case opts.Sink == nil:
		return nil, errors.New("control: RelayReporter needs a Sink")
	case opts.ProxyID == "":
		return nil, errors.New("control: RelayReporter needs a ProxyID")
	case opts.Registrations == nil:
		return nil, errors.New("control: RelayReporter needs Registrations")
	}
	r := &RelayReporter{
		sink:          opts.Sink,
		proxyID:       opts.ProxyID,
		registrations: opts.Registrations,
		interval:      opts.Interval,
		logger:        opts.Logger,
		after:         opts.After,
		finalTimeout:  RelayFinalReportTimeout,
		wake:          make(chan struct{}, 1),
	}
	if r.interval <= 0 {
		r.interval = DefaultRelayReportInterval
	}
	if r.after == nil {
		r.after = time.After
	}
	return r, nil
}

// Changed says the set of registrations may have changed. It never blocks, is
// safe from any goroutine, and coalesces: any number of calls while a report is
// in flight cause exactly one more report after it, carrying the set as it is
// when that report is sent.
func (r *RelayReporter) Changed() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// Run reports until ctx ends, then makes one best-effort report of an empty
// set, bounded by RelayFinalReportTimeout: the hub has closed every
// registration by then, and saying so spares Control waiting out three
// intervals. Run never returns early — every failure is retried.
func (r *RelayReporter) Run(ctx context.Context) {
	defer r.final(ctx)

	// serverAfter is report_after_seconds from the last successful answer; a
	// failed call has no answer and leaves it as it was.
	var serverAfter, backoff time.Duration
	for {
		resp, err := r.report(ctx, r.current())
		if ctx.Err() != nil {
			return
		}
		var wait time.Duration
		if err == nil {
			serverAfter, backoff = resp.ReportAfter(), 0
			wait = r.effective(serverAfter)
		} else {
			backoff = nextRelayBackoff(backoff, r.effective(serverAfter))
			wait = backoff
		}
		select {
		case <-ctx.Done():
			return
		case <-r.wake:
			// A change is reported at once, whatever the backoff says.
		case <-r.after(wait):
		}
	}
}

// effective is the interval in force: the server's, when it asked for a shorter
// one, and the proxy's ceiling otherwise.
func (r *RelayReporter) effective(serverAfter time.Duration) time.Duration {
	if serverAfter > 0 && serverAfter < r.interval {
		return serverAfter
	}
	return r.interval
}

// nextRelayBackoff is the wait after one more failure: 1s, doubling, never
// above the effective interval.
func nextRelayBackoff(prev, ceiling time.Duration) time.Duration {
	next := relayReportMinBackoff
	if prev > 0 {
		next = prev * 2
	}
	return min(next, ceiling)
}

// current is the registration set as it is now: sorted, de-duplicated, and
// never nil.
func (r *RelayReporter) current() []string {
	ids := slices.DeleteFunc(slices.Clone(r.registrations()), func(id string) bool { return id == "" })
	slices.Sort(ids)
	ids = slices.Compact(ids)
	if ids == nil {
		ids = []string{}
	}
	return ids
}

// report makes one report and logs a transition between delivering and
// failing. Retries in between are silent.
func (r *RelayReporter) report(ctx context.Context, ids []string) (*RelayRegistrationReportResponse, error) {
	resp, err := r.call(ctx, ids)
	switch {
	case err == nil && r.failing:
		r.failing = false
		r.logf("control: relay registrations: reports for proxy %s delivered again (%d registered)", r.proxyID, len(ids))
	case err != nil && !r.failing && ctx.Err() == nil:
		r.failing = true
		r.logf("control: relay registrations: report for proxy %s failed (%s); retrying with backoff — no session or registration is affected",
			r.proxyID, relayErrorClass(err))
	}
	return resp, err
}

// call sends one report. It does not wait past ctx for a sink that ignores its
// context: a conformant sink has abandoned the call by then, so at most one
// report is ever in flight with one, and a non-conformant one cannot hold the
// reporter — or shutdown — hostage.
func (r *RelayReporter) call(ctx context.Context, ids []string) (*RelayRegistrationReportResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, relayReportCallTimeout)
	defer cancel()
	type result struct {
		resp *RelayRegistrationReportResponse
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := r.sink.ReportRelayRegistrations(ctx, r.proxyID, &RelayRegistrationReport{RegisteredProxyIDs: ids})
		done <- result{resp, err}
	}()
	select {
	case res := <-done:
		if res.err == nil && (res.resp == nil || !res.resp.Accepted) {
			res.err = protocolError("ReportRelayRegistrations", errors.New("server did not accept the relay-registration report"))
		}
		return res.resp, res.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// final reports the empty set once, on a fresh context bounded by finalTimeout.
func (r *RelayReporter) final(ctx context.Context) {
	finalCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.finalTimeout)
	defer cancel()
	if _, err := r.call(finalCtx, []string{}); err != nil && !r.failing {
		r.logf("control: relay registrations: final report for proxy %s failed (%s); Hoplock Control will age its registrations out",
			r.proxyID, relayErrorClass(err))
	}
}

func (r *RelayReporter) logf(format string, args ...any) {
	if r.logger != nil {
		r.logger.Printf(format, args...)
	}
}

// relayErrorClass names a failed report's class for a log line: never a body,
// never a credential.
func relayErrorClass(err error) string {
	class := "error"
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		class = "timed out"
	case errors.Is(err, ErrUnauthorized):
		class = "unauthorized"
	case errors.Is(err, ErrServer):
		class = "server failure"
	case errors.Is(err, ErrTransport):
		class = "unreachable"
	case errors.Is(err, ErrProtocol):
		class = "contract violation"
	case errors.Is(err, ErrBadRequest):
		class = "refused"
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode != 0 {
		if apiErr.Code != "" {
			return fmt.Sprintf("%s, HTTP %d %s", class, apiErr.StatusCode, apiErr.Code)
		}
		return fmt.Sprintf("%s, HTTP %d", class, apiErr.StatusCode)
	}
	return class
}
