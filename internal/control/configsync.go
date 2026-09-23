// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"slices"
	"sync"
	"time"
)

// DefaultConfigRetryInterval is how long a proxy waits before retrying a
// configuration fetch that failed. Configuration is not on the data path, so
// there is no hurry: the proxy is serving on its running document meanwhile.
const DefaultConfigRetryInterval = 30 * time.Second

// configCallTimeout bounds one fetch or report made by ConfigSync.
const configCallTimeout = 30 * time.Second

// ConfigApplier applies a configuration document's settings (PLAN D18).
//
// It is implemented outside this package (config.Fleet), because what a setting
// means belongs to the bootstrap schema and not to the wire.
type ConfigApplier interface {
	// ApplyConfig applies settings WHOLE OR NOT AT ALL:
	//
	//   - an error rejects the document, and nothing in it is applied;
	//   - a non-empty restartRequired means the document is valid but changes at
	//     least one setting that takes effect only at startup, and NOTHING in it
	//     is applied — the process keeps running exactly one document;
	//   - otherwise every setting in it is now in force.
	//
	// nil settings means "nothing is published": every fleet-owned setting goes
	// back to its bootstrap value, under the same three outcomes.
	ApplyConfig(settings map[string]json.RawMessage) (restartRequired []string, err error)
}

// ConfigStatus is what a proxy knows about its configuration, and is what it
// reports.
type ConfigStatus struct {
	// Running names the document every setting of which is in force. Zero means
	// the bootstrap file alone.
	Running ConfigRef
	// Desired names the newest document the proxy knows of.
	Desired ConfigRef
	// State says what became of Desired.
	State ConfigState
	// RestartRequired lists the settings holding a pending_restart document.
	RestartRequired []string
	// LastError says why Desired was rejected or could not be fetched.
	LastError string
	// At is when the proxy reached this state.
	At time.Time
}

// Report renders the status as the wire report.
func (s ConfigStatus) Report() *ProxyConfigReport {
	return &ProxyConfigReport{
		RunningVersion:  s.Running.Version,
		RunningHash:     s.Running.Hash,
		DesiredVersion:  s.Desired.Version,
		DesiredHash:     s.Desired.Hash,
		State:           s.State,
		RestartRequired: slices.Clone(s.RestartRequired),
		LastError:       s.LastError,
		ReportedAt:      s.At.UTC(),
	}
}

// ConfigSyncOptions configures a ConfigSync.
type ConfigSyncOptions struct {
	// Source fetches documents and receives reports. Required.
	Source FleetConfigSource
	// Applier applies a fetched document. Required.
	Applier ConfigApplier
	// ProxyID is this proxy. Required.
	ProxyID string
	// RetryInterval is how long to wait before retrying a failed fetch. Zero
	// means DefaultConfigRetryInterval.
	RetryInterval time.Duration
	// Now overrides the clock (tests).
	Now func() time.Time
	// Logger receives state changes and failures; nil discards them. It is
	// given keys and versions, never setting values.
	Logger *log.Logger
}

// ConfigSync follows the proxy's desired configuration (PLAN D18): it is told by
// the revocation stream that something moved (ConfigNotifier), fetches the
// current document, applies it, and reports what it is running.
//
// Its failure rule is the one the whole feature rests on: a document that
// cannot be fetched, parsed, or applied leaves the proxy on the last document
// that could, and is reported — it never ends a session or refuses a
// connection, and it never wedges the loop. The next notification, reconnect,
// or retry tries again.
type ConfigSync struct {
	src           FleetConfigSource
	applier       ConfigApplier
	proxyID       string
	retryInterval time.Duration
	now           func() time.Time
	logger        *log.Logger

	wake chan struct{}

	mu sync.Mutex
	// held is the hash of the last document fetched and evaluated, whatever the
	// outcome, and heldValid says there is one. It is what If-None-Match sends
	// and what a notification is compared with, so neither a reconnect nor a
	// replayed event re-evaluates a document already decided.
	held      string
	heldValid bool
	// evaluated is the outcome of evaluating the held document.
	evaluated ConfigStatus
	// fetchErr, when set, is the last fetch failure; announced is the document
	// the latest notification named. Both clear on the next successful fetch.
	fetchErr  string
	announced ConfigRef
}

var _ ConfigNotifier = (*ConfigSync)(nil)

// NewConfigSync builds a sync that starts out running on the bootstrap file
// alone. Seed it with Started when the process evaluated a document at startup.
func NewConfigSync(opts ConfigSyncOptions) (*ConfigSync, error) {
	if opts.Source == nil || opts.Applier == nil {
		return nil, errors.New("control: ConfigSync needs a Source and an Applier")
	}
	if opts.ProxyID == "" {
		return nil, errors.New("control: ConfigSync needs a ProxyID")
	}
	s := &ConfigSync{
		src:           opts.Source,
		applier:       opts.Applier,
		proxyID:       opts.ProxyID,
		retryInterval: opts.RetryInterval,
		now:           opts.Now,
		logger:        opts.Logger,
		wake:          make(chan struct{}, 1),
	}
	if s.retryInterval <= 0 {
		s.retryInterval = DefaultConfigRetryInterval
	}
	if s.now == nil {
		s.now = time.Now
	}
	s.evaluated = ConfigStatus{State: ConfigStateApplied, At: s.now()}
	return s, nil
}

// Started records what the process evaluated at startup, before any component
// was built from it. doc is the fetched document (nil when fetchErr is set);
// applyErr is why it could not be used, in which case the process started on
// the bootstrap file alone.
//
// A document evaluated at startup needs no restart: every setting in it was in
// force from the first instant, which is why a restart is what clears
// pending_restart.
func (s *ConfigSync) Started(doc *ProxyConfigDocument, fetchErr, applyErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	at := s.now()
	if fetchErr != nil {
		s.fetchErr = fetchErr.Error()
		return
	}
	s.held, s.heldValid = doc.Hash, true
	if applyErr != nil {
		s.evaluated = ConfigStatus{Desired: doc.Ref(), State: ConfigStateRejected, LastError: applyErr.Error(), At: at}
		return
	}
	s.evaluated = ConfigStatus{Running: doc.Ref(), Desired: doc.Ref(), State: ConfigStateApplied, At: at}
}

// Status returns what the proxy currently reports.
func (s *ConfigSync) Status() ConfigStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statusLocked()
}

func (s *ConfigSync) statusLocked() ConfigStatus {
	st := s.evaluated
	st.RestartRequired = slices.Clone(st.RestartRequired)
	if s.fetchErr != "" {
		st.State = ConfigStateFetchFailed
		st.LastError = s.fetchErr
		st.RestartRequired = nil
		if !s.announced.IsZero() {
			st.Desired = s.announced
		}
	}
	return st
}

// ConfigChanged implements ConfigNotifier. A notification naming the document
// already held is dropped here: it is a replay, or news the proxy has already
// acted on. Anything else asks for a fetch — of the CURRENT document, not of
// the one named, so a replayed notification for an older version can never
// bring that version back.
func (s *ConfigSync) ConfigChanged(ev *ConfigChangedEvent) {
	if ev == nil {
		return
	}
	s.mu.Lock()
	if s.heldValid && ev.Hash == s.held {
		s.mu.Unlock()
		return
	}
	s.announced = ConfigRef{Version: ev.Version, Hash: ev.Hash}
	s.mu.Unlock()
	s.poke()
}

// StreamConnected implements ConfigNotifier.
func (s *ConfigSync) StreamConnected() { s.poke() }

// poke asks the loop for a sync without blocking; pokes coalesce.
func (s *ConfigSync) poke() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run follows the desired configuration until ctx ends. It never returns early:
// every failure is reported and retried rather than ending the loop.
func (s *ConfigSync) Run(ctx context.Context) {
	retry := time.NewTimer(time.Hour)
	retry.Stop()
	defer retry.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-retry.C:
		}
		if !s.SyncOnce(ctx) && ctx.Err() == nil {
			retry.Reset(s.retryInterval)
		}
	}
}

// SyncOnce fetches the desired document, applies it if it is new, and reports
// the outcome. It returns false only when the fetch failed. Exported so a test
// can drive one step without a goroutine.
func (s *ConfigSync) SyncOnce(ctx context.Context) bool {
	s.mu.Lock()
	ifNoneMatch := ""
	if s.heldValid {
		ifNoneMatch = s.held
	}
	s.mu.Unlock()

	fetchCtx, cancel := context.WithTimeout(ctx, configCallTimeout)
	doc, err := s.src.FetchProxyConfig(fetchCtx, s.proxyID, ifNoneMatch)
	cancel()

	ok := true
	switch {
	case errors.Is(err, ErrConfigNotModified):
		s.mu.Lock()
		s.fetchErr, s.announced = "", ConfigRef{}
		s.mu.Unlock()
	case err != nil:
		if ctx.Err() != nil {
			return false
		}
		ok = false
		s.mu.Lock()
		s.fetchErr = err.Error()
		running := s.evaluated.Running
		s.mu.Unlock()
		s.logf("control: fleet configuration: fetch failed (%v); still running %s, retrying in %s",
			err, refText(running), s.retryInterval)
	default:
		s.evaluate(doc)
	}
	s.report(ctx)
	return ok
}

// evaluate applies a freshly fetched document unless it is the one held.
func (s *ConfigSync) evaluate(doc *ProxyConfigDocument) {
	s.mu.Lock()
	s.fetchErr, s.announced = "", ConfigRef{}
	if s.heldValid && doc.Hash == s.held {
		// The server ignored If-None-Match; the answer is still "unchanged".
		s.mu.Unlock()
		return
	}
	running := s.evaluated.Running
	s.mu.Unlock()

	restart, err := s.applier.ApplyConfig(doc.Settings)

	st := ConfigStatus{Running: running, Desired: doc.Ref(), At: s.now()}
	switch {
	case err != nil:
		st.State, st.LastError = ConfigStateRejected, err.Error()
		s.logf("control: fleet configuration %s REJECTED, still running %s: %v", refText(doc.Ref()), refText(running), err)
	case len(restart) > 0:
		st.State, st.RestartRequired = ConfigStatePendingRestart, slices.Clone(restart)
		s.logf("control: fleet configuration %s needs a restart to take effect (%v); still running %s",
			refText(doc.Ref()), restart, refText(running))
	default:
		st.State, st.Running = ConfigStateApplied, doc.Ref()
		s.logf("control: fleet configuration %s applied", refText(doc.Ref()))
	}

	s.mu.Lock()
	s.held, s.heldValid = doc.Hash, true
	s.evaluated = st
	s.mu.Unlock()
}

// report tells Control what this proxy is running. A failed report is logged
// and otherwise ignored: the next sync reports again.
func (s *ConfigSync) report(ctx context.Context) {
	rep := s.Status().Report()
	reportCtx, cancel := context.WithTimeout(ctx, configCallTimeout)
	defer cancel()
	if _, err := s.src.ReportProxyConfig(reportCtx, s.proxyID, rep); err != nil && ctx.Err() == nil {
		s.logf("control: fleet configuration: report failed: %v", err)
	}
}

func (s *ConfigSync) logf(format string, args ...any) {
	if s.logger != nil {
		s.logger.Printf(format, args...)
	}
}

// refText names a document in a log line.
func refText(r ConfigRef) string {
	if r.IsZero() {
		return "the bootstrap configuration"
	}
	return "version " + r.Version
}
