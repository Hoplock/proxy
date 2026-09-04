// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Scenario is one committed, reproducible load run. Everything the harness
// varies lives here rather than in flags: a measurement whose inputs are a
// shell history is not a measurement anybody can repeat.
type Scenario struct {
	// Name labels the run in the report and in load/results/.
	Name string `yaml:"name"`
	// Kind selects what is measured: "connection" drives SSH connections
	// through a real proxy; "provisioning" measures ephemeral-user account
	// churn on the host it runs on. They are separate kinds because they
	// saturate different things — one a proxy, the other a target.
	Kind string `yaml:"kind"`
	// Description is free text carried into the report so a raw result file
	// says what it was trying to answer.
	Description string `yaml:"description"`

	Run          Run          `yaml:"run"`
	Workload     Workload     `yaml:"workload"`
	Control      ControlCfg   `yaml:"control"`
	Proxy        ProxyCfg     `yaml:"proxy"`
	Provisioning Provisioning `yaml:"provisioning"`
}

// Scenario kinds.
const (
	KindConnection   = "connection"
	KindProvisioning = "provisioning"
)

// Run is the shape of the offered load.
type Run struct {
	// Mode is "rate" (open Rate connections per second, each doing its work
	// and closing) or "hold" (ramp to Concurrency live connections and keep
	// them open). Rate measures establishment; hold measures what a live
	// connection costs.
	Mode string `yaml:"mode"`
	// Duration is the measured window, after Warmup.
	Duration time.Duration `yaml:"duration"`
	// Warmup is run first and excluded from every statistic. It is what makes
	// a cache-hit-rate number mean "in steady state" rather than "including
	// the cold cache", and both numbers are reported.
	Warmup time.Duration `yaml:"warmup"`
	// Rate is offered connections per second (mode "rate").
	Rate float64 `yaml:"rate"`
	// RateSteps sweeps several offered rates in one run, against ONE proxy
	// process, reporting a row each. It is how "where does it saturate" is
	// answered from a committed file rather than from a shell loop whose steps
	// nobody can prove ran against the same build.
	RateSteps []float64 `yaml:"rate_steps"`
	// Concurrency is the number of live connections held (mode "hold").
	Concurrency int `yaml:"concurrency"`
	// MaxInflight caps simultaneous handshakes in rate mode, so an offered
	// rate the system cannot meet backs up in the generator rather than in an
	// unbounded goroutine count. Zero means 4x Rate, floor 64.
	MaxInflight int `yaml:"max_inflight"`
	// Session is what each connection does once established: "exec" opens a
	// session channel and runs Command, "open" does nothing. "open" isolates
	// establishment cost; "exec" is the UC2 health-check shape.
	Session string `yaml:"session"`
	// Command is the exec payload for Session "exec".
	Command string `yaml:"command"`
	// Hold is how long a connection stays open after its work, in rate mode.
	Hold time.Duration `yaml:"hold"`
	// RestartBetweenSteps restarts the proxy process before each step. It is
	// required for a target sweep and wrong for a rate sweep: cached decisions
	// and a warm heap carry across steps, so a later target step would inherit
	// an entry table the earlier one filled, and a later rate step would be
	// compared against a colder proxy if it did not.
	RestartBetweenSteps bool `yaml:"restart_between_steps"`
	// SampleInterval is how often the proxy process is sampled for RSS, file
	// descriptors and CPU. Zero means 250ms.
	SampleInterval time.Duration `yaml:"sample_interval"`
}

// Run modes.
const (
	ModeRate = "rate"
	ModeHold = "hold"
)

// Session kinds.
const (
	SessionExec = "exec"
	SessionOpen = "open"
)

// Workload is the shape of the access pattern, which is the half of a cache
// measurement that a throughput number cannot see.
type Workload struct {
	// Subjects is the number of distinct authenticated identities.
	Subjects int `yaml:"subjects"`
	// Targets is the number of distinct target names. Each is a distinct
	// authorize-request shape in the proxy's cache, which is the whole point:
	// UC2 is one subject against very many targets.
	Targets int `yaml:"targets"`
	// TargetSteps sweeps the number of distinct target names in one run,
	// reporting a row each. It is how the decision cache's behaviour under
	// fan-out is measured rather than argued about: the interesting question
	// is what happens as the working set crosses the cache's entry bound, and
	// that is a curve, not a point.
	TargetSteps []int `yaml:"target_steps"`
	// Order is "cycle" (round-robin, the shape of a poller sweeping a fleet)
	// or "random".
	Order string `yaml:"order"`
}

// Workload orders.
const (
	OrderCycle  = "cycle"
	OrderRandom = "random"
)

// ControlCfg is what the instrumented mock Hoplock Control does. These are the
// server's choices, not the proxy's: the proxy can never widen them.
type ControlCfg struct {
	// CacheHint attaches a cache hint to every authorize decision.
	CacheHint bool `yaml:"cache_hint"`
	// CacheTTL is the lifetime the server grants.
	CacheTTL time.Duration `yaml:"cache_ttl"`
	// CacheScope is the server's sharing scope for the key it issues:
	// "per-target" (one key per subject+target) or "per-subject" (one key
	// covering every target that subject may reach). The second is the widest
	// sharing the contract permits, and measuring it is how we find out
	// whether the proxy's cache can exploit it.
	CacheScope string `yaml:"cache_scope"`
	// Latency is injected into every control call, so a run can ask what
	// happens when Hoplock Control is not on loopback.
	Latency time.Duration `yaml:"latency"`
	// HeartbeatInterval is the revocation stream's heartbeat. It must be well
	// inside the proxy's stale_after or the cache fails closed.
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
}

// Cache scopes.
const (
	ScopePerTarget  = "per-target"
	ScopePerSubject = "per-subject"
)

// ProxyCfg is the handful of proxy settings a load run varies. Everything else
// in the generated config.yaml is fixed, and printed into the report.
type ProxyCfg struct {
	// CacheMaxTTL is control.cache.max_ttl (0 honours the server exactly).
	CacheMaxTTL time.Duration `yaml:"cache_max_ttl"`
	// CacheStaleAfter is control.cache.stale_after.
	CacheStaleAfter time.Duration `yaml:"cache_stale_after"`
	// LogBatchSize, LogFlushInterval and LogQueueSize are the telemetry
	// pipeline's throughput knobs. They matter here because log shipping is
	// itself a control call, and "control requests per connection" is
	// meaningless without saying what they were set to.
	LogBatchSize     int           `yaml:"log_batch_size"`
	LogFlushInterval time.Duration `yaml:"log_flush_interval"`
	LogQueueSize     int           `yaml:"log_queue_size"`
}

// Provisioning is the ephemeral-user measurement (PLAN §5.1). It is deliberately
// not a proxy measurement: `useradd` and `userdel` serialise on the target's
// account-database lock, so the ceiling it finds is per TARGET and no amount of
// proxy capacity moves it.
type Provisioning struct {
	// Executor is how the account operations are run. "local" runs them on
	// this host, which is the only executor that isolates the target-side lock
	// from SSH round-trip time.
	Executor string `yaml:"executor"`
	// Cycles is the number of create/teardown cycles per concurrency level.
	Cycles int `yaml:"cycles"`
	// Concurrency is the levels swept, in order. The ceiling is where total
	// throughput stops rising with it.
	Concurrency []int `yaml:"concurrency"`
	// Home creates and removes a home directory (useradd -m / userdel -r), so
	// the run can separate the account-database lock from filesystem cost by
	// being run twice.
	Home bool `yaml:"home"`
	// Prefix names created accounts. Every account the harness makes carries
	// it, so a crashed run is sweepable by hand.
	Prefix string `yaml:"prefix"`
	// AuthorizedKeys writes an authorized_keys file into the home, which is
	// what the real provisioning path does. Requires Home.
	AuthorizedKeys bool `yaml:"authorized_keys"`
}

// Provisioning executors.
const ExecutorLocal = "local"

// LoadScenario reads and validates a scenario file. Unknown keys are rejected,
// on internal/config's reasoning: a misspelt knob that silently does nothing is
// a measurement of the wrong thing.
func LoadScenario(path string) (*Scenario, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return decodeScenario(f)
}

func decodeScenario(r io.Reader) (*Scenario, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	var s Scenario
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("decode scenario: %w", err)
	}
	s.applyDefaults()
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("scenario %q: %w", s.Name, err)
	}
	return &s, nil
}

func (s *Scenario) applyDefaults() {
	if s.Kind == "" {
		s.Kind = KindConnection
	}
	if s.Run.SampleInterval <= 0 {
		s.Run.SampleInterval = 250 * time.Millisecond
	}
	if s.Run.Session == "" {
		s.Run.Session = SessionExec
	}
	if s.Run.Command == "" {
		s.Run.Command = "show version"
	}
	if s.Workload.Subjects <= 0 {
		s.Workload.Subjects = 1
	}
	if s.Workload.Targets <= 0 {
		s.Workload.Targets = 1
	}
	if s.Workload.Order == "" {
		s.Workload.Order = OrderCycle
	}
	if s.Control.CacheScope == "" {
		s.Control.CacheScope = ScopePerTarget
	}
	if s.Control.HeartbeatInterval <= 0 {
		s.Control.HeartbeatInterval = 2 * time.Second
	}
	if s.Proxy.CacheStaleAfter <= 0 {
		s.Proxy.CacheStaleAfter = 30 * time.Second
	}
	if s.Proxy.LogBatchSize <= 0 {
		s.Proxy.LogBatchSize = 64
	}
	if s.Proxy.LogFlushInterval == 0 {
		s.Proxy.LogFlushInterval = time.Second
	}
	if s.Proxy.LogQueueSize <= 0 {
		s.Proxy.LogQueueSize = 8192
	}
	if s.Run.Mode == ModeRate && s.Run.MaxInflight <= 0 {
		peak := s.Run.Rate
		for _, r := range s.Run.RateSteps {
			peak = max(peak, r)
		}
		s.Run.MaxInflight = max(64, int(peak*4))
	}
	if s.Kind == KindProvisioning {
		if s.Provisioning.Executor == "" {
			s.Provisioning.Executor = ExecutorLocal
		}
		if s.Provisioning.Cycles <= 0 {
			s.Provisioning.Cycles = 40
		}
		if len(s.Provisioning.Concurrency) == 0 {
			s.Provisioning.Concurrency = []int{1, 2, 4, 8, 16}
		}
		if s.Provisioning.Prefix == "" {
			s.Provisioning.Prefix = "hl-load"
		}
	}
}

func (s *Scenario) validate() error {
	if s.Name == "" {
		return fmt.Errorf("name is required")
	}
	switch s.Kind {
	case KindConnection:
		return s.validateConnection()
	case KindProvisioning:
		return s.validateProvisioning()
	default:
		return fmt.Errorf("unknown kind %q (want %q or %q)", s.Kind, KindConnection, KindProvisioning)
	}
}

func (s *Scenario) validateConnection() error {
	switch s.Run.Mode {
	case ModeRate:
		if s.Run.Rate <= 0 && len(s.Run.RateSteps) == 0 {
			return fmt.Errorf("run.rate or run.rate_steps is required in mode %q", ModeRate)
		}
		for _, r := range s.Run.RateSteps {
			if r <= 0 {
				return fmt.Errorf("run.rate_steps entries must be positive, got %v", r)
			}
		}
	case ModeHold:
		if s.Run.Concurrency <= 0 {
			return fmt.Errorf("run.concurrency must be positive in mode %q", ModeHold)
		}
		if len(s.Run.RateSteps) > 0 {
			return fmt.Errorf("run.rate_steps only applies to mode %q", ModeRate)
		}
	default:
		return fmt.Errorf("unknown run.mode %q (want %q or %q)", s.Run.Mode, ModeRate, ModeHold)
	}
	if s.Run.Duration <= 0 {
		return fmt.Errorf("run.duration must be positive")
	}
	switch s.Run.Session {
	case SessionExec, SessionOpen:
	default:
		return fmt.Errorf("unknown run.session %q (want %q or %q)", s.Run.Session, SessionExec, SessionOpen)
	}
	switch s.Workload.Order {
	case OrderCycle, OrderRandom:
	default:
		return fmt.Errorf("unknown workload.order %q", s.Workload.Order)
	}
	if len(s.Run.RateSteps) > 0 && len(s.Workload.TargetSteps) > 0 {
		return fmt.Errorf("run.rate_steps and workload.target_steps cannot both be set: " +
			"a sweep with two moving dimensions cannot attribute what changed")
	}
	for _, t := range s.Workload.TargetSteps {
		if t <= 0 {
			return fmt.Errorf("workload.target_steps entries must be positive, got %d", t)
		}
	}
	if len(s.Workload.TargetSteps) > 1 && !s.Run.RestartBetweenSteps {
		return fmt.Errorf("workload.target_steps needs run.restart_between_steps: " +
			"cached decisions carry across steps, so a later step would measure an " +
			"entry table an earlier one filled")
	}
	switch s.Control.CacheScope {
	case ScopePerTarget, ScopePerSubject:
	default:
		return fmt.Errorf("unknown control.cache_scope %q", s.Control.CacheScope)
	}
	if s.Control.CacheHint && s.Control.CacheTTL <= 0 {
		return fmt.Errorf("control.cache_ttl must be positive when control.cache_hint is set")
	}
	if s.Control.CacheHint && s.Control.CacheTTL < s.Run.Duration {
		// Not fatal, but it makes the hit rate a measurement of the TTL rather
		// than of the key shape, which is what this harness exists to look at.
		return fmt.Errorf("control.cache_ttl (%s) is shorter than run.duration (%s): "+
			"the run would measure expiry, not the key shape", s.Control.CacheTTL, s.Run.Duration)
	}
	return nil
}

func (s *Scenario) validateProvisioning() error {
	if s.Provisioning.Executor != ExecutorLocal {
		return fmt.Errorf("unknown provisioning.executor %q (want %q)", s.Provisioning.Executor, ExecutorLocal)
	}
	if s.Provisioning.AuthorizedKeys && !s.Provisioning.Home {
		return fmt.Errorf("provisioning.authorized_keys needs provisioning.home")
	}
	for _, c := range s.Provisioning.Concurrency {
		if c <= 0 {
			return fmt.Errorf("provisioning.concurrency levels must be positive, got %d", c)
		}
	}
	return nil
}

// stepPlan is one row of a sweep: an offered rate and a working-set size.
type stepPlan struct {
	Rate float64
	// Targets is the number of distinct target names this step uses.
	Targets int
	// NameOffset shifts the target names so a step's working set is disjoint
	// from every earlier step's. Without it a target sweep would measure a
	// cache another step warmed.
	NameOffset uint64
}

// steps returns the sweep this scenario asks for. A scenario with neither
// rate_steps nor target_steps is a one-step sweep, so every caller has one
// shape to handle.
func (s *Scenario) steps() []stepPlan {
	if s.Kind != KindConnection {
		return nil
	}
	base := stepPlan{Rate: s.Run.Rate, Targets: s.Workload.Targets}
	switch {
	case len(s.Run.RateSteps) > 0:
		out := make([]stepPlan, 0, len(s.Run.RateSteps))
		for _, r := range s.Run.RateSteps {
			p := base
			p.Rate = r
			out = append(out, p)
		}
		return out
	case len(s.Workload.TargetSteps) > 0:
		out := make([]stepPlan, 0, len(s.Workload.TargetSteps))
		var offset uint64
		for _, t := range s.Workload.TargetSteps {
			p := base
			p.Targets = t
			p.NameOffset = offset
			offset += uint64(t)
			out = append(out, p)
		}
		return out
	default:
		return []stepPlan{base}
	}
}
