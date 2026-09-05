// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/sshtest"
)

// ConnectionResult is one connection-kind run: the header that says what was
// run and on what, plus a row per offered-rate step.
type ConnectionResult struct {
	Scenario    string       `json:"scenario"`
	Description string       `json:"description"`
	Kind        string       `json:"kind"`
	StartedAt   time.Time    `json:"started_at"`
	Host        HostInfo     `json:"host"`
	Steps       []StepResult `json:"steps"`
	// Saturation names what the sweep ran into, when there was more than one
	// step to compare.
	Saturation string `json:"saturation,omitempty"`
	// ProxyLogTail is the end of the proxy's stderr, present only when
	// something failed.
	ProxyLogTail string `json:"proxy_log_tail,omitempty"`
}

// StepResult is everything one step measured. Every field is either something
// that was observed or something derived from observations by an arithmetic the
// report states — never a mixture presented as one number.
type StepResult struct {
	Mode        string  `json:"mode"`
	Duration    string  `json:"measured_duration"`
	Warmup      string  `json:"warmup"`
	OfferedRate float64 `json:"offered_rate_per_sec,omitempty"`
	HoldTarget  int     `json:"hold_target_connections,omitempty"`
	Subjects    int     `json:"subjects"`
	Targets     int     `json:"targets"`
	Order       string  `json:"target_order"`
	CacheHint   bool    `json:"cache_hint"`
	CacheScope  string  `json:"cache_scope,omitempty"`
	CacheTTL    string  `json:"cache_ttl,omitempty"`

	Attempted uint64 `json:"attempted"`
	Succeeded uint64 `json:"succeeded"`
	Failed    uint64 `json:"failed"`

	AchievedRate float64 `json:"achieved_rate_per_sec"`
	PeakLive     int     `json:"peak_live_connections"`

	ConnectMeanMS float64 `json:"connect_mean_ms"`
	ConnectP50MS  float64 `json:"connect_p50_ms"`
	ConnectP95MS  float64 `json:"connect_p95_ms"`
	ConnectP99MS  float64 `json:"connect_p99_ms"`
	SessionMeanMS float64 `json:"session_mean_ms,omitempty"`
	SessionP95MS  float64 `json:"session_p95_ms,omitempty"`

	BaselineRSSKiB    int64   `json:"baseline_rss_kib"`
	PlateauRSSKiB     float64 `json:"plateau_rss_kib"`
	PlateauLive       float64 `json:"plateau_live_connections"`
	PlateauSamples    int     `json:"plateau_samples"`
	RSSPerConnKiB     float64 `json:"rss_per_live_connection_kib"`
	PeakRSSKiB        int64   `json:"peak_rss_kib"`
	PeakFDs           int     `json:"peak_fds"`
	FDLimit           uint64  `json:"fd_limit"`
	PeakThreads       int     `json:"peak_threads"`
	ProxyCPUSeconds   float64 `json:"proxy_cpu_seconds"`
	ProxyCPUPerConnMS float64 `json:"proxy_cpu_ms_per_connection"`
	ProxyCPUCores     float64 `json:"proxy_cpu_cores_used"`

	ControlCalls    []CallReport `json:"control_calls"`
	ControlPerConn  float64      `json:"control_calls_per_connection"`
	AuthorizeCalls  uint64       `json:"authorize_calls"`
	CacheHitRatePct float64      `json:"authorize_cache_hit_rate_pct"`

	Errors []ErrorCount `json:"errors,omitempty"`
	Notes  []string     `json:"notes,omitempty"`
}

// HostInfo records the machine a run was taken on. A throughput number without
// it is not comparable to anything.
type HostInfo struct {
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	NumCPU  int    `json:"num_cpu"`
	GoVer   string `json:"go_version"`
	CPUName string `json:"cpu_model,omitempty"`
	MemMiB  int64  `json:"total_memory_mib,omitempty"`
}

// runConnection drives one connection-kind scenario end to end: one target, one
// instrumented Control, one proxy process, and every offered-rate step in turn.
func runConnection(ctx context.Context, sc *Scenario, binary, workDir string) (*ConnectionResult, error) {
	target, err := sshtest.StartTarget(sshtest.Options{})
	if err != nil {
		return nil, fmt.Errorf("start target: %w", err)
	}
	defer func() { _ = target.Close() }()
	targetHost, targetPort, err := splitHostPort(target.Addr().String())
	if err != nil {
		return nil, err
	}

	const token = "loadgen-token"
	ctrl := newControlServer(sc, targetHost, targetPort, token)
	if err := ctrl.start(); err != nil {
		return nil, err
	}
	defer ctrl.stop()

	listenAddr, err := freeLoopbackAddr()
	if err != nil {
		return nil, err
	}
	setup := proxySetup{
		Dir:        workDir,
		ControlURL: ctrl.baseURL(),
		Token:      token,
		ProxyID:    "loadgen-proxy",
		ListenAddr: listenAddr,
		Scenario:   sc,
	}
	proxy, err := startProxy(ctx, binary, setup)
	if err != nil {
		return nil, err
	}
	defer func() { _ = proxy.stop() }()

	clientSigner, err := sshtest.GenerateSigner()
	if err != nil {
		return nil, err
	}

	res := &ConnectionResult{
		Scenario:    sc.Name,
		Description: sc.Description,
		Kind:        sc.Kind,
		StartedAt:   time.Now().UTC(),
		Host:        hostInfo(),
	}

	// By default every step runs against the SAME proxy process: a rate sweep
	// whose steps each got a fresh process would compare a warm proxy against a
	// cold one and call the difference saturation. A target sweep needs the
	// opposite, and asks for it (see Run.RestartBetweenSteps).
	for i, plan := range sc.steps() {
		if i > 0 && sc.Run.RestartBetweenSteps {
			_ = proxy.stop()
			proxy, err = startProxy(ctx, binary, setup)
			if err != nil {
				return nil, err
			}
		}
		step, err := runStep(ctx, sc, plan, proxy, ctrl, listenAddr, clientSigner)
		if err != nil {
			return nil, err
		}
		res.Steps = append(res.Steps, *step)
		if ctx.Err() != nil {
			break
		}
	}
	res.Saturation = diagnoseConnectionSaturation(res)
	for _, st := range res.Steps {
		if st.Failed > 0 {
			// A user-facing denial says only that something is unavailable —
			// that is the disclosure rule (PLAN §4.3), and it makes the proxy's
			// own log the only place a failed run can be diagnosed from.
			res.ProxyLogTail = tail(proxy.log(), 20)
			break
		}
	}
	return res, nil
}

// runStep measures one offered rate (or the single hold-mode step).
func runStep(
	ctx context.Context, sc *Scenario, plan stepPlan,
	proxy *proxyProcess, ctrl *controlServer, listenAddr string, signer ssh.Signer,
) (*StepResult, error) {
	drv := newDriver(sc, plan, listenAddr, proxy.hostKey, signer)

	// Baseline is taken per step, with the proxy idle: after an earlier step
	// the process holds memory it has not returned to the OS, and charging that
	// to the next step's connections would inflate every later row.
	idle(ctx, 2*time.Second)
	baseline, err := (&procSampler{pid: proxy.pid(), clockHz: 100}).sample()
	if err != nil {
		return nil, fmt.Errorf("baseline sample: %w\nproxy log:\n%s", err, proxy.log())
	}

	sampler := newProcSampler(proxy.pid(), sc.Run.SampleInterval)
	sampler.run(func() int { return int(drv.live.Load()) })

	// Warmup: same load, discarded. Without it the cache hit rate reported is
	// dominated by the cold cache and says nothing about steady state.
	//
	// Hold mode has no warmup phase: its connections are opened once and kept,
	// so there is no steady state to reach — Warmup is its RAMP instead (see
	// below), and running the whole ramp-and-hold twice would only double the
	// run.
	if sc.Run.Warmup > 0 && sc.Run.Mode == ModeRate {
		drv.measuring.Store(false)
		driveFor(ctx, drv, sc.Run.Warmup, 0)
		// Let the telemetry pipeline drain before the counters are zeroed. Log
		// shipping is asynchronous and batched, so without this the warmup's
		// records would be counted against the measured window.
		settle(ctx, sc)
		drv.reset()
		ctrl.reset()
	}

	measureStart := time.Now()
	cpuStart := mustCPU(sampler)
	drv.measuring.Store(true)
	sampler.clear()

	ramp := sc.Run.Warmup
	if ramp == 0 {
		ramp = 2 * time.Second
	}
	driveFor(ctx, drv, sc.Run.Duration, ramp)
	elapsed := time.Since(measureStart)
	sampler.close()
	// Drain again, for the same reason: the last batches of the window belong
	// to it, and a report that stops counting at the last connection
	// systematically under-reports log shipping.
	settle(ctx, sc)
	cpuEnd := mustCPU(sampler)

	step := buildStepResult(sc, drv, ctrl, sampler, baseline, cpuStart, cpuEnd, elapsed)
	if step.Failed > 0 {
		step.Notes = append(step.Notes,
			fmt.Sprintf("%d of %d connections failed; see errors", step.Failed, step.Attempted))
	}
	return step, nil
}

func idle(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// driveFor runs the scenario's load shape for one window.
func driveFor(ctx context.Context, drv *driver, window, ramp time.Duration) {
	switch drv.sc.Run.Mode {
	case ModeRate:
		drv.runRate(ctx, window)
	case ModeHold:
		drv.runHold(ctx, ramp, window)
	}
}

// settle waits long enough for the proxy's batched log shipping to flush.
func settle(ctx context.Context, sc *Scenario) {
	wait := 2 * sc.Proxy.LogFlushInterval
	if wait < time.Second {
		wait = time.Second
	}
	idle(ctx, wait)
}

func mustCPU(s *procSampler) float64 {
	v, err := s.readCPU()
	if err != nil {
		return 0
	}
	return v
}

// diagnoseConnectionSaturation reads the sweep and names what it ran into.
// It refuses to guess from one step: "where does it saturate" needs a curve.
func diagnoseConnectionSaturation(res *ConnectionResult) string {
	steps := res.Steps
	if len(steps) == 0 || steps[0].Mode != ModeRate {
		return ""
	}
	varies := false
	for _, s := range steps {
		if s.OfferedRate != steps[0].OfferedRate {
			varies = true
		}
	}
	if len(steps) > 1 && !varies {
		// A sweep that held the rate fixed varied something else. Calling one
		// of its rows "the saturation point" would attribute a difference to
		// the dimension that did not move.
		return ""
	}
	if len(steps) < 2 {
		return "not established: a single offered rate is a point, not a curve — " +
			"use run.rate_steps to sweep"
	}
	last := steps[len(steps)-1]
	// Descriptors and Control latency are ruled out before CPU, because both
	// have different fixes and both would otherwise be read as CPU.
	if last.FDLimit > 0 && float64(last.PeakFDs) > 0.8*float64(last.FDLimit) {
		return fmt.Sprintf("file descriptors: the top step reached %d of a %d soft limit",
			last.PeakFDs, last.FDLimit)
	}
	var controlPerConnMS float64
	for _, c := range last.ControlCalls {
		controlPerConnMS += c.PerConn * c.MeanMicros / 1000
	}
	if last.ConnectMeanMS > 0 && controlPerConnMS > 0.5*last.ConnectMeanMS {
		return fmt.Sprintf("Hoplock Control latency: %.1f ms of the %.1f ms mean connect time "+
			"is time this run's Control spent handling calls", controlPerConnMS, last.ConnectMeanMS)
	}
	shortfall := 1 - last.AchievedRate/last.OfferedRate
	switch {
	case shortfall < 0.05:
		return fmt.Sprintf("nothing yet: the top step (%.0f conn/s offered) was met within %.0f%%, "+
			"so the ceiling is above this sweep. The CPU-bound ceiling derived from "+
			"per-connection CPU is the figure to size on", last.OfferedRate, shortfall*100)
	default:
		return fmt.Sprintf("CPU: the top step offered %.0f conn/s and achieved %.0f (%.0f%% short) "+
			"while the proxy used %.2f of %d cores. Note that the generator and the target "+
			"share those cores, so this is a FLOOR on the proxy's rate, not its ceiling",
			last.OfferedRate, last.AchievedRate, shortfall*100, last.ProxyCPUCores, res.Host.NumCPU)
	}
}

func buildStepResult(
	sc *Scenario, drv *driver, ctrl *controlServer, sampler *procSampler,
	baseline Sample, cpuStart, cpuEnd float64, elapsed time.Duration,
) *StepResult {
	connect, session := drv.latencies()
	succeeded := drv.succeeded.Load()
	samples := sampler.all()

	peakFDs, peakThreads, peakLive := 0, 0, 0
	var peakRSS int64
	for _, s := range samples {
		if s.RSSKiB > peakRSS {
			peakRSS = s.RSSKiB
		}
		if s.FDs > peakFDs {
			peakFDs = s.FDs
		}
		if s.Threads > peakThreads {
			peakThreads = s.Threads
		}
		if s.Live > peakLive {
			peakLive = s.Live
		}
	}
	// Memory per live connection is a HOLD-mode measurement and nothing else.
	// Rate-mode connections do not overlap: the sampler catches one or two live
	// at a time, and dividing a whole process's RSS by that produces a number
	// that looks like a measurement and is noise. Leaving the field zero is the
	// honest answer, and the report says which scenario to run instead.
	var nPlateau int
	var plateauRSS, plateauLive float64
	if sc.Run.Mode == ModeHold {
		nPlateau, plateauRSS, plateauLive = plateau(samples, 0.1)
	}

	res := &StepResult{
		Mode:        sc.Run.Mode,
		Duration:    elapsed.Round(time.Millisecond).String(),
		Warmup:      sc.Run.Warmup.String(),
		OfferedRate: drv.plan.Rate,
		HoldTarget:  sc.Run.Concurrency,
		Subjects:    sc.Workload.Subjects,
		Targets:     drv.plan.Targets,
		Order:       sc.Workload.Order,
		CacheHint:   sc.Control.CacheHint,

		Attempted: drv.started.Load(),
		Succeeded: succeeded,
		Failed:    drv.failed.Load(),
		PeakLive:  peakLive,

		ConnectMeanMS: ms(meanDuration(connect)),
		ConnectP50MS:  ms(percentile(connect, 0.50)),
		ConnectP95MS:  ms(percentile(connect, 0.95)),
		ConnectP99MS:  ms(percentile(connect, 0.99)),
		SessionMeanMS: ms(meanDuration(session)),
		SessionP95MS:  ms(percentile(session, 0.95)),

		BaselineRSSKiB:  baseline.RSSKiB,
		PlateauRSSKiB:   plateauRSS,
		PlateauLive:     plateauLive,
		PlateauSamples:  nPlateau,
		PeakRSSKiB:      peakRSS,
		PeakFDs:         peakFDs,
		FDLimit:         fdLimit(),
		PeakThreads:     peakThreads,
		ProxyCPUSeconds: cpuEnd - cpuStart,

		Errors: drv.errorTable(),
	}
	if sc.Control.CacheHint {
		res.CacheScope = sc.Control.CacheScope
		res.CacheTTL = sc.Control.CacheTTL.String()
	}
	if elapsed > 0 {
		res.AchievedRate = float64(succeeded) / elapsed.Seconds()
		res.ProxyCPUCores = res.ProxyCPUSeconds / elapsed.Seconds()
	}
	if succeeded > 0 {
		res.ProxyCPUPerConnMS = res.ProxyCPUSeconds * 1000 / float64(succeeded)
	}
	if plateauLive > 0 {
		res.RSSPerConnKiB = (plateauRSS - float64(baseline.RSSKiB)) / plateauLive
	}

	res.ControlCalls = ctrl.snapshot(succeeded)
	var total uint64
	for _, c := range res.ControlCalls {
		total += c.Count
	}
	if succeeded > 0 {
		res.ControlPerConn = float64(total) / float64(succeeded)
	}
	res.AuthorizeCalls = ctrl.count(control.PathAuthorize)
	// The proxy does not report its cache statistics over the wire, so the hit
	// rate is derived: one authorize per connection is what an uncached proxy
	// would do, and every connection that did NOT produce an authorize call was
	// served from cache. It is exact for this harness because nothing else in
	// the run calls authorize.
	if succeeded > 0 {
		hits := float64(succeeded) - float64(res.AuthorizeCalls)
		if hits < 0 {
			hits = 0
		}
		res.CacheHitRatePct = hits / float64(succeeded) * 100
	}
	return res
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func hostInfo() HostInfo {
	h := HostInfo{OS: runtime.GOOS, Arch: runtime.GOARCH, NumCPU: runtime.NumCPU(), GoVer: runtime.Version()}
	h.CPUName = readCPUModel()
	h.MemMiB = readTotalMemMiB()
	return h
}

func readCPUModel() string {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	for _, line := range splitLines(string(b)) {
		if k, v, ok := cutColon(line); ok && k == "model name" {
			return v
		}
	}
	return ""
}

func readTotalMemMiB() int64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range splitLines(string(b)) {
		if k, _, ok := cutColon(line); ok && k == "MemTotal" {
			return parseKiB(line) / 1024
		}
	}
	return 0
}
