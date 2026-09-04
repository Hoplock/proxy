// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// ProvisioningResult is what the ephemeral-user measurement found.
//
// It is separate from ConnectionResult because it answers a different kind of
// question. Every other number this harness produces is per PROXY and moves
// when you add proxies. This one is per TARGET: `useradd` and `userdel` take
// the target's account-database lock, so a fleet of proxies pointed at one host
// contends for the same lock and the ceiling does not move (PLAN §5.1).
type ProvisioningResult struct {
	Scenario    string    `json:"scenario"`
	Description string    `json:"description"`
	Kind        string    `json:"kind"`
	StartedAt   time.Time `json:"started_at"`
	Host        HostInfo  `json:"host"`

	Executor       string `json:"executor"`
	NSSBackend     string `json:"nss_passwd_backend"`
	HomeDirectory  bool   `json:"creates_home_directory"`
	AuthorizedKeys bool   `json:"writes_authorized_keys"`
	Cycles         int    `json:"cycles_per_level"`

	// Single is the serial cost of one provision/teardown cycle: the number
	// D17's arithmetic needs.
	Single StageCost `json:"single_cycle"`
	// Levels is the concurrency sweep. The ceiling is where throughput stops
	// rising with concurrency.
	Levels []ProvisioningLevel `json:"levels"`

	// CeilingPerSec is the highest measured cycles per second across the sweep.
	CeilingPerSec float64 `json:"ceiling_cycles_per_sec"`
	// CeilingAt is the concurrency level that reached it.
	CeilingAt int `json:"ceiling_at_concurrency"`
	// Saturated names what stopped it going higher.
	Saturated string `json:"saturated"`

	Notes []string `json:"notes,omitempty"`
}

// StageCost is the timing breakdown of one cycle.
type StageCost struct {
	Samples      int     `json:"samples"`
	CreateMeanMS float64 `json:"create_mean_ms"`
	CreateP95MS  float64 `json:"create_p95_ms"`
	KeyMeanMS    float64 `json:"key_mean_ms,omitempty"`
	RemoveMeanMS float64 `json:"remove_mean_ms"`
	RemoveP95MS  float64 `json:"remove_p95_ms"`
	TotalMeanMS  float64 `json:"total_mean_ms"`
	TotalP95MS   float64 `json:"total_p95_ms"`
}

// ProvisioningLevel is one point of the concurrency sweep.
type ProvisioningLevel struct {
	Concurrency int     `json:"concurrency"`
	Cycles      int     `json:"cycles"`
	Failures    int     `json:"failures"`
	Elapsed     string  `json:"elapsed"`
	PerSec      float64 `json:"cycles_per_sec"`
	// Efficiency is PerSec divided by the serial rate times concurrency: 1.0
	// would be perfect scaling, and the distance below it is the serialisation.
	Efficiency float64   `json:"parallel_efficiency"`
	Cost       StageCost `json:"cost"`
}

// runProvisioning sweeps concurrency levels of account create/teardown.
func runProvisioning(ctx context.Context, sc *Scenario) (*ProvisioningResult, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("provisioning measurement needs Linux (useradd/userdel)")
	}
	if os.Geteuid() != 0 {
		return nil, errors.New("provisioning measurement must run as root: it creates and removes real accounts")
	}
	for _, bin := range []string{"useradd", "userdel"} {
		if _, err := exec.LookPath(bin); err != nil {
			return nil, fmt.Errorf("provisioning measurement needs %s on PATH: %w", bin, err)
		}
	}

	p := sc.Provisioning
	res := &ProvisioningResult{
		Scenario:       sc.Name,
		Description:    sc.Description,
		Kind:           sc.Kind,
		StartedAt:      time.Now().UTC(),
		Host:           hostInfo(),
		Executor:       p.Executor,
		NSSBackend:     nssPasswdBackend(),
		HomeDirectory:  p.Home,
		AuthorizedKeys: p.AuthorizedKeys,
		Cycles:         p.Cycles,
	}

	// Sweep the levels in the order the scenario names them. Serial first is
	// not an accident: every efficiency below is relative to it, so it must be
	// measured on the same machine in the same run.
	var serialRate float64
	levels := append([]int(nil), p.Concurrency...)
	sort.Ints(levels)
	for _, c := range levels {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		lvl, err := sweepLevel(ctx, sc, c)
		if err != nil {
			return nil, err
		}
		if c == 1 {
			serialRate = lvl.PerSec
			res.Single = lvl.Cost
		}
		if serialRate > 0 {
			lvl.Efficiency = lvl.PerSec / (serialRate * float64(c))
		}
		res.Levels = append(res.Levels, lvl)
		if lvl.PerSec > res.CeilingPerSec {
			res.CeilingPerSec, res.CeilingAt = lvl.PerSec, c
		}
	}
	res.Saturated = diagnoseSaturation(res)
	return res, nil
}

// sweepLevel runs Cycles create/teardown cycles at one concurrency level.
func sweepLevel(ctx context.Context, sc *Scenario, concurrency int) (ProvisioningLevel, error) {
	p := sc.Provisioning
	lvl := ProvisioningLevel{Concurrency: concurrency, Cycles: p.Cycles}

	var (
		mu       sync.Mutex
		creates  []time.Duration
		keys     []time.Duration
		removes  []time.Duration
		totals   []time.Duration
		failures int
	)

	work := make(chan int, p.Cycles)
	for i := range p.Cycles {
		work <- i
	}
	close(work)

	start := time.Now()
	var wg sync.WaitGroup
	for w := range concurrency {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := range work {
				if ctx.Err() != nil {
					return
				}
				name := accountName(p.Prefix, worker, i)
				c, k, r, err := oneCycle(ctx, sc, name)
				mu.Lock()
				if err != nil {
					failures++
				} else {
					creates = append(creates, c)
					if k > 0 {
						keys = append(keys, k)
					}
					removes = append(removes, r)
					totals = append(totals, c+k+r)
				}
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start)

	lvl.Failures = failures
	lvl.Elapsed = elapsed.Round(time.Millisecond).String()
	if elapsed > 0 {
		lvl.PerSec = float64(len(totals)) / elapsed.Seconds()
	}
	lvl.Cost = StageCost{
		Samples:      len(totals),
		CreateMeanMS: ms(meanDuration(creates)),
		CreateP95MS:  ms(percentile(creates, 0.95)),
		KeyMeanMS:    ms(meanDuration(keys)),
		RemoveMeanMS: ms(meanDuration(removes)),
		RemoveP95MS:  ms(percentile(removes, 0.95)),
		TotalMeanMS:  ms(meanDuration(totals)),
		TotalP95MS:   ms(percentile(totals, 0.95)),
	}
	return lvl, nil
}

// accountName mirrors the shape phase 0007 uses on a real target: a fixed
// prefix so a crashed run is sweepable by hand, then something unique.
func accountName(prefix string, worker, i int) string {
	return fmt.Sprintf("%s-%d-%d", prefix, worker, i)
}

// oneCycle is the account half of PLAN §5.1's lifecycle: create the account,
// optionally write the session key into it, then remove it.
//
// It runs the commands directly rather than over SSH on purpose. The SSH legs
// of provisioning are a PROXY cost and are measured by the connection kind; what
// this has to isolate is the target-side serialisation, and a round trip in the
// loop would hide it behind network time.
func oneCycle(ctx context.Context, sc *Scenario, name string) (create, key, remove time.Duration, err error) {
	p := sc.Provisioning

	createArgs := []string{"-M"}
	if p.Home {
		createArgs = []string{"-m"}
	}
	createArgs = append(createArgs, "-s", "/bin/sh", name)

	t0 := time.Now()
	if out, err := runCmd(ctx, "useradd", createArgs...); err != nil {
		return 0, 0, 0, fmt.Errorf("useradd %s: %w: %s", name, err, out)
	}
	create = time.Since(t0)

	if p.AuthorizedKeys {
		t1 := time.Now()
		if err := writeAuthorizedKeys(name); err != nil {
			// Best effort teardown; the account exists and must not be left.
			_, _ = runCmd(ctx, "userdel", delArgs(p.Home, name)...)
			return 0, 0, 0, err
		}
		key = time.Since(t1)
	}

	t2 := time.Now()
	if out, err := runCmd(ctx, "userdel", delArgs(p.Home, name)...); err != nil {
		return 0, 0, 0, fmt.Errorf("userdel %s: %w: %s", name, err, out)
	}
	remove = time.Since(t2)
	return create, key, remove, nil
}

func delArgs(home bool, name string) []string {
	if home {
		return []string{"-r", name}
	}
	return []string{name}
}

// writeAuthorizedKeys puts a key in the account's ~/.ssh, with the permissions
// sshd insists on. The key is a fixed literal: generating one per cycle would
// measure key generation, which the proxy does once per session and is already
// counted in the connection run.
func writeAuthorizedKeys(name string) error {
	home := filepath.Join("/home", name)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return err
	}
	const pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGloadgenplaceholderkeynotusable loadgen\n"
	return os.WriteFile(filepath.Join(sshDir, "authorized_keys"), []byte(pub), 0o600)
}

func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// nssPasswdBackend reports what /etc/nsswitch.conf resolves accounts through.
// A fleet on a directory-backed NSS will not behave like one on flat files, so
// a provisioning number that does not say which was measured is not usable.
func nssPasswdBackend() string {
	b, err := os.ReadFile("/etc/nsswitch.conf")
	if err != nil {
		return "unknown"
	}
	for _, line := range splitLines(string(b)) {
		if k, v, ok := cutColon(line); ok && k == "passwd" {
			return v
		}
	}
	return "unknown"
}

// diagnoseSaturation names what stopped the sweep going faster. It reasons from
// the measured shape rather than guessing: perfect scaling means nothing
// serialised; a flat throughput curve with rising per-cycle latency is a lock.
func diagnoseSaturation(res *ProvisioningResult) string {
	if len(res.Levels) < 2 {
		return "not established: the sweep had fewer than two levels"
	}
	var serial, best ProvisioningLevel
	for _, l := range res.Levels {
		if l.Concurrency == 1 {
			serial = l
		}
		if l.PerSec > best.PerSec {
			best = l
		}
	}
	if serial.PerSec == 0 {
		return "not established: no serial level in the sweep"
	}
	gain := best.PerSec / serial.PerSec
	switch {
	case gain < 1.25:
		return fmt.Sprintf(
			"the target's account-database lock: %d concurrent provisioners reached only %.2fx the serial "+
				"rate while mean cycle latency rose from %.0fms to %.0fms — the work is serialised, "+
				"not queued behind a resource that more of would relieve",
			best.Concurrency, gain, serial.Cost.TotalMeanMS, best.Cost.TotalMeanMS)
	case gain < float64(best.Concurrency)*0.5:
		return fmt.Sprintf(
			"partial serialisation: %d concurrent provisioners reached %.2fx the serial rate "+
				"(perfect scaling would be %dx), so part of the cycle takes the account-database lock "+
				"and part does not",
			best.Concurrency, gain, best.Concurrency)
	default:
		return fmt.Sprintf(
			"nothing serialised within the levels swept: %d concurrent provisioners reached %.2fx "+
				"the serial rate, so the ceiling is above this sweep",
			best.Concurrency, gain)
	}
}
