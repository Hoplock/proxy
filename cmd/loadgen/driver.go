// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// driver offers SSH connections to the proxy and records what each one cost.
//
// It is a closed-loop generator with an open-loop clock: connections are
// started on a fixed schedule (rate mode) rather than as fast as the previous
// one finished, so a proxy that slows down shows up as a growing in-flight
// count and a missed offered rate — not as a quietly lower offered load, which
// is how a naive generator hides saturation from itself.
type driver struct {
	sc *Scenario
	// plan is this step's offered rate and working set.
	plan      stepPlan
	proxyAddr string
	hostKey   ssh.PublicKey
	signer    ssh.Signer

	live      atomic.Int64
	started   atomic.Uint64
	succeeded atomic.Uint64
	failed    atomic.Uint64

	measuring atomic.Bool

	mu        sync.Mutex
	connectD  []time.Duration
	sessionD  []time.Duration
	errors    map[string]int
	nextIndex atomic.Uint64
}

func newDriver(sc *Scenario, plan stepPlan, proxyAddr string, hostKey ssh.PublicKey, signer ssh.Signer) *driver {
	return &driver{
		sc:        sc,
		plan:      plan,
		proxyAddr: proxyAddr,
		hostKey:   hostKey,
		signer:    signer,
		errors:    make(map[string]int),
	}
}

// username builds the SSH username for the i-th connection: D1's
// "<login>#<target>" split. The login selects the subject and the target
// selects the cache shape, so the two dimensions of the workload are both
// carried here.
func (d *driver) username(i uint64) string {
	subjects := uint64(d.sc.Workload.Subjects)
	targets := uint64(d.plan.Targets)
	var t uint64
	if d.sc.Workload.Order == OrderRandom {
		t = rand.Uint64N(targets)
	} else {
		t = i % targets
	}
	return fmt.Sprintf("svc%d#t%07d.load.invalid", i%subjects, d.plan.NameOffset+t)
}

func (d *driver) clientConfig(user string) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(d.signer)},
		HostKeyCallback: ssh.FixedHostKey(d.hostKey),
		Timeout:         30 * time.Second,
	}
}

// one runs a single connection end to end and records it.
func (d *driver) one(ctx context.Context, i uint64) {
	d.started.Add(1)
	user := d.username(i)

	start := time.Now()
	conn, err := (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, "tcp", d.proxyAddr)
	if err != nil {
		d.fail("dial", err)
		return
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, d.proxyAddr, d.clientConfig(user))
	if err != nil {
		_ = conn.Close()
		d.fail("handshake", err)
		return
	}
	connectCost := time.Since(start)
	client := ssh.NewClient(c, chans, reqs)
	d.live.Add(1)
	defer func() {
		_ = client.Close()
		d.live.Add(-1)
	}()

	var sessionCost time.Duration
	if d.sc.Run.Session == SessionExec {
		sessStart := time.Now()
		sess, err := client.NewSession()
		if err != nil {
			d.fail("session", err)
			return
		}
		out, err := sess.CombinedOutput(d.sc.Run.Command)
		if err != nil {
			_ = sess.Close()
			// The proxy reports a denial to the USER over stderr and exits 254
			// (internal/proxy/feedback.go), so the exit code alone would hide
			// every policy failure behind one number.
			d.fail("exec", fmt.Errorf("%w: %s", err, firstLine(out)))
			return
		}
		_ = sess.Close()
		sessionCost = time.Since(sessStart)
	}

	if hold := d.sc.Run.Hold; hold > 0 {
		select {
		case <-ctx.Done():
		case <-time.After(hold):
		}
	}
	d.succeeded.Add(1)
	d.record(connectCost, sessionCost)
}

func (d *driver) record(connect, session time.Duration) {
	if !d.measuring.Load() {
		return
	}
	d.mu.Lock()
	d.connectD = append(d.connectD, connect)
	if session > 0 {
		d.sessionD = append(d.sessionD, session)
	}
	d.mu.Unlock()
}

func (d *driver) fail(stage string, err error) {
	d.failed.Add(1)
	if !d.measuring.Load() {
		return
	}
	d.mu.Lock()
	d.errors[stage+": "+classify(err)]++
	d.mu.Unlock()
}

// firstLine returns the first non-empty line of output, for an error message.
func firstLine(b []byte) string {
	for _, line := range strings.Split(string(b), "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}

// classify collapses an error to something countable. The full text of ten
// thousand identical failures is noise; the shape of them is the finding.
func classify(err error) string {
	s := err.Error()
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// reset drops everything recorded so far. Called when warmup ends.
func (d *driver) reset() {
	d.mu.Lock()
	d.connectD = nil
	d.sessionD = nil
	d.errors = make(map[string]int)
	d.mu.Unlock()
	d.started.Store(0)
	d.succeeded.Store(0)
	d.failed.Store(0)
}

// runRate offers connections at a fixed rate for d, bounded by MaxInflight.
func (d *driver) runRate(ctx context.Context, dur time.Duration) {
	period := time.Duration(float64(time.Second) / d.plan.Rate)
	if period <= 0 {
		period = time.Microsecond
	}
	sem := make(chan struct{}, d.sc.Run.MaxInflight)
	var wg sync.WaitGroup
	deadline := time.After(dur)
	ticker := time.NewTicker(period)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case <-deadline:
			wg.Wait()
			return
		case <-ticker.C:
			select {
			case sem <- struct{}{}:
			default:
				// In-flight cap reached: the offered rate could not be met.
				// The shortfall is visible as achieved-vs-offered in the
				// report, which is the saturation signal.
				continue
			}
			i := d.nextIndex.Add(1) - 1
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				d.one(ctx, i)
			}()
		}
	}
}

// runHold ramps to Concurrency live connections and keeps them there for dur.
// Each connection does its work once and then idles, so what the plateau
// measures is the cost of BEING connected rather than of connecting.
func (d *driver) runHold(ctx context.Context, ramp, dur time.Duration) {
	holdCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	n := d.sc.Run.Concurrency
	gap := time.Duration(0)
	if ramp > 0 && n > 0 {
		gap = ramp / time.Duration(n)
	}
	var wg sync.WaitGroup
	for range n {
		select {
		case <-ctx.Done():
			cancel()
			wg.Wait()
			return
		default:
		}
		wg.Add(1)
		idx := d.nextIndex.Add(1) - 1
		go func() {
			defer wg.Done()
			d.holdOne(holdCtx, idx)
		}()
		if gap > 0 {
			time.Sleep(gap)
		}
	}

	select {
	case <-ctx.Done():
	case <-time.After(dur):
	}
	cancel()
	wg.Wait()
}

// holdOne connects, does the scenario's work once, and stays connected until
// the context ends.
func (d *driver) holdOne(ctx context.Context, i uint64) {
	d.started.Add(1)
	user := d.username(i)
	start := time.Now()
	conn, err := (&net.Dialer{Timeout: 60 * time.Second}).DialContext(ctx, "tcp", d.proxyAddr)
	if err != nil {
		d.fail("dial", err)
		return
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, d.proxyAddr, d.clientConfig(user))
	if err != nil {
		_ = conn.Close()
		d.fail("handshake", err)
		return
	}
	connectCost := time.Since(start)
	client := ssh.NewClient(c, chans, reqs)
	d.live.Add(1)
	defer func() {
		_ = client.Close()
		d.live.Add(-1)
	}()

	var sessionCost time.Duration
	if d.sc.Run.Session == SessionExec {
		sessStart := time.Now()
		if sess, err := client.NewSession(); err == nil {
			if out, err := sess.CombinedOutput(d.sc.Run.Command); err != nil {
				d.fail("exec", fmt.Errorf("%w: %s", err, firstLine(out)))
			}
			_ = sess.Close()
			sessionCost = time.Since(sessStart)
		} else {
			d.fail("session", err)
		}
	}
	d.succeeded.Add(1)
	d.record(connectCost, sessionCost)
	<-ctx.Done()
}

// errorTable returns the recorded failures, most frequent first.
func (d *driver) errorTable() []ErrorCount {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]ErrorCount, 0, len(d.errors))
	for k, v := range d.errors {
		out = append(out, ErrorCount{Stage: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > 10 {
		out = out[:10]
	}
	return out
}

// ErrorCount is one failure shape and how often it happened.
type ErrorCount struct {
	Stage string `json:"stage"`
	Count int    `json:"count"`
}

// latencies returns copies of the recorded distributions.
func (d *driver) latencies() (connect, session []time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	connect = append(connect, d.connectD...)
	session = append(session, d.sessionD...)
	return connect, session
}
