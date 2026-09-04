// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// procSampler reads what the proxy PROCESS costs, from /proc.
//
// The proxy runs as a child process rather than in this one on purpose: memory
// per live connection cannot be attributed if the generator, the target and the
// proxy share a heap. Everything here is Linux-only, which is stated in
// load/README.md rather than papered over — a memory number from a different
// kernel's accounting would not be comparable anyway.
type procSampler struct {
	pid      int
	interval time.Duration
	clockHz  float64

	stop chan struct{}
	done chan struct{}

	mu      sync.Mutex
	samples []Sample
}

// Sample is one observation of the proxy process.
type Sample struct {
	At time.Time `json:"at"`
	// RSSKiB is resident set size.
	RSSKiB int64 `json:"rss_kib"`
	// FDs is the number of open file descriptors.
	FDs int `json:"fds"`
	// CPUSeconds is cumulative user+system CPU consumed since process start.
	CPUSeconds float64 `json:"cpu_seconds"`
	// Threads is the OS thread count, which is where a Go proxy's per-thread
	// stacks show up when goroutines block in syscalls.
	Threads int `json:"threads"`
	// Live is the number of connections the generator believed were live.
	Live int `json:"live_connections"`
}

func newProcSampler(pid int, interval time.Duration) *procSampler {
	return &procSampler{
		pid:      pid,
		interval: interval,
		// USER_HZ is 100 on every Linux target this runs on; the value is
		// compiled into the kernel ABI rather than discoverable without cgo.
		clockHz: 100,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
}

// run samples until stopped. liveFn reports the generator's current live count
// so a sample carries the load it was taken under.
func (p *procSampler) run(liveFn func() int) {
	go func() {
		defer close(p.done)
		t := time.NewTicker(p.interval)
		defer t.Stop()
		for {
			select {
			case <-p.stop:
				return
			case <-t.C:
				s, err := p.sample()
				if err != nil {
					continue // the process is gone; the run is ending anyway
				}
				s.Live = liveFn()
				p.mu.Lock()
				p.samples = append(p.samples, s)
				p.mu.Unlock()
			}
		}
	}()
}

func (p *procSampler) close() {
	close(p.stop)
	<-p.done
}

// sample takes one observation now, outside the loop, for the baseline.
func (p *procSampler) sample() (Sample, error) {
	s := Sample{At: time.Now()}
	rss, threads, err := p.readStatus()
	if err != nil {
		return s, err
	}
	s.RSSKiB, s.Threads = rss, threads
	if cpu, err := p.readCPU(); err == nil {
		s.CPUSeconds = cpu
	}
	if fds, err := p.countFDs(); err == nil {
		s.FDs = fds
	}
	return s, nil
}

func (p *procSampler) readStatus() (rssKiB int64, threads int, err error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", p.pid))
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "VmRSS:"):
			rssKiB = parseKiB(line)
		case strings.HasPrefix(line, "Threads:"):
			threads, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Threads:")))
		}
	}
	return rssKiB, threads, sc.Err()
}

func parseKiB(line string) int64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	v, _ := strconv.ParseInt(fields[1], 10, 64)
	return v
}

func (p *procSampler) readCPU() (float64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", p.pid))
	if err != nil {
		return 0, err
	}
	// Fields after the parenthesised comm name; utime and stime are the 14th
	// and 15th overall, i.e. index 11 and 12 counting from the field after ")".
	s := string(b)
	i := strings.LastIndex(s, ")")
	if i < 0 {
		return 0, fmt.Errorf("sampler: malformed /proc/%d/stat", p.pid)
	}
	fields := strings.Fields(s[i+1:])
	if len(fields) < 13 {
		return 0, fmt.Errorf("sampler: short /proc/%d/stat", p.pid)
	}
	utime, _ := strconv.ParseFloat(fields[11], 64)
	stime, _ := strconv.ParseFloat(fields[12], 64)
	return (utime + stime) / p.clockHz, nil
}

func (p *procSampler) countFDs() (int, error) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", p.pid))
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

// clear drops the samples taken so far. The measured window calls it when
// warmup ends: samples from the warmup describe a different cache and a
// different connection count, and averaging them in would move the plateau.
func (p *procSampler) clear() {
	p.mu.Lock()
	p.samples = nil
	p.mu.Unlock()
}

// all returns the samples taken so far.
func (p *procSampler) all() []Sample {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Sample, len(p.samples))
	copy(out, p.samples)
	return out
}

// plateau summarises the samples whose live count is within tolerance of the
// maximum observed. Memory per live connection is read off the plateau rather
// than off a peak: a single peak sample can catch a garbage collection cycle,
// and a mean over a ramp measures the ramp.
func plateau(samples []Sample, tolerance float64) (n int, meanRSSKiB float64, meanLive float64) {
	maxLive := 0
	for _, s := range samples {
		if s.Live > maxLive {
			maxLive = s.Live
		}
	}
	if maxLive == 0 {
		return 0, 0, 0
	}
	floor := float64(maxLive) * (1 - tolerance)
	var sumRSS, sumLive float64
	for _, s := range samples {
		if float64(s.Live) >= floor {
			n++
			sumRSS += float64(s.RSSKiB)
			sumLive += float64(s.Live)
		}
	}
	if n == 0 {
		return 0, 0, 0
	}
	return n, sumRSS / float64(n), sumLive / float64(n)
}

// percentile returns the p-th percentile of durations (p in [0,1]), nearest
// rank. The slice is sorted in place.
func percentile(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	if !sort.SliceIsSorted(d, func(i, j int) bool { return d[i] < d[j] }) {
		sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	}
	idx := int(p * float64(len(d)))
	if idx >= len(d) {
		idx = len(d) - 1
	}
	return d[idx]
}

func meanDuration(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	var total time.Duration
	for _, v := range d {
		total += v
	}
	return total / time.Duration(len(d))
}
