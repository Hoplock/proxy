// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"fmt"
	"io"
	"strings"
)

// Every printed number is tagged. "measured" is something the run observed;
// "derived" is arithmetic on measured values, and the arithmetic is printed
// beside it. Nothing is printed without one of the two, because the whole point
// of this phase is that the plan currently carries derived figures that read
// like measured ones.
const (
	tagMeasured = "measured"
	tagDerived  = "derived"
)

func writeConnectionReport(w io.Writer, r *ConnectionResult) {
	h := r.Host
	fmt.Fprintf(w, "== %s ==\n", r.Scenario)
	if r.Description != "" {
		fmt.Fprintf(w, "%s\n", wrap(r.Description, 78))
	}
	fmt.Fprintf(w, "\nHardware: %s, %d logical CPUs, %d MiB RAM, %s/%s, %s\n",
		orDash(h.CPUName), h.NumCPU, h.MemMiB, h.OS, h.Arch, h.GoVer)
	for i := range r.Steps {
		writeStep(w, &r.Steps[i], h, len(r.Steps) > 1, i+1)
	}
	if len(r.Steps) > 1 {
		writeSweepTable(w, r.Steps)
	}
	if r.Saturation != "" {
		fmt.Fprintf(w, "\n-- Where it saturates --\n  %s\n", wrapIndent(r.Saturation, 76, "  "))
	}
	if r.ProxyLogTail != "" {
		fmt.Fprintf(w, "\n-- Proxy log (tail) --\n%s\n", r.ProxyLogTail)
	}
}

func writeStep(w io.Writer, r *StepResult, h HostInfo, numbered bool, n int) {
	head := "\n-- Step --\n"
	if numbered {
		head = fmt.Sprintf("\n-- Step %d: %.0f conn/s offered --\n", n, r.OfferedRate)
	}
	fmt.Fprint(w, head)
	fmt.Fprintf(w, "Method:   %s mode, %s measured after %s warmup; %d subject(s) x %d target name(s), %s order\n",
		r.Mode, r.Duration, r.Warmup, r.Subjects, r.Targets, r.Order)
	if r.CacheHint {
		fmt.Fprintf(w, "          server cache hint ON, scope %s, ttl %s\n", r.CacheScope, r.CacheTTL)
	} else {
		fmt.Fprintf(w, "          server cache hint OFF (every connection re-authorizes)\n")
	}

	fmt.Fprintf(w, "\n  Establishment\n")
	if r.Mode == ModeRate {
		row(w, tagMeasured, "offered rate", fmt.Sprintf("%.0f conn/s", r.OfferedRate), "")
	}
	row(w, tagMeasured, "connections completed", fmt.Sprintf("%d ok, %d failed", r.Succeeded, r.Failed), "")
	if r.Mode == ModeRate {
		row(w, tagMeasured, "achieved rate", fmt.Sprintf("%.1f conn/s", r.AchievedRate), "succeeded / elapsed")
	} else {
		// In hold mode every connection is opened once and kept, so a rate
		// would just be the ramp divided by the window — a property of the
		// scenario, not of the proxy.
		row(w, tagMeasured, "connections held", fmt.Sprintf("%d at the plateau", r.PeakLive), "")
	}
	row(w, tagMeasured, "connect latency", fmt.Sprintf("mean %.1f ms, p50 %.1f, p95 %.1f, p99 %.1f",
		r.ConnectMeanMS, r.ConnectP50MS, r.ConnectP95MS, r.ConnectP99MS), "TCP + SSH handshake + user auth")
	if r.SessionMeanMS > 0 {
		row(w, tagMeasured, "session+exec latency", fmt.Sprintf("mean %.1f ms, p95 %.1f", r.SessionMeanMS, r.SessionP95MS), "")
	}

	fmt.Fprintf(w, "\n  What the proxy process cost\n")
	row(w, tagMeasured, "baseline RSS (idle)", fmt.Sprintf("%d KiB", r.BaselineRSSKiB), "")
	if r.RSSPerConnKiB > 0 {
		row(w, tagMeasured, "plateau RSS", fmt.Sprintf("%.0f KiB at %.0f live conns (%d samples)",
			r.PlateauRSSKiB, r.PlateauLive, r.PlateauSamples), "")
		row(w, tagDerived, "RSS per live connection", fmt.Sprintf("%.1f KiB", r.RSSPerConnKiB),
			"(plateau RSS - baseline RSS) / plateau live")
	} else {
		row(w, tagMeasured, "peak RSS", fmt.Sprintf("%d KiB", r.PeakRSSKiB), "")
		fmt.Fprintf(w, "             memory per live connection is not measurable in %s mode: connections\n"+
			"             do not overlap long enough to form a plateau. Use a hold-mode scenario.\n", r.Mode)
	}
	row(w, tagMeasured, "peak file descriptors", fmt.Sprintf("%d of %d soft limit", r.PeakFDs, r.FDLimit), "")
	row(w, tagMeasured, "peak OS threads", fmt.Sprintf("%d", r.PeakThreads), "")
	row(w, tagMeasured, "proxy CPU", fmt.Sprintf("%.2f s (%.2f cores of %d)", r.ProxyCPUSeconds, r.ProxyCPUCores, h.NumCPU), "")
	cpuHow := "proxy CPU seconds / connections"
	if r.Mode == ModeHold {
		cpuHow = "proxy CPU seconds / connections; in hold mode that is establishing AND holding one"
	}
	row(w, tagDerived, "proxy CPU per connection", fmt.Sprintf("%.2f ms", r.ProxyCPUPerConnMS), cpuHow)
	if r.ProxyCPUPerConnMS > 0 && r.Mode == ModeRate {
		row(w, tagDerived, "CPU-bound ceiling", fmt.Sprintf("%.0f conn/s per proxy on %d cores",
			1000/r.ProxyCPUPerConnMS*float64(h.NumCPU), h.NumCPU),
			"cores / CPU-seconds per connection; assumes perfect core scaling")
	}
	if r.RSSPerConnKiB > 0 {
		for _, budget := range []int{1, 4, 16} {
			row(w, tagDerived, fmt.Sprintf("concurrent conns at %d GiB", budget),
				fmt.Sprintf("%.0f", (float64(budget)*1024*1024-float64(r.BaselineRSSKiB))/r.RSSPerConnKiB),
				"(budget - baseline) / RSS per live connection")
		}
	}

	fmt.Fprintf(w, "\n  Hoplock Control load\n")
	row(w, tagMeasured, "control calls per connection", fmt.Sprintf("%.3f", r.ControlPerConn), "all endpoints")
	for _, c := range r.ControlCalls {
		row(w, tagMeasured, "  "+callName(c.Path),
			fmt.Sprintf("%.3f/conn (%d calls, mean %.2f ms server-side)", c.PerConn, c.Count, c.MeanMicros/1000), "")
	}
	row(w, tagDerived, "authorize cache hit rate", fmt.Sprintf("%.1f%%", r.CacheHitRatePct),
		"(connections - authorize calls) / connections")

	if len(r.Errors) > 0 {
		fmt.Fprintf(w, "\n  Failures\n")
		for _, e := range r.Errors {
			fmt.Fprintf(w, "  %6d  %s\n", e.Count, e.Stage)
		}
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "\n  NOTE: %s\n", wrapIndent(n, 76, "        "))
	}
}

// writeSweepTable is the whole point of a multi-step run: the curve, on one
// screen, so "where does it stop scaling" is a thing you can see rather than a
// thing you have to compute from paragraphs.
func writeSweepTable(w io.Writer, steps []StepResult) {
	fmt.Fprintf(w, "\n-- Sweep --\n")
	fmt.Fprintf(w, "  %8s  %8s  %9s  %8s  %8s  %8s  %9s  %7s\n",
		"offered", "targets", "achieved", "p50 ms", "p99 ms", "cores", "cpu ms/c", "hit %")
	for _, s := range steps {
		fmt.Fprintf(w, "  %8.0f  %8d  %9.1f  %8.1f  %8.1f  %8.2f  %9.2f  %7.1f\n",
			s.OfferedRate, s.Targets, s.AchievedRate, s.ConnectP50MS, s.ConnectP99MS,
			s.ProxyCPUCores, s.ProxyCPUPerConnMS, s.CacheHitRatePct)
	}
	for _, s := range steps {
		if s.Failed > 0 {
			fmt.Fprintf(w, "  (%d connections failed at %.0f conn/s x %d targets)\n",
				s.Failed, s.OfferedRate, s.Targets)
		}
	}
}

func writeProvisioningReport(w io.Writer, r *ProvisioningResult) {
	h := r.Host
	fmt.Fprintf(w, "== %s ==\n", r.Scenario)
	if r.Description != "" {
		fmt.Fprintf(w, "%s\n", wrap(r.Description, 78))
	}
	fmt.Fprintf(w, "\nHardware: %s, %d logical CPUs, %d MiB RAM, %s/%s\n",
		orDash(h.CPUName), h.NumCPU, h.MemMiB, h.OS, h.Arch)
	fmt.Fprintf(w, "Method:   %s executor, NSS passwd backend %q, home dir %v, authorized_keys %v, %d cycles per level\n",
		r.Executor, r.NSSBackend, r.HomeDirectory, r.AuthorizedKeys, r.Cycles)

	fmt.Fprintf(w, "\n-- One provision/teardown cycle (serial) --\n")
	row(w, tagMeasured, "useradd", fmt.Sprintf("mean %.1f ms, p95 %.1f", r.Single.CreateMeanMS, r.Single.CreateP95MS), "")
	if r.Single.KeyMeanMS > 0 {
		row(w, tagMeasured, "authorized_keys write", fmt.Sprintf("mean %.1f ms", r.Single.KeyMeanMS), "")
	}
	row(w, tagMeasured, "userdel", fmt.Sprintf("mean %.1f ms, p95 %.1f", r.Single.RemoveMeanMS, r.Single.RemoveP95MS), "")
	row(w, tagMeasured, "whole cycle", fmt.Sprintf("mean %.1f ms, p95 %.1f", r.Single.TotalMeanMS, r.Single.TotalP95MS), "")

	fmt.Fprintf(w, "\n-- Concurrency sweep against ONE target --\n")
	fmt.Fprintf(w, "  %5s  %10s  %12s  %10s  %s\n", "conc", "cycles/s", "efficiency", "mean ms", "failures")
	for _, l := range r.Levels {
		fmt.Fprintf(w, "  %5d  %10.2f  %11.0f%%  %10.1f  %d\n",
			l.Concurrency, l.PerSec, l.Efficiency*100, l.Cost.TotalMeanMS, l.Failures)
	}
	fmt.Fprintf(w, "\n")
	row(w, tagMeasured, "per-target ceiling", fmt.Sprintf("%.1f provision/teardown cycles per second (at concurrency %d)",
		r.CeilingPerSec, r.CeilingAt), "")
	fmt.Fprintf(w, "  [%s] what saturated: %s\n", tagMeasured, wrapIndent(r.Saturated, 74, "      "))
	for _, n := range r.Notes {
		fmt.Fprintf(w, "\nNOTE: %s\n", wrap(n, 78))
	}
}

func row(w io.Writer, tag, label, value, how string) {
	fmt.Fprintf(w, "  [%-8s] %-32s %s\n", tag, label, value)
	if how != "" {
		fmt.Fprintf(w, "  %-10s %-32s   (%s)\n", "", "", how)
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func wrap(s string, width int) string { return wrapIndent(s, width, "") }

func wrapIndent(s string, width int, indent string) string {
	words := strings.Fields(s)
	var b strings.Builder
	col := 0
	for i, word := range words {
		if col > 0 && col+1+len(word) > width {
			b.WriteString("\n" + indent)
			col = len(indent)
		} else if i > 0 {
			b.WriteByte(' ')
			col++
		}
		b.WriteString(word)
		col += len(word)
	}
	return b.String()
}
