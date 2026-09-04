// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"strings"
	"testing"
	"time"
)

func TestPlateauIgnoresTheRamp(t *testing.T) {
	// A mean over the whole run measures the ramp; a single peak sample can
	// catch a garbage collection. The plateau is the samples taken at (near)
	// full load, which is the only window where RSS divided by live
	// connections means anything.
	samples := []Sample{
		{RSSKiB: 10_000, Live: 10},
		{RSSKiB: 50_000, Live: 100},
		{RSSKiB: 52_000, Live: 98},
		{RSSKiB: 51_000, Live: 95},
	}
	n, rss, live := plateau(samples, 0.1)
	if n != 3 {
		t.Fatalf("plateau samples = %d, want the 3 at full load", n)
	}
	if rss < 50_000 || rss > 52_000 {
		t.Errorf("plateau RSS = %.0f, want it between the plateau samples", rss)
	}
	if live < 95 || live > 100 {
		t.Errorf("plateau live = %.0f, want it between 95 and 100", live)
	}
}

func TestPlateauWithNoLiveConnections(t *testing.T) {
	if n, _, _ := plateau([]Sample{{RSSKiB: 100}}, 0.1); n != 0 {
		t.Errorf("plateau samples = %d, want 0 when nothing was live", n)
	}
}

func TestPercentile(t *testing.T) {
	d := []time.Duration{5, 1, 4, 2, 3}
	if got := percentile(d, 0.5); got != 3 {
		t.Errorf("p50 = %v, want 3", got)
	}
	if got := percentile(d, 0.99); got != 5 {
		t.Errorf("p99 = %v, want 5", got)
	}
	if got := percentile(nil, 0.5); got != 0 {
		t.Errorf("p50 of nothing = %v, want 0", got)
	}
}

func TestSaturationNeedsACurve(t *testing.T) {
	one := &ConnectionResult{Steps: []StepResult{{Mode: ModeRate, OfferedRate: 100, AchievedRate: 100}}}
	if got := diagnoseConnectionSaturation(one); !strings.Contains(got, "not established") {
		t.Errorf("one step diagnosed as %q, want it to refuse", got)
	}
	// A sweep that held the rate fixed varied something else; naming one of its
	// rows the saturation point would attribute a change to the wrong axis.
	fixed := &ConnectionResult{Steps: []StepResult{
		{Mode: ModeRate, OfferedRate: 100, AchievedRate: 100, Targets: 10},
		{Mode: ModeRate, OfferedRate: 100, AchievedRate: 100, Targets: 1000},
	}}
	if got := diagnoseConnectionSaturation(fixed); got != "" {
		t.Errorf("fixed-rate sweep diagnosed as %q, want no verdict", got)
	}
}

func TestSaturationNamesDescriptorsBeforeCPU(t *testing.T) {
	// Descriptors, Control latency and CPU have different fixes, so a report
	// that collapses them into "it was slow" is not actionable.
	res := &ConnectionResult{
		Host: HostInfo{NumCPU: 8},
		Steps: []StepResult{
			{Mode: ModeRate, OfferedRate: 100, AchievedRate: 100},
			{Mode: ModeRate, OfferedRate: 500, AchievedRate: 200, PeakFDs: 950, FDLimit: 1024},
		},
	}
	if got := diagnoseConnectionSaturation(res); !strings.Contains(got, "file descriptors") {
		t.Errorf("diagnosis = %q, want it to name file descriptors", got)
	}
}

func TestSaturationNamesControlLatency(t *testing.T) {
	res := &ConnectionResult{
		Host: HostInfo{NumCPU: 8},
		Steps: []StepResult{
			{Mode: ModeRate, OfferedRate: 100, AchievedRate: 100},
			{
				Mode: ModeRate, OfferedRate: 500, AchievedRate: 200,
				ConnectMeanMS: 20,
				ControlCalls:  []CallReport{{Path: "/v1/authorize", PerConn: 1, MeanMicros: 15_000}},
			},
		},
	}
	if got := diagnoseConnectionSaturation(res); !strings.Contains(got, "Control latency") {
		t.Errorf("diagnosis = %q, want it to name Control latency", got)
	}
}

func TestProvisioningSaturationReadsTheCurve(t *testing.T) {
	serialised := &ProvisioningResult{Levels: []ProvisioningLevel{
		{Concurrency: 1, PerSec: 30, Cost: StageCost{TotalMeanMS: 33}},
		{Concurrency: 8, PerSec: 33, Cost: StageCost{TotalMeanMS: 240}},
	}}
	if got := diagnoseSaturation(serialised); !strings.Contains(got, "account-database lock") {
		t.Errorf("diagnosis = %q, want it to name the lock", got)
	}
	scaling := &ProvisioningResult{Levels: []ProvisioningLevel{
		{Concurrency: 1, PerSec: 30},
		{Concurrency: 8, PerSec: 230},
	}}
	if got := diagnoseSaturation(scaling); !strings.Contains(got, "nothing serialised") {
		t.Errorf("diagnosis = %q, want it to say the ceiling is above the sweep", got)
	}
	if got := diagnoseSaturation(&ProvisioningResult{}); !strings.Contains(got, "not established") {
		t.Errorf("diagnosis = %q, want it to refuse an empty sweep", got)
	}
}

func TestReportTagsEveryFigure(t *testing.T) {
	// The point of the phase is that docs/PLAN.md carries derived figures that
	// read like measured ones. A report that repeated the trick would be worse
	// than none.
	var b strings.Builder
	writeConnectionReport(&b, &ConnectionResult{
		Scenario: "t",
		Host:     HostInfo{NumCPU: 4},
		Steps: []StepResult{{
			Mode: ModeRate, OfferedRate: 100, AchievedRate: 99, Succeeded: 99,
			ConnectMeanMS: 3, ProxyCPUPerConnMS: 5, PlateauLive: 50, PlateauRSSKiB: 20000,
			BaselineRSSKiB: 10000, RSSPerConnKiB: 200,
		}},
	})
	out := b.String()
	for _, want := range []string{tagMeasured, tagDerived, "RSS per live connection", "CPU-bound ceiling"} {
		if !strings.Contains(out, want) {
			t.Errorf("report is missing %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		// Every value line starts with a tag; headers and continuations do not
		// carry values.
		if strings.HasPrefix(line, "  [") && !strings.Contains(line, tagMeasured) && !strings.Contains(line, tagDerived) {
			t.Errorf("untagged value line: %q", line)
		}
	}
}

func TestWrapIndent(t *testing.T) {
	got := wrapIndent("one two three four", 9, "..")
	if !strings.Contains(got, "\n..") {
		t.Errorf("wrapIndent = %q, want a wrapped line with the indent", got)
	}
}
