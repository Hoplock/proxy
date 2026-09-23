// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// configReport is the part of a proxy's configuration report the scenario
// reads (api/control.yaml, ProxyConfigReport).
type configReport struct {
	RunningVersion  string   `json:"running_version"`
	DesiredVersion  string   `json:"desired_version"`
	State           string   `json:"state"`
	RestartRequired []string `json:"restart_required"`
	LastError       string   `json:"last_error"`
}

// publishConfig publishes a fleet document through the mock's stand-in for
// Hoplock Control's publisher (POST /debug/config).
func publishConfig(t *testing.T, version, settings string) {
	t.Helper()
	body := fmt.Sprintf(`{"version":%q,"settings":%s}`, version, settings)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+controlAddr+"/debug/config", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("publish %s: %v", version, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("publish %s: status %s", version, resp.Status)
	}
}

// configReportOf is the last configuration report from one proxy.
func configReportOf(proxyID string) (configReport, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+controlAddr+"/debug/config/reports", nil)
	if err != nil {
		return configReport{}, false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return configReport{}, false
	}
	defer func() { _ = resp.Body.Close() }()
	var all map[string]configReport
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&all) != nil {
		return configReport{}, false
	}
	rep, ok := all[proxyID]
	return rep, ok
}

// waitForReport waits until every named proxy reports what want accepts.
func waitForReport(t *testing.T, what string, want func(configReport) bool, proxies ...string) {
	t.Helper()
	waitFor(t, what, func() bool {
		for _, p := range proxies {
			if rep, ok := configReportOf(p); !ok || !want(rep) {
				return false
			}
		}
		return true
	})
}

// testFleetConfig is a rollout through the real binaries (PLAN D18): the event
// reaches each proxy, the proxy fetches, applies what it can apply live, and
// reports what it is running. What a document CONTAINS is chosen to change
// nothing the rest of the suite depends on — every value equals the proxies'
// own bootstrap value — so the scenario tests the delivery and the reporting,
// not a second copy of the settings' own tests, and it ends by restoring.
func testFleetConfig(t *testing.T) {
	proxies := []string{proxyDirect, proxyZone}

	t.Run("a live document is applied and reported running", func(t *testing.T) {
		publishConfig(t, "e2e-live", `{"control.cache.max_ttl":"0s"}`)
		waitForReport(t, "e2e-live to be running", func(r configReport) bool {
			return r.State == "applied" && r.RunningVersion == "e2e-live"
		}, proxies...)
	})

	t.Run("a document needing a restart is pending, never running", func(t *testing.T) {
		publishConfig(t, "e2e-restart", `{"control.cache.max_ttl":"0s","logging.batch_size":16}`)
		waitForReport(t, "e2e-restart to be pending", func(r configReport) bool {
			return r.State == "pending_restart" && r.DesiredVersion == "e2e-restart" &&
				r.RunningVersion == "e2e-live" && len(r.RestartRequired) == 1 && r.RestartRequired[0] == "logging.batch_size"
		}, proxies...)
	})

	t.Run("a document naming a bootstrap setting is rejected and the proxy keeps serving", func(t *testing.T) {
		publishConfig(t, "e2e-orphan", `{"control.base_url":"http://nowhere.invalid:1"}`)
		waitForReport(t, "e2e-orphan to be rejected", func(r configReport) bool {
			return r.State == "rejected" && r.DesiredVersion == "e2e-orphan" &&
				r.RunningVersion == "e2e-live" && strings.Contains(r.LastError, "control.base_url")
		}, proxies...)

		s := aliceOn(proxyDirect, "host.company.com")
		s.command = "/bin/echo still-serving"
		r := ssh(t, s)
		wantExit(t, r, "a session after a rejected document", 0)
		wantContains(t, r, "a session after a rejected document", "still-serving")
	})

	t.Run("restoring the bootstrap values", func(t *testing.T) {
		publishConfig(t, "e2e-restore", `{}`)
		waitForReport(t, "e2e-restore to be running", func(r configReport) bool {
			return r.State == "applied" && r.RunningVersion == "e2e-restore"
		}, proxies...)
	})
}
