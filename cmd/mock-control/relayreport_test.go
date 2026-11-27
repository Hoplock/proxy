// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// postRelayReport sends a raw body to the report endpoint, so the validation
// table can send what the real client never would.
func postRelayReport(t *testing.T, m *mock, proxyID, token, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, m.srv.URL+control.RelayRegistrationReportPath(proxyID), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var env errorEnvelope
	_ = json.NewDecoder(resp.Body).Decode(&env)
	return resp.StatusCode, env.Error.Code
}

// debugRelayRegistrations reads the mock-only debug endpoint.
func debugRelayRegistrations(t *testing.T, m *mock) map[string]relayRegistrationReport {
	t.Helper()
	resp, err := http.Get(m.srv.URL + pathDebugRelayRegistrations)
	if err != nil {
		t.Fatalf("GET %s: %v", pathDebugRelayRegistrations, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", pathDebugRelayRegistrations, resp.StatusCode)
	}
	var out map[string]relayRegistrationReport
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func relayFixtures() *fixtures {
	return &fixtures{
		ProxyToken:  "relay-token",
		FleetConfig: fixtureFleetConfig{Enrolled: []string{"proxy-hub", "proxy-other"}},
	}
}

func TestRelayRegistrationReportValidation(t *testing.T) {
	m := startMock(t, relayFixtures(), serverOptions{})
	for _, tc := range []struct {
		name   string
		proxy  string
		token  string
		body   string
		status int
		code   string
	}{
		{name: "an empty set", body: `{"registered_proxy_ids":[]}`, status: 200},
		{name: "a set", body: `{"registered_proxy_ids":["proxy-zone","proxy-b"]}`, status: 200},
		{name: "an unknown field", body: `{"registered_proxy_ids":[],"since":"2026-01-01T00:00:00Z"}`, status: 400, code: "invalid_request"},
		{name: "no set", body: `{}`, status: 400, code: "invalid_request"},
		{name: "a null set", body: `{"registered_proxy_ids":null}`, status: 400, code: "invalid_request"},
		{name: "an empty id", body: `{"registered_proxy_ids":["proxy-zone",""]}`, status: 400, code: "invalid_request"},
		{name: "a duplicate id", body: `{"registered_proxy_ids":["proxy-zone","proxy-zone"]}`, status: 400, code: "invalid_request"},
		{name: "not JSON", body: `registered_proxy_ids=proxy-zone`, status: 400, code: "invalid_request"},
		{name: "an unenrolled hub", proxy: "proxy-stranger", body: `{"registered_proxy_ids":[]}`, status: 404, code: "not_enrolled"},
		{name: "a rejected token", token: "wrong", body: `{"registered_proxy_ids":[]}`, status: 401, code: "unauthorized"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy, token := tc.proxy, tc.token
			if proxy == "" {
				proxy = "proxy-hub"
			}
			if token == "" {
				token = "relay-token"
			}
			status, code := postRelayReport(t, m, proxy, token, tc.body)
			if status != tc.status || code != tc.code {
				t.Errorf("status %d code %q, want %d %q", status, code, tc.status, tc.code)
			}
		})
	}
}

// TestARefusedRelayReportRecordsNothing: a malformed report must not replace a
// good one, or the mock would show a hub as holding nothing when it said
// nothing valid at all.
func TestARefusedRelayReportRecordsNothing(t *testing.T) {
	m := startMock(t, relayFixtures(), serverOptions{})
	if _, err := m.client.ReportRelayRegistrations(context.Background(), "proxy-hub",
		&control.RelayRegistrationReport{RegisteredProxyIDs: []string{"proxy-zone"}}); err != nil {
		t.Fatal(err)
	}
	if status, _ := postRelayReport(t, m, "proxy-hub", "relay-token", `{"registered_proxy_ids":null}`); status != 400 {
		t.Fatalf("a null set answered %d", status)
	}
	if rep, _ := m.server.relayReport("proxy-hub"); !slices.Equal(rep.RegisteredProxyIDs, []string{"proxy-zone"}) {
		t.Errorf("after a refused report the hub holds %v, want the last good set", rep.RegisteredProxyIDs)
	}
}

func TestRelayRegistrationReportIsKeptPerHubAndReplaced(t *testing.T) {
	now := time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	m := startMock(t, relayFixtures(), serverOptions{Now: clock})
	ctx := context.Background()

	report := func(hub string, ids ...string) {
		t.Helper()
		resp, err := m.client.ReportRelayRegistrations(ctx, hub, &control.RelayRegistrationReport{RegisteredProxyIDs: ids})
		if err != nil {
			t.Fatalf("report from %s: %v", hub, err)
		}
		if !resp.Accepted || resp.ReportAfterSeconds != 0 {
			t.Errorf("answered %+v, want accepted and no interval", resp)
		}
	}
	report("proxy-hub", "proxy-zone")
	report("proxy-other")
	now = now.Add(time.Minute)
	report("proxy-hub", "proxy-b", "proxy-zone")

	got := debugRelayRegistrations(t, m)
	if len(got) != 2 {
		t.Fatalf("debug endpoint holds %d hubs, want 2: %+v", len(got), got)
	}
	if hub := got["proxy-hub"]; !slices.Equal(hub.RegisteredProxyIDs, []string{"proxy-b", "proxy-zone"}) || !hub.ReceivedAt.Equal(now) {
		t.Errorf("proxy-hub = %+v, want the replacing set received at %v", hub, now)
	}
	if other := got["proxy-other"]; other.RegisteredProxyIDs == nil || len(other.RegisteredProxyIDs) != 0 {
		t.Errorf("proxy-other = %+v, want an empty set, not an absent one", other)
	}

	resp, err := http.Post(m.srv.URL+pathDebugReset, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := debugRelayRegistrations(t, m); len(got) != 0 {
		t.Errorf("after %s the debug endpoint holds %+v", pathDebugReset, got)
	}
}

func TestRelayRegistrationReportAnswersTheFixtureInterval(t *testing.T) {
	fx := relayFixtures()
	fx.RelayRegistrations.ReportAfterSeconds = 5
	m := startMock(t, fx, serverOptions{})
	resp, err := m.client.ReportRelayRegistrations(context.Background(), "proxy-hub", &control.RelayRegistrationReport{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.ReportAfter() != 5*time.Second {
		t.Errorf("ReportAfter = %v, want 5s", resp.ReportAfter())
	}

	// The real client reads a 404 as a refusal carrying not_enrolled.
	_, err = m.client.ReportRelayRegistrations(context.Background(), "proxy-stranger", &control.RelayRegistrationReport{})
	var apiErr *control.APIError
	if !errors.Is(err, control.ErrBadRequest) || !errors.As(err, &apiErr) || apiErr.Code != "not_enrolled" {
		t.Errorf("an unenrolled hub = %v, want a refusal carrying not_enrolled", err)
	}
}

func TestRelayRegistrationFixtureValidation(t *testing.T) {
	_, err := parseFixtures(strings.NewReader("relay_registrations:\n  report_after_seconds: -1\n"))
	if err == nil || !strings.Contains(err.Error(), "relay_registrations.report_after_seconds must not be negative") {
		t.Errorf("a negative interval = %v, want it refused", err)
	}
	fx := mustParseFixtures(t, "relay_registrations:\n  report_after_seconds: 7\n")
	if fx.RelayRegistrations.ReportAfterSeconds != 7 {
		t.Errorf("report_after_seconds = %d, want 7", fx.RelayRegistrations.ReportAfterSeconds)
	}
}
