// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// newTestControl starts an instrumented control server for one test.
func newTestControl(t *testing.T, sc *Scenario) *controlServer {
	t.Helper()
	c := newControlServer(sc, "127.0.0.1", 2222, "tok")
	if err := c.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(c.stop)
	return c
}

func post[T any](t *testing.T, c *controlServer, path string, body any, wantStatus int) T {
	t.Helper()
	blob, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, c.baseURL()+path, bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != wantStatus {
		t.Fatalf("POST %s: status %d, want %d", path, resp.StatusCode, wantStatus)
	}
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return out
}

func TestAuthorizeResponseSatisfiesTheContract(t *testing.T) {
	// The proxy refuses a response it cannot fully understand, so a harness
	// whose decisions do not validate measures denial latency and nothing else.
	sc := decode(t, "name: x\nrun:\n  mode: rate\n  rate: 1\n  duration: 1s\n")
	c := newTestControl(t, sc)
	resp := post[control.AuthorizeResponse](t, c, control.PathAuthorize, control.AuthorizeRequest{
		Identity: &control.Identity{Subject: "svc0@load.invalid", Login: "svc0"},
		Target:   "t0000001.load.invalid",
	}, http.StatusOK)
	if err := resp.Validate(); err != nil {
		t.Fatalf("authorize response does not satisfy the contract: %v", err)
	}
}

func TestLogBatchUsesTheStatusTheClientRequires(t *testing.T) {
	// internal/control/rest.go accepts only 202 here. A 200 would make every
	// batch fail into the proxy's resilience buffer, and "control calls per
	// connection" would silently become a measurement of retry behaviour.
	sc := decode(t, "name: x\nrun:\n  mode: rate\n  rate: 1\n  duration: 1s\n")
	c := newTestControl(t, sc)
	got := post[control.LogBatchResponse](t, c, control.PathIngestLogBatch,
		control.LogBatchRequest{Records: []control.LogRecord{{}, {}}}, http.StatusAccepted)
	if got.Accepted != 2 {
		t.Errorf("accepted = %d, want 2", got.Accepted)
	}
}

func TestCacheKeyScope(t *testing.T) {
	req := func(target string) *control.AuthorizeRequest {
		return &control.AuthorizeRequest{
			Identity: &control.Identity{Subject: "svc0@load.invalid"},
			Target:   target,
		}
	}
	perTarget := newControlServer(decode(t, "name: x\nrun:\n  mode: rate\n  rate: 1\n  duration: 1s\ncontrol:\n  cache_hint: true\n  cache_ttl: 60s\n  cache_scope: per-target\n"), "h", 22, "")
	if a, b := perTarget.cacheKey(req("a")), perTarget.cacheKey(req("b")); a == b {
		t.Errorf("per-target scope issued one key %q for two targets", a)
	}
	perSubject := newControlServer(decode(t, "name: x\nrun:\n  mode: rate\n  rate: 1\n  duration: 1s\ncontrol:\n  cache_hint: true\n  cache_ttl: 60s\n  cache_scope: per-subject\n"), "h", 22, "")
	if a, b := perSubject.cacheKey(req("a")), perSubject.cacheKey(req("b")); a != b {
		t.Errorf("per-subject scope issued %q and %q for two targets of one subject", a, b)
	}
}

func TestControlCountsAndResets(t *testing.T) {
	sc := decode(t, "name: x\nrun:\n  mode: rate\n  rate: 1\n  duration: 1s\n")
	c := newTestControl(t, sc)
	for range 3 {
		post[control.AuthorizeResponse](t, c, control.PathAuthorize, control.AuthorizeRequest{
			Identity: &control.Identity{Subject: "s"}, Target: "t",
		}, http.StatusOK)
	}
	if got := c.count(control.PathAuthorize); got != 3 {
		t.Fatalf("authorize count = %d, want 3", got)
	}
	snap := c.snapshot(3)
	if len(snap) != 1 || snap[0].PerConn != 1 {
		t.Fatalf("snapshot = %+v, want one endpoint at 1.000/conn", snap)
	}
	// reset is what makes the reported rate a steady-state number rather than
	// one that includes the warmup.
	c.reset()
	if got := c.count(control.PathAuthorize); got != 0 {
		t.Errorf("authorize count after reset = %d, want 0", got)
	}
}

func TestInjectedLatencyIsCharged(t *testing.T) {
	sc := decode(t, "name: x\nrun:\n  mode: rate\n  rate: 1\n  duration: 1s\ncontrol:\n  latency: 30ms\n")
	c := newTestControl(t, sc)
	start := time.Now()
	post[control.AuthenticateResponse](t, c, control.PathAuthenticateCert,
		control.AuthenticateCertRequest{Login: "svc0"}, http.StatusOK)
	if elapsed := time.Since(start); elapsed < 25*time.Millisecond {
		t.Errorf("call took %s, want at least the injected 30ms", elapsed)
	}
}

func TestUnauthorizedWithoutTheToken(t *testing.T) {
	sc := decode(t, "name: x\nrun:\n  mode: rate\n  rate: 1\n  duration: 1s\n")
	c := newTestControl(t, sc)
	resp, err := http.Post(c.baseURL()+control.PathAuthorize, "application/json", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}
