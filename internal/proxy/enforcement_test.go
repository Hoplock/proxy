// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"strings"
	"testing"

	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/logging"
)

// Phase 0019's engine half: the record says which rung the session actually
// stood on, and a proxy-side rung is checked against this session's own policy
// before the target leg is dialled.

// enforcedHarness is a proxy whose every route carries one enforcement choice.
//
// The authorize closure reads the harness's target lazily, because a custom
// authorize replaces the WHOLE response — including the host and port the
// harness's own default fills in — and it is called at dial time, by which
// point the harness exists.
func enforcedHarness(t *testing.T, e *control.EnforcementPolicy, requests *control.RequestPolicy) *harness {
	t.Helper()
	var h *harness
	h = newHarness(t, harnessOptions{
		authorize: func(req *control.AuthorizeRequest) (*control.AuthorizeResponse, error) {
			host, port := h.targetHostPort()
			return &control.AuthorizeResponse{
				RouteType:         control.RouteTypeDirect,
				Target:            host,
				TargetPort:        port,
				PermittedChannels: []string{"session"},
				PermittedRequests: requests,
				// An empty blacklist filters nothing, which keeps these tests
				// about the enforcement axis and nothing else.
				FilterPolicy: control.FilterPolicy{Mode: control.FilterModeBlacklist},
				Enforcement:  e,
			}, nil
		},
	})
	return h
}

// TestTheRecordNamesTheRungInForceOnEachAxis. The default route stands on the
// two proxy-side rungs, and the record says so rather than saying nothing: a
// reviewer asking what bounded a session must not have to infer it from an
// absent field.
func TestTheRecordNamesTheRungInForceOnEachAxis(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	client := h.mustDial(h.username())
	defer func() { _ = client.Close() }()
	h.flushRecords()

	rec, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Attributes[logging.AttrEvent] == "enforcement.applied"
	})
	if !ok {
		t.Fatal("no enforcement record was written for the session")
	}
	if got := rec.Attributes[logging.AttrEnforcementExecution]; got != string(control.ExecutionProxyInspected) {
		t.Errorf("execution rung = %q, want the absent-value default", got)
	}
	if got := rec.Attributes[logging.AttrEnforcementReach]; got != string(control.ReachProxyChannelPolicy) {
		t.Errorf("reach rung = %q, want the absent-value default", got)
	}
	if got := rec.Attributes[logging.AttrEnforcementVerified]; got != "true" {
		t.Errorf("verified = %q, want true for a rung this proxy provides itself", got)
	}
}

// TestAnAttestedRungIsRecordedAsUnverified. An unverified claim in an audit
// record is a liability unless the record says it is one.
func TestAnAttestedRungIsRecordedAsUnverified(t *testing.T) {
	h := enforcedHarness(t, &control.EnforcementPolicy{
		Execution: control.ExecutionPlatformAttested,
		Reach:     control.ReachPlatformAttested,
		Attestation: &control.Attestation{
			AssertedBy: "network-engineering",
			Reference:  "baseline/edge@v3",
		},
	}, nil)
	client := h.mustDial(h.username())
	defer func() { _ = client.Close() }()
	h.flushRecords()

	rec, ok := h.awaitRecord(func(r control.LogRecord) bool {
		return r.Attributes[logging.AttrEvent] == "enforcement.applied"
	})
	if !ok {
		t.Fatal("no enforcement record was written for the session")
	}
	switch {
	case rec.Attributes[logging.AttrEnforcementExecution] != string(control.ExecutionPlatformAttested):
		t.Errorf("execution rung = %q, want the attested rung rather than \"none\"",
			rec.Attributes[logging.AttrEnforcementExecution])
	case rec.Attributes[logging.AttrEnforcementVerified] != "false":
		t.Error("an attested rung must be recorded as unverified")
	case rec.Attributes[logging.AttrEnforcementAttestedBy] != "network-engineering":
		t.Errorf("attested_by = %q, want the route's attestation",
			rec.Attributes[logging.AttrEnforcementAttestedBy])
	case rec.Attributes[logging.AttrEnforcementAttestation] != "baseline/edge@v3":
		t.Errorf("attestation = %q, want where the claim is written down",
			rec.Attributes[logging.AttrEnforcementAttestation])
	}
	if !strings.Contains(rec.Message, "attested") {
		t.Errorf("message = %q, want it to say the claim was not verified here", rec.Message)
	}
}

// TestNoInteractiveShellIsCheckedAgainstThisSessionsPolicy.
//
// The contract refuses a response naming the rung while permitting shell or
// pty-req, so this catches the shape the contract cannot: a locally configured
// route, or a server that got it wrong. It is an OUTAGE, not a denial, and the
// session never reaches the target.
func TestNoInteractiveShellIsCheckedAgainstThisSessionsPolicy(t *testing.T) {
	for _, tc := range []struct {
		name     string
		requests *control.RequestPolicy
	}{
		{"no request policy at all", nil},
		{"a policy that still permits a shell", &control.RequestPolicy{Types: []string{"shell", "exec"}}},
		{"a policy that still permits a terminal", &control.RequestPolicy{Types: []string{"exec", "pty-req"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := enforcedHarness(t, &control.EnforcementPolicy{
				Execution: control.ExecutionNoInteractiveShell,
			}, tc.requests)
			text, _ := runAndCollect(t, h, "uptime")
			// An OUTAGE and not a denial: the estate is misconfigured, the
			// user did nothing wrong, and PLAN §4.3 gives them the session id
			// to quote.
			if !strings.Contains(text, testSessionID) {
				t.Errorf("user saw %q, want an outage naming the session id", text)
			}
			if strings.Contains(text, "access denied") {
				t.Errorf("user saw %q, want an outage rather than a denial", text)
			}
		})
	}

	t.Run("a policy that actually denies both is served", func(t *testing.T) {
		h := enforcedHarness(t, &control.EnforcementPolicy{
			Execution: control.ExecutionNoInteractiveShell,
		}, &control.RequestPolicy{Types: []string{"exec"}})
		if text, _ := runAndCollect(t, h, "uptime"); strings.Contains(text, testSessionID) {
			t.Errorf("user saw %q, want the session served", text)
		}
	})
}
