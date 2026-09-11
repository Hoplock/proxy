// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
	"strings"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// grantWindow is a fixed window, so the assertions below are on the exact text
// an auditor would read rather than on "something that parses".
var (
	grantStart = time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	grantEnd   = time.Date(2026, 3, 1, 17, 0, 0, 0, time.UTC)
)

// TestGrantContextReachesEveryRecordOfTheSession is D16's carriage rule: the
// grant context is copied onto the session's records, so a security team asking
// "what did the change ticket that authorised this actually let them do" reads
// one session's records and finds the ticket on all of them.
func TestGrantContextReachesEveryRecordOfTheSession(t *testing.T) {
	shipper, server := newTestShipper(t, func(o *Options) { o.BatchSize = 1000 })
	rec := shipper.Session(SessionInfo{SessionID: "sess-1", ProxyID: "proxy-1"})

	// Before the decision exists there is nothing to carry, which is why the
	// start record is made first here: it is the one record that legitimately
	// carries less.
	rec.Start(nil)
	rec.SetGrant(GrantFrom(&control.AuthorizeResponse{GrantContext: &control.GrantContext{
		System:      "change-management",
		Reference:   "CHG-1234",
		WindowStart: &grantStart,
		WindowEnd:   &grantEnd,
		Additional:  &control.AdditionalContext{Text: "approved by the Tuesday CAB"},
	}}))
	rec.Authorize("authorized", nil)
	rec.Request("request exec", Attrs{}.Set(AttrCommand, "uptime"))
	rec.Denied("request refused", nil)
	rec.End(nil)
	flush(t, shipper)

	for _, r := range server.delivered() {
		if r.Kind == control.LogKindSessionStart {
			if _, ok := r.Attributes[AttrGrantSystem]; ok {
				t.Errorf("the start record carries a grant context the session did not have yet: %v", r.Attributes)
			}
			continue
		}
		for key, want := range map[string]string{
			AttrGrantSystem:      "change-management",
			AttrGrantReference:   "CHG-1234",
			AttrGrantWindowStart: "2026-03-01T09:00:00Z",
			AttrGrantWindowEnd:   "2026-03-01T17:00:00Z",
			AttrGrantAdditional:  "approved by the Tuesday CAB",
		} {
			if got := r.Attributes[key]; got != want {
				t.Errorf("%s record carries %s=%q, want %q", r.Kind, key, got, want)
			}
		}
	}
	// Including the critical one: a refusal takes the priority path, and it must
	// not be the one record that arrives without the context of the grant it was
	// refused under (D8).
	prio := server.priorityRecords()
	if len(prio) != 1 {
		t.Fatalf("delivered %d priority records, want 1", len(prio))
	}
	if prio[0].Attributes[AttrGrantReference] != "CHG-1234" {
		t.Errorf("the critical record carries no grant reference: %v", prio[0].Attributes)
	}
}

// TestAdditionalContextObjectFormIsNotStringified is the half of the rule that
// is easy to get wrong: additional_context is a string OR an object, and the
// object's fields reach the record as fields.
//
// One attribute per field is what makes "every session CHG-1234 authorised" a
// query rather than a substring search, and it is also the only rendering that
// does not put words in the asserting system's mouth — which is the same reason
// control.AdditionalContext refuses to coerce a shape on the way in.
func TestAdditionalContextObjectFormIsNotStringified(t *testing.T) {
	grant := GrantFrom(&control.AuthorizeResponse{GrantContext: &control.GrantContext{
		System: "scanner",
		Additional: &control.AdditionalContext{Fields: map[string]any{
			"scan_id":  "s-99",
			"severity": float64(7),
			"authenticated": map[string]any{
				"by": "nessus",
			},
		}},
	}})
	attrs := grant.stamp(Attrs{})

	for key, want := range map[string]string{
		AttrGrantAdditionalPrefix + "scan_id":       "s-99",
		AttrGrantAdditionalPrefix + "severity":      "7",
		AttrGrantAdditionalPrefix + "authenticated": `{"by":"nessus"}`,
	} {
		if got := attrs[key]; got != want {
			t.Errorf("attribute %s is %q, want %q", key, got, want)
		}
	}
	// The object form must not also arrive as the string form: a reader that
	// found both would have to decide which one the server actually sent.
	if got, ok := attrs[AttrGrantAdditional]; ok {
		t.Errorf("the object form was also stringified into %s=%q", AttrGrantAdditional, got)
	}
	for key := range attrs {
		if strings.Contains(key, "severity") && strings.Contains(attrs[key], "e+") {
			t.Errorf("%s=%q renders a JSON number as Go would print a float", key, attrs[key])
		}
	}
}

// TestAGrantContextWithNothingInItIsNoGrantContext keeps the absent-value
// default honest: a response that carries an empty object leaves the session's
// records exactly as a response with no grant context at all would.
func TestAGrantContextWithNothingInItIsNoGrantContext(t *testing.T) {
	for name, resp := range map[string]*control.AuthorizeResponse{
		"no response":     nil,
		"no grant":        {},
		"an empty grant":  {GrantContext: &control.GrantContext{}},
		"an empty object": {GrantContext: &control.GrantContext{Additional: &control.AdditionalContext{Fields: map[string]any{}}}},
	} {
		if g := GrantFrom(resp); g != nil {
			t.Errorf("%s produced a grant context: %+v", name, g)
		}
	}
}

// TestDeliverableIsTheCaptureBoundsPredicate states what
// require_session_capture actually turns on (D16, PLAN §6.5): a disk buffer is a
// logging path, and a proxy with no pipeline at all is not.
func TestDeliverableIsTheCaptureBoundsPredicate(t *testing.T) {
	var none *SessionRecorder
	if none.Deliverable() {
		t.Error("a nil recorder reports a logging path; a proxy without a pipeline has none")
	}

	buffered, _ := newTestShipper(t, nil)
	if rec := buffered.Session(SessionInfo{SessionID: "sess-1"}); !rec.Deliverable() {
		t.Error("a recorder with a disk buffer reports no logging path; the buffer IS one (PLAN §7)")
	}
}
