// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package channel

import (
	"context"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
)

// stub is a test inspector. Each field it is given turns on one capability, so
// one type covers the allow, deny, mutate, flag, and stream cases without five
// near-identical declarations.
type stub struct {
	name    string
	open    func(*OpenEvent) Decision
	request func(*RequestEvent) Decision
	stream  func(*StreamEvent) io.Reader
	// seen records every event this inspector was shown, in order.
	seen *[]string
}

func (s *stub) Name() string { return s.name }

func (s *stub) InspectOpen(_ context.Context, ev *OpenEvent) Decision {
	s.note("open:" + ev.ChannelType)
	if s.open == nil {
		return Allow()
	}
	return s.open(ev)
}

func (s *stub) InspectRequest(_ context.Context, ev *RequestEvent) Decision {
	s.note("request:" + ev.Type)
	if s.request == nil {
		return Allow()
	}
	return s.request(ev)
}

func (s *stub) InspectStream(_ context.Context, ev *StreamEvent) io.Reader {
	s.note("stream:" + ev.Direction.String())
	if s.stream == nil {
		return nil
	}
	return s.stream(ev)
}

func (s *stub) note(what string) {
	if s.seen != nil {
		*s.seen = append(*s.seen, s.name+" "+what)
	}
}

// sessionPolicy permits a session channel and every request on it, so a test
// about inspectors is not also a test about policy.
func sessionPolicy() testPolicy { return testPolicy{channels: []string{"session", "x11"}} }

// TestAllowInspectorLetsTheChannelThrough is the baseline: an inspector that
// answers Allow changes nothing.
func TestAllowInspectorLetsTheChannelThrough(t *testing.T) {
	var seen []string
	reg := NewRegistry()
	reg.Register("session", &stub{name: "allow", seen: &seen})
	p := newPipeline(t, sessionPolicy(), reg)

	insp, decision := p.Open(context.Background(), OpenEvent{ChannelType: "session", Direction: FromClient})
	if decision.Denied() {
		t.Fatalf("an allowing inspector denied the channel: %q", decision.Reason)
	}
	if d := insp.Request(context.Background(), RequestEvent{Type: control.RequestShell}); d.Denied() {
		t.Fatal("an allowing inspector denied the request")
	}
	want := []string{"allow open:session", "allow request:shell"}
	if strings.Join(seen, "|") != strings.Join(want, "|") {
		t.Errorf("inspector saw %v, want %v", seen, want)
	}
}

// TestDenyInspectorRefusesAndStopsTheChain proves the two halves of a denial:
// the channel is refused with the inspector's own clause, and nothing after it
// in the chain gets a say.
func TestDenyInspectorRefusesAndStopsTheChain(t *testing.T) {
	var seen []string
	reg := NewRegistry()
	reg.Register("session",
		&stub{name: "deny", seen: &seen, open: func(*OpenEvent) Decision {
			return DenyWithDetail("Not on this session.", "the operator's reason")
		}},
		&stub{name: "after", seen: &seen},
	)
	p := newPipeline(t, sessionPolicy(), reg)

	insp, decision := p.Open(context.Background(), OpenEvent{ChannelType: "session", Direction: FromClient})
	if !decision.Denied() {
		t.Fatal("the denying inspector was ignored")
	}
	if insp != nil {
		t.Error("a denied open returned an inspection")
	}
	if got, want := decision.Reason, "Not on this session."; got != want {
		t.Errorf("reason = %q, want %q", got, want)
	}
	if got, want := decision.By, "deny"; got != want {
		t.Errorf("decision.By = %q, want %q", got, want)
	}
	if len(seen) != 1 || seen[0] != "deny open:session" {
		t.Errorf("chain saw %v; a decision already made must not be reconsidered", seen)
	}
}

// TestDenyInspectorRefusesARequest is the same on the axis 0010 attaches to.
func TestDenyInspectorRefusesARequest(t *testing.T) {
	reg := NewRegistry()
	reg.Register("session", &stub{name: "filter", request: func(ev *RequestEvent) Decision {
		if ev.Command == "rm -rf /" {
			return Deny("That command is blocked.")
		}
		return Allow()
	}})
	p := newPipeline(t, sessionPolicy(), reg)
	insp, _ := p.Open(context.Background(), OpenEvent{ChannelType: "session", Direction: FromClient})

	// The command reaches the inspector already parsed: that is the seam 0010
	// attaches to, and it must not have to unmarshal the payload again.
	blocked := insp.Request(context.Background(), RequestEvent{
		Type:    control.RequestExec,
		Payload: ssh.Marshal(struct{ Command string }{"rm -rf /"}),
	})
	if !blocked.Denied() {
		t.Fatal("the filter's denial was ignored")
	}
	allowed := insp.Request(context.Background(), RequestEvent{
		Type:    control.RequestExec,
		Payload: ssh.Marshal(struct{ Command string }{"uptime"}),
	})
	if allowed.Denied() {
		t.Fatalf("an unmatched command was denied: %q", allowed.Reason)
	}
}

// TestMutatingInspectorRewritesThePayloadForTheRest proves a chain is a
// pipeline: what the second inspector sees is what the first produced.
func TestMutatingInspectorRewritesThePayloadForTheRest(t *testing.T) {
	var got string
	reg := NewRegistry()
	reg.Register("session",
		&stub{name: "rewrite", open: func(*OpenEvent) Decision { return Mutate([]byte("rewritten")) }},
		&stub{name: "observe", open: func(ev *OpenEvent) Decision {
			got = string(ev.Payload)
			return Allow()
		}},
	)
	p := newPipeline(t, sessionPolicy(), reg)

	_, decision := p.Open(context.Background(), OpenEvent{
		ChannelType: "session",
		Direction:   FromClient,
		Payload:     []byte("original"),
	})
	if got != "rewritten" {
		t.Errorf("the second inspector saw %q, want %q", got, "rewritten")
	}
	if string(decision.PayloadOr([]byte("original"))) != "rewritten" {
		t.Error("the caller was handed the original payload; a mutation nobody applies is not a mutation")
	}
}

// TestFlagLetsTheEventThroughAndIsRecorded covers the action that exists so an
// inspector can say "someone should know" without ending a session.
func TestFlagLetsTheEventThroughAndIsRecorded(t *testing.T) {
	var logged []string
	p, err := New(Options{
		Policy: sessionPolicy(),
		Inspectors: func() *Registry {
			reg := NewRegistry()
			reg.Register("session", &stub{name: "watch", open: func(*OpenEvent) Decision {
				return Flag("someone opened a session")
			}})
			return reg
		}(),
		SessionID: "session-1",
		Logf:      func(format string, args ...any) { logged = append(logged, format) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, decision := p.Open(context.Background(), OpenEvent{ChannelType: "session", Direction: FromClient}); decision.Denied() {
		t.Fatal("a flag denied the channel")
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "flagged") {
		t.Errorf("log lines = %v, want one flag", logged)
	}
}

// TestAncillaryDenialIsDowngraded holds the line PLAN §6.2 draws: a resize is
// always relayed, so an inspector may watch one but may not veto it.
func TestAncillaryDenialIsDowngraded(t *testing.T) {
	reg := NewRegistry()
	reg.Register("session", &stub{name: "overreach", request: func(*RequestEvent) Decision {
		return Deny("No resizing.")
	}})
	p := newPipeline(t, sessionPolicy(), reg)
	insp, _ := p.Open(context.Background(), OpenEvent{ChannelType: "session", Direction: FromClient})

	if d := insp.Request(context.Background(), RequestEvent{Type: "window-change"}); d.Denied() {
		t.Error("an inspector vetoed a terminal resize; ancillary requests are always relayed")
	}
	if d := insp.Request(context.Background(), RequestEvent{Type: control.RequestShell}); !d.Denied() {
		t.Error("the same inspector was ignored on a request that does carry policy")
	}
}

// TestPassthroughReaderIsTheSourceItself is the performance contract stated as
// an identity: with no stream inspector, the pump copies from the very reader
// it was given.
func TestPassthroughReaderIsTheSourceItself(t *testing.T) {
	p := newPipeline(t, sessionPolicy(), NewRegistry())
	insp, _ := p.Open(context.Background(), OpenEvent{ChannelType: "session", Direction: FromClient})
	if insp.Inspected() {
		t.Error("a channel with no inspectors reports itself inspected")
	}

	src := strings.NewReader("payload")
	if got := insp.Reader(context.Background(), FromClient, false, src); got != io.Reader(src) {
		t.Errorf("Reader returned %T, want the source itself", got)
	}
	// A nil inspection is the same: a caller that never opened a channel
	// through the pipeline is not a special case.
	var none *Inspection
	if got := none.Reader(context.Background(), FromClient, false, src); got != io.Reader(src) {
		t.Errorf("a nil inspection wrapped the stream")
	}
	if none.Request(context.Background(), RequestEvent{Type: control.RequestShell}).Denied() {
		t.Error("a nil inspection denied a request")
	}
}

// TestStreamInspectorsWrapEachDirectionInOrder covers the other half: when
// inspectors are registered, every direction goes through them, in order.
func TestStreamInspectorsWrapEachDirectionInOrder(t *testing.T) {
	var seen []string
	reg := NewRegistry()
	reg.Register("session",
		&stub{name: "upper", seen: &seen, stream: func(ev *StreamEvent) io.Reader {
			return &mapReader{src: ev.Source, fn: strings.ToUpper}
		}},
		&stub{name: "suffix", seen: &seen, stream: func(ev *StreamEvent) io.Reader {
			return &mapReader{src: ev.Source, fn: func(s string) string { return s + "!" }}
		}},
	)
	p := newPipeline(t, sessionPolicy(), reg)
	insp, _ := p.Open(context.Background(), OpenEvent{ChannelType: "session", Direction: FromClient})
	if !insp.Inspected() {
		t.Error("a channel with inspectors reports itself un-inspected")
	}

	r := insp.Reader(context.Background(), FromClient, false, strings.NewReader("hi"))
	if got, want := readAll(t, r), "HI!"; got != want {
		t.Errorf("stream = %q, want %q — the wrappers did not compose in order", got, want)
	}
	if got := readAll(t, insp.Reader(context.Background(), FromTarget, true, strings.NewReader("er"))); got != "ER!" {
		t.Errorf("stderr stream = %q, want %q", got, "ER!")
	}
	want := []string{
		"upper open:session", "suffix open:session",
		"upper stream:client", "suffix stream:client",
		"upper stream:target", "suffix stream:target",
	}
	if strings.Join(seen, "|") != strings.Join(want, "|") {
		t.Errorf("inspectors saw %v, want %v", seen, want)
	}
}

// TestOnlyTheCapabilitiesAnInspectorImplementsAreUsed is why the interface is a
// small set rather than one wide one: an inspector that only decides requests
// must not force a channel onto the wrapped-stream path.
func TestOnlyTheCapabilitiesAnInspectorImplementsAreUsed(t *testing.T) {
	reg := NewRegistry()
	reg.Register("session", requestOnly{})
	p := newPipeline(t, sessionPolicy(), reg)
	insp, _ := p.Open(context.Background(), OpenEvent{ChannelType: "session", Direction: FromClient})

	src := strings.NewReader("payload")
	if got := insp.Reader(context.Background(), FromClient, false, src); got != io.Reader(src) {
		t.Error("a request-only inspector put the byte stream on the wrapped path")
	}
	if !insp.Request(context.Background(), RequestEvent{Type: control.RequestShell}).Denied() {
		t.Error("the request-only inspector was not consulted")
	}
}

// requestOnly implements RequestInspector and nothing else.
type requestOnly struct{}

func (requestOnly) Name() string { return "request-only" }

func (requestOnly) InspectRequest(context.Context, *RequestEvent) Decision {
	return Deny("No.")
}

// mapReader applies fn to everything it reads. It is a transforming wrapper,
// which is the shape a mutating stream inspector returns.
type mapReader struct {
	src  io.Reader
	fn   func(string) string
	rest string
	done bool
}

func (m *mapReader) Read(p []byte) (int, error) {
	if !m.done {
		buf, err := io.ReadAll(m.src)
		if err != nil {
			return 0, err
		}
		m.rest = m.fn(string(buf))
		m.done = true
	}
	if m.rest == "" {
		return 0, io.EOF
	}
	n := copy(p, m.rest)
	m.rest = m.rest[n:]
	return n, nil
}
