// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package channel

import (
	"context"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
)

func execEvent(command string) RequestEvent {
	return RequestEvent{
		Direction: FromClient,
		Type:      control.RequestExec,
		WantReply: true,
		Payload:   ssh.Marshal(struct{ Command string }{command}),
	}
}

// TestATerminatingDecisionIsADenialFirst is the property every existing caller
// depends on: code that asks "may this proceed" must never read a terminate as
// a yes, whatever it does about the session afterwards.
func TestATerminatingDecisionIsADenialFirst(t *testing.T) {
	var seen []string
	reg := NewRegistry()
	reg.Register("session",
		&stub{name: "killer", seen: &seen, request: func(*RequestEvent) Decision {
			return TerminateWithDetail("This session has been terminated by policy.", "rule 0 matched")
		}},
		&stub{name: "after", seen: &seen},
	)

	insp, open := newPipeline(t, sessionPolicy(), reg).Open(context.Background(), OpenEvent{ChannelType: "session"})
	if open.Denied() {
		t.Fatalf("the channel open was refused: %+v", open)
	}

	d := insp.Request(context.Background(), execEvent("rm -rf /"))
	if !d.Terminates() {
		t.Errorf("decision %v does not terminate", d.Action)
	}
	if !d.Denied() {
		t.Error("a terminating decision must also read as a denial")
	}
	if d.By != "killer" {
		t.Errorf("decision attributed to %q, want the inspector that made it", d.By)
	}
	if d.Detail != "rule 0 matched" {
		t.Errorf("operator detail = %q, want it preserved for the audit trail", d.Detail)
	}
	for _, event := range seen {
		if event == "after request:exec" {
			t.Error("the chain kept running after a terminating decision")
		}
	}
}

// TestANoticeSurvivesToTheCaller is the warn-and-continue shape: the event
// proceeds and the user hears about it, which needs the decision to reach the
// transport rather than being flattened into an allow.
func TestANoticeSurvivesToTheCaller(t *testing.T) {
	reg := NewRegistry()
	reg.Register("session",
		&stub{name: "warner", request: func(*RequestEvent) Decision {
			return Warn("Warning: this command is flagged by policy.", "rule 2 matched")
		}},
		&stub{name: "mutator", request: func(ev *RequestEvent) Decision {
			return Mutate(ev.Payload)
		}},
	)

	insp, _ := newPipeline(t, sessionPolicy(), reg).Open(context.Background(), OpenEvent{ChannelType: "session"})
	d := insp.Request(context.Background(), execEvent("sudo reboot"))

	if d.Denied() {
		t.Fatal("a warning refused the request; the command must run")
	}
	if d.Notice != "Warning: this command is flagged by policy." {
		t.Errorf("notice = %q, want it to reach the transport past the mutating inspector", d.Notice)
	}
}

// TestEveryChannelIsNamed covers the id an inspector correlates its own events
// by, and an audit record names the channel with.
func TestEveryChannelIsNamed(t *testing.T) {
	pipe := newPipeline(t, sessionPolicy(), nil)
	ctx := context.Background()

	first, _ := pipe.Open(ctx, OpenEvent{ChannelType: "session"})
	second, _ := pipe.Open(ctx, OpenEvent{ChannelType: "session"})

	if first.Info().ChannelID == "" {
		t.Fatal("a channel was opened without an id")
	}
	if first.Info().ChannelID == second.Info().ChannelID {
		t.Errorf("two channels share the id %q", first.Info().ChannelID)
	}
	for _, id := range []string{first.Info().ChannelID, second.Info().ChannelID} {
		if len(id) <= len("session-1") || id[:len("session-1")] != "session-1" {
			t.Errorf("channel id %q is not scoped to its session", id)
		}
	}
}

// TestCloneLayersWithoutTouchingTheOriginal is the per-session registry: a
// session's own inspectors must not leak into every other session on the proxy.
func TestCloneLayersWithoutTouchingTheOriginal(t *testing.T) {
	base := NewRegistry()
	base.Register("session", &stub{name: "proxy-wide"})

	layered := base.Clone()
	layered.Register("session", &stub{name: "per-session"})

	if got := len(base.Inspectors("session")); got != 1 {
		t.Errorf("the proxy-wide registry now has %d inspectors, want 1", got)
	}
	chain := layered.Inspectors("session")
	if len(chain) != 2 || chain[0].Name() != "proxy-wide" || chain[1].Name() != "per-session" {
		t.Errorf("layered chain = %v, want the proxy-wide inspector first", chain)
	}

	// A nil registry clones to a usable empty one, so a proxy with nothing
	// configured is not a special case.
	var none *Registry
	clone := none.Clone()
	clone.Register("session", &stub{name: "only"})
	if got := len(clone.Inspectors("session")); got != 1 {
		t.Errorf("cloning a nil registry produced %d inspectors, want 1", got)
	}
}
