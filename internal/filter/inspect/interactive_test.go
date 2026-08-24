// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package inspect

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/channel"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/filter"
)

// interactiveChannel is a session channel that has been turned interactive.
var interactiveChannelInfo = channel.Info{
	SessionID: "sess-1",
	ChannelID: "sess-1/1",
	Type:      SessionChannel,
}

func newInteractive(t *testing.T, audit filter.Sink) *Interactive {
	t.Helper()
	return NewInteractive(Options{
		Engine: mustEngine(t, control.FilterPolicy{
			Mode: control.FilterModeBlacklist,
			Rules: []control.FilterRule{
				{Match: "rm -rf /*", Action: control.FilterActionKillSession},
				{Match: "sudo *", Action: control.FilterActionWarnAndContinue},
			},
		}),
		Audit: audit,
		Now:   func() time.Time { return time.Unix(1, 0).UTC() },
	})
}

// keystrokes runs a stream through the inspector and returns what the target
// received.
func keystrokes(t *testing.T, insp *Interactive, shell bool, input string) string {
	t.Helper()
	ctx := context.Background()
	if shell {
		insp.InspectRequest(ctx, &channel.RequestEvent{
			Channel:   interactiveChannelInfo,
			Direction: channel.FromClient,
			Type:      control.RequestShell,
		})
	}
	reader := insp.InspectStream(ctx, &channel.StreamEvent{
		Channel:   interactiveChannelInfo,
		Direction: channel.FromClient,
		Source:    strings.NewReader(input),
	})
	var got bytes.Buffer
	if _, err := io.Copy(&got, reader); err != nil {
		t.Fatalf("copy: %v", err)
	}
	return got.String()
}

// TestInspectionDoesNotAlterTheStream is the promise that makes best-effort
// inspection acceptable on an interactive channel at all: every byte the client
// sent reaches the target unchanged, including the control bytes the scanner
// reads for its own purposes.
func TestInspectionDoesNotAlterTheStream(t *testing.T) {
	audit := &recorder{}
	insp := newInteractive(t, audit)

	input := "sudo systemctl restart nginx\r" + // a match
		"ls -l\ttab\x1b[Dleft\x7f\x08\r\n" + // completion, cursor keys, editing
		"héllo wörld\n" + // multi-byte
		"\x03\x15" + // ^C, ^U
		"rm -rf /var\r"
	if got := keystrokes(t, insp, true, input); got != input {
		t.Errorf("the target received %q, want the stream unchanged (%q)", got, input)
	}
	if len(audit.events) == 0 {
		t.Fatal("an interactive session produced no audit events at all")
	}
	for _, ev := range audit.events {
		if ev.Enforced {
			t.Errorf("event %+v claims enforcement on the interactive tier", ev)
		}
		if ev.Tier != filter.TierInteractive || ev.Guarantee != filter.GuaranteeAuditSignal {
			t.Errorf("event %+v, want the interactive tier and its guarantee", ev)
		}
		if ev.Outcome != filter.OutcomeObserved {
			t.Errorf("outcome = %q, want %q", ev.Outcome, filter.OutcomeObserved)
		}
		if ev.Request != control.RequestShell || ev.ChannelID != interactiveChannelInfo.ChannelID {
			t.Errorf("event %+v, want the channel context filled in", ev)
		}
	}
}

// TestLinesAreReassembledFromKeystrokes covers the heuristics themselves: what
// the scanner is expected to catch, and — just as important — what it is
// documented not to.
func TestLinesAreReassembledFromKeystrokes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		input   string
		command string // the command the audit event should name, "" for none
	}{
		{"a plain line", "rm -rf /data\r", "rm -rf /data"},
		{"a line ended with LF", "rm -rf /data\n", "rm -rf /data"},
		{"typed across reads", "rm -rf /da" + "ta\r", "rm -rf /data"},
		{"a corrected typo", "rm -rf /datax\x7f\r", "rm -rf /data"},
		{"a cursor key in the middle", "rm -rf \x1b[C/data\r", "rm -rf /data"},
		{"a killed line", "rm -rf /data\x15uptime\r", ""},
		{"an abandoned line", "rm -rf /data\x03\r", ""},
		{"an unfinished line", "rm -rf /data", ""},
		{"a line nothing matches", "uptime\r", ""},
		{"an over-long line", strings.Repeat("a", maxInteractiveLine+1) + " rm -rf /data\r", ""},
	} {
		audit := &recorder{}
		insp := newInteractive(t, audit)
		keystrokes(t, insp, true, tc.input)
		switch {
		case tc.command == "" && len(audit.events) > 0:
			t.Errorf("%s: recorded %q, want nothing", tc.name, audit.events[0].Command)
		case tc.command == "":
		case len(audit.events) == 0:
			t.Errorf("%s: recorded nothing, want %q", tc.name, tc.command)
		case audit.events[0].Command != tc.command:
			t.Errorf("%s: recorded %q, want %q", tc.name, audit.events[0].Command, tc.command)
		}
	}
}

// TestAnExecChannelsStdinIsNotReadAsCommands is why the inspector waits for the
// request that makes a channel interactive: a piped file is not a keystroke
// stream, and reporting its lines as commands would fill a security feed with
// the contents of everything anyone ever uploaded.
func TestAnExecChannelsStdinIsNotReadAsCommands(t *testing.T) {
	audit := &recorder{}
	insp := newInteractive(t, audit)
	if got := keystrokes(t, insp, false, "rm -rf /data\nsudo everything\n"); got == "" {
		t.Fatal("the stream was swallowed")
	}
	if len(audit.events) != 0 {
		t.Errorf("recorded %d events from an exec channel's stdin", len(audit.events))
	}
}

// TestTheTargetsOutputIsNeverScanned keeps the inspector on the client's half
// of the channel: a log line the target printed is not a command the user ran.
func TestTheTargetsOutputIsNeverScanned(t *testing.T) {
	audit := &recorder{}
	insp := newInteractive(t, audit)
	ctx := context.Background()
	insp.InspectRequest(ctx, &channel.RequestEvent{
		Channel:   interactiveChannelInfo,
		Direction: channel.FromClient,
		Type:      control.RequestShell,
	})

	source := strings.NewReader("rm -rf /data\r")
	for _, ev := range []*channel.StreamEvent{
		{Channel: interactiveChannelInfo, Direction: channel.FromTarget, Source: source},
		{Channel: interactiveChannelInfo, Direction: channel.FromClient, Stderr: true, Source: source},
	} {
		if got := insp.InspectStream(ctx, ev); got != io.Reader(source) {
			t.Error("a stream that carries no commands was wrapped")
		}
	}
	if len(audit.events) != 0 {
		t.Errorf("recorded %d events from a stream that is not the user's keystrokes", len(audit.events))
	}
}
