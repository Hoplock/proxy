// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
	"bytes"
	"context"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/hoplock/proxy/internal/channel"
	"github.com/hoplock/proxy/internal/control"
)

// captureThrough runs data through the capture reader and returns what the far
// side received, plus the stream records that were produced.
func captureThrough(t *testing.T, shipper *Shipper, server *fakeControl, ev *channel.StreamEvent) (string, []control.LogRecord) {
	t.Helper()
	rec := shipper.Session(SessionInfo{SessionID: "sess-1"})
	reader := NewStreamCapture(rec).InspectStream(context.Background(), ev)
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read through the capture: %v", err)
	}
	flush(t, shipper)

	var streams []control.LogRecord
	for _, r := range server.delivered() {
		if r.Kind == control.LogKindStream {
			streams = append(streams, r)
		}
	}
	return string(out), streams
}

// TestCaptureChangesNothingOnTheWire is the rule that makes the audit trail and
// the session the same thing: the recorder observes, and a byte it saw is the
// byte the far side got.
func TestCaptureChangesNothingOnTheWire(t *testing.T) {
	shipper, server := newTestShipper(t, func(o *Options) { o.BatchSize = 1000 })
	const data = "the quick brown fox\r\n\x1b[0m\x00\xff"

	got, streams := captureThrough(t, shipper, server, &channel.StreamEvent{
		Channel:   channel.Info{SessionID: "sess-1", ChannelID: "ch-1", Type: "session"},
		Direction: channel.FromTarget,
		Source:    strings.NewReader(data),
	})

	if got != data {
		t.Errorf("the far side received %q, want %q", got, data)
	}
	if len(streams) == 0 {
		t.Fatal("nothing was captured")
	}
	var captured bytes.Buffer
	for _, r := range streams {
		captured.Write(r.Payload)
	}
	if captured.String() != data {
		t.Errorf("captured %q, want %q", captured.String(), data)
	}
}

// TestALargeReadIsSplitAcrossRecordsInOrder is what the capture format promises
// a replay tool: concatenate one direction's chunks in sequence order and you
// have the stream back.
func TestALargeReadIsSplitAcrossRecordsInOrder(t *testing.T) {
	shipper, server := newTestShipper(t, func(o *Options) {
		o.BatchSize = 1000
		o.MaxPayloadBytes = 8
	})
	data := strings.Repeat("abcdefgh", 5) // exactly five records

	got, streams := captureThrough(t, shipper, server, &channel.StreamEvent{
		Channel:   channel.Info{SessionID: "sess-1", ChannelID: "ch-1", Type: "session"},
		Direction: channel.FromTarget,
		Source:    strings.NewReader(data),
	})

	if got != data {
		t.Errorf("the far side received %q, want the data unchanged", got)
	}
	if len(streams) != 5 {
		t.Fatalf("captured %d records, want 5 at 8 bytes each", len(streams))
	}
	var rebuilt bytes.Buffer
	for i, r := range streams {
		if len(r.Payload) > 8 {
			t.Errorf("record %d carries %d bytes, over the cap", i, len(r.Payload))
		}
		if got, want := r.Attributes[AttrSequence], strconv.Itoa(i); got != want {
			t.Errorf("record %d has seq %q, want %q", i, got, want)
		}
		if r.Attributes[AttrCaptureFormat] != CaptureFormatRawChunk {
			t.Errorf("record %d does not say how to read its payload", i)
		}
		rebuilt.Write(r.Payload)
	}
	if rebuilt.String() != data {
		t.Errorf("the chunks rebuild to %q, want %q", rebuilt.String(), data)
	}
}

// TestCaptureNamesTheStreamItCameFrom keeps the three streams of a channel
// apart, which is what a replay needs to show what the user typed separately
// from what the target printed.
func TestCaptureNamesTheStreamItCameFrom(t *testing.T) {
	tests := []struct {
		name      string
		direction channel.Direction
		stderr    bool
		want      string
	}{
		{"client input", channel.FromClient, false, "stdin"},
		{"target output", channel.FromTarget, false, "stdout"},
		{"target stderr", channel.FromTarget, true, "stderr"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shipper, server := newTestShipper(t, func(o *Options) { o.BatchSize = 1000 })
			_, streams := captureThrough(t, shipper, server, &channel.StreamEvent{
				Channel:   channel.Info{SessionID: "sess-1", ChannelID: "ch-1", Type: "session"},
				Direction: tt.direction,
				Stderr:    tt.stderr,
				Source:    strings.NewReader("data"),
			})
			if len(streams) != 1 {
				t.Fatalf("captured %d records, want 1", len(streams))
			}
			if got := streams[0].Attributes[AttrStream]; got != tt.want {
				t.Errorf("stream = %q, want %q", got, tt.want)
			}
			if got := streams[0].Attributes[AttrDirection]; got != tt.direction.String() {
				t.Errorf("direction = %q, want %q", got, tt.direction)
			}
		})
	}
}

// TestOnlyTheSessionChannelIsCaptured keeps a tunnelled backup out of the
// telemetry pipeline: a forward's audit value is its destination, recorded when
// it opens, not its bytes.
func TestOnlyTheSessionChannelIsCaptured(t *testing.T) {
	shipper, _ := newTestShipper(t, nil)
	reg := channel.NewRegistry()
	Register(reg, shipper.Session(SessionInfo{SessionID: "sess-1"}))

	if got := reg.Inspectors(CaptureChannel); len(got) != 1 {
		t.Fatalf("the session channel has %d inspectors, want 1", len(got))
	}
	if got := reg.Inspectors("direct-tcpip"); len(got) != 0 {
		t.Errorf("direct-tcpip has %d inspectors, want none: forwards are not captured", len(got))
	}
}

// TestRegisteringWithoutARecorderAttachesNothing keeps the pass-through path
// available to a proxy with no telemetry configured.
func TestRegisteringWithoutARecorderAttachesNothing(t *testing.T) {
	reg := channel.NewRegistry()
	Register(reg, nil)
	if got := reg.Inspectors(CaptureChannel); len(got) != 0 {
		t.Errorf("a nil recorder registered %d inspectors, want none", len(got))
	}
}
