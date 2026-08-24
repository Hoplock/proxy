// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
	"context"
	"io"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/hoplock/proxy/internal/channel"
)

// CaptureName identifies the stream recorder in logs and decisions.
const CaptureName = "session-capture"

// CaptureChannel is the SSH channel type whose bytes are captured.
//
// It is the session channel and only the session channel, because that is
// where a session a security team would want to replay lives: a shell, an
// exec, an sftp subsystem. A port forward's audit value is its destination —
// recorded when the channel opens (D5a axis 3a) — not its bytes, and capturing
// those would turn every tunnelled backup into proxy telemetry. Anything else
// keeps phase 0009's straight-copy path with no wrapper at all.
const CaptureChannel = "session"

// StreamCapture is the channel.StreamInspector that feeds a session's bytes
// into its record (PLAN §7).
//
// It observes and never transforms: the reader it returns hands every byte
// straight on and records a copy. A capture that could change what the target
// sees would make the audit trail and the session two different things.
type StreamCapture struct {
	rec *SessionRecorder
	max int
	now func() time.Time
}

// NewStreamCapture returns the capture inspector for one session. A nil
// recorder returns nil, which registers nothing.
func NewStreamCapture(rec *SessionRecorder) *StreamCapture {
	if rec == nil {
		return nil
	}
	return &StreamCapture{rec: rec, max: rec.shipper.MaxPayloadBytes(), now: rec.shipper.now}
}

// Register attaches stream capture to a session's registry.
//
// The registry is the per-session layer (channel.Registry.Clone): a recorder
// belongs to one session, so it cannot live in the proxy-wide registry every
// session shares.
func Register(reg *channel.Registry, rec *SessionRecorder) {
	capture := NewStreamCapture(rec)
	if capture == nil {
		return
	}
	reg.Register(CaptureChannel, capture)
}

// Name implements channel.Inspector.
func (c *StreamCapture) Name() string { return CaptureName }

// InspectStream implements channel.StreamInspector.
func (c *StreamCapture) InspectStream(_ context.Context, ev *channel.StreamEvent) io.Reader {
	if c == nil || ev == nil || ev.Source == nil {
		return nil
	}
	return &captureReader{
		src:     ev.Source,
		rec:     c.rec,
		max:     c.max,
		now:     c.now,
		started: c.now(),
		info:    ev.Channel,
		dir:     ev.Direction,
		stream:  streamName(ev.Direction, ev.Stderr),
	}
}

// streamName says which of a channel's three streams the bytes belong to, in
// the words a replay tool uses: what the user typed, what the target printed,
// and what it printed on stderr.
func streamName(dir channel.Direction, stderr bool) string {
	if dir == channel.FromClient {
		return "stdin"
	}
	if stderr {
		return "stderr"
	}
	return "stdout"
}

// captureReader copies one direction of one channel through unchanged while
// recording what passes.
//
// One record per read, split at the payload cap. That is the ttyrec model: the
// chunk boundaries are the boundaries the bytes actually arrived on, so a
// replay reproduces the timing a user saw rather than a re-chunked
// approximation of it. Coalescing keystrokes into fewer, larger records would
// cost that timing, and the batching layer already amortises the volume.
type captureReader struct {
	src     io.Reader
	rec     *SessionRecorder
	max     int
	now     func() time.Time
	started time.Time
	info    channel.Info
	dir     channel.Direction
	stream  string
	seq     atomic.Uint64
}

// Read implements io.Reader.
func (r *captureReader) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	if n > 0 {
		r.capture(p[:n])
	}
	return n, err
}

// capture records the bytes of one read, splitting anything over the payload
// cap across consecutive records.
func (r *captureReader) capture(b []byte) {
	at := r.now()
	offset := at.Sub(r.started)
	for len(b) > 0 {
		chunk := b
		if len(chunk) > r.max {
			chunk = chunk[:r.max]
		}
		b = b[len(chunk):]

		// The payload is copied because p belongs to the pump and is reused on
		// the next read, while the record outlives this call by design.
		payload := make([]byte, len(chunk))
		copy(payload, chunk)

		r.rec.Stream(payload, at, Attrs{}.
			Set(AttrCapture, CaptureChunk).
			Set(AttrCaptureFormat, CaptureFormatRawChunk).
			Set(AttrChannelID, r.info.ChannelID).
			Set(AttrChannelType, r.info.Type).
			Set(AttrDirection, r.dir.String()).
			Set(AttrStream, r.stream).
			Set(AttrOffsetMS, strconv.FormatInt(offset.Milliseconds(), 10)).
			Set(AttrSequence, strconv.FormatUint(r.seq.Add(1)-1, 10)).
			SetInt(AttrBytes, len(payload)))
	}
}
