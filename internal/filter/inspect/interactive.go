// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package inspect

import (
	"context"
	"io"
	"sync"
	"unicode/utf8"

	"github.com/hoplock/proxy/internal/channel"
	"github.com/hoplock/proxy/internal/control"
)

// InteractiveName identifies the interactive inspector in logs and audit events.
const InteractiveName = "command-filter/interactive"

// maxInteractiveLine bounds one reconstructed line. A stream that never sends a
// newline must not grow a buffer without limit, and a line this long is not a
// command anyone typed — it is a paste, a file, or an attempt to exhaust the
// proxy. Over the limit the line is abandoned rather than truncated: half a
// command matched against a pattern is a false report, and a false report in a
// security feed costs more than a missed one on a tier that promises nothing.
const maxInteractiveLine = 4096

// Interactive reconstructs command lines from an interactive stream and reports
// what policy would have said about them.
//
// It is an AUDIT SIGNAL and nothing more (PLAN §6.3, D12). Three properties
// hold, and they are what "best-effort" has to mean if it is to be honest:
//
//   - it never denies a request and never ends a session, so nothing here can
//     be mistaken for enforcement — a match on this tier is recorded with
//     enforced=false and outcome=observed, whatever action the policy names;
//   - it never writes to the stream, so a pty is never corrupted by
//     inspection: a warning injected into a raw-mode terminal mid-line is
//     itself corruption, and a command already typed cannot be un-typed;
//   - it copies bytes through untouched, so what the target receives is exactly
//     what the client sent.
//
// What defeats it, for the avoidance of any doubt in a sales conversation:
// line editing beyond the simple cases below, arrow keys, history recall,
// tab completion, multi-byte encodings other than UTF-8, base64 and any other
// transformation, an editor's shell escape, and a shell started inside the
// shell. Enforcement on an interactive route is D12's answer, not this file's:
// restricted exec, or the target-side enforcement points phase 0015 opens.
type Interactive struct {
	opts Options

	mu sync.Mutex
	// interactive marks the channels that have become interactive, by channel
	// id. A session channel that only ever runs an exec carries the command's
	// stdin, not keystrokes, and reading commands out of stdin would fill a
	// security feed with the contents of piped files.
	interactive map[string]bool
}

// NewInteractive returns the interactive inspector for a connection's policy.
func NewInteractive(opts Options) *Interactive {
	return &Interactive{opts: opts, interactive: make(map[string]bool)}
}

// Name implements channel.Inspector.
func (i *Interactive) Name() string { return InteractiveName }

// InspectRequest implements channel.RequestInspector. It decides nothing: it
// watches for the requests that turn a session channel into an interactive one,
// so that the stream inspector knows whether it is looking at keystrokes.
func (i *Interactive) InspectRequest(_ context.Context, ev *channel.RequestEvent) channel.Decision {
	if ev.Direction != channel.FromClient {
		return channel.Allow()
	}
	switch ev.Type {
	case control.RequestShell, control.RequestPTY:
		i.mu.Lock()
		i.interactive[ev.Channel.ChannelID] = true
		i.mu.Unlock()
	}
	return channel.Allow()
}

// InspectStream implements channel.StreamInspector. It wraps the client's half
// of a channel and leaves every other direction alone.
func (i *Interactive) InspectStream(_ context.Context, ev *channel.StreamEvent) io.Reader {
	if ev.Direction != channel.FromClient || ev.Stderr {
		// The target's output is not the user's commands, and neither is
		// anything on the extended-data stream.
		return ev.Source
	}
	return &lineScanner{owner: i, info: ev.Channel, src: ev.Source}
}

// isInteractive reports whether a channel has become an interactive one.
func (i *Interactive) isInteractive(channelID string) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.interactive[channelID]
}

// release forgets a channel once its stream has ended.
func (i *Interactive) release(channelID string) {
	i.mu.Lock()
	delete(i.interactive, channelID)
	i.mu.Unlock()
}

// report evaluates one reconstructed line and records what policy would say.
func (i *Interactive) report(info channel.Info, line string) {
	d, worth := i.opts.Engine.Interactive(line)
	if !worth {
		return
	}
	i.opts.sink().Record(auditEvent(d, i.opts.now(), false, info, control.RequestShell, InteractiveName))
}

// lineScanner copies a client stream through unchanged while reassembling the
// lines the user typed.
//
// It is per stream, so its buffer is per channel with no shared state to lock,
// and it holds no reference to the bytes it passed on.
type lineScanner struct {
	owner *Interactive
	info  channel.Info
	src   io.Reader

	line []byte
	// escape tracks an ANSI escape sequence being skipped, so that a cursor
	// key does not land in the middle of a reconstructed command.
	escape escapeState
	// overflow marks a line already past the limit: its bytes are dropped
	// until the next newline rather than reported as a command.
	overflow bool
}

// Read implements io.Reader. The bytes are handed on exactly as they arrived,
// whatever the scan concludes.
func (s *lineScanner) Read(p []byte) (int, error) {
	n, err := s.src.Read(p)
	if n > 0 && s.owner.isInteractive(s.info.ChannelID) {
		s.scan(p[:n])
	}
	if err != nil {
		s.owner.release(s.info.ChannelID)
	}
	return n, err
}

// scan feeds one chunk of keystrokes through the line reassembly.
func (s *lineScanner) scan(b []byte) {
	for _, c := range b {
		switch {
		case s.escape == escapeIntroduced:
			// "ESC [" (CSI) and "ESC O" (SS3, which is what an arrow key sends
			// in application mode) both continue; anything else was a two-byte
			// escape that has now ended.
			if c == '[' || c == 'O' {
				s.escape = escapeSequence
				continue
			}
			s.escape = escapeNone
		case s.escape == escapeSequence:
			// A CSI sequence ends on its final byte, in @…~. The parameter and
			// intermediate bytes before it are below that range.
			if c >= 0x40 && c <= 0x7e {
				s.escape = escapeNone
			}
		case c == '\r' || c == '\n':
			s.finish()
		case c == 0x1b: // ESC
			s.escape = escapeIntroduced
		case c == 0x7f || c == 0x08: // DEL, backspace
			s.backspace()
		case c == 0x15 || c == 0x03: // ^U kill line, ^C abandon line
			s.reset()
		case c < 0x20:
			// Every other control byte is not part of a command: a tab is
			// completion rather than text, and the rest are signals.
		default:
			if len(s.line) >= maxInteractiveLine {
				s.overflow = true
				s.line = s.line[:0]
				continue
			}
			s.line = append(s.line, c)
		}
	}
}

// finish reports the line the user just entered, if there is one worth
// reporting.
func (s *lineScanner) finish() {
	line, overflow := s.line, s.overflow
	s.reset()
	if overflow || len(line) == 0 {
		return
	}
	s.owner.report(s.info, string(line))
}

// backspace removes the last rune, so that editing an argument does not leave
// its first half in the reconstructed line.
func (s *lineScanner) backspace() {
	if len(s.line) == 0 {
		return
	}
	_, size := utf8.DecodeLastRune(s.line)
	s.line = s.line[:len(s.line)-size]
}

func (s *lineScanner) reset() {
	s.line = s.line[:0]
	s.overflow = false
}

// escapeState is how much of an escape sequence has been seen.
type escapeState int

const (
	escapeNone escapeState = iota
	escapeIntroduced
	escapeSequence
)
