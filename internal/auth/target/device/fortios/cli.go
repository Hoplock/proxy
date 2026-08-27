// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package fortios

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/hoplock/proxy/internal/auth/target/device"
)

// This file is the prompt/response state machine, and it is a state machine
// rather than a command pipe for three reasons that are all properties of the
// far end rather than of this code:
//
//  1. FortiOS PAGES. `config system console` defaults to `set output more`, and
//     that setting is permanent and device-wide — there is no per-session way to
//     turn it off, and turning it off permanently would be a configuration
//     change on a customer's device made for our convenience. So long output
//     arrives in screens separated by a `--More--` marker that must be answered.
//  2. FortiOS has MODES. `config system admin` changes the prompt, `edit <name>`
//     changes it again, and `end` unwinds them. A command sent in the wrong mode
//     is not an error the device reports usefully; it is a command that means
//     something else.
//  3. FortiOS reports failure as OUTPUT, not as an exit status. There is no exit
//     status at all: the entire conversation happens inside one shell channel,
//     so "did that work" is a question about text.
//
// Nothing here interprets what a command MEANS. It reads until the device is
// waiting again, hands the text back, and lets the driver decide.

// readTimeout bounds how long one command may take to come back to a prompt.
const readTimeout = 20 * time.Second

// maxOutput bounds what one command may return. A device answering a `show`
// with megabytes is a device having a bad day, and holding it all is how one
// bad device becomes the proxy's memory problem.
const maxOutput = 1 << 20

// maxPages bounds how many `--More--` screens one command may produce. It is a
// loop guard: a device that answers every space with another page would
// otherwise hold this goroutine forever.
const maxPages = 512

// promptPattern matches the end of a FortiOS prompt.
//
// A FortiOS prompt is the hostname followed by an optional mode path and a
// terminator: `FGT-1 # `, `FGT-1 (admin) # `, `FGT-1 (hl-a1b2-alice-…) # `. The
// match is anchored to the END of what has arrived so far, which is what makes
// "the device is waiting for me" a decidable question on a stream with no
// framing.
var promptPattern = regexp.MustCompile(`(?m)^[^\r\n]*[#$] ?$`)

// morePattern matches the pager's marker in its several renderings.
var morePattern = regexp.MustCompile(`--More--|<--- More --->|\(END\)`)

// errorPatterns are the failure strings FortiOS emits as ordinary output.
//
// They are matched rather than parsed because FortiOS gives no machine-readable
// failure channel — this is the whole reason a driver is a state machine. A
// pattern that is missing here turns a failure into a silent success, which on
// the create path means a session that connects with a credential the device
// never accepted, so the list is deliberately broad and each entry says what it
// is for.
var errorPatterns = []struct {
	pattern *regexp.Regexp
	what    string
}{
	// The generic failure. FortiOS appends a return code that varies by cause
	// and is not documented as a stable contract, so the code is reported but
	// never branched on.
	{regexp.MustCompile(`(?i)command fail\.?\s*return code\s*(-?\d+)`), "the command failed"},
	// A value the parser could not accept — the shape a mis-escaped value takes.
	{regexp.MustCompile(`(?i)value parse error before`), "the device rejected a value"},
	// A reference to an object that does not exist, e.g. an access profile.
	{regexp.MustCompile(`(?i)entry not found in datasource`), "the device does not have that object"},
	{regexp.MustCompile(`(?i)^\s*unknown action\b`), "the device did not understand the command"},
	{regexp.MustCompile(`(?i)command parse error`), "the device could not parse the command"},
	{regexp.MustCompile(`(?i)input value is invalid`), "the device rejected a value"},
	{regexp.MustCompile(`(?i)permission denied`), "the management administrator is not permitted to do that"},
	{regexp.MustCompile(`(?i)the string is too long`), "the device rejected a value as too long"},
	{regexp.MustCompile(`(?i)object (is )?in use`), "the object is in use on the device"},
}

// notFoundPattern is the subset of failures that mean "there is nothing there".
//
// It is separated from the rest because REMOVAL MUST BE IDEMPOTENT (D13):
// teardown runs on the normal path, on error, on panic, and from the reaper, so
// deleting an administrator that is already gone is a success. Treating it as a
// failure would make every second teardown attempt look like a device problem
// and would keep the reaper retrying something that is already done.
var notFoundPattern = regexp.MustCompile(`(?i)entry not found|does not exist|no such entry`)

// ErrDeviceRefused means the device ran the command and refused it.
//
// It is deliberately NOT device.ErrUnsupported: a refusal is this attempt
// failing, and D13's rule is that a failed attempt fails the session rather
// than dropping to a weaker ladder rung the server ranked lower.
var ErrDeviceRefused = errors.New("auth/target/device/fortios: the device refused the command")

// cliSession is one privileged CLI conversation with a device.
type cliSession struct {
	shell   device.Shell
	buf     bytes.Buffer
	reads   chan readResult
	readErr error
	closed  bool
}

type readResult struct {
	data []byte
	err  error
}

// openCLI wraps a shell and reads past the login banner to the first prompt.
//
// The banner matters: a FortiGate greets a login with a version block and, on
// many units, a warning about the default password or an expiring licence.
// Reading to the first prompt is what stops that text from being attributed to
// the first command as if it were its output.
func openCLI(ctx context.Context, shell device.Shell) (*cliSession, error) {
	s := &cliSession{shell: shell, reads: make(chan readResult, 8)}
	go s.pump()
	if _, err := s.readToPrompt(ctx); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("auth/target/device/fortios: never reached a CLI prompt: %w", err)
	}
	return s, nil
}

// pump moves the shell's output onto a channel so reads can honour a context.
// A device that stops talking mid-command must not wedge the session that is
// waiting for it, and an io.Reader has no deadline of its own.
func (s *cliSession) pump() {
	buf := make([]byte, 4096)
	for {
		n, err := s.shell.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			s.reads <- readResult{data: chunk}
		}
		if err != nil {
			s.reads <- readResult{err: err}
			close(s.reads)
			return
		}
	}
}

// send writes one command line and returns everything the device said before it
// was ready again.
func (s *cliSession) send(ctx context.Context, line string) (string, error) {
	if strings.ContainsAny(line, "\r\n") {
		// Belt and braces over the validation each value already passed: a
		// newline here would inject a second command into a configuration
		// parser, which is the failure mode this whole file is written around.
		return "", fmt.Errorf("%w: a command line may not contain a newline", errInvalidValue)
	}
	if _, err := io.WriteString(s.shell, line+"\n"); err != nil {
		// The line is NOT in this error: one of the lines this driver sends
		// carries a password, and a transport failure is exactly the moment
		// something gets logged verbatim. The caller labels its own step.
		return "", fmt.Errorf("auth/target/device/fortios: writing to the device failed: %w", err)
	}
	out, err := s.readToPrompt(ctx)
	if err != nil {
		return out, err
	}
	// The device echoes the command it was given; dropping the echo keeps a
	// password-bearing command out of the text that later reaches an error.
	return stripEcho(out, line), nil
}

// readToPrompt reads until the device is waiting for input again, answering the
// pager on the way.
func (s *cliSession) readToPrompt(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	s.buf.Reset()
	pages := 0
	for {
		if text, ok := splitAtPrompt(s.buf.Bytes()); ok {
			return text, nil
		}
		if morePattern.Match(s.buf.Bytes()) {
			pages++
			if pages > maxPages {
				return s.buf.String(), fmt.Errorf("auth/target/device/fortios: the device kept paging past %d screens", maxPages)
			}
			// A space is the pager's "next screen". `q` would quit the pager
			// and truncate the answer, which on the enumerate path would mean a
			// sweep that silently misses the accounts on later screens.
			if _, err := io.WriteString(s.shell, " "); err != nil {
				return s.buf.String(), fmt.Errorf("auth/target/device/fortios: answer the pager: %w", err)
			}
			s.dropMoreMarker()
		}
		if s.buf.Len() > maxOutput {
			return s.buf.String(), fmt.Errorf("auth/target/device/fortios: the device returned more than %d bytes", maxOutput)
		}

		select {
		case <-ctx.Done():
			return s.buf.String(), fmt.Errorf("auth/target/device/fortios: the device stopped responding: %w", ctx.Err())
		case res, ok := <-s.reads:
			if !ok {
				if s.readErr != nil {
					return s.buf.String(), s.readErr
				}
				return s.buf.String(), io.EOF
			}
			if len(res.data) > 0 {
				s.buf.Write(res.data)
			}
			if res.err != nil {
				s.readErr = res.err
				if res.err != io.EOF {
					return s.buf.String(), res.err
				}
			}
		}
	}
}

// dropMoreMarker removes the pager marker so it is not re-detected and so it
// never reaches the driver as if it were output.
func (s *cliSession) dropMoreMarker() {
	cleaned := morePattern.ReplaceAll(s.buf.Bytes(), nil)
	s.buf.Reset()
	s.buf.Write(cleaned)
}

// Close ends the conversation, leaving configuration mode first where it can.
func (s *cliSession) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	// `end` twice then `exit`: unwinding an edit and a config block costs
	// nothing when there is nothing to unwind, and leaving a device sitting in
	// configuration mode holds an object lock on units running workspace mode.
	_, _ = io.WriteString(s.shell, "end\nend\nexit\n")
	return s.shell.Close()
}

// splitAtPrompt reports whether the device has finished speaking, and returns
// what it said.
//
// The prompt must be the TAIL of what has arrived, not merely present: a `#`
// inside earlier output is a comment or a hostname in a banner, and treating
// one as an invitation would send the next command into the middle of the
// previous one's output.
func splitAtPrompt(b []byte) (text string, ok bool) {
	trimmed := bytes.TrimRight(b, " \t\r")
	if len(trimmed) == 0 {
		return "", false
	}
	idx := bytes.LastIndexByte(trimmed, '\n')
	if !promptPattern.Match(bytes.TrimRight(trimmed[idx+1:], "\r")) {
		return "", false
	}
	if idx < 0 {
		return "", true
	}
	return string(bytes.TrimRight(trimmed[:idx], "\r\n")), true
}

// stripEcho removes the device's echo of the command it was just given.
func stripEcho(out, line string) string {
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		if strings.TrimSpace(strings.TrimRight(l, "\r")) == strings.TrimSpace(line) {
			return strings.TrimLeft(strings.Join(append(lines[:i:i], lines[i+1:]...), "\n"), "\r\n")
		}
	}
	return out
}

// checkOutput turns FortiOS's textual failure reporting into an error.
//
// It is applied to EVERY command's output, including the ones that "cannot
// fail", because on this platform a failure and a success are the same shape
// and the only difference is a line of text. The command is named in the error;
// its ARGUMENTS are not, because one of them is sometimes a password.
func checkOutput(command, out string) error {
	for _, e := range errorPatterns {
		if m := e.pattern.FindStringSubmatch(out); m != nil {
			detail := e.what
			if len(m) > 1 && m[1] != "" {
				detail = fmt.Sprintf("%s (return code %s)", e.what, m[1])
			}
			return fmt.Errorf("%w: %s: %s", ErrDeviceRefused, command, detail)
		}
	}
	return nil
}

// isNotFound reports whether output means "there was nothing there", which on
// the removal path is success.
func isNotFound(out string) bool { return notFoundPattern.MatchString(out) }
