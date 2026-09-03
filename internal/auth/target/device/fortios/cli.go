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
//  3. FortiOS reports failure as OUTPUT, not as an exit status. Fortinet
//     documents the shape — "CLI error codes are shown in the command line if
//     the command execution fails… a summary, followed by `Command fail. Return
//     code -X`" — and there is no exit status to read alongside it, because the
//     entire conversation happens inside one shell channel. So "did that work"
//     is a question about text.
//
// The conversation is held over a SHELL channel rather than an exec request,
// and the reason is worth stating at its real strength rather than as an
// absolute. Fortinet does not document whether the FortiOS SSH server honours
// an exec request either way. What Fortinet does document is that every
// published way of driving a FortiGate over SSH uses an interactive shell, and
// its own scripting example forces a PTY (`ssh -t -t`) — the flag you reach for
// precisely when the far end will not work without one. Independently, FortiOS
// devices return nothing to paramiko's `exec_command()` and need
// `invoke_shell()`, and netmiko drives them through a shell throughout. A shell
// channel is therefore the only mode with evidence behind it; that an exec
// request is REFUSED is an inference from strong circumstantial evidence, and
// it is on this phase's hardware list rather than stated as fact.
//
// Nothing here interprets what a command MEANS. It reads until the device is
// waiting again, hands the text back, and lets the driver decide.

// deviceNow is the unit's wall clock now, carried forward from the reading
// taken when the session opened.
//
// The elapsed term is what keeps a window honest on a long session: a create
// that happens forty seconds after the status read would otherwise open a
// window forty seconds in the past, which on a one-minute granularity is a
// whole unit of the thing being measured. It is measured against this process's
// clock rather than re-read from the device because what can drift over one
// session is the OFFSET between two clocks, not the passage of time.
//
// It returns false when the unit reported no readable clock.
func (s *cliSession) deviceNow() (time.Time, bool) {
	if s.deviceTime.IsZero() {
		return time.Time{}, false
	}
	return s.deviceTime.Add(time.Since(s.readAt)), true
}

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
	// The generic failure. Fortinet publishes a table of return codes and the
	// code varies by cause, so it is reported and never branched on — which is
	// what the same page justifies.
	{regexp.MustCompile(`(?i)command fail\.?\s*return code\s*(-?\d+)`), "the command failed"},
	// A value the parser could not accept — the shape a mis-escaped value
	// takes. Both spellings are real: Fortinet's canonical example in the
	// Administration Guide is `Command parse error before '<x>'` (matched
	// below), while `value parse error before '<x>'` is what the KBs show,
	// normally after a `node_check_object fail!` line.
	{regexp.MustCompile(`(?i)value parse error before`), "the device rejected a value"},
	// A reference to an object that does not exist, e.g. an access profile.
	{regexp.MustCompile(`(?i)entry not found in datasource`), "the device does not have that object"},
	{regexp.MustCompile(`(?i)^\s*unknown action\b`), "the device did not understand the command"},
	{regexp.MustCompile(`(?i)command parse error`), "the device could not parse the command"},
	{regexp.MustCompile(`(?i)input value is invalid`), "the device rejected a value"},
	{regexp.MustCompile(`(?i)permission denied`), "the management administrator is not permitted to do that"},
	{regexp.MustCompile(`(?i)the string is too long`), "the device rejected a value as too long"},
	{regexp.MustCompile(`(?i)object (is )?in use`), "the object is in use on the device"},
	// The rejection a name outside FortiOS's character set draws, documented in
	// the naming-rules KB. accountNamePattern already excludes the characters
	// that trigger it and it arrives alongside a `Command fail. Return code`
	// line that is matched above, so this entry is belt and braces — which is
	// the standard this list is held to, because a pattern missing here turns a
	// failure into a silent success.
	{regexp.MustCompile(`(?i)the string contains xss vulnerability characters`), "the device rejected a name"},
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
	// vdomMode is what the unit answered when the session opened. It decides
	// which scope the administrator table lives in, so it belongs to the
	// SESSION rather than to the driver: one driver serves every unit of its
	// kind, and two of them can be running different modes.
	vdomMode vdomMode
	// deviceTime is the unit's own wall clock as it reported it when the
	// session opened, and readAt is when this process read it.
	//
	// They are a PAIR and they are on the session for the same reason vdomMode
	// is: one driver serves every unit of its kind, and two units can be in two
	// timezones. What they are for is `set end`, which is an absolute local
	// datetime on the device — so a window computed from this proxy's clock
	// would be wrong by the offset between them, in one direction locking the
	// account out and in the other holding it open past its deadline.
	//
	// deviceTime is the zero time when the unit's status did not carry a
	// readable clock, and the driver refuses to render an expiry rather than
	// falling back to its own (see CreateAccount).
	deviceTime time.Time
	readAt     time.Time
	// depth is how many configuration levels this session has opened and not
	// closed. Close unwinds exactly that many, which is what a fixed `end\nend`
	// could not do once `config global` made the nesting depend on the unit.
	depth int
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
	// The depth is tracked on the line being SENT rather than on a successful
	// answer, and that direction is chosen on purpose: a `config` the device
	// refused leaves the session where it was and costs Close one harmless
	// extra `end`, while a `config` that succeeded on a device that then
	// stopped answering would otherwise leave Close one `end` short — and that
	// is the failure that strands a configuration block.
	s.trackNesting(line)
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

// Close ends the conversation, leaving configuration mode first.
//
// It unwinds ONE `end` PER LEVEL THIS SESSION OPENED, plus one for an entry
// that may still be open under the innermost one, and never fewer than two —
// which is byte-identical to what phase 0014 sent on the only unit shape it
// served. Until phase 0016 the two were a fixed depth, correct only because the
// driver refused a unit running virtual domains: there the administrator table
// is one level deeper, inside `config global`, and two `end`s would leave the
// session sitting in configuration mode. That is not cosmetic — a device left
// in a configuration block holds an object lock on units running workspace
// mode, so the next session's `config` fails on something this one did.
//
// Extra `end`s at the top level are harmless noise the device answers and
// nobody reads, which is why the floor of two costs nothing; an `end` too few
// is the failure this counts to avoid.
func (s *cliSession) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	ends := s.depth + 1
	if ends < minUnwindDepth {
		ends = minUnwindDepth
	}
	_, _ = io.WriteString(s.shell, strings.Repeat("end\n", ends)+"exit\n")
	return s.shell.Close()
}

// minUnwindDepth is the floor on Close's unwinding: one `end` for a
// configuration block and one for an entry inside it.
const minUnwindDepth = 2

// trackNesting follows what a command did to the CLI's configuration depth.
//
// It is deliberately a property of the SESSION and not of the command tables:
// every path that can leave a block open — a failed sequence, an abandoned
// create, a read that entered `config global` — goes through send, and a depth
// each caller maintained for itself would be a depth that drifts on the error
// paths, which are exactly the paths that leave a device in configuration mode.
//
// `edit` is not counted. On FortiOS the `end` that closes a configuration block
// commits and closes an open entry inside it as well, which is why Close's
// floor of two covers one block plus one entry rather than two blocks.
func (s *cliSession) trackNesting(line string) {
	switch {
	case line == "abort":
		// `abort` discards the whole uncommitted block outright, wherever in it
		// the session was.
		s.depth = 0
	case line == "end":
		if s.depth > 0 {
			s.depth--
		}
	case strings.HasPrefix(line, "config "):
		s.depth++
	}
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
