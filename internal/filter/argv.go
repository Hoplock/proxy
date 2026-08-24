// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package filter

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// This file is the restricted tier's front door, and the only part of this
// package that faces adversarial input directly. Everything it does follows
// from one rule: a command that cannot be reduced to exactly ONE argument
// vector is denied, never best-effort matched. An ambiguous parse inside a
// default-deny boundary is the whole vulnerability class.

// maxCommandLength bounds the work one exec request can ask for. It is far
// above any real command and far below anything worth spending time on.
const maxCommandLength = 64 << 10

// ParseError says why a command could not be reduced to one argument vector.
// Its text names the shell syntax that stopped the parse, which is operator
// detail: it goes in the audit record, never to the user (PLAN §4.3).
type ParseError struct {
	// Reason is the human-readable explanation.
	Reason string
	// Offset is the byte the parse stopped at, or -1 when the problem is the
	// whole string.
	Offset int
}

func (e *ParseError) Error() string {
	if e.Offset < 0 {
		return e.Reason
	}
	return fmt.Sprintf("%s (at byte %d)", e.Reason, e.Offset)
}

// ParseArgv reduces an exec command string to the argument vector it
// unambiguously means, or refuses it.
//
// It is deliberately not a shell. A shell's job is to expand; this parser's job
// is to establish that there is nothing to expand, so that the vector the proxy
// approved is the vector the target runs. It therefore accepts only:
//
//   - words separated by spaces and tabs;
//   - single quotes, which make their contents inert to us and to the target's
//     shell alike — 'a b', '*.txt';
//   - double quotes around text containing no $, no backquote and no
//     backslash, which are then equally inert.
//
// Everything else is refused: any control character (a newline is a command
// separator), any of ; | & < > ( ) { } $ ` \ * ? [ ] ~ # ! , a NUL byte,
// invalid UTF-8, an unterminated quote, and the empty command. Several of
// those — the globbing characters especially — are inert to *this* parser and
// would be refused by nothing, which is exactly why they are refused here: the
// target's sshd hands an exec string to the user's login shell, so a "*" the
// proxy approved as a literal argument is a "*" the target expands. Refusing
// it keeps "the command that runs is the argv that was approved" true rather
// than nearly true. A policy that means a glob writes it '*' and gets the
// literal.
func ParseArgv(command string) ([]string, error) {
	if len(command) > maxCommandLength {
		return nil, &ParseError{Reason: "the command is longer than this proxy will parse", Offset: -1}
	}
	if !utf8.ValidString(command) {
		return nil, &ParseError{Reason: "the command is not valid UTF-8", Offset: -1}
	}
	// Checked before the scan rather than during it, so that a NUL is refused
	// wherever it hides — inside single quotes included, where nothing else
	// looks at the bytes.
	if i := strings.IndexByte(command, 0); i >= 0 {
		return nil, &ParseError{Reason: "the command contains a NUL byte", Offset: i}
	}

	var (
		argv    []string
		word    strings.Builder
		started bool // a word is in progress, so '' still produces an argument
	)
	for i := 0; i < len(command); {
		c := command[i]
		switch {
		case c == ' ' || c == '\t':
			if started {
				argv = append(argv, word.String())
				word.Reset()
				started = false
			}
			i++

		case c == '\'':
			end := strings.IndexByte(command[i+1:], '\'')
			if end < 0 {
				return nil, &ParseError{Reason: "a single quote is never closed", Offset: i}
			}
			word.WriteString(command[i+1 : i+1+end])
			started = true
			i += end + 2

		case c == '"':
			j := i + 1
			for ; j < len(command) && command[j] != '"'; j++ {
				switch command[j] {
				case '$', '`', '\\':
					// Inside double quotes these still expand, so the string
					// means something we cannot decide from the string alone.
					return nil, &ParseError{
						Reason: "the command contains shell expansion inside double quotes: " + describeByte(command[j]),
						Offset: j,
					}
				case 0:
					return nil, &ParseError{Reason: "the command contains a NUL byte", Offset: j}
				}
			}
			if j >= len(command) {
				return nil, &ParseError{Reason: "a double quote is never closed", Offset: i}
			}
			word.WriteString(command[i+1 : j])
			started = true
			i = j + 1

		case shellActive(c):
			return nil, &ParseError{
				Reason: "the command contains shell syntax: " + describeByte(c),
				Offset: i,
			}

		default:
			word.WriteByte(c)
			started = true
			i++
		}
	}
	if started {
		argv = append(argv, word.String())
	}
	if len(argv) == 0 {
		return nil, &ParseError{Reason: "the command is empty", Offset: -1}
	}
	return argv, nil
}

// shellActive reports whether a byte outside quotes means something to a shell.
// It errs towards yes: a character refused here costs a policy author one pair
// of quotes, and a character wrongly allowed costs the boundary.
func shellActive(c byte) bool {
	if c < 0x20 || c == 0x7f {
		// Every control character, which is where the newline lives: a command
		// separator that a pattern would read as part of one command.
		return true
	}
	switch c {
	case ';', '|', '&', '<', '>', '(', ')', '{', '}', '$', '`', '\\',
		'*', '?', '[', ']', '~', '#', '!', '\'', '"':
		return true
	}
	return false
}

// describeByte names a byte for an operator-facing error.
func describeByte(c byte) string {
	switch {
	case c == 0:
		return "a NUL byte"
	case c == '\n':
		return "a newline"
	case c == '\r':
		return "a carriage return"
	case c < 0x20 || c == 0x7f:
		return fmt.Sprintf("control byte %#02x", c)
	default:
		return fmt.Sprintf("%q", string(rune(c)))
	}
}
