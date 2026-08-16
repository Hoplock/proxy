// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package routing

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"unicode/utf8"
)

// DefaultTargetPort is the SSH port used when the management server's route
// does not name one. The port is the server's to choose (D2); this is only the
// fallback for a response that left it unset.
const DefaultTargetPort = 22

// maxHostnameLength is the DNS limit on a presentation-format name.
const maxHostnameLength = 253

// Parsing outcomes. Both are user input problems, not policy decisions: they
// are decided locally, before the management server is asked anything, and must
// never be reported to the user as a denial.
var (
	// ErrMalformedUsername means the SSH username did not carry a target in the
	// configured form (D1), e.g. "alice" with no delimiter, or two delimiters.
	ErrMalformedUsername = errors.New("routing: SSH username does not encode a target")
	// ErrInvalidTarget means the target segment was present but is not a usable
	// hostname or IP address.
	ErrInvalidTarget = errors.New("routing: target is not a valid hostname or IP address")
)

// ParseUsername splits an SSH username into the login and the target it encodes
// (D1), e.g. "alice#host.company.com" with delimiter "#".
//
// SSH has no SNI or Host header, so by the time the connection arrives the name
// the user typed is gone: the username is the only field left that the client
// sends and the user controls. That is why the target rides in it, and why this
// function runs before authentication — the login presented for authentication
// must be the login, never "login+target".
//
// It is pure and cheap on purpose: the SSH auth callbacks and the proxy engine
// both need the split, at different moments and with no shared state, so both
// call this rather than passing a parse result around.
func ParseUsername(username, delimiter string) (login, target string, err error) {
	if utf8.RuneCountInString(delimiter) != 1 {
		// The delimiter comes from validated config; a caller that got here with
		// a bad one has a wiring bug, and guessing a delimiter would silently
		// authenticate somebody as the wrong login.
		return "", "", fmt.Errorf("%w: delimiter %q is not a single character", ErrMalformedUsername, delimiter)
	}

	i := strings.Index(username, delimiter)
	if i < 0 {
		return "", "", fmt.Errorf("%w: no %q in %q", ErrMalformedUsername, delimiter, username)
	}
	login, rest := username[:i], username[i+len(delimiter):]
	if strings.Contains(rest, delimiter) {
		// Two delimiters cannot be resolved without guessing which one splits
		// the name, and guessing wrong picks a different target.
		return "", "", fmt.Errorf("%w: %q contains %q more than once", ErrMalformedUsername, username, delimiter)
	}
	if login == "" {
		return "", "", fmt.Errorf("%w: login is empty in %q", ErrMalformedUsername, username)
	}
	if err := validateLogin(login); err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrMalformedUsername, err)
	}
	if rest == "" {
		return "", "", fmt.Errorf("%w: target is empty in %q", ErrMalformedUsername, username)
	}

	target, err = NormalizeTarget(rest)
	if err != nil {
		return "", "", err
	}
	return login, target, nil
}

// NormalizeTarget canonicalises a target so that two spellings of one host
// reach the management server — and the audit log — as one string. It lowercases
// (DNS is case-insensitive, policy keys are not) and drops the root dot.
func NormalizeTarget(target string) (string, error) {
	t := strings.TrimSpace(target)
	t = strings.TrimSuffix(t, ".")
	t = strings.ToLower(t)

	if t == "" {
		return "", fmt.Errorf("%w: empty", ErrInvalidTarget)
	}
	if len(t) > maxHostnameLength {
		return "", fmt.Errorf("%w: longer than %d characters", ErrInvalidTarget, maxHostnameLength)
	}
	if ip := net.ParseIP(t); ip != nil {
		return ip.String(), nil
	}
	if err := validateHostname(t); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidTarget, err)
	}
	return t, nil
}

// validateHostname checks the label rules of RFC 1123. It is deliberately
// strict: the target string ends up in a policy request, a dial, and a log
// line, and a name carrying whitespace or control characters could forge a log
// record or reach an unintended host.
func validateHostname(host string) error {
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return errors.New("empty label")
		}
		if len(label) > 63 {
			return fmt.Errorf("label %q is longer than 63 characters", label)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("label %q starts or ends with %q", label, "-")
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			default:
				return fmt.Errorf("label %q contains %q", label, r)
			}
		}
	}
	return nil
}

// validateLogin rejects a login the bastion could not safely present, log, or
// reason about. It does not decide whether the login exists — that is the
// management server's answer, not the bastion's (D2).
func validateLogin(login string) error {
	if len(login) > 64 {
		return errors.New("login is longer than 64 characters")
	}
	for _, r := range login {
		if r < 0x20 || r == 0x7f {
			return errors.New("login contains a control character")
		}
		if r == ' ' || r == '\t' {
			return errors.New("login contains whitespace")
		}
	}
	return nil
}
