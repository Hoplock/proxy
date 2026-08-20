// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"errors"
	"fmt"
	"strings"
)

// This file is the entire target-side surface of the ephemeral method (D6,
// PLAN §5.1): three POSIX shell scripts and the validation that decides what
// may be interpolated into them.
//
// They are plain /bin/sh on purpose. The hosts this method is for are a Linux
// and BSD fleet, not a fleet with a configuration-management agent, and a
// provisioner that needed Python, bash, or a preinstalled helper on the target
// would work on a demo estate and nowhere else. Everything below runs on a
// stock system.
//
// Three properties are load-bearing and each is stated where it is implemented:
// provisioning is idempotent, teardown is idempotent AND verifies, and
// discovery lists only this proxy's accounts.

// Exit statuses the scripts use for failures the proxy distinguishes. They sit
// above the range a normal utility returns so a wrapped `useradd` failure and a
// verification failure are never confused.
const (
	exitCreateFailed = 90
	exitUserRemains  = 91
	exitHomeRemains  = 92
)

// ErrInvalidScriptValue means a value could not be safely interpolated into a
// provisioning script.
var ErrInvalidScriptValue = errors.New("auth/target: invalid value for a provisioning script")

// provisionScript creates the ephemeral account and installs its key.
//
// It is IDEMPOTENT because PLAN §5.1 requires it: a crashed prior session can
// leave an account behind, and provisioning that failed on "user exists" would
// turn one crash into an outage for that login. The account is created only if
// it is absent, and the key file is written unconditionally — a leftover
// account from another session's crash must end up holding THIS session's key
// and nothing else, which is why the write truncates instead of appending.
func (a *EphemeralAuthenticator) provisionScript(principal, home, authorizedKey string) (string, error) {
	if err := validatePrincipal(principal); err != nil {
		return "", err
	}
	if err := validatePath(home); err != nil {
		return "", err
	}
	if err := validateScriptValue("authorized key", authorizedKey); err != nil {
		return "", err
	}
	shell := a.shell
	if err := validatePath(shell); err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("set -eu\n")
	fmt.Fprintf(&b, "p=%s\n", quote(principal))
	fmt.Fprintf(&b, "h=%s\n", quote(home))
	b.WriteString(`if ! id -u "$p" >/dev/null 2>&1; then` + "\n")
	fmt.Fprintf(&b, "  useradd -m -d \"$h\" -s %s \"$p\" || exit %d\n", quote(shell), exitCreateFailed)
	b.WriteString("fi\n")
	// A leftover account may have a home that useradd did not create.
	b.WriteString(`mkdir -p "$h/.ssh"` + "\n")
	fmt.Fprintf(&b, "printf '%%s\\n' %s > \"$h/.ssh/authorized_keys\"\n", quote(authorizedKey))
	b.WriteString(`chmod 700 "$h/.ssh"` + "\n")
	b.WriteString(`chmod 600 "$h/.ssh/authorized_keys"` + "\n")
	// sshd's StrictModes refuses a key file the account does not own, so the
	// chown is not tidiness: without it the login this whole script exists to
	// enable is rejected.
	b.WriteString(`chown -R "$p" "$h/.ssh"` + "\n")
	b.WriteString(`chown "$p" "$h"` + "\n")
	return b.String(), nil
}

// teardownScript removes the account, its home, and its processes.
//
// It is IDEMPOTENT — every step tolerates the thing already being gone, so the
// normal path, an error path, and a reaper sweep can all run it — and it
// VERIFIES, because a teardown that reports success it did not achieve is worse
// than one that fails loudly: the account it left behind is a standing login on
// a production host, and nothing else in the system is watching for it.
func (a *EphemeralAuthenticator) teardownScript(principal, home string) (string, error) {
	if err := validatePrincipal(principal); err != nil {
		return "", err
	}
	if err := validatePath(home); err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "p=%s\n", quote(principal))
	fmt.Fprintf(&b, "h=%s\n", quote(home))
	// The user's processes go first: userdel refuses while the account is in
	// use, and a session that outlived its credentials is the case this whole
	// method exists to prevent.
	b.WriteString(`pkill -KILL -u "$p" >/dev/null 2>&1 || true` + "\n")
	b.WriteString(`userdel -r "$p" >/dev/null 2>&1 || userdel "$p" >/dev/null 2>&1 || true` + "\n")
	// -r may leave the home behind (a mail spool it could not remove aborts it
	// on some systems), and a home directory holding an authorized_keys file is
	// the half of the credential that still matters.
	b.WriteString(`rm -rf "$h"` + "\n")
	fmt.Fprintf(&b, "if id -u \"$p\" >/dev/null 2>&1; then echo \"account still present\" >&2; exit %d; fi\n", exitUserRemains)
	fmt.Fprintf(&b, "if [ -e \"$h\" ]; then echo \"home directory still present\" >&2; exit %d; fi\n", exitHomeRemains)
	b.WriteString("exit 0\n")
	return b.String(), nil
}

// discoverScript lists this proxy's ephemeral accounts and the age of each.
//
// It reads the account database rather than the home directories: a session
// that died between useradd and the key write leaves an account with no home,
// and a sweep that only looked at /home would walk straight past it. The
// timestamp is the home directory's mtime, and a missing home reports 0 —
// which reads as "older than any grace period" and gets the half-created
// account removed, which is exactly right.
func (a *EphemeralAuthenticator) discoverScript() (string, error) {
	if err := validateScriptValue("principal prefix", a.prefix); err != nil {
		return "", err
	}
	var b strings.Builder
	// The target's own clock, so ages are measured where the timestamps were
	// written. See Reaper.parseDiscovery.
	b.WriteString(`printf 'now\t%s\n' "$(date +%s 2>/dev/null || echo 0)"` + "\n")
	b.WriteString("{ getent passwd 2>/dev/null || cat /etc/passwd 2>/dev/null; } |\n")
	b.WriteString(`while IFS=: read -r n x u g c h s; do` + "\n")
	b.WriteString("  case \"$n\" in\n")
	fmt.Fprintf(&b, "    %s*) ;;\n", quote(a.prefix))
	b.WriteString("    *) continue ;;\n")
	b.WriteString("  esac\n")
	b.WriteString("  t=0\n")
	b.WriteString(`  if [ -n "$h" ] && [ -d "$h" ]; then` + "\n")
	b.WriteString(`    t=$(stat -c %Y "$h" 2>/dev/null || stat -f %m "$h" 2>/dev/null || echo 0)` + "\n")
	b.WriteString("  fi\n")
	b.WriteString(`  printf '%s\t%s\t%s\n' "$n" "$t" "$h"` + "\n")
	b.WriteString("done\n")
	return b.String(), nil
}

// homeFor is where an ephemeral account's home directory goes.
func (a *EphemeralAuthenticator) homeFor(principal string) string {
	return strings.TrimSuffix(a.homeBase, "/") + "/" + principal
}

// validatePath accepts an absolute path made of characters that mean themselves
// in a shell. It is applied to configuration, not to anything a user or the
// management server can influence, so it can afford to be strict: an operator
// with a space in a home base can change the home base.
func validatePath(p string) error {
	if p == "" {
		return fmt.Errorf("%w: empty path", ErrInvalidScriptValue)
	}
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("%w: %q is not absolute", ErrInvalidScriptValue, p)
	}
	for _, r := range p {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '/', r == '.', r == '-', r == '_':
		default:
			return fmt.Errorf("%w: %q contains %q", ErrInvalidScriptValue, p, string(r))
		}
	}
	if strings.Contains(p, "..") {
		return fmt.Errorf("%w: %q contains %q", ErrInvalidScriptValue, p, "..")
	}
	return nil
}

// validateScriptValue rejects the characters that would end a quoted string or
// a line. shellQuote already handles both; this is the second lock on a door
// that opens onto root on a production host.
func validateScriptValue(what, v string) error {
	if v == "" {
		return fmt.Errorf("%w: empty %s", ErrInvalidScriptValue, what)
	}
	if strings.ContainsAny(v, "'\n\r\x00") {
		return fmt.Errorf("%w: %s contains a quote or newline", ErrInvalidScriptValue, what)
	}
	return nil
}

// quote is shellQuote under the name that reads better inside a script builder.
func quote(s string) string { return shellQuote(s) }
