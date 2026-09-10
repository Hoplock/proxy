// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"errors"
	"fmt"
	"strconv"
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
	// exitUIDExhausted means every uid the proxy offered was already taken on
	// the target (phase 0027). It is its own status because the proxy answers it
	// differently from a useradd that failed: the range, not the account, is
	// what has to change.
	exitUIDExhausted = 96
	// exitUIDMarkFailed means the account was created but the target could not
	// record its uid, so the next allocation there would have nothing to
	// allocate above. It fails the session on purpose: an unrecorded uid is a
	// uid the next session may be handed, which is the defect 0027 closes.
	exitUIDMarkFailed = 97
)

// The keys the discovery script prints its uid census under (phase 0027).
// parseUIDCensus reads them; the reaper's parseDiscovery ignores them, because
// neither is a principal and neither starts with this proxy's prefix.
const (
	uidKeyInUse     = "uid"
	uidKeyWatermark = "uidmark"
)

// uidInUseFailed is the exit status for a useradd that refused a uid because
// something else holds it. It is shadow-utils' E_UID_IN_USE, verified on
// shadow 4.13 (Ubuntu 24.04, Debian stable): `useradd -u <taken>` exits 4 and
// says "UID <n> is not unique", where a duplicate NAME exits 9. The scripts
// branch on it, so it is named here beside the statuses they return.
const uidInUseFailed = 4

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
// The uid is the PROXY's to choose (phase 0027). It arrives here as a list —
// the allocation first, then the fallbacks a lost race lands on — and the script
// prints the uid it ended up with, because that is not always one of them: an
// adopted account from a crashed session keeps the uid it already had, and the
// audit record has to name the uid that exists rather than the one that was
// asked for.
func (a *EphemeralAuthenticator) provisionScript(c *confinement, authorizedKey string, uids []int) (string, error) {
	principal, home := c.principal, c.home
	if len(uids) == 0 {
		return "", fmt.Errorf("%w: no uid was allocated for %s", ErrUIDUnavailable, principal)
	}
	if err := validatePrincipal(principal); err != nil {
		return "", err
	}
	if err := validatePath(home); err != nil {
		return "", err
	}
	if err := validateScriptValue("authorized key", authorizedKey); err != nil {
		return "", err
	}
	// The account's login shell is the DISPATCHER wherever one is rendered, so
	// that a login reaching this account by another route — su, cron, a second
	// key — lands on the same boundary as the one the key forces. Where no rung
	// is rendered it is the proxy's configured target shell, unchanged from
	// phase 0007.
	shell := a.shell
	if c.dispatcher {
		shell = c.dir + "/" + dispatcherName
	}
	if err := validatePath(shell); err != nil {
		return "", err
	}
	confine, err := a.confineProvisionFragment(c)
	if err != nil {
		return "", err
	}

	mark, err := a.uidWatermarkPath()
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("set -eu\n")
	fmt.Fprintf(&b, "p=%s\n", quote(principal))
	fmt.Fprintf(&b, "h=%s\n", quote(home))
	fmt.Fprintf(&b, "w=%s\n", quote(mark))
	b.WriteString(`if ! id -u "$p" >/dev/null 2>&1; then` + "\n")
	// -u AND NOT -K. `-K UID_MIN=…` only moves the range the target's own
	// allocator searches; inside that range it still hands back the uid a
	// torn-down account held, which is the whole defect (see uid.go, measured).
	// The uid therefore has to be chosen off-target and passed explicitly.
	//
	// The loop exists for ONE case: another provisioner taking this uid between
	// the census and this call. Only shadow's "uid is not unique" is retried —
	// every other failure is this account's own and is reported as one, rather
	// than being retried seven times and then reported as an exhausted range.
	b.WriteString("  created=no\n")
	fmt.Fprintf(&b, "  for u in %s; do\n", uidList(uids))
	b.WriteString("    st=0\n")
	fmt.Fprintf(&b, "    useradd -m -d \"$h\" -s %s -u \"$u\" \"$p\" 2>/dev/null || st=$?\n", quote(shell))
	b.WriteString("    if [ \"$st\" -eq 0 ]; then created=yes; break; fi\n")
	fmt.Fprintf(&b, "    if [ \"$st\" -ne %d ]; then exit %d; fi\n", uidInUseFailed, exitCreateFailed)
	b.WriteString("  done\n")
	fmt.Fprintf(&b, "  if [ \"$created\" != yes ]; then exit %d; fi\n", exitUIDExhausted)
	b.WriteString("fi\n")
	// Reported before anything else can fail, and read from the account database
	// rather than assumed from the loop above, so the record names the uid the
	// target actually holds.
	fmt.Fprintf(&b, "uid=$(id -u \"$p\") || exit %d\n", exitCreateFailed)
	fmt.Fprintf(&b, "printf '%s\\t%%s\\n' \"$uid\"\n", uidKeyInUse)
	// The watermark is what makes the invariant survive this session, this
	// process, and this proxy: the next allocation on this target allocates
	// strictly above it. A uid that could not be recorded is a uid the next
	// session may be handed, so this failing FAILS THE SESSION — the account is
	// removed by the caller's cleanup, and the operator is told a directory is
	// not writable rather than silently getting reuse back.
	//
	// The mark is a directory whose FILENAMES are the uids, and that shape is
	// load-bearing: two provisioners on one target run at the same time (PLAN
	// §5.1, and phase 0026 asserts the overlap), and a single file holding the
	// number would be a read-modify-write between them — interleave two and the
	// mark goes BACKWARDS over a uid that is still in use, which is the reuse
	// this phase exists to prevent, reintroduced by the fix. Creating a file
	// named after the uid is atomic and reads nothing, so the maximum can only
	// ever move up.
	//
	// ROOT-OWNED AND ROOT-ONLY, re-established on every provisioning rather than
	// assumed from whatever `mkdir -p` found. Lowering the mark is the one way to
	// make this proxy hand out a uid it has already used, so the directory that
	// holds it gets the same treatment as the dispatcher next to it: a mark a
	// session could delete is not a mark. `mkdir -p` leaves an existing
	// directory's mode alone, so setting it here is what covers a base an
	// operator pointed somewhere permissive, and a provisioning shell with an
	// unusual umask. It is 700 rather than the dispatcher's 755 because nothing
	// but the provisioner ever reads it.
	fmt.Fprintf(&b, "mkdir -p \"$w\" || exit %d\n", exitUIDMarkFailed)
	fmt.Fprintf(&b, "chown 0:0 \"${w%%/*}\" \"$w\" || exit %d\n", exitUIDMarkFailed)
	fmt.Fprintf(&b, "chmod 755 \"${w%%/*}\" || exit %d\n", exitUIDMarkFailed)
	fmt.Fprintf(&b, "chmod 700 \"$w\" || exit %d\n", exitUIDMarkFailed)
	fmt.Fprintf(&b, ": > \"$w/$uid\" || exit %d\n", exitUIDMarkFailed)
	// Pruning keeps the directory at one entry without ever removing a mark
	// ABOVE this one, so a concurrent provisioner that allocated higher is never
	// erased. A lower mark left behind by a racer is harmless: the maximum is
	// what is read.
	b.WriteString(`for f in "$w"/*; do` + "\n")
	b.WriteString(`  n=${f##*/}` + "\n")
	b.WriteString(`  case "$n" in ''|*[!0-9]*) continue ;; esac` + "\n")
	b.WriteString(`  if [ "$n" -lt "$uid" ]; then rm -f "$f" || true; fi` + "\n")
	b.WriteString("done\n")
	if c.dispatcher {
		// A leftover account from another session's crash must end up on THIS
		// session's terms, and the login shell is one of them: an adopted
		// account still pointing at a previous session's dispatcher would run a
		// previous session's allow-list. It runs only where a dispatcher is
		// rendered, because that is the only case where the shell is this
		// phase's to change.
		fmt.Fprintf(&b, "usermod -s %s \"$p\" >/dev/null 2>&1 || true\n", quote(shell))
	}
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
	// The enforcement rungs come LAST, and after the account exists, so that
	// every artefact they create has an account to be attributed to. See
	// confineProvisionFragment for why that ordering is what lets the reaper
	// remove a residue without a grace period.
	b.WriteString(confine)
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
	confine, err := confineTeardownFragment(a.enforceBase)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "p=%s\n", quote(principal))
	fmt.Fprintf(&b, "h=%s\n", quote(home))
	b.WriteString(confine)
	// The key goes first. A teardown that fails halfway has then already closed
	// the account to new logins, rather than leaving one that outlives the
	// enforcement rung the rest of this script is removing.
	b.WriteString(`rm -f "$h/.ssh/authorized_keys" >/dev/null 2>&1 || true` + "\n")
	// The user's processes go next: userdel refuses while the account is in
	// use, and a session that outlived its credentials is the case this whole
	// method exists to prevent.
	b.WriteString(`pkill -KILL -u "$p" >/dev/null 2>&1 || true` + "\n")
	// BEFORE the account, always. See confineTeardownFragment: `useradd` reuses
	// freed uids, so a uid-keyed rule that outlives its account silently
	// attaches to whoever gets that uid next. Since phase 0027 this proxy chooses
	// the uid and never reuses one, which removes the way that happens on the
	// provisioning path — and not the reason for this ordering, which is a
	// teardown that fails halfway on a target whose range was widened or
	// misconfigured.
	b.WriteString("purge_rules iptables\n")
	b.WriteString("purge_rules ip6tables\n")
	// Before the home is removed: rm -rf on a mount point empties the mounted
	// filesystem and leaves the directory behind.
	b.WriteString("i=0\n")
	b.WriteString(`while [ "$i" -lt 8 ] && mounted; do` + "\n")
	b.WriteString(`  umount "$h" >/dev/null 2>&1 || umount -l "$h" >/dev/null 2>&1 || break` + "\n")
	b.WriteString("  i=$((i + 1))\n")
	b.WriteString("done\n")
	b.WriteString(`userdel -r "$p" >/dev/null 2>&1 || userdel "$p" >/dev/null 2>&1 || true` + "\n")
	// -r may leave the home behind (a mail spool it could not remove aborts it
	// on some systems), and a home directory holding an authorized_keys file is
	// the half of the credential that still matters.
	b.WriteString(`rm -rf "$h"` + "\n")
	b.WriteString(`rm -rf "$c"` + "\n")
	fmt.Fprintf(&b, "if rules_remain; then echo \"packet filter rules still present\" >&2; exit %d; fi\n", exitRuleRemains)
	fmt.Fprintf(&b, "if mounted; then echo \"home directory is still mounted\" >&2; exit %d; fi\n", exitMountRemains)
	fmt.Fprintf(&b, "if id -u \"$p\" >/dev/null 2>&1; then echo \"account still present\" >&2; exit %d; fi\n", exitUserRemains)
	fmt.Fprintf(&b, "if [ -e \"$h\" ]; then echo \"home directory still present\" >&2; exit %d; fi\n", exitHomeRemains)
	fmt.Fprintf(&b, "if [ -e \"$c\" ]; then echo \"confinement directory still present\" >&2; exit %d; fi\n", exitConfineRemains)
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
	// The uid census (phase 0027), taken over EVERY account rather than only
	// this proxy's: a uid is not available because no ephemeral account holds
	// it, it is available because NOTHING holds it — another proxy's account and
	// a local one an operator put in the range both count.
	b.WriteString(`  case "$u" in ''|*[!0-9]*) u=-1 ;; esac` + "\n")
	fmt.Fprintf(&b, "  if [ \"$u\" -ge %d ] && [ \"$u\" -le %d ]; then printf '%s\\t%%s\\n' \"$u\"; fi\n",
		a.uids.min, a.uids.max, uidKeyInUse)
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
	// The high-water mark, which is the half of the census an account database
	// cannot supply: it is what the range has ever handed out, not what it holds
	// now, and it is the only thing that stops a torn-down account's uid being
	// allocated straight back (phase 0027). A missing or unreadable marker reads
	// as 0, which leaves the accounts above as the only evidence — right for a
	// target nothing has provisioned on, and the reason the marker is WRITTEN on
	// the provisioning path rather than trusted to exist.
	mark, err := a.uidWatermarkPath()
	if err != nil {
		return "", err
	}
	fmt.Fprintf(&b, "w=%s\n", quote(mark))
	b.WriteString("hi=0\n")
	b.WriteString(`for f in "$w"/*; do` + "\n")
	b.WriteString(`  n=${f##*/}` + "\n")
	b.WriteString(`  case "$n" in ''|*[!0-9]*) continue ;; esac` + "\n")
	b.WriteString(`  if [ "$n" -gt "$hi" ]; then hi=$n; fi` + "\n")
	b.WriteString("done\n")
	fmt.Fprintf(&b, "printf '%s\\t%%s\\n' \"$hi\"\n", uidKeyWatermark)
	// The artefacts of a rung whose account may already be gone (phase 0019).
	// A session that died mid-rung is the case this exists for.
	residue, err := confineDiscoverFragment(a.enforceBase, a.homeBase, a.prefix)
	if err != nil {
		return "", err
	}
	b.WriteString(residue)
	return b.String(), nil
}

// homeFor is where an ephemeral account's home directory goes.
func (a *EphemeralAuthenticator) homeFor(principal string) string {
	return strings.TrimSuffix(a.homeBase, "/") + "/" + principal
}

// uidWatermarkPath is the target-side file recording the highest uid this system
// has ever allocated there (phase 0027).
//
// It is a SIBLING of the per-account confinement directories, not a child of
// one: teardown removes `<base>/<principal>`, and a number that has to outlive
// the account it describes cannot live inside it.
func (a *EphemeralAuthenticator) uidWatermarkPath() (string, error) {
	path := strings.TrimSuffix(a.enforceBase, "/") + "/" + uidWatermarkName
	if err := validatePath(path); err != nil {
		return "", err
	}
	return path, nil
}

// uidList renders the allocated uids as the shell word list the provisioning
// loop iterates. They are integers, so nothing here can be quoted out of.
func uidList(uids []int) string {
	parts := make([]string, 0, len(uids))
	for _, uid := range uids {
		parts = append(parts, strconv.Itoa(uid))
	}
	return strings.Join(parts, " ")
}

// parseProvisionedUID reads the uid the provisioning script reported.
//
// A script that ran and did not report one is a FAILURE rather than a silent
// zero: the uid is what the audit record joins a target's own trail to a session
// id (PLAN §5.1), and a provisioning whose uid cannot be established is one
// where nothing can promise the account is not standing on a previous
// session's files.
func parseProvisionedUID(out []byte) (int, error) {
	for _, line := range strings.Split(string(out), "\n") {
		key, value, ok := strings.Cut(strings.TrimRight(line, "\r"), "\t")
		if !ok || strings.TrimSpace(key) != uidKeyInUse {
			continue
		}
		uid, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || uid < 0 {
			continue
		}
		return uid, nil
	}
	return 0, fmt.Errorf("%w: the target reported no uid for the account it created", ErrUIDUnavailable)
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
