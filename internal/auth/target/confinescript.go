// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hoplock/proxy/internal/control"
)

// The target-side shell for the enforcement rungs. It is script.go's companion
// and it obeys the same three properties: provisioning is idempotent, teardown
// is idempotent AND verifies, and discovery lists only this proxy's artefacts.
//
// TEARDOWN HERE IS UNCONDITIONAL. It removes every rung's state for a principal
// whether or not that rung was rendered, tolerating each absence, because the
// orphan reaper runs the same script for an account it has never seen and
// cannot know what the session that created it was standing on. A teardown that
// needed to be told what to remove would be a teardown the crash path could not
// run, which is the half of the guarantee PLAN §5.1 says has to survive the
// process dying.

// The literal tab and newline the dispatcher's own parsing needs. They are
// named because a tab inside a bracket expression is invisible in a diff and
// somebody will otherwise "tidy" it into a space.
const (
	scriptTab = "\t"
	// dispatcherCharSet is what a request may be made of: letters, digits, the
	// punctuation a path or an option needs, and the two separators. Everything
	// else — a quote, a dollar, a semicolon, a backquote, a newline, a glob — is
	// denied before matching starts.
	//
	// It is an ALLOW-LIST OF CHARACTERS rather than a deny-list of shell
	// syntax, which is the same argument D12 makes one level up: a deny-list is
	// incomplete on the day it ships. The "-" is last because a "-" anywhere
	// else in a bracket expression is a range.
	//
	// The two separators are BACKSLASH-ESCAPED and that is not decoration: a
	// `case` pattern is a WORD, and an unquoted blank inside one ends it —
	// dash rejects the unescaped form outright ("word unexpected"), and a shell
	// that accepted it would be matching against a pattern nobody wrote.
	dispatcherCharSet = "\\ \\" + scriptTab + "A-Za-z0-9_=/.:,+@%-"
)

// dispatcherScript is the program `command=` runs and the account's login
// shell.
//
// It is the BOUNDARY the account-restricted rung claims, and every line of it
// is load-bearing:
//
//   - it is DEFAULT-DENY. Anything it does not positively recognise exits
//     without running a command. PLAN §6.5 records the classic mistake of the
//     opposite arrangement — a dispatcher that passes SSH_ORIGINAL_COMMAND to a
//     shell is "wide open", and the rung is the dispatcher rather than the
//     option that invokes it;
//   - it NEVER INTERPOSES A SHELL. The request is split into an argument vector
//     with globbing disabled and executed with exec; nothing re-expands what
//     was approved, which is the property D12 requires of restricted exec;
//   - it accepts a CONSERVATIVE CHARACTER SET rather than rejecting a list of
//     metacharacters. An allow-list of characters cannot be incomplete on the
//     day it ships, which a deny-list of shell syntax always is;
//   - it is the account's LOGIN SHELL as well as its forced command, so a login
//     that reaches the account by another route — su, cron, a second key — lands
//     here too. A shell invokes it as `-c <command>`, and that form is read only
//     when SSH_ORIGINAL_COMMAND is absent: when the key's `command=` fired, the
//     `-c` argument is this script's own path and the user's request is in the
//     environment variable.
//
// A RESTRICTED SHELL IS DELIBERATELY NOT THE LOGIN SHELL, and this is the one
// place the mechanism departs from PLAN §6.5's candidate row. A restricted
// shell refuses to execute a command name containing "/", and the dispatcher
// must live outside the account's home (the home is mounted noexec under
// account-confined), so rbash as the login shell would refuse the dispatcher
// and every session on the rung would fail. What survives of that row is the
// half that composes: the CURATED PATH, which this script sets as the account's
// whole search path before it execs. That is a GUARDRAIL and it is described as
// one here, in 0018's words — it adds depth beneath the boundary, and any
// interpreter reachable through it ends what it is worth.
func (c *confinement) dispatcherScript() (string, error) {
	binDir := c.dir + "/" + curatedBinName
	if err := validatePath(binDir); err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("# Hoplock ephemeral-account command dispatcher. Generated per session; do not edit.\n")
	b.WriteString("set -u\n")
	b.WriteString("deny() {\n")
	b.WriteString("  echo 'hoplock: this account may run only the commands its policy names' >&2\n")
	b.WriteString("  exit 126\n")
	b.WriteString("}\n")

	// run is the only path out of this script that executes anything.
	b.WriteString("run() {\n")
	fmt.Fprintf(&b, "  PATH=%s\n", quote(binDir))
	b.WriteString("  export PATH\n")
	if c.noNewPrivs {
		// account-confined's "cannot gain privilege", made of the thing that
		// actually delivers it. It is FAIL-CLOSED: a target that lost setpriv
		// between the probe and this login runs nothing, rather than running
		// the command without the confinement its record claims.
		b.WriteString("  for s in /usr/bin/setpriv /bin/setpriv /usr/sbin/setpriv /sbin/setpriv; do\n")
		b.WriteString("    if [ -x \"$s\" ]; then exec \"$s\" --no-new-privs -- \"$@\"; fi\n")
		b.WriteString("  done\n")
		b.WriteString("  echo 'hoplock: this account is confined and the confinement is unavailable' >&2\n")
		b.WriteString("  exit 126\n")
	} else {
		b.WriteString("  exec \"$@\"\n")
	}
	b.WriteString("}\n")

	// The request. SSH_ORIGINAL_COMMAND is what the key's command= option
	// leaves behind; `-c` is how any shell is invoked for an exec request.
	b.WriteString("cmd=${SSH_ORIGINAL_COMMAND-}\n")
	b.WriteString("if [ -z \"$cmd\" ] && [ \"${1-}\" = '-c' ]; then cmd=${2-}; fi\n")
	b.WriteString("[ -n \"$cmd\" ] || deny\n")
	// The conservative character set. A request holding anything else — a
	// quote, a dollar, a semicolon, a backquote, a newline, a glob — is denied
	// before matching starts, which is D12's rule for restricted exec one layer
	// further down.
	// Built by concatenation rather than by a format string: the set holds a
	// literal tab and a "%", and every layer of quoting between here and the
	// target's shell is one more chance to render a pattern that means
	// something else.
	b.WriteString("case \"$cmd\" in\n  *[!" + dispatcherCharSet + "]*) deny ;;\nesac\n")
	b.WriteString("set -f\n")
	fmt.Fprintf(&b, "IFS=' %s'\n", scriptTab)
	// Word splitting with globbing off: the vector, and nothing expanded.
	b.WriteString("set -- $cmd\n")
	b.WriteString("[ \"$#\" -gt 0 ] || deny\n")

	for i, cmdSpec := range c.commands {
		fragment, err := matcherFunc(i, cmdSpec)
		if err != nil {
			return "", err
		}
		b.WriteString(fragment)
	}
	for i := range c.commands {
		fmt.Fprintf(&b, "if try_%d \"$@\"; then run \"$@\"; fi\n", i)
	}
	b.WriteString("deny\n")
	return b.String(), nil
}

// matcherFunc renders one allow-list entry as a shell function over the
// positional parameters.
//
// The rendering mirrors internal/filter's RestrictedExec semantics element for
// element, because the two must agree: the proxy denies at the exec request and
// this denies at the account, and a session that got past one and not the other
// would make one of the two records wrong. In particular ARGUMENTS NOT COVERED
// BY A SPEC ARE DENIED — there is no trailing allowance and no wildcard tail,
// so a vector longer than the spec never matches.
func matcherFunc(index int, cmd control.RestrictedCommand) (string, error) {
	if err := validateScriptValue("allow-listed executable", cmd.Executable); err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "try_%d() {\n", index)
	fmt.Fprintf(&b, "  [ \"$1\" = %s ] || return 1\n", quote(cmd.Executable))

	switch cmd.Form {
	case control.CommandFormExact, "":
		fmt.Fprintf(&b, "  [ \"$#\" -eq %d ] || return 1\n", len(cmd.Argv)+1)
		for i, arg := range cmd.Argv {
			if err := validateArgValue(arg); err != nil {
				return "", err
			}
			fmt.Fprintf(&b, "  [ \"$%d\" = %s ] || return 1\n", i+2, quote(arg))
		}
	case control.CommandFormPositional:
		required := 0
		for _, spec := range cmd.Args {
			if !spec.Optional {
				required++
			}
		}
		fmt.Fprintf(&b, "  [ \"$#\" -ge %d ] || return 1\n", required+1)
		fmt.Fprintf(&b, "  [ \"$#\" -le %d ] || return 1\n", len(cmd.Args)+1)
		for i, spec := range cmd.Args {
			test, err := argTest(i+2, spec)
			if err != nil {
				return "", err
			}
			if test == "" {
				continue
			}
			fmt.Fprintf(&b, "  if [ \"$#\" -ge %d ]; then\n    %s\n  fi\n", i+2, test)
		}
	default:
		return "", fmt.Errorf("%w: unknown command form %q", ErrRungUnavailable, cmd.Form)
	}
	b.WriteString("  return 0\n}\n")
	return b.String(), nil
}

// argTest renders one argument position's check, or "" when the spec
// constrains nothing.
func argTest(pos int, spec control.ArgumentSpec) (string, error) {
	switch spec.Kind {
	case control.ArgumentLiteral:
		if err := validateArgValue(spec.Value); err != nil {
			return "", err
		}
		return fmt.Sprintf("[ \"$%d\" = %s ] || return 1", pos, quote(spec.Value)), nil
	case control.ArgumentPrefix:
		if err := validateArgValue(spec.Value); err != nil {
			return "", err
		}
		return fmt.Sprintf("case \"$%d\" in %s*) ;; *) return 1 ;; esac", pos, quote(spec.Value)), nil
	case control.ArgumentOneOf:
		if len(spec.Values) == 0 {
			return "", fmt.Errorf("%w: a oneof argument names no values", ErrRungUnavailable)
		}
		patterns := make([]string, 0, len(spec.Values))
		for _, v := range spec.Values {
			if err := validateArgValue(v); err != nil {
				return "", err
			}
			patterns = append(patterns, quote(v))
		}
		return fmt.Sprintf("case \"$%d\" in %s) ;; *) return 1 ;; esac", pos, strings.Join(patterns, "|")), nil
	case control.ArgumentAny:
		// Named rather than smuggled in as an empty prefix, exactly as the
		// contract names it: it is the one shape here that is not a boundary,
		// and a reviewer should be able to find every use of it by searching.
		return "", nil
	default:
		return "", fmt.Errorf("%w: unknown argument kind %q", ErrRungUnavailable, spec.Kind)
	}
}

// validateArgValue is validateScriptValue for a policy argument, with the extra
// rule that a shell PATTERN character cannot appear in something rendered into
// a `case` pattern. A literal "*" in a policy would otherwise become a wildcard
// on the target and widen the allow-list the proxy holds.
func validateArgValue(v string) error {
	if err := validateScriptValue("allow-listed argument", v); err != nil {
		return err
	}
	if strings.ContainsAny(v, "*?[]|()") {
		return fmt.Errorf("%w: allow-listed argument %q contains a shell pattern character, which the target-side matcher cannot render without widening it",
			ErrInvalidScriptValue, v)
	}
	return nil
}

// provisionFragment is what the provisioning script does after the account
// exists.
//
// Order is a property rather than a preference. The account is created first —
// script.go does that — so that every artefact this fragment creates has an
// account to be attributed to: a residue with no account can then only be an
// orphan, never a session mid-provision, which is what lets the reaper remove
// one without a grace period. The packet filter goes last because it is keyed
// on the uid, which does not exist until the account does.
func (a *EphemeralAuthenticator) confineProvisionFragment(c *confinement) (string, error) {
	if c == nil || (!c.dispatcher && c.egress == nil && !c.noexecHome) {
		return "", nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "c=%s\n", quote(c.dir))

	if c.dispatcher {
		dispatch, err := c.dispatcherScript()
		if err != nil {
			return "", err
		}
		if strings.Contains(dispatch, dispatchHeredoc) {
			return "", fmt.Errorf("%w: the rendered dispatcher contains its own heredoc delimiter", ErrInvalidScriptValue)
		}
		// Rebuilt rather than merged: a leftover directory from a crashed
		// session with this name must end up holding THIS session's allow-list
		// and nothing else, which is the same rule script.go applies to
		// authorized_keys.
		fmt.Fprintf(&b, "rm -rf \"$c\" || exit %d\n", exitConfineFailed)
		fmt.Fprintf(&b, "mkdir -p \"$c/%s\" || exit %d\n", curatedBinName, exitConfineFailed)
		// Root-owned and not writable by the account: an allow-list the session
		// could rewrite is not an allow-list.
		b.WriteString("chmod 755 \"$c\" \"$c/" + curatedBinName + "\"\n")
		for _, exe := range curatedExecutables(c.commands) {
			// Resolved on the TARGET, at provisioning time. The proxy performs
			// no PATH search of its own — internal/filter matches argv[0]
			// exactly as the user wrote it — so this is the one place a name
			// becomes a path, and it becomes one only inside a directory the
			// account cannot write.
			fmt.Fprintf(&b, "t=$(command -v %s 2>/dev/null || true)\n", quote(exe))
			fmt.Fprintf(&b, "if [ -n \"$t\" ]; then ln -sf \"$t\" \"$c/%s/%s\"; fi\n",
				curatedBinName, exe)
		}
		fmt.Fprintf(&b, "cat > \"$c/%s\" <<'%s'\n%s%s\n", dispatcherName, dispatchHeredoc, dispatch, dispatchHeredoc)
		fmt.Fprintf(&b, "chmod 555 \"$c/%s\" || exit %d\n", dispatcherName, exitConfineFailed)
	}

	if c.noexecHome {
		// account-confined's "cannot execute what the session wrote". The bind
		// is onto the home itself so that nothing outside it is affected, and
		// the remount is what carries the flags: a plain bind inherits the
		// parent filesystem's options.
		fmt.Fprintf(&b, "mount --bind \"$h\" \"$h\" || exit %d\n", exitConfineFailed)
		fmt.Fprintf(&b, "mount -o remount,bind,noexec,nosuid,nodev \"$h\" || exit %d\n", exitConfineFailed)
	}

	if c.egress != nil {
		fragment, err := c.egressFragment()
		if err != nil {
			return "", err
		}
		b.WriteString(fragment)
	}
	return b.String(), nil
}

// dispatchHeredoc delimits the dispatcher inside the provisioning script. It is
// quoted at the point of use, so nothing in the dispatcher is expanded by the
// shell that writes it.
const dispatchHeredoc = "HOPLOCK_DISPATCH_EOF"

// exitConfineFailed is a rung that could not be rendered. It is distinct from
// exitCreateFailed so that "the account could not be created" and "the account
// could not be confined" are never confused: the second one is a session that
// must not run, and the failure isolation in Provision removes what it made.
const exitConfineFailed = 96

// curatedExecutables lists the bare executable names the curated PATH must
// carry, deduplicated and ordered so two identical policies render identically.
// An entry naming an absolute path needs no symlink and gets none.
func curatedExecutables(cmds []control.RestrictedCommand) []string {
	seen := map[string]bool{}
	var names []string
	for _, cmd := range cmds {
		name := cmd.Executable
		if name == "" || strings.Contains(name, "/") || seen[name] {
			continue
		}
		if validateScriptValue("allow-listed executable", name) != nil {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// egressFragment installs this session's per-uid packet filter.
//
// EVERY RULE CARRIES A COMMENT NAMING THE ACCOUNT, and that is not decoration:
// teardown and the orphan reaper find rules by that comment, which is what
// makes a rule whose account is already gone findable at all. A uid is not a
// name — `useradd` reuses freed uids — so a rule identified only by the uid it
// matches is a rule nobody can attribute after the account goes.
func (c *confinement) egressFragment() (string, error) {
	var b strings.Builder
	tag := ruleTagPrefix + c.principal
	if err := validateScriptValue("rule tag", tag); err != nil {
		return "", err
	}
	fmt.Fprintf(&b, "u=$(id -u \"$p\") || exit %d\n", exitConfineFailed)
	fmt.Fprintf(&b, "tag=%s\n", quote(tag))

	if c.egress.isolate {
		// "Reaches nothing off the host": loopback is what is left, and it is
		// permitted because the rung's sentence is about what leaves the host.
		for _, bin := range []string{"iptables", "ip6tables"} {
			fmt.Fprintf(&b, "%s -A OUTPUT -m owner --uid-owner \"$u\" -o lo -m comment --comment \"$tag\" -j ACCEPT || exit %d\n",
				bin, exitConfineFailed)
		}
	} else {
		for _, rule := range c.egress.rules {
			fragment, err := rule.render()
			if err != nil {
				return "", err
			}
			b.WriteString(fragment)
		}
	}
	// The default-reject, on BOTH families, always. A REJECT rather than a DROP
	// because the rung's failure mode has to be a refused connection rather
	// than a hang: a process that hangs on a denied destination looks like a
	// broken network to whoever is watching, and the whole point of an
	// enforcement point is that its refusals are legible.
	//
	// THIS DOES NOT CUT THE SSH SESSION IT CONFINES, and the temptation to
	// "fix" that by exempting port 22 is a hole big enough to drive the whole
	// reach axis through — it would let a confined session reach any host in
	// the estate on 22. The owner match reads the socket's sk_uid, fixed at
	// socket CREATION: sshd accepted this connection as root before it dropped
	// to the ephemeral account, so it carries uid 0 for its whole life and
	// never matches. Only sockets the session opens for itself do. PLAN §6.5,
	// "A default-REJECT on the session's own uid", has the long version and
	// names the tests that pin both halves.
	for _, bin := range []string{"iptables", "ip6tables"} {
		reject := "icmp-port-unreachable"
		if bin == "ip6tables" {
			reject = "icmp6-port-unreachable"
		}
		fmt.Fprintf(&b, "%s -A OUTPUT -m owner --uid-owner \"$u\" -m comment --comment \"$tag\" -j REJECT --reject-with %s || exit %d\n",
			bin, reject, exitConfineFailed)
	}
	return b.String(), nil
}

// render is one permitted destination as an iptables rule.
//
// A destination naming a PORT is rendered for TCP and UDP alike, because the
// vocabulary an operator writes says "this host on this port" and says nothing
// about a protocol. A destination naming no port names no protocol either.
func (r egressRule) render() (string, error) {
	bin := "iptables"
	if r.v6 {
		bin = "ip6tables"
	}
	if r.dest != "" {
		if err := validateScriptValue("permitted destination", r.dest); err != nil {
			return "", err
		}
	}
	dest := ""
	if r.dest != "" {
		dest = " -d " + quote(r.dest)
	}
	var b strings.Builder
	if r.ports == "" {
		fmt.Fprintf(&b, "%s -A OUTPUT -m owner --uid-owner \"$u\"%s -m comment --comment \"$tag\" -j ACCEPT || exit %d\n",
			bin, dest, exitConfineFailed)
		return b.String(), nil
	}
	if err := validateScriptValue("permitted port", r.ports); err != nil {
		return "", err
	}
	for _, proto := range []string{"tcp", "udp"} {
		fmt.Fprintf(&b, "%s -A OUTPUT -m owner --uid-owner \"$u\"%s -p %s --dport %s -m comment --comment \"$tag\" -j ACCEPT || exit %d\n",
			bin, dest, proto, quote(r.ports), exitConfineFailed)
	}
	return b.String(), nil
}

// confineTeardownFragment removes every rung's state for one principal.
//
// It runs for EVERY teardown, including one for an account this proxy has never
// seen, which is why nothing in it is conditional on what was rendered. The
// ordering below is the phase's teardown contract and each step is there for a
// failure somebody has actually had:
//
//  1. the key goes first, so a teardown that fails halfway has already closed
//     the account to new logins rather than leaving one that outlives its
//     boundary;
//  2. the account's processes go next, because userdel refuses while the
//     account is in use;
//  3. THE PACKET FILTER RULES GO BEFORE THE ACCOUNT. `useradd` reuses freed
//     uids, so a rule that outlives its account silently attaches to whoever
//     gets that uid next — an egress boundary quietly transplanted onto an
//     unrelated session, or an allow-list transplanted onto one that was
//     supposed to have none. This ordering is the whole of that fix on this
//     side; phase 0024's non-reusing range is the other half;
//  4. the mount goes before the home is removed, because rm -rf on a mount
//     point empties the mounted filesystem and leaves the directory;
//  5. everything is VERIFIED, and a verification failure is loud. A teardown
//     that reports a success it did not achieve is worse than one that fails.
func confineTeardownFragment(base string) (string, error) {
	if err := validatePath(base); err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "c=%s/\"$p\"\n", quote(strings.TrimSuffix(base, "/")))
	fmt.Fprintf(&b, "tag=%s\"$p\"\n", quote(ruleTagPrefix))
	b.WriteString(`purge_rules() {` + "\n")
	b.WriteString(`  b=$1` + "\n")
	b.WriteString(`  command -v "$b" >/dev/null 2>&1 || return 0` + "\n")
	b.WriteString(`  i=0` + "\n")
	b.WriteString(`  while [ "$i" -lt 64 ]; do` + "\n")
	b.WriteString(`    n=$("$b" -L OUTPUT -n --line-numbers 2>/dev/null | awk -v t="$tag" 'index($0, t) { print $1; exit }')` + "\n")
	b.WriteString(`    [ -n "$n" ] || break` + "\n")
	b.WriteString(`    "$b" -D OUTPUT "$n" >/dev/null 2>&1 || break` + "\n")
	b.WriteString(`    i=$((i + 1))` + "\n")
	b.WriteString(`  done` + "\n")
	b.WriteString("}\n")
	b.WriteString(`rules_remain() {` + "\n")
	b.WriteString(`  for b in iptables ip6tables; do` + "\n")
	b.WriteString(`    command -v "$b" >/dev/null 2>&1 || continue` + "\n")
	b.WriteString(`    if "$b" -S OUTPUT 2>/dev/null | grep -q -- "$tag"; then return 0; fi` + "\n")
	b.WriteString(`  done` + "\n")
	b.WriteString(`  return 1` + "\n")
	b.WriteString("}\n")
	// `mount` with no arguments rather than /proc/self/mounts: the fleets this
	// method serves include BSD, which has no /proc, and every mount(8) in
	// range prints "<source> on <mountpoint> ...".
	b.WriteString(`mounted() { mount 2>/dev/null | awk -v h="$h" '{ for (i = 1; i < NF; i++) if ($i == "on" && $(i + 1) == h) { found = 1 } } END { exit !found }'; }` + "\n")
	return b.String(), nil
}

// confineDiscoverFragment lists the artefacts of a rung whose account may
// already be gone.
//
// It is the reaper's answer to "a session that died mid-rung". An account is
// created before any of these exists, so an artefact WITHOUT an account can
// only be an orphan — never a session mid-provision — which is why the reaper
// may remove one without waiting out a grace period.
func confineDiscoverFragment(base, homeBase, prefix string) (string, error) {
	if err := validatePath(base); err != nil {
		return "", err
	}
	if err := validatePath(homeBase); err != nil {
		return "", err
	}
	if err := validateScriptValue("principal prefix", prefix); err != nil {
		return "", err
	}
	base = strings.TrimSuffix(base, "/")
	homeBase = strings.TrimSuffix(homeBase, "/")

	var b strings.Builder
	// Confinement directories.
	fmt.Fprintf(&b, "for d in %s/%s*; do\n", quote(base), prefix)
	b.WriteString("  [ -d \"$d\" ] || continue\n")
	b.WriteString(`  printf 'residue\t%s\tconfinement\n' "${d##*/}"` + "\n")
	b.WriteString("done\n")
	// Mounts left over a home directory.
	b.WriteString("mount 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == \"on\") { print $(i + 1); break } }' | while read -r m; do\n")
	fmt.Fprintf(&b, "  case \"$m\" in\n    %s/%s*) printf 'residue\\t%%s\\tmount\\n' \"${m##*/}\" ;;\n  esac\n", quote(homeBase), prefix)
	b.WriteString("done\n")
	// Packet-filter rules, by the comment they carry.
	b.WriteString("for b in iptables ip6tables; do\n")
	b.WriteString("  command -v \"$b\" >/dev/null 2>&1 || continue\n")
	fmt.Fprintf(&b, "  \"$b\" -S OUTPUT 2>/dev/null | sed -n 's/.*--comment \"\\{0,1\\}%s\\([A-Za-z0-9_-]*\\)\"\\{0,1\\}.*/\\1/p'\n", ruleTagPrefix)
	b.WriteString("done | sort -u | while read -r n; do\n")
	b.WriteString("  [ -n \"$n\" ] || continue\n")
	b.WriteString(`  printf 'residue\t%s\trule\n' "$n"` + "\n")
	b.WriteString("done\n")
	return b.String(), nil
}
