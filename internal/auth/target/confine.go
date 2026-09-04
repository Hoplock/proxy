// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/hoplock/proxy/internal/control"
)

// This file renders phase 0018's enforcement rungs onto the ephemeral POSIX
// account (PLAN §6.5, D12 as amended). It is the whole target-side mechanism
// for the four applied rungs a Linux host can take, and the mechanism is stated
// here rather than in the vocabulary on purpose: a rung is named after what it
// GUARANTEES so that an operator reading an audit record need not know what
// rbash is, and which mechanism this proxy reaches for is local to this
// repository.
//
// What this proxy renders, per rung:
//
//	account-restricted   an authorized_keys `command=` dispatcher plus the key's
//	                     own capability fence (`restrict`, or the individual
//	                     `no-*` options on an sshd that predates it). The
//	                     dispatcher validates SSH_ORIGINAL_COMMAND against the
//	                     route's own restricted_exec allow-list and execs the
//	                     approved argv directly, never through a shell. Beneath
//	                     it, and only as a GUARDRAIL, the account's login shell
//	                     is a restricted shell and its PATH is a curated
//	                     directory of symlinks it cannot write.
//	account-confined     the above, plus a home bind-mounted noexec,nosuid,nodev
//	                     and an exec that drops PR_SET_NO_NEW_PRIVS. Those are
//	                     the two things the rung's extra sentence names: the
//	                     session cannot execute what it wrote, and it cannot
//	                     gain privilege.
//	account-egress-      a per-uid packet filter (`-m owner --uid-owner`) on
//	  restricted         BOTH address families, permitting the route's
//	                     permitted_destinations and rejecting everything else.
//	account-network-     the same filter, permitting loopback and rejecting
//	  isolated           every off-host destination on both families.
//
// THE BOUNDARY AND THE GUARDRAIL ARE NOT THE SAME THING, and this file says so
// wherever both appear. The dispatcher is the boundary: it is default-deny, it
// parses rather than pattern-matches, and it interposes no shell. The restricted
// shell and the curated PATH are a guardrail — rbash has a long history of
// escapes and any interpreter in the curated directory ends it (PLAN §6.5) — so
// they add depth and their absence never turns a rung into a lie. A future
// reader who promotes the second sentence to the first has broken the rung
// without changing a line of shell.
//
// TWO MECHANISMS PLAN §6.5 LISTS AS CANDIDATES ARE DELIBERATELY NOT USED, and
// the learnings carry the long version:
//
//   - systemd sandboxing by a drop-in on the session's user-<uid>.slice. A
//     .slice unit takes resource control settings; the sandboxing directives the
//     rung would need (NoNewPrivileges=, ProtectSystem=, RestrictSUIDSGID=) are
//     exec-context settings that a slice does not carry, and systemd logs an
//     unknown key and proceeds. That is precisely the silently-ignored directive
//     PLAN §6.5 says a capability probe exists to catch, so this proxy does not
//     write it. setpriv and a noexec home deliver the same two guarantees with
//     nothing to misread.
//   - systemd IPAddressAllow=/IPAddressDeny= for the reach axis. It speaks
//     addresses and prefixes only, and the route's destinations carry PORTS. A
//     rung that silently widened "the database on 5432" to "that address, every
//     port" would claim a guarantee it is not delivering; the packet filter
//     renders the port.

// Where the confinement's own files live on the target.
//
// It is OUTSIDE the account's home for a reason that is the rung itself: under
// account-confined the home is mounted noexec, so a dispatcher living in it
// could not be executed. It is also root-owned and not writable by the account,
// which is what stops the session rewriting its own allow-list.
const (
	// DefaultEnforcementBase is the parent directory of per-account
	// confinement material.
	DefaultEnforcementBase = "/var/lib/hoplock"
	// dispatcherName is the per-account command dispatcher.
	dispatcherName = "dispatch"
	// curatedBinName is the per-account curated PATH directory.
	curatedBinName = "bin"
	// ruleTagPrefix marks this system's packet-filter rules. Teardown and the
	// orphan reaper both find rules BY COMMENT, which is what makes a rule
	// whose account is already gone findable at all.
	ruleTagPrefix = "hoplock:"
)

// Exit statuses the confinement adds to script.go's. They are teardown
// VERIFICATION failures: each one says a rung's state outlived the account it
// belonged to, which is the failure this phase's teardown contract exists to
// make loud.
const (
	exitRuleRemains    = 93
	exitMountRemains   = 94
	exitConfineRemains = 95
)

// confinement is one session's rendered enforcement: which mechanisms apply,
// and the paths they occupy.
//
// It is built before anything is created on the target, from the route's rungs
// and the target's probed capabilities, so that a rung this target cannot take
// is refused BEFORE a single account exists (PLAN §4.3: nothing is provisioned).
type confinement struct {
	principal string
	home      string
	// base is DefaultEnforcementBase; dir is base/<principal>.
	base string
	dir  string

	exec  control.ExecutionRung
	reach control.ReachRung

	// dispatcher says the account's key carries a command= dispatcher and the
	// allow-list it enforces. It is the BOUNDARY.
	dispatcher bool
	commands   []control.RestrictedCommand
	// restrict is the single `restrict` keyword; when false the individual
	// no-* options are written instead, which is the same fence on an sshd
	// that predates 7.2.
	restrict bool
	// shell is the account's login shell and curated says its PATH is the
	// curated directory. Both are the GUARDRAIL half.
	shell   string
	curated bool
	// noexecHome and noNewPrivs are account-confined's two extra guarantees.
	noexecHome bool
	noNewPrivs bool
	// egress is the reach axis's rendering, or nil when the reach rung needs
	// nothing of the target.
	egress *egressPlan
}

// egressPlan is the per-uid packet filter for one session.
type egressPlan struct {
	// isolate is account-network-isolated: loopback and nothing else.
	isolate bool
	// rules are the permitted destinations, already split per address family.
	rules []egressRule
}

// egressRule is one permitted destination, rendered for one address family.
type egressRule struct {
	// v6 selects ip6tables rather than iptables.
	v6 bool
	// dest is the -d argument, or empty for "any address".
	dest string
	// ports is the --dport argument ("443", "5432:5500"), or empty for every
	// port. When it is empty the rule names no protocol either, so a
	// destination written without a port permits every protocol to it — which
	// is what "the destination" means to whoever wrote the policy.
	ports string
}

// planConfinement decides what will be rendered, or refuses.
//
// It is the ONE place that maps a rung to a mechanism, and it refuses before
// creating anything. Every refusal is ErrRungUnavailable — outage-class, naming
// the session id at the layer that reports it (PLAN §4.3) — and never a
// downgrade: a session that ran a rung weaker than its record claims is the
// failure this whole phase exists to prevent.
func (a *EphemeralAuthenticator) planConfinement(e *Enforcement, p *probe, principal, home string) (*confinement, error) {
	c := &confinement{
		principal: principal,
		home:      home,
		base:      a.enforceBase,
		exec:      e.ExecutionRung(),
		reach:     e.ReachRung(),
	}
	c.dir = strings.TrimSuffix(c.base, "/") + "/" + principal
	if err := validatePath(c.dir); err != nil {
		return nil, err
	}

	caps := p.capabilities()
	now := p.at
	switch c.exec {
	case control.ExecutionProxyInspected, control.ExecutionNoInteractiveShell:
		// Proxy-side rungs: nothing is rendered on the target, and nothing has
		// to be, which is why they are unaffected by a stale or absent
		// capability record.
	case control.ExecutionAccountRestricted, control.ExecutionAccountConfined:
		if !caps.ProvidesExecution(c.exec, now, control.DefaultCapabilityTTL) {
			return nil, fmt.Errorf("%w: %s cannot provide %q (probe: %s)",
				ErrRungUnavailable, home, c.exec, probeSummary(p))
		}
		if e.RestrictedExec == nil || len(e.RestrictedExec.Commands) == 0 {
			// The policy is NOT re-authored here. An empty allow-list beside
			// this rung is a route the contract already refuses (0018), so
			// reaching it means a locally configured route — and rendering a
			// dispatcher over an allow-list this proxy invented is exactly the
			// second policy author D2 forbids.
			return nil, fmt.Errorf("%w: %q renders filter_policy.restricted_exec and the route carries none",
				ErrRungUnavailable, c.exec)
		}
		c.dispatcher = true
		c.commands = e.RestrictedExec.Commands
		c.restrict = p.yes(probeRestrict)
		c.curated = true
		c.shell = p.get(probeRestrictedShell)
		if c.shell == "" {
			// No restricted shell on this host. The guardrail narrows to the
			// curated PATH alone; the boundary is untouched, so the rung is
			// still delivered rather than refused.
			c.shell = a.shell
		}
		if c.exec == control.ExecutionAccountConfined {
			c.noexecHome, c.noNewPrivs = true, true
		}
	case control.ExecutionPlatformAuthorized, control.ExecutionPlatformAttested:
		// Both are a device's, and this method serves POSIX hosts. It is
		// ErrRungUnavailable rather than a skipped rung because the ladder has
		// already been walked by the time a POSIX provisioner is running.
		return nil, fmt.Errorf("%w: %q is a device rung and this target is administered as a POSIX host",
			ErrRungUnavailable, c.exec)
	default:
		// An unknown rung is never coerced down: running the session weaker
		// than the policy names is the one reading that is never available.
		return nil, fmt.Errorf("%w: unknown execution rung %q", ErrRungUnavailable, c.exec)
	}

	switch c.reach {
	case control.ReachProxyChannelPolicy:
	case control.ReachAccountEgressRestricted, control.ReachAccountNetworkIsolated:
		if !caps.ProvidesReach(c.reach, now, control.DefaultCapabilityTTL) {
			return nil, fmt.Errorf("%w: %s cannot provide %q (probe: %s)",
				ErrRungUnavailable, home, c.reach, probeSummary(p))
		}
		plan, err := planEgress(c.reach, e.PermittedDestinations)
		if err != nil {
			return nil, err
		}
		c.egress = plan
	case control.ReachPlatformAttested:
		return nil, fmt.Errorf("%w: %q asserts the target constrains the account already, and this method administers the account itself",
			ErrRungUnavailable, c.reach)
	default:
		return nil, fmt.Errorf("%w: unknown reach rung %q", ErrRungUnavailable, c.reach)
	}
	return c, nil
}

// probeSummary renders the observation behind a refusal, for the operator's
// half of the message. The user is told nothing of it (PLAN §4.3).
func probeSummary(p *probe) string {
	keys := make([]string, 0, len(p.values))
	for k := range p.values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+p.values[k])
	}
	return strings.Join(parts, " ")
}

// planEgress renders the route's destinations as per-uid filter rules.
//
// TWO RULES ABOUT WHAT IT REFUSES, both of which are the difference between a
// rung and a claim:
//
//   - A destination named by HOSTNAME OR WILDCARD is refused. A packet filter
//     resolves a name once, at insert time, and a rule that drifts from the
//     policy it was rendered from is worse than no rule: it is a boundary
//     nobody can audit. This is the same finding PLAN §6.5 records against
//     IPAddressAllow= and it applies to any address-shaped mechanism.
//   - BOTH ADDRESS FAMILIES ARE ALWAYS CLOSED. A destination list naming only
//     IPv4 addresses still gets an IPv6 default-reject, because a rung that
//     closes one family and leaves the other open is the exact mistake phase
//     0015 found on the device side and it is not one this side repeats.
func planEgress(rung control.ReachRung, dests []control.ForwardDestination) (*egressPlan, error) {
	if rung == control.ReachAccountNetworkIsolated {
		// The rung's whole content is "nothing off the host", so the policy
		// names nothing and loopback is what remains.
		return &egressPlan{isolate: true}, nil
	}
	if len(dests) == 0 {
		return nil, fmt.Errorf("%w: %q renders enforcement.permitted_destinations and the route names none",
			ErrRungUnavailable, rung)
	}
	plan := &egressPlan{}
	for _, d := range dests {
		dest, v6, anyFamily, err := renderDestination(d.Host)
		if err != nil {
			return nil, err
		}
		ports, err := renderPorts(d)
		if err != nil {
			return nil, err
		}
		if anyFamily {
			plan.rules = append(plan.rules,
				egressRule{v6: false, dest: "", ports: ports},
				egressRule{v6: true, dest: "", ports: ports})
			continue
		}
		plan.rules = append(plan.rules, egressRule{v6: v6, dest: dest, ports: ports})
	}
	return plan, nil
}

// renderDestination turns a policy host into a filter address.
func renderDestination(host string) (dest string, v6, anyFamily bool, err error) {
	switch host {
	case "", "*":
		// "any host" is a deliberate entry in the forwarding vocabulary and it
		// means the same here: the destination axis is unrestricted and the
		// port axis still is not.
		return "", false, true, nil
	}
	if addr, e := netip.ParseAddr(host); e == nil {
		return addr.String(), addr.Is6(), false, nil
	}
	if prefix, e := netip.ParsePrefix(host); e == nil {
		return prefix.String(), prefix.Addr().Is6(), false, nil
	}
	return "", false, false, fmt.Errorf(
		"%w: a reach rung renders addresses, and %q is a name or a pattern — "+
			"a filter resolves a name once, at insert time, so the rule would drift from the policy it claims to enforce",
		ErrRungUnavailable, host)
}

// renderPorts turns a policy destination's port into a --dport argument.
func renderPorts(d control.ForwardDestination) (string, error) {
	switch {
	case d.PortRange != nil:
		if d.PortRange.From <= 0 || d.PortRange.To < d.PortRange.From || d.PortRange.To > 65535 {
			return "", fmt.Errorf("%w: port range %d-%d cannot be rendered",
				ErrRungUnavailable, d.PortRange.From, d.PortRange.To)
		}
		return fmt.Sprintf("%d:%d", d.PortRange.From, d.PortRange.To), nil
	case d.Port > 0:
		if d.Port > 65535 {
			return "", fmt.Errorf("%w: port %d cannot be rendered", ErrRungUnavailable, d.Port)
		}
		return fmt.Sprintf("%d", d.Port), nil
	default:
		return "", nil
	}
}

// mechanisms names what was rendered, for the audit record's operator half.
func (c *confinement) mechanisms() (execMechanism, reachMechanism string) {
	if c == nil {
		return "", ""
	}
	var parts []string
	if c.dispatcher {
		fence := "no-agent-forwarding,no-port-forwarding,no-pty,no-user-rc,no-X11-forwarding"
		if c.restrict {
			fence = "restrict"
		}
		parts = append(parts, "authorized_keys command= dispatcher + "+fence)
		parts = append(parts, "curated PATH "+c.dir+"/"+curatedBinName+" (guardrail)")
		parts = append(parts, "login shell "+c.shell+" (guardrail)")
	}
	if c.noexecHome {
		parts = append(parts, "home bind-mounted noexec,nosuid,nodev")
	}
	if c.noNewPrivs {
		parts = append(parts, "setpriv --no-new-privs on every exec")
	}
	execMechanism = strings.Join(parts, "; ")

	if c.egress != nil {
		if c.egress.isolate {
			reachMechanism = "per-uid packet filter (iptables/ip6tables -m owner): loopback only"
		} else {
			reachMechanism = fmt.Sprintf("per-uid packet filter (iptables/ip6tables -m owner): %d permitted destination rule(s), default reject on both families",
				len(c.egress.rules))
		}
	}
	return execMechanism, reachMechanism
}

// caveat is what the rung is ACTUALLY enforcing where that is narrower than the
// name suggests. It goes on the audit record for the reason PLAN §6.5 gives:
// a record that names only the guarantee cannot answer the question anybody
// asks of it afterwards.
func (c *confinement) caveat() string {
	if c == nil {
		return ""
	}
	var parts []string
	if c.dispatcher {
		// The interpreter problem, recorded rather than refused (0018): a
		// shipped deny-list of interpreter names would be a blacklist
		// masquerading as a boundary, incomplete on the day it shipped.
		if names := interpretersIn(c.commands); len(names) > 0 {
			parts = append(parts, "the rendered allow-list names "+strings.Join(names, ", ")+
				", each of which can hand back a shell: the rung bounds the mechanism, not the list")
		}
		if c.shell == DefaultTargetShell {
			parts = append(parts, "no restricted shell on this target, so the guardrail beneath the dispatcher is the curated PATH alone")
		}
	}
	if c.egress != nil && !c.egress.isolate {
		parts = append(parts, "loopback is not permitted unless the policy names it, so a session needing a local resolver must have one named")
	}
	return strings.Join(parts, "; ")
}

// knownInterpreters are the allow-list entries PLAN §6.5 names as handing back
// a shell. It is a REPORTING list and never a deny-list: a proxy-side refusal
// over a name would be a blacklist masquerading as a boundary, incomplete on
// day one, and would refuse a legitimate route at connect time in front of a
// user. 0018 settled this — the proxy may warn, and must not refuse.
var knownInterpreters = []string{
	"awk", "bash", "csh", "dash", "ed", "env", "ex", "find", "gawk", "gdb", "ksh",
	"less", "lua", "man", "more", "mawk", "nano", "nmap", "node", "perl", "pico",
	"python", "python2", "python3", "ruby", "sed", "sh", "ssh", "tar", "tclsh",
	"vi", "view", "vim", "watch", "zsh",
}

// interpretersIn names the allow-list entries that can hand back a shell.
func interpretersIn(cmds []control.RestrictedCommand) []string {
	seen := map[string]bool{}
	var found []string
	for _, cmd := range cmds {
		base := cmd.Executable
		if i := strings.LastIndex(base, "/"); i >= 0 {
			base = base[i+1:]
		}
		for _, name := range knownInterpreters {
			if base == name && !seen[base] {
				seen[base] = true
				found = append(found, base)
			}
		}
	}
	sort.Strings(found)
	return found
}
