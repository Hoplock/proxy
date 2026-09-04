// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// This file is the POSIX half of contract v4's capability advertisement (PLAN
// §6.5): what one TARGET can take, found by connecting to it.
//
// It is here rather than in internal/control because it is the only place in
// the system that has a privileged login to the target. Authorize happens
// BEFORE the proxy has ever touched it, which is why this cannot ride on the
// authorize request and why the report takes /v1/hostkeys/report's shape.
//
// The probe is a DECLARATION-FREE measurement: every line of it asks the target
// a question rather than asking a version number what it implies. "systemd is
// present" is not the same claim as "this systemd honours the directive this
// rung needs", and a silently-ignored directive is a rung claiming a guarantee
// it is not delivering — which is the failure PLAN §6.5 says the capability
// probe exists to catch.
//
// It grants nothing. The authority for a rung is the authorize response, and
// this is re-checked against the live target at provisioning time, so the worst
// a stale record can cause is a refused session.

// probe is one target's answers, keyed as the script prints them.
type probe struct {
	// values are the raw key→value pairs, kept whole so the operator-facing
	// Detail can carry what a rung was refused for.
	values map[string]string
	// at is when the observation was made, on the PROXY's clock: it is compared
	// against the proxy's own TTL and never against anything the target said.
	at time.Time
}

// Probe keys. Each one is a question the script answers with "yes", "no", or a
// version string; nothing here is inferred from anything else.
const (
	probeSSHDVersion = "sshd_version"
	// probeKeyOptions says the sshd honours authorized_keys options at all, and
	// probeRestrict says it understands the single `restrict` keyword (OpenSSH
	// 7.2+). An sshd without `restrict` is served with the individual `no-*`
	// options rather than refused: they are the same fence spelled longer, and
	// an UNKNOWN option makes OpenSSH refuse the key outright, which would turn
	// a supported target into an outage.
	probeKeyOptions = "sshd_key_options"
	probeRestrict   = "sshd_restrict"
	// probeRestrictedShell is the path of a restricted shell, or empty. It is
	// the GUARDRAIL half of the account-restricted rung and never the boundary,
	// so its absence narrows the rung's defence in depth and does not refuse it.
	probeRestrictedShell = "restricted_shell"
	// probeNoNewPrivs says setpriv can drop PR_SET_NO_NEW_PRIVS on the way into
	// an exec. It is what "cannot gain privilege" is actually made of.
	probeNoNewPrivs = "no_new_privs"
	// probeBindMount says a bind mount can be remounted noexec,nosuid,nodev.
	// It is what "cannot execute what the session wrote" is actually made of,
	// and it is measured by DOING it on a scratch directory rather than by
	// looking for a mount binary: an unprivileged container has the binary and
	// not the capability.
	probeBindMount = "bind_mount"
	// probeIPv4Filter and probeIPv6Filter say a per-uid packet filter can be
	// installed on each family. BOTH are required by both reach rungs: a rung
	// that closes IPv4 and leaves IPv6 open is the exact mistake phase 0015
	// found on the device side, and it is not one this side gets to repeat.
	probeIPv4Filter = "ipv4_owner_filter"
	probeIPv6Filter = "ipv6_owner_filter"
	// probeSystemd and probeCgroup2 are recorded for the operator and are not
	// read by any decision here. They are what a future rung rendered through
	// the service manager would turn on, and their absence is the most common
	// reason a target cannot take one.
	probeSystemd = "systemd"
	probeCgroup2 = "cgroup2"
)

// probeScript asks the target what it can enforce.
//
// It is plain POSIX shell for script.go's reason: the fleet this method serves
// has no configuration-management agent, and a probe that needed Python would
// answer "cannot enforce anything" on hosts that can enforce plenty. Every
// check cleans up after itself — the probe is run on a production host, on the
// path of a session that has not been provisioned yet, and it must leave
// nothing behind whether it succeeds or fails.
func probeScript() string {
	var b strings.Builder
	b.WriteString("set -u\n")
	b.WriteString(`say() { printf '%s\t%s\n' "$1" "$2"; }` + "\n")

	// sshd. `-T` parses the configuration and exits, which is the only way to
	// ask a running sshd what it understands without restarting it.
	b.WriteString(`v=$( (sshd -V 2>&1 || /usr/sbin/sshd -V 2>&1 || ssh -V 2>&1) | head -n 1 )` + "\n")
	b.WriteString(`say ` + probeSSHDVersion + ` "$v"` + "\n")
	b.WriteString(`sshdbin=$(command -v sshd || echo /usr/sbin/sshd)` + "\n")
	b.WriteString(`if [ -x "$sshdbin" ] && "$sshdbin" -T >/dev/null 2>&1; then` + "\n")
	b.WriteString(`  say ` + probeKeyOptions + ` yes` + "\n")
	// An sshd whose effective configuration disables authorized_keys entirely
	// cannot carry a command= dispatcher, and the rung is then unavailable
	// rather than weaker.
	b.WriteString(`  if "$sshdbin" -T 2>/dev/null | grep -qi '^pubkeyauthentication no'; then say ` + probeKeyOptions + ` no; fi` + "\n")
	b.WriteString("else\n")
	b.WriteString(`  say ` + probeKeyOptions + ` unknown` + "\n")
	b.WriteString("fi\n")
	// `restrict` is 7.2+. Version strings are "OpenSSH_9.2p1, ..."; anything
	// this cannot parse answers "no", which costs a longer option list and
	// nothing else.
	b.WriteString(`case "$v" in` + "\n")
	b.WriteString(`  OpenSSH_[1-6].*) say ` + probeRestrict + ` no ;;` + "\n")
	b.WriteString(`  OpenSSH_7.[01]*) say ` + probeRestrict + ` no ;;` + "\n")
	b.WriteString(`  OpenSSH_*) say ` + probeRestrict + ` yes ;;` + "\n")
	b.WriteString(`  *) say ` + probeRestrict + ` no ;;` + "\n")
	b.WriteString("esac\n")

	// A restricted shell, by path. rbash is bash's mode rather than a separate
	// program on most distributions, so the symlink is what is looked for.
	b.WriteString("rs=\n")
	b.WriteString(`for c in /bin/rbash /usr/bin/rbash /bin/rksh /usr/bin/rksh; do` + "\n")
	b.WriteString(`  if [ -x "$c" ]; then rs=$c; break; fi` + "\n")
	b.WriteString("done\n")
	b.WriteString(`say ` + probeRestrictedShell + ` "$rs"` + "\n")

	// no-new-privs, measured by running something under it.
	b.WriteString(`if command -v setpriv >/dev/null 2>&1 && setpriv --no-new-privs /bin/true >/dev/null 2>&1; then` + "\n")
	b.WriteString(`  say ` + probeNoNewPrivs + ` yes` + "\n")
	b.WriteString(`else say ` + probeNoNewPrivs + ` no; fi` + "\n")

	// A bind mount that can be remounted with the three flags, measured by
	// doing it. The scratch directory is removed whichever way it goes.
	b.WriteString(`d=$(mktemp -d 2>/dev/null || echo "")` + "\n")
	b.WriteString(`bm=no` + "\n")
	b.WriteString(`if [ -n "$d" ]; then` + "\n")
	b.WriteString(`  if mount --bind "$d" "$d" >/dev/null 2>&1; then` + "\n")
	b.WriteString(`    if mount -o remount,bind,noexec,nosuid,nodev "$d" >/dev/null 2>&1; then bm=yes; fi` + "\n")
	b.WriteString(`    umount "$d" >/dev/null 2>&1 || umount -l "$d" >/dev/null 2>&1 || true` + "\n")
	b.WriteString("  fi\n")
	b.WriteString(`  rmdir "$d" >/dev/null 2>&1 || true` + "\n")
	b.WriteString("fi\n")
	b.WriteString(`say ` + probeBindMount + ` "$bm"` + "\n")

	// The per-uid packet filter, on both families, measured by installing a
	// rule for a uid that cannot exist and removing it again. Listing the
	// tables would answer "the binary is present"; this answers "this kernel
	// will take the rule", which is the question.
	b.WriteString(probeFilterFragment("v4", "iptables", probeIPv4Filter))
	b.WriteString(probeFilterFragment("v6", "ip6tables", probeIPv6Filter))

	b.WriteString(`if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then` + "\n")
	b.WriteString(`  say ` + probeSystemd + ` "$(systemctl --version 2>/dev/null | head -n 1)"` + "\n")
	b.WriteString(`else say ` + probeSystemd + ` ""; fi` + "\n")
	b.WriteString(`if [ -f /sys/fs/cgroup/cgroup.controllers ]; then say ` + probeCgroup2 + ` yes; else say ` + probeCgroup2 + ` no; fi` + "\n")
	return b.String()
}

// probeFilterFragment installs and removes one throwaway rule.
//
// The uid it names is deliberately one no account holds (2**31-2, above every
// allocation range a distribution uses), so that a probe interrupted between
// the insert and the delete leaves a rule that matches nothing rather than a
// rule that matches somebody. The comment match is probed at the same time
// because teardown finds this proxy's rules BY COMMENT: a netfilter that takes
// the owner match and not the comment one would leave rules nothing can find.
func probeFilterFragment(suffix, binary, key string) string {
	var b strings.Builder
	tag := "hoplock-probe"
	b.WriteString("f" + suffix + "=no\n")
	b.WriteString(`if command -v ` + binary + ` >/dev/null 2>&1; then` + "\n")
	b.WriteString(`  if ` + binary + ` -A OUTPUT -m owner --uid-owner ` + probeSentinelUID +
		` -m comment --comment '` + tag + `' -j ACCEPT >/dev/null 2>&1; then` + "\n")
	b.WriteString(`    f` + suffix + `=yes` + "\n")
	b.WriteString(`    ` + binary + ` -D OUTPUT -m owner --uid-owner ` + probeSentinelUID +
		` -m comment --comment '` + tag + `' -j ACCEPT >/dev/null 2>&1 || f` + suffix + `=no` + "\n")
	b.WriteString("  fi\n")
	b.WriteString("fi\n")
	b.WriteString(`say ` + key + ` "$f` + suffix + `"` + "\n")
	return b.String()
}

// probeSentinelUID is the uid the filter probe names: above every allocation
// range a distribution uses, so a probe that dies between insert and delete
// leaves a rule matching nobody.
const probeSentinelUID = "2147483646"

// parseProbe reads the script's output.
func parseProbe(out []byte, now time.Time) *probe {
	p := &probe{values: map[string]string{}, at: now}
	for _, line := range strings.Split(string(out), "\n") {
		key, value, ok := strings.Cut(strings.TrimRight(line, "\r"), "\t")
		if !ok {
			continue
		}
		p.values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return p
}

func (p *probe) get(key string) string {
	if p == nil {
		return ""
	}
	return p.values[key]
}

func (p *probe) yes(key string) bool { return p.get(key) == "yes" }

// keyOptions reports whether authorized_keys options are honoured. An sshd this
// probe could not interrogate answers "unknown", and unknown is treated as YES
// here — deliberately, and it is the one place in this file that does.
//
// The reason is that the check is redundant: an sshd that ignores key options
// ignores the `command=` dispatcher, and the rung's own acceptance test (the
// dispatcher answering a login) fails immediately and visibly. Refusing on
// "could not run sshd -T" would instead refuse every target whose provisioning
// account cannot execute the sshd binary, which is most of the fleets that run
// the provisioning account as something other than root.
func (p *probe) keyOptions() bool { return p.get(probeKeyOptions) != "no" }

// capabilities renders the probe as the record the server accumulates.
//
// The mapping from measurements to rungs is the whole content of this function
// and it is stated once, here, so that the refusal at provisioning time and the
// advertisement to the server can never disagree about what a rung needs.
func (p *probe) capabilities() control.TargetCapabilities {
	caps := control.TargetCapabilities{
		ObservedAt: p.at,
		Detail:     map[string]string{},
	}
	for k, v := range p.values {
		caps.Detail[k] = v
	}
	if p.keyOptions() {
		// account-restricted is the command= dispatcher plus the key's own
		// capability fence. The restricted shell and the curated PATH are its
		// guardrail half and are not required for it: their absence removes
		// depth, not the boundary.
		caps.Execution = append(caps.Execution, control.ExecutionAccountRestricted)
		if p.yes(probeNoNewPrivs) && p.yes(probeBindMount) {
			// account-confined is that, plus the two things its extra sentence
			// names: no privilege gain (no-new-privs) and no executing what the
			// session wrote (a noexec,nosuid,nodev home).
			caps.Execution = append(caps.Execution, control.ExecutionAccountConfined)
		}
	}
	if p.yes(probeIPv4Filter) && p.yes(probeIPv6Filter) {
		caps.Reach = append(caps.Reach,
			control.ReachAccountEgressRestricted,
			control.ReachAccountNetworkIsolated)
	}
	return caps
}

// probeCache holds one observation per target for as long as it is fresh.
//
// It is a cache and not a record: it saves a round trip on the session path,
// and every rung is still re-checked against it at provisioning time. The TTL
// is control.DefaultCapabilityTTL for the reason that constant gives — a
// target's enforcement surface changes with a package upgrade or a kernel boot,
// neither of which announces itself here.
type probeCache struct {
	mu  sync.Mutex
	ttl time.Duration
	by  map[string]*probe
}

func newProbeCache(ttl time.Duration) *probeCache {
	if ttl <= 0 {
		ttl = control.DefaultCapabilityTTL
	}
	return &probeCache{ttl: ttl, by: map[string]*probe{}}
}

// get returns a fresh observation for a target, or nil.
func (c *probeCache) get(addr string, now time.Time) *probe {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.by[addr]
	if !ok || now.Sub(p.at) > c.ttl {
		return nil
	}
	return p
}

func (c *probeCache) put(addr string, p *probe) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.by[addr] = p
}

// observe probes a target over an already-open management login, using the
// cached answer while it is fresh.
func (a *EphemeralAuthenticator) observe(ctx context.Context, admin AdminSession, tgt Target) *probe {
	now := a.now()
	if p := a.probes.get(tgt.Addr(), now); p != nil {
		return p
	}
	out, err := admin.Run(ctx, probeScript())
	if err != nil {
		// A probe that could not run is an EMPTY observation, which provides
		// nothing that has to be applied — the same fail-safe answer a stale or
		// absent record gets (PLAN §6.5). It is not cached: the next session
		// asks again rather than inheriting a bad minute.
		a.logf("auth/target: ephemeral-user could not probe %s for enforcement capabilities: %v", tgt, err)
		return parseProbe(nil, now)
	}
	p := parseProbe(out, now)
	a.probes.put(tgt.Addr(), p)
	a.report(tgt, p)
	return p
}

// report tells the server what the target can take.
//
// It is fire-and-forget on a detached context because it is an OBSERVATION and
// not a request for a decision: the session that triggered it may end a
// millisecond later, and a report that failed changes nothing about the session
// — the authority for a rung is the authorize response, and this proxy
// re-checks the live target anyway.
func (a *EphemeralAuthenticator) report(tgt Target, p *probe) {
	if a.reporter == nil {
		return
	}
	req := &control.CapabilityReportRequest{
		Target:       tgt.Host,
		TargetPort:   tgt.Port,
		Capabilities: p.capabilities(),
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), capabilityReportTimeout)
		defer cancel()
		if _, err := a.reporter.ReportCapabilities(ctx, req); err != nil {
			a.logf("auth/target: ephemeral-user could not report %s's enforcement capabilities: %v", tgt, err)
		}
	}()
}

// capabilityReportTimeout bounds one capability report. It is short because
// nothing waits for it.
const capabilityReportTimeout = 15 * time.Second
