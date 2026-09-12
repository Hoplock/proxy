// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

//go:build e2e

package e2e

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestTopology is the prototype's acceptance gate.
//
// It is one test with ordered subtests rather than many top-level tests because
// the order is part of the specification: the telemetry assertions read what the
// scenarios before them produced, the ephemeral-account leak check has to run
// after every session that could have leaked one, and the outage scenario stops
// Hoplock Control out from under everything else.
func TestTopology(t *testing.T) {
	requireTopology(t)

	t.Run("network isolation", testIsolation)
	t.Run("routing", testRouting)
	t.Run("channel policy", testChannelPolicy)
	t.Run("command policy", testCommandPolicy)
	t.Run("target credentials", testTargetCredentials)
	// Directly after the credential scenarios, because it is the same subject
	// seen under load: what the per-session token in an ephemeral principal is
	// for (PLAN §5.1). It has to run before the outage scenario, which stops
	// Hoplock Control — a session cannot be provisioned without it — and before
	// the leak check, which is what proves neither of its overlapping teardowns
	// took the other's account with it.
	t.Run("concurrent provisioning", testConcurrentProvisioning)
	// Next to the credential scenarios for the same reason, and after the
	// concurrency one because both read the target's own account database: this
	// is what the numeric half of an ephemeral account's identity is worth
	// (PLAN §5.1, phase 0027). Before the outage scenario, which stops Hoplock
	// Control — nothing can be provisioned without it — and before the leak
	// check, whose claim is about the accounts these scenarios leave behind.
	t.Run("uid allocation", testUIDAllocation)
	// Before the outage scenario, which stops Hoplock Control: these read the
	// records they produced. They also OPEN a breaker on one credential and
	// leave it open for the rest of the run, which is safe only because
	// `stale-fleet` is named by exactly one route in the fixtures.
	t.Run("target credential rejection", testCredentialRejection)
	// The same defect on the other leg (phase 0033), so it sits beside the
	// scenario it mirrors. Before the outage scenario for the same reason that
	// one is: it reads the priority record its own session produced, and
	// Hoplock Control has to be up both to refuse the chain key and to receive
	// the record. It opens no breaker and leaves nothing behind.
	t.Run("chain identity rejection", testChainIdentityRejection)
	t.Run("device credentials", testDeviceCredentials)
	t.Run("target-side enforcement", testEnforcement)
	t.Run("denial disclosure", testDenialDisclosure)
	// Next to the disclosure scenario, because half of it is the same claim on
	// a second axis: a denial must not say WHICH FACTOR failed any more than it
	// says which target existed. It is before telemetry and the outage scenario
	// because it reads the audit record its own session produced, and Hoplock
	// Control has to be up both to decide the second factor and to receive it.
	t.Run("password and out-of-band MFA", testPasswordMFA)
	t.Run("telemetry", testTelemetry)
	// The other three session bounds (D16). It is before both scenarios that
	// stop Hoplock Control, for two reasons: it reads the records its own
	// sessions produced, and one subtest takes the mock's LOG DESTINATION down
	// and brings it back — which is only a different thing from stopping the
	// server while the server is up.
	t.Run("session bounds", testSessionBounds)
	// Before the outage scenario, and it stops Hoplock Control itself for one
	// of its subtests — the whole claim of a locally enforced deadline is that
	// it holds when the policy service does not. It restarts it and waits for
	// the drained records, so the scenario below still has a delivered history
	// to compare against.
	t.Run("session deadline", testSessionDeadline)
	// Stops Hoplock Control, so nothing may run after it but the leak check.
	t.Run("outage disclosure and log drain", testOutage)
	t.Run("no ephemeral accounts left behind", testNoEphemeralLeak)
}

// --- isolation ---------------------------------------------------------------

// testIsolation checks the claims the compose networks are there to make. They
// are asserted rather than assumed because every routing scenario below is only
// evidence of anything if they hold: a target the user node could reach directly
// would make "it went through the proxy" unfalsifiable.
func testIsolation(t *testing.T) {
	// The control: the user node can resolve the proxies it is meant to use, so
	// the two failures below are about reachability and not about a broken
	// resolver.
	if r := execIn(t, nodeUser, "getent", "hosts", proxyDirect); r.code != 0 {
		t.Fatalf("the user node cannot resolve %s; the isolation checks below would prove nothing\n%s", proxyDirect, r)
	}

	if r := execIn(t, nodeUser, "getent", "hosts", nodeTarget); r.code == 0 {
		t.Errorf("the user node can reach the target directly; it must only reach it through a proxy\n%s", r)
	}
	// The appliance is on the same terms as the target, and the claim matters
	// more there: a device the proxy provisions administrators on is a device
	// nobody should be able to reach around the proxy.
	if r := execIn(t, nodeUser, "getent", "hosts", nodeDevice); r.code == 0 {
		t.Errorf("the user node can reach the appliance directly; the device scenarios would prove nothing\n%s", r)
	}
	// The relay claim (D11): the zone proxy is not reachable from where users
	// are, and its listener is bound to loopback inside its own container
	// (deploy/proxy/proxy-zone.yaml, asserted in test/topology). Sessions get
	// there over the registration it opened, or not at all.
	if r := execIn(t, nodeUser, "getent", "hosts", proxyZone); r.code == 0 {
		t.Errorf("the zone proxy is reachable from the user node; the relay scenario would prove nothing\n%s", r)
	}
}

// --- routing -----------------------------------------------------------------

func testRouting(t *testing.T) {
	t.Run("direct route runs a command", func(t *testing.T) {
		s := aliceOn(proxyDirect, "host.company.com")
		s.command = "/bin/echo direct-exec-ok"
		r := ssh(t, s)
		wantExit(t, r, "direct exec", 0)
		wantContains(t, r, "direct exec", "direct-exec-ok")
	})

	t.Run("direct route opens an interactive shell", func(t *testing.T) {
		s := aliceOn(proxyDirect, "host.company.com")
		s.opts = []string{"-tt"}
		s.stdin = "echo direct-shell-ok\nexit\n"
		r := ssh(t, s)
		wantContains(t, r, "direct shell", "direct-shell-ok")
	})

	// proxy-nexthop is not on the target's network at all, so both of these
	// reached the target through a second proxy or not at all.
	t.Run("nexthop route in dial mode runs a command", func(t *testing.T) {
		s := aliceOn(proxyNextHop, "deep.company.com")
		s.command = "/bin/echo dial-exec-ok"
		r := ssh(t, s)
		wantExit(t, r, "dial exec", 0)
		wantContains(t, r, "dial exec", "dial-exec-ok")
	})

	t.Run("nexthop route in dial mode opens an interactive shell", func(t *testing.T) {
		s := aliceOn(proxyNextHop, "deep.company.com")
		s.opts = []string{"-tt"}
		s.stdin = "echo dial-shell-ok\nexit\n"
		wantContains(t, ssh(t, s), "dial shell", "dial-shell-ok")
	})

	// The architecture's central claim (D11). The zone proxy accepts no inbound
	// connection from any network, and the route names an address that cannot
	// resolve — so a session that arrived travelled over the registration the
	// zone proxy opened outbound, and nothing else could have carried it.
	t.Run("nexthop route in relay mode runs a command", func(t *testing.T) {
		s := aliceOn(proxyNextHop, "zone.company.com")
		s.command = "/bin/echo relay-exec-ok"
		r := ssh(t, s)
		wantExit(t, r, "relay exec", 0)
		wantContains(t, r, "relay exec", "relay-exec-ok")
	})

	t.Run("nexthop route in relay mode opens an interactive shell", func(t *testing.T) {
		s := aliceOn(proxyNextHop, "zone.company.com")
		s.opts = []string{"-tt"}
		s.stdin = "echo relay-shell-ok\nexit\n"
		wantContains(t, ssh(t, s), "relay shell", "relay-shell-ok")
	})

	// The route below points at a proxy that IS dialable and would serve the
	// session happily. A proxy that quietly downgraded a relay hop to a dial
	// would pass this; refusing it is the point.
	t.Run("a relay route with no registration is an outage, not a dial", func(t *testing.T) {
		s := aliceOn(proxyNextHop, "ghost.company.com")
		s.command = "/bin/echo must-not-run"
		r := ssh(t, s)
		wantFailure(t, r, "relay hop with no registration")
		wantNotContains(t, r, "relay hop with no registration", "must-not-run")
		wantContains(t, r, "relay hop with no registration", "the next proxy in the chain is not currently connected")
		wantContains(t, r, "relay hop with no registration", "not a permissions problem")
	})

	// Neither proxy can see the whole chain; the hop trail is what makes both
	// of these detectable at all. Both render as the same deliberately vague
	// outage: a loop and an exhausted hop count are faults in the estate's own
	// routing, and the operator reads which one in the audit log.
	t.Run("a routing loop is refused", func(t *testing.T) {
		s := aliceOn(proxyNextHop, "loop.company.com")
		s.command = "/bin/echo must-not-run"
		r := ssh(t, s)
		wantFailure(t, r, "routing loop")
		wantNotContains(t, r, "routing loop", "must-not-run")
		wantContains(t, r, "routing loop", "the chain of proxies to this target could not be extended")
	})

	t.Run("the hop cap is enforced", func(t *testing.T) {
		s := aliceOn(proxyNextHop, "hopcap.company.com")
		s.command = "/bin/echo must-not-run"
		r := ssh(t, s)
		wantFailure(t, r, "hop cap")
		wantNotContains(t, r, "hop cap", "must-not-run")
		wantContains(t, r, "hop cap", "the chain of proxies to this target could not be extended")
	})
}

// --- channel policy (D5a, all three axes) ------------------------------------

func testChannelPolicy(t *testing.T) {
	// Axis 1: channel types. The route names a working credential, so the only
	// thing that can refuse this session is the empty channel allow-list.
	//
	// The user gets the generic denial rather than a channel-open rejection
	// because the engine accepts the client's session channel BEFORE anything
	// can fail — that ordering is what gives every later failure somewhere to
	// speak (PLAN §4.3). Which channel type was refused is in the audit record,
	// asserted in the telemetry scenario.
	t.Run("a channel type not on the allow-list is refused", func(t *testing.T) {
		s := aliceOn(proxyDirect, "nochan.company.com")
		s.command = "/bin/echo must-not-run"
		r := ssh(t, s)
		wantFailure(t, r, "denied channel type")
		wantNotContains(t, r, "denied channel type", "must-not-run")
		wantContains(t, r, "denied channel type", "Access denied.")
	})

	// Axis 2: in-channel requests. Both of these ride one `session` channel, so
	// the allow-list above cannot express either of them.
	//
	// The assertions are on what OpenSSH prints. The proxy also writes its own
	// clause ("The sftp subsystem is not available on this session.") to the
	// channel's stderr, but sftp and `ssh -tt` both abandon the channel on a
	// failed request before rendering it — so the clause is asserted where it
	// reliably lands, in the audit record (see the telemetry scenario).
	t.Run("sftp is denied while the shell succeeds", func(t *testing.T) {
		r := execIn(t, nodeUser, append(append([]string{"sftp"}, sshBaseArgs...),
			"-i", keyAlice, "-P", proxyPort, "-b", "/dev/null",
			"alice#host.company.com@"+proxyDirect)...)
		wantFailure(t, r, "sftp")
		wantContains(t, r, "sftp", "subsystem request failed")

		s := aliceOn(proxyDirect, "host.company.com")
		s.opts = []string{"-tt"}
		s.stdin = "echo shell-still-ok\nexit\n"
		wantContains(t, ssh(t, s), "shell beside the denied sftp", "shell-still-ok")
	})

	t.Run("a terminal is denied while exec succeeds", func(t *testing.T) {
		s := aliceOn(proxyDirect, "nopty.company.com")
		s.opts = []string{"-tt"}
		s.command = "/bin/echo must-not-run"
		r := ssh(t, s)
		wantFailure(t, r, "denied pty-req")
		wantContains(t, r, "denied pty-req", "PTY allocation request failed")
		wantNotContains(t, r, "denied pty-req", "must-not-run")

		s = aliceOn(proxyDirect, "nopty.company.com")
		s.command = "/bin/echo nopty-exec-ok"
		r = ssh(t, s)
		wantExit(t, r, "exec beside the denied terminal", 0)
		wantContains(t, r, "exec beside the denied terminal", "nopty-exec-ok")
	})

	// Axis 2 for forwarding channels: the destination inside the payload is
	// what the policy is about. Permitting the channel type alone would permit
	// tunnelling anywhere.
	t.Run("a tunnel to the permitted destination succeeds", func(t *testing.T) {
		s := svcOn(proxyDirect, "fwd.company.com")
		s.opts = []string{"-W", "target:22"}
		r := ssh(t, s)
		wantExit(t, r, "permitted forward", 0)
		wantContains(t, r, "permitted forward", "SSH-2.0")
	})

	t.Run("a tunnel to another port is refused", func(t *testing.T) {
		s := svcOn(proxyDirect, "fwd.company.com")
		s.opts = []string{"-W", "target:80"}
		r := ssh(t, s)
		wantFailure(t, r, "forward to another port")
		wantContains(t, r, "forward to another port", "Forwarding to target:80 is not available on this session.")
	})

	t.Run("a tunnel to another host is refused", func(t *testing.T) {
		s := svcOn(proxyDirect, "fwd.company.com")
		s.opts = []string{"-W", "control:8080"}
		r := ssh(t, s)
		wantFailure(t, r, "forward to another host")
		wantContains(t, r, "forward to another host", "Forwarding to control:8080 is not available on this session.")
	})

	// Axis 3: connection-level global requests. Remote forwarding is not a
	// channel open at all, so the channel allow-list never sees it — and "may
	// never open a listener" is exactly what an empty list here means.
	t.Run("tcpip-forward is refused and leaves no listener", func(t *testing.T) {
		const port = "19000"
		s := aliceOn(proxyDirect, "host.company.com")
		s.opts = []string{"-o", "ExitOnForwardFailure=yes", "-R", "127.0.0.1:" + port + ":127.0.0.1:22"}
		s.command = "/bin/echo must-not-run"
		r := ssh(t, s)
		wantFailure(t, r, "tcpip-forward")
		wantContains(t, r, "tcpip-forward", "port forwarding failed")

		listeners := execIn(t, nodeTarget, "ss", "-lnt")
		if strings.Contains(listeners.stdout, ":"+port) {
			t.Errorf("the target is listening on %s after a refused tcpip-forward\n%s", port, listeners)
		}
	})
}

// --- command policy (D12's tiers, and the four actions) ----------------------

func testCommandPolicy(t *testing.T) {
	// The enforced tier: the command is parsed into an argument vector and must
	// be covered completely by one allow-list entry.
	t.Run("restricted exec runs an approved argv", func(t *testing.T) {
		s := svcOn(proxyDirect, "appliance.company.com")
		s.command = "/bin/uptime"
		r := ssh(t, s)
		wantExit(t, r, "approved argv", 0)
		wantContains(t, r, "approved argv", "load average")
	})

	t.Run("restricted exec denies an unapproved argv", func(t *testing.T) {
		s := svcOn(proxyDirect, "appliance.company.com")
		s.command = "/bin/ls /"
		r := ssh(t, s)
		wantFailure(t, r, "unapproved argv")
		wantContains(t, r, "unapproved argv", "That command was blocked by policy.")
	})

	// The tiers are different things, in the product and not only in unit
	// tests. The same shell wrapper is a boundary violation under restricted
	// exec and merely an unmatched command under the filtered tier — whose
	// pattern rules are anchored on the whole command and demonstrably cannot
	// see inside it (D12).
	t.Run("restricted exec denies a shell wrapper the filtered tier lets through", func(t *testing.T) {
		const wrapped = "sh -c '/bin/ls /'"

		s := svcOn(proxyDirect, "appliance.company.com")
		s.command = wrapped
		r := ssh(t, s)
		wantFailure(t, r, "wrapped command under restricted exec")
		wantContains(t, r, "wrapped command under restricted exec", "That command was blocked by policy.")

		// The filtered route even carries a rule naming "/bin/ls *". It stops
		// the bare command and cannot stop the wrapper: that is the guarantee
		// difference, visible in the product.
		s = svcOn(proxyDirect, "filtered.company.com")
		s.command = "/bin/ls /"
		r = ssh(t, s)
		wantFailure(t, r, "bare command under filtered exec")
		wantContains(t, r, "bare command under filtered exec", "Directory listings are not permitted from this account.")

		s = svcOn(proxyDirect, "filtered.company.com")
		s.command = wrapped
		r = ssh(t, s)
		wantExit(t, r, "wrapped command under filtered exec", 0)
		wantContains(t, r, "wrapped command under filtered exec", "etc")
	})

	// The four match actions.
	t.Run("a blacklisted command is blocked", func(t *testing.T) {
		s := aliceOn(proxyDirect, "host.company.com")
		s.command = "reboot now"
		r := ssh(t, s)
		wantFailure(t, r, "block_command")
		wantContains(t, r, "block_command", "That command was blocked by policy.")
		wantContains(t, r, "block_command", "Reboots go through the change process.")
	})

	t.Run("a warned command is recorded and still runs", func(t *testing.T) {
		s := aliceOn(proxyDirect, "host.company.com")
		s.command = "sudo -n /bin/true"
		r := ssh(t, s)
		wantContains(t, r, "warn_and_continue", "Privileged command")
		wantNotContains(t, r, "warn_and_continue", "That command was blocked by policy.")
		wantNotContains(t, r, "warn_and_continue", "This session has been terminated by policy.")
	})

	t.Run("a killing command ends the session", func(t *testing.T) {
		s := aliceOn(proxyDirect, "host.company.com")
		s.command = "shutdown -h now"
		r := ssh(t, s)
		wantFailure(t, r, "kill_session")
		wantContains(t, r, "kill_session", "This session has been terminated by policy.")
		wantContains(t, r, "kill_session", "Destructive command.")
	})

	t.Run("a whitelisted command is allowed and logged", func(t *testing.T) {
		s := svcOn(proxyDirect, "allowlist.company.com")
		s.command = "/bin/echo allowlist-ok"
		r := ssh(t, s)
		wantExit(t, r, "allow_and_log", 0)
		wantContains(t, r, "allow_and_log", "allowlist-ok")
	})

	t.Run("a command no whitelist rule matched is blocked by the mode", func(t *testing.T) {
		s := svcOn(proxyDirect, "allowlist.company.com")
		s.command = "/bin/ls /"
		r := ssh(t, s)
		wantFailure(t, r, "whitelist default")
		wantContains(t, r, "whitelist default", "That command was blocked by policy.")
	})
}

// --- target credentials (D6, D6a) --------------------------------------------

func testTargetCredentials(t *testing.T) {
	t.Run("ephemeral-user logs in as an account it created", func(t *testing.T) {
		s := aliceOn(proxyDirect, "host.company.com")
		s.command = "/usr/bin/id -un"
		r := ssh(t, s)
		wantExit(t, r, "ephemeral-user", 0)
		// hl-<proxy tag>-<login>-<token>: the proxy tag scopes the orphan
		// reaper, the login keeps the account attributable on the target, and
		// the token is what makes two sessions for one login safe (PLAN §5.1).
		account := strings.TrimSpace(r.stdout)
		if !strings.HasPrefix(account, "hl-") || !strings.Contains(account, "-alice-") {
			t.Errorf("ephemeral-user: logged in as %q, want an hl-<tag>-alice-<token> account\n%s", account, r)
		}
	})

	// The appliance case: an account that already exists, on a device the proxy
	// has no rights to administer. Nothing about the target may change.
	t.Run("brokered-key logs in without modifying the target", func(t *testing.T) {
		const snapshot = "cat /etc/passwd; cat /home/netadmin/.ssh/authorized_keys; ls -la /home/netadmin /home/netadmin/.ssh"

		// The subtest above leaves an ephemeral account whose teardown runs as
		// its session closes, asynchronously — the same reason the device
		// scenarios poll for a removed administrator. Left unwaited it can
		// land BETWEEN the two snapshots below, and an account disappearing
		// reads as "brokered-key modified the target". Wait for the target to
		// be quiet, so the comparison is about this session and nothing else.
		waitFor(t, "the previous session's ephemeral account to be removed", func() bool {
			return !strings.Contains(execIn(t, nodeTarget, "getent", "passwd").stdout, "hl-")
		})

		before := execIn(t, nodeTarget, "sh", "-c", snapshot)
		if before.code != 0 {
			t.Fatalf("snapshot the target: %v", before)
		}

		s := svcOn(proxyDirect, "appliance.company.com")
		s.command = "/bin/echo brokered-ok"
		r := ssh(t, s)
		wantExit(t, r, "brokered-key", 0)
		wantContains(t, r, "brokered-key", "brokered-ok")

		after := execIn(t, nodeTarget, "sh", "-c", snapshot)
		if after.stdout != before.stdout {
			t.Errorf("brokered-key modified the target:\n--- before ---\n%s\n--- after ---\n%s",
				before.stdout, after.stdout)
		}
	})

	// Phase 0028. The account the proxy logs into a target as never comes from
	// `identity.Login` — the string the user typed at her own SSH client — so a
	// session where nothing else names one is REFUSED rather than served on a
	// guess.
	//
	// `unnamed.company.com` on proxy-nexthop is the only shape in this topology
	// that can still reach that state: the route names no `target_auth`, so the
	// proxy falls back to its locally configured method, and that proxy is the
	// one whose `auth.target.brokered_key.username` is deliberately unset
	// (deploy/proxy/proxy-nexthop.yaml). Every other route and every other
	// proxy names an account explicitly, which is why the rest of the suite is
	// unaffected by this phase.
	t.Run("a route with no account name anywhere is an outage that touches nothing", func(t *testing.T) {
		before := ephemeralAccountsOn(t)

		s := aliceOn(proxyNextHop, "unnamed.company.com")
		s.command = "/bin/echo must-not-run"
		r := ssh(t, s)

		wantFailure(t, r, "no account name")
		wantNotContains(t, r, "no account name", "must-not-run")

		// Outage class, not a denial (PLAN §4.3). Nobody decided alice may not
		// reach this target: the estate could not say who to log in as, and
		// that is a configuration fault an operator fixes — so she is told it
		// is a service problem and given the reference her ticket needs.
		wantContains(t, r, "no account name", "This is a service problem")
		wantContains(t, r, "no account name", "credentials for the target could not be provisioned")
		wantNotContains(t, r, "no account name", "Access denied.")
		if sessionIDOf(r) == "" {
			t.Errorf("the outage does not name a session id\n%s", r)
		}

		// Nothing was provisioned. The refusal happens before the management
		// login and before the target leg is dialled, so the target is exactly
		// as it was found. The assertion is that no NEW account appeared — a
		// previous scenario's teardown legitimately makes the count fall.
		if appeared := added(before, ephemeralAccountsOn(t)); len(appeared) > 0 {
			t.Errorf("the refused session left accounts behind: %v", appeared)
		}
	})
}

// --- uid allocation (PLAN §5.1, phase 0027) ----------------------------------

// inheritProbe is the file one session writes OUTSIDE its home so the next
// session can be asked whether it owns it.
//
// /tmp is the point: it is world-writable, it is not the account's home, and
// teardown deliberately does not walk the filesystem — so the file SURVIVES the
// session that wrote it. What must not survive is the inheritance.
const inheritProbe = "/tmp/hoplock-uid-inherit-probe"

// uidOfSession runs one session and returns the uid the target ran it as.
func uidOfSession(t *testing.T, s session) (int, string) {
	t.Helper()
	s.command = "/usr/bin/id -u; /usr/bin/id -un"
	r := ssh(t, s)
	wantExit(t, r, "uid allocation", 0)
	fields := strings.Fields(r.stdout)
	if len(fields) != 2 {
		t.Fatalf("uid allocation: the session printed %q, want a uid and an account name\n%s", r.stdout, r)
	}
	uid, err := strconv.Atoi(fields[0])
	if err != nil {
		t.Fatalf("uid allocation: the session printed uid %q: %v", fields[0], err)
	}
	return uid, fields[1]
}

// waitForNoEphemeralAccounts waits until the target holds none of this proxy's
// accounts.
//
// Teardown runs as the session closes, asynchronously. A scenario that provisions
// again without waiting would be asserting about two accounts that overlapped —
// which is a different claim, already covered by the concurrency scenario, and it
// would make "the uid was not reused" pass for the wrong reason: a uid held by a
// live account could not be reused by anything.
func waitForNoEphemeralAccounts(t *testing.T, what string) {
	t.Helper()
	waitFor(t, what, func() bool {
		return !strings.Contains(execIn(t, nodeTarget, "getent", "passwd").stdout, "hl-")
	})
}

func testUIDAllocation(t *testing.T) {
	// Two sequential sessions, each fully torn down before the next. Every uid is
	// FREE by the time the next one is provisioned, which is the exact state in
	// which a target's own allocator hands the last one straight back.
	t.Run("two sequential sessions do not share a uid", func(t *testing.T) {
		waitForNoEphemeralAccounts(t, "the target to hold no ephemeral account before the first session")

		first, firstAccount := uidOfSession(t, aliceOn(proxyDirect, "host.company.com"))
		waitForNoEphemeralAccounts(t, "the first session's account to be removed")
		second, secondAccount := uidOfSession(t, aliceOn(proxyDirect, "host.company.com"))

		if first == second {
			t.Errorf("two sequential sessions both ran as uid %d (%s then %s); a torn-down "+
				"account's uid must not come back", first, firstAccount, secondAccount)
		}
		for _, uid := range []int{first, second} {
			// The dedicated range, above every distribution's own UID_MAX. A uid
			// the fleet's allocator could also hand out is not a dedicated range,
			// whatever else is true of it.
			if uid < 2000000 || uid > 2999999 {
				t.Errorf("a session ran as uid %d, want one inside the dedicated range 2000000-2999999", uid)
			}
		}
		if second < first {
			t.Errorf("the second session's uid %d is below the first's %d; allocation is meant to "+
				"be strictly above the high-water mark", second, first)
		}
	})

	// The real one. A file written outside the home survives its session — that
	// is expected and is not what is being asserted. What must not survive is
	// somebody ELSE inheriting ownership of it.
	t.Run("a second login does not inherit the first's files", func(t *testing.T) {
		// Removed as root first, so a re-run against a topology left up by
		// `make e2e-up` starts from nothing. Without this the probe would be
		// owned by an earlier session's uid, the write below would be refused,
		// and the scenario would fail for a reason that is not the claim.
		execIn(t, nodeTarget, "rm", "-f", inheritProbe)
		waitForNoEphemeralAccounts(t, "the target to hold no ephemeral account before the first session")

		// Session A: alice writes the probe and reports the uid that owns it.
		a := aliceOn(proxyDirect, "host.company.com")
		a.command = "/usr/bin/id -u > " + inheritProbe + "; /usr/bin/id -u"
		ra := ssh(t, a)
		wantExit(t, ra, "uid allocation", 0)
		writer, err := strconv.Atoi(strings.TrimSpace(ra.stdout))
		if err != nil {
			t.Fatalf("session A printed uid %q: %v\n%s", ra.stdout, err, ra)
		}
		waitForNoEphemeralAccounts(t, "session A's account to be removed")

		// The file is still there, owned by a uid that no longer names anybody.
		// Asserting on its ABSENCE would be asserting that the proxy sweeps the
		// filesystem, which it deliberately does not (PLAN §5.1).
		owner := execIn(t, nodeTarget, "stat", "-c", "%u", inheritProbe)
		if owner.code != 0 {
			t.Fatalf("the probe did not survive session A, so there is nothing to inherit: %v", owner)
		}
		if got := strings.TrimSpace(owner.stdout); got != strconv.Itoa(writer) {
			t.Fatalf("the probe is owned by uid %s and session A ran as %d", got, writer)
		}

		// Session B: a DIFFERENT PERSON on the same target.
		reader, account := uidOfSession(t, svcOn(proxyDirect, "inherit.company.com"))
		if reader == writer {
			t.Errorf("svc-deploy's session ran as uid %d, the same uid alice's session left files "+
				"under; %s now owns %s", reader, account, inheritProbe)
		}

		// Asserted from the target's own side too, because that is where
		// ownership actually is: the file's uid must not be the account B holds.
		after := strings.TrimSpace(execIn(t, nodeTarget, "stat", "-c", "%u", inheritProbe).stdout)
		if after != strconv.Itoa(writer) {
			t.Errorf("the probe's owner changed from %d to %s across the two sessions", writer, after)
		}
		if after == strconv.Itoa(reader) {
			t.Errorf("the probe is owned by uid %s, which is the second session's own uid", after)
		}
		execIn(t, nodeTarget, "rm", "-f", inheritProbe)
	})

	// The audit half (prompt 0027 §3). The account NAME is deleted at teardown,
	// so a record holding only the name leaves an incident responder with a join
	// key that names nothing.
	t.Run("the provisioning record carries the uid", func(t *testing.T) {
		s := aliceOn(proxyDirect, "host.company.com")
		s.command = "/usr/bin/id -u"
		r := ssh(t, s)
		wantExit(t, r, "uid allocation", 0)
		uid := strings.TrimSpace(r.stdout)
		id := sessionIDOf(r)
		if id == "" {
			t.Fatalf("uid allocation: no session id in the proxy's banner\n%s", r)
		}

		var found bool
		waitFor(t, "the provisioning record for this session to be delivered", func() bool {
			for _, rec := range fetchLogs(t).Batched {
				if rec.SessionID != id || rec.Kind != "provisioning" {
					continue
				}
				if rec.Attributes["target_account_uid"] == uid {
					found = true
					return true
				}
			}
			return false
		})
		if !found {
			t.Errorf("no provisioning record for %s carried target_account_uid=%s", id, uid)
		}
	})
}

// --- concurrent provisioning (PLAN §5.1) -------------------------------------

// concurrentHold is how long each overlapping session stays on the target.
//
// It has to outlast provisioning both sessions plus the polls that observe the
// overlap, and stay comfortably inside commandTimeout: a session the harness
// killed for running long would be torn down because the CLIENT went away,
// which is a different path from the one under test.
const concurrentHold = 15 * time.Second

// holdingCommand reports the account it is running as and then keeps the
// session open. The account is taken from what the client printed rather than
// only from the target, so that the two halves of the claim stay independent:
// what the session was logged in AS, and what the target actually HELD.
func holdingCommand() string {
	return fmt.Sprintf("/usr/bin/id -un; /bin/sleep %d", int(concurrentHold.Seconds()))
}

// overlapping starts every session at once and returns a function that collects
// what they produced.
//
// sshE is what makes this possible: it takes no *testing.T precisely so it can
// run off the test goroutine, where t.Fatalf is illegal (0012 added it for the
// outage scenario). Everything asserted here is asserted by the caller, on the
// test goroutine, from the results this hands back.
func overlapping(t *testing.T, sessions ...session) func() []result {
	t.Helper()

	type outcome struct {
		res result
		err error
	}
	done := make(chan outcome, len(sessions))
	for _, s := range sessions {
		go func(s session) {
			res, err := sshE(s)
			done <- outcome{res: res, err: err}
		}(s)
	}

	return func() []result {
		t.Helper()
		out := make([]result, 0, len(sessions))
		for range sessions {
			o := <-done
			if o.err != nil {
				t.Errorf("an overlapping session could not run: %v\n%s", o.err, o.res)
				continue
			}
			out = append(out, o.res)
		}
		return out
	}
}

// testConcurrentProvisioning is the situation the token in an ephemeral
// principal exists for (PLAN §5.1, "Why a per-session account"), and the one
// nothing else in the tree exercises against a real target.
//
// The interesting claim is not that two sessions both worked — a shared account
// would let both work too. It is that the target carried TWO ACCOUNTS while they
// ran: one uid each, so neither session could attach to the other's tmux socket,
// signal its processes or read its files without the proxy seeing a channel
// open, and neither teardown had the other's account to remove.
//
// "While they ran" is therefore observed and not assumed. Run one after the
// other, every assertion below would hold and prove nothing — it would be a
// slower copy of the ephemeral-user scenario that already exists.
func testConcurrentProvisioning(t *testing.T) {
	t.Run("two overlapping sessions get two different accounts", func(t *testing.T) {
		// An earlier scenario's account is removed as its session closes, and
		// that teardown is asynchronous: counting accounts before it finished
		// would count somebody else's.
		waitFor(t, "the target to be free of ephemeral accounts before the overlap", func() bool {
			return len(ephemeralAccountsOn(t)) == 0
		})

		hold := func() session {
			s := aliceOn(proxyDirect, "host.company.com")
			s.command = holdingCommand()
			return s
		}
		collect := overlapping(t, hold(), hold())

		// The whole scenario rests on this: the target's own account database,
		// read while both sessions are live, holding two accounts at once.
		var live []string
		waitUpTo(t, concurrentHold, "both sessions to hold an account on the target at the same moment", func() bool {
			live = ephemeralAccountsOn(t)
			return len(live) == 2
		})
		for _, name := range live {
			if !strings.HasPrefix(name, "hl-") || !strings.Contains(name, "-alice-") {
				t.Errorf("account %q on the target is not an hl-<tag>-alice-<token> account; live: %v", name, live)
			}
		}

		results := collect()
		if len(results) != 2 {
			return // collect() already said which session could not run
		}
		reported := make([]string, 0, 2)
		for i, r := range results {
			wantExit(t, r, fmt.Sprintf("overlapping ephemeral session %d", i+1), 0)
			reported = append(reported, strings.TrimSpace(r.stdout))
		}
		if reported[0] == reported[1] {
			t.Errorf("both sessions logged in as %q; the per-session token is what stops two sessions "+
				"for one login sharing an account (PLAN §5.1)", reported[0])
		}
		// The two accounts the target held are the two accounts the clients
		// were logged in as — not two of one session's and none of the other's.
		if got, want := sortedJoin(reported), sortedJoin(live); got != want {
			t.Errorf("the sessions reported accounts %s, the target held %s at the same moment", got, want)
		}

		// Two teardowns, neither of which took the other's account with it and
		// neither of which left its own behind. The suite-wide leak check runs
		// much later; this one is what attributes a leak to the overlap.
		waitFor(t, "both ephemeral accounts to be removed", func() bool {
			return len(ephemeralAccountsOn(t)) == 0
		})
		if homes := execIn(t, nodeTarget, "sh", "-c", "ls /home"); strings.Contains(homes.stdout, "hl-") {
			t.Errorf("ephemeral home directories left behind by two overlapping sessions:\n%s", homes.stdout)
		}
	})

	// The mirror image (D6a, PLAN §5.2). Nothing is provisioned, so the two
	// sessions do share a uid — and the claim is not isolation but that the
	// method has no per-session state for concurrency to corrupt: both work,
	// and the target is byte-identical afterwards.
	t.Run("two overlapping brokered sessions change nothing on the target", func(t *testing.T) {
		const snapshot = "cat /etc/passwd; cat /home/netadmin/.ssh/authorized_keys; ls -la /home/netadmin /home/netadmin/.ssh"

		// Same reason as the brokered scenario in testTargetCredentials: an
		// ephemeral account disappearing between the two snapshots would read
		// as "brokered-key modified the target".
		waitFor(t, "the target to be free of ephemeral accounts before the snapshot", func() bool {
			return len(ephemeralAccountsOn(t)) == 0
		})

		before := execIn(t, nodeTarget, "sh", "-c", snapshot)
		if before.code != 0 {
			t.Fatalf("snapshot the target: %v", before)
		}

		hold := func() session {
			s := svcOn(proxyDirect, "standing.company.com")
			s.command = holdingCommand()
			return s
		}
		collect := overlapping(t, hold(), hold())

		// The overlap cannot be read out of the account database here — one
		// standing account is the whole point — so it is counted in the
		// processes the two sessions are running as it.
		waitUpTo(t, concurrentHold, "both brokered sessions to be running on the target at the same moment", func() bool {
			return standingSessionsOn(t) == 2
		})

		results := collect()
		if len(results) != 2 {
			return
		}
		for i, r := range results {
			what := fmt.Sprintf("overlapping brokered session %d", i+1)
			wantExit(t, r, what, 0)
			if account := strings.TrimSpace(r.stdout); account != brokeredAccount {
				t.Errorf("%s: logged in as %q, want the standing account %q\n%s", what, account, brokeredAccount, r)
			}
		}

		after := execIn(t, nodeTarget, "sh", "-c", snapshot)
		if after.stdout != before.stdout {
			t.Errorf("two overlapping brokered sessions modified the target:\n--- before ---\n%s\n--- after ---\n%s",
				before.stdout, after.stdout)
		}
	})
}

// brokeredAccount is the standing account every brokered route in the fixtures
// logs in as. It exists on the target image before the proxy ever connects, and
// nothing the proxy does creates or removes it.
const brokeredAccount = "netadmin"

// standingSessionsOn counts the held brokered sessions running on the target.
//
// It counts processes rather than accounts because there is only ever one
// account to count. `who` would not do: an exec channel opens no pty and writes
// no utmp record, so the sessions these scenarios run are invisible to it.
func standingSessionsOn(t *testing.T) int {
	t.Helper()
	r := execIn(t, nodeTarget, "sh", "-c", "pgrep -u "+brokeredAccount+" -x sleep | wc -l")
	n, err := strconv.Atoi(strings.TrimSpace(r.stdout))
	if err != nil {
		t.Fatalf("count the standing account's running sessions from %q: %v", r.stdout, err)
	}
	return n
}

// sortedJoin renders a set of account names so two of them can be compared
// without depending on the order getent or the goroutines happened to produce.
func sortedJoin(names []string) string {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	return strings.Join(sorted, ", ")
}

// --- refused target credentials (prompt 0025) --------------------------------

// refusedTarget is the fixture route whose brokered credential the target does
// not accept (deploy/control/fixtures.template.yaml). No other route names
// `stale-fleet`, so the breaker these scenarios open cannot withhold anything
// else.
const refusedTarget = "refused.company.com"

// testCredentialRejection is the acceptance evidence for phase 0025: the target
// is up and answering, and what it refuses is a credential the PROXY holds.
//
// Phase 0012 found this reported as "the target could not be reached" and
// retried at whatever rate users arrived — and because a decrypting proxy is a
// single source address, the target's own per-source defences then blocked the
// proxy for everybody. `PerSourcePenalties` is off in the target image on
// purpose (deploy/target/entrypoint.sh): containment has to be proven by the
// proxy's own behaviour, not by the target giving up on it.
func testCredentialRejection(t *testing.T) {
	// The proxy's threshold is 2 (deploy/proxy/proxy-direct.yaml), so the first
	// two sessions here reach the target and the third does not.
	t.Run("the user is told a credential was refused, not that the target is unreachable", func(t *testing.T) {
		before := targetRefusedLogins(t)

		s := aliceOn(proxyDirect, refusedTarget)
		s.command = "/bin/echo must-not-run"
		r := ssh(t, s)

		wantFailure(t, r, "refused credential")
		wantNotContains(t, r, "refused credential", "must-not-run")

		// It is an OUTAGE: the proxy's own credential is not something the user
		// can fix by presenting a different one of theirs.
		wantContains(t, r, "refused credential", "not a permissions problem")
		wantNotContains(t, r, "refused credential", "Access denied.")
		wantContains(t, r, "refused credential", "credential for this target was refused")
		// The classification this phase exists to correct.
		wantNotContains(t, r, "refused credential", "the target could not be reached")
		if sessionIDOf(r) == "" {
			t.Errorf("the outage carries no session id as a support reference (PLAN §4.3)\n%s", r)
		}

		// It discloses nothing about the credential: not the reference, not the
		// account, not the method. The target's own name is not on this list —
		// the user typed it, and repeating it back reveals nothing (§4.3).
		for _, leak := range []string{"stale-fleet", "netadmin", "brokered-key"} {
			wantNotContains(t, r, "refused credential", leak)
		}

		// The target really was reached and really did refuse us. This
		// assertion is also what makes the NEXT scenario's negative assertion
		// mean anything: it proves the marker moves when a login is attempted,
		// so a count that does not move is the proxy not attempting one.
		waitFor(t, "the target to record the refused login", func() bool {
			return targetRefusedLogins(t) > before
		})

		rec := waitForPriorityRecord(t, "target.credential_rejected")
		if rec.Attributes["target_addr"] != nodeTarget+":22" {
			t.Errorf("the record names target %q, want %q", rec.Attributes["target_addr"], nodeTarget+":22")
		}
		if rec.Attributes["credential_method"] != "brokered-key" {
			t.Errorf("the record names method %q, want brokered-key", rec.Attributes["credential_method"])
		}
		if rec.Attributes["credential_handle"] != "stale-fleet" {
			t.Errorf("the record names credential %q, want the route's credential_ref",
				rec.Attributes["credential_handle"])
		}
		if rec.Severity != "critical" {
			t.Errorf("the record is %s; a refused credential must not wait in a batch (D8)", rec.Severity)
		}
	})

	t.Run("past the threshold the proxy stops reaching the target", func(t *testing.T) {
		// The second session reaches the threshold.
		s := aliceOn(proxyDirect, refusedTarget)
		s.command = "/bin/true"
		wantFailure(t, ssh(t, s), "refused credential, second attempt")

		// Everything below is measured against the target's own log rather
		// than against elapsed time: "the proxy stopped trying" is a claim
		// about connections, and a timing assertion here would be a flake
		// waiting to happen.
		before := targetRefusedLogins(t)

		r := ssh(t, s)
		wantFailure(t, r, "withheld credential")
		wantContains(t, r, "withheld credential", "is not attempting the connection at present")
		wantNotContains(t, r, "withheld credential", "Access denied.")

		if after := targetRefusedLogins(t); after != before {
			t.Errorf("the target saw %d more login attempts after the breaker opened; it must see none",
				after-before)
		}

		rec := waitForPriorityRecord(t, "target.credential_withheld")
		if rec.Attributes["rejection_breaker"] != "open" || rec.Attributes["rejection_count"] != "2" {
			t.Errorf("the withheld record = %v, want an open breaker at two consecutive rejections",
				rec.Attributes)
		}
	})

	// The assertion that catches the tempting wrong key: containment is scored
	// on the credential and the target, never on the target alone and never on
	// the user or the route.
	t.Run("a different credential to the same target still works", func(t *testing.T) {
		s := svcOn(proxyDirect, "appliance.company.com")
		s.command = "/bin/echo still-working"
		r := ssh(t, s)
		wantExit(t, r, "another credential to the same target", 0)
		wantContains(t, r, "another credential to the same target", "still-working")
	})
}

// --- chain identity rejection (phase 0033) -----------------------------------

// strangerTarget is reached from `proxy-stranger`, whose chain identity the
// fixtures deliberately do not register (deploy/gen-material.sh). It is the one
// route that proxy exists to serve, and it can never succeed.
const strangerTarget = "stranger.company.com"

// testChainIdentityRejection is the acceptance evidence for phase 0033: the
// next proxy is up and answering, and what it refuses is the chain identity key
// the PROXY holds.
//
// Phase 0025 found and fixed this on the proxy→target leg and left it live one
// function away on the proxy→proxy one, where `handshakeNextHop` reported every
// non-host-key handshake failure as "the next proxy in the chain could not be
// reached". The next proxy here is genuinely reachable — it serves
// `deep.company.com` over the very same leg for a proxy the fleet recognises —
// so a run that reports it unreachable is reporting the one part of the estate
// that is working.
//
// The refusal itself is the trust model working (PLAN §6.1): no hop takes an
// upstream's word for who is connecting, and a fingerprint Hoplock Control does
// not know is not one of its proxies. Nothing here asserts otherwise; what is
// asserted is how this proxy reports it.
func testChainIdentityRejection(t *testing.T) {
	t.Run("the user is told this proxy was not accepted, not that the next one is unreachable", func(t *testing.T) {
		s := aliceOn(proxyStranger, strangerTarget)
		s.command = "/bin/echo must-not-run"
		r := ssh(t, s)

		wantFailure(t, r, "refused chain identity")
		wantNotContains(t, r, "refused chain identity", "must-not-run")

		// It is an OUTAGE: the chain identity is the proxy's own credential, and
		// no key of the user's would get them any further.
		wantContains(t, r, "refused chain identity", "not a permissions problem")
		wantNotContains(t, r, "refused chain identity", "Access denied.")
		wantContains(t, r, "refused chain identity", "not accepted by the next proxy in the chain")
		// The classification this phase exists to correct.
		wantNotContains(t, r, "refused chain identity", "could not be reached")
		if sessionIDOf(r) == "" {
			t.Errorf("the outage carries no session id as a support reference (PLAN §4.3)\n%s", r)
		}

		// It discloses nothing about the chain: not which proxy refused us, not
		// where it lives, not the key, and not how far along the session got.
		// Neither the target's name nor the proxy the user connected to is on
		// this list — the user typed both, and repeating them back reveals
		// nothing (§4.3); the OpenSSH client prints the latter itself.
		for _, leak := range []string{proxyDirect, "SHA256:", "chain_proxy_stranger", "hop-auth"} {
			wantNotContains(t, r, "refused chain identity", leak)
		}
	})

	t.Run("a critical record names the hop, the direction and the key's fingerprint", func(t *testing.T) {
		rec := waitForPriorityRecord(t, "chain.identity_rejected")

		if rec.Severity != "critical" {
			t.Errorf("the record is %s; a refused chain identity must not wait in a batch (D8)", rec.Severity)
		}
		if rec.Attributes["hop_next_proxy"] != proxyDirect {
			t.Errorf("the record names next proxy %q, want %q", rec.Attributes["hop_next_proxy"], proxyDirect)
		}
		if rec.Attributes["hop_connection"] != "dial" {
			t.Errorf("the record names direction %q, want dial", rec.Attributes["hop_connection"])
		}
		if rec.Attributes["stage"] != "hop-auth" {
			t.Errorf("the record names stage %q, want hop-auth", rec.Attributes["stage"])
		}

		// The handle is what joins the two sides of one refusal: it is what
		// `ssh-keygen -lf` prints for the key this proxy offered, and what the
		// far hop's own logs will show for the key it turned away. It is never
		// the key, and never a path that would let a reader find one.
		handle := rec.Attributes["credential_handle"]
		if !strings.HasPrefix(handle, "SHA256:") {
			t.Errorf("the record's credential handle = %q, want a key fingerprint", handle)
		}
		if want := chainKeyFingerprint(t, "chain_proxy_stranger"); handle != want {
			t.Errorf("the record's credential handle = %q, want %q — the fingerprint of the key "+
				"proxy-stranger presents", handle, want)
		}
		for key, value := range rec.Attributes {
			if strings.Contains(value, "PRIVATE KEY") || strings.Contains(value, "BEGIN OPENSSH") {
				t.Errorf("record attribute %s carries key material", key)
			}
		}
	})

	// The assertion that keeps the one above from passing for the wrong reason.
	// The leg proxy-stranger was refused on is the SAME leg proxy-nexthop uses
	// successfully, to the same next proxy in the same direction — so the
	// refusal is about the key and about nothing else in the topology.
	t.Run("the same leg still works for a proxy the fleet recognises", func(t *testing.T) {
		s := aliceOn(proxyNextHop, "deep.company.com")
		s.command = "/bin/echo chain-still-working"
		r := ssh(t, s)
		wantExit(t, r, "a registered proxy on the same leg", 0)
		wantContains(t, r, "a registered proxy on the same leg", "chain-still-working")
	})
}

// chainKeyFingerprint reads a generated chain key's SHA256 fingerprint the way
// an operator would, with ssh-keygen inside a node that mounts the material.
//
// It is read rather than hard-coded because the keys are generated per run:
// nothing in this repository can know the value in advance, which is the same
// reason the fixtures are rendered rather than committed.
func chainKeyFingerprint(t *testing.T, name string) string {
	t.Helper()
	r := execIn(t, nodeUser, "ssh-keygen", "-lf", "/material/"+name+".pub")
	if r.code != 0 {
		t.Fatalf("read %s's fingerprint: %v", name, r)
	}
	fields := strings.Fields(r.stdout)
	if len(fields) < 2 {
		t.Fatalf("ssh-keygen -lf printed %q, want \"<bits> <fingerprint> ...\"", r.stdout)
	}
	return fields[1]
}

// targetRefusedLogins counts the logins the target's own sshd saw reach
// authentication and not complete it — which is what a refused credential looks
// like from the target's side, and the only place it is visible at all.
//
// sshd says "authenticating user" only about a connection that got that far and
// then went away, so a successful session never moves this and the count is a
// count of attempts the target actually had to deal with. That is the measure
// containment has to be proven against: not elapsed time, which is a flake
// waiting to happen, and not the proxy's own view, which is the thing under
// test.
func targetRefusedLogins(t *testing.T) int {
	t.Helper()
	r := compose(t, "logs", nodeTarget)
	if r.code != 0 {
		t.Fatalf("read the target's log: %v", r)
	}
	return strings.Count(r.output(), "authenticating user")
}

// waitForPriorityRecord waits for the priority record carrying an event name.
//
// The priority endpoint is where a critical record goes (D8) and the handoff to
// it is non-blocking, so the record lands shortly after the client call returns
// rather than before it.
func waitForPriorityRecord(t *testing.T, event string) logRecord {
	t.Helper()
	var found logRecord
	waitFor(t, "the "+event+" record to reach Hoplock Control", func() bool {
		for _, rec := range fetchLogs(t).Priority {
			if rec.Attributes["event"] == event {
				found = rec
				return true
			}
		}
		return false
	})
	return found
}

// --- target-side enforcement (PLAN §6.5, phase 0019) -------------------------

// testEnforcement is the rungs against a real sshd and a real kernel.
//
// Everything the proxy enforces, it enforces on a string in flight. These
// scenarios are about the half that is not: an account whose executables are
// bounded by a dispatcher sshd runs, and whose sockets are bounded by a
// per-uid packet filter. The claim that a rung also holds for a connection made
// AROUND the proxy cannot be asserted from here — the user node has no route to
// the target and no copy of the session key, which is the whole point of the
// topology — so it is asserted in `make test-sshd` instead, against the same
// image.
func testEnforcement(t *testing.T) {
	// An off-host destination that is genuinely reachable from the target when
	// no rung is in force. A destination nothing could reach anyway would make
	// every assertion below vacuous.
	offHost := hostIPFrom(t, nodeTarget, "control")

	t.Run("an automation account runs its two binaries and nothing else", func(t *testing.T) {
		s := svcOn(proxyDirect, "confined.company.com")
		s.command = "uptime"
		r := ssh(t, s)
		wantExit(t, r, "account-restricted: the permitted binary", 0)

		// The account's whole PATH is the curated directory the rung built, so
		// a bare name resolves there or nowhere.
		s.command = "id -un"
		wantFailure(t, ssh(t, s), "account-restricted: a binary the policy does not name")
	})

	t.Run("the reach rung permits the named destination and refuses the rest", func(t *testing.T) {
		s := svcOn(proxyDirect, "confined.company.com")
		s.command = "nc -z -w 2 127.0.0.1 22"
		wantExit(t, ssh(t, s), "account-egress-restricted: the permitted destination", 0)

		// Same session shape, same binary, a destination the policy did not
		// name. Nothing about this connection is an SSH channel, so
		// `permitted_forwards` never sees it — which is the finding the whole
		// reach axis exists for.
		s.command = "nc -z -w 2 " + offHost + " 8080"
		wantFailure(t, ssh(t, s), "account-egress-restricted: a destination the policy did not name")
	})

	t.Run("an isolated account reaches loopback and nothing off the host", func(t *testing.T) {
		s := svcOn(proxyDirect, "isolated.company.com")
		s.command = "nc -z -w 2 127.0.0.1 22"
		wantExit(t, ssh(t, s), "account-network-isolated: loopback", 0)

		s.command = "nc -z -w 2 " + offHost + " 8080"
		wantFailure(t, ssh(t, s), "account-network-isolated: an off-host destination")
	})

	t.Run("a rung the proxy cannot render is an outage that provisions nothing", func(t *testing.T) {
		before := ephemeralAccountsOn(t)

		s := svcOn(proxyDirect, "unrenderable.company.com")
		s.command = "uptime"
		r := ssh(t, s)
		wantFailure(t, r, "an unrenderable rung")
		// Outage class (PLAN §4.3): a service problem, with the session id to
		// quote, and never a denial — the user asked for nothing wrong.
		wantContains(t, r, "an unrenderable rung", "This is a service problem")
		if sessionIDOf(r) == "" {
			t.Errorf("the outage does not name a session id\n%s", r)
		}
		// The claim is that the refused session provisioned NOTHING, so the
		// assertion is that no account appeared — not that the count is
		// unchanged. A previous scenario's teardown runs concurrently with this
		// sample and legitimately makes the count fall, which an equality check
		// reads as a failure. (It did, on the first CI run to get this far.)
		if appeared := added(before, ephemeralAccountsOn(t)); len(appeared) > 0 {
			t.Errorf("the refused session left accounts behind: %v", appeared)
		}
	})

	t.Run("an attested rung runs, provisions nothing, and is recorded", func(t *testing.T) {
		// The ephemeral accounts are filtered OUT of the snapshot: they churn
		// while this scenario runs — a neighbouring session's teardown is
		// concurrent with both samples — and they are not what this assertion is
		// about. What it claims is that an attested rung configured nothing:
		// the pre-existing account and its key are exactly as they were.
		const snapshot = "grep -v '^hl-' /etc/passwd; cat /home/netadmin/.ssh/authorized_keys"
		before := execIn(t, nodeTarget, "sh", "-c", snapshot)

		s := svcOn(proxyDirect, "attested.company.com")
		s.command = "/bin/echo attested-ok"
		r := ssh(t, s)
		wantExit(t, r, "platform-attested", 0)
		wantContains(t, r, "platform-attested", "attested-ok")

		if after := execIn(t, nodeTarget, "sh", "-c", snapshot); after.stdout != before.stdout {
			t.Errorf("an attested rung modified the target:\n--- before ---\n%s\n--- after ---\n%s",
				before.stdout, after.stdout)
		}
	})

	// The record names the rung IN FORCE on each axis. A record that said
	// "boundary" for a session that ran at a weaker rung is the only outcome
	// here worse than not shipping the feature, so this asserts against what
	// the target was actually made to do above rather than against the route.
	t.Run("the audit record names the rung in force on each axis", func(t *testing.T) {
		wanted := []string{"account-restricted", "account-confined", "platform-attested"}
		var logs debugLogs
		missing := func() []string {
			var absent []string
			for _, rung := range wanted {
				if enforcementRecord(logs, rung) == nil {
					absent = append(absent, rung)
				}
			}
			return absent
		}
		// The wait names WHICH rung is missing rather than timing out on "the
		// records". A rung that never reached a record is usually a rung the
		// target refused, and the refusal says why — but only if the failure
		// points at it.
		waitFor(t, "the enforcement records to reach Hoplock Control (missing so far: "+
			strings.Join(wanted, ", ")+")", func() bool {
			logs = fetchLogs(t)
			return len(missing()) == 0
		})
		if absent := missing(); len(absent) > 0 {
			t.Fatalf("no enforcement record names %s; a rung that produced no record is usually one the target refused, and the proxy's log says why",
				strings.Join(absent, ", "))
		}

		restricted := enforcementRecord(logs, "account-restricted")
		if got := restricted.Attributes["enforcement_reach"]; got != "account-egress-restricted" {
			t.Errorf("reach rung = %q, want the route's\n%+v", got, restricted.Attributes)
		}
		if got := restricted.Attributes["enforcement_verified"]; got != "true" {
			t.Errorf("verified = %q, want true for a rung this proxy applied itself", got)
		}
		if got := restricted.Attributes["enforcement_mechanism_execution"]; !strings.Contains(got, "dispatcher") {
			t.Errorf("mechanism = %q, want it to name what actually enforced the rung", got)
		}

		confined := enforcementRecord(logs, "account-confined")
		if got := confined.Attributes["enforcement_reach"]; got != "account-network-isolated" {
			t.Errorf("reach rung = %q, want the route's\n%+v", got, confined.Attributes)
		}

		attested := enforcementRecord(logs, "platform-attested")
		if got := attested.Attributes["enforcement_verified"]; got != "false" {
			t.Errorf("verified = %q: an attested rung is a claim this system did not check", got)
		}
		if got := attested.Attributes["enforcement_attested_by"]; got != "network-engineering" {
			t.Errorf("attested_by = %q, want the attestation's source", got)
		}
	})
}

// enforcementRecord finds the enforcement record naming one execution rung.
func enforcementRecord(logs debugLogs, rung string) *logRecord {
	for _, set := range [][]logRecord{logs.Batched, logs.Priority} {
		for i := range set {
			r := set[i]
			if r.Attributes["event"] == "enforcement.applied" &&
				r.Attributes["enforcement_execution"] == rung {
				return &set[i]
			}
		}
	}
	return nil
}

// hostIPFrom resolves a name from inside one node, so a scenario can name a
// destination by address rather than relying on the target being able to
// resolve it — which, under a reach rung, it may deliberately not be able to.
func hostIPFrom(t *testing.T, node, name string) string {
	t.Helper()
	r := execIn(t, node, "getent", "hosts", name)
	if r.code != 0 {
		t.Fatalf("%s cannot resolve %s; the reach scenarios would prove nothing\n%s", node, name, r)
	}
	fields := strings.Fields(r.stdout)
	if len(fields) == 0 {
		t.Fatalf("getent hosts %s returned nothing on %s\n%s", name, node, r)
	}
	return fields[0]
}

// added returns the accounts present in after that were not present in before.
func added(before, after []string) []string {
	was := make(map[string]bool, len(before))
	for _, name := range before {
		was[name] = true
	}
	var appeared []string
	for _, name := range after {
		if !was[name] {
			appeared = append(appeared, name)
		}
	}
	return appeared
}

// ephemeralAccountsOn lists the accounts this system has created on the target.
func ephemeralAccountsOn(t *testing.T) []string {
	t.Helper()
	r := execIn(t, nodeTarget, "getent", "passwd")
	if r.code != 0 {
		t.Fatalf("read the target's account database: %v", r)
	}
	var names []string
	for _, line := range strings.Split(r.stdout, "\n") {
		if strings.HasPrefix(line, "hl-") {
			names = append(names, strings.SplitN(line, ":", 2)[0])
		}
	}
	return names
}

// --- device credentials (D13, D14, PLAN §5.3) --------------------------------

// testDeviceCredentials is phase 0014 against a real SSH client.
//
// The device node is a CLI over SSH with no useradd, no authorized_keys and no
// home directory — the gear D13 exists for. What these scenarios watch is that
// a session to it gets an administrator that did not exist a moment earlier, is
// attributable to the person who opened it, and is gone afterwards.
func testDeviceCredentials(t *testing.T) {
	t.Run("a device session logs in as an administrator the proxy created", func(t *testing.T) {
		before := deviceAccounts(t)

		// An appliance session is a CLI, not a command pipe: the client asks
		// for a shell and types. That is also what the driver assumes, and the
		// fake device refuses an exec request exactly as many real appliances
		// do — so a scenario that used `ssh host cmd` here would be testing a
		// shape this method never sees.
		s := aliceOn(proxyDirect, "fortigate.company.com")
		s.stdin = "show system admin\nexit\n"
		r := ssh(t, s)
		wantExit(t, r, "ephemeral-account", 0)

		created := deviceAccountIn(r.stdout)
		if created == "" {
			t.Fatalf("ephemeral-account: the device's administrator table shows no hl-<tag>-alice-<token> account\n%s", r)
		}
		for _, name := range before {
			if name == created {
				t.Fatalf("ephemeral-account: %q existed before the session; the account must not have been adopted", created)
			}
		}
	})

	t.Run("the administrator is removed when the session ends", func(t *testing.T) {
		s := aliceOn(proxyDirect, "fortigate.company.com")
		s.stdin = "show system admin\nexit\n"
		r := ssh(t, s)
		wantExit(t, r, "ephemeral-account", 0)

		// Teardown runs as the session closes, so the check is polled rather
		// than immediate — but it is bounded, because "eventually" is not the
		// guarantee: a standing administrator on a firewall is exactly what
		// this method exists to prevent.
		waitFor(t, "the device administrator to be removed", func() bool {
			accounts, err := tryDeviceAccounts()
			if err != nil {
				return false
			}
			for _, name := range accounts {
				if strings.HasPrefix(name, "hl-") {
					return false
				}
			}
			return true
		})
		if deviceAccountIn(r.stdout) == "" {
			t.Errorf("ephemeral-account: the session never saw its own account\n%s", r)
		}
	})

	// Phase 0016: the same appliance running virtual domains, served by a
	// second listener on the device node. What this watches is that the unit
	// shape the driver used to REFUSE now gets a session, and that the
	// administrator it gets is scoped to the virtual domain the route named
	// rather than to the whole unit.
	t.Run("a session to a unit running virtual domains is scoped to one of them", func(t *testing.T) {
		s := aliceOn(proxyDirect, "fortigate-vdom.company.com")
		// `get system status` rather than `show system admin`: on a partitioned
		// unit the administrator table is a global one, and reading it is not
		// what a per-VDOM administrator is there to do. The account is observed
		// through the audit record and the appliance's own table instead.
		s.stdin = "get system status\nexit\n"
		r := ssh(t, s)
		wantExit(t, r, "ephemeral-account on a partitioned unit", 0)
		wantContains(t, r, "ephemeral-account on a partitioned unit", "Virtual domain configuration: multiple")

		// The mapping event is where the scope has to appear. `device:2222` is
		// the same string whether the administrator was global or scoped to one
		// customer's virtual domain, so an audit record without the field
		// cannot say what the privileged account could reach (PLAN §5.3).
		var scoped logRecord
		waitFor(t, "the account-mapping record for the partitioned unit", func() bool {
			for _, rec := range fetchLogs(t).Priority {
				if rec.Attributes["event"] == "device.account.mapping" && rec.Attributes["device_field.vdom"] == "customer-a" {
					scoped = rec
					return true
				}
			}
			return false
		})
		if got := scoped.Attributes["target_account"]; !strings.HasPrefix(got, "hl-") {
			t.Errorf("the mapping record names account %q, which is not one this proxy created", got)
		}

		// And it is gone afterwards, on this unit as on the other one: a
		// partitioned unit is not a shape where teardown is best-effort.
		waitFor(t, "the administrator on the partitioned unit to be removed", func() bool {
			admins, err := tryDeviceAdministrators(deviceVDOMDebugAddr)
			if err != nil {
				return false
			}
			for _, a := range admins {
				if strings.HasPrefix(a.Name, "hl-") {
					return false
				}
			}
			return true
		})
	})

	// Phase 0029: a FortiSwitch, on a third listener on the appliance node.
	//
	// What this scenario holds in place is a DECISION and not only a driver.
	// 0029's prompt expected a FortiLink-managed switch to be administered
	// through its managing FortiGate — the shape 0016 established for a
	// virtual domain, one level further out — and Fortinet's documentation
	// does not support that: `config switch-controller security-policy
	// local-access` configures a managed switch's own allowaccess list and
	// `ssh` is in the default for both its interfaces. So the switch is its
	// own endpoint with its own host key, and there is no device field on the
	// route at all. If a later phase reintroduces one, this scenario is what
	// makes that a deliberate change.
	t.Run("a session to a FortiSwitch gets an administrator on the switch itself", func(t *testing.T) {
		before, err := tryDeviceAdministrators(deviceSwitchDebugAddr)
		if err != nil {
			t.Fatalf("read the switch's administrator table: %v", err)
		}

		s := aliceOn(proxyDirect, "fortiswitch.company.com")
		// `get system status` because it is the command that proves WHICH box
		// answered: FortiSwitchOS reports a `Version: FortiSwitch-…` line and
		// no virtual-domain configuration, and the driver refuses a unit that
		// does not. A session that landed on either FortiGate would fail here
		// rather than quietly pass.
		s.stdin = "get system status\nshow system admin\nexit\n"
		r := ssh(t, s)
		wantExit(t, r, "ephemeral-account on a FortiSwitch", 0)
		wantContains(t, r, "ephemeral-account on a FortiSwitch", "Version: FortiSwitch")

		created := deviceAccountIn(r.stdout)
		if created == "" {
			t.Fatalf("ephemeral-account on a FortiSwitch: no hl-<tag>-alice-<token> account in the switch's table\n%s", r)
		}
		for _, a := range before {
			if a.Name == created {
				t.Fatalf("ephemeral-account on a FortiSwitch: %q existed before the session; it must not have been adopted", created)
			}
		}

		// The audit record names the switch and not a FortiGate. That is the
		// whole payoff of making the switch its own endpoint: a reviewer
		// asking "what did this session touch" reads one address and does not
		// have to know the FortiLink topology to answer it.
		var mapping logRecord
		waitFor(t, "the account-mapping record for the switch", func() bool {
			for _, rec := range fetchLogs(t).Priority {
				if rec.Attributes["event"] == "device.account.mapping" && rec.Attributes["target_account"] == created {
					mapping = rec
					return true
				}
			}
			return false
		})
		if got := mapping.Attributes["platform"]; got != "fortiswitchos" {
			t.Errorf("the mapping record names platform %q, want fortiswitchos", got)
		}

		// And it is gone afterwards. On this platform that matters more than
		// on a FortiGate: FortiSwitchOS's `set schedule` names a table it does
		// not have, so the driver declares no expiry mechanism and the reaper
		// is the ONLY thing that ever removes one of these accounts.
		waitFor(t, "the administrator on the switch to be removed", func() bool {
			admins, err := tryDeviceAdministrators(deviceSwitchDebugAddr)
			if err != nil {
				return false
			}
			for _, a := range admins {
				if strings.HasPrefix(a.Name, "hl-") {
					return false
				}
			}
			return true
		})

		// The switch's own administrator is untouched, exactly as on the two
		// FortiGates.
		admins, err := tryDeviceAdministrators(deviceSwitchDebugAddr)
		if err != nil {
			t.Fatalf("read the switch's administrator table: %v", err)
		}
		found := false
		for _, a := range admins {
			if a.Name == "admin" {
				found = true
			}
		}
		if !found {
			t.Errorf("the switch's own administrator is gone; the proxy must only ever remove what it created (have: %+v)", admins)
		}
	})

	t.Run("the device's own administrator is never touched", func(t *testing.T) {
		accounts := deviceAccounts(t)
		found := false
		for _, name := range accounts {
			if name == "admin" {
				found = true
			}
		}
		if !found {
			t.Errorf("the device's own administrator is gone; the proxy must only ever remove what it created (have: %v)", accounts)
		}
	})

	// D14: an unsatisfiable first entry is skipped and the session is served by
	// the next one. Nothing here is proxy-invented — the ladder, and its order,
	// are the server's.
	t.Run("an unsatisfiable ladder entry falls through to the next", func(t *testing.T) {
		s := aliceOn(proxyDirect, "ladder.company.com")
		s.command = "/bin/echo ladder-ok"
		r := ssh(t, s)
		wantExit(t, r, "ladder fall-through", 0)
		wantContains(t, r, "ladder fall-through", "ladder-ok")

		// The rung in force is an AUDIT fact and never a user-facing one (D14):
		// the client was told nothing about which credential it got, and the
		// record says which one that was.
		if strings.Contains(r.stderr, "ephemeral-account") || strings.Contains(r.stderr, "brokered") {
			t.Errorf("the client was told which credential rung it got:\n%s", r.stderr)
		}
	})
}

// deviceAccountIn finds this proxy's administrator in `show system admin`
// output, which renders one entry per `edit "<name>"` line.
func deviceAccountIn(out string) string {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 2 || fields[0] != "edit" {
			continue
		}
		name := strings.Trim(fields[1], `"`)
		// Both device platforms accept names above PLAN §5.3's threshold of
		// 32 — FortiOS documents 64, and the FortiSwitch driver declares a
		// conservative 35 for a field Fortinet gives no size for — so the
		// readable scheme survives on each and the account on the device names
		// the person it belongs to. This helper reads either unit's table.
		if strings.HasPrefix(name, "hl-") && strings.Contains(name, "-alice-") {
			return name
		}
	}
	return ""
}

// --- disclosure (PLAN §4.3) --------------------------------------------------

// testDenialDisclosure is the deny half of the rule: vague, and identical
// whatever was actually wrong. The outage half is testOutage.
func testDenialDisclosure(t *testing.T) {
	const target = "forbidden.company.com"

	s := aliceOn(proxyDirect, target)
	s.command = "/bin/echo must-not-run"
	r := ssh(t, s)

	wantFailure(t, r, "unauthorized target")
	wantNotContains(t, r, "unauthorized target", "must-not-run")
	wantContains(t, r, "unauthorized target", "Access denied.")

	// It is a denial, not an outage: the two branches must never converge.
	wantNotContains(t, r, "unauthorized target", "not a permissions problem")

	// Nothing may say whether the target exists, which credential method it
	// would have used, or which permission set applied. A precise denial is a
	// directory of the estate, given away one login attempt at a time.
	for _, leak := range []string{target, "ephemeral-user", "brokered-key", "readOnlyGroup", "deployGroup"} {
		wantNotContains(t, r, "unauthorized target", leak)
	}
}

// --- password + out-of-band MFA (PLAN §4.1, §4.3) ----------------------------

// The password users in deploy/control/fixtures.template.yaml. Neither has a
// key, so neither has any way in but the fallback method. These are test
// fixtures; the password is never a secret and never reaches a log (D8).
const (
	mfaLogin    = "bob"
	mfaPassword = "bob-e2e-password"

	mfaDeniedLogin    = "mallory"
	mfaDeniedPassword = "mallory-e2e-password"

	// mfaPrompt is the fixture's own challenge text. Asserting on the SERVER's
	// wording rather than the proxy's default is what shows the prompt travelled
	// end to end: Hoplock Control knows which factor the user actually has, and
	// user.DefaultMFAPrompt is only what the proxy says when it was told nothing.
	mfaPrompt = "Approve the Hoplock Proxy sign-in on your phone."

	// mfaProgress is the "still waiting" line the proxy repeats while polling.
	mfaProgress = "Still waiting for approval"
)

// testPasswordMFA is the method PLAN §4.1 falls back to, against a real OpenSSH
// client for the first time. Phase 0012's topology was certificate-only, so
// everything below had unit-test evidence and nothing else.
//
// Only proxy-direct offers the method (deploy/proxy/proxy-direct.yaml), and only
// these scenarios ask for it: sshBaseArgs still pins publickey, so every other
// scenario in the suite is on the certificate path exactly as before.
func testPasswordMFA(t *testing.T) {
	// One invocation carries three assertions because they are three properties
	// of the same login, and re-running it to assert them separately would be
	// three MFA waits proving one thing each.
	t.Run("an approved second factor reaches the target, and the wait is explained", func(t *testing.T) {
		s := mfaOn(proxyDirect, mfaLogin, mfaPassword, "host.company.com")
		s.command = "/usr/bin/id -un"
		r := ssh(t, s)

		wantExit(t, r, "password-mfa approval", 0)
		// The challenge the server issued reached the person waiting on it.
		wantContains(t, r, "password-mfa approval", mfaPrompt)
		// And the wait was explained while it lasted. This is the entire reason
		// the flow rides keyboard-interactive rather than plain password auth
		// (PLAN §4.3): password auth has no field to say this in, and a user
		// staring at a frozen terminal cannot tell a pending approval from a
		// hung proxy. The fixture's `pending_polls` is what makes the wait long
		// enough to have a middle.
		wantContains(t, r, "password-mfa approval", mfaProgress)

		// The session is a real session on the far side, not just an accepted
		// authentication: it provisioned an account and ran a command on it.
		account := strings.TrimSpace(r.stdout)
		if !strings.HasPrefix(account, "hl-") || !strings.Contains(account, "-"+mfaLogin+"-") {
			t.Errorf("password-mfa approval: ran as %q, want an hl-<tag>-%s-<token> account\n%s",
				account, mfaLogin, r)
		}
	})

	// The disclosure rule on a second axis (PLAN §4.3). testDenialDisclosure
	// asserts a denial never says which TARGET; this asserts it never says which
	// FACTOR. A message that separated "wrong password" from "MFA refused" would
	// hand an attacker a password oracle one login attempt at a time.
	t.Run("a denied second factor discloses no factor", func(t *testing.T) {
		s := mfaOn(proxyDirect, mfaDeniedLogin, mfaDeniedPassword, "host.company.com")
		s.command = "/bin/echo must-not-run"
		denied := ssh(t, s)

		wantFailure(t, denied, "denied second factor")
		wantNotContains(t, denied, "denied second factor", "must-not-run")
		wantContains(t, denied, "denied second factor", "Access denied.")
		// A denial, not an outage: the two branches must never converge.
		wantNotContains(t, denied, "denied second factor", "not a permissions problem")
		for _, leak := range []string{"password", "Password", "MFA", "mfa", "second factor", "approval was"} {
			wantNotContains(t, denied, "denied second factor", leak)
		}

		// The other half of the claim, and the half no assertion on wording can
		// make on its own: a login whose FIRST factor was wrong must be told the
		// same thing. Mallory's password is right and her approval is refused;
		// this one's password is wrong and never reaches a second factor. If the
		// two endings differ, the difference is the oracle.
		wrong := mfaOn(proxyDirect, mfaLogin, "not-"+mfaPassword, "host.company.com")
		wrong.command = "/bin/echo must-not-run"
		refused := ssh(t, wrong)

		wantFailure(t, refused, "wrong password")
		if got, want := endingOf(refused), endingOf(denied); got != want {
			t.Errorf("a wrong password ends with %q and a refused second factor with %q; "+
				"a denial that separates the two is a password oracle (PLAN §4.3)", got, want)
		}

		// What this does NOT claim: that the two runs are indistinguishable.
		// They are not — a correct password gets an MFA challenge and a wrong
		// one never does, so the presence of the challenge tells an attacker
		// the first factor was right. That is a property of asking for an
		// out-of-band approval at all, it is decided by Hoplock Control rather
		// than by the proxy, and it is not something this phase may quietly fix
		// under the heading of a test. It is written up in
		// prompts/queued/0034-mfa-challenge-first-factor-oracle.md.
	})

	// The audit trail is where the estate sees which method let someone in, and
	// it is the only place a certificate login and a password+MFA login are
	// distinguishable after the fact.
	t.Run("the audit trail attributes the session to password-mfa", func(t *testing.T) {
		s := mfaOn(proxyDirect, mfaLogin, mfaPassword, "host.company.com")
		s.command = "/bin/echo audited"
		r := ssh(t, s)
		wantExit(t, r, "password-mfa audit", 0)

		id := sessionIDOf(r)
		if id == "" {
			t.Fatalf("the proxy quoted no session id, so its records cannot be found\n%s", r)
		}

		var auth *logRecord
		var logs debugLogs
		waitFor(t, "the session's authentication record to reach Hoplock Control", func() bool {
			logs = fetchLogs(t)
			auth = recordFor(logs, id, "auth")
			return auth != nil
		})
		if got := auth.Attributes["auth_method"]; got != "password-mfa" {
			t.Errorf("session %s authenticated over keyboard-interactive is recorded as auth_method=%q, want %q",
				id, got, "password-mfa")
		}
		if auth.Login != mfaLogin {
			t.Errorf("session %s is attributed to login %q, want %q", id, auth.Login, mfaLogin)
		}
		if start := recordFor(logs, id, "session_start"); start == nil {
			t.Errorf("session %s produced no session_start record", id)
		} else if got := start.Attributes["auth_method"]; got != "password-mfa" {
			t.Errorf("session %s starts with auth_method=%q, want %q", id, got, "password-mfa")
		}

		// The initial-auth password is never logged (D8, PLAN §7), and this is
		// the only run in the suite where the proxy has ever held one. Every
		// record delivered so far, not just this session's: a leak into some
		// other record would still be the password in the audit store.
		for _, set := range [][]logRecord{logs.Batched, logs.Priority} {
			for _, rec := range set {
				if rec.mentions(mfaPassword) {
					t.Errorf("a %s record names the initial-auth password; it must never be logged (PLAN §7)", rec.Kind)
				}
			}
		}
	})
}

// endingOf is the last thing the PROXY said before the connection closed — the
// message the user is left holding, and the one PLAN §4.3's disclosure rule is
// about.
//
// Two failures cannot be compared on their whole output. OpenSSH signs off with
// the username it was invoked with ("bob#host.company.com@proxy-direct:
// Permission denied"), the proxy's banner carries a session id that is different
// every time, and the client warns about the host key it just learned. All three
// differ between any two runs whatever the proxy said, so a comparison that kept
// them would fail always and assert nothing.
func endingOf(r result) string {
	var last string
	for _, line := range strings.Split(r.output(), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case strings.Contains(line, "Permission denied"):
		case strings.Contains(line, "Session sess-"):
		case strings.HasPrefix(line, "Warning: Permanently added"):
		default:
			last = line
		}
	}
	return last
}

// recordFor finds one session's record of a given kind, wherever it was
// delivered: an authentication record rides the batch, but a phase that made one
// urgent would move it to the priority endpoint without changing what it says.
func recordFor(logs debugLogs, sessionID, kind string) *logRecord {
	for _, set := range [][]logRecord{logs.Batched, logs.Priority} {
		for i := range set {
			if set[i].SessionID == sessionID && set[i].Kind == kind {
				return &set[i]
			}
		}
	}
	return nil
}

// --- telemetry (D8) ----------------------------------------------------------

func testTelemetry(t *testing.T) {
	// The scenarios above produced these; the shipper batches on a timer, so
	// the batched path is waited for rather than read once.
	var logs debugLogs
	waitFor(t, "a batch of session records to reach Hoplock Control", func() bool {
		logs = fetchLogs(t)
		return countKind(logs.Batched, "session_start") > 0 && countKind(logs.Batched, "session_end") > 0
	})

	if n := countKind(logs.Batched, "command"); n == 0 {
		t.Errorf("no command records were delivered; %d batched records in total", len(logs.Batched))
	}

	// A refusal does not wait in a batch behind the session it was refused on
	// (D8): it goes immediately, over the priority endpoint. Every one of these
	// was produced by a scenario above.
	if len(logs.Priority) == 0 {
		t.Fatalf("no priority records were delivered; blocked commands and denials must not wait in a batch")
	}
	// Each of these was refused by a scenario above. Several are refusals the
	// SSH client never rendered — it abandoned the channel first — so the audit
	// record is the only place the estate can see them at all, which is most of
	// why they take the immediate path.
	for _, want := range []string{
		"reboot",   // a blocked command
		"shutdown", // a command that killed the session
		"Channel type session is not available on this session.",
		"The sftp subsystem is not available on this session.",
		"An interactive terminal is not available on this session.",
		"Forwarding to target:80 is not available on this session.",
	} {
		if !mentionedIn(logs.Priority, want) {
			t.Errorf("no priority record mentions %q; %d priority records in total", want, len(logs.Priority))
		}
	}
}

func countKind(records []logRecord, kind string) int {
	n := 0
	for _, r := range records {
		if r.Kind == kind {
			n++
		}
	}
	return n
}

func mentionedIn(records []logRecord, text string) bool {
	for _, r := range records {
		if r.mentions(text) {
			return true
		}
	}
	return false
}

// --- the other session bounds (D16, phase 0031) ------------------------------

// The fixture routes, one per bound (deploy/control/fixtures.template.yaml).
const (
	// recordedTarget may only run if the session is recorded.
	recordedTarget = "recorded.company.com"
	// cappedSubjectTarget allows one live session per SUBJECT.
	cappedSubjectTarget = "capped.company.com"
	// cappedPerTarget allows one live session TO THE TARGET, across subjects.
	cappedPerTarget = "capped-target.company.com"
	// grantedTarget and grantedFieldsTarget carry a grant context, in the two
	// forms additional_context takes.
	grantedTarget       = "granted.company.com"
	grantedFieldsTarget = "granted-fields.company.com"
)

// testSessionBounds is the acceptance evidence for the three session bounds the
// proxy enforces that are not the deadline (docs/PLAN.md §6.5, D16).
//
// Each subtest asserts the bound AND the class PLAN §4.3 puts its refusal in,
// because the class is half the feature: a capture refusal that read as a denial
// would send a user to ask for permissions they already have, and a full ceiling
// that read as an outage would tell them the estate is broken when it is busy.
func testSessionBounds(t *testing.T) {
	t.Run("a route that must be recorded runs while the log destination is down", func(t *testing.T) {
		// The proxy's disk buffer is a logging path (PLAN §7), so a proxy
		// spooling to it satisfies the bound. Refusing these sessions would turn
		// every log-destination outage into an outage of the estate, for exactly
		// the routes that are watched most closely.
		const marker = "capture-while-buffering"
		t.Cleanup(func() { setLogSink(t, true) })
		setLogSink(t, false)

		s := aliceOn(proxyDirect, recordedTarget)
		s.command = "/bin/echo " + marker
		r := ssh(t, s)

		wantExit(t, r, "a recorded route while the log destination is down", 0)
		wantContains(t, r, "a recorded route while the log destination is down", marker)
		wantNotContains(t, r, "a recorded route while the log destination is down", "could not be recorded")
		wantNotContains(t, r, "a recorded route while the log destination is down", "Access denied.")

		// And the records were not lost: they were owed, and they arrive when
		// the destination does.
		setLogSink(t, true)
		var sessionID string
		waitFor(t, "the buffered records of the recorded session to drain", func() bool {
			sessionID = sessionOfRecord(t, marker)
			return sessionID != ""
		})
		// The bound is on the decision, so it is on the record of the decision:
		// an auditor reading a session that ran has to be able to see that this
		// one would have been refused unrecorded.
		if !recordAttrIs(recordsOfSession(t, sessionID), "authorize", "session_capture_required", "true") {
			t.Errorf("session %s has no authorize record saying capture was required:\n%s",
				sessionID, formatRecords(recordsOfSession(t, sessionID)))
		}
	})

	t.Run("a subject at its ceiling is denied, and the slot comes back", func(t *testing.T) {
		// An earlier scenario's account is removed as its session closes, and
		// that teardown is asynchronous: counting accounts before it finished
		// would count somebody else's session as this ceiling's.
		waitFor(t, "the target to be free of ephemeral accounts before the ceiling", func() bool {
			return len(ephemeralAccountsOn(t)) == 0
		})

		hold := aliceOn(proxyDirect, cappedSubjectTarget)
		hold.command = holdingCommand()
		collect := overlapping(t, hold)
		// The ceiling is only being tested if the first session is LIVE when the
		// second arrives, and the account on the target is what says so: the
		// admission check runs before anything is provisioned.
		waitUpTo(t, concurrentHold, "the first capped session to hold an account on the target", func() bool {
			return len(ephemeralAccountsOn(t)) == 1
		})

		second := aliceOn(proxyDirect, cappedSubjectTarget)
		second.command = "/bin/true"
		r := ssh(t, second)

		wantFailure(t, r, "a second session at the subject's ceiling")
		wantContains(t, r, "a second session at the subject's ceiling", "Access denied.")
		// A DENIAL, not an outage: the estate is healthy and the answer is no.
		wantNotContains(t, r, "a second session at the subject's ceiling", "not a permissions problem")
		// And a vague one: not the cap, not how many sessions are live, not
		// whose, and nothing about the target. The session id is NOT on this
		// list — every session is given its own in the pre-auth banner
		// (user.BannerMessage), so it is not something a denial discloses.
		for _, leak := range []string{"ceiling", "concurren", "limit", cappedSubjectTarget} {
			wantNotContains(t, r, "a second session at the subject's ceiling", leak)
		}

		results := collect()
		if len(results) == 1 {
			wantExit(t, results[0], "the session that held the only slot", 0)
		}

		// The cap that was hit exists only on the audit record, and it is a
		// POLICY DECISION there rather than a fault.
		var refusal logRecord
		waitFor(t, "the refusal record naming the subject ceiling", func() bool {
			refusal = findRecord(t, func(rec logRecord) bool {
				return rec.Attributes["concurrency_scope"] == "subject"
			})
			return refusal.SessionID != ""
		})
		for key, want := range map[string]string{
			"concurrency_limit": "1",
			"concurrency_live":  "1",
		} {
			if got := refusal.Attributes[key]; got != want {
				t.Errorf("the refusal record carries %s=%q, want %q", key, got, want)
			}
		}
		if refusal.Kind != "policy_decision" || refusal.Severity != "critical" {
			t.Errorf("the refusal was recorded as %s/%s, want policy_decision/critical",
				refusal.Kind, refusal.Severity)
		}

		// The slot comes back. A cap that did not give one up would turn the
		// first session of a proxy's life into its only one.
		waitFor(t, "the capped session's account to be removed", func() bool {
			return len(ephemeralAccountsOn(t)) == 0
		})
		third := aliceOn(proxyDirect, cappedSubjectTarget)
		third.command = "/bin/true"
		wantExit(t, ssh(t, third), "the next session after the slot was freed", 0)
	})

	t.Run("a target at its ceiling refuses a second subject", func(t *testing.T) {
		// The scope that is not reachable through the other one: the subject
		// refused here has no session anywhere and no per-subject cap at all.
		waitFor(t, "the target to be free of ephemeral accounts before the target ceiling", func() bool {
			return len(ephemeralAccountsOn(t)) == 0
		})

		hold := aliceOn(proxyDirect, cappedPerTarget)
		hold.command = holdingCommand()
		collect := overlapping(t, hold)
		waitUpTo(t, concurrentHold, "the first session to hold the target's only slot", func() bool {
			return len(ephemeralAccountsOn(t)) == 1
		})

		other := svcOn(proxyDirect, cappedPerTarget)
		other.command = "/bin/true"
		r := ssh(t, other)

		wantFailure(t, r, "a second subject at the target's ceiling")
		wantContains(t, r, "a second subject at the target's ceiling", "Access denied.")
		wantNotContains(t, r, "a second subject at the target's ceiling", "not a permissions problem")

		results := collect()
		if len(results) == 1 {
			wantExit(t, results[0], "the session that held the target's only slot", 0)
		}

		var refusal logRecord
		waitFor(t, "the refusal record naming the target ceiling", func() bool {
			refusal = findRecord(t, func(rec logRecord) bool {
				return rec.Attributes["concurrency_scope"] == "target"
			})
			return refusal.SessionID != ""
		})
		if refusal.Login != "svc-deploy" {
			t.Errorf("the refusal is attributed to %q, want the subject that was refused", refusal.Login)
		}
		if got := refusal.Attributes["concurrency_limit"]; got != "1" {
			t.Errorf("the refusal record carries a limit of %q, want 1", got)
		}
		waitFor(t, "the capped target's account to be removed", func() bool {
			return len(ephemeralAccountsOn(t)) == 0
		})
	})

	t.Run("a grant context is on every record of the session and nowhere else", func(t *testing.T) {
		const marker = "grant-context-text"
		s := aliceOn(proxyDirect, grantedTarget)
		s.command = "/bin/echo " + marker
		r := ssh(t, s)
		wantExit(t, r, "a route carrying a grant context", 0)

		// The user is told nothing about it, on any path: the grant context is
		// about the estate's reasons, not about the user's own request.
		for _, secret := range []string{"change-management", "CHG-1234", "Tuesday CAB", "2026-03-01"} {
			wantNotContains(t, r, "a route carrying a grant context", secret)
		}

		var records []logRecord
		waitFor(t, "the granted session's records to arrive", func() bool {
			id := sessionOfRecord(t, marker)
			if id == "" {
				return false
			}
			records = recordsOfSession(t, id)
			return hasKind(records, "session_end")
		})
		// Verbatim, on every record the session produced after the decision. The
		// two before it — the handshake's and the authentication's — carry less,
		// because nothing knew it yet.
		want := map[string]string{
			"grant_system":             "change-management",
			"grant_reference":          "CHG-1234",
			"grant_window_start":       "2026-03-01T09:00:00Z",
			"grant_window_end":         "2026-03-01T17:00:00Z",
			"grant_additional_context": "approved by the Tuesday CAB",
		}
		checked := 0
		for _, rec := range records {
			if rec.Kind == "session_start" || rec.Kind == "auth" {
				continue
			}
			checked++
			for key, value := range want {
				if got := rec.Attributes[key]; got != value {
					t.Errorf("%s record carries %s=%q, want %q", rec.Kind, key, got, value)
				}
			}
		}
		if checked == 0 {
			t.Errorf("no record of the granted session was checked:\n%s", formatRecords(records))
		}
	})

	t.Run("the object form of additional context arrives as fields", func(t *testing.T) {
		// Not a different spelling of the string form but a different thing:
		// each field is its own attribute, so "every session this scan
		// authorised" stays a query rather than a substring search.
		const marker = "grant-context-fields"
		s := aliceOn(proxyDirect, grantedFieldsTarget)
		s.command = "/bin/echo " + marker
		r := ssh(t, s)
		wantExit(t, r, "a route carrying an object grant context", 0)
		for _, secret := range []string{"vuln-scanner", "scan-7781", "s-99", "secops"} {
			wantNotContains(t, r, "a route carrying an object grant context", secret)
		}

		var records []logRecord
		waitFor(t, "the scanner session's records to arrive", func() bool {
			id := sessionOfRecord(t, marker)
			if id == "" {
				return false
			}
			records = recordsOfSession(t, id)
			return hasKind(records, "session_end")
		})
		for key, value := range map[string]string{
			"grant_system":                          "vuln-scanner",
			"grant_additional_context.scan_id":      "s-99",
			"grant_additional_context.requested_by": "secops",
		} {
			if !recordAttrIs(records, "session_end", key, value) {
				t.Errorf("the session_end record does not carry %s=%q:\n%s",
					key, value, formatRecords(records))
			}
		}
		for _, rec := range records {
			if _, ok := rec.Attributes["grant_additional_context"]; ok {
				t.Errorf("%s record also carries the object form as one string: %v",
					rec.Kind, rec.Attributes["grant_additional_context"])
			}
		}
	})
}

// findRecord is the first delivered record matching want, on either path, or the
// zero record.
func findRecord(t *testing.T, want func(logRecord) bool) logRecord {
	t.Helper()
	logs := fetchLogs(t)
	for _, rec := range append(append([]logRecord{}, logs.Priority...), logs.Batched...) {
		if want(rec) {
			return rec
		}
	}
	return logRecord{}
}

// recordAttrIs reports whether some record of a kind carries the attribute.
func recordAttrIs(records []logRecord, kind, key, want string) bool {
	for _, rec := range records {
		if rec.Kind == kind && rec.Attributes[key] == want {
			return true
		}
	}
	return false
}

// hasKind reports whether a record of this kind is among them.
func hasKind(records []logRecord, kind string) bool {
	for _, rec := range records {
		if rec.Kind == kind {
			return true
		}
	}
	return false
}

// formatRecords renders records for a failure message: a scenario that fails on
// an attribute is usually failing because a different record than expected
// arrived.
func formatRecords(records []logRecord) string {
	var b strings.Builder
	for _, rec := range records {
		fmt.Fprintf(&b, "  %s/%s %v\n", rec.Kind, rec.Severity, rec.Attributes)
	}
	return b.String()
}

// --- session deadline (D16, phase 0024) --------------------------------------

// deadlineHold is how long the held session asks for. It has to outlive the
// route's own deadline comfortably, because the assertion is that the PROXY
// ended the session and not that the command finished.
const deadlineHold = 120

// expiringTarget is the fixture route Hoplock Control bounds in time
// (deploy/control/fixtures.template.yaml). Its deadline is 30 seconds and the
// proxies' warning lead time is 8, so a session on it is warned and then closed
// well inside one client invocation.
const expiringTarget = "expiring.company.com"

// heldOnExpiringRoute is a session that would run for minutes if nothing ended
// it, with an optional command run first.
func heldOnExpiringRoute(setup string) session {
	s := aliceOn(proxyDirect, expiringTarget)
	s.opts = []string{"-tt"}
	s.stdin = fmt.Sprintf("%secho deadline-marker\nsleep %d\nexit\n", setup, deadlineHold)
	return s
}

// testSessionDeadline is the acceptance evidence for the one session bound the
// proxy enforces itself (docs/PLAN.md §6.5, D16).
//
// Every subtest here holds a session open past its deadline, so this group
// costs about two minutes of wall clock. That is the feature: a deadline
// cannot be demonstrated faster than it elapses.
func testSessionDeadline(t *testing.T) {
	t.Run("the user is warned, then told the session reached its authorized end", func(t *testing.T) {
		r := ssh(t, heldOnExpiringRoute(""))

		// The session ran; it was not refused before it started.
		wantContains(t, r, "session deadline", "deadline-marker")
		// Both messages, and the warning first — a warning after the fact is
		// not a warning.
		wantContains(t, r, "session deadline", "reaches its authorized end in")
		wantContains(t, r, "session deadline", "has reached its authorized end")
		out := r.output()
		if warned, expired := strings.Index(out, "reaches its authorized end in"),
			strings.Index(out, "has reached its authorized end"); warned > expired {
			t.Errorf("session deadline: the warning came after the expiry message\n%s", r)
		}
		// Reconnecting is the remedy, which is the opposite of what an outage
		// message says — and it is neither of PLAN §4.3's two branches.
		wantContains(t, r, "session deadline", "reconnect")
		wantNotContains(t, r, "session deadline", "Access denied.")
		wantNotContains(t, r, "session deadline", "not a permissions problem")
		// Nothing about the policy, who set the deadline, or what the route
		// allows.
		wantNotContains(t, r, "session deadline", "readOnlyGroup")

		// 253, not the 254 a policy kill reports and not the 0 a finished
		// command would: a pipeline can tell "time ran out" from "policy
		// stopped you" without reading the text.
		wantExit(t, r, "session deadline", 253)
	})

	t.Run("the ephemeral account is gone afterwards", func(t *testing.T) {
		// The same claim testNoEphemeralLeak makes at the end of the run,
		// reached by a different path: teardown ran because the session
		// EXPIRED, not because anyone closed it. The account is watched into
		// existence first, or "no account is left" would also be true of a
		// session that never provisioned one.
		held := make(chan result, 1)
		go func() {
			r, err := sshE(heldOnExpiringRoute(""))
			if err != nil {
				t.Errorf("the held session could not be run: %v\n%s", err, r)
			}
			held <- r
		}()

		waitFor(t, "the expiring session's ephemeral account to be created", func() bool {
			return strings.Contains(execIn(t, nodeTarget, "getent", "passwd").stdout, "hl-")
		})

		r := <-held
		wantContains(t, r, "expiry teardown", "has reached its authorized end")
		waitFor(t, "the expired session's ephemeral account to be removed", func() bool {
			return !strings.Contains(execIn(t, nodeTarget, "getent", "passwd").stdout, "hl-")
		})
		if homes := execIn(t, nodeTarget, "sh", "-c", "ls /home"); strings.Contains(homes.stdout, "hl-") {
			t.Errorf("an ephemeral home survived the expiry:\n%s", homes.stdout)
		}
	})

	t.Run("a backgrounded process does not survive the expiry", func(t *testing.T) {
		// This is what makes docs/PLAN.md §5.1's paragraph on detached work
		// true rather than aspirational: teardown runs `pkill -KILL -u`, so
		// nohup buys nothing. The sleep is long enough that finding it gone can
		// only mean it was killed.
		const marker = "4242"
		r := ssh(t, heldOnExpiringRoute("nohup sleep "+marker+" >/dev/null 2>&1 &\n"))
		wantContains(t, r, "detached work", "has reached its authorized end")

		waitFor(t, "the detached process to be killed with its session", func() bool {
			return execIn(t, nodeTarget, "pgrep", "-f", "sleep "+marker).code != 0
		})
	})

	t.Run("the deadline holds with Hoplock Control stopped", func(t *testing.T) {
		// The reason the deadline is enforced locally at all (§6.4): revocation
		// needs the event stream, and an immortal privileged session is least
		// acceptable exactly when that stream is down. Without this subtest the
		// feature is untested where it matters.
		before := fetchLogs(t)
		held := make(chan result, 1)
		go func() {
			r, err := sshE(heldOnExpiringRoute(""))
			if err != nil {
				t.Errorf("the held session could not be run: %v\n%s", err, r)
			}
			held <- r
		}()

		waitFor(t, "the held session to reach Hoplock Control", func() bool {
			return countKind(fetchLogs(t).Batched, "session_start") > countKind(before.Batched, "session_start")
		})

		if r := compose(t, "stop", nodeControl); r.code != 0 {
			t.Fatalf("stop Hoplock Control: %v", r)
		}
		restarted := false
		restart := func() {
			if restarted {
				return
			}
			restarted = true
			if r := compose(t, "start", nodeControl); r.code != 0 {
				t.Errorf("restart Hoplock Control: %v", r)
			}
		}
		t.Cleanup(restart)

		r := <-held
		wantContains(t, r, "deadline with control stopped", "has reached its authorized end")
		wantExit(t, r, "deadline with control stopped", 253)
		sessionID := sessionIDOf(r)
		if sessionID == "" {
			t.Fatalf("could not read the expired session's id from what it was told\n%s", r)
		}

		restart()
		waitFor(t, "Hoplock Control to answer again", func() bool {
			_, err := tryFetchLogs()
			return err == nil
		})
		// The record drains from the proxy's disk buffer once Control is back,
		// which is also what leaves the outage scenario below a delivered
		// history to compare against. An operator asking why this session
		// stopped reads `end_reason`, not the absence of anything else.
		waitFor(t, "the expired session's records to drain", func() bool {
			for _, rec := range fetchLogs(t).Batched {
				if rec.SessionID != sessionID || rec.Kind != "session_end" {
					continue
				}
				if got := rec.Attributes["end_reason"]; got != "session_deadline" {
					t.Errorf("session_end end_reason = %q, want %q", got, "session_deadline")
				}
				return true
			}
			return false
		})
	})
}

// --- outage ------------------------------------------------------------------

// outageHold is how long the session that straddles the outage stays open. It
// has to outlive stopping Hoplock Control and the failed connection below it,
// with room to spare on a loaded CI runner.
const outageHold = 30

// testOutage is the other half of the disclosure rule and the other half of
// D8's resilience story, in one scenario because they are one event: with
// Hoplock Control stopped the user must be told this is an outage rather than a
// denial, and the records describing what happened must survive to be delivered
// when it comes back.
//
// The buffering half needs a session that OUTLIVES the outage. A connection
// attempted while Hoplock Control is down never authenticates — the proxy never
// caches an authentication (D2) — so it produces no session records at all, and
// asserting on the disk buffer after one would assert nothing. So a session is
// opened first, held open across the stop, and ended before the restart: every
// record it produced in between had nowhere to go but the buffer.
//
// It runs last: it stops a node every other scenario depends on.
func testOutage(t *testing.T) {
	before := fetchLogs(t)
	if len(before.Batched) == 0 {
		t.Fatalf("nothing had been delivered before the outage; this scenario would prove nothing")
	}

	held := make(chan result, 1)
	go func() {
		s := aliceOn(proxyDirect, "host.company.com")
		s.opts = []string{"-tt"}
		s.stdin = fmt.Sprintf("echo outage-marker\nsleep %d\nexit\n", outageHold)
		r, err := sshE(s)
		if err != nil {
			t.Errorf("the held session could not be run: %v\n%s", err, r)
		}
		held <- r
	}()

	waitFor(t, "the held session to reach Hoplock Control", func() bool {
		return countKind(fetchLogs(t).Batched, "session_start") > countKind(before.Batched, "session_start")
	})

	if r := compose(t, "stop", nodeControl); r.code != 0 {
		t.Fatalf("stop Hoplock Control: %v", r)
	}
	// A safety net for a failure before the restart below: nothing after this
	// scenario can run against a stopped Hoplock Control.
	t.Cleanup(func() {
		if r := compose(t, "start", nodeControl); r.code != 0 {
			t.Errorf("restart Hoplock Control: %v", r)
		}
	})

	// The disclosure half: a NEW connection while the policy service is down.
	s := aliceOn(proxyDirect, "host.company.com")
	s.command = "/bin/echo must-not-run"
	r := ssh(t, s)

	wantFailure(t, r, "control outage")
	wantNotContains(t, r, "control outage", "must-not-run")
	// The point of the rule: the user stops retrying credentials, files the
	// right ticket, and has a reference the logs can be searched by.
	wantContains(t, r, "control outage", "not a permissions problem")
	wantContains(t, r, "control outage", "the policy service is unavailable")
	wantContains(t, r, "control outage", "Quote session id")
	wantNotContains(t, r, "control outage", "Access denied.")

	// The buffering half. The held session ends while Hoplock Control is still
	// down, so its last records had nowhere to go but the disk buffer.
	heldResult := <-held
	heldID := sessionIDOf(heldResult)
	if heldID == "" {
		t.Fatalf("could not read the held session's id from what it was told\n%s", heldResult)
	}
	wantContains(t, heldResult, "the held session", "outage-marker")

	if r := compose(t, "start", nodeControl); r.code != 0 {
		t.Fatalf("restart Hoplock Control: %v", r)
	}
	waitFor(t, "Hoplock Control to answer again", func() bool {
		_, err := tryFetchLogs()
		return err == nil
	})

	// The mock's ingested state died with its container, so a record carrying
	// the held session's id can only have been drained from the proxy's buffer.
	waitFor(t, "the buffered records to drain", func() bool {
		for _, rec := range fetchLogs(t).Batched {
			if rec.SessionID == heldID {
				return true
			}
		}
		return false
	})
}

// --- cleanup -----------------------------------------------------------------

// testNoEphemeralLeak is the acceptance criterion that nothing is left behind:
// every account the ephemeral method created — including for the session policy
// killed mid-command — has been removed by teardown.
func testNoEphemeralLeak(t *testing.T) {
	r := execIn(t, nodeTarget, "getent", "passwd")
	if r.code != 0 {
		t.Fatalf("read the target's account database: %v", r)
	}
	var leaked []string
	for _, line := range strings.Split(r.stdout, "\n") {
		if strings.HasPrefix(line, "hl-") {
			leaked = append(leaked, line)
		}
	}
	if len(leaked) > 0 {
		t.Errorf("ephemeral accounts left on the target after the suite:\n%s", strings.Join(leaked, "\n"))
	}

	homes := execIn(t, nodeTarget, "sh", "-c", "ls /home")
	if strings.Contains(homes.stdout, "hl-") {
		t.Errorf("ephemeral home directories left on the target:\n%s", homes.stdout)
	}

	// The artefacts an ENFORCEMENT RUNG leaves (PLAN §6.5, phase 0019). A
	// packet filter rule that outlives its account is the worst of these by a
	// distance: `useradd` reuses freed uids, so the rule silently attaches to
	// whoever gets that uid next — an egress boundary transplanted onto an
	// unrelated session, or an allow-list transplanted onto one that was
	// supposed to have none. Since phase 0027 the proxy allocates the uid and
	// never reuses one, which closes the way that happens to a session this proxy
	// provisioned; the rule still has to go, because nothing else would remove it
	// and a range an operator widens later would reopen it.
	for _, check := range []struct{ what, script string }{
		{"packet filter rules", "iptables -S OUTPUT; ip6tables -S OUTPUT"},
		{"confinement directories", "ls -a /var/lib/hoplock 2>/dev/null || true"},
		{"mounted home directories", "mount"},
	} {
		r := execIn(t, nodeTarget, "sh", "-c", check.script)
		if strings.Contains(r.stdout, "hl-") {
			t.Errorf("enforcement residue left on the target (%s):\n%s", check.what, r.stdout)
		}
	}

	// ONE thing is deliberately left behind, and it is asserted rather than
	// tolerated: the uid high-water mark (phase 0027). It is what makes a
	// torn-down account's uid unavailable to the next session, so it has to
	// outlive every account here — a mark swept away with the accounts would hand
	// the whole range back on the next provisioning.
	mark := execIn(t, nodeTarget, "sh", "-c", "ls /var/lib/hoplock/uid-watermark 2>/dev/null || true")
	marks := strings.Fields(mark.stdout)
	if len(marks) == 0 {
		t.Error("the uid high-water mark is gone from the target; the next session could be handed " +
			"a uid this suite's accounts already held")
	}
	for _, name := range marks {
		uid, err := strconv.Atoi(name)
		if err != nil {
			t.Errorf("the uid mark directory holds %q, which is not a uid", name)
			continue
		}
		if uid < 2000000 || uid > 2999999 {
			t.Errorf("the uid mark records %d, outside the dedicated range 2000000-2999999", uid)
		}
	}

	// The same check on the appliance. It matters more there, not less: this
	// driver renders no expiry onto the device — FortiOS can deny an
	// administrator's login on a schedule but never deletes one, and phase 0015
	// declined even that (see docs/PLAN.md §5.3) — so nothing but the proxy's
	// own teardown and its reaper ever removes one of these, and what is left
	// behind is a privileged administrator rather than an unprivileged shell
	// account.
	var onDevice []string
	for _, name := range deviceAccounts(t) {
		if strings.HasPrefix(name, "hl-") {
			onDevice = append(onDevice, name)
		}
	}
	if len(onDevice) > 0 {
		t.Errorf("device administrators left on the appliance after the suite:\n%s", strings.Join(onDevice, "\n"))
	}

	// And on the FortiSwitch, where the argument above is stronger still: the
	// switch driver declares NO expiry mechanism at all — FortiSwitchOS's
	// `set schedule` names a `config firewall schedule` table the platform
	// does not have — so the proxy's teardown and its reaper are the only two
	// things in the world that remove one of these accounts (phase 0029).
	var onSwitch []string
	switchAdmins, err := tryDeviceAdministrators(deviceSwitchDebugAddr)
	if err != nil {
		t.Errorf("read the switch's administrator table: %v", err)
	}
	for _, a := range switchAdmins {
		if strings.HasPrefix(a.Name, "hl-") {
			onSwitch = append(onSwitch, a.Name)
		}
	}
	if len(onSwitch) > 0 {
		t.Errorf("device administrators left on the FortiSwitch after the suite:\n%s", strings.Join(onSwitch, "\n"))
	}
}
