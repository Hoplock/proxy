// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"testing"
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
	t.Run("device credentials", testDeviceCredentials)
	t.Run("denial disclosure", testDenialDisclosure)
	t.Run("telemetry", testTelemetry)
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
		// FortiOS accepts 35-character names, above PLAN §5.3's threshold, so
		// the readable scheme survives here and the account on the device names
		// the person it belongs to.
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
}
