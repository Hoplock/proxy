// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
)

// Phase 0019's rungs against a REAL sshd, in the container deploy/target
// builds. `make test-sshd` brings it up; every test here skips without it.
//
// The fake host in confine_test.go answers everything about the scripts. What
// only this file can answer is whether the rung is real:
//
//   - does sshd honour the `restrict` and `command=` options the rung writes,
//     for a connection that never went through the proxy;
//   - does a per-uid packet filter installed by the provisioning script
//     actually refuse a destination the policy did not name, promptly;
//   - does a freed uid hand a new session anything the old one was standing
//     behind.
//
// A rung whose marketing claim is not executable somewhere is a rung nobody can
// check, and PLAN §6.5 makes the claims quite specific.

// enforcementProbe is a file the allow-listed command is permitted to read, and
// nothing else on the target matches the prefix the policy names.
const enforcementProbeFile = "/etc/hoplock-probe"

// catProbeOnly is the allow-list PLAN §6.5's bypass test is written against:
// exactly one executable, exactly one argument shape.
func catProbeOnly() *control.RestrictedExecPolicy {
	return &control.RestrictedExecPolicy{Commands: []control.RestrictedCommand{{
		Executable: "cat",
		Form:       control.CommandFormPositional,
		Args:       []control.ArgumentSpec{{Kind: control.ArgumentPrefix, Value: "/etc/hoplock-"}},
	}}}
}

func sshdEphemeral(t *testing.T, sshd *sshdTarget, proxyID string) *EphemeralAuthenticator {
	t.Helper()
	auth, err := NewEphemeralAuthenticator(EphemeralOptions{
		ProxyID:        proxyID,
		Dialer:         sshd.dialer,
		KeyExpiry:      true,
		ReaperInterval: -1,
		ReaperGrace:    time.Nanosecond,
	})
	if err != nil {
		t.Fatalf("NewEphemeralAuthenticator: %v", err)
	}
	t.Cleanup(func() { _ = auth.Close() })
	return auth
}

// TestSSHDAccountRestrictedHoldsAgainstADirectConnection is the rung's whole
// argument in one test.
//
// The client here is NOT the proxy. It holds the session's key and connects
// straight to the target, which is the failure mode nothing else in this system
// covers — and the rung has to hold anyway, because the boundary is sshd's and
// the dispatcher's rather than the proxy's.
func TestSSHDAccountRestrictedHoldsAgainstADirectConnection(t *testing.T) {
	sshd := requireSSHD(t)
	ctx := context.Background()
	auth := sshdEphemeral(t, sshd, "integration-restricted")

	sshd.run(t, "printf 'probe\\n' > "+shellQuote(enforcementProbeFile))
	t.Cleanup(func() { sshd.run(t, "rm -f "+shellQuote(enforcementProbeFile)) })

	tgt := sshd.target
	tgt.Auth = ephemeralRoute(nil)
	tgt.Enforcement = &Enforcement{
		Execution:      control.ExecutionAccountRestricted,
		RestrictedExec: catProbeOnly(),
	}
	access, err := auth.Provision(ctx, testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	account := access.ClientConfig.User
	t.Cleanup(func() { _ = access.Close(context.Background()) })

	// A script the session "uploaded". It is written by the management login
	// because `restrict` denies the session sftp — which is itself part of the
	// rung — and the question under test is whether the account can EXECUTE it.
	uploaded := "/home/" + account + "/payload.sh"
	sshd.run(t, "printf '#!/bin/sh\\nid\\n' > "+shellQuote(uploaded)+
		" && chmod 755 "+shellQuote(uploaded)+" && chown "+shellQuote(account)+" "+shellQuote(uploaded))

	client := sshd.dialAs(t, access.ClientConfig)
	defer func() { _ = client.Close() }()

	if out, err := sshdExec(client, "cat "+enforcementProbeFile); err != nil || !strings.Contains(out, "probe") {
		t.Errorf("the permitted command failed: %v (%q)", err, out)
	}
	for name, command := range map[string]string{
		"a shell":                    "sh -c id",
		"a shell reading a secret":   "sh -c 'cat /etc/shadow'",
		"an unnamed executable":      "id",
		"a file outside the policy":  "cat /etc/shadow",
		"an uploaded script":         uploaded,
		"an uploaded script via sh":  "sh " + uploaded,
		"a command with a separator": "cat " + enforcementProbeFile + "; id",
	} {
		if out, err := sshdExec(client, command); err == nil {
			t.Errorf("%s (%q) ran on the target: %q", name, command, out)
		}
	}
	// No interactive session either, and the two halves of that fail at
	// DIFFERENT LAYERS — which is the whole shape of the rung, so they are
	// asserted separately rather than as one "no shell" check.
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = sess.Close() }()

	// sshd, from the key's `restrict`: the terminal request itself is refused.
	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err == nil {
		t.Error("the account obtained a terminal, which `restrict` is supposed to deny")
	}

	// The dispatcher, from `command=`: sshd ACCEPTS the shell request and runs
	// the forced command in its place, so Shell() returning nil proves nothing
	// — it means the request was accepted, not that a shell was obtained. What
	// the account gets is the dispatcher, with no command in the environment,
	// which is default-deny. The claim is therefore about what the session
	// DID, so it is asserted on the exit status.
	var out bytes.Buffer
	sess.Stdout, sess.Stderr = &out, &out
	if err := sess.Shell(); err != nil {
		// Refused outright is also a pass: it is a stronger answer than the
		// one below, and some sshd configurations give it.
		return
	}
	if err := sess.Wait(); err == nil {
		t.Errorf("the account obtained a working shell: %q", out.String())
	}
}

// TestSSHDEgressRungRefusesADestinationThePolicyDidNotName is the reach axis,
// asserted with a binary the EXECUTION rung permits — so the two axes are shown
// to be independent, which is the configuration this phase exists to make
// expressible.
func TestSSHDEgressRungRefusesADestinationThePolicyDidNotName(t *testing.T) {
	sshd := requireSSHD(t)
	ctx := context.Background()
	auth := sshdEphemeral(t, sshd, "integration-egress")

	if out := sshd.run(t, "command -v nc || true"); strings.TrimSpace(out) == "" {
		t.Skip("the target image has no nc; the reach rung needs a client the execution rung can permit")
	}

	tgt := sshd.target
	tgt.Auth = ephemeralRoute(nil)
	tgt.Enforcement = &Enforcement{
		Execution: control.ExecutionAccountRestricted,
		RestrictedExec: &control.RestrictedExecPolicy{Commands: []control.RestrictedCommand{{
			Executable: "nc",
			Form:       control.CommandFormPositional,
			Args: []control.ArgumentSpec{
				{Kind: control.ArgumentLiteral, Value: "-z"},
				{Kind: control.ArgumentLiteral, Value: "-w"},
				{Kind: control.ArgumentLiteral, Value: "2"},
				{Kind: control.ArgumentAny},
				{Kind: control.ArgumentLiteral, Value: "22"},
			},
		}}},
		Reach: control.ReachAccountEgressRestricted,
		// The target's own sshd, which is listening on every address, so the
		// only difference between the two destinations below is the rung.
		PermittedDestinations: []control.ForwardDestination{{Host: "127.0.0.1", Port: 22}},
	}
	access, err := auth.Provision(ctx, testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = access.Close(context.Background()) })

	client := sshd.dialAs(t, access.ClientConfig)
	defer func() { _ = client.Close() }()

	if _, err := sshdExec(client, "nc -z -w 2 127.0.0.1 22"); err != nil {
		t.Errorf("the permitted destination was refused: %v", err)
	}
	start := time.Now()
	if _, err := sshdExec(client, "nc -z -w 2 127.0.0.2 22"); err == nil {
		t.Error("a destination the policy did not name was reachable")
	}
	// A REFUSED connection rather than a hang: a session that hangs on a denied
	// destination looks like a broken network to whoever is watching.
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("the denied destination took %s to fail, which is a timeout rather than a refusal", elapsed)
	}
}

// TestSSHDTeardownRemovesEveryRungArtefact, verified on the target itself.
func TestSSHDTeardownRemovesEveryRungArtefact(t *testing.T) {
	sshd := requireSSHD(t)
	ctx := context.Background()
	auth := sshdEphemeral(t, sshd, "integration-teardown")

	tgt := sshd.target
	tgt.Auth = ephemeralRoute(nil)
	tgt.Enforcement = &Enforcement{
		Execution:             control.ExecutionAccountRestricted,
		RestrictedExec:        catProbeOnly(),
		Reach:                 control.ReachAccountEgressRestricted,
		PermittedDestinations: []control.ForwardDestination{{Host: "127.0.0.1", Port: 22}},
	}
	access, err := auth.Provision(ctx, testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	account := access.ClientConfig.User
	tag := ruleTagPrefix + account

	if out := sshd.run(t, "iptables -S OUTPUT"); !strings.Contains(out, tag) {
		t.Fatalf("the rung installed no rules; the rest of this test would prove nothing:\n%s", out)
	}
	if err := access.Close(ctx); err != nil {
		t.Fatalf("teardown: %v", err)
	}

	if sshd.accountExists(t, account) {
		t.Errorf("account %q survived teardown", account)
	}
	for _, check := range []struct{ what, script string }{
		{"IPv4 rules", "iptables -S OUTPUT"},
		{"IPv6 rules", "ip6tables -S OUTPUT"},
		{"the confinement directory", "ls -a " + shellQuote(DefaultEnforcementBase) + " 2>/dev/null || true"},
		{"mounts", "mount"},
	} {
		if out := sshd.run(t, check.script); strings.Contains(out, account) {
			t.Errorf("%s still name the account:\n%s", check.what, out)
		}
	}
}

// TestSSHDUIDReuseInheritsNothing is the one failure here that is silent in
// every other test (PLAN §6.5, and phase 0024's other half).
func TestSSHDUIDReuseInheritsNothing(t *testing.T) {
	sshd := requireSSHD(t)
	ctx := context.Background()
	auth := sshdEphemeral(t, sshd, "integration-uid")

	confined := func() *Enforcement {
		return &Enforcement{
			Execution:             control.ExecutionAccountRestricted,
			RestrictedExec:        catProbeOnly(),
			Reach:                 control.ReachAccountEgressRestricted,
			PermittedDestinations: []control.ForwardDestination{{Host: "127.0.0.1", Port: 22}},
		}
	}
	tgt := sshd.target
	tgt.Auth = ephemeralRoute(nil)

	// Provision and tear down until a uid is handed out twice. useradd reuses
	// the lowest free uid, so on a quiet target this happens on the second
	// round; the loop is here so the test does not depend on that.
	var uids []string
	var reused string
	for i := 0; i < 6 && reused == ""; i++ {
		tgt.Enforcement = confined()
		access, err := auth.Provision(ctx, testIdentity(), tgt)
		if err != nil {
			t.Fatalf("Provision: %v", err)
		}
		uid := strings.TrimSpace(sshd.run(t, "id -u "+shellQuote(access.ClientConfig.User)))
		if err := access.Close(ctx); err != nil {
			t.Fatalf("teardown: %v", err)
		}
		if contains(uids, uid) {
			reused = uid
		}
		uids = append(uids, uid)
	}
	if reused == "" {
		t.Skipf("no uid was reused in six rounds (saw %v); the hazard is not reproducible on this target", uids)
	}

	// The session that lands on the reused uid asks for NO reach rung, so any
	// rule it stands behind is one it inherited.
	tgt.Enforcement = &Enforcement{
		Execution:      control.ExecutionAccountRestricted,
		RestrictedExec: catProbeOnly(),
	}
	access, err := auth.Provision(ctx, testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = access.Close(context.Background()) })

	for _, script := range []string{"iptables -S OUTPUT", "ip6tables -S OUTPUT"} {
		if out := sshd.run(t, script); strings.Contains(out, ruleTagPrefix) {
			t.Errorf("a rule outlived its account and now attaches to the reused uid %s:\n%s", reused, out)
		}
	}
	if out := sshd.run(t, "mount"); strings.Contains(out, DefaultHomeBase+"/hl-") {
		t.Errorf("a mount outlived its account:\n%s", out)
	}
}

// TestSSHDReaperRemovesResidueOfASessionThatDiedMidRung.
func TestSSHDReaperRemovesResidueOfASessionThatDiedMidRung(t *testing.T) {
	sshd := requireSSHD(t)
	ctx := context.Background()
	auth := sshdEphemeral(t, sshd, "integration-residue")

	tgt := sshd.target
	tgt.Auth = ephemeralRoute(nil)
	tgt.Enforcement = &Enforcement{
		Execution:             control.ExecutionAccountRestricted,
		RestrictedExec:        catProbeOnly(),
		Reach:                 control.ReachAccountEgressRestricted,
		PermittedDestinations: []control.ForwardDestination{{Host: "127.0.0.1", Port: 22}},
	}
	access, err := auth.Provision(ctx, testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	account := access.ClientConfig.User

	// The session dies mid-rung: something else removes the account and the
	// rung's state is left behind with nothing pointing at it.
	sshd.run(t, "userdel -r "+shellQuote(account)+" >/dev/null 2>&1 || true")
	auth.reaper.release(sshd.target, account)
	if out := sshd.run(t, "iptables -S OUTPUT"); !strings.Contains(out, ruleTagPrefix+account) {
		t.Fatalf("the residue this test needs is not there:\n%s", out)
	}

	if _, err := auth.reaper.Sweep(ctx, sshd.target); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	for _, script := range []string{"iptables -S OUTPUT", "ip6tables -S OUTPUT", "mount"} {
		if out := sshd.run(t, script); strings.Contains(out, account) {
			t.Errorf("the sweep left residue behind (%s):\n%s", script, out)
		}
	}
}

// dialAs opens a client connection with a provisioned configuration. It is
// whoami's transport half, exposed because these tests run several commands
// over one connection.
func (s *sshdTarget) dialAs(t *testing.T, cfg *ssh.ClientConfig) *ssh.Client {
	t.Helper()
	dialCfg := *cfg
	dialCfg.HostKeyCallback = s.target.HostKeyCallback
	dialCfg.Timeout = 30 * time.Second
	client, err := ssh.Dial("tcp", s.target.Addr(), &dialCfg)
	if err != nil {
		t.Fatalf("log in as %q: %v", cfg.User, err)
	}
	return client
}

// sshdExec runs one command over an existing connection and returns its output.
func sshdExec(client *ssh.Client, command string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer func() { _ = sess.Close() }()
	out, err := sess.CombinedOutput(command)
	if err != nil {
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			return string(out), exitErr
		}
		return string(out), err
	}
	return string(out), nil
}
