// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hoplock/proxy/internal/control"
)

// These are phase 0019's tests against the fake host, which runs the scripts
// under a real /bin/sh with a working model of every command a rung reaches for
// (fakehost_test.go). They answer the questions PLAN §6.5 makes claims about:
// does the dispatcher actually deny what it says it denies, are the packet
// filter rules actually installed and actually removed, and is a rung the
// target cannot provide actually refused with nothing left behind.
//
// What they cannot answer is whether a REAL sshd honours the key options the
// rung writes, which is sshd_test.go's job (`make test-sshd`).

// catOnly is the smallest interesting allow-list: exactly the one PLAN §6.5's
// bypass test is written against.
func catOnly() *control.RestrictedExecPolicy {
	return &control.RestrictedExecPolicy{Commands: []control.RestrictedCommand{{
		Executable: "cat",
		Form:       control.CommandFormPositional,
		Args: []control.ArgumentSpec{{
			Kind:  control.ArgumentPrefix,
			Value: "/etc/hoplock-",
		}},
	}}}
}

func restrictedRoute() *Enforcement {
	return &Enforcement{
		Execution:      control.ExecutionAccountRestricted,
		RestrictedExec: catOnly(),
	}
}

func confinedRoute(dests ...control.ForwardDestination) *Enforcement {
	e := &Enforcement{
		Execution:      control.ExecutionAccountConfined,
		RestrictedExec: catOnly(),
	}
	if len(dests) > 0 {
		e.Reach = control.ReachAccountEgressRestricted
		e.PermittedDestinations = dests
	}
	return e
}

func withEnforcement(h *fakeHost, e *Enforcement) Target {
	tgt := h.tgt()
	tgt.Enforcement = e
	tgt.Auth = ephemeralRoute(nil)
	return tgt
}

// enforcedEphemeral is an ephemeral provisioner whose confinement material
// lives inside the fake host's temporary root.
func enforcedEphemeral(t *testing.T, h *fakeHost, proxyID string) *EphemeralAuthenticator {
	t.Helper()
	return newTestEphemeral(t, h, proxyID, func(o *EphemeralOptions) {
		o.EnforcementBase = filepath.Join(h.root, "enforce")
	})
}

// TestAccountRestrictedRendersTheDispatcherAndTheKeyOptions is the rung's
// shape: the key carries the fence and the dispatcher, the account's login
// shell IS the dispatcher, and the allow-list on the target is the route's.
func TestAccountRestrictedRendersTheDispatcherAndTheKeyOptions(t *testing.T) {
	h := startFakeHost(t)
	auth := enforcedEphemeral(t, h, "proxy-a")

	access, err := auth.Provision(context.Background(), testIdentity(), withEnforcement(h, restrictedRoute()))
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	account := access.ClientConfig.User

	line := h.authorizedKeys(t, account)
	for _, want := range []string{"restrict", `command="`, dispatcherName} {
		if !strings.Contains(line, want) {
			t.Errorf("authorized_keys = %q, want it to carry %q", line, want)
		}
	}

	dispatch := filepath.Join(h.root, "enforce", account, dispatcherName)
	if got := h.shellFor(t, account); got != dispatch {
		t.Errorf("login shell = %q, want the dispatcher %q", got, dispatch)
	}
	body, err := os.ReadFile(dispatch)
	if err != nil {
		t.Fatalf("read the dispatcher: %v", err)
	}
	if !strings.Contains(string(body), "'cat'") {
		t.Errorf("the dispatcher does not carry the route's allow-list:\n%s", body)
	}
	// The curated PATH: a symlink the account cannot write, resolved on the
	// target rather than by the proxy.
	if _, err := os.Lstat(filepath.Join(h.root, "enforce", account, curatedBinName, "cat")); err != nil {
		t.Errorf("curated PATH entry for cat: %v", err)
	}

	if access.Enforcement == nil || access.Enforcement.Execution != control.ExecutionAccountRestricted {
		t.Fatalf("Enforcement = %+v, want the rung in force", access.Enforcement)
	}
	if !access.Enforcement.Verified {
		t.Error("an applied rung must be recorded as verified")
	}
}

// TestDispatcherDeniesEverythingButTheAllowList is 0010's bypass test moved one
// layer down, and it is the executable form of the rung's marketing claim.
//
// It runs the GENERATED dispatcher under a real /bin/sh, which is the only way
// to answer the question: a test that asserted on the script's text would prove
// this package emits the strings it emits.
func TestDispatcherDeniesEverythingButTheAllowList(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skipf("no /bin/sh: %v", err)
	}
	dir := t.TempDir()
	// The allow-list's prefix points inside the temporary directory, so the
	// test needs no privilege and no fixture outside it. The SHAPE is PLAN
	// §6.5's bypass test: exactly one executable, exactly one argument shape.
	allowed := filepath.Join(dir, "readable-")
	c := &confinement{
		principal:  "hl-abcd-alice-0000",
		home:       filepath.Join(dir, "home"),
		base:       dir,
		dir:        filepath.Join(dir, "hl-abcd-alice-0000"),
		dispatcher: true,
		commands: []control.RestrictedCommand{{
			Executable: "cat",
			Form:       control.CommandFormPositional,
			Args:       []control.ArgumentSpec{{Kind: control.ArgumentPrefix, Value: allowed}},
		}},
	}
	script, err := c.dispatcherScript()
	if err != nil {
		t.Fatalf("dispatcherScript: %v", err)
	}
	path := filepath.Join(dir, "dispatch")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// The curated PATH holds exactly what the allow-list names.
	bin := filepath.Join(c.dir, curatedBinName)
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	real, err := exec.LookPath("cat")
	if err != nil {
		t.Skipf("no cat on this machine: %v", err)
	}
	if err := os.Symlink(real, filepath.Join(bin, "cat")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("shadow\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	permitted := allowed + "one"
	if err := os.WriteFile(permitted, []byte("ok\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	run := func(command string) (string, int) {
		t.Helper()
		cmd := exec.Command("/bin/sh", path)
		cmd.Env = append(os.Environ(), "SSH_ORIGINAL_COMMAND="+command)
		out, err := cmd.CombinedOutput()
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return string(out), exitErr.ExitCode()
		}
		if err != nil {
			t.Fatalf("run %q: %v", command, err)
		}
		return string(out), 0
	}

	if out, code := run("cat " + permitted); code != 0 || !strings.Contains(out, "ok") {
		t.Errorf("the permitted command was denied: exit %d, %q", code, out)
	}
	denied := map[string]string{
		"a shell":                      "sh -c cat",
		"a shell with an argument":     "sh -c 'cat " + secret + "'",
		"an unnamed executable":        "id",
		"an argument outside the spec": "cat " + secret,
		"a second argument":            "cat " + permitted + " " + permitted,
		"a shell metacharacter":        "cat " + permitted + "; id",
		"a pipe":                       "cat " + permitted + " | id",
		"a substitution":               "cat $(id)",
		"a glob":                       "cat " + allowed + "*",
		"an interactive login":         "",
	}
	for name, command := range denied {
		if _, code := run(command); code == 0 {
			t.Errorf("%s (%q) was permitted by the dispatcher", name, command)
		}
	}
}

// TestAccountConfinedMountsTheHomeNoexec covers the half of account-confined
// that account-restricted does not claim: the session cannot execute what it
// wrote.
func TestAccountConfinedMountsTheHomeNoexec(t *testing.T) {
	h := startFakeHost(t)
	auth := enforcedEphemeral(t, h, "proxy-a")

	access, err := auth.Provision(context.Background(), testIdentity(), withEnforcement(h, confinedRoute()))
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	home := h.homeFor(access.ClientConfig.User)
	points := h.mountPoints(t)
	if len(points) != 1 || points[0] != home {
		t.Fatalf("mount points = %v, want just the session's home %q", points, home)
	}
	var remount string
	for _, line := range h.commandLog(t) {
		if strings.HasPrefix(line, "mount ") && strings.Contains(line, "remount") {
			remount = line
		}
	}
	for _, flag := range []string{"noexec", "nosuid", "nodev"} {
		if !strings.Contains(remount, flag) {
			t.Errorf("remount = %q, want it to carry %q", remount, flag)
		}
	}
	if !strings.Contains(access.Enforcement.ExecutionMechanism, "setpriv") {
		t.Errorf("mechanism = %q, want it to name what delivers 'no privilege gain'",
			access.Enforcement.ExecutionMechanism)
	}
}

// TestEgressRungRendersBothFamiliesAndRejectsByDefault is the reach axis's
// shape. The IPv6 half is the point: a rung that closes one family and leaves
// the other open is the mistake phase 0015 found on the device side.
func TestEgressRungRendersBothFamiliesAndRejectsByDefault(t *testing.T) {
	h := startFakeHost(t)
	auth := enforcedEphemeral(t, h, "proxy-a")

	route := confinedRoute(control.ForwardDestination{Host: "10.1.2.3", Port: 5432})
	access, err := auth.Provision(context.Background(), testIdentity(), withEnforcement(h, route))
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	tag := ruleTagPrefix + access.ClientConfig.User

	v4 := h.rules(t, false)
	if len(v4) != 3 {
		t.Fatalf("IPv4 rules = %v, want tcp and udp accepts plus the default reject", v4)
	}
	for _, rule := range v4 {
		if !strings.Contains(rule, tag) || !strings.Contains(rule, "--uid-owner") {
			t.Errorf("rule %q must carry the account's tag and the uid match", rule)
		}
	}
	if !strings.Contains(v4[0], "-d 10.1.2.3") || !strings.Contains(v4[0], "--dport 5432") {
		t.Errorf("first rule = %q, want the route's destination", v4[0])
	}
	if !strings.Contains(v4[2], "REJECT") {
		t.Errorf("last IPv4 rule = %q, want the default reject", v4[2])
	}
	// A destination list naming only IPv4 still closes IPv6.
	v6 := h.rules(t, true)
	if len(v6) != 1 || !strings.Contains(v6[0], "REJECT") {
		t.Fatalf("IPv6 rules = %v, want exactly the default reject", v6)
	}
	// REJECT and not DROP: the failure mode has to be a refused connection
	// rather than a hang.
	for _, rule := range append(v4, v6...) {
		if strings.Contains(rule, "DROP") {
			t.Errorf("rule %q drops rather than rejects, which makes a denied destination look like a broken network", rule)
		}
	}
}

// TestNetworkIsolatedPermitsOnlyLoopback.
func TestNetworkIsolatedPermitsOnlyLoopback(t *testing.T) {
	h := startFakeHost(t)
	auth := enforcedEphemeral(t, h, "proxy-a")

	route := &Enforcement{
		Execution:      control.ExecutionAccountRestricted,
		RestrictedExec: catOnly(),
		Reach:          control.ReachAccountNetworkIsolated,
	}
	if _, err := auth.Provision(context.Background(), testIdentity(), withEnforcement(h, route)); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	for _, v6 := range []bool{false, true} {
		rules := h.rules(t, v6)
		if len(rules) != 2 {
			t.Fatalf("rules (v6=%v) = %v, want loopback plus the default reject", v6, rules)
		}
		if !strings.Contains(rules[0], "-o lo") {
			t.Errorf("first rule = %q, want the loopback allowance", rules[0])
		}
		if !strings.Contains(rules[1], "REJECT") {
			t.Errorf("second rule = %q, want the default reject", rules[1])
		}
	}
}

// TestARungTheTargetCannotProvideIsRefusedWithNothingLeftBehind is PLAN §4.3's
// rule as an assertion: outage-class, and the target exactly as it was found.
func TestARungTheTargetCannotProvideIsRefusedWithNothingLeftBehind(t *testing.T) {
	for _, tc := range []struct {
		name    string
		missing string
		route   *Enforcement
	}{
		{"no ip6tables, so no reach rung", "ip6tables",
			confinedRoute(control.ForwardDestination{Host: "10.0.0.1", Port: 443})},
		{"no setpriv, so no account-confined", "setpriv", confinedRoute()},
		{"no bind mount, so no account-confined", "mount", confinedRoute()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := startFakeHost(t)
			h.breakCommand(t, tc.missing)
			auth := enforcedEphemeral(t, h, "proxy-a")

			_, err := auth.Provision(context.Background(), testIdentity(), withEnforcement(h, tc.route))
			if !errors.Is(err, ErrRungUnavailable) {
				t.Fatalf("Provision error = %v, want ErrRungUnavailable", err)
			}
			if got := h.ephemeralAccounts(t); len(got) != 0 {
				t.Errorf("accounts left behind: %v", got)
			}
			entries, _ := os.ReadDir(h.home)
			if len(entries) != 0 {
				t.Errorf("homes left behind: %v", entries)
			}
			if got := h.rules(t, false); len(got) != 0 {
				t.Errorf("rules left behind: %v", got)
			}
		})
	}
}

// TestTeardownRemovesEveryRungArtefactAndVerifies.
func TestTeardownRemovesEveryRungArtefactAndVerifies(t *testing.T) {
	h := startFakeHost(t)
	auth := enforcedEphemeral(t, h, "proxy-a")

	route := confinedRoute(control.ForwardDestination{Host: "10.1.2.3", Port: 5432})
	access, err := auth.Provision(context.Background(), testIdentity(), withEnforcement(h, route))
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	account := access.ClientConfig.User
	if err := access.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if got := h.ephemeralAccounts(t); len(got) != 0 {
		t.Errorf("accounts remain: %v", got)
	}
	if got := h.rules(t, false); len(got) != 0 {
		t.Errorf("IPv4 rules remain: %v", got)
	}
	if got := h.rules(t, true); len(got) != 0 {
		t.Errorf("IPv6 rules remain: %v", got)
	}
	if got := h.mountPoints(t); len(got) != 0 {
		t.Errorf("mounts remain: %v", got)
	}
	if _, err := os.Stat(filepath.Join(h.root, "enforce", account)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the confinement directory remains: %v", err)
	}
}

// TestTeardownRemovesRulesBeforeTheAccount is the uid hazard as an ordering
// assertion. A rule that outlives its account attaches to whoever gets that uid
// next, so the order below is a guarantee rather than a preference.
func TestTeardownRemovesRulesBeforeTheAccount(t *testing.T) {
	h := startFakeHost(t)
	auth := enforcedEphemeral(t, h, "proxy-a")

	route := confinedRoute(control.ForwardDestination{Host: "10.1.2.3", Port: 5432})
	access, err := auth.Provision(context.Background(), testIdentity(), withEnforcement(h, route))
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if err := access.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lastDelete, firstUserdel := -1, -1
	for i, line := range h.commandLog(t) {
		switch {
		case strings.HasPrefix(line, "FAKEHOST_RULES") && strings.Contains(line, " -D "):
			lastDelete = i
		case strings.HasPrefix(line, "userdel ") && firstUserdel < 0:
			firstUserdel = i
		}
	}
	if lastDelete < 0 || firstUserdel < 0 {
		t.Fatalf("expected both a rule deletion and a userdel in %v", h.commandLog(t))
	}
	if lastDelete > firstUserdel {
		t.Errorf("the last rule deletion (%d) came after userdel (%d): a rule that outlives its account attaches to whoever gets that uid next",
			lastDelete, firstUserdel)
	}
}

// TestTeardownFailsLoudlyWhenARuleSurvives. A teardown that reports a success
// it did not achieve is worse than one that fails.
func TestTeardownFailsLoudlyWhenARuleSurvives(t *testing.T) {
	h := startFakeHost(t)
	auth := enforcedEphemeral(t, h, "proxy-a")

	route := confinedRoute(control.ForwardDestination{Host: "10.1.2.3", Port: 5432})
	access, err := auth.Provision(context.Background(), testIdentity(), withEnforcement(h, route))
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	h.setEnv("FAKEHOST_RULE_DELETE_FAILS", "1")

	err = access.Close(context.Background())
	if err == nil {
		t.Fatal("teardown reported success while the account's packet filter rules were still installed")
	}
	var rce *RemoteCommandError
	if !errors.As(err, &rce) || rce.ExitStatus != exitRuleRemains {
		t.Fatalf("teardown error = %v, want the rule-verification failure (exit %d)", err, exitRuleRemains)
	}
}

// TestANewSessionInheritsNothingFromAReusedUID is the failure that is silent in
// every other test. The fake useradd hands out the same uid every time, which
// makes this the default case rather than a contrivance.
func TestANewSessionInheritsNothingFromAReusedUID(t *testing.T) {
	h := startFakeHost(t)
	auth := enforcedEphemeral(t, h, "proxy-a")
	ctx := context.Background()
	route := confinedRoute(control.ForwardDestination{Host: "10.1.2.3", Port: 5432})

	first, err := auth.Provision(ctx, testIdentity(), withEnforcement(h, route))
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	firstAccount := first.ClientConfig.User
	if err := first.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The second session asks for NO reach rung at all, so any rule it ends up
	// standing behind is one it inherited.
	second, err := auth.Provision(ctx, testIdentity(), withEnforcement(h, restrictedRoute()))
	if err != nil {
		t.Fatalf("second Provision: %v", err)
	}
	if second.ClientConfig.User == firstAccount {
		t.Fatal("the two sessions share an account name, which the uniqueness token exists to prevent")
	}
	for _, v6 := range []bool{false, true} {
		if got := h.rules(t, v6); len(got) != 0 {
			t.Errorf("the second session inherited rules (v6=%v): %v", v6, got)
		}
	}
	if got := h.mountPoints(t); len(got) != 0 {
		t.Errorf("the second session inherited mounts: %v", got)
	}
}

// TestReaperRemovesResidueWhoseAccountIsGone is the session that died
// mid-rung: a mounted home, a rule, or a confinement directory with no account.
func TestReaperRemovesResidueWhoseAccountIsGone(t *testing.T) {
	h := startFakeHost(t)
	auth := enforcedEphemeral(t, h, "proxy-a")
	ctx := context.Background()

	access, err := auth.Provision(ctx, testIdentity(),
		withEnforcement(h, confinedRoute(control.ForwardDestination{Host: "10.1.2.3", Port: 5432})))
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	account := access.ClientConfig.User

	// The proxy dies here: the account is removed by something else — a
	// hand-run userdel, another tool — and the rung's state is left behind.
	// Nothing in this process knows the session is over.
	if _, err := h.run(t, `userdel `+account); err != nil {
		t.Fatalf("remove the account behind the proxy's back: %v", err)
	}
	auth.reaper.release(h.tgt(), account)
	if got := h.rules(t, false); len(got) == 0 {
		t.Fatal("the test needs rules to survive the account for there to be anything to sweep")
	}

	if _, err := auth.reaper.Sweep(ctx, h.tgt()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	for _, v6 := range []bool{false, true} {
		if got := h.rules(t, v6); len(got) != 0 {
			t.Errorf("the sweep left rules behind (v6=%v): %v", v6, got)
		}
	}
	if got := h.mountPoints(t); len(got) != 0 {
		t.Errorf("the sweep left mounts behind: %v", got)
	}
	if _, err := os.Stat(filepath.Join(h.root, "enforce", account)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the sweep left the confinement directory behind: %v", err)
	}
}

// TestReaperDoesNotSweepALiveSession'sResidue: residue is aged by its account
// where one exists, so a live session keeps its rules.
func TestReaperKeepsALiveSessionsResidue(t *testing.T) {
	h := startFakeHost(t)
	auth := enforcedEphemeral(t, h, "proxy-a")
	ctx := context.Background()

	access, err := auth.Provision(ctx, testIdentity(),
		withEnforcement(h, confinedRoute(control.ForwardDestination{Host: "10.1.2.3", Port: 5432})))
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	removed, err := auth.reaper.Sweep(ctx, h.tgt())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(removed) != 0 {
		t.Fatalf("the sweep removed a live session's account: %v", removed)
	}
	if got := h.rules(t, false); len(got) == 0 {
		t.Error("the sweep removed a live session's packet filter rules")
	}
	_ = access.Close(ctx)
}

// TestPlanRefusesWhatItCannotRenderFaithfully. Each of these would produce a
// rule that claims more than it enforces.
func TestPlanRefusesWhatItCannotRenderFaithfully(t *testing.T) {
	for _, tc := range []struct {
		name string
		e    *Enforcement
	}{
		{"a destination named by hostname", &Enforcement{
			Execution:             control.ExecutionProxyInspected,
			Reach:                 control.ReachAccountEgressRestricted,
			PermittedDestinations: []control.ForwardDestination{{Host: "db.example.com", Port: 5432}},
		}},
		{"a destination named by wildcard pattern", &Enforcement{
			Execution:             control.ExecutionProxyInspected,
			Reach:                 control.ReachAccountEgressRestricted,
			PermittedDestinations: []control.ForwardDestination{{Host: "*.example.com", Port: 5432}},
		}},
		{"an egress rung naming no destinations", &Enforcement{
			Execution: control.ExecutionProxyInspected,
			Reach:     control.ReachAccountEgressRestricted,
		}},
		{"an execution rung with no allow-list to render", &Enforcement{
			Execution: control.ExecutionAccountRestricted,
		}},
		{"a device rung on a POSIX host", &Enforcement{
			Execution: control.ExecutionPlatformAuthorized,
		}},
		{"an attested reach rung on an account this proxy administers", &Enforcement{
			Execution: control.ExecutionProxyInspected,
			Reach:     control.ReachPlatformAttested,
		}},
		{"an unknown execution rung", &Enforcement{Execution: "account-hardened"}},
		{"an unknown reach rung", &Enforcement{Reach: "account-firewalled"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := startFakeHost(t)
			auth := enforcedEphemeral(t, h, "proxy-a")
			_, err := auth.Provision(context.Background(), testIdentity(), withEnforcement(h, tc.e))
			if !errors.Is(err, ErrRungUnavailable) {
				t.Fatalf("Provision error = %v, want ErrRungUnavailable", err)
			}
			if got := h.ephemeralAccounts(t); len(got) != 0 {
				t.Errorf("accounts left behind: %v", got)
			}
		})
	}
}

// TestTheAllowListIsNeverReAuthoredHere: the wildcard the proxy's own matcher
// would treat as a literal must not become a shell pattern on the target.
func TestAnAllowListArgumentIsNeverWidenedIntoAPattern(t *testing.T) {
	c := &confinement{
		principal:  "hl-abcd-alice-0000",
		dir:        "/var/lib/hoplock/hl-abcd-alice-0000",
		dispatcher: true,
		commands: []control.RestrictedCommand{{
			Executable: "cat",
			Form:       control.CommandFormExact,
			Argv:       []string{"/etc/*"},
		}},
	}
	if _, err := c.dispatcherScript(); !errors.Is(err, ErrInvalidScriptValue) {
		t.Fatalf("dispatcherScript error = %v, want ErrInvalidScriptValue for a pattern character", err)
	}
}

// TestTheInterpreterProblemIsWarnedAboutAndNeverRefused (0018's decision).
func TestTheInterpreterProblemIsWarnedAboutAndNeverRefused(t *testing.T) {
	h := startFakeHost(t)
	auth := enforcedEphemeral(t, h, "proxy-a")

	route := &Enforcement{
		Execution: control.ExecutionAccountRestricted,
		RestrictedExec: &control.RestrictedExecPolicy{Commands: []control.RestrictedCommand{
			{Executable: "/usr/bin/find", Form: control.CommandFormExact, Argv: []string{"/tmp"}},
		}},
	}
	access, err := auth.Provision(context.Background(), testIdentity(), withEnforcement(h, route))
	if err != nil {
		t.Fatalf("Provision refused an allow-list naming an interpreter, which 0018 forbids: %v", err)
	}
	if !strings.Contains(access.Enforcement.Caveat, "find") {
		t.Errorf("caveat = %q, want it to name the interpreter the rung is bounded by", access.Enforcement.Caveat)
	}
}

// TestCapabilitiesAreReportedForTheTargetTheProxyTouched.
func TestCapabilitiesAreReportedForTheTargetTheProxyTouched(t *testing.T) {
	h := startFakeHost(t)
	reporter := &fakeCapabilityReporter{done: make(chan *control.CapabilityReportRequest, 4)}
	auth := newTestEphemeral(t, h, "proxy-a", func(o *EphemeralOptions) {
		o.EnforcementBase = filepath.Join(h.root, "enforce")
		o.Reporter = reporter
	})

	if _, err := auth.Provision(context.Background(), testIdentity(), withEnforcement(h, restrictedRoute())); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	req := <-reporter.done
	if req.Target != h.target.Host() {
		t.Errorf("reported target = %q, want %q", req.Target, h.target.Host())
	}
	if !req.Capabilities.ProvidesExecution(control.ExecutionAccountConfined, req.Capabilities.ObservedAt, control.DefaultCapabilityTTL) {
		t.Errorf("capabilities = %+v, want the fake host's full set", req.Capabilities)
	}
	if req.Capabilities.Detail[probeSSHDVersion] == "" {
		t.Error("the report carries no operator detail")
	}
}

type fakeCapabilityReporter struct {
	done chan *control.CapabilityReportRequest
}

func (r *fakeCapabilityReporter) ReportCapabilities(_ context.Context, req *control.CapabilityReportRequest) (*control.CapabilityReportResponse, error) {
	r.done <- req
	return &control.CapabilityReportResponse{Accepted: true}, nil
}

// TestProxyCapabilitiesNameEveryAppliedRungThisBuildRenders. It is the one
// declaration Hoplock Control chooses from, and a build that quietly stopped
// rendering a rung while still advertising it would be choosing for a server.
func TestProxyCapabilitiesNameEveryAppliedRungThisBuildRenders(t *testing.T) {
	caps := ProxyCapabilities()
	for _, rung := range []control.ExecutionRung{
		control.ExecutionNoInteractiveShell,
		control.ExecutionAccountRestricted,
		control.ExecutionAccountConfined,
		control.ExecutionPlatformAuthorized,
	} {
		if !caps.ProvidesExecution(rung) {
			t.Errorf("execution rung %q is not advertised", rung)
		}
	}
	for _, rung := range []control.ReachRung{
		control.ReachAccountEgressRestricted,
		control.ReachAccountNetworkIsolated,
	} {
		if !caps.ProvidesReach(rung) {
			t.Errorf("reach rung %q is not advertised", rung)
		}
	}
	// And nothing this build does NOT render.
	if caps.ProvidesExecution("account-hardened") || caps.ProvidesReach("account-firewalled") {
		t.Error("a build must not advertise a rung it has never heard of")
	}
}
