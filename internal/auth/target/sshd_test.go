// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// This file is the same phase's tests against a REAL sshd, in the container
// deploy/target builds. Everything else in this package runs against a fake host
// whose account database is a text file, which is the right trade for a test
// that has to run everywhere — but it cannot answer the two questions only a
// real sshd can:
//
//   - does the account this proxy creates actually accept the key it installed?
//     StrictModes, the home directory's ownership, and the permissions on
//     .ssh/authorized_keys all decide that, and a fake that accepts every key
//     cannot fail on any of them;
//   - does `useradd` on a real distribution behave the way the scripts assume,
//     down to the exit status for "user exists"?
//
// It is deliberately NOT behind a build tag: a test excluded from the build is
// a test that stops compiling without anyone noticing. It skips when the
// topology is not up, and `make test-sshd` is what brings it up. Phase 0012
// folds this container into the full e2e topology and runs it in CI.
const (
	envSSHDAddr        = "HOPLOCK_TEST_SSHD_ADDR"
	envSSHDMgmtKey     = "HOPLOCK_TEST_SSHD_MANAGEMENT_KEY"
	envSSHDProvUser    = "HOPLOCK_TEST_SSHD_PROVISIONING_USER"
	envSSHDBrokeredKey = "HOPLOCK_TEST_SSHD_BROKERED_KEY"
	envSSHDBrokeredUsr = "HOPLOCK_TEST_SSHD_BROKERED_USER"
)

// sshdTarget is the container's SSH endpoint plus the material to log into it.
type sshdTarget struct {
	target   Target
	dialer   AdminDialer
	provUser string
}

func requireSSHD(t *testing.T) *sshdTarget {
	t.Helper()
	addr := os.Getenv(envSSHDAddr)
	if addr == "" {
		t.Skipf("%s is not set; run `make test-sshd` to bring up deploy/target", envSSHDAddr)
	}
	host, portText, ok := strings.Cut(addr, ":")
	if !ok {
		t.Fatalf("%s = %q, want host:port", envSSHDAddr, addr)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("%s = %q: %v", envSSHDAddr, addr, err)
	}

	keyPath := os.Getenv(envSSHDMgmtKey)
	if keyPath == "" {
		t.Fatalf("%s is set but %s is not", envSSHDAddr, envSSHDMgmtKey)
	}
	signer, err := loadSigner(keyPath, "")
	if err != nil {
		t.Fatalf("load the management key: %v", err)
	}
	provUser := os.Getenv(envSSHDProvUser)
	if provUser == "" {
		provUser = "root"
	}
	dialer, err := NewSSHAdminDialer(SSHAdminOptions{
		Signer:  signer,
		User:    provUser,
		Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewSSHAdminDialer: %v", err)
	}

	return &sshdTarget{
		// Trust on first use: which host keys are trusted is Hoplock Control's
		// decision in production (D7), and there is no policy service here.
		target: Target{Host: host, Port: port, HostKeyCallback: func(string, net.Addr, ssh.PublicKey) error {
			return nil
		}},
		dialer:   dialer,
		provUser: provUser,
	}
}

// TestSSHDEphemeralUserLifecycle is the acceptance criterion against a real
// sshd: the account is created, the session logs in AS that account with the
// key that was installed, and the account is gone afterwards.
func TestSSHDEphemeralUserLifecycle(t *testing.T) {
	sshd := requireSSHD(t)
	ctx := context.Background()

	auth, err := NewEphemeralAuthenticator(EphemeralOptions{
		ProxyID:        "integration-proxy",
		Dialer:         sshd.dialer,
		KeyExpiry:      true,
		ReaperInterval: -1,
	})
	if err != nil {
		t.Fatalf("NewEphemeralAuthenticator: %v", err)
	}
	t.Cleanup(func() { _ = auth.Close() })

	tgt := sshd.target
	tgt.Auth = ephemeralRoute(nil)
	access, err := auth.Provision(ctx, testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	principal := access.ClientConfig.User

	// The real proof: sshd accepts the key for the account that was created.
	// Every permission and ownership rule in the provisioning script is under
	// test here, because StrictModes rejects the login if any of them is wrong.
	if got := sshd.whoami(t, access.ClientConfig); got != principal {
		t.Errorf("logged in as %q, want %q", got, principal)
	}

	if err := access.Close(ctx); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if sshd.accountExists(t, principal) {
		t.Errorf("account %q survived teardown", principal)
	}
	if _, err := ssh.Dial("tcp", tgt.Addr(), access.ClientConfig); err == nil {
		t.Error("the removed account still accepts a login")
	}
}

// TestSSHDOrphanIsReaped is the crash path against a real account database.
func TestSSHDOrphanIsReaped(t *testing.T) {
	sshd := requireSSHD(t)
	ctx := context.Background()

	crashed, err := NewEphemeralAuthenticator(EphemeralOptions{
		ProxyID:        "integration-orphan",
		Dialer:         sshd.dialer,
		ReaperInterval: -1,
		// The shortest grace the reaper accepts, so the sweep below does not
		// have to wait out a real clock. It is NOT enough on its own — see the
		// ageing step further down.
		ReaperGrace: time.Nanosecond,
	})
	if err != nil {
		t.Fatalf("NewEphemeralAuthenticator: %v", err)
	}
	t.Cleanup(func() { _ = crashed.Close() })

	tgt := sshd.target
	tgt.Auth = ephemeralRoute(nil)
	access, err := crashed.Provision(ctx, testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	principal := access.ClientConfig.User

	// Age the orphan explicitly.
	//
	// The sweep ages a candidate by its home directory's mtime, on the TARGET's
	// clock, in WHOLE SECONDS (Reaper.parseDiscovery). A home created in the
	// same second as the sweep is therefore zero seconds old and inside any
	// grace period however short — including the nanosecond above — so this
	// test passed or failed on whether the target's clock happened to tick
	// between two operations that take a few hundred milliseconds. On a CI
	// runner it does not. The fake-host reaper tests never hit this because
	// they set an account's age directly (fakeHost.addAccount).
	//
	// Touching the home into the distant past says what the test means — this
	// orphan is old — instead of sleeping and hoping.
	sshd.run(t, "touch -d @1 "+shellQuote(crashed.homeFor(principal)))

	// The process dies: no teardown, no registry.
	restarted, err := NewEphemeralAuthenticator(EphemeralOptions{
		ProxyID:        "integration-orphan",
		Dialer:         sshd.dialer,
		ReaperInterval: -1,
		ReaperGrace:    time.Nanosecond,
	})
	if err != nil {
		t.Fatalf("NewEphemeralAuthenticator: %v", err)
	}
	t.Cleanup(func() { _ = restarted.Close() })

	removed, err := restarted.reaper.Sweep(ctx, sshd.target)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if !contains(removed, principal) {
		t.Fatalf("sweep removed %v, want it to include %s", removed, principal)
	}
	if sshd.accountExists(t, principal) {
		t.Errorf("orphaned account %q survived the sweep", principal)
	}
}

// TestSSHDBrokeredKeyLeavesTheTargetUnmodified is D6a against a real host: the
// session uses an account that already exists, and nothing about the host
// changes.
func TestSSHDBrokeredKeyLeavesTheTargetUnmodified(t *testing.T) {
	sshd := requireSSHD(t)
	ctx := context.Background()

	keyPath := os.Getenv(envSSHDBrokeredKey)
	account := os.Getenv(envSSHDBrokeredUsr)
	if keyPath == "" || account == "" {
		t.Skipf("%s and %s are not set", envSSHDBrokeredKey, envSSHDBrokeredUsr)
	}
	pem, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read the brokered credential: %v", err)
	}

	before := sshd.run(t, "getent passwd | wc -l; cat "+shellQuote("/home/"+account+"/.ssh/authorized_keys"))

	source := &mapCredentialSource{creds: map[string]*Credential{
		account: {PrivateKey: append([]byte(nil), pem...)},
	}}
	auth, err := NewBrokeredKeyAuthenticator(BrokeredKeyOptions{Source: source, Username: account})
	if err != nil {
		t.Fatalf("NewBrokeredKeyAuthenticator: %v", err)
	}

	tgt := sshd.target
	tgt.Auth = brokeredRoute(map[string]string{ParamCredentialRef: account})
	access, err := auth.Provision(ctx, testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if got := sshd.whoami(t, access.ClientConfig); got != account {
		t.Errorf("logged in as %q, want the pre-existing account %q", got, account)
	}
	if err := access.Close(ctx); err != nil {
		t.Errorf("teardown: %v", err)
	}

	after := sshd.run(t, "getent passwd | wc -l; cat "+shellQuote("/home/"+account+"/.ssh/authorized_keys"))
	if before != after {
		t.Errorf("the target changed:\nbefore: %q\nafter:  %q", before, after)
	}
}

// whoami logs into the target with a provisioned configuration and asks the
// target who it thinks is connected.
func (s *sshdTarget) whoami(t *testing.T, cfg *ssh.ClientConfig) string {
	t.Helper()
	dialCfg := *cfg
	dialCfg.HostKeyCallback = s.target.HostKeyCallback
	dialCfg.Timeout = 30 * time.Second
	client, err := ssh.Dial("tcp", s.target.Addr(), &dialCfg)
	if err != nil {
		t.Fatalf("log in as %q: %v", cfg.User, err)
	}
	defer func() { _ = client.Close() }()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = sess.Close() }()
	out, err := sess.Output("id -un")
	if err != nil {
		t.Fatalf("id -un: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// run executes a command on the target over the management login.
func (s *sshdTarget) run(t *testing.T, script string) string {
	t.Helper()
	admin, err := s.dialer.Dial(context.Background(), s.target)
	if err != nil {
		t.Fatalf("management login: %v", err)
	}
	defer func() { _ = admin.Close() }()
	out, err := admin.Run(context.Background(), script)
	if err != nil {
		t.Fatalf("run %q: %v", script, err)
	}
	return string(out)
}

// accountExists asks the target whether an account is present.
func (s *sshdTarget) accountExists(t *testing.T, name string) bool {
	t.Helper()
	admin, err := s.dialer.Dial(context.Background(), s.target)
	if err != nil {
		t.Fatalf("management login: %v", err)
	}
	defer func() { _ = admin.Close() }()
	_, err = admin.Run(context.Background(), "id -u "+shellQuote(name))
	return err == nil
}

func contains(list []string, want string) bool {
	for _, got := range list {
		if got == want {
			return true
		}
	}
	return false
}
