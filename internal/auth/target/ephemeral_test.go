// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
)

// newTestEphemeral builds the provisioner against a fake host, with background
// sweeping off so that every sweep in a test is one the test asked for.
func newTestEphemeral(t *testing.T, h *fakeHost, proxyID string, adjust ...func(*EphemeralOptions)) *EphemeralAuthenticator {
	t.Helper()
	opts := EphemeralOptions{
		ProxyID:  proxyID,
		Dialer:   h.dialer(t),
		HomeBase: h.home,
		// Inside the fake host's temporary root, never the real
		// /var/lib/hoplock: it holds phase 0019's confinement material and phase
		// 0027's uid watermark, and a shared default would make every test in
		// this package write to the machine running it.
		EnforcementBase: h.enforce,
		KeyExpiry:       true,
		ReaperInterval:  -1,
	}
	for _, f := range adjust {
		f(&opts)
	}
	auth, err := NewEphemeralAuthenticator(opts)
	if err != nil {
		t.Fatalf("NewEphemeralAuthenticator: %v", err)
	}
	t.Cleanup(func() { _ = auth.Close() })
	return auth
}

func ephemeralRoute(params map[string]string) *control.TargetAuth {
	return &control.TargetAuth{Method: control.TargetAuthEphemeralUser, Params: params}
}

// TestEphemeralProvisionsAndTearsDown is the acceptance criterion in one test:
// the account exists and works while the session does, and is gone afterwards.
func TestEphemeralProvisionsAndTearsDown(t *testing.T) {
	h := startFakeHost(t)
	auth := newTestEphemeral(t, h, "proxy-a")
	ctx := context.Background()

	tgt := h.tgt()
	tgt.Auth = ephemeralRoute(nil)
	access, err := auth.Provision(ctx, testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	principal := access.ClientConfig.User
	if !strings.HasPrefix(principal, principalPrefix) {
		t.Errorf("account %q does not carry the reaper's prefix %q", principal, principalPrefix)
	}
	if !strings.Contains(principal, "alice") {
		t.Errorf("account %q does not name the login it belongs to", principal)
	}
	if !h.hasAccount(t, principal) {
		t.Fatalf("account %q was not created; the host has %v", principal, h.accounts(t))
	}

	assertMode(t, filepath.Join(h.homeFor(principal), ".ssh"), 0o700)
	assertMode(t, filepath.Join(h.homeFor(principal), ".ssh", "authorized_keys"), 0o600)

	// The session really logs in as the ephemeral account, offering the key
	// that was installed for it — and nothing else is in the file, because a
	// leftover account must not keep an old key.
	offered := loginAs(t, h, access.ClientConfig)
	if logins := h.target.Logins(); logins[len(logins)-1] != principal {
		t.Errorf("target saw login %q, want %q", logins[len(logins)-1], principal)
	}
	want := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(offered)))
	if got := strings.TrimSpace(h.authorizedKeys(t, principal)); got != want {
		t.Errorf("authorized_keys = %q, want exactly the key the session offers, %q", got, want)
	}

	if err := access.Close(ctx); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if h.hasAccount(t, principal) {
		t.Errorf("account %q survived teardown", principal)
	}
	if _, err := os.Stat(h.homeFor(principal)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("home directory survived teardown: %v", err)
	}
	// The user's processes are killed before the account goes, or userdel would
	// refuse on a target where the session is still running.
	assertOrder(t, h, "pkill", "userdel")

	// Teardown is idempotent: a second call is a no-op, not a failure against
	// an account another session may since have created.
	before := len(h.scripts())
	if err := access.Close(ctx); err != nil {
		t.Errorf("second teardown = %v, want nil", err)
	}
	if got := len(h.scripts()); got != before {
		t.Errorf("second teardown ran %d more script(s), want 0", got-before)
	}
}

// TestEphemeralProvisioningFailureLeavesNothingBehind covers PLAN §5.1's
// failure isolation: a session that is denied must not leave a working account.
func TestEphemeralProvisioningFailureLeavesNothingBehind(t *testing.T) {
	h := startFakeHost(t)
	auth := newTestEphemeral(t, h, "proxy-a")
	// The account is created and the script then fails, which is the dangerous
	// shape: failing before useradd leaves nothing to clean up anyway.
	h.setEnv("FAKEHOST_FAILS_AFTER_USERADD", "1")

	tgt := h.tgt()
	tgt.Auth = ephemeralRoute(nil)
	access, err := auth.Provision(context.Background(), testIdentity(), tgt)
	if err == nil {
		_ = access.Close(context.Background())
		t.Fatal("Provision succeeded on a target whose useradd failed")
	}
	if left := h.ephemeralAccounts(t); len(left) != 0 {
		t.Errorf("a denied session left %v behind", left)
	}
	entries, err := os.ReadDir(h.home)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("a denied session left home directories behind: %v", entries)
	}
}

// TestEphemeralConcurrentSessionsForOneLogin is the concurrency criterion: two
// sessions for the same user on the same target at the same time.
func TestEphemeralConcurrentSessionsForOneLogin(t *testing.T) {
	h := startFakeHost(t)
	auth := newTestEphemeral(t, h, "proxy-a")
	ctx := context.Background()

	const sessions = 4
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		granted []*ProvisionedAccess
		errs    []error
	)
	for range sessions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tgt := h.tgt()
			tgt.Auth = ephemeralRoute(nil)
			access, err := auth.Provision(ctx, testIdentity(), tgt)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			granted = append(granted, access)
		}()
	}
	wg.Wait()
	if len(errs) > 0 {
		t.Fatalf("concurrent provisioning failed: %v", errs)
	}

	// Distinct accounts, each holding only its own key: this is what "must not
	// clobber each other" means concretely.
	seen := map[string]bool{}
	for _, access := range granted {
		principal := access.ClientConfig.User
		if seen[principal] {
			t.Fatalf("two sessions were given the same account %q", principal)
		}
		seen[principal] = true
		want := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(loginAs(t, h, access.ClientConfig))))
		if got := strings.TrimSpace(h.authorizedKeys(t, principal)); got != want {
			t.Errorf("account %q holds %q, want its own key %q", principal, got, want)
		}
	}
	if got := len(h.ephemeralAccounts(t)); got != sessions {
		t.Errorf("host holds %d ephemeral accounts, want %d", got, sessions)
	}

	// Every session cleans up, and one session's teardown removes only its own.
	for i, access := range granted {
		if err := access.Close(ctx); err != nil {
			t.Errorf("teardown %d: %v", i, err)
		}
		if got, want := len(h.ephemeralAccounts(t)), sessions-i-1; got != want {
			t.Errorf("after teardown %d the host holds %d accounts, want %d", i, got, want)
		}
	}
	if left := h.ephemeralAccounts(t); len(left) != 0 {
		t.Errorf("accounts left after the suite: %v", left)
	}
}

// TestEphemeralOrphanIsReapedAfterACrash is the crash criterion. A process that
// dies runs no teardown; the account it left is found by a LATER process,
// because the naming convention survives what the registry does not.
func TestEphemeralOrphanIsReapedAfterACrash(t *testing.T) {
	h := startFakeHost(t)
	crashed := newTestEphemeral(t, h, "proxy-a")
	ctx := context.Background()

	tgt := h.tgt()
	tgt.Auth = ephemeralRoute(nil)
	access, err := crashed.Provision(ctx, testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	principal := access.ClientConfig.User
	// The process dies here: no teardown, no registry, nothing but the account
	// on the target and the passage of time.
	h.backdate(t, h.homeFor(principal), time.Hour)

	restarted := newTestEphemeral(t, h, "proxy-a")
	removed, err := restarted.reaper.Sweep(ctx, h.tgt())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(removed) != 1 || removed[0] != principal {
		t.Fatalf("sweep removed %v, want [%s]", removed, principal)
	}
	if h.hasAccount(t, principal) {
		t.Errorf("orphaned account %q survived the sweep", principal)
	}
	if _, err := os.Stat(h.homeFor(principal)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("orphaned home survived the sweep: %v", err)
	}
}

// TestReaperLeavesLiveAndYoungAccountsAlone is the other half of the reaper:
// what it must NOT remove. Both rules are load-bearing — the first protects a
// long session, the second a session another process is mid-way through
// provisioning.
func TestReaperLeavesLiveAndYoungAccountsAlone(t *testing.T) {
	h := startFakeHost(t)
	auth := newTestEphemeral(t, h, "proxy-a")
	ctx := context.Background()

	tgt := h.tgt()
	tgt.Auth = ephemeralRoute(nil)
	access, err := auth.Provision(ctx, testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	live := access.ClientConfig.User
	// Old enough to be swept on age alone, and held by a live session.
	h.backdate(t, h.homeFor(live), 24*time.Hour)

	young := h.addAccount(t, auth.prefix+"bob-00000001", time.Minute)

	removed, err := auth.reaper.Sweep(ctx, h.tgt())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(removed) != 0 {
		t.Fatalf("sweep removed %v, want nothing", removed)
	}
	if !h.hasAccount(t, live) {
		t.Error("the sweep removed a live session's account")
	}
	if _, err := os.Stat(young); err != nil {
		t.Errorf("the sweep removed an account younger than the grace period: %v", err)
	}
	if err := access.Close(ctx); err != nil {
		t.Errorf("teardown: %v", err)
	}
}

// TestReaperIgnoresAnotherProxysAccounts is why the prefix carries a proxy tag.
// Two proxies fronting one target is the normal case in an estate with more
// than one region, and a sweep that removed every hl- account would end the
// other proxy's live sessions.
func TestReaperIgnoresAnotherProxysAccounts(t *testing.T) {
	h := startFakeHost(t)
	mine := newTestEphemeral(t, h, "proxy-a")
	theirs := newTestEphemeral(t, h, "proxy-b")
	if mine.prefix == theirs.prefix {
		t.Fatalf("two proxies share the account prefix %q", mine.prefix)
	}

	other := h.addAccount(t, theirs.prefix+"carol-00000001", 24*time.Hour)
	ours := h.addAccount(t, mine.prefix+"carol-00000002", 24*time.Hour)

	removed, err := mine.reaper.Sweep(context.Background(), h.tgt())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(removed) != 1 || !strings.HasPrefix(removed[0], mine.prefix) {
		t.Fatalf("sweep removed %v, want only this proxy's account", removed)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("the sweep removed another proxy's account: %v", err)
	}
	if _, err := os.Stat(ours); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the sweep left this proxy's orphan behind: %v", err)
	}
}

// TestEphemeralTolerlatesALeftoverAccount covers the idempotency PLAN §5.1
// asks for: provisioning must survive an account a crashed session left with
// the same name.
func TestEphemeralToleratesALeftoverAccount(t *testing.T) {
	h := startFakeHost(t)
	auth := newTestEphemeral(t, h, "proxy-a")

	// Force the collision the random token normally makes impossible.
	name := auth.prefix + "alice-deadbeef"
	h.addAccount(t, name, time.Hour)
	script, err := auth.provisionScript(
		&confinement{principal: name, home: h.homeFor(name), base: auth.enforceBase},
		"ssh-ed25519 AAAAnew", []int{DefaultUIDMin})
	if err != nil {
		t.Fatalf("provisionScript: %v", err)
	}
	admin, err := auth.dialer.Dial(context.Background(), h.tgt())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = admin.Close() }()
	if _, err := admin.Run(context.Background(), script); err != nil {
		t.Fatalf("provisioning over a leftover account: %v", err)
	}
	if got, want := strings.TrimSpace(h.authorizedKeys(t, name)), "ssh-ed25519 AAAAnew"; got != want {
		t.Errorf("authorized_keys = %q, want %q — the leftover key must be replaced, not appended to", got, want)
	}
}

// TestEphemeralKeyLifetimeIsWrittenToTheTarget proves the route's
// lifetime_seconds reaches sshd rather than being remembered only here.
func TestEphemeralKeyLifetimeIsWrittenToTheTarget(t *testing.T) {
	h := startFakeHost(t)
	auth := newTestEphemeral(t, h, "proxy-a")
	ctx := context.Background()

	tgt := h.tgt()
	tgt.Auth = ephemeralRoute(map[string]string{ParamLifetimeSeconds: "900"})
	access, err := auth.Provision(ctx, testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	defer func() { _ = access.Close(ctx) }()

	line := h.authorizedKeys(t, access.ClientConfig.User)
	if !strings.HasPrefix(line, `expiry-time="`) {
		t.Errorf("authorized_keys = %q, want an expiry-time restriction", line)
	}
	if !strings.Contains(line, `Z" ssh-`) {
		t.Errorf("authorized_keys = %q, want the expiry in UTC", line)
	}
}

// TestEphemeralRefusesWhatItCannotHonour is the contract's rule about
// parameters (api/README.md): an unknown one may be a constraint, and a known
// one this proxy cannot enforce is no better.
func TestEphemeralRefusesWhatItCannotHonour(t *testing.T) {
	h := startFakeHost(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name    string
		params  map[string]string
		expiry  bool
		wantErr error
	}{
		{
			name:    "an unknown parameter",
			params:  map[string]string{"source_address": "10.0.0.0/8"},
			expiry:  true,
			wantErr: ErrUnknownParam,
		},
		{
			name:    "an unsupported key type",
			params:  map[string]string{ParamKeyType: "dsa"},
			expiry:  true,
			wantErr: ErrInvalidParam,
		},
		{
			name:    "a lifetime that is not a number",
			params:  map[string]string{ParamLifetimeSeconds: "fifteen minutes"},
			expiry:  true,
			wantErr: ErrInvalidParam,
		},
		{
			name:    "a lifetime this proxy cannot enforce",
			params:  map[string]string{ParamLifetimeSeconds: "900"},
			expiry:  false,
			wantErr: ErrInvalidParam,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := newTestEphemeral(t, h, "proxy-a", func(o *EphemeralOptions) { o.KeyExpiry = tc.expiry })
			tgt := h.tgt()
			tgt.Auth = ephemeralRoute(tc.params)
			access, err := auth.Provision(ctx, testIdentity(), tgt)
			if err == nil {
				_ = access.Close(ctx)
				t.Fatal("the route was served")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Provision = %v, want errors.Is(..., %v)", err, tc.wantErr)
			}
			if left := h.ephemeralAccounts(t); len(left) != 0 {
				t.Errorf("a refused route provisioned %v", left)
			}
		})
	}
}

// TestEphemeralUsesTheRoutesUsername proves the server's username parameter
// decides the account, while the uniqueness token stays — which is what keeps
// two sessions for one server-named account from colliding.
func TestEphemeralUsesTheRoutesUsername(t *testing.T) {
	h := startFakeHost(t)
	auth := newTestEphemeral(t, h, "proxy-a")
	ctx := context.Background()

	tgt := h.tgt()
	tgt.Auth = ephemeralRoute(map[string]string{ParamUsername: "svc-deploy"})
	access, err := auth.Provision(ctx, testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	defer func() { _ = access.Close(ctx) }()

	principal := access.ClientConfig.User
	if !strings.Contains(principal, "svc-deploy") {
		t.Errorf("account %q does not carry the route's username", principal)
	}
	if strings.HasSuffix(principal, "svc-deploy") {
		t.Errorf("account %q has no uniqueness token; two sessions would collide", principal)
	}
}

// TestEphemeralRSAKeyType covers the other key algorithm, for targets whose
// sshd is too old for ed25519.
func TestEphemeralRSAKeyType(t *testing.T) {
	h := startFakeHost(t)
	auth := newTestEphemeral(t, h, "proxy-a")
	ctx := context.Background()

	tgt := h.tgt()
	tgt.Auth = ephemeralRoute(map[string]string{ParamKeyType: KeyTypeRSA})
	access, err := auth.Provision(ctx, testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	defer func() { _ = access.Close(ctx) }()

	if got := loginAs(t, h, access.ClientConfig).Type(); got != ssh.KeyAlgoRSA {
		t.Errorf("key type = %q, want %q", got, ssh.KeyAlgoRSA)
	}
}

// TestEphemeralNeedsAnIdentity keeps the plane's rule: nothing is provisioned
// for a connection that cannot be attributed.
func TestEphemeralNeedsAnIdentity(t *testing.T) {
	h := startFakeHost(t)
	auth := newTestEphemeral(t, h, "proxy-a")
	if _, err := auth.Provision(context.Background(), nil, h.tgt()); err == nil {
		t.Error("an unauthenticated connection was provisioned for")
	}
}

// TestEphemeralTeardownReportsAnAccountItCouldNotRemove: a teardown that
// silently succeeded while the account stayed would be the worst outcome in
// this package, so the script verifies and the error surfaces.
func TestEphemeralTeardownReportsAnAccountItCouldNotRemove(t *testing.T) {
	h := startFakeHost(t)
	auth := newTestEphemeral(t, h, "proxy-a")
	ctx := context.Background()

	tgt := h.tgt()
	tgt.Auth = ephemeralRoute(nil)
	access, err := auth.Provision(ctx, testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	principal := access.ClientConfig.User
	h.setEnv("FAKEHOST_USERDEL_FAILS", "1")

	err = access.Close(ctx)
	if err == nil {
		t.Fatal("teardown reported success while the account was still there")
	}
	var remote *RemoteCommandError
	if !errors.As(err, &remote) || remote.ExitStatus != exitUserRemains {
		t.Fatalf("teardown = %v, want exit %d", err, exitUserRemains)
	}
	if remote.Stage != "teardown" {
		t.Errorf("error stage = %q, want %q", remote.Stage, "teardown")
	}

	// The account is released from the live set even so, which is what lets the
	// reaper pick it up: a failed teardown must not protect its own leftovers.
	if auth.reaper.isLive(tgt, principal) {
		t.Error("a failed teardown left the account marked live, so no sweep will ever remove it")
	}
	// The home directory did go, so the account now has none — which the sweep
	// reads as "age unknown" and therefore reapable, exactly the treatment a
	// half-created account needs.
	h.setEnv("FAKEHOST_USERDEL_FAILS", "")
	removed, err := auth.reaper.Sweep(ctx, h.tgt())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(removed) != 1 || removed[0] != principal {
		t.Errorf("sweep removed %v, want [%s]", removed, principal)
	}
}

// loginAs logs into the fake host with a provisioned client configuration and
// returns the public key the target was offered.
//
// Going through a real login is the point: a credential is only provisioned if
// the account it names can be logged into with the key that was installed, and
// nothing short of connecting proves that.
func loginAs(t *testing.T, h *fakeHost, cfg *ssh.ClientConfig) ssh.PublicKey {
	t.Helper()
	dialCfg := *cfg
	dialCfg.HostKeyCallback = ssh.FixedHostKey(h.target.HostKey())
	dialCfg.Timeout = 20 * time.Second
	client, err := ssh.Dial("tcp", h.target.Addr().String(), &dialCfg)
	if err != nil {
		t.Fatalf("log in as %q: %v", cfg.User, err)
	}
	_ = client.Close()
	keys := h.target.Keys()
	if len(keys) == 0 {
		t.Fatal("the target recorded no offered key")
	}
	return keys[len(keys)-1]
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s has mode %o, want %o", path, got, want)
	}
}

// assertOrder checks that the first fake command ran before the second.
func assertOrder(t *testing.T, h *fakeHost, first, second string) {
	t.Helper()
	data, err := os.ReadFile(h.log)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	log := string(data)
	i, j := strings.Index(log, first), strings.Index(log, second)
	switch {
	case i < 0:
		t.Errorf("%s never ran", first)
	case j < 0:
		t.Errorf("%s never ran", second)
	case i > j:
		t.Errorf("%s ran after %s", first, second)
	}
}

// --- uid allocation against a real shell (phase 0027) ------------------------

// uidOf is the uid the fake host holds for the account an access connected as.
func uidOf(t *testing.T, h *fakeHost, access *ProvisionedAccess) int {
	t.Helper()
	return h.uidFor(t, access.ClientConfig.User)
}

// TestEphemeralAllocatesFromTheDedicatedRange covers the two claims that
// together are the phase: the uid comes from the configured range rather than
// from the target's own allocator, and the account it reports is the account the
// target really holds.
func TestEphemeralAllocatesFromTheDedicatedRange(t *testing.T) {
	h := startFakeHost(t)
	auth := newTestEphemeral(t, h, "proxy-a")
	ctx := context.Background()
	tgt := h.tgt()
	tgt.Auth = ephemeralRoute(nil)

	access, err := auth.Provision(ctx, testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	defer func() { _ = access.Close(ctx) }()

	uid := uidOf(t, h, access)
	if uid < DefaultUIDMin || uid > DefaultUIDMax {
		t.Errorf("the account holds uid %d, want one inside the dedicated range %d-%d",
			uid, DefaultUIDMin, DefaultUIDMax)
	}
	if access.AccountUID != uid {
		t.Errorf("the access reports uid %d and the target holds %d", access.AccountUID, uid)
	}
	if got := h.watermark(t); got != uid {
		t.Errorf("the target's uid mark is %d, want the allocated %d — a mark that is not written is reuse next time", got, uid)
	}
}

// TestTwoSequentialSessionsDoNotShareAUID is the defect, stated as a test.
//
// The first account is fully torn down before the second is provisioned, so
// its uid is FREE — and every allocator that picks a free uid, including the
// target's own, would hand it straight back. This is the acceptance criterion of
// prompt 0027, and it fails against the pre-0027 provisioning path.
func TestTwoSequentialSessionsDoNotShareAUID(t *testing.T) {
	h := startFakeHost(t)
	auth := newTestEphemeral(t, h, "proxy-a")
	ctx := context.Background()
	tgt := h.tgt()
	tgt.Auth = ephemeralRoute(nil)

	var uids []int
	for i := 0; i < 4; i++ {
		access, err := auth.Provision(ctx, testIdentity(), tgt)
		if err != nil {
			t.Fatalf("Provision %d: %v", i, err)
		}
		uid := uidOf(t, h, access)
		if err := access.Close(ctx); err != nil {
			t.Fatalf("teardown %d: %v", i, err)
		}
		for _, seen := range uids {
			if seen == uid {
				t.Fatalf("session %d was handed uid %d again after it had been torn down (saw %v)", i, uid, uids)
			}
		}
		if i > 0 && uid <= uids[i-1] {
			t.Errorf("session %d got uid %d, which is not above the previous %d", i, uid, uids[i-1])
		}
		uids = append(uids, uid)
	}
	if got := h.watermark(t); got != uids[len(uids)-1] {
		t.Errorf("the uid mark is %d after four sessions, want the highest allocated %d", got, uids[len(uids)-1])
	}
	// The mark directory converges to one entry: it is pruned by every
	// allocation, and a mark per session on a long-lived target would grow
	// without bound.
	if marks := h.marks(t); len(marks) != 1 {
		t.Errorf("the mark directory holds %v, want only the highest", marks)
	}
}

// TestANewProxyProcessDoesNotRepeatTheLastOneUID is why the mark lives on the
// TARGET. A restarted proxy — or a second proxy serving the same fleet — has no
// memory of what it allocated, and the invariant has to survive that: the number
// is a property of the host, not of a process.
func TestANewProxyProcessDoesNotRepeatTheLastOneUID(t *testing.T) {
	h := startFakeHost(t)
	ctx := context.Background()
	tgt := h.tgt()
	tgt.Auth = ephemeralRoute(nil)

	first := newTestEphemeral(t, h, "proxy-a")
	access, err := first.Provision(ctx, testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	before := uidOf(t, h, access)
	if err := access.Close(ctx); err != nil {
		t.Fatalf("teardown: %v", err)
	}

	// A different process, with a fresh allocator and no in-memory history.
	second := newTestEphemeral(t, h, "proxy-a")
	access, err = second.Provision(ctx, testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision after a restart: %v", err)
	}
	defer func() { _ = access.Close(ctx) }()
	if after := uidOf(t, h, access); after <= before {
		t.Errorf("a restarted proxy allocated uid %d after %d; the mark on the target is what has to prevent that", after, before)
	}
}

// TestConcurrentSessionsDoNotShareAUID is the same claim under the concurrency
// PLAN §5.1 requires. Two censuses taken a microsecond apart cannot mention an
// account that does not exist yet, which is what the allocator's own per-target
// state is for.
func TestConcurrentSessionsDoNotShareAUID(t *testing.T) {
	h := startFakeHost(t)
	auth := newTestEphemeral(t, h, "proxy-a")
	ctx := context.Background()
	tgt := h.tgt()
	tgt.Auth = ephemeralRoute(nil)

	const sessions = 4
	type outcome struct {
		access *ProvisionedAccess
		err    error
	}
	results := make(chan outcome, sessions)
	for i := 0; i < sessions; i++ {
		go func() {
			access, err := auth.Provision(ctx, testIdentity(), tgt)
			results <- outcome{access, err}
		}()
	}

	seen := map[int]string{}
	var held []*ProvisionedAccess
	for i := 0; i < sessions; i++ {
		got := <-results
		if got.err != nil {
			t.Errorf("concurrent Provision: %v", got.err)
			continue
		}
		held = append(held, got.access)
		uid := uidOf(t, h, got.access)
		if other, ok := seen[uid]; ok {
			t.Errorf("%s and %s are both uid %d at the same instant",
				other, got.access.ClientConfig.User, uid)
		}
		seen[uid] = got.access.ClientConfig.User
	}
	for _, access := range held {
		if err := access.Close(ctx); err != nil {
			t.Errorf("teardown: %v", err)
		}
	}
}

// TestEphemeralRefusesRatherThanWrapping is the fail-closed half (prompt 0027
// §2), end to end: a range with two uids in it serves two sessions and then
// refuses, with nothing created on the target.
func TestEphemeralRefusesRatherThanWrapping(t *testing.T) {
	h := startFakeHost(t)
	auth := newTestEphemeral(t, h, "proxy-a", func(o *EphemeralOptions) {
		o.UIDMin = 4000
		o.UIDMax = 4001
	})
	ctx := context.Background()
	tgt := h.tgt()
	tgt.Auth = ephemeralRoute(nil)

	for i := 0; i < 2; i++ {
		access, err := auth.Provision(ctx, testIdentity(), tgt)
		if err != nil {
			t.Fatalf("Provision %d: %v", i, err)
		}
		if err := access.Close(ctx); err != nil {
			t.Fatalf("teardown %d: %v", i, err)
		}
	}

	// Both uids are free now. Wrapping would serve this session; refusing is the
	// decision, because a uid the range has already handed out may own files a
	// previous session wrote outside its home.
	if _, err := auth.Provision(ctx, testIdentity(), tgt); !errors.Is(err, ErrUIDUnavailable) {
		t.Fatalf("Provision past the top of the range = %v, want ErrUIDUnavailable", err)
	}
	if accounts := h.ephemeralAccounts(t); len(accounts) != 0 {
		t.Errorf("a refused session left %v on the target; a uid refusal must provision nothing", accounts)
	}
}

// TestARecycledUIDIsRefusedRatherThanReported keeps the report honest for the
// one case where the target chooses the uid: an account adopted from a crashed
// session keeps the uid it already had, and the record has to name THAT.
func TestAnAdoptedAccountReportsTheUIDItAlreadyHad(t *testing.T) {
	h := startFakeHost(t)
	auth := newTestEphemeral(t, h, "proxy-a")

	name := auth.prefix + "alice-deadbeef"
	h.addAccount(t, name, time.Hour) // addAccount writes uid 1001
	script, err := auth.provisionScript(
		&confinement{principal: name, home: h.homeFor(name), base: auth.enforceBase},
		"ssh-ed25519 AAAAnew", []int{DefaultUIDMin})
	if err != nil {
		t.Fatalf("provisionScript: %v", err)
	}
	admin, err := auth.dialer.Dial(context.Background(), h.tgt())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = admin.Close() }()
	out, err := admin.Run(context.Background(), script)
	if err != nil {
		t.Fatalf("provisioning over a leftover account: %v", err)
	}
	uid, err := parseProvisionedUID(out)
	if err != nil {
		t.Fatalf("parseProvisionedUID: %v", err)
	}
	if uid != 1001 {
		t.Errorf("the script reported uid %d for an adopted account holding 1001", uid)
	}
}

// TestAUIDTheTargetRefusesFallsThroughToTheNextCandidate covers the race the
// candidate list exists for: another provisioner took the allocation between the
// census and the useradd. It must cost a retry inside one script, not a refused
// session.
func TestAUIDTheTargetRefusesFallsThroughToTheNextCandidate(t *testing.T) {
	h := startFakeHost(t)
	auth := newTestEphemeral(t, h, "proxy-a")

	// Something else already holds the first two candidates.
	h.addAccountWithUID(t, "someone-else", 5000)
	h.addAccountWithUID(t, "someone-later", 5001)

	name := auth.prefix + "alice-abcd1234"
	script, err := auth.provisionScript(
		&confinement{principal: name, home: h.homeFor(name), base: auth.enforceBase},
		"ssh-ed25519 AAAA", []int{5000, 5001, 5002})
	if err != nil {
		t.Fatalf("provisionScript: %v", err)
	}
	admin, err := auth.dialer.Dial(context.Background(), h.tgt())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = admin.Close() }()
	out, err := admin.Run(context.Background(), script)
	if err != nil {
		t.Fatalf("provisioning against two taken uids: %v", err)
	}
	uid, err := parseProvisionedUID(out)
	if err != nil {
		t.Fatalf("parseProvisionedUID: %v", err)
	}
	if uid != 5002 {
		t.Errorf("the account holds uid %d, want the first free candidate 5002", uid)
	}
}

// TestAUIDTheTargetCannotRecordFailsTheSession covers the other fail-closed
// path: the account exists and its uid could not be written down, so the next
// allocation on that target would have nothing to allocate above it.
func TestAUIDTheTargetCannotRecordFailsTheSession(t *testing.T) {
	h := startFakeHost(t)
	auth := newTestEphemeral(t, h, "proxy-a")
	ctx := context.Background()
	tgt := h.tgt()
	tgt.Auth = ephemeralRoute(nil)

	// A mark directory that cannot be created, because a FILE is in its place.
	if err := os.MkdirAll(h.enforce, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(h.enforce, uidWatermarkName), []byte("not a directory\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := auth.Provision(ctx, testIdentity(), tgt)
	if !errors.Is(err, ErrUIDUnavailable) {
		t.Fatalf("Provision with an unwritable uid mark = %v, want ErrUIDUnavailable", err)
	}
	if accounts := h.ephemeralAccounts(t); len(accounts) != 0 {
		t.Errorf("the failed provisioning left %v behind", accounts)
	}
}
