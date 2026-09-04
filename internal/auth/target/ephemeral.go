// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/identity"
)

// MethodEphemeralUser names the just-in-time provisioner (D6).
const MethodEphemeralUser = string(control.TargetAuthEphemeralUser)

// Ephemeral key algorithms, as the contract's key_type parameter spells them.
const (
	KeyTypeEd25519 = "ed25519"
	KeyTypeRSA     = "rsa"
)

// ephemeralRSABits is the size of an ephemeral RSA key. It exists only for
// targets whose sshd predates ed25519; a key that lives for one session is not
// where key size is the binding constraint, but 3072 keeps it above every
// policy floor a customer is likely to run.
const ephemeralRSABits = 3072

// DefaultHomeBase is where ephemeral home directories are created.
const DefaultHomeBase = "/home"

// DefaultTargetShell is the login shell given to an ephemeral account.
const DefaultTargetShell = "/bin/sh"

// EphemeralOptions configures the just-in-time provisioner.
type EphemeralOptions struct {
	// ProxyID scopes the account naming convention to this proxy, so two
	// proxies serving one target never reap each other's live sessions.
	// Required.
	ProxyID string
	// Dialer opens the management-certificate login. Required.
	Dialer AdminDialer
	// HomeBase is the parent directory of ephemeral home directories. Empty
	// means DefaultHomeBase.
	HomeBase string
	// TargetShell is the login shell given to ephemeral accounts. Empty means
	// DefaultTargetShell.
	TargetShell string
	// KeyExpiry writes OpenSSH's expiry-time restriction into authorized_keys
	// when a route asks for a lifetime. Disable it only for a fleet whose sshd
	// predates 8.2 — a route that then asks for a lifetime is refused rather
	// than served with a key that never expires.
	KeyExpiry bool
	// ReaperInterval is how often orphans are swept. Zero means
	// DefaultReaperInterval; negative disables background sweeping entirely —
	// both the periodic sweep and the one that follows a provisioning — leaving
	// only an explicit call to Reaper.Sweep.
	ReaperInterval time.Duration
	// ReaperGrace is how old an untracked account must be before a sweep
	// removes it. Zero means DefaultReaperGrace.
	ReaperGrace time.Duration
	// EnforcementBase is the parent directory of the per-account confinement
	// material an enforcement rung renders (PLAN §6.5, phase 0019). Empty means
	// DefaultEnforcementBase. It is deliberately OUTSIDE the account's home:
	// under account-confined the home is mounted noexec, so a dispatcher living
	// in it could not be executed, and a dispatcher the account could write
	// would not be an allow-list.
	EnforcementBase string
	// Reporter records what a target can enforce, so a server never chooses a
	// rung this target cannot take (contract v4). Nil skips reporting, which
	// costs the server a better-informed choice and costs the session nothing:
	// a report GRANTS NOTHING, and every rung is re-checked against the live
	// target here anyway.
	Reporter control.CapabilityReporter
	// Logger receives provisioning, teardown, and sweep events; nil discards
	// them. It is never given a private key.
	Logger *log.Logger
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// EphemeralAuthenticator provisions a short-lived OS account and key on the
// target for one session, and removes both when the session ends (D6,
// PLAN §5.1).
//
// It is the strongest credential story available on a Linux fleet — no standing
// accounts, no shared secret, nothing to rotate, and an audit trail on the
// target that names a person — and it is the most invasive: it needs a
// preloaded management certificate and an account that may create and delete
// users. Targets that cannot offer that are what brokered-key is for (D6a), and
// which of the two applies is the server's decision, per route.
//
// What makes it safe to run is not the provisioning, which is the easy half. It
// is that every account it creates is removed: teardown runs on the normal
// path, on error, on panic, and on signal (the engine's session close), it is
// idempotent, it verifies, and anything that still slips through is found later
// by the orphan reaper. See reaper.go for the half of the guarantee that
// survives the process dying.
type EphemeralAuthenticator struct {
	dialer      AdminDialer
	prefix      string
	homeBase    string
	shell       string
	enforceBase string
	keyExpiry   bool
	reporter    control.CapabilityReporter
	probes      *probeCache
	logger      *log.Logger
	now         func() time.Time
	reaper      *Reaper
}

var (
	_ TargetAuthenticator = (*EphemeralAuthenticator)(nil)
	_ Lifecycle           = (*EphemeralAuthenticator)(nil)
)

// NewEphemeralAuthenticator validates opts and returns the provisioner.
func NewEphemeralAuthenticator(opts EphemeralOptions) (*EphemeralAuthenticator, error) {
	switch {
	case opts.ProxyID == "":
		return nil, errors.New("auth/target: ephemeral-user requires the proxy id")
	case opts.Dialer == nil:
		return nil, errors.New("auth/target: ephemeral-user requires a management connection")
	}

	a := &EphemeralAuthenticator{
		dialer:      opts.Dialer,
		prefix:      principalPrefixFor(opts.ProxyID),
		homeBase:    opts.HomeBase,
		shell:       opts.TargetShell,
		enforceBase: opts.EnforcementBase,
		keyExpiry:   opts.KeyExpiry,
		reporter:    opts.Reporter,
		probes:      newProbeCache(control.DefaultCapabilityTTL),
		logger:      opts.Logger,
		now:         opts.Now,
	}
	if a.homeBase == "" {
		a.homeBase = DefaultHomeBase
	}
	if a.shell == "" {
		a.shell = DefaultTargetShell
	}
	if a.enforceBase == "" {
		a.enforceBase = DefaultEnforcementBase
	}
	if a.now == nil {
		a.now = time.Now
	}
	if err := validatePath(a.homeBase); err != nil {
		return nil, err
	}
	if err := validatePath(a.shell); err != nil {
		return nil, err
	}
	if err := validatePath(a.enforceBase); err != nil {
		return nil, err
	}
	a.reaper = newReaper(a, opts.ReaperInterval, opts.ReaperGrace)
	return a, nil
}

// Name implements TargetAuthenticator.
func (a *EphemeralAuthenticator) Name() string { return MethodEphemeralUser }

// Start begins the periodic orphan sweep. It implements Lifecycle.
func (a *EphemeralAuthenticator) Start(ctx context.Context) { a.reaper.Start(ctx) }

// Close stops the orphan sweep. Sessions still hold their own teardown; this
// only ends the background work.
func (a *EphemeralAuthenticator) Close() error { return a.reaper.Close() }

// Provision creates this session's account and key on the target.
//
// The order is the one PLAN §5.1 fixes, and each step is undone by the one
// cleanup path: management login, create account, install key, hand back a
// client configuration plus the teardown that removes all of it. A failure at
// any step tears down what the earlier ones did before returning, so a denied
// session leaves the target exactly as it found it.
func (a *EphemeralAuthenticator) Provision(ctx context.Context, id *identity.Identity, tgt Target) (*ProvisionedAccess, error) {
	if id == nil {
		return nil, errors.New("auth/target: ephemeral-user requires an authenticated identity")
	}

	p := newParams(tgt.Auth)
	login := p.str(ParamUsername, id.Login)
	keyType := p.str(ParamKeyType, KeyTypeEd25519)
	lifetime, hasLifetime, err := p.duration(ParamLifetimeSeconds)
	if err != nil {
		return nil, err
	}
	if err := p.rest(); err != nil {
		return nil, err
	}
	if hasLifetime && !a.keyExpiry {
		// A lifetime this proxy cannot enforce is refused rather than ignored.
		// The alternative is a session that runs on a key with no expiry while
		// the server's audit record says otherwise, which is worse than an
		// honest outage — and the fix is a configuration change on a fleet
		// whose sshd can express it.
		return nil, fmt.Errorf("%w: %s is set but key expiry is disabled on this proxy",
			ErrInvalidParam, ParamLifetimeSeconds)
	}
	if login == "" {
		return nil, errors.New("auth/target: ephemeral-user has no login to derive an account from")
	}

	principal, err := newPrincipal(a.prefix, login)
	if err != nil {
		return nil, err
	}
	home := a.homeFor(principal)

	signer, err := generateSessionKey(keyType)
	if err != nil {
		return nil, err
	}

	// The management login comes BEFORE anything is decided about the rung,
	// because deciding needs the target's answer. Nothing has been created yet,
	// so a rung this target cannot provide is refused with the target exactly
	// as it was found (PLAN §4.3: an outage-class denial, and nothing
	// provisioned).
	admin, err := a.dialer.Dial(ctx, tgt)
	if err != nil {
		return nil, err
	}
	defer func() { _ = admin.Close() }()

	confinement, err := a.planConfinement(tgt.Enforcement, a.observe(ctx, admin, tgt), principal, home)
	if err != nil {
		return nil, err
	}

	authorizedKey, err := a.authorizedKeyLine(signer.PublicKey(), lifetime, confinement)
	if err != nil {
		return nil, err
	}
	script, err := a.provisionScript(confinement, authorizedKey)
	if err != nil {
		return nil, err
	}

	if _, err := admin.Run(ctx, script); err != nil {
		// Failure isolation (PLAN §5.1): whatever the script managed before it
		// failed is removed now, on the connection that is already open, so a
		// denied session never leaves a half-created account — or a half-applied
		// rung — behind.
		a.cleanUpFailedProvision(ctx, admin, principal, home)
		return nil, stageErr("provision", err)
	}

	hostKey := admin.HostKey()
	a.reaper.observe(tgt, hostKey)
	a.reaper.track(tgt, principal)
	// Sweeping now rather than at startup is what makes orphans from a CRASHED
	// PROCESS recoverable: after a restart the proxy has no idea which targets
	// it owes cleanup on until it touches one again, and this is that moment.
	// It runs in the background because it is not this session's latency.
	a.reaper.sweepInBackground(tgt)

	execMechanism, reachMechanism := confinement.mechanisms()
	enforcement := resultFor(tgt.Enforcement, execMechanism, reachMechanism)
	enforcement.Caveat = confinement.caveat()

	a.logf("auth/target: ephemeral-user provisioned subject=%s target=%s account=%s key=%s enforcement=%s/%s",
		id.Subject, tgt, principal, keyType, enforcement.Execution, enforcement.Reach)
	if names := interpretersIn(confinement.commands); len(names) > 0 {
		// A warning and never a refusal (0018): an allow-list containing an
		// interpreter is not an allow-list, but a shipped deny-list of
		// interpreter names in the proxy would be a blacklist masquerading as a
		// boundary — incomplete on the day it shipped, and refusing a
		// legitimate route at connect time in front of a user.
		a.logf("auth/target: WARNING session=%s renders an allow-list naming %s, each of which can hand back a shell: the rung bounds the mechanism, not the list",
			tgt.SessionID, strings.Join(names, ", "))
	}

	return &ProvisionedAccess{
		ClientConfig: &ssh.ClientConfig{
			User: principal,
			Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
			// HostKeyCallback is the proxy's to set (D7), as on every
			// implementation of this interface.
		},
		Enforcement: enforcement,
		Teardown: func(ctx context.Context) error {
			return a.teardown(ctx, tgt, hostKey, principal, home)
		},
	}, nil
}

// teardown removes one ephemeral account. It is reached from
// ProvisionedAccess.Close — which runs it exactly once — and from the reaper,
// which runs it for accounts nobody is holding.
func (a *EphemeralAuthenticator) teardown(ctx context.Context, tgt Target, hostKey ssh.PublicKey, principal, home string) error {
	defer a.reaper.release(tgt, principal)

	script, err := a.teardownScript(principal, home)
	if err != nil {
		return err
	}

	admin, err := a.dialer.Dial(ctx, pin(tgt, hostKey))
	if err != nil {
		// Loud, and only loud: there is nothing else this layer can do about a
		// target that is unreachable at teardown. The account is released from
		// the live set on the way out either way, which makes it an orphan —
		// the one thing in this package that is guaranteed to be looked at
		// again (see Reaper.release).
		return fmt.Errorf("auth/target: ephemeral-user teardown for %s: %w", principal, err)
	}
	defer func() { _ = admin.Close() }()

	if _, err := admin.Run(ctx, script); err != nil {
		return stageErr("teardown", err)
	}
	a.logf("auth/target: ephemeral-user removed target=%s account=%s", tgt, principal)
	return nil
}

// cleanUpFailedProvision undoes a partial provisioning on the connection that
// was already open. Its own failure is logged and swallowed: the session is
// being denied either way, and what it could not remove is what the reaper is
// for.
func (a *EphemeralAuthenticator) cleanUpFailedProvision(ctx context.Context, admin AdminSession, principal, home string) {
	script, err := a.teardownScript(principal, home)
	if err != nil {
		a.logf("auth/target: ephemeral-user could not build cleanup for %s: %v", principal, err)
		return
	}
	if _, err := admin.Run(ctx, script); err != nil {
		a.logf("auth/target: ephemeral-user cleanup after failed provisioning of %s: %v", principal, err)
	}
}

// authorizedKeyLine renders the public key as an authorized_keys entry,
// carrying the route's lifetime as OpenSSH's expiry-time restriction.
//
// The expiry is written on the TARGET, not remembered by the proxy, because a
// lifetime the proxy alone enforces stops meaning anything the moment the proxy
// is the thing that failed. sshd refuses the key after the deadline whatever
// this process is doing.
func (a *EphemeralAuthenticator) authorizedKeyLine(pub ssh.PublicKey, lifetime time.Duration, c *confinement) (string, error) {
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	var options []string
	if lifetime > 0 {
		expiry := a.now().UTC().Add(lifetime).Format("20060102150405")
		options = append(options, fmt.Sprintf("expiry-time=%q", expiry+"Z"))
	}
	// The rung's own half of the line. `restrict` (or, on an sshd that predates
	// it, the individual no-* options) is the capability fence; command= is the
	// dispatcher, and it is what makes this the ONE rung in the system that
	// also holds against a connection made with this key that never went
	// through the proxy.
	if c != nil && c.dispatcher {
		if c.restrict {
			options = append(options, "restrict")
		} else {
			options = append(options,
				"no-agent-forwarding", "no-port-forwarding", "no-pty",
				"no-user-rc", "no-X11-forwarding")
		}
		dispatch := c.dir + "/" + dispatcherName
		if err := validatePath(dispatch); err != nil {
			return "", err
		}
		options = append(options, fmt.Sprintf("command=%q", dispatch))
	}
	if len(options) > 0 {
		line = strings.Join(options, ",") + " " + line
	}
	if err := validateScriptValue("authorized key", line); err != nil {
		return "", err
	}
	return line, nil
}

// generateSessionKey makes this session's keypair. It is generated per session
// and never written to disk: the only copies that exist are this process's
// memory and the public half in the account's authorized_keys, which teardown
// removes.
func generateSessionKey(keyType string) (ssh.Signer, error) {
	switch keyType {
	case KeyTypeEd25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("auth/target: generate ephemeral key: %w", err)
		}
		return ssh.NewSignerFromKey(priv)
	case KeyTypeRSA:
		priv, err := rsa.GenerateKey(rand.Reader, ephemeralRSABits)
		if err != nil {
			return nil, fmt.Errorf("auth/target: generate ephemeral key: %w", err)
		}
		return ssh.NewSignerFromKey(priv)
	default:
		return nil, fmt.Errorf("%w: %s=%q", ErrInvalidParam, ParamKeyType, keyType)
	}
}

// pin returns tgt with its host-key policy fixed to the key the management
// login already saw.
//
// Teardown and sweeps must not depend on the policy service: the session's
// callback reports every key to Hoplock Control (D7) and fails closed when the
// server is unreachable, which at teardown time would mean an account left
// behind because a *different* component was down. The key was accepted once,
// on this connection, and re-using it is both stricter and independent.
func pin(tgt Target, hostKey ssh.PublicKey) Target {
	if hostKey != nil {
		tgt.HostKeyCallback = ssh.FixedHostKey(hostKey)
	}
	return tgt
}

// stageErr labels a remote command failure with what it was doing.
func stageErr(stage string, err error) error {
	var rce *RemoteCommandError
	if errors.As(err, &rce) && rce.Stage == "" {
		rce.Stage = stage
	}
	return err
}

func (a *EphemeralAuthenticator) logf(format string, args ...any) {
	if a.logger == nil {
		return
	}
	a.logger.Printf(format, args...)
}
