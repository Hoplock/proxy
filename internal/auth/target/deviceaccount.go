// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/auth/target/device"
	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/identity"
)

// MethodEphemeralAccount names the device provisioner (D13, PLAN §5.3).
const MethodEphemeralAccount = string(control.TargetAuthEphemeralAccount)

// The contract parameters this method reads. They are control's constants
// rather than new copies: phase 0013 left a note asking 0014 to collapse the
// duplicates onto control.Param* once it was in this package, and two
// almost-correct copies of a parameter name eventually disagree about one.
const (
	ParamPlatform       = control.ParamPlatform
	ParamCredentialKind = control.ParamCredentialKind
	ParamExpiryPosture  = control.ParamExpiryPosture
)

// collisionBudget is how many fresh tokens a provisioning tries before giving
// up.
//
// The device path never adopts an existing account (D13), so a collision means
// drawing again. The budget is small on purpose: with a token of four base36
// characters at the very tightest limit, more than a couple of collisions in a
// row is not bad luck, it is a device whose administrator table is full of this
// proxy's leftovers — and retrying harder would hide exactly the condition an
// operator needs to see.
const collisionBudget = 5

// DefaultDeviceReaperInterval and DefaultDeviceReaperGrace pace the device
// sweep.
//
// They are TIGHTER than the POSIX reaper's (10m/30m) and the reason is D13's:
// where a platform cannot enforce expiry — which is every platform this
// repository has a driver for — the reaper is the PRIMARY removal path and not
// a crash-recovery backstop. A sweep interval sized for "the rare crash" would
// be sized for the common case here, and the common case is a privileged
// administrator on a firewall.
const (
	DefaultDeviceReaperInterval = 2 * time.Minute
	DefaultDeviceReaperGrace    = 10 * time.Minute
)

// generatedPasswordLen is the length of a generated device password.
//
// It is long because it is never typed and never remembered: it exists in this
// process's memory and in the device's own configuration, and nowhere else.
const generatedPasswordLen = 48

// ErrRungUnsatisfiable means this proxy understood a ladder rung and cannot
// serve it (D14).
//
// It is the distinction the Selector walks on, and it is NOT an error the
// session sees: an unsatisfiable rung is skipped and the next one is tried. Its
// opposite is an error from an attempt that was made, which fails the session
// rather than quietly dropping to a weaker credential the server ranked lower.
var ErrRungUnsatisfiable = errors.New("auth/target: this proxy cannot satisfy the credential method the route named")

// ErrNoLoggingPath means a route that depends on the mapping event for
// attribution reached a proxy that cannot emit one.
//
// On a constrained platform the account name carries no login, so the mapping
// event is the ONLY place the account is tied to a person (PLAN §5.3). A proxy
// with no logging path at all — not even its disk buffer — would create a
// privileged administrator that nothing on earth can attribute, which is worse
// than the session not happening. It is the same fail-closed rule as D16's
// required capture, reached from a different direction.
var ErrNoLoggingPath = errors.New("auth/target: this route needs the account-mapping event and this proxy has no logging path")

// AccountMapping is the event that carries attribution on a constrained
// platform (PLAN §5.3, D8).
//
// Every field is here because something downstream cannot be joined without it.
// On Linux the target itself names the user and this event is a convenience; on
// a device whose administrator name is eleven characters of base36 it is the
// whole audit trail, which is why the provisioner emits it on D8's PRIORITY
// path rather than letting it wait in a batch that a crash would lose.
type AccountMapping struct {
	// Account is the administrator that was created on the device.
	Account string
	// SessionID, Subject and Login are who it belongs to.
	SessionID string
	Subject   string
	Login     string
	// Target and Platform are where it was created and by which driver.
	Target   string
	Platform string
	// Profile is the platform's own authorization scope for the account — an
	// access profile, a role, a privilege level. It is here because on a device
	// it is the only thing bounding what the account may do, and phase 0017
	// replaces the fixed default with a policy choice that this field is how
	// anybody will be able to audit.
	Profile string
	// Method and Rung are the credential method in force and its position in
	// the server's ladder (D14). They are an audit fact and never a
	// user-facing one.
	Method string
	Rung   int
	// ExpiryPosture is who, if anyone, enforces the account's end (D13).
	ExpiryPosture string
	// Lifetime is how long the account was meant to live. Zero under the
	// accepted-risk posture.
	Lifetime time.Duration
	// Constrained says the account name had to give up its login segment, so
	// this event is the only attribution that exists.
	Constrained bool
	// PersistsAcrossReload and PersistenceReason carry the driver's declaration
	// (D13). They are on the session record because a standing-account risk
	// belongs where the risk is taken, not only in a driver's source.
	PersistsAcrossReload bool
	PersistenceReason    string
	// At is when the account was created.
	At time.Time
}

// SweepFailure is an orphaned device account a sweep could not remove.
//
// It is reported rather than counted because of what it is: on a platform that
// cannot expire an account, a sweep that quietly fails leaves a live privileged
// administrator on a firewall and nobody finds out. That is the failure mode
// D13 names, and a log line the operator has to go looking for is not an answer
// to it.
type SweepFailure struct {
	Target   string
	Platform string
	Account  string
	Reason   string
	At       time.Time
}

// DeviceEventSink is where the device path's two must-not-be-lost events go.
//
// It is an interface here and implemented in internal/logging for the same
// reason filter.Sink is: the credential plane should not have to know what a
// telemetry pipeline looks like, and a test needs somewhere to put the events
// that is not a network.
type DeviceEventSink interface {
	// Deliverable reports whether an event emitted now has somewhere to go —
	// the network, or failing that the local disk buffer. It is what makes
	// ErrNoLoggingPath a decision rather than a hope.
	Deliverable() bool
	// AccountMapping records one account→identity mapping on the priority path.
	AccountMapping(AccountMapping)
	// SweepFailure records an orphan that could not be removed.
	SweepFailure(SweepFailure)
}

// DeviceAccountOptions configures the device provisioner.
type DeviceAccountOptions struct {
	// ProxyID scopes the account naming convention to this proxy. Required.
	ProxyID string
	// Drivers is the platform registry. Required; an unregistered platform is
	// an unsatisfiable rung, never the nearest driver.
	Drivers *device.Registry
	// SourceAddress is the address devices see this proxy connect from. It is
	// used to pin an account where the driver declares it can
	// (Capabilities.PinsSourceAddress); empty means no pin.
	SourceAddress string
	// AccessProfile is the platform authorization scope created administrators
	// are given. No driver in this build has a default — phase 0015 removed the
	// one that did, because no FortiOS built-in is a safe one — so a driver
	// given neither this nor a per-route profile refuses to create an account
	// rather than choosing a privileged scope on a customer's device. WHICH
	// profile a route gets is phase 0016's vocabulary and 0017's to apply; this
	// is the proxy-wide setting until then.
	AccessProfile string
	// Events receives the mapping event and sweep failures. Nil means the
	// proxy has no logging path, which refuses any route whose driver declares
	// a constrained name limit (ErrNoLoggingPath).
	Events DeviceEventSink
	// ReaperInterval and ReaperGrace pace the sweep. Zero means the defaults;
	// a negative interval disables background sweeping.
	ReaperInterval time.Duration
	ReaperGrace    time.Duration
	// Logger receives provisioning, teardown, and sweep events; nil discards
	// them. It is never given a password or a private key.
	Logger *log.Logger
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// DeviceAccountAuthenticator creates a short-lived administrator on a device
// for one session and removes it afterwards (D13, PLAN §5.3).
//
// It is the ephemeral model reaching gear that has no useradd, no
// authorized_keys and no home directory. The lifecycle is PLAN §5.1's, step for
// step — log in privileged, create the account, install the credential,
// connect, remove it on teardown — with every step executed by a driver for the
// platform the route NAMED. Nothing is inferred from a banner: guessing wrong
// means running configuration commands against the wrong parser, on a device
// whose configuration is the customer's production network.
//
// Three things differ from the POSIX path, and each is a consequence of what a
// device is rather than a preference:
//
//   - A collision is NEVER adopted. With a short uniqueness token an existing
//     name is plausibly another live session's (PLAN §5.3).
//   - Attribution may live only in the mapping event, so a route that depends
//     on it is refused when this proxy cannot emit one.
//   - The reaper is the PRIMARY removal path wherever the driver cannot expire
//     an account, which is every platform this repository ships a driver for.
type DeviceAccountAuthenticator struct {
	proxyID string
	drivers *device.Registry
	source  string
	profile string
	events  DeviceEventSink
	logger  *log.Logger
	now     func() time.Time
	reaper  *deviceReaper
}

var (
	_ TargetAuthenticator = (*DeviceAccountAuthenticator)(nil)
	_ Lifecycle           = (*DeviceAccountAuthenticator)(nil)
	_ RungChecker         = (*DeviceAccountAuthenticator)(nil)
)

// NewDeviceAccountAuthenticator validates opts and returns the provisioner.
func NewDeviceAccountAuthenticator(opts DeviceAccountOptions) (*DeviceAccountAuthenticator, error) {
	switch {
	case opts.ProxyID == "":
		return nil, errors.New("auth/target: ephemeral-account requires the proxy id")
	case opts.Drivers == nil || len(opts.Drivers.Platforms()) == 0:
		return nil, errors.New("auth/target: ephemeral-account requires at least one device driver")
	}
	a := &DeviceAccountAuthenticator{
		proxyID: opts.ProxyID,
		drivers: opts.Drivers,
		source:  opts.SourceAddress,
		profile: opts.AccessProfile,
		events:  opts.Events,
		logger:  opts.Logger,
		now:     opts.Now,
	}
	if a.now == nil {
		a.now = time.Now
	}
	a.reaper = newDeviceReaper(a, opts.ReaperInterval, opts.ReaperGrace)
	return a, nil
}

// Name implements TargetAuthenticator.
func (a *DeviceAccountAuthenticator) Name() string { return MethodEphemeralAccount }

// Start begins the periodic device sweep. It implements Lifecycle.
func (a *DeviceAccountAuthenticator) Start(ctx context.Context) { a.reaper.Start(ctx) }

// Close stops it.
func (a *DeviceAccountAuthenticator) Close() error { return a.reaper.Close() }

// route is one parsed ephemeral-account route, resolved against a driver's
// declarations.
type deviceRoute struct {
	username string
	platform string
	kind     control.CredentialKind
	posture  control.ExpiryPosture
	lifetime time.Duration
	driver   device.Driver
	caps     device.Capabilities
	naming   naming
}

// CanSatisfy reports whether this proxy can serve a rung, WITHOUT connecting to
// anything (D14, RungChecker).
//
// Everything it consults is a declaration: the registry knows which platforms
// this build carries, and a driver's Capabilities are answerable without a
// device. That is the whole reason phase 0013 insisted they be data — a rung
// the ladder is about to skip has nothing to connect to, and a check that
// needed a connection would turn "skip this entry" into "dial a firewall to
// find out whether to skip this entry".
func (a *DeviceAccountAuthenticator) CanSatisfy(auth *control.TargetAuth, _ Target) error {
	_, err := a.resolve(auth)
	return err
}

// resolve parses a route and answers it against the named driver's
// declarations.
func (a *DeviceAccountAuthenticator) resolve(auth *control.TargetAuth) (*deviceRoute, error) {
	p := newParams(auth)
	r := &deviceRoute{
		username: p.str(ParamUsername, ""),
		platform: p.str(ParamPlatform, ""),
		kind:     control.CredentialKind(p.str(ParamCredentialKind, "")),
		posture:  control.ExpiryPosture(p.str(ParamExpiryPosture, "")),
	}
	lifetime, hasLifetime, err := p.duration(ParamLifetimeSeconds)
	if err != nil {
		return nil, err
	}
	r.lifetime = lifetime
	if err := p.rest(); err != nil {
		return nil, err
	}

	// Contract v3 makes all four required and phase 0013's Validate refuses a
	// response missing one, so reaching here without them means a locally
	// configured route rather than a served one. It is still refused: the
	// alternative is a default, and there is no safe default for "which
	// platform is this firewall".
	switch {
	case r.username == "":
		// There is deliberately NO fallback to identity.Login here. Login is
		// what the user typed at their SSH client, and internal/identity says
		// it must never be the basis of an authorization decision — choosing
		// an account name is one. Prompt 0024 closes that fallback everywhere
		// it still exists; this method never opened one.
		return nil, fmt.Errorf("%w: %s is required", ErrInvalidParam, ParamUsername)
	case r.platform == "":
		return nil, fmt.Errorf("%w: %s is required and is never inferred", ErrInvalidParam, ParamPlatform)
	case r.kind == "":
		return nil, fmt.Errorf("%w: %s is required", ErrInvalidParam, ParamCredentialKind)
	case r.posture == "":
		return nil, fmt.Errorf("%w: %s is required", ErrInvalidParam, ParamExpiryPosture)
	case r.posture != control.ExpiryPostureAcceptedRisk && !hasLifetime:
		return nil, fmt.Errorf("%w: %s is required unless the posture is %q",
			ErrInvalidParam, ParamLifetimeSeconds, control.ExpiryPostureAcceptedRisk)
	}

	driver, err := a.drivers.Lookup(r.platform)
	if err != nil {
		// An unknown platform is an unsatisfiable rung rather than a hard
		// failure: the ladder exists so that a PDP can rank a device method
		// above a standing credential and still get a session on a proxy that
		// has no driver for that platform (D14).
		return nil, fmt.Errorf("%w: %v", ErrRungUnsatisfiable, err)
	}
	r.driver = driver
	r.caps = driver.Capabilities()

	if !r.caps.Accepts(r.kind) {
		return nil, fmt.Errorf("%w: %s cannot install a %q credential (it accepts %v)",
			ErrRungUnsatisfiable, r.platform, r.kind, r.caps.CredentialKinds)
	}
	if r.posture == control.ExpiryPostureTargetEnforced && !r.caps.EnforcesExpiry {
		// A posture the driver cannot satisfy is a SKIPPED RUNG, not a
		// downgrade: serving it proxy-enforced instead would mean the audit
		// record says the device holds the deadline when nothing does.
		return nil, fmt.Errorf("%w: %s cannot expire an account on the device, and the route requires the %q posture",
			ErrRungUnsatisfiable, r.platform, r.posture)
	}

	r.naming, err = newNaming(a.proxyID, r.caps.MaxAccountNameLen)
	if err != nil {
		// A limit too short to carry a reaper prefix and a token is an
		// OUTAGE-class refusal, not a skipped rung: the platform is right, the
		// route is right, and this proxy simply must not create an account it
		// cannot later find or keep unique.
		return nil, err
	}

	if !r.naming.readable && !a.loggingAvailable() {
		return nil, fmt.Errorf("%w: %s caps administrator names at %d characters, so the account name carries no login",
			ErrNoLoggingPath, r.platform, r.caps.MaxAccountNameLen)
	}
	return r, nil
}

// loggingAvailable reports whether the mapping event has anywhere to go.
func (a *DeviceAccountAuthenticator) loggingAvailable() bool {
	return a.events != nil && a.events.Deliverable()
}

// Provision creates this session's administrator on the device.
func (a *DeviceAccountAuthenticator) Provision(ctx context.Context, id *identity.Identity, tgt Target) (*ProvisionedAccess, error) {
	if id == nil {
		return nil, errors.New("auth/target: ephemeral-account requires an authenticated identity")
	}
	r, err := a.resolve(tgt.Auth)
	if err != nil {
		return nil, err
	}

	// The session's host-key policy is handed down and WATCHED on the way past
	// (D7). The proxy owns host trust in both directions, so the driver borrows
	// the callback rather than deciding for itself — and the key it approved is
	// remembered, because teardown and every sweep must be able to reach the
	// device without the policy service. That callback calls Hoplock Control
	// and fails closed, and at teardown time the session's context is already
	// cancelled: an account left behind because a DIFFERENT component was down
	// is the failure this watching prevents.
	watcher := &hostKeyWatcher{inner: tgt.HostKeyCallback}
	ep := device.Endpoint{
		Host:            tgt.Host,
		Port:            tgt.Port,
		SessionID:       tgt.SessionID,
		HostKeyCallback: watcher.callback(),
	}
	profile := a.profile

	account, name, err := a.create(ctx, r, ep, profile)
	if err != nil {
		return nil, err
	}
	a.reaper.observe(ep, r)
	a.reaper.pinHostKey(ep, watcher.key())

	auth, cleanup, err := a.installCredential(ctx, r, ep, name)
	if err != nil {
		// Whatever was created is removed now, on the driver that created it,
		// so a denied session leaves the device exactly as it found it.
		a.removeQuietly(ctx, r, ep, name)
		return nil, err
	}

	a.reaper.track(ep, name)
	// The same reason PLAN §5.1 sweeps here: after a restart the proxy has no
	// idea which devices it owes cleanup on until it touches one again, and
	// this is that moment.
	a.reaper.sweepInBackground(ep, r)

	mapping := AccountMapping{
		Account:              name,
		SessionID:            tgt.SessionID,
		Subject:              id.Subject,
		Login:                id.Login,
		Target:               tgt.String(),
		Platform:             r.platform,
		Method:               MethodEphemeralAccount,
		Rung:                 tgt.Rung,
		ExpiryPosture:        string(r.posture),
		Lifetime:             r.lifetime,
		Profile:              account.Profile,
		Constrained:          !r.naming.readable,
		PersistsAcrossReload: r.caps.PersistsAcrossReload,
		PersistenceReason:    r.caps.PersistenceReason,
		At:                   a.now(),
	}
	if a.events != nil {
		a.events.AccountMapping(mapping)
	}
	a.logf("auth/target: ephemeral-account provisioned subject=%s target=%s platform=%s account=%s posture=%s",
		id.Subject, tgt, r.platform, name, r.posture)

	access := &ProvisionedAccess{
		ClientConfig: &ssh.ClientConfig{
			User: name,
			Auth: []ssh.AuthMethod{auth},
			// HostKeyCallback is the proxy's to set (D7).
		},
		Method: MethodEphemeralAccount,
		Rung:   tgt.Rung,
		Teardown: func(ctx context.Context) error {
			cleanup()
			return a.teardown(ctx, r, ep, name)
		},
	}

	if r.posture == control.ExpiryPostureProxyEnforced && r.lifetime > 0 {
		a.enforceExpiry(r, ep, name, r.lifetime)
	}
	return access, nil
}

// create draws a name and creates the account, retrying on collision.
//
// It NEVER adopts (D13, PLAN §5.3). The POSIX path's idempotent treatment of an
// existing account is safe because the name encodes the session; here the token
// can be four base36 characters, so an existing name is more plausibly another
// live session's — and adopting one means two sessions sharing an account whose
// first teardown removes the other's access.
func (a *DeviceAccountAuthenticator) create(ctx context.Context, r *deviceRoute, ep device.Endpoint, profile string) (*device.Account, string, error) {
	var lastErr error
	for attempt := 0; attempt < collisionBudget; attempt++ {
		name, err := r.naming.name(r.username)
		if err != nil {
			return nil, "", err
		}
		source := ""
		if r.caps.PinsSourceAddress {
			source = a.source
		}
		account, err := r.driver.CreateAccount(ctx, device.CreateRequest{
			Endpoint:      ep,
			Name:          name,
			Profile:       profile,
			SourceAddress: source,
			Lifetime:      r.lifetime,
		})
		switch {
		case err == nil:
			return account, name, nil
		case errors.Is(err, device.ErrAccountExists):
			lastErr = err
			a.logf("auth/target: ephemeral-account name %s is taken on %s:%d, drawing another", name, ep.Host, ep.Port)
			continue
		default:
			return nil, "", err
		}
	}
	return nil, "", fmt.Errorf("auth/target: ephemeral-account could not find a free administrator name on %s:%d after %d attempts: %w",
		ep.Host, ep.Port, collisionBudget, lastErr)
}

// installCredential generates this session's credential and puts it on the
// account, returning the SSH auth method and the function that zeroes it.
//
// PLAN §5.2's rule, generalised: a generated password never touches disk, never
// appears in a log, an error, or a configuration file this proxy writes, and is
// zeroed on teardown. It WILL appear in the device's own configuration and in
// the device's AAA logs — that is the device's record, it is outside this
// system's control, and pretending otherwise would be the dishonest half of an
// otherwise true claim.
func (a *DeviceAccountAuthenticator) installCredential(ctx context.Context, r *deviceRoute, ep device.Endpoint, name string) (ssh.AuthMethod, func(), error) {
	switch r.kind {
	case control.CredentialKindPassword:
		secret, err := generatePassword(generatedPasswordLen)
		if err != nil {
			return nil, nil, err
		}
		if err := r.driver.InstallCredential(ctx, device.CredentialRequest{
			Endpoint: ep, Name: name, Kind: r.kind, Password: string(secret),
		}); err != nil {
			zero(secret)
			return nil, nil, err
		}
		// A callback rather than ssh.Password: the material this process HOLDS
		// between provisioning and teardown is then the byte slice, which
		// zeroing actually reaches. x/crypto wants a string at dial time and
		// that copy is unavoidable — what is avoidable is a second copy living
		// in an ssh.ClientConfig for the whole session, which is what
		// ssh.Password would be.
		spent := false
		auth := ssh.PasswordCallback(func() (string, error) {
			if spent {
				return "", errors.New("auth/target: the device credential has been torn down")
			}
			return string(secret), nil
		})
		return auth, func() { spent = true; zero(secret) }, nil

	case control.CredentialKindPublicKey:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("auth/target: generate a session key: %w", err)
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			return nil, nil, fmt.Errorf("auth/target: generate a session key: %w", err)
		}
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			return nil, nil, fmt.Errorf("auth/target: generate a session key: %w", err)
		}
		line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
		if err := r.driver.InstallCredential(ctx, device.CredentialRequest{
			Endpoint: ep, Name: name, Kind: r.kind, PublicKey: line,
		}); err != nil {
			return nil, nil, err
		}
		return ssh.PublicKeys(signer), func() {}, nil

	default:
		// Unreachable while resolve holds its invariant; kept because the
		// alternative to an explicit refusal is a substitution, and the server
		// chose the kind.
		return nil, nil, fmt.Errorf("%w: %s=%q", ErrInvalidParam, ParamCredentialKind, r.kind)
	}
}

// teardown removes one session's administrator.
func (a *DeviceAccountAuthenticator) teardown(ctx context.Context, r *deviceRoute, ep device.Endpoint, name string) error {
	defer a.reaper.release(ep, name)

	// Removing an account must not depend on Hoplock Control being reachable,
	// so teardown pins to the key the provisioning connection already saw
	// rather than re-running the session's callback, which calls Control and
	// fails closed (PLAN §5.1, and target.pin for the POSIX half).
	ep = a.reaper.pin(ep)
	if err := r.driver.RemoveAccount(ctx, device.RemoveRequest{Endpoint: ep, Name: name}); err != nil {
		return fmt.Errorf("auth/target: ephemeral-account teardown of %s on %s:%d: %w", name, ep.Host, ep.Port, err)
	}
	a.logf("auth/target: ephemeral-account removed target=%s:%d platform=%s account=%s", ep.Host, ep.Port, r.platform, name)
	return nil
}

// removeQuietly undoes a partial provisioning. Its own failure is logged and
// swallowed: the session is being denied either way, and what it could not
// remove is what the reaper is for.
func (a *DeviceAccountAuthenticator) removeQuietly(ctx context.Context, r *deviceRoute, ep device.Endpoint, name string) {
	if err := r.driver.RemoveAccount(ctx, device.RemoveRequest{Endpoint: ep, Name: name}); err != nil {
		a.logf("auth/target: ephemeral-account cleanup after a failed provisioning of %s: %v", name, err)
	}
}

// enforceExpiry removes the account when its lifetime runs out, for the posture
// that says this proxy holds the deadline (D13).
//
// It removes the ACCOUNT, which is this phase's whole subject. Ending the
// SESSION at the same moment is prompt 0023's, and the two are deliberately not
// conflated here: the credential is what this method provisioned and the
// credential is what it takes back.
func (a *DeviceAccountAuthenticator) enforceExpiry(r *deviceRoute, ep device.Endpoint, name string, lifetime time.Duration) {
	a.reaper.afterFunc(lifetime, func() {
		// Detached from the session's context on purpose: the deadline is the
		// point, and a cancelled session context would make the removal it
		// exists for the first thing to be skipped.
		ctx, cancel := context.WithTimeout(context.Background(), sweepTimeout)
		defer cancel()
		if err := a.teardown(ctx, r, ep, name); err != nil {
			a.logf("auth/target: ephemeral-account could not remove %s at its deadline: %v", name, err)
			a.reportSweepFailure(SweepFailure{
				Target: fmt.Sprintf("%s:%d", ep.Host, ep.Port), Platform: r.platform,
				Account: name, Reason: err.Error(), At: a.now(),
			})
		}
	})
}

func (a *DeviceAccountAuthenticator) reportSweepFailure(f SweepFailure) {
	if a.events != nil {
		a.events.SweepFailure(f)
	}
}

func (a *DeviceAccountAuthenticator) logf(format string, args ...any) {
	if a.logger == nil {
		return
	}
	a.logger.Printf(format, args...)
}

// passwordAlphabet is what a generated device password is drawn from.
//
// It excludes the characters a configuration parser treats specially, so that a
// generated password can never be the thing that ends a command early on a
// device this proxy is configuring. The length carries the entropy.
const passwordAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.@%+=:,"

// generatePassword returns n characters of cryptographic randomness as bytes,
// so the caller can zero them.
func generatePassword(n int) ([]byte, error) {
	out := make([]byte, n)
	max := big.NewInt(int64(len(passwordAlphabet)))
	for i := range out {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, fmt.Errorf("auth/target: generate a device password: %w", err)
		}
		out[i] = passwordAlphabet[v.Int64()]
	}
	return out, nil
}

// hostKeyWatcher runs the session's host-key policy and remembers what it
// approved.
//
// It is the device path's equivalent of the POSIX provisioner's `seen` capture
// in sshAdminDialer.Dial, and it exists for the same one reason: removing an
// account must not depend on a different component being reachable.
type hostKeyWatcher struct {
	inner ssh.HostKeyCallback

	mu   sync.Mutex
	seen ssh.PublicKey
}

func (w *hostKeyWatcher) callback() ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if w.inner == nil {
			return errors.New("auth/target: the device management connection has no host key policy")
		}
		if err := w.inner(hostname, remote, key); err != nil {
			return err
		}
		w.mu.Lock()
		w.seen = key
		w.mu.Unlock()
		return nil
	}
}

func (w *hostKeyWatcher) key() ssh.PublicKey {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.seen
}
