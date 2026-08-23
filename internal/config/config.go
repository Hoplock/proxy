// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

// Package config loads and validates the proxy's YAML bootstrap
// configuration (PLAN §8, D9).
package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/hoplock/proxy/internal/identity"
)

// DefaultTargetDelimiter separates the login from the target hostname in the
// SSH username, e.g. "alice#host.company.com" (D1).
const DefaultTargetDelimiter = "#"

// The proxy→target authentication methods (PLAN §4.2, D6/D6a). They live here,
// rather than in internal/auth/target, for the same reason the user-plane
// method names live in internal/identity: config has to validate the name, and
// a name spelled in two places eventually gets spelled two ways.
const (
	// TargetAuthMethodStaticKey is the phase-0005 placeholder: one preloaded
	// key for every session on every target.
	TargetAuthMethodStaticKey = "static-key"
	// TargetAuthMethodEphemeralUser creates a short-lived OS account and key on
	// the target and removes both afterwards (D6).
	TargetAuthMethodEphemeralUser = "ephemeral-user"
	// TargetAuthMethodBrokeredKey uses a per-target credential held for the
	// session and never written to disk (D6a).
	TargetAuthMethodBrokeredKey = "brokered-key"
)

// Brokered credential sources (D6a). The source is where the proxy's LOCAL
// material lives; a future Hoplock Control that mints per-session credentials
// is another target_auth method, not another entry here.
const (
	// BrokeredSourceDir reads one file per credential reference.
	BrokeredSourceDir = "dir"
	// BrokeredSourceEnv reads the process environment.
	BrokeredSourceEnv = "env"
)

// Defaults for the credential methods that phase 0007 added.
const (
	// DefaultBrokeredFileSuffix is appended to a credential reference to name
	// its file.
	DefaultBrokeredFileSuffix = ".key"
	// DefaultBrokeredEnvPrefix prefixes the environment variable holding a
	// credential.
	DefaultBrokeredEnvPrefix = "HOPLOCK_BROKERED_"
)

// Config is the proxy's bootstrap configuration. It holds only what the
// proxy needs to start and reach Hoplock Control; every policy decision
// is made remotely (D2), so nothing policy-related belongs here.
type Config struct {
	Proxy   Proxy   `yaml:"proxy"`
	Control Control `yaml:"control"`
	Routing Routing `yaml:"routing"`
	Chain   Chain   `yaml:"chain"`
	Auth    Auth    `yaml:"auth"`
	Dial    Dial    `yaml:"dial"`
}

// Proxy describes the local SSH listener and this proxy's own identity.
type Proxy struct {
	// ID identifies this proxy to Hoplock Control. It is on every
	// management call and is the address of this proxy's revocation stream
	// (PLAN §6.4), so it is deployment-assigned and required: a proxy that
	// cannot be named cannot be told to kill a session.
	ID string `yaml:"id"`
	// ListenAddr is the "host:port" the SSH listener binds to.
	ListenAddr string `yaml:"listen_addr"`
	// HostKeyPath is the path to the proxy's SSH host private key.
	HostKeyPath string `yaml:"host_key_path"`
}

// Control describes how to reach Hoplock Control (PDP).
type Control struct {
	// BaseURL is the root URL of the Control API, e.g.
	// "https://control.example.com".
	BaseURL string `yaml:"base_url"`
	// Token authenticates this proxy to Hoplock Control as a bearer
	// token. Empty is allowed so a development topology can run without one;
	// a real deployment sets it (or supplies mTLS at the transport instead).
	Token string `yaml:"token"`
	// Cache tunes reuse of authorize decisions the server permitted (PLAN §6.4).
	Cache Cache `yaml:"cache"`
}

// Cache tunes the proxy's side of server-authorised policy caching. Nothing
// here can widen a decision: the server owns the lifetime, and these settings
// only ever make the proxy ask more often than it was allowed to.
type Cache struct {
	// MaxTTL clamps the server's cache lifetime downwards. Zero — the default —
	// honours the server exactly. Every decision a clamp actually shortens is
	// counted and logged, because a proxy quietly diverging from what the
	// server asked for is indistinguishable from a fault (PLAN §6.4).
	MaxTTL time.Duration `yaml:"max_ttl"`
	// StaleAfter is how long the revocation stream may be unheard before the
	// cache stops serving and storing decisions. Zero means the package
	// default.
	StaleAfter time.Duration `yaml:"stale_after"`
}

// Dial tunes the outbound leg to the target. None of it decides anything; it
// bounds how long a user waits for a failure they cannot see.
type Dial struct {
	// DialTimeout bounds dialling and handshaking the target leg. Zero means
	// the package default.
	DialTimeout time.Duration `yaml:"dial_timeout"`
	// DefaultTargetPort is used when Hoplock Control's route names no
	// port. Zero means the package default (22).
	DefaultTargetPort int `yaml:"default_target_port"`
}

// Routing holds the rules for deriving the target from the SSH username (D1).
type Routing struct {
	// TargetDelimiter is the single character separating login from target in
	// the SSH username. Defaults to DefaultTargetDelimiter.
	TargetDelimiter string `yaml:"target_delimiter"`
}

// Chain configures multi-hop routing: how this proxy presents itself to another
// proxy, how far a chain may go, and — for the relay direction — which upstream
// it registers with and whether it accepts registrations of its own (D11,
// PLAN §6.1).
//
// None of it decides which sessions chain, or in which direction. That is the
// route's hop metadata, decided by Hoplock Control per connection (D2); a
// proxy configured for both directions still obeys the one it is told.
type Chain struct {
	// IdentityKeyPath is the private key this proxy presents to another proxy
	// — to the next hop when it extends a chain, and to the upstream when it
	// registers a relay. It is this proxy's identity, never the user's:
	// the far side authenticates THIS PROXY and asks Hoplock Control to
	// re-establish the user, so nothing takes an upstream's word for who is
	// connecting. Empty means this proxy cannot chain, and a next-hop route
	// is refused as an outage.
	IdentityKeyPath string `yaml:"identity_key_path"`
	// IdentityCertPath is an optional OpenSSH certificate for that key, for a
	// fleet whose proxies are certified by a CA rather than listed by hand.
	// The certificate must name this proxy's id among its principals.
	IdentityCertPath string `yaml:"identity_cert_path"`
	// MaxHops caps how many proxies one session may traverse. Zero means
	// routing.DefaultMaxHops. It can only ever shorten a chain the server
	// allowed, never lengthen one.
	MaxHops int `yaml:"max_hops"`
	// Upstream registers an outbound relay connection with another proxy, so
	// that proxy can send sessions here without dialling in. This is the half
	// that removes the inbound firewall rule for a protected zone.
	Upstream ChainUpstream `yaml:"upstream"`
	// Accept listens for relay registrations from downstream proxies.
	Accept ChainAccept `yaml:"accept"`
}

// ChainUpstream is the downstream half of the relay: this proxy registering
// with the one above it.
type ChainUpstream struct {
	// Address is the "host:port" of the upstream proxy's registration
	// listener. Empty disables registration entirely.
	Address string `yaml:"address"`
	// HostKeyPath is the upstream's expected SSH host public key. REQUIRED
	// when Address is set: this registration is an inbound path for sessions,
	// so an unverified upstream is one that can be impersonated into
	// receiving them. There is no trust-on-first-use here — the fleet's own
	// keys are known at deployment time, unlike a target's (D7).
	HostKeyPath string `yaml:"host_key_path"`
	// DialTimeout bounds one registration attempt. Zero means the package
	// default.
	DialTimeout time.Duration `yaml:"dial_timeout"`
	// KeepaliveInterval is how often this proxy pings the upstream. Zero means
	// the package default; negative disables the ping.
	KeepaliveInterval time.Duration `yaml:"keepalive_interval"`
	// MinBackoff and MaxBackoff bound the reconnect delay. Zero means the
	// package defaults.
	MinBackoff time.Duration `yaml:"min_backoff"`
	MaxBackoff time.Duration `yaml:"max_backoff"`
}

// ChainAccept is the upstream half of the relay: this proxy holding
// registrations open for the proxies below it.
type ChainAccept struct {
	// ListenAddr is the "host:port" the registration listener binds to. Empty
	// accepts no registrations, which is the default: a proxy is a relay hub
	// only where the topology says so.
	ListenAddr string `yaml:"listen_addr"`
	// HostKeyPath is the key the registration listener presents. Empty reuses
	// proxy.host_key_path, which is the same identity from a registering
	// proxy's point of view.
	HostKeyPath string `yaml:"host_key_path"`
	// AuthorizedKeysPath lists the proxies that may register, in OpenSSH
	// authorized_keys format. THE COMMENT ON EACH LINE IS THE PROXY ID that
	// key may register as: a key that named no id could register as any of
	// them and start receiving their sessions.
	AuthorizedKeysPath string `yaml:"authorized_keys_path"`
	// TrustedCAPath lists the CA public keys whose user certificates may
	// register. A certificate must name the claimed proxy id as a principal.
	TrustedCAPath string `yaml:"trusted_ca_path"`
	// KeepaliveInterval is how often the hub pings a registration. Zero means
	// the package default; negative disables the ping.
	KeepaliveInterval time.Duration `yaml:"keepalive_interval"`
}

// Registers reports whether this proxy registers a relay with an upstream.
func (c Chain) Registers() bool { return c.Upstream.Address != "" }

// AcceptsRegistrations reports whether this proxy hosts relay registrations.
func (c Chain) AcceptsRegistrations() bool { return c.Accept.ListenAddr != "" }

// Auth holds the proxy's authentication planes. Each plane is a pluggable
// interface with swappable implementations (D4); config chooses which ones run,
// never what they decide.
type Auth struct {
	// User configures the user→proxy plane (PLAN §4.1).
	User UserAuth `yaml:"user"`
	// Target configures the proxy→target plane (PLAN §4.2).
	Target TargetAuth `yaml:"target"`
}

// TargetAuth configures how the proxy logs into targets.
//
// Since contract v2 (phase 0006) the *selection* belongs to Hoplock Control:
// the authorize response's `target_auth` names the method per route, because one
// proxy routinely fronts a Linux estate and an appliance estate at once (D6a).
// What lives here is the LOCAL MATERIAL each method needs — which key, which
// provisioning account — plus the fallback used when a v1 server sends no
// `target_auth` at all.
type TargetAuth struct {
	// Method is the fallback used when the authorize response carries no
	// target_auth. Defaults to TargetAuthMethodStaticKey, the phase-0005
	// placeholder.
	Method string `yaml:"method"`
	// StaticKey configures the placeholder implementation.
	StaticKey StaticKeyAuth `yaml:"static_key"`
	// EphemeralUser configures just-in-time provisioning (D6).
	EphemeralUser EphemeralUserAuth `yaml:"ephemeral_user"`
	// BrokeredKey configures session-scoped credentials (D6a).
	BrokeredKey BrokeredKeyAuth `yaml:"brokered_key"`
}

// EphemeralUserAuth is the local material the just-in-time provisioner needs
// (D6, PLAN §5.1): the management certificate preloaded on targets, the account
// it logs in as, and the shape of what it creates there.
//
// Every field here describes THIS PROXY or the fleet it fronts. None of it
// decides which sessions use the method — that is the route's target_auth, and
// a proxy that could choose for itself would be originating policy (D2).
type EphemeralUserAuth struct {
	// ManagementKeyPath is the management certificate's private key, preloaded
	// on targets as an authorized key for ProvisioningUser. Required for this
	// method.
	ManagementKeyPath string `yaml:"management_key_path"`
	// ManagementCertPath is an optional OpenSSH certificate for that key, for
	// fleets that trust a CA rather than a key.
	ManagementCertPath string `yaml:"management_cert_path"`
	// ProvisioningUser is the privileged account on the target. Required for
	// this method.
	ProvisioningUser string `yaml:"provisioning_user"`
	// Shell is the remote command the provisioning scripts are handed to. A
	// provisioning account that is not root sets it to "sudo -n sh -c", so the
	// whole script runs inside one privileged shell. Empty means "sh -c".
	Shell string `yaml:"shell"`
	// HomeBase is the parent directory of ephemeral home directories. Empty
	// means "/home".
	HomeBase string `yaml:"home_base"`
	// TargetShell is the login shell given to ephemeral accounts. Empty means
	// "/bin/sh".
	TargetShell string `yaml:"target_shell"`
	// KeyExpiry writes OpenSSH's expiry-time restriction into the ephemeral
	// authorized_keys entry when a route asks for a lifetime. Defaults to true.
	// Set it to false only for a fleet whose sshd predates 8.2 — a route that
	// then asks for a lifetime is REFUSED rather than served with a key that
	// never expires.
	KeyExpiry *bool `yaml:"key_expiry"`
	// Timeout bounds one management login and the script it runs. Zero means
	// the package default.
	Timeout time.Duration `yaml:"timeout"`
	// Reaper tunes the orphan sweep.
	Reaper ReaperAuth `yaml:"reaper"`
}

// ReaperAuth tunes the orphan reaper (PLAN §5.1). Neither field is policy: they
// bound how quickly an account left behind by a dead session is found.
type ReaperAuth struct {
	// Interval is how often the periodic sweep runs. Zero means the package
	// default; negative disables background sweeping entirely, which leaves
	// accounts from a crashed proxy to be found by hand.
	Interval time.Duration `yaml:"interval"`
	// Grace is how old an untracked ephemeral account must be before a sweep
	// removes it. Zero means the package default. It must stay comfortably
	// longer than a provisioning takes: it is what protects a session this
	// process does not know about yet.
	Grace time.Duration `yaml:"grace"`
}

// BrokeredKeyAuth is the local material for session-scoped credentials (D6a,
// PLAN §5.2).
//
// The credential itself is never in this file and never on the proxy's disk in
// a form this config names: Dir points at a store an operator manages, EnvPrefix
// at variables a scheduler injects. Which one a session uses is the route's
// credential_ref, an opaque handle that carries no material of its own.
type BrokeredKeyAuth struct {
	// Source is BrokeredSourceDir or BrokeredSourceEnv. Empty means
	// BrokeredSourceDir.
	Source string `yaml:"source"`
	// Username logs into every brokered target as this account when the route
	// names none. Empty uses the authenticated login.
	Username string `yaml:"username"`
	// Dir holds one file per credential reference. Required for the dir source.
	Dir string `yaml:"dir"`
	// FileSuffix is appended to a reference to name its file. Empty means
	// DefaultBrokeredFileSuffix.
	FileSuffix string `yaml:"file_suffix"`
	// EnvPrefix prefixes the environment variable holding a credential. Empty
	// means DefaultBrokeredEnvPrefix.
	EnvPrefix string `yaml:"env_prefix"`
}

// StaticKeyAuth configures the placeholder target authenticator: one preloaded
// key for every session on every target. It provisions nothing and expires
// nothing, so it belongs in development topologies only (PLAN §4.2).
type StaticKeyAuth struct {
	// KeyPath is the private key the proxy logs into targets with.
	KeyPath string `yaml:"key_path"`
	// Username logs into every target as this account instead of the
	// authenticated login. Empty — the default — uses the login.
	Username string `yaml:"username"`
}

// UserAuth enables and tunes the user→proxy authenticators.
type UserAuth struct {
	// Methods is the set of enabled authentication methods, by name
	// ("cert", "password-mfa"). Defaults to DefaultUserAuthMethods.
	//
	// It is a set, not an order: the proxy always tries certificates first and
	// falls back to password+MFA (PLAN §4.1). Listing them the other way round
	// would prompt every user for a password before looking at the key their
	// client already offered, so the order is not the operator's to change.
	// An explicitly empty list is rejected — a proxy with no enabled method
	// can authenticate nobody.
	Methods []string `yaml:"methods"`
	// MFA tunes the wait for an out-of-band second factor.
	MFA MFA `yaml:"mfa"`
}

// MFA tunes how the proxy waits on an out-of-band second factor. None of it
// decides anything: Hoplock Control states the pacing and the expiry, and
// these settings only bound how the proxy behaves while it obeys them.
type MFA struct {
	// MinPollInterval floors the server's poll_after_ms, so a challenge with a
	// tiny or absent interval cannot turn into a polling hot loop. Zero means
	// the package default.
	MinPollInterval time.Duration `yaml:"min_poll_interval"`
	// ProgressInterval is the minimum gap between "still waiting" messages
	// shown to the user while the approval is outstanding. Zero means the
	// package default.
	ProgressInterval time.Duration `yaml:"progress_interval"`
	// MaxWait caps the total wait for an approval. The server's expiry still
	// wins whenever it is sooner: the proxy may give up earlier than the
	// server, never later. Zero means the package default.
	MaxWait time.Duration `yaml:"max_wait"`
}

// DefaultUserAuthMethods is the enabled set when auth.user.methods is omitted:
// both methods, which is the flow PLAN §4.1 describes end to end.
func DefaultUserAuthMethods() []string {
	return []string{string(identity.MethodCert), string(identity.MethodPasswordMFA)}
}

// Sentinel causes, wrapped by FieldError so callers can classify a failure with
// errors.Is without string matching.
var (
	// ErrMissing indicates a required field was empty.
	ErrMissing = errors.New("required field is missing")
	// ErrInvalid indicates a field was set but its value is not usable.
	ErrInvalid = errors.New("field value is invalid")
	// ErrMalformed indicates the file could not be parsed as the expected YAML.
	ErrMalformed = errors.New("malformed configuration file")
)

// FieldError reports a single invalid configuration field. Field is the YAML
// path of the offending key (e.g. "proxy.listen_addr").
type FieldError struct {
	Field  string
	Detail string
	Cause  error
}

func (e *FieldError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("%s: %v", e.Field, e.Cause)
	}
	return fmt.Sprintf("%s: %v (%s)", e.Field, e.Cause, e.Detail)
}

// Unwrap exposes the sentinel cause to errors.Is.
func (e *FieldError) Unwrap() error { return e.Cause }

// ValidationError collects every field problem found in one pass so an operator
// can fix a config in a single edit instead of one restart per mistake.
type ValidationError struct {
	Fields []*FieldError
}

func (e *ValidationError) Error() string {
	parts := make([]string, 0, len(e.Fields))
	for _, f := range e.Fields {
		parts = append(parts, f.Error())
	}
	return "invalid configuration: " + strings.Join(parts, "; ")
}

// Unwrap lets errors.Is/errors.As reach the individual field errors.
func (e *ValidationError) Unwrap() []error {
	errs := make([]error, 0, len(e.Fields))
	for _, f := range e.Fields {
		errs = append(errs, f)
	}
	return errs
}

// Load reads, decodes, defaults, and validates the config file at path.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	cfg, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("config %q: %w", path, err)
	}
	return cfg, nil
}

// Parse decodes the config from r, applies defaults, and validates the result.
// Unknown keys are rejected: a typo in a security-relevant setting must fail
// loudly rather than silently fall back to a default.
func Parse(r io.Reader) (*Config, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: file is empty", ErrMalformed)
		}
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// applyDefaults fills in the values that have a safe, documented default.
func (c *Config) applyDefaults() {
	if c.Routing.TargetDelimiter == "" {
		c.Routing.TargetDelimiter = DefaultTargetDelimiter
	}
	// A nil slice means the key was absent; an empty one means the operator
	// wrote "methods: []" and meant it. Only the first gets a default, so
	// disabling every method fails validation instead of being silently undone.
	if c.Auth.User.Methods == nil {
		c.Auth.User.Methods = DefaultUserAuthMethods()
	}
	if c.Auth.Target.Method == "" {
		c.Auth.Target.Method = TargetAuthMethodStaticKey
	}
}

// Validate reports every problem with c as a *ValidationError.
func (c *Config) Validate() error {
	var v ValidationError

	if c.Proxy.ID == "" {
		v.add("proxy.id", ErrMissing, "")
	}

	if c.Proxy.ListenAddr == "" {
		v.add("proxy.listen_addr", ErrMissing, "")
	} else if _, _, err := net.SplitHostPort(c.Proxy.ListenAddr); err != nil {
		v.add("proxy.listen_addr", ErrInvalid, `expected "host:port"`)
	}

	if c.Proxy.HostKeyPath == "" {
		v.add("proxy.host_key_path", ErrMissing, "")
	}

	if c.Control.BaseURL == "" {
		v.add("control.base_url", ErrMissing, "")
	} else {
		u, err := url.Parse(c.Control.BaseURL)
		switch {
		case err != nil:
			v.add("control.base_url", ErrInvalid, "not a URL")
		case u.Scheme != "http" && u.Scheme != "https":
			v.add("control.base_url", ErrInvalid, "scheme must be http or https")
		case u.Host == "":
			v.add("control.base_url", ErrInvalid, "missing host")
		}
	}

	for _, d := range []struct {
		field string
		value time.Duration
	}{
		{"control.cache.max_ttl", c.Control.Cache.MaxTTL},
		{"control.cache.stale_after", c.Control.Cache.StaleAfter},
		{"dial.dial_timeout", c.Dial.DialTimeout},
	} {
		if d.value < 0 {
			v.add(d.field, ErrInvalid, "must not be negative")
		}
	}

	if p := c.Dial.DefaultTargetPort; p < 0 || p > 65535 {
		v.add("dial.default_target_port", ErrInvalid, "must be between 1 and 65535")
	}

	if err := validateDelimiter(c.Routing.TargetDelimiter); err != nil {
		v.add("routing.target_delimiter", ErrInvalid, err.Error())
	}

	c.validateChain(&v)

	c.validateAuth(&v)

	if len(v.Fields) > 0 {
		return &v
	}
	return nil
}

// validateChain checks multi-hop and relay settings (D11). Each half is
// checked only when the operator asked for it: most proxies neither register
// nor accept registrations, and the ones that do usually do exactly one.
func (c *Config) validateChain(v *ValidationError) {
	if c.Chain.MaxHops < 0 {
		v.add("chain.max_hops", ErrInvalid, "must not be negative")
	}
	if c.Chain.IdentityCertPath != "" && c.Chain.IdentityKeyPath == "" {
		v.add("chain.identity_key_path", ErrMissing,
			"a chain identity certificate needs the private key it certifies")
	}

	if u := c.Chain.Upstream; c.Chain.Registers() {
		if _, _, err := net.SplitHostPort(u.Address); err != nil {
			v.add("chain.upstream.address", ErrInvalid, `expected "host:port"`)
		}
		if u.HostKeyPath == "" {
			v.add("chain.upstream.host_key_path", ErrMissing,
				"the upstream's host key must be known: this registration is an inbound path for sessions")
		}
		if c.Chain.IdentityKeyPath == "" {
			v.add("chain.identity_key_path", ErrMissing,
				"registering with an upstream needs this proxy's identity key")
		}
		for _, d := range []struct {
			field string
			value time.Duration
		}{
			{"chain.upstream.dial_timeout", u.DialTimeout},
			{"chain.upstream.min_backoff", u.MinBackoff},
			{"chain.upstream.max_backoff", u.MaxBackoff},
		} {
			if d.value < 0 {
				v.add(d.field, ErrInvalid, "must not be negative")
			}
		}
	} else if upstreamConfigured(u) {
		v.add("chain.upstream.address", ErrMissing,
			"the upstream is configured but has no address to register with")
	}

	if a := c.Chain.Accept; c.Chain.AcceptsRegistrations() {
		if _, _, err := net.SplitHostPort(a.ListenAddr); err != nil {
			v.add("chain.accept.listen_addr", ErrInvalid, `expected "host:port"`)
		}
		if a.AuthorizedKeysPath == "" && a.TrustedCAPath == "" {
			v.add("chain.accept.authorized_keys_path", ErrMissing,
				"accepting registrations needs an authorized_keys file or a trusted CA; "+
					"an unauthenticated registration is a way to receive other proxies' sessions")
		}
	} else if acceptConfigured(a) {
		v.add("chain.accept.listen_addr", ErrMissing,
			"registrations are configured but there is no address to accept them on")
	}
}

// upstreamConfigured and acceptConfigured report whether the operator wrote
// anything SUBSTANTIVE about a half of the relay. Timing settings do not count:
// they are documented with their defaults in config.example.yaml, and a
// deployment that leaves those lines in place while disabling the relay has not
// asked for anything.
func upstreamConfigured(u ChainUpstream) bool { return u.HostKeyPath != "" }

func acceptConfigured(a ChainAccept) bool {
	return a.HostKeyPath != "" || a.AuthorizedKeysPath != "" || a.TrustedCAPath != ""
}

// validateAuth checks the authentication planes. Method names are validated
// against the identity model rather than against a list local to this package,
// so a name can only ever be spelled one way across config, logs, and the
// authenticated identity.
func (c *Config) validateAuth(v *ValidationError) {
	if len(c.Auth.User.Methods) == 0 {
		v.add("auth.user.methods", ErrMissing, "at least one method must be enabled")
	}

	seen := make(map[string]bool, len(c.Auth.User.Methods))
	for i, name := range c.Auth.User.Methods {
		field := fmt.Sprintf("auth.user.methods[%d]", i)
		switch {
		case !identity.Method(name).Valid():
			v.add(field, ErrInvalid, fmt.Sprintf("unknown method %q", name))
		case seen[name]:
			v.add(field, ErrInvalid, fmt.Sprintf("method %q is listed twice", name))
		default:
			seen[name] = true
		}
	}

	mfa := c.Auth.User.MFA
	for _, d := range []struct {
		field string
		value time.Duration
	}{
		{"auth.user.mfa.min_poll_interval", mfa.MinPollInterval},
		{"auth.user.mfa.progress_interval", mfa.ProgressInterval},
		{"auth.user.mfa.max_wait", mfa.MaxWait},
	} {
		if d.value < 0 {
			v.add(d.field, ErrInvalid, "must not be negative")
		}
	}

	c.validateTargetAuth(v)
}

// validateTargetAuth checks the proxy→target plane. Only the settings of the
// selected method are checked: phase 0006 adds a method that needs no static
// key, and a config that still carries one must not be forced to keep it valid.
func (c *Config) validateTargetAuth(v *ValidationError) {
	t := c.Auth.Target
	switch t.Method {
	case TargetAuthMethodStaticKey, TargetAuthMethodEphemeralUser, TargetAuthMethodBrokeredKey:
	default:
		v.add("auth.target.method", ErrInvalid,
			fmt.Sprintf("unknown method %q", t.Method))
	}

	// Each method's settings are checked when it is the fallback OR when
	// anything about it was written down. The second half matters since
	// contract v2: the method a route names is the SERVER's choice, so a proxy
	// is normally configured for methods it is not itself defaulting to, and a
	// typo in one of them must not wait for the first route that selects it.
	if t.Method == TargetAuthMethodStaticKey || t.StaticKey != (StaticKeyAuth{}) {
		if t.StaticKey.KeyPath == "" {
			v.add("auth.target.static_key.key_path", ErrMissing,
				"the static-key method logs into targets with this key")
		}
	}
	if t.Method == TargetAuthMethodEphemeralUser || ephemeralConfigured(t.EphemeralUser) {
		if t.EphemeralUser.ManagementKeyPath == "" {
			v.add("auth.target.ephemeral_user.management_key_path", ErrMissing,
				"the ephemeral-user method logs into targets with the management certificate")
		}
		if t.EphemeralUser.ProvisioningUser == "" {
			v.add("auth.target.ephemeral_user.provisioning_user", ErrMissing,
				"the privileged account the management certificate logs in as")
		}
		if t.EphemeralUser.Timeout < 0 {
			v.add("auth.target.ephemeral_user.timeout", ErrInvalid, "must not be negative")
		}
		if t.EphemeralUser.Reaper.Grace < 0 {
			v.add("auth.target.ephemeral_user.reaper.grace", ErrInvalid, "must not be negative")
		}
	}
	if t.Method == TargetAuthMethodBrokeredKey || brokeredConfigured(t.BrokeredKey) {
		switch t.BrokeredKey.Source {
		case "", BrokeredSourceDir:
			if t.BrokeredKey.Dir == "" {
				v.add("auth.target.brokered_key.dir", ErrMissing,
					"the dir source reads one credential file per reference from here")
			}
		case BrokeredSourceEnv:
		default:
			v.add("auth.target.brokered_key.source", ErrInvalid,
				fmt.Sprintf("unknown source %q", t.BrokeredKey.Source))
		}
	}
}

// ephemeralConfigured reports whether the operator wrote anything about the
// ephemeral method.
func ephemeralConfigured(e EphemeralUserAuth) bool {
	return e.ManagementKeyPath != "" || e.ManagementCertPath != "" || e.ProvisioningUser != "" ||
		e.Shell != "" || e.HomeBase != "" || e.TargetShell != "" || e.KeyExpiry != nil ||
		e.Timeout != 0 || e.Reaper != (ReaperAuth{})
}

// brokeredConfigured reports whether the operator wrote anything about the
// brokered method.
func brokeredConfigured(b BrokeredKeyAuth) bool { return b != (BrokeredKeyAuth{}) }

// EphemeralKeyExpiry resolves the key_expiry setting, which defaults to true:
// a fleet that can express a key lifetime should, and the operators who cannot
// are the ones who have to say so.
func (e EphemeralUserAuth) EphemeralKeyExpiry() bool {
	if e.KeyExpiry == nil {
		return true
	}
	return *e.KeyExpiry
}

func (v *ValidationError) add(field string, cause error, detail string) {
	v.Fields = append(v.Fields, &FieldError{Field: field, Detail: detail, Cause: cause})
}

// validateDelimiter enforces that the delimiter is a single character that
// cannot occur in a login name or a hostname, so splitting the SSH username is
// unambiguous (D1).
func validateDelimiter(d string) error {
	if utf8.RuneCountInString(d) != 1 {
		return errors.New("must be exactly one character")
	}
	r, _ := utf8.DecodeRuneInString(d)
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return errors.New("must not be alphanumeric")
	case r == '.', r == '-', r == '_':
		return errors.New("must not be a character valid in a hostname or login")
	}
	return nil
}
