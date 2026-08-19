// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/hoplock/proxy/internal/control"
)

// wildcard matches any login or target in a route rule.
const wildcard = "*"

// Revocation stream defaults. The heartbeat is well inside the proxy's
// default timeout (control.DefaultHeartbeatTimeout), so a healthy stream is never
// mistaken for a dead one.
const (
	defaultHeartbeatMS  = 5_000
	defaultReplayBuffer = 128
)

// fixtures is the mock server's entire world: who exists, what they may reach,
// and how host keys are treated. It is static and declarative so a test (or the
// e2e topology) gets the same answers on every run.
//
// The file format is documented in api/README.md; fixtures.example.yaml is the
// worked example and is exercised by the tests.
type fixtures struct {
	// ProxyToken, when set, is the bearer token every /v1 request must
	// present. Empty disables proxy authentication (handy for local curl).
	ProxyToken string `yaml:"proxy_token"`
	// Users are matched by login for both authentication flows.
	Users []fixtureUser `yaml:"users"`
	// Routes are evaluated in order; the first match wins. No match is a deny.
	Routes []fixtureRoute `yaml:"routes"`
	// HostKeys configures the trust-on-first-use behaviour (D7).
	HostKeys fixtureHostKeys `yaml:"host_keys"`
	// Events configures the revocation stream (PLAN §6.4).
	Events fixtureEvents `yaml:"events"`
}

// fixtureEvents tunes the server→proxy event stream.
type fixtureEvents struct {
	// HeartbeatMS is the interval between heartbeat events. Zero uses
	// defaultHeartbeatMS; a negative value disables heartbeats entirely, which
	// is how a test drives a proxy's missed-heartbeat detection.
	HeartbeatMS int `yaml:"heartbeat_ms"`
	// ReplayBuffer is how many events are retained for replay after a
	// reconnect. A proxy resuming from before the retained history is told to
	// resync. Zero uses defaultReplayBuffer.
	ReplayBuffer int `yaml:"replay_buffer"`
}

// fixtureUser is one principal the mock knows about.
type fixtureUser struct {
	// Login is the SSH login (target segment already stripped).
	Login string `yaml:"login"`
	// Identity is returned verbatim on a successful authentication.
	Identity fixtureIdentity `yaml:"identity"`
	// KeyFingerprints are the SHA256 fingerprints accepted for cert auth. Empty
	// means this user cannot authenticate with a key.
	KeyFingerprints []string `yaml:"key_fingerprints"`
	// Password is accepted for password auth. Empty means this user cannot
	// authenticate with a password. Fixtures are test data, never real secrets.
	Password string `yaml:"password"`
	// MFA configures the out-of-band second factor for the password flow.
	MFA fixtureMFA `yaml:"mfa"`
}

// fixtureIdentity mirrors control.Identity in YAML form.
type fixtureIdentity struct {
	Subject     string            `yaml:"subject"`
	DisplayName string            `yaml:"display_name"`
	Source      string            `yaml:"source"`
	Principals  []string          `yaml:"principals"`
	Groups      []string          `yaml:"groups"`
	Claims      map[string]string `yaml:"claims"`
}

// fixtureMFA makes the out-of-band factor deterministic: the challenge stays
// pending for exactly PendingPolls polls, then resolves as Decision says.
type fixtureMFA struct {
	Required bool `yaml:"required"`
	// Decision is "approve" or "deny" once the challenge resolves.
	Decision string `yaml:"decision"`
	// PendingPolls is how many polls are answered with mfa_required before the
	// decision is applied. Zero resolves on the first poll.
	PendingPolls int `yaml:"pending_polls"`
	// PollAfterMS is echoed to the client as the minimum poll interval.
	PollAfterMS int `yaml:"poll_after_ms"`
	// TTLMS is how long the challenge token stays valid.
	TTLMS int `yaml:"ttl_ms"`
	// Prompt is the text shown to the user while waiting.
	Prompt string `yaml:"prompt"`
}

// MFA decisions.
const (
	mfaApprove = "approve"
	mfaDeny    = "deny"
)

// fixtureRoute is one authorize rule. Login and Target are matched exactly, or
// with "*" to match anything.
type fixtureRoute struct {
	Login  string `yaml:"login"`
	Target string `yaml:"target"`
	// RouteType is "direct" or "nexthop".
	RouteType string `yaml:"route_type"`
	// ResolvedTarget overrides the host returned for a direct route. Empty
	// returns the target the user asked for.
	ResolvedTarget string `yaml:"resolved_target"`
	// NextHop is the proxy to chain to; required for "nexthop".
	NextHop string `yaml:"next_hop"`
	// MaxHops caps the chain length for a next-hop route.
	MaxHops int `yaml:"max_hops"`
	// TargetPort is the port to connect to; zero omits it (target default).
	TargetPort int `yaml:"target_port"`
	// Permissions is the opaque permission set name carried into logs.
	Permissions string `yaml:"permissions"`
	// PermittedChannels is the channel allow-list; empty denies every channel.
	PermittedChannels []string `yaml:"permitted_channels"`
	// FilterPolicy is the command filter policy for the connection.
	FilterPolicy fixtureFilterPolicy `yaml:"filter_policy"`
	// Cache authorises the proxy to reuse this decision. Absent (or a zero
	// ttl_seconds) means the decision is not cacheable.
	Cache fixtureCacheHint `yaml:"cache"`
}

// fixtureCacheHint mirrors control.CacheHint in YAML form.
type fixtureCacheHint struct {
	// TTLSeconds is how long the proxy may reuse the decision. Zero means do
	// not cache.
	TTLSeconds int `yaml:"ttl_seconds"`
	// Key overrides the cache key. Empty derives one per (subject, target),
	// which is the narrowest useful scope; set it explicitly to model a server
	// that shares one decision across targets.
	Key string `yaml:"key"`
}

// fixtureFilterPolicy mirrors control.FilterPolicy in YAML form.
type fixtureFilterPolicy struct {
	// Mode decides commands no rule matched: "whitelist" blocks them,
	// "blacklist" allows them.
	Mode string `yaml:"mode"`
	// Rules are evaluated in order; the first match wins.
	Rules []fixtureFilterRule `yaml:"rules"`
}

// fixtureFilterRule mirrors control.FilterRule in YAML form.
type fixtureFilterRule struct {
	Match   string `yaml:"match"`
	Action  string `yaml:"action"`
	Message string `yaml:"message"`
}

// fixtureHostKeys configures host-key reporting.
type fixtureHostKeys struct {
	// Decision is "accept" or "reject" for a key the server has not seen
	// before. The prototype's TOFU behaviour is "accept" (D7).
	Decision string `yaml:"decision"`
	// Known pre-seeds keys so a report can be answered with known=true.
	Known []fixtureKnownHostKey `yaml:"known"`
}

// fixtureKnownHostKey is one pre-trusted target host key.
type fixtureKnownHostKey struct {
	Target      string `yaml:"target"`
	Fingerprint string `yaml:"fingerprint"`
}

// loadFixtures reads, decodes, defaults, and validates the fixture file.
func loadFixtures(path string) (*fixtures, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open fixtures %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	fx, err := parseFixtures(f)
	if err != nil {
		return nil, fmt.Errorf("fixtures %q: %w", path, err)
	}
	return fx, nil
}

// parseFixtures decodes fixtures from r. Unknown keys are rejected so a typo in
// a policy field fails at startup instead of silently widening access.
func parseFixtures(r io.Reader) (*fixtures, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)

	var fx fixtures
	if err := dec.Decode(&fx); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("malformed fixtures: file is empty")
		}
		return nil, fmt.Errorf("malformed fixtures: %v", err)
	}

	fx.applyDefaults()
	if err := fx.validate(); err != nil {
		return nil, err
	}
	return &fx, nil
}

func (f *fixtures) applyDefaults() {
	if f.HostKeys.Decision == "" {
		f.HostKeys.Decision = string(control.HostKeyAccept)
	}
	if f.Events.HeartbeatMS == 0 {
		f.Events.HeartbeatMS = defaultHeartbeatMS
	}
	if f.Events.ReplayBuffer == 0 {
		f.Events.ReplayBuffer = defaultReplayBuffer
	}
	for i := range f.Users {
		u := &f.Users[i]
		if u.Identity.Subject == "" {
			u.Identity.Subject = u.Login
		}
		if u.Identity.Source == "" {
			u.Identity.Source = "fixture"
		}
		if u.MFA.Required {
			if u.MFA.Decision == "" {
				u.MFA.Decision = mfaApprove
			}
			if u.MFA.PollAfterMS == 0 {
				u.MFA.PollAfterMS = 100
			}
			if u.MFA.TTLMS == 0 {
				u.MFA.TTLMS = 60_000
			}
		}
	}
	for i := range f.Routes {
		r := &f.Routes[i]
		if r.Login == "" {
			r.Login = wildcard
		}
		if r.Target == "" {
			r.Target = wildcard
		}
		if r.RouteType == "" {
			r.RouteType = string(control.RouteTypeDirect)
		}
		if r.FilterPolicy.Mode == "" {
			r.FilterPolicy.Mode = string(control.FilterModeBlacklist)
		}
	}
}

// validate reports every problem at once so a fixture file can be fixed in one
// edit instead of one restart per mistake.
func (f *fixtures) validate() error {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	seenLogins := make(map[string]bool, len(f.Users))
	for i, u := range f.Users {
		switch {
		case u.Login == "":
			add("users[%d].login is required", i)
		case seenLogins[u.Login]:
			add("users[%d].login %q is duplicated", i, u.Login)
		default:
			seenLogins[u.Login] = true
		}
		if len(u.KeyFingerprints) == 0 && u.Password == "" {
			add("users[%d] (%s) has neither key_fingerprints nor password", i, u.Login)
		}
		if u.MFA.Required && u.MFA.Decision != mfaApprove && u.MFA.Decision != mfaDeny {
			add("users[%d].mfa.decision %q must be %q or %q", i, u.MFA.Decision, mfaApprove, mfaDeny)
		}
		if u.MFA.PendingPolls < 0 {
			add("users[%d].mfa.pending_polls must not be negative", i)
		}
	}

	for i, r := range f.Routes {
		switch control.RouteType(r.RouteType) {
		case control.RouteTypeDirect:
			if r.NextHop != "" {
				add("routes[%d] is direct but sets next_hop", i)
			}
		case control.RouteTypeNextHop:
			if r.NextHop == "" {
				add("routes[%d] is nexthop but has no next_hop", i)
			}
			if r.ResolvedTarget != "" {
				add("routes[%d] is nexthop but sets resolved_target", i)
			}
		default:
			add("routes[%d].route_type %q must be %q or %q", i, r.RouteType,
				control.RouteTypeDirect, control.RouteTypeNextHop)
		}
		if r.MaxHops < 0 {
			add("routes[%d].max_hops must not be negative", i)
		}
		if r.TargetPort < 0 || r.TargetPort > 65535 {
			add("routes[%d].target_port %d is out of range", i, r.TargetPort)
		}
		if r.Cache.TTLSeconds < 0 {
			add("routes[%d].cache.ttl_seconds must not be negative", i)
		}
		if r.Cache.TTLSeconds == 0 && r.Cache.Key != "" {
			// A key without a lifetime caches nothing; saying so at startup
			// beats wondering later why the decision is never reused.
			add("routes[%d].cache.key is set but ttl_seconds is 0 (nothing is cached)", i)
		}
		switch control.FilterMode(r.FilterPolicy.Mode) {
		case control.FilterModeWhitelist, control.FilterModeBlacklist:
		default:
			add("routes[%d].filter_policy.mode %q must be %q or %q", i, r.FilterPolicy.Mode,
				control.FilterModeWhitelist, control.FilterModeBlacklist)
		}
		for j, rule := range r.FilterPolicy.Rules {
			if rule.Match == "" {
				add("routes[%d].filter_policy.rules[%d] has no match pattern", i, j)
			}
			switch control.FilterAction(rule.Action) {
			case control.FilterActionAllowAndLog, control.FilterActionBlockCommand,
				control.FilterActionWarnAndContinue, control.FilterActionKillSession:
			default:
				// No default action: every rule states its own, or the policy is
				// ambiguous about how severely to treat that command.
				add("routes[%d].filter_policy.rules[%d] (%q): %q is not a known action",
					i, j, rule.Match, rule.Action)
			}
		}
	}

	switch control.HostKeyDecision(f.HostKeys.Decision) {
	case control.HostKeyAccept, control.HostKeyReject:
	default:
		add("host_keys.decision %q must be %q or %q", f.HostKeys.Decision,
			control.HostKeyAccept, control.HostKeyReject)
	}
	for i, k := range f.HostKeys.Known {
		if k.Target == "" || k.Fingerprint == "" {
			add("host_keys.known[%d] needs both target and fingerprint", i)
		}
	}

	if f.Events.ReplayBuffer < 0 {
		add("events.replay_buffer must not be negative")
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid fixtures: %s", strings.Join(problems, "; "))
	}
	return nil
}

// user returns the fixture user with the given login.
func (f *fixtures) user(login string) (*fixtureUser, bool) {
	for i := range f.Users {
		if f.Users[i].Login == login {
			return &f.Users[i], true
		}
	}
	return nil, false
}

// route returns the first rule matching login and target.
func (f *fixtures) route(login, target string) (*fixtureRoute, bool) {
	for i := range f.Routes {
		r := &f.Routes[i]
		if (r.Login == wildcard || r.Login == login) &&
			(r.Target == wildcard || r.Target == target) {
			return r, true
		}
	}
	return nil, false
}

// hasKeyFingerprint reports whether the user accepts the given key.
func (u *fixtureUser) hasKeyFingerprint(fp string) bool {
	for _, known := range u.KeyFingerprints {
		if known == fp {
			return true
		}
	}
	return false
}

// identity converts the fixture identity into its wire form.
func (u *fixtureUser) identity() *control.Identity {
	return &control.Identity{
		Subject:     u.Identity.Subject,
		Login:       u.Login,
		DisplayName: u.Identity.DisplayName,
		Source:      u.Identity.Source,
		Principals:  u.Identity.Principals,
		Groups:      u.Identity.Groups,
		Claims:      u.Identity.Claims,
	}
}
