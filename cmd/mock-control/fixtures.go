// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

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
	// Proxies are the fleet's own proxies, recognised by the key they present
	// when one of them extends a chain to another (D11). A chain leg is
	// authenticated as the PREVIOUS HOP, and the identity it is answered with
	// is the user's — re-established here, by the PDP, rather than asserted by
	// the upstream proxy. This is the mock's model of the chain trust model in
	// PLAN §6.1; a real Control would key it off the fleet's own registry.
	Proxies []fixtureProxy `yaml:"proxies"`
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

// fixtureProxy is one proxy in the fleet.
type fixtureProxy struct {
	// ID is the proxy id, as it appears in conn.proxy_id and in a hop trail.
	ID string `yaml:"id"`
	// KeyFingerprints are the SHA256 fingerprints of the keys this proxy may
	// present when it authenticates a chain leg.
	KeyFingerprints []string `yaml:"key_fingerprints"`
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
	// ProxyID restricts the rule to the proxy asking. Empty (or "*") matches
	// any proxy. It is what lets one fixture file describe a chain: the same
	// login and target answer "nexthop" at the edge proxy and "direct" at the
	// one behind it, which is exactly how a route differs per hop.
	ProxyID string `yaml:"proxy_id"`
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
	// PermittedRequests is the in-channel request policy (D5a). ABSENT MEANS
	// NOT POLICED, which is what every fixture written before phase 0006 means
	// and why they all keep working; present-but-empty denies every request.
	PermittedRequests *fixtureRequestPolicy `yaml:"permitted_requests"`
	// PermittedForwards is the forwarding destination policy (D5a). Absent
	// means destinations are not policed.
	PermittedForwards *fixtureForwardPolicy `yaml:"permitted_forwards"`
	// PermittedGlobalRequests is the connection-level request allow-list
	// (D5a). Absent means global requests are relayed unpoliced.
	PermittedGlobalRequests *fixtureGlobalRequestPolicy `yaml:"permitted_global_requests"`
	// TargetAuth is the credential method the server picks for this route
	// (D6a). Absent leaves the proxy on its locally configured method.
	TargetAuth *fixtureTargetAuth `yaml:"target_auth"`
	// TargetAuthLadder is the v3 ORDERED ladder of credential methods (D14).
	// Absent leaves the proxy on its locally configured method; present and
	// EMPTY is a denial, which is why it is a pointer. Setting it beside
	// target_auth is refused at startup, exactly as the client refuses it.
	TargetAuthLadder *[]fixtureTargetAuth `yaml:"target_auth_ladder"`
	// AlgorithmProfile is the per-route algorithm preset for the proxy→target
	// leg: "default" (the absent-value default), "legacy-rsa-sha1", or
	// "legacy-device".
	AlgorithmProfile string `yaml:"algorithm_profile"`
	// HopConnection is "dial" or "relay" for a nexthop route (D11). Empty
	// means "dial".
	HopConnection string `yaml:"hop_connection"`
	// NextProxyID is the next proxy's id, which a "relay" hop needs to select
	// the registration to open a channel over. Required with hop_connection:
	// relay.
	NextProxyID string `yaml:"next_proxy_id"`
	// FilterPolicy is the command filter policy for the connection.
	FilterPolicy fixtureFilterPolicy `yaml:"filter_policy"`
	// Enforcement is WHERE this route's policy is enforced, per axis
	// (contract v4). Absent means both axes take their default, which is
	// proxy-side enforcement only — what every fixture written before phase
	// 0018 means, and why they all keep working.
	Enforcement *fixtureEnforcement `yaml:"enforcement"`
	// SessionDeadlineSeconds sets session_deadline this many seconds from the
	// authorize call. It is a DURATION here and an absolute instant on the
	// wire: a fixture cannot carry a timestamp that is still in the future
	// tomorrow, and the contract deliberately refuses a duration (a duration
	// re-anchors on every hop). Zero means no deadline.
	SessionDeadlineSeconds int `yaml:"session_deadline_seconds"`
	// RequireSessionCapture makes the route refuse a proxy that cannot record
	// at all (D16). False is today's behaviour.
	RequireSessionCapture bool `yaml:"require_session_capture"`
	// GrantContext is why access was granted, as an external system asserted
	// it. The proxy logs it and never reads it.
	GrantContext *fixtureGrantContext `yaml:"grant_context"`
	// Concurrency caps live sessions per subject and/or per target. Absent
	// means uncapped.
	Concurrency *fixtureConcurrency `yaml:"concurrency"`
	// Cache authorises the proxy to reuse this decision. Absent (or a zero
	// ttl_seconds) means the decision is not cacheable.
	Cache fixtureCacheHint `yaml:"cache"`
}

// fixtureEnforcement mirrors control.EnforcementPolicy in YAML form.
type fixtureEnforcement struct {
	// Execution is the rung for what the session may execute: "proxy-inspected"
	// (the default), "no-interactive-shell", "account-restricted",
	// "account-confined", "platform-authorized", or "platform-attested".
	Execution string `yaml:"execution"`
	// Reach is the rung for what the session may reach:
	// "proxy-channel-policy" (the default), "account-egress-restricted",
	// "account-network-isolated", or "platform-attested".
	Reach string `yaml:"reach"`
	// PlatformRole is the device role the account is scoped to. Required by
	// "platform-authorized", forbidden otherwise.
	PlatformRole string `yaml:"platform_role"`
	// PermittedDestinations are what a "account-egress-restricted" session's
	// own processes may open. Same shape as permitted_forwards' entries, and
	// deliberately a different thing.
	PermittedDestinations []fixtureForwardDestination `yaml:"permitted_destinations"`
	// Attestation names who asserts an attested rung. Required by
	// "platform-attested" on either axis, forbidden otherwise.
	Attestation *fixtureAttestation `yaml:"attestation"`
}

// fixtureAttestation mirrors control.Attestation in YAML form.
type fixtureAttestation struct {
	// AssertedBy is who makes the claim.
	AssertedBy string `yaml:"asserted_by"`
	// Reference is where the claim is written down.
	Reference string `yaml:"reference"`
	// AssertedAt is when it was last affirmed, RFC 3339. Optional.
	AssertedAt string `yaml:"asserted_at"`
}

// fixtureGrantContext mirrors control.GrantContext in YAML form.
//
// Every value here is test data the proxy copies to its log records and never
// reads. Nothing in a fixture makes it policy, which is the whole point.
type fixtureGrantContext struct {
	System    string `yaml:"system"`
	Reference string `yaml:"reference"`
	// WindowStart and WindowEnd are RFC 3339 instants. Recorded, not enforced.
	WindowStart string `yaml:"window_start"`
	WindowEnd   string `yaml:"window_end"`
	// AdditionalText and AdditionalFields are the two forms
	// additional_context takes on the wire. Setting both is a fixture error:
	// the field is one or the other, never both.
	AdditionalText   string            `yaml:"additional_context_text"`
	AdditionalFields map[string]string `yaml:"additional_context_fields"`
}

// fixtureConcurrency mirrors control.ConcurrencyLimits in YAML form.
type fixtureConcurrency struct {
	PerSubject int `yaml:"max_sessions_per_subject"`
	PerTarget  int `yaml:"max_sessions_per_target"`
}

// fixtureRequestPolicy mirrors control.RequestPolicy in YAML form.
type fixtureRequestPolicy struct {
	// Types are permitted request types: pty-req, shell, exec, env, x11-req,
	// auth-agent-req. "subsystem" is not one of them — name subsystems below.
	Types []string `yaml:"types"`
	// Subsystems are permitted by name, so sftp is deniable while shell stays.
	Subsystems []string `yaml:"subsystems"`
}

// fixtureForwardPolicy mirrors control.ForwardPolicy in YAML form.
type fixtureForwardPolicy struct {
	// DirectTCPIP are destinations the client may forward to.
	DirectTCPIP []fixtureForwardDestination `yaml:"direct_tcpip"`
	// ForwardedTCPIP are destinations the target may forward back for.
	ForwardedTCPIP []fixtureForwardDestination `yaml:"forwarded_tcpip"`
}

// fixtureForwardDestination mirrors control.ForwardDestination in YAML form.
type fixtureForwardDestination struct {
	// Host is exact, a "*."-prefixed wildcard, a bare "*", or a CIDR.
	Host string `yaml:"host"`
	// Port is an exact port; mutually exclusive with PortRange. Both unset
	// permits any port on a matching host.
	Port int `yaml:"port"`
	// PortRange is an inclusive range.
	PortRange *fixturePortRange `yaml:"port_range"`
}

// fixturePortRange mirrors control.PortRange in YAML form.
type fixturePortRange struct {
	From int `yaml:"from"`
	To   int `yaml:"to"`
}

// fixtureGlobalRequestPolicy mirrors control.GlobalRequestPolicy in YAML form.
type fixtureGlobalRequestPolicy struct {
	// Types are permitted global request names, e.g. tcpip-forward.
	Types []string `yaml:"types"`
}

// fixtureTargetAuth mirrors control.TargetAuth in YAML form.
type fixtureTargetAuth struct {
	// Method is "ephemeral-user", "brokered-key", "ephemeral-account", or
	// "static-key".
	Method string `yaml:"method"`
	// Params are method-scoped parameters. Fixture values are never real
	// secrets — credential_ref names local material, it does not carry it.
	Params map[string]string `yaml:"params"`
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
	// Rules are evaluated in order; the first match wins. They are the
	// filtered-exec tier and must be empty under exec_mode: restricted.
	Rules []fixtureFilterRule `yaml:"rules"`
	// ExecMode is "filtered" (the rules decide — a guardrail) or "restricted"
	// (restricted_exec decides — a boundary). Empty means "filtered" (D12).
	ExecMode string `yaml:"exec_mode"`
	// RestrictedExec is the enforced tier. Required with exec_mode:
	// restricted, forbidden otherwise.
	RestrictedExec *fixtureRestrictedExec `yaml:"restricted_exec"`
}

// fixtureRestrictedExec mirrors control.RestrictedExecPolicy in YAML form.
type fixtureRestrictedExec struct {
	// Commands is the default-deny allow-list. Empty denies every exec.
	Commands []fixtureRestrictedCommand `yaml:"commands"`
}

// fixtureRestrictedCommand mirrors control.RestrictedCommand in YAML form.
type fixtureRestrictedCommand struct {
	// Executable is matched against argv[0] exactly, as written.
	Executable string `yaml:"executable"`
	// Form is "exact" (argv below is the whole vector) or "positional".
	Form string `yaml:"form"`
	// Argv is the complete argument vector; form: exact only.
	Argv []string `yaml:"argv"`
	// Args is one spec per position; form: positional only. Anything not
	// covered by a spec is denied — there is no trailing allowance.
	Args []fixtureArgumentSpec `yaml:"args"`
}

// fixtureArgumentSpec mirrors control.ArgumentSpec in YAML form.
type fixtureArgumentSpec struct {
	// Kind is "literal", "prefix", "oneof", or "any".
	Kind string `yaml:"kind"`
	// Value is required and non-empty for "literal" and "prefix".
	Value string `yaml:"value"`
	// Values is required and non-empty for "oneof".
	Values []string `yaml:"values"`
	// Optional marks a trailing position that may be absent.
	Optional bool `yaml:"optional"`
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
	// checkMethod names the offending entry itself, because a ladder makes
	// "the route's method" ambiguous the moment there is more than one.
	checkMethod := func(where, method string) {
		switch control.TargetAuthMethod(method) {
		case control.TargetAuthEphemeralUser, control.TargetAuthBrokeredKey,
			control.TargetAuthEphemeralAccount, control.TargetAuthStaticKey:
		default:
			add("%s.method %q is not a known method", where, method)
		}
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

	seenProxies := make(map[string]bool, len(f.Proxies))
	for i, p := range f.Proxies {
		switch {
		case p.ID == "":
			add("proxies[%d].id is required", i)
		case seenProxies[p.ID]:
			add("proxies[%d].id %q is duplicated", i, p.ID)
		default:
			seenProxies[p.ID] = true
		}
		if len(p.KeyFingerprints) == 0 {
			add("proxies[%d] (%s) has no key_fingerprints; it could authenticate no chain leg", i, p.ID)
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
		if r.HopConnection != "" && control.RouteType(r.RouteType) != control.RouteTypeNextHop {
			add("routes[%d].hop_connection is set on a %q route", i, r.RouteType)
		}
		switch control.HopConnection(r.HopConnection) {
		case "", control.HopConnectionDial:
		case control.HopConnectionRelay:
			if r.NextProxyID == "" {
				add("routes[%d].hop_connection is relay but next_proxy_id is empty", i)
			}
		default:
			add("routes[%d].hop_connection %q must be %q or %q", i, r.HopConnection,
				control.HopConnectionDial, control.HopConnectionRelay)
		}
		if r.TargetAuth != nil && r.TargetAuthLadder != nil {
			add("routes[%d] sets both target_auth and target_auth_ladder; "+
				"the ladder supersedes the single object, they are not layers (D14)", i)
		}
		if r.TargetAuth != nil {
			checkMethod(fmt.Sprintf("routes[%d].target_auth", i), r.TargetAuth.Method)
		}
		if r.TargetAuthLadder != nil {
			for j, entry := range *r.TargetAuthLadder {
				checkMethod(fmt.Sprintf("routes[%d].target_auth_ladder[%d]", i, j), entry.Method)
			}
		}
		switch control.AlgorithmProfile(r.AlgorithmProfile) {
		case "", control.AlgorithmProfileDefault, control.AlgorithmProfileLegacyRSASHA1,
			control.AlgorithmProfileLegacyDevice:
		default:
			add("routes[%d].algorithm_profile %q must be %q, %q or %q", i, r.AlgorithmProfile,
				control.AlgorithmProfileDefault, control.AlgorithmProfileLegacyRSASHA1,
				control.AlgorithmProfileLegacyDevice)
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
		if r.SessionDeadlineSeconds < 0 {
			add("routes[%d].session_deadline_seconds must not be negative", i)
		}
		if e := r.Enforcement; e != nil {
			if a := e.Attestation; a != nil {
				if _, err := fixtureTime(a.AssertedAt); err != nil {
					add("routes[%d].enforcement.attestation.asserted_at %q is not an RFC 3339 instant",
						i, a.AssertedAt)
				}
			}
		}
		if g := r.GrantContext; g != nil {
			for field, value := range map[string]string{
				"window_start": g.WindowStart, "window_end": g.WindowEnd,
			} {
				if _, err := fixtureTime(value); err != nil {
					add("routes[%d].grant_context.%s %q is not an RFC 3339 instant", i, field, value)
				}
			}
			if g.AdditionalText != "" && len(g.AdditionalFields) > 0 {
				// additional_context is a string OR an object on the wire, so a
				// fixture that sets both is describing a response that cannot
				// exist. Picking one would be the mock inventing policy.
				add("routes[%d].grant_context sets both additional_context_text and "+
					"additional_context_fields; the field is one or the other", i)
			}
		}
		// The remaining policy rules — the exec tiers, the forwarding
		// destinations, the request types, the enforcement rungs and what each
		// one requires — are exactly the ones the real client enforces, so the
		// fixture is checked against that same code rather than against a
		// second, drifting copy of it. A fixture the proxy would reject as a
		// contract violation must not start the mock.
		if err := r.authorizeResponse("fixture.invalid", nil).Validate(); err != nil {
			add("routes[%d]: %v", i, err)
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

// route returns the first rule matching login, target, and the asking proxy.
func (f *fixtures) route(login, target, proxyID string) (*fixtureRoute, bool) {
	for i := range f.Routes {
		r := &f.Routes[i]
		if (r.Login == wildcard || r.Login == login) &&
			(r.Target == wildcard || r.Target == target) &&
			(r.ProxyID == "" || r.ProxyID == wildcard || r.ProxyID == proxyID) {
			return r, true
		}
	}
	return nil, false
}

// proxyByKey returns the fleet proxy that owns a key fingerprint.
func (f *fixtures) proxyByKey(fingerprint string) (*fixtureProxy, bool) {
	for i := range f.Proxies {
		for _, known := range f.Proxies[i].KeyFingerprints {
			if known == fingerprint {
				return &f.Proxies[i], true
			}
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

// authorizeResponse builds the wire response for this route, apart from the
// per-request fields (target, hop trail, decision id, cache key) the handler
// fills in. It is also what validate() runs the client's own contract checks
// against, so the mock cannot serve a policy the proxy would refuse.
func (r *fixtureRoute) authorizeResponse(target string, hopTrail []string) *control.AuthorizeResponse {
	resp := &control.AuthorizeResponse{
		RouteType:               control.RouteType(r.RouteType),
		Target:                  target,
		TargetPort:              r.TargetPort,
		Permissions:             r.Permissions,
		PermittedChannels:       r.PermittedChannels,
		PermittedRequests:       r.PermittedRequests.wire(),
		PermittedForwards:       r.PermittedForwards.wire(),
		PermittedGlobalRequests: r.PermittedGlobalRequests.wire(),
		TargetAuth:              r.TargetAuth.wire(),
		TargetAuthLadder:        ladderWire(r.TargetAuthLadder),
		AlgorithmProfile:        control.AlgorithmProfile(r.AlgorithmProfile),
		FilterPolicy:            r.FilterPolicy.wire(),
		Enforcement:             r.Enforcement.wire(),
		RequireSessionCapture:   r.RequireSessionCapture,
		GrantContext:            r.GrantContext.wire(),
		Concurrency:             r.Concurrency.wire(),
	}
	if resp.PermittedChannels == nil {
		// An absent allow-list must serialise as [] (deny all), not null.
		resp.PermittedChannels = []string{}
	}
	if resp.RouteType == control.RouteTypeNextHop {
		resp.Target = r.NextHop
		resp.Hop = &control.HopMetadata{
			Connection:  control.HopConnection(r.HopConnection),
			NextProxyID: r.NextProxyID,
			FinalTarget: target,
			MaxHops:     r.MaxHops,
			HopTrail:    hopTrail,
		}
	} else if r.ResolvedTarget != "" {
		resp.Target = r.ResolvedTarget
	}
	return resp
}

// deadline resolves session_deadline_seconds against the clock at authorize
// time. The contract carries an absolute instant on purpose (a duration
// re-anchors on every hop), so the fixture's duration is anchored exactly once,
// here, by the server that made the decision.
func (r *fixtureRoute) deadline(now time.Time) *time.Time {
	if r.SessionDeadlineSeconds <= 0 {
		return nil
	}
	at := now.Add(time.Duration(r.SessionDeadlineSeconds) * time.Second)
	return &at
}

func (p *fixtureRequestPolicy) wire() *control.RequestPolicy {
	if p == nil {
		return nil
	}
	return &control.RequestPolicy{Types: p.Types, Subsystems: p.Subsystems}
}

func (p *fixtureForwardPolicy) wire() *control.ForwardPolicy {
	if p == nil {
		return nil
	}
	return &control.ForwardPolicy{
		DirectTCPIP:    forwardDestinations(p.DirectTCPIP),
		ForwardedTCPIP: forwardDestinations(p.ForwardedTCPIP),
	}
}

func forwardDestinations(in []fixtureForwardDestination) []control.ForwardDestination {
	if in == nil {
		return nil
	}
	out := make([]control.ForwardDestination, len(in))
	for i, d := range in {
		out[i] = control.ForwardDestination{Host: d.Host, Port: d.Port}
		if d.PortRange != nil {
			out[i].PortRange = &control.PortRange{From: d.PortRange.From, To: d.PortRange.To}
		}
	}
	return out
}

func (p *fixtureGlobalRequestPolicy) wire() *control.GlobalRequestPolicy {
	if p == nil {
		return nil
	}
	return &control.GlobalRequestPolicy{Types: p.Types}
}

func (a *fixtureTargetAuth) wire() *control.TargetAuth {
	if a == nil {
		return nil
	}
	return &control.TargetAuth{Method: control.TargetAuthMethod(a.Method), Params: a.Params}
}

// ladderWire converts a fixture ladder, keeping ABSENT and EMPTY apart: absent
// leaves the proxy on its locally configured method, empty denies the session,
// and collapsing the two here would turn a fixture's denial into a connection.
func ladderWire(entries *[]fixtureTargetAuth) *control.TargetAuthLadder {
	if entries == nil {
		return nil
	}
	ladder := make(control.TargetAuthLadder, 0, len(*entries))
	for i := range *entries {
		ladder = append(ladder, *(*entries)[i].wire())
	}
	return &ladder
}

func (p fixtureFilterPolicy) wire() control.FilterPolicy {
	return control.FilterPolicy{
		Mode:           control.FilterMode(p.Mode),
		Rules:          filterRules(p.Rules),
		ExecMode:       control.ExecMode(p.ExecMode),
		RestrictedExec: p.RestrictedExec.wire(),
	}
}

func (p *fixtureRestrictedExec) wire() *control.RestrictedExecPolicy {
	if p == nil {
		return nil
	}
	out := &control.RestrictedExecPolicy{Commands: make([]control.RestrictedCommand, len(p.Commands))}
	for i, c := range p.Commands {
		out.Commands[i] = control.RestrictedCommand{
			Executable: c.Executable,
			Form:       control.CommandForm(c.Form),
			Argv:       c.Argv,
		}
		if c.Args != nil {
			args := make([]control.ArgumentSpec, len(c.Args))
			for j, a := range c.Args {
				args[j] = control.ArgumentSpec{
					Kind:     control.ArgumentKind(a.Kind),
					Value:    a.Value,
					Values:   a.Values,
					Optional: a.Optional,
				}
			}
			out.Commands[i].Args = args
		}
	}
	return out
}

func (e *fixtureEnforcement) wire() *control.EnforcementPolicy {
	if e == nil {
		return nil
	}
	return &control.EnforcementPolicy{
		Execution:             control.ExecutionRung(e.Execution),
		Reach:                 control.ReachRung(e.Reach),
		PlatformRole:          e.PlatformRole,
		PermittedDestinations: forwardDestinations(e.PermittedDestinations),
		Attestation:           e.Attestation.wire(),
	}
}

func (a *fixtureAttestation) wire() *control.Attestation {
	if a == nil {
		return nil
	}
	out := &control.Attestation{AssertedBy: a.AssertedBy, Reference: a.Reference}
	if t, err := fixtureTime(a.AssertedAt); err == nil {
		out.AssertedAt = t
	}
	return out
}

func (g *fixtureGrantContext) wire() *control.GrantContext {
	if g == nil {
		return nil
	}
	out := &control.GrantContext{System: g.System, Reference: g.Reference}
	out.WindowStart, _ = fixtureTime(g.WindowStart)
	out.WindowEnd, _ = fixtureTime(g.WindowEnd)
	switch {
	case len(g.AdditionalFields) > 0:
		fields := make(map[string]any, len(g.AdditionalFields))
		for k, v := range g.AdditionalFields {
			fields[k] = v
		}
		out.Additional = &control.AdditionalContext{Fields: fields}
	case g.AdditionalText != "":
		out.Additional = &control.AdditionalContext{Text: g.AdditionalText}
	}
	return out
}

func (c *fixtureConcurrency) wire() *control.ConcurrencyLimits {
	if c == nil {
		return nil
	}
	return &control.ConcurrencyLimits{PerSubject: c.PerSubject, PerTarget: c.PerTarget}
}

// fixtureTime parses an optional RFC 3339 instant from a fixture. An empty
// string is an absent instant and not an error, because every timestamp in a
// fixture is optional; a malformed one is reported by validate() rather than
// silently becoming the zero time, which the contract refuses anyway.
func fixtureTime(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, err
	}
	return &t, nil
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

// ClaimChainHop names the proxy whose key authenticated a chain leg. The
// identity itself is the user's, issued by the server: a hop learns who is
// connecting from the PDP, never from the proxy in front of it (PLAN §6.1).
const ClaimChainHop = "chain_hop_proxy_id"

// chainIdentity is the identity answered to a chain leg: the user's, with the
// hop that presented the key recorded on it for audit.
func (u *fixtureUser) chainIdentity(hop string) *control.Identity {
	id := u.identity()
	claims := make(map[string]string, len(id.Claims)+1)
	for k, v := range id.Claims {
		claims[k] = v
	}
	claims[ClaimChainHop] = hop
	id.Claims = claims
	return id
}

// vocabularyVersion reports the lowest policy vocabulary that can express this
// response. A proxy that declared an older version refuses a field it does not
// know rather than dropping it, so the mock has to know when it is about to
// send one.
//
// It answers per RESPONSE rather than per build: a fixture written before phase
// 0006 is still v1 and is still servable to a v1 proxy, and the same now holds
// for a v2 fixture against a v2 proxy. Every field added to the contract needs
// a case here, or the mock will hand it to a proxy that fails the session
// closed on it.
func vocabularyVersion(r *control.AuthorizeResponse) int {
	switch {
	case r.Enforcement != nil,
		r.SessionDeadline != nil,
		r.RequireSessionCapture,
		r.GrantContext != nil,
		r.Concurrency != nil:
		return 4
	}
	switch {
	case r.TargetAuthLadder != nil,
		r.AlgorithmProfile != "",
		r.TargetAuth != nil && r.TargetAuth.Method == control.TargetAuthEphemeralAccount:
		return 3
	}
	switch {
	case r.PermittedRequests != nil,
		r.PermittedForwards != nil,
		r.PermittedGlobalRequests != nil,
		r.TargetAuth != nil,
		r.FilterPolicy.ExecMode != "",
		r.FilterPolicy.RestrictedExec != nil,
		r.Hop != nil && (r.Hop.Connection != "" || r.Hop.NextProxyID != ""):
		return 2
	}
	return 1
}
