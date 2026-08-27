// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"net/url"
	"time"
)

// API paths, absolute from Hoplock Control's base URL. They are exported
// so the mock server and the contract test can route/verify against the same
// constants the client dials, instead of repeating string literals.
const (
	PathAuthenticateCert     = "/v1/auth/cert"
	PathAuthenticatePassword = "/v1/auth/password"
	PathPollMFA              = "/v1/auth/mfa/poll"
	PathAuthorize            = "/v1/authorize"
	PathReportHostKey        = "/v1/hostkeys/report"
	PathIngestLogBatch       = "/v1/logs/batch"
	PathIngestPriorityLog    = "/v1/logs/priority"
	// PathProxyEvents is the revocation stream, templated on the proxy id.
	// Build a concrete path with ProxyEventsPath rather than by formatting
	// this constant, so the escaping stays in one place.
	PathProxyEvents = "/v1/proxies/{proxy_id}/events"
)

// PolicyVersion is the highest policy vocabulary this client implements, sent
// as AuthorizeRequest.PolicyVersion (PLAN D5a/D6a/D11/D12/D13/D14, phases 0006
// and 0013).
//
// Version 1 was the phase 0002/0003 vocabulary: permitted_channels and a
// filter rule list. Version 2 adds in-channel requests, forwarding
// destinations, global requests, target_auth, hop connection direction, and
// the exec enforcement mode. Version 3 (phase 0013) adds the ordered credential
// ladder (D14), the ephemeral-account method and its device-driver parameters
// (D13), the per-route algorithm profile, and the requirement that every
// provisioning method names its username.
//
// The server must not answer with policy fields introduced after the version
// the proxy declares. That is what makes it safe for this client to refuse an
// authorize response carrying a field it does not understand rather than
// dropping it: an unknown field may be a restriction, and a dropped
// restriction is a silently widened policy.
const PolicyVersion = 3

// QueryLastEventID is the query parameter carrying the last event the proxy
// processed, so the server can replay the gap after a reconnect (PLAN §6.4).
const QueryLastEventID = "last_event_id"

// ProxyEventsPath returns the revocation stream path for one proxy.
func ProxyEventsPath(proxyID string) string {
	return "/v1/proxies/" + url.PathEscape(proxyID) + "/events"
}

// ConnMeta describes the SSH connection a call is made on behalf of. It travels
// with every request so the server can decide on, and correlate logs by, the
// connection rather than the identity alone.
type ConnMeta struct {
	// SessionID is proxy-assigned and stable for the whole session.
	SessionID string `json:"session_id"`
	// ProxyID identifies the proxy making the call.
	ProxyID string `json:"proxy_id"`
	// ClientAddr is the SSH client's remote address ("host:port").
	ClientAddr string `json:"client_addr"`
	// ServerAddr is the local address the client connected to ("host:port").
	ServerAddr string `json:"server_addr,omitempty"`
	// ClientVersion is the SSH client identification string, as offered.
	ClientVersion string `json:"client_version,omitempty"`
	// HopTrail lists the proxy ids already traversed, oldest first, for loop
	// detection on next-hop routes (PLAN §6.1). Empty on a user's first hop.
	HopTrail []string `json:"hop_trail,omitempty"`
	// Timestamp is when the proxy made the call.
	Timestamp time.Time `json:"timestamp"`
}

// Identity is the authenticated principal as Hoplock Control sees it.
// It is a claims model, not a boolean, so AD/Okta/OIDC sources can be added
// without changing any caller (D4).
//
// This is the wire representation. Phase 0004 introduces the proxy's internal
// identity model in internal/identity and converts to and from this type at the
// control boundary.
type Identity struct {
	// Subject is the stable unique id of the principal at its source.
	Subject string `json:"subject"`
	// Login is the SSH login name with the target segment stripped (D1).
	Login string `json:"login"`
	// DisplayName is a human-friendly name, for logs and prompts.
	DisplayName string `json:"display_name,omitempty"`
	// Source names the identity source that decided ("fixture", "ad", ...).
	Source string `json:"source"`
	// Principals are the principals the identity may assume on targets.
	Principals []string `json:"principals,omitempty"`
	// Groups are the group memberships policy may key on.
	Groups []string `json:"groups,omitempty"`
	// Claims carries additional source-specific claims.
	Claims map[string]string `json:"claims,omitempty"`
}

// PublicKeyMaterial is an SSH public key or certificate as offered on the wire.
type PublicKeyMaterial struct {
	// Type is the SSH key algorithm name, e.g. "ssh-ed25519".
	Type string `json:"type"`
	// Blob is the SSH wire encoding of the key; it marshals as base64.
	Blob []byte `json:"blob"`
	// Fingerprint is the OpenSSH-style SHA256 fingerprint ("SHA256:...").
	Fingerprint string `json:"fingerprint"`
	// IsCertificate is true when the material is a certificate, not a bare key.
	IsCertificate bool `json:"is_certificate,omitempty"`
}

// AuthStatus is the outcome of an authentication call that did not deny.
type AuthStatus string

const (
	// AuthStatusAuthenticated means the flow is complete and Identity is set.
	AuthStatusAuthenticated AuthStatus = "authenticated"
	// AuthStatusMFARequired means MFA is outstanding and MFA is set; the caller
	// polls PollMFA until it resolves.
	AuthStatusMFARequired AuthStatus = "mfa_required"
)

// AuthenticateCertRequest relays a public key or certificate offered by a
// client. The proxy validates nothing locally; the server decides.
type AuthenticateCertRequest struct {
	Login string `json:"login"`
	// Target is the target parsed from the SSH username, informational here;
	// it is authorized by Authorize.
	Target    string            `json:"target,omitempty"`
	PublicKey PublicKeyMaterial `json:"public_key"`
	Conn      ConnMeta          `json:"conn"`
}

// AuthenticatePasswordRequest relays a password from a password or
// keyboard-interactive flow. Any out-of-band MFA is the server's concern.
type AuthenticatePasswordRequest struct {
	Login  string `json:"login"`
	Target string `json:"target,omitempty"`
	// Password is the password as typed. It must never be logged, echoed in an
	// error, or stored (PLAN §7); String and GoString redact it so that even an
	// accidental %v or %#v of this struct cannot leak it.
	Password string   `json:"password"`
	Conn     ConnMeta `json:"conn"`
}

// String redacts the password so the struct is safe to format.
func (r AuthenticatePasswordRequest) String() string {
	return "control.AuthenticatePasswordRequest{Login:" + r.Login +
		", Target:" + r.Target + ", Password:[REDACTED], Conn.SessionID:" +
		r.Conn.SessionID + "}"
}

// GoString redacts the password for the %#v verb.
func (r AuthenticatePasswordRequest) GoString() string { return r.String() }

// MFAPollRequest polls an outstanding MFA challenge.
type MFAPollRequest struct {
	// Token is the MFAChallenge.Token being polled.
	Token string   `json:"token"`
	Conn  ConnMeta `json:"conn"`
}

// MFAChallenge is an out-of-band second factor the server is waiting on.
type MFAChallenge struct {
	// Token is the opaque handle to poll with.
	Token string `json:"token"`
	// Prompt is text the proxy may show the user while waiting.
	Prompt string `json:"prompt,omitempty"`
	// PollAfterMS is the minimum delay before the next poll.
	PollAfterMS int `json:"poll_after_ms"`
	// ExpiresAt is when the token dies; polling after it returns a deny.
	ExpiresAt time.Time `json:"expires_at"`
}

// PollAfter returns PollAfterMS as a duration.
func (c MFAChallenge) PollAfter() time.Duration {
	return time.Duration(c.PollAfterMS) * time.Millisecond
}

// AuthenticateResponse is returned by every authentication call that did not
// deny. Exactly one of Identity or MFA is set, per Status.
type AuthenticateResponse struct {
	Status   AuthStatus    `json:"status"`
	Identity *Identity     `json:"identity,omitempty"`
	MFA      *MFAChallenge `json:"mfa,omitempty"`
}

// AuthMethod names how an identity was authenticated, for policy and audit.
type AuthMethod string

const (
	// AuthMethodCert is certificate/public-key authentication.
	AuthMethodCert AuthMethod = "cert"
	// AuthMethodPasswordMFA is password plus out-of-band MFA.
	AuthMethodPasswordMFA AuthMethod = "password-mfa"
)

// AuthorizeRequest asks whether an authenticated identity may reach a target,
// and how to get there.
type AuthorizeRequest struct {
	Identity   *Identity  `json:"identity"`
	Target     string     `json:"target"`
	TargetPort int        `json:"target_port,omitempty"`
	AuthMethod AuthMethod `json:"auth_method,omitempty"`
	// PolicyVersion is the highest policy vocabulary the proxy implements
	// (PolicyVersion). Absent means 1. The server must not answer with policy
	// fields introduced after it; the client refuses a response that does.
	PolicyVersion int      `json:"policy_version,omitempty"`
	Conn          ConnMeta `json:"conn"`
}

// RouteType says what AuthorizeResponse.Target refers to.
type RouteType string

const (
	// RouteTypeDirect means Target is the end host.
	RouteTypeDirect RouteType = "direct"
	// RouteTypeNextHop means Target is the next proxy in the chain.
	RouteTypeNextHop RouteType = "nexthop"
)

// AuthorizeResponse is the complete policy for a connection: where to connect,
// which channels are allowed, and which command filter to enforce. Anything not
// permitted here is denied.
type AuthorizeResponse struct {
	RouteType  RouteType `json:"route_type"`
	Target     string    `json:"target"`
	TargetPort int       `json:"target_port,omitempty"`
	// Permissions is an opaque permission set name, carried into logs.
	Permissions string `json:"permissions,omitempty"`
	// PermittedChannels lists the SSH channel types the session may open (D5).
	// An empty list denies every channel.
	//
	// It is the coarsest of the three policy axes (D5a) and never stands
	// alone: "session" carries scp, sftp, a shell, and a one-shot command
	// alike, and a direct-tcpip channel's meaning is the destination in its
	// payload. See PermittedRequests and PermittedForwards.
	PermittedChannels []string `json:"permitted_channels"`
	// PermittedRequests is the in-channel request policy (D5a axis 2,
	// enforced by phase 0009). NIL MEANS NOT POLICED — the v1 default, so a
	// server that never heard of this field does not accidentally deny every
	// shell. A non-nil policy is an allow-list: anything it does not name is
	// denied, and an empty one denies every request.
	PermittedRequests *RequestPolicy `json:"permitted_requests,omitempty"`
	// PermittedForwards is the forwarding destination policy (D5a axis 2,
	// enforced by phase 0009). Nil means destinations are not policed; a
	// non-nil policy permits only the destinations it lists, per direction.
	PermittedForwards *ForwardPolicy `json:"permitted_forwards,omitempty"`
	// PermittedGlobalRequests is the connection-level request policy (D5a
	// axis 3, enforced by phase 0009). Nil means global requests are relayed
	// unpoliced, which is what the proxy does today; a non-nil policy relays
	// only the types it lists and answers the rest with a false reply.
	PermittedGlobalRequests *GlobalRequestPolicy `json:"permitted_global_requests,omitempty"`
	// TargetAuth is the credential method the server chose for this route
	// (D6a, consumed by phase 0007). Nil means the proxy uses its locally
	// configured method, which is v1 behaviour.
	//
	// It is the v2 shape and it is kept, not polymorphised: TargetAuthLadder
	// below is the v3 shape, and a response setting both is refused. Read the
	// route's credentials through Ladder rather than through either field, so
	// that no caller has to know which shape the server chose.
	TargetAuth *TargetAuth `json:"target_auth,omitempty"`
	// TargetAuthLadder is the ORDERED list of credential methods the server
	// named for this route (D14, contract v3, walked by phase 0014).
	//
	// Three states, and they are three different policies:
	//
	//   - NIL (absent) — the server named no method; the proxy uses its
	//     locally configured one. This is what a v1 server implies and what
	//     phase 0005 does today.
	//   - NON-NIL AND EMPTY — the server named no method it will accept, which
	//     is a DENIAL, not "use local config". It is the same absent-versus-
	//     empty rule as permitted_channels: [] and it fails toward deny.
	//   - NON-EMPTY — walk it top-down and use the first entry this proxy can
	//     satisfy; exhausting it is an outage-class denial (PLAN §4.3).
	//
	// The pointer is what carries the first two states apart, which is why this
	// is *TargetAuthLadder and not TargetAuthLadder. Do not "simplify" it to a
	// value type: a plain slice with omitempty serialises an empty ladder as an
	// absent one, turning a denial into a locally configured credential.
	TargetAuthLadder *TargetAuthLadder `json:"target_auth_ladder,omitempty"`
	// AlgorithmProfile names the SSH algorithm set the proxy may offer on the
	// proxy→target leg for this route (contract v3, applied by phase 0014).
	// Empty means AlgorithmProfileDefault: nothing beyond the library defaults.
	// Anything else is a weakening and is audited as one.
	AlgorithmProfile AlgorithmProfile `json:"algorithm_profile,omitempty"`
	FilterPolicy     FilterPolicy     `json:"filter_policy"`
	// Hop is set when RouteType is RouteTypeNextHop.
	Hop *HopMetadata `json:"hop,omitempty"`
	// DecisionID correlates this decision with the server's audit trail.
	DecisionID string `json:"decision_id,omitempty"`
	// Cache is the server's permission to reuse this decision for a bounded
	// time. Absent means do not cache (PLAN §6.4).
	Cache *CacheHint `json:"cache,omitempty"`
}

// Ladder returns the credential methods the server named for this route, in
// the order it named them, and whether it named any at all.
//
// It is the ONE place the v2 single object and the v3 ordered list are read,
// so that nothing downstream has to know which shape a given server speaks:
//
//   - named == false — the server named nothing; the proxy falls back to its
//     locally configured method (v1/v2 absent behaviour).
//   - named == true with an empty ladder — the server named nothing it will
//     accept. That is a DENIAL and must not be confused with the line above.
//   - named == true with entries — walk them top-down (D14).
//
// A v2 response carrying a single target_auth object reads as a ONE-ENTRY
// ladder, which is exactly D6a's original behaviour: the proxy uses that method
// or the session fails. A response carrying both shapes never reaches here —
// Validate refuses it.
//
// The returned slice aliases the response. Callers that keep it past the
// decision's lifetime take a Clone, exactly as they do for every other policy
// field.
func (r *AuthorizeResponse) Ladder() (rungs []TargetAuth, named bool) {
	if r == nil {
		return nil, false
	}
	if r.TargetAuthLadder != nil {
		return []TargetAuth(*r.TargetAuthLadder), true
	}
	if r.TargetAuth != nil {
		return []TargetAuth{*r.TargetAuth}, true
	}
	return nil, false
}

// Profile returns the algorithm profile this route runs on, resolving the
// absent-value default so no caller has to decide what an empty one meant.
func (r *AuthorizeResponse) Profile() AlgorithmProfile {
	if r == nil || r.AlgorithmProfile == "" {
		return AlgorithmProfileDefault
	}
	return r.AlgorithmProfile
}

// CacheHint is Hoplock Control authorising the proxy to reuse this
// authorize decision for later connections (PLAN §6.4, D2).
//
// The lifetime belongs to the server: a proxy may hold the decision for less
// time than TTLSeconds, never longer, and never invents a hint of its own. That
// keeps the PDP in charge of its own risk appetite — it can return no hint at
// all for a sensitive target.
type CacheHint struct {
	// Key identifies the decision for invalidation and decides how widely it
	// may be shared. It is OPAQUE: the proxy never constructs, parses, or
	// derives meaning from it. A server must never issue one key to two
	// identities — the proxy refuses to serve an entry to a different subject,
	// but the contract, not that check, is what makes sharing safe.
	Key string `json:"key,omitempty"`
	// TTLSeconds is how long the decision may be reused. Absent or zero means
	// do not cache; there is no default lifetime.
	TTLSeconds int `json:"ttl_seconds"`
}

// TTL returns TTLSeconds as a duration. A zero TTL means "do not cache".
func (h *CacheHint) TTL() time.Duration {
	if h == nil {
		return 0
	}
	return time.Duration(h.TTLSeconds) * time.Second
}

// EventType names an event on the revocation stream.
type EventType string

const (
	// EventTypeSessionKill orders the proxy to tear sessions down now.
	EventTypeSessionKill EventType = "session_kill"
	// EventTypeCacheInvalidate drops cached authorize decisions.
	EventTypeCacheInvalidate EventType = "cache_invalidate"
	// EventTypeHeartbeat is the server proving the stream is still alive, so a
	// silently dead connection is detectable.
	EventTypeHeartbeat EventType = "heartbeat"
	// EventTypeResync says the proxy missed events it cannot be given: it
	// drops its entire cache and re-authorizes from scratch.
	EventTypeResync EventType = "resync"
)

// RevocationEvent is one line of the server→proxy event stream
// (GET /v1/proxies/{proxy_id}/events). The payload field that is set is the
// one named by Type; every other one is absent.
//
// The stream is what makes a cached decision safe to hold (PLAN §6.4): it is
// the server's only way to withdraw access it has already granted, and the only
// way to end a session that is already in flight.
type RevocationEvent struct {
	// EventID is server-assigned and opaque. The proxy stores the last one it
	// processed and echoes it back on reconnect (QueryLastEventID) so the server
	// can replay the gap; it never parses or orders by it itself.
	EventID string `json:"event_id"`
	// Type says which payload below applies.
	Type EventType `json:"type"`
	// Timestamp is when the server emitted the event.
	Timestamp time.Time `json:"timestamp"`
	// SessionKill is set when Type is EventTypeSessionKill.
	SessionKill *SessionKillEvent `json:"session_kill,omitempty"`
	// CacheInvalidate is set when Type is EventTypeCacheInvalidate.
	CacheInvalidate *CacheInvalidateEvent `json:"cache_invalidate,omitempty"`
}

// SessionKillEvent ends sessions that are already running. Exactly one of
// SessionIDs, Subject, or All selects what dies.
type SessionKillEvent struct {
	// SessionIDs names individual sessions by their proxy-assigned id.
	SessionIDs []string `json:"session_ids,omitempty"`
	// Subject kills every session belonging to one authenticated subject.
	Subject string `json:"subject,omitempty"`
	// All kills every session on this proxy.
	All bool `json:"all,omitempty"`
	// Reason is operator-authored text, shown to the user before the connection
	// closes and carried into the audit log (PLAN §4.3). A revoked session must
	// not look like a crash, so a server should always set it — and must keep
	// policy internals out of it, because it is displayed verbatim.
	Reason string `json:"reason,omitempty"`
}

// CacheInvalidateEvent drops cached authorize decisions. Exactly one of Keys,
// Subject, or All selects what is dropped. It never affects live sessions:
// those already hold their policy snapshot and are ended with a session_kill.
type CacheInvalidateEvent struct {
	// Keys are CacheHint.Key values, as the server issued them.
	Keys []string `json:"keys,omitempty"`
	// Subject drops every decision cached for one subject.
	Subject string `json:"subject,omitempty"`
	// All drops the whole cache.
	All bool `json:"all,omitempty"`
}

// FilterMode decides what happens to a command that matches no rule. It exists
// so that a policy always has a defined default and cannot fail open by
// omission.
type FilterMode string

const (
	// FilterModeWhitelist blocks any command no rule matched: the rules are the
	// permitted set.
	FilterModeWhitelist FilterMode = "whitelist"
	// FilterModeBlacklist allows any command no rule matched: the rules are the
	// caught set. A blacklist with no rules means no filtering.
	FilterModeBlacklist FilterMode = "blacklist"
)

// FilterAction is what the proxy does when the filter policy matches.
type FilterAction string

const (
	// FilterActionAllowAndLog permits the command and records an audit event.
	FilterActionAllowAndLog FilterAction = "allow_and_log"
	// FilterActionBlockCommand refuses the command but keeps the session.
	FilterActionBlockCommand FilterAction = "block_command"
	// FilterActionWarnAndContinue warns the user and permits the command.
	FilterActionWarnAndContinue FilterAction = "warn_and_continue"
	// FilterActionKillSession tears the whole session down.
	FilterActionKillSession FilterAction = "kill_session"
)

// FilterPolicy is the per-connection command filter policy (PLAN §6.3).
//
// Rules are evaluated in order and the FIRST MATCH WINS, so a specific rule
// placed before a broad one decides the outcome — "rm -rf /" can kill the
// session while "rm *" only warns. A command that matches no rule is decided by
// Mode, which is why Mode is required: there is always a defined default.
type FilterPolicy struct {
	Mode FilterMode `json:"mode"`
	// Rules are the ordered pattern→action list. Empty leaves every command to
	// Mode: an empty whitelist blocks everything, an empty blacklist filters
	// nothing.
	//
	// This is the FILTERED EXEC tier — a guardrail, not a boundary (D12). It
	// must be empty when ExecMode is ExecModeRestricted.
	Rules []FilterRule `json:"rules,omitempty"`
	// ExecMode selects which tier decides an exec request (D12, enforced by
	// phase 0010). Empty means ExecModeFiltered, which is v1 behaviour.
	//
	// The two tiers are ALTERNATIVES, NOT LAYERS. A policy that sets both Rules
	// and RestrictedExec is a contract violation the client refuses outright:
	// silently resolving it would mean a guardrail and a boundary disagreeing
	// about the same command with no defensible answer for which won.
	ExecMode ExecMode `json:"exec_mode,omitempty"`
	// RestrictedExec is the enforced tier. Required when ExecMode is
	// ExecModeRestricted, forbidden otherwise.
	RestrictedExec *RestrictedExecPolicy `json:"restricted_exec,omitempty"`
}

// Validate checks a filter policy against the contract, including the rule that
// the two exec tiers are alternatives rather than layers (D12).
//
// It is exported for the same reason AuthorizeResponse.Validate is: the policy
// engine in internal/filter compiles this shape and must fail closed on
// anything the wire refuses, and two almost-correct copies of one rule
// eventually disagree — with the disagreement landing on whichever of them a
// server is talking to.
func (p FilterPolicy) Validate() error { return p.validate() }

// Exec returns the exec tier this policy selects, resolving the absent-value
// default so callers never have to decide what an empty ExecMode meant.
func (p FilterPolicy) Exec() ExecMode {
	if p.ExecMode == "" {
		return ExecModeFiltered
	}
	return p.ExecMode
}

// FilterRule pairs one command pattern with the action to take when it matches.
// Per-rule actions are the point: a single action for a whole list would force
// every command in a policy down to the same severity.
type FilterRule struct {
	// Match is the command pattern. Matching semantics belong to the filter
	// engine and are the same regardless of Mode.
	Match string `json:"match"`
	// Action is what the proxy does when Match matches.
	Action FilterAction `json:"action"`
	// Message is optional operator-authored text shown to the user when this
	// rule fires (e.g. "use the deploy pipeline instead"). It is displayed
	// verbatim, so a server must not put policy internals in it (PLAN §4.3).
	Message string `json:"message,omitempty"`
}

// HopMetadata carries the chaining constraints for a next-hop route.
type HopMetadata struct {
	// Connection says how this proxy reaches the next one (D11, consumed by
	// phase 0008). Empty means HopConnectionDial, which is the original
	// next-hop behaviour and keeps a v1 server's route working.
	Connection HopConnection `json:"connection,omitempty"`
	// NextProxyID is the proxy id of the next hop — the same id that proxy
	// presents when it registers, which is how a relay hop selects the
	// registration to open a channel over. Required when Connection is
	// HopConnectionRelay; informational on a dial hop.
	NextProxyID string `json:"next_proxy_id,omitempty"`
	// FinalTarget is the end host the chain is being built toward.
	FinalTarget string `json:"final_target,omitempty"`
	// MaxHops caps the total hops for the session.
	MaxHops int `json:"max_hops,omitempty"`
	// HopTrail is the trail to forward to the next proxy (PLAN §6.1).
	HopTrail []string `json:"hop_trail,omitempty"`
}

// Direction returns how the next hop is reached, resolving the absent-value
// default. A nil HopMetadata reads as HopConnectionDial for the same reason an
// absent field does.
func (h *HopMetadata) Direction() HopConnection {
	if h == nil || h.Connection == "" {
		return HopConnectionDial
	}
	return h.Connection
}

// HostKeyReportRequest reports a target host key the proxy has just seen (D7).
type HostKeyReportRequest struct {
	Target     string            `json:"target"`
	TargetPort int               `json:"target_port,omitempty"`
	HostKey    PublicKeyMaterial `json:"host_key"`
	Conn       ConnMeta          `json:"conn"`
}

// HostKeyDecision says whether the proxy may continue the target handshake.
type HostKeyDecision string

const (
	// HostKeyAccept permits the handshake to continue.
	HostKeyAccept HostKeyDecision = "accept"
	// HostKeyReject aborts the target connection.
	HostKeyReject HostKeyDecision = "reject"
)

// HostKeyReportResponse is the server's trust decision for a reported key.
type HostKeyReportResponse struct {
	Decision HostKeyDecision `json:"decision"`
	// Known is false when the server had not seen this key for this target
	// before. The prototype accepts and records it (trust-on-first-use, D7).
	Known  bool   `json:"known"`
	Reason string `json:"reason,omitempty"`
}

// LogKind classifies a log record. It is a string rather than a closed enum so
// later phases can add kinds without a contract change; the values below are
// the ones the contract documents.
type LogKind string

// Log record kinds.
const (
	LogKindSessionStart   LogKind = "session_start"
	LogKindSessionEnd     LogKind = "session_end"
	LogKindAuth           LogKind = "auth"
	LogKindAuthorize      LogKind = "authorize"
	LogKindChannelOpen    LogKind = "channel_open"
	LogKindChannelClose   LogKind = "channel_close"
	LogKindCommand        LogKind = "command"
	LogKindPolicyDecision LogKind = "policy_decision"
	LogKindHostKey        LogKind = "host_key"
	LogKindStream         LogKind = "stream"
	LogKindProvisioning   LogKind = "provisioning"
	LogKindError          LogKind = "error"
)

// Severity ranks a log record. Critical records take the priority path (D8).
type Severity string

// Log record severities.
const (
	SeverityInfo     Severity = "info"
	SeverityWarn     Severity = "warn"
	SeverityCritical Severity = "critical"
)

// LogRecord is one structured session log record (PLAN §7).
type LogRecord struct {
	// RecordID is client-assigned and unique, so the server can de-duplicate a
	// batch that was retried after a timeout or drained from the disk buffer.
	RecordID  string    `json:"record_id"`
	SessionID string    `json:"session_id"`
	Timestamp time.Time `json:"timestamp"`
	Kind      LogKind   `json:"kind"`
	Severity  Severity  `json:"severity"`
	// Message is a human-readable summary and must not contain credentials.
	Message string `json:"message,omitempty"`
	Subject string `json:"subject,omitempty"`
	Login   string `json:"login,omitempty"`
	Target  string `json:"target,omitempty"`
	// Attributes carries structured detail, e.g. the matched command and action.
	Attributes map[string]string `json:"attributes,omitempty"`
	// Payload is stream capture for replay-oriented records; it marshals as
	// base64 and is omitted for every other kind.
	Payload []byte `json:"payload,omitempty"`
}

// LogBatchRequest ships accumulated records on the throughput path (D8).
type LogBatchRequest struct {
	Records []LogRecord `json:"records"`
}

// LogBatchResponse reports how many records the server stored. Fewer than sent
// means the remainder were duplicates and may be dropped.
type LogBatchResponse struct {
	Accepted int `json:"accepted"`
}

// LogPriorityRequest ships a single critical record on the low-latency path.
type LogPriorityRequest struct {
	Record LogRecord `json:"record"`
}

// LogPriorityResponse acknowledges a durable critical record. The proxy may
// act on the event (e.g. kill the session) once it has this.
type LogPriorityResponse struct {
	Accepted  bool   `json:"accepted"`
	ReceiptID string `json:"receipt_id,omitempty"`
}
