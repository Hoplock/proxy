// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package mgmt

import (
	"net/url"
	"time"
)

// API paths, absolute from the management server's base URL. They are exported
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
	// PathBastionEvents is the revocation stream, templated on the bastion id.
	// Build a concrete path with BastionEventsPath rather than by formatting
	// this constant, so the escaping stays in one place.
	PathBastionEvents = "/v1/bastions/{bastion_id}/events"
)

// QueryLastEventID is the query parameter carrying the last event the bastion
// processed, so the server can replay the gap after a reconnect (PLAN §6.4).
const QueryLastEventID = "last_event_id"

// BastionEventsPath returns the revocation stream path for one bastion.
func BastionEventsPath(bastionID string) string {
	return "/v1/bastions/" + url.PathEscape(bastionID) + "/events"
}

// ConnMeta describes the SSH connection a call is made on behalf of. It travels
// with every request so the server can decide on, and correlate logs by, the
// connection rather than the identity alone.
type ConnMeta struct {
	// SessionID is bastion-assigned and stable for the whole session.
	SessionID string `json:"session_id"`
	// BastionID identifies the bastion making the call.
	BastionID string `json:"bastion_id"`
	// ClientAddr is the SSH client's remote address ("host:port").
	ClientAddr string `json:"client_addr"`
	// ServerAddr is the local address the client connected to ("host:port").
	ServerAddr string `json:"server_addr,omitempty"`
	// ClientVersion is the SSH client identification string, as offered.
	ClientVersion string `json:"client_version,omitempty"`
	// HopTrail lists the bastion ids already traversed, oldest first, for loop
	// detection on next-hop routes (PLAN §6.1). Empty on a user's first hop.
	HopTrail []string `json:"hop_trail,omitempty"`
	// Timestamp is when the bastion made the call.
	Timestamp time.Time `json:"timestamp"`
}

// Identity is the authenticated principal as the management server sees it.
// It is a claims model, not a boolean, so AD/Okta/OIDC sources can be added
// without changing any caller (D4).
//
// This is the wire representation. Phase 0004 introduces the bastion's internal
// identity model in internal/identity and converts to and from this type at the
// mgmt boundary.
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
// client. The bastion validates nothing locally; the server decides.
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
	return "mgmt.AuthenticatePasswordRequest{Login:" + r.Login +
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
	// Prompt is text the bastion may show the user while waiting.
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
	Conn       ConnMeta   `json:"conn"`
}

// RouteType says what AuthorizeResponse.Target refers to.
type RouteType string

const (
	// RouteTypeDirect means Target is the end host.
	RouteTypeDirect RouteType = "direct"
	// RouteTypeNextHop means Target is the next bastion in the chain.
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
	PermittedChannels []string     `json:"permitted_channels"`
	FilterPolicy      FilterPolicy `json:"filter_policy"`
	// Hop is set when RouteType is RouteTypeNextHop.
	Hop *HopMetadata `json:"hop,omitempty"`
	// DecisionID correlates this decision with the server's audit trail.
	DecisionID string `json:"decision_id,omitempty"`
	// Cache is the server's permission to reuse this decision for a bounded
	// time. Absent means do not cache (PLAN §6.4).
	Cache *CacheHint `json:"cache,omitempty"`
}

// CacheHint is the management server authorising the bastion to reuse this
// authorize decision for later connections (PLAN §6.4, D2).
//
// The lifetime belongs to the server: a bastion may hold the decision for less
// time than TTLSeconds, never longer, and never invents a hint of its own. That
// keeps the PDP in charge of its own risk appetite — it can return no hint at
// all for a sensitive target.
type CacheHint struct {
	// Key identifies the decision for invalidation and decides how widely it
	// may be shared. It is OPAQUE: the bastion never constructs, parses, or
	// derives meaning from it. A server must never issue one key to two
	// identities — the bastion refuses to serve an entry to a different subject,
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
	// EventTypeSessionKill orders the bastion to tear sessions down now.
	EventTypeSessionKill EventType = "session_kill"
	// EventTypeCacheInvalidate drops cached authorize decisions.
	EventTypeCacheInvalidate EventType = "cache_invalidate"
	// EventTypeHeartbeat is the server proving the stream is still alive, so a
	// silently dead connection is detectable.
	EventTypeHeartbeat EventType = "heartbeat"
	// EventTypeResync says the bastion missed events it cannot be given: it
	// drops its entire cache and re-authorizes from scratch.
	EventTypeResync EventType = "resync"
)

// RevocationEvent is one line of the server→bastion event stream
// (GET /v1/bastions/{bastion_id}/events). The payload field that is set is the
// one named by Type; every other one is absent.
//
// The stream is what makes a cached decision safe to hold (PLAN §6.4): it is
// the server's only way to withdraw access it has already granted, and the only
// way to end a session that is already in flight.
type RevocationEvent struct {
	// EventID is server-assigned and opaque. The bastion stores the last one it
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
	// SessionIDs names individual sessions by their bastion-assigned id.
	SessionIDs []string `json:"session_ids,omitempty"`
	// Subject kills every session belonging to one authenticated subject.
	Subject string `json:"subject,omitempty"`
	// All kills every session on this bastion.
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

// FilterAction is what the bastion does when the filter policy matches.
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
	Rules []FilterRule `json:"rules,omitempty"`
}

// FilterRule pairs one command pattern with the action to take when it matches.
// Per-rule actions are the point: a single action for a whole list would force
// every command in a policy down to the same severity.
type FilterRule struct {
	// Match is the command pattern. Matching semantics belong to the filter
	// engine and are the same regardless of Mode.
	Match string `json:"match"`
	// Action is what the bastion does when Match matches.
	Action FilterAction `json:"action"`
	// Message is optional operator-authored text shown to the user when this
	// rule fires (e.g. "use the deploy pipeline instead"). It is displayed
	// verbatim, so a server must not put policy internals in it (PLAN §4.3).
	Message string `json:"message,omitempty"`
}

// HopMetadata carries the chaining constraints for a next-hop route.
type HopMetadata struct {
	// FinalTarget is the end host the chain is being built toward.
	FinalTarget string `json:"final_target,omitempty"`
	// MaxHops caps the total hops for the session.
	MaxHops int `json:"max_hops,omitempty"`
	// HopTrail is the trail to forward to the next bastion (PLAN §6.1).
	HopTrail []string `json:"hop_trail,omitempty"`
}

// HostKeyReportRequest reports a target host key the bastion has just seen (D7).
type HostKeyReportRequest struct {
	Target     string            `json:"target"`
	TargetPort int               `json:"target_port,omitempty"`
	HostKey    PublicKeyMaterial `json:"host_key"`
	Conn       ConnMeta          `json:"conn"`
}

// HostKeyDecision says whether the bastion may continue the target handshake.
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

// LogPriorityResponse acknowledges a durable critical record. The bastion may
// act on the event (e.g. kill the session) once it has this.
type LogPriorityResponse struct {
	Accepted  bool   `json:"accepted"`
	ReceiptID string `json:"receipt_id,omitempty"`
}
