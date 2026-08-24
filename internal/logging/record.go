// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hoplock/proxy/internal/control"
)

// The attribute keys below are the record schema's second half: the wire shape
// of a record is control.LogRecord, and everything structured that is not one
// of its own fields lives in Attributes under one of these names.
//
// They are constants rather than string literals at the call sites for the
// reason the field names in filter.AuditEvent are: a query written against
// "channel_id" keeps working only if nothing renames it by accident.
const (
	// Session-wide.
	AttrProxyID        = "proxy_id"        // the proxy that recorded this leg
	AttrClientAddr     = "client_addr"     // where the client connected from
	AttrServerAddr     = "server_addr"     // the proxy address it reached
	AttrClientVersion  = "client_version"  // the client's SSH identification
	AttrAuthMethod     = "auth_method"     // identity.Method: how the user proved who they are
	AttrIdentitySource = "identity_source" // where the identity came from (D4)
	AttrHopPeer        = "hop_peer"        // true when the client is another proxy
	AttrHopTrail       = "hop_trail"       // the proxies this session has already crossed
	AttrDuration       = "duration_ms"     // session or channel lifetime
	AttrReason         = "reason"          // why a session or channel ended
	AttrStage          = "stage"           // which part of setup failed
	AttrError          = "error"           // the failure text, never a credential

	// Route and policy (the authorize record).
	AttrRouteType         = "route_type"         // direct or nexthop
	AttrPermissions       = "permissions"        // the opaque permission-set name
	AttrDecisionID        = "decision_id"        // correlates with Hoplock Control's own trail
	AttrTargetPort        = "target_port"        //
	AttrFinalTarget       = "final_target"       // the end host, on a chained session
	AttrHopNextProxy      = "hop_next_proxy"     // the proxy this leg hands off to (D11)
	AttrHopConnection     = "hop_connection"     // dial or relay: this leg's direction (D11)
	AttrExecMode          = "exec_mode"          // filtered or restricted (D12)
	AttrFilterMode        = "filter_mode"        // whitelist or blacklist
	AttrCredentialMethod  = "credential_method"  // the target-credential method (D6a)
	AttrTargetAccount     = "target_account"     // the account the proxy connected to the target as
	AttrPermittedChannels = "permitted_channels" //

	// Channels, requests, and forwarding.
	AttrChannelID   = "channel_id"   // names the channel within the session
	AttrChannelType = "channel_type" //
	AttrDirection   = "direction"    // client or target: who opened, or which way bytes go
	AttrRequest     = "request"      // the in-channel request type
	AttrSubsystem   = "subsystem"    // the subsystem name, so sftp is visible on its own
	AttrCommand     = "command"      // the exec command as it arrived
	AttrScope       = "scope"        // channel or connection, for a request record
	AttrForwardHost = "forward_host" // a forwarding channel's destination (D5a axis 3a)
	AttrForwardPort = "forward_port" //
	AttrExitStatus  = "exit_status"  //

	// Policy decisions.
	AttrAction    = "action"     // what the decision did
	AttrOutcome   = "outcome"    // what actually happened to the command
	AttrEnforced  = "enforced"   // false for everything only observed
	AttrTier      = "tier"       // the tier that decided (D12)
	AttrGuarantee = "guarantee"  // what that tier may claim (D12)
	AttrMatched   = "matched"    //
	AttrRuleIndex = "rule_index" //
	AttrDetail    = "detail"     // the operator's half of a decision; never shown to the user
	AttrInspector = "inspector"  // who decided
	AttrPriority  = "priority"   // the delivery class the producer asked for (D8)
	AttrEvent     = "event"      // the producer's own event name, e.g. command.policy

	// Host keys and credentials.
	AttrHostKeyType        = "host_key_type"
	AttrHostKeyFingerprint = "host_key_fingerprint"
	AttrHostKeyKnown       = "host_key_known"

	// Stream capture.
	AttrCapture       = "capture"        // header or chunk
	AttrCaptureFormat = "capture_format" // how to read Payload
	AttrStream        = "stream"         // stdout, stderr, or stdin
	AttrOffsetMS      = "offset_ms"      // milliseconds since the channel opened
	AttrSequence      = "seq"            // per-stream ordinal, so a reader can detect a gap
	AttrBytes         = "bytes"          //
	AttrTerm          = "term"           // the replay header's terminal type
	AttrWidth         = "width"          //
	AttrHeight        = "height"         //
)

// CaptureFormatRawChunk is the value of AttrCaptureFormat on every stream
// record this package produces.
//
// A chunk is the bytes of one read off the wire, verbatim, with the offset of
// its first byte in AttrOffsetMS and its position in AttrSequence. That is the
// ttyrec/asciinema model — a timed sequence of opaque terminal writes — with
// the framing left to the reader, so a replay tool reconstructs a session by
// concatenating the chunks of one direction in sequence order and sleeping the
// offsets. It is deliberately not asciinema's own JSON: re-encoding terminal
// bytes into JSON strings at capture time would make the proxy the thing that
// has to be right about encodings, and a chunk that failed to encode would be
// a hole in an audit record.
const CaptureFormatRawChunk = "raw-chunk"

// Capture values for AttrCapture.
const (
	// CaptureHeader is a stream record with no payload that carries the
	// terminal geometry a replay needs (a pty-req, or a window-change).
	CaptureHeader = "header"
	// CaptureChunk is a stream record carrying captured bytes.
	CaptureChunk = "chunk"
)

// Attrs is the structured detail of one record. A nil Attrs is usable.
type Attrs map[string]string

// Set adds a key, ignoring an empty value so a record never carries a key that
// says nothing. It returns the map so a call site can chain.
func (a Attrs) Set(key, value string) Attrs {
	if a == nil || key == "" || value == "" {
		return a
	}
	a[key] = value
	return a
}

// SetInt adds an integer-valued key.
func (a Attrs) SetInt(key string, value int) Attrs { return a.Set(key, strconv.Itoa(value)) }

// SetBool adds a boolean-valued key. Unlike Set it keeps a false, because
// "enforced=false" is the whole content of an observed decision.
func (a Attrs) SetBool(key string, value bool) Attrs {
	if a == nil || key == "" {
		return a
	}
	a[key] = strconv.FormatBool(value)
	return a
}

// Event is one thing worth recording, before the recorder stamps the session
// onto it. Every capture point produces one of these.
type Event struct {
	// Kind classifies the record. Use the control.LogKind constants: they are
	// the values api/control.yaml documents.
	Kind control.LogKind
	// Severity ranks it. SeverityCritical is what takes the priority path, so
	// it is a delivery decision as much as a description (D8).
	Severity control.Severity
	// Message is a human-readable summary. It must never contain a credential.
	Message string
	// Attrs is the structured detail.
	Attrs Attrs
	// Payload is stream capture, for LogKindStream records only.
	Payload []byte
	// At overrides the record's timestamp; zero means now.
	At time.Time
}

// SessionInfo identifies the session every record from a recorder belongs to.
type SessionInfo struct {
	SessionID string
	ProxyID   string
	// Subject, Login, and Target are filled in by Identify once authentication
	// and username parsing have established them. Records made before that —
	// a handshake failure has no identity — simply carry less.
	Subject string
	Login   string
	Target  string
}

// SessionRecorder builds the records for one session and hands them to a
// Shipper.
//
// A nil *SessionRecorder is usable and records nothing, so a proxy running
// without a telemetry pipeline is not a special case at any capture point.
type SessionRecorder struct {
	shipper *Shipper
	started time.Time

	mu   sync.Mutex
	info SessionInfo

	records atomic.Uint64
}

// Session returns a recorder for one session. It is the only way to make one:
// a record with no session is not a session record.
func (s *Shipper) Session(info SessionInfo) *SessionRecorder {
	if s == nil || info.SessionID == "" {
		return nil
	}
	return &SessionRecorder{shipper: s, started: s.now(), info: info}
}

// SessionID is the session this recorder records, empty on a nil recorder.
func (r *SessionRecorder) SessionID() string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.info.SessionID
}

// Identify fills in who the session belongs to and what it asked for, so that
// every record made from here on carries it. Empty values leave what is
// already known alone: identity and target are established at different points
// and neither erases the other.
func (r *SessionRecorder) Identify(subject, login, tgt string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if subject != "" {
		r.info.Subject = subject
	}
	if login != "" {
		r.info.Login = login
	}
	if tgt != "" {
		r.info.Target = tgt
	}
}

// Records is how many records this session has produced. It exists for tests
// and for an operator asking how chatty a session was.
func (r *SessionRecorder) Records() uint64 {
	if r == nil {
		return 0
	}
	return r.records.Load()
}

// Record ships one event.
//
// It never blocks on the network: delivery is the Shipper's, and the only work
// done on the caller's goroutine is building the record. That is what lets a
// capture point sit directly in the path of a command decision.
func (r *SessionRecorder) Record(ev Event) {
	if r == nil {
		return
	}
	rec := r.build(ev)
	r.records.Add(1)
	if ev.Severity == control.SeverityCritical {
		// D8: a critical record does not wait in a batch. The Shipper flushes
		// whatever has accumulated first, so the batch that would have carried
		// the surrounding context still arrives before it.
		r.shipper.RecordPriority(rec)
		return
	}
	r.shipper.Record(rec)
}

// build turns an event into the wire record.
func (r *SessionRecorder) build(ev Event) control.LogRecord {
	r.mu.Lock()
	info := r.info
	r.mu.Unlock()

	at := ev.At
	if at.IsZero() {
		at = r.shipper.now()
	}
	attrs := ev.Attrs
	if attrs == nil {
		attrs = Attrs{}
	}
	attrs.Set(AttrProxyID, info.ProxyID)

	sev := ev.Severity
	if sev == "" {
		sev = control.SeverityInfo
	}
	return control.LogRecord{
		RecordID:   r.shipper.newRecordID(),
		SessionID:  info.SessionID,
		Timestamp:  at.UTC(),
		Kind:       ev.Kind,
		Severity:   sev,
		Message:    ev.Message,
		Subject:    info.Subject,
		Login:      info.Login,
		Target:     info.Target,
		Attributes: attrs,
		Payload:    ev.Payload,
	}
}

// Elapsed is how long this session has been running, rounded for a log line.
func (r *SessionRecorder) Elapsed() time.Duration {
	if r == nil {
		return 0
	}
	return r.shipper.now().Sub(r.started)
}

// --- the capture points -----------------------------------------------------
//
// Each method below is one point in the session's life, named for what happened
// rather than for the record it makes. internal/proxy calls them; the mapping
// from "what happened" to kind, severity, and attributes lives here so the
// transport never has to decide what severity a host key is.

// Start records the beginning of a session: who connected, from where, and how
// they proved it.
func (r *SessionRecorder) Start(attrs Attrs) {
	r.Record(Event{
		Kind:     control.LogKindSessionStart,
		Severity: control.SeverityInfo,
		Message:  "session started",
		Attrs:    attrs,
	})
}

// Auth records the authentication outcome the connection carries. The
// initial-auth password is not among its inputs and never can be: the
// authenticator hands over an identity, not a credential (PLAN §7).
func (r *SessionRecorder) Auth(message string, attrs Attrs) {
	r.Record(Event{
		Kind:     control.LogKindAuth,
		Severity: control.SeverityInfo,
		Message:  message,
		Attrs:    attrs,
	})
}

// Authorize records Hoplock Control's decision for this connection: the route,
// the permission set, the policy that will be enforced, and — on a chained
// session — the next proxy and the direction this leg travels (D11).
func (r *SessionRecorder) Authorize(message string, attrs Attrs) {
	r.Record(Event{
		Kind:     control.LogKindAuthorize,
		Severity: control.SeverityInfo,
		Message:  message,
		Attrs:    attrs,
	})
}

// HostKey records a target host key the proxy trusted (D7).
func (r *SessionRecorder) HostKey(message string, attrs Attrs) {
	r.Record(Event{
		Kind:     control.LogKindHostKey,
		Severity: control.SeverityInfo,
		Message:  message,
		Attrs:    attrs,
	})
}

// Provisioning records the target-credential method that was used, so an
// auditor can tell an ephemeral account from a brokered key without inferring
// it (D6a).
func (r *SessionRecorder) Provisioning(message string, attrs Attrs) {
	r.Record(Event{
		Kind:     control.LogKindProvisioning,
		Severity: control.SeverityInfo,
		Message:  message,
		Attrs:    attrs,
	})
}

// ChannelOpen records a channel that policy allowed to exist.
func (r *SessionRecorder) ChannelOpen(attrs Attrs) {
	r.Record(Event{
		Kind:     control.LogKindChannelOpen,
		Severity: control.SeverityInfo,
		Message:  "channel opened",
		Attrs:    attrs,
	})
}

// ChannelClose records the end of a channel and how long it lived.
func (r *SessionRecorder) ChannelClose(attrs Attrs) {
	r.Record(Event{
		Kind:     control.LogKindChannelClose,
		Severity: control.SeverityInfo,
		Message:  "channel closed",
		Attrs:    attrs,
	})
}

// Request records an in-channel or connection-level request: the pty, the
// shell, the exec and its command, the subsystem by name. This is the axis
// that makes sftp visible as itself rather than as "a session channel"
// (D5a axis 2).
func (r *SessionRecorder) Request(message string, attrs Attrs) {
	r.Record(Event{
		Kind:     control.LogKindCommand,
		Severity: control.SeverityInfo,
		Message:  message,
		Attrs:    attrs,
	})
}

// Denied records a refusal by the channel pipeline's own policy — a channel
// type, a request, a forwarding destination, a global request.
//
// It is critical, and therefore immediate (D8): a refusal is the event a
// security team is watching for, and it must not wait in a batch behind the
// session it was refused on.
func (r *SessionRecorder) Denied(message string, attrs Attrs) {
	r.Record(Event{
		Kind:     control.LogKindPolicyDecision,
		Severity: control.SeverityCritical,
		Message:  message,
		Attrs:    attrs,
	})
}

// Stream records captured bytes, or a replay header when payload is nil.
func (r *SessionRecorder) Stream(payload []byte, at time.Time, attrs Attrs) {
	r.Record(Event{
		Kind:     control.LogKindStream,
		Severity: control.SeverityInfo,
		Attrs:    attrs,
		Payload:  payload,
		At:       at,
	})
}

// Failure records something that went wrong on the proxy's side. It is warn
// rather than critical: a target that would not answer is an outage, not a
// security event, and treating the two alike would put every network blip on
// the priority path.
func (r *SessionRecorder) Failure(message string, attrs Attrs) {
	r.Record(Event{
		Kind:     control.LogKindError,
		Severity: control.SeverityWarn,
		Message:  message,
		Attrs:    attrs,
	})
}

// End records the close of a session, with its lifetime.
func (r *SessionRecorder) End(attrs Attrs) {
	if r == nil {
		return
	}
	if attrs == nil {
		attrs = Attrs{}
	}
	attrs.Set(AttrDuration, fmt.Sprintf("%d", r.Elapsed().Milliseconds()))
	r.Record(Event{
		Kind:     control.LogKindSessionEnd,
		Severity: control.SeverityInfo,
		Message:  "session ended",
		Attrs:    attrs,
	})
}
