// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"encoding/json"
	"strings"
)

// This file carries the policy vocabulary added by phase 0006 (PLAN D5a, D6a,
// D11, D12): the two channel axes a channel-type allow-list cannot express, the
// server's choice of target credential method, and the exec enforcement mode.
//
// Nothing here is enforced by this package. Each type names the phase that
// consumes it, and the absent-value default of every field is stated on the
// field, because a policy field whose default is unwritten is a policy field
// that will eventually be guessed at.

// SSH channel request types the in-channel request policy governs (D5a axis 2).
// These are the requests that decide what a session channel *is*.
const (
	// RequestPTY is "pty-req": the channel becomes an interactive terminal.
	RequestPTY = "pty-req"
	// RequestShell is "shell": an interactive login shell.
	RequestShell = "shell"
	// RequestExec is "exec": a one-shot command, which is also how scp runs.
	RequestExec = "exec"
	// RequestEnv is "env": an environment variable set before the command.
	RequestEnv = "env"
	// RequestX11 is "x11-req": X11 forwarding for this channel.
	RequestX11 = "x11-req"
	// RequestAuthAgent is "auth-agent-req". It covers OpenSSH's
	// "auth-agent-req@openssh.com" too — they are the same request, and a
	// policy naming one means both.
	RequestAuthAgent = "auth-agent-req"
	// RequestSubsystem is "subsystem". It is NOT a member of
	// RequestPolicy.Types: a subsystem is permitted by name in
	// RequestPolicy.Subsystems, so that sftp is deniable while shell stays.
	RequestSubsystem = "subsystem"
)

// requestAuthAgentOpenSSH is the vendored spelling of RequestAuthAgent.
const requestAuthAgentOpenSSH = "auth-agent-req@openssh.com"

// ancillaryChannelRequests are session requests that carry no policy of their
// own. They are relayed whatever RequestPolicy says, because denying a terminal
// resize or an exit status is a broken session, not an enforced one.
var ancillaryChannelRequests = map[string]bool{
	"window-change":   true,
	"signal":          true,
	"exit-status":     true,
	"exit-signal":     true,
	"break":           true,
	"eow@openssh.com": true,
	"xon-xoff":        true,
}

// IsAncillaryChannelRequest reports whether a channel request is outside the
// in-channel request policy (D5a). Phase 0009 relays these unconditionally.
func IsAncillaryChannelRequest(name string) bool { return ancillaryChannelRequests[name] }

// RequestPolicy is the in-channel request allow-list (D5a axis 2, enforced by
// phase 0009).
//
// A session channel is opened before anyone knows what it is for; the request
// that follows is what makes it an interactive login, a one-shot command, or a
// file transfer. This is therefore the axis that expresses "may log in, may not
// copy files off the box" and "CI may run commands but never gets a PTY" —
// neither of which a channel-type allow-list can say.
//
// A NIL *RequestPolicy MEANS NOT POLICED, which is what a v1 server produced
// and must keep meaning, or a server that never heard of this field would deny
// every shell. A non-nil policy is an allow-list: anything it does not name is
// denied, so an empty policy denies every request exactly as
// PermittedChannels == [] denies every channel. Both halves matter — a
// truncated or half-understood response then fails toward deny.
type RequestPolicy struct {
	// Types are the permitted request types, from the Request* constants.
	// RequestSubsystem is deliberately not one of them.
	Types []string `json:"types,omitempty"`
	// Subsystems are the subsystem names permitted by exact match. Empty
	// denies every subsystem while leaving Types untouched.
	Subsystems []string `json:"subsystems,omitempty"`
}

// RequestPermitted reports whether a channel request of this type may be
// relayed. A nil policy permits everything (the v1 default); ancillary requests
// are permitted regardless.
//
// Subsystem requests are not decided here: call SubsystemPermitted with the
// subsystem's name, because the name is the policy.
func (p *RequestPolicy) RequestPermitted(name string) bool {
	if IsAncillaryChannelRequest(name) {
		return true
	}
	if p == nil {
		return true
	}
	if name == requestAuthAgentOpenSSH {
		name = RequestAuthAgent
	}
	return contains(p.Types, name)
}

// SubsystemPermitted reports whether a subsystem may be started, by name. A nil
// policy permits every subsystem; a non-nil one permits only those it names.
func (p *RequestPolicy) SubsystemPermitted(name string) bool {
	if p == nil {
		return true
	}
	return contains(p.Subsystems, name)
}

// Forwarding channel types, named so the two directions are never confused.
const (
	// ChannelDirectTCPIP is opened by the client toward a destination.
	ChannelDirectTCPIP = "direct-tcpip"
	// ChannelForwardedTCPIP is opened by the target back toward the client,
	// after a tcpip-forward global request created the listener.
	ChannelForwardedTCPIP = "forwarded-tcpip"
)

// ForwardPolicy is the forwarding destination allow-list (D5a axis 2, enforced
// by phase 0009).
//
// A direct-tcpip open carries the host and port it wants, so the destination —
// not the channel type — is what policy is about. Allowing or denying the type
// wholesale is the difference between a toggle and a firewall.
//
// Nil means destinations are not policed (v1 behaviour: the channel type alone
// decides). A non-nil policy permits only what it lists, per direction; a
// direction whose list is empty is denied entirely. The two axes are
// conjunctive: a channel type absent from PermittedChannels stays denied
// however permissive this policy is.
type ForwardPolicy struct {
	// DirectTCPIP are the destinations the client may open a forward to.
	DirectTCPIP []ForwardDestination `json:"direct_tcpip,omitempty"`
	// ForwardedTCPIP are the destinations the target may open a forward back
	// for. It is the same channel type in the other direction and needs its own
	// list: a route that may tunnel out to the database must not thereby accept
	// arbitrary channels pushed the other way.
	ForwardedTCPIP []ForwardDestination `json:"forwarded_tcpip,omitempty"`
}

// Destinations returns the permitted destinations for one forwarding channel
// type, and whether that type is policed at all. A nil policy is not policed;
// an unknown channel type has no destinations and is policed, which denies it.
func (p *ForwardPolicy) Destinations(channelType string) (dests []ForwardDestination, policed bool) {
	if p == nil {
		return nil, false
	}
	switch channelType {
	case ChannelDirectTCPIP:
		return p.DirectTCPIP, true
	case ChannelForwardedTCPIP:
		return p.ForwardedTCPIP, true
	default:
		return nil, true
	}
}

// ForwardDestination is one permitted forwarding destination: a host pattern
// and, optionally, a port constraint. A channel is permitted when it matches at
// least one destination in the list for its direction.
//
// The matching itself belongs to phase 0009. What the contract fixes is the
// shape and the meanings: Host is exact, a "*."-prefixed wildcard, a bare "*",
// or a CIDR; a CIDR never matches a hostname and a hostname never matches an IP
// literal, because the proxy does not resolve names to decide policy — a DNS
// answer is not a decision the PDP made.
type ForwardDestination struct {
	// Host is the host pattern: exact, wildcard, or CIDR.
	Host string `json:"host"`
	// Port is an exact permitted port. Mutually exclusive with PortRange.
	// Leaving both unset permits any port on a matching host, which is a
	// deliberate entry rather than an omission.
	Port int `json:"port,omitempty"`
	// PortRange is an inclusive permitted range.
	PortRange *PortRange `json:"port_range,omitempty"`
}

// PortRange is an inclusive port range.
type PortRange struct {
	From int `json:"from"`
	To   int `json:"to"`
}

// Connection-level global request types (D5a axis 3).
const (
	// GlobalRequestTCPIPForward asks the target to open a listener: remote
	// forwarding, requested on the connection rather than by opening a channel,
	// and therefore invisible to a channel-type allow-list.
	GlobalRequestTCPIPForward = "tcpip-forward"
	// GlobalRequestCancelTCPIPForward withdraws one.
	GlobalRequestCancelTCPIPForward = "cancel-tcpip-forward"
	// GlobalRequestStreamLocalForward is the Unix-socket equivalent.
	GlobalRequestStreamLocalForward = "streamlocal-forward@openssh.com"
	// GlobalRequestCancelStreamLocalForward withdraws one.
	GlobalRequestCancelStreamLocalForward = "cancel-streamlocal-forward@openssh.com"
)

// unpolicedGlobalRequests are connection-level requests that carry no policy.
// Denying a keepalive breaks a healthy session, and no-more-sessions is a
// restriction the client is asking for — refusing it would be perverse.
var unpolicedGlobalRequests = map[string]bool{
	"keepalive@openssh.com":         true,
	"no-more-sessions@openssh.com":  true,
	"hostkeys-00@openssh.com":       true,
	"hostkeys-prove-00@openssh.com": true,
}

// IsUnpolicedGlobalRequest reports whether a global request is outside the
// global request policy. Phase 0009 relays these unconditionally.
func IsUnpolicedGlobalRequest(name string) bool { return unpolicedGlobalRequests[name] }

// GlobalRequestPolicy is the connection-level request allow-list (D5a axis 3,
// enforced by phase 0009).
//
// Remote forwarding is requested with tcpip-forward on the connection, so a
// channel-type allow-list never sees it — and denying the resulting
// forwarded-tcpip channel is not equivalent, because the listener is created on
// the target either way and only the connections through it fail.
//
// Nil means global requests are relayed unpoliced, which is what
// internal/proxy's serveGlobalRequests does today. A non-nil policy relays only
// the types it names and answers the rest with a false reply; an empty policy
// denies all of them.
type GlobalRequestPolicy struct {
	// Types are the permitted global request names, matched exactly.
	Types []string `json:"types,omitempty"`
}

// Permitted reports whether a global request may be relayed. A nil policy
// permits everything; unpoliced request types are permitted regardless.
func (p *GlobalRequestPolicy) Permitted(name string) bool {
	if IsUnpolicedGlobalRequest(name) {
		return true
	}
	if p == nil {
		return true
	}
	return contains(p.Types, name)
}

// TargetAuthMethod names how the proxy authenticates to a target (D6a).
type TargetAuthMethod string

const (
	// TargetAuthEphemeralUser creates a short-lived OS user and key on the
	// target and removes them afterwards (D6, PLAN §5.1).
	TargetAuthEphemeralUser TargetAuthMethod = "ephemeral-user"
	// TargetAuthBrokeredKey uses a per-target credential held only for the
	// session and never written to disk (PLAN §5.2), for the appliances, network
	// gear, and OT devices the proxy cannot administer.
	TargetAuthBrokeredKey TargetAuthMethod = "brokered-key"
	// TargetAuthEphemeralAccount creates a short-lived administrator on a
	// device through a platform driver and removes it afterwards (D13, PLAN
	// §5.3). It is the same lifecycle as TargetAuthEphemeralUser in a different
	// vocabulary over a different transport: a FortiGate cannot run useradd,
	// but it can create an administrator, set its credential, scope it, and
	// delete it again.
	TargetAuthEphemeralAccount TargetAuthMethod = "ephemeral-account"
	// TargetAuthStaticKey is the development placeholder from phase 0005. It is
	// named in the contract so a fixture can select it; it is not a production
	// method.
	TargetAuthStaticKey TargetAuthMethod = "static-key"
)

// Provisioning methods are the ones where the proxy NAMES THE ACCOUNT it logs
// in as, rather than being handed one. Every one of them requires the username
// parameter (contract v3, phase 0013).
//
// Before v3 the username defaulted to identity.Identity.Login, and Login is a
// CLIENT-TYPED STRING — internal/identity says in as many words that it must
// never be the basis of an authorization decision. Letting it name an OS or
// device account is that rule leaking through the back door: the account name
// is what the target's own audit trail, its file ownership, and (on a password
// credential) half the credential pair are made of. So the server names it, or
// there is no route.
//
// brokered-key is deliberately not in this set: it logs into an account that
// already exists and is chosen by the operator, and phase 0007's behaviour for
// it is unchanged. Its username fallback is the same leak reached from a
// different direction and is recorded as a follow-up rather than fixed here.
func (m TargetAuthMethod) requiresUsername() bool {
	switch m {
	case TargetAuthEphemeralUser, TargetAuthEphemeralAccount, TargetAuthStaticKey:
		return true
	default:
		return false
	}
}

// Parameter names the contract defines for target_auth entries (api/README.md,
// "Target credentials"). They are scoped to their method: username means the
// account to create for ephemeral-user and the account that already exists for
// brokered-key, which is why each method reads its own.
//
// The contract owns the VOCABULARY — which values these may take and which of
// them a method requires — and that is what Validate checks. Whether a proxy
// implements every parameter an entry carries is a different question with a
// different answer, and internal/auth/target answers it at provision time
// (ErrUnknownParam): an unknown parameter may be a constraint, and a proxy that
// cannot honour one must not connect. Do not move that check here and do not
// duplicate it — two almost-correct copies of one rule eventually disagree.
const (
	// ParamUsername names the account on the target. Required on every
	// provisioning method (see requiresUsername).
	ParamUsername = "username"
	// ParamKeyType selects the ephemeral key algorithm (ephemeral-user).
	ParamKeyType = "key_type"
	// ParamLifetimeSeconds bounds how long the provisioned credential stays
	// valid, in whole seconds.
	ParamLifetimeSeconds = "lifetime_seconds"
	// ParamCredentialRef selects which local material a brokered-key session
	// uses. It is an opaque handle, never credential material (D6a).
	ParamCredentialRef = "credential_ref"
	// ParamPlatform names the device driver an ephemeral-account route needs
	// (D13). It is required and never inferred: guessing from a banner means
	// running configuration commands against the wrong parser.
	ParamPlatform = "platform"
	// ParamCredentialKind says which credential an ephemeral-account driver
	// should install (D13).
	ParamCredentialKind = "credential_kind"
	// ParamExpiryPosture says who, if anyone, enforces the account's expiry
	// (D13).
	ParamExpiryPosture = "expiry_posture"
	// ParamDeviceFieldPrefix opens the namespace of PLATFORM-SPECIFIC fields an
	// ephemeral-account route may carry (contract v3.1, phase 0016).
	//
	// It exists because some devices are not one target. A FortiGate running
	// virtual domains is one unit partitioned into many, and an administrator
	// on it is either global or scoped to one VDOM; a FortiLink-managed
	// FortiSwitch is administered THROUGH the FortiGate in front of it. The
	// route has to be able to say which of them a session is for, and the
	// endpoint cannot: host and port are what DNS resolves, what the host key
	// is pinned to, and what the audit record names, so overloading them would
	// make one device look like several hosts that do not exist.
	//
	// The contract owns the SHAPE of these keys and nothing else. Which fields
	// a platform has is the driver's to declare (device.Capabilities.Fields),
	// for the same reason the set of platforms is open: D13 makes
	// customer-written drivers a first-class case, and a contract that
	// enumerated their fields would be a contract that had to be revised for
	// every driver anybody writes.
	ParamDeviceFieldPrefix = "device_field."
)

// DeviceFields returns the platform-specific fields on an ephemeral-account
// entry, keyed WITHOUT the namespace prefix.
//
// It is a read of what the route said, not a judgement about it: whether a
// driver accepts a field is answered by the driver's declarations at
// provisioning time, where an unaccepted one is a skipped rung (D14) rather
// than a contract violation.
func (a *TargetAuth) DeviceFields() map[string]string {
	if a == nil || len(a.Params) == 0 {
		return nil
	}
	var fields map[string]string
	for k, v := range a.Params {
		name, ok := strings.CutPrefix(k, ParamDeviceFieldPrefix)
		if !ok {
			continue
		}
		if fields == nil {
			fields = map[string]string{}
		}
		fields[name] = v
	}
	return fields
}

// CredentialKind is the credential an ephemeral-account driver installs on the
// device (D13, PLAN §5.3).
//
// A driver DECLARES which kinds its platform accepts; a route naming a kind the
// driver does not accept is a skipped ladder entry (D14), not a downgrade to
// the other kind. The proxy never substitutes one for the other, because the
// two have materially different exposure and the server chose.
type CredentialKind string

const (
	// CredentialKindPassword installs a generated password. It is a reusable
	// secret that lands in the device's running configuration and, on many
	// platforms, in its own logs.
	CredentialKindPassword CredentialKind = "password"
	// CredentialKindPublicKey installs a generated public key. Nothing secret
	// reaches the device.
	CredentialKindPublicKey CredentialKind = "publickey"
)

// ExpiryPosture says who enforces the end of an ephemeral account's life (D13).
//
// On a POSIX host this question does not arise: OpenSSH's expiry-time
// restriction in authorized_keys makes the key die whether or not the proxy is
// alive to remove it (PLAN §5.1). Most device platforms have no equivalent, so
// the posture becomes something the PDP SELECTS per target, and the posture in
// force is an audit fact.
//
// There is no absent-value default on purpose. A default would be either
// dishonest (claiming enforcement the platform does not have) or silently the
// weakest option, and "the risk was accepted" is a sentence somebody has to
// write down rather than one a proxy infers.
type ExpiryPosture string

const (
	// ExpiryPostureTargetEnforced requires the device itself to expire the
	// account. PLAN §5.1's rule holds for this posture and only for it: a
	// driver that cannot express expiry makes this a skipped ladder entry.
	ExpiryPostureTargetEnforced ExpiryPosture = "target-enforced"
	// ExpiryPostureProxyEnforced means the proxy removes the account when the
	// lifetime elapses. It is real while the proxy lives and is exactly as
	// strong as the reaper behind it.
	ExpiryPostureProxyEnforced ExpiryPosture = "proxy-enforced"
	// ExpiryPostureAcceptedRisk means nobody enforces expiry and the PDP has
	// said so explicitly. It is named rather than reached by omission so that
	// it is visible in the policy and in the audit record.
	ExpiryPostureAcceptedRisk ExpiryPosture = "accepted-risk"
)

// TargetAuthLadder is the ordered list of credential methods the server named
// for this route (D14, contract v3, walked by phase 0014).
//
// The proxy walks it TOP-DOWN and uses the first entry it can satisfy: an entry
// naming a method this build does not implement, or has no local material for,
// or whose driver cannot meet its declared terms, is SKIPPED. Exhausting the
// ladder is a clean session denial (outage-class, PLAN §4.3).
//
// What has never been permitted, and still is not, is the proxy connecting with
// a method the server did not name. D6a's rule survives D14 untouched — what
// changed is who may author the fallback, not whether one exists. A PDP that
// will not accept degradation on a target writes a ONE-ENTRY ladder, which
// behaves exactly as D6a originally specified.
//
// The rung actually used is an AUDIT FACT AND NOT A USER-FACING ONE. It goes to
// the record and the operator surface (attributes target_auth_method and
// target_auth_rung, api/README.md); the user is told nothing. This is the one
// place PLAN §4.3's disclosure rule does not apply, and the reason is that the
// information is about the estate rather than about the user's own request:
// "you got the weaker credential" tells an attacker which targets are softest
// and tells an honest user nothing they can act on. Do not "fix" that.
type TargetAuthLadder []TargetAuth

// MarshalJSON emits an empty ladder as [] rather than null.
//
// It is not cosmetic. A present ladder means the server named its methods, and
// an empty one is a DENIAL; null decodes back into an absent ladder, which
// means "use the proxy's locally configured method" — the exact method the
// server declined to name. Without this, a nil slice behind a non-nil pointer
// would quietly convert a denial into a connection on every hop that re-encodes
// a decision.
func (l TargetAuthLadder) MarshalJSON() ([]byte, error) {
	if l == nil {
		return []byte("[]"), nil
	}
	return json.Marshal([]TargetAuth(l))
}

// AlgorithmProfile names the SSH algorithm set the proxy may offer on the
// proxy→target leg for this route (contract v3, applied by phase 0014).
//
// Much of the estate D13 exists to reach speaks key exchanges, host-key
// algorithms, ciphers, and MACs that golang.org/x/crypto/ssh does not enable by
// default, and without a way to say so those routes simply do not connect.
//
// Two properties make that safe, and it needs both:
//
//   - It is NAMED BY THE SERVER, PER ROUTE. It is deliberately not a
//     proxy-wide config knob, because a fleet-wide knob weakens every leg in
//     the fleet to serve the oldest device on it — and a fleet-wide sed is
//     exactly how that happens.
//   - It is a NAMED PRESET, not an algorithm list. A preset cannot be widened
//     one algorithm at a time by someone who does not know what they are
//     enabling, and the audit record names something a reviewer understands
//     rather than a string of identifiers they must decode.
//
// Anything other than AlgorithmProfileDefault is a WEAKENING and emits its own
// audit event (api/README.md), on D14's sibling rule for methods: an operator
// finds out that a route runs on SHA-1 from the record, not by reading policy.
type AlgorithmProfile string

const (
	// AlgorithmProfileDefault offers only what the SSH library enables by
	// default. It is the absent-value default and the only profile that is not
	// a weakening.
	AlgorithmProfileDefault AlgorithmProfile = "default"
	// AlgorithmProfileLegacyRSASHA1 additionally offers RSA with SHA-1
	// signatures (ssh-rsa) for host keys and public-key authentication. It is
	// the single most common reason a device of this era refuses a modern
	// client, and it is separate from the profile below so that a route needing
	// only this does not also get CBC and SHA-1 key exchange.
	AlgorithmProfileLegacyRSASHA1 AlgorithmProfile = "legacy-rsa-sha1"
	// AlgorithmProfileLegacyDevice is AlgorithmProfileLegacyRSASHA1 plus the
	// SHA-1 key exchanges, CBC ciphers, and SHA-1 MACs that appliance firmware
	// of that era offers. It is the widest profile this contract defines and it
	// is meant for the routes that connect on nothing else.
	AlgorithmProfileLegacyDevice AlgorithmProfile = "legacy-device"
)

// TargetAuth is the server's choice of target credential method for this route
// (D6a, consumed by phase 0007).
//
// The choice belongs to the server because one proxy routinely fronts a Linux
// estate that accepts just-in-time provisioning and an appliance estate that can
// never create a user; auth.target.method in config.yaml cannot express that.
// With this object, that config key is local material only — which key, which
// provisioning account — never the selection.
//
// Nil means the proxy uses its locally configured method (v1 behaviour, and
// what phase 0005 does today).
//
// A method the proxy does not implement, or has no local material for, is an
// OUTAGE-CLASS DENIAL (PLAN §4.3): the session fails and says it is an outage.
// It is never a fallback to another method, which would mean connecting with
// credentials the server did not choose.
//
// Contract v3 (D14) supersedes this single object with TargetAuthLadder, an
// ORDERED list of exactly these entries. The two are alternatives and never
// layers: a response carrying both is refused (Validate), on the same reasoning
// as restricted_exec beside a rule list in phase 0010 — two statements of which
// credential to use, disagreeing, have no defensible resolution. A v2 server
// keeps sending this object and it keeps meaning what it meant; Ladder reads
// either shape.
type TargetAuth struct {
	// Method names the credential method.
	Method TargetAuthMethod `json:"method"`
	// Params are method-specific parameters, open on purpose so a future
	// Hoplock Control that mints per-session credentials is another method
	// rather than another breaking change.
	//
	// Parameter names are scoped to their method (api/README.md lists the ones
	// defined today). A proxy that implements the named method must refuse a
	// parameter it does not know, for the same reason it refuses an unknown
	// top-level field: an unknown parameter may be a constraint. Values are
	// never logged, never echoed in an error, and never written to disk.
	Params map[string]string `json:"params,omitempty"`
}

// ExecMode selects which tier decides an exec request (D12, enforced by phase
// 0010). It exists because "seen reliably" is not "cannot be evaded", and the
// product must not let the two blur.
type ExecMode string

const (
	// ExecModeFiltered runs the ordered rule list against the whole exec
	// string: a GUARDRAIL. Every command is seen before it runs, and sh -c, any
	// interpreter, and any encoding still get past a pattern. This is the
	// absent-value default, and what a v1 server means.
	ExecModeFiltered ExecMode = "filtered"
	// ExecModeRestricted uses RestrictedExec: a BOUNDARY. The command is parsed
	// rather than matched, only named executables with approved argument shapes
	// run, anything else is denied, and no shell is interposed to re-expand what
	// was approved.
	ExecModeRestricted ExecMode = "restricted"
)

// RestrictedExecPolicy is the restricted exec tier (D12, consumed by phase
// 0010): a default-deny allow-list of executables together with the shape of
// their permitted arguments.
//
// What earns the word "enforcement" is the mechanism, not the strictness:
//
//   - the exec command string is PARSED into an argument vector using POSIX
//     shell word splitting and quote removal, never pattern-matched;
//   - a command that cannot be one argument vector is denied before matching
//     starts — anything containing ";", "|", "&", a backquote, "$(", "${", "<",
//     ">", a newline, or an unterminated quote, because those are shell syntax
//     and no argv means them;
//   - the parsed vector must be covered COMPLETELY by one entry of Commands, or
//     it is denied;
//   - the approved vector runs directly on the target, never through sh -c, so
//     nothing re-expands what was approved.
//
// An empty Commands list denies every exec, which is a coherent policy — a
// route that may log in interactively but run no one-shot command — rather than
// an accident.
type RestrictedExecPolicy struct {
	// Commands are tried in order; the first entry that accepts the vector
	// permits it. No entry accepting it denies the command.
	Commands []RestrictedCommand `json:"commands"`
}

// CommandForm says how a RestrictedCommand describes its arguments.
type CommandForm string

const (
	// CommandFormExact means Argv is the complete argument vector.
	CommandFormExact CommandForm = "exact"
	// CommandFormPositional means Args describes one argument position each.
	CommandFormPositional CommandForm = "positional"
)

// RestrictedCommand is one permitted executable and the shape of its permitted
// arguments.
type RestrictedCommand struct {
	// Executable is matched against argv[0] EXACTLY, as the user wrote it. A
	// policy that means /usr/bin/systemctl says so. The proxy performs no PATH
	// search, no symlink resolution, and no basename comparison of its own:
	// every one of those would silently accept a name the server did not write.
	Executable string `json:"executable"`
	// Form selects which of Argv and Args applies.
	Form CommandForm `json:"form"`
	// Argv is the complete argument list after the executable, compared element
	// by element. Required for CommandFormExact, forbidden otherwise.
	Argv []string `json:"argv,omitempty"`
	// Args is one spec per argument position, in order. Required for
	// CommandFormPositional, forbidden otherwise.
	//
	// ARGUMENTS NOT COVERED BY A SPEC ARE DENIED: there is no trailing
	// allowance and no wildcard tail, so a vector longer than Args never
	// matches. Optional trailing positions are expressed with
	// ArgumentSpec.Optional.
	Args []ArgumentSpec `json:"args,omitempty"`
}

// ArgumentKind is the permitted shape of one argument position.
type ArgumentKind string

const (
	// ArgumentLiteral requires the argument to equal Value.
	ArgumentLiteral ArgumentKind = "literal"
	// ArgumentPrefix requires the argument to start with Value, which must not
	// be empty.
	ArgumentPrefix ArgumentKind = "prefix"
	// ArgumentOneOf requires the argument to equal one of Values.
	ArgumentOneOf ArgumentKind = "oneof"
	// ArgumentAny leaves the argument unconstrained. It is named rather than
	// smuggled in as an empty prefix so that it is visible in the policy and in
	// the audit record: it is the one shape here that is not a boundary, and a
	// reviewer should be able to find every use of it by searching for the word.
	ArgumentAny ArgumentKind = "any"
)

// ArgumentSpec is the permitted shape of one argument position.
type ArgumentSpec struct {
	Kind ArgumentKind `json:"kind"`
	// Value is required and non-empty for ArgumentLiteral and ArgumentPrefix.
	Value string `json:"value,omitempty"`
	// Values is required and non-empty for ArgumentOneOf.
	Values []string `json:"values,omitempty"`
	// Optional says this position may be absent. Only trailing positions may be
	// optional: once a spec is optional every spec after it must be too, or the
	// positions after it would be ambiguous.
	Optional bool `json:"optional,omitempty"`
}

// HopConnection says how this proxy reaches the next one (D11, consumed by
// phase 0008).
type HopConnection string

const (
	// HopConnectionDial means this proxy opens a connection to the next one. It
	// is simple and it needs an inbound firewall rule at the next hop. It is the
	// absent-value default, which is the original next-hop behaviour.
	HopConnectionDial HopConnection = "dial"
	// HopConnectionRelay means the next proxy has already registered an
	// outbound relay connection with this one, and this proxy opens a channel
	// over it. The protected zone needs no inbound rule at all.
	//
	// A relay hop with no live registration is an OUTAGE (PLAN §4.3), never a
	// silent downgrade to dial: dialling would punch through exactly the
	// boundary this mode exists to preserve, at the moment an operator is least
	// able to see it.
	HopConnectionRelay HopConnection = "relay"
)

// contains reports whether list holds an exact match for v.
func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}
