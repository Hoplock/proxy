// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package device

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
)

// Driver performs the ephemeral-account lifecycle on one platform (PLAN §5.3,
// D13).
//
// The lifecycle is the same one PLAN §5.1 performs on a POSIX host — log in
// privileged, create the account, install the credential, connect, remove it on
// teardown — executed in the platform's own vocabulary over the platform's own
// transport. What is missing on a device is not the model; it is something that
// knows how to say "create this account" to a FortiGate.
//
// The interface is shaped like target.TargetAuthenticator on purpose: context
// first, a typed request per operation, and an error that distinguishes THIS
// PLATFORM CANNOT from THIS ATTEMPT FAILED (see ErrUnsupported). Phase 0014's
// provisioner and reaper both branch on that distinction, and a driver that
// blurs it turns a permanent limitation into an infinite retry — or a transient
// device reboot into a permanently skipped ladder rung.
//
// D13 makes CUSTOMER-WRITTEN DRIVERS a first-class case: the estates that need
// this most are the ones running a platform nobody else has. The declarative
// driver document and the subprocess contract that serve them are a later
// phase, and both arrive as implementations of this interface — a document
// interpreter is one Driver, a subprocess supervisor is another — rather than
// as a second seam beside it. That is the whole reason the operations are named
// and typed here instead of being a command list.
type Driver interface {
	// Platform is the identifier the contract's `platform` parameter names
	// (control.ParamPlatform). It is what the registry keys on, so it must be
	// stable across releases: it appears in policy somebody else wrote.
	Platform() string

	// Capabilities returns what this platform can and cannot do. It is DATA,
	// read by the provisioner, and it must not depend on having connected to
	// anything — see the type's own documentation for why.
	Capabilities() Capabilities

	// CreateAccount creates the account named in req and returns what it
	// created.
	//
	// It must NOT adopt an existing account of the same name. On a constrained
	// platform the uniqueness token is short enough that an existing name is
	// plausibly another live session's, and adopting one means two sessions
	// sharing an account whose first teardown removes the other's access. A
	// name that already exists is reported with ErrAccountExists so the caller
	// can retry with a fresh token; the retry budget is the provisioner's, not
	// the driver's.
	CreateAccount(ctx context.Context, req CreateRequest) (*Account, error)

	// InstallCredential installs one credential on an account this driver
	// created. The kind must be one the platform accepts
	// (Capabilities.CredentialKinds); anything else is ErrUnsupported and never
	// a substitution of the other kind.
	InstallCredential(ctx context.Context, req CredentialRequest) error

	// RemoveAccount removes an account this proxy created. It must be
	// IDEMPOTENT: teardown runs on the normal path, on error, and from the
	// reaper, and an account that is already gone is a success, not a failure.
	RemoveAccount(ctx context.Context, req RemoveRequest) error

	// ListAccounts enumerates the accounts on the device that belong to this
	// proxy, so the reaper can find what a crashed session left behind.
	//
	// "Belong to this proxy" is decided by the name prefix in req, never by the
	// driver's own guess: one proxy's reaper deleting another's live accounts
	// on a shared device is the failure this argument exists to prevent.
	ListAccounts(ctx context.Context, req ListRequest) ([]Account, error)
}

// Endpoint is the device an operation is performed against, and the identity of
// the session performing it.
//
// Every request below embeds one rather than the driver holding a connection,
// because a driver is a description of a platform and not a session: the same
// driver serves every device of its kind, and the reaper reaches devices no
// session is currently using.
type Endpoint struct {
	// Host is the device's hostname or IP, as Hoplock Control routed it.
	Host string
	// Port is the device's management port.
	Port int
	// SessionID correlates every operation with the session that caused it,
	// which is what makes the mapping event in PLAN §5.3 joinable.
	SessionID string
	// HostKeyCallback is the host-key policy for the driver's own privileged
	// connection to the device (D7).
	//
	// It is here for the same reason target.Target carries one: host trust is a
	// management-server decision and the proxy holds it, so a driver BORROWS it
	// rather than inventing one. A driver that opens a connection with no
	// policy at all is the most privileged connection this proxy makes,
	// unauthenticated in one direction.
	//
	// A session hands down its own callback; teardown and every reaper sweep
	// pin to the key that connection already saw, because removing an account
	// must not depend on Hoplock Control being reachable (PLAN §5.1, and the
	// same rule target.pin implements for the POSIX path).
	//
	// It is typed on SSH because every driver in this repository speaks SSH. A
	// future driver on another transport ignores it, which is honest: it has
	// its own trust decision to describe, and describing it as an SSH callback
	// would be worse than leaving this field unread.
	HostKeyCallback ssh.HostKeyCallback
}

// CreateRequest asks a driver to create one short-lived administrator.
type CreateRequest struct {
	Endpoint
	// Name is the account name, already constrained to what
	// Capabilities.MaxAccountNameLen allows. The naming scheme is PLAN §5.3's
	// and belongs to the provisioner (phase 0014): a driver never invents,
	// truncates, or "fixes" a name, because the reaper prefix and the
	// uniqueness token are load-bearing and a driver cannot know which half it
	// just shortened.
	Name string
	// Profile is the platform's own authorization scope for the account — an
	// access profile, a role, a privilege level. It is opaque to this package;
	// what the string means is the platform's business.
	Profile string
	// SourceAddress optionally pins the account to the address it may be used
	// from. It is set only when Capabilities.PinsSourceAddress is true; a
	// driver that cannot pin must report ErrUnsupported rather than creating an
	// unpinned account, which would silently drop a restriction.
	SourceAddress string
	// Lifetime is how long the account should live, and it is set ONLY when
	// the DEVICE is to hold that deadline — when the route asked for
	// control.ExpiryPostureTargetEnforced and this driver declares
	// Capabilities.EnforcesExpiry. A driver that receives one renders it; a
	// driver that receives zero renders nothing, and the proxy holds the
	// deadline instead.
	//
	// The provisioner decides which of those it is, and that placement is
	// deliberate (phase 0017). Rendering expiry on FortiOS means a SECOND
	// OBJECT on a customer's firewall per session, so "does this route want the
	// device to hold the deadline" must be answered in the one place that reads
	// the route and the declaration together — not inside each driver, where a
	// proxy-enforced route would start quietly paying for a device object it
	// never asked for and the audit record would say `proxy-enforced` about a
	// deadline the device is also holding.
	Lifetime time.Duration
	// Fields are the route's platform-specific fields, keyed without the
	// contract's namespace prefix (control.ParamDeviceFieldPrefix). Every key
	// here was checked against Capabilities.Fields before the driver was
	// reached, so a driver may treat an undeclared one as a programming error
	// rather than as policy.
	//
	// They ride on CREATION and not on the other three operations, and that is
	// a statement about what these fields are for on the platforms this
	// repository serves: a VDOM scopes the administrator being created, while
	// removal, enumeration and credential installation address the same
	// administrator table on the same unit whatever it was scoped to. A
	// platform where the field selects a DIFFERENT MANAGED DEVICE — a
	// FortiLink-attached switch behind its FortiGate — needs them on the rest
	// too, and that is the phase that adds them, on the reaper's terms: it
	// sweeps a device it reaches from an endpoint, not from a route.
	Fields map[string]string
}

// CredentialRequest asks a driver to install one credential on an account it
// created.
type CredentialRequest struct {
	Endpoint
	// Name is the account created by CreateAccount.
	Name string
	// Kind selects which of the two fields below carries the credential.
	Kind control.CredentialKind
	// Password is the generated password, set only for
	// control.CredentialKindPassword. It is credential material: it is never
	// logged, never echoed in an error, and never written to disk (PLAN §7).
	Password string
	// PublicKey is the generated public key in OpenSSH authorized_keys form,
	// set only for control.CredentialKindPublicKey.
	PublicKey string
}

// RemoveRequest asks a driver to remove one account.
type RemoveRequest struct {
	Endpoint
	// Name is the account to remove. Removing an account that is already gone
	// is a success.
	Name string
}

// ListRequest asks a driver to enumerate this proxy's accounts on a device.
type ListRequest struct {
	Endpoint
	// Prefix selects the accounts that belong to this proxy — PLAN §5.3's
	// "hl-" plus the proxy tag. A driver returns only accounts whose name
	// starts with it and never widens the selection.
	Prefix string
}

// Account is one account on a device, as a driver sees it.
type Account struct {
	// Name is the account name on the device.
	Name string
	// Profile is the platform's authorization scope, if the platform reports
	// one. Empty means the driver could not tell, not that there is none.
	Profile string
	// CreatedAt is when the device says the account was created. It is the zero
	// time when the platform does not record it — most do not — and the reaper
	// must therefore treat a zero value as "age unknown" rather than as
	// "created at the epoch, sweep it now".
	CreatedAt time.Time
}

// Capabilities is what a driver DECLARES about its platform (PLAN §5.3).
//
// Declarations are DATA, NOT BEHAVIOUR. A driver states them and the
// provisioner reads them, so that phase 0014's decisions — which naming scheme,
// which expiry posture, refuse or serve — are made in ONE place against a
// uniform description, rather than separately inside each driver where they
// would drift and could not be reviewed together. A driver that decided any of
// those for itself would be a driver whose refusals nobody could audit.
//
// They must also be answerable WITHOUT CONNECTING. The provisioner reads them
// to decide whether a route is servable at all, which it must be able to do
// before it opens anything — including for a ladder rung it is about to skip.
type Capabilities struct {
	// MaxAccountNameLen is the longest administrator name the platform
	// accepts. It selects the naming scheme (PLAN §5.3): at 32 or more the
	// readable `hl-<tag>-<login>-<token>` scheme is used unchanged; between 11
	// and 31 the login segment is dropped and the reaper prefix and uniqueness
	// token are kept; below 11 the route is refused. Zero means undeclared,
	// which is refused rather than assumed generous.
	MaxAccountNameLen int
	// EnforcesExpiry says the DEVICE expires the account on its own, whether or
	// not this proxy is alive to remove it — the equivalent of OpenSSH's
	// expiry-time restriction (PLAN §5.1). It is what makes
	// control.ExpiryPostureTargetEnforced satisfiable; a route demanding that
	// posture from a driver declaring false is a skipped ladder rung.
	EnforcesExpiry bool
	// ExpiryMechanism says WHAT the device does when the deadline passes, in
	// one line. It is required on a driver that declares EnforcesExpiry and
	// ignored otherwise, and CheckShipped holds a shipped driver to that.
	//
	// It exists because EnforcesExpiry is one bit and the platforms behind it
	// do not agree on what the bit means. OpenSSH's expiry-time (PLAN §5.1)
	// refuses new authentications and leaves an established session running;
	// FortiOS's `set schedule` refuses new authentications, leaves the ACCOUNT
	// on the device for the reaper, and says nothing anywhere about a session
	// already open. Both are honestly "the device ends the account's usefulness
	// whether or not the proxy is alive", and neither is "the device cuts the
	// session at T" — which is what a reader of the bit alone would assume.
	//
	// It is a string for PersistenceReason's reason, and it reaches the
	// operator through the same route: the provisioning record, on every
	// session the driver serves. A posture in an audit record that says
	// `target-enforced` without saying what the target enforces is a record
	// that cannot answer the only question anybody asks of it afterwards.
	ExpiryMechanism string
	// PersistsAcrossReload says account creation survives a device reload —
	// that the driver writes the account to saved configuration.
	//
	// D13 originally forbade a HOPLOCK-SHIPPED driver from declaring true: a
	// reload would then be a free reaper, and the product's claim of no
	// standing accounts would survive a crashed proxy. Phase 0014 found that
	// rule unsatisfiable on the very platform D13 named as its example.
	// FortiOS has no runtime-only configuration plane — `end` writes to flash
	// under the default `cfg-save automatic`, and the alternatives are
	// device-wide settings that change every other change on the unit — so a
	// FortiGate driver can be honest or it can ship, and a driver that declares
	// false while persisting is the worse of the two by a distance.
	//
	// So the rule became: a shipped driver may declare true when the PLATFORM
	// leaves it no choice, and must say WHY in PersistenceReason. What is still
	// forbidden is a driver that persists BY CHOICE, silently. CheckShipped
	// enforces that, and the provisioner records the declaration on every
	// session such a driver serves.
	PersistsAcrossReload bool
	// PersistenceReason says why the platform gives the driver no choice about
	// PersistsAcrossReload. It is required on a shipped driver that declares
	// persistence and ignored otherwise.
	//
	// It is a string rather than a second bool because the point is
	// REVIEWABILITY: another flag would be one more thing to flip, whereas a
	// sentence naming the platform mechanism ("FortiOS commits to flash on
	// `end`; cfg-save is device-wide") is a claim somebody can check against
	// the vendor's documentation. It reaches the operator surface through the
	// provisioning record, so a standing-account risk is stated where the risk
	// is taken.
	PersistenceReason string
	// CredentialKinds are the credentials the platform accepts. The route's
	// control.ParamCredentialKind must be one of them; a route naming one that
	// is not is a skipped rung, never a substitution of the other kind, because
	// a password and a public key have materially different exposure and the
	// server chose.
	CredentialKinds []control.CredentialKind
	// CommandAuthorization names the platform's OWN command authorizer, in one
	// line: what it is called on this platform, and what binds an account to
	// it. It is what makes control.ExecutionPlatformAuthorized satisfiable
	// (PLAN §6.5, phase 0019) — a driver declaring nothing here has no
	// mechanism that delivers that guarantee, and a route naming the rung is a
	// SKIPPED LADDER RUNG on this platform rather than a session run without
	// the rung.
	//
	// It is a string rather than a bool for ExpiryMechanism's reason. "The
	// device authorizes commands" is one bit and the platforms behind it do not
	// agree on what the bit buys: a FortiOS access profile, an IOS privilege
	// level, a Junos login class and a parser view group commands in different
	// ways and at different granularities, and the rung's whole failure mode is
	// the vendor's grouping. A reader of the bit alone would take
	// `platform-authorized` for something finer than any vendor sells.
	CommandAuthorization string
	// AuthorizationCaveat says how the platform's authorizer LEAKS BY GROUPING,
	// in one line. It is required on a driver declaring CommandAuthorization
	// and ignored otherwise, and CheckShipped holds a shipped driver to that.
	//
	// Vendor RBAC is coarse and named (PLAN §6.5): a profile permitting
	// diagnostics may include a command with a shell escape, and one permitting
	// "read-only" may still include a configuration write on some releases. The
	// provisioner puts this on the session's audit record, so that the record
	// carries what the rung is ACTUALLY enforcing rather than the name of the
	// guarantee it was asked for.
	AuthorizationCaveat string
	// PinsSourceAddress says an account can be restricted to the address it is
	// used from. It is a free extra restriction where it exists and is not
	// required anywhere.
	PinsSourceAddress bool
	// Fields are the PLATFORM-SPECIFIC fields this driver accepts on a route
	// (control.ParamDeviceFieldPrefix, contract v3.1, phase 0016).
	//
	// They exist because some devices are not one target: a FortiGate running
	// virtual domains is one unit partitioned into many, and a route has to be
	// able to say which partition a session administers. The contract carries
	// such a field as data and does not interpret it; this declaration is what
	// says which ones mean anything here.
	//
	// It is a DECLARATION and therefore answerable without connecting, like
	// every other value in this struct: the provisioner reads it to decide
	// whether a rung is satisfiable before it opens anything. A route naming a
	// field that is not declared here is a SKIPPED RUNG (D14) — an unknown
	// parameter may be a constraint, and a proxy that cannot honour one must
	// not connect — which is also what makes the namespace additive: a build
	// that predates a field declines the route rather than dropping it.
	//
	// Nil means the platform has none, which is the honest answer for a device
	// that is exactly one target.
	Fields []Field
}

// Field is one platform-specific route field a driver accepts.
//
// The description is not decoration: an operator reading a skipped rung wants
// to know what the field they misspelled was for, and a driver document (D13)
// generated from these declarations needs something to say about each one.
type Field struct {
	// Name is the field's name WITHOUT the contract's namespace prefix — the
	// `vdom` in `device_field.vdom`.
	Name string
	// Description says what the field means on this platform, in one line.
	Description string
}

// AuthorizesCommands reports whether the platform has an authorizer of its own
// that control.ExecutionPlatformAuthorized can be rendered onto.
func (c Capabilities) AuthorizesCommands() bool {
	return strings.TrimSpace(c.CommandAuthorization) != ""
}

// AcceptsField reports whether the platform accepts a route field of that name.
func (c Capabilities) AcceptsField(name string) bool {
	for _, f := range c.Fields {
		if f.Name == name {
			return true
		}
	}
	return false
}

// Accepts reports whether the platform accepts a credential kind.
func (c Capabilities) Accepts(kind control.CredentialKind) bool {
	for _, k := range c.CredentialKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// Residue is an object a driver created BESIDE an account, which outlives the
// account when a session dies at the wrong moment (phase 0017).
//
// It exists because ending an account's usefulness on a device is not always
// one object. A FortiGate expires an administrator through a `config firewall
// schedule onetime` entry that `set schedule` names, so a session that provides
// the target-enforced posture writes TWO objects and a crash between them
// leaves the second one behind. That is a new leak class, and a leak class with
// no sweep is a leak.
//
// It is deliberately NOT modelled as an account. The reaper's account sweep
// answers "is this administrator live", and a schedule is not something anybody
// can log in as: reporting one through ListAccounts would put an object on the
// operator's account records that is not an account, and would make the
// reaper's liveness question meaningless for half its input.
type Residue struct {
	// Name is the object's name on the device. It carries the same reaper
	// prefix the accounts do — that is what makes it sweepable at all.
	Name string
	// Kind names what the object is, for the log and the sweep-failure record:
	// "firewall schedule", not "account". An operator reading that a sweep
	// failed needs to know which object is still on their firewall.
	Kind string
}

// ResidueSweeper is implemented by a driver that creates such objects.
//
// It is an OPTIONAL interface rather than a fifth Driver method, and that is a
// judgement about who pays. Most platforms have no second object — a driver for
// one would implement a no-op, and the declarative driver document and
// subprocess contract D13 defers would each have to carry an operation that
// does nothing on nearly every platform. A driver that creates residue
// implements this; a driver that does not, does not, and the reaper asks.
//
// The two operations mirror ListAccounts and RemoveAccount exactly, including
// the rules that matter: the prefix in the request is the caller's and is never
// widened, and removal is idempotent because it runs from teardown, from the
// reaper, and from a retry after a failure.
type ResidueSweeper interface {
	// ListResidue enumerates objects this proxy created beside its accounts
	// that NO ACCOUNT ON THE DEVICE references any more.
	//
	// "No account references it" is the driver's to establish, because only the
	// driver knows what the reference looks like. What the driver must not do
	// is decide WHETHER to remove one: an object that is unreferenced right now
	// may be one another session created a round trip ago and is about to name,
	// so the reaper applies its own grace period to the answer, on the same
	// first-seen rule it ages an untracked account by.
	ListResidue(ctx context.Context, req ListRequest) ([]Residue, error)

	// RemoveResidue removes one object this proxy created. Like RemoveAccount
	// it is IDEMPOTENT: an object that is already gone is a success.
	RemoveResidue(ctx context.Context, req RemoveRequest) error
}

// ErrUnsupported means THIS PLATFORM CANNOT do what was asked — pin a source
// address, install a public key, expire an account — and no retry, no backoff,
// and no different device of the same kind will change that.
//
// It is the distinction phase 0014's provisioner branches on. An unsupported
// operation makes the ladder rung unsatisfiable and the proxy walks to the next
// one (D14); a failed attempt is an error on a rung the proxy could satisfy,
// and it fails the session rather than quietly degrading to a weaker rung the
// server ranked lower. Getting this backwards in either direction is a security
// bug: one turns a device outage into a silent downgrade, the other turns a
// permanent limitation into a session that never connects.
var ErrUnsupported = errors.New("auth/target/device: the platform does not support this operation")

// ErrAccountExists means an account of that name is already on the device.
//
// It is not an error the driver resolves. The device path deliberately differs
// from PLAN §5.1's idempotent treatment of an existing account: with a short
// uniqueness token an existing name is more plausibly another live session's,
// so the provisioner retries with a fresh token and never adopts.
var ErrAccountExists = errors.New("auth/target/device: an account of that name already exists")

// Unsupported returns an ErrUnsupported naming the driver and what it cannot
// do, so an operator reading the log learns which limitation skipped the rung.
func Unsupported(platform, what string) error {
	return fmt.Errorf("%w: %s cannot %s", ErrUnsupported, platform, what)
}
