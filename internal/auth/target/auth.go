// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/identity"
)

// Target is the host the proxy is about to log into on the user's behalf.
type Target struct {
	// Host is the target hostname or IP, as Hoplock Control routed it.
	Host string
	// Port is the target's SSH port.
	Port int
	// Auth is Hoplock Control's per-route choice of credential method and its
	// parameters (D6a, contract v2), copied off the authorize response. Nil
	// means the proxy's locally configured fallback method, which is what a v1
	// server implies.
	//
	// It travels on the target rather than in a second argument because the
	// server decides it per route, exactly as it decides the host and port: one
	// proxy routinely fronts a Linux estate that accepts just-in-time
	// provisioning and an appliance estate that can never create a user, so
	// "where" and "how" are answered together or not at all.
	Auth *control.TargetAuth
	// HostKeyCallback is the session's target host-key policy (D7). An
	// implementation that opens its own connection to the target — the
	// ephemeral provisioner's management login is the one that does — must use
	// it rather than inventing a trust decision of its own.
	//
	// It is the mirror of the rule below on ProvisionedAccess.ClientConfig: host
	// trust belongs to the proxy in both directions, and this field is how a
	// provisioner borrows it instead of duplicating it.
	HostKeyCallback ssh.HostKeyCallback
	// Ladder is the ORDERED list of credential methods Hoplock Control named
	// for this route (D14, contract v3). The Selector walks it top-down,
	// setting Auth to each rung in turn, and stops at the first one this proxy
	// can satisfy.
	//
	// The pointer carries three states and they are not interchangeable: nil is
	// "the server named none", a non-nil empty ladder is A DENIAL, and a
	// non-empty one is the list to walk. Phase 0013's contract types make the
	// same distinction for the same reason — collapsing empty into absent turns
	// a denial into a connection on the proxy's own credential.
	Ladder *control.TargetAuthLadder
	// SessionID identifies the session this provisioning belongs to. The device
	// method needs it: on a constrained platform the mapping event is the only
	// place the account is tied to anything, and an event that cannot be joined
	// to a session is not attribution (PLAN §5.3).
	SessionID string
	// Rung is which entry of Ladder produced Auth, counting from one. It is set
	// by the Selector and read for the audit record: D14 makes the rung in
	// force an audit fact, and the user is told nothing about it.
	Rung int
	// Enforcement is WHERE this route's policy is enforced, on each of the two
	// axes (contract v4, PLAN §6.5, phase 0019), together with the allow-list
	// an execution rung renders.
	//
	// It travels on the target for the reason Auth does: the server decides it
	// per route, and rendering it is something only the party that provisions
	// the account can do. Nil means both axes take their absent-value default —
	// proxy-side enforcement only, which is exactly a v3 server's behaviour.
	Enforcement *Enforcement
}

// Addr is the "host:port" to dial.
func (t Target) Addr() string { return net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) }

// String implements fmt.Stringer.
func (t Target) String() string { return t.Addr() }

// TargetAuthenticator produces the credentials the proxy uses to log into a
// target, and guarantees teardown of anything it provisioned (PLAN §4.2).
//
// It is the mirror of the user→proxy plane (D4): both take and return an
// identity rather than a boolean, so AD/Okta claims decide what the proxy may
// assume on the far side without any caller changing.
//
// The name repeats the package name because it names the *plane*
// (proxy→target), as PLAN §4.2 fixes it; its counterpart is
// user.UserAuthenticator.
type TargetAuthenticator interface {
	// Name identifies the implementation for logging and metrics.
	Name() string
	// Provision prepares just-in-time access for id on target and returns the
	// SSH client configuration to dial with, plus its teardown.
	//
	// Implementations must leave HostKeyCallback unset: which target host keys
	// are trusted is a management-server decision (D7), and the proxy — which
	// holds the session's management client and its connection metadata — is
	// what fills it in. A credential provider that also decided host trust
	// would be two policies in one place.
	Provision(ctx context.Context, id *identity.Identity, target Target) (*ProvisionedAccess, error)
}

// ProvisionedAccess is one session's credentials plus the promise to remove
// them again.
type ProvisionedAccess struct {
	// ClientConfig dials the target. HostKeyCallback is set by the proxy.
	ClientConfig *ssh.ClientConfig
	// Teardown removes whatever Provision created. It MUST be safe to call more
	// than once and MUST run even if the session crashed; callers use Close,
	// which enforces the once-only part for every implementation.
	Teardown func(context.Context) error
	// Method is the credential method that actually provisioned this access,
	// and Rung is its position in the server's ladder, counting from one (D14).
	//
	// They exist because the ladder makes "which credential did this session
	// get" a question with more than one possible answer, and the audit record
	// has to name the entry that was USED rather than the entry that was asked
	// for. It is an audit fact and never a user-facing one: telling a user they
	// got the weaker credential tells an attacker which targets are softest and
	// tells an honest user nothing they can act on (D14).
	Method string
	Rung   int
	// Enforcement is what was ACTUALLY rendered on the target, never what the
	// route asked for (PLAN §6.5, phase 0019). Nil means the provisioner did
	// not answer, and the Selector fills it in from the method's own
	// capabilities rather than leaving the audit record silent.
	Enforcement *EnforcementResult

	once sync.Once
	err  error
}

// Close runs Teardown exactly once and returns its result on every call.
//
// It exists so that "teardown is idempotent" is a property of this type rather
// than a rule each implementation has to re-implement correctly: a session can
// tear down on the normal path, on error, and from a reaper without deleting a
// user another session has since created.
func (p *ProvisionedAccess) Close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	p.once.Do(func() {
		if p.Teardown != nil {
			p.err = p.Teardown(ctx)
		}
	})
	return p.err
}

// ErrUnknownMethod is returned when configuration names a target
// authentication method this build does not have.
var ErrUnknownMethod = errors.New("auth/target: unknown target authentication method")
