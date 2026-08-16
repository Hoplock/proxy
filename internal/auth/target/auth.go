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

	"github.com/mauroasilva/securecommandproxy/internal/identity"
)

// Target is the host the bastion is about to log into on the user's behalf.
type Target struct {
	// Host is the target hostname or IP, as the management server routed it.
	Host string
	// Port is the target's SSH port.
	Port int
}

// Addr is the "host:port" to dial.
func (t Target) Addr() string { return net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) }

// String implements fmt.Stringer.
func (t Target) String() string { return t.Addr() }

// TargetAuthenticator produces the credentials the bastion uses to log into a
// target, and guarantees teardown of anything it provisioned (PLAN §4.2).
//
// It is the mirror of the user→bastion plane (D4): both take and return an
// identity rather than a boolean, so AD/Okta claims decide what the bastion may
// assume on the far side without any caller changing.
//
// The name repeats the package name because it names the *plane*
// (bastion→target), as PLAN §4.2 fixes it; its counterpart is
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
