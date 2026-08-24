// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package inspect

import "github.com/hoplock/proxy/internal/channel"

// SessionChannel is the SSH channel type command policy attaches to. Commands
// arrive nowhere else: a port forward carries a destination, not a command
// (PLAN §6.2).
const SessionChannel = "session"

// Register attaches both inspectors to a session's registry, in the order they
// must run: the enforcing exec inspector first, so that a command it refuses is
// refused whatever the observer would have said about it.
//
// The registry is the per-session layer (channel.Registry.Clone): the policy
// these inspectors carry is per connection (D2), so they cannot live in the
// proxy-wide registry that every session shares.
func Register(reg *channel.Registry, opts Options) {
	reg.Register(SessionChannel, NewExec(opts), NewInteractive(opts))
}
