// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

// Package relay carries next-hop sessions over connections a downstream proxy
// opened to its upstream (D11, PLAN §6.1).
//
// A proxy in a protected zone cannot be dialled: an inbound firewall rule per
// enclave is the objection this architecture exists to remove, not to charge
// per zone. So the direction is inverted, exactly as it already is for the
// revocation stream one layer up (PLAN §6.4): the downstream proxy REGISTERS
// with its upstream over a long-lived outbound SSH connection, and the upstream
// opens a channel over that registration whenever a route sends a session that
// way. The protected zone needs no inbound rule at all.
//
// Two halves live here:
//
//   - Hub is the upstream side. It listens for registrations, authenticates
//     each registering proxy against the fleet's keys or CA (a registration is
//     an inbound path into this proxy's routing, so an unauthenticated one is a
//     way to receive other people's sessions), keeps one registration per proxy
//     id, and hands out net.Conns to the engine through Open.
//   - Registrar is the downstream side. It keeps one outbound registration open
//     with backoff, and serves every channel the upstream opens over it as if
//     it were an inbound client connection.
//
// Nothing here decides anything. Which sessions travel this way is the route's
// hop.connection (D11), and a relay hop with no live registration is an outage,
// never a dial: downgrading it would punch through the boundary the mode exists
// to preserve.
package relay
