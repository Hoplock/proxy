// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

// Package filter implements the command policy engine: the two exec tiers D12
// defines, and the best-effort interactive tier that is neither (PLAN §6.3).
//
// The package is pure logic. It holds no SSH types, opens nothing, and writes
// nothing: it answers "what does this connection's policy say about this
// command string", and internal/filter/inspect turns that answer into SSH.
// That separation is what lets the tier that is sold as a security boundary be
// tested exhaustively against the strings an attacker actually sends.
//
// The three tiers, named as PLAN §6.3 names them and as the audit record
// records them:
//
//   - TierRestricted — a BOUNDARY. The server names permitted executables and
//     the shape of their arguments; the command is parsed into an argument
//     vector rather than pattern-matched; anything not named is denied; a
//     command that cannot be parsed unambiguously is denied.
//   - TierFiltered — a GUARDRAIL. An ordered rule list is matched against the
//     whole exec string, first match wins, and the mode decides what no rule
//     matched. Every command is seen before it runs, and "sh -c", any
//     interpreter, and any encoding still get past a pattern.
//   - TierInteractive — an AUDIT SIGNAL. Line editing, encodings, and shell
//     escapes defeat it by construction, so it reports and never enforces.
//
// The two exec tiers are alternatives per connection, not layers: a policy
// setting both is a contract violation (D12), refused by New rather than
// resolved.
package filter
