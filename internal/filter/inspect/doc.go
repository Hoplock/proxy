// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

// Package inspect attaches the command policy engine to the channel inspection
// pipeline (PLAN §6.2, §6.3).
//
// It is the SSH-facing half of internal/filter, and the split is deliberate:
// the engine decides, this package translates. Everything here is about where a
// command is found in the SSH protocol, what the user is told about it, and
// what the audit record says — never about what the policy means.
//
// Two inspectors live here, and keeping them apart is the point of D12:
//
//   - Exec inspects the "exec" request, where the whole command is available
//     before anything runs. It ENFORCES: it blocks, warns, and ends sessions,
//     in whichever of the two exec tiers the policy selected.
//   - Interactive reconstructs command lines from an interactive stream. It
//     REPORTS AND NOTHING ELSE. It never denies a request, never writes to the
//     stream, and never alters a byte, because line editing, encodings, and
//     shell escapes defeat keystroke inspection by construction, and a
//     guarantee that can be defeated by pressing the left-arrow key must not be
//     sold — or implemented — as enforcement.
package inspect
