// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

// Package fortios implements the ephemeral-account device drivers for
// Fortinet's FortiOS CLI (D13, PLAN §5.3).
//
// It is the first driver in the system, and it exists to prove the claim D13
// makes: that a FortiGate cannot run useradd and has no authorized_keys, but
// CAN create an administrator, scope it to an access profile, pin it to a
// source address, give it a credential, and delete it again — the same
// operations PLAN §5.1 performs on a POSIX host, in a different vocabulary over
// a different transport.
//
// # What was verified, and against what
//
// Phase 0014's prompt required these to be established from Fortinet's current
// documentation rather than from memory, because each one changes the driver.
// The findings and their sources are recorded in
// docs/learnings/0014-fortios-device-drivers-learnings.md; the ones that shaped
// the code are:
//
//   - An administrator name field accepts 35 characters, which is above PLAN
//     §5.3's threshold of 32, so FortiOS gets the READABLE naming scheme and the
//     constrained scheme is exercised here only by tests. That is worth knowing
//     before assuming the constrained path is dead code: it is not, it is the
//     path every tighter platform will take.
//   - There is no per-administrator expiry field. FortiOS cannot expire an
//     account on its own, so Capabilities.EnforcesExpiry is false and a route
//     demanding the target-enforced posture is a SKIPPED RUNG rather than a
//     session served on a promise nobody keeps.
//   - An administrator carries a password AND up to three SSH public keys, and
//     the two do not exclude one another. Turning password login off is
//     `config system global`, device-wide, so this driver never touches it.
//   - `config system console` defaults to paging (`set output more`) and is a
//     PERMANENT setting rather than a per-session one, so the driver must page
//     through `--More--` rather than turn paging off — turning it off would be a
//     configuration change on a customer's device that nobody asked for.
//   - FortiOS reports failures as OUTPUT TEXT ("Command fail. Return code -3",
//     "entry not found in datasource", "value parse error before '…'"), not as
//     an exit status. There is no exit status to read: the whole conversation
//     happens inside one shell channel.
//   - Configuration is written to flash on `end` under the default
//     `set cfg-save automatic`. FortiOS has NO runtime-only configuration
//     plane, so an administrator created here SURVIVES A RELOAD and
//     Capabilities.PersistsAcrossReload is true. See the type's own comment,
//     and D13 in docs/PLAN.md, which this phase amended to say so.
//
// # Why the command sequences are data
//
// D13 defers the declarative driver document and its subprocess contract, and
// says both arrive later as implementations of device.Driver. The command
// sequences here are therefore written as tables of steps rather than as
// procedural code with strings in it, so that the document format can be
// EXTRACTED from them rather than retrofitted against them. What is not data —
// and deliberately so — is the value validation: a configuration parser on the
// far end means a mis-escaped value is a configuration change nobody asked for,
// and that check belongs in code that a document cannot switch off.
package fortios
