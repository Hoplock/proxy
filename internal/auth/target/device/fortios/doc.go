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
// Phase 0014 established these from WEB-SEARCH SUMMARIES of Fortinet's
// documentation, because its session could not reach docs.fortinet.com. Phase
// 0015 re-checked all ten claims against the pages themselves and wrote the
// result up in docs/FORTIOS-DOC-VERIFICATION.md, with the page, the versions
// and the wording behind each verdict. Six held, three were wrong, one is true
// but undocumented, and the same reading found a gap none of them covered.
// Read that file before trusting or changing anything below; what follows is
// the corrected list, not the original one.
//
//   - An administrator name field accepts 64 characters (`config system admin`
//     / `name`, `Maximum length: 64`). 0014 declared 35, which is the figure
//     the naming-rules KB gives for "most name fields" and the right one for
//     `accprofile` and `schedule` — not for this field. Both clear PLAN §5.3's
//     threshold of 32, so FortiOS gets the READABLE naming scheme either way
//     and the constrained scheme is exercised here only by tests. That is worth
//     knowing before assuming the constrained path is dead code: it is not, it
//     is the path every tighter platform will take.
//   - There IS a per-administrator expiry mechanism, and 0014 said there was
//     not. `set schedule` points at a `config firewall schedule onetime` entry
//     with an absolute `set end`, and FortiOS denies the login when the window
//     has closed. This driver still declares Capabilities.EnforcesExpiry false,
//     but by DECISION — see the reasoning on Capabilities — and a route
//     demanding control.ExpiryPostureTargetEnforced is still a skipped rung.
//   - FortiOS documents THREE built-in access profiles, not four: `super_admin`
//     (immutable), `prof_admin` (editable), and `super_admin_readonly`
//     (immutable, assignable, and absent from the GUI's profile list).
//     `prof_admin_readonly` appears in no Fortinet source. There is therefore
//     no default access profile here at all; the route or the proxy's
//     configuration names one.
//   - An administrator carries a password AND up to three SSH public keys, and
//     the two do not exclude one another — Fortinet's own procedure sets both
//     in one `edit`. Turning password login off is `config system global` /
//     `set admin-ssh-password`, device-wide, so this driver never touches it.
//   - `config system console` defaults to paging (`set output more`) and is a
//     PERMANENT, device-wide setting rather than a per-session one, so the
//     driver must page through `--More--` rather than turn paging off — turning
//     it off would be a configuration change on a customer's device that nobody
//     asked for. netmiko saves and restores the global value for exactly this
//     reason. Two details worth knowing: the setting governs `show`, `get` and
//     `?` output but NOT debug or sniffer output, and changing it needs a
//     privileged profile the accounts this driver creates will not have.
//   - FortiOS reports failures as OUTPUT TEXT ("Command fail. Return code -1",
//     "Entry not found in datasource", "Command parse error before '…'"), not
//     as an exit status. There is no exit status to read: the whole
//     conversation happens inside one shell channel.
//   - Configuration is written to flash on `end` under the default
//     `set cfg-save automatic`. FortiOS has NO runtime-only configuration
//     plane, so an administrator created here SURVIVES A RELOAD and
//     Capabilities.PersistsAcrossReload is true. See the type's own comment,
//     and D13 in docs/PLAN.md, which phase 0014 amended to say so.
//   - `trusthost1` pins an administrator to a source address and defaults to
//     `0.0.0.0 0.0.0.0`, which allows any IPv4 address. It has a parallel that
//     0014 missed: `ip6-trusthost1`..`10` default to `::/0`. A pin that sets
//     only the IPv4 field is not a pin, so this driver writes both — and
//     refuses an IPv6 source address rather than writing one into an
//     `ipv4-classnet` field (see trustHost).
//
// # The unit shapes this driver serves
//
// One: a single-VDOM FortiGate. A unit running virtual domains keeps the
// administrator table inside `config global`, requires `set vdom` for a
// VDOM-scoped account, and does not accept `super_admin_readonly` for one — a
// different command sequence at a different nesting depth, which phase 0014
// neither sent nor detected. This driver reads `get system status` when it
// opens a session and refuses anything but `disable` (ErrMultiVDOM), because
// D13's rule is that an unsupported configuration is an outage-class denial and
// never a best-effort attempt. Supporting virtual domains is a queued phase,
// and it starts with a contract question — what a "target" is when one unit
// holds many — rather than with a command sequence.
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
