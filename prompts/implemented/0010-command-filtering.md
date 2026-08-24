# 0010 — Command filtering & policy actions

> Renumbered from 0009 (`docs/PLAN.md` §10, renumbering note). Scope grew: this
> phase now ships **restricted exec** (D12) alongside the pattern rule list.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — especially §2 (D5, **D12**), §4.3 (what the user is told),
  §6.3 (the three tiers: restricted exec / filtered exec / interactive).
- `docs/learnings/` — read summaries; open `0009` (how to attach an inspector),
  `0006` (the filter policy shape, including restricted exec) and `0002` (the
  original rule-list shape).

## Objective
Implement command policy as inspectors on the 0009 pipeline, in the two exec
tiers D12 defines plus best-effort interactive inspection — and keep the three
apart in the code, in the audit record, and in the documentation.

## In scope

### The policy engine (`internal/filter`)
Pure logic, no SSH types, exhaustively unit-tested in isolation.

- **Filtered exec (guardrail).** Hoplock Control supplies an **ordered
  rule list** — each rule a `match` pattern with **its own action**
  (`allow_and_log`, `block_command`, `warn_and_continue`, `kill_session`) and an
  optional operator `message` — plus a **mode** (`whitelist` | `blacklist`)
  deciding commands no rule matched. **First match wins**, so evaluation order is
  part of the contract, not an implementation detail: `rm -rf /` placed before
  `rm *` must decide. Mode is the fallback for an unmatched command
  (`whitelist` blocks, `blacklist` allows), so there is always a defined answer.
- **Restricted exec (boundary, D12).** The policy names permitted executables
  together with the shape of their permitted arguments (0006's schema). The
  command is **parsed into argv, not pattern-matched**; anything not named is
  denied; arguments not covered by a shape are denied. No shell is interposed to
  re-expand what was approved — the command that runs is the argv that was
  approved.
  - Parsing is adversarial input. Quoting, escapes, embedded newlines, NUL, and
    non-UTF-8 all arrive here. A command that cannot be parsed unambiguously is
    **denied**, never "best-effort matched" — an ambiguous parse in a
    default-deny boundary is the whole vulnerability class.
  - The engine reports which tier decided, so the audit record can distinguish a
    boundary from a guardrail.
- The two are **alternatives per connection, not layers** (0006 rejects a policy
  setting both).

### The exec inspector (attached via 0009)
Extracts the command from the `exec` request and applies the policy **before**
forwarding.
- `block_command`: refuse the exec with a message on stderr saying it was
  **blocked by policy** and a non-zero exit status — never a silent failure or
  a bare close, which is indistinguishable from a broken command (PLAN §4.3).
- `kill_session`: tell the user the session is being terminated by policy,
  then terminate it.
- `warn_and_continue`: send a warning back to the user, allow the command.
- `allow_and_log`: allow, emit an audit event.
- Restricted-exec denial uses the `block_command` presentation.

Per PLAN §4.3 the user learns **that** policy stopped them, never the policy's
contents: no echoing of the list, the mode, the permitted executables, or which
pattern matched. That detail belongs in the audit event, not on the terminal.

### The shell/pty inspector
Best-effort inspection of the interactive stream for audit/alerting. Must be
clearly documented as **not hard enforcement** (line-editing, encodings, and
shell tricks bypass it). Reasonable heuristics only; never block the interactive
path in ways that corrupt the pty.

### Audit
Every match emits a **distinct audit event** flagged for **immediate** delivery,
recording the tier that decided (0011 consumes this; until then emit through the
existing basic logging with a clear "critical/immediate" marker and a stable
event shape 0011 can pick up).

## Out of scope
- The batching/priority/buffer transport for logs (0011) — just produce the
  events with the right shape and priority flag.
- Contract changes (0006 defined the policy shape).

## Acceptance criteria
- Unit tests for the rule engine across both modes and all four actions,
  including: a policy whose rules carry **different** actions applies each one
  to its own command; the first matching rule wins when two patterns overlap;
  and an unmatched command falls to the mode's default (blocked under
  `whitelist`, allowed under `blacklist`).
- Unit tests for restricted exec: an approved executable with an approved argv
  runs; the same executable with an argument outside its shape is denied; an
  unnamed executable is denied; and **a command that does not parse
  unambiguously is denied** (quoting, embedded NUL, invalid UTF-8).
- **A bypass test that documents the difference between the tiers**: with a
  filtered-exec policy denying `cat /etc/shadow`, assert that
  `sh -c 'cat /etc/shadow'` reaches the target (the guardrail's honest limit),
  and that under a restricted-exec policy naming only `cat` the same command is
  denied. This test is the executable form of D12 and must not be softened —
  if it ever fails, either the boundary broke or the guardrail started making a
  promise it cannot keep.
- A test asserts a blocked command produces user-visible text plus a non-zero
  exit status, and that neither the matched pattern, the permitted-executable
  list, nor the mode appears in what the user sees.
- Integration tests: a blacklisted `exec` is blocked; a whitelisted-only `exec`
  outside the list is blocked; `warn_and_continue` warns but runs;
  `kill_session` ends the session; `allow_and_log` emits an audit event;
  restricted exec allows and denies end to end.
- An interactive-session test shows a flagged command produces an audit event
  (best-effort), and confirms the pty stream is not corrupted by inspection.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0010-command-filtering-learnings.md`. Summary block MUST document
the audit-event shape + priority flag + tier marker (so 0011 consumes it), the
enforcement guarantees in D12's three tiers and the exact words used for each,
and the config/policy inputs.
