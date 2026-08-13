# 0008 — Command filtering & policy actions

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — especially §2 (D5), §6.3 (filtering: whitelist/blacklist +
  actions; exec-enforced vs interactive best-effort).
- `docs/learnings/` — read summaries; open `0007` (how to attach an inspector),
  `0002` (filter policy shape in the route response).

## Objective
Implement command filtering as inspectors on the 0007 pipeline. The management
server supplies, per connection, the **mode** (`whitelist` | `blacklist`), the
**list**, and the **action on match** (`allow_and_log`, `block_command`,
`warn_and_continue`, `kill_session`). Enforce reliably on `exec`; best-effort on
interactive `shell`.

## In scope
- `internal/filter`: pure policy engine — given (mode, list, command string) →
  match decision; given (action, match) → effect. Well-unit-tested in isolation.
- An **exec inspector** (attached via 0007): extracts the full command from the
  `exec` request and applies the policy **before** forwarding. This path is
  **enforced**.
  - `block_command`: refuse the exec (clean error to the client).
  - `kill_session`: terminate the whole session.
  - `warn_and_continue`: send a warning back to the user, allow the command.
  - `allow_and_log`: allow, emit an audit event.
- A **shell/pty inspector**: best-effort inspection of the interactive stream for
  audit/alerting. Must be clearly documented as **not hard enforcement**
  (line-editing, encodings, and shell tricks can bypass it). Reasonable heuristics
  only; do not block the interactive path in ways that corrupt the pty.
- Every match emits a **distinct audit event** flagged for **immediate** delivery
  (the logging pipeline in 0009 consumes this; until then, emit through the
  existing basic logging with a clear "critical/immediate" marker and a stable
  event shape 0009 can pick up).
- Filter policy is read from the authorize+route response (0002 shape); no
  hard-coded lists.

## Out of scope
- The batching/priority/buffer transport for logs (0009) — just produce the
  events with the right shape and priority flag.

## Acceptance criteria
- Unit tests for the policy engine across both modes and all four actions.
- Integration tests: a blacklisted `exec` is blocked; a whitelisted-only `exec`
  outside the list is blocked; `warn_and_continue` warns but runs;
  `kill_session` ends the session; `allow_and_log` emits an audit event.
- An interactive-session test shows a flagged command produces an audit event
  (best-effort), and confirms the pty stream is not corrupted by inspection.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0008-command-filtering-learnings.md`. Summary block MUST document
the audit-event shape + priority flag (so 0009 consumes it), the enforcement
guarantees (exec = enforced, interactive = best-effort), and the config/policy
inputs.
