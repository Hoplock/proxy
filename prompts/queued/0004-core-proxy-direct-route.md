# 0004 — Core SSH proxy engine & direct route

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — especially §1 (flow), §2 (D1, D2, D5, D7), §3 (proxy/channel),
  §4.2 (target auth interface + static-key placeholder), §6.1–6.2.
- `docs/learnings/` — read summaries; open `0002` (mgmt client + route payload)
  and `0003` (identity + user auth entry points).

## Objective
Deliver the first **end-to-end working proxy** for a **direct** route: accept an
authenticated client, resolve the target, dial it, and **generically pass through
all SSH channel types**. Use a simple placeholder for target auth so the pipeline
works before ephemeral provisioning (0005) lands.

## In scope
- `internal/routing` (initial): parse the target from the SSH username using the
  configured delimiter (D1, default `#`) → `login` + `target`; normalize/validate.
  Then call the management server's **authorize + route** endpoint and handle the
  `direct` case (return the route). Leave a clear TODO/interface point for
  `nexthop` (0006).
- `internal/proxy`: the core engine.
  - Client-facing `ssh.ServerConfig` wired to 0003's user auth.
  - After auth + authorize(direct): dial the target over SSH.
  - **Generic channel passthrough**: for every channel the client opens, open a
    matching channel to the target and pump both directions, including channel
    **requests** (`pty-req`, `env`, `shell`, `exec`, `subsystem`,
    `window-change`, etc.) and global requests. Handle `session`, and forward
    others generically. Preserve exit-status/exit-signal and clean teardown.
  - Enforce the **permitted-channel allow-list** from the route response at a
    coarse level here (full framework is 0007) — deny channels not permitted.
  - Session lifecycle: open, run, guaranteed close of both sides.
- `internal/auth/target` (placeholder only): a `static-key` `TargetAuthenticator`
  (PLAN §4.2) that returns an `ssh.ClientConfig` from a configured test key, with
  a no-op `Teardown`. Clearly marked as a placeholder to be superseded by 0005.
- Host keys: present the bastion's own host key to clients; for the target use
  **trust-on-first-use** and call the **report host key** endpoint on new keys
  (D7).
- Minimal integration test harness proving E2E (see below).

## Out of scope
- Ephemeral user provisioning (0005). Multi-hop (0006). Inspection pipeline
  internals and command filtering (0007/0008). Full logging pipeline (0009) —
  basic structured session start/stop logging is fine, but the batching/priority/
  buffer machinery is 0009.

## Acceptance criteria
- An integration test (using `cmd/mock-management` + an in-test/containerized
  `sshd` target + the static-key target auth) demonstrates:
  a user authenticates to the bastion, is authorized to a **direct** target, runs
  an `exec` command, and gets correct output and exit status; and opens an
  interactive `shell` and exchanges data.
- Channels not in the permitted list are refused.
- Both connection legs close cleanly with no leaked goroutines (test with
  `-race`).
- New target host keys trigger a report call (asserted against the mock).

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0004-core-proxy-direct-route-learnings.md`. Summary block MUST
describe the proxy engine's structure, how channels/requests are pumped, the
`routing` entry points, and the exact seam where 0005 replaces the static-key
target auth and where 0006 plugs in `nexthop`.
