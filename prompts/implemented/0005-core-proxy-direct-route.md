# 0005 — Core SSH proxy engine & direct route

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — especially §1 (flow), §2 (D1, D2, D5, D7), §3 (proxy/channel),
  §4.2 (target auth interface + static-key placeholder), §4.3 (what the user is
  told), §6.1–6.2.
- `docs/learnings/` — read summaries; open `0002` (control client + route payload)
  and `0004` (identity + user auth entry points).

## Objective
Deliver the first **end-to-end working proxy** for a **direct** route: accept an
authenticated client, resolve the target, dial it, and **generically pass through
all SSH channel types**. Use a simple placeholder for target auth so the pipeline
works before ephemeral provisioning (0006) lands.

## In scope
- `internal/routing` (initial): parse the target from the SSH username using the
  configured delimiter (D1, default `#`) → `login` + `target`; normalize/validate.
  Then call Hoplock Control's **authorize + route** endpoint and handle the
  `direct` case (return the route). Leave a clear TODO/interface point for
  `nexthop` (0007).
- `internal/proxy`: the core engine.
  - Client-facing `ssh.ServerConfig` wired to 0004's user auth.
  - After auth + authorize(direct): dial the target over SSH.
  - **Generic channel passthrough**: for every channel the client opens, open a
    matching channel to the target and pump both directions, including channel
    **requests** (`pty-req`, `env`, `shell`, `exec`, `subsystem`,
    `window-change`, etc.) and global requests. Handle `session`, and forward
    others generically. Preserve exit-status/exit-signal and clean teardown.
  - Enforce the **permitted-channel allow-list** from the route response at a
    coarse level here (full framework is 0008) — deny channels not permitted.
  - Session lifecycle: open, run, guaranteed close of both sides.
  - **User-facing feedback (PLAN §4.3).** The proxy is the last thing standing
    between a failure and a user staring at a dead terminal, so it must always
    say why a connection ended:
    - **Accept the client's session channel before the target leg is up**, so
      there is somewhere to write progress ("connecting to <target>…") while
      authorize, provisioning, and the target dial happen. This is an ordering
      requirement on the engine, not a formatting detail — design the session
      lifecycle around it.
    - Write feedback to the channel's **stderr**, never stdout, and keep it to
      failures only when the channel has no pty (`scp`, `sftp`, `exec`), so
      tooling parsing the stream is not corrupted.
    - Apply the disclosure split on every failure path (authorize, target dial,
      host-key rejection, provisioning): `control.IsUnauthorized` → a generic
      "access denied" that names neither target nor reason; anything else →
      an explicit "this is an outage, not a permissions problem" plus the
      session id as a support reference.
    - Fail before the channel exists → `SSH_MSG_DISCONNECT` with a reason code
      and description. Fail after → stderr plus a non-zero `exit-status`, then
      a clean close. **A bare TCP drop is never an acceptable outcome.**
- `internal/auth/target` (placeholder only): a `static-key` `TargetAuthenticator`
  (PLAN §4.2) that returns an `ssh.ClientConfig` from a configured test key, with
  a no-op `Teardown`. Clearly marked as a placeholder to be superseded by 0006.
- Host keys: present the proxy's own host key to clients; for the target use
  **trust-on-first-use** and call the **report host key** endpoint on new keys
  (D7).
- Minimal integration test harness proving E2E (see below).

## Out of scope
- Ephemeral user provisioning (0006). Multi-hop (0007). Inspection pipeline
  internals and command filtering (0008/0009). Full logging pipeline (0010) —
  basic structured session start/stop logging is fine, but the batching/priority/
  buffer machinery is 0010.

## Acceptance criteria
- An integration test (using `cmd/mock-control` + an in-test/containerized
  `sshd` target + the static-key target auth) demonstrates:
  a user authenticates to the proxy, is authorized to a **direct** target, runs
  an `exec` command, and gets correct output and exit status; and opens an
  interactive `shell` and exchanges data.
- Channels not in the permitted list are refused.
- Both connection legs close cleanly with no leaked goroutines (test with
  `-race`).
- A test asserts the user receives distinguishable text for (a) an authorize
  deny and (b) a management-server outage, that the deny text names neither the
  target nor the reason, and that the outage text carries the session id.
- A test asserts that a failure after the session channel opened produces stderr
  output and a non-zero exit status rather than a silent close.
- New target host keys trigger a report call (asserted against the mock).

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0005-core-proxy-direct-route-learnings.md`. Summary block MUST
describe the proxy engine's structure, how channels/requests are pumped, the
`routing` entry points, and the exact seam where 0006 replaces the static-key
target auth and where 0007 plugs in `nexthop`.
