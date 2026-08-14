# 0006 — Ephemeral target credential provisioning

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — especially §2 (D6), §4.2 (TargetAuthenticator), **§5 (full
  lifecycle & robustness requirements)**.
- `docs/learnings/` — read summaries; open `0005` (proxy seam for target auth)
  and `0002` (mgmt client).

## Objective
Implement the real **bastion→target** authenticator: just-in-time ephemeral user
provisioning via a management certificate, with **guaranteed teardown** and
**orphan cleanup**. This replaces the `static-key` placeholder from 0005.

## In scope
- `internal/auth/target`: an ephemeral `TargetAuthenticator` (PLAN §4.2, D6):
  1. Log into the target with the **management certificate** as a privileged
     provisioning account.
  2. **Create** an OS user matching the authenticated username (idempotent;
     tolerate a leftover from a crashed prior session).
  3. **Generate** a short-lived keypair/cert; install the public key in that
     user's `authorized_keys` with locked-down permissions.
  4. Return an `ssh.ClientConfig` for connecting as the ephemeral user, plus a
     `Teardown` that (re)logs in with the management cert, kills the user's
     processes, and removes the user + home + keys.
- **Robustness (PLAN §5):**
  - Teardown is **idempotent** and runs on normal close, error, panic, and
    signal. Provisioned sessions are tracked.
  - An **orphan reaper**: on bastion startup and periodically, clean up ephemeral
    users/keys left by dead sessions (identify them by a naming convention or a
    tracked registry).
  - **Concurrency safety**: concurrent sessions for the same username on the same
    target must not clobber each other (unique principals or per-(user,target)
    coordination). Document the chosen approach.
  - Provisioning failure denies the session cleanly, leaving nothing behind.
- Wire it in as the default target authenticator (config-selectable), superseding
  the placeholder, without changing the proxy's call site (0005's seam).
- Config: management-cert location/identity, provisioning account, reaper
  interval, naming convention.

## Out of scope
- Multi-hop (0007). Channel inspection/filtering (0008/0009).

## Acceptance criteria
- Integration test against a real `sshd` target (container) proving: user is
  created on connect, session works as that user, user is removed on disconnect.
- A crash/abort test proving teardown still removes the user (via reaper and/or
  deferred teardown).
- A concurrency test: two simultaneous sessions for the same username don't
  corrupt each other and both clean up.
- No leftover users/keys after the suite.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0006-ephemeral-target-provisioning-learnings.md`. Summary block
MUST document the exact teardown guarantees, the orphan-reaper mechanism and
naming convention, the concurrency approach, and any target-side prerequisites
(the mgmt cert / provisioning account) that the e2e topology (0011) must set up.
