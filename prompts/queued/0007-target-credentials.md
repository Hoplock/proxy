# 0007 — Target credentials: ephemeral provisioning & brokered keys

> Renumbered from 0006 when the contract-vocabulary phase was inserted ahead of
> it (`docs/PLAN.md` §10, renumbering note). Scope grew: this phase now ships
> **both** production target-credential methods (D6a).

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — especially §2 (**D6, D6a**), §4.2 (the two methods and how
  the server selects one), **§5 (full lifecycle & robustness requirements)**,
  §4.3 (what the user is told when provisioning fails).
- `docs/learnings/` — read summaries; open `0006` (the `target_auth` field),
  `0005` (proxy seam for target auth) and `0002` (mgmt client).

## Objective
Implement the real **bastion→target** credential plane: just-in-time ephemeral
user provisioning via a management certificate (`ephemeral-user`), and a
session-scoped credential for targets that cannot be administered at all
(`brokered-key`). Both replace the `static-key` placeholder from 0005, and the
**management server chooses between them per route** via 0006's `target_auth`.

## In scope

### `ephemeral-user` (D6, PLAN §5.1)
- `internal/auth/target`: an ephemeral `TargetAuthenticator` (PLAN §4.2):
  1. Log into the target with the **management certificate** as a privileged
     provisioning account.
  2. **Create** an OS user matching the authenticated username (idempotent;
     tolerate a leftover from a crashed prior session).
  3. **Generate** a short-lived keypair/cert; install the public key in that
     user's `authorized_keys` with locked-down permissions.
  4. Return an `ssh.ClientConfig` for connecting as the ephemeral user, plus a
     `Teardown` that (re)logs in with the management cert, kills the user's
     processes, and removes the user + home + keys.
- **Robustness (PLAN §5.1):**
  - Teardown is **idempotent** and runs on normal close, error, panic, and
    signal. Provisioned sessions are tracked.
  - An **orphan reaper**: on bastion startup and periodically, clean up ephemeral
    users/keys left by dead sessions (identify them by a naming convention or a
    tracked registry).
  - **Concurrency safety**: concurrent sessions for the same username on the same
    target must not clobber each other (unique principals or per-(user,target)
    coordination). Document the chosen approach.
  - Provisioning failure denies the session cleanly, leaving nothing behind.

### `brokered-key` (D6a, PLAN §5.2)
- A second `TargetAuthenticator` for targets that cannot create users — network
  appliances, storage, hypervisors, OT gear. It changes nothing on the target:
  it uses an account that already exists.
- The credential is held **in memory for the session only**: never written to
  disk by the bastion, never in a log line, an error string, or a config dump.
  Zero it in `Teardown`.
- Where the credential comes from is a **seam**, not a hard-coded store: an
  interface with a local implementation (a file or environment-provided secret
  keyed by target, loaded on demand) that a future management-server-minted
  credential can implement instead. Name the interface in your learnings — the
  management server's plan expects to implement it.
- `Teardown` still exists and is still guaranteed; here it zeroes memory and
  closes the leg. There is no remote state to undo, which is the entire point.

### Selection & wiring
- The method comes from `target_auth.method` in the authorize response (0006).
  Bastion config keeps only the **local material** each method needs (management
  cert path, provisioning account, credential source), never the selection.
- A method the bastion does not implement, or has no local material for, is a
  clean **outage-class** denial (PLAN §4.3) naming the session id — never a
  silent fallback to another method, which would mean connecting with
  credentials the server did not choose.
- Wire both in without changing the proxy's call site (0005's seam:
  `target.NewFromConfig` gains cases; `session.setup` is untouched).
- Config: management-cert location/identity, provisioning account, reaper
  interval, naming convention, brokered-credential source.

## Out of scope
- Multi-hop (0008). Channel inspection/filtering (0009/0010).
- A management server that mints target credentials — 0006's `target_auth` is
  extensible for it; implement only the local credential source here.

## Acceptance criteria
- Integration test against a real `sshd` target (container) proving:
  `ephemeral-user` creates the user on connect, the session works as that user,
  and the user is removed on disconnect.
- A crash/abort test proving teardown still removes the user (via reaper and/or
  deferred teardown).
- A concurrency test: two simultaneous sessions for the same username don't
  corrupt each other and both clean up.
- No leftover users/keys after the suite.
- `brokered-key`: an integration test against a target with a **pre-existing**
  account and no provisioning rights, proving the session works and the target
  is unmodified (no user created, `authorized_keys` untouched).
- A test asserting the brokered credential appears in **no** log record, error
  string, or on-disk artifact produced during the session.
- A routing test: a route naming an unimplemented `target_auth.method` is denied
  as an outage with the session id, and nothing is provisioned.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0007-target-credentials-learnings.md`. Summary block MUST
document the exact teardown guarantees, the orphan-reaper mechanism and naming
convention, the concurrency approach, the credential-source interface for
`brokered-key`, and any target-side prerequisites (the mgmt cert / provisioning
account, and the pre-existing account for brokered targets) that the e2e
topology (0012) must set up.
