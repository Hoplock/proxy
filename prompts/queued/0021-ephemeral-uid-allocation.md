# 0021 — UID allocation: stop a fresh account inheriting a dead one's files

> New prompt. It closes a **cross-user information flow** that exists today, is
> not theoretical, and is not covered by anything else in the queue.
>
> Pairs with **0016**, which owns the other half (confinement). Neither alone is
> the fix, and this one does not depend on 0016 landing first.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — **§5.1** (the ephemeral lifecycle, the principal's shape, and
  *Why a per-session account*, which already records UID reuse as a known cost),
  §4.3 (what the user is told), D6.
- `docs/learnings/` summaries: **0007** (the provisioning scripts, the reaper,
  and the account-name-as-registry design), **0012** (the e2e topology you owe
  a scenario), **0016**'s prompt (the confinement rungs — read its scope so the
  two phases meet rather than overlap).

## The defect

`provisionScript` in `internal/auth/target/script.go` creates the account with:

```sh
useradd -m -d "$h" -s <shell> "$p"
```

No `-K UID_MIN`, no `-u`. So the target's own allocator hands out the **lowest
free UID**, which means a torn-down ephemeral account's UID is reused by the
very next `useradd` on that host — near-certainly, not eventually.

Teardown removes the account, its processes, and its home
(`pkill -KILL -u` → `userdel -r` → `rm -rf "$h"`, then verifies). It does not
and should not walk the filesystem. So any file the session wrote **outside its
home** keeps the bare numeric UID:

1. session A for `alice` gets uid 1001, writes `/tmp/scratch`;
2. teardown removes A; uid 1001 is free again;
3. session B for `bob` — a *different person* — gets uid 1001 and now **owns**
   `/tmp/scratch`: reads it, rewrites it, `chmod`s it.

That is a cross-user information flow through a world-writable directory, and
nothing in the tree addresses it.

## Why not simply sweep the filesystem at teardown

Settled; do not relitigate it, and record the reasoning if you touch this area:

- **Time.** Teardown runs on every session end, error, panic, signal and reaper
  sweep, bounded by `auth.target.ephemeral_user.timeout`. A walk over millions
  of inodes across NFS takes minutes. A *timing-out* teardown is worse than no
  sweep: the account survives, which is what the verify step exists to prevent.
- **Blast radius.** It makes the proxy a filesystem-wide delete primitive on a
  production host, reaching shared storage. Operators would refuse that
  capability, and deleting an artifact somebody needed is worse than an orphan.
- **Races.** If the UID is already recycled, the walk deletes the *new* session's
  files — the bug, with more force.
- **It cannot be complete.** Unmounted filesystems, snapshots, backups, ACLs and
  xattrs naming the uid, files inside containers.

The invariant is a property of **allocation**, not of deletion.

## Objective

A freshly provisioned ephemeral account never inherits anything from a previous
one, and when it cannot be guaranteed, the session is refused rather than served.

## In scope

### 1. A dedicated UID range, allocated to avoid reuse

- New config under `auth.target.ephemeral_user`: a UID range (`uid_min`,
  `uid_max`) and the policy knobs below. Defaults must be **outside** the
  distribution's ordinary `UID_MIN..UID_MAX` so ephemeral accounts never collide
  with the fleet's own. 0001's gotcha applies — bootstrap decoding is strict, so
  every field lands in `internal/config/config.go` *and* `config.example.yaml`.
- Allocate the **next** free UID above the highest currently in use within the
  range, not the lowest free one. `discoverScript` already reads the account
  database for the reaper; extend it to report UIDs rather than adding a second
  round trip.
- **Decide and document what happens at wrap-around**, when the range is
  exhausted and allocation must return to the bottom. This is the one moment
  reuse becomes possible again, and it is the only moment where a bounded check
  is affordable. Options worth weighing in the learnings: refuse and alarm; wrap
  and accept with a recorded warning; wrap after a check scoped to the paths a
  session can actually write. Pick one, say why, and make the choice
  configurable only if you can justify both settings.
- **Verify `useradd` flag support before relying on it.** `-K KEY=VALUE` is
  shadow-utils; the fleet §5.1 describes is not only GNU/Linux. Establish what
  the target actually accepts, and where the flag is unavailable, allocate the
  uid in the proxy and pass `-u` explicitly. Say in the learnings which you
  found and on what.

### 2. Fail closed

A route asking for `ephemeral-user` on a target where a non-reusing UID cannot be
allocated is **refused as an outage** (§4.3), never served with a recycled uid.
It is not a denial: the user cannot fix it with different credentials. Reuse
0019's stage/classification seam if it has landed; if it has not, add the stage
the same way and say so.

### 3. Record it

The allocated uid belongs in the provisioning audit record (`internal/logging`,
0011's capture points) alongside the account name. Without it, the join key §5.1
promises between a target's own audit trail and a session id is a name that has
already been deleted; the uid is what a `find -uid` in an incident actually has
to work with.

### 4. Prove it

`test/e2e` and `deploy/control/fixtures.template.yaml` (0012 owns both; that file
is the **mock** Control's fixtures inside this repository's rig, not the sibling
Control repo). Subtests go in `TestTopology`, whose ordering is deliberate —
before the outage scenario — and do not touch the shared `sshBaseArgs`.

- Two sequential sessions on one target get **different** UIDs.
- The real one: session A writes a file outside its home; after A's teardown,
  session B **for a different login** does not own it. Assert ownership, not
  absence — the file is expected to survive; what must not survive is the
  inheritance.
- A unit test for the allocator's wrap-around decision, whatever you chose.

## Out of scope

- **Confining where the account can write.** That is 0016's filesystem rung, and
  it is the other half of this fix: with a private tmp and a confined home there
  is nothing outside `$h` to inherit, and `rm -rf "$h"` becomes complete. Do not
  implement it here; do make sure the two meet, and say in the learnings what
  remains exposed until 0016 lands.
- Sweeping, deleting, or chowning files anywhere. See above.
- `brokered-key` and device accounts — the proxy creates no account there.
- `api/control.yaml`. This is proxy-local. If you think the server must choose
  the range, stop and ask (`docs/PROTOCOL.md` §9).

## Acceptance criteria

- Ephemeral accounts allocate from a dedicated range and consecutive accounts on
  one target do not share a uid.
- The wrap-around behaviour is implemented, tested, and justified in writing.
- A target that cannot satisfy the allocation refuses the route as an outage,
  and the message discloses nothing about the target.
- The provisioning record carries the uid; no credential material is added.
- e2e proves the cross-login inheritance is gone.
- `go build ./...`, `go vet ./...`, `go test ./...`, `golangci-lint run`,
  `make e2e` all pass.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0021-ephemeral-uid-allocation-learnings.md`. The summary block
MUST record: the range defaults and why those numbers; the allocation rule; the
wrap-around decision and its justification; which `useradd` flags the targets you
tested actually accept; and — explicitly — what is still inheritable until
0016's confinement lands, because that sentence is the honest scope of this fix.
