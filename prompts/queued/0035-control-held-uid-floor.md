# 0035 — Hold the ephemeral UID floor where the target cannot reach it

> **New prompt, added by phase 0027 and raised in review on its PR.** 0027 made
> uid allocation non-reusing and fails closed where it cannot be. It left the
> high-water mark **on the target**, which is the party this proxy does not trust,
> and it left one case open that no attacker is needed to reach: a proxy restart.
>
> **It revises `api/control.yaml`, so it must run BEFORE 0036** (the contract
> collapse, which must follow every phase that touches the contract) and it
> carries a cross-repo obligation. Read `docs/CROSS-REPO-PROTOCOL.md` in full —
> §1's shared surfaces, §4's downstream-impact check and the sync kickoff it owes,
> and §5's ordering. This is the first contract change since 0023.

## Read first
- `docs/PROTOCOL.md` — session workflow, and §6 on prompt numbering.
- `docs/CROSS-REPO-PROTOCOL.md` — **in full.** `api/` changes here create work in
  Hoplock Control, and the ordering and the kickoff you owe the user are there.
- `docs/PLAN.md` — **§5.1** (the ephemeral lifecycle, *UID allocation is the
  proxy's*, and the trust-boundary paragraph that states exactly what is and is
  not closed today), §5.3 (device accounts — the targets that can store
  nothing), §4.3 (what the user is told), §6.4 (the decision cache), D2, D3, D6.
- `docs/learnings/` summaries: **0027** (read its *Why the floor is not (yet)
  Control's* section in full — it is the design sketch this prompt is built
  from, including the shape that was tried and rejected), **0023** (the host-key
  cache hint, the closest existing contract precedent), **0022** (the decision
  cache, and why a cached decision is served during a Control outage), **0013**
  (the report-shaped endpoint, `POST /v1/capabilities/report`), **0002** (the
  contract and the mock).

## The defect

`internal/auth/target/uid.go` allocates strictly above the highest of three
things: the in-range uids an account holds now, this process's own record of what
it has issued, and a **high-water mark stored on the target** at
`<enforcement_base>/uid-watermark/`.

The first two are trustworthy or cheap to trust. The third is state a security
invariant depends on, sitting on the machine the proxy is defending against, and
it is load-bearing in exactly one situation: **a proxy that has restarted.** The
in-process record is empty then, so a fresh process has only the target's word
for the floor, and a mark that has been lowered — deleted by root on the target,
lost with a reimaged host, absent because the directory was never writable — puts
a torn-down session's uid back in play. The next session inherits ownership of
whatever the previous one wrote outside its home.

Two further cases need no attacker and no restart at all:

- **A replaced proxy.** Immutable infrastructure, a new container, a scaled-out
  replica: the mark is the only continuity, and where it is missing the range
  starts again from the bottom.
- **A target the proxy cannot write to.** 0027 assumed a target that takes
  `ephemeral-user` is a target it can write files on, which is true of the home
  directory and `authorized_keys` — but **not** of `/var/lib` on a host with a
  read-only root filesystem, which is an ordinary hardened shape. Those targets
  are refused today, as an outage, on a route that worked before 0027.

## Objective

The uid floor for a target is held where neither the target nor any single proxy
owns it, so that the non-reuse invariant survives a proxy restart, a replaced
proxy, two proxies on one target, and **a target on which the proxy can write
nothing at all** — without coupling provisioning to Hoplock Control's
availability and without adding a Control call per session.

## In scope

### 1. A uid-block lease on the contract

Hoplock Control grants a proxy an **exclusive block of uids for a target** —
`[from, to)` with a term — and the proxy allocates inside its own block locally.
The shape matters and the reasoning is settled; do not relitigate it, and record
it if you touch this area:

- **Exclusivity closes the multi-proxy case by construction.** Two proxies
  holding two blocks cannot collide, so nothing has to read a shared counter on
  the session path.
- **A granted block is safe to hold across a Control outage**, because it cannot
  have been granted to anybody else. That is what keeps this from coupling
  provisioning to Control's availability the way §5.1's teardown and D16's
  deadline are deliberately *not* coupled.
- **It costs one call per BLOCK, not per session.** 0022 and 0023 spent two whole
  phases taking per-connection Control calls from 3.17 to 1.17 (§9.1); a
  per-session allocate call would give that back.
- **Control needs only a per-target allocation cursor** it advances on grant. No
  per-session write, no read-modify-write on the session path.

**THE FLOOR MUST NOT BE A FIELD ON THE AUTHORIZE RESPONSE.** This was the first
shape proposed and it is wrong: `control.CachingClient` serves a cached authorize
decision while Control is unreachable (bounded by `StreamStale`/`StaleAfter`), and
0022 and 0023 exist to make cache hits the common case — so a floor carried on a
cacheable decision is replayed from whenever it was cached, and **a stale floor is
a lowered floor, which is the reuse this work exists to prevent.** Anything
cacheable is disqualified for the same reason. A lease is not disqualified because
a lease is exclusive: replaying it grants the same block to the same proxy.

Decide and write down:

- the endpoint and its shape (a lease request/response pair; `POST
  /v1/uids/lease` is the obvious spelling, beside 0013's
  `/v1/capabilities/report` and 0023's host-key report);
- the **term**, and what renewal looks like. A lease that expires while a session
  holds an account from it must not make that account's uid reusable;
- **what happens when a block is exhausted mid-outage.** Fail closed is the
  posture consistent with 0027 (§4.3's outage branch, nothing provisioned) and is
  the recommended default — but it turns a Control outage plus a busy target into
  a provisioning outage, so say so plainly and make the term the operator's knob
  rather than hiding the trade-off;
- how a lease is **keyed**. A target is `host:port` to the proxy today, which
  0027's learnings flag as imperfect where many names resolve to one host. If a
  lease is keyed on something better, that is a target-identity answer and 0029
  shares the question — do not answer it twice.

### 2. It must work on a target that stores nothing

**This is a first-class requirement, not a nicety.** §5.3's devices — firewalls,
switches, filers — offer a CLI and no filesystem the proxy may write; and an
ordinary Linux host with a read-only root filesystem cannot take
`<enforcement_base>` either, though it can take `useradd -m` and an
`authorized_keys` in a writable `/home`.

So: **the lease alone must be sufficient.** A proxy holding a valid block must be
able to provision with no target-side mark at all, and must not refuse a route
because a directory is unwritable.

The target-side mark is therefore **demoted, not deleted**: it becomes an optional
corroborating signal that may only ever *raise* the floor, never lower it — the
same "the server informs, the proxy re-checks against the live target"
relationship `probeCache` and 0023's host-key hint already have. Keep it because
it is what stops a lost lease record from being the moment the invariant quietly
weakens; make its absence, and its failure to be written, a **logged fact and not
an outage**.

Where you land, the following must hold and must be tested:
- a target whose `<enforcement_base>` cannot be created or written is **served**,
  on the lease alone, with the mark's absence recorded;
- a target that *can* store the mark still gets it, and a mark reporting a floor
  **above** the lease's cursor still wins;
- a mark reporting a floor **below** what the proxy has issued changes nothing
  (0027 already asserts this — keep those tests passing).

### 3. Answer the device question explicitly rather than assuming it

0027 scoped `ephemeral-account` out on the grounds that the proxy allocates no uid
on a device. Confirm or refute that in writing rather than inheriting it: does a
freshly provisioned device administrator inherit anything from a torn-down one?
The expected answer is **no** — device accounts are name-keyed, the names carry a
per-session random token (`principal.go`), and phase 0017's schedule objects are
keyed on the administrator's name and removed by its teardown — but 0015 found
four documented facts about FortiOS that were wrong, so check rather than assume.
If there is an analogue (a recycled admin index, a session id, a numbered object
slot), it is a finding for the learnings and a new prompt, not work for this one.

### 4. The proxy side

- `internal/control`: the lease client, and where the lease is held. It is
  **per-target durable state**, so decide whether it survives a proxy restart on
  local disk (`internal/logging`'s buffer is the precedent for proxy-local
  persistence) or is re-leased on start. Re-leasing is simpler and is probably
  right: a fresh lease is a fresh block, and the cursor at Control is what makes
  it non-overlapping.
- `internal/auth/target/uid.go`: the allocator takes its floor and ceiling from
  the lease. Keep `ErrUIDUnavailable`, the no-wrap decision, the pressure warning
  and the `provision-uid` stage — all four still apply, now to the block rather
  than to the configured range.
- `auth.target.ephemeral_user.uid_min`/`uid_max` become the range Control
  allocates blocks *from*, or move to Control entirely. Decide which; if they
  move, `internal/config` and `config.example.yaml` lose them and 0001's strict
  decoding means that is a breaking config change to call out.
- The lease must appear in the provisioning audit record beside
  `target_account_uid`, or an incident cannot tell which proxy's block a uid came
  from.

### 5. The mock, the contract test, and the rig

`cmd/mock-control` grows the endpoint and a per-target cursor;
`api/control.yaml` carries the schema and a version bump (4.1 → **4.2**, unless
you are removing fields, in which case say why it is not 5.0);
`deploy/control/fixtures.template.yaml` and `test/e2e` prove it end to end.

## Out of scope

- **Sweeping, deleting or chowning files on a target.** Settled in 0027 and
  PLAN §5.1: the invariant is a property of allocation, not of deletion.
- **The wrap-around decision.** 0027 settled it — allocation refuses at the top of
  its range rather than returning to the bottom, and that is not configurable.
  A lease changes what "the top" means and nothing else.
- **0019's filesystem confinement.** Still the other half, still separate.
- **Making a root attacker on the target harmless.** Out of reach and worth saying
  so once: root there can `chown` the files it wants inherited, so no uid scheme
  helps. This phase is about a restart, a replacement, and a target that stores
  nothing.

## Acceptance criteria

- A proxy that restarts, and a *different* proxy on the same target, both
  allocate strictly above every uid the target has ever been given — with the
  target-side mark **absent**.
- A target on which `<enforcement_base>` cannot be written is **served**, not
  refused, and the mark's absence is recorded.
- A tampered or under-reported mark cannot lower an allocation (0027's tests
  still pass).
- Provisioning succeeds while Hoplock Control is unreachable, for as long as the
  proxy holds a block; exhausting a block during an outage is an outage-class
  refusal that discloses nothing about the target.
- Per-connection Control calls are unchanged for a proxy holding a block —
  asserted, because "one call per block" is the claim that justifies the shape.
- The contract change is versioned, mocked, and covered by the contract test;
  the downstream-impact check and sync kickoff of
  `docs/CROSS-REPO-PROTOCOL.md` §4 are done.
- `go build ./...`, `go vet ./...`, `go test ./...`, `golangci-lint run`,
  `make e2e` all pass.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0035-control-held-uid-floor-learnings.md`. The summary block MUST
record: the endpoint and lease shape; the term and the exhausted-mid-outage
decision; whether `uid_min`/`uid_max` stayed in proxy config or moved; what the
target-side mark is now for; the answer to the device question in §3; and the
contract version, with the cross-repo obligation and the kickoff handed over.
