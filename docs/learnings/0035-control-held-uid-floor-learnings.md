# 0035 — Hold the ephemeral UID floor where the target cannot reach it — Learnings

> **Vocabulary note (added by 0037).** The superseded contract vocabularies
> described here were removed in **0037**, which left one live vocabulary stated
> in the present tense; the versioning mechanism (`policy_version`,
> `control.PolicyVersion`, the MUST-NOT-answer-above rule, `vocabularyVersion`)
> was **kept**. Read the generations below as history — see `docs/PLAN.md` §4.2,
> "As collapsed (phase 0037)".

## Summary
- **What shipped:** the floor under an `ephemeral-user` account's uid is now an
  **exclusive uid block leased from Hoplock Control per proxy per target**
  (`POST /v1/uids/lease`, **contract 4.3**), not a mark on the target. It closes
  the proxy restart, the replaced proxy and the multi-proxy cases at once, and a
  target that can store **nothing** is now served instead of refused. Contract
  change ⇒ cross-repo obligation.
- **The endpoint:** `POST /v1/uids/lease`. Request `{proxy_id, target,
  target_port, uid_count, range_min, range_max, observed_floor}`; response
  `{lease_id, uid_from, uid_to (EXCLUSIVE), term_seconds}`. No `conn` — a lease
  is not made on behalf of a session.
- **The one invariant a server must keep:** the per-target cursor **only ever
  advances**. A granted block is never granted again — used, abandoned or
  expired alike — so there is no release call and nothing to reclaim.
- **Term and renewal:** `term_seconds`, default **24h** (`DefaultUIDLeaseTerm`);
  renewal is a **fresh block** taken in the **background** (`renew_before`,
  default 1h, or below 1/8 of the block remaining), never on the session path.
  An expired lease does **not** make a live session's uid reusable — the cursor
  is what retires it, not the term.
- **Exhausted mid-outage: FAIL CLOSED**, and said out loud. A block ends when it
  is exhausted **or** when its term ends; both then refuse (outage-class, PLAN
  §4.3, `provision-uid`, nothing provisioned). `uid_lease.uid_count` is how many
  sessions an outage covers, the server's term is how long.
- **`uid_min`/`uid_max` STAYED in proxy config**, meaning changed: the range a
  block is **accepted from**, sent on the request and **refused rather than
  clamped** on the grant. No breaking config change.
- **The target-side mark is corroboration now.** It may only ever RAISE the
  leased floor; its absence is a logged fact and an audit field
  (`target_uid_marked`), never an outage. Exit status **97**
  (`exitUIDMarkFailed`) is gone and the number is not reused.
- **The device question (§3) is NO, checked not assumed.** A device account is
  name-keyed with a per-session random token and every object the drivers create
  is `edit "<name>"`, never a numbered slot; `ephemeral-account` needs no lease
  at all, so a device route is unaffected by a Control outage.
- **Key files:** `api/{control.yaml,README.md}`;
  `internal/control/{lease.go (new),lease_test.go (new),rest.go,contract_test.go}`;
  `internal/auth/target/{uid.go,ephemeral.go,script.go,auth.go,registry.go}` +
  `uidlease_test.go` (new); `internal/{config/config.go,logging/record.go,proxy/logging.go}`;
  `cmd/mock-control/{uidlease.go (new),uidlease_test.go (new),server.go,fixtures.go,fixtures.example.yaml}`;
  `cmd/{proxy/main.go,loadgen/control.go}`; `config.example.yaml`; `README.md`;
  `deploy/control/fixtures.template.yaml`; `test/{e2e/scenarios_test.go,topology/config_test.go}`;
  `docs/PLAN.md` §5.1, §9.1, §10.
- **What the NEXT session must know:** a Control that does not implement
  `/v1/uids/lease` refuses every `ephemeral-user` route, because the proxy fails
  closed rather than falling back to a floor it cannot trust. The cross-repo
  sync for `hoplock/control` is owed (§ *Cross-repo obligation* below).

## Details

### The endpoint, and the four properties that fall out of exclusivity

The design was settled in phase 0027's learnings and this phase built it rather
than relitigating it. What is worth recording is which property comes from where,
because a future change that keeps the endpoint and drops one of these breaks the
whole thing:

- **Exclusivity closes the multi-proxy case by construction.** Two proxies hold
  two blocks, so nothing reads a shared counter on the session path and there is
  no contention to get wrong.
- **A granted block is safe across a Control outage**, because it cannot have
  been granted to anybody else. This is what keeps provisioning uncoupled from
  Control's availability, which PLAN §5.1's teardown and D16's deadline are
  deliberately uncoupled from for the same reason.
- **One call per BLOCK.** 0022 and 0023 spent two phases taking per-connection
  Control calls from 3.17 to 1.17 (§9.1). A per-session floor would have given
  most of that back. Asserted rather than reasoned about:
  `TestOneCallPerBlockNotPerSession` and
  `TestProvisioningSurvivesAControlOutageWhileTheBlockLasts`.
- **Control stores one integer per target.** No per-session write and no
  read-modify-write on the session path. `cmd/mock-control/uidlease.go` is the
  whole server side and is deliberately small: a mock that needed more than a
  cursor would be evidence the claim is wrong.

### What a term is actually for, which took some deciding

The obvious reading — a lease expires so the server can reclaim the block — is
**wrong and dangerous**. Reclaiming a block would hand its uids to somebody else,
which is the reuse the whole mechanism prevents. The cursor is monotonic, so an
abandoned block is simply burned.

So the term does not protect the invariant; it bounds **how long this proxy may
keep provisioning on this target without reaching Control**. That makes it an
availability knob and nothing else, and it is why:

- a short term buys nothing and only narrows the outage a proxy rides out
  (`DefaultUIDLeaseTerm` is a day for that reason);
- expiry costs availability and never correctness, which is what
  `UIDBlock.Live`'s comment says and `TestAnExpiredBlockIsNotAllocatedFrom`
  asserts;
- "a lease that expires while a session holds an account from it must not make
  that account's uid reusable" — the prompt's requirement — is satisfied **by
  construction** rather than by any code: the cursor is already above that uid.

### Fail closed, and where the operator's knob actually is

A block ends two ways and both refuse while Control is unreachable. That turns a
Control outage plus a busy target into a provisioning outage for that target, and
the prompt asked for it to be said plainly rather than hidden. It is said in four
places on purpose, because each has a different reader: `api/control.yaml`'s
endpoint description (the server author), `config.example.yaml`'s `uid_lease`
block (the operator), PLAN §5.1 (the next session), and
`TestASpentBlockDuringAnOutageFailsClosed` /
`TestAnExhaustedBlockMidOutageIsAnOutageAndDisclosesNothing` (anyone who changes
it).

The knob is two-sided and neither half alone is honest: `uid_count` is **how many
sessions** an outage covers, the server's `term_seconds` is **how long**. The
proxy renews in the background well before either runs out, so an outage has to
start inside that margin, on a target whose block is nearly spent, to be felt at
all.

### Why `uid_min`/`uid_max` stayed in proxy config

The prompt offered "the range Control allocates blocks from, or move to Control
entirely". They stayed, with their meaning narrowed to *the range this proxy will
accept a block from*, for three reasons:

1. **They encode fleet facts the server cannot know** — above every
   distribution's own `UID_MAX`, above systemd's dynamic-user range, at the top
   of SSSD's default id-mapping range, below 2^31 so a uid stays a positive
   int32. The reasoning lives in `uid.go`'s header and in `internal/config`, and
   a server has no way to re-derive it.
2. **A block below them is worse than the defect the lease prevents**: it would
   collide with the target's *own* accounts. So a block outside the range is
   **refused, not clamped** (`UIDLeaseHolder.accept`) — clamping would silently
   change what the server granted, and the two would then disagree about which
   uids are spent.
3. **Removing them would be a breaking config change** (0001's strict decoding)
   that bought nothing.

They travel on the request as `range_min`/`range_max` so a Control with no range
of its own — the mock, and a first deployment — can allocate from them. The mock
takes that route, which is why its fixture leaves `range_min`/`range_max` at 0.

### `observed_floor`: honouring an untrusted party in one direction

The proxy sends the highest uid it has seen given out on the target (the mark,
the census, its own record). It is a target's word, so it may only ever **raise**
the server's cursor.

It exists for a case that is otherwise a slow failure: a server whose cursor sits
**below** a mark an earlier 0027-era deployment left would grant block after block
that the proxy must immediately discard, one lease call per attempt. With it the
cursor catches up in one call. The allocator retries exactly **once** on a spent
block for the same reason — a loop would burn the target's range one block per
attempt.

**The cost is recorded rather than glossed:** root on a target can report a large
floor and burn that target's range, turning a confidentiality guarantee into an
availability problem on that one target. It is bounded by `range_max`, it reaches
no other target, it is loud (the pressure warning, then the refusal), and it is
the same direction 0027 already accepted — a raised mark already made the proxy
skip uids. It is the server's to clamp or ignore, and `api/control.yaml` says so.

### The trap, made structural

0027's learnings named it and this phase made it un-writable rather than
un-advised: **the floor must not ride on the authorize response**, because that
decision is cacheable and `CachingClient` serves it while Control is unreachable
— so a replayed floor is a *lowered* floor.

`UIDLeaser` is a separate narrow interface, `RESTClient` implements it, and
`CachingClient` **deliberately does not**. Wiring a caching client in is a
compile error, and `TestACachingClientCannotLeaseUIDs` asserts the property
survives someone adding a forwarding method "for symmetry" with
`ReportCapabilities`.

### The mark, demoted — and the narrowing it removes

0027 made the mark load-bearing, which quietly required `<enforcement_base>` to
be writable on **every** ephemeral provisioning, not just on routes rendering a
0019 rung. The shape that broke is ordinary: a Linux host with a **read-only root
filesystem** and a writable `/home` can run `useradd -m` and hold an
`authorized_keys`, and cannot take `/var/lib/hoplock`.

Now:

- the provisioning script's mark sequence is one `if` condition (every step
  best-effort, `set -eu`-safe) that reports `uidmarked yes|no`;
- `exitUIDMarkFailed` (97) is **deleted and the number is retired** — a status a
  deployed target may still return must keep meaning what it meant;
- absence is logged and lands on the provisioning record as
  `target_uid_marked`, so a fleet that silently stopped corroborating is visible
  rather than inferred;
- a target that *can* hold the mark still gets one, and a mark above the block's
  floor still wins (`TestAMarkAboveTheBlockStillWins`).

`TestAUIDTheTargetCannotRecordFailsTheSession` was **inverted, not deleted**:
`TestATargetThatCannotRecordTheUIDIsStillServed` asserts the opposite of what its
predecessor asserted, because the claim genuinely reversed. The e2e has the same
pair end to end, arranged by standing a *file* where the mark directory goes.

### Two refusals that must not be confused

`allocate` checks the configured range **before** the block, and the order is the
behaviour:

- past `uid_max` — final. `accept()` refuses a block above it, so no fresh block
  can help; the message is 0027's, naming the operator's remedy.
- past the block's end but inside the range — `errUIDBlockSpent`, recoverable,
  and the caller takes a fresh block. **This is not a wrap**: the next block is
  above this one because the cursor only advances.

`errUIDBlockSpent` wraps `ErrUIDUnavailable` so a caller that cannot recover
still reports the right class of failure.

### The device question (prompt §3), answered by reading rather than inheriting

0027 scoped devices out on the grounds that the proxy allocates no uid there.
Confirmed, and for two independent reasons — 0015's four wrong FortiOS facts are
why this was checked rather than assumed:

1. **The proxy allocates nothing numeric on a device.** Every uid symbol in
   `internal/auth/target` is an `EphemeralAuthenticator` method; a device
   `ProvisionedAccess` comes back with `AccountUID == 0` and `UIDLease == ""`.
   That also means **a device route needs no lease**, so a Control outage does
   not touch `ephemeral-account` at all.
2. **The device's own objects are name-keyed.** Every object the drivers create
   is `edit "<name>"` — `config system admin`, and 0017's
   `config firewall schedule onetime` — never a numbered slot of the kind
   `config firewall policy` (`edit <policyid>`) uses, and the names carry a
   per-session random token (`principal.go`). A freshly provisioned
   administrator shares no identifier with a torn-down one.

`TestADeviceAdministratorInheritsNothingNumeric` asserts both halves. **No new
prompt**: there is no analogue to close. If a platform ever appears with a
recycled admin index, a session id, or a numbered object slot, that is a finding
for its own phase and this one does not quietly cover it.

### Where the lease is held: re-leased, not persisted

`UIDLeaseHolder` keeps one block per target in memory, with a per-target mutex so
two sessions on one target make one call and a call for one target never blocks
another. Nothing is written to disk. `internal/logging`'s buffer is the precedent
for proxy-local durable state and it does not apply here: a fresh lease is a
fresh block and the cursor at Control is what makes it non-overlapping, so a file
would buy nothing while adding one whose staleness would be indistinguishable
from a lowered floor.

### The mock's `/debug/reset` does NOT reset the cursor

Worth its own note because it is a test-only defect waiting to happen: the e2e
suite resets the mock between scenarios, and resetting a cursor would **rewind**
it — granting a block overlapping one a proxy is still allocating from. The
omission is commented where every other reset line is, and
`TestTheUIDCursorSurvivesAReset` asserts it.

### Keying: `host:port`, and deliberately not answered twice

A lease is keyed on host and port, exactly as the mark, §6.4's host-key decisions
and contract v4's capability reports are, and it carries the same known
imprecision: several DNS names resolving to one host are several keys. That is a
**target-identity** question, it is 0029's, and answering it here would answer it
a second time and differently. 0027's learnings flagged it; it is still flagged.

### What could not be run in this session

`make e2e` needs Docker and this session's environment has none. Everything it
gates was run: `go build ./...`, `go vet ./...`, `go vet -tags e2e ./test/e2e/`,
`go test -race ./...`, `golangci-lint run` (v2.13.2, matching CI), and
`make openapi-check`. The two new e2e subtests are compiled but unexecuted here;
CI's e2e job is what proves them.

### Cross-repo obligation

`api/control.yaml` and `api/README.md` changed, which is a shared surface
(`docs/CROSS-REPO-PROTOCOL.md` §1). `hoplock/control` owes a **sync PR** after
this one merges: contract 4.3, the new endpoint, and the per-target allocation
cursor with its monotonicity requirement — which is a real implementation
obligation, not only text, and belongs in whichever Control prompt covers the
contract surface. `hoplock/enterprise` consumes `ext/` and not `api/`, so its
answer is **None**. The PR carries the ready-to-run kickoff.

### Follow-ups

None queued. Two things a future phase may want, recorded here because neither is
a defect:

1. **The lease is not renewed on a timer, only on demand.** A target with no
   sessions for longer than the term simply re-leases on the next one, paying one
   call. A proxy that wanted a warm block on every target it has ever served
   would need a background refresher, which is capacity work and would burn
   blocks on idle targets — the opposite trade to the one this phase made.
2. **`observed_floor` is sent on every lease request, not only the first.** It is
   free (the census is in hand) and it is what lets a server catch up, but a
   server that ignores it sees a field it never uses. If a future contract
   revision wants to narrow it, the migration case in *`observed_floor`* above is
   what it has to keep working.
