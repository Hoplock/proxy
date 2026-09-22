# 0045 — A floor under the target leg: `algorithm_floor`

## Read first

- `docs/PROTOCOL.md` — session workflow, especially **§3** (scope discipline,
  the rename/dangling-reference sweep, and the table of plan indexes that go
  stale in the same PR that makes them wrong), **§7** and **§8**.
- `docs/PLAN.md`:
  - **§4.2** (proxy → target) — the `algorithm_profile` paragraph beginning
    "One field beside the credential travels with the route" (per route, named by
    the server, a named preset rather than an algorithm list, an **audit fact,
    not a user-facing one**), the ladder walk and what exhausting it means, and
    "As collapsed (phase 0037)" (one live vocabulary, what `policy_version` does
    and does not carry, and what 0037 kept).
  - **§4.3** — the disclosure rule: the **deny** branch is Control's `401` and is
    deliberately vague; **everything else** is an outage and is explicit. This
    phase adds a failure and must put it in the right branch (see "Semantics").
  - **§5.3** — read **"What is true today"** first, then only the reaper as the
    primary removal path: the driver's privileged connection and the sweep dial
    the same device the session does.
  - **§6.4** — an authorize decision is reusable on a server-set TTL, so
    anything on it is replayed. A floor is policy, not a per-session artifact,
    so replay is harmless — but say so rather than leave it for a reviewer.
  - **§6.5** — a record names what was **in force**, never what the route asked
    for. The negotiated key exchange is exactly that kind of fact.
  - **§7** — logging & telemetry: **severity decides the endpoint**, why a
    service outage is `warn` and not `critical`, and that an attribute key is
    query surface.
  - **§10** — this phase's row.
  - Decisions: **D2** (the proxy originates no policy — the floor is named by
    Control per route; there is no proxy-wide knob, and config must never lower
    it), **D3** (this repository owns the contract), **D9** (`x/crypto/ssh` —
    the library bounds which hybrid exchanges this proxy can negotiate at all,
    and that is the finding that reshaped the request), **D14** (the ladder:
    what is skipped and what is not — a floor failure is **not** a rung
    failure), **D13** (the driver seam; the floor rides the same per-endpoint
    carrier the profile does), **D7** (host-key policy on those same
    connections, unchanged here), **D8** (which path the new records take).
- `api/README.md` — **"Versioning: one live vocabulary, and a proxy that fails
  closed"**, **"Algorithm profile (`algorithm_profile`, phase 0014)"**,
  **"Absent-value defaults, in one table"**, **"Capability advertisement"**
  (the per-proxy and per-target halves this phase extends, and "a report is an
  observation and grants nothing"), and **"Changing the contract"** — the recipe
  you follow, step by step.
- `api/control.yaml` — `AuthorizeResponse.algorithm_profile`, the
  `## Versioning` block in `info.description`, and the capability shapes:
  `ProxyCapabilities`, `TargetCapabilities`, `CapabilityReportRequest`,
  `CapabilityReportResponse` and the `POST /v1/capabilities/report` path.
- `internal/auth/target/probe.go` — how the `ephemeral-user` probe caches an
  observation per target while it is fresh and reports it fire-and-forget on a
  detached context. The key-exchange observation below reuses that pattern and
  must not add a Control call to the session path.
- `docs/learnings/` — read the summaries; open
  `0013-device-provisioning-contract-v3-learnings.md` (where
  `algorithm_profile` entered the wire), `0025-target-auth-failure-containment-learnings.md`
  (the one classifier for target-leg failures, the rejection breaker, and why a
  failure that is not a credential refusal must never be scored against a
  credential), `0037-collapse-contract-to-one-version-learnings.md`, and — **it
  will exist by the time you run, because this phase depends on it** —
  `0043-algorithm-profile-and-device-events-learnings.md`: the profile
  expansion in `internal/control/algorithms.go`, the profile on
  `routing.Route`, `device.Endpoint` and `target.Target`, and how it survives the
  reaper's bare-endpoint copy, and its answer to "Decided in 0045's review"
  (`default` as the secure set, and the `ssh-dss` question). **Also read `0044-brokered-certificate-credentials-learnings.md`'s summary for
  the `policy_version` number it left behind.**
- `docs/CROSS-REPO-PROTOCOL.md` — **§1, §2, §3.2, §4.1, §5**. This phase answers
  an upstream request, so §5's "The PR that answers an upstream request is not a
  sync" binds it: once merged it owes a **downstream sync to every consuming
  repository, including the one that raised the request**.

## Depends on

- **0043** — hard dependency. It carries `algorithm_profile` from the decision
  to every connection the session causes to the target (session leg, POSIX
  management login, the driver's privileged CLI connection, the reaper's sweep)
  and expands it in **one** place. The floor is a constraint on that same
  expansion travelling the same path; building it before 0043 would mean
  building 0043's plumbing twice. If 0043 is not in `prompts/implemented/`,
  stop and say so.
- **0044** — ordering only. It bumps `control.PolicyVersion` 4 → 5; this phase
  bumps it again. Take the **next number above whatever it is when you start**
  and do not hard-code one from this prompt.

## Where this came from

An **upstream request** from `hoplock/control` (`docs/CROSS-REPO-PROTOCOL.md`
§3.2), raised in [Hoplock/control#36](https://github.com/Hoplock/control/pull/36)
while Control queued its own post-quantum posture phase (its 0019). The surface
is `api/control.yaml`, which Control vendors read-only (its **M1**); the
audit-attribute half lands on the records `internal/logging` emits, which
Control stores (its **M8**, `audit.AttrAlgorithmProfile` since its 0010).

**The gap, in this repository's words.** `algorithm_profile` can only
**weaken** the proxy→target leg: `default | legacy-rsa-sha1 | legacy-device`,
every non-default value a weakening. So policy can say "this route may use RSA
with SHA-1" and has no way to say "this route must negotiate a hybrid
post-quantum key exchange". There is no floor — for post-quantum or anything
else — and the vocabulary is this repository's, so Control cannot add one.

**The shape requested**, quoted:

```
# In the authorize response, a sibling of algorithm_profile — NOT a new value
# inside it.
algorithm_floor:
  type: string
  enum: [pq-hybrid-kex]
  description: |
    The minimum the proxy→target leg must negotiate. Absent ⇒ no floor stated,
    which is today's behaviour and keeps this additive.
    `pq-hybrid-kex` — the leg MUST negotiate a hybrid post-quantum key exchange
    (`mlkem768x25519-sha256` or `sntrup761x25519-sha512`).
# In LogRecord.attributes, so a floor is observable after the fact.
kex_algorithm: "mlkem768x25519-sha256"
```

plus three semantics: a floor that cannot be met fails the session rather than
falling back; a route naming `legacy-device` and a floor is contradictory and is
refused at the first authorize call; and it is vocabulary, so it bumps
`policy_version`.

**What downstream cannot do until this lands.** Policy cannot require a minimum
algorithm posture on the proxy→target leg — the leg carrying session contents,
which is also the leg whose traffic ends up in Control's audit store. A
deployment can configure its proxies' key exchange but cannot express the
requirement **as policy** or verify **per session** that it held, and cannot say
"this production route must be post-quantum and that legacy appliance route
may not be". Control's 0019 builds everything else and names this gap; nothing
there is approximated.

**Treat the request as a need, not a specification** (§3.2). It is right about
the structure — a sibling field, not a profile value — and this phase takes that
as asked. It is wrong in three details it could not see from Control's side,
and the phase builds the corrected form below.

**Amended in review (PR #64): the floor is a dial, not a switch.** The owner
asked whether an administrator of Control and a proxy fleet can change the floor
as new algorithms are released, and tune it up or down to match their
compliance needs. With one value the answer was "only on/off". So this phase
builds the floor as an **ordered ladder of named levels** (Correction 4), has
each proxy **declare** the levels and member algorithms its build enforces
(§4), and has proxies **report** which level each target was seen to meet (§5).
With that, Control can show an administrator which targets a change would break
*before* they raise the floor, and which proxies can enforce it. Algorithm lists
remain ruled out (§4.2): the dial moves between named levels, never between
identifiers.

**Amended again in review: banned algorithms.** The owner then asked for a way
for an administrator to make sure a vulnerable algorithm is not used, without
waiting for a proxy release. Levels can't do that: they move in named steps, and
a new step ships with the software. So this phase also adds `algorithm_bans`
(§6), a per-route list of SSH algorithm identifiers the proxy **must not
offer**, on any axis. This is a list of identifiers, and §4.2 rules those out,
but §4.2's objection is to lists that **widen** what a route offers. A ban can
only remove. It can't be used to weaken a route one identifier at a time, and
it names exactly the fact an auditor wants to see. The phase writes that
distinction into §4.2: **a list may narrow a route, never widen it.**

## Objective

Let Control name, per route, a **minimum level** of key exchange the
proxy→target leg must negotiate, chosen from an ordered ladder it can move up or
down, and name algorithms the leg must never use; apply it on every connection the session causes to that target; fail
closed and legibly when the target cannot meet it; record the key exchange
actually negotiated on every target leg; and give Control what it needs to
manage the dial safely across a fleet. That means which levels each proxy build
enforces and with which algorithms, and which level each target has been seen
to meet.

## What this phase must settle

### 1. The shape, in this repository's vocabulary

**Taken as asked:** `AuthorizeResponse.algorithm_floor`, a string enum, a
**sibling** of `algorithm_profile`. The requester's reason is correct and is the
one to write into `api/README.md`: a profile is a named *weakening* preset and a
floor is a *minimum*, and a route may legitimately want `default` **and** a
floor, which one field cannot express. It is also the §4.2 argument again: a
named value, not an algorithm list, so it cannot be tuned one identifier at a
time and a reviewer reads a word rather than decoding one.

- Enum: `[modern-kex, pq-hybrid-kex]`, **ordered** (Correction 4). Absent ⇒
  **no floor**, today's behaviour. Add it to "Absent-value defaults, in one
  table".
- Go: `control.AlgorithmFloor` (string type) with `AlgorithmFloorModernKEX =
  "modern-kex"` and `AlgorithmFloorPQHybridKEX = "pq-hybrid-kex"`, plus a
  `Rank() int` (absent = 0) and an `AlgorithmFloors()` list in rank order. The
  order is defined in **one** place, and every comparison in the phase uses
  `Rank`, never a string compare. All of it goes in `internal/control/policy.go`
  beside `AlgorithmProfile`; `AuthorizeResponse.AlgorithmFloor` with
  `json:"algorithm_floor,omitempty"`; `validate()` in `validate.go` refusing an
  unknown value (refused, never coerced — the `algorithm_profile` argument
  applies unchanged: coercing to "no floor" silently drops a restriction).

**Correction 1 — the floor is defined by a property, and this proxy can offer
exactly one member of it.** The request lists `mlkem768x25519-sha256` **or**
`sntrup761x25519-sha512`. `golang.org/x/crypto/ssh` (v0.56.0 as of this
writing; D9) implements `mlkem768x25519-sha256`
(`ssh.KeyExchangeMLKEM768X25519`) and does **not** implement
`sntrup761x25519-sha512` at all. So a floor defined as "either" is one this proxy
cannot honour as written: a target offering only sntrup761 — OpenSSH 9.0–9.8's
default hybrid, a large installed base — would fail a floor the contract says it
meets. The contract therefore states:

- `pq-hybrid-kex` means the leg **MUST** negotiate a hybrid post-quantum key
  exchange **that this proxy implements**; today that set is exactly
  `mlkem768x25519-sha256`, and the description says so by name;
- in practice that requires OpenSSH 9.9+ (or a device firmware offering
  ML-KEM768 hybrid) on the target — say this in `api/README.md`, because it is
  the fact an operator needs before turning a floor on across an estate, and
  Control needs it to write honest guidance;
- **widening the set** (sntrup761, when the library gains it) keeps the value's
  meaning and is a description-only edit, not a vocabulary revision. Say that
  too, so the next session does not bump the version for it.

Verify the library claim against the `go.mod` version when you start; if
x/crypto has gained sntrup761 in the meantime, include it and state which
version did.

**Correction 2 — the attribute is `target_kex_algorithm`, not `kex_algorithm`.**
A record here describes up to three SSH legs (user→proxy, proxy→proxy,
proxy→target), and every target-leg fact already carries the `target_` prefix
(`target_addr`, `target_account`, `target_uid_lease`). An unqualified
`kex_algorithm` would be ambiguous on the one record where it matters. This
repository owns the names it emits (0043 settled "one name per field" on that
basis), so it chooses, and Control is told in the sync. Control asked for one
constant; it still costs one constant.

- `logging.AttrTargetKexAlgorithm = "target_kex_algorithm"` — the key exchange
  **negotiated** on the proxy→target leg, on **every** session whose target leg
  came up, floor or no floor. Read it from the established connection:
  `ssh.Conn` from `ssh.NewClientConn` is asserted to
  `ssh.AlgorithmsConnMetadata` and `.Algorithms().KeyExchange` is the value.
  Never stamp what was *offered*; §6.5.
- `logging.AttrAlgorithmFloor = "algorithm_floor"` — the floor **in force**,
  stamped wherever 0043 stamps `algorithm_profile`, and **omitted** when there
  is none. State that absence rule in §7 exactly as 0043 had to for the profile.
- Stamp both on the device account-mapping event too (0043 made it carry the
  profile, for the same reason: it is the only record a constrained device
  session leaves) — the driver's own connection's negotiated exchange is what
  goes there, taken from `internal/auth/target/device/shell.go`'s client.

**Correction 3 — "refuse `legacy-device` with a floor" is right, and the reason
is an axis, not the word "legacy".** Profiles and the floor act on different
axes. `legacy-rsa-sha1` adds only SHA-1 **signatures** (host keys and public-key
auth); it says nothing about key exchange, so `legacy-rsa-sha1` + `pq-hybrid-kex`
is coherent (a modern OpenSSH holding an old RSA key) and **is accepted**.
`legacy-device` exists to add the SHA-1 **key exchanges** that the floor
excludes — a route naming both describes a leg that can never connect — so that
pair is refused. Write the rule as the axis in the contract, as a table, so the
next profile added is placed by rule rather than by analogy:

| `algorithm_profile` | with any `algorithm_floor` (`modern-kex` or above) |
| --- | --- |
| `default` (or absent) | accepted |
| `legacy-rsa-sha1` | accepted — different axis |
| `legacy-device` | **refused** — it widens the very axis the floor narrows |

"Refused" means what an unknown profile means: `validate()` returns a contract
violation, `ErrProtocol`, outage-class — Control sent policy that cannot be
obeyed, and the server **MUST NOT** send it. It is not a deny.

**Correction 4 — the floor is an ordered ladder, because an administrator has
to be able to tune it.** One value only lets a route turn post-quantum on or
off. Compliance usually works in steps, and an estate reaches them one step at
a time: forbid SHA-1 key exchange everywhere now, require PQ hybrid on
production once the targets are upgraded. So the enum is a **total order**,
lowest first. Each level is defined by the set of key exchanges it accepts:

| Rank | Level | Accepts (this build) | Excludes |
| --- | --- | --- | --- |
| 0 | *(absent)* | whatever the profile offers | nothing |
| 1 | `modern-kex` | every key exchange `x/crypto/ssh` implements **except** the SHA-1 ones (`ssh.InsecureAlgorithms().KeyExchanges`); today `mlkem768x25519-sha256`, `curve25519-sha256`, `ecdh-sha2-nistp256/384/521`, `diffie-hellman-group14-sha256`, `diffie-hellman-group16-sha512`, `diffie-hellman-group-exchange-sha256` | SHA-1 key exchange |
| 2 | `pq-hybrid-kex` | the implemented hybrid set: today exactly `mlkem768x25519-sha256` | every classical exchange |

Derive the rank-1 set from the library's own list, not a hand-copied one: it is
`ssh.SupportedAlgorithms().KeyExchanges`, which at x/crypto v0.56.0 is exactly
the eight exchanges above and already leaves out the three in
`ssh.InsecureAlgorithms().KeyExchanges` (checked while amending this prompt).
Assert that the two lists are disjoint. If a later library version changes
either list, the library wins and the table is updated.

**The invariant that makes it a dial, stated in the contract as the rule for
adding a level:** every key exchange a level accepts is also accepted by every
level below it. Raising the floor can only shrink the accepted set, and lowering
it can only grow it. So "tune up or down" means one thing, and Control can
compare two levels by rank alone. A future level (a pure-PQ exchange, a larger
ML-KEM parameter set) goes in **above** the current top only if it keeps the
invariant, and is an ordinary vocabulary revision.

**What is deliberately *not* a level.** A regime whose accepted set is not
nested with the others cannot be placed on this ladder. FIPS is the obvious
case: it forbids `curve25519-sha256`, which `modern-kex` accepts, yet it sits
neither above nor below `pq-hybrid-kex`. Such a regime is a different construct,
not a rung. Say so in `api/README.md` so nobody tries to squeeze it in. That
construct is out of scope here.

**What `modern-kex` does on the wire.** 0043 makes `default` the library's
**secure set** (decided in PR #64's review; see 0043's "Decided in 0045's
review"). Under `default` and `legacy-rsa-sha1` the key-exchange offer is then
already exactly the `modern-kex` set, so the level changes nothing on the wire
for those routes. Say so in the contract, so nobody reads the level as doing
more than it does. What it adds:
- **a commitment that holds under policy change:** a later edit putting the
  route on `legacy-device` is **refused** rather than applied. That is the
  point of a floor, and the bottom rung is where a compliance statement such as
  "no SHA-1 key exchange, anywhere" is written;
- **a rung for the target report** (§5): "meets `modern-kex`" is the fact that
  separates a target needing `legacy-device` from one that doesn't;
- **independence from the library's classification:** `default` follows it
  (0043), while `modern-kex` is defined by this contract as "no SHA-1 key
  exchange". If the library ever reclassifies, the level's promise still
  holds and the pinned-list test says which side moved.

### 2. Applying it

The floor narrows 0043's expansion; it does not travel separately.

- **One place.** Extend the function 0043 put in
  `internal/control/algorithms.go` so it takes the floor as well as the profile
  and returns the lists in force. Under a floor, the key-exchange list is
  **exactly** that level's accepted set, **ordered highest level first**. Under
  `pq-hybrid-kex` that is the hybrid set alone, not "hybrids first", which would
  let the target pick classical. Every other axis is the profile's answer,
  unchanged.
- **The offer is always ordered by level, floor or no floor**, and that
  includes 0043's `legacy-device` expansion: the SHA-1 exchanges it adds go
  **after** every modern one. SSH negotiation picks the client's first
  preference the server also offers. So when the offer is ordered highest level
  first, the exchange that gets negotiated tells you the highest level this
  target meets among those offered. §5 depends on that inference, so assert the
  ordering in a test.
  Note that `default` expands to *nothing* under 0043 (library defaults); with a
  floor, the key-exchange list becomes explicit while the other axes may stay
  library-default. Keep `internal/control` free of `x/crypto/ssh` as 0043
  required: the algorithm name is a string constant there, and a test in a
  package that does import x/crypto asserts it equals
  `ssh.KeyExchangeMLKEM768X25519` so the two cannot drift.
- **Every connection the session causes to that target**, on exactly the path
  0043 built: `routing.Route` → `target.Target` → `device.Endpoint`; the session
  leg (`internal/proxy/session.go`, `dialTarget`), the POSIX management login
  (`internal/auth/target/admin.go`), the driver's privileged CLI connection
  (`internal/auth/target/device/shell.go`), and the **reaper's sweep**
  (`deviceReaper.observe`'s bare endpoint keeps the floor for the reason 0043
  made it keep the profile). A floor that held on the session leg while the
  proxy administered the device over a classical exchange would be the silent
  downgrade §6.5 forbids.
- **Config cannot lower it.** `SSHShellOptions` (the connection-less fallback)
  may not remove a floor a route named, and no proxy-wide knob is added (D2).
- The hop leg is out of scope (below).

### 3. Semantics when the floor (or a ban, §6) cannot be met

Everything in this section applies equally when a handshake fails because the
target offers only algorithms a **ban** removed, on any axis. It is one failure
class, "the target cannot meet this route's algorithm policy", with one
classifier, one stage and one event. The record names which axis failed.

The request frames this as an "outage-class denial". In this repository those
are two different branches of §4.3, and the difference is the point of the
disclosure rule:

- It is **not a deny.** A deny is Control's `401`, and its message is
  deliberately vague ("access denied"). Nothing was refused to the user; the
  *target* could not meet policy, and a user told "access denied" files an
  access request that no approval will fix.
- It is the **outage branch** of §4.3: explicit, honest, the session id as a
  support reference — and **specific**: the target does not support the key
  exchange this route requires. That discloses nothing about policy the user
  could not learn from `ssh -vv` against the target themselves.
- It **never falls back.** No retry with a wider list, no walk to the next rung
  (D14): every rung dials the same target under the same floor, so walking would
  only repeat the failure, and the ladder is about credentials, not transport.
- It **never scores the credential.** `ProvisionedAccess.DialOutcome` already
  ignores non-rejections; add a test that proves a floor failure leaves the
  0025 breaker untouched, because the handshake error arrives on the same line
  of `dialTarget` a rejection does.

Mechanics:

- **Extend 0043's classifier; do not add a second one.** 0043 introduced
  `IsAlgorithmPolicyUnmet`, `stageAlgorithmPolicy` and
  `target.algorithm_policy_unmet` for a target the profile can't reach. A floor
  or ban failing is the same class. The record now also says **why** the offer
  lacked what the target needed: the profile, the floor, or a ban. Add an
  `algorithm_policy_cause` attribute (`profile` | `floor` | `ban`), decided by
  which step of the expansion removed the target's offered algorithms on that
  axis.
- **The stage is 0043's `stageAlgorithmPolicy`.** Extend its user message so
  a floor or ban failure names the requirement (for example, "this route
  requires a post-quantum key exchange") without disclosing policy beyond what
  `ssh -vv` would show.
- **The record is 0043's**: `warn`, batch path, `event` `target.algorithm_policy_unmet`,
  carrying `algorithm_floor` and `algorithm_bans.<axis>` as in force,
  `algorithm_policy_cause`, `target_addr`, `algorithm_axis` (the axis that failed), and **what the target
  offered on that axis**, taken from
  `AlgorithmNegotiationError.RequestedAlgorithms`
  (`target_algorithms_offered`, one comma-joined string). That list is public
  protocol metadata, not credential material, and it tells the operator whether
  the fix is an OpenSSH upgrade or a configuration change on the target. `warn`, not `critical`, on §7's own rule: this
  is a target-posture fact, not a security event — KEXINIT is covered by the
  exchange hash the host key signs and the host key is checked under D7, so an
  on-path attacker cannot strip the hybrid without failing host-key
  verification first. If you conclude otherwise, write the reason into §7.
- The same failure on the driver's privileged connection or the management
  login fails provisioning with the same classification; on the **sweep** it is
  a sweep failure on the path sweep failures already take (the device was
  provisioned under the same floor, so this means the device changed under the
  proxy — say that in the record's message).

### 4. Each proxy declares the levels it enforces

The dial is only safe to turn if Control knows which proxies can honour a
setting, and with which algorithms. A level's member set can change with a proxy
release (sntrup761 arriving is exactly that), so during a rolling upgrade two
builds can accept different exchanges for the same level. That is acceptable.
Hiding it is not.

- `ProxyCapabilities.algorithm_floors`: an array of `{level, key_exchanges}`,
  one entry per level this build enforces, `key_exchanges` being that level's
  accepted set **in this build**. For example:
  `[{level: modern-kex, key_exchanges: [...]}, {level: pq-hybrid-kex,
  key_exchanges: [mlkem768x25519-sha256]}]`. Build it from the same function
  §2 uses, so it cannot describe anything other than what the proxy offers.
  Go: `control.AlgorithmFloorCapability`, on `control.ProxyCapabilities`.
- **Absent declares nothing**, as it does for the rest of `ProxyCapabilities`.
  The server **MUST NOT** send a floor level that the requesting proxy did not
  declare. This is the per-level form of the `policy_version` rule and covers
  what the version cannot: a level added in a later build.
  - The proxy's backstop: `validate()` refuses a floor the build does not
    implement, which is already true since an unknown enum value is refused.
  - The mock's server half: `cmd/mock-control` answers a `500` for a route
    whose floor the request did not declare, matching `vocabularyVersion`.
- This rides `AuthorizeRequest`, which `policy_version` does not govern (it
  governs the *response*), so it moves `info.version` and not the vocabulary
  number. State that in the README beside the existing `capabilities` prose.

### 5. Each target is reported against the ladder

To tune a floor **up** safely, an administrator needs to know which targets
would fail before they change it. The proxy is the only party that sees a
target's key exchange, and it sees one on **every** target handshake. So:

- `TargetCapabilities.kex`: an optional object
  `{floor_met, negotiated, offered, observed_at}`, all strings except `offered`
  (array) and `observed_at` (date-time).
  - `floor_met` is the **highest level** the target was observed to meet, or
    `none`.
  - `negotiated` is the exchange used.
  - `offered` is the target's full key-exchange list when the proxy knows it
    (a failed negotiation gives it through
    `ssh.AlgorithmNegotiationError.RequestedAlgorithms`) and is absent
    otherwise. A successful handshake does not expose the peer's list in
    `x/crypto/ssh`, and **you must not parse KEXINIT off the wire to get it**.
- **How `floor_met` is derived**, in one function beside the §2 expansion,
  unit-tested for every level:
  - After a **success**, it is the highest level whose accepted set contains
    `negotiated`. This is sound only because the offer is ordered highest level
    first (§2): a target that preferred classical was not offered PQ, or does
    not have it.
  - After a **floor failure**, compute it exactly from `offered`.
  - If the offer was capped by a floor, a success at that floor proves **at
    least** that level. Report that level. Never report a higher one you did
    not test.
- **Reported for every credential method**, not only `ephemeral-user`: brokered,
  device and certificate routes have key exchanges too.
  - Use `probe.go`'s pattern: a per-target cache keyed by address; report only
    when there is no fresh observation, or when `floor_met` **changed**, because
    a change is news, and a target whose level dropped is news a security team
    wants.
  - Honour `report_after_seconds`. Send fire-and-forget on a detached context,
    **never on the session path**. 0023 cut Control calls per connection, and
    this must not add one back.
- **Merge, don't clobber.** A kex-only report (no `execution`/`reach`) must not
  read as "this target can take no enforcement rungs". State the merge rule in
  the contract, where the server has to implement it:
  - each of `kex` and the rung observation has its own `observed_at` and is
    replaced only by a report that carries it;
  - an absent sub-object leaves the stored one untouched.
  
  Either the `ephemeral-user` probe and the kex observation from the same
  session go out as **one** report, or they go out as two that the rule makes
  safe. Pick one, say which, and have the mock implement the rule.
- It is still **an observation that grants nothing** ("Capability
  advertisement"): the authorize response is the authority, and the live
  handshake re-checks it every time. A stale or wrong report can cost a refused
  session, never a session below its floor.
- `POST /v1/capabilities/report` is outside `policy_version`, so this moves
  `info.version` only.

### 6. Banned algorithms (`algorithm_bans`)

**The shape.** `AuthorizeResponse.algorithm_bans`, an object with one optional
array per axis, each holding SSH algorithm identifiers exactly as SSH spells
them:

```yaml
algorithm_bans:
  key_exchanges:   [diffie-hellman-group14-sha256]
  ciphers:         [aes128-cbc]
  macs:            []
  host_keys:       [ssh-rsa]
  public_key_auth: [ssh-rsa]
```

Absent ⇒ **nothing banned**. It is per axis rather than one flat list because
some identifiers appear on more than one axis. `ssh-rsa` is both a host-key
and a public-key algorithm, and an administrator may want to ban it for one
and not the other. Go: `control.AlgorithmBans` with one `[]string` per axis,
on `AuthorizeResponse`, deep-copied in `clone.go`.

**It is Control's policy, per route (D2).** An administrator banning an
algorithm "everywhere" is Control applying the ban to every route it serves.
The contract carries only the per-route result. No proxy config knob is added,
and config can't un-ban anything.

**Applying it: subtract last.** `internal/control/algorithms.go` computes the
lists in force in this order: the profile's expansion (0043), then the floor's
narrowing (§2), then **remove every banned identifier**. A ban always wins,
including over what `legacy-device` adds. It rides the same path to every
connection the session causes to the target (§2's list: session leg,
management login, driver CLI, reaper sweep).
- An axis with **no** ban keeps 0043's behaviour exactly. `default` still
  means "library defaults, no explicit list".
- An axis **with** a ban has to become an explicit list, since the library has
  no "all defaults except X" option. **Subtract from what the route would have
  offered without the ban, never from `ssh.SupportedAlgorithms()`.** The two
  differ (see Correction 4's note on `default`), and building from "supported"
  would make a ban **add** algorithms the route never offered, which is the one
  thing a ban must not do.
  - 0043 makes every profile, `default` included, expand to an **explicit**
    list on every axis. So there is always a concrete list to subtract from,
    and no need to reconstruct the library's unexported defaults.
  - Assert that a ban which is empty on an axis leaves that axis's offer
    unchanged, so turning a ban on changes the offer by exactly the banned
    names and nothing else.
- `public_key_auth` is enforced where 0043 applies `legacy-rsa-sha1`'s
  public-key algorithms (the signer's algorithm set). Reuse that mechanism; do
  not build a second one.

**What is refused at authorize** (`validate()` → `ErrProtocol`, the server
**MUST NOT** send it, same discipline as Correction 3):
- a ban that leaves an axis with **nothing** to offer;
- a ban that removes **every** member of the floor level's accepted set. For
  example, banning `mlkem768x25519-sha256` under `pq-hybrid-kex` describes a
  leg that can never connect;
- an empty-string identifier, or the same identifier listed twice on one axis.

**What is not refused: a name this build does not implement.** Banning
something the proxy never offers is already satisfied. Refusing it would turn
a same-day ban issued after an advisory into an outage on every proxy build
that never had the algorithm. So an unknown name is accepted. What it can't be
is **silent**, because a typo in a ban looks exactly like a working ban:
- the proxy stamps `algorithm_bans_unmatched` on the record, listing the
  banned names that matched nothing this build could offer;
- each proxy declares everything it *can* offer, per axis, in
  `ProxyCapabilities.algorithms`: the same five axis names, listing every
  identifier any profile or floor level in this build can put in an offer,
  built from the same function. Control can then warn about a ban that
  matches nothing anywhere in the fleet **before** it is saved. That check is
  Control's work and goes into the sync.

**Recording it, so a ban is verifiable per session.** The floor only needed
the negotiated key exchange, but a ban can be on any axis. So on every target
leg, record what was actually negotiated on each axis
`ssh.NegotiatedAlgorithms` exposes:
- `target_kex_algorithm` (already in §1) and `target_host_key_algorithm`;
- `target_cipher_out` and `target_cipher_in` (proxy→target and target→proxy);
- `target_mac_out` and `target_mac_in`, omitted when an AEAD cipher makes the
  MAC implicit.

Also stamp each non-empty ban axis as `algorithm_bans.<axis>` (sorted,
comma-joined). That is one attribute per axis, following the
`device_field.<name>` pattern, so "which sessions ran under a ban on X" is a
filter rather than a substring search. The public-key algorithm used is not
exposed by `NegotiatedAlgorithms`; record the signer algorithm the proxy
offered instead, and name it as that.

**The target report stays about the target.** A handshake whose key-exchange
offer a ban reduced cannot say what the target *would* have picked. Such a
successful handshake produces **no** `floor_met` observation (§5). A
**failed** one still does, because the target's full list comes back in the
error.

**The emergency runbook, written into `api/README.md`**, because an advisory is
the moment this is for and nobody should have to work it out on the day:
1. Control adds the ban to the affected routes' policy.
2. Control sends `cache_invalidate` with `all`. Cached decisions otherwise keep
   the old policy until their TTL (§6.4), and the proxy never overrides a
   decision (D2), so this step is what makes the ban take effect at the next
   connection.
3. Sessions already running keep the algorithms they negotiated. SSH re-keys
   within the session's existing configuration, so the ban doesn't reach them.
   To end them, Control sends `session_kill`, finding them by the negotiated
   attributes above (for example, every open session whose
   `target_cipher_out` is the banned cipher). The `reason` is shown to the user
   (§4.3), so it should say why.

### 7. Versioning

`algorithm_floor` is a new field inside the strictly-decoded authorize response,
so it is vocabulary, and so is `algorithm_bans`. Both levels and the bans ship
in the same revision, so this is one bump, not three: follow "Changing the contract" exactly — `control.yaml`
first, Go types, `clone.go` and the mutation test, `control.PolicyVersion` to the
next number, the README prose that states the current value, `info.version` to
the next **minor**, and `cmd/mock-control`'s `vocabularyVersion` tiering the field
above the baseline so a proxy on the old number is answered a `500` rather than
policy it would refuse.

State in the contract the obligation this puts on the server, because it is the
one place a floor or a ban could be lost silently: **a route whose policy
carries a floor or a ban MUST NOT be served to a proxy declaring an older
vocabulary with it omitted** — the server refuses (as the mock does, with its `500`) rather than
thinning the policy. Omitting a floor is a dropped restriction, which is the
exact failure the version mechanism exists to prevent. This is a Control
obligation and goes into the sync.

The floor and the bans ride the reusable decision (§6.4) with no change to
caching: a replayed floor is the same floor. The one consequence is the ban
runbook's step 2. Say so in one sentence where each field is described.

`ProxyCapabilities.algorithms` rides the request, like `algorithm_floors`, so
it moves `info.version` only.

## In scope

- `api/control.yaml` — the field and its ordered levels, its description (each
  level's accepted set, the nesting invariant as the rule for adding a level,
  what is not a level, the axis table, the server's MUST NOTs),
  `ProxyCapabilities.algorithm_floors`, `TargetCapabilities.kex` and the
  report merge rule, `AuthorizeResponse.algorithm_bans` (subtract-last, what is
  refused, what is merely unmatched), `ProxyCapabilities.algorithms`,
  `info.version`, and the `## Versioning` block's current number.
- `api/README.md` — a subsection beside "Algorithm profile" (the ladder and how
  to tune it, and bans beside it with the emergency runbook), the absent-value
  table, "Capability advertisement", and the current-number prose.
- `internal/control` — `policy.go`, `contract.go`, `validate.go` (including the
  profile × floor rule and the ban refusals), `clone.go`, `algorithms.go` (the
  expansion: profile, then floor, then bans), and the
  contract cross-check tests that read `control.yaml`.
- `internal/control` also: `enforcement.go` (`ProxyCapabilities.AlgorithmFloors`,
  `TargetCapabilities.Kex`), and wherever the proxy builds its
  `AuthorizeRequest.capabilities`.
- `internal/routing/resolve.go` — the floor on `routing.Route`, deep-copied
  beside the profile.
- `internal/auth/target` — `auth.go` (`Target`), `admin.go`, `devicereaper.go`,
  `registry.go`, `device/driver.go` (`Endpoint`), `device/shell.go`, the new
  classifier beside `reject.go`, and the per-target kex observation cache and
  reporter (beside `probe.go`, sharing its freshness pattern, reached from
  every method).
- `internal/proxy` — `session.go` (`dialTarget`: apply, classify, read the
  negotiated exchange), `feedback.go` (the stage and its message), `logging.go`.
- `internal/logging` — `record.go` (`AttrAlgorithmFloor`,
  `AttrAlgorithmBansPrefix`, `AttrAlgorithmBansUnmatched`,
  `AttrTargetKexAlgorithm`, `AttrTargetHostKeyAlgorithm`, the four
  cipher/MAC attributes, `AttrAlgorithmAxis`, `AttrTargetAlgorithmsOffered`,
  the event name), `device.go`.
- `cmd/mock-control` — fixture field, validation (including the refused pair),
  `vocabularyVersion`, the `500` for a floor the proxy did not declare, a
  per-route `algorithm_bans` fixture with the same refusals, the
  capability-report merge rule, and `fixtures.example.yaml`.
- `test/e2e` — a route with a floor against a target that offers ML-KEM and one
  that does not, and a route with a ban (see acceptance).
- `docs/PLAN.md` — §4.2 (the floor and the bans beside the profile, and the
  rule that a list may narrow a route but never widen it), §4.3 (where this
  failure sits), §7 (the attribute keys, the event, its severity, the
  absence rules), §10's row. If you add an `As <verb> (phase 0045)` layer to
  §5.3, recompose "What is true today" and refresh its layer count.

## Out of scope

- **Control's side** — storing the attribute, deriving a column, its
  policy authoring UI, its own TLS posture (its 0019). This phase emits and
  enforces; Control consumes, as numbered work there.
- **Proxy→proxy legs** — the hop leg (`internal/proxy/nexthop.go`) and relay
  registration (`internal/relay`). A route's floor is about the device on the
  far end; the chain's own posture is this proxy's configuration, not route
  policy. If you think it should be policy too, note it as a follow-up in the
  learnings — do not build it.
- **The user→proxy leg.** The proxy's own server config, not route policy.
  That includes **bans on it**. An administrator who wants a vulnerable
  algorithm gone from *every* leg also wants it gone from the proxy's own
  listener and from the hop leg. Those are fleet configuration, which is
  0042's area rather than route policy's. Note it in the learnings as a
  follow-up that should reuse this phase's per-axis ban shape, and do not
  build it here.
- **Allow-lists.** A per-route list that *adds* algorithms stays ruled out
  (§4.2). Only removal is added here.
- **Floors on any other axis** (ciphers, MACs, host-key algorithms). Name the
  field and the ladder so a sibling axis can be added later without renaming
  this one. Add none now.
- **Non-nested regimes** (FIPS and the like). Correction 4 says why they are
  not rungs. Designing their construct is a later phase; note it in the
  learnings as a follow-up.
- **Control's console for the dial**, meaning the impact preview and fleet
  coverage view that §4 and §5 feed. This phase supplies the data. The UI is
  Control's numbered work.
- **Implementing sntrup761** or vendoring an implementation of it.
- **A proxy-wide floor knob.** D2; §4.2's argument against a fleet-wide profile
  applies in reverse.

## Acceptance criteria

- A route with `algorithm_floor: pq-hybrid-kex` completes a session against a
  target offering `mlkem768x25519-sha256`, and the record carries
  `target_kex_algorithm = mlkem768x25519-sha256` and `algorithm_floor =
  pq-hybrid-kex`.
- The **same route** against a target offering only classical exchanges (and,
  separately, one offering only `sntrup761x25519-sha512` plus classical — the
  case Correction 1 exists for) fails at setup with the new stage; the user sees
  the outage-branch message naming the key-exchange requirement and the session
  id; a `warn` `target.algorithm_policy_unmet` record carries the offered list;
  the 0025 breaker is untouched; no ladder walk happens.
- **Without** a floor, the same classical-only target still connects, and the
  record still carries `target_kex_algorithm` (the classical one). Nothing that
  connects today stops connecting.
- The client configuration under a floor offers **exactly** the implemented
  hybrid set for key exchange — asserted on the applied `ssh.ClientConfig`, not
  on the expansion function alone — and the other axes are whatever the profile
  alone would give. A table test over every profile × {no floor, floor}.
- `legacy-device` + `pq-hybrid-kex` is refused by `validate()` as
  `ErrProtocol`; `legacy-rsa-sha1` + `pq-hybrid-kex` and `default` +
  `pq-hybrid-kex` are accepted. The mock refuses the same pair in fixture
  validation.
- An unknown `algorithm_floor` value is refused, not coerced.
- **The ladder is a dial:** a table test asserts that every level's accepted
  set contains the accepted set of every level above it (the Correction 4
  invariant), over `AlgorithmFloors()`, so adding a level that breaks it fails
  the build. The rank-1 set is asserted equal to
  `ssh.SupportedAlgorithms().KeyExchanges` and disjoint from the insecure set.
- The same route moved **down** from `pq-hybrid-kex` to `modern-kex` connects to
  a classical-only modern target. Moved **up** again, it fails with the floor
  stage. Only the decision changed, not the proxy's config.
- Under `legacy-device` with no floor, the offer lists every SHA-1 exchange
  after every modern one.
- `AuthorizeRequest.capabilities.algorithm_floors` lists both levels, each with
  exactly the key exchanges §2 offers for it (built from the same function, and
  asserted equal). The mock answers `500` for a route whose floor the request
  did not declare.
- `floor_met` is derived correctly for a target offering ML-KEM, one offering
  only modern classical, one offering only sntrup761 plus classical, and one
  offering only SHA-1. Check success and floor-failure paths for each, and
  check that a success under a capped offer never reports above the cap.
- A kex report goes out for a brokered-key or device route as well as an
  `ephemeral-user` one. A second session to the same target within the freshness
  window sends **none**. A session that sees `floor_met` change sends one at
  once. No report is made on the session path (setup does not wait on it; a
  failing reporter does not fail the session).
- The mock's store keeps a target's rung observation when a kex-only report
  arrives, and the reverse. Asserted through the real client.
- The driver's privileged connection, the management login and the **reaper's
  sweep** all dial under the floor — test the sweep specifically, as 0043 did
  for the profile.
- `clone.go`'s mutation test covers the new field; a proxy declaring the
  previous `policy_version` is answered a `500` by the mock for a route with a
  floor; the contract cross-check tests pass against the edited `control.yaml`.
- A test in a package importing x/crypto asserts the string constant in
  `internal/control` equals `ssh.KeyExchangeMLKEM768X25519`.
- **Bans:** a table test over profile × floor × bans on every axis asserts the
  applied `ssh.ClientConfig` offers exactly the expected lists, and that a ban
  always wins over a profile's additions. An axis with no ban is byte-for-byte
  what it was without the feature.
- Banning a cipher the target also offers alongside others connects on another
  cipher, and the record's `target_cipher_out`/`_in` shows which. Banning the
  target's **only** common cipher fails with the algorithm-policy stage,
  `algorithm_axis` naming the cipher axis and `target_algorithms_offered`
  listing the target's ciphers. The 0025 breaker is untouched in both cases.
- `validate()` refuses a ban that empties an axis, a ban that removes every
  member of the floor's level, an empty identifier and a duplicate. It
  **accepts** a ban naming an algorithm this build doesn't implement, and that
  name appears in `algorithm_bans_unmatched` on the record.
- `ProxyCapabilities.algorithms` lists, per axis, every identifier any profile
  or level can offer (built from the same function, asserted equal).
- **A ban never adds:** for every profile × floor, the offer with bans is a
  subset of the offer without them, axis by axis, asserted as a property over
  the whole table. A ban on an algorithm the route didn't offer (for example
  `diffie-hellman-group1-sha1` under `default`) changes nothing on the wire.
- A successful handshake under a key-exchange ban produces no `floor_met`
  report. A failed one does.
- A proxy declaring the previous `policy_version` is answered `500` by the mock
  for a route with a ban.
- The emergency runbook works as written. In an integration test against the
  mock: a cached decision without the ban serves a session; the fixture gains
  the ban; `cache_invalidate` `all` is sent; the next session runs under the
  ban. A session opened before the change still reports its original cipher
  until `session_kill` ends it.
- `make build vet test lint`, the licence-header check, `go test ./test/docs/...`
  and the e2e topology all pass.

## Definition of Done & hand-off

Per `docs/PROTOCOL.md` §4, plus what this phase owes because of where it came
from and what it touches:

- **`docs/PLAN.md`'s indexes** (§3's table): §10's row updated with what was
  delivered; the register only if a decision changed (none is expected — this is
  §4.2's argument extended, not a new `D`).
- **`## Cross-repo impact`** (`docs/CROSS-REPO-PROTOCOL.md` §4.1) naming
  `hoplock/control` **and** `hoplock/enterprise`, with "None" written down where
  that is the finding (Enterprise consumes `ext/`, not `api/` — check rather than
  assume), and a ready-to-run sync kickoff for each repository with obligations.
- **Control is owed that sync even though Control asked for this** — §5's "The
  PR that answers an upstream request is not a sync". It is the one most easily
  skipped, because Control is already waiting and it is tempting to assume it
  needs no telling; the session there that re-vendors `contract/` and wires its
  0019 is a fresh one that knows nothing. Its obligations are concrete and the
  kickoff must list them:
  - re-vendor the contract; the new `policy_version` number;
  - the field is `algorithm_floor`, an **ordered** ladder `modern-kex` <
    `pq-hybrid-kex`, compared by rank; the nesting invariant is the contract's
    rule for adding levels; `pq-hybrid-kex` means **ML-KEM768 hybrid only**
    today, **not** sntrup761, so any Control text or guidance promising
    "either" is wrong;
  - the server MUST NOT send a level the proxy did not declare in
    `capabilities.algorithm_floors`, and each declared level's
    `key_exchanges` is the per-build truth that a fleet view shows during a
    rolling upgrade;
  - `TargetCapabilities.kex` arrives from every credential method, and the
    server merges it per sub-object without clobbering the rung observation.
    Together with the proxy declarations, it is what Control's console needs
    to show "raising this route to level X would break these targets" and
    "these proxies cannot enforce X yet". That console is Control's work, and
    the obligation is to plan it;
  - the attribute is **`target_kex_algorithm`**, not the `kex_algorithm` it
    asked for, plus `algorithm_floor` (omitted when none), the other negotiated
    attributes (`target_host_key_algorithm`, `target_cipher_out`/`_in`,
    `target_mac_out`/`_in`), `algorithm_bans.<axis>`,
    `algorithm_bans_unmatched`, and the `target.algorithm_policy_unmet` event
    with `algorithm_axis` and `target_algorithms_offered`;
  - `algorithm_bans` is per route and per axis, applied after the profile and
    the floor, and a ban always wins. A "ban everywhere" is Control applying
    it to every route. Control's policy validation should refuse what the
    proxy refuses (an emptied axis, an emptied floor level) and **warn**, not
    refuse, on a name no proxy in the fleet declared in
    `capabilities.algorithms`;
  - the emergency runbook in `api/README.md` (ban, `cache_invalidate` `all`,
    optional `session_kill` of sessions found by the negotiated attributes) is
    a Control workflow to plan;
  - `legacy-device` + floor is refused by the proxy; `legacy-rsa-sha1` + floor
    is **accepted** — Control's policy validation should match, not reject more;
  - the server MUST NOT serve a route with a floor or a ban to an
    older-vocabulary proxy with either omitted.
- The **learnings summary** names the field and its levels in rank order, each
  level's member set in this build, the capability declaration and the target
  report and its merge rule, the ban shape and order of application, what is
  refused and what is only unmatched, the runbook, the attribute keys and event, the stage, the profile × floor rule, the
  version number reached, and what Control must change — that last line is what
  the sync session reads.
