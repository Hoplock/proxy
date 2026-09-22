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
  **"Absent-value defaults, in one table"**, and **"Changing the contract"** —
  the recipe you follow, step by step.
- `api/control.yaml` — `AuthorizeResponse.algorithm_profile` and the
  `## Versioning` block in `info.description`.
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
  reaper's bare-endpoint copy. **Also read `0044-brokered-certificate-credentials-learnings.md`'s summary for
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

## Objective

Let Control name, per route, a **minimum** key exchange the proxy→target leg
must negotiate; apply it on every connection the session causes to that target;
fail closed and legibly when the target cannot meet it; and record the key
exchange actually negotiated on every target leg, so the floor is observable in
production and not only assertable in a test.

## What this phase must settle

### 1. The shape, in this repository's vocabulary

**Taken as asked:** `AuthorizeResponse.algorithm_floor`, a string enum, a
**sibling** of `algorithm_profile`. The requester's reason is correct and is the
one to write into `api/README.md`: a profile is a named *weakening* preset and a
floor is a *minimum*, and a route may legitimately want `default` **and** a
floor, which one field cannot express. It is also the §4.2 argument again: a
named value, not an algorithm list, so it cannot be tuned one identifier at a
time and a reviewer reads a word rather than decoding one.

- Enum: `[pq-hybrid-kex]`. Absent ⇒ **no floor**, today's behaviour. Add it to
  "Absent-value defaults, in one table".
- Go: `control.AlgorithmFloor` (string type) with
  `AlgorithmFloorPQHybridKEX = "pq-hybrid-kex"`, in `internal/control/policy.go`
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

| `algorithm_profile` | with `algorithm_floor: pq-hybrid-kex` |
| --- | --- |
| `default` (or absent) | accepted |
| `legacy-rsa-sha1` | accepted — different axis |
| `legacy-device` | **refused** — it widens the very axis the floor narrows |

"Refused" means what an unknown profile means: `validate()` returns a contract
violation, `ErrProtocol`, outage-class — Control sent policy that cannot be
obeyed, and the server **MUST NOT** send it. It is not a deny.

### 2. Applying it

The floor narrows 0043's expansion; it does not travel separately.

- **One place.** Extend the function 0043 put in
  `internal/control/algorithms.go` so it takes the floor as well as the profile
  and returns the lists in force. Under `pq-hybrid-kex` the key-exchange list is
  **exactly** the implemented hybrid set — not "hybrids first", which would let
  the target pick classical. Every other axis is the profile's answer, unchanged.
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

### 3. Semantics when the floor cannot be met

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

- **One classifier**, beside 0025's `IsAuthRejection` in
  `internal/auth/target` (e.g. `IsAlgorithmFloorUnmet(err) bool`), using
  `errors.As` on `*ssh.AlgorithmNegotiationError` with `What == "key exchange"`
  **and** a floor in force. Without a floor, the same error is an ordinary dial
  failure and stays one — do not reclassify existing behaviour.
- **A stage of its own** in `internal/proxy/feedback.go` (e.g.
  `stageAlgorithmFloor`), with the comment explaining why it is separate from
  `stageDial` in the house style (it sends an operator somewhere different: the
  network is fine, the target's SSH server is too old for this route). Classify
  it **after** the host-key branch and **before** the rejection branch in
  `dialTarget`.
- **A record**: `warn`, batch path, `event` `target.algorithm_floor_unmet`,
  carrying `algorithm_floor`, `target_addr`, and the **target's offered key
  exchanges** from `AlgorithmNegotiationError.RequestedAlgorithms`
  (`target_kex_offered`, one comma-joined string — it is public protocol
  metadata, not credential material, and it is what tells the operator whether
  the fix is an OpenSSH upgrade). `warn`, not `critical`, on §7's own rule: this
  is a target-posture fact, not a security event — KEXINIT is covered by the
  exchange hash the host key signs and the host key is checked under D7, so an
  on-path attacker cannot strip the hybrid without failing host-key
  verification first. If you conclude otherwise, write the reason into §7.
- The same failure on the driver's privileged connection or the management
  login fails provisioning with the same classification; on the **sweep** it is
  a sweep failure on the path sweep failures already take (the device was
  provisioned under the same floor, so this means the device changed under the
  proxy — say that in the record's message).

### 4. Versioning

`algorithm_floor` is a new field inside the strictly-decoded authorize response,
so it is vocabulary: follow "Changing the contract" exactly — `control.yaml`
first, Go types, `clone.go` and the mutation test, `control.PolicyVersion` to the
next number, the README prose that states the current value, `info.version` to
the next **minor**, and `cmd/mock-control`'s `vocabularyVersion` tiering the field
above the baseline so a proxy on the old number is answered a `500` rather than
policy it would refuse.

State in the contract the obligation this puts on the server, because it is the
one place a floor could be lost silently: **a route whose policy carries a floor
MUST NOT be served to a proxy declaring an older vocabulary with the floor
omitted** — the server refuses (as the mock does, with its `500`) rather than
thinning the policy. Omitting a floor is a dropped restriction, which is the
exact failure the version mechanism exists to prevent. This is a Control
obligation and goes into the sync.

The floor rides the reusable decision (§6.4) with no change to caching: a
replayed floor is the same floor. Say so in one sentence where the field is
described.

## In scope

- `api/control.yaml` — the field, its description (the property, the one
  implemented member, the axis table, the server's MUST NOT), `info.version`,
  the `## Versioning` block's current number.
- `api/README.md` — a subsection beside "Algorithm profile", the absent-value
  table, the current-number prose.
- `internal/control` — `policy.go`, `contract.go`, `validate.go` (including the
  profile × floor rule), `clone.go`, `algorithms.go` (the expansion), and the
  contract cross-check tests that read `control.yaml`.
- `internal/routing/resolve.go` — the floor on `routing.Route`, deep-copied
  beside the profile.
- `internal/auth/target` — `auth.go` (`Target`), `admin.go`, `devicereaper.go`,
  `registry.go`, `device/driver.go` (`Endpoint`), `device/shell.go`, and the new
  classifier beside `reject.go`.
- `internal/proxy` — `session.go` (`dialTarget`: apply, classify, read the
  negotiated exchange), `feedback.go` (the stage and its message), `logging.go`.
- `internal/logging` — `record.go` (`AttrAlgorithmFloor`,
  `AttrTargetKexAlgorithm`, `AttrTargetKexOffered`, the event name), `device.go`.
- `cmd/mock-control` — fixture field, validation (including the refused pair),
  `vocabularyVersion`, and `fixtures.example.yaml`.
- `test/e2e` — a route with a floor against a target that offers ML-KEM and one
  that does not (see acceptance).
- `docs/PLAN.md` — §4.2 (the floor beside the profile), §4.3 (where this
  failure sits), §7 (the three attribute keys, the event, its severity, the
  absence rule), §10's row. If you add an `As <verb> (phase 0045)` layer to
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
- **The user→proxy leg.** The proxy's own server config; not route policy.
- **Floors on any other axis** (ciphers, MACs, host-key algorithms). The enum is
  built to take more values later; add none now.
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
  id; a `warn` `target.algorithm_floor_unmet` record carries the offered list;
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
- The driver's privileged connection, the management login and the **reaper's
  sweep** all dial under the floor — test the sweep specifically, as 0043 did
  for the profile.
- `clone.go`'s mutation test covers the new field; a proxy declaring the
  previous `policy_version` is answered a `500` by the mock for a route with a
  floor; the contract cross-check tests pass against the edited `control.yaml`.
- A test in a package importing x/crypto asserts the string constant in
  `internal/control` equals `ssh.KeyExchangeMLKEM768X25519`.
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
  - the field is `algorithm_floor` with one value, `pq-hybrid-kex`, and it
    means **ML-KEM768 hybrid only** today — **not** sntrup761 — so any Control
    text or guidance promising "either" is wrong;
  - the attribute is **`target_kex_algorithm`**, not the `kex_algorithm` it
    asked for, plus `algorithm_floor` (omitted when none) and the
    `target.algorithm_floor_unmet` event with `target_kex_offered`;
  - `legacy-device` + floor is refused by the proxy; `legacy-rsa-sha1` + floor
    is **accepted** — Control's policy validation should match, not reject more;
  - the server MUST NOT serve a floored route to an older-vocabulary proxy with
    the floor omitted.
- The **learnings summary** names the field and value, the implemented member
  set, the attribute keys and event, the stage, the profile × floor rule, the
  version number reached, and what Control must change — that last line is what
  the sync session reads.
