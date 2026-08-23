# 0013 — Device provisioning: the method, the driver seam, contract v3

> New phase (privileged-access revision, PLAN §10). It comes **after** 0012's
> prototype gate and **before** the device drivers in 0014, for the reason 0006
> came before 0009: the vocabulary is revised before anything is built against
> it. It also comes before the enforcement-point survey (0015), because a
> device's own RBAC is a candidate rung there and the survey cannot rank a
> method that does not yet exist.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/CROSS-REPO-PROTOCOL.md` — **required**: this phase changes `api/`, a
  shared surface. §2 (upstream merges first), §4 (the Cross-repo impact section
  this PR owes), §5 (sync PR conventions).
- `docs/PLAN.md` — **D13** and **D14** (this phase implements their contract),
  D6a (what they amend), §4.2 (the method table), §5.1 (what the POSIX
  provisioner does and which of its guarantees do not transfer), §5.3 (the
  device lifecycle, the declarations, the naming rules), §13 UC1.
- `docs/learnings/` — read summaries; open `0006` (how a contract revision is
  shaped, versioned, and defaulted — follow it exactly) and `0007` (the
  `TargetAuthenticator` seam, `ProvisionedAccess`, the principal scheme, the
  reaper's contract).

## Objective
Give Hoplock Control the vocabulary to route a session to a device the proxy
cannot administer as a POSIX host, and give this repository the Go seam a driver
will implement — on the wire and in types, and **nothing that connects to
anything**.

No driver. No provisioning. No naming change. No reaper change. 0014 does all of
that, against what this phase writes down.

## Why this phase exists

D6a assumed the appliance estate was reachable only by `brokered-key`, because
it cannot create users. D13 corrects that: it cannot create *POSIX* users. A
FortiGate creates administrators, sets their credentials, scopes them to an
access profile, pins them to a source address, and deletes them again — the same
lifecycle D6 performs, in a different vocabulary over a different transport.

What is missing is not a method, it is the **seam a driver plugs into**, and the
contract vocabulary for Control to name one. Both are contract-shaped rather
than engine work, and both are things 0014 and 0015 would otherwise have to
invent while they were busy with something else.

## In scope

### 1. The contract (`api/control.yaml`, `api/README.md`)

**`target_auth` becomes an ordered list (D14).** The single object becomes a
sequence the proxy walks top-down, using the first entry it can satisfy. This is
the breaking half of the revision and it needs care:

- A v2 server sends one object. Decide how that keeps working — a `oneOf`
  accepting object-or-array, a new plural field beside the old one, or a hard
  break gated on `policy_version`. **Recommend the plural field**: it makes the
  v2 shape unambiguous rather than polymorphic, and `policy_version` already
  tells the server which to send. Reject the recommendation if the round-trip
  tests say otherwise, and say why in the PR.
- Both present is a **contract violation the client refuses**, on 0010's
  precedent (`restricted_exec` beside a non-empty `rules` list): two statements
  of which credential to use, disagreeing, have no defensible resolution.
- An empty list is a denial, not "use local config". Absent stays "use local
  config", which is what a v1 server implies.
- The proxy records **which entry it used** as an audit field. Per D14 this is
  audit-only: it is not disclosed to the user, and §4.3 does not apply. Say that
  on the field so a later reader does not "fix" it.

**The `ephemeral-account` method** (PLAN §4.2, §5.3), with method-scoped params.
At minimum: `platform` (which driver — required, never inferred),
`credential_kind` (`password` | `publickey`), `lifetime_seconds`, and the
**expiry posture** (`target-enforced` | `proxy-enforced` | `accepted-risk`,
D13). Document each on the field, including that a posture the driver cannot
satisfy is a skipped ladder entry rather than a downgrade.

**`username` becomes required** on every provisioning method — `ephemeral-user`,
`ephemeral-account`, and `static-key` alike. Today it defaults to `id.Login`,
which is a **client-typed string** (`internal/identity/identity.go` says in as
many words that `Login` must never be the basis of an authorization decision),
and letting it name an OS or device account is that rule leaking through the
back door. This is a small break; make it loudly, with the fixture updates in
the same PR.

**A per-route algorithm profile.** Much of this estate speaks key exchanges,
ciphers, and host-key algorithms that `golang.org/x/crypto/ssh` does not enable
by default, and without a way to say so those routes simply do not connect. The
profile is **named by the server, per route** — never a proxy-wide config knob,
which would weaken every leg in the fleet to serve the oldest device on it.
Decide whether the profile is a named preset or an explicit algorithm list
(**recommend named presets**: a fleet-wide `sed` cannot then widen it, and the
audit record names something a reviewer understands). Weakening **emits its own
audit event**, per D14's sibling rule for methods.

`policy_version` moves to **3**, following 0006's pattern
(`control.PolicyVersion`); the server MUST NOT answer with fields above the
version the proxy advertised.

### 2. `internal/control`

Types, `Clone`, validation, and the mock, following 0006's shape exactly: every
new field gets its JSON tag, its absent-value default, and its consuming phase
documented on the field. `cmd/mock-control` fixtures gain the new keys so 0014
and 0012's topology can select them; `fixtures.example.yaml` and
`api/README.md`'s fixture table move with them.

### 3. The driver seam (`internal/auth/target/device`, types only)

A new package holding **what a driver is**, with no driver in it:

- A `Driver` interface covering the lifecycle in PLAN §5.3 — create the account,
  install the credential, remove it, and enumerate this proxy's accounts for the
  reaper. Model it on `TargetAuthenticator`'s shape (context first, a typed
  request, an error that distinguishes "this platform cannot" from "this attempt
  failed"), because 0014's provisioner and reaper both branch on that
  distinction.
- A `Capabilities` struct carrying the declarations PLAN §5.3 tabulates: maximum
  account-name length, whether expiry is enforceable on the device, whether
  creation persists across reload, accepted credential kinds, whether a source
  address can be pinned. Declarations are **data, not behaviour** — a driver
  states them and the provisioner reads them, so that 0014's decisions
  (which naming scheme, which posture, refuse or serve) are made in one place
  rather than inside each driver.
- A registry mapping the contract's `platform` value to a driver, with an
  unknown platform an outage-class denial (§4.3) and never a guess.
- The invariant that a **Hoplock-shipped driver may not declare
  `PersistsAcrossReload`**, expressed as a test over the registry rather than a
  comment. A customer driver may; the test is scoped to what this repository
  ships, and its failure message must say why.

Interfaces and structs only: the package must have no network code, and
`go test ./...` must pass with nothing in `internal/proxy` or
`internal/auth/target` (outside the new package) modified.

## Out of scope
- **Any driver**, FortiOS or otherwise — 0014.
- The provisioner, the reaper, and the constrained naming scheme — 0014. PLAN
  §5.3 already specifies the naming rules; do not implement them here and do not
  re-litigate them.
- The declarative driver document format and the subprocess contract (D13).
  They are a later phase; the `Driver` interface is shaped so both become
  implementations of it, and the PR says how.
- Enforcement rungs, including device RBAC — 0015 surveys, 0016 applies.
- The session-bounds fields (deadline, grant context, required capture) — 0015.

## Acceptance criteria
- `make openapi-check` passes. `api/README.md` documents the ladder, the new
  method and its params, the `username` requirement, and the algorithm profile,
  each with its absent-value default, in the style of the existing
  "Absent-value defaults, in one table".
- `internal/control` tests: the ladder round-trips and preserves order; a v2
  single-object response still parses to a one-entry ladder; both shapes present
  is refused; an empty ladder is a denial; `Clone` deep-copies the ladder such
  that a cached decision cannot be mutated through it; an unknown method,
  platform, credential kind, or posture is refused rather than coerced; a
  provisioning method with no `username` is refused.
- `internal/auth/target/device` compiles with no driver, and the
  no-persisting-driver invariant is a passing test over an empty registry that
  would fail if a persisting driver were registered (add a test-only fixture
  driver to prove the test can fail).
- The mock server serves a ladder from fixtures, including a two-entry ladder
  and a single-entry one.
- **No behaviour change**: `go test ./...` passes with no test in
  `internal/proxy`, `internal/filter`, or `internal/auth/user` modified.

## Cross-repo impact

This phase changes `api/`, which `hoplock/control` vendors read-only (D3). Per
`docs/CROSS-REPO-PROTOCOL.md` §2 **this PR merges first**; per §3.1 the session
that merges it opens the Control sync PR. Fill in the section with what you
actually found (§4: "None" is a finding and must be written down), and give the
sync nothing left to invent — the obligations are:

- Control must be able to author an **ordered** `target_auth`, and must
  understand that a one-entry ladder is the way to refuse degradation.
- Control must send `username` on every provisioning method; its own fixtures
  and policy authoring change.
- Control must be able to name a platform and an expiry posture, and must not
  name a platform the proxy has not advertised.
- The `ephemeral-account` method exists and Enterprise's eventual device policy
  authoring hangs off it.

Each of those already has a home in Control's queue, landed by the
privileged-access revision. The sync **updates that existing text** — replacing
"when the contract carries a ladder" with the field's real name, shape, and
absent-value default — and per `CROSS-REPO-PROTOCOL.md` §5 it **queues no new
prompt**. Locate them by title, since Control renumbers its own queue:
*Contract vendoring & conformance harness* (the version bump itself),
*Fleet registry, health & config distribution* (which platforms and methods a
proxy advertises), *South-bound authorize & route* (authoring and emitting the
ladder), and *Audit ingest & tamper-evident store* (the ladder entry actually
used, and the ephemeral-account mapping event). If you find work that fits none
of them, that is a roadmap revision in Control with its own PR.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`, plus the Cross-repo impact section. Move to
`implemented/`; add
`docs/learnings/0013-device-provisioning-contract-v3-learnings.md`. The summary
block MUST carry: the ladder shape chosen and how a v2 response maps onto it,
the `ephemeral-account` params and their defaults, the algorithm-profile shape,
the `Driver` and `Capabilities` signatures verbatim, and the registry's failure
modes — 0014 is written from that summary alone.
