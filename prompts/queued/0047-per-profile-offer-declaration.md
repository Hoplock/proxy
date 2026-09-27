# 0047 — Declare what each algorithm profile offers, per axis

## Read first

- `docs/PROTOCOL.md`: the session workflow, especially **§3** (scope
  discipline, the rename/dangling-reference sweep, and the table of plan indexes
  that go stale in the same PR that makes them wrong), **§7** and **§8**.
- `docs/PLAN.md`:
  - **§2's register**, then these decisions in full:
    - **D3**: this repository owns the contract, and Hoplock Control vendors
      it read-only. This phase is a contract change and nothing else.
    - **D2**: the proxy originates no policy. The declaration grants nothing
      and gates nothing. It is a fact about a build, for a server to judge
      policy against before policy is issued.
    - **D9**: `x/crypto/ssh`. What a profile offers is what this build's
      library offers under it, which is why the declaration is per build and
      derived rather than written out.
  - **§4.2**, only the algorithm paragraphs: the one that introduces
    `algorithm_profile` ("One field beside the credential travels with the
    route…"), then "**As applied (phase 0043)**", "**`default` is the library's
    secure set**", "**As extended (phase 0045)**" and "**A list may narrow a
    route, never widen it**". They already settle everything this phase leans
    on, so do not re-derive any of it:
    - the profiles are **named presets, not lists**, and no finer presets exist;
    - the expansion is **one function**, `control.AlgorithmPolicy.Algorithms`.
      It applies the profile, then intersects with the floor, then subtracts
      the bans;
    - a floor narrows **only** the key-exchange axis;
    - `curve25519-sha256` and `curve25519-sha256@libssh.org` are one exchange;
    - `Validate` refuses a ban that leaves an axis nothing to offer.
  - **§5.3**, only "**What is true today**", to confirm that this phase adds no
    layer there. The device seam receives the same expanded lists it does
    today, through `device.Endpoint.Algorithms`.
  - **§8**: conventions (licence header, contract-first).
  - **§10**: this phase's row.
- `api/README.md`: "**Capability advertisement**", the "**Versioning**" text
  on what `policy_version` does and does not govern, and "**Changing the
  contract**". This phase follows steps 1–3, 5 and 6, and **not** step 4.
- `api/control.yaml`: `ProxyCapabilities`, `AlgorithmFloorCapability`,
  `OfferableAlgorithms`, `AlgorithmBans`, and the `algorithm_profile` enum on
  `AuthorizeResponse`. Also the `info.description` paragraph that lists what a
  proxy **declares** on the request as outside `policy_version`.
- Code, read before designing anything:
  - `internal/control/algorithms.go`: `Algorithms`, `AlgorithmProfile.Algorithms`,
    `AlgorithmPolicy.{Algorithms,stages,WireKeyExchanges}`,
    `withoutBannedKeyExchanges`, `OfferableAlgorithms`, `union` and
    `AlgorithmFloorCapabilities`. The new builder sits beside the last two and
    follows their pattern.
  - `internal/control/enforcement.go`: `ProxyCapabilities` and
    `AlgorithmFloorCapability`.
  - `internal/control/policy.go`: `AlgorithmProfiles()` and `AlgorithmFloors()`.
  - `internal/control/validate.go`: the algorithm block ending in "leaves the
    route nothing to offer on that axis". **This is the refusal the declaration
    must let a server reproduce exactly.**
  - `internal/control/clone.go`: `ProxyCapabilities.Clone`.
  - `internal/control/contract_test.go`: `TestEnumsMatchContract` and
    `TestSpecDocumentsTheAlgorithmSchemas`.
  - `internal/control/floor_test.go`, around `AlgorithmFloorCapabilities`.
  - `internal/auth/target/enforcement.go`: `ProxyCapabilities()`, the one place
    this build's declaration is assembled.
  - `cmd/mock-control/algorithms_test.go`: `authorizeWith` and `declaring`.
- `docs/learnings/`: read the summaries, then open
  `0045-algorithm-floor-learnings.md` in full, because it built everything this
  phase extends. Also read the summary of
  `0043-algorithm-profile-and-device-events-learnings.md`, which covers what
  each profile expands to and why `default` is the secure set.
- `docs/CROSS-REPO-PROTOCOL.md`: **§1, §2, §3.2, §4.1, §5**. This phase answers
  an upstream request, so §5's "The PR that answers an upstream request is not
  a sync" binds it. Once merged, it owes a **downstream sync to every consuming
  repository, including the one that raised the request**.

## Depends on

- **Nothing hard.** 0045 is implemented. It added `capabilities.algorithm_floors`,
  `capabilities.algorithms` and the ban refusals this phase makes judgeable.
- **0046: ordering only.** It moves `info.version`. Take the **next minor
  above whatever it is when you start**, and do not hard-code a number from
  this prompt.

## Where this came from

An **upstream request** from `hoplock/control` (`docs/CROSS-REPO-PROTOCOL.md`
§3.2), raised in the `## Upstream request` section of
[Hoplock/control#41](https://github.com/Hoplock/control/pull/41). That PR is the
docs sync that followed this repository's #69 (phase 0045). The sync put the
work into Control's own phase **0014**, which builds the authoring-time checks
for `algorithm_floor` and `algorithm_bans` against its capability store (its
**M17**: warn, never refuse, on what the fleet declares).

**The gap, in this repository's words.** `Validate` refuses a route whose bans
leave any axis nothing to offer. The contract says a server **must not send**
what the proxy refuses. So Control has to refuse exactly that, and no more.
Whether a ban empties an axis depends on what the route's **profile** offers
on that axis **in that build**. The wire carries three related facts, and none
of them is that one:

- `capabilities.algorithm_floors` gives each level's key exchanges per build.
  This settles the key-exchange axis for every profile, because `modern-kex`'s
  set is what `default` and `legacy-rsa-sha1` offer on it.
- `capabilities.algorithms` is the union over every profile and level. The
  profiles nest and a floor only narrows, so the union equals `legacy-device`'s
  offer. That settles every axis for a `legacy-device` route.
- A ban that removes the whole union on an axis empties that axis under every
  profile.

**What is left cannot be judged downstream:** a ban that empties `ciphers`,
`macs`, `host_keys` or `public_key_auth` under `default` or `legacy-rsa-sha1`
only. Control's 0014 is told not to close the gap by copying the profile lists
into code, because this repository pins them per build and a copy drifts. It
is also told not to derive them from the contract's prose, which names the
legacy additions only in part. Instead it builds one seam named for this
missing declaration. The seam answers what the wire answers and reports
"unknown" for the rest. An unknown is never a refusal and never a silent pass.

**The shape requested**, in the requester's words from #41's commit message and
its 0014 text: *"an exact 'ban empties an axis' check needs each build's offer
per profile and per axis, which the wire does not carry"*. The missing
declaration is *"each build's offer per profile and per axis"*.

**What downstream cannot do until this lands.** Control cannot refuse, at
authoring time, a ban that leaves a `default` or `legacy-rsa-sha1` route no
cipher, MAC, host-key algorithm or public-key signature algorithm to offer. It
can only report it as "unknown". An author who saves such a ban is not
stopped. Every proxy then refuses that route **at connect time**, as a
contract violation and an outage (§4.3's outage branch). That happens during
exactly the emergency the ban was meant for: an advisory, and the runbook's
ban → `cache_invalidate` → `session_kill`. Control built the seam unwired and
approximated nothing.

**Taken as asked.** The request is right, in the form requested, and nothing
here contradicts a D decision:

- A **declaration**, not a check this proxy performs for Control. The proxy is
  a client of Control and exposes nothing Control could call to ask "would you
  refuse this?". The facts must ride a request the proxy already makes, and
  `AuthorizeRequest.capabilities` is where 0045 put their siblings.
- **Per profile**, not per profile × floor. A floor narrows only the
  key-exchange axis (§4.2), and each level's key exchanges are already declared
  in `algorithm_floors`. The per-profile lists plus the per-level lists
  therefore determine every axis of every accepted profile × floor × ban
  combination. A full product would repeat the non-key-exchange axes once per
  level for nothing.
- **Per build and derived**, exactly as 0045 did for `algorithm_floors` and
  `algorithms`. The lists are built by the expansion every connection dials
  with, so they cannot describe anything the proxy does not offer. A copy that
  drifts is the failure the request exists to avoid, whether the copy is here
  or in Control.

**Settled by existing decisions, not re-opened here.** The declaration makes no
profile widenable and introduces no finer preset. It is a report, not a list a
server sends (§4.2, "A list may narrow a route, never widen it"). It is request
data, which `policy_version` does not govern (`api/README.md`, the 0045
precedent), so it moves `info.version` and not the vocabulary number.

## Objective

Add `capabilities.algorithm_profiles` to `AuthorizeRequest`. It declares, for
every `algorithm_profile` this build accepts, what that profile offers on each
axis before any floor or ban. It is built by the function every connection
dials with. Prove in a test that these lists and `algorithm_floors` are enough
to reproduce `Validate`'s axis-emptiness refusal exactly.

## The shape

### Contract (`api/control.yaml`)

`ProxyCapabilities` gains one property, beside `algorithm_floors`, with the
same list-of-objects pattern:

```yaml
        algorithm_profiles:
          type: array
          description: |
            Every `algorithm_profile` this build accepts, one entry per
            profile, each with what that profile offers on the proxy→target
            leg **in this build**, per axis, before any `algorithm_floor`
            narrows it and before any `algorithm_bans` subtract from it. Key
            exchanges are in the wire form, as in `algorithm_floors`.

            It is what lets a server refuse exactly what the proxy refuses.
            With each level's key exchanges from `algorithm_floors`, it
            determines what any accepted profile, floor and ban combination
            leaves on every axis. So a server can tell, before a ban is saved,
            whether the ban leaves a route nothing to offer, which the proxy
            refuses as a contract violation. The profiles nest, so
            `algorithms` is the union of these lists.

            Absent declares nothing. A server that needs a profile this
            declaration does not list cannot judge that profile, and it must
            not treat the missing entry as proof either way. It rides the
            request, which `policy_version` does not govern.
          items:
            $ref: '#/components/schemas/AlgorithmProfileCapability'

    AlgorithmProfileCapability:
      type: object
      description: One `algorithm_profile` a proxy build accepts, and what it offers.
      required: [profile, algorithms]
      properties:
        profile:
          type: string
          enum: [default, legacy-rsa-sha1, legacy-device]
        algorithms:
          $ref: '#/components/schemas/OfferableAlgorithms'
```

`OfferableAlgorithms` is reused as the per-axis shape, as is. There is one
spelling per axis in this contract (`Algorithms`' doc comment), and the axis
keys are `key_exchanges`, `ciphers`, `macs`, `host_keys` and `public_key_auth`.
Update `OfferableAlgorithms`' description so it no longer claims to be only the
build-wide union. The wording is yours. Its fields do not change.

Update the `info.description` paragraph that lists what a proxy **declares**
on the request as outside `policy_version`, so it names `algorithm_profiles`
as well.

`api/README.md`'s "**Capability advertisement**" per-proxy bullet names the
new declaration and what it is for: an exact authoring-time refusal. It also
states the composition rule a server applies. That rule is:

1. start from the profile's list on each axis;
2. under a floor, intersect key exchanges with that level's declared list;
3. subtract the bans, treating both curve25519 spellings as one.

An axis left empty is refused. **Write the rule once, in the README, in terms
of the declared lists. Do not restate the lists themselves anywhere in prose.**

### Go (`internal/control`)

```go
// enforcement.go, beside AlgorithmFloorCapability
type AlgorithmProfileCapability struct {
	Profile    AlgorithmProfile `json:"profile"`
	Algorithms Algorithms       `json:"algorithms"`
}

// ProxyCapabilities gains, beside AlgorithmFloors:
	AlgorithmProfiles []AlgorithmProfileCapability `json:"algorithm_profiles,omitempty"`
```

```go
// algorithms.go, beside AlgorithmFloorCapabilities
func AlgorithmProfileCapabilities() []AlgorithmProfileCapability
```

- One entry per `AlgorithmProfiles()`, in that order.
- Each entry's `Algorithms` is `AlgorithmPolicy{Profile: p}`'s expansion: no
  floor and no bans. Key exchanges come from `WireKeyExchanges()`, so they are
  in wire form, alias included, as in `AlgorithmFloorCapabilities`. Every other
  axis comes from `Algorithms()`.
- Nothing is written out by hand. The doc comment says why, in the words
  `OfferableAlgorithms` and `AlgorithmFloorCapabilities` already use.

`ProxyCapabilities.Clone` deep-copies the new slice, including each entry's
lists. `internal/auth/target.ProxyCapabilities()` sets
`AlgorithmProfiles: control.AlgorithmProfileCapabilities()` beside
`AlgorithmFloors`, and the comment above it covers both.

**Decide, and say in your learnings, whether `ProxyCapabilities.Declares()`
should count a profiles-only declaration.** 0045 left the same question open
for floors. Answer it the same way unless you find a reason not to.

### Mock (`cmd/mock-control`)

The mock does no authoring, so it does not judge bans. It must accept the new
field on authorize, which it already does if it decodes into
`control.ProxyCapabilities`, and a test must show that. **Do not add a refusal
to the mock.** Nothing here asks the server to refuse anything new at serve
time.

## In scope

- `api/control.yaml`: the property, the schema, both description updates, and
  `info.version` one minor up.
- `api/README.md`: the "Capability advertisement" bullet and the composition
  rule.
- `internal/control`: the type, the builder, the `Clone` change, and the tests
  below.
- `internal/auth/target/enforcement.go`: sending the declaration.
- `cmd/mock-control`: an accept test.
- `docs/PLAN.md`:
  - one paragraph under §4.2's "**As extended (phase 0045)**" block, or a short
    `As declared (phase 0047)` paragraph after it. Say what is declared, that it
    is derived, and that it closes the gap Control's 0014 left as "unknown";
  - §10's row updated with what was delivered.

## Out of scope

- **Gating profiles on the declaration.** Profiles are response vocabulary,
  governed by `policy_version`. Do not add a "server must not send an
  undeclared profile" rule. It would be a new obligation on Control that
  nobody asked for, and it duplicates what `policy_version` already enforces.
- **Any change to what a profile, floor or ban expands to**, or to `Validate`.
  If you find the proxy's refusal and the composition rule disagree, that is a
  finding for your learnings and the user, not something to fix quietly here.
- **Removing or redefining `capabilities.algorithms`.** It stays. Control's
  typo warning uses it, and removing a request field is a break with no gain.
- **Per-target data.** What a target accepts is `TargetCapabilities`' business
  and is unchanged.
- **Recording declarations per proxy for a fleet view.** That is Control's
  (its M5 bounds how), exactly as for `algorithm_floors`.
- **`policy_version`.** It does not move.

## Acceptance criteria

- An authorize request from this build carries `capabilities.algorithm_profiles`
  with one entry per profile in `AlgorithmProfiles()`. Each entry equals that
  profile's no-floor, no-ban expansion, with key exchanges in wire form.
- **The declaration is sufficient, and this is the test that proves the
  request is met.** A reference judgement is written in a test, using **only**
  the wire declaration (`algorithm_profiles` and `algorithm_floors`, decoded
  from JSON, never from Go internals) and the composition rule in
  `api/README.md`. It must agree with `Validate`'s axis-emptiness refusal:
  - for every accepted profile × floor pair (absent, `modern-kex`,
    `pq-hybrid-kex`; `legacy-device` × floor is refused and is excluded);
  - for a ban set that, on each axis in turn, removes: everything; everything
    but one; one; both curve25519 spellings; each curve25519 spelling alone;
    and a name no build offers.

  Every disagreement fails with the case named. If the two ever disagree, the
  declaration is not enough, and Control's check built on it would refuse more
  or less than the proxy does.
- `algorithms` equals the union over `algorithm_profiles` on every axis, as
  sets. The test pins it, so a future profile or level that breaks nesting
  fails the build rather than silently making `algorithms` a different fact.
- A **cross-build fixture test** shows the declaration is what flows. Swap a
  profile's cipher list in a hand-built `ProxyCapabilities`, and the reference
  judgement's verdict for a ban on the remaining cipher changes with it. The
  judgement must read the declaration, not the build.
- `TestEnumsMatchContract` covers `AlgorithmProfileCapability.profile`.
  `TestSpecDocumentsTheAlgorithmSchemas` covers the new schema and the
  `$ref` from `AlgorithmProfileCapability.algorithms` to `OfferableAlgorithms`.
- `ProxyCapabilities.Clone` deep-copies the new field. Mutating the clone's
  lists leaves the original intact, and this is tested.
- The mock accepts an authorize request carrying the field.
- `make build vet test lint`, the licence-header check and
  `go test ./test/docs/...` pass.

## Required tests

- `internal/control`:
  - `AlgorithmProfileCapabilities` matches `AlgorithmPolicy{Profile: p}` per
    profile, in wire form, in `AlgorithmProfiles()` order;
  - the union test;
  - the **sufficiency** test and the cross-build fixture test above;
  - the `Clone` test;
  - the contract tests.
- `internal/auth/target`: `ProxyCapabilities()` carries the declaration. Extend
  the existing test that checks `AlgorithmFloors` there.
- `cmd/mock-control`: an authorize carrying `algorithm_profiles` is served as
  before.

## Definition of Done & hand-off

Per `docs/PROTOCOL.md` §4, plus what this phase owes because of where it came
from and what it touches:

- **`docs/PLAN.md`'s indexes** (§3's table): §10's row, updated with what was
  delivered. The §2 register is unchanged, because no decision moves. Say so
  in the PR rather than leaving a reviewer to wonder.
- **`## Cross-repo impact`** (`docs/CROSS-REPO-PROTOCOL.md` §4.1) names
  `hoplock/control` **and** `hoplock/enterprise`. Enterprise consumes `ext/`,
  not `api/`, so "None" is the likely answer there, but check before you write
  it down. Hand over a ready-to-run sync kickoff for each repository with
  obligations.
- **Control is owed that sync even though Control asked for this** (§5, "The
  PR that answers an upstream request is not a sync"). It is the easiest one
  to skip: Control is already waiting and knows what it asked for. But the
  session there that re-vendors the contract is a fresh one that knows
  nothing, and until it runs, Control's 0014 seam keeps answering "unknown"
  for a question the wire can now answer. The kickoff must list these
  obligations:
  - **Re-vendor** the contract at the new `info.version` (its M1).
    `policy_version` is unchanged.
  - **Wire Control's 0014 seam** (the one named for "each build's offer per
    profile and per axis") to `capabilities.algorithm_profiles`. Use the
    composition rule in `api/README.md`, so that "unknown" remains only for a
    proxy whose declaration omits the profile, or omits
    `algorithm_profiles` altogether.
  - **Refuse exactly what the proxy refuses**, and apply the refusal per
    proxy. The declarations are per build, so during a rolling upgrade one ban
    can empty an axis on one build and not on another. A proxy whose own
    declaration shows the axis emptied refuses that route. Decide, under its
    M17, whether the author sees that as a refusal or as a per-build finding,
    and say which. **Never copy the lists into code**, which #41 already
    forbids.
  - Record the declaration per proxy within its M5 budget, beside
    `algorithm_floors`, if its fleet view shows per-build offers.
  - Update its PLAN, where #41 recorded this as a named cross-repo dependency,
    to say it is met, citing this repository's PR.
- **The learnings summary** names:
  - the field, the type and the builder;
  - that the lists are pre-floor and pre-ban, with key exchanges in wire form;
  - the composition rule, and the test that proves it sufficient;
  - the `Declares()` decision;
  - the new `info.version`;
  - what Control must change. That last item is what the sync session reads.
