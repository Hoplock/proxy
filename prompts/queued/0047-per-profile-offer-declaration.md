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
  - `internal/control/contract_test.go`: `TestEnumsMatchContract`,
    `TestSpecDocumentsTheAlgorithmSchemas` and its helper `jsonFields`.
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
**M17**).

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

**The shape requested**, quoted from #41's `## Upstream request`:

> ```yaml
> # On ProxyCapabilities (AuthorizeRequest.capabilities), beside algorithm_floors
> # and algorithms. It rides the request, so policy_version does not govern it.
> algorithm_profiles:
>   type: array
>   description: |
>     What each algorithm_profile offers on the proxy→target leg in THIS build,
>     per axis, before any floor or ban: the profile stage of the expansion every
>     connection dials with. Lists are alias-complete, as algorithm_floors is.
>   items:
>     $ref: '#/components/schemas/AlgorithmProfileCapability'
>
> AlgorithmProfileCapability:
>   type: object
>   required: [profile, key_exchanges, ciphers, macs, host_keys, public_key_auth]
>   properties:
>     profile:         {type: string, enum: [default, legacy-rsa-sha1, legacy-device]}
>     key_exchanges:   {type: array, items: {type: string}}
>     ciphers:         {type: array, items: {type: string}}
>     macs:            {type: array, items: {type: string}}
>     host_keys:       {type: array, items: {type: string}}
>     public_key_auth: {type: array, items: {type: string}}
> ```
>
> With it, the server computes each axis exactly as the proxy does. It takes the
> profile's list, narrows the key exchanges to the declared level's set,
> subtracts the bans, and refuses an empty axis. If upstream prefers to narrow
> the server's MUST NOT to what the declarations let it judge instead, that is a
> real answer too.

**What downstream cannot do until this lands.** In the request's words:

> A ban that empties the cipher, MAC, host-key or public-key-auth axis of a
> `default` or `legacy-rsa-sha1` route passes Control's authoring checks with
> only an advisory. Every proxy then refuses that route at its first authorize
> as a contract violation. The route has an outage (fail-closed, never a
> widening), found at connect time rather than at publish time.

A contract violation is §4.3's **outage** branch. So the failure lands in
exactly the emergency the ban was meant for: an advisory, and the runbook's ban
→ `cache_invalidate` → `session_kill`. Control built the seam unwired and
approximated nothing.

**Taken as asked, shape included.** The request is right, in the form
requested, and nothing here contradicts a D decision:

- **The shape as sketched.** Each entry is flat: `profile` beside the five axis
  lists, with every axis **required**. The flat form mirrors
  `AlgorithmFloorCapability`'s `{level, key_exchanges}`. The axis keys are the
  five this contract already spells one way. `required` is what makes the
  judgement exact, because a server never has to decide what a missing axis
  means.
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

**The alternative the request offers, declined.** The request would also accept
narrowing Control's MUST NOT to what the declarations already let it judge.
That changes nothing the proxy does. The proxy still refuses the route, so the
only effect would be to make the outage contract-compliant rather than
prevent it, and the outage arrives exactly when a ban is issued in a hurry.
The declaration costs one derived list per profile, on a request that already
carries two derived declarations. So the gap is closed at its source.

**One addition the request's composition sentence leaves out.** A server that
subtracts bans from alias-complete lists by plain set difference judges wrong.
`curve25519-sha256` and `curve25519-sha256@libssh.org` are **one exchange**
(`AlgorithmBans` already says so), and a ban on either spelling removes both.
Take a ban that removes every other exchange the route offers (under its floor,
if it has one), and names `curve25519-sha256` but not its alias. Plain
subtraction leaves the `@libssh.org` spelling and judges the axis non-empty.
The proxy leaves nothing and refuses the route. The server would then
under-refuse, which is the outage this phase exists to prevent. So
`api/README.md`'s composition rule states the one-exchange rule as a step, and
the sufficiency test below covers this case for each spelling.

**Settled by existing decisions, not re-opened here.** The declaration makes no
profile widenable and introduces no finer preset. It is a report, not a list a
server sends (§4.2, "A list may narrow a route, never widen it"). It is request
data, which `policy_version` does not govern (`api/README.md`, the 0045
precedent), so it moves `info.version` and not the vocabulary number.

## Objective

Add `capabilities.algorithm_profiles` to `AuthorizeRequest`. It declares, for
every `algorithm_profile` this build accepts, what that profile offers on each
axis before any floor or ban, in the flat shape the request sketched, with
every axis required. It is built by the function every connection dials with.
Prove in a test that these lists and `algorithm_floors` are enough to
reproduce `Validate`'s axis-emptiness refusal exactly.

## The shape

### Contract (`api/control.yaml`)

Take the request's sketch as the schema, with its descriptions written out.
`ProxyCapabilities` gains one property, beside `algorithm_floors` and
`algorithms`:

```yaml
        algorithm_profiles:
          type: array
          description: |
            Every `algorithm_profile` this build accepts, one entry per
            profile, each with what that profile offers on the proxy→target
            leg **in this build**, per axis, before any `algorithm_floor`
            narrows it and before any `algorithm_bans` subtract from it: the
            profile stage of the expansion every connection dials with. Lists
            are alias-complete, as `algorithm_floors` is.

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
      description: |
        One `algorithm_profile` a proxy build accepts, and what it offers on
        each axis before any floor or ban. Every axis is present.
      required: [profile, key_exchanges, ciphers, macs, host_keys, public_key_auth]
      properties:
        profile:
          type: string
          enum: [default, legacy-rsa-sha1, legacy-device]
        key_exchanges:
          type: array
          items:
            type: string
        ciphers:
          type: array
          items:
            type: string
        macs:
          type: array
          items:
            type: string
        host_keys:
          type: array
          items:
            type: string
        public_key_auth:
          type: array
          items:
            type: string
```

The five axis keys are the ones `AlgorithmBans` and `OfferableAlgorithms`
already use. `OfferableAlgorithms` itself does not change: it stays the
build-wide union.

Update the `info.description` paragraph that lists what a proxy **declares**
on the request as outside `policy_version`, so that it names
`algorithm_profiles` too.

In `api/README.md`, the per-proxy bullet of "**Capability advertisement**"
names the new declaration and what it is for: an exact authoring-time refusal.
It also states the composition rule a server applies:

1. start from the profile's list on each axis;
2. under a floor, intersect key exchanges with that level's declared list;
3. subtract the bans, treating `curve25519-sha256` and
   `curve25519-sha256@libssh.org` as one exchange: a ban on either removes
   both.

An axis left empty is refused. **Write the rule once, in the README, in terms
of the declared lists. Do not restate the lists themselves anywhere in prose.**

### Go (`internal/control`)

```go
// enforcement.go, beside AlgorithmFloorCapability
type AlgorithmProfileCapability struct {
	// Profile is the algorithm_profile value.
	Profile AlgorithmProfile `json:"profile"`
	// Algorithms is what the profile offers, per axis, before any floor or
	// ban. It is embedded, so the five axis keys sit beside `profile` on the
	// wire and are spelled by the one type that spells them.
	Algorithms
}

// ProxyCapabilities gains, beside AlgorithmFloors:
	AlgorithmProfiles []AlgorithmProfileCapability `json:"algorithm_profiles,omitempty"`
```

Embedding keeps the rule in `Algorithms`' doc comment, that an axis is spelled
one way. Update that comment, which says a list per axis travels in two places,
to say three. Embedding has three consequences, and each is owed a test or a
line:

- **`required` rests on an invariant.** `Algorithms`' fields are `omitempty`,
  and the contract makes every axis required. That holds only because no
  profile offers an empty axis (0043: `default` is the library's secure set on
  every axis). Pin it: marshal every entry `AlgorithmProfileCapabilities()`
  returns, and assert that all five keys are present and non-empty.
- **`jsonFields` must see the embedded fields.** In `contract_test.go` it reads
  only tagged fields, so it would see `profile` and silently skip the five
  axes. Teach it to descend into an anonymous struct field, so
  `TestSpecDocumentsTheAlgorithmSchemas` checks every key the type sends.
- **The promoted `Clone` is not the entry's.** It returns only the embedded
  `Algorithms`. `ProxyCapabilities.Clone` copies each entry as
  `AlgorithmProfileCapability{Profile: e.Profile, Algorithms: e.Algorithms.Clone()}`,
  beside the `AlgorithmFloors` loop.

```go
// algorithms.go, beside AlgorithmFloorCapabilities
func AlgorithmProfileCapabilities() []AlgorithmProfileCapability
```

- One entry per `AlgorithmProfiles()`, in that order.
- Each entry is `AlgorithmPolicy{Profile: p}` expanded with no floor and no
  bans. Key exchanges come from `WireKeyExchanges()`, so they are
  alias-complete, exactly as in `AlgorithmFloorCapabilities`. Every other axis
  comes from `Algorithms()`.
- Nothing is written out by hand. The doc comment says why, in the words
  `OfferableAlgorithms` and `AlgorithmFloorCapabilities` already use.

`internal/auth/target.ProxyCapabilities()` sets
`AlgorithmProfiles: control.AlgorithmProfileCapabilities()` beside
`AlgorithmFloors`, and the comment above it covers both.

### Mock (`cmd/mock-control`)

The mock does no authoring, so it does not judge bans. It must accept the new
field on authorize, which it already does if it decodes into
`control.ProxyCapabilities`, and a test must show that. **Do not add a refusal
to the mock.** Nothing here asks the server to refuse anything new at serve
time.

## In scope

- `api/control.yaml`: the property, the schema, the `info.description`
  update, and `info.version` one minor up.
- `api/README.md`: the "Capability advertisement" bullet and the composition
  rule.
- `internal/control`: the type, the builder, the `Clone` change, `Algorithms`'
  doc comment, `jsonFields`, and the tests below.
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
  profile's no-floor, no-ban expansion, with alias-complete key exchanges, and
  all five axes are present and non-empty on the wire.
- **The declaration is sufficient, and this is the test that proves the
  request is met.** A reference judgement is written in a test, using **only**
  the wire declaration (`algorithm_profiles` and `algorithm_floors`, decoded
  from JSON, never from Go internals) and the composition rule in
  `api/README.md`. It must agree with `Validate`'s axis-emptiness refusal:
  - for every accepted profile × floor pair (absent, `modern-kex`,
    `pq-hybrid-kex`; `legacy-device` × floor is refused and is excluded);
  - for a ban set that, on each axis in turn, removes: everything; everything
    but one; one; and a name no build offers. On the key-exchange axis, add
    each curve25519 spelling alone, both together, and every other exchange
    plus one spelling. The last is the case plain set subtraction gets
    wrong.

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
  `TestSpecDocumentsTheAlgorithmSchemas`, with `jsonFields` descending into
  the embedded `Algorithms`, covers all six properties of
  `AlgorithmProfileCapability`. It also pins the schema's `required` list as
  all six, and the `$ref` from `ProxyCapabilities.algorithm_profiles.items` to
  `AlgorithmProfileCapability`.
- `ProxyCapabilities.Clone` deep-copies the new field. Mutating the clone's
  lists leaves the original intact, and this is tested.
- The mock accepts an authorize request carrying the field.
- `make build vet test lint`, the licence-header check and
  `go test ./test/docs/...` pass.

## Required tests

- `internal/control`:
  - `AlgorithmProfileCapabilities` matches `AlgorithmPolicy{Profile: p}` per
    profile, alias-complete, in `AlgorithmProfiles()` order;
  - every entry marshals with all five axis keys present and non-empty. This is
    the invariant `required` rests on;
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
  - **Wire Control's seam to `capabilities.algorithm_profiles`.** The seam is
    named for "each build's offer per profile and per axis". It is in Control's
    0014 item 4, which was still queued when this prompt was written and
    already expects this: "If the declaration has landed and been synced, wire
    it in place of 'unknown'". Land the wiring there. If 0014 has been
    implemented by the time of the sync, land it in the queued prompt that owns
    the seam. Use the composition rule in `api/README.md`, the curve25519 step
    included, so that "unknown" remains only for a proxy whose declaration
    omits the profile or omits `algorithm_profiles` altogether.
  - **Refuse exactly what the proxy refuses**, and apply the refusal per
    proxy. The declarations are per build, so during a rolling upgrade one ban
    can empty an axis on one build and not on another. A proxy whose own
    declaration shows the axis emptied refuses that route. Decide, under its
    M17, whether the author sees that as a refusal or as a per-build finding,
    and say which. **Never copy the lists into code**, which #41 already
    forbids.
  - Record the declaration per proxy within its M5 budget, beside
    `algorithm_floors`, if its fleet view shows per-build offers.
  - Its 0014 item 2 asks whether a floor-only declaration counts for
    `ProxyCapabilities.Declares()`. A profiles-only declaration raises the same
    question. Answer it there, the same way.
  - Update its PLAN §5.2 and §10's 0014 row, which record this as a named
    cross-repo dependency, to say it is met, citing this repository's PR.
- **The learnings summary** names:
  - the field, the type and the builder;
  - that the lists are pre-floor and pre-ban, alias-complete, with every axis
    required;
  - the composition rule, the curve25519 step included, and the test that
    proves it sufficient;
  - the new `info.version`;
  - what Control must change. That last item is what the sync session reads.
