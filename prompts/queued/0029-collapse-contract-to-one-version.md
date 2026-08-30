# 0029 — Drop the superseded contract vocabularies

> **New prompt, and it must run LAST.** Every phase that revises the contract
> adds a vocabulary generation and, with it, code and prose that keep the
> *previous* generation working. That is correct while building in phases: each
> revision has to leave the one before it functioning so the phases already
> merged keep passing. It stops being correct at release. Proxy and Hoplock
> Control ship together, and nothing older than that release has ever been
> deployed — so every line that exists to keep a v1, v2 or v3 peer working is
> describing a peer that does not exist and never will.
>
> **Read the next section before anything else.** This phase removes support for
> *superseded* versions. It does **not** remove the versioning mechanism, and
> getting that backwards would break the product's ability to evolve after
> release.
>
> **This prompt must be the highest-numbered queued prompt when it runs.** If a
> later session queues work after it, renumber under `docs/PROTOCOL.md` §6 so
> this stays last. In particular it **cannot start before 0018 (contract v4) has
> merged**, and before any contract revision 0021 turns out to need — collapsing
> before the last revising phase just means doing it twice.

## What this phase removes, and what it must keep

These are two different things and the whole prompt turns on the difference.

**Removed — support for superseded versions.** At release the contract has one
live vocabulary: the highest one development reached. Everything that exists so
that an *older* peer keeps working goes with the versions it served — the
superseded field shapes kept alive beside their replacements, the normalisation
that translates between an old shape and a new one, the absent-value defaults
whose only justification is "that is what a v1 server produced", and the prose
narrating what each generation added.

**Kept — the versioning mechanism itself.** `AuthorizeRequest.policy_version`,
`control.PolicyVersion`, and the rule that **the server MUST NOT answer with
policy fields introduced after the version the proxy declares** all stay, fully
working. They are not back-compat debt; they are how the contract evolves
*after* release. A v5 will land one day, a fleet will not upgrade atomically,
and that mechanism is what makes a mid-upgrade fleet safe rather than an
outage. It also stays load-bearing for the proxy's fail-closed rule: refusing an
unknown field is only safe for a server that can tell what this proxy can read.

So after this phase the mechanism is intact and its *history* is empty: one
declared version, one vocabulary, and a documented path for the next one.

Three further things resemble the target and are **not** it — deleting them
would be a regression, not a simplification:

1. **Strict decoding / fail-closed on an unknown field.** Unchanged, and it
   keeps its `policy_version` justification.
2. **The open namespaces** — `target_auth` `params` and `device_field.<name>`.
   These are extension points for platform-specific data, deliberately open so a
   new driver is not a schema change.
3. **The `legacy-rsa-sha1` / `legacy-device` algorithm profiles.** "Legacy"
   there means *the device on the far end is old*, a permanent fact about real
   estates, not a statement about this contract's history.

## Read first
- `docs/PROTOCOL.md` — session workflow, and **§3's rename rule** (nothing may
  point at a name you deleted). This phase deletes more names than any phase so
  far; that rule is much of the work.
- `docs/CROSS-REPO-PROTOCOL.md` — **in full**. This touches `api/`, the shared
  surface `hoplock/control` vendors (D3), so §2 (upstream merges first), §4 (the
  `## Cross-repo impact` section and the ready-to-run sync kickoff you owe) and
  §5 all apply.
- `docs/PLAN.md` — D2, D3, D5a, D6a, D11, D12, D13, D14, §5.3, §10, §11.
- `api/control.yaml` and `api/README.md` — **as they stand on `main` when you
  start**, not as described below. The inventory in this prompt was taken when
  `main` was at phase 0016; phases 0017–0028 will have added to it.
- `docs/learnings/` summaries: **0002** (the contract and mock), **0006**
  (vocabulary v2 and the `policy_version` pattern), **0013** (v3, the ladder,
  the one deliberate break), **0016** (v3.1 and `device_field.<name>`), plus
  whatever 0018 left behind for v4.

## Objective

Leave exactly one **live** vocabulary in the repository — the current one,
stated in the present tense — while leaving the versioning mechanism able to
carry the next one.

The test of success is a reader's: someone opening `api/control.yaml` and
`api/README.md` for the first time should never have to work out which
generation a field belongs to before they can use it, and should still find a
clear answer to "how do I add a field in the next version?".

## Two decisions to settle first

Settle both before you start editing, and record the answer in the PR.

**1. What number the release vocabulary carries.** Two defensible answers: keep
the number development reached (if the last revision was v4, `PolicyVersion`
stays `4` and the next is `5`), or renumber the release baseline to `1` because
it is the first vocabulary ever released.

**Recommend: keep the number.** Renumbering makes every frozen record in
`docs/learnings/` and `prompts/implemented/` — which describe a *different* v1,
v2 and v3 — ambiguous rather than merely historical, and it collides with the
`/v1` path prefix, which is a different numbering entirely. Continuing the
sequence costs nothing and stays unambiguous forever.

**2. The `/v1` path prefix: keep it.** It is a URL namespace, not a
compatibility layer — no path was ever served at another prefix, and renaming
every endpoint is churn with a cross-repo cost. What goes is the *prose*
explaining why the prefix "stays at `/v1`" across vocabulary revisions, which
only makes sense if the reader knows there were revisions. If you disagree after
reading the contract, raise it with the user before changing paths — do not
decide it silently.

## In scope

The lists below are the inventory as of phase 0016. **Treat them as a starting
point, not as the specification** — re-derive the real list on `main` with the
sweep in "How to find all of it", and say in your PR what you found beyond this.

### 1. `api/control.yaml`

- **`info.description`** — delete the "Policy vocabulary v2 (phase 0006)" and
  "Policy vocabulary v3 (phase 0013)" sections (and v4's, from 0018). Rewrite it
  as a single statement of what the contract is. Keep the substance those
  sections introduced — the fail-closed rule, the whole-policy-per-authorize
  model, `401` as a decision — and drop the framing that it *changed*.
- **`AuthorizeRequest.policy_version` — the property stays.** Rewrite its
  description: today it enumerates what versions 1, 2 and 3 each contained.
  Replace that history with the current version, the MUST-NOT-answer-above rule,
  and its relationship to fail-closed decoding. Drop the `default: 1` — an
  absent `policy_version` used to mean "the phase 0002 vocabulary", and there is
  no such peer now. Decide deliberately what absent means instead (recommend:
  required, or refused — a proxy that cannot say what it reads is not one this
  contract knows) and write it down.
- **`target_auth` (singular) on the authorize response** — remove the property.
  `target_auth_ladder` becomes the only way a server names a credential method,
  and the "a response carrying both is refused" rule disappears with the field
  it guarded. Move any documentation living on the singular object (the method
  enum, the `params` namespace, the per-method parameter tables) onto the ladder
  entry schema; none of it may be lost.
  - **Note the type-vs-field distinction:** the *entry* schema is still needed —
    a ladder is a list of exactly these objects. It is the top-level singular
    **field** that goes.
- **Per-field version prose** — every "since contract v3", "contract v3.1",
  "Before v3 it defaulted to…", "unchanged from v2", "a v2 server keeps sending
  this object", "what a v1 server implies", "this is the one break in v3". A
  field says what it means; it does not narrate how it got there. Where such a
  sentence carries a *reason* that is still load-bearing — e.g. **why**
  `username` is required on every provisioning method, that `identity.Login` is
  a client-typed string that must never decide authorization — keep the reason
  and drop the chronology.
- **Absent-value defaults: check each one, do not sweep.** Many are real
  present-tense semantics ("absent means use local config") and stay. Some exist
  only to reproduce an older generation's behaviour, and those go with it. The
  question for each field is: *if this contract had been written from scratch
  today, would the default still be there?* Keeping a default is fine; keeping
  a default whose only documented reason is "that is what a v2 server produced"
  is the thing this phase exists to remove — restate the reason or remove the
  default.
- **`info.version`** — set to the release vocabulary settled above (e.g.
  `4.0.0`), and keep it meaningful: it moves again when v5 lands.

### 2. `internal/control`

- `contract.go`: **keep** the `PolicyVersion` constant, set to the release
  vocabulary; rewrite its comment, which currently narrates what v1, v2 and v3
  each added. What it should say instead: what this version is, that the server
  must not answer above it, and that a future revision bumps it — the same
  mechanism, with no history behind it.
- `contract.go`: **keep** `AuthorizeRequest.PolicyVersion`.
- `contract.go`: delete `AuthorizeResponse.TargetAuth` (the singular field) and
  collapse `AuthorizeResponse.Ladder()` — with one shape there is nothing to
  choose between, and the method may no longer be earning its place. Keep the
  `TargetAuth` **type**: it is the ladder's element.
- `validate.go`: delete the both-present-is-a-violation check and any rule
  phrased in terms of a superseded version.
- `clone.go` and the mutation test: drop the singular field's entries. The
  mutation test itself **stays** — it is what stops a future v5 field being
  added in one place and forgotten in three.
- `policy.go`: version chronology in doc comments.

### 3. `internal/routing` and `internal/auth/target`

- `internal/routing/resolve.go`: `Route.TargetAuth` and the normalisation block
  that mirrors the singular field into a one-entry ladder and back (~lines
  271–289 as of 0016). One shape in, one shape stored.
- `internal/auth/target/selector.go`: `rungs()` currently falls back to
  `tgt.Auth` when there is no ladder. That fallback goes with the field.
- Anything else reading the singular form — sweep, do not guess.

### 4. `cmd/mock-control` and the fixtures

- `fixtures.go`: `vocabularyVersion()` currently tiers response fields into
  versions 3, 2 and 1. **Keep the function and the `500` it drives in
  `server.go`** — that is the server half of the mechanism, and it is what a
  v5-aware Control will need. Collapse its tiers to the single release baseline
  and leave a comment saying where a future version's fields get tiered above
  it.
- Fixture support for the singular `target_auth`, in `fixtures.go`,
  `cmd/mock-control/fixtures.example.yaml` and
  `deploy/control/fixtures.template.yaml` — including the "Required since
  contract v3" comments, which become "Required".
- `server_test.go`: split the version tests by what they actually assert.
  - Tests that a **superseded shape** still works (a fixture in the v2 shape, a
    response carrying the singular field) — delete; the shape is gone.
  - Tests of the **mechanism** (a proxy declaring a version below what the route
    needs gets a `500` rather than policy it would reject three lines later) —
    **keep**, re-expressed against the release baseline. This is the regression
    test for the next bump and it must not be deleted along with the history.
  - Do not weaken a test into passing. If one no longer has a subject, delete it
    and say so in the PR.

### 5. Docs

- `api/README.md`: delete the "v3→v3.1", "v2→v3" and "v1→v2 rename" revision
  sections (and v4's), and the version rows/columns in the field tables that
  date a field to a generation. **Keep and rewrite** the `policy_version`
  negotiation paragraphs — they document a live mechanism, and they currently
  explain it through its history.
- `api/README.md` **"Changing the contract"** — this recipe stays, and step 4's
  "bump `control.PolicyVersion`" is the point of the whole phase surviving
  intact. Extend it with what this phase establishes: a revision adds a
  vocabulary, it does **not** keep the previous one alive, and consumers move
  with it under `docs/CROSS-REPO-PROTOCOL.md`.
- `docs/PLAN.md`: the phase table's contract-version labels, and the passages in
  D5a, D6a, D13, D14 and §5.3 that describe keeping older generations working.
  **Add a short note recording this collapse and its boundary** — superseded
  vocabularies removed, mechanism retained — so a future session reading an
  older learnings file does not reintroduce the pattern, and does not conclude
  the versioning was abandoned.
- `README.md`: the "since contract v3" reference (~line 43).
- `config.example.yaml` and any Go comment dating a behaviour to a superseded
  contract version.

### 6. What is NOT rewritten

`docs/learnings/` and `prompts/implemented/` are **frozen historical records**
(`docs/PROTOCOL.md` §3). 0006, 0013 and 0016's learnings describe contracts that
really did exist here, and they stay true to what their phase shipped. Give the
affected learnings files a **one-line pointer** — "the superseded vocabularies
described here were removed in 0029; the versioning mechanism was kept" — and
change nothing else. Do not rename a file in `prompts/implemented/`.

## Out of scope

- Removing, weakening or bypassing `policy_version`, `control.PolicyVersion`,
  the MUST-NOT-answer-above rule, or `vocabularyVersion()`.
- Renaming the `/v1` paths (see above).
- Removing strict decoding, the fail-closed rule, the open `params` /
  `device_field.<name>` namespaces, or the `legacy-*` algorithm profiles.
- Any behaviour change beyond removing the superseded way of saying something.
  If you find yourself changing what a *live* field means, stop: that is a
  contract revision and it belongs in its own prompt.
- The mock server's debug endpoints and anything else marked "mock-only".

## How to find all of it

Do not work from this prompt's inventory alone. Sweep the **whole repository**
(`docs/PROTOCOL.md` §3), excluding `prompts/implemented/` and `docs/learnings/`
from edits but not from the search — a hit there tells you what to look for in
live files:

```
grep -rn "policy_version\|PolicyVersion\|vocabularyVersion" .
grep -rni "contract v[0-9]\|vocabulary v[0-9]\|policy vocabulary" .
grep -rn "v1 server\|v2 server\|v3 server\|v4 server\|older proxy\|a v2 proxy" .
grep -rni "since v[0-9]\|before v[0-9]\|unchanged from v[0-9]\|superseded" .
grep -rn "target_auth\b\|TargetAuth\b" --include=*.go --include=*.yaml .
```

The first grep is the one whose hits you mostly **keep and rewrite** rather than
delete. Put the greps you ran in the PR body, not the adjective "thorough" — a
reviewer cannot re-derive "I looked carefully"
(`docs/CROSS-REPO-PROTOCOL.md` §5).

## Acceptance criteria

- [ ] `go build ./...`, `go vet ./...`, `go test ./...`, `golangci-lint run` all
      pass.
- [ ] `policy_version` still travels on every authorize request, the server
      still refuses to answer above the declared version, and a test proves both.
- [ ] `control.PolicyVersion` equals the release vocabulary, and no comment,
      schema description or doc enumerates what a superseded version contained.
- [ ] The authorize response has exactly one way to name a target credential
      method (`target_auth_ladder`), and nothing in the repository reads a
      singular `target_auth` field.
- [ ] `api/control.yaml` and `api/README.md` carry no version-history section
      and no per-field "since version N" annotation; every reason those
      sentences carried survives, restated in the present tense.
- [ ] `api/README.md` still tells a future session exactly how to add a field in
      the next vocabulary, and that recipe matches what the code now does.
- [ ] `internal/control`'s contract cross-check test (paths and enums against
      `control.yaml` and `api/README.md`) still passes and still covers the same
      surface — it must not have been narrowed to accommodate the deletions.
- [ ] The e2e topology (`deploy/`, phase 0012) comes up and its scenarios pass.
- [ ] Every fixture in `cmd/mock-control/fixtures.example.yaml` and
      `deploy/control/fixtures.template.yaml` still parses and still expresses
      the same policy.
- [ ] The affected learnings files carry a one-line pointer and are otherwise
      unchanged.

## Required tests

- **The mechanism, unchanged:** a proxy declaring a version below what a route
  needs is answered with the `500`, not with policy it would refuse; a proxy
  declaring the release version gets the route. Re-expressed against the new
  baseline, not deleted.
- An authorize response carrying an **unknown** field is still refused as a
  contract violation (`ErrProtocol`, outage-class, never a deny).
- The `internal/control` validation, clone and mutation tests, updated for the
  single shape — a new field added to the authorize response must still fail the
  mutation test until it is handled everywhere. That is the test protecting v5.
- A route naming a credential method **only** through the ladder provisions
  correctly end-to-end through the mock server, so removing the mirroring block
  is covered by behaviour and not just by compilation.
- `cmd/mock-control` fixture-loading tests over the updated example fixtures.

## Cross-repo obligation

`api/control.yaml` and `api/README.md` are a shared surface: `hoplock/control`
vendors them read-only (D3). This is the largest change that surface has taken,
and it **removes** vocabulary, so a Control that still sends a singular
`target_auth` — or that still implements a superseded generation to be
accommodating — stops being correct the moment this merges. Control keeps
reading and honouring `policy_version`: its obligation is to drop the older
vocabularies, not the mechanism, and the sync must say so in those words or it
will be read as "versioning is gone".

The PR therefore owes, under a heading spelled exactly `## Cross-repo impact`:

- the concrete obligations for `hoplock/control` — every removed field and
  identifier, found by grep across its `prompts/`, `docs/` and `README.md`,
  **and** the explicit statement that `policy_version` support stays;
- a **ready-to-run sync kickoff** for it, filled in from the "Downstream sync"
  block in `docs/KICKOFF.md`, with this PR's URL and a `<short-description>`;
- an explicit **"None"** for `hoplock/enterprise` if that is the finding — an
  omitted section is indistinguishable from never having looked.

Put the kickoff in your reply to the user as well as in the PR body, naming the
repository to run it in and saying plainly that it needs a fresh session with
that repository checked out. Upstream merges first: this PR, then the sync.

## Deliverables

1. The superseded vocabularies removed and every consumer updated, as above,
   with the versioning mechanism intact and tested.
2. `docs/PLAN.md` updated, including the note recording the collapse and its
   boundary.
3. `prompts/queued/0029-collapse-contract-to-one-version.md` moved to
   `prompts/implemented/` (same filename) in this PR.
4. `docs/learnings/0029-collapse-contract-to-one-version-learnings.md`, with the
   summary block `docs/PROTOCOL.md` §5 requires. It must state, for the next
   session: **one live vocabulary from here on, and the next revision bumps
   `PolicyVersion` rather than keeping this one alive beside it.**
5. A PR whose description states the prompt implemented, the two decisions
   settled, the greps run, the deletions made, anything found beyond this
   prompt's inventory, and the Definition of Done checklist.
