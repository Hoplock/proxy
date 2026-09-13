# 0037 — Drop the superseded contract vocabularies — Learnings

## Summary
- **What shipped:** one live contract vocabulary. The singular `target_auth`
  field, the both-present refusal, the shape normalisation, and every
  version-history section and "since contract vN" annotation are gone.
  `target_auth_ladder` is now the only way a server names a credential method.
- **Key packages/files:** `api/control.yaml`, `api/README.md`,
  `internal/control` (`contract.go`, `validate.go`, `clone.go`, `policy.go`),
  `internal/routing/resolve.go`, `internal/auth/target/selector.go`,
  `cmd/mock-control` (`fixtures.go`, `server.go`), both fixture files,
  `docs/PLAN.md` §4.2.
- **Key interfaces/types:** `AuthorizeResponse.TargetAuth` **removed** (the
  `TargetAuth` *type* stays — it is the ladder's element);
  `routing.Route.TargetAuth` removed, replaced by
  `routing.Route.NamedCredentialMethod()`; `AuthorizeResponse.Ladder()`
  collapsed to one shape; `AuthorizeRequest.PolicyVersion` is now **required**
  (`json:"policy_version"`, no `omitempty`).
- **Decisions affected:** D6a, D13, D14 prose restated in the present tense; no
  register row moved. D3's cross-repo obligation applies (contract change).
- **Gotchas:** removing superseded *versions* is not removing *versioning* —
  `policy_version`, `control.PolicyVersion`, the MUST-NOT-answer-above rule and
  `vocabularyVersion()` are all intact and tested. `policy_version` now has no
  absent-value default; the mock answers `400` to a request without one.
- **What the NEXT session must know:** **one live vocabulary from here on, and
  the next revision bumps `PolicyVersion` rather than keeping this one alive
  beside it.** Write the new field in the present tense, tier it in
  `vocabularyVersion()` above the current baseline, and move the consumers with
  it under `docs/CROSS-REPO-PROTOCOL.md`.

## Details

### The two decisions this phase had to settle first

**1. The release vocabulary keeps its number: `PolicyVersion` stays `4`,** and
the next revision is `5`. Renumbering the baseline to `1` was the alternative
and was rejected for the reason the prompt gave: every frozen record in
`docs/learnings/` and `prompts/implemented/` describes a *different* v1, v2 and
v3, so renumbering would make those records ambiguous rather than merely
historical — and `1` collides with the `/v1` path prefix, which is a different
numbering entirely.

`info.version` in `api/control.yaml` moved **4.3.0 → 4.0.0**. It is the
*document's* version and it encoded the revision history (`.3` was the third
revision on top of v4); with one vocabulary there are no revisions on top of it
yet. It is still meaningful and still moves at the next revision — that is the
only property the prompt asked it to keep. Nothing pins it (no test, no
consumer in this repo), but Control's prompts cite `4.3.0` as the vendored
document version, so this is a sync obligation.

**2. The `/v1` path prefix stays.** It is a URL namespace, not a compatibility
layer: no path was ever served at another prefix. What went is the prose
explaining why it "stays at `/v1`" across vocabulary revisions, which only makes
sense to a reader who knows there were revisions.

### What was actually removed, beyond the prompt's inventory

The prompt's inventory was taken at phase 0016 and said so. Re-derived on `main`
at `ae8a239`, the real list added:

- **`api/control.yaml` had no 4.3 section** in `info.description` — phase 0035
  put the uid-lease substance on the endpoint and bumped `info.version` only.
  `api/README.md` did have a `v4.2→v4.3` section. So five `info.description`
  sections were deleted (v2, v3, v4, 4.1, 4.2) and seven README revision
  sections (v4.2→v4.3 down to v1→v2).
- **`AuthorizeRequest.policy_version` had `default: 1`** in the schema *and*
  `omitempty` on the Go field. Both are gone; see "policy_version is now
  required" below.
- **Version dating had spread well past `api/`** — 40-odd `(contract v4, …)` /
  `(contract 4.1, phase 0023)` markers across `internal/logging`,
  `internal/proxy`, `internal/config`, `cmd/loadgen`, `cmd/proxy` and the
  fixture YAMLs, plus "what a v1/v2/v3 server meant" phrasings on absent-value
  defaults in `internal/channel`, `internal/routing`, `internal/control` and
  their tests. All restated in the present tense; `phase NNNN` provenance
  markers were **kept** — they say who built a thing, not which generation it
  belongs to.
- **Both fixture files used the singular `target_auth` heavily** — 9 routes in
  `cmd/mock-control/fixtures.example.yaml` and 22 in
  `deploy/control/fixtures.template.yaml`. Each became a one-entry
  `target_auth_ladder`. The conversion was done by script and checked
  semantically (parse before, parse after, assert the only difference is
  `target_auth: X` → `target_auth_ladder: [X]`), then the rendered deploy
  template was run through the real `parseFixtures` — 37 routes, all valid.

### `policy_version` is now required

The prompt asked for a deliberate answer to "what does absent mean now?", since
absent used to mean "the phase 0002 vocabulary". The answer chosen is
**required, and a request without it is refused**:

- `AuthorizeRequest` lists `policy_version` in the schema's `required` array and
  the `default: 1` is gone.
- The Go field lost `omitempty`, so it always travels. `RESTClient.Authorize`
  already filled it in when zero, so no caller changed.
- `cmd/mock-control` answers `400 invalid_request` to a request without one —
  a `400` rather than a `500` because the request is malformed, not the policy.

The reasoning, written into both documents: a proxy that cannot say what it is
able to read is one the server would have to guess for, and the guess decides
which restrictions get silently dropped.

### What was kept, and why each is not the target

Four things resemble what this phase removed and are load-bearing:

1. **The versioning mechanism.** `policy_version` on every request,
   `control.PolicyVersion`, the MUST-NOT-answer-above rule, and
   `vocabularyVersion()` in `cmd/mock-control` (the server half — the `500` a
   proxy one vocabulary behind gets, instead of policy it would refuse).
   `vocabularyVersion()` now returns the single baseline for every response and
   carries a comment showing where the next revision's fields get tiered above
   it. It is not vestigial: the tiering point is the whole reason it survived.
2. **Strict decoding / fail-closed**, with its `policy_version` justification
   intact. Refusing an unknown field is only defensible against a server that
   can tell what this proxy can read.
3. **The open namespaces** — `params` and `device_field.<name>`. Extension
   points, not back-compat.
4. **The `legacy-rsa-sha1` / `legacy-device` profiles.** "Legacy" there is about
   the *device*, permanently.

### The three live reasons rescued from the deleted history

The prompt was right that three revision sections carried reasoning rather than
chronology. Each was restated in the present tense, beside what it governs:

- **4.1's** reason — `policy_version` governs `/v1/authorize` and nothing else,
  because that is the response decoded strictly and so the only place an unknown
  field could be a restriction — is now a paragraph in `info.description`'s
  "Versioning" section, in the `policy_version` property description, and in
  `api/README.md`'s versioning section.
- **4.2's** reason — a *tightening* adds no field and changes no field's
  meaning, so it is not expressible through the version at all and is announced
  as a break — is beside `policy_version` in both documents and on
  `params.username` itself.
- **4.3's** two statements — the per-target allocation cursor only ever
  advances, and why the uid floor is **not** a field on the cacheable authorize
  response — were already beside the endpoint in `control.yaml`; they were
  missing from `api/README.md` once its revision section went, so they were
  written into the "Ephemeral uid blocks" section there.

### Tests: what was deleted, what was re-expressed

Deleted, because the shape is gone and the test had no subject left:

- `control.TestV2SingleObjectReadsAsAOneEntryLadder` — replaced by
  `TestOneEntryLadderIsD6aExactly`, which asserts the same property (a one-entry
  ladder is D6a unchanged) against the shape that still exists.
- `control.TestBothShapesTogetherIsRefused` and the mock's
  `TestFixturesRefuseBothCredentialShapes` — there is one shape to set.
- `enforcement_test.go`'s "the single v2 object is brokered-key" subtest and
  `ladder_test.go`'s two "as a single object" halves — each had a ladder-shaped
  twin already asserting the same rule.
- `server_test.go`'s "a v2 route still answers a v2 shape" subtest — re-aimed at
  what it now proves: a route naming one method and no profile.

Re-expressed, **not** deleted — this is the regression test for the next bump:

- `TestVersionGateAnswersPerRoute` became
  `TestTheVersionGateIsTheMechanismForTheNextBump`. It asserts that a proxy
  declaring `control.PolicyVersion` is served every route, that a proxy
  declaring `PolicyVersion-1` gets the `500` naming the mismatch, and that a
  request with no `policy_version` gets the `400`. The comment says where the
  next revision re-introduces the per-route distinction.
- `control.TestAuthorizeDeclaresItsPolicyVersion` and the strict-decode /
  `ErrProtocol` tests are untouched.
- The clone and mutation tests keep their full surface with the singular field's
  entries dropped. `internal/control`'s contract cross-check
  (`TestSpecDocumentsThePolicySchemas`, `TestReadmeDocumentsTheContract`) lost
  exactly one entry — `target_auth`, the deleted field — and nothing else; it
  was not narrowed to accommodate the deletions.

`internal/routing` gained `TestResolveCarriesThePolicyVocabulary`'s ladder
assertions and a `NamedCredentialMethod()` check on both the named and the
unnamed route, so removing the mirroring block is covered by behaviour.

### `Route.TargetAuth` and the mirroring block

`internal/routing` used to normalise both ways: a singular field became a
one-entry ladder, and a ladder's first entry was copied back onto the singular
field. Both are gone. Two consumers read the singular field and were rehomed:

- `internal/proxy/session.go` passed `Auth: route.TargetAuth` into
  `target.Target`. That was always redundant — `Selector.provisionOne` sets
  `tgt.Auth` to the rung it is running, on every path — so the line was simply
  deleted. `Target.Auth`'s doc comment now says it is *set by the Selector*, per
  rung, and is never a caller's input.
- `internal/proxy/logging.go` recorded the credential method from it, in two
  places. Both now call `routing.Route.NamedCredentialMethod()`, which returns
  the method the server put **first**. The distinction the old comment drew
  still holds and is still recorded: which rung was *used* comes from the
  provisioner, not from the route.

`Selector.rungs()` lost its `tgt.Auth` fallback. Several
`internal/auth/target` tests were passing a route through `Target.Auth` to
`selector.Provision` and only passing because the selector's fallback happened
to be the same method; they now pass a `Ladder`, which is what the Selector
reads.

### Verification

- `go build ./...`, `go vet ./...`, `go vet -tags e2e ./...`, `go test ./...`,
  `go test ./test/docs/...`, `make license-check` all pass.
- `golangci-lint` **could not be run in this session** — the installed binary is
  built against go1.25 and the module targets go1.26, so it refuses to load its
  config. CI runs it.
- The **e2e topology could not be run**: Docker is unavailable in this session.
  `go test -tags e2e ./test/topology/` — which parses every deploy config and
  `deploy/control/fixtures.template.yaml` and asserts the properties the
  scenarios depend on — passes, and the rendered template was additionally run
  through `cmd/mock-control`'s real `parseFixtures` (37 routes). CI runs the
  Docker half.
- **A pre-existing flake in `internal/proxy` is not from this change.** Tests in
  that package intermittently fail with `exec request: EOF` (seen on
  `TestCIMayRunCommandsButNeverGetsATerminal` and
  `TestAPTYRequestRecordsTheReplayHeader`) at roughly 1 run in 16. It reproduces
  on `main` with the branch stashed. Left alone: fixing it is a different phase.

### The greps

Run over the whole repository, excluding `prompts/implemented/` and
`docs/learnings/` from edits but not from the search:

```
grep -rn "policy_version\|PolicyVersion\|vocabularyVersion" .
grep -rni "contract v[0-9]\|contract [0-9]\.[0-9]\|vocabulary v[0-9]\|policy vocabulary" .
grep -rn "v1 server\|v2 server\|v3 server\|v4 server\|older proxy\|a v2 proxy" .
grep -rni "since v[0-9]\|since contract\|before v[0-9]\|unchanged from v[0-9]\|superseded" .
grep -rn "target_auth\b\|TargetAuth\b" --include=*.go --include=*.yaml .
```

The affected learnings files were derived, not copied from the prompt:
`grep -rln "policy_version\|PolicyVersion\|vocabulary v\|contract v[0-9]\|contract 4\." docs/learnings/`
returns nine — 0006, 0007, 0013, 0014, 0016, 0018, 0023, 0028, 0035 — three more
than the prompt's as-of-0033 list, because 0007 and 0014 cite the vocabulary
they consume and 0035 added the newest revision. Each got the one-line pointer
and nothing else.

### The plan's indexes (PROTOCOL §3)

- **§5.3's "What is true today"** — refreshed. Its "Scope, and what a route may
  name" paragraph dated `device_field.<name>` to "contract v3.1"; the label is
  gone and the rule reads in the present tense. No layer was added, so the
  header's layer count is unchanged and
  `TestDeviceSeamHeaderCountsItsLayers` still passes.
- **§2's decision register** — **checked, and no row changed.** D5a, D6a, D13
  and D14 all had prose rewritten, but none moved or lost a rendering: D5a is
  still §6.2/§6.3, D6a still §5.1/§5.2, D13 still §5.3, D14 still §4.2/§5.3, and
  no Status changed (D14 still amends D6a; D13's three amendments stand).
- **§10's composed mapping** — **deliberately untouched.** This phase renumbers
  nothing, so `renumberings` in `test/docs/indexes_test.go` gains no entry.

### Cross-repo

`hoplock/control` has real obligations and they are in the PR's
`## Cross-repo impact` section with a ready-to-run sync kickoff.
`hoplock/enterprise` is **None**: its only hits on the contract are inside its
mirrored copy of `docs/CROSS-REPO-PROTOCOL.md`, which this PR does not change.

### `prompts/queued/` is now empty, and stays present

This is the last queued prompt, so moving it emptied the directory — and git
does not track directories, so it vanished and
`test/docs/indexes_test.go` failed on a missing path. An empty queue is a
legitimate state and the directory is part of the workflow
(`docs/PROTOCOL.md` §0 step 4 sends every session to it), so it is held open
with `prompts/queued/.gitkeep`. Both tests already ignore it: one keys on a
4-digit prefix that parses as an int, the other on the `.md` suffix.

### Follow-ups

None queued.
