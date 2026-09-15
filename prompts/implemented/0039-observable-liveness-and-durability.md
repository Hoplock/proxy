# 0039 — Observable liveness and durability

## Read first
- `docs/PROTOCOL.md` — session workflow, especially §3 (scope, and "the plan is
  written in the present tense"), §7, and §8.
- `docs/PLAN.md` — **§6.4** (policy caching & session revocation, the
  subscription, the fail-closed rule and its two timers) and **§7** (logging &
  telemetry, the two paths and what the priority ack means). Decisions **D2**
  (the proxy originates no policy; Control decides once per connection), **D7**
  (host-key policy comes from the server), **D8** (batch vs priority path).
  **§4.3** for the disclosure rule, because nothing here may change what a user
  is told.
- `api/README.md` — **"Revoking (`GET /v1/proxies/{proxy_id}/events`)"**,
  **"Logs: two paths, on purpose"**, **"Versioning: one live vocabulary, and a
  proxy that fails closed"**, and **"Changing the contract"** (the recipe you
  are following, including which changes bump `control.PolicyVersion` and which
  do not — this one does not).
- `api/control.yaml` — the `RevocationEvent` schema and the
  `/v1/proxies/{proxy_id}/events` path description.
- `docs/learnings/` — read summaries; open
  `0003-policy-caching-and-session-revocation-learnings.md` (the subscription
  loop, the heartbeat timer, and `CacheOptions.StaleAfter`).
- `docs/CROSS-REPO-PROTOCOL.md` — §1, §2, §4. This phase edits `api/`, which is
  a shared surface, so the PR owes a `## Cross-repo impact` section and a
  ready-to-run sync kickoff for `hoplock/control`.

## Where this came from

`hoplock/control` phase 0002 built `cmd/pdpconform`, the black-box conformance
suite that decides whether an implementation of this contract is correct
(control M1). Writing it surfaced **two obligations this contract states but
does not make observable**, so the suite cannot grade them from the wire and
takes them as configuration instead:

1. The contract requires heartbeats "at a steady interval" and control's own
   plan asks a suite to assert they "arrive within the interval the server
   advertises" — but **nothing on the stream advertises one**. A suite has to be
   told the interval out of band, which means it is grading a number a human
   typed rather than a claim the server made.
2. **Nothing in this contract publishes an event or reads a log record back.**
   The priority ack means *durable* and gap recovery means *no event was
   silently skipped*; neither is checkable through the contract surface alone,
   so the suite needs a read path and a publish path the implementation supplies
   from outside it.

Neither is a bug in an implementation. They are gaps in what the document makes
**checkable**, and the fix is different for each: the first is a missing field,
the second is a missing sentence.

## Objective

Make the liveness obligation gradeable from the wire, and make the durability
and no-skip obligations gradeable **honestly** — by saying plainly that they are
not observable through this contract and naming what a harness needs instead.

## In scope

### 1. The server states the heartbeat interval it is keeping

Add an optional field to `RevocationEvent`:

```yaml
heartbeat_interval_seconds:
  type: integer
  format: int32
  minimum: 1
```

Set by the server on `heartbeat` events (it may set it on any event; a proxy
reads it wherever it appears). It names the interval the server is currently
keeping, so a later event may carry a different value and that is a re-statement
rather than a contradiction.

Three rules go in the document beside it, and the field is worth little without
them:

- **Absent means what every server did before the field existed**: the proxy
  falls back to its own timers, exactly as today. This is the same
  absent-value discipline as `HostKeyReportResponse.cache`, and for the same
  reason.
- **It may only ever tighten detection, never loosen it.** A proxy may use it
  to notice a dead stream *sooner* than its configured timeout; it must never
  extend that timeout to accommodate a large advertised interval. Otherwise a
  broken or hostile server could silence itself indefinitely by announcing that
  it intends to — which is the fail-closed rule in §6.4 inverted. Same idiom as
  `cache.ttl_seconds` (a proxy may clamp shorter, never longer) and
  `report_after_seconds` (sooner is always allowed, later is not); say so in
  those words, so a reader meets a rule they already know.
- **There is still a ceiling, and the field does not replace it.** A conformant
  server emits heartbeats comfortably inside the proxy's reconnect timeout
  (20s). State that bound as a number in the document rather than as
  "comfortably": a server advertising 600s and then keeping to it is a server
  that passes its own claim and breaks every proxy in the fleet. **Both** are
  conformance requirements — the server keeps the interval it advertises, *and*
  that interval is within the ceiling.

**This does NOT bump `control.PolicyVersion`.** The number governs
`/v1/authorize` and nothing else, because that is the response the proxy decodes
strictly; a field on another endpoint is the contract's own worked example of
what falls outside it ("Versioning", and "Changing the contract" step 4, whose
condition is a field on `AuthorizeResponse` or something it contains). The
events stream is not decoded strictly — a proxy already ignores an event type it
does not recognise — so this field reaches older peers harmlessly. Leave
`PolicyVersion` at `4`; move `info.version` per this repository's own
convention.

### 2. Say what a conformance harness cannot see

Two paragraphs, no new endpoints.

- Under **"Logs: two paths, on purpose"**: the priority ack means the record is
  durable, and **that guarantee is not observable through this contract** —
  nothing here reads a record back. An implementation that wants the guarantee
  graded exposes a read path of its own, outside `/v1`, and a harness takes it
  as an input. `cmd/mock-control`'s `GET /debug/logs` is the reference shape and
  is already documented as mock-only.
- Under **"Revoking"**: gap recovery promises that a reconnecting proxy is
  either replayed or told `resync`, and never silently skipped. Grading it
  requires an event to be published while the subscriber is away, and
  **nothing here publishes one** — an event originates from an operator action
  on a surface this contract does not describe. Same answer: the implementation
  supplies it, the harness takes it as an input, and
  `cmd/mock-control`'s `POST /debug/revoke` is the reference shape.

Write both as statements of fact about the contract's scope, not as apologies.
Neither operation is proxy-facing, so neither belongs on `/v1`; the point is
that a reader building a server, or a harness, learns this from the document
instead of discovering it.

### 3. Carry it through the repository

- `internal/control` — the field on `RevocationEvent`, with the accessor that
  resolves its absent value (the package's existing idiom: `Ladder`, `Profile`,
  `EnforcedExecution` and friends). Its enum/field cross-check test against
  `control.yaml` and `api/README.md` must still pass, and this file documents
  every field name on the wire, so add it there too.
- `cmd/mock-control` — emit the field, derived from the existing
  `events.heartbeat_ms` fixture key, so the mock advertises what it is actually
  doing. A fixture that disables heartbeats (`heartbeat_ms` negative) advertises
  nothing. Document the behaviour in `api/README.md`'s fixture table.
- `docs/PLAN.md` §6.4 — the subscription's description gains the advertised
  interval and the tighten-only rule. **Revise in place**, present tense; the
  reasoning goes in your learnings file, not in a dated layer under the text it
  supersedes (PROTOCOL §3).

## Out of scope

- **Adding any `/v1` endpoint**, for reading logs back or for publishing an
  event. Neither is a proxy-facing operation, and putting them on this contract
  would make every Hoplock Control implement an operator API it does not need.
  If you find yourself designing one, you have left this phase.
- **Changing the proxy's reconnect timeout or `CacheOptions.StaleAfter`**, or
  making either derive from the advertised interval. The field is advisory and
  may only tighten detection (above); wiring it into the timers is a behaviour
  change with fail-closed consequences and belongs in its own phase if anyone
  wants it. Adding the field and the rule is this phase; consuming it is not.
- **Promoting `/debug/logs` and `/debug/revoke` into the contract** as a named
  convention every implementation must offer. It is a defensible idea and it is
  not this phase: it would put a requirement on servers in order to make a test
  easier, which is the wrong way round.
- `control.PolicyVersion`, the policy vocabulary, and anything on
  `/v1/authorize`.

## Acceptance criteria

- `RevocationEvent.heartbeat_interval_seconds` exists in `api/control.yaml`
  with its absent-value default, the tighten-only rule, and the ceiling stated
  beside it, and in `api/README.md`'s event table and field list.
- `internal/control` carries the field and its resolver; the existing
  cross-check tests against `control.yaml` and `api/README.md` pass unchanged in
  intent.
- `control.PolicyVersion` is **still `4`**, and a test or an explicit note says
  why this change did not move it.
- `cmd/mock-control` advertises the interval it is actually keeping, driven by
  the existing fixture key, and advertises nothing when heartbeats are disabled.
  `cmd/mock-control/fixtures.example.yaml` still parses and the end-to-end tests
  through the real client still pass.
- A test asserts a server **cannot** satisfy the requirement by advertising an
  interval it does not keep: emit at an interval longer than the advertised one
  and show the mismatch is detectable. (This is the assertion the downstream
  suite will make; proving it is expressible here is what makes the field worth
  adding.)
- `api/README.md` states, in the two places named above, that durability and
  gap recovery are not observable through this contract and what a harness needs
  instead.
- `docs/PLAN.md` §6.4 revised in place.
- `go test ./...` passes; the PR carries a `## Cross-repo impact` section with a
  ready-to-run sync kickoff for `hoplock/control`
  (`docs/CROSS-REPO-PROTOCOL.md` §4).

## Cross-repo dependency (state this in the PR)

`hoplock/control` vendors `api/` read-only (D3, control M1) and already has a
conformance suite that will consume this. Its obligations after this merges,
which is what the `## Cross-repo impact` section should say:

- `make contract-sync REF=<this commit>` — re-vendor `contract/control.yaml`
  and regenerate `contract/UPSTREAM`.
- `internal/contract` — add `HeartbeatIntervalSeconds` to `RevocationEvent` and
  a resolver for its absent value beside the others in `resolve.go`.
- `cmd/pdpconform` — the heartbeat case currently takes
  `events.heartbeat_interval_seconds` from its expectation file. It should read
  the server's advertised value from the stream, fall back to the
  expectation-file input only when the server advertises nothing, and assert
  both halves: that heartbeats arrive within the advertised interval **and**
  that the advertised interval is within the ceiling. Its
  `cmd/pdpconform/README.md` records this as an open ambiguity today and that
  paragraph comes out.
- `cmd/pdpconform/README.md` and
  `docs/learnings/0002-contract-vendoring-and-conformance-learnings.md` — the
  second recorded ambiguity (no publish/read-back surface) is now answered by
  the document rather than open; update both to cite the answer instead of
  reporting a gap.
- The CI `conform` job pins the mock to the commit in `contract/UPSTREAM`, so it
  follows the re-vendor with no further change.

There is no work for `hoplock/enterprise`: this change does not touch `ext/`.

## Definition of Done & hand-off

Per `docs/PROTOCOL.md`. Move this prompt to `prompts/implemented/`; add
`docs/learnings/0039-observable-liveness-and-durability-learnings.md`. The
summary block MUST give: the field's name and absent-value default, the
tighten-only rule in one line, the ceiling you chose and why, confirmation that
`control.PolicyVersion` did not move and the reasoning, and the downstream sync
kickoff you handed over.
