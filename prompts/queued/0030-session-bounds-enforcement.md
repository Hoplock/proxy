# 0030 — The other three session bounds: capture, concurrency, grant context

> **New prompt, added by phase 0019.** Phase 0018 defined **four** session bounds
> (D16) and its learnings assigned the remaining three to 0019. Prompt 0019's own
> scope does not name them — it is the target-side enforcement phase, and
> `docs/PROTOCOL.md` §3 says a phase implements exactly what its prompt
> specifies — so they were left, and this is the prompt that owns them. The
> fourth, `session_deadline`, is phase **0025**'s and is not touched here.
>
> **Appended rather than inserted.** It depends on nothing 0020–0029 change and
> nothing they do depends on it, so it can run any time after 0018. Phase 0023's
> e2e work is named "concurrency" but is about two sessions *provisioning at
> once*, not about the caps here; the two do not collide.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — **§6.5 "Session bounds (D16)"** (the table of four fields and
  what each absent value means), **§4.3** (the disclosure rule: which of these is
  a denial and which is an outage), §7 (the telemetry pipeline and its disk
  buffer), §13 UC2 and UC3 (the use cases the caps and the grant context exist
  for), §6.4 (the session registry the caps are counted against).
- `docs/learnings/` — read summaries; open **`0018`** (the fields as shipped, the
  fixture keys, and the structural test that says the grant context is never
  consulted by a decision path), **`0011`** (the shipper, the disk buffer, and
  `SessionRecorder`), **`0003`** (`control.SessionRegistry`, which is where a
  live session count is knowable at all), **`0019`** (how the enforcement record
  reached the audit trail, which is the pattern the grant context follows).

## Objective

Make the three remaining D16 bounds real, each in the class PLAN §4.3 assigns it,
without letting any of them become policy the proxy originates.

## In scope

### 1. `require_session_capture` — refuse a route that cannot be recorded
- Checked **before the target leg is dialled** (PLAN §6.5). A session that
  reached the target and then failed this check has already happened.
- **Buffering to local disk counts.** §7's buffer is a resilience path and not a
  degraded mode, so a proxy faithfully spooling to disk during a Control outage
  still satisfies the route. The predicate already exists in the shape
  `internal/logging` gives the device path (`Deliverable()`, phase 0014); reuse
  it rather than inventing a second answer.
- The refusal is **outage-class** (§4.3) and names the session id: the estate is
  unhealthy, the user asked for nothing wrong, and different credentials will not
  help.

### 2. `concurrency` — per-subject and per-target ceilings
- Counted against the proxy's own `control.SessionRegistry`, because the live
  count is knowable only there.
- Exceeding a cap is a **policy denial**, deliberately vague (§4.3) — never an
  outage. The estate is healthy and the answer is "no".
- Both scopes are independent and either may be absent; zero means uncapped.
- Say in the learnings what the cap does NOT bound: it is per proxy, and a
  chained route crosses several. Decide, state, and test whether a hop counts
  against the cap on each proxy it traverses.

### 3. `grant_context` — carried into every record for the session
- Copied onto the session's log records (`internal/logging`), **never parsed,
  never matched against, and never the basis of a proxy-side decision** (D2,
  D15), and **never shown to the user** — a denial stays vague.
- `AdditionalContext` is a string **or** an object; both forms reach the record
  intact. Do not stringify the object form.
- 0018 shipped `TestGrantContextIsNotConsultedByAnyDecisionPath`, an AST walk
  that already permits `internal/logging` to mention the type. **Do not weaken
  that test.** If it needs a new package in its allow-list, that is a signal
  worth arguing for in the PR description rather than a line to edit quietly.

### 4. Topology and CI (`deploy/`)
Extend 0012's topology with a route for each bound, and scenarios in
`TestTopology` (`test/e2e/scenarios_test.go`). Two things that will bite: those
subtests are ordered deliberately — the outage scenario stops Hoplock Control and
the ephemeral-leak check runs last — so new groups go **before** the outage one;
and `sshBaseArgs` in `test/e2e/harness_test.go` is shared by every scenario, so
pass per-scenario client options rather than changing it.

The fixture keys already exist (0018): `require_session_capture`,
`concurrency.max_sessions_per_subject`, `concurrency.max_sessions_per_target`,
`grant_context` with `additional_context_text` **or**
`additional_context_fields` (never both — a fixture setting both describes a
response that cannot exist and fails at startup).

## Out of scope
- **`session_deadline`.** Phase 0025 owns it. Do not enforce it here, and do not
  reshape the field.
- Making the grant context readable by any decision path, in any form, however
  convenient. That is the one thing this prompt exists to prevent.
- Changing the contract. Every field here shipped in v4; `api/` should not need
  to be touched, and touching it creates a cross-repo obligation
  (`docs/CROSS-REPO-PROTOCOL.md`).

## Acceptance criteria
- A route with `require_session_capture` is refused as an **outage** naming the
  session id when there is no logging path at all, and is **served** when the
  network is down but the disk buffer is accepting records. Both are tested.
- A subject at its per-subject cap is **denied** (vague, §4.3, no session id
  needed) and the denial is on the audit record with the cap that was hit; a
  session that ends frees its slot, verified by a subsequent session succeeding.
- The same for a target at its per-target cap, with a subject that is under its
  own.
- A route carrying a grant context produces records that carry it verbatim, in
  both `additional_context` forms, and the user is told nothing about it.
- `TestGrantContextIsNotConsultedByAnyDecisionPath` still passes, unweakened.
- No route without these fields changes behaviour in any way.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0030-session-bounds-enforcement-learnings.md`. The summary block
must state, for each of the three bounds: where it is enforced, its class under
§4.3 (denial or outage), what its absent value means, and — for the caps —
exactly what they do and do not bound on a chained route.
