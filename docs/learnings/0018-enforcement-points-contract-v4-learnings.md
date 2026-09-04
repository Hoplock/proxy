# 0018 — Enforcement points: survey & contract v4 — Learnings

## Summary
- **What shipped:** **contract v4**. The survey of where policy is actually
  enforced (`docs/PLAN.md` **§6.5**, both axes, four columns per candidate, D12
  amended), the rung vocabulary Control chooses from, proxy-level and per-target
  capability advertisement, and D16's four session bounds. **Nothing is
  enforced** — 0019 renders the rungs, 0025 closes a session at its deadline.
- **Key files:** `docs/PLAN.md` (D12, **§6.5** new, §6.2/§6.3 pointers, §10, §13),
  `api/control.yaml` + `api/README.md` (v4), `internal/control/enforcement.go`
  (new) + `{contract,validate,clone,policy,rest,cache}.go` (+
  `enforcement_test.go` new, `contract_test.go`), `cmd/mock-control/{fixtures,
  server}.go` + `fixtures.example.yaml` + `server_test.go`.
- **Rung vocabulary — axis 1, `enforcement.execution`** (guarantee in one line):
  | Rung | Guarantee | Kind |
  | --- | --- | --- |
  | `proxy-inspected` | What the proxy sees at the `exec` request is what it decides. **Absent-value default** | applied, proxy |
  | `no-interactive-shell` | No shell or pty is obtainable, so every command run is one the proxy decided | applied, proxy |
  | `account-restricted` | The account executes only what `restricted_exec` names, for every login to it | applied, target |
  | `account-confined` | …plus no privilege gain and no executing what the session wrote | applied, target |
  | `platform-authorized` | The device's own authorizer decides, under `platform_role` | applied, target |
  | `platform-attested` | The target enforces its own command authorization already | **attested** |
- **Rung vocabulary — axis 2, `enforcement.reach`:**
  | Rung | Guarantee | Kind |
  | --- | --- | --- |
  | `proxy-channel-policy` | SSH-channel forwarding only. **Absent-value default** | applied, proxy |
  | `account-egress-restricted` | The session's own processes reach only `permitted_destinations` | applied, target |
  | `account-network-isolated` | The session's processes reach nothing off the host | applied, target |
  | `platform-attested` | The target already constrains what the account reaches | **attested** |
- **Absent-value default:** an absent `enforcement` object means **both** axes
  take their default — proxy-side enforcement only, exactly a v3 server's
  behaviour. Same for all four session bounds: no deadline, capture not
  required, no grant context, uncapped.
- **Capability advertisement:** `AuthorizeRequest.capabilities`
  (`ProxyCapabilities`) for the build; **`POST /v1/capabilities/report`** for the
  target, on `/v1/hostkeys/report`'s shape because authorize happens *before* the
  proxy has touched the target. **Absent, undated and stale are one case** and
  provide nothing that has to be applied; the rungs needing nothing of the target
  (both defaults, and attested) are unaffected. `DefaultCapabilityTTL` = 15m.
- **Refusal rule:** a rung the proxy cannot provide is an **outage-class denial**
  naming the session id (§4.3), **never a downgrade**. The rung is a property of
  the **route**; a ladder entry that cannot carry it is a **skipped rung** (D14);
  a route where **no** named method provisions the target carrying an **applied**
  rung is a **contract violation refused at `Validate`**.
- **Audit fields (0019 emits):** `enforcement_execution`, `enforcement_reach`,
  `enforcement_verified` (`false` on attested), `enforcement_attested_by` — the
  rung **in force**, never the one requested.
- **What the NEXT session (0019) must know:** read the rung through
  `AuthorizeResponse.EnforcedExecution()` / `EnforcedReach()`, never the field;
  `TargetAuthMethod.Provisions()` decides whether an applied rung is reachable on
  a ladder entry; `ProxyCapabilities`/`TargetCapabilities` `Provides*` are the
  fail-safe checks; `CapabilityReporter` (not `Client`) is where the report goes.

## Details

### Deviations from the prompt, and why

Two, both deliberate and both stated here because a later reader will otherwise
read them as oversights.

**1. The survey is `docs/PLAN.md` §6.5, not a subsection of §6.3.** The prompt
asks for "a new `docs/PLAN.md` subsection under §6.3". Half the survey is not
about commands: axis 2 is what a session may *reach*, whose nearest relative is
§6.2's forwarding policy, and filing it under "Command filtering" would mis-file
it permanently. §6.3 and §6.2 each gained a pointer to §6.5 instead. Nothing
else about the survey changed.

**2. `enforcement` hangs at the top level, not on `filter_policy`.** The prompt
recommends `filter_policy` and asks for the reasoning if that is rejected. The
recommendation is right about *one* axis: the execution rung really does select
where the existing `restricted_exec` policy is enforced. It is wrong about the
reach axis, which has no policy object to attach to — and must not be attached
to `permitted_forwards`, because the survey's central finding is that
`permitted_forwards` does **not** cover what a reach rung covers. Attaching it
there would encode the opposite of what the survey says. Splitting the two (one
on `filter_policy`, one at the top level) would put one server decision in two
places, which is the shape that produces a session whose audit record claims a
rung that was never applied. One object, both axes, top level.

### The decisions the prompt asked for, and the answers

- **Rung: property of the route, or of each ladder entry?** *The route.* One
  policy stating two guarantees would leave the audit record having to say which.
  The ladder already gives the right behaviour: an entry that cannot carry the
  rung is a **skipped rung** (D14), the proxy walks on, and exhausting the ladder
  is the outage-class denial it already was. It never runs without the rung
  ("refuse, or run without it?" — neither: skip, then deny).
- **What an attestation is worth unverified.** Attributable or nothing:
  `attestation.asserted_by` and `attestation.reference` are both **required** on
  an attested rung, and the record says this system verified neither. An
  attestation beside an *applied* rung is refused — a reader could not tell which
  half the record meant. Verifying an attestation (reading the device's
  configuration back) is a real future feature and needs no field-shape change.
- **The interpreter problem.** *The contract's problem as a documented rule, and
  Control's to enforce at authoring time — not a proxy-side refusal.* A shipped
  deny-list of interpreter names in the proxy would be a blacklist masquerading
  as a boundary (what D12 rejects), incomplete on day one, and would refuse a
  route over a name collision at connect time. A rung is a claim about the
  **mechanism**, bounded by the list it renders. 0019 may emit a `warn` audit
  event when it renders a list containing a known interpreter; it must not
  refuse one.
- **Stale/absent capability records.** One case, and it fails safe: nothing that
  has to be **applied** is provided. This is safe rather than merely convenient
  because a report **grants nothing** — the authority is the authorize response
  and the proxy re-checks against the live target at provisioning time, so the
  worst a stale record causes is a refused session.
- **The uid hazard.** A per-uid packet filter is only per-session while the uid
  is, and `useradd` reuses freed uids. Any rung keyed on uid is part of the
  **teardown contract** and part of what the orphan reaper looks for — 0019 owns
  that half, 0024 owns the non-reusing range.

### Validation rules `Validate` now enforces (all with tests)

| Rule | Refusal |
| --- | --- |
| Unknown rung on either axis | never coerced — coercing down runs the session weaker than the policy names |
| `platform_role` | required by `platform-authorized`, forbidden otherwise |
| `permitted_destinations` | required non-empty by `account-egress-restricted`, forbidden otherwise; entries checked like any `ForwardDestination` |
| `attestation` | required by an attested rung on either axis, forbidden otherwise; `asserted_by` and `reference` non-empty |
| `no-interactive-shell` | needs `permitted_requests` present and denying `shell` **and** `pty-req` (absent polices nothing) |
| `account-restricted` / `account-confined` | need `filter_policy.exec_mode: restricted` — the only place the contract names an executable |
| applied rung + a named ladder where nothing provisions | refused; an **absent** ladder is not (local config is invisible here) |
| `session_deadline` present but zero | refused — the zero instant would close every session as it opened |
| negative concurrency cap; inverted grant window | refused (shape only: the grant context is never read for a decision) |
| `additional_context` that is not a string or an object | refused rather than coerced |

### The grant context is not consulted, and there is a test that says so

`TestGrantContextIsNotConsultedByAnyDecisionPath` is structural, in two halves:
the type's method set carries only `Clone` (and `AdditionalContext` only its two
JSON methods, so "just a `Matches` method" fails the build), and an AST walk
over every non-test `.go` file asserts that only `internal/control` (defines it),
`internal/logging` (may read it, to build a record) and `cmd/mock-control` (a
**server**: it authors the field) mention `GrantContext`. **This phase does not
wire it into `internal/logging`** — that is 0019's, and the test already permits
that package so it will not have to be edited.

### Shapes 0025 is written against — unchanged from its prompt

`session_deadline` is an **absolute RFC 3339 instant** on `AuthorizeResponse`,
`*time.Time`, absent means no deadline. It was not reshaped. 0025 still owns the
two questions this phase left open: what the user is told at expiry, and whether
a warning precedes it. Reaching it is neither a denial nor an outage.

### Why `ReportCapabilities` is not on `Client`

Adding a method to `control.Client` would force every fake in the tree
(`internal/proxy`, `internal/routing`, `internal/logging`) to grow a stub for a
call only 0019 makes — and the prompt's "no test in `internal/proxy`,
`internal/auth/target`, or `internal/filter` modified" forbids exactly that. It
is `CapabilityReporter`, a one-method interface implemented by `*RESTClient` and
forwarded by `*CachingClient` (never cached: a report is an observation, and a
decorator answering from memory would be reporting the past).

### Mock server and fixtures

New route keys: `enforcement` (`execution`, `reach`, `platform_role`,
`permitted_destinations`, `attestation`), `session_deadline_seconds`,
`require_session_capture`, `grant_context`, `concurrency`. Two shapes are
fixture-only and worth knowing:

- **`session_deadline_seconds` is a duration**, anchored by the server at
  authorize time (`fixtureRoute.deadline`). The wire field is an absolute
  instant; a fixture cannot hold one that is still in the future tomorrow.
- **`additional_context` is `additional_context_text` OR
  `additional_context_fields`**, never both — the wire field is a string or an
  object, so a fixture setting both describes a response that cannot exist and
  fails at startup.

`vocabularyVersion` gained a v4 case; `TestV2ProxyIsStillServedV2Routes` became
`TestVersionGateAnswersPerRoute` and now covers the v3→v4 step too (its old v2/v3
example routes acquired rungs, so it moved to routes that are still v2 and v3).
`fixtures.example.yaml` exercises **every rung on both axes**, including an
attested rung on a `brokered-key` route and a UC3 route carrying all four session
bounds and deliberately **no** rung.

### The e2e obligation

This phase connects to nothing and owes no scenario. It owed the rig two things
and both hold: `cmd/mock-control` accepts the vocabulary (strict decoding means
an unknown key is a startup failure), and `deploy/control/fixtures.template.yaml`
still loads — verified by rendering it with `deploy/gen-material.sh` and starting
the real `cmd/mock-control` binary against the rendered `fixtures.yaml`. The
**full `make e2e-up` could not run in this session**: Docker is unavailable in
it. The compose stack is CI's `e2e` job. The template was deliberately left
otherwise unchanged — the phase that consumes the vocabulary owes the scenarios.

### Follow-ups this phase does not do

- **0019** renders every applied rung, probes and reports target capabilities,
  enforces `require_session_capture` before the target leg is dialled, enforces
  the concurrency caps against the `SessionRegistry`, carries the grant context
  into `internal/logging`'s records, and emits the audit fields above. It also
  turns `auth.target.ephemeral_account.access_profile` (proxy config, required
  since 0015) into the route's `enforcement.platform_role`, which is what 0015
  said should happen.
- **0025** enforces `session_deadline`.
- **Attestation verification** — reading a device's configuration back to check
  an attested claim — is a real feature with no contract change needed.
