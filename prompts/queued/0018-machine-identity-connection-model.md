# 0018 — Machine-identity connection model: bound the snapshot, not the connection

> New phase (privileged-access revision, PLAN §10). **Conditional on 0017.** If
> 0017's measurements and the customer's answer show that connection-per-check
> is comfortably within budget, this phase is not needed and the right outcome
> is to say so and delete it. Read 0017's learnings summary before anything
> else; its closing verdict may be the whole answer.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/learnings/0017-…` — **first, and possibly last**: the measured numbers
  and the verdict on whether D17's premise survived.
- `docs/PLAN.md` — **D17** (what this implements, and what it amends in D2), D2
  and §6.4 (the caching and revocation model this must not undermine), §7 (what
  a session record contains today), §13 UC2.
- `docs/learnings/` — open `0003` (cache and revocation), `0005` (the connection
  lifecycle and the session registry), `0009` (the channel pipeline, since the
  unit of policy moves onto it), `0011` (what a log record is per session).

## Objective
Let a machine identity hold **one connection and many channels** without that
connection becoming standing authorization: the connection survives, the
decision expires and is renewed.

## Why this is delicate

D2's guarantee is that the data path makes no calls to Hoplock Control, which is
safe because a connection is short. Stretching a connection to days without
stretching the decision with it is the entire problem — a policy snapshot that
outlives its subject's access is precisely what §6.4's fail-closed rule exists to
prevent, and a persistent M2M connection is the most attractive way to reintroduce
it by accident.

The resolution in D17 is one sentence — bound the snapshot, not the connection —
and it has consequences the sentence does not: what happens to channels already
open when a snapshot expires, what happens when re-authorization *narrows* the
policy rather than denying it, and what the audit record means when one
connection carries a thousand checks under a dozen successive decisions.

## In scope

### 1. The snapshot lifetime

- A **maximum snapshot age** carried by the route (server-owned, like the cache
  hint: the proxy may clamp shorter, never longer, never invent one). Absent
  means today's behaviour — the snapshot lasts the connection, which for a short
  connection is unchanged.
- **Re-authorization on expiry**, on the connection, not on the data path of a
  channel already flowing. Decide and document what happens to in-flight
  channels when the new decision is narrower: a channel that is no longer
  permitted must not continue, and a channel mid-transfer that is *still*
  permitted must not be interrupted. Those are different rules and the contract
  must be able to say which applies.
- **A denial on re-authorization ends the connection**, with §4.3's disclosure —
  it is not a silent stall and not a permanent retry loop.
- **Revocation stays the fast path.** This mechanism bounds the damage of a
  missed revocation; it does not replace one. The fail-closed rule in §6.4 is
  unchanged: a proxy that cannot hear revocations stops serving cached decisions
  and re-authorizes, and now also declines to extend a snapshot.

### 2. Audit granularity

The unit of record becomes the **channel**, not the connection: one persistent
connection carrying a thousand health checks must produce a thousand
attributable records, each naming the decision in force when it ran, or the
audit trail says less than the short-connection model it replaced. Decide how a
record references its decision (`decision_id` already exists) and make the
connection-level record a container rather than the unit.

### 3. What must not change

- No new authority for the proxy. It does not decide when to extend, only when
  to ask again.
- No weakening for interactive sessions. This model is selected by the route,
  and a human session is unaffected by its existence.
- Provisioning is unchanged: an `ephemeral-user` or `ephemeral-account` route
  that opts into a long-lived connection holds one account for that connection's
  life, which is a deliberate trade the route makes and the audit record states.

## Out of scope
- Client-side multiplexing behaviour. What an automation's SSH client does with
  `ControlMaster` is the customer's; this phase makes the proxy safe under it.
- Any change to the filter engine or the policy axes. The same policy applies;
  only its lifetime and its unit of record change.
- The scale harness — 0017 owns it. Use it to prove the improvement; do not
  rebuild it.

## Acceptance criteria
- A route can carry a maximum snapshot age; absent behaves exactly as today, and
  a proxy-side clamp is observable (counted and logged per affected decision),
  matching §6.4's existing rule for cache hints.
- Tests: a snapshot expires and is renewed without dropping the connection; a
  narrowed decision stops a newly-opened channel that is no longer permitted; a
  denial on renewal closes the connection with a disclosed reason; a lost
  revocation subscription prevents renewal-by-extension.
- Each channel produces its own audit record naming the decision in force.
- 0017's harness shows the intended reduction in Control request rate for the
  UC2 pattern, reported as a before/after with the same scenario file.
- `docs/PLAN.md` D17 updated from "proposed" to what was built, including
  whatever the in-flight-channel rule turned out to be.

## The e2e topology obligation

Phase 0012 built the five-node topology in `deploy/` and the scenario suite in
`test/e2e` (see its learnings, and `deploy/README.md`). **A phase that changes
what a session can do owes it a scenario there** — a change proven only by unit
tests is a change nobody has watched a real SSH client survive.

Concretely: add the route to `deploy/control/fixtures.template.yaml` (that file
is the **mock** Hoplock Control's fixtures inside this repository's test rig —
it is not the sibling Control repo, which vendors only `api/control.yaml`), and
add a subtest to `TestTopology` in `test/e2e/scenarios_test.go`. Each fixture
route names the scenarios it backs, so a failing scenario leads to one rule
rather than to a search — keep that up.

Two things that will bite:

- `TestTopology`'s subtests are **ordered deliberately**. The telemetry
  assertions read what earlier scenarios produced, the outage scenario stops
  Hoplock Control, and the ephemeral-leak check runs last so it sees everything.
  New groups go before the outage scenario.
- `sshBaseArgs` in `test/e2e/harness_test.go` is shared by every scenario.
  Changing it changes all of them at once; pass per-scenario options instead.

If this phase genuinely cannot be represented in the topology, **say so
explicitly in the learnings and say why**. "No e2e scenario" is a finding worth
writing down; an omission is indistinguishable from an oversight.

## Cross-repo impact

If the maximum snapshot age is a new contract field, this phase changes `api/`
and owes `docs/CROSS-REPO-PROTOCOL.md` §2, §4, and a Control sync. Check whether
0003's cache hint can carry it instead — reusing an existing server-owned
lifetime would be the smaller change, and the PR should say which was chosen and
why.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`, plus Cross-repo impact if `api/` moved. Move to
`implemented/`; add
`docs/learnings/0018-machine-identity-connection-model-learnings.md`. The summary
block MUST carry the snapshot-age field and its default, the in-flight-channel
rule, the audit-record shape, and the measured before/after.
