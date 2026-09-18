# 0042 — Fleet configuration distribution

## Read first
- `docs/PROTOCOL.md` — session workflow, especially §3 (scope, and "the plan is
  written in the present tense"), §7, and §8.
- `docs/PLAN.md` — **§6.4** (policy caching & session revocation: the outbound
  subscription, the event types, the heartbeat and its two rules, the
  fail-closed rule) and **§8** (cross-cutting conventions, whose one line
  "**Config**: YAML **bootstrap** (`internal/config`)" is the whole seam this
  phase opens). Decisions **D2** (the proxy originates no policy, and what that
  does and does not say about *configuration*), **D3** (this repo owns the
  contract; Hoplock Control implements it), **D8** (log shipping, one of the
  settings an operator would want to set fleet-wide), and **D11** (relay
  registration, another). **§6.1** for `chain.upstream`/`chain.accept`, the
  registration settings a distributed config would carry.
- `api/README.md` — **"Revoking (`GET /v1/proxies/{proxy_id}/events`)"**,
  **"Versioning: one live vocabulary, and a proxy that fails closed"**,
  **"Absent-value defaults, in one table"**, and **"Changing the contract"** (the
  recipe you are following, including which changes bump `control.PolicyVersion`
  and which do not — **this one does not**, see below).
- `api/control.yaml` — the `RevocationEvent` schema, the
  `/v1/proxies/{proxy_id}/events` path description, and `info.version`
  (**4.1.0** today).
- `docs/learnings/` — read summaries; open
  `0003-policy-caching-and-session-revocation-learnings.md` (the subscription
  loop, reconnect, `last_event_id`, replay and `resync`) and
  `0039-observable-liveness-and-durability-learnings.md` (the closest precedent:
  a field added to this same event, why it did not move `policy_version`, and how
  `cmd/mock-control` was made unable to lie about it).
- `docs/CROSS-REPO-PROTOCOL.md` — **§1, §2, §3.2, §4, §5**. This phase edits
  `api/`, a shared surface, so the PR owes a `## Cross-repo impact` section with
  a ready-to-run sync kickoff for `hoplock/control`. It is also **the phase that
  answers an upstream request**, which §5's "The PR that answers an upstream
  request is not a sync" makes explicit: the repository that raised it is a
  consumer like any other and the easiest to forget, because it is the one
  already waiting.

## Where this came from

An **upstream request** from `hoplock/control` (§3.2), raised by its phase 0006
in [Hoplock/control#27](https://github.com/Hoplock/control/pull/27).

Control's M6 makes the fleet a graph and its 0006 built the registry over it:
proxies enroll, heartbeat, declare their zones and reachability, and — the part
that concerns this repository — receive a **versioned configuration document**.
The argument for it is the one this repository's §8 already concedes in a single
word: a proxy's config is a *bootstrap*, and everything above the bootstrap is a
property of the fleet rather than of the host. An operator should configure a
fleet, not N files.

Control built all of that: immutable versions per zone and per proxy, composition
into one effective document per proxy, first-class rollback, and drift between
desired and running visible in its fleet view. What it could not build is the
delivery, and it did not invent it:

> `contract/control.yaml` enumerates `RevocationEvent.type` as `session_kill`,
> `cache_invalidate`, `heartbeat`, `resync`, and none of them can say "your
> desired configuration moved".

So Control's publisher seam (`fleet.ConfigPublisher`) is defined, defaulted to a
no-op, and **visibly unwired**: a publish is durable and shows as drift, and a
proxy that has not caught up is reported rather than assumed current. Nothing was
approximated, which is what makes this phase additive rather than a correction.

**What Control asked for, verbatim in shape:** an event type — or a field on the
heartbeat event — naming the proxy's desired config version and hash, which the
proxy answers by fetching the document and then reporting what it is running.

**Treat that as a need, not a specification.** It is the tip of the phase, and
§3.2 stops a downstream author at the tip on purpose: the three questions under
"What this phase must settle" are ones Control's session could not answer,
because answering them means reading this repository's plan.

## Objective

Let Hoplock Control distribute configuration to a fleet, and let a proxy apply
it, report what it is running, and survive a bad document.

## What this phase must settle

These are decisions, not implementation details, and the phase is not done until
`docs/PLAN.md` states each one in the present tense.

### 1. Which settings are fleet-owned, and which stay bootstrap

**This is the decision the phase exists to make, and it wants a new `D`.** D2
says the proxy originates no *policy*; configuration is not policy, so D2 neither
grants nor forbids this and the register is currently silent. Draw the line
explicitly and say what governs it.

The line has a natural shape: a setting must stay local if the proxy needs it to
*reach Hoplock Control at all* — the Control URL, its own identity and key
material, the listen address — because a proxy that could be told those remotely
is one a bad document can orphan permanently, with no channel left to fix it
over. Everything above that is a candidate: log shipping cadence (D8), the zones
it serves, relay registrations (D11, §6.1), chain settings, cache sizing
(`control.cache.max_entries`, §6.4).

Say which side each setting is on, and say it where an operator reads about that
setting rather than only in one list.

### 2. How the document arrives

The event says *that* configuration moved. It must not *be* the configuration,
and the reason is on the wire already: the stream is replayable from a
`last_event_id`, so a document carried inline would be replayed — and a replayed
configuration is a stale configuration applied as if current. The event is a
notification; the document is fetched.

Specify the fetch. A new `GET /v1/proxies/{proxy_id}/config` is the obvious
shape and matches the stream's own path convention, but it is yours to justify:
whatever you choose, state what it answers when the proxy is not enrolled, when
no document has been published, and how the proxy tells "unchanged" from
"changed" without re-applying on every reconnect (the hash is there for this).

### 3. How the running version gets back, and what "applied" means

Control's registry expects a proxy to report the version it is running — that is
what makes its drift view mean anything. This repository currently has **no
proxy→server call that could carry it**: Control's own enrollment and heartbeat
surfaces are outside `/v1` and are not this contract's.

So specify it, and while you are there specify what "running" claims. A document
whose settings need a restart to take effect is not being *run* by a process that
has only stored it, and a proxy that reported it as running would make Control's
drift view say the rollout finished when it had not. Decide which settings apply
live and which do not, and make the report unable to overstate itself.

### 4. A bad document must not take a proxy out of service

Control keeps the previous version and makes rollback first-class, which bounds
the operator's exposure — but only if the proxy is still reachable to receive the
rollback. Specify what a proxy does with a document it cannot parse, or can parse
and cannot apply: it keeps serving on the last good one, says so loudly enough
for an operator to see it (Control's fleet view has a `last_error` field waiting
for exactly this), and does not wedge.

Same for a fetch it cannot complete: configuration is not on the data path, so
failing to get it must never end a session or refuse a connection.

## In scope

- `api/control.yaml`: the new event type and its payload, the fetch endpoint, and
  the report path chosen under §3 above. `info.version` moves to **4.2.0**.
- `api/README.md`: the prose half, under the existing "Revoking" section and
  wherever the new endpoints belong. The absent-value table gains any new field.
- `internal/control`: the client side — recognising the event, fetching, applying,
  reporting. `events.go`/`revocation.go` own the stream today.
- `internal/config`: whatever the bootstrap/fleet split needs. Keep the loader
  strict; a key the schema does not define stays an error.
- `cmd/mock-control`: serve the new endpoints and emit the event, on 0039's
  standard — the mock must not be able to claim something it does not do.
- `docs/PLAN.md`: the new `D`, §6.4's event list, §8's config line, and §10's
  phase table.
- Tests: unit tests for the client side, and the e2e topology exercising a real
  rollout if it can do so without becoming a second test of Control.

## Out of scope

- **Control's side.** It is built (its 0006). This phase does not specify what
  Control stores, how it composes a document, or how it versions one.
- **The bootstrap file's format.** Still YAML, still strict, still documented in
  the example file.
- **Anything that would put configuration on the data path.** A session in flight
  is governed by the snapshot it was authorized with (D2); configuration is not
  policy and must not start behaving like it.

## The versioning answer, stated so nobody re-derives it

`policy_version` **does not move.** It governs `/v1/authorize` and nothing else —
the one response the proxy decodes strictly, and therefore the only place an
unknown field could be a silently dropped restriction. This phase adds an event
type and one or two endpoints, neither of which is that response. 0039 is the
precedent and `api/README.md`'s "Versioning" section is the rule.

`info.version` **does** move, to 4.2.0. And the contract already licenses the
event type without a version bump at all:

> A proxy ignores a type it does not recognise, so the server may add types
> without breaking older proxies.

Say in the PR that you checked this, because it is the sentence that makes the
change additive, and an implementer who has not read it will reach for a bump
that would break every proxy in a mid-upgrade fleet.

## Acceptance criteria

- A proxy holding the subscription receives the new event, fetches the document,
  applies what it can apply live, and reports the version it is running.
- A proxy built before the type existed **ignores it** and keeps working —
  asserted, not assumed, since it is the property the additive claim rests on.
- A replayed event does not apply a stale document. Test it through the replay
  path (`last_event_id`), not by calling the handler twice.
- An unparseable document, an unapplicable one, and an unreachable fetch each
  leave the proxy serving on its last good configuration, each surface an error
  an operator can see, and none refuses a connection or ends a session.
- A document whose settings need a restart is not reported as running.
- A setting the phase puts on the bootstrap side cannot be set by a distributed
  document — tested, because this is the rule that stops a bad push orphaning a
  proxy with no channel left to fix it over.
- `cmd/mock-control` serves the new endpoints and emits the event from its
  fixtures, and cannot advertise a version it does not serve (0039's standard).
- `make build vet test lint`, the OpenAPI validator, and the licence check pass;
  the e2e topology still passes.

## Definition of Done & hand-off

Per `docs/PROTOCOL.md`, plus the two this phase owes because of where it came
from:

- The PR carries `## Cross-repo impact` with a ready-to-run sync kickoff for
  `hoplock/control` (`docs/CROSS-REPO-PROTOCOL.md` §4.1). **Control is the
  repository that raised this request**, so the obligation is easy to skip on the
  grounds that it already knows — it does not: the session there that vendors the
  contract and wires `fleet.ConfigPublisher` is a fresh one that knows nothing
  (§5, "The PR that answers an upstream request is not a sync").
- The learnings summary names the event type, the endpoints, the new `D`, the
  bootstrap/fleet line, and what Control must do to wire its publisher — that
  last one is what the sync session reads.
