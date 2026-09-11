# 0031 — The other three session bounds — Learnings

## Summary
- **What shipped:** D16's three remaining session bounds, enforced
  (`docs/PLAN.md` §6.5, new subsection). **`require_session_capture`** — checked
  in `internal/proxy/bounds.go` before the target leg is dialled and before
  anything is provisioned, on the telemetry pipeline's own `Deliverable()`;
  **outage-class**, naming the session id; absent means capture happens if
  configured and its absence stops nothing. **`concurrency`** — counted against
  the proxy's own live-session registry in one critical section, same place, same
  ordering; a **policy denial**, deliberately vague; absent (and zero, per scope)
  means uncapped. **`grant_context`** — stamped by the session recorder onto
  every record made after the decision; refuses nothing, discloses nothing;
  absent means no external grant context. **No contract change** — every field
  shipped in v4, `api/` untouched, so no cross-repo obligation.
- **The caps are PER PROXY and a chained session is counted on every proxy it
  crosses** — one slot each, under the same subject and the same requested
  target. A cap of *N* is *N* sessions **here**, never an estate-wide ceiling,
  and it bounds live sessions rather than connection rate. Tested
  (`TestAChainedSessionIsCountedOnThisProxyToo`).
- **Key files:** `internal/proxy/{bounds.go (new),session.go,proxy.go,logging.go,
  feedback.go}`; `internal/logging/{grant.go (new),record.go}`;
  `internal/routing/resolve.go`; `internal/control/{contract,enforcement}.go`
  (doc pointers only); `cmd/mock-control/server.go`;
  `deploy/control/fixtures.template.yaml`, `deploy/README.md`;
  `test/e2e/{scenarios,harness}_test.go`, `test/topology/config_test.go`;
  `docs/PLAN.md` §6.5, §7, §10.
- **Types/identifiers added:** `proxy.ErrCaptureUnavailable`, `stageCapture`,
  `stageConcurrency`, `Server.{admit,release,liveSessions}`, `liveSession`,
  `capExceeded`, `concurrencyScope`; `logging.{Grant,GrantFrom}`,
  `SessionRecorder.{SetGrant,Deliverable}`, `logging.Attr{CaptureRequired,
  ConcurrencyLimitSubject,ConcurrencyLimitTarget,ConcurrencyScope,
  ConcurrencyLimit,ConcurrencyLive,GrantSystem,GrantReference,GrantWindowStart,
  GrantWindowEnd,GrantAdditional,GrantAdditionalPrefix}`;
  `routing.Route.{RequireSessionCapture,Concurrency,Grant,
  MaxSessionsPerSubject(),MaxSessionsPerTarget()}`; mock-only
  `POST /debug/logs/sink`.
- **The grant context travels in a form nothing can read.** 0018's
  `TestGrantContextIsNotConsultedByAnyDecisionPath` passes **unweakened and with
  no new package in its allow-list**: `internal/logging` extracts what a record
  needs from the *authorize response*, and `routing.Route.Grant` is a
  `*logging.Grant` — no exported field, no exported method. See Details.
- **What the NEXT session must know:** the live-session registry
  (`Server.live`) is what a cap counts, and a session joins it whether or not its
  route carries a cap; it is freed in `Server.remove`, the one place a session
  leaves the engine. A new capture point that does not go through
  `SessionRecorder` will not carry the grant context (the two device events do
  not — see Details).

## Details

### Where each bound is enforced, and why there

Both checks sit in `session.setup`, after the deadline is armed and **before the
route types diverge** — so a chained session is bounded on every hop exactly as
its deadline is (0024) — and before `Provision` and `dialTarget`. PLAN §6.5 asks
for the capture check "before the target leg is dialled"; doing it before
provisioning as well is free and is the same argument one step earlier (an
account created for a session that is then refused is an account that existed).

**Capture is checked first, and the order is deliberate.** If this session cannot
be recorded at all, every answer after it — including a concurrency denial — is
one the audit trail would not contain, and a refusal nobody can read afterwards
is what the bound exists to prevent.

`require_session_capture` turns on `Shipper.Deliverable()`, reached through a new
`(*SessionRecorder).Deliverable()` so the engine asks its own recorder rather
than reaching past it. Reusing the predicate was the prompt's instruction and is
also the point: **a disk buffer is a logging path** (PLAN §7), so the only proxy
that refuses is one with no path at all — which in practice means one built
without a pipeline. `target.ErrNoLoggingPath` (PLAN §5.3's device attribution
rule) already turned on the same predicate from the other direction, and the two
now answer the same question the same way.

`concurrency` counts against a new `Server.live` map — session id to
`{subject, target}` — rather than a flag on each session. Two reasons: the count
is taken under the server's lock while a session's subject is behind its own, and
taking them in that order is how a lock cycle gets built by someone who was only
adding a counter; and the map *is* the thing a cap is counted against, so naming
it that way makes the code say so. Counting and admission are one critical
section, without which two sessions arriving together each see the other as
absent — the only interesting way a ceiling of one can be wrong, and what
`TestTwoSessionsArrivingTogetherCannotBothTakeTheLastSlot` drives with six
concurrent clients.

A session with **no** caps is registered too. A cap counts the sessions a proxy
holds, not the ones that happen to carry a cap, so an uncapped session still
occupies the slot a capped one counts.

### What the caps do not bound

- **Not the estate.** Per proxy, as above. Three hops under a cap of one means
  three live sessions in the estate, one per proxy. A fleet-wide count would have
  to be asked of Control per connection, which is the round trip D2's decision
  cache exists to avoid, and Control cannot answer it from `ConnMeta` because the
  live count is knowable only where the sessions are.
- **Not rate.** Sessions that end as fast as they start never reach a ceiling. A
  cap is not a throttle, and PLAN §5.1's serialisation on the target's account
  database is still the thing that bounds provisioning throughput.
- **Not the login.** The per-subject scope keys on the identity's **subject**,
  the same stable id a revocation keys on (§6.4), never on the typed login — the
  same person connecting under a different spelling is the same subject.
- **Not a route's own target string.** The per-target scope keys on the target
  the user asked for, as `ParseUsername` normalised it, which is the value that
  is identical on every hop of a chain. Keying on the resolved host would count a
  next-hop route against the *next proxy* rather than against the target.

### The grant context, and the test 0018 left behind

0018 shipped an AST walk asserting that only `internal/control`,
`internal/logging` and `cmd/mock-control` name `GrantContext` at all. Carrying
the value from the authorize response to the recorder looks like it needs
`internal/routing` and `internal/proxy` added to that list — the prompt
anticipated exactly that and asked for the argument rather than a quiet edit.

It needs neither, and the reason is a better design than the allow-list entry
would have been: **`logging.GrantFrom` takes the whole `*control.AuthorizeResponse`**
and keeps only the attributes a record will carry, inside the one package that is
already allowed to read the field. What `routing.Route` carries is a
`*logging.Grant`: a struct whose single field is unexported, with no exported
method. So the engine cannot read it even by accident, and the rule D16 states in
prose and 0018 enforces in an AST walk is also enforced by the type system. The
cost is one import — `internal/routing` now imports `internal/logging` — which is
acyclic (`logging` does not import `routing`) and says something true about the
field: the only thing this part of the decision is for is the record.

`additional_context`'s two forms stay two things. A string becomes one attribute
(`grant_additional_context`); an **object** becomes one attribute per field
(`grant_additional_context.<name>`), which is the `device_field.` pattern from
0016 and for the same reason — "every session this change authorised" is a query
about a field, and a flattened object turns it into a substring search. A
non-string value is re-encoded as the JSON it arrived as, so a number reaches the
record as `7` rather than as Go's rendering of a decoded float.

**The one gap, stated rather than papered over:** the grant context is stamped in
`SessionRecorder.build`, so it reaches every record that recorder makes. The two
events `internal/logging/device.go` emits are not among them — an account-mapping
event carries its session id as a *field* and a sweep failure belongs to no
session at all, so neither is built by a session recorder. Closing it would mean
teaching `internal/auth/target` to carry the grant context, which puts a policy
payload in the credential plane and would need that package in 0018's allow-list:
a worse trade than the gap. A device session's grant context is on every other
record it produces, including its own `provisioning` record.

### Disclosure (PLAN §4.3)

- Capture: a new `capture` stage whose outage detail is "this session could not
  be recorded, and it may not run unrecorded" — true, actionable for whoever runs
  the telemetry pipeline, and silent about the target and the policy. The session
  id rides along, as every outage's does.
- Concurrency: `capExceeded` wraps `control.ErrUnauthorized`, so
  `user.FailureMessageFor` renders the generic denial and **cannot** be made more
  informative by a caller who knows more. The cap, the live count and the session
  id are all withheld: "you are at your limit of one" is the policy, and "this
  target is busy" says the target exists. Its own `concurrency` stage exists for
  the audit record's `stage` attribute, and `outageDetail` deliberately has no
  case for it.
- The cap that was hit lives only on the audit trail: a `policy_decision` record
  at `critical` severity (so it takes D8's priority path, like every other
  refusal) carrying `concurrency_scope`, `concurrency_limit` and
  `concurrency_live`. The ceilings **in force** are on the authorize record of
  every admitted session (`concurrency_limit_subject`/`_target`), together with
  `session_capture_required`: a session that ran under a ceiling of two is a
  different fact from one that ran under none.

### Testing

- `internal/proxy/bounds_test.go` — both halves of the capture claim (refused as
  an outage with no logging path and **nothing logged into on the target**;
  served while both log endpoints refuse and the buffer keeps the records), the
  two scopes, the slot coming back, the admission race, the chained-session
  decision, the grant context on every record and on no user-visible path, and
  the object form surviving the engine.
- `internal/logging/grant_test.go` — `GrantFrom` on both forms, the window
  instants, an empty grant context producing none, and `Deliverable` as the
  capture bound's predicate.
- `internal/routing/resolve_test.go` — the three fields reaching the route, the
  absent-value defaults, and the deep copy.
- `cmd/mock-control/server_test.go` — the log-sink switch refuses both endpoints
  with a 503 (so the shipper treats the records as owed) while authorize keeps
  answering.
- `test/e2e/scenarios_test.go` — a new `session bounds` group, placed before both
  scenarios that stop Hoplock Control: it reads its own records, and one subtest
  takes the **log destination** down, which is only a different thing from
  stopping the server while the server is up.
- `test/topology/config_test.go` — pins the fixture routes and the ceilings of
  one the scenarios are written against.

Three harness additions worth knowing about. `fakeClient.AuthenticateCert` now
derives the subject from the login (`bob` → `bob@example.com`; `alice` still
resolves to `testSubject`), because a per-subject cap needs two subjects.
`uniqueSessionIDs` replaces the engine's fixed test session id with a counter for
the tests that hold two sessions at once — the registry is keyed by session id,
and two sessions sharing one would be one session as far as a cap is concerned.
`fakeClient.ingestDown` refuses both log endpoints.

### The mock's new debug switch, and why the e2e needed it

"Served when the network is down but the disk buffer is accepting" cannot be
staged by stopping Hoplock Control: with Control stopped a session cannot be
authorized at all, so the check under test never runs. What is needed is a proxy
whose records are undeliverable while its decisions still arrive — which is also
a real failure, since the log destination and the policy service are not the same
service. `POST /debug/logs/sink` with `{"accepting":false}` makes both log
endpoints answer **503** (chosen so the shipper treats the records as owed rather
than dropping them) and leaves everything else up. `/debug/reset` clears it, and
the scenario restores it in a `t.Cleanup`.

`api/README.md` has a "Mock-only endpoints" table and this endpoint is
**deliberately not in it**: `api/` is a vendored shared surface
(`docs/CROSS-REPO-PROTOCOL.md` §1), so a doc-only edit there would cost two sync
PRs to document a test hook. It is documented in `deploy/README.md` instead,
beside the other debug commands a person actually runs, and in the constant's own
comment. A future session adding a *contract* endpoint should still update
`api/`; a future mock-only one has a precedent either way and should pick
deliberately.

### What could not be run in this session

`make e2e` and `golangci-lint run`. There is no Docker daemon in this environment
(`docker info` fails on the socket), so the new e2e group has been vet-checked and
compiled under `-tags e2e` but not executed; and the available `golangci-lint` is
built against Go 1.25, which refuses a module targeting 1.26 — the same
constraint `.github/workflows/ci.yml` documents at the pinned version. In their
place: `go build`, `go vet -tags e2e`, `go test -race ./...` (all green),
`gofmt -l` (clean), and `staticcheck -tags e2e ./...` (clean), which covers the
`staticcheck` and `unused` linters the project enables.

### Follow-ups

None queued. Two things a later phase might want, neither of which is a gap in
this one:

- A **status endpoint** would have a use for `Server.liveSessions()`, which exists
  now and is otherwise only read by tests (as `Server.Sessions()` already was).
- If the device sink's two events ever need the grant context, the shape to reach
  for is the Shipper holding the per-session grant rather than the credential
  plane carrying it — see the gap above.
