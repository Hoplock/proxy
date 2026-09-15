# 0039 — Observable liveness and durability — Learnings

## Summary
- What shipped: `RevocationEvent.heartbeat_interval_seconds` — the server now
  **states on the wire** the heartbeat interval it is keeping, so the liveness
  obligation is gradeable from the stream instead of from a harness's config
  file. Plus two paragraphs saying plainly what this contract does **not** make
  observable (log durability, gap recovery) and what a harness needs instead.
- Key packages/files: `api/control.yaml` (4.0.0 → **4.1.0**), `api/README.md`,
  `internal/control/{contract.go,heartbeat_test.go,contract_test.go}`,
  `cmd/mock-control/{events.go,fixtures.go,fixtures.example.yaml,events_test.go}`,
  `docs/PLAN.md` §6.4.
- Key interfaces/types: `RevocationEvent.HeartbeatIntervalSeconds int32`;
  `(*RevocationEvent).AdvertisedHeartbeatInterval() (time.Duration, bool)`;
  `control.MaxHeartbeatIntervalSeconds = 10`.
- **Absent-value default:** the proxy falls back to its own timers, exactly as
  every server behaved before the field existed. The field advertises; it does
  not configure.
- **Tighten-only:** a proxy may use it to notice a dead stream *sooner* than its
  configured timeout, never to extend that timeout — sooner is always allowed,
  later is not (same idiom as `cache.ttl_seconds` and `report_after_seconds`).
- **The ceiling is 10s**, chosen as half `DefaultHeartbeatTimeout` (20s) so that
  **two** consecutive intervals fit inside the reconnect timeout — one lost or
  delayed heartbeat must not make a healthy stream look dead. Keeping the
  advertised interval and staying inside the ceiling are **both** conformance
  requirements; a server advertising 600s and keeping to it passes the first and
  breaks every proxy in the fleet.
- **`control.PolicyVersion` did not move and is still `4`.** The number governs
  `/v1/authorize` and nothing else — that is the response decoded strictly, so
  it is the only place an unknown field could be a dropped restriction. This
  field is on another endpoint's payload, and the events stream already requires
  a proxy to ignore what it does not recognise, so it reaches an older peer
  harmlessly. `TestHeartbeatIntervalDidNotMoveThePolicyVersion` asserts both the
  number and, structurally, that the field is absent from `AuthorizeResponse`.
- Decisions affected: none amended. D2, D7, D8 unchanged; this makes an existing
  obligation observable, it does not move one.
- Downstream: `hoplock/control` sync kickoff handed to the user in the PR's
  `## Cross-repo impact` section (re-vendor, `internal/contract` resolver,
  `cmd/pdpconform` heartbeat case, two docs that record the gaps as open).
  `hoplock/enterprise`: None.

## Details

### Where this came from, and why the fix is two different shapes

`hoplock/control` phase 0002 built `cmd/pdpconform`, the black-box conformance
suite for this contract, and writing it surfaced two obligations the document
states but does not make **checkable**:

1. Heartbeats "at a steady interval" — with no interval on the wire, the suite
   graded a number a human typed into an expectation file. That is a missing
   **field**.
2. The priority ack means *durable* and gap recovery means *no event was
   silently skipped* — and nothing in this contract reads a record back or
   publishes an event. That is a missing **sentence**, not a missing endpoint.

Neither was a bug in an implementation, which is why neither fix changes
behaviour. The second is the more interesting one: the honest answer is that
these operations are not proxy-facing, so putting them on `/v1` would make every
Hoplock Control implement an operator API it does not need in order to make
someone else's test easier. Both README paragraphs are therefore written as
statements of fact about the contract's scope — they name
`cmd/mock-control`'s `GET /debug/logs` and `POST /debug/revoke` as the
**reference shapes** a harness takes as inputs, and both stay mock-only.

### Why the ceiling is a number and not "comfortably"

The path description used to say heartbeats must arrive "comfortably inside the
proxy's timeout". A server cannot be graded against an adverb, and once the
server is allowed to *state* an interval, "comfortably" becomes actively
dangerous: a server advertising 600s keeps its own claim perfectly while being
indistinguishable from dead.

10s comes from the only other number in the system:
`DefaultHeartbeatTimeout = 20s`. Halving it is what leaves room for exactly one
lost heartbeat. `TestHeartbeatCeilingLeavesRoomForALostHeartbeat` asserts
`2 * ceiling <= DefaultHeartbeatTimeout`, so if a later phase retunes the
timeout the two constants cannot drift apart silently.

### Advertising is not consuming, deliberately

Nothing in the proxy reads the field yet, and that is the phase boundary. Wiring
it into `RevocationStream`'s timer or into `CacheOptions.StaleAfter` is a
behaviour change with fail-closed consequences (a value that *shortened*
detection would change when the cache goes dark), so it belongs in its own
phase. `AdvertisedHeartbeatInterval` resolves the absent value and stops there.

The tighten-only rule is what makes leaving the field unconsumed safe **and**
what makes it safe to consume later: because the value can only ever make
detection stricter, a hostile or broken server gains nothing by lying upward.

`cmd/loadgen`'s stand-in control server was deliberately left alone. It
heartbeats and advertises nothing, which is not an oversight — it is the
absent-value default working: a proxy talking to it stays on its own timers,
exactly as before. The rule that nothing has to be updated everywhere at once is
the point of having an absent-value default at all.

### The assertion that makes the field worth adding

`internal/control/heartbeat_test.go` proves the downstream suite's assertion is
expressible from what the contract now carries. `heartbeatConformance` is the
grader — deliberately a **test** helper, not package surface, because it grades
rather than enforces — and it checks both halves. Three cases:

- a server keeping what it advertises passes;
- a server advertising 2s and delivering every 6s **fails**, and before this
  field there was no way to notice: the suite would have compared 6s against its
  own expectation file;
- a server advertising 600s and keeping to it **fails the ceiling**, which is
  why the ceiling is a requirement of its own rather than a note.

The stream is real — a real `httptest` NDJSON server, read through the real
`RESTClient` — and the advertised value is read off the wire. Only the *spacing*
between arrivals is simulated: the emit handshake already fixes the order of
events, so a clock the test supplies saves it from sleeping for seconds without
weakening what is under test. This follows the injected-clock discipline the
cache tests already use.

### The mock advertises what it actually does

`advertisedHeartbeatSeconds()` derives the value from `events.heartbeat_ms` —
the same fixture key that drives the ticker — so the mock structurally cannot
advertise one interval and keep another. Sub-second fixture intervals (the tests
use 20ms) round **up** to the whole second: the wire field has `minimum: 1`, and
a server heartbeating sooner than it advertised still keeps its claim, while one
rounding down would not. A fixture with `heartbeat_ms` negative disables
heartbeats and advertises nothing.

### Test notes

- `internal/control/contract_test.go` gained the field in two cross-checks: the
  spec-presence map (so `control.yaml` must document it) and the README name
  list (so `api/README.md` must too). Both are the existing drift guards; no new
  mechanism.
- `cmd/mock-control/events_test.go` asserts end-to-end through the real client
  that the first heartbeat carries the interval, that it arrived inside it, and
  that it is under the ceiling — plus a table for the derivation itself.

### Follow-ups (not queued; nobody has asked for them)

- **Consuming the advertisement.** A proxy could tighten its reconnect timeout
  toward the advertised interval. Out of scope here by name; it needs its own
  phase because it changes when the fail-closed rule bites.
- **Rejecting an over-ceiling advertisement at the client.** Today a proxy
  ignores one, which is correct and costs nothing — the value can only tighten.
  Turning it into an `ErrProtocol` would make a misconfigured server an outage,
  which is a real design call and not obviously the right one.
