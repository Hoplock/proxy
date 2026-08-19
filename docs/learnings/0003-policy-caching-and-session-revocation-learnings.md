# 0003 — Policy caching & session revocation — Learnings

## Summary
- What shipped: server-authorised reuse of authorize decisions and the
  server→proxy revocation stream that makes it safe — contract, client-side
  cache, subscription loop, and mock support. No proxy wiring yet (no proxy
  exists until 0005).
- Key packages/files: `api/control.yaml` + `api/README.md`,
  `internal/control/{contract,rest,cache,events,revocation}.go` (+ tests),
  `cmd/mock-control/{events,server,fixtures}.go`,
  `cmd/mock-control/fixtures.example.yaml`.
- Key types: `CacheHint{Key,TTLSeconds}` on `AuthorizeResponse`;
  `RevocationEvent{EventID,Type,Timestamp,SessionKill,CacheInvalidate}` with
  `EventType` `session_kill|cache_invalidate|heartbeat|resync`;
  `CachingClient`/`CacheOptions`/`CacheStats`/`CacheController`;
  `EventStreamer`/`EventStream` + `RESTClient.StreamEvents`;
  `RevocationStream`/`StreamOptions`; `SessionRegistry` + `NopSessionRegistry`.
  New path `PathProxyEvents` = `GET /v1/bastions/{bastion_id}/events`,
  `ProxyEventsPath(id)`, `QueryLastEventID`.
- **Cache key semantics:** the key is the server's, opaque, and defines the
  invalidation *and* sharing scope; a proxy never builds, parses, or extends
  one, and a key must never span identities (the client also refuses to serve an
  entry to another subject). No hint, `ttl_seconds: 0`, or a TTL without a key
  ⇒ not cached. `CacheOptions.MaxTTL` clamps **down only**, is **off by
  default** (the server's lifetime is honoured exactly), and every decision it
  shortens is counted in `CacheStats.Clamped` and logged via
  `CacheOptions.Logger` — see "Making the clamp observable" below.
- **Fail-closed rule:** while the revocation stream has been unheard for longer
  than `CacheOptions.StaleAfter` (**default 30s**, `DefaultStaleAfter`) the
  cache serves nothing and stores nothing — every connection re-authorizes.
  Live sessions are **not** killed. Both halves are deliberate.
- **Gap recovery:** the proxy reconnects with `?last_event_id=<last
  processed>`; the **server** decides — replay everything after it, or emit
  `resync` as the first line (⇒ proxy drops its whole cache). No id = start
  from now. Missed heartbeats (default timeout 20s) mean a dead stream.
- **What 0005 must implement:** `SessionRegistry` —
  `KillSession(ctx, sessionID, reason) error`,
  `KillSubject(ctx, subject, reason) error`, `KillAll(ctx, reason) error`. It
  MUST show `reason` to the user before closing the connection (PLAN §4.3).
- Decisions affected: D2 (the caching half it already allows), D8/D9 unchanged.
  **No `docs/PLAN.md` change** — §6.4 described this mechanism and the
  implementation did not deviate.

## Details

### The two-level cache, and why

The cache key is only known *after* the response, so a lookup cannot be by
server key alone. `CachingClient` therefore keeps two maps:

- `shapes`: request shape → server key. The shape is everything that could
  change the answer (subject, login, target, port, auth method, hop trail) and
  is a **proxy-side lookup key only**.
- `entries`: server key → `{key, subject, expiresAt, resp}`.

This is what makes "the server chooses the sharing scope" real: if the server
answers two different requests with one key, both shapes point at one entry and
one `cache_invalidate` drops both. The proxy can never share a decision more
widely than the server did, because it never invents a key. `MaxEntries`
(default 4096) bounds both maps; hitting it costs hits, never correctness.

Responses are **deep-copied in and out** (`AuthorizeResponse.clone`), so one
session mutating its own `PermittedChannels` or filter rules cannot rewrite the
policy handed to the next. A test asserts this.

Denies are not cached either: a `401` is as revocable as an allow and the server
re-decides it for free.

### Staleness

`CachingClient.StreamAlive(t)` is called by `RevocationStream` on every
successful connect and every event (heartbeats included); `StreamStale()` is
`now - lastAlive > StaleAfter`. A proxy that has **never** connected is stale,
so a deployment that runs the caching client without a subscription gets no
cache at all — the correct fail-closed outcome, and worth knowing before
debugging a "cache that never hits".

Nothing is *stored* while stale either, so a decision banked during a blind
period cannot be served after recovery without the server having had a chance to
invalidate it.

### Stream mechanics

`EventStreamer` is deliberately **separate from `Client`**: it is the one
long-lived call, `CachingClient` has nothing to add to it, and a fake `Client`
in a test should not have to implement it. `RESTClient` implements both, and
`StreamEvents` bypasses `Options.Timeout` (the response is long-lived; ctx is
the only bound).

`RevocationStream.Subscribe` blocks until ctx ends, and returns:

- `nil` on cancellation — the normal way to stop;
- the error only for `ErrUnauthorized`/`ErrBadRequest`, i.e. the proxy's own
  credential was rejected or the request was malformed. Retrying those forever
  would only hide a misconfiguration. Everything else reconnects with bounded
  exponential backoff (1s → 30s by default, resetting after a clean close).

Per event: `lastEventID` is advanced, the cache is marked alive, then the type is
dispatched. **Cache invalidation happens before the kill** for `session_kill`,
so a connection racing the teardown cannot be authorized from a decision that is
on its way out. A kill with no `reason` gets `defaultRevocationReason`, because
PLAN §4.3 requires the user be told *something*. Unknown event types are logged
and ignored (forward compatibility); a malformed line is `ErrProtocol` and drops
the connection.

Registry errors are logged, never fatal: a kill for a session this proxy never
had is normal.

### Mock server

- `GET /v1/bastions/{bastion_id}/events` is registered from `control.PathProxyEvents`
  directly — the constant is already a `net/http` wildcard pattern, so client and
  mock cannot drift on the route shape.
- **The stream would be killed by the server's `ReadTimeout`/`WriteTimeout`.**
  The handler clears both with `http.NewResponseController(w).SetReadDeadline/
  SetWriteDeadline(time.Time{})`. Any future long-lived endpoint needs the same.
- Event ids are `evt-<n>` from the shared counter, so they are monotonic and the
  *server* can parse them to replay "everything after n" and to decide when a
  gap is too old (`evictedThrough`). To the proxy they stay opaque.
- Heartbeats and resyncs are per-connection and are **not** retained for replay:
  they carry no state, and heartbeats would otherwise evict real events.
- A subscriber more than 64 events behind is disconnected rather than skipped —
  it reconnects and replays, so lagging costs a reconnect, never an event.
- `POST /debug/revoke` (mock-only) publishes an event and returns
  `{"event_id","delivered"}`; `delivered` is how a test confirms the
  subscription was live before asserting on the effect.
- Fixtures: `routes[].cache: {ttl_seconds, key}` and `events: {heartbeat_ms,
  replay_buffer}`. `heartbeat_ms: -1` disables heartbeats, which is how the
  proxy's missed-heartbeat path is exercised. Decoding is still strict, so
  every new field had to reach `fixtures.example.yaml` too.

### Making the clamp observable (added after 0003 merged)

Review question on the merged PR: why is a proxy allowed to shorten the
server's TTL at all, when that means two proxies in a fleet behave differently?

The objection is right about the cost and wrong about the default. `MaxTTL` is
zero unless an operator sets it, so out of the box the server's `ttl_seconds` is
honoured exactly. The clamp survives because it can only ever cause *more* calls
to the PDP — it cannot widen access, extend a decision, or invent one, so it does
not invert D2 the way a proxy-side TTL *floor* would — and it is the only lever
for turning caching down on one proxy during an incident without a Hoplock Control server deploy.

What changed is that it is no longer silent: a clamp that actually shortens a
stored decision increments `CacheStats.Clamped` and logs the key and both
lifetimes through the new `CacheOptions.Logger`. Both fire **only when the entry
was really stored**, so the count matches the decisions it applied to rather than
the calls it was merely configured for. `docs/PLAN.md` §6.4 now requires this:
off by default, observable when set.

If evidence later shows nobody uses the clamp, deleting `MaxTTL` outright is the
next step — the counter is what will tell you.

### Test notes

- The cache tests inject `CacheOptions.Now` and never sleep. `newTestCache`
  marks the stream alive first, because otherwise every test would be measuring
  the fail-closed rule instead of what it meant to.
- `RevocationStream` tests inject `StreamOptions.Sleep` to make backoff instant
  *and* assert the schedule (1s, 2s, 4s, 4s…). The heartbeat path uses a real
  20ms timeout — the one place a real timer is unavoidable.
- The end-to-end test in `cmd/mock-control/events_test.go` runs the real
  `RESTClient` + `CachingClient` + `RevocationStream` against the mock: it waits
  for `!cache.StreamStale()` (which is also the proof the subscription is up),
  asserts a second `Authorize` returns the same `decision_id` (a hit — the mock
  assigns a fresh id per decision), revokes by subject, then asserts both the
  registry call *with the operator's reason intact* and a fresh `decision_id`
  afterwards.
- `internal/control/contract_test.go` now checks a GET path as well as the POSTs
  (`checkResponses` helper), including that `bastion_id` and `last_event_id` are
  documented parameters, and covers the new `RevocationEvent.type` enum.

### Follow-ups (not done here, not blocking)

- **0005** implements `SessionRegistry` on the proxy and owes the user-facing
  half of PLAN §4.3: `reason` must reach the client before the connection
  closes. It also wires `CachingClient` + `RevocationStream` into `cmd/proxy`
  and will need config for `bastion_id`, `cache.max_ttl`, and
  `cache.stale_after` — `internal/config` decodes strictly, so the struct and
  `config.example.yaml` change together (the proxy token from 0002 is still
  outstanding in the same place).
- Backoff has no jitter, deliberately (deterministic tests). A fleet of proxies
  reconnecting to a Hoplock Control server that just restarted would benefit from it;
  add it behind `StreamOptions` when there is a fleet to protect.
- Nothing is cached across a restart, by design (out of scope here). If that is
  ever wanted, the persisted entries must be dropped unless the stream can be
  resumed from an id the server will still honour.
- `CachingClient` does not expose `StreamEvents`, so wiring code needs the
  `RESTClient` (or another `EventStreamer`) as well as the decorated `Client`.
