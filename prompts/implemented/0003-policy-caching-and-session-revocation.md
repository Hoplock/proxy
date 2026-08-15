# 0003 — Policy caching & session revocation

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — especially §2 (D2, D8), §4.3 (what the user is told), §6.4
  (caching & revocation), §7.
- `docs/learnings/0002-...-learnings.md` — the contract, the `mgmt.Client`
  interface, the error sentinels (a deny is **only** `ErrUnauthorized`), and how
  the mock's fixtures work. You are extending all three.
- `api/README.md` §"Caching and the latency budget" — the cost model and the
  seam this phase implements.

## Objective
Let the management server authorise a bastion to **reuse an authorize decision
for a bounded time**, and give the server a way to **kill an active session or
invalidate cached decisions at any moment**. The second is what makes the first
safe: without revocation, a cached allow outlives a withdrawal of access for the
length of its TTL.

Ship the contract, the client-side cache, and the revocation subscription.
Bastion-side *enforcement* of a kill is explicitly not in this phase — there are
no SSH sessions to tear down until 0005 — so this phase defines the hook 0005
implements.

## In scope

### 1. Contract (`api/management.yaml` + `api/README.md`)
- **Cache hint on `AuthorizeResponse`**: an optional `cache` object —
  `ttl_seconds` (integer; absent or `0` means **do not cache**) and `key`
  (opaque string chosen by the server). The bastion MUST treat `key` as opaque,
  MUST NOT construct or parse one, and MUST NOT extend a TTL. The server chooses
  the key, and therefore the sharing scope (per subject+target, per subject, …);
  document that a key must never be shared across identities.
- **Revocation stream**: `GET /v1/bastions/{bastion_id}/events` — a long-lived
  response of newline-delimited JSON, one event per line. Outbound-only from the
  bastion, because bastions sit behind firewalls and must not need an inbound
  listener (PLAN §1). Event envelope: `event_id`, `type`, `timestamp`, plus:
  - `session_kill` — `session_ids[]` **or** `subject` **or** `all`, plus
    `reason`. The reason is carried into the audit log **and** shown to the user
    before teardown (PLAN §4.3) — a revoked session must not look like a crash.
    Define `reason` as operator-authored text safe to display, and say so in the
    contract so a server author does not put policy internals in it.
  - `cache_invalidate` — `keys[]` **or** `subject` **or** `all`.
  - `heartbeat` — so a silently dead stream is detectable.
  - `resync` — "you missed events": the bastion drops its entire cache and
    re-authorizes from scratch.
- **Gap recovery**: the bastion sends the last `event_id` it processed on
  (re)connect (`?last_event_id=`); the server either replays from there or
  answers `resync`. Specify which side decides and what the server does when the
  id is too old to replay.

### 2. `internal/mgmt`
- `CachingClient` — a decorator implementing `Client`:
  `NewCachingClient(inner Client, opts CacheOptions) *CachingClient`. **Only
  `Authorize` is cached**; every other method passes through untouched.
  Authentication results are never cached — an MFA approval is a per-session
  assertion and certificate validation is where revocation bites. Say so in a
  comment; a future reader will be tempted.
  - Honours the server's `ttl_seconds`. `CacheOptions.MaxTTL` clamps it
    **downward only**: an operator may be more conservative than the server,
    never more permissive.
  - `Invalidate(keys ...string)`, `InvalidateAll()`, and a `Stats()` for
    hit/miss/expiry counts.
  - Injectable clock (`CacheOptions.Now`) so expiry is testable without sleeps.
- `RevocationStream` — subscribes to the events endpoint:
  `Subscribe(ctx context.Context, bastionID string) error`, reconnecting with
  bounded exponential backoff, treating a missed heartbeat as a dead stream, and
  routing each event to the cache and to a `SessionRegistry`.
- **Fail-closed rule** (specify and test): while the stream has been down for
  longer than `CacheOptions.StaleAfter` (default 30s), the `CachingClient`
  serves **nothing** from cache — every `Authorize` goes to the server. A stream
  outage must **not** kill active sessions: losing the ability to hear about a
  revocation is a reason to stop trusting cached decisions, not a reason to drop
  users mid-command. Both halves of that rule are deliberate; keep them.
- `SessionRegistry` — the hook 0005 implements in `internal/proxy`:
  ```go
  type SessionRegistry interface {
      KillSession(ctx context.Context, sessionID, reason string) error
      KillSubject(ctx context.Context, subject, reason string) error
      KillAll(ctx context.Context, reason string) error
  }
  ```
  Ship a no-op implementation so the stream is usable before 0005 lands.
  Document that an implementation MUST deliver the `reason` to the user before
  closing the connection (PLAN §4.3); that obligation is on the proxy in 0005,
  and this phase's job is to carry the reason to it intact.

### 3. Mock server (`cmd/mock-management`)
- Serve the events stream, including heartbeats at a fixture-set interval.
- Fixture support for `cache: {ttl_seconds: N}` per route.
- `POST /debug/revoke` (mock-only, alongside the existing debug endpoints):
  takes an event body and delivers it to subscribed bastions, so tests and the
  e2e topology can kill a live session on demand.

## Out of scope
- Tearing down real SSH sessions — 0005 implements `SessionRegistry`.
- Caching authentication or MFA results; caching anything across a restart.
- A poll-based fallback for bastions that cannot hold a long-lived connection.
- Server→bastion push over anything other than this stream (no inbound listener).

## Acceptance criteria
- `api/management.yaml` still validates (`make openapi-check`) and the contract
  test in `internal/mgmt` covers the new path and the new enums.
- `CachingClient` unit tests, with an injected clock, for: hit, miss, expiry,
  `ttl_seconds: 0` never caching, `MaxTTL` clamping down but never up,
  invalidate-by-key / by-subject / all, and the stale-stream rule.
- A cached decision is provably never served after **any** of: TTL expiry, an
  invalidation naming it, a `resync`, or the stream going stale.
- `RevocationStream` tests: reconnect with backoff, missed heartbeat detected,
  `resync` triggers `InvalidateAll`, context cancellation ends the subscription
  cleanly, and events dispatch to a fake `SessionRegistry`.
- An end-to-end test against the mock: subscribe, `POST /debug/revoke`, and
  assert the fake registry was called and the cache dropped the entry.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move this prompt to `implemented/`; add
`docs/learnings/0003-policy-caching-and-session-revocation-learnings.md`. The
Summary block MUST state the cache key semantics, the exact fail-closed rule and
its default, the event schema and gap-recovery behaviour, and the
`SessionRegistry` signature 0005 has to implement — later phases depend on all
four. Update `docs/PLAN.md` if the mechanism deviates from §6.4.
