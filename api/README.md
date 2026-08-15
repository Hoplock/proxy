# Management API — contract

`management.yaml` is the **source of truth** for every conversation between a
bastion (Policy Enforcement Point) and the management server (Policy Decision
Point). It is an OpenAPI 3 document; this file is the short human-readable
companion. If the two disagree, the OpenAPI document wins.

- Go types and client: `internal/mgmt` — the only package allowed to talk to the
  management server (PLAN §3).
- Reference implementation: `cmd/mock-management` (see "Mock server" below).
- Architecture and decisions referenced here: `docs/PLAN.md` (D2, D3, D5, D7,
  D8, D9).

## Ground rules

- **JSON over HTTPS**, one POST per decision (D9). All paths are absolute from
  the server's base URL and versioned with a `/v1` prefix.
- **The bastion originates no policy, but it does not re-ask per action.** Every
  authentication, authorization, route, channel, and filter decision is *made*
  by the server (D2) — and `POST /v1/authorize` returns the **whole policy for
  the connection** in one response: route, channel allow-list, and the complete
  filter policy. The bastion holds that snapshot for the connection's lifetime
  and enforces it locally, so opening a channel, running a command, and pumping
  a stream cost **zero** calls to this API. The round trips are at session
  setup (auth, authorize, host-key report), not on the data path.
- **The snapshot outlives the connection only if the server says so.** An
  authorize decision may carry a `cache` hint (an opaque key plus a TTL the
  *server* sets), and the bastion may then reuse it for later connections — but
  only while it can still hear the revocation stream. No hint means no reuse.
  See "Caching and the latency budget" below.
- **`401` is a decision, not a failure.** It means *deny*. Transport failures,
  timeouts, and `5xx` are different, and a caller must never treat them as
  either a deny or an allow — it fails the session closed. The two are also
  reported to the end user differently, and never collapsed into one message: a
  deny is deliberately vague, an outage says plainly that it is an outage
  (PLAN §4.3). Failing closed is not the same as failing silently.
- **Bastion→server authentication** is a bearer token
  (`Authorization: Bearer <token>`), deliberately a thin seam: a deployment can
  move to mTLS or a signed assertion without changing any payload.
- **Errors** use one envelope: `{"error":{"code","message"}}`. Messages never
  contain credentials.

## Endpoints

| Path | Purpose | Success | Go client method |
| --- | --- | --- | --- |
| `POST /v1/auth/cert` | Authenticate an offered public key or certificate | `200` | `AuthenticateCert` |
| `POST /v1/auth/password` | Authenticate a password, possibly starting MFA | `200` | `AuthenticatePassword` |
| `POST /v1/auth/mfa/poll` | Poll an outstanding out-of-band MFA challenge | `200` | `PollMFA` |
| `POST /v1/authorize` | Authorize an identity for a target and return the route + policy | `200` | `Authorize` |
| `POST /v1/hostkeys/report` | Report a target host key, get the trust decision | `200` | `ReportHostKey` |
| `POST /v1/logs/batch` | Ingest a batch of log records | `202` | `IngestLogBatch` |
| `POST /v1/logs/priority` | Ingest one critical record, immediately | `200` | `IngestPriorityLog` |
| `GET /v1/bastions/{bastion_id}/events` | Subscribe to the revocation stream (NDJSON) | `200` | `StreamEvents` |

Every endpoint can also answer `400` (malformed request), `401` (deny), and
`500` (server failure).

### Authentication (certificate first, then password + MFA)

The bastion tries the certificate flow first and falls back to password +
out-of-band MFA (PLAN §4.1). Both flows return an **identity with claims**, not
a boolean, so AD/Okta/OIDC can be added later without changing callers (D4).

MFA is entirely the server's concern. `POST /v1/auth/password` returns either
`status: authenticated` (no second factor needed) or `status: mfa_required` with
an `mfa` challenge. The bastion then polls `POST /v1/auth/mfa/poll` with the
challenge token, no more often than `poll_after_ms`, until it gets
`authenticated` (approved) or `401` (denied, expired, or unknown token). The
bastion never contacts the MFA provider.

The submitted password is never logged, echoed in an error, or stored — on
either side (PLAN §7). `mgmt.AuthenticatePasswordRequest` redacts it in its
`String`/`GoString` methods so an accidental `%v` cannot leak it.

### Authorize + route

One call shapes the whole session. The response carries:

- `route_type`: `direct` (target is the end host) or `nexthop` (target is the
  next bastion, which repeats the flow — PLAN §6.1);
- `target` / `target_port`: where to connect, per `route_type`;
- `permissions`: opaque permission-set name, carried into logs;
- `permitted_channels`: the SSH channel allow-list; **an empty list denies every
  channel** (D5);
- `filter_policy`: an ordered `rules` list, each rule a `match` pattern with
  **its own** `action` (`allow_and_log`, `block_command`, `warn_and_continue`,
  `kill_session`) and an optional operator `message`, plus a `mode`
  (`whitelist`/`blacklist`) deciding commands no rule matched. **First match
  wins**; per-rule actions let one policy warn on `sudo`, block `shutdown`, and
  kill the session on `rm -rf /` (PLAN §6.3);
- `hop` (next-hop routes only): `final_target`, `max_hops`, and the `hop_trail`
  to forward, which is how loops and runaway chains are caught.

### Host keys

The bastion reports every target host key it sees before completing the target
handshake. The prototype's server trusts on first use and records the key, and
answers `known: false` the first time (D7). The response always carries an
explicit `decision`, so a stricter per-target policy later needs no change on
the bastion.

### Logs: two paths, on purpose

`/v1/logs/batch` is the throughput path; `/v1/logs/priority` is a **separate
endpoint** for blocked commands and other critical events (D8). Separate rather
than a flag on the batch endpoint so a critical event is never queued behind a
large batch, can carry its own timeout and connection, and is trivially
prioritised in the server and in any middlebox. The batch endpoint answers `202`
(accepted for storage); the priority endpoint answers `200` and its ack means
the record is **durable**, so the bastion can act on the event knowing it was
recorded.

Records carry a client-assigned `record_id`; the server de-duplicates on it, so
retrying a batch after a timeout or draining the local disk buffer is safe.
`accepted` counts records actually stored.

## Caching and the latency budget

Where the round trips are for one session, before any caching:

| Phase | Calls | On the critical path? |
| --- | --- | --- |
| Authenticate (cert) | 1 | yes |
| Authenticate (password + MFA) | 1 + one per poll | yes, and bounded by the user |
| Authorize + route | 1 | yes |
| Host-key report | 1 per target host key | yes, before the target handshake |
| Channel open / command / stream data | **0** | — |
| Logs | batched, off the data path | no (priority records excepted, by design) |

So the **session stream carries no management-server latency**: `/v1/authorize`
delivers the channel allow-list and the full command filter policy up front, and
the bastion enforces both against that connection-scoped snapshot. A blocked
command costs a local match. The one deliberate exception is D8's priority log
path — a critical security event is shipped synchronously so the bastion knows
it was recorded before acting on it — which trades latency for auditability
exactly when that trade is worth making.

What that does not do by itself is amortise setup **across** connections: ~3
sequential round trips per session, again per hop on a chain, and again for
every `scp` beside a shell. Two mechanisms address it, and they only make sense
together — a cached allow with no way to withdraw it is just a slower
revocation.

### Reusing an authorize decision (`cache`)

`AuthorizeResponse` may carry a `cache` object: an opaque `key` and a
`ttl_seconds`. **Absent, or `ttl_seconds: 0`, means do not cache** — that is the
default for every route that does not opt in.

- **Only the authorize decision is cacheable.** Authentication never is: an MFA
  approval is a per-session assertion, and certificate validation is where
  revocation bites. `mgmt.CachingClient` passes every other call straight
  through.
- **The server owns the lifetime.** By default the bastion honours
  `ttl_seconds` exactly. An operator may set a local ceiling
  (`CacheOptions.MaxTTL`), which clamps **downward only** — never longer, and
  the bastion never invents a hint. That keeps the PDP in charge of its own risk
  appetite: omit `cache` for a sensitive target and every connection is
  re-decided.

  A clamp is off unless configured, and never silent when it is: every decision
  whose lifetime it shortens is counted in `CacheStats.Clamped` and logged with
  the key and both lifetimes. A bastion caching for less time than its peers is
  otherwise indistinguishable from a server or network problem, and that is the
  real cost of setting one.
- **The key is opaque and chooses the sharing scope.** The bastion never
  constructs or parses one; it only echoes it back in a `cache_invalidate`
  event. Two requests answered with the same key are one cached decision,
  invalidated together — so a key may be per subject+target, per subject, per
  permission set. A key **must never be shared across identities**: it would let
  one user be served another's policy. (`CachingClient` also refuses to serve an
  entry to a different subject, but that is a backstop, not the contract.)

### Revoking (`GET /v1/bastions/{bastion_id}/events`)

A long-lived NDJSON response, one `RevocationEvent` per line. It is **outbound
from the bastion** because bastions sit behind firewalls and must not need an
inbound listener, which makes this the server's only route to a running bastion:
the kill switch for a session already in flight, and the thing that bounds the
damage of a cached allow. A server that issues cache hints must serve it.

| `type` | Effect |
| --- | --- |
| `session_kill` | End the named `session_ids`, or every session for a `subject`, or `all`. The `reason` is **shown to the user** before the connection closes and copied into the audit log (PLAN §4.3) — a revoked session must not look like a crash — so it must be safe to disclose. |
| `cache_invalidate` | Drop the decisions cached under `keys`, or for a `subject`, or `all`. Running sessions are untouched: they already hold their snapshot. |
| `heartbeat` | Liveness only. A silent stream is indistinguishable from a healthy idle one, so a bastion that stops hearing these reconnects (default timeout 20s). |
| `resync` | "You missed events that cannot be replayed": the bastion drops its entire cache and re-authorizes from scratch. |

**Gap recovery.** On reconnect the bastion sends the last `event_id` it
processed as `?last_event_id=`. The **server** decides what happens: replay
everything after that id before resuming live delivery, or — when the id is too
old, unknown, or no history is kept — emit `resync` as the first line and
nothing older. No `last_event_id` means a fresh subscription starting from now.

**Fail-closed rule.** While the bastion has not heard the stream for longer than
`CacheOptions.StaleAfter` (default 30s) it serves **nothing** from cache and
stores nothing new: every connection is re-authorized. It does **not** kill live
sessions — losing the ability to hear about a revocation is a reason to distrust
the cache, not to drop users mid-command. Both halves are deliberate.

The window in which a withdrawn authorization can still be honoured is therefore
the entry's remaining TTL, and only while the stream is also down — which is why
`ttl_seconds` belongs in seconds to low minutes.

## Go types

`internal/mgmt` has one struct per payload; the JSON tags are the contract.
Requests/responses: `AuthenticateCertRequest`, `AuthenticatePasswordRequest`,
`MFAPollRequest`, `AuthenticateResponse`, `AuthorizeRequest`,
`AuthorizeResponse`, `HostKeyReportRequest`, `HostKeyReportResponse`,
`LogBatchRequest`, `LogBatchResponse`, `LogPriorityRequest`,
`LogPriorityResponse`. Shared types: `ConnMeta`, `Identity`,
`PublicKeyMaterial`, `MFAChallenge`, `FilterPolicy`, `FilterRule`, `HopMetadata`,
`LogRecord`, `CacheHint`, `RevocationEvent`, `SessionKillEvent`,
`CacheInvalidateEvent`.

Caching and revocation live in the same package: `CachingClient` (a `Client`
decorator, `Authorize` only), `RevocationStream` (the subscription loop), and
`SessionRegistry` — the interface the proxy implements in phase 0005 to actually
tear a session down, with `NopSessionRegistry` standing in until then.
Enum values have named constants (`RouteTypeDirect`, `FilterActionKillSession`,
`SeverityCritical`, …); a test asserts they match the enums in this document.

Errors are classified with sentinels — `ErrUnauthorized` (the deny decision, via
`mgmt.IsUnauthorized`), `ErrBadRequest`, `ErrServer`, `ErrTransport`,
`ErrProtocol` — all wrapped in an `*APIError` that names the failing operation.

## Mock server

`cmd/mock-management` implements this contract from a static fixture file, which
makes policy deterministic and scriptable for tests and for the e2e topology.

```
go run ./cmd/mock-management -listen 127.0.0.1:8080 \
    -fixtures cmd/mock-management/fixtures.example.yaml [-log-dir /tmp/mocklogs]
```

`cmd/mock-management/fixtures.example.yaml` is the worked example and is
exercised by the tests, so it always parses. Unknown keys are rejected at
startup, and every problem in a file is reported at once.

### Fixture format

| Key | Meaning |
| --- | --- |
| `bastion_token` | Bearer token required on every `/v1` request. Empty disables bastion auth. |
| `users[]` | `login`, `identity` (`subject`, `display_name`, `source`, `principals`, `groups`, `claims`), `key_fingerprints` (accepted for cert auth), `password`, and `mfa`. |
| `users[].mfa` | `required`, `decision` (`approve`/`deny`), `pending_polls` (how many polls stay pending before resolving — this is what makes MFA deterministic), `poll_after_ms`, `ttl_ms`, `prompt`. |
| `routes[]` | Matched in order, first match wins; no match is a `401`. `login` and `target` accept `*`. Then `route_type`, `resolved_target` (direct only), `next_hop` + `max_hops` (nexthop only), `target_port`, `permissions`, `permitted_channels`, `filter_policy` (`mode` plus ordered `rules`, each `match` + `action` + optional `message`), and `cache`. |
| `routes[].cache` | `ttl_seconds` (0 or absent: not cacheable) and an optional `key`. An unset key derives one per (subject, target); set it explicitly to model a server that shares one decision across targets. |
| `host_keys` | `decision` (`accept`/`reject`) applied to keys not seen before, and `known[]` (`target` + `fingerprint`) to pre-seed trusted keys. |
| `events` | `heartbeat_ms` (interval between heartbeats; negative disables them, to exercise a bastion's missed-heartbeat detection) and `replay_buffer` (events retained for replay; resuming from before them answers `resync`). |

Defaults: `identity.subject` falls back to the login and `identity.source` to
`fixture`; a route defaults to `login: "*"`, `target: "*"`, `route_type:
direct`, an `allow_and_log` blacklist, and **no** cache hint;
`host_keys.decision` defaults to `accept` (TOFU); `events.heartbeat_ms` to
`5000` and `events.replay_buffer` to `128`. Fixtures are test data — never put a
real secret in one.

### Mock-only endpoints

These are **not** part of the contract; no production server implements them.

| Path | Purpose |
| --- | --- |
| `GET /debug/logs` | Returns `{"batched":[…],"priority":[…]}` — everything ingested so far, for assertions. |
| `POST /debug/reset` | Clears ingested logs, MFA challenges, learned host keys, and the retained event history. |
| `POST /debug/revoke` | Publishes a `RevocationEvent` to every subscriber, standing in for an operator action. Returns `{"event_id","delivered"}`, so a test can confirm a subscription was live. |

With `-log-dir`, ingested records are also mirrored to `batch.jsonl` and
`priority.jsonl` in that directory, so a scenario can inspect them after the
process exits.

## Changing the contract

1. Edit `management.yaml` first.
2. Update the Go types in `internal/mgmt` and the mock server to match.
3. Run `go test ./...` — `internal/mgmt` cross-checks the client's paths and
   enums against this document, and `cmd/mock-management` is driven end-to-end
   through the real client.
4. If the change alters the architecture, update `docs/PLAN.md` in the same PR
   (PROTOCOL §3).
