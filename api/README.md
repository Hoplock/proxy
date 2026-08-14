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
- **The snapshot does not outlive the connection.** There is no cross-connection
  policy cache in the prototype (D2), so a second SSH session re-runs setup. If
  that cost matters, it is a contract change — see "Caching" below.
- **`401` is a decision, not a failure.** It means *deny*. Transport failures,
  timeouts, and `5xx` are different, and a caller must never treat them as
  either a deny or an allow — it fails the session closed.
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
- `filter_policy`: `mode` (`whitelist`/`blacklist`), `commands`, and `action`
  (`allow_and_log`, `block_command`, `warn_and_continue`, `kill_session`) —
  PLAN §6.3;
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

Where the round trips actually are, for one session:

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

What this does **not** do is amortise setup across connections. Today a session
costs ~3 sequential round trips before the first byte flows, every time, and a
next-hop chain pays that per hop. A user opening several sessions (an `scp`
alongside a shell, a tool that reconnects) pays it each time. That is D2's
deliberate prototype choice — "the bastion caches nothing security-relevant
beyond the lifetime of a connection" — not an oversight, and the contract
currently has **no field to express a cache lifetime**.

Phase 0003 addresses it (`prompts/queued/0003-policy-caching-and-session-revocation.md`,
PLAN §6.4). The shape matters more than the mechanism:

- **Cache the authorize decision, not the authentication.** An MFA approval is a
  per-session assertion; caching it defeats the second factor. Certificate
  validation is where revocation is enforced, so it is the wrong thing to skip.
  The authorize decision — route + channels + filter policy for
  (subject, target, auth method) — is the reusable part.
- **The server sets the lifetime, not the bastion.** The natural addition is an
  optional cache hint on `AuthorizeResponse` (a TTL, plus a key the server
  controls), so the PDP keeps ownership of its own risk appetite and can return
  a zero TTL for sensitive targets. A bastion-side TTL would let the PEP decide
  policy, which is precisely the inversion D2 exists to prevent.
- **Revocation is the hard half.** Any cached allow outlives a revocation for up
  to its TTL. That bounds the acceptable TTL (seconds to low minutes), or needs
  a server→bastion invalidation path, which is a bigger change than a TTL field.

## Go types

`internal/mgmt` has one struct per payload; the JSON tags are the contract.
Requests/responses: `AuthenticateCertRequest`, `AuthenticatePasswordRequest`,
`MFAPollRequest`, `AuthenticateResponse`, `AuthorizeRequest`,
`AuthorizeResponse`, `HostKeyReportRequest`, `HostKeyReportResponse`,
`LogBatchRequest`, `LogBatchResponse`, `LogPriorityRequest`,
`LogPriorityResponse`. Shared types: `ConnMeta`, `Identity`,
`PublicKeyMaterial`, `MFAChallenge`, `FilterPolicy`, `HopMetadata`, `LogRecord`.
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
| `routes[]` | Matched in order, first match wins; no match is a `401`. `login` and `target` accept `*`. Then `route_type`, `resolved_target` (direct only), `next_hop` + `max_hops` (nexthop only), `target_port`, `permissions`, `permitted_channels`, `filter_policy`. |
| `host_keys` | `decision` (`accept`/`reject`) applied to keys not seen before, and `known[]` (`target` + `fingerprint`) to pre-seed trusted keys. |

Defaults: `identity.subject` falls back to the login and `identity.source` to
`fixture`; a route defaults to `login: "*"`, `target: "*"`, `route_type:
direct`, and an `allow_and_log` blacklist; `host_keys.decision` defaults to
`accept` (TOFU). Fixtures are test data — never put a real secret in one.

### Mock-only endpoints

These are **not** part of the contract; no production server implements them.

| Path | Purpose |
| --- | --- |
| `GET /debug/logs` | Returns `{"batched":[…],"priority":[…]}` — everything ingested so far, for assertions. |
| `POST /debug/reset` | Clears ingested logs, MFA challenges, and learned host keys. |

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
