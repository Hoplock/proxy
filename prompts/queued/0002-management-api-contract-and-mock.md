# 0002 — Management API contract & mock server

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — architecture. Especially §1 (flow), §2 (D2, D3, D7, D8, D9),
  §4 (auth delegates to the server), §6 (routing/policy from server), §7 (logs).
- `docs/learnings/` — read summary blocks; open `0001` learnings for module
  path, config struct, and license header.

## Objective
Define the **management-server API contract** (the single most important
interface in the system) and ship a **mock/reference management server** plus a
typed Go **client**. Everything else in the system depends on this contract, so
it must be precise, versioned, and testable.

## In scope
- **Contract in `api/`** (source of truth): document each endpoint with request/
  response JSON schemas. Use an OpenAPI 3 document (`api/management.yaml`) plus a
  short human-readable `api/README.md`. Cover:
  1. **Authenticate (cert)** — bastion submits offered public key/cert + conn
     metadata; server returns an **identity/claims** object or 401.
  2. **Authenticate (password + MFA)** — bastion submits username + password +
     conn metadata; server performs out-of-band MFA and returns identity or 401.
     Model MFA as the server's concern; the bastion just relays and polls/waits
     per the contract.
  3. **Authorize + route** — given identity + requested target + conn metadata,
     returns `401` OR a route: `route_type` (`direct` | `nexthop`), `target`,
     `permissions`, **permitted channel types**, **filter policy** (mode
     `whitelist|blacklist`, list, action `allow_and_log|block_command|
     warn_and_continue|kill_session`), and any hop metadata. (Mirror PLAN §1/§6.)
  4. **Report host key** — bastion reports a newly seen target host key (D7).
  5. **Ingest logs (batch)** — accepts a batch of structured log records.
  6. **Ingest logs (priority/immediate)** — accepts a single critical record
     with low latency (D8). May be the same endpoint with a priority flag —
     decide and document.
- **Contract types in `internal/mgmt`**: Go structs for every payload, plus a
  `Client` interface abstracting the transport (so tests use the mock and later
  phases can swap REST for gRPC/streaming without touching callers).
- **REST client implementation** (`internal/mgmt`, JSON over HTTPS, D9):
  context-aware, timeouts, typed errors (distinguish 401 from transport errors),
  and a clear seam for auth of the bastion→server channel (stub/token for now).
- **Mock server** (`cmd/mock-management`): implements the contract from a static
  config/fixture file (e.g. users, allowed targets, routes, per-target policy,
  channel allow-lists). Deterministic and scriptable for tests. It should be able
  to return `direct`, `nexthop`, `401`, and various filter policies based on
  fixtures. Store received logs in memory/on disk so tests can assert on them.

## Out of scope
- Real authentication backends (AD/Okta) — the mock reads fixtures.
- Bastion-side consumption of these calls (auth/proxy phases consume them).

## Acceptance criteria
- `api/management.yaml` validates as OpenAPI 3.
- `internal/mgmt.Client` interface + REST implementation compile and are
  unit-tested against an `httptest` server.
- `cmd/mock-management` serves all endpoints; a test drives it end-to-end for:
  cert auth success/deny, password+MFA success/deny, authorize→direct,
  authorize→nexthop, authorize→401, host-key report, batch log ingest, priority
  log ingest.
- Fixtures documented so later phases (and the e2e topology) can configure it.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move this prompt to `implemented/`; add
`docs/learnings/0002-management-api-contract-and-mock-learnings.md`. The Summary
block MUST list every endpoint, the exact Go type names for each payload, the
`mgmt.Client` interface signature, and how to configure the mock's fixtures —
later phases depend heavily on this. If the contract had to deviate from PLAN
§1/§6, update `docs/PLAN.md` in this PR.
