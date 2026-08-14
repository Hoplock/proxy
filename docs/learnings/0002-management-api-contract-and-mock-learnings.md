# 0002 — Management API contract & mock server — Learnings

## Summary
- What shipped: the management API contract (`api/management.yaml`, OpenAPI 3 +
  `api/README.md`), the typed Go client and contract types in `internal/mgmt`,
  and a fixture-driven mock server in `cmd/mock-management` with debug endpoints
  for tests. No bastion-side consumption yet.
- Key packages/files: `api/management.yaml`, `api/README.md`,
  `internal/mgmt/{contract,client,rest,errors}.go`,
  `cmd/mock-management/{server,fixtures,main}.go`,
  `cmd/mock-management/fixtures.example.yaml`, `Makefile` (`openapi-check`),
  `.github/workflows/ci.yml` (job `openapi`).
- Endpoints (7): `POST /v1/auth/cert`, `POST /v1/auth/password`,
  `POST /v1/auth/mfa/poll`, `POST /v1/authorize`, `POST /v1/hostkeys/report`,
  `POST /v1/logs/batch` (→`202`), `POST /v1/logs/priority` (→`200`). Path
  constants: `mgmt.PathAuthenticateCert`, `PathAuthenticatePassword`,
  `PathPollMFA`, `PathAuthorize`, `PathReportHostKey`, `PathIngestLogBatch`,
  `PathIngestPriorityLog`.
- Key types: `mgmt.Client` (7 methods, all `(ctx, *Req) (*Resp, error)`:
  `AuthenticateCert`, `AuthenticatePassword`, `PollMFA`, `Authorize`,
  `ReportHostKey`, `IngestLogBatch`, `IngestPriorityLog`), `RESTClient` +
  `Options{BaseURL,Token,HTTPClient,Timeout,UserAgent}`; payloads
  `AuthenticateCertRequest`, `AuthenticatePasswordRequest`, `MFAPollRequest`,
  `AuthenticateResponse`, `AuthorizeRequest`, `AuthorizeResponse`,
  `HostKeyReportRequest/Response`, `LogBatchRequest/Response`,
  `LogPriorityRequest/Response`; shared `ConnMeta`, `Identity`,
  `PublicKeyMaterial`, `MFAChallenge`, `FilterPolicy`, `HopMetadata`,
  `LogRecord`; errors `ErrUnauthorized`/`ErrBadRequest`/`ErrServer`/
  `ErrTransport`/`ErrProtocol` + `*APIError` + `IsUnauthorized(err)`.
- Decisions made/affected: D2, D3, D7, D8 (priority logs are a **separate
  endpoint**, decision recorded in `api/README.md`), D9. No PLAN changes needed.
- Gotchas: **a deny is `ErrUnauthorized` only** — every other error means
  "unknown", so callers must fail closed and never treat an outage as a deny.
  `AuthorizeResponse.PermittedChannels == []` denies *all* channels. Mock
  fixtures decode strictly (unknown key = startup failure).
- What the NEXT session (0004) must know: use `mgmt.Client`, never HTTP; build
  `internal/identity` from `mgmt.Identity` (the wire DTO) and convert at the
  mgmt boundary; the cert-first-then-password+MFA order and the MFA polling loop
  are already specified below; run the mock with
  `-fixtures cmd/mock-management/fixtures.example.yaml`.

## Details

### Where the truth lives
`api/management.yaml` is the source of truth; `api/README.md` is the readable
companion (endpoint table, fixture format, mock-only endpoints, and the "how to
change the contract" checklist). `internal/mgmt` mirrors it in Go, and
`internal/mgmt/contract_test.go` fails if they drift: it checks the document is
OpenAPI 3.x, that every client path constant is documented with a `requestBody`,
the exact success status the client expects, and a `401`, that all `$ref`s
resolve, and that every enum in the document matches the Go constants.
`make openapi-check` (CI job `openapi`) runs a real OpenAPI 3 validator.

### The error contract (most important thing to get right downstream)
All client methods return `*APIError` wrapping a sentinel:

| Situation | Sentinel | Meaning for the caller |
| --- | --- | --- |
| HTTP 401 | `ErrUnauthorized` | **Deny decision.** Refuse the session. |
| other 4xx | `ErrBadRequest` | Caller bug. Fail closed. |
| 5xx | `ErrServer` | Server broken. Fail closed. |
| no usable response | `ErrTransport` | Unreachable/timeout. Fail closed. |
| response violates the contract | `ErrProtocol` | Don't trust it. Fail closed. |

Transport failures wrap the underlying cause too (`%w: %w`), so
`errors.Is(err, context.DeadlineExceeded)` works — 0010 can use that to decide
whether to retry a log shipment. The client validates responses before returning
them: unknown enum values, `authenticated` without an identity, `mfa_required`
without a token, a route without a target, and a priority ack with
`accepted: false` are all `ErrProtocol`, so callers can dereference without
re-checking the contract.

### Auth flow the bastion (0004) implements
1. `AuthenticateCert` — cert/public key first. A success is always
   `AuthStatusAuthenticated`; a cert response asking for MFA is a protocol
   error, by design.
2. On no acceptable cert: `AuthenticatePassword`. If the response is
   `AuthStatusMFARequired`, loop on `PollMFA` with `resp.MFA.Token`, waiting at
   least `resp.MFA.PollAfter()` between polls, until `AuthStatusAuthenticated`
   (approved) or a deny (refused/expired/spent token — tokens are single-use).
3. The password never reaches a log: `AuthenticatePasswordRequest.String` and
   `GoString` print `[REDACTED]`, the client never logs bodies, and the mock
   compares and drops it. A test asserts `%v`/`%+v`/`%#v` cannot leak it. Keep
   that property when adding fields.

### Session-shaping call
`Authorize` returns the *whole* policy: `RouteType` (`direct` | `nexthop`),
`Target`/`TargetPort`, `Permissions`, `PermittedChannels`, `FilterPolicy`
(`Mode` whitelist/blacklist, `Commands`, `Action` allow_and_log/block_command/
warn_and_continue/kill_session), optional `Hop` (`FinalTarget`, `MaxHops`,
`HopTrail`), and a `DecisionID` for audit correlation. For `nexthop`, `Target`
is the **next bastion** and the user's host travels in `Hop.FinalTarget`; the
server returns the hop trail with the calling bastion appended, which is what
0007 uses for loop detection and the hop limit.

### Logging paths (0010)
Batch → `202` + `accepted` count; priority → `200` and the ack means durable, so
a `kill_session` can be actioned knowing the event was recorded. `RecordID` is
client-assigned and the server de-duplicates on it, so retrying a batch after a
timeout or draining the disk buffer is safe and idempotent.

### Mock server
Fixture-driven and deterministic; format documented in `api/README.md` and
worked through in `cmd/mock-management/fixtures.example.yaml` (which a test
loads, so it can never rot). Notable behaviours:
- Routes are matched **in order, first match wins**, with `*` wildcards for
  login and target; no match is a `401`. There is no implicit catch-all.
- MFA determinism comes from `pending_polls`: exactly that many polls answer
  "still pending" before `decision` (`approve`/`deny`) applies. `ttl_ms` expiry
  is testable via `serverOptions.Now`.
- Host keys are trust-on-first-use: the first report of a key answers
  `known: false` and records it; a fixture-seeded key answers `known: true`. A
  key already trusted is accepted even when the policy for unknown keys is
  `reject`.
- Mock-only (not in the contract): `GET /debug/logs` returns everything ingested,
  `POST /debug/reset` clears logs, MFA challenges, and learned host keys.
  `-log-dir` also mirrors records into `batch.jsonl`/`priority.jsonl`. Phase
  0011 should drive scenario assertions through these.
- `-fixtures` defaults to `fixtures.example.yaml` in the working directory; the
  compose topology will need to mount a fixture file and pass the flag.

### Test approach
`cmd/mock-management/server_test.go` drives the mock **through the real
`mgmt.RESTClient`**, so each test exercises contract, client, and server
together: cert success/deny, password+MFA approve/deny/expiry/spent-token,
authorize direct/nexthop/wildcard/deny, host-key TOFU and the rejecting policy,
batch + priority ingest with de-duplication, bastion-token enforcement, and
fixture validation. `internal/mgmt/rest_test.go` covers the client alone against
`httptest`. Note for future tests: a handler that blocks must **not** wait on
`r.Context().Done()` while the request body is unread — the server only notices
the client disconnect after the body is consumed, so the handler hangs and
`httptest.Server.Close` deadlocks. Use a release channel closed in `t.Cleanup`
(see `newBlockingTestClient`).

### Latency model (asked during review of this PR)
`/v1/authorize` is a **per-connection snapshot, not a per-action question**: it
returns route + channel allow-list + the complete filter policy in one response,
and 0008/0009 enforce that locally. The data path therefore makes **zero** calls
to the management server — a blocked command is a local list match. Setup costs
~3 sequential round trips (auth, authorize, host-key report), multiplied per hop
on a chain, and nothing is amortised across connections (D2's prototype choice).
The contract shipped here has **no cache-lifetime field**; `api/README.md`
§"Caching and the latency budget" records the cost table and the seam (optional
server-set TTL on `AuthorizeResponse`, never a bastion-side TTL, and why the
authentication calls are the wrong thing to cache). Phase **0003** was queued
out of this review to add it, together with the server-driven session-kill
mechanism that makes a cached allow safe to hold.

### User-facing feedback (asked during review of this PR)
The error taxonomy above has a user-visible half that was unspecified anywhere:
what the person at the SSH prompt is told when setup fails. Failing closed is
not the same as failing silently, and a bare disconnect makes a denial
indistinguishable from an outage. PLAN §4.3 now states the disclosure rule — a
deny is deliberately vague ("access denied", never naming login, target, or
policy, because a precise message is an oracle); every other failure is explicit
that it is an outage and carries the session id as a support reference — and
maps the four SSH mechanisms available (auth banner, keyboard-interactive
`instruction`, session-channel stderr, disconnect reason) onto the phases that
own them. Two consequences are design rather than wording: MFA must ride
keyboard-interactive (the only flow with an `instruction` field), and the proxy
must accept the client's session channel *before* the target leg exists or it
has nowhere to write progress. Requirements and tests were folded into 0003,
0004, 0005, 0009, and 0011 rather than made a phase of their own.

### Deviations
- Branch name is `claude/queued-prompt-implementation-vl5dhe` rather than
  PROTOCOL §2's `claude/NNNN-short-description`, because the session was started
  with that branch pre-assigned (same as 0001). Nothing else in §2 changed.
- `api/.gitkeep` was removed now that `api/` has real content.
- The prompt asked to decide how priority log ingest is modelled: it is a
  separate endpoint, not a flag on the batch endpoint. Rationale in
  `api/README.md` ("Logs: two paths, on purpose"). This is within D8's
  "dedicated priority path", so `docs/PLAN.md` needed no change.

### Follow-ups (not done here, not blocking)
- One new prompt was added out of this PR's review:
  `0003-policy-caching-and-session-revocation`. The previously queued 0003–0010
  were renumbered to 0004–0011 (queued only — `implemented/` is untouched) and
  their cross-references rewritten, so the PROTOCOL §6 invariants still hold.
  `docs/PLAN.md` gained §6.4, an amended D2, and a new phase-table row.
- A second review question (what the user sees when setup fails) added PLAN §4.3
  and folded user-feedback requirements + tests into the queued 0003, 0004,
  0005, 0009, and 0011. No new phase, and no code change in this PR.
- `internal/identity` (0004) should own the bastion's identity model and convert
  to/from `mgmt.Identity`; `mgmt.Identity.Claims` is `map[string]string` on the
  wire, so a richer internal claims type must serialise into that shape or the
  contract changes with it.
- The bastion→server credential is a bearer token stub (`Options.Token`, no
  config field yet). Whichever phase wires the real client into the bastion
  should add it to `internal/config` and `config.example.yaml` — the config
  decoder is strict, so both must change together.
