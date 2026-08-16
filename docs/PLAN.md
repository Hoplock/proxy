# SecureCommandProxy — Implementation Plan

> Status: living document. This is the single source of architectural truth.
> Every implementation session MUST read this file and `docs/PROTOCOL.md` before
> starting work. Keep it current: if a prompt changes the architecture, the same
> PR updates this plan.

---

## 1. Product summary

SecureCommandProxy is a **decrypting SSH bastion** (a policy-enforcing SSH
proxy). A user's SSH client connects to the bastion; the bastion terminates the
SSH connection, authenticates the user, opens a **fresh SSH connection** to the
target, and proxies traffic between the two. Because both legs are decrypted
inside the bastion, it can **log everything** and **filter/inspect** commands and
channels.

The bastion is deliberately **thin**. All policy decisions are made by a central
**Management Server** (referred to here as "the API" or "management server"). The
bastion is the Policy Enforcement Point (PEP); the management server is the
Policy Decision Point (PDP).

> Note on terminology: this is an **SSH** proxy, not SSL/TLS. SSH has its own
> transport encryption; there is no "SSL" to terminate. The repo name and branch
> use "SSL" loosely — throughout the code and docs we say "SSH".

### End-to-end flow (v1)

1. User runs SSH toward a name like `host.company.com.<brand>.proxy`. Wildcard
   DNS (`*.<brand>.proxy`, anycast/geo) resolves it to the **nearest bastion**.
2. The bastion accepts the connection and determines the intended **target**
   (see Decision D1).
3. The bastion authenticates the user (Section 4), delegating the decision to the
   management server.
4. The bastion calls the management server's **authorize + route** endpoint. The
   server returns either `401 Unauthorized` or a **route**:
   - `{ "route_type": "direct",  "target": "host.company.com",     "permissions": "readOnlyGroup", ... }`
   - `{ "route_type": "nexthop", "target": "bastionHost.company.com", "permissions": "readOnlyGroup", ... }`
5. For `direct`: the bastion provisions ephemeral target credentials (Section 5),
   opens the target SSH connection, and proxies channels.
6. For `nexthop`: the bastion opens an SSH connection to the next bastion, which
   repeats steps 2–5. This allows a **single firewall punch-through per hop**.
7. All session data is logged and shipped to the management server (Section 7).
8. On session end, ephemeral credentials/users are removed (Section 5).

---

## 2. Key decisions

Each decision has an ID so prompts and learnings can reference it. Decisions
marked **(confirm)** are recommendations pending explicit user confirmation.

- **D1 — Target identity transport (confirmed).** SSH has no SNI/Host header, so
  the target hostname the user typed is not on the wire after DNS resolution.
  The target is therefore **encoded in the SSH username** using a configurable
  delimiter (default `#`): `alice#host.company.com`. The bastion parses and
  strips the target segment **before** authentication, then authorizes
  `user=alice, target=host.company.com`. The `.<brand>.proxy` DNS name is used
  only for geo-routing to the nearest bastion; a thin client-side SSH-config /
  wrapper delivers the clean `ssh host.company.com.<brand>.proxy` UX by
  rewriting it into the encoded form. The delimiter and parsing rules live in
  the bastion bootstrap config.
- **D2 — The bastion originates no policy.** Every authn/authz/route/policy
  decision is *made* by the management server. A decision is fetched **once per
  connection** and enforced locally for that connection's lifetime, so the data
  path (channel opens, commands, stream bytes) makes no calls to the server at
  all — the latency is at session setup, not in the stream (§6.4).
  The bastion may reuse an authorize decision across connections **only** when
  the server explicitly authorises it with a server-set TTL, and only while it
  can still hear revocations (§6.4). It never caches authentication results, and
  it never widens a decision it was given.
- **D3 — Management server is a separate component.** This repo defines the
  **API contract** and ships a **mock/reference management server**
  (`cmd/mock-management`) used for development and CI. The production management
  server is out of scope for this repo.
- **D4 — Auth planes are pluggable interfaces.** `user→bastion` and
  `bastion→target` are separate Go interfaces, each with swappable
  implementations chosen by config, and each segregated into its own package.
  Both are designed around an **identity/claims** model so AD/Okta/OIDC can be
  added later without changing callers.
- **D5 — Generic channel passthrough first, inspection later.** v1 proxies all
  SSH channel types generically. The management server returns the set of
  **permitted channels** per connection; the bastion enforces that allow-list.
  The channel layer is built as a **middleware/inspection pipeline** so filters
  can attach to any channel type later without touching the transport core, and
  without adding latency to un-inspected channels.
- **D6 — Ephemeral just-in-time target users.** The bastion holds a
  **management certificate** preloaded on targets. On session start it logs in
  with the management cert, creates a target OS user matching the authenticated
  username, injects a freshly generated short-lived key/cert into that user's
  `authorized_keys`, connects as that user, and on session end logs back in with
  the management cert to remove the user. Orphan cleanup is mandatory (Section 5).
- **D7 — Host key policy from the server.** Prototype: **trust-on-first-use**,
  but every newly seen target host key is reported to the management server.
  Later: per-target configurable policy fetched from the management server based
  on server criticality.
- **D8 — Logs go to the management server.** Structured logs are **batched** to
  the management server for efficiency. **Blocked commands and other critical
  security events are sent immediately** (flush the in-flight batch or use a
  dedicated priority channel). Local disk is only a **resilience buffer** for
  when the network is unavailable; logs drain to the server when it recovers.
- **D9 — Tech choices.** Go (min **1.25**, target latest stable). SSH plumbing:
  `golang.org/x/crypto/ssh`. Bastion bootstrap config: **YAML**. API + policy +
  log payloads: **JSON over HTTPS (REST)** for the prototype; a streaming/gRPC
  transport may be added later behind the same client interface.
  The floor is set by `golang.org/x/crypto`, which *is* this project's SSH
  implementation and so is the dependency least worth holding back: current
  releases require Go ≥ 1.25.0, and pinning an older Go pins an older SSH
  stack. The floor was 1.24 through phase 0004; it moves when x/crypto moves
  it, and CI tracks the latest stable release rather than the floor.
- **D10 — Proprietary/closed source.** Private repo, all rights reserved. A
  proprietary `LICENSE` and per-file SPDX + copyright headers are added in the
  scaffold phase (Section 8).

---

## 3. Architecture & repository layout

```
securecommandproxy/
├── cmd/
│   ├── bastion/            # the proxy daemon (main)
│   └── mock-management/    # reference/mock management API for dev + CI
├── internal/
│   ├── config/             # YAML bootstrap config loader
│   ├── identity/           # identity + claims model (AD/Okta/OIDC-ready)
│   ├── mgmt/               # management API client + shared contract types
│   ├── auth/
│   │   ├── user/           # user→bastion authenticators (cert, password+MFA)
│   │   └── target/         # bastion→target authenticators (ephemeral, mgmt-cert)
│   ├── routing/            # target parsing (D1) + route resolution + multi-hop
│   ├── proxy/              # core SSH proxy engine, session lifecycle
│   ├── channel/            # channel allow-listing + inspection pipeline
│   ├── filter/             # command filtering (whitelist/blacklist + actions)
│   └── logging/            # session capture, batching, priority flush, buffer
├── api/                    # API contract (OpenAPI/JSON Schema) — source of truth
├── deploy/                 # docker-compose e2e topology + fixtures
├── .github/workflows/      # CI (build, vet, test, lint, e2e)
├── docs/
│   ├── PLAN.md             # this file
│   ├── PROTOCOL.md         # session workflow (read before any work)
│   └── learnings/          # one learnings file per implemented prompt
├── prompts/
│   ├── queued/             # not-yet-implemented prompts (NNNN-name.md)
│   └── implemented/        # completed prompts (never renamed)
├── go.mod
├── LICENSE
├── Makefile
└── README.md
```

### Component responsibilities

- **`cmd/bastion`** — wires config → listeners → auth → proxy → logging. Small.
- **`internal/mgmt`** — the ONLY place that talks to the management server. Every
  other package depends on interfaces here, not on HTTP. Makes the whole system
  testable against the mock and swappable transports later.
- **`internal/identity`** — `Identity` (subject, principals, claims, groups,
  source) and `Claims`. Returned by user authenticators; consumed by routing and
  policy. This is the AD/Okta-ready seam (D4).
- **`internal/auth/user`** — `UserAuthenticator` interface + implementations.
- **`internal/auth/target`** — `TargetAuthenticator` interface + implementations.
- **`internal/proxy`** — accepts the client SSH connection, orchestrates authz +
  route + target dial + channel pumping. Transport-level correctness lives here.
- **`internal/channel`** — the inspection pipeline (D5). Enforces the permitted
  channel allow-list; hosts pluggable per-channel inspectors.
- **`internal/filter`** — command policy engine (D5/filtering); pure logic, fed
  by the channel pipeline.
- **`internal/logging`** — session recorder + shipper (D8).

---

## 4. Authentication design

### 4.1 user → bastion (`internal/auth/user`)

```go
// UserAuthenticator decides whether an incoming SSH client is a known identity.
// Implementations are stateless PEP shims; the real decision is remote.
type UserAuthenticator interface {
    // Name identifies the method for logging/metrics ("cert", "password-mfa", ...).
    Name() string
    // AuthenticateCert is called when the client offers a public key/certificate.
    AuthenticateCert(ctx context.Context, meta ConnMeta, key ssh.PublicKey) (*identity.Identity, error)
    // AuthenticatePassword is called for keyboard-interactive / password flows.
    AuthenticatePassword(ctx context.Context, meta ConnMeta, password string) (*identity.Identity, error)
}
```

Order (D5 answers): **certificate first**. If the client presents no acceptable
certificate, fall back to **password + out-of-band MFA**. Both flows delegate to
the management server via `internal/mgmt` — the bastion holds no credential
database. The initial-auth password is **never logged** (D8/redaction).

### 4.2 bastion → target (`internal/auth/target`)

```go
// TargetAuthenticator produces the credentials the bastion uses to log into a
// target, and guarantees teardown of anything it provisioned.
type TargetAuthenticator interface {
    Name() string
    // Provision prepares just-in-time access for `id` on `target` and returns
    // an ssh.ClientConfig plus a Teardown handle. Teardown MUST be safe to call
    // more than once and MUST run even if the session crashes.
    Provision(ctx context.Context, id *identity.Identity, target Target) (*ProvisionedAccess, error)
}

type ProvisionedAccess struct {
    ClientConfig *ssh.ClientConfig
    Teardown     func(context.Context) error
}
```

The prototype implementation is the **ephemeral-user provisioner** (D6). A simpler
`static-key` implementation is used as a placeholder in the first proxy phase so
end-to-end proxying works before the full provisioner lands.

Both interfaces take/return `identity.Identity` (not booleans) so that AD/Okta
claims flow through unchanged (D4/D8-answers question 8).

### 4.3 What the user is told (disclosure rule)

A policy proxy that fails silently is indistinguishable from a broken network,
and a user who cannot tell "I am not allowed" from "the service is down" files
the wrong ticket — or retries a denial forever. The bastion therefore **always
says something before it closes a connection**, and what it says splits along
one line:

- **Deny** (`401` from any endpoint) → deliberately vague: "access denied". It
  never reveals whether the login, the target, or the policy was the problem,
  and never whether the target exists. Anything more precise turns the bastion
  into an oracle for probing the estate.
- **Everything else** (management server unreachable, `5xx`, contract violation,
  target unreachable, provisioning failure) → explicit and honest: this is not a
  permissions problem, it is an outage, plus the **session id as a support
  reference**. That text is safe to disclose and turns a mystery disconnect into
  a ticket that can be answered from the logs.

The same rule covers policy actions mid-session: a blocked command says it was
blocked, and a session killed by the management server prints the server's
`reason` before teardown (§6.4). Never a bare drop.

SSH gives four places to speak, and each phase owns the ones it touches:

| Moment | Mechanism | Owner |
| --- | --- | --- |
| Before/during auth | `SSH_MSG_USERAUTH_BANNER` | 0004 |
| Waiting on MFA | keyboard-interactive `instruction` + zero-prompt info requests | 0004 |
| After auth, before the target leg is up | session channel **stderr** | 0005 |
| Any hard failure | `SSH_MSG_DISCONNECT` (reason code + description), or channel stderr + non-zero `exit-status` | 0005 |

Two consequences that are design, not wording:

- **MFA rides keyboard-interactive, not plain password auth**, because that is
  the only flow with an `instruction` field in which to explain the wait and
  repeat "still waiting" while polling (§4.1).
- **The proxy must accept the client's session channel before the target leg
  exists**, or there is nothing to write progress to. That ordering belongs to
  the proxy engine (§3, 0005).

Feedback is written to stderr, never stdout, and suppressed for non-interactive
channels (no pty — `scp`, `sftp`, `exec`) beyond what a failure requires, so
tooling that parses the stream is not corrupted.

---

## 5. Ephemeral target provisioning (D6)

Lifecycle per session:

1. **mgmt-cert login** to the target as a privileged provisioning account.
2. **Create user** matching the authenticated username (idempotent; handle
   "already exists" from a previous crashed session).
3. **Generate** a short-lived keypair/cert; write the public key into that user's
   `authorized_keys` (locked-down perms).
4. **Connect** as the ephemeral user; hand the `ssh.ClientConfig` to the proxy.
5. **Teardown** on session end (and on crash via a reaper): mgmt-cert login →
   kill the user's processes → remove the user and its home/keys.

Robustness requirements:

- **Guaranteed teardown**: teardown runs on normal close, error, panic, and
  process signal. Provisioned sessions are tracked so an **orphan reaper** can
  clean up leftovers on startup and periodically.
- **Concurrency**: two sessions for the same username on the same target must not
  clobber each other's users/keys — use per-(user,target) coordination or unique
  ephemeral principals.
- **Failure isolation**: a provisioning failure denies the session cleanly; it
  never leaves a half-created user.

> This is the highest-risk feature. Its prompt (0005) covers cleanup/orphan
> handling and concurrency explicitly, and its learnings file must document the
> exact teardown guarantees for later sessions.

---

## 6. Channels, routing, and filtering

### 6.1 Routing (`internal/routing`)

- **Target parsing (D1)**: split the SSH username on the configured delimiter into
  `login` + `target`. Validate/normalize the target hostname.
- **Route resolution**: call the management server's authorize+route endpoint with
  `(identity, target, conn metadata)`. Handle `direct` and `nexthop`.
- **Multi-hop**: for `nexthop`, dial the next bastion and re-run the flow.
  Enforce a **max hop count** and **loop detection** (carry a hop trail).

### 6.2 Channels (`internal/channel`, D5)

- The authorize+route response includes **permitted channel types**. The channel
  layer **denies any channel not on the allow-list**.
- Inspection pipeline: each channel is wrapped by an ordered list of
  **inspectors**. In v1 the list is empty (pure passthrough) for everything except
  where filtering attaches. Inspectors must be **zero-copy where possible** and add
  no latency when none are registered for a channel type.

### 6.3 Command filtering (`internal/filter`, D5-answers 12–14)

- The management server tells the bastion, per connection, an **ordered rule
  list** — each rule a `match` pattern with **its own action** (`allow_and_log`,
  `block_command`, `warn_and_continue`, `kill_session`) and an optional operator
  message — plus a **mode** (`whitelist` or `blacklist`) that decides commands
  no rule matched. Per-rule actions matter: one policy has to be able to warn on
  `sudo`, block `shutdown`, and kill the session on `rm -rf /`; a single action
  for the whole list would flatten all three to the same severity.
- **First match wins**, so a specific rule placed before a broad one decides the
  outcome. Mode is required, so an unmatched command always has a defined
  answer: `whitelist` blocks it, `blacklist` allows it. A `blacklist` with no
  rules filters nothing; a `whitelist` with no rules blocks everything.
- **`exec`** requests: the full command is available up front — filtering is
  **enforced** reliably.
- **Interactive `shell`/pty**: keystroke streams are inspected **best-effort**
  (audit/alerting), never claimed as hard enforcement. The pipeline is the same;
  only the reliability guarantee differs. This limitation is documented for users.
- A match produces a **distinct audit event** (D8) sent immediately.

---

### 6.4 Policy caching & session revocation (D2)

The authorize+route response is a **per-connection policy snapshot**, not a
per-action question: it carries the route, the channel allow-list, and the whole
filter policy, and the bastion enforces all three locally. Nothing on the data
path talks to the management server.

Setup, however, is not amortised: each connection costs ~3 sequential round
trips (authenticate, authorize, host-key report), paid again per hop on a chain.
Two mechanisms address that, and they only make sense together:

- **Server-authorised caching.** The server may attach a cache hint (an opaque
  key + a TTL) to an authorize decision. Absent hint means do not cache. The
  **server** owns the lifetime — a bastion may clamp it shorter but never
  longer, and may never invent one — so the PDP keeps ownership of its own risk
  appetite and can refuse caching per target. A local clamp is **off by
  default** and, where set, must be **observable** (counted and logged per
  affected decision): it is the one place a bastion's behaviour diverges from
  what the server asked for, and an unannounced divergence across a fleet is
  indistinguishable from a server or network fault. **Authentication is never cached**:
  an MFA approval is a per-session assertion, and certificate validation is
  where revocation is enforced.
- **Server-driven revocation.** The bastion holds a long-lived outbound
  subscription to the management server (bastions are behind firewalls and must
  not need an inbound listener) and receives: kill a named session, kill every
  session for a subject, invalidate cached decisions, or resync. This is what
  bounds the damage of a cached allow, and it is the only way the server can end
  a session that is already in flight.

Fail-closed rule: if the bastion cannot hear revocations (the subscription has
been down beyond a short threshold), it stops serving cached decisions and
re-authorizes every connection. It does **not** kill live sessions — losing the
revocation channel is a reason to distrust the cache, not to drop users
mid-command.

Phase 0003 delivers the contract, the client-side cache, and the subscription;
the session-kill hook it defines is implemented by the proxy in 0005.

## 7. Logging & telemetry (`internal/logging`, D8)

- **What**: session metadata (session id, user identity + source, target, route
  type, auth method, timestamps, channel types, policy decisions) + enough
  stream capture for a security team to **reconstruct the session** (replay-
  friendly, e.g. asciinema/ttyrec-style records for pty sessions).
- **How**: structured, compact records. **Batched** shipment to the management
  server for throughput; **immediate** shipment for blocked/critical events
  (flush current batch or dedicated priority path).
- **Resilience**: when the management server is unreachable, buffer to local disk
  (one area per session) and **drain on recovery**. Local storage is a buffer,
  not the destination.
- **Redaction**: the initial-auth password is never written. Passwords typed
  *during* a session are acceptable to capture (they should already be
  considered compromised and rotated).

---

## 8. Cross-cutting conventions

- **Module path**: `github.com/mauroasilva/securecommandproxy`.
- **Go**: min 1.25 (the `go` directive in `go.mod`); CI pins the toolchain to the
  latest stable minor (`GO_VERSION` in `.github/workflows/ci.yml`). Keep the two
  distinct: the floor rises only when a dependency forces it, while CI moves with
  each Go release. The `build-test` job runs on **both**, with
  `GOTOOLCHAIN: local`, so the floor is enforced rather than merely asserted —
  raising the `go` directive past the matrix fails that leg loudly instead of
  being papered over by an automatic toolchain download. `golangci-lint`
  type-checks with the Go it was built against, so its pin in the `lint` job must
  be bumped alongside `GO_VERSION` or it panics on the newer stdlib.
- **Config**: YAML bootstrap (`internal/config`), documented with an example file.
- **License (D10)**: proprietary `LICENSE` ("All rights reserved / confidential"),
  plus a per-file header:
  `// Copyright (c) 2026 Mauro Silva. All rights reserved.` +
  `// SPDX-License-Identifier: LicenseRef-Proprietary`.
- **Errors/logging**: no secrets in error strings; structured logging internally.
- **Testing**: unit tests per package; table-driven where sensible; the mock
  management server backs integration tests.
- **CI**: `go build ./...`, `go vet ./...`, `go test ./...`, a linter
  (`golangci-lint`), and the e2e job (Section 9). See D9.

---

## 9. Test topology (answer to Q21)

**Yes — the full 5-node topology fits inside one GitHub Actions runner** using
Docker containers on a shared Docker network (via `docker compose` in
`deploy/`), no external infrastructure required for the prototype:

| Node                | Container                              |
| ------------------- | -------------------------------------- |
| Management server   | `cmd/mock-management`                  |
| User (SSH client)   | thin image running the test client     |
| Bastion (direct)    | `cmd/bastion` configured for direct    |
| Bastion (next-hop)  | `cmd/bastion` configured to chain      |
| Target (sshd)       | an `sshd` image with the mgmt cert     |

The GitHub Actions job builds the images, `docker compose up`s the topology, runs
scenario tests (direct route, next-hop route, blocked command, channel denial,
provisioning + teardown, logging), and tears down. Real geo/anycast/scale testing
needs real infrastructure and is **out of scope** for the prototype; the compose
topology validates behavior, not distribution.

---

## 10. Phased delivery

One prompt = one PR = one phase (see `prompts/queued/`). Ordering and scope:

| #    | Phase                                   | Delivers                                                            |
| ---- | --------------------------------------- | ------------------------------------------------------------------ |
| 0001 | Project scaffold & conventions          | module, layout, license+headers, Makefile, CI skeleton, config stub |
| 0002 | Management API contract + mock server   | `api/` contract, `internal/mgmt` client, `cmd/mock-management`      |
| 0003 | Policy caching + session revocation     | cache hint + revocation stream in the contract, `internal/mgmt` cache + subscription, `SessionRegistry` hook |
| 0004 | Identity model + user→bastion auth      | `internal/identity`, `internal/auth/user`, cert-first + password/MFA |
| 0005 | Core proxy engine + direct route        | `internal/proxy`, generic channel passthrough, E2E with static-key target auth; implements `SessionRegistry` |
| 0006 | Ephemeral target provisioning           | `internal/auth/target` ephemeral provisioner + orphan reaper       |
| 0007 | Multi-hop / next-hop routing            | `internal/routing` chaining, loop/hop-limit protection             |
| 0008 | Channel allow-list + inspection pipeline| `internal/channel` enforcement + pluggable inspector framework     |
| 0009 | Command filtering + policy actions      | `internal/filter`, exec-enforced + interactive best-effort         |
| 0010 | Logging & telemetry pipeline            | `internal/logging` batching, priority flush, disk buffer, redaction |
| 0011 | Full E2E topology + CI gate + hardening | `deploy/` 5-node compose, CI e2e job, cleanup                      |

Prompts may add or re-order later phases; any prompt that introduces new queued
prompts MUST preserve the numbering invariants in `docs/PROTOCOL.md`.

---

## 11. Out of scope for the prototype

- Real management server (only the contract + mock live here).
- Real geo/anycast DNS and scale/distribution testing.
- Tamper-evident/append-only log storage (D8 notes the eventual destination).
- AD/Okta/OIDC concrete implementations (interfaces are AD/Okta-ready only).
- Target host-key pinning policy (prototype is TOFU-with-report, D7).
