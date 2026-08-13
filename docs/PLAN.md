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

- **D1 — Target identity transport (confirm).** SSH has no SNI/Host header, so
  the target hostname the user typed is not on the wire after DNS resolution.
  The target is therefore **encoded in the SSH username** using a configurable
  delimiter (default `#`): `alice#host.company.com`. The bastion parses and
  strips the target segment **before** authentication, then authorizes
  `user=alice, target=host.company.com`. The `.<brand>.proxy` DNS name is used
  only for geo-routing to the nearest bastion; a thin client-side SSH-config /
  wrapper delivers the clean `ssh host.company.com.<brand>.proxy` UX by
  rewriting it into the encoded form. The delimiter and parsing rules live in
  the bastion bootstrap config.
- **D2 — The bastion is stateless about policy.** Every authn/authz/route/policy
  decision comes from the management server per-connection. The bastion caches
  nothing security-relevant beyond the lifetime of a connection (later versions
  may add short TTL caches; not in the prototype).
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
- **D9 — Tech choices.** Go (min **1.24**, target latest stable). SSH plumbing:
  `golang.org/x/crypto/ssh`. Bastion bootstrap config: **YAML**. API + policy +
  log payloads: **JSON over HTTPS (REST)** for the prototype; a streaming/gRPC
  transport may be added later behind the same client interface.
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

- The management server tells the bastion, per connection, the **mode**
  (`whitelist` or `blacklist`), the **list**, and the **action on match**:
  `allow_and_log`, `block_command`, `warn_and_continue`, or `kill_session`.
- **`exec`** requests: the full command is available up front — filtering is
  **enforced** reliably.
- **Interactive `shell`/pty**: keystroke streams are inspected **best-effort**
  (audit/alerting), never claimed as hard enforcement. The pipeline is the same;
  only the reliability guarantee differs. This limitation is documented for users.
- A match produces a **distinct audit event** (D8) sent immediately.

---

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
- **Go**: min 1.24; CI pins the toolchain.
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
| 0003 | Identity model + user→bastion auth      | `internal/identity`, `internal/auth/user`, cert-first + password/MFA |
| 0004 | Core proxy engine + direct route        | `internal/proxy`, generic channel passthrough, E2E with static-key target auth |
| 0005 | Ephemeral target provisioning           | `internal/auth/target` ephemeral provisioner + orphan reaper       |
| 0006 | Multi-hop / next-hop routing            | `internal/routing` chaining, loop/hop-limit protection             |
| 0007 | Channel allow-list + inspection pipeline| `internal/channel` enforcement + pluggable inspector framework     |
| 0008 | Command filtering + policy actions      | `internal/filter`, exec-enforced + interactive best-effort         |
| 0009 | Logging & telemetry pipeline            | `internal/logging` batching, priority flush, disk buffer, redaction |
| 0010 | Full E2E topology + CI gate + hardening | `deploy/` 5-node compose, CI e2e job, cleanup                      |

Prompts may add or re-order later phases; any prompt that introduces new queued
prompts MUST preserve the numbering invariants in `docs/PROTOCOL.md`.

---

## 11. Out of scope for the prototype

- Real management server (only the contract + mock live here).
- Real geo/anycast DNS and scale/distribution testing.
- Tamper-evident/append-only log storage (D8 notes the eventual destination).
- AD/Okta/OIDC concrete implementations (interfaces are AD/Okta-ready only).
- Target host-key pinning policy (prototype is TOFU-with-report, D7).
