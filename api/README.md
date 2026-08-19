# Control API — contract

`control.yaml` is the **source of truth** for every conversation between a
proxy (Policy Enforcement Point) and Hoplock Control (Policy Decision
Point). It is an OpenAPI 3 document; this file is the short human-readable
companion. If the two disagree, the OpenAPI document wins.

- Go types and client: `internal/control` — the only package allowed to talk to Hoplock
  Control (PLAN §3).
- Reference implementation: `cmd/mock-control` (see "Mock server" below).
- Architecture and decisions referenced here: `docs/PLAN.md` (D2, D3, D5, D7,
  D8, D9).

## Ground rules

- **JSON over HTTPS**, one POST per decision (D9). All paths are absolute from
  the server's base URL and versioned with a `/v1` prefix.
- **The proxy originates no policy, but it does not re-ask per action.** Every
  authentication, authorization, route, channel, and filter decision is *made*
  by the server (D2) — and `POST /v1/authorize` returns the **whole policy for
  the connection** in one response: route, channel allow-list, and the complete
  filter policy. The proxy holds that snapshot for the connection's lifetime
  and enforces it locally, so opening a channel, running a command, and pumping
  a stream cost **zero** calls to this API. The round trips are at session
  setup (auth, authorize, host-key report), not on the data path.
- **The snapshot outlives the connection only if the server says so.** An
  authorize decision may carry a `cache` hint (an opaque key plus a TTL the
  *server* sets), and the proxy may then reuse it for later connections — but
  only while it can still hear the revocation stream. No hint means no reuse.
  See "Caching and the latency budget" below.
- **`401` is a decision, not a failure.** It means *deny*. Transport failures,
  timeouts, and `5xx` are different, and a caller must never treat them as
  either a deny or an allow — it fails the session closed. The two are also
  reported to the end user differently, and never collapsed into one message: a
  deny is deliberately vague, an outage says plainly that it is an outage
  (PLAN §4.3). Failing closed is not the same as failing silently.
- **Proxy→server authentication** is a bearer token
  (`Authorization: Bearer <token>`), deliberately a thin seam: a deployment can
  move to mTLS or a signed assertion without changing any payload.
- **Errors** use one envelope: `{"error":{"code","message"}}`. Messages never
  contain credentials.

## Versioning: additive fields, and a proxy that fails closed

Phase 0006 revised the **vocabulary** `/v1/authorize` answers in — see "Policy
vocabulary v2" below — without changing a single endpoint or its semantics, so
the path prefix stays `/v1`. Two rules make that safe in both directions, and
they only work together:

- **Every new field is additive with a documented absent-value default**, and
  every one of those defaults is the behaviour a v1 server already produced. A
  v2 proxy therefore works unchanged against a v1 server: nothing silently
  becomes "deny everything", and nothing silently becomes "allow everything".
  The defaults are listed field by field below and repeated on each schema in
  `control.yaml`.
- **A proxy fails closed on a field it does not understand.** The authorize
  response is decoded *strictly*: an unrecognised field is a contract violation
  (`ErrProtocol`, an outage-class failure — never a deny), not something to
  drop. Every field in that response is policy, so an unknown one may be a
  restriction, and a dropped restriction is a widened session.

The second rule would make any server upgrade a fleet-wide outage, so the proxy
declares what it can read: `AuthorizeRequest.policy_version` carries the highest
vocabulary it implements (absent means `1`; the current value is `2`, exported
as `control.PolicyVersion`). **The server MUST NOT answer with policy fields
introduced after that version.** A server that respects it can add vocabulary
freely; a server that ignores it is caught at the first response instead of
having its policy quietly thinned.

### The v1→v2 rename

One breaking change rides along, deliberately batched into the release that was
breaking anyway (PLAN §11): `ConnMeta.bastion_id` is now `proxy_id`, and
`GET /v1/bastions/{bastion_id}/events` is now
`GET /v1/proxies/{proxy_id}/events`. Nothing else on the wire moved.

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
| `GET /v1/proxies/{proxy_id}/events` | Subscribe to the revocation stream (NDJSON) | `200` | `StreamEvents` |

Every endpoint can also answer `400` (malformed request), `401` (deny), and
`500` (server failure).

### Authentication (certificate first, then password + MFA)

The proxy tries the certificate flow first and falls back to password +
out-of-band MFA (PLAN §4.1). Both flows return an **identity with claims**, not
a boolean, so AD/Okta/OIDC can be added later without changing callers (D4).

MFA is entirely the server's concern. `POST /v1/auth/password` returns either
`status: authenticated` (no second factor needed) or `status: mfa_required` with
an `mfa` challenge. The proxy then polls `POST /v1/auth/mfa/poll` with the
challenge token, no more often than `poll_after_ms`, until it gets
`authenticated` (approved) or `401` (denied, expired, or unknown token). The
proxy never contacts the MFA provider.

The submitted password is never logged, echoed in an error, or stored — on
either side (PLAN §7). `control.AuthenticatePasswordRequest` redacts it in its
`String`/`GoString` methods so an accidental `%v` cannot leak it.

### Authorize + route

One call shapes the whole session. The response carries:

- `route_type`: `direct` (target is the end host) or `nexthop` (target is the
  next proxy, which repeats the flow — PLAN §6.1);
- `target` / `target_port`: where to connect, per `route_type`;
- `permissions`: opaque permission-set name, carried into logs;
- `permitted_channels`: the SSH channel allow-list; **an empty list denies every
  channel** (D5);
- `permitted_requests`, `permitted_forwards`, `permitted_global_requests`: the
  other two policy axes (D5a) — see "Policy vocabulary v2" below;
- `target_auth`: which target credential method to use (D6a), below;
- `filter_policy`: an ordered `rules` list, each rule a `match` pattern with
  **its own** `action` (`allow_and_log`, `block_command`, `warn_and_continue`,
  `kill_session`) and an optional operator `message`, plus a `mode`
  (`whitelist`/`blacklist`) deciding commands no rule matched. **First match
  wins**; per-rule actions let one policy warn on `sudo`, block `shutdown`, and
  kill the session on `rm -rf /` (PLAN §6.3). It also carries `exec_mode` and
  `restricted_exec` (D12), below;
- `hop` (next-hop routes only): `final_target`, `max_hops`, the `hop_trail`
  to forward — which is how loops and runaway chains are caught — plus the
  `connection` direction and `next_proxy_id` (D11), below.

## Policy vocabulary v2

A flat list of permitted channel **types** cannot express what this product
sells, because SSH puts very different operations inside one channel type
(PLAN D5a). `permitted_channels` is therefore one of three axes, and the other
two arrived in phase 0006 together with a server-chosen target credential
method, a hop connection direction, and an exec enforcement mode.

Nothing below is enforced yet; each field names the phase that consumes it.

### Absent-value defaults, in one table

| Field | Absent means | Empty/present means | Consumed by |
| --- | --- | --- | --- |
| `permitted_requests` | in-channel requests are **not policed** (v1) | an allow-list; `{}` denies every request | 0009 |
| `permitted_forwards` | destinations are **not policed** (v1) | an allow-list per direction; an empty direction denies it | 0009 |
| `permitted_global_requests` | global requests are **relayed unpoliced** (v1) | an allow-list; `{}` denies all of them | 0009 |
| `target_auth` | the proxy uses its **locally configured** method (v1) | the server's choice for this route | 0007 |
| `hop.connection` | `dial` (the original next-hop behaviour) | `dial` or `relay` | 0008 |
| `filter_policy.exec_mode` | `filtered` (the v1 rule list) | `filtered` or `restricted` | 0010 |
| `policy_version` (request) | `1` | the vocabulary the proxy implements | — |

Absence and emptiness are **not** the same thing, and the difference is the
whole point: a server that never heard of `permitted_requests` must not thereby
deny every shell, while a server that sends `permitted_requests: {}` has
decided to permit nothing — exactly as `permitted_channels: []` denies every
channel. So a truncated or half-understood object always fails toward deny, and
only a wholly absent one reads as "this server does not speak this axis".

### In-channel requests (`permitted_requests`, D5a, phase 0009)

A `session` channel is opened before anyone knows what it is for; the request
that follows is what makes it an interactive login, a one-shot command, or a
file transfer. This axis is what expresses "may log in, may not copy files off
the box" and "CI may run commands but never gets a PTY".

- `types`: `pty-req`, `shell`, `exec`, `env`, `x11-req`, `auth-agent-req`.
  `auth-agent-req` covers OpenSSH's `auth-agent-req@openssh.com` — they are the
  same request and a policy naming one means both.
- `subsystems`: subsystem names, matched exactly. `subsystem` is deliberately
  **not** a member of `types`: naming subsystems individually is what makes
  `sftp` deniable while `shell` stays. An absent or empty `subsystems` denies
  every subsystem without touching `types`.

Requests that decide nothing about what a channel *is* carry no policy and are
relayed regardless: `window-change`, `signal`, `exit-status`, `exit-signal`,
`break`, `eow@openssh.com`, `xon-xoff`. Denying a terminal resize is a broken
session, not an enforced one.

### Forwarding destinations (`permitted_forwards`, D5a, phase 0009)

A `direct-tcpip` open carries the host and port it wants in its payload, so the
**destination** is what policy is actually about; allowing or denying the
channel type wholesale is the difference between a firewall and a toggle.

- `direct_tcpip`: destinations the **client** may open a forward to.
- `forwarded_tcpip`: destinations the **target** may open a forward back for.
  It is the same channel type in the other direction and gets its own list: a
  route that may tunnel out to the database must not thereby accept arbitrary
  channels pushed the other way.

Each entry is a `host` plus an optional port constraint — `port` (exact) or
`port_range` (`from`/`to`, inclusive); setting both is a contract violation, and
setting neither permits any port on a matching host, which is an entry the
server wrote deliberately. `host` is exact, a `*.`-prefixed wildcard, a bare
`*`, or a CIDR. **A CIDR never matches a hostname and a hostname never matches
an IP literal**: the proxy does not resolve names to decide policy, because a
DNS answer is not a decision the PDP made.

The two axes are conjunctive. A channel type absent from `permitted_channels`
stays denied however permissive this object is.

### Global requests (`permitted_global_requests`, D5a, phase 0009)

Remote forwarding is a **connection-level** request (`tcpip-forward`), not a
channel open, so a channel-type allow-list never sees it — and denying the
resulting `forwarded-tcpip` channel is not equivalent, because the listener is
created on the target either way and only the connections through it fail. A
denied global request is answered with a `false` reply rather than relayed.
`internal/proxy`'s `serveGlobalRequests` relays everything today; phase 0009 is
where it starts consulting this list.

Transport hygiene requests are outside the policy and always relayed:
`keepalive@openssh.com`, `no-more-sessions@openssh.com`,
`hostkeys-00@openssh.com`, `hostkeys-prove-00@openssh.com`.

### Target credentials (`target_auth`, D6a, phase 0007)

Which method the proxy uses to log into the target is the **server's** choice,
per route — one proxy routinely fronts a Linux estate that accepts just-in-time
provisioning and an appliance estate that can never create a user, and
`auth.target.method` in `config.yaml` cannot express that. With this object that
config key becomes **local material only** (which key, which provisioning
account), never the selection.

| `method` | What it does | Documented `params` |
| --- | --- | --- |
| `ephemeral-user` | Creates a short-lived OS user + key on the target and removes it (D6, PLAN §5.1) | `username`, `key_type`, `lifetime_seconds` |
| `brokered-key` | Uses a per-target credential held for the session and never written to disk (PLAN §5.2) | `username`, `credential_ref` |
| `static-key` | The phase 0005 development placeholder; not a production method | `username` |

`params` is an open string map **on purpose**: a future Hoplock Control that
mints per-session target credentials arrives as another `method` plus its own
parameters, not as another breaking change. Parameter names are scoped to their
method, and a proxy that implements the named method must refuse a parameter it
does not know — an unknown parameter may be a constraint. `credential_ref` is an
opaque handle naming material the proxy already holds; **no credential material
travels on this API**, and no parameter value is ever logged or written to disk.

A method the proxy does not implement, or has no local material for, is an
**outage-class denial** (PLAN §4.3): the session fails and says it is an outage.
It is never a fallback to another method, which would mean connecting with
credentials the server did not choose.

### Hop connection direction (`hop.connection`, D11, phase 0008)

- `dial` — this proxy opens a connection to the next one. Simple, and it needs
  an inbound firewall rule at the next hop.
- `relay` — the next proxy has already registered an **outbound** relay
  connection with this one, which opens a channel over it instead of dialling.
  The protected zone needs no inbound rule at all. `next_proxy_id` names the
  registration to use and is **required** in this mode.

A `relay` hop with no live registration is an **outage**, never a silent
downgrade to `dial`: dialling would punch through exactly the boundary the mode
exists to preserve, at the moment an operator is least able to see it.

### Exec tiers (`filter_policy.exec_mode`, D12, phase 0010)

"Seen reliably" is not "cannot be evaded", and the two must not blur, so the
mode says which of two tiers decides an `exec` request:

- `filtered` — the ordered `rules` list against the whole command string. A
  **guardrail**: every command is seen before it runs, and `sh -c`, any
  interpreter, an editor shell escape, and any encoding still get past a
  pattern.
- `restricted` — `restricted_exec` decides. A **boundary**: the command is
  parsed, only named executables with approved argument shapes run, anything
  unnamed is denied, and no shell is interposed to re-expand what was approved.

**They are alternatives, not layers.** A policy setting both `restricted_exec`
and a non-empty `rules` list is a contract violation the client rejects
outright: silently resolving it would mean a guardrail and a boundary
disagreeing about the same command with no defensible answer for which won.
Under `restricted`, `mode` keeps its meaning only for the best-effort
interactive tier — with an empty rule list, `whitelist` blocks every command
typed into a shell and `blacklist` leaves them to audit alone.

`restricted_exec.commands` is a default-deny allow-list; an empty list denies
every `exec`, which is a coherent policy rather than an accident. Each entry is:

- `executable` — matched against `argv[0]` **exactly, as written**. No `PATH`
  search, no symlink resolution, no basename comparison: every one of those
  would silently accept a name the server did not write.
- `form: exact` with `argv` — the complete argument vector after the
  executable, compared element by element. A different length does not match.
- `form: positional` with `args` — one spec per argument position, in order.
  **Arguments not covered by a spec are denied**: there is no trailing
  allowance and no wildcard tail, so a vector longer than `args` never matches.
  Trailing positions that may be absent are marked `optional`, and once a spec
  is optional every spec after it must be too.

An `args` spec has a `kind`: `literal` (equals `value`), `prefix` (starts with
`value`, which must be non-empty), `oneof` (equals one of `values`), or `any`
(unconstrained). `any` is **named** rather than smuggled in as an empty prefix
so it stays visible in the policy and in the audit record — it is the one shape
here that is not a boundary, and a reviewer should be able to find every use of
it by searching for the word.

Enforcement details phase 0010 owes this contract: the command string is parsed
with POSIX shell word splitting and quote removal, and a command that cannot be
one argument vector — anything containing `;`, `|`, `&`, a backquote, `$(`,
`${`, `<`, `>`, a newline, or an unterminated quote — is denied before matching
begins, because that is shell syntax and no argv means it.

### Host keys

The proxy reports every target host key it sees before completing the target
handshake. The prototype's server trusts on first use and records the key, and
answers `known: false` the first time (D7). The response always carries an
explicit `decision`, so a stricter per-target policy later needs no change on
the proxy.

### Logs: two paths, on purpose

`/v1/logs/batch` is the throughput path; `/v1/logs/priority` is a **separate
endpoint** for blocked commands and other critical events (D8). Separate rather
than a flag on the batch endpoint so a critical event is never queued behind a
large batch, can carry its own timeout and connection, and is trivially
prioritised in the server and in any middlebox. The batch endpoint answers `202`
(accepted for storage); the priority endpoint answers `200` and its ack means
the record is **durable**, so the proxy can act on the event knowing it was
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
the proxy enforces both against that connection-scoped snapshot. A blocked
command costs a local match. The one deliberate exception is D8's priority log
path — a critical security event is shipped synchronously so the proxy knows
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
  revocation bites. `control.CachingClient` passes every other call straight
  through.
- **The server owns the lifetime.** By default the proxy honours
  `ttl_seconds` exactly. An operator may set a local ceiling
  (`CacheOptions.MaxTTL`), which clamps **downward only** — never longer, and
  the proxy never invents a hint. That keeps the PDP in charge of its own risk
  appetite: omit `cache` for a sensitive target and every connection is
  re-decided.

  A clamp is off unless configured, and never silent when it is: every decision
  whose lifetime it shortens is counted in `CacheStats.Clamped` and logged with
  the key and both lifetimes. A proxy caching for less time than its peers is
  otherwise indistinguishable from a server or network problem, and that is the
  real cost of setting one.
- **The key is opaque and chooses the sharing scope.** The proxy never
  constructs or parses one; it only echoes it back in a `cache_invalidate`
  event. Two requests answered with the same key are one cached decision,
  invalidated together — so a key may be per subject+target, per subject, per
  permission set. A key **must never be shared across identities**: it would let
  one user be served another's policy. (`CachingClient` also refuses to serve an
  entry to a different subject, but that is a backstop, not the contract.)

### Revoking (`GET /v1/proxies/{proxy_id}/events`)

A long-lived NDJSON response, one `RevocationEvent` per line. It is **outbound
from the proxy** because proxies sit behind firewalls and must not need an
inbound listener, which makes this the server's only route to a running proxy:
the kill switch for a session already in flight, and the thing that bounds the
damage of a cached allow. A server that issues cache hints must serve it.

| `type` | Effect |
| --- | --- |
| `session_kill` | End the named `session_ids`, or every session for a `subject`, or `all`. The `reason` is **shown to the user** before the connection closes and copied into the audit log (PLAN §4.3) — a revoked session must not look like a crash — so it must be safe to disclose. |
| `cache_invalidate` | Drop the decisions cached under `keys`, or for a `subject`, or `all`. Running sessions are untouched: they already hold their snapshot. |
| `heartbeat` | Liveness only. A silent stream is indistinguishable from a healthy idle one, so a proxy that stops hearing these reconnects (default timeout 20s). |
| `resync` | "You missed events that cannot be replayed": the proxy drops its entire cache and re-authorizes from scratch. |

**Gap recovery.** On reconnect the proxy sends the last `event_id` it
processed as `?last_event_id=`. The **server** decides what happens: replay
everything after that id before resuming live delivery, or — when the id is too
old, unknown, or no history is kept — emit `resync` as the first line and
nothing older. No `last_event_id` means a fresh subscription starting from now.

**Fail-closed rule.** While the proxy has not heard the stream for longer than
`CacheOptions.StaleAfter` (default 30s) it serves **nothing** from cache and
stores nothing new: every connection is re-authorized. It does **not** kill live
sessions — losing the ability to hear about a revocation is a reason to distrust
the cache, not to drop users mid-command. Both halves are deliberate.

The window in which a withdrawn authorization can still be honoured is therefore
the entry's remaining TTL, and only while the stream is also down — which is why
`ttl_seconds` belongs in seconds to low minutes.

## Go types

`internal/control` has one struct per payload; the JSON tags are the contract.
Requests/responses: `AuthenticateCertRequest`, `AuthenticatePasswordRequest`,
`MFAPollRequest`, `AuthenticateResponse`, `AuthorizeRequest`,
`AuthorizeResponse`, `HostKeyReportRequest`, `HostKeyReportResponse`,
`LogBatchRequest`, `LogBatchResponse`, `LogPriorityRequest`,
`LogPriorityResponse`. Shared types: `ConnMeta`, `Identity`,
`PublicKeyMaterial`, `MFAChallenge`, `FilterPolicy`, `FilterRule`, `HopMetadata`,
`LogRecord`, `CacheHint`, `RevocationEvent`, `SessionKillEvent`,
`CacheInvalidateEvent`. The v2 policy vocabulary adds `RequestPolicy`,
`ForwardPolicy`, `ForwardDestination`, `PortRange`, `GlobalRequestPolicy`,
`TargetAuth`, `RestrictedExecPolicy`, `RestrictedCommand`, and `ArgumentSpec`.

Every payload has a `Clone` method, and `AuthorizeResponse.Clone` is the single
deep copy the cache and `internal/routing` both use: a decision is handed to many
sessions, and none of them may share backing memory with another. A field added
to any of these types needs a line in `clone.go` and a case in the mutation
test — that is the one omission nothing else catches.

`AuthorizeResponse.Validate` is the contract's fail-closed gate, exported so the
mock server checks its fixtures against the same rules the client enforces.

Caching and revocation live in the same package: `CachingClient` (a `Client`
decorator, `Authorize` only), `RevocationStream` (the subscription loop), and
`SessionRegistry` — the interface the proxy implements in phase 0005 to actually
tear a session down, with `NopSessionRegistry` standing in until then.
Enum values have named constants (`RouteTypeDirect`, `FilterActionKillSession`,
`SeverityCritical`, `TargetAuthBrokeredKey`, `ExecModeRestricted`,
`HopConnectionRelay`, …); tests assert that they match the enums in
`control.yaml` **and** that this file documents every path and every field name
on the wire.

Errors are classified with sentinels — `ErrUnauthorized` (the deny decision, via
`control.IsUnauthorized`), `ErrBadRequest`, `ErrServer`, `ErrTransport`,
`ErrProtocol` — all wrapped in an `*APIError` that names the failing operation.

## Mock server

`cmd/mock-control` implements this contract from a static fixture file, which
makes policy deterministic and scriptable for tests and for the e2e topology.

```
go run ./cmd/mock-control -listen 127.0.0.1:8080 \
    -fixtures cmd/mock-control/fixtures.example.yaml [-log-dir /tmp/mocklogs]
```

`cmd/mock-control/fixtures.example.yaml` is the worked example and is
exercised by the tests, so it always parses. Unknown keys are rejected at
startup, and every problem in a file is reported at once.

### Fixture format

| Key | Meaning |
| --- | --- |
| `proxy_token` | Bearer token required on every `/v1` request. Empty disables proxy auth. |
| `users[]` | `login`, `identity` (`subject`, `display_name`, `source`, `principals`, `groups`, `claims`), `key_fingerprints` (accepted for cert auth), `password`, and `mfa`. |
| `users[].mfa` | `required`, `decision` (`approve`/`deny`), `pending_polls` (how many polls stay pending before resolving — this is what makes MFA deterministic), `poll_after_ms`, `ttl_ms`, `prompt`. |
| `routes[]` | Matched in order, first match wins; no match is a `401`. `login` and `target` accept `*`. Then `route_type`, `resolved_target` (direct only), `next_hop` + `max_hops` + `hop_connection` + `next_proxy_id` (nexthop only), `target_port`, `permissions`, `permitted_channels`, `permitted_requests`, `permitted_forwards`, `permitted_global_requests`, `target_auth`, `filter_policy`, and `cache`. |
| `routes[].permitted_requests` | `types` (from `pty-req`, `shell`, `exec`, `env`, `x11-req`, `auth-agent-req`) and `subsystems` (by name). **Omit the key** to leave requests unpoliced; write `{}` to deny every one. |
| `routes[].permitted_forwards` | `direct_tcpip` and `forwarded_tcpip`, each a list of `host` + optional `port` or `port_range` (`from`/`to`). Omit the key to leave destinations unpoliced; an empty direction denies it. |
| `routes[].permitted_global_requests` | `types`, e.g. `[tcpip-forward]`. Omit the key to relay everything; `types: []` denies all of them. |
| `routes[].target_auth` | `method` (`ephemeral-user`, `brokered-key`, `static-key`) plus method-scoped `params`. Omit to leave the proxy on its configured method. Fixture params are test data — `credential_ref` names local material, it never carries a secret. |
| `routes[].hop_connection` | `dial` (default) or `relay` for a nexthop route. `relay` requires `next_proxy_id`. |
| `routes[].filter_policy` | `mode` plus ordered `rules` (each `match` + `action` + optional `message`), and `exec_mode` (`filtered`, the default, or `restricted`) with `restricted_exec`. Setting `restricted_exec` beside a rule list fails at startup, exactly as the client would refuse it. |
| `routes[].filter_policy.restricted_exec` | `commands[]`: `executable` plus either `form: exact` with `argv`, or `form: positional` with `args[]` (`kind` of `literal`/`prefix`/`oneof`/`any`, `value`/`values`, `optional`). Anything not covered by a spec is denied. |
| `routes[].cache` | `ttl_seconds` (0 or absent: not cacheable) and an optional `key`. An unset key derives one per (subject, target); set it explicitly to model a server that shares one decision across targets. |
| `host_keys` | `decision` (`accept`/`reject`) applied to keys not seen before, and `known[]` (`target` + `fingerprint`) to pre-seed trusted keys. |
| `events` | `heartbeat_ms` (interval between heartbeats; negative disables them, to exercise a proxy's missed-heartbeat detection) and `replay_buffer` (events retained for replay; resuming from before them answers `resync`). |

Defaults: `identity.subject` falls back to the login and `identity.source` to
`fixture`; a route defaults to `login: "*"`, `target: "*"`, `route_type:
direct`, an `allow_and_log` blacklist, and **no** cache hint;
`host_keys.decision` defaults to `accept` (TOFU); `events.heartbeat_ms` to
`5000` and `events.replay_buffer` to `128`. Every phase 0006 key defaults to
**absent**, which is why fixture files written before it still parse and still
mean what they meant. Fixtures are test data — never put a real secret in one.

Route fixtures are validated at startup with the **client's own**
`AuthorizeResponse.Validate`, not a second copy of the rules, so the mock cannot
serve a policy a real proxy would refuse. A route that needs the v2 vocabulary
is answered with a `500` when the proxy declares `policy_version: 1`, rather
than with policy that proxy would reject three lines later.

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

1. Edit `control.yaml` first.
2. Update the Go types in `internal/control` and the mock server to match.
3. Run `go test ./...` — `internal/control` cross-checks the client's paths and
   enums against `control.yaml` and this file, and `cmd/mock-control` is driven
   end-to-end through the real client.
4. If the change adds a field to `AuthorizeResponse` or anything it contains:
   give it a documented absent-value default, add it to `clone.go` and to the
   mutation test, and bump `control.PolicyVersion`. A proxy fails closed on a
   field it does not know, so the version is what lets an older one keep
   working.
5. If the change alters the architecture, update `docs/PLAN.md` in the same PR
   (PROTOCOL §3).
