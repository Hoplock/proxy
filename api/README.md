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
vocabulary it implements (absent means `1`; the current value is `3`, exported
as `control.PolicyVersion`). **The server MUST NOT answer with policy fields
introduced after that version.** A server that respects it can add vocabulary
freely; a server that ignores it is caught at the first response instead of
having its policy quietly thinned.

### The v3.1→v4 revision

Phase 0018 answers a different question from every revision before it. v2 and
v3 said **what** a session may do; v4 says **where that is enforced**, and
bounds how long and on what grounds the session exists at all (PLAN D12 as
amended, D16, §6.5) — see "Policy vocabulary v4" below.

The endpoints gain one member, `POST /v1/capabilities/report`, because
`/v1/authorize` happens *before* the proxy has ever touched the target and a
first-ever connection has nothing to put on `AuthorizeRequest`. Every v4 field
on the authorize response is additive with a documented absent-value default,
and each default is exactly what a v3 server already produced: proxy-side
enforcement only, no deadline, no required capture, no grant context, no
concurrency cap.

`policy_version` moves to `4`.

### The v3→v3.1 revision

Phase 0016 adds one thing and breaks nothing: the `device_field.<name>`
namespace on `ephemeral-account` params, for devices that are **one unit
partitioned into many** — see "Additional device fields" below. It is additive
in the strong sense, because the params object was already open and the proxy's
rule for a parameter it does not implement is to **skip the rung**, not to drop
the field: a proxy built before v3.1 refuses to connect on a route naming a
field it cannot honour, which is the outcome a constraint deserves.

`policy_version` stays `3`. It numbers the vocabulary a proxy can *read*, and
nothing here changes how a response is read — an older proxy parses a v3.1 route
exactly as it always did and declines the rung.

### The v2→v3 revision

Phase 0013 revises the vocabulary again, for the estate the proxy cannot
administer as a POSIX host (PLAN D13, D14) — see "Policy vocabulary v3" below.
The endpoints are again untouched, and every v3 field is additive with a
documented absent-value default **except one**, called out here because it is
the only break:

**`username` becomes required on every provisioning method** —
`ephemeral-user`, `ephemeral-account`, and `static-key`. Until v3 it defaulted
to the identity's `login`, which is a **client-typed string**
(`internal/identity` says in as many words that `Login` must never be the basis
of an authorization decision), and letting it name an OS or device account was
that rule leaking through the back door. A v2 server that omitted it now gets
its route refused as a contract violation, loudly, at the first authorize call.
`brokered-key` is deliberately not in that set: it logs into an account that
already exists and was chosen by an operator, and its v2 behaviour is unchanged.

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
| `POST /v1/capabilities/report` | Report the enforcement rungs a target can take (v4) | `200` | `ReportCapabilities` |
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
- `target_auth`: which target credential method to use (D6a), below — or
  `target_auth_ladder`, the ordered list that supersedes it in v3 (D14). **Both
  present is refused**;
- `algorithm_profile`: the per-route SSH algorithm preset for the proxy→target
  leg (v3), below;
- `filter_policy`: an ordered `rules` list, each rule a `match` pattern with
  **its own** `action` (`allow_and_log`, `block_command`, `warn_and_continue`,
  `kill_session`) and an optional operator `message`, plus a `mode`
  (`whitelist`/`blacklist`) deciding commands no rule matched. **First match
  wins**; per-rule actions let one policy warn on `sudo`, block `shutdown`, and
  kill the session on `rm -rf /` (PLAN §6.3). It also carries `exec_mode` and
  `restricted_exec` (D12), below;
- `enforcement`: **where** the policy above is enforced, a rung on each of two
  axes (v4), below;
- `session_deadline`, `require_session_capture`, `grant_context`,
  `concurrency`: the bounds a session exists under (v4, D16), below;
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
| `target_auth_ladder` | the proxy uses its **locally configured** method (v1/v2) | an ordered ladder; `[]` **denies the session** | 0014 |
| `algorithm_profile` | `default` — nothing beyond the library defaults | a named preset; anything but `default` is a weakening | 0014 |
| `hop.connection` | `dial` (the original next-hop behaviour) | `dial` or `relay` | 0008 |
| `filter_policy.exec_mode` | `filtered` (the v1 rule list) | `filtered` or `restricted` | 0010 |
| `enforcement` | **proxy-side enforcement only** — `execution: proxy-inspected`, `reach: proxy-channel-policy` (v3) | a rung per axis; a rung the proxy cannot provide is an **outage**, never a downgrade | 0019 |
| `enforcement.platform_role` | — (**required** for `platform-authorized`, forbidden otherwise) | the device role the ephemeral account is scoped to | 0019 |
| `enforcement.permitted_destinations` | — (**required** for `account-egress-restricted`, forbidden otherwise) | destinations the session's own processes may open | 0019 |
| `enforcement.attestation` | — (**required** for `platform-attested`, forbidden otherwise) | who asserts the target's own enforcement, and where that is written down | 0019 |
| `session_deadline` | **no deadline** (v3) | an absolute instant the proxy enforces locally | 0025 |
| `require_session_capture` | `false` — capture happens if configured, and its absence stops nothing (v3) | a proxy with no recording path at all refuses the session (**outage**) | 0019 |
| `grant_context` | **no external grant context** (v3) | opaque context copied to every log record; never parsed, never matched, never a decision | 0019 |
| `concurrency` | **uncapped** (v3) | a per-subject and/or per-target ceiling; exceeding it is a **policy denial**, not an outage | 0019 |
| `capabilities` (request) | the proxy **declares nothing**, so only rungs needing no capability may be chosen | the rungs this build can provide | — |
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
| `ephemeral-user` | Creates a short-lived OS user + key on the target and removes it (D6, PLAN §5.1) | `username` (**required**), `key_type`, `lifetime_seconds` |
| `brokered-key` | Uses a per-target credential held for the session and never written to disk (PLAN §5.2) | `username`, `credential_ref` |
| `ephemeral-account` | Creates a short-lived administrator on a device through a platform driver and removes it (D13, PLAN §5.3) | `username`, `platform`, `credential_kind`, `expiry_posture` (**all required**), `lifetime_seconds` |
| `static-key` | The phase 0005 development placeholder; not a production method | `username` (**required**) |

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

## Policy vocabulary v3

Contract v3 (phase 0013) is the vocabulary for routing a session to a device the
proxy cannot administer as a POSIX host: an ordered credential ladder, the
`ephemeral-account` method and the driver parameters it needs, and a per-route
algorithm profile for the legs that connect on nothing modern.

Nothing below is enforced yet — phase 0014 walks the ladder, drives the drivers,
and applies the profile. The one thing that *is* enforced here is the contract
gate: a response the proxy cannot read exactly is refused as a contract
violation (an outage, never a deny).

### The credential ladder (`target_auth_ladder`, D14, phase 0014)

`target_auth` said which single method to use, and an unsatisfiable one was a
clean denial. That rule optimises for never connecting with the wrong credential
at the cost of not connecting at all — and a session that does not happen
produces no recording, no command policy, and no audit trail. For a product
whose first claim is reaching the devices nothing else reaches, denial is
frequently the worse security outcome.

What made a fallback unacceptable was never degradation; it was **the proxy
choosing**. So the field becomes an ordered list the PDP authors:

```json
"target_auth_ladder": [
  {"method": "ephemeral-account",
   "params": {"username": "hoplock", "platform": "fortios",
              "credential_kind": "publickey", "expiry_posture": "target-enforced",
              "lifetime_seconds": "900"}},
  {"method": "brokered-key",
   "params": {"username": "netadmin", "credential_ref": "edge-fleet-2026"}}
]
```

The proxy walks it **top-down and uses the first entry it can satisfy**. An
entry naming a method this build does not implement, or has no local material
for, or whose driver cannot meet its declared terms, is **skipped**. Exhausting
the ladder is an outage-class denial (PLAN §4.3). Nothing is proxy-invented: a
**one-entry ladder** is exactly D6a's original behaviour, and a PDP that will
not accept degradation on a target writes one.

| Shape | Means |
| --- | --- |
| Absent | The proxy uses its **locally configured** method (v1/v2 behaviour) |
| `[]` | **A denial.** The server named no method it will accept — the same absent-versus-empty rule as `permitted_channels: []` |
| Non-empty | Walk it in order |
| Both `target_auth` and `target_auth_ladder` | **A contract violation the proxy refuses**, on the `restricted_exec`-beside-`rules` precedent (D12): two statements of which credential to use, disagreeing, have no defensible resolution |

A v2 server keeps sending a single `target_auth` object, and the proxy reads it
as a one-entry ladder. Both shapes are read through one accessor
(`AuthorizeResponse.Ladder`), so nothing downstream has to know which shape a
given server speaks.

**The rung used is an audit fact, not a user-facing one.** The record and the
operator surface carry `target_auth_method` and `target_auth_rung` (the 0-based
index); the user is told nothing. This is the one place PLAN §4.3's disclosure
rule does not apply, and the reason is that the information is about the estate
rather than about the user's own request: "you got the weaker credential" tells
an attacker which targets are softest and tells an honest user nothing they can
act on. It is written down here so a later reader does not "fix" it.

**Read versus satisfy.** An entry the proxy cannot *read* — unknown method,
malformed `platform`, unknown credential kind or posture, a missing required
parameter — is a contract violation that refuses the **whole response**, not a
rung to skip. Only an entry the proxy cannot *satisfy* is skipped. Keeping the
two apart is what stops a server hiding a constraint in an entry the proxy would
silently drop.

### Ephemeral accounts on devices (`ephemeral-account`, D13, phase 0014)

A FortiGate cannot run `useradd`, has no `authorized_keys` and no home
directory — but it can create an administrator, set its password or public key,
scope it to an access profile, restrict it to a source address, and delete it
again. Those are the same operations `ephemeral-user` performs; the transport
and the vocabulary differ, not the model. The per-platform implementation is a
**driver** (`internal/auth/target/device`), and the route **names the platform**
— the proxy never sniffs a banner and guesses, because guessing wrong means
running configuration commands against the wrong parser.

| Param | Values | Absent means |
| --- | --- | --- |
| `username` | The account name the proxy provisions | **Refused** (contract violation) |
| `platform` | Which driver, e.g. `fortios`. Lowercase letters, digits, single hyphens | **Refused** — never inferred |
| `credential_kind` | `password` or `publickey` | **Refused** |
| `expiry_posture` | `target-enforced`, `proxy-enforced`, `accepted-risk` | **Refused** |
| `lifetime_seconds` | Whole seconds | **Refused** unless the posture is `accepted-risk` |
| `device_field.<name>` | A platform-specific field handed to the driver as data (contract v3.1) | The driver's own default — for `vdom` on a FortiGate, a **global** administrator |

None of them has an absent-value default, and that is the point. `platform` is
never guessed. A `credential_kind` default would hand out the weaker of two
materially different exposures — a password is a reusable secret that lands in
the device's running configuration and often in its own logs, a public key is
not — to a policy that never said so. And "the risk was accepted" is a sentence
somebody writes down, never one a proxy infers from an omission. A posture that
enforces an expiry with no expiry to enforce is a statement with no content, so
`lifetime_seconds` is required wherever the posture claims enforcement.

**The expiry posture exists because OpenSSH's `expiry-time` does not.** On a
POSIX host an ephemeral key dies whether or not the proxy is alive (PLAN §5.1);
most device platforms have no equivalent, so the PDP selects the posture per
target and the posture in force is in the audit record. PLAN §5.1's rule that a
fleet unable to express expiry is refused holds for `target-enforced` and **only**
for it.

**A posture or credential kind the driver cannot satisfy is a skipped ladder
entry, not a downgrade.** The proxy walks on to the next rung; it never
substitutes a password for a key, or proxy-enforced expiry for target-enforced.

Whether a driver for a well-formed `platform` exists is **not** a contract
question. D13 makes customer-written drivers a first-class case, so the set of
platforms is open and the contract cannot enumerate it; a platform the proxy has
no driver for is an outage-class denial at provisioning time, and never the
nearest driver. A proxy advertises the platforms it carries
(`device.Registry.Platforms`), and a server should not name one it has not been
told about.

#### Additional device fields (`device_field.<name>`, contract v3.1, phase 0016)

Some devices are not one target. A FortiGate running virtual domains is **one
unit partitioned into many**, and an administrator on it is either global or
scoped to a single VDOM; a FortiLink-managed FortiSwitch is administered
*through* the FortiGate in front of it. A route has to be able to say which of
them a session is for.

The endpoint cannot say it. `host`/`port` is what DNS resolves, what the host
key is pinned to, and what the audit record names — overloading it (a
`host/vdom` form, say) would make one device look like several hosts that do not
exist, on the one field every other part of the system already reads.

So `ephemeral-account` carries an **open namespace of additional fields** beside
its five parameters: any parameter named `device_field.<name>` is a
platform-specific field handed to the named driver as data.

- The contract **does not enumerate them**. Customer-written drivers are a
  first-class case (D13), so the set of fields is as open as the set of
  platforms — for exactly the reason the contract does not enumerate `platform`
  values either.
- What the contract checks is the **shape**: `<name>` is lowercase letters,
  digits, hyphens and underscores, 64 characters or fewer; the value is
  non-empty and 256 characters or fewer; at most 16 fields ride on one entry.
- A **driver declares** the names it accepts (`device.Capabilities.Fields`). A
  route naming a field the driver does not declare is a **skipped ladder entry**
  (D14): an unknown parameter may be a constraint, and a proxy that cannot
  honour one must not connect. That is also what makes this revision additive —
  a proxy built before v3.1 refuses the rung rather than dropping the field.
- Fields are **policy metadata, never credential material**, and they are
  **audit facts**: the account-mapping record carries them, because on a
  partitioned device the target string alone does not say which partition the
  administrator was created in.

Documented today:

| Field | Platform | Meaning |
| --- | --- | --- |
| `device_field.vdom` | `fortigate` | The virtual domain a VDOM-scoped administrator is created in. Absent, a unit running virtual domains gets a **global** administrator; a unit not running them is unaffected, and naming a VDOM on one is an outage-class denial (PLAN §5.3, phase 0016). |

### Algorithm profile (`algorithm_profile`, phase 0014)

Much of that estate speaks key exchanges, ciphers, host-key algorithms, and MACs
that a modern SSH library does not enable by default, and without a way to say
so those routes simply do not connect. So the profile for the **proxy→target**
leg is named by the server, per route.

| Profile | What it adds |
| --- | --- |
| `default` | Nothing. The absent-value default, and the only profile that is not a weakening |
| `legacy-rsa-sha1` | RSA with SHA-1 signatures (`ssh-rsa`) for host keys and public-key auth |
| `legacy-device` | `legacy-rsa-sha1` plus the SHA-1 key exchanges, CBC ciphers, and SHA-1 MACs that appliance firmware of that era offers |

Two properties make this safe and it needs both. It is **per route, named by the
server** — never a proxy-wide config knob, which would weaken every leg in the
fleet to serve the oldest device on it, and a fleet-wide `sed` is exactly how
that happens. And it is a **named preset**, not an algorithm list, so it cannot
be widened one algorithm at a time by someone who does not know what they are
enabling, and the audit record names something a reviewer understands rather
than a string of identifiers they have to decode.

Anything but `default` is a weakening and **emits its own audit event**
(`algorithm_profile` in the record), on D14's sibling rule for credential
methods: an operator learns that a route runs on SHA-1 from the record, not by
reading policy. An unknown profile is refused rather than coerced — coercing to
`default` would deny every route on the estate this exists for, and coercing to
the widest would weaken a leg nobody asked to weaken.

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

The registration itself is **proxy-to-proxy plumbing and not part of this
contract**: it is an SSH connection the downstream proxy opens to its upstream,
authenticated with the fleet's own keys or CA (`internal/relay`, PLAN §6.1).
The server names the direction and the proxy id; how the two proxies then reach
each other is theirs.

#### What a chained hop sends this API (phase 0008)

Each hop of a chain runs the whole flow for itself — there is no "trusted
upstream" shortcut, because a proxy that accepted one would be a proxy an
attacker only has to compromise once:

- **`POST /v1/auth/cert`** carries the **previous hop's** public key, with the
  user's `login` from the SSH username. A server recognising the key as one of
  its own proxies answers with the **user's** identity, which it establishes
  itself; it never receives an identity assertion from the proxy. (The mock
  models this with its `proxies[]` fixtures.)
- **`POST /v1/authorize`** carries `conn.hop_trail`: the proxy ids the session
  has already travelled through, oldest first, empty on the user's first hop.
  It is what makes the server's view of a chain match the proxies'.

The trail travels between proxies as an SSH connection-level request
(`hop-trail@hoplock.io`) sent before any channel is opened. It carries no
authority: every entry in it can only cause a refusal — a loop, or the hop cap
— so forging one restricts the forger. The authority on a chain leg is the
previous hop's key, above.

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

## Policy vocabulary v4

Contract v4 (phase 0018) answers a question the earlier vocabularies could not
ask: **where** a policy claim is actually enforced. The survey behind it — every
candidate enforcement point, on both axes, with what it guarantees, what it does
not, what the target must already provide, and how it fails — is
`docs/PLAN.md` §6.5. This section is the wire half.

Nothing below is enforced yet. Phase 0019 renders a rung onto an account; phase
0025 closes a session at its deadline.

### Enforcement points (`enforcement`, D12 as amended, phase 0019)

D12 already draws the line between a guardrail and a boundary, and restricted
exec is on the right side of it. But both of its tiers are enforced **in the
proxy, at the `exec` request** — and a route that permits `shell` hands the user
a shell, with no request left for the proxy to parse. Everything the filter
engine promises evaporates the moment a pty is permitted.

On `ephemeral-user` and `ephemeral-account` routes the proxy holds the strongest
lever in the system and has not been pulling it: **it creates the account**. So
the enforcement story is a **ladder**, which rung a route stands on is a policy
decision that belongs to the PDP (D2), and there are **two ladders** — what a
session may *execute* and what it may *reach* are separate questions with
separate mechanisms.

| `execution` | Guarantee | Kind |
| --- | --- | --- |
| `proxy-inspected` | What the proxy sees at the `exec` request is what the proxy decides. Nothing about a session permitted a shell, nothing at all about a connection made around the proxy. **The absent-value default.** | applied, proxy |
| `no-interactive-shell` | The session can obtain no interactive shell or terminal, so every command it runs is one the proxy decided | applied, proxy |
| `account-restricted` | The **account** can execute only the executables `restricted_exec` names, for every login to it — including one that never went through this proxy | applied, target |
| `account-confined` | `account-restricted`, plus the session's processes cannot gain privilege and cannot execute anything the session itself wrote | applied, target |
| `platform-authorized` | The **device's own** command authorizer decides, for the account the proxy created, under the role in `platform_role` | applied, target |
| `platform-attested` | The target enforces its own command authorization on the account already; the proxy configures nothing | **attested** |

| `reach` | Guarantee | Kind |
| --- | --- | --- |
| `proxy-channel-policy` | `permitted_forwards` and `permitted_global_requests` decide, per channel open and global request — **SSH-channel forwarding only**. **The absent-value default.** | applied, proxy |
| `account-egress-restricted` | The session's own processes reach only `permitted_destinations`; a connection anywhere else fails on the target, channel or no channel | applied, target |
| `account-network-isolated` | The session's processes reach nothing off the host at all | applied, target |
| `platform-attested` | The target already constrains what the account can reach; the proxy configures nothing | **attested** |

**`permitted_forwards` does not cover egress, and this is the most expensive
place to be wrong.** It governs what may be tunnelled *through SSH channels*. A
process the session starts on the target opens its own sockets and never touches
a channel, so the proxy cannot see it, let alone deny it. A console that
answered "can this account reach the database?" from `permitted_forwards` would
be answering a different question, and an operator reading it would believe the
answer. The rungs that do cover it are `account-egress-restricted` and
`account-network-isolated` — and, without this proxy applying anything,
`platform-attested`.

**Applied versus attested.** An *applied* rung is one the proxy configures per
session and tears down. An *attested* rung is one the target enforces already —
an IOS privilege level, a Junos login class with `allow-commands`, a per-account
ACL — configured once by the network team, not by this product. The proxy
applies nothing for it and the record says who does. Attested rungs are how the
appliance estate carries a real enforcement claim instead of "none available",
and they are the only kind a `brokered-key` route can carry.

**What an attestation is worth.** It is not verified by anything here, so the
contract does not pretend otherwise: it makes the claim **attributable**.
`attestation.asserted_by` names who says so and `attestation.reference` names
where that is written down, both required, and the audit record says the proxy
verified neither. "Trust us" and an empty string are the same answer.

**The coupling to the credential method is conditional.** An applied rung needs
the proxy to administer the account, which only `ephemeral-user` and
`ephemeral-account` do — `brokered-key` changes nothing on the target by
definition (D6a). Since D14 a route names an *ordered ladder*, so:

| Case | Outcome |
| --- | --- |
| An applied rung, and **some** ladder entry provisions the target | Fine. An entry that cannot carry the route's rung is a **skipped rung** (D14): the proxy walks on |
| An applied rung, and **no** entry in the named ladder provisions the target | **A contract violation the proxy refuses.** Such a policy can only fail at connect time, in front of a user |
| An applied rung and **no ladder at all** (local config) | Not refusable here — the response cannot see the proxy's local method. Resolved at provisioning time, outage-class |
| An **attested** rung on any route, `brokered-key` included | Fine. Nobody here applies it |

The rung is therefore a property of the **route**, not of each ladder entry. One
policy stating two different guarantees would leave the audit record having to
say which, and a session running below the rung its record claims is the failure
this whole vocabulary exists to prevent. Exhausting the ladder is already an
outage-class denial (D14); running the session without the rung is never an
option.

**The rung's claim must agree with the rest of the response**, or the proxy
refuses it:

- `no-interactive-shell` needs `permitted_requests` present and denying both
  `shell` and `pty-req`. Absent `permitted_requests` polices nothing, which
  permits exactly the two requests the rung says cannot happen.
- `account-restricted` and `account-confined` need
  `filter_policy.exec_mode: restricted`. They render the permitted executables
  onto the account, and `restricted_exec` is the only place the contract names
  an executable; a pattern rule list has patterns, not executables.

**An allow-list containing an interpreter is not an allow-list.** `find`, `awk`,
`less`, `vi`, `tar`, `python`, and most editors hand back a shell (GTFOBins). It
is stated here as **a documented rule of the contract, enforced by Control at
authoring time**, and deliberately **not** as a proxy-side refusal: a shipped
deny-list of interpreter names in the proxy would be a blacklist masquerading as
a boundary — exactly what D12 rejects — incomplete on the day it shipped, and
liable to refuse a route over a name collision. So a rung is a claim about the
**mechanism**, bounded by the list it renders; where that list can hand back a
shell, the rung's real guarantee is `no-interactive-shell` at best, and the
policy author owns that.

**The audit record carries the rung that was in force**, not the one requested:
`enforcement_execution`, `enforcement_reach`, `enforcement_verified` (`false` on
an attested rung), and `enforcement_attested_by`. Whether the record says
`account-restricted` or `proxy-inspected` is the whole point of the vocabulary,
so it is never the requested value.

### Capability advertisement (v4)

A server cannot sensibly choose a rung that cannot be provided, and what is
available depends on the **target** far more than on the proxy: whether it runs
systemd, whether cgroup v2 is mounted, whether SELinux is enforcing, whether
netfilter is reachable, whether it is a Linux host at all.

- **Per proxy**: `AuthorizeRequest.capabilities` — the rungs this *build*
  implements, beside `policy_version` on the same pattern. Absent declares
  nothing.
- **Per target**: `POST /v1/capabilities/report` — the rungs this *target* can
  take, discovered by probing it. It takes the shape of `/v1/hostkeys/report`
  (D7) because authorize happens **before** the proxy has ever touched the
  target, so a first-ever connection has nothing to put on the request.
  `report_after_seconds` lets the server own the freshness of its own record.

**Stale and absent both fail safe, and they mean the same thing.** A record with
no `observed_at`, one older than its TTL, and no record at all are treated
identically: they provide **nothing that has to be applied**. What they do not
affect is a rung needing nothing of the target — the two proxy-side defaults,
and an attested rung, which nobody here applies. That is precisely how an
appliance nobody can probe still carries a real enforcement claim.

The reason this is safe rather than merely convenient: **a report is an
observation and grants nothing.** The authority for a rung is the authorize
response, and the proxy re-checks the rung against the live target when it
provisions. So the worst a stale record can cause is a refused session — never a
session running below the rung its own audit record claims.

### Session bounds (D16, phase 0019/0025)

Four fields that bound how long and on what grounds a session exists. They are
not enforcement points; they ride this revision because they are fields on the
same object.

| Field | What it does |
| --- | --- |
| `session_deadline` | An **absolute instant** the **proxy enforces locally**, so it holds when the revocation stream is down — which is exactly when an immortal root session is least acceptable. An instant rather than a duration because a duration re-anchors on every hop of a chained route. Reaching it is neither a denial nor an outage: the close is explained (§4.3). Phase 0025 owns what the user is told and whether a warning precedes it |
| `require_session_capture` | The route runs only if the session is recorded, checked **before the target leg is dialled**. **Buffering to local disk counts** — the 0011 disk buffer is a resilience path, not a degraded mode — so the refusal (outage-class) triggers only when there is no path at all. It is the compensating control that makes D16's unbounded-privilege grant defensible: root can disable a target's auditing and scrub its traces; it cannot touch a session captured in the proxy |
| `grant_context` | Why access was granted: the external `system`, its `reference`, the window it asserted, and `additional_context` (a string **or** an object). **The proxy treats all of it as opaque** — copied to every log record, never parsed, never matched against, never the basis of a proxy-side decision (D2), and never shown to the user. `window_start`/`window_end` are **recorded, not enforced**; `session_deadline` is the bound |
| `concurrency` | `max_sessions_per_subject` and/or `max_sessions_per_target`. Enforced by the proxy against its own session registry, because the live session count is knowable only there. Exceeding a cap is a **policy denial** (vague, §4.3), not an outage. Both optional and independent; absent means uncapped |

`grant_context` is the field a later reader will want to make policy out of.
Do not: D15 says the push receiver, the probe providers, and the shipped
integrations are Control's and Enterprise's, and the decision they feed was
already made upstream before this response was written. The proxy never learns
that any of those systems exist.

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
The v3 vocabulary adds `TargetAuthLadder`, `CredentialKind`, `ExpiryPosture`,
and `AlgorithmProfile`, plus the `Param*` constants naming the parameters the
contract defines. `AuthorizeResponse.Ladder` is the one accessor that reads both
credential shapes, and `AuthorizeResponse.Profile` resolves the profile's
absent-value default; call those rather than reading the fields, so no caller
has to know which vocabulary a given server speaks.

The v4 vocabulary adds `EnforcementPolicy` with `ExecutionRung` and `ReachRung`
(each with `Attested` and `RequiresProvisioning` predicates), `Attestation`,
`GrantContext`, `AdditionalContext`, `ConcurrencyLimits`, `ProxyCapabilities`,
`TargetCapabilities`, and the `CapabilityReportRequest`/`Response` pair.
`AuthorizeResponse.EnforcedExecution` and `EnforcedReach` resolve the two
absent-value defaults, and `TargetAuthMethod.Provisions` is what decides whether
an applied rung is reachable on a route. `TargetCapabilities.Fresh` is where
"stale and absent mean the same thing" lives, and `DefaultCapabilityTTL` is the
window.

`ReportCapabilities` is on **`CapabilityReporter`**, a narrower interface than
`Client`, and deliberately so: the report is made once a target leg is up, and
every other holder of a `Client` in this tree — the router, the user
authenticator, the log shipper — would otherwise have to grow a stub for a call
it never makes. `*RESTClient` and `*CachingClient` both implement it.

`GrantContext` carries **no comparison, matching, or predicate helper**, and a
test asserts it never grows one. Adding "just a `Matches` method" is how the
proxy starts originating policy, which D2 forbids.

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
| `proxies[]` | The fleet's own proxies: `id` plus `key_fingerprints`. A cert-auth call offering one of these keys is a **chain leg** (D11): the mock answers with the requested login's identity plus a `chain_hop_proxy_id` claim naming the hop, modelling a server that authenticates the previous hop and re-establishes the user itself. |
| `users[].mfa` | `required`, `decision` (`approve`/`deny`), `pending_polls` (how many polls stay pending before resolving — this is what makes MFA deterministic), `poll_after_ms`, `ttl_ms`, `prompt`. |
| `routes[]` | Matched in order, first match wins; no match is a `401`. `login`, `target`, and `proxy_id` accept `*` (`proxy_id` may also be omitted). `proxy_id` matches `conn.proxy_id`, which is how one fixture file describes a chain: the same login and target answer `nexthop` at the edge proxy and `direct` at the one behind it. Then `route_type`, `resolved_target` (direct only), `next_hop` + `max_hops` + `hop_connection` + `next_proxy_id` (nexthop only), `target_port`, `permissions`, `permitted_channels`, `permitted_requests`, `permitted_forwards`, `permitted_global_requests`, `target_auth`, `filter_policy`, and `cache`. |
| `routes[].permitted_requests` | `types` (from `pty-req`, `shell`, `exec`, `env`, `x11-req`, `auth-agent-req`) and `subsystems` (by name). **Omit the key** to leave requests unpoliced; write `{}` to deny every one. |
| `routes[].permitted_forwards` | `direct_tcpip` and `forwarded_tcpip`, each a list of `host` + optional `port` or `port_range` (`from`/`to`). Omit the key to leave destinations unpoliced; an empty direction denies it. |
| `routes[].permitted_global_requests` | `types`, e.g. `[tcpip-forward]`. Omit the key to relay everything; `types: []` denies all of them. |
| `routes[].target_auth` | `method` (`ephemeral-user`, `brokered-key`, `ephemeral-account`, `static-key`) plus method-scoped `params`. Omit to leave the proxy on its configured method. Fixture params are test data — `credential_ref` names local material, it never carries a secret. |
| `routes[].target_auth.params` | Method-scoped; `ephemeral-account` also takes the open `device_field.<name>` namespace (contract v3.1), e.g. `device_field.vdom: customer-a`. |
| `routes[].target_auth_ladder` | The v3 ordered ladder: a list of the same `method` + `params` entries. Omit to leave the proxy on its configured method; write `[]` to deny the session. Setting it **beside** `target_auth` fails at startup, exactly as the client would refuse it. |
| `routes[].algorithm_profile` | `default` (the default), `legacy-rsa-sha1`, or `legacy-device`. |
| `routes[].hop_connection` | `dial` (default) or `relay` for a nexthop route. `relay` requires `next_proxy_id`. |
| `routes[].filter_policy` | `mode` plus ordered `rules` (each `match` + `action` + optional `message`), and `exec_mode` (`filtered`, the default, or `restricted`) with `restricted_exec`. Setting `restricted_exec` beside a rule list fails at startup, exactly as the client would refuse it. |
| `routes[].filter_policy.restricted_exec` | `commands[]`: `executable` plus either `form: exact` with `argv`, or `form: positional` with `args[]` (`kind` of `literal`/`prefix`/`oneof`/`any`, `value`/`values`, `optional`). Anything not covered by a spec is denied. |
| `routes[].enforcement` | `execution` and `reach` (the two v4 rungs), plus `platform_role`, `permitted_destinations` (same entry shape as `permitted_forwards`), and `attestation` (`asserted_by`, `reference`, optional RFC 3339 `asserted_at`). Omit the key for proxy-side enforcement only. A rung whose required parameter is missing, whose claim contradicts the route's own `permitted_requests` or `exec_mode`, or which is applied on a ladder where nothing provisions the target, fails at startup — exactly as the client would refuse it. |
| `routes[].session_deadline_seconds` | A **duration** anchored by the server at authorize time; the wire field is an absolute instant. `0` or absent means no deadline. |
| `routes[].require_session_capture` | `true` makes a proxy with no recording path at all refuse the route. |
| `routes[].grant_context` | `system`, `reference`, `window_start`/`window_end` (RFC 3339), and **one** of `additional_context_text` or `additional_context_fields` — the wire field is a string or an object, so setting both fails at startup. All of it is test data the proxy logs and never reads. |
| `routes[].concurrency` | `max_sessions_per_subject` and/or `max_sessions_per_target`. Absent or `0` is uncapped. |
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

The mock also keeps the **last capability report per target** (v4) in memory, so
a test can assert the proxy reported at all. It answers `accepted` and decides
nothing: a capability report is an observation, not a request for a decision.

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
6. If the change touches this contract at all, it touches a **shared surface**:
   `hoplock/control` vendors `api/` read-only (D3). Follow
   `docs/CROSS-REPO-PROTOCOL.md` — upstream merges first (§2), and the PR owes a
   `## Cross-repo impact` section with a ready-to-run sync kickoff (§4).
