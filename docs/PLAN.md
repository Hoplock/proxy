# Hoplock Proxy — Implementation Plan

> Status: living document. This is the single source of architectural truth.
> Every implementation session MUST read this file and `docs/PROTOCOL.md` before
> starting work. Keep it current: if a prompt changes the architecture, the same
> PR updates this plan.

---

## 1. Product summary

Hoplock Proxy is a **decrypting, policy-enforcing SSH proxy** — the data plane
of Hoplock. A user's SSH client connects to the proxy; the proxy terminates the
SSH connection, authenticates the user, opens a **fresh SSH connection** to the
target, and proxies traffic between the two. Because both legs are decrypted
inside the proxy, it can **log everything** and **filter/inspect** commands and
channels.

The proxy is deliberately **thin**. All policy decisions are made by a central
**Hoplock Control** (referred to here as "the API" or "Hoplock Control"). The
proxy is the Policy Enforcement Point (PEP); Hoplock Control is the
Policy Decision Point (PDP).

> Note on terminology: this is an **SSH** proxy, not SSL/TLS. SSH has its own
> transport encryption; there is no "SSL" to terminate. Early branches and
> issues in this repository's history use "SSL" loosely — throughout the code
> and docs we say "SSH".

### End-to-end flow (v1)

1. User runs SSH toward a name like `host.company.com.<brand>.proxy`. Wildcard
   DNS (`*.<brand>.proxy`, anycast/geo) resolves it to the **nearest proxy**.
2. The proxy accepts the connection and determines the intended **target**
   (see Decision D1).
3. The proxy authenticates the user (Section 4), delegating the decision to Hoplock
   Control.
4. The proxy calls Hoplock Control's **authorize + route** endpoint. The
   server returns either `401 Unauthorized` or a **route**:
   - `{ "route_type": "direct",  "target": "host.company.com",     "permissions": "readOnlyGroup", ... }`
   - `{ "route_type": "nexthop", "target": "proxyHost.company.com", "permissions": "readOnlyGroup", ... }`
5. For `direct`: the proxy provisions ephemeral target credentials (Section 5),
   opens the target SSH connection, and proxies channels.
6. For `nexthop`: the proxy opens an SSH connection to the next proxy, which
   repeats steps 2–5. This allows a **single firewall punch-through per hop**.
7. All session data is logged and shipped to Hoplock Control (Section 7).
8. On session end, ephemeral credentials/users are removed (Section 5).

---

## 2. Key decisions

Each decision has an ID so prompts and learnings can reference it. Decisions
marked **(confirm)** are recommendations pending explicit user confirmation.

- **D1 — Target identity transport (confirmed).** SSH has no SNI/Host header, so
  the target hostname the user typed is not on the wire after DNS resolution.
  The target is therefore **encoded in the SSH username** using a configurable
  delimiter (default `#`): `alice#host.company.com`. The proxy parses and
  strips the target segment **before** authentication, then authorizes
  `user=alice, target=host.company.com`. The `.<brand>.proxy` DNS name is used
  only for geo-routing to the nearest proxy; a thin client-side SSH-config /
  wrapper delivers the clean `ssh host.company.com.<brand>.proxy` UX by
  rewriting it into the encoded form. The delimiter and parsing rules live in
  the proxy bootstrap config.

  **Why not `ssh -J` (ProxyJump), which does put the target on the wire.** A
  jump host learns the target from the `direct-tcpip` channel the client opens,
  so no username encoding is needed — and that is exactly why it cannot be used
  here. Under ProxyJump the client runs its SSH handshake *with the target*
  through that tunnel, so the inner session stays end-to-end encrypted and the
  jump host sees ciphertext: no channel policy, no command visibility, no
  session capture — none of the reasons this product exists. The username
  encoding is the price of decryption, and only a decrypting proxy has to pay
  it. This is the first question a technical evaluator asks, so the answer is
  recorded here as "considered and rejected", not "not considered".
- **D2 — The proxy originates no policy.** Every authn/authz/route/policy
  decision is *made* by Hoplock Control. A decision is fetched **once per
  connection** and enforced locally for that connection's lifetime, so the data
  path (channel opens, commands, stream bytes) makes no calls to the server at
  all — the latency is at session setup, not in the stream (§6.4).
  The proxy may reuse an authorize decision across connections **only** when
  the server explicitly authorises it with a server-set TTL, and only while it
  can still hear revocations (§6.4). It never caches authentication results, and
  it never widens a decision it was given.
- **D3 — Hoplock Control is a separate component.** This repo defines the
  **API contract** and ships a **mock/reference Hoplock Control**
  (`cmd/mock-control`) used for development and CI. The production Hoplock Control is out of scope for this repo and is specified in its own sibling
  repository, which vendors `api/control.yaml` from here and treats it as
  read-only: **this repo owns the contract, that one implements it.** A contract
  change is made here first, and the sibling repo's conformance suite is what
  proves the two still agree.
- **D4 — Auth planes are pluggable interfaces.** `user→proxy` and
  `proxy→target` are separate Go interfaces, each with swappable
  implementations chosen by config, and each segregated into its own package.
  Both are designed around an **identity/claims** model so AD/Okta/OIDC can be
  added later without changing callers.
- **D5 — Generic channel passthrough first, inspection later.** v1 proxies all
  SSH channel types generically. Hoplock Control returns the set of
  **permitted channels** per connection; the proxy enforces that allow-list.
  The channel layer is built as a **middleware/inspection pipeline** so filters
  can attach to any channel type later without touching the transport core, and
  without adding latency to un-inspected channels.
- **D5a — The policy vocabulary has three axes, not one (amended, phase 0006).**
  A flat list of permitted channel *types* is too coarse to express what this
  product claims to sell, because SSH puts very different operations inside one
  channel type. `scp`, `sftp`, an interactive shell, and a one-shot command all
  ride `session`; a port forward's whole meaning is the destination inside its
  `direct-tcpip` payload; and remote forwarding is not a channel open at all but
  a connection-level **global request**. So policy is expressed over:
  1. **channel types** — which channels may exist, in both directions;
  2. **in-channel requests** — `pty-req`, `shell`, `exec`, `subsystem` (by
     name, so `sftp` is deniable on its own), `env`, `x11-req`,
     `auth-agent-req`;
  3. **destinations and global requests** — permitted host/port targets for
     `direct-tcpip`, and an allow-list for connection-level requests
     (`tcpip-forward`, `no-more-sessions`, …).

  Only all three make "may open a shell on production, may not copy files off
  it, may not tunnel anywhere except the database, and may never open a
  listener" a policy this proxy can express. Two of these are the difference
  between a proxy and a firewall, and both are contract shapes rather than
  engine work: phase 0006 revises `api/control.yaml` before the inspection
  pipeline (0009) is built against the old vocabulary.
- **D6 — Ephemeral just-in-time target users.** The proxy holds a
  **management certificate** preloaded on targets. On session start it logs in
  with the management cert, creates a target OS user matching the authenticated
  username, injects a freshly generated short-lived key/cert into that user's
  `authorized_keys`, connects as that user, and on session end logs back in with
  the management cert to remove the user. Orphan cleanup is mandatory (Section 5).
- **D6a — Two target-credential methods, chosen by the server (amended, phase
  0006).** D6 is the strongest credential story available on a Linux fleet: no
  standing accounts, no shared secret, nothing to rotate. It is also the most
  *target-invasive* model in the field — it needs a privileged provisioning
  account, a preloaded management certificate, and the ability to create and
  delete OS users and write `authorized_keys`. A router, a firewall, a storage
  filer, a hypervisor, or an OT controller can do none of that, and those are
  exactly the devices that can never run an endpoint agent and therefore gain
  the most from an inline enforcement point. An architecture that only ships D6
  is closed to them.

  So `TargetAuthenticator` gets a **second production implementation** —
  brokered credentials, the grown-up form of the `static-key` placeholder: a
  per-target credential the proxy holds only for the session's duration and
  never writes to disk. And the choice between methods belongs to the
  **Hoplock Control**, per route, not to proxy-local config: one proxy
  fronting both a Linux estate and an appliance estate is the normal case, and
  `auth.target.method` in `config.yaml` cannot express it. The authorize
  response therefore carries a `target_auth` object (a method name plus
  method-specific parameters), and the proxy config keeps only the local
  material each method needs. The object is extensible on purpose: a future
  Hoplock Control that mints target credentials itself slots in as another
  method without a third breaking change.
- **D7 — Host key policy from the server.** Prototype: **trust-on-first-use**,
  but every newly seen target host key is reported to Hoplock Control.
  Later: per-target configurable policy fetched from Hoplock Control based
  on server criticality.
- **D8 — Logs go to Hoplock Control.** Structured logs are **batched** to
  Hoplock Control for efficiency. **Blocked commands and other critical
  security events are sent immediately** (flush the in-flight batch or use a
  dedicated priority channel). Local disk is only a **resilience buffer** for
  when the network is unavailable; logs drain to the server when it recovers.
- **D9 — Tech choices.** Go (min **1.25**, target latest stable). SSH plumbing:
  `golang.org/x/crypto/ssh`. Proxy bootstrap config: **YAML**. API + policy +
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
- **D11 — A hop is reached over a connection the *downstream* proxy opened
  (new, phase 0008).** The original next-hop sketch had each proxy dial the
  next one, and described the result as "a single firewall punch-through per
  hop". One hole per hop is still a hole per hop: in a segmented estate every
  one of them is a change request, a review board, and a standing inbound path
  into a more sensitive zone — which is the objection this architecture exists
  to remove, not to charge per enclave.

  The proxy already solves this problem once, in the right direction: the
  revocation stream (§6.4) is outbound from the proxy *because* proxies sit
  behind firewalls and must not need an inbound listener. That reasoning does
  not stop being true one layer down. So a proxy in a protected zone
  **registers an outbound relay connection** with its upstream and the upstream
  dials the next hop *through* it; the protected zone needs no inbound rule at
  all. Forward dialling stays supported for the zones where it is genuinely
  simpler (an upstream that is already reachable), so the route says which
  applies: the authorize response's hop metadata carries a **connection
  direction**, and neither proxy infers it.

  This is written down before 0008 rather than after, because connection
  direction is not a detail inside a hop protocol — it *is* the hop protocol,
  and retrofitting it later is a rewrite.
- **D12 — "Enforced" is a claim about the boundary, not about interception
  (new, phase 0010).** §6.3 splits `exec` (the whole command is visible up
  front) from interactive shells (keystrokes, best-effort). That split is real,
  but it describes **interception reliability** and must not be read as a
  security boundary: pattern-matching the string in an `exec` request is not one
  either. A rule denying `cat /etc/shadow` is satisfied by `sh -c 'cat
  /etc/shadow'`, by `base64 -d | sh`, by any interpreter, editor shell escape,
  or uploaded binary. Reliable interception of an unrestricted shell command is
  still an unrestricted shell.

  The proxy therefore offers **two exec modes**, and only one of them is sold
  as enforcement:
  - **Filtered exec** (the D5 rule list) — a *guardrail*. Better failure mode
    than the interactive path because the whole command is seen before it runs,
    and honest about being a guardrail everywhere it is documented.
  - **Restricted exec** — a genuine boundary: the policy names permitted
    executables together with the shape of their arguments, the command is
    parsed rather than pattern-matched, anything unnamed is denied, and no shell
    is interposed to re-expand what was approved. A default-deny list of
    approved argv shapes is defensible under adversarial review in a way a
    blacklist of regexes is not.

  Which mode applies is per connection and comes from the server. Marketing,
  docs, and the audit record use the same two words for the same two things.

  **Where** either mode is enforced is a separate question, opened by phase
  0015. Both tiers above are enforced *in the proxy, at the `exec` request*, so
  both stop meaning anything the moment a route permits an interactive shell —
  which this decision says in as many words. The ephemeral method (D6, §5.1)
  creates the account, writes its `authorized_keys`, and chooses its shell, so
  on those routes the same policy can be enforced by sshd and the kernel
  instead, where it also survives a connection that never went through a proxy.
  0015 surveys those enforcement points and gives Hoplock Control the vocabulary
  to choose one per route; 0016 implements them. This decision is amended there
  rather than replaced.
- **D13 — Ephemeral accounts on devices the proxy cannot administer as a host
  (new, phase 0013).** D6a split target credentials into `ephemeral-user` for
  hosts that accept provisioning and `brokered-key` for everything else, on the
  grounds that "a router, a firewall, a storage filer, a hypervisor, or an OT
  controller can do none of that". That is true of *POSIX* provisioning and only
  of POSIX provisioning. A FortiGate cannot run `useradd`, has no
  `authorized_keys` and no home directory — but it can create an administrator,
  set its password or public key, scope it to an access profile, restrict it to
  a source address, and delete it again. Those are the same operations D6
  performs; the transport and the vocabulary differ, not the model.

  So the ephemeral model reaches this gear, and what stands between them is not
  the credential method but the absence of a **device driver layer**: something
  that knows how to say "create this account" to one platform.
  `ephemeral-account` is a third method, and a driver is the per-platform
  implementation of its operations. The route **names the platform**; the proxy
  never sniffs a banner and guesses, because guessing wrong means running
  configuration commands against the wrong parser.

  Three properties D6 inherited from the operating system are unavailable here,
  and each is replaced rather than assumed:

  - **Expiry.** OpenSSH's `expiry-time` makes an ephemeral key die whether or
    not the proxy is alive (§5.1); most device platforms have no equivalent. So
    expiry becomes a per-target posture the **PDP selects** — target-enforced
    where the platform can do it, proxy-enforced where it cannot, or explicitly
    accepted as a risk — and the posture in force is in the audit record.
    §5.1's rule that a fleet unable to express expiry is refused holds for the
    target-enforced posture; it is not a rule about every fleet.
  - **The account name as the registry.** `hl-<tag>-<login>-<token>` needs 31
    characters and many platforms cap administrator names far below that. A
    driver therefore *declares* its limit, and below 32 the name gives up its
    readable login segment rather than its reaper prefix or its uniqueness token
    (§5.3). Attribution moves into a mapping event the proxy emits on D8's
    priority path — which makes that event load-bearing in a way it never is on
    Linux, where the target itself names the user. Lose the event and
    attribution exists nowhere.
  - **Invisibility.** Creating a POSIX user disturbs nothing anyone watches.
    Creating a device administrator is a **configuration change**: it lands in
    config-change logs, backup diffs, and drift detection, twice per session.
    Hoplock's own drivers therefore never persist the account to saved
    configuration — a reload is then a free reaper — and the noise is answered
    by *publishing* the changes for correlation, never by suppressing the
    device's own logging of them (§5.3).

  **Customer-written drivers are a first-class case**, not an afterthought: the
  estates that need this most are the ones running a platform nobody else has.
  The seam is declarative first — a driver is a document naming the connect
  mode, the command sequence per operation, expected prompts, error patterns,
  and the platform's declared limits — with a subprocess contract as the escape
  hatch and a compiled SDK deliberately deferred. A customer driver may persist
  accounts where a Hoplock driver may not; it declares that it does, and every
  session it serves records it.

- **D14 — The server sends a ladder of credential methods, not one (amends D6a,
  new, phase 0013).** D6a said an unsatisfiable method is a clean denial and
  "never a silent fallback to a different method". The rule is right and its
  conclusion was too narrow: it optimises for never connecting with the wrong
  credential at the cost of not connecting at all — and a session that does not
  happen produces no recording, no command policy, and no audit trail. For a
  product whose first claim is reaching the devices nothing else reaches, denial
  is frequently the worse security outcome.

  What made fallback unacceptable was never degradation; it was the **proxy**
  choosing. So `target_auth` becomes an **ordered list the PDP authors**: the
  proxy walks it top-down, stops at the first entry it can satisfy, and records
  which one that was. Nothing is proxy-invented — a single-entry list is exactly
  D6a's original behaviour, and a PDP that will not accept degradation on a
  target writes one. D6a's actual rule survives untouched: the proxy never
  connects with a method the server did not name.

  The rung in force is an **audit fact, not a user-facing one**. It goes to the
  record and the operator surface; the user is told nothing. "You got the weaker
  credential" tells an attacker which targets are softest and tells an honest
  user nothing they can act on. This is the one place §4.3's disclosure rule
  does not apply, and the reason is that the information is about the estate
  rather than about the user's own request.

- **D15 — External authorization context belongs to Hoplock Control (new, phase
  0015).** Some access is legitimate only while something outside this system
  says so: a vulnerability scan is running, a change ticket is approved and
  inside its window, an incident is open. Hoplock must learn that in two
  directions — an inbound **push** ("a scan is starting against targetX") and an
  outbound **probe** ("is this access legitimate right now?") — and customers
  must be able to integrate systems nobody here has heard of.

  None of that is the proxy's. D2 says the proxy originates no policy, and a
  push that grants access and a probe that validates one are both policy
  *inputs*, consumed while the PDP decides. So the proxy stays entirely ignorant
  of Qualys, of BMC Helix, and of whatever a customer builds: it asks Control
  for a route and gets one, exactly as today. The framework is Control's `ext/`
  seam (**M16**) and the shipped integrations are Enterprise's (**E13**), per
  `docs/CROSS-REPO-PROTOCOL.md` §1. Both downstream decisions exist; this
  repository's obligation is the vocabulary in D16 and nothing more.

  Two consequences do land here, and both are already built. **Revocation is the
  stop path**: when the scan ends or the ticket closes, §6.4's stream is what
  ends a session already in flight. And **caching must not outlive the window**,
  which needs nothing new, because the cache hint is server-owned — a PDP
  granting time-boxed access simply omits it.

  Three design constraints the framework must honour are recorded here because
  this repository owns the cross-repo protocol. Push and probe are **not
  redundant**: push is fast and spoofable, probe is authoritative and needs the
  external system reachable, so a push opens a pending window and a probe
  confirms at authorize time, failing closed for privileged grants. A push is
  **untrusted input naming a target** and must be constrained to a
  pre-registered scope for that integration — otherwise the push endpoint *is*
  an access-granting API. And replay, clock skew, and a server-side ceiling on
  window length belong to the framework, not to each integration, or the first
  customer-written provider becomes the weakest one.

- **D16 — Unbounded privilege is bounded by time and by the record, not by
  command policy (new, phase 0015).** A vulnerability scanner needs root and
  changes its command set with every content update. Every tier of D12's ladder
  is worthless against it by construction — there is no argv shape to name, and
  no rule list survives an interpreter. The product must say that plainly rather
  than imply a filter is watching.

  What actually constrains such access is three things, and they are what the
  contract must express: it **did not exist before the window** (D6/D13); it
  ends at a **deadline the proxy enforces locally** — so it holds when the
  revocation stream is down, which is precisely when an immortal root session is
  least acceptable; and it was **recorded outside the target's reach**. That
  last is the strongest claim in the system and the reason capture is not
  optional here: root on a target can disable its auditing and scrub its traces;
  it cannot touch a session captured in the proxy. A route may therefore require
  capture, and a proxy that cannot record — not even to its disk buffer —
  refuses it.

  The record must also say **why** access was granted. `decision_id` correlates
  a decision; nothing carries the ticket, the scan, or the window. A structured
  grant context does, and the proxy treats it as opaque: logged, never parsed,
  and never the basis of a decision the proxy makes itself.

- **D17 — Machine identities need a different connection model (amends D2, new,
  phase 0018).** D2's "one decision per connection" is safe because connections
  are short: a snapshot enforced for the life of a ten-minute session is not
  standing authorization. Machine-to-machine health checking breaks that
  assumption from both ends. An estate of 350,000 targets polled every minute is
  ~5,800 new connections per second — five figures of authorize load, an SSH
  handshake per check, and, on `ephemeral-user` or `ephemeral-account` routes,
  an account creation per check, which is not a thing that can be done. Yet the
  natural fix — one persistent connection per (automation, target) with a
  channel per check — is exactly the standing authorization D2 exists to
  prevent.

  Both halves are right, so the resolution is to **bound the snapshot rather
  than the connection**: a long-lived machine connection carries a maximum
  snapshot age and re-authorizes when it expires, with the revocation stream
  still the fast path. The connection survives; the decision does not. Audit
  granularity moves with it — the unit of record becomes the channel, not the
  connection.

  Those numbers are arithmetic, not measurement, and they rest on an assumption
  worth testing before it is designed for: most large estates health-check
  network devices over SNMP or streaming telemetry rather than SSH, and those
  that use SSH typically do so every five to fifteen minutes, not every sixty
  seconds. Phase 0017 exists to replace the arithmetic with measurement, and it
  runs first for that reason.

---

## 3. Architecture & repository layout

```
hoplock/
├── cmd/
│   ├── proxy/            # the proxy daemon (main)
│   └── mock-control/    # reference/mock Control API for dev + CI
├── internal/
│   ├── config/             # YAML bootstrap config loader
│   ├── identity/           # identity + claims model (AD/Okta/OIDC-ready)
│   ├── control/            # Control API client + shared contract types
│   ├── auth/
│   │   ├── user/           # user→proxy authenticators (cert, password+MFA)
│   │   └── target/         # proxy→target authenticators (ephemeral, mgmt-cert)
│   ├── routing/            # target parsing (D1) + route resolution + multi-hop
│   ├── relay/              # proxy↔proxy relay registrations (D11)
│   ├── proxy/              # core SSH proxy engine, session lifecycle
│   ├── channel/            # channel allow-listing + inspection pipeline
│   ├── filter/             # command filtering (whitelist/blacklist + actions)
│   ├── logging/            # session capture, batching, priority flush, buffer
│   └── sshtest/            # test support: in-process SSH target + key helpers
├── api/                    # API contract (OpenAPI/JSON Schema) — source of truth
├── deploy/                 # docker-compose e2e topology + fixtures
├── .github/workflows/      # CI (build, vet, test, lint, e2e)
├── docs/
│   ├── PLAN.md             # this file
│   ├── PROTOCOL.md         # session workflow (read before any work)
│   ├── CROSS-REPO-PROTOCOL.md  # shared with control + enterprise; this repo owns it
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

- **`cmd/proxy`** — wires config → listeners → auth → proxy → logging. Small.
- **`internal/control`** — the ONLY place that talks to Hoplock Control. Every
  other package depends on interfaces here, not on HTTP. Makes the whole system
  testable against the mock and swappable transports later.
- **`internal/identity`** — `Identity` (subject, principals, claims, groups,
  source) and `Claims`. Returned by user authenticators; consumed by routing and
  policy. This is the AD/Okta-ready seam (D4).
- **`internal/auth/user`** — `UserAuthenticator` interface + implementations.
- **`internal/auth/target`** — `TargetAuthenticator` interface + implementations.
- **`internal/relay`** — the transport half of D11: the registration a
  downstream proxy opens to its upstream, and the channels the upstream opens
  back over it. It decides nothing; the route says which sessions travel this
  way.
- **`internal/proxy`** — accepts the client SSH connection, orchestrates authz +
  route + target dial + channel pumping. Transport-level correctness lives here.
- **`internal/channel`** — the inspection pipeline (D5). Enforces the permitted
  channel allow-list; hosts pluggable per-channel inspectors.
- **`internal/filter`** — command policy engine (D5/filtering); pure logic, fed
  by the channel pipeline.
- **`internal/logging`** — session recorder + shipper (D8).

---

## 4. Authentication design

### 4.1 user → proxy (`internal/auth/user`)

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
Hoplock Control via `internal/control` — the proxy holds no credential
database. The initial-auth password is **never logged** (D8/redaction).

### 4.2 proxy → target (`internal/auth/target`)

```go
// TargetAuthenticator produces the credentials the proxy uses to log into a
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

There are **three production implementations** (D6a, D13), and Hoplock Control
picks between them per route in its authorize response — never proxy-local
config, because one proxy routinely fronts estates that need different
methods. Since D14 the response carries an **ordered list** rather than a single
method, and the proxy uses the first entry it can satisfy:

| Method | What it does | For |
| --- | --- | --- |
| `ephemeral-user` | Creates a short-lived OS user + key on the target and removes it afterwards (D6, §5) | Linux/BSD fleets that accept a provisioning account |
| `brokered-key` | Uses a per-target credential held for the session and never written to disk | Appliances, network and OT gear: anything that cannot create users |
| `ephemeral-account` | Creates a short-lived administrator on a device through a platform driver and removes it afterwards (D13, §5.3) | Network, security and OT appliances that can create accounts but are not POSIX hosts |

`static-key` remains as the development placeholder from phase 0005 —
`brokered-key` is what it grows into. A method the proxy does not implement, or
has no local material for, is **skipped**, and the next entry in the server's
list is tried (D14). Exhausting the list is a clean session denial (an
outage-class failure, §4.3). What has never been permitted, and still is not, is
the proxy connecting with a method the server did not name: a single-entry list
therefore behaves exactly as D6a originally specified.

On the wire (contract v2, phase 0006) this is `target_auth`: a `method` from
the table above plus a method-scoped `params` string map — `username`,
`key_type`, `lifetime_seconds` for `ephemeral-user`; `username` and an opaque
`credential_ref` for `brokered-key`. **No credential material travels on the
API**; `credential_ref` selects material the proxy already holds. An absent
`target_auth` leaves the proxy on its locally configured method, which is what
a v1 server implies and what phase 0005 does today.

Both interfaces take/return `identity.Identity` (not booleans) so that AD/Okta
claims flow through unchanged (D4/D8-answers question 8).

### 4.3 What the user is told (disclosure rule)

A policy proxy that fails silently is indistinguishable from a broken network,
and a user who cannot tell "I am not allowed" from "the service is down" files
the wrong ticket — or retries a denial forever. The proxy therefore **always
says something before it closes a connection**, and what it says splits along
one line:

- **Deny** (`401` from any endpoint) → deliberately vague: "access denied". It
  never reveals whether the login, the target, or the policy was the problem,
  and never whether the target exists. Anything more precise turns the proxy
  into an oracle for probing the estate.
- **Everything else** (Hoplock Control unreachable, `5xx`, contract violation,
  target unreachable, provisioning failure) → explicit and honest: this is not a
  permissions problem, it is an outage, plus the **session id as a support
  reference**. That text is safe to disclose and turns a mystery disconnect into
  a ticket that can be answered from the logs.

The same rule covers policy actions mid-session: a blocked command says it was
blocked, and a session killed by Hoplock Control prints the server's
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
- **A failure is reported only once the client has asked for something.** An SSH
  client starts reading a channel's output after it sends its `shell` or `exec`
  request, so a message written before that is written into a stream nobody is
  reading. Explaining too early is indistinguishable from not explaining at all.

`SSH_MSG_DISCONNECT` is the row this table cannot fully deliver:
`golang.org/x/crypto/ssh` does not expose it (`ssh.Conn` offers only `Close`;
sending a disconnect is on the library's own TODO list), so a proxy built on
it cannot attach a reason code to a connection close. The engine's answer is the
ordering above — the session channel exists before anything can fail, so the
explanation goes over the channel — plus a channel-open **rejection** carrying
the reason for anything opened after a failure, which is the same information in
the mechanism SSH does give a server. Only a client that opens no channel at all
gets an unexplained close. If x/crypto ever exports a disconnect, the engine
already reaches for it.

Feedback is written to stderr, never stdout, and suppressed for non-interactive
channels (no pty — `scp`, `sftp`, `exec`) beyond what a failure requires, so
tooling that parses the stream is not corrupted.

---

## 5. Target credentials (D6, D6a)

### 5.1 `ephemeral-user` — just-in-time provisioning (D6)

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

> This is the highest-risk feature. Its prompt covers cleanup/orphan handling
> and concurrency explicitly, and its learnings file must document the exact
> teardown guarantees for later sessions.

**As built (phase 0007).** Three choices give the requirements above their
concrete form, and later phases depend on all three:

- **The account name is the registry.** Accounts are named
  `hl-<proxy tag>-<login>-<token>`, where the tag is a digest of this proxy's
  id. The reaper finds orphans by that prefix, which is why a crash — the case
  that destroys every in-memory record — is still recoverable; the tag stops one
  proxy from sweeping another's live sessions on a shared target; the token is
  the answer to concurrency (unique principals, not coordination), so two
  sessions for one login never share an account or a teardown.
- **Sweeps happen on the provisioning path, not only on a timer.** A restarted
  proxy has no idea which targets it owes cleanup on, so the first successful
  provisioning on a target triggers a (rate-limited, background) sweep of it.
  A live account is never swept whatever its age; an untracked one is swept once
  it is older than a grace period, which is what protects a session that is
  being provisioned right now.
- **A key lifetime is enforced on the target.** `lifetime_seconds` becomes
  OpenSSH's `expiry-time` restriction in `authorized_keys`, so the key stops
  working whether or not this proxy is alive to remove it. A proxy configured
  for a fleet whose sshd cannot express that refuses the route rather than
  serving it with a key that never expires.

### 5.2 `brokered-key` — a credential held only for the session (D6a)

The target is unchanged: nothing is created, nothing is removed, and the only
prerequisite is an account that already exists on it. The proxy is handed
(or fetches) the credential for **this** session, uses it, and drops it.

- The credential **never touches disk on the proxy** and never appears in a
  log, an error, or a config file. Where it comes from is a seam — a local
  secret store today, a Hoplock Control server that mints per-session credentials
  later (the same `target_auth` object grows a method, D6a).
- `Teardown` still exists and is still guaranteed, but its job is zeroing the
  in-memory credential and closing the leg — there is no remote state to undo,
  which is exactly why this method works on a device the proxy cannot
  administer.
- Weaker than D6 by construction: the account is standing and shared across
  sessions, so **the audit trail is the proxy's**, not the target's. The
  target sees one login from the proxy; who was actually behind it is knowable
  only from this system's records. That is an honest trade for reaching devices
  D6 cannot, and it is the reason session capture (§7) is not optional for
  routes using this method.

**As built (phase 0007).** The seam is `target.CredentialSource`: one method,
`Credential(ctx, CredentialRequest) (*Credential, error)`, where the request
carries the target, the route's opaque `credential_ref`, the account name, and
the subject. Two local implementations ship — a directory of files and the
process environment, both keyed by the reference and read on demand rather than
cached. **A Hoplock Control that mints per-session credentials implements this
interface**; it arrives as another `target_auth` method plus a source, and
nothing that touches a credential changes.

### 5.3 `ephemeral-account` — a short-lived administrator on a device (D13)

The lifecycle mirrors §5.1 exactly — log in privileged, create the account,
install the credential, connect, remove it on teardown — and every step is
executed by a **driver** for the named platform rather than by POSIX commands.
The route names the platform; nothing is inferred from a banner.

A driver **declares its platform's constraints**, and the provisioner reads
those declarations rather than assuming Linux:

| Declaration | Why the provisioner needs it |
| --- | --- |
| Maximum account-name length | Selects the naming scheme below |
| Whether expiry can be enforced on the device | Selects the expiry posture (D13) |
| Whether account creation persists across reload | Hoplock drivers must answer "no"; a customer driver may answer "yes" and have it recorded |
| Which credential kinds it accepts (password, public key) | The route's `credential_kind` must be one of them |
| Whether the account can be pinned to a source address | A free extra restriction where it exists |

**Naming under a constrained limit.** With a declared limit of *X*:

- *X* ≥ 32 — the §5.1 scheme unchanged: `hl-<proxy tag>-<login>-<token>`.
- 11 ≤ *X* < 32 — `hl-` + a 4-character proxy tag + an (*X*−7)-character token,
  base36 throughout. The readable login segment is what is dropped, because a
  six-character truncation of `automation-disk-check` reads as attributable when
  it is not, while its absence is honest. The reaper prefix and the uniqueness
  token both survive: without the first, one proxy's reaper deletes another's
  live accounts; without the second, two concurrent sessions share an account
  and each teardown removes the other's access.
- *X* < 11 — the route is refused (outage-class, §4.3). Below that the token
  falls under four base36 characters, and a name that short is both
  collision-prone and *guessable* — and on password credentials the account name
  is half the credential pair.

Base36 rather than hex is not cosmetic: at *X* = 12 the token is five characters,
worth ~26 bits in base36 against 20 in hex, and that difference lands exactly
where the budget is tightest.

**Collision behaviour differs from §5.1.** The ephemeral provisioner treats an
existing account idempotently, which is safe when the name encodes the session.
With a short token an existing account is more plausibly *another live
session's*, so the device path verifies non-existence and, on collision,
**retries with a fresh token** — it never adopts. A small retry budget, then
refusal.

**Attribution lives in the log, so the log is mandatory.** On a constrained
platform the account name carries no login, so the proxy emits a mapping event
— account name, session id, subject, target, platform, the rung and posture in
force — on D8's **priority path**, not batched. A route whose driver declares a
constrained limit is refused if the proxy has no logging path at all, not even
its disk buffer: attribution that exists in exactly one place must actually
reach that place. This is the same fail-closed rule as D16's required capture,
reached from a different direction.

**Configuration-change noise is documented, not suppressed.** Two config changes
per session, per device, land in the customer's backup diffs and drift
detection. Hoplock does not offer to hide them — teaching an operator to
exclude privileged-account creation from change logging would remove the record
that makes Hoplock's own actions reviewable. The shipped answer is a documented
note (exclude `hl-*` account objects from drift *alerting*, not from logging),
and the real answer is a **reconciliation feed**: Control publishes every change
Hoplock made — device, object, timestamp, session, identity — for the customer's
NCM or SIEM to correlate and auto-close. That inverts the problem, because an
`hl-*` object appearing on a device that Hoplock never reported is then a
high-quality detection rather than noise. It is an outbound integration and so
reuses D15's provider seam in Control rather than growing its own.

Account **pooling** — pre-creating administrators and rotating only their
credentials — is recorded here as the named alternative for customers who can
consume neither, and rejected as the default: it caps concurrency per device,
leaves a pool member holding a live credential after a proxy crash, and demotes
the product's claim from "no standing accounts" to "no standing credentials",
which is a materially weaker sentence.

---

## 6. Channels, routing, and filtering

### 6.1 Routing (`internal/routing`)

- **Target parsing (D1)**: split the SSH username on the configured delimiter into
  `login` + `target`. Validate/normalize the target hostname.
- **Route resolution**: call Hoplock Control's authorize+route endpoint with
  `(identity, target, conn metadata)`. Handle `direct` and `nexthop`.
- **Multi-hop**: for `nexthop`, reach the next proxy and re-run the flow.
  Enforce a **max hop count** and **loop detection** (carry a hop trail).
- **Connection direction (D11)**: the hop metadata says how the next proxy is
  reached, and there are two ways:
  - `dial` — this proxy opens a TCP/SSH connection to the next one. Simple,
    and it requires an inbound rule at the next hop.
  - `relay` — the next proxy has already **registered an outbound relay
    connection** with this one; this proxy opens a channel over that existing
    connection instead of dialling. The protected zone needs no inbound rule.

  On the wire (contract v2, phase 0006) this is `hop.connection`, with
  `hop.next_proxy_id` naming the registration a `relay` hop opens a channel
  over. An absent `hop.connection` means `dial`, so a v1 server's route still
  works. `routing.Route.HopDirection()` resolves that default for callers.

  A proxy that accepts relay registrations authenticates the registering
  proxy the same way Hoplock Control authenticates a proxy, keeps one
  registration per proxy id, and re-registers with backoff when the link
  drops. A route naming a `relay` hop with no live registration fails as an
  outage (§4.3) — it is never silently downgraded to `dial`, which would punch
  through the boundary the mode exists to preserve.

#### How a hop is actually opened (phase 0008)

A hop leg is an ordinary SSH connection from one proxy to the next, and the
direction changes only where its byte stream comes from: a socket this proxy
dialled, or a channel (`relay-session@hoplock.io`) over a registration the next
proxy opened to it. Everything above that stream is identical, which is what
makes "the route decides, the proxy obeys" true rather than aspirational.

On that connection the upstream proxy presents:

- the SSH username `login<delimiter>final_target`, so the next hop parses it
  with the same D1 rule it applies to a user — **a chained fleet must therefore
  agree on the delimiter**;
- its own **chain identity key** (`chain.identity_key_path`), never the user's;
- the client version `SSH-2.0-Hoplock_Proxy_hop`, which is how the next hop
  knows to expect a trail before it authorizes anything.

**Chain trust model.** Each hop authenticates the hop in front of it *through
Hoplock Control*, and Hoplock Control answers with the user's identity, which it
establishes itself. The proxy asserts nothing about who the user is: it relays a
key and a login, exactly as it does for a user's own client (§4.1). A hop
therefore never has to trust an upstream's claim — the trust is in the fleet's
keys and in the PDP, which is where every other decision in this system already
lives (D2). It also means a compromised proxy cannot mint an identity: it can
only offer its own key, and the server decides what that key may assert.

**Hop trail, loops, and the cap.** Immediately after authenticating and before
opening any channel, the upstream sends a connection-level request
`hop-trail@hoplock.io` carrying the proxy ids traversed so far, the final
target, and the cap in force. The next hop records it, forwards it to Hoplock
Control as `conn.hop_trail`, and refuses the session when:

- its own id is already in the incoming trail, or the route's `next_proxy_id`
  is (a **loop**); or
- extending the chain would exceed the **strictest** of the inherited cap, the
  route's `max_hops`, and the proxy's own `chain.max_hops`
  (`routing.DefaultMaxHops` when none is set).

Both refusals are outages with the session id (§4.3) plus an audit line naming
the trail: they are faults in the estate's routing, not decisions about the
user. The trail carries **no authority** — every entry in it can only cause a
refusal — so a client that forged one would only restrict itself, and a hop that
announces itself and then sends no trail is refused rather than served with an
empty one.

**Relay registration.** `internal/relay` holds both halves. The downstream proxy
(`chain.upstream`) keeps one outbound SSH connection open to the upstream's
registration listener, reconnecting with bounded backoff, exactly as the
revocation stream does one layer up (§6.4). The upstream (`chain.accept`)
authenticates each registering proxy with the fleet's own material — an
`authorized_keys` file whose **comment names the proxy id that key may claim**,
or a trusted CA whose user certificates must name the claimed id as a principal
— keeps one registration per id, and opens a channel over it per session. The
registration is proxy-to-proxy plumbing and not part of the Control API: users
never reach that listener, and it carries no channels from the registrant.

A dropped registration takes the sessions riding it down with the transport, and
nothing more: the replacement carries new sessions only, and nothing cancels
work in flight on its own.

### 6.2 Channels (`internal/channel`, D5)

- The authorize+route response includes **permitted channel types**. The channel
  layer **denies any channel not on the allow-list**, in both directions: a
  channel the session may not open is not one it may be handed by the target.
- It also carries the other two axes of D5a, and each is enforced where SSH
  actually decides it. The field names below are the ones the contract ships
  (`api/control.yaml`, contract v2 from phase 0006); each is **absent by
  default, and absent means "not policed"** — which is what a v1 server meant —
  while a *present but empty* object denies everything on its axis, exactly as
  `permitted_channels: []` does:
  - **In-channel requests** — `permitted_requests` (`types`, `subsystems`). A
    `session` channel is opened before anyone knows what it is for; the request
    that follows (`pty-req`, `shell`, `exec`, `subsystem`) is what makes it an
    interactive login, a one-shot command, or a file transfer. Enforcement is
    therefore at the *request*, not the open, and subsystems are named
    individually — `subsystems`, not a `subsystem` entry in `types` — so `sftp`
    can be denied while `shell` stays. This is what expresses "may log in, may
    not copy files off the box" and "CI may run commands but never gets a PTY".
    Requests that decide nothing (`window-change`, `signal`, `exit-status`,
    `break`) are outside the policy and always relayed.
  - **Forwarding destinations** — `permitted_forwards` (`direct_tcpip`,
    `forwarded_tcpip`; each entry a `host` plus `port` or `port_range`). A
    `direct-tcpip` open carries the host and port it wants; policy matches
    against them (exact host, `*.`-wildcard, or CIDR, plus an exact port or an
    inclusive range) so a route can permit `postgres.prod:5432` and nothing
    else. Allow/deny on the channel type alone is the difference between a
    firewall and a toggle. `forwarded-tcpip` is the same channel type in the
    other direction and gets its own list. The proxy never resolves a name to
    decide policy: a CIDR matches only IP literals, and a DNS answer is not a
    decision the PDP made.
  - **Global requests** — `permitted_global_requests` (`types`). Remote
    forwarding is requested at the connection level (`tcpip-forward`), not by
    opening a channel, so it is invisible to a channel-type allow-list. Denying
    the resulting `forwarded-tcpip` channel is not equivalent: the listener is
    still created on the target and only the connections through it fail.
    Connection-level requests get their own allow-list, refused with a `false`
    reply rather than relayed. Transport hygiene (`keepalive@openssh.com`,
    `no-more-sessions@openssh.com`, the `hostkeys-*@openssh.com` pair) is
    outside the policy and always relayed.
- Inspection pipeline: each channel is wrapped by an ordered list of
  **inspectors**. In v1 the list is empty (pure passthrough) for everything except
  where filtering attaches. Inspectors must be **zero-copy where possible** and add
  no latency when none are registered for a channel type.

### 6.3 Command filtering (`internal/filter`, D5-answers 12–14)

- Hoplock Control tells the proxy, per connection, an **ordered rule
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
- **`exec`** requests: the full command is available up front, so the rule list
  is applied **reliably** — every command is seen before it runs.
- **Interactive `shell`/pty**: keystroke streams are inspected **best-effort**
  (audit/alerting), never claimed as hard enforcement. The pipeline is the same;
  only the reliability guarantee differs. This limitation is documented for users.
- A match produces a **distinct audit event** (D8) sent immediately.

**Three tiers, named honestly (D12).** "Seen reliably" is not "cannot be
evaded", and the product must not let the two blur:

| Tier | Mechanism | Guarantee |
| --- | --- | --- |
| Restricted exec | Server names permitted executables + argument shapes; command is parsed, not matched; unnamed ⇒ denied; no shell interposed | **Enforcement.** Default-deny, defensible under adversarial review |
| Filtered exec | Ordered rule list against the full `exec` string | **Guardrail.** Every command is seen; `sh -c`, interpreters, and encodings still get past a pattern |
| Interactive shell | Best-effort keystroke inspection | **Audit signal.** Line editing, encodings, and shell escapes defeat it by construction |

The mode is per connection and comes from the server: `filter_policy.exec_mode`
is `filtered` (the `rules` list) or `restricted` (`filter_policy.restricted_exec`),
and an absent `exec_mode` means `filtered`, which is what a v1 server meant. The
two are **alternatives, not layers** — a policy setting `restricted_exec`
alongside a non-empty `rules` list is a contract violation the client rejects
outright, because a guardrail and a boundary disagreeing about one command have
no defensible resolution.

`restricted_exec.commands[]` names an `executable` (matched against `argv[0]`
exactly, with no `PATH` search or basename comparison) plus either
`form: exact` with an `argv` compared element by element, or
`form: positional` with an `args[]` of per-position specs (`kind` of `literal`,
`prefix`, `oneof`, or `any`, and `optional` for trailing positions). **Anything
not covered by a spec is denied**: there is no trailing allowance, so the shape
of a permitted command is bounded by what the server wrote. `any` is a named
kind rather than an empty prefix precisely so every unconstrained position stays
visible to a reviewer.

The audit event records which tier decided, so a later review can tell a
boundary from a guardrail without re-reading the policy.

---

### 6.4 Policy caching & session revocation (D2)

The authorize+route response is a **per-connection policy snapshot**, not a
per-action question: it carries the route, the channel allow-list, and the whole
filter policy, and the proxy enforces all three locally. Nothing on the data
path talks to Hoplock Control.

Setup, however, is not amortised: each connection costs ~3 sequential round
trips (authenticate, authorize, host-key report), paid again per hop on a chain.
Two mechanisms address that, and they only make sense together:

- **Server-authorised caching.** The server may attach a cache hint (an opaque
  key + a TTL) to an authorize decision. Absent hint means do not cache. The
  **server** owns the lifetime — a proxy may clamp it shorter but never
  longer, and may never invent one — so the PDP keeps ownership of its own risk
  appetite and can refuse caching per target. A local clamp is **off by
  default** and, where set, must be **observable** (counted and logged per
  affected decision): it is the one place a proxy's behaviour diverges from
  what the server asked for, and an unannounced divergence across a fleet is
  indistinguishable from a server or network fault. **Authentication is never cached**:
  an MFA approval is a per-session assertion, and certificate validation is
  where revocation is enforced.
- **Server-driven revocation.** The proxy holds a long-lived outbound
  subscription to Hoplock Control (proxies are behind firewalls and must
  not need an inbound listener) and receives: kill a named session, kill every
  session for a subject, invalidate cached decisions, or resync. This is what
  bounds the damage of a cached allow, and it is the only way the server can end
  a session that is already in flight.

Fail-closed rule: if the proxy cannot hear revocations (the subscription has
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
- **How**: structured, compact records. **Batched** shipment to Hoplock Control for throughput; **immediate** shipment for blocked/critical events
  (flush current batch or dedicated priority path).
- **Resilience**: when Hoplock Control is unreachable, buffer to local disk
  (one area per session) and **drain on recovery**. Local storage is a buffer,
  not the destination.
- **Redaction**: the initial-auth password is never written. Passwords typed
  *during* a session are acceptable to capture (they should already be
  considered compromised and rotated).

---

## 8. Cross-cutting conventions

- **Module path**: `github.com/hoplock/proxy`.
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
  Hoplock Control backs integration tests.
- **CI**: `go build ./...`, `go vet ./...`, `go test ./...`, a linter
  (`golangci-lint`), and the e2e job (Section 9). See D9.

---

## 9. Test topology (answer to Q21)

**Yes — the full 5-node topology fits inside one GitHub Actions runner** using
Docker containers on a shared Docker network (via `docker compose` in
`deploy/`), no external infrastructure required for the prototype:

| Node                | Container                              |
| ------------------- | -------------------------------------- |
| Hoplock Control   | `cmd/mock-control`                  |
| User (SSH client)   | thin image running the test client     |
| Proxy (direct)    | `cmd/proxy` configured for direct    |
| Proxy (next-hop)  | `cmd/proxy` configured to chain      |
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
| 0002 | Control API contract + mock server   | `api/` contract, `internal/control` client, `cmd/mock-control`      |
| 0003 | Policy caching + session revocation     | cache hint + revocation stream in the contract, `internal/control` cache + subscription, `SessionRegistry` hook |
| 0004 | Identity model + user→proxy auth      | `internal/identity`, `internal/auth/user`, cert-first + password/MFA |
| 0005 | Core proxy engine + direct route        | `internal/proxy`, generic channel passthrough, E2E with static-key target auth; implements `SessionRegistry` |
| 0006 | Policy vocabulary — contract v2         | `api/` + `internal/control`: in-channel requests, forwarding destinations, global requests, `target_auth`, hop direction |
| 0007 | Target credentials                      | `internal/auth/target`: ephemeral provisioner + orphan reaper, and `brokered-key` (D6a) |
| 0008 | Multi-hop / next-hop routing            | `internal/routing` chaining, relay registration (D11), loop/hop-limit protection |
| 0009 | Channel allow-list + inspection pipeline| `internal/channel` enforcement of all three axes + pluggable inspector framework |
| 0010 | Command filtering + policy actions      | `internal/filter`: restricted exec (enforced), filtered exec, interactive best-effort |
| 0011 | Logging & telemetry pipeline            | `internal/logging` batching, priority flush, disk buffer, redaction |
| 0012 | Full E2E topology + CI gate + hardening | `deploy/` 5-node compose, CI e2e job, cleanup                      |
| 0013 | Device provisioning — contract v3        | `ephemeral-account` + the driver seam and its declared capabilities (D13), the ordered method ladder (D14), constrained naming, per-route algorithm profile |
| 0014 | FortiOS device drivers                  | `internal/auth/target/device`: the FortiGate/FortiSwitch drivers, device provisioner, device reaper, fake-device tests |
| 0015 | Enforcement points — contract v4         | survey of where policy is actually enforced (D12 amendment) incl. device RBAC, server-chosen rung + capability advertisement, session deadline + grant context + required capture (D15, D16) |
| 0016 | Target-side enforcement                 | `internal/auth/target` renders the chosen rung onto the ephemeral account (`authorized_keys` options, shell/PATH, filesystem) and onto a device account (access profile, trusted host), teardown + reaper + e2e |
| 0017 | Scale harness & sizing evidence         | synthetic load harness outside the compose topology; measured per-proxy ceilings and Control request rates; validates or refutes D17's arithmetic |
| 0018 | Machine-identity connection model       | persistent M2M connections with a bounded snapshot age and per-channel audit (D17, amends D2) |

Prompts may add or re-order later phases; any prompt that introduces new queued
prompts MUST preserve the numbering invariants in `docs/PROTOCOL.md`.

> **Renumbering note (privileged-access revision).** Phases 0013, 0014, 0017 and
> 0018 are new, and the two enforcement-point phases moved down to make room for
> the device work they now depend on: **0013→0015, 0014→0016**. Only queued
> prompts were renumbered (`docs/PROTOCOL.md` §6); implemented prompts 0001–0007
> keep their frozen names. Anything written before this revision that hands work
> to "0013" means the enforcement-point contract, now **0015**, and "0014" means
> target-side enforcement, now **0016** — including D12's own closing paragraph,
> which was updated in place. The contract version numbering follows the same
> shift: v3 is now phase 0013 (device provisioning) and the enforcement-point
> revision becomes **v4**.
>
> **Renumbering note (contract-v2 revision).** Phase 0006 is new: it revises the
> management contract so the vocabulary in D5a/D6a/D11 exists *before* anything
> is built against the old one. Under `docs/PROTOCOL.md` §6, queued prompts were
> renumbered to keep implementation order — **0006→0007, 0007→0008, 0008→0009,
> 0009→0010, 0010→0011, 0011→0012** — while implemented prompts 0001–0005 keep
> their frozen names. Learnings files written before this revision refer to
> phases by their **old** numbers (e.g. 0005's learnings hand the channel
> allow-list to "0008", now 0009); resolve them through this mapping.

---

## 11. Naming: the Hoplock rename

This repository was `SecureCommandProxy` and its central component was called
"the bastion". Both are gone; the product is **Hoplock** and this component is
**Hoplock Proxy**. What moved:

| Was | Is | Kind |
| --- | --- | --- |
| `github.com/mauroasilva/securecommandproxy` | `github.com/hoplock/proxy` | Go module path |
| `cmd/bastion` (binary `bastion`) | `cmd/proxy` (binary `hoplock-proxy`) | command |
| `cmd/mock-management` | `cmd/mock-control` | command |
| `internal/mgmt` (package `mgmt`) | `internal/control` (package `control`) | package |
| `api/management.yaml` | `api/control.yaml` | contract |
| "the bastion" | "the proxy" / Hoplock Proxy | prose, comments, identifiers |
| "the management server" | Hoplock Control | prose, comments |
| config `bastion:` | config `proxy:` | config key |
| config `management:` | config `control:` | config key |
| config `proxy:` (engine tuning) | config `dial:` | config key |

That last row is not cosmetic. `bastion:` (this proxy's identity and listener)
and `proxy:` (outbound-leg tuning) collided once "bastion" became "proxy", so
the outbound settings moved to `dial:` — `dial.dial_timeout` and
`dial.default_target_port`. An old config file fails to load with a clear
unknown-key error rather than being silently misread, which is the right
outcome for a strict decoder.

### What deliberately did NOT change

**Wire identifiers kept their names through phase 0005**, even though they said
"bastion":

- `bastion_id` — the JSON field on `ConnMeta` and the revocation stream
- `/v1/bastions/{bastion_id}/events` — the revocation subscription path

Renaming a field on the wire is a contract break, and a contract break is worth
paying for once, deliberately, not as a side effect of a `sed`. Phase 0006 was
already queued to revise this contract for the D5a/D6a/D11 vocabulary, and it
is a **versioned, coordinated** change with Hoplock Control on the other side.
So the rename was batched into it, alongside changes that were breaking anyway.

**Done in phase 0006** (contract v2): `bastion_id` → `proxy_id`, and
`/v1/bastions/{bastion_id}/events` → `/v1/proxies/{proxy_id}/events`. The Go
identifier `ProxyID` had already been renamed in the sweep and now carries a
`json:"proxy_id"` tag; that deliberate, temporary mismatch is closed. Nothing
else on the wire moved.

Two other things kept their old names on purpose:

- **"management certificate"** (D6) is a domain term for the privileged
  provisioning credential on a target. It has nothing to do with Hoplock
  Control and would be actively confusing if renamed.
- **`prompts/implemented/` filenames** are frozen by `docs/PROTOCOL.md` §6, so
  `0002-management-api-contract-and-mock.md` keeps its name even though the
  contract file it produced is now `api/control.yaml`. Their *contents* were
  swept, because a future session reads them as reference, not as an audit log.

---

## 12. Out of scope for the prototype

- Real Hoplock Control (only the contract + mock live here) — it has its own
  repository and its own plan (D3).
- Real geo/anycast DNS and scale/distribution testing.
- Tamper-evident/append-only log storage (D8 notes the eventual destination);
  it belongs to Hoplock Control, which owns the audit store.
- AD/Okta/OIDC concrete implementations (interfaces are AD/Okta-ready only).
  The proxy never talks to an IdP: it authenticates *against Hoplock Control*, which is the component that federates. Nothing here changes when
  that lands.
- Target host-key pinning policy (prototype is TOFU-with-report, D7).
- Policy authoring, simulation, JIT access requests and approvals, and the
  operator/audit surface. These are the product's north-bound features and they
  live in Hoplock Control. The proxy's job is to enforce a decision and
  to explain a denial well enough to be traced (§4.3) — not to author one.
- **External-system integrations** — the push receiver, the probe providers, the
  provider registry, and the shipped Qualys and BMC Helix integrations (D15).
  The framework is Control's `ext/`; the two shipped integrations are
  Enterprise's. The proxy never learns that any of them exist.
- **The drift reconciliation feed** (§5.3). Publishing Hoplock's device changes
  for a customer's NCM or SIEM to correlate is downstream export, not a new
  subsystem: the proxy's job is to emit the device configuration-change event as
  a distinct, queryable audit kind (§7), and Control's store plus Enterprise's
  SIEM export (E7) carry it the rest of the way.
- **Credential-vault mode for scanners.** Handing just-in-time credentials to a
  scanner that then connects to the target *directly*, rather than through the
  proxy, is a plausible and much easier-to-sell deployment for Qualys — and it
  forfeits session capture, which D16 identifies as the control that makes an
  unbounded-privilege grant defensible at all. It is a separate product surface,
  not a proxy feature, and it is out of scope until that trade is deliberately
  accepted.
- **A compiled plugin SDK for device drivers** (D13). The declarative driver
  document and the subprocess contract come first; the seam is shaped so an SDK
  can be added without moving `TargetAuthenticator`.

---

## 13. Reference use cases

Three customer-shaped scenarios, recorded so a session can check its work
against them by name instead of re-deriving them. They are not phases; each is
served by several, and the phase table says which.

### UC1 — Privileged access to network and security appliances

A telco estate of ~300,000 devices — FortiGates and FortiSwitches first — that
cannot run an endpoint agent, cannot create POSIX users, and often cannot
enforce credential expiry. Operators need just-in-time privileged access with
per-session attribution, and the estate is exactly the population that gains
most from an inline enforcement point because nothing else can reach it.

Served by: D13 (method + driver layer), D14 (ladder), §5.3 (naming, expiry
posture, config-change noise), phases 0013–0014, with the device enforcement
rung in 0015–0016.

### UC2 — Machine-to-machine automation with a fixed command set

An automation host runs several distinct automations against the same targets.
Each has its own credential, its own permitted executables, and no business
holding an interactive shell. This is the use case the policy vocabulary is
sharpest on — `restricted_exec` plus `permitted_requests` without `pty-req` or
`shell` is a genuine boundary rather than a guardrail (D12) — and the one where
"one identity per automation" matters most: policy hangs off the identity, so
automations sharing a credential can only ever be given the union of their
permissions.

Two constraints belong in customer-facing docs rather than being discovered:
shell pipelines are not expressible under `restricted_exec` by design (no shell
is interposed, so a pipeline needs a vetted wrapper binary — which is also the
natural fit for a forced-command rung), and `login` is never the identity: the
codebase forbids keying decisions on it, so per-automation separation must come
from the credential.

Served by: existing D5a/D12 vocabulary, plus D17 and phases 0017–0018 once the
estate is large enough for connection-per-check to stop being viable.

### UC3 — Scanners and ticket-scoped access

A vulnerability scanner needs root, changes its command set with every content
update, and must not hold access to a target it is not currently scanning.
Legitimacy is asserted by an external system — a scan starting, a change ticket
inside its window — which Hoplock learns by push or by probe. Command policy
cannot constrain this access; time, scope, and an out-of-reach recording can.

The honest claim for this use case is *just-in-time, scoped, and recorded* —
never *filtered*. Marketing, docs, and the audit record use those words.

Served by: D15 (where the integrations live — not here), D16 (deadline, grant
context, required capture), D6/D13 for the credential, §6.4's revocation stream
for the stop path, and phase 0015 for the contract.
