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

### The register — read this first

This section is ~7k tokens and most phases need two or three of its entries.
The register says what each decision settles, **whether it still says that**,
and roughly where the plan renders it, so you can open the two that matter
instead of reading nineteen. It is an index, not a substitute: a decision you
are about to build on, argue with, or amend is read in full below.

The **Status** column is the part that is expensive to discover by reading,
because an amendment lives *inside* the entry it amends — D13 has been amended
three times and you only learn that several hundred words in.

| D | Settles | Status | Mainly in |
| --- | --- | --- | --- |
| **D1** | Target is encoded in the SSH username (`alice#host`); ProxyJump rejected, with reasons | confirmed | §6.1 |
| **D2** | The proxy originates no policy: Control decides, once per connection, enforced locally | live — **D17 proposed amending it and was withdrawn** | §6.4 |
| **D3** | Control is a separate component; this repo owns the contract and ships a mock | live | §3, `api/` |
| **D4** | Both auth planes are pluggable interfaces over an identity/claims model | live | §4.1, §4.2 |
| **D5** | Generic channel passthrough first, inspection pipeline later | live, **widened by D5a** | §6.2 |
| **D5a** | Policy has three axes (channel types, in-channel ops, destinations), not one | amends D5 (0006) | §6.2, §6.3 |
| **D6** | Ephemeral just-in-time target users, created and removed per session | live | §5.1 |
| **D6a** | Two credential methods, chosen by the **server** per route | amends D6 (0006), **amended by D14** | §5.1, §5.2 |
| **D7** | Host-key policy comes from the server; TOFU in the prototype, every new key reported | live | §6.4 |
| **D8** | Logs batch to Control; security events go on a **priority path**; disk is a buffer only | live | §7 |
| **D9** | Go ≥1.26, `x/crypto/ssh`, YAML bootstrap, JSON/HTTPS API | live | §8 |
| **D10** | Proprietary, all rights reserved; per-file SPDX headers | live | §8 |
| **D11** | A hop is reached over a connection the **downstream** proxy opened | new (0008) | §6.1 |
| **D12** | "Enforced" is a claim about the **boundary**, not about interception | new (0010), **amended by 0018** — §6.5 is where it landed | §6.3, §6.5 |
| **D13** | Ephemeral **accounts on devices**, through a per-platform driver seam | new (0013), **amended three times**: 0014 (persistence may be declared), 0015 (declarations must be decisions), 0017 (a declaration carries its reasoning) | §5.3 |
| **D14** | The server sends an ordered **ladder** of credential methods; first satisfiable wins | amends D6a (0013) | §4.2, §5.3 |
| **D15** | External authorization context (tickets, incidents, scan windows) belongs to Control | new (0018) | §6.5 |
| **D16** | Unbounded privilege is bounded by **time and the record**, not by command policy | new (0018) | §6.5, §4.3 |
| **D17** | Machine identities need a long-lived connection model | ⊘ **WITHDRAWN** (phase 0021, itself retired). **D2 is not amended.** Read the verdict at the head of the entry, not the argument | §9.1 |

**Two reading rules this table encodes.** An entry that says *amends* replaces
part of what it names — read both, newest first. An entry marked ⊘ is kept
because the reasoning is worth having and because other documents cite it;
nothing in the code depends on it.

**Keep this register current in the same PR that changes a decision** — it is a
live reference under `docs/PROTOCOL.md` §3, and an index that lies about a
decision's status is worse than no index.

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
- **D9 — Tech choices.** Go (min **1.26**, target latest stable). SSH plumbing:
  `golang.org/x/crypto/ssh`. Proxy bootstrap config: **YAML**. API + policy +
  log payloads: **JSON over HTTPS (REST)** for the prototype; a streaming/gRPC
  transport may be added later behind the same client interface.
  The floor is set by `golang.org/x/crypto`, which *is* this project's SSH
  implementation and so is the dependency least worth holding back: current
  releases require Go ≥ 1.26.0, and pinning an older Go pins an older SSH
  stack. The floor was 1.24 through phase 0004 and 1.25 until x/crypto v0.56.0;
  it moves when x/crypto moves it, and CI tracks the latest stable release
  rather than the floor.

  That rule earned itself in September 2026, which is worth recording because it
  is the case the rule was written for. `x/crypto` v0.55.0 drew two advisories —
  GO-2026-6354 and GO-2026-6355, denial of service on a deadlocked SSH channel —
  reachable from both ends of this proxy: `proxy.Server.handleConn` and
  `target.sshAdminDialer.Dial`. The fix ships only in v0.56.0, which requires Go
  1.26. Holding the floor at 1.25 would have meant holding a known-vulnerable SSH
  stack in an SSH proxy, which is precisely the trade this decision says not to
  make.
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

  **Where** either mode is enforced is a separate question, and **phase 0018
  answered it** (§6.5). Both tiers above are enforced *in the proxy, at the
  `exec` request*, so both stop meaning anything the moment a route permits an
  interactive shell — which this decision says in as many words. The ephemeral
  method (D6, §5.1) creates the account, writes its `authorized_keys`, and
  chooses its shell, so on those routes the same policy can be enforced by sshd
  and the kernel instead, where it also survives a connection that never went
  through a proxy.

  **As amended (phase 0018).** The enforcement story is a **ladder**, not a
  line, and which rung a route stands on is a policy decision that belongs to
  the PDP (D2) — exactly as the credential method does (D6a). Four things
  follow, and each is a decision rather than an observation:

  - **There are two ladders, not one.** "What a session may run" and "what it
    may reach" are separate questions with separate mechanisms, and only the
    first is what D12 was about. An account that can run exactly `uptime` and
    `cat`, and can also open a socket to anything in the estate, is a pivot
    point wearing an allow-list. The contract names a rung on each axis
    independently (`enforcement.execution`, `enforcement.reach`), and §6.5
    surveys both.
  - **Denying the interactive shell is itself an enforcement point, and it is
    free.** It needs nothing of the target, nothing installed, and no new
    mechanism: the axis has shipped since 0006 (D5a axis 2). A route permitting
    `exec` but not `shell`/`pty-req` turns restricted exec from "a boundary for
    the commands it sees" into a boundary, full stop. It is the first rung of
    the ladder and the cheapest strong one in the table.
  - **A rung is either APPLIED or ATTESTED, and the difference is in the
    vocabulary.** An applied rung is one the proxy configures per session and
    tears down; an attested one is enforced by the target already, configured by
    somebody who is not this product — an IOS privilege level, a Junos login
    class, a per-account ACL. The proxy applies nothing for an attested rung and
    the record names who does. Attested rungs are how the appliance estate gets
    a real enforcement claim instead of "none available", and they are the only
    kind a `brokered-key` route can carry.
  - **A rung the proxy cannot provide is an outage-class denial** (§4.3), never
    a silent downgrade — D6a's rule for credential methods, unchanged and for
    the same reason. The audit record carries the rung that was **in force**,
    not the one requested.

  0019 renders the rungs; this decision is amended here rather than replaced.
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
    The noise is answered by *publishing* the changes for correlation, never by
    suppressing the device's own logging of them (§5.3).

    This decision originally added "and Hoplock's own drivers therefore never
    persist the account to saved configuration — a reload is then a free
    reaper". **Phase 0014 amended that**, because it is unsatisfiable on the
    platform this decision names as its own example. FortiOS has no runtime-only
    configuration plane: under the default `config system global` /
    `set cfg-save automatic`, the change is written to flash when the
    configuration block ends, and the alternatives (`manual`, `revert`) are
    device-wide settings governing every change on the unit rather than a
    per-command choice a driver could make. A FortiGate driver could be honest
    or it could ship.

    So the rule is now: **a shipped driver may declare `PersistsAcrossReload`
    when the platform leaves it no choice, and must say which platform mechanism
    forces it** (`Capabilities.PersistenceReason`), which the proxy records on
    every session that driver serves. What remains forbidden is persistence *by
    choice*, silently — the case the original rule was really written against.
    `device.CheckShipped` enforces the amended rule over the shipped registry.

    The consequence is not cosmetic and is stated here rather than buried in a
    driver: where a platform both persists the account and cannot expire it,
    **the orphan reaper is the only removal path there is** (§5.3), and the
    product's claim on such a fleet is "no standing accounts while the proxy or
    its reaper is healthy" rather than the unconditional sentence. A customer
    driver was always allowed to declare persistence; the change is that a
    Hoplock driver may too, on the same terms and with the same record.

    **Phase 0015 amended this decision again, in one place.** 0014 established
    its FortiOS facts from web-search summaries because Fortinet's sites were
    unreachable from that session, said so, and asked for a re-check.
    `docs/FORTIOS-DOC-VERIFICATION.md` is that re-check and it found the expiry
    claim wrong: `config system admin` has `set schedule`, pointing at a `config
    firewall schedule onetime` entry with an absolute end, and FortiOS denies the
    login when the window has closed. So the sentence "most device platforms have
    no equivalent" above is still true of platforms in general and **was never
    true of the platform this decision names as its example**.

    The rule that follows is about DECLARATIONS rather than about FortiOS. A
    driver declaring `EnforcesExpiry: false` is saying *this driver does not
    enforce expiry*, and it must be false because somebody decided the driver
    will not do it — with the reasoning written down — and never because nobody
    checked whether the platform could. The two are indistinguishable in the
    field and opposite in what they cost: the first is a scope decision, the
    second is a capability the estate paid for and did not get. The same holds
    for every other field in `Capabilities`.

    **Phase 0017 added the other half of that rule**, having taken the FortiOS
    mechanism 0015 declined. A declaration whose meaning a reader cannot recover
    from the bit must carry its reasoning in the struct, and there are now two
    such fields: `PersistenceReason` beside `PersistsAcrossReload`, and
    **`ExpiryMechanism` beside `EnforcesExpiry`** — required on a shipped driver
    that declares expiry, and checked by `device.CheckShipped` rather than
    trusted. `EnforcesExpiry` is one bit over platforms that do not agree on
    what it buys: OpenSSH's `expiry-time` and FortiOS's `set schedule` both
    refuse the next authentication and neither disturbs a session already open,
    while a reader of the bit alone would take the deadline to reach the live
    session. Both reasons ride on the provisioning record, so the operator reads
    the claim where the risk is taken rather than in a driver's source.

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
  0018).** Some access is legitimate only while something outside this system
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
  command policy (new, phase 0018).** A vulnerability scanner needs root and
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

- **D17 — Machine identities need a different connection model (proposed as
  phase 0021 — WITHDRAWN; D2 is *not* amended. The verdict is at the end of
  this entry; read it before the argument.)** D2's "one decision per connection" is safe because connections
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
  seconds. Phase 0020 exists to replace the arithmetic with measurement, and it
  runs first for that reason.

  **Measured (phase 0020, §9.1) — the premise does not survive in this form.**
  A connection costs this proxy ~2.6 ms of CPU and a live one ~118 KiB, so
  5,800 connections per second is a **single-digit number of proxies**: a
  deployment, not an architecture, and one that needs no change to the
  connection model. Per-check provisioning is not the wall the paragraph above
  calls it either — the constraint is per *target*, and one target sustains 58
  account cycles per second against the 0.017/s a 60-second poll of it asks for
  (§5.1). What measurement *did* find is a different problem in the same place:
  the proxy's decision cache stopped working above a fixed 4,096-entry bound, so
  the Hoplock Control request rate — the largest number in the chain — did not
  amortise across a fleet at all. Phase **0022** fixed that: the bound is
  `control.cache.max_entries`, and a proxy sized to its estate measures 2.17
  Control calls per connection at fan-out (§9.1).

  The assumption under all of it was **asked rather than measured around**, and
  answered: the health checking is over SSH, at a **five-minute** interval, with
  sixty seconds kept as a worst case. At five minutes the estate is 1,167
  connections per second — **one to two proxies** — so the connection-volume
  argument for this decision does not survive at the real interval either.

  **Withdrawn — phase 0021 evaluated this decision and did not build it.** The
  full argument is in
  `docs/learnings/0021-machine-identity-connection-model-learnings.md`; the
  three legs are:

  - **The connection arithmetic is gone** (above), and per-check provisioning
    was never the per-target wall this decision called it.
  - **The Control load that is left has a cheaper answer.** Phases **0022**
    (cache eviction) and **0023** (host-key report reuse) take 3.17 Control
    calls per connection to **1.17** (§9.1, "What the Control rate becomes
    after 0022 and 0023") without amending D2, and for every route rather than
    only machine ones. **Both are built and both figures are measured**, so
    this leg of the withdrawal no longer rests on a projection. What survives them is one `POST /v1/auth/cert` per
    check — and a persistent connection removes *that* only by not
    authenticating each check, which is §6.4's "authentication is never cached"
    rule under another name. That is a change to the security model, not an
    optimisation of it, and whoever wants it must argue it as one.
  - **The mechanism this decision proposes already exists, twice.** A
    server-owned lifetime on a policy snapshot is §6.4's `CacheHint` TTL —
    clampable down only, never up, never invented, revocation-aware and
    fail-closed — and it amortises one decision across many short connections. A
    bound on how long a single connection may hold a snapshot is 0018's
    `SessionDeadline`, enforced locally by phase **0024**, which applies to a
    multiplexed client connection exactly as it does to a human's. Together they
    are "bound the snapshot, not the connection", already contracted, with no
    standing authorization and no amendment to D2.

  So **D2 is not amended**: one decision per connection stands, and the
  connection stays short. The unit of audit stays the connection, because the
  per-channel record was a cost this change would have incurred rather than a
  requirement standing on its own.

  **What would revive it.** Not a larger estate — that arithmetic scales with
  proxies. It returns if the *authentication* rate becomes the binding
  constraint: an estate and poll interval whose one-auth-per-check floor exceeds
  what a real Hoplock Control can serve, **and** a customer willing to accept
  certificate revocation being enforced only by the revocation stream between
  snapshot renewals. That is a product decision, not a capacity one. The number
  **0021 is retired and must never be reused** (`docs/PROTOCOL.md` §6).

---

## 3. Architecture & repository layout

```
hoplock/
├── cmd/
│   ├── proxy/            # the proxy daemon (main)
│   ├── mock-control/    # reference/mock Control API for dev + CI
│   └── loadgen/          # the scale harness (§9.1); not in any gating job
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
│   ├── filter/             # command policy engine (pure logic: the three tiers)
│   │   └── inspect/        # the engine attached to the channel pipeline (SSH-facing)
│   ├── logging/            # session capture, batching, priority flush, buffer
│   └── sshtest/            # test support: in-process SSH target + key helpers
├── api/                    # API contract (OpenAPI/JSON Schema) — source of truth
├── deploy/                 # docker-compose e2e topology + fixtures
├── load/                   # load scenarios + the measurements behind §9.1
├── .github/workflows/      # CI (build, vet, test, lint, e2e, test-sshd) +
│                           #   load (manual only — it gates nothing)
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
- **`internal/filter`** — command policy engine (D5/D12); pure logic, no SSH
  types, fed by the channel pipeline. Its `inspect` subpackage is the SSH-facing
  half: the inspectors that read a command out of an `exec` request or an
  interactive stream, decide what the user is told, and emit the audit event.
  The split is what lets the tier sold as a boundary be tested exhaustively
  against the strings an attacker sends.
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

**As written down (contract v3, phase 0013).** D14's ladder is
`target_auth_ladder`, an ordered array of exactly those objects. The two shapes
are alternatives and never layers — a response carrying both is refused — and a
v2 single object reads as a one-entry ladder, so D6a's original behaviour is
what a v2 server keeps getting. Absent still means "use local config"; an empty
ladder is a **denial**, on the same absent-versus-empty rule as
`permitted_channels: []`. `ephemeral-account` adds `platform`,
`credential_kind`, and `expiry_posture` to the parameter vocabulary (§5.3), and
**`username` becomes required** on every method where the proxy names the
account it provisions (`ephemeral-user`, `ephemeral-account`, `static-key`) —
it used to default to `identity.Login`, a client-typed string that §4.1 forbids
as the basis of an authorization decision. `brokered-key` keeps its v2
behaviour, because the account it uses is a standing one an operator chose; that
its username still falls back to the login is a known gap, recorded in 0013's
learnings rather than closed there.

**As finished (contract v4.2, phase 0028).** That gap is closed: **`username` is
required on `brokered-key` too**, which makes it required on every method the
contract defines, and no account name reaches a target from `identity.Login` on
any path. The v3 reasoning for the exclusion was sound and did not reach the
code — `brokered.go` still fell back to the login when neither the route nor the
proxy's own configuration named an account — and `static-key` was worse than a
fallback: the contract required a `username` on its routes and the authenticator
never read them at all. Each method now resolves the account in a fixed order
ending in a **refusal**, outage-class per §4.3 with nothing provisioned:
`brokered-key` takes the route's `username` then
`auth.target.brokered_key.username`; `static-key` takes the route's `username`
(which it now reads, refusing an unknown parameter like every other method) then
`auth.target.static_key.username`; `ephemeral-user` takes the route's `username`
then **`identity.Principals`** — server-established, immutable per D2, and
therefore the property `Login` lacks — accepting exactly one principal and
refusing both none and several, because picking one of several would make the
order a server happened to serialise a list in into policy. `policy_version`
stays **4**: it declares what a proxy can read, and a tightening is not
expressible through it. `brokered-key` deliberately does **not** consult
`Principals` — its account is standing and shared (§5.2), so a per-identity
principal would imply an attribution the method does not provide — and no method
cross-checks a route-named `username` against `Principals`, because the PDP
naming an account is the PDP's decision and overriding it would be the proxy
originating policy (D2).

**As extended (contract v3.1, phase 0016).** `ephemeral-account` params carry an
open namespace of platform-specific fields, `device_field.<name>`, for devices
that are one unit partitioned into many — a FortiGate running virtual domains
today, a FortiLink-managed switch behind its FortiGate in 0029. The contract
checks their shape and nothing else; which fields exist is the driver's to
declare, exactly as the set of platforms is. A field the driver does not declare
is a skipped rung (D14) and never a field dropped, which is both the safety
property and the reason the revision needs no new `policy_version`. §5.3 carries
the reasoning and what it binds.

One field beside the credential travels with the route, because the estate D13
reaches needs it: **`algorithm_profile`**, a server-named preset selecting which
SSH key exchanges, host-key algorithms, ciphers, and MACs the proxy may offer on
the proxy→target leg. It is per route rather than proxy-wide on purpose — a
fleet-wide knob weakens every leg in the fleet to serve the oldest device on it
— and it is a named preset (`default`, `legacy-rsa-sha1`, `legacy-device`)
rather than an algorithm list, so it cannot be widened one identifier at a time
and the audit record names something a reviewer understands. Anything but
`default` is a weakening and emits its own audit event, on D14's sibling rule
for methods. The rung in force and the profile in force are both **audit facts,
not user-facing ones** (D14): §4.3's disclosure rule does not apply to either.

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

**A session reaching its `session_deadline` is a third case, and stretching
either branch over it would be wrong** (D16, §6.5, phase 0024). Nothing was
refused, so it is not a denial; nothing is broken, so it is not an outage — and
telling a user "this is a service problem" about a session that ended exactly as
it was authorized to sends them to open a ticket against a system that did its
job. It therefore has its own wording, on the same session-channel stderr:
a **warning** at a configurable lead time (`session.deadline_warning`,
defaulting to a minute) while there is still time to act, and at expiry a
message saying the session reached its authorized end and that **reconnecting is
the remedy** — which is true here and is the opposite of what an outage message
says. Both carry the proxy's prefix, and neither discloses the policy, who set
the deadline, or how long the route allows. The channel ends with its own exit
status (253), so a script can tell "time ran out" from the 254 a policy kill
reports. A session with no channel open is told nothing, which is the
`SSH_MSG_DISCONNECT` limitation already recorded below and not a new one.

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

**What a target owes the proxy before any of this works (phase 0025).** All
three methods below end in the proxy authenticating to the target, and a
decrypting proxy is a **single source address** to every target it fronts —
which is the deployment model, not an artefact of any one topology. A target's
per-source abuse defences are built on the opposite assumption, so
`PerSourcePenalties` (on by default since OpenSSH 9.8), `MaxStartups` and
`MaxSessions` each need a decision before a fleet goes behind this proxy;
`README.md` §"Target prerequisites" is the operator-facing version, with what
happens when they are left alone.

The proxy does not depend on that decision having been made. A credential the
target **refuses** is classified as its own failure rather than as an
unreachable host (§4.3's outage branch, with wording that names the side the
credential belongs to and nothing else), recorded as a critical audit event
naming the credential's opaque handle, and withheld after a configurable run of
consecutive rejections (`auth.target.rejection`). The breaker is keyed on
(target, method, credential) and never on the user or the route: a wrong
credential is wrong for everybody, a right one must keep working while another
is failing, and keying on the subject would hand any user who can reach a target
a way to withhold it from the next. It originates no policy (D2) on the same
test that licenses `chain.max_hops` — it can only make the proxy attempt less
than Hoplock Control authorised, never more — and a session it stops is an
outage, never a denial.

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

Since phase 0019 an **enforcement rung** (§6.5) may be rendered onto the account
between steps 2 and 4, and it extends both ends of that lifecycle. The order is
part of the guarantee rather than an implementation detail:

- provisioning creates the **account first**, so every artefact a rung leaves has
  an account to be attributed to. A residue with no account can then only be a
  session that died mid-rung — never one mid-provision — which is what lets the
  reaper remove it without waiting out a grace period;
- teardown removes the **key** first (closing the account to new logins before
  anything else is undone), then the processes, then **the packet filter rules
  BEFORE the account**, then the mount, then the account and its home, then the
  confinement directory — and it **verifies every one of them**. `useradd` reuses
  freed uids, so a uid-keyed rule that outlives its account silently attaches to
  whoever gets that uid next; phase **0027**'s non-reusing range is the other
  half of the same problem and has landed, so nothing this proxy provisions is
  handed a departed account's number — the ordering still stands, because it is
  what holds for a rule left by a session that died mid-rung and for a range an
  operator has widened onto uids something else has held;
- the orphan reaper looks for those artefacts by name — every rule carries a
  comment naming the account — so a rule, a mount, or a dispatcher whose account
  is already gone is still findable and still removed.

Robustness requirements:

- **Guaranteed teardown**: teardown runs on normal close, error, panic, and
  process signal. Provisioned sessions are tracked so an **orphan reaper** can
  clean up leftovers on startup and periodically.
- **Concurrency**: two sessions for the same username on the same target must not
  clobber each other's users/keys — use per-(user,target) coordination or unique
  ephemeral principals. These two are **not** equivalent, and the reasons the
  second was chosen are not the ones this requirement states; see *Why a
  per-session account* below.
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
  proxy from sweeping another's live sessions on a shared target; and the token
  makes each session's account unique, so two sessions for one login never share
  an account or a teardown.

  **Where the `<login>` segment comes from (phase 0028).** The route's
  `username`, or — when the route names none — the identity's `Principals`, and
  otherwise nothing: the route is refused. It is *never* `identity.Login`. The
  name is the attribution here, so a segment taken from what the user typed at
  their SSH client made the target's own audit trail mean nothing: §4.1 forbids
  keying a decision on `Login`, `Login` is not guaranteed stable across logins,
  and choosing the account is the most consequential decision the proxy makes.
  `Principals` is server-established and immutable per D2, which is the property
  that makes it an answer. Exactly one principal is used; several is refused
  unless the route names one, because picking the first would make a server's
  serialisation order into policy.
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

**Why a per-session account.** The requirement above frames concurrency as
sessions clobbering each other's teardown. That framing is the weakest argument
for unique principals and, taken alone, would not justify their cost: teardown
of a shared account is a refcount problem, and a refcount is solvable. The
reasons that actually carry the decision are these, in order:

- **The account is where per-session enforcement is rendered.** §6 and D15 make
  the enforcement rung a *per-session* choice, and phase 0019 renders it onto
  the account itself — `authorized_keys` options, shell and `PATH`, filesystem
  confinement, a session deadline. One account cannot carry two rungs. Two
  sessions with identical permissions today are not two sessions with identical
  confinement tomorrow, and retrofitting per-session accounts underneath a
  shared-account model is a rewrite, not a change.
- **A shared account is a route around the proxy.** Same uid means the second
  session can attach to the first's `tmux` or `screen` socket, signal its
  processes, and read its history and files. That is one user inheriting
  another's live terminal *without the proxy seeing a channel open* — and every
  policy claim in §6 is made about channels the proxy sees. For a product whose
  claim is per-session enforcement, sharing the account is a hole in the claim
  rather than an untidiness.
- **Attribution has to survive on the target.** `who`, `last`, file ownership,
  and the target's own auditd are where a customer correlates. Two sessions on
  one account are indistinguishable there, however well the proxy logged them.
  The account name is the join key back to the session id (§7).
- **Credential lifetime is per session.** Each account's `authorized_keys`
  carries its own `expiry-time`; one shared account is one key with whichever
  lifetime happened to land first.

**What it costs, recorded rather than glossed.** `useradd` and `userdel` run per
session and serialise on the target's account-database lock, so a busy proxy has
a **per-target provisioning ceiling that no amount of proxy capacity moves**.
Phase 0020 measured it (§9.1): **58 provision/teardown cycles per second**
against one target on flat-file NSS, flat from **two** concurrent provisioners
onward while cycle latency rises linearly — the account-database lock, and not
the filesystem, which accounts for under 2 ms of a 25.6 ms cycle. A
directory-backed NSS must be measured on its own, and the harness records which
backend a figure came from. For scale: a 60-second poll of one target asks it
for 0.017 cycles/s, so this ceiling binds bursts and reprovisioning storms
rather than routine polling. Account churn also means
UID churn, and a reused UID inherits ownership of anything a deleted account
left behind. Teardown deliberately does not sweep the filesystem for a departing
uid — the invariant is a property of **allocation**, not of deletion, and a walk
over a production host's filesystem at every session end would be slow,
incomplete, and a delete primitive nobody should grant. So:

**UID allocation is the proxy's, not the target's (phase 0027).** `useradd` with
no `-u` allocates out of the fleet's own range, and shadow's allocator hands a
torn-down account's uid straight back to the next caller — measured on shadow
4.13: create, delete, create, and the second account holds the first's uid.
`-K UID_MIN=…`, the flag that looks like the fix, is not one: it moves the range
searched and nothing else, and inside a dedicated range the freed uid still comes
straight back. So the uid is chosen **off-target** and passed as an explicit
`-u`, from a dedicated range (`auth.target.ephemeral_user.uid_min`/`uid_max`,
default `2000000-2999999`, above every distribution's own `UID_MAX`), **strictly
above everything the target has ever handed out**: the highest in-range uid any
account holds now, and a high-water mark recorded on the target itself under
`enforcement_base`, so the guarantee survives a teardown, a proxy restart, and a
second proxy on the same fleet.

**It does not wrap, and it fails closed.** At the top of the range allocation
refuses rather than returning to the bottom, because wrapping is the one moment
reuse becomes possible again and a warning in a log is not a boundary; the
operator's remedy is to raise `uid_max`, and every allocation past nine tenths of
the range warns so the refusal is never the first anyone hears of it. A target
whose census cannot be read, or that cannot record the uid it allocated, refuses
the session the same way — as an **outage** (§4.3, its own `provision-uid` stage),
never a denial, and with nothing provisioned. The uid is on the provisioning
audit record beside the account name, because the name is deleted at teardown and
the number is what a `find -uid` and the target's own auditd actually speak.

**Who is trusted with the floor, and who is not.** The census and the mark are
both read off the **target**, which is the party this proxy does not trust, so
everything the target says may only ever **raise** the next uid and never lower
it: the allocator takes the maximum of the mark, the census, and its own record
of what it has handed out. A target that under-reports — a mark an attacker with
root has deleted, a census missing an account — can therefore only make the proxy
SKIP uids, which is loud (the pressure warning, then the refusal), and never make
it reuse one. The mark directory is root-owned and mode 700, re-established on
every provisioning rather than inherited, so nothing short of root on the target
can lower it at all; and a root attacker there defeats this guarantee more
directly by `chown`ing the files they want inherited.

The residual is a **proxy restart**, which empties the in-process record and
leaves a fresh process with only the target's word for the floor. Closing that
needs the floor held where neither the target nor any single proxy owns it —
which is Hoplock Control, and which is a **contract change** with a cross-repo
obligation (D3). It is therefore a phase of its own rather than part of 0027, and
phase 0027's learnings carry the design sketch. Two things that sketch settles and
a future session must not re-derive: the floor may **not** ride on the authorize
response, because that decision is cacheable and a replayed floor is a lowered
one; and a **uid-block lease** per proxy per target is what keeps the invariant
without coupling provisioning to Control's availability or adding a call per
session.

Phase **0019**'s filesystem confinement is the other half: with a home mounted
`noexec` and nothing writable outside it there is nothing left to inherit, and
`rm -rf "$h"` becomes complete. Neither alone is the fix. Until a route names a
confining rung, a session can still write to `/tmp`, `/var/tmp` and `/dev/shm`,
and those files outlive it — what 0027 guarantees is that they are never
**inherited** by a later session.

The trade-off a user actually feels is different, and is accepted deliberately:
**one person in two windows cannot see their own work, and cannot reattach to
their earlier session.** "Run `tmux` on the target" is the normal answer to
that, and per-session accounts are precisely what removes it — because session
isolation and reattachability are the same mechanism seen from two sides, and
this product cannot have the first without giving up the second. A user who
needs a durable working session should be given a longer session, not a shared
account.

**Nothing detached outlives the session either, and that is the same trade-off
from the other side.** Teardown runs `pkill -KILL -u` against the session's
account, so `nohup`, `setsid`, `tmux`, `screen`, and a plain backgrounded job
all die when the session ends — whether it ended because the user typed `exit`,
because Hoplock Control revoked it, or because it reached its `session_deadline`
(§6.5, phase 0024). No residue is the design, not an omission: an ephemeral
account whose processes survived it would be a uid still running work after the
account it was attributed to is gone — and, before phase 0027 made allocation
non-reusing, possibly under a uid that had since been given to someone else.

So **work that must outlive a human's session is not a human's session.** It is
either a machine identity with its own credential and its own bounds (§13 UC2),
or a job handed to something on the target that owns its own lifecycle — a
systemd unit, a batch scheduler, a queue runner — started by an approved argv
under the session's execution rung (§6.5). Both of those are auditable as what
they are; a `nohup`ed process is a session that stopped being a session while
still holding the access one was granted.

And this is the reattachability trade-off again, from the other side. The proxy
can only record what flows through it (§7), so a process that keeps running with
nothing attached is a process producing output no capture can see. Detached
persistence and session capture are mutually exclusive *by construction*, which
is why "let them `nohup` it" is not a setting: it would silently delete the
audit trail for exactly the work that ran longest.

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

**Who the account is (phase 0028).** The route's `username`, or the operator's
`auth.target.brokered_key.username`, and otherwise the route is refused
(outage-class, §4.3). Contract v4.2 makes `username` required on this method too,
so a served route always names one and the local key answers only the v1-shaped
route that names no `target_auth` at all. Unlike §5.1 this method deliberately
does **not** read the identity's `Principals`: the account is standing and shared
across sessions by construction, so a per-identity principal is the wrong shape
for it and using one would imply exactly the attribution the bullet above says
this method does not provide.

### 5.3 `ephemeral-account` — a short-lived administrator on a device (D13)

The lifecycle mirrors §5.1 exactly — log in privileged, create the account,
install the credential, connect, remove it on teardown — and every step is
executed by a **driver** for the named platform rather than by POSIX commands.
The route names the platform; nothing is inferred from a banner.

#### What is true today — read this before the layers below

The rest of this section is **append-only**: eight `As <verb> (phase N)` blocks
recording what each phase established, several of which supersede parts of
earlier ones. Composing them costs ~8k tokens and is how a session ends up
building against a rule that was overturned two phases later. This block is the
composed answer. **It states outcomes, not reasoning** — when you need to know
*why*, or you are about to change one of these, the layer that decided it is
below and is still the authority.

**The model.** The route names the `platform`; nothing is sniffed. A driver
performs create / install-credential / remove / enumerate, and **declares** its
platform's limits as data (`device.Capabilities`) which the provisioner reads to
decide naming, posture, and refuse-or-serve in one place. An unregistered
platform is an outage-class denial, never the nearest driver.

**A limitation and a failure are not the same thing**, and the distinction is
load-bearing in both directions: *this platform cannot* (`ErrUnsupported`) makes
the ladder rung unsatisfiable and the proxy walks to the next one (D14), while
*this attempt failed* fails the session rather than degrading to a rung the
server ranked lower. Getting it backwards turns a device outage into a silent
downgrade, or a permanent limitation into a session that never connects.

**An unsupported unit shape is a denial, never a best-effort attempt.** On
FortiOS the served shapes are `disable`, `multiple` and `split-task`; a unit
whose virtual-domain line cannot be read **at all**, or that reports anything
else, is refused outage-class — and refused rather than skipped, because
skipping would answer the shape of one unit with a credential the server ranked
lower.

**Naming.** Limit ≥32 → `hl-<tag>-<login>-<token>`; 11–31 → the **login segment**
is dropped, never the reaper prefix or the uniqueness token; <11 → the route is
refused. Base36 throughout. The longest name is exactly **31** characters, which
is exactly the FortiOS schedule-name limit — an invariant with a test, because
one more character would break every device-enforced FortiOS route.

**Collisions are never adopted.** Non-existence is verified; a collision retries
with a fresh token, on a small budget, then refuses. This differs from §5.1
deliberately.

**Attribution is the log.** On a constrained platform the name carries no login,
so the account-mapping event on D8's **priority path** is the only attribution
there is — and a route whose driver declares a constrained limit is **refused**
if the proxy has no logging path at all, including its disk buffer. Route fields
and the declared caveats ride on that record too.

**Scope, and what a route may name.** A `device_field.<name>` names a
**partition** of the endpoint device (contract v3.1) — never a different device
behind it. Fields are declared per driver; an undeclared one is a **skipped
rung** (D14), never a dropped field. They ride on **creation only**: removal,
enumeration and credential installation address the same administrator table.
On FortiOS, no `device_field.vdom` means a **global** account; one means a
VDOM-scoped account, and an unknown VDOM is refused before anything is created.

**The account's authorization scope** comes from the route's
`enforcement.platform_role` on a `platform-authorized` route, and otherwise from
`auth.target.ephemeral_account.access_profile`, which is required and checked at
startup. A route naming that rung with no role is **refused**, not silently given
the proxy-wide default. The rung is satisfiable only where the driver declares
`CommandAuthorization`, and a shipped driver declaring one must also declare
`AuthorizationCaveat`. **Source-address pinning has no rung name** — it is
applied unconditionally wherever declared, on both IPv4 and IPv6, and an IPv6
source address is refused rather than rendered into an IPv4 field.

**Expiry is per route, and costs a second object where it is taken.** A driver
receives a lifetime **only** under `target-enforced` where it declares
`EnforcesExpiry`; every other route reaches it with zero. A route that asks and
cannot be served **fails** — it is never quietly downgraded. On FortiOS the
deadline is a `config firewall schedule onetime` object named after the
administrator, computed from the **device's** clock (`execute date` / `execute
time`; a unit that will not report its clock is refused), with
`expiration-days 0`. Removal deletes the **administrator first**, the schedule
second, and attempts both every time.

**Removal and sweeping.** Teardown is idempotent and unwinds exactly the nesting
the session opened. The **reaper is the primary removal path**, not a backstop,
wherever a platform persists accounts and cannot expire them — and a failed
sweep is an event on D8's priority path. `device.ResidueSweeper` is an
**optional** driver interface for the second object, swept after the account
pass under the same prefix scoping and first-seen grace period. The reaper
sweeps a device it reaches from an **endpoint**, keyed on `host:port`.

**Shipped platforms.**

| | `fortios` (FortiGate) | `fortiswitchos` (FortiSwitch) |
| --- | --- | --- |
| Name limit | **64** (documented) | **35** (assumed — undocumented) |
| `EnforcesExpiry` | **true**, `set schedule` | **false**, on a documentation *contradiction* |
| `PersistsAcrossReload` | true (`cfg-save` is device-wide) | true, same mechanism |
| Built-in profiles | three; none read-only usable by a VDOM-scoped account | **one**, `super_admin` |
| Device fields | `vdom` | **none** — the switch is its own endpoint |

A FortiSwitch is reached **directly**, at its own `host:port` with its own host
key; FortiLink is a deployment fact, not a target identity. A managing FortiGate
closing SSH on it is an ordinary unreachable device — a **retryable failure**,
not a skipped rung.

**Known gaps, carried rather than closed.** The proxy-wide `access_profile` is
one FortiOS-shaped string for every platform, so the switch driver runs with no
default when the configured value is a FortiOS built-in (phase **0036** owns the
fix). Whether FortiOS's schedule covers an **SSH** login is an inference from the
field's shape — Fortinet publishes only a GUI denial — and it is carried to the
operator through `ExpiryMechanism`. Which scope the schedule table lives in on a
partitioned unit is undocumented; the failure names the assumption.

A driver **declares its platform's constraints**, and the provisioner reads
those declarations rather than assuming Linux:

| Declaration | Why the provisioner needs it |
| --- | --- |
| Maximum account-name length | Selects the naming scheme below |
| Whether expiry can be enforced on the device | Selects the expiry posture (D13) |
| Whether account creation persists across reload | Declared truthfully by every driver; a Hoplock driver may answer "yes" only where the platform leaves no choice, and must say which mechanism forces it (D13, as amended by phase 0014) |
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

**Expiry is rarely the platform's, and on FortiOS it is now taken.** On most
platforms nothing on the device ends the account, so `target-enforced` is a
posture those routes cannot ask for and asking is a **skipped ladder rung**
rather than a downgrade. The consequence is the one above and it survives the
change below: the reaper is sized and reported as the primary removal path, not
as a crash-recovery backstop, and a sweep that fails is an event on D8's
priority path rather than a log line somebody might read.

Phase 0015 corrected the reason and left the outcome; **phase 0017 changed the
outcome**. Until 0015 this paragraph said FortiOS "has no per-account expiry
field and no schedule on `config system admin`". It has both: `set schedule`
names a `config firewall schedule onetime` entry carrying an absolute `set end`,
and FortiOS refuses the login out of window — Fortinet's KB shows the denial as
`reason="out_of_schedule"`. 0015 declined to take the mechanism, with the
reasoning under "As corrected" below; 0017 took it, under "As taken".

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

**As built (phase 0014).** The first drivers are FortiOS
(`internal/auth/target/device/fortios`), reached over a prompt/response state
machine rather than a command pipe: the platform pages by default and cannot be
told not to per session, has configuration modes with their own prompts, and
reports failure as output text with no exit status behind it. The provisioner is
`target.DeviceAccountAuthenticator`; the naming generalisation lives in
`principal.go` and produces byte-identical names on the POSIX path; the sweep is
`target.deviceReaper`; and the mapping event and sweep failures reach D8 through
`target.DeviceEventSink`, implemented in `internal/logging`. The
`ephemeral-account` and `brokered-key` ladder is walked in `target.Selector`: a
rung this proxy cannot satisfy is skipped, a failed *attempt* fails the session,
and an exhausted ladder is a clean denial.

**As corrected (phase 0015).** `docs/FORTIOS-DOC-VERIFICATION.md` re-checked
0014's ten FortiOS claims against Fortinet's own pages, from a session that could
reach them. Six held; three were wrong; one is a sound inference Fortinet does
not state; and the same reading found **multi-VDOM**, which none of the claims
covered and the driver did not handle. Three decisions came out of that, settled
with the user and recorded here because each changes what the contract means and
not only what the driver types.

1. **`EnforcesExpiry` stays false, by decision** — *superseded by phase 0017
   below, which takes the mechanism; what survives is the reasoning about what
   it costs, which 0017 pays rather than avoids.* FortiOS *can* time-bound an
   administrator — `set schedule` against a `config firewall schedule onetime`
   entry, denied at authentication. Taking it means creating and tearing down a
   **second object per session**, naming it under the scheme above (the field
   caps schedule names at 35), and teaching the reaper to sweep an orphaned one:
   a new leak class, on a customer's firewall. It also denies *login* rather than
   removing the account, so it retires neither the reaper nor
   `PersistsAcrossReload`; and whether it cuts an already-established session is
   undocumented. That is a phase, not a fact correction, and it is queued as one.
   Until it lands the declaration means "this driver does not enforce expiry".
2. **A multi-VDOM unit is detected and refused, not attempted** — *superseded
   by phase 0016 below, which administers those units; what remains of the
   refusal is a unit whose shape cannot be read at all.* On a unit
   running virtual domains the administrator table lives inside `config global`,
   a VDOM-scoped account needs `set vdom`, and the driver's `end`-unwinding is
   one level short — so 0014's sequence is aimed at a scope it cannot vouch for.
   The driver reads `get system status` when it opens a session and serves only
   `Virtual domain configuration: disable`, refusing anything else, and refusing
   equally when it cannot read the answer at all. D13's rule decides this: an
   unsupported configuration is an **outage-class denial**, never a best-effort
   attempt — and never a skipped rung either, because skipping would answer the
   shape of one unit with a credential the server ranked lower. Support is
   phase **0016**, and it owns the question phase 0029 asks again for a
   FortiLink-managed switch and phase 0018's contract has to be able to express:
   **what a target is when one device holds many.** 0016 answers it first, once,
   and the others build on that answer — which is why it was renumbered to the
   head of the queue rather than left where 0015 first parked it (§10).
3. **There is no default access profile; a route or the proxy names one.** The
   shipped default was chosen by ranking `super_admin_readonly` against
   `prof_admin_readonly`, and no Fortinet source documents the second profile at
   all — FortiOS has three built-ins, not four. What survives of the first is not
   enough for a default: it is read-only (wrong for most of §13's UC1), it cannot
   run `diagnose` from FortiOS 7.4.x, and it is the *global* read-only profile,
   so a per-VDOM account cannot use it — those "must use either the `prof_admin`
   administrator profile, or a custom profile". A privileged account's scope on a
   customer's firewall is now a decision an operator makes:
   `auth.target.ephemeral_account.access_profile` is **required**, checked at
   startup, and phase 0019 is what turns it into policy.

   **As taken (phase 0019).** The route's `enforcement.platform_role` is what a
   `platform-authorized` session's administrator is scoped to, and the
   proxy-wide setting is what every other route still gets — so it stays
   required rather than becoming optional: a route that names no rung must
   still get a scope somebody chose. A route naming the rung with no role is
   refused rather than falling back to the proxy's, because falling back would
   put a scope the route did not name behind a record saying the route chose
   one. The rung is satisfiable only where the driver declares an authorizer of
   its own (`device.Capabilities.CommandAuthorization`) — a route naming it on a
   platform that declares none is a **skipped ladder rung** (D14), not a session
   served without it — and a shipped driver that declares one must also declare
   how it **leaks by grouping** (`AuthorizationCaveat`, held by `CheckShipped`),
   which the provisioner records on every session it serves. Source-address
   pinning is unchanged and still has no rung name of its own: it is applied
   unconditionally wherever the driver declares it (§6.5).

Two smaller corrections landed with them. The administrator-name field is **64**
characters, not 35 — both clear the threshold above, so the naming scheme is
unaffected and only the stated fact was wrong. And an account "pinned to the
proxy's address" was pinned on IPv4 only: `ip6-trusthost1`..`10` are parallel
fields defaulting to `::/0`, so the driver now writes both, and refuses an IPv6
source address rather than rendering one into an `ipv4-classnet` field.

**As extended (phase 0016): a unit running virtual domains is administered, and
a target can name a partition of one device.** 0015's refusal is narrowed to
what it can still honestly refuse. Three decisions came out of it, settled with
the user, and the first is binding beyond this driver.

1. **What a target is when one device is many: the endpoint stays the device,
   and the ROUTE names the partition.** A VDOM name arrives as an
   `ephemeral-account` parameter in an open namespace —
   **`device_field.<name>`**, contract v3.1 — handed to the driver as data and
   declared per driver (`device.Capabilities.Fields`), never inferred and never
   defaulted by the proxy. The alternatives were weighed and rejected: encoding
   it in the target (`host/vdom`) overloads the one string DNS resolves, the
   host key is pinned to, the reaper sweeps and the audit record names, so one
   unit would look like several hosts that do not exist; proxy-local
   configuration contradicts §4.2's rule that the method and its parameters are
   Control's per-route decision; and a FortiOS-specific `vdom` parameter would
   have made 0029 author a second answer to the same question, which is the
   outcome the three phases were sequenced to avoid.

   **This answer is binding on 0018 and 0029.** 0029's FortiLink-managed switch
   is the same shape one level further out — the endpoint is the managing
   FortiGate, and a field names the switch behind it — and 0018's contract
   describes the namespace rather than inventing a second way to say the same
   thing. Two properties are load-bearing and neither is optional: a field the
   driver does not declare is a **skipped rung** (D14) rather than a field
   quietly dropped, which is what makes the namespace additive to a proxy that
   predates it; and the fields are **audit facts** on the account-mapping event,
   because `host:port` names the unit and not the partition, so a record without
   them cannot say what the privileged account could reach.

   What did NOT move is the reaper: it sweeps a device it reaches from an
   endpoint, and on a FortiGate every administrator lives in one global table
   whatever VDOM it is scoped to. The fields ride on creation only. A platform
   where a field selects a genuinely different managed device — 0029's switch —
   is the phase that carries them onto the other operations, on the reaper's
   terms.

2. **Both administrator scopes are served, and the field selects.** With no
   `device_field.vdom` the account is created at **global** scope through the
   `config global` wrapper — the shape phase 0014 was written for, and what a
   proxy administering a whole unit keeps getting after that unit is
   partitioned. With one, the account is **VDOM-scoped** (`set vdom`), which is
   the point of the feature. Serving only the global half would have been the
   smaller change and would have handed out the *more* privileged of the two.

   One consequence is an operator prerequisite and is stated here because it
   cannot be worked around: a per-VDOM administrator "must use either the
   `prof_admin` administrator profile, or a custom profile", and
   `super_admin_readonly` is the *global* read-only profile — so **there is no
   built-in read-only profile a VDOM-scoped account can hold**, and a customer
   who wants one builds it. The driver refuses the two documented global
   built-ins for a VDOM-scoped account rather than letting the device fail the
   sequence half way through.

3. **A VDOM the unit does not have is checked before anything is created.** The
   driver reads the unit's virtual domains (`show system vdom` in global scope)
   and refuses an unknown one as an outage-class denial (`ErrUnknownVDOM`, not
   `ErrUnsupported`, on decision 2's reasoning from 0015). The check is not a
   guarantee — a VDOM can be deleted between the read and the write — so a
   refused `set vdom` still fails the attempt; what the check buys is that a
   stale VDOM name in policy does not leave a half-created privileged
   administrator to roll back on a customer's firewall.

**Which unit shapes the driver serves, and what is still refused.** Served:
`disable`, `multiple`, and `split-task` — the last because the Administration
Guide documents per-VDOM administrators for it with the same recipe. Refused,
and this is all that is left of `ErrMultiVDOM`: a `get system status` whose
virtual-domain line cannot be read at all, and any value that is none of those
three. The teardown unwinds the nesting the session opened rather than a fixed
depth, because on a partitioned unit the administrator table is one level
deeper and a session left inside a configuration block holds an object lock
under workspace mode.

**As taken (phase 0017): a FortiGate holds its own administrator's deadline,
and it costs a second object.** Phase 0015 established the mechanism and
declined it; this phase renders it. Four decisions came out of it, settled with
the user.

1. **Denying login MEETS the bar for `EnforcesExpiry`, and the bar is now
   written down.** The field says the device ends the account's usefulness
   whether or not the proxy is alive, and the thing to compare a firewall's
   answer against is not another firewall: it is OpenSSH's `expiry-time`
   restriction (§5.1), which is what `target-enforced` has meant on the POSIX
   path since D6. That also refuses new authentications, also leaves an
   established session running, and also leaves the credential object for the
   reaper. FortiOS's `set schedule` is the same shape, so the posture is served
   rather than skipped — the contract was already written around these
   semantics.

   The decision was taken **conditional on the window closing every door into
   the account rather than one of them**, and a verification pass on a
   reachable network narrowed that condition without closing it. What is
   established: `schedule` is one field **per administrator**, in the same
   `config system admin` table as `password`, `ssh-public-key1`..`3`,
   `remote-auth` and `two-factor`, with no per-credential variant in any
   supported release — there is nowhere for an exception to be expressed. What
   is not: the only `reason="out_of_schedule"` denial Fortinet publishes is a
   **GUI/HTTPS** login, not an SSH one of either kind. So the coverage this
   rests on is an inference from the field's shape, it is carried to the
   operator on every session through `ExpiryMechanism` rather than left in a
   comment, and it remains the decisive item on the hardware list in the strict
   sense: if a public-key login bypasses the schedule, the declaration is wrong
   and comes back out.

2. **What the device does at the deadline is DECLARED, not left to the bit.**
   `EnforcesExpiry` cannot distinguish a platform that cuts a live session from
   one that only refuses the next login, and no platform here does the first.
   `Capabilities.ExpiryMechanism` carries the sentence, `device.CheckShipped`
   requires it of a shipped driver that expires accounts, and it rides on the
   account-mapping record (`expiry_mechanism`) for every session where the
   device holds the deadline — so an audit record that says `target-enforced`
   also says what that bought. Whether an already-established session survives
   its window closing is undocumented and is stated as undocumented; ending the
   SESSION at its deadline is 0024's, and was deliberately not conflated with
   ending the account's usefulness here.

3. **The schedule takes the administrator's own name, and teardown removes both
   objects.** The naming scheme above produces exactly **31** characters at its
   longest, which is exactly what `config firewall schedule onetime`'s own
   `name` field accepts — so the second object inherits the reaper prefix and
   the uniqueness token by BEING the first object's name, and it fits with
   nothing to spare. (Neither figure this phase first argued between was right:
   35 is the width of the fields that *reference* a schedule, and 32 was a
   general KB figure. A reference field is wider than the object it points at.)
   That the two limits meet exactly is now an invariant with a test on the
   naming side, because one more character of login or token would break every
   device-enforced FortiOS route. That is what makes an orphan decidable from a device read
   alone rather than from proxy state a crash would have lost. Removal deletes
   the administrator **first** and the schedule second, because the platform
   refuses to delete an object something still references — and it attempts both
   on every removal, since neither teardown nor the reaper knows which posture
   created what it is removing.

   The new leak class is swept rather than accepted. `device.ResidueSweeper` is
   an **optional** driver interface — most platforms have no second object and
   pay nothing — and the reaper calls it after its account pass, under the same
   prefix scoping and the same first-seen grace period, because a schedule is
   legitimately unreferenced for one round trip while another session is
   creating it.

4. **A route that asked for a device-held deadline is the only route that gets
   one.** The provisioner hands a driver a lifetime only under the
   target-enforced posture; every other route reaches the driver with zero and
   gets the single-object session phase 0014 shipped. Rendering expiry on every
   route would put a second object on a customer's firewall nobody asked for,
   and would leave a device deadline behind a record that says
   `proxy-enforced`. A route that asks and cannot be served **fails** — the
   window is computed from the DEVICE's clock (`set end` is an absolute local
   datetime, so the proxy's clock would be wrong by the offset between them),
   and a unit that will not report its clock is refused rather than guessed at.

**What was verified afterwards, and what is still unverified.** The implementing
session could not reach Fortinet's documentation — the egress block phase 0014
hit, not the reachable session 0015 and 0016 had — so it added no new sourced
facts and built so that each guess fails loudly. A verification pass then ran out
of band and is recorded in `docs/FORTIOS-DOC-VERIFICATION.md` under claim 2. It
corrected three things in this phase: the schedule-name limit (31, above), the
clock (the device is now asked with `execute date` / `execute time`, which the
Administration Guide documents in every supported release, rather than only the
`System time` line of `get system status`, which no Fortinet page carries), and
`expiration-days`, which defaults to 3 and would have earned the customer's unit
a warning event log for every session — it is now set to 0 explicitly. It also
established that FortiOS does **not** delete an expired one-time schedule, so
the residue sweep is load-bearing rather than belt-and-braces.

Two readings remain unverified and one of them got weaker. **Which scope the
schedule table lives in on a partitioned unit** is documented nowhere, and the
two indirect signals that exist point *away* from `config global`; the code is
unchanged because there is no known-correct alternative — a global
administrator's `set schedule` would still have to resolve somewhere nobody has
written down — but the failure on such a unit now names the assumption. It stays
safe for the same reason as before: the schedule is created **before** the
administrator references it, so a schedule written where the administrator
cannot see it fails the reference and fails the attempt, rather than leaving an
administrator whose deadline the device ignores. And **whether the schedule
covers an SSH login** is decision 1's inference, which needs a unit.

**As decided (phase 0029): a FortiLink-managed FortiSwitch is its own target,
and FortiLink is a deployment fact rather than a target identity.** This phase
was written expecting the opposite, and the expectation did not survive reading
Fortinet's documentation. Three decisions came out of it, settled with the user.

1. **The premise was wrong, and the correction is the phase's main deliverable.**
   Phase 0029's prompt stated that a FortiLink-managed switch "has no
   independent administrative plane the proxy can SSH into: it is administered
   *through* its managing FortiGate", and asked for 0016's answer stretched one
   level further out — the FortiGate as endpoint, `device_field.switch` naming
   the switch behind it. What the documentation says is that **`config
   switch-controller security-policy local-access`** on the FortiGate
   configures the "allowaccess list for mgmt and internal interfaces on managed
   FortiSwitch units", and **`ssh` is in the default for both**
   (`https ping ssh`). A managed switch keeps its own SSH administrative plane
   and its own `config system admin` table; whether this proxy can reach that
   address is a routing and firewall-policy question in the customer's
   deployment, not a property of the platform.

   So the endpoint is the **switch**, at its own `host:port`, with its own host
   key — and the platform name (`fortiswitchos`) is one name for both
   management modes. This does not stretch 0016's answer; it leaves it exactly
   where it was. 0016's rule is that the endpoint stays the **device** and a
   route field names a **partition** of one device. A FortiSwitch is not a
   partition of its FortiGate: it is a separate device with its own
   administrator table, configuration and serial number. Encoding it as a field
   on another device's route would have made `host:port` name a unit the
   account does not live on — the precise failure 0016 rejected `host/vdom`
   for. **0029 therefore declares no device fields at all**, and 0016's
   statement that "a platform where a field selects a genuinely different
   managed device — 0029's switch — is the phase that carries them onto the
   other operations" is left unspent: no such platform arrived. The reaper is
   unchanged, `CreateRequest.Fields` still ride on creation only, and
   `device.Field` needs no notion of a field that selects a subordinate device.

   The alternatives, and why each was rejected:

   - *the FortiGate as endpoint with `device_field.switch`* — the shape the
     prompt asked for. Once the switch turned out to be reachable it buys
     nothing and costs the audit record: every mapping event, host-key pin and
     reaper sweep would address a device the administrator is not on.
   - *the switch as target with a field naming its managing FortiGate* —
     nothing in the driver needs to know the manager, so the field would be an
     unverifiable fact in policy that goes stale the moment a switch is
     re-homed.
   - *a platform name encoding the relationship* (`fortiswitch-via-fortigate`)
     — the management mode does not change the CLI the driver speaks, so a
     switch moved between FortiGates, or out of FortiLink into standalone,
     would change its **platform** in policy while remaining the same device
     with the same administrator table.

   **The one estate this does not serve** is a deployment that deliberately
   keeps its switches unroutable from the proxy. That case is real, it was
   queued as **0030**, and **phase 0030 withdrew it** — the answer is a
   deployment, not a product feature. See "As settled (phase 0030)" below.

2. **What is genuinely FortiLink-specific is declared, not encoded in the
   identity.** Three things, all sourced. FortiSwitchOS documents exactly **one**
   built-in access profile, `super_admin`, which "cannot be deleted or
   modified" and has access to everything including administrator management —
   so FortiOS's `prof_admin` and `super_admin_readonly` do not exist here and
   the driver refuses them before it dials, on the same reasoning as 0016's
   `checkVDOMProfile`. A managing FortiGate can close SSH on the switch through
   `local-access`, which this proxy sees as an ordinary unreachable device and
   therefore a **retryable** failure rather than a skipped rung. And the
   FortiGate has **no view of the switch's administrator table** — `config
   switch-controller managed-switch` carries no administrator fields, and
   `switch-profile`'s `login-passwd-override` overrides the built-in `admin`
   account's password only — so nothing on the FortiGate will ever reconcile
   away an account this proxy leaves behind.

   Which yields the leak class this phase names and cannot close.
   `execute switch-controller switch-action set-standalone` and
   `execute switch-controller factory-reset` both return the switch to factory
   defaults, which **destroys** an account this proxy created. Plain
   **deauthorization does not**: it removes the switch from management without
   touching its configuration. On a switch the proxy reaches directly that
   changes nothing — the reaper still sweeps it. On one it could only reach
   through its FortiGate it would strand the account beyond recovery, which is
   a second argument for the switch being its own endpoint. Phase 0030 was
   queued to answer that hazard and **answered it by not taking it on**: the
   proxy never provisions an account on a device it has no route to, so there
   is nothing to strand.

3. **`EnforcesExpiry` is FALSE, and on a contradiction rather than an absence.**
   FortiSwitchOS's `config system admin` *does* carry `set schedule
   <schedule-name>`, described as "Restrict times that an administrator can log
   in. Defined in config firewall schedule." But **FortiSwitchOS has no `config
   firewall schedule`** — its CLI reference puts `config system schedule
   onetime`, `... recurring` and `... group` under `config system`, and carries
   no firewall schedule table anywhere. The field exists and the table its own
   description names does not, and which table it resolves against is unstated.
   Declaring true on that would claim a deadline the driver cannot establish the
   device honours, which is the one thing phase 0017 said the bit must mean. So
   a route asking for `target-enforced` on this platform is a **skipped ladder
   rung** (D14), the reaper is the primary removal path here exactly as this
   section describes for every platform that cannot expire an account, and
   resolving the contradiction needs a real unit.

   `PersistsAcrossReload` is **true**, for FortiOS's reason and with the same
   evidence: `config system global` / `set cfg-save {automatic | manual |
   revert}` exists here too, so `end` writes to flash under the default and the
   alternatives are device-wide.

   One figure is **not** documented and is flagged as an assumption:
   FortiSwitchOS's CLI reference gives `config system admin`'s `<admin_name>`
   no size at all. The driver declares **35** — the naming-rules KB's general
   "most name fields accept 35 characters", which is the conservative reading
   and is exactly the reasoning that made 35 *wrong* for FortiOS, used here for
   the opposite reason. It clears this section's threshold of 32, so a switch
   administrator gets the readable naming scheme and no behaviour turns on it.
   `internal/sshtest`'s fake switch enforces the same number deliberately, so
   the fake is exactly as strict as the claim.

**As settled (phase 0030): an unroutable switch is a DEPLOYMENT question, and
the phase queued to answer it in the product is withdrawn.** 0029 named the one
estate its answer does not serve — a deployment that deliberately keeps its
FortiLink management subnet unroutable from the proxy — and queued 0030 to
administer those switches *through* their managing FortiGate. That phase was
withdrawn before any of it was built. Nothing here changed; what follows is the
reasoning, so that no future session re-derives it.

**Two deployments already serve that estate, and neither needs a mechanism.**

1. **Put a proxy where it can reach the switch.** 0029's `fortiswitchos`
   platform then administers it with everything the ephemeral model promises:
   the switch's own `host:port` and host key, its own short-lived
   administrator, its own reaper sweep, and `set ssh-public-key1` usable as the
   session credential. A proxy is a process, not an appliance — §9.1 measures
   one at 2.6 ms of CPU and 118 KiB of RSS per connection — so an additional
   proxy inside a management segment is a deployment decision of the kind this
   product already expects an operator to make for geo-routing (D1).
2. **Administer the switch from a FortiGate session.** The operator takes an
   ordinary `fortigate` route to the managing FortiGate and reaches the
   switch's CLI from inside that session with `execute switch-controller ssh`.
   On that path the FortiGate administrator **is** ephemeral, the session is
   captured, and the FortiGate's own access profile decides whether
   `execute switch-controller ssh` may run at all — §6.5's `platform-authorized`
   rung, doing exactly what it says on the device that holds the route.

   **What that path does not provide, stated rather than implied:** the switch
   login uses the switch's **own standing credential**, which Hoplock does not
   broker, rotate, or remove. So the product's claim on option 2 covers the
   FortiGate leg and stops there, and an estate that wants no standing
   credentials on its switches takes option 1. (The inner CLI rides inside the
   captured FortiGate session and is therefore recorded; what does not reach it
   is the proxy's `exec`-level filtering, for §6.5's ordinary reason — an
   interactive shell — and not for a FortiLink-specific one.)

**What building it would have cost, which is why neither deployment is the
lesser answer.** Four things, and the first is on its own decisive:

- **A second ephemeral account on a customer's firewall, per switch session**,
  with its own teardown, its own orphan class and its own reaper bookkeeping.
  That is a new leak class on the highest-value device in the estate, taken on
  in order to reach a lower-value one.
- **The nested hop is password-only.** FortiOS's outbound client is documented
  as a "Simple SSH client" with no identity-file parameter, no client key store
  and no forwarding, so `set ssh-public-key1` — the stronger credential kind,
  and the one connecting directly keeps usable — is unavailable on exactly the
  path that is hardest to audit.
- **Deauthorization strands, and nothing sweeps it.** Plain deauthorization
  removes a switch from management without touching its configuration, and the
  FortiGate has no view of the switch's administrator table, so on a switch
  reachable only through its FortiGate the proxy loses its only route to an
  account it is responsible for and nothing on either device reconciles it
  away. A leak class with no sweep is a leak (D13, and the reasoning
  `device.ResidueSweeper` exists for).
- **A per-channel reach preamble on the data path of every session.**
  `ProvisionedAccess` hands back an `*ssh.ClientConfig`; driving
  `execute switch-controller ssh` and answering its password prompt before the
  user's bytes flow needs a seam that runs per channel, in front of §6.2's
  inspection pipeline and §6.3's filtering. That is new machinery in front of
  every session this proxy serves, to serve one topology.

**And it would have answered "what is a target" a second time, against 0029.**
The same physical switch may be routable from one proxy and not from another,
so an endpoint or platform identity that depends on which proxy is asking is
policy that cannot be authored once in Hoplock Control — which is what D2
requires of it. 0016's rule is left standing exactly as 0029 left it: the
endpoint is the device the proxy connects to, and a route field names a
**partition** of that device, never a different device behind it.

**One consequence for the driver seam.** 0016 wrote that "a platform where a
field selects a genuinely different managed device — 0029's switch — is the
phase that carries [the fields] onto the other operations". 0029 left that
sentence unspent because no such platform arrived, and **it stays unspent**:
`device.CreateRequest.Fields` ride on creation only, `device.Field` needs no
notion of a field that selects a subordinate device, and the reaper still
sweeps a device it reaches from an endpoint. A future phase that introduces
such a platform picks that work up; there is none queued, and nothing in the
tree is waiting for it.

**What would revive this.** Not a request to reach a switch — both deployments
above do that. It comes back for a customer whose management subnet genuinely
cannot host a proxy **and** who will not accept a standing credential on the
switch for the FortiGate path, because that is the only combination neither
option serves. Write it as a **new, higher-numbered prompt**; the number
**0030 is retired** (`docs/PROTOCOL.md` §6).

**A note on the proxy-wide access profile, which is now under-specified.**
`auth.target.ephemeral_account.access_profile` is one value for every platform
a proxy serves, and it is FortiOS-shaped: the built-ins most estates have
configured do not exist on a FortiSwitch. The switch driver is therefore built
with **no default profile** when the configured one is a FortiOS built-in — a
state the driver already supports, in which a route naming its own scope
(`enforcement.platform_role`, §6.5) is served and a route relying on the
proxy-wide default is refused, outage-class, with nothing provisioned. The two
alternatives were both worse: passing it anyway means `set accprofile` refused
half way through a sequence that has already created the administrator, and
refusing at startup means every FortiGate-only deployment stops booting the day
this driver ships over a platform it does not serve. A per-platform default is
the real answer and belongs to whichever phase next touches that setting.

**As written down (phase 0013).** The contract half is in §4.2 above: the
`ephemeral-account` method, its four required parameters, and the ladder that
lets a PDP rank it above or below a standing credential. The Go half is
`internal/auth/target/device` — a `Driver` interface covering the four
operations above (create, credential, remove, enumerate), the `Capabilities`
struct carrying the declarations this section tabulates, and a registry keyed on
the contract's `platform`, for which an unregistered platform is an
outage-class denial and never the nearest driver. Declarations are **data**: a
driver states them and the provisioner reads them, so that the decisions above —
which naming scheme, which posture, refuse or serve — are made in one place
rather than inside each driver. `Driver` is also the shape the declarative
driver document and the subprocess contract (D13) become implementations of,
rather than a second seam beside it. Phase 0013 ships **no driver** and nothing
that connects; the invariant that a Hoplock-shipped driver may not declare
`PersistsAcrossReload` is a test over the shipped registry rather than a comment
on the field.

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
target, the cap in force, and — since phase 0024 — the **session deadline the
chain resolved** (§6.5). The next hop records it, forwards the trail to Hoplock
Control as `conn.hop_trail`, takes the earlier of the deadline and its own
authorize answer, and refuses the session when:

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
empty one. The deadline it now carries is the same kind of thing: it can only
ever shorten a session, never lengthen one, so a forged value costs its sender
the session. A hop whose build does not understand the field refuses the request
outright rather than dropping it, which fails closed — an unbounded chained
session is the outcome worth refusing a hop over.

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

    `permitted_forwards` governs what may be tunnelled **through SSH
    channels**, and nothing else: a process the session starts on the target
    opens its own sockets and never touches a channel. What a session may
    *reach* is therefore a second axis with its own rungs (§6.5), and this
    field is the weakest of them.
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
  There are two layers of registration, because there are two sources of an
  inspector's knowledge: a **proxy-wide** registry built from config and shared
  by every session, and a **per-session** layer for inspectors carrying a
  policy that is per connection (D2) — command filtering is one, so its engine
  is compiled from the route and registered into a clone of the proxy-wide
  registry for that session alone. An inspector can allow, flag, mutate, deny,
  or **terminate** (deny and end the session, phase 0010's `kill_session`); the
  session teardown is the transport's to perform, never an inspector's.

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

All three tiers are enforced **in the proxy, at the `exec` request**. *Where*
that claim is enforced is the separate question §6.5 answers, and the reason
this section's guarantees stop at the proxy's own front door.

**How each tier behaves in the code (phase 0010).** The engine is
`internal/filter` — pure logic, no SSH types — and `internal/filter/inspect`
attaches it to the pipeline as two inspectors on the `session` channel:

- **The exec inspector enforces.** A blocked command is delivered as the
  channel's OWN failure — the request is answered affirmatively, the reason goes
  to the channel's stderr, and the channel ends with a non-zero exit status —
  because a false reply to the request makes a client print its own generic
  error and stop reading, losing the sentence PLAN §4.3 requires. That is the
  one place command policy differs from the request axis (D5a axis 2), which
  refuses the *request* and is correctly answered with a protocol-level refusal.
  `kill_session` tells the user and then ends the whole session, the same path a
  revocation takes. `warn_and_continue` writes a proxy-prefixed notice and lets
  the command run.
- **The user is told THAT policy stopped them and nothing else.** Never the
  pattern, the mode, the permitted executables, or which tier decided. The
  operator-authored `message` on a rule is the only policy-derived text a user
  sees, and the server owns keeping internals out of it.
- **Restricted exec parses, and refuses anything it cannot parse into exactly
  one argument vector.** Quoting and quote removal are modelled; every shell
  metacharacter is refused outside single quotes — including the globbing
  characters, which are inert to the parser but not to the target: sshd hands an
  exec string to the user's login shell, so an approved `*` is a `*` the target
  expands. A policy that means a literal glob writes it quoted.
- **The interactive tier reports and nothing else.** It reassembles lines from
  the client's keystrokes (backspace, `^U`, `^C`, and ANSI escape sequences are
  handled; anything cleverer is not), records what policy would have said with
  `enforced=false`, and never denies a request, never ends a session, and never
  writes a byte to the stream — a warning injected into a raw-mode terminal is
  itself corruption, and a command already typed cannot be un-typed. Enforcement
  on an interactive route is restricted exec, or the target-side enforcement
  points phase 0018 opens; it is never this.

**The audit event (D8, consumed by 0011).** Every decision worth recording —
a rule matched, or the command was blocked, warned about, or killed the session
— emits one `command.policy` event with `priority: immediate`, carrying `tier`,
`guarantee` (`enforcement` | `guardrail` | `audit_signal`), `action`, `outcome`,
`enforced`, the command, and the operator-only `detail` naming what decided.
Until 0011 ships the batching/priority transport these go to the proxy log as
one line each, with the same field names; 0011 changes where they go, not what
they are called.

---

### 6.4 Policy caching & session revocation (D2)

The authorize+route response is a **per-connection policy snapshot**, not a
per-action question: it carries the route, the channel allow-list, and the whole
filter policy, and the proxy enforces all three locally. Nothing on the data
path talks to Hoplock Control.

Setup, however, is not amortised: each connection costs ~3 sequential round
trips (authenticate, authorize, host-key report), paid again per hop on a chain.
Phase 0020 measured that as **3.17 Control calls per connection** uncached and
**2.17** on a cache hit — a hint removes the authorize call and nothing else —
and found that the client-side cache stopped working above a fixed 4,096-entry
bound, which is why UC2's fan-out got almost no benefit from it (§9.1).

Phase **0022** answered that half without touching anything above: the bound is
now `control.cache.max_entries` (default **32,768** lookup paths, at a measured
~1 KiB each), and a full cache **evicts its least recently used entry** instead
of refusing the new decision. Who owns a decision's lifetime did not change.
Sizing that setting to the estate is what makes the fan-out hit rate follow the
working set; eviction is what stops a cache filled by a cold sweep from
refusing everything that comes after it (§9.1, "The decision cache under
fan-out").

Phase **0023** took the largest item out of the residue 0022 leaves. The
host-key report ran once per connection unconditionally and its answer was never
reused, which made it **46% of the 2.17 calls that survive a cache hit** — a
proxy reconnecting to a target it has seen ten thousand times reported the same
key ten thousand times and asked for the same answer every time. It is now
reusable on **the same mechanism as an authorize decision and no other**: an
optional `cache` hint on `HostKeyReportResponse` (contract 4.1), the server's
opaque key and lifetime, the same revocation stream, the same fail-closed rule,
and the same table and bound. Absent hint means report every connection, exactly
as before. Measured: **2.17 → 1.17** calls per connection (§9.1).

What makes that safe is the shape the proxy keys the reuse on, and it is not
negotiable by any hint: **target, port, and the key's fingerprint**. A target
presenting a key the server has not ruled on is a different lookup, misses, and
is reported — so the man-in-the-middle, the rotated key and the rebuilt host all
still reach Hoplock Control on the first connection that sees the new key, which
is the case D7 exists for. Two answers are never reused whatever the server
hints: a `reject` (as revocable as an accept, and a security event the server
must keep seeing) and a first sighting (`known: false` — recording the key has
already changed the server's own answer, and replaying it would put "first use"
into the audit log for every later connection). A subject-scoped
`cache_invalidate` does not touch host-key entries, because a host-key decision
is not made for a subject; withdrawing that trust is what the decision's own key
and `resync` are for.

**What it costs an operator sizing the cache:** a server hinting both decisions
gives a proxy **two lookup paths per connection** instead of one, and they share
`control.cache.max_entries`. An estate that sized that setting to its target
count under 0022 covers half as many targets under 0023, and the setting's name
does not say so. `CacheStats` reports host-key reuse apart from authorize reuse
for the same reason: one number mixing them cannot say which call an estate is
paying for.

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

### 6.5 Where policy is actually enforced (D12 as amended, phase 0018)

§6.3's three tiers are all enforced **in the proxy, at the `exec` request**, so
all three stop meaning anything the moment a route permits an interactive shell.
This section is the survey that answers the question D12 left open — *where* a
claim is enforced — and the vocabulary Hoplock Control uses to choose per route.
It sits here rather than inside §6.3 because half of it is not about commands at
all: the second axis is about what a session may **reach**, which §6.2 is the
nearest relative of. Phase 0019 renders what is named here; nothing in this
section is enforced yet.

The columns are the four things a reviewer has to be able to audit for each
candidate: what it **guarantees**, what it does **not**, what the **target must
already provide**, and **how it fails**.

#### Axis 1 — what the session may execute

| Candidate (where it runs) | Guarantees | Does not guarantee | Target must provide | How it fails |
| --- | --- | --- | --- | --- |
| **Pattern rule list**, filtered exec (proxy, per `exec` request) | Every `exec` string is seen before it runs, and an audit event names what matched | Anything. `sh -c`, any interpreter, a base64 pipe, or an editor escape passes a pattern (D12) | Nothing | **Silently**, by a command the pattern did not describe. The session continues and the record says "allowed" |
| **Restricted exec**, argv-parsed (proxy, per `exec` request) | A parsed vector must be covered completely by a named executable and argument shape; nothing unnamed runs, and no shell re-expands what was approved | Anything about a session that was permitted `shell` or `pty-req` — there is then no request to parse. Nor anything about a connection that did not come through this proxy | Nothing | **Closed**, at the request: an unparseable or uncovered command is denied and recorded |
| **Denying `shell`/`pty-req`** (proxy, per in-channel request; D5a axis 2, shipped 0006/0009) | The session can obtain no interactive terminal, so every command it runs is one the proxy decided. It is what makes the row above a boundary rather than a boundary-for-what-it-sees | Anything about a connection made around the proxy; the account itself is unchanged | Nothing | **Closed**, at the request, with the reason on the channel (§4.3) |
| **`command=` / `ForceCommand` dispatcher** in the ephemeral `authorized_keys` (target, sshd, per connection) | Every login on that key runs one named program, whatever the client asked for, **including a login that never went through this proxy**. The requested command arrives as `SSH_ORIGINAL_COMMAND` for the dispatcher to vet | Anything about what the dispatcher then does. It is a program somebody writes, and it is the whole boundary | An sshd that honours `authorized_keys` options, and the dispatcher binary or script | **Closed** if the dispatcher is default-deny; **wide open** if it passes `SSH_ORIGINAL_COMMAND` to a shell, which is the classic mistake |
| **`restrict` key options** — no pty, agent, port or X11 forwarding (target, sshd) | The key cannot obtain a pty, an agent, a forward, or X11, whatever the proxy or client asks | Which commands run. It is a capability fence, not an allow-list | An sshd new enough for `restrict` (OpenSSH 7.2+); older ones need each `no-*` option named | **Closed** at authentication for the fenced capability; an unknown option in `authorized_keys` makes OpenSSH **refuse the key**, which is an outage rather than a widening |
| **Restricted shell + curated `PATH` directory** (target, shell) | The account's interactive shell refuses `/`-containing commands, redirection, and `PATH` changes, so it runs only what the curated directory holds | Much. `rbash` is a hardening measure with a long history of escapes, and any interpreter in the curated directory ends it | A shell supporting the mode, and a curated directory the account cannot write | **Silently**, through any list entry that can spawn a shell |
| **Per-session `noexec`/`nosuid` home, or a mount namespace** (target, kernel) | The session cannot execute a binary it wrote, and cannot gain privilege through a setuid file it placed | Which of the system's own binaries it runs | A kernel and a mount the provisioner controls; per-session isolation needs the account to be per-session, which §5.1 makes it | **Closed** at `execve`. Its failure is an operational one: a home that was not mounted with the flags leaves no trace in the session record unless the rung is verified |
| **systemd sandboxing** — `ProtectSystem=strict`, `ProtectHome=`, `NoNewPrivileges=`, `SystemCallFilter=`, `RestrictSUIDSGID=` — by a drop-in on the session's `user-<uid>.slice`, or a `systemd-run` wrapper behind `command=` (target, systemd + cgroup v2) | A read-only system tree, no privilege escalation, no setuid/setgid gain, and a syscall allow-list, applied to **every process the session starts** rather than to the one it asked for | Which permitted binaries run, and nothing at all on a target that is not systemd | systemd with cgroup v2, and the ability to drop a unit file and `daemon-reload` | **Closed** by the kernel; a process hitting the filter dies with `SIGSYS`, which looks like a crash to the user unless the rung is disclosed |
| **MAC confinement** — SELinux type, AppArmor profile (target, kernel) | The strongest and most precise confinement available on Linux, and the only one that is not bypassable by a mistake in a shell script | Anything without a policy written for this estate's binaries and this product's account shape | An enforcing MAC with a policy module, plus login-to-context mapping | **Closed** by the kernel, and in practice **permissive**, because a fleet that hits denials turns the module off. The failure mode is organisational |
| **Device RBAC** — the platform's own command authorization bound to the ephemeral account: a FortiOS access profile, an IOS privilege level or parser view, a Junos login class (target, vendor, **per session**, D13) | The device's own authorizer decides, **ahead of anything the proxy could parse**, on the account this session created — and it is effective against a connection that never went through a proxy | Fineness. Vendor RBAC is **coarse and named**: the guarantee is exactly the vendor's grouping and no finer | A driver (§5.3), and a role that exists on the platform | **Closed** by the device. It **leaks by grouping**: a profile that permits diagnostics may include a command with a shell escape, and one that permits "read-only" may still include configuration write on some releases. On FortiOS specifically the built-ins are three, `super_admin_readonly` cannot run `diagnose` from 7.4.x, and no built-in read-only profile can be held by a VDOM-scoped account at all (0015, 0016) — which is why the role is **named by the route** and never defaulted |
| **Nothing** | — | — | — | Everything the session does is a policy question nobody answered |

#### Axis 2 — what the session may reach

| Candidate (where it runs) | Guarantees | Does not guarantee | Target must provide | How it fails |
| --- | --- | --- | --- | --- |
| **`permitted_forwards`, `permitted_global_requests`** (proxy, per channel open and global request; D5a axis 3, shipped) | No **SSH channel** carries traffic to a destination the route did not name, in either direction, and no listener is created on the target | **Anything a process on the target opens for itself.** A `curl`, a `psql`, a reverse shell — none of them is a channel, so the proxy never sees it | Nothing | **Closed** at the channel open, with the reason on the channel. Its real failure is being **mistaken for egress control**, which it is not |
| **`no-port-forwarding` / `restrict`** in the ephemeral `authorized_keys` (target, sshd, per connection) | The key cannot forward, **including on a connection made around the proxy** | Same gap as the row above: sshd's forwarding restriction is about SSH forwarding, not about sockets a process opens | An sshd honouring `authorized_keys` options | **Closed** at the request; an unknown option makes OpenSSH refuse the key |
| **systemd `IPAddressDeny=any` + `IPAddressAllow=`** on the session's slice (target, systemd + eBPF, cgroup v2) | Every socket **every process in the session** opens is filtered against an address allow-list, in the kernel | Names or ports. The filter is address-and-prefix only, so "the database on 5432 and nothing else" is expressible only as an address, and a policy written in hostnames cannot be rendered faithfully | systemd with cgroup v2 and BPF firewalling available to the manager | **Closed** — the connection is refused locally. It fails **open on a kernel or container without BPF firewalling**, where systemd logs a warning and proceeds, which is the case a capability probe has to catch |
| **systemd `PrivateNetwork=yes`** (target, kernel netns) | The session's processes get loopback and nothing else. The strongest reach rung and the easiest to verify | Any session that legitimately needs the network — it is all or nothing | systemd and network namespaces | **Closed**, completely. It fails by being **too strong for the route**, which is a policy-authoring failure rather than a security one |
| **Per-uid packet filter** — `iptables -m owner --uid-owner`, nftables `meta skuid` (target, netfilter) | Locally-originated traffic from that uid is filtered, with the port and protocol precision the systemd rung lacks | Anything not originating locally from that uid | netfilter reachable, and rules the provisioner may install and remove | **Closed** while the rule exists — and this rung carries a hazard of its own, below: a rule that outlives its account silently attaches to whoever gets that uid next |
| **MAC network rules** — SELinux socket classes, AppArmor `network` rules (target, kernel) | Precise, kernel-enforced, and not bypassable by a mistake in a script | Anything without a policy written for this estate | An enforcing MAC with a policy module | As on axis 1: **closed** by the kernel, **permissive** in practice |
| **The target's own ACL, role, or privilege level, pre-provisioned** (target, vendor) | What the platform already enforces for that account, against every connection, whether or not this product exists | Nothing this product configured, verified, or can change | An account already scoped by whoever administers the estate | It does not fail so much as **go unrecorded**: without an attestation, nobody can tell this rung from "none available" |
| **Trusted-host / source-address pinning** on the ephemeral device account (target, vendor, **per session**, D13, §5.3) | Only the proxy's address may authenticate as that account, which closes the account against use from anywhere else | It bounds **who may reach the account**, not what the account may reach. It is on this axis by adjacency, not by kind | A platform declaring `PinsSourceAddress`; on FortiOS both `trusthost` and `ip6-trusthost` are written, and an IPv6 source address is refused rather than rendered into an IPv4 field (0015) | **Closed** at authentication. It is applied unconditionally wherever the driver declares it, so it earns **no rung name of its own** — a rung the server may or may not choose would make an unconditional protection look optional |
| **Nothing** | — | — | — | The account can reach whatever the network lets it, and the record says nothing |

#### What the survey concluded

**`permitted_forwards` does not cover egress, and this is the most expensive
place in the product to be wrong.** It governs what may be tunnelled *through
SSH channels*. A process the session starts on the target opens its own sockets
and never touches a channel, so the proxy cannot see it, let alone deny it. An
operator reading a console that answered "can this account reach the database?"
from `permitted_forwards` would believe an answer to a different question. The
rungs that do cover it are `account-egress-restricted` and
`account-network-isolated` — and, with this proxy applying nothing,
`platform-attested`.

**systemd is the best cost-to-strength ratio in the table, and the survey says
so.** On a modern Linux fleet it is the only rung on either axis that needs no
policy module, no custom MAC, and no binary installed: it is a drop-in file and
a `daemon-reload`. It covers both axes, it applies to every process the session
starts rather than to the one it asked for, and it is verifiable from the
target's own state. Its two costs are real and are recorded rather than glossed:
`IPAddressAllow=` speaks addresses and prefixes only, so a destination policy
written in hostnames cannot be rendered faithfully; and BPF firewalling is not
available everywhere, where systemd **warns and proceeds** — which is exactly the
case the per-target capability report exists to catch before a route is
authored.

**An allow-list containing an interpreter is not an allow-list.** `find`, `awk`,
`less`, `vi`, `tar`, `python`, and most editors hand back a shell. The decision:
this is **the contract's problem as a documented rule, and Control's to enforce
at policy-authoring time — not a proxy-side refusal.** A shipped deny-list of
interpreter names in the proxy would be a blacklist masquerading as a boundary,
which is precisely what D12 rejects; it would be incomplete on the day it
shipped; and it would refuse a legitimate route over a name collision, at
connect time, in front of a user. So a rung is a claim about the **mechanism**,
bounded by the list it renders, and where that list can hand back a shell the
real guarantee is `no-interactive-shell` at best. Phase 0019 may emit a
`warn`-severity audit event when it renders a list containing a known
interpreter; it must not refuse one.

**A uid-keyed rung is part of the teardown contract.** `useradd` reuses a freed
uid, so a per-uid packet filter rule that outlives its account silently attaches
to whoever gets that uid next — a rule written for an automation becomes a rule
governing a person. Any rung keyed on uid is therefore removed by the same
teardown that removes the account, and is part of what the orphan reaper looks
for, with the same guarantee as the account itself, or it is not a rung. Phase
**0027**'s non-reusing uid range is the other half of the same problem and is
delivered (§5.1): the proxy allocates the uid, so a rule this proxy leaves behind
can no longer be transplanted onto a session it provisioned. 0019 owns the
teardown half, and it is not made redundant by that — it is what holds for a rung
whose account died mid-provision, and for a range an operator has moved onto uids
something else has held.

**Some rungs are attested rather than applied, and that is what makes appliances
reachable.** A router, a firewall, or a filer typically enforces its own command
authorization natively and permanently — IOS privilege levels and RBAC views,
Junos login classes with `allow-commands`/`deny-commands`, per-account ACLs —
configured once by the network team, not by this product. On such a target the
session's account already stands behind a boundary at least as strong as
anything a Linux rung provides, and calling that "no enforcement available"
would be false. So the ladder has two kinds of rung, and the vocabulary says
which: **applied** (the proxy configures it per session and tears it down) and
**attested** (the target enforces it already; the proxy configures nothing).

**What an attestation is worth without verification.** Nothing, unless it is
attributable — and an unverified claim in an audit record is a liability, so the
contract does not pretend. An attested rung **requires** `attestation.asserted_by`
(who says so) and `attestation.reference` (where it is written down: a
configuration baseline, a standard, a control id), and the audit record carries
both plus the fact that this system verified neither. "Trust us" and an empty
string are the same answer. Verifying an attestation — reading the device's own
configuration back and checking it — is a real feature and is **not** this
phase's; it would be a capability probe on the device driver, and the field
shapes here do not have to change for it to arrive.

**Enforcement point and credential method are coupled, conditionally.** An
applied rung needs the proxy to administer the account, which only
`ephemeral-user` and `ephemeral-account` do; `brokered-key` changes nothing on
the target by definition (D6a). Since D14 the route names an *ordered ladder*, so
the coupling is per entry rather than per route, and the decision is:

- **The rung is a property of the ROUTE**, not of each ladder entry. One policy
  stating two different guarantees would leave the audit record having to say
  which, and a record that names a rung the session did not stand on is the
  failure this whole section exists to prevent.
- **An entry that cannot carry the route's rung is a skipped rung** (D14),
  exactly as a posture or credential kind the driver cannot satisfy is. The
  proxy walks on. It never runs the session without the rung — that is the
  silent downgrade D6a forbids — and it never refuses the route because one
  entry could not carry it.
- **A route whose every named method leaves the target untouched, carrying an
  applied rung, is a contract violation refused outright.** Skipping could only
  ever exhaust the ladder there, so the policy can fail only at connect time, in
  front of a user — and a policy that can only fail at connect time is one
  Control should never have been able to author.
- **An attested rung is unaffected**, on every method. It is the point of having
  the distinction.

**Capabilities are advertised in two halves, and both fail safe.** A server
cannot sensibly choose a rung that cannot be provided, and what is available
depends on the target far more than on the proxy. The proxy's own capabilities
ride on `AuthorizeRequest` beside `policy_version` (0006's pattern); the
target's are **discovered by probing it and reported** on
`POST /v1/capabilities/report`, which takes the shape of `/v1/hostkeys/report`
(D7) because authorize happens *before* the proxy has ever touched the target.
A record that is **stale, undated, or absent** provides nothing that has to be
applied — the three are treated identically, because they mean the same thing to
anyone choosing a rung from one. What they do not affect is a rung needing
nothing of the target: the two proxy-side defaults, and an attested rung, which
nobody here applies — which is precisely how an appliance nobody can probe still
carries a real enforcement claim. The reason this is safe rather than merely
convenient is that **a report grants nothing**: the authority for a rung is the
authorize response, the proxy re-checks it against the live target when it
provisions, and the worst a stale record can cause is a refused session.

#### The rung vocabulary

Named after what each rung **guarantees**, never after its mechanism: an
operator reading an audit record must not have to know what `rbash` is, and
which mechanism a proxy reaches for is local to that proxy and belongs in this
repository's docs and its config.

| `enforcement.execution` | Guarantee | Kind | Candidates above |
| --- | --- | --- | --- |
| `proxy-inspected` | What the proxy sees at the `exec` request is what the proxy decides. **The absent-value default: today's behaviour** | applied, proxy | rows 1–2 |
| `no-interactive-shell` | The session can obtain no interactive shell or terminal, so every command it runs is one the proxy decided | applied, proxy | row 3 |
| `account-restricted` | The account can execute only the executables `restricted_exec` names, for every login to it | applied, target | rows 4–6 |
| `account-confined` | `account-restricted`, plus the session's processes cannot gain privilege and cannot execute anything the session itself wrote | applied, target | rows 7–9 |
| `platform-authorized` | The device's own command authorizer decides, under the role the route names | applied, target | row 10 |
| `platform-attested` | The target enforces its own command authorization on the account already | **attested** | — |

| `enforcement.reach` | Guarantee | Kind | Candidates above |
| --- | --- | --- | --- |
| `proxy-channel-policy` | SSH-channel forwarding is policed and nothing else. **The absent-value default: today's behaviour** | applied, proxy | rows 1–2 |
| `account-egress-restricted` | The session's own processes reach only the destinations the policy names | applied, target | rows 3, 5, 6 |
| `account-network-isolated` | The session's processes reach nothing off the host at all | applied, target | row 4 |
| `platform-attested` | The target already constrains what the account can reach | **attested** | row 7 |

`api/README.md` carries the wire half: where the object hangs, the required
parameters per rung, the refusal rules, and the audit fields. Two shapes are
worth stating here because they are architecture rather than encoding:

- **The object hangs at the top level of the authorize response, not on
  `filter_policy`.** The recommendation to hang it on `filter_policy` is right
  about the execution axis — that rung really does select *where the existing
  `restricted_exec` policy is enforced*. It is wrong about the reach axis, which
  has no policy object to attach to and must not be attached to
  `permitted_forwards`, because this survey's central finding is that
  `permitted_forwards` does **not** cover what a reach rung covers. Splitting one
  server decision across two places is how a session ends up with a record
  claiming a rung that was never applied.
- **`enforcement.permitted_destinations` reuses `ForwardDestination`'s shape and
  none of its meaning.** An operator writes one destination vocabulary; the two
  lists are never merged, and one never widens the other.

#### What this proxy actually renders (phase 0019)

The vocabulary above is named after guarantees so that an operator reading an
audit record need not know what `rbash` is. Which mechanism *this* proxy reaches
for is local to this repository, and it is written down here so that a rung's
claim can be checked against the thing that delivers it. The per-session record
carries the same answer (`enforcement_mechanism_execution`,
`enforcement_mechanism_reach`) for the session in front of you.

| Rung | Rendered on a POSIX host by | Rendered on a device by |
| --- | --- | --- |
| `account-restricted` | an `authorized_keys` **`command=` dispatcher** plus the key's capability fence (`restrict`, or the individual `no-*` options on an sshd older than 7.2). The dispatcher validates `SSH_ORIGINAL_COMMAND` against the route's own `restricted_exec` list and `exec`s the approved argv directly, never through a shell. It is also the account's **login shell**, so `su`, `cron`, and a second key land on it too. Beneath it, as a **guardrail**, the account's whole `PATH` is a curated directory of symlinks it cannot write | — |
| `account-confined` | the above, plus the home **bind-mounted `noexec,nosuid,nodev`** and every `exec` wrapped in **`setpriv --no-new-privs`**: the two things the rung's extra sentence names | — |
| `account-egress-restricted` | a **per-uid packet filter** (`iptables`/`ip6tables -m owner --uid-owner`) permitting `permitted_destinations` and rejecting the rest, on **both address families always** | — |
| `account-network-isolated` | the same filter, permitting loopback and rejecting every off-host destination on both families | — |
| `platform-authorized` | — | the platform's own authorizer, named by the driver's `CommandAuthorization` declaration and scoped by the route's `platform_role`. On FortiOS that is `set accprofile` |
| `platform-attested`, `proxy-inspected`, `proxy-channel-policy` | nothing is rendered | nothing is rendered |

Four choices in that table are decisions rather than details, and each one was
made against a candidate the survey lists:

- **The dispatcher is the boundary; the curated `PATH` is a guardrail.** Row 6's
  restricted shell is *not* used as the login shell, because a restricted shell
  refuses to execute a command name containing `/` and the dispatcher must live
  outside the home (which `account-confined` mounts `noexec`). Making `rbash` the
  login shell would refuse the dispatcher and fail every session on the rung. What
  survives of that row is the curated directory, and it is described as a
  guardrail everywhere it appears.
- **systemd sandboxing is not the mechanism for `account-confined`.** A `.slice`
  unit carries resource-control settings; `NoNewPrivileges=`, `ProtectSystem=`
  and `RestrictSUIDSGID=` are exec-context settings a slice does not carry, and
  systemd logs an unknown key and proceeds. That is precisely the
  silently-ignored directive this section says a capability probe exists to
  catch, so this proxy does not write it. `setpriv` and a `noexec` home deliver
  the same two guarantees with nothing to misread.
- **`IPAddressAllow=` is not the mechanism for the reach axis.** It speaks
  addresses and prefixes only, and a route's destinations carry **ports**. The
  packet filter renders the port; the systemd rung would have had to widen "the
  database on 5432" into "that address, every port".
- **A destination named by hostname is refused, not resolved.** A filter resolves
  a name once, at insert time, so the rule would drift from the policy it claims
  to enforce. The refusal is outage-class, and it is the same finding this
  section already records against `IPAddressAllow=`.

**Both address families are always closed.** A destination list naming only IPv4
addresses still gets an IPv6 default-reject. A rung that closes one family and
leaves the other open is the mistake phase 0015 found on the device side, and it
is not one this side repeats.

**The reach rungs bound OFF-HOST reach and loopback is not free.**
`account-network-isolated` permits loopback, because its sentence is about what
leaves the host. `account-egress-restricted` permits loopback only if the policy
names it — which is faithful to its sentence and is a real operational
constraint: a session that needs a local resolver must have one named.

**A default-REJECT on the session's own uid does not cut the session carrying
it, and nobody should "fix" the fact that it looks like it should.** This is the
first question anyone asks of the reach rungs, and getting the answer wrong in
either direction is expensive.

The rules match on `-m owner --uid-owner <the session's uid>`, and netfilter's
owner match reads the socket's `sk_uid` — which is fixed when the socket is
CREATED, from the creating process's uid. It is not the uid of whatever process
later holds the descriptor. sshd's listening socket, and the connection accepted
from it, are created by root long before sshd forks the session's child and
drops to the ephemeral account. That connection therefore carries `sk_uid` 0 for
its whole life and never matches these rules. What does match is every socket
the session's own processes open for themselves — which is exactly, and only,
what the rung is a claim about.

Both halves are pinned by tests rather than left to the reading above: the
`target-side enforcement` scenarios run a command over a session whose uid is
under a default-REJECT and get its output back, and
`TestSSHDEgressRungRefusesADestinationThePolicyDidNotName` does the same over a
connection with no proxy in the path.

**The trap this exists to prevent** is the plausible-looking repair. An engineer
who assumes the filter must be strangling the session reaches for an exemption —
`--dport 22 -j ACCEPT` before the reject — and that hole is not small: it lets a
confined session reach **any host in the estate on port 22**, which is the
pivot the reach axis exists to close (§6.5's survey opens on exactly that
scenario). There is nothing to exempt. If a session ever does die the moment its
rung is applied, the cause is elsewhere and the rule set is not where to look.

**A containerised target needs one thing a host does not.** Docker's default
AppArmor profile denies `mount` outright, before capabilities are consulted, so
`CAP_SYS_ADMIN` is necessary and not sufficient for the filesystem half of
`account-confined`. It is recorded here rather than only in `deploy/` because
the estates this product is sold into increasingly *are* containers, and the
symptom — a probe reporting `bind_mount=no` on a target that plainly has
`mount` — reads as a proxy bug rather than a host policy.

**What each rung needs of the target, and how the proxy finds out.** Every one of
these is *measured* rather than inferred from a version number, over the
management login, before anything is created: the probe installs and removes a
throwaway filter rule for a uid no account holds, bind-mounts and remounts a
scratch directory, and runs `/bin/true` under `setpriv`. `systemd` and cgroup v2
are recorded for the operator and read by no decision. The result is what
`POST /v1/capabilities/report` carries, and it is re-checked against the live
target at provisioning time — so a stale record costs a refused session and
never a session running below the rung its own record claims.

#### Session bounds (D16)

Four fields ride the same contract revision. They are not enforcement points —
they bound how long and on what grounds a session exists — and they are here
because they are fields on the same object, and a fifth contract bump for them
would have cost Control a third sync for no gain.

| Field | What it is | Absent means |
| --- | --- | --- |
| `session_deadline` | An **absolute instant** the **proxy enforces locally**, so it holds when the revocation stream is down — which is exactly when an immortal root session is least acceptable, and the reason this is not "just use revocation". An instant rather than a duration because a duration re-anchors on every hop of a chained route, silently multiplying the window. Applies to any route | No deadline (today's behaviour) |
| `require_session_capture` | The route runs only if the session is recorded, checked **before the target leg is dialled**. **Buffering to local disk counts** (§7's buffer is a resilience path, not a degraded mode), so the refusal is outage-class and triggers only when there is no path at all | Capture happens if configured, and its absence stops nothing |
| `grant_context` | Why access was granted: the external system, its reference, the window it asserted, and an `additional_context` admitting a string or an object. **Opaque to the proxy** — copied to every log record, never parsed, never matched against, never the basis of a proxy-side decision (D2, D15), and never shown to the user | No external grant context |
| `concurrency` | A per-subject and/or per-target ceiling on live sessions, enforced by the proxy against its own registry because the live count is knowable only there. Exceeding it is a **policy denial** (vague, §4.3), never an outage | Uncapped |

Reaching the deadline is **neither a denial nor an outage**: the session is
closed and the close is explained (§4.3). The two questions this section left
open — what the user is told at expiry, and whether a warning precedes it — were
answered by phase **0024**, which enforces the field: a warning at
`session.deadline_warning` before the instant, an expiry message naming the
session id and saying that reconnecting is the remedy, and exit status 253 so a
script can tell an expiry from a policy kill. The wording is §4.3's third case.

Two properties of the enforcement belong here rather than only in that phase's
learnings, because they are what make the field's *shape* the right one:

- **It is enforced locally**, on the proxy's own timer, with no call to Hoplock
  Control at any point. That is the whole reason the bound exists beside
  revocation, and it is proven end to end with Control stopped.
- **Ending a session from the proxy's side closes BOTH legs.** Credential
  teardown is deferred behind the channel pumps, and a pump blocked reading the
  target leg does not unblock when the client's side closes — nothing on the
  target end knows the client has gone. Without closing the leg, a session ended
  by the proxy keeps its account, and anything that account has backgrounded,
  for the whole remaining runtime of whatever it happened to be running. It
  applies identically to a revocation (§6.4): "the session was killed" has to
  mean the account is gone, not only the connection.
- **A chained session's deadline can only ever shorten.** The instant the chain
  resolved travels to the next hop on the `hop-trail@hoplock.io` request beside
  the trail and the hop cap, and each hop takes the earlier of it and its own
  authorize answer (`routing.ShortenDeadline`). A hop answered a *later*
  deadline than the session arrived with does not extend it — the failure mode
  an absolute instant was chosen to avoid, and one that is invisible until a
  session crosses three proxies.

#### The other three bounds, as enforced (phase 0031)

The three fields beside the deadline are enforced by `internal/proxy/bounds.go`,
both checks **before the target leg is dialled and before anything is
provisioned** — a session that reached the target and then failed one of them has
already happened. What each one is, in the class §4.3 assigns it:

| Bound | Where | Class | Absent |
| --- | --- | --- | --- |
| `require_session_capture` | Before the target leg, against the telemetry pipeline's own `Deliverable()` — **a disk buffer is a logging path**, so only a proxy with no path at all refuses | **Outage**, naming the session id: the estate cannot record, nothing the user has would help | Capture happens if configured, and its absence stops nothing |
| `concurrency` | Against the proxy's own live-session registry, counted and admitted in **one critical section** so two arrivals cannot both take the last slot | **Policy denial**, deliberately vague: the cap, the live count and the session id are all withheld and live only on the audit record | Uncapped, on both scopes independently |
| `grant_context` | Stamped by the session recorder onto every record the session makes after the decision | Refuses nothing | No external grant context |

Two properties belong here rather than only in that phase's learnings, because
they are what the bounds mean rather than how they were coded:

- **A concurrency cap is PER PROXY, and a chained session occupies one slot on
  every proxy it crosses.** The live count is knowable only to a proxy's own
  registry (§6.4) — that is why the field exists at all rather than Control
  deciding from `ConnMeta` — so what a cap of *N* bounds is *N* sessions **here**.
  It is not an estate-wide ceiling: a three-hop route under a cap of one is three
  proxies each holding one session, counted under the same subject and the same
  requested target on each. An estate-wide count would have to be asked of
  Hoplock Control per connection, which is the round trip D2's decision cache
  exists to avoid. The cap also bounds live sessions and not connection *rate*:
  sessions that end as fast as they start never reach one.
- **The grant context is carried in a form that cannot be read.** D16 says it is
  recorded and never consulted, and 0018 made that structural with an AST walk
  over which packages may name the type at all. Rather than widen that list, the
  telemetry pipeline extracts what a record needs **from the authorize response
  itself** (`logging.GrantFrom`), and `routing.Route` carries a `*logging.Grant`
  — a handle with no exported field and no exported method. So between the
  contract and the recorder there is nothing to decide from, which is the rule
  expressed in the type system rather than in a comment. `additional_context`'s
  two forms stay two things: a string is one attribute, an object becomes one
  attribute per field, never flattened into one string.

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

**Implemented shape (phase 0011).** `internal/logging` has three layers, and the
seam between them is what makes each testable alone:

- A **`SessionRecorder`** turns what happened on one session into
  `control.LogRecord`s. It owns the schema — the `kind`, the `severity`, and the
  attribute keys a security team's queries are written against — and touches
  neither the network nor the disk. A nil recorder records nothing, which is how
  every capture point stays free of a "is logging configured" branch.
- A **`Shipper`** delivers them. One goroutine owns delivery; capture points hand
  it records over a channel and never block on the network, which is what lets a
  recorder sit inside the decision that blocked a command.
- A **disk buffer** catches what could not be delivered, one directory per
  session, and drains it in order on recovery.

**Severity decides the endpoint.** `critical` takes `/v1/logs/priority`;
everything else rides a batch. That is the whole rule, and it is why no capture
point has to remember which path its event belongs on. A critical record does
both halves of D8 rather than choosing between them: the delivery goroutine
flushes the in-flight batch *first* and then posts the record, so the context of
a blocked command reaches Hoplock Control no later than the block itself. What
is critical: a policy refusal (channel, request, destination, global request), a
session kill, and a command-policy decision whose action was `block_command` or
`kill_session` — whether or not it was enforced, because an interactive-tier
match that only *observed* the command someone would have been blocked for is
exactly the signal a SOC wants now (D12). A service outage is `warn`, not
`critical`: an unreachable target is not a security event, and putting every
network blip on the priority path would make the path meaningless.

**The buffer is a buffer.** While anything is owed to the server, new records
join it on disk rather than overtaking it — an outage costs latency, never
fidelity or ordering. Segments are named by a global sequence, so lexical order
is delivery order across sessions as well as within one; a priority segment
drains to the priority endpoint, because an outage must not downgrade a blocked
command to ordinary telemetry. A previous run's segments are adopted on start,
which is the crash case the buffer exists for.

**Capture is observation.** The stream recorder attaches to the `session`
channel only — a forward's audit value is its destination, recorded when the
channel opens (D5a axis 3a), not its bytes — and hands every byte straight on.
A chunk is one read off the wire, verbatim, with the offset of its first byte
and its ordinal: the ttyrec/asciinema model with the framing left to the reader,
so a replay concatenates one direction's chunks in sequence order and sleeps the
offsets. A `pty-req` writes a replay header carrying the terminal geometry.

**Redaction is structural.** No capture point is ever handed the initial-auth
password: the user authenticator returns an identity, never a credential. The
end-to-end test asserts it against every stored record *and* every byte in the
disk buffer, so the property stays structural rather than becoming a filter
somebody has to remember to apply.

**Every record says why access was granted, where anything said so.** A route
carrying D16's `grant_context` stamps it onto every record the session makes from
the authorize decision onward — the records before it, a handshake's and an
authentication's, carry less because nothing knew it yet. It is stamped in the one
function that builds a record rather than at the capture points, so "every record
for the session carries it" is a property of the recorder and not of thirty call
sites. The two events the DEVICE sink emits (`device.go`) are the exception and
not an oversight: an account-mapping event carries its session id as a field and a
sweep failure belongs to no session at all, so neither is built by a session
recorder, and the alternative — teaching `internal/auth/target` to carry the grant
— would put a policy payload in the credential plane, which is exactly what §6.5
keeps it out of.

**Every session says how it ended.** The `session_end` record carries
`end_reason`, and it takes exactly one of four values — `client_close`,
`setup_failed`, `revoked`, `session_deadline` — so "why did this session stop"
is a field an operator reads rather than an inference from which other records
happen to be present. It was added by phase 0024 for the fourth of those: an
expiry is neither a failure nor a revocation, and without a name of its own it
would have been visible only as the absence of everything else. The name is
query surface and is as load-bearing as any other attribute key.

Still out of scope: tamper-evident/append-only storage at the destination
(Section 12), and coalescing keystroke-sized chunks into fewer records.

---

## 8. Cross-cutting conventions

- **Module path**: `github.com/hoplock/proxy`.
- **Go**: min 1.26 (the `go` directive in `go.mod`); CI pins the toolchain to the
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
- **CI**: seven jobs gate a pull request (`.github/workflows/ci.yml`):
  `build-test` (`go build`, `go vet`, `go test -race`, on the go.mod floor and
  on `GO_VERSION`), `lint` (`golangci-lint`), `openapi` (validates
  `api/control.yaml`), `license` (per-file headers), `e2e` (Section 9),
  `test-sshd`, and `govulncheck`. See D9.

  An **eighth** workflow, `load`, exists and deliberately gates nothing: it is
  `workflow_dispatch` only. A load run (§9.1) is neither fast nor
  deterministic, and a hosted runner's throughput varies enough between runs
  that gating a pull request on it would report the runner rather than the
  proxy. It is in the repository so a run is reproducible by anyone, not so it
  can fail somebody's PR.

  **`test-sshd` runs the tests that only a real sshd and a real kernel can
  answer**, against the `deploy/target/` container with **no proxy in the
  path**: whether sshd honours the `authorized_keys` options an enforcement
  rung writes for a connection made around the proxy (§6.5), whether a per-uid
  packet filter really refuses a destination the policy did not name, and
  whether a freed uid hands the next session anything the last one stood
  behind. Those tests skip cleanly when the container is absent — which is what
  keeps `go test ./...` green on a machine without Docker — so without this job
  the skip is permanent and the strongest claim in §6.5 is untested. It is
  separate from `e2e` rather than a step inside it because the two answer
  different questions, and a reviewer should not have to open a log to learn
  which one broke.

  **`govulncheck` is a gate rather than a periodic chore because of what this
  project's dependency tree is.** `golang.org/x/crypto/ssh` is not incidental
  here — it is the proxy's SSH implementation, and its advisory rate is high:
  the v0.44.0 → v0.55.0 bump alone crossed 15 fixed advisories, around six of
  them server-side DoS and panic issues in `x/crypto/ssh` itself, landing in
  exactly the paths §6 builds on. It runs `govulncheck ./...` with the default
  symbol-level analysis, so it reports only vulnerabilities **reachable** from
  this module's code and does not cry wolf about packages the proxy never calls
  into. It **can go red with no code change**, when a new advisory lands against
  a dependency already in `go.mod`: that is the intended signal, and the answer
  is to upgrade, or to record an explicit dated justification — never to delete
  the job. It needs network access to `https://vuln.go.dev`, which some
  development sandboxes deny with an opaque 403, so `make vulncheck` reports
  that case as a skip and the check is deliberately absent from
  `docs/PROTOCOL.md`'s Definition of Done. CI is where it must pass.

---

## 9. Test topology (answer to Q21)

**Yes — the full topology fits inside one GitHub Actions runner** using Docker
containers on shared Docker networks (`docker compose` in `deploy/`), no
external infrastructure required. It is the prototype's acceptance gate: the
scenario suite in `test/e2e` drives it and the `e2e` CI job runs both on every
pull request. `deploy/README.md` is the operator's guide to it.

| Node role           | Container                                      |
| ------------------- | ---------------------------------------------- |
| Hoplock Control     | `cmd/mock-control`, fixture-driven             |
| User (SSH client)   | a thin image running a real OpenSSH client     |
| Proxy (direct)      | `cmd/proxy` reaching the target itself         |
| Proxy (next-hop)    | `cmd/proxy` reaching the target only by chaining |
| Target (sshd)       | an `sshd` image with the mgmt cert and a standing appliance account |

The compose file runs **two** containers in the downstream-proxy role, because
the two hop connection directions (D11) make incompatible demands on one:
`dial` needs a downstream that accepts an inbound connection, and the entire
point of `relay` is a downstream that accepts none. `proxy-zone` is that second
one — no published port, its SSH listener bound to loopback inside its own
container, and the route that reaches it names an address that cannot resolve,
so a relayed session that arrives has provably travelled over the registration
it opened outbound. A relay scenario run against a proxy that does listen would
prove nothing.

The networks are load-bearing, not decoration. The user node is not on the
target's network, so "the target is reachable only through a proxy" is a
property of the topology; and the next-hop proxy is not on it either, so a
chained session that reached the target cannot have been served locally.

The suite covers both hop directions, all three policy axes (D5a), both
credential methods (D6, D6a), both exec tiers (D12), the four match actions,
loop and hop-cap refusal, both branches of the disclosure rule (§4.3), and the
telemetry pipeline including outage buffering and drain (D8). Since phase 0026
it also covers **both user authentication methods** — `proxy-direct` offers
`password-mfa` beside `cert`, and the MFA scenarios drive keyboard-interactive
with a real client — and **two sessions provisioning on one target at once**,
observed overlapping in the target's own account database rather than assumed
(§5.1).

Real geo/anycast/scale testing needs real infrastructure and is **out of scope**
for the prototype; the compose topology validates behavior, not distribution.
Sizing is §9.1, measured by a synthetic harness that is deliberately not this
topology.

---

### 9.1 Measured scale and sizing (phase 0020)

D17's numbers are arithmetic. These are not. `cmd/loadgen` (see
`load/README.md`) drives real SSH connections through the real proxy binary,
run as a child process, against an instrumented Hoplock Control and a cheap
in-process target, and samples the proxy from `/proc`. Raw output is in
`load/results/`, reproducible from the scenario files in `load/scenarios/`.

**Every figure below is labelled measured or derived, and a derived one carries
its arithmetic.** That distinction is the point of the phase: what this section
replaced read like measurement and was not.

**Hardware.** One Intel Xeon @ 2.10GHz, **4 logical cores**, 16 GiB RAM, Linux,
Go 1.26. The load generator, the stand-in target and the proxy share those four
cores — which bounds what these numbers can claim; see "What these numbers
cannot say".

**Load shape.** One SSH connection, one `exec`, one close: the UC2 health-check
shape D17 argues about. The credential is `static-key`, which provisions
nothing, so establishment cost is not confounded by a credential method.
Provisioning is measured separately below, because it saturates a *target*
rather than a proxy.

#### What a connection costs a proxy

| Figure | Value | |
| --- | --- | --- |
| Connect latency (TCP + SSH handshake + auth), p50 / p99 at 100 conn/s | 2.6 / 3.6 ms | measured |
| Connect latency, p50 / p99 at 600 conn/s | 6.3 / 16.2 ms | measured |
| Proxy CPU per connection, at 600–900 conn/s | **2.6–2.9 ms** | measured |
| Establishment rate sustained | **716 conn/s** | measured — a **floor** |
| Establishment rate, CPU-bound | ~1,500 conn/s per proxy on 4 cores | derived: cores ÷ CPU-seconds per connection |

**What saturated: CPU.** At 900 conn/s offered, 716 were achieved and p99
connect latency reached 49 ms. Nothing else was near a limit — the proxy held
**121 descriptors** of a 20,000 soft limit and 12 OS threads, and this run's
Control answered in tens of microseconds. Descriptors, Control latency and CPU
are reported separately in every run because the three have different fixes.

Per-connection CPU *falls* as offered rate rises (5.9 ms at 100 conn/s, 2.6 ms
at 900) because the proxy's fixed costs — the revocation subscription, log
shipping, GC — amortise. Size on the busiest step; the idle-proxy figure
describes nothing.

#### What a live connection costs

| Figure | Value | |
| --- | --- | --- |
| RSS per live connection | **118 KiB** | measured: 2,000 held connections, 186 plateau samples |
| Descriptors per live connection | **2** | measured: 4,011 for 2,000 connections |
| Proxy baseline RSS, idle | 11.7 MiB | measured |
| Concurrent connections at a 1 GiB budget | ~8,800 | derived: (budget − baseline) ÷ RSS per connection |
| Concurrent connections at a 4 GiB budget | ~35,400 | derived |
| Concurrent connections at a 16 GiB budget | ~141,800 | derived |

#### What a connection costs Hoplock Control

This is the number the sibling repository is sized by.

| Figure | Value | |
| --- | --- | --- |
| Control calls per connection, **uncached** | **3.17** | measured |
| — `POST /v1/auth/cert` | 1.00 | measured |
| — `POST /v1/authorize` | 1.00 | measured |
| — `POST /v1/hostkeys/report` | 1.00 | measured |
| — `POST /v1/logs/batch` | 0.17 | measured, at `batch_size: 64` |
| Control calls per connection, **cache hit** | **2.17** | measured |

§6.4's "~3 sequential round trips" is confirmed exactly. What is worth noticing
is the other two. A cache hint removes the authorize call and **nothing else**.
Authentication is never cached by design, but the host-key report is neither a
decision nor cached: a proxy reconnecting to a target it has seen ten thousand
times reports the same host key ten thousand times. At **46% of the residual
2.17 calls** it is the largest remaining item rather than a rounding error, and
phase **0023** proposes the fix.

Log shipping scales with `logging.batch_size`, so 0.17 is a configuration
rather than a property: roughly 11 records per session at 64 records per batch.

#### The same table after phase 0023

Phase 0023 built that fix, and re-measuring is how it is shown rather than
claimed. Two scenarios differing in **one knob** — `control.host_key_cache_hint`
— on the hardware named above, 100/300/600 conn/s, one subject, 32 targets,
10 s warmup, 20 s measured per step.

| Figure | 02, authorize hint only | 09, both hints | |
| --- | --- | --- | --- |
| Control calls per connection | **2.173** | **1.173** | measured |
| — `POST /v1/auth/cert` | 1.000 | 1.000 | measured |
| — `POST /v1/hostkeys/report` | 1.000 | **0.000** | measured |
| — `POST /v1/logs/batch` | 0.173 | 0.173 | measured |
| authorize cache hit rate | 100% | 100% | derived |
| host-key cache hit rate | 0% | **100%** | derived |
| proxy CPU per connection | 2.85 ms | 2.75 ms | measured, at 600 conn/s |

The 02 column reproduces the 2.17 measured before this phase to three decimal
places on the same hardware, which is what makes the 09 column a comparison
rather than two unrelated runs. `01-establishment.yaml` (no hint at all) remains
the 3.17 baseline both are read against.

What is left at 1.173 is `POST /v1/auth/cert` at 1.000 and `POST /v1/logs/batch`
at 0.173 — an authentication, which §6.4 never caches by design, and a
configuration (`logging.batch_size`). **The Control load of a connection is now
one authentication.**

The host-key report reaching zero rather than something small is a property of
the run, not a claim about production: the warmup sweeps every target past its
first sighting before the measured window, and only a key the server has already
ruled on is hinted. A real estate pays one report per (target, host key) after
each proxy restart and one more whenever a key changes — which is the report D7
is actually about.

#### The decision cache under fan-out (UC2), before phase 0022

**These are the pre-0022 figures and they are kept as the baseline.** What the
same runs measure against the code that ships today is the subsection after
this one; the finding below is what made that change.

One subject, a working set of distinct targets, a fixed 250 conn/s, and a
warmup long enough to sweep the whole set before measuring — so a miss means a
miss and not a first visit. Two runs: the server issuing a key per
(subject, target), and the server issuing **one** key covering every target the
subject may reach, which is the widest sharing §6.4 permits.

| Distinct targets | Hit rate, key per target | Hit rate, one shared key | |
| --- | --- | --- | --- |
| 512 | 100% | 100% | measured |
| 2,048 | 100% | 100% | measured |
| 4,096 | 100% | 100% | measured |
| 8,192 | 59% | 59% | measured |

At 8,192 targets both runs made **exactly 4,096 authorize calls**:
`internal/control`'s `DefaultMaxEntries`, to the entry. The cache holds the
first 4,096 request shapes it sees and then refuses every further decision —
`store` drops a new entry when the table is full rather than evicting an old
one, so there is no eviction policy at all. Over a full sweep the hit rate is
therefore `MaxEntries / N`.

| Derived from that relationship | Value | |
| --- | --- | --- |
| Hit rate at UC2's 300,000-target estate | **~1.4%** | derived: 4,096 ÷ 300,000 |
| Control calls per connection at that hit rate | ~3.16 | derived: caching removes ~1.4% of one call |

**The two runs being identical is the finding.** A server sharing one key across
every target buys nothing, because the proxy's *shape* map — the
(subject, login, target, port, method, hop trail) lookup that finds the key — is
bounded by the same constant as the entry table. No server-side key choice can
reach this; the limit is in the proxy. The bound is also not settable from
`config.yaml`. Phase **0022** carries the change; phase 0020 measured and did
not fix.

#### The same runs after phase 0022

Same scenarios, same hardware, same 250 conn/s and 40 s warmup; the only
difference is a proxy carrying 0022, whose cache holds **32,768** lookup paths
by default and **evicts the least recently used** one when full.

| Distinct targets | Key per target | One shared key | Before, either | |
| --- | --- | --- | --- | --- |
| 512 | 100% | 100% | 100% | measured |
| 2,048 | 100% | 100% | 100% | measured |
| 4,096 | 100% | 100% | 100% | measured |
| 8,192 | **100%** | **100%** | 59% | measured |

Zero authorize calls at every step: the working set now fits, which is the
whole of what a bigger, settable bound buys. Control calls per connection at
8,192 targets go from 2.58 to **2.17** — §6.4's cached figure, reached at a
fan-out where it previously was not.

**What it costs, measured from the process rather than the heap.** At 8,192
targets the proxy's peak RSS went from 25.6 MiB (holding 4,096 entries) to
33.2 MiB (holding 8,192) on the key-per-target run: ~1.7 KiB of RSS per cached
entry against the 1.0 KiB of live heap `BenchmarkCachedEntryFootprint`
measures, the difference being GC headroom. The shared-key run grew by 0.5 KiB
of RSS per target instead, because one decision serves all of them and only the
lookup path is per target — the first measurable benefit a server gets from
sharing a key widely.

| Derived from those figures | Value | |
| --- | --- | --- |
| Heap at the default bound, full | ~32 MiB | derived: 32,768 × 1.0 KiB |
| Entries needed for UC2's 300,000-target estate | 300,000 | stated: `control.cache.max_entries` |
| Heap at that setting, full | ~300 MiB | derived: 300,000 × 1.0 KiB |

**Eviction is not a substitute for sizing, and the harness says so.**
`08-uc2-fanout-evicting.yaml` pins `max_entries` back to 4,096 and reruns the
sweep: 100% at 4,096 targets, and **0%** at 8,192 — against the 59% the same
bound gave before 0022. A strict cycle over a working set larger than the cache
is the worst case for LRU, which evicts each entry roughly one visit before it
is wanted, where refusing to store held whichever 4,096 shapes arrived first.
The trade is deliberate and is stated here rather than buried: eviction is what
keeps a **changing** working set cached at all — a cache filled by a cold sweep
used to refuse everything that came after it, permanently — and the fix for a
working set larger than the cache is to size the cache, which before 0022 was
not something an operator could do. `CacheStats.Evicted` is how a running proxy
says the bound is too small; `Expired` says the TTLs are too short.

#### What `ephemeral-user` costs a target (§5.1)

This is the one measurement here that is not per proxy. `useradd` and `userdel`
take the target's account-database lock, so however many proxies front a host,
the host's account churn rate is what it is.

Measured on flat-file NSS (`passwd: files`), run locally with no SSH leg: the
management logins are a *proxy* cost and are counted above; what this isolates
is the target-side serialisation.

| Figure | Home + key | Account DB only | |
| --- | --- | --- | --- |
| `useradd` | 12.0 ms | 11.0 ms | measured |
| `authorized_keys` write | 0.1 ms | — | measured |
| `userdel` | 13.5 ms | 12.7 ms | measured |
| **One serial cycle** | **25.6 ms** | **23.7 ms** | measured |
| **Per-target ceiling** | **58 cycles/s** | **62 cycles/s** | measured |
| Concurrency at which throughput plateaus | 2 | 2 | measured |
| Mean cycle latency at 32 concurrent | 509 ms | 494 ms | measured |

**What saturates: the target's account-database lock, not the filesystem and
not the NSS backend.** Dropping the home directory and the key write changes the
serial cycle by 1.9 ms and the ceiling by four cycles per second — the account
operations themselves are essentially the whole cost. Throughput is flat from
**two** concurrent provisioners through thirty-two while mean cycle latency
rises 26 ms → 509 ms, roughly linearly: a queue in front of a lock, not a
resource that more of would relieve.

**A directory-backed NSS will not behave like this.** These figures are for flat
files. A fleet on LDAP or SSSD must re-run
`load/scenarios/06-provisioning-ceiling.yaml` on such a host before quoting a
ceiling, and the harness records the backend in every result for that reason.

**What that means for D17.** A 60-second poll of one target asks that target for
**0.017 cycles/s** against a measured ceiling of 58. Per-check provisioning is
not the per-target wall D17 describes. What it does cost is ~26 ms of
target-side latency plus the management SSH legs on *every* check — a real
per-connection cost, and a good argument for `brokered-key` or a longer-lived
credential on machine routes, but not the impossibility claimed.

#### What it implies for a 350,000-target estate

Derived throughout, from the measured figures above, on the hardware named
above. Each row assumes one connection per check and no concurrent checks
against one target.

| Poll interval | Connections/sec | Proxies at the measured floor (716/s) | Proxies at the derived ceiling (~1,500/s) | Control req/sec, uncached |
| --- | --- | --- | --- | --- |
| 60 s — *worst case* | 5,833 | 9 | 4 | 18,500 |
| **5 min — the real interval** | **1,167** | **2** | **1** | **3,700** |
| 15 min | 389 | 1 | 1 | 1,230 |

The five-minute row is the one to size against; see "The assumption, now
answered" below for why, and why the sixty-second row is kept anyway.

Per 1,000 targets at a 60-second poll: **16.7 conn/s** and **53 Control
requests/sec** uncached — 36 with a cache that worked, which today it does not
at this fan-out.

**The conclusion D17 draws does not follow from these numbers.** A single-digit
proxy fleet is a deployment, not an architecture: it needs no change to the
connection model, no standing authorization, and no new audit granularity. The
Control request rate is the larger number and the one to design against — and it
is exactly where the cache finding bit, because at a 1.4% hit rate it did not
amortise at all. Phase 0022 turned that hit rate into a question of sizing
`control.cache.max_entries` rather than a fixed ceiling.

#### What the Control rate becomes after 0022 and 0023

Derived from the measured call table above, at the five-minute row's 1,167
connections per second. **0022 and 0023 are both now built**, so both of their
rows are measured per connection rather than projected. This is the comparison
phase **0021** was weighed against before being withdrawn (D17), and it has held
up: the projection it was weighed against is what the code now measures.

| Model | Control calls per check | Control req/s at 1,167 checks/s | |
| --- | --- | --- | --- |
| Before 0022, at UC2's fan-out (hit rate ~1.4%) | ~3.16 | ~3,690 | derived |
| With **0022** — the cache works at fan-out, sized to it | **2.17** | ~2,530 | measured per connection (above); req/s derived |
| With **0022 + 0023** — host-key decision reused too | **1.17** | **~1,370** | measured per connection (above); req/s derived |

**Both rows are now measured.** The last one was a projection when this table
was written; phase 0023 built it and the run is the table above
("The same table after phase 0023"), which landed on 1.173 against the 1.17
projected here.

What is left at 1.17 is `POST /v1/auth/cert` at 1.00 and `POST /v1/logs/batch`
at 0.17. The second is a configuration (`logging.batch_size`), not a property.
The first is authentication, which §6.4 never caches by design, because an MFA
approval is a per-session assertion and certificate validation is where
revocation is enforced.

**So after 0022 and 0023 the Control load for UC2 is one authentication per
check** — which is what a system whose security claim is "every access is
authenticated against the PDP" ought to cost. Driving it lower means
authenticating less often, which is a security argument and not a capacity one.

One caveat carries from 0022 and is sharper now: an estate reaches 1.17 only
while its working set fits `control.cache.max_entries`, and a server hinting
both decisions makes each connection cost **two** lookup paths. UC2's
300,000-target estate needs 600,000 entries, ~600 MiB at the measured ~1.0 KiB
each, to hold both — twice what the 0022 row above implies.

#### What these numbers cannot say

- **The generator, the target and the proxy share four cores.** Every achieved
  rate here is a **floor** on what the proxy can do. The ceiling is derived from
  the proxy process's own CPU-seconds per connection and assumes perfect core
  scaling, which is why it is labelled derived and is roughly twice the floor.
- **One in-process target answers for the whole fleet.** The fleet is the
  distinct target *names*, because that is what the cache keys on. Nothing here
  says what a connection costs a real target — except the provisioning
  measurement, which is about targets and says so.
- **Hoplock Control was on loopback** and answered in tens of microseconds. A
  real PDP is a network hop and a database away. `control.latency` in a scenario
  injects a stated delay for the run that asks that question; these runs did
  not.
- **This is one machine.** Re-run the scenarios on the hardware you intend to
  deploy before quoting any of this as a capacity plan.

#### The assumption, now answered

Everything above sizes the model D17 assumes: connection per check, over SSH,
every sixty seconds. Whether that describes a real estate is a question for the
customer rather than for a benchmark, so phase 0020 asked it rather than
measuring around it.

**Answer: the health checking is over SSH, at a five-minute interval.** The
sixty-second figure is retained as a **worst case**, not as the design target.

That makes the **5-minute row the one to size against**: 1,167 conn/s,
**one to two proxies**, and ~3,700 Hoplock Control requests per second — a
single deployment on hardware no larger than the box these numbers were taken
on. The 60-second row stays in the table because a worst case worth naming is
worth sizing, and because a poll interval is the kind of thing that changes
without anyone re-reading this section.

Two consequences follow. 0021's author started from them, and they are why that
phase was withdrawn rather than built (D17):

- **The connection volume argument for D17 is gone at the real interval.** One
  to two proxies is not a reason to change the connection model, and at the
  worst case it is still single digits.
- **The Control request rate is what is left.** 3,700 req/s at the real
  interval uncached. It is the number that did *not* amortise, because the
  decision cache did not work at this fan-out — phase 0022 fixed that, and a
  proxy whose `control.cache.max_entries` covers its estate measures 2.17 calls
  per connection there (see above), or ~2,530 req/s.

#### Other findings from the harness

None of these were fixed here — this phase changes no behaviour.

- **The host-key report is per connection and never cached** (see the call
  table above). A proxy reconnecting to a known target re-reports the same key
  every time, so it is a third of the residual Control load after caching. It is
  a *report* rather than a decision, so §6.4's caching rules do not cover it and
  a change would be a contract question.
- **A few connections fail with an EOF during `exec` under overload — and the
  evidence says that is the harness, not the proxy.** Reproduced across
  ~118,000 connections at 900 conn/s offered with the proxy's full log
  captured: for a failing connection the proxy logs **nothing** unusual, every
  session it starts has a matching end bar those in flight when it is stopped,
  and the only proxy-side error in 397,673 log lines is `handshake failed: EOF`
  — the proxy watching a *client* vanish before the handshake completes. The
  generator, the in-process target and the proxy share four cores at that
  offered rate, so a client losing a connection is the expected cost of
  measuring past saturation. Recorded because the absence of a proxy-side error
  is evidence rather than proof: a run that sees this **below** saturation, or
  one where the proxy logs a dropped session, has something real.

---

## 10. Phased delivery

One prompt = one PR = one phase (see `prompts/queued/`). Ordering and scope:

> **The number is the run order.** Take the lowest-numbered prompt in
> `prompts/queued/` and you are taking the right one — the queued block is kept
> contiguous and in intended order immediately above the frozen implemented
> block, so no session has to be told which prompt to start (`docs/PROTOCOL.md`
> §6). The queue was renumbered for that in the run-order revision below.
>
> So: **0022** (the decision cache, **delivered**) → **0023** (host-key report
> reuse, **delivered**) → **0024** (the session deadline), then the rest by
> number, with **0037**, the contract collapse, last. The first three are
> promoted because they make an argument this plan already relies on *true*
> rather than merely written down: 0022 and 0023 are the cheaper answer that
> replaced the withdrawn 0021 (D17) — now measured, not projected — and 0024
> enforces the `SessionDeadline` that the same withdrawal leans on.

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
| 0014 | FortiOS device drivers                  | `internal/auth/target/device/fortios`: the FortiGate driver, device provisioner, device reaper, ladder walk, fake-device tests. The FortiSwitch drivers moved to 0029/0030 — a FortiLink-managed switch is administered *through* its FortiGate, which is a different target identity and a contract question, now answered first by 0016. **That last premise did not survive phase 0029**, which found a managed switch keeps its own SSH plane and made it its own endpoint; read the 0029 row. 0030, which held what was left of it, is **withdrawn** — read its row too |
| 0015 | FortiOS driver corrections              | act on `docs/FORTIOS-DOC-VERIFICATION.md`: FortiOS *does* have per-admin expiry (`set schedule`), `prof_admin_readonly` is undocumented, the name limit is 64 not 35, and multi-VDOM is unhandled. Ran first because every later phase touching a device builds on facts it corrects. The two capabilities it declined became **0016** and **0017**, which now run next |
| 0016 | FortiOS multi-VDOM support              | administer a unit running virtual domains instead of refusing it: the `config global` wrapper, `set vdom`, the depth-tracking unwind — and **the answer to what a target is when one device is many**: contract **v3.1**'s open `device_field.<name>` namespace (§5.3), which 0018's contract and 0029's switch driver both build on rather than re-answer (deferred from 0015) |
| 0017 | FortiOS target-enforced expiry          | `expiry_posture: target-enforced` is rendered onto a FortiGate through `config firewall schedule onetime` + `set schedule`: the schedule takes the administrator's name, teardown removes both objects, and the reaper sweeps an orphaned one through the optional `device.ResidueSweeper`. `EnforcesExpiry` is **true**, and what the device does at the deadline is declared beside it (`ExpiryMechanism`) and recorded on every session (§5.3, "As taken"). Settles the capability 0018's survey must advertise (deferred from 0015) |
| 0018 | Enforcement points — contract v4         | the survey of where policy is actually enforced, both axes, in §6.5 (D12 amended); the rung vocabulary Control chooses from, **applied** and **attested**; proxy-level and per-target capability advertisement (`POST /v1/capabilities/report`); and D16's session bounds — deadline, required capture, grant context, concurrency caps |
| 0019 | Target-side enforcement                 | `internal/auth/target` renders the chosen rung onto the ephemeral account — an `authorized_keys` `command=` dispatcher over the route's own `restricted_exec` list, a curated `PATH`, a `noexec,nosuid,nodev` home, `setpriv --no-new-privs`, and a per-uid packet filter on both address families — and onto a device account through the platform's own authorizer under `enforcement.platform_role`. Plus the capability probe and `POST /v1/capabilities/report`, the teardown ordering the uid hazard requires, the reaper's residue sweep, the four audit fields, and the e2e scenarios. The mechanism table is §6.5, "What this proxy actually renders" |
| 0020 | Scale harness & sizing evidence         | `cmd/loadgen` + `load/`: a synthetic load harness outside the compose topology, and the measured per-proxy ceilings, Control request rates, cache behaviour under fan-out and per-target provisioning ceiling it produced. **Results and sizing guidance: §9.1.** It refutes D17's arithmetic and finds a different problem — the cache's entry bound, queued as 0022 |
| 0021 | Machine-identity connection model       | **Withdrawn — evaluated, not built.** 0020's measurements removed the connection-volume and provisioning arguments, and the Control load that was left has a cheaper answer in 0022 + 0023 (3.17 → 1.17 calls per connection, both now measured, no amendment to D2). D2 stands; the number **0021 is retired and must never be reused**. Reasoning: `docs/learnings/0021-machine-identity-connection-model-learnings.md`, and D17 |
| 0022 | The decision cache under fan-out        | a finding from 0020, not a new idea: the authorize cache held a fixed 4,096 entries with **no eviction**, so a working set larger than that cached the first 4,096 shapes and refused the rest. **Delivered:** LRU eviction over the lookup paths (with `CacheStats.Evicted` beside `Expired`), the bound settable as `control.cache.max_entries`, and a default re-derived from a measured ~1 KiB per entry — 4,096 → **32,768**. Sizing the setting to the estate is what an operator past the default does; measurements in §9.1. No contract change |
| 0023 | Host-key report reuse                   | a second finding from 0020: with authorize caching working, `POST /v1/hostkeys/report` was 46% of the remaining Control calls, re-asking the same question about an unchanged key on every connection. **Delivered:** an optional `cache` hint on `HostKeyReportResponse` (**contract 4.1**; `policy_version` stays 4), reuse in `CachingClient` keyed on target+port+**fingerprint** so a changed key still reports (D7), a `reject` and a first sighting never reused, host-key reuse counted apart in `CacheStats`, and the measured **2.17 → 1.17** calls per connection (§9.1, scenarios 02 vs 09). Contract change — carried a cross-repo obligation |
| 0024 | Session deadline & lifetime            | enforce 0018's deadline locally, warn before it and explain it at expiry (neither a denial nor an outage), and record in §5.1 that detached work does not outlive a session. **Delivered:** a local timer armed at authorize from the instant the chain resolved (`routing.ShortenDeadline` — a hop may only ever shorten it, and the resolved instant travels on the hop-trail request), expiry through the engine's ordinary teardown, the two messages and exit status **253** in §4.3, `end_reason` on every session_end record, and the detached-work consequence in §5.1. No contract change |
| 0025 | Target credential rejection             | classify a refused proxy→target credential as its own stage, contain it with a per-credential circuit breaker, disclose and record it honestly, and document the target prerequisites a single-source-address proxy implies. **Delivered:** `target.IsAuthRejection` (the one place that knows x/crypto's wording, with a tripwire test that drives a real rejection), the `target-auth` and `target-auth-withheld` stages and their §4.3 wording, a breaker keyed on (target, method, credential handle) consulted *before* provisioning through `Selector`/`ProvisionedAccess.DialOutcome` — the seam the device drivers adopt — `auth.target.rejection` in config, two critical `error` records naming the credential's handle and never its material, and §5's/README's target prerequisites. It also queued **0033**, the same defect on the proxy→proxy leg, which it found and scoped out. No contract change |
| 0026 | e2e coverage: MFA & concurrency         | end-to-end coverage for the password+MFA flow and for two concurrent sessions provisioning on one target — the two gaps in 0012's list that are not `docs/PLAN.md` §12 deferrals. **Delivered:** `password-mfa` enabled on `proxy-direct` only and driven by a real OpenSSH client through `SSH_ASKPASS` + `SSH_ASKPASS_REQUIRE=force` (the `user` image's `askpass.sh`), with `sshBaseArgs` untouched so every other scenario is still on the certificate path; an approval, its progress lines, a denial that ends exactly as a wrong password does, and `auth_method=password-mfa` in the audit trail; and two overlapping sessions on one login whose **overlap is observed** in the target's own account database — two accounts at one instant — then removed by two independent teardowns, with the `brokered-key` mirror leaving the target byte-identical. No production code changed. It queued **0034**: the challenge itself still discloses whether the first factor was right |
| 0027 | Ephemeral UID allocation                | a dedicated, non-reusing UID range so a fresh ephemeral account never inherits a torn-down one's files; fail closed when it cannot be guaranteed (pairs with 0019's confinement). **Delivered:** the uid is the proxy's choice and travels as an explicit `useradd -u` — `-K UID_MIN=…` was measured and rejected, because it moves the range the target's own allocator searches and still hands a freed uid straight back — allocated strictly above the highest in-range uid in use **and** a high-water mark recorded on the target under `enforcement_base`, so the invariant survives a teardown, a restart and a second proxy. `auth.target.ephemeral_user.uid_min`/`uid_max` default to **2000000-2999999**, above every distribution's own `UID_MAX`. **Allocation does not wrap**: at the top of the range, on an unreadable census, or where the mark cannot be written, the route is refused as an outage on its own `provision-uid` stage with nothing provisioned, and every allocation past nine tenths of the range warns. The uid is on the provisioning record beside the account name. What is still inheritable until a route names one of 0019's confining rungs: anything a session wrote outside its home — and 0027 is what stops a *later* session inheriting it |
| 0028 | Close the login fallback                | remove every remaining use of `identity.Login` as an account name, on all methods and all paths (the row this table was missing; the prompt has been queued since phase 0013). **Delivered:** `username` is required on `brokered-key` too (**contract v4.2**, a break; `policy_version` stays 4, because it declares what a proxy can *read* and a tightening is not expressible through it), which makes it required on every method the contract defines; each of the three remaining call sites resolves the account in a fixed order ending in a refusal — `brokered-key`: route → `auth.target.brokered_key.username` → refuse; `static-key`: route → `auth.target.static_key.username` → refuse, and it now **reads the route at all**, which it never did, so the document requiring a `username` and the proxy using something else no longer disagree and an unknown parameter is refused like everywhere else; `ephemeral-user`: route → **`identity.Principals`** → refuse, taking exactly one principal and refusing none or several. Refusals are outage-class (§4.3) with nothing provisioned and no target leg dialled. `brokered-key` deliberately does not read `Principals` (its account is standing and shared, §5.2) and nothing cross-checks a route-named account against them (that would be the proxy originating policy, D2). The `Principals` doc comment, false since it was written, now describes what actually draws from it. Contract change — carried a cross-repo obligation |
| 0029 | FortiSwitchOS driver                    | the FortiSwitch driver, and the target-identity question the phase was queued to answer (deferred from 0014). **Delivered, and the answer is not the one the prompt expected:** a FortiLink-managed switch keeps its own SSH administrative plane — `config switch-controller security-policy local-access` has `ssh` in the default allowaccess for both its interfaces — so the switch is **its own endpoint** and FortiLink is a deployment fact, not a target identity. 0016's answer is left intact rather than stretched, and **no device field is declared**: `fortios.SwitchDriver` is a separate type from the FortiGate driver (so it is not a `device.ResidueSweeper` for a schedule table FortiSwitchOS does not have), reusing 0014's CLI state machine and value validation through helpers moved onto `cliSession`. `EnforcesExpiry` is **false** on a documentation contradiction (`set schedule` names a `config firewall schedule` table the platform lacks); the one built-in profile is `super_admin`, so the FortiOS built-ins are refused before dialling; the unit's identity is confirmed from `get system status` because the two platforms accept the same administrator commands. **No contract change** — `api/` untouched, so no cross-repo obligation. §5.3 carries the reasoning |
| 0030 | FortiLink-mediated administration       | **Withdrawn — decided, not built.** The estate 0029 does not serve — switches deliberately unroutable from the proxy — is served by a **deployment** rather than by a mechanism: put a proxy where it can reach the switch (0029's `fortiswitchos` then works unchanged), or administer the switch from an ordinary `fortigate` session, accepting that the switch login is then a standing credential Hoplock does not broker. Building it would have put a second ephemeral account on a customer's firewall per switch session, made the user's hop password-only, taken on a strand-with-no-sweep leak class, and put a per-channel reach preamble in front of every session — to reach a device a proxy could simply be routed to. `device.CreateRequest.Fields` therefore still ride on creation only. The number **0030 is retired and must never be reused**. Reasoning: §5.3 "As settled (phase 0030)" and `docs/learnings/0030-fortilink-mediated-administration-learnings.md` |
| 0031 | The other three session bounds          | required capture, the concurrency caps, and the grant context on the audit record — D16's remaining three bounds, which 0018 defined and no phase since had enforced (`session_deadline` is 0024's). The row this table was missing; the prompt had been queued since phase 0019. **Delivered:** all three in `internal/proxy/bounds.go`, checked before the target leg is dialled and before anything is provisioned — required capture as an **outage** on its own `capture` stage, turning on the telemetry pipeline's existing `Deliverable()` so a proxy spooling to its disk buffer still satisfies it (PLAN §7; the same predicate §5.3's device attribution uses); the caps as a **policy denial** counted against the proxy's own live-session registry in one critical section, per-proxy by construction and recorded with the ceiling that was hit, which the user is never told; and the grant context stamped by the session recorder onto every record after the decision, carried from the response in a handle with no readable surface (`logging.GrantFrom`, `routing.Route.Grant`) so 0018's AST walk needed no new package and `additional_context`'s object form reaches the record as fields rather than as one string. Plus `POST /debug/logs/sink` on the mock, which is what lets the e2e take the log destination down while authorize keeps answering. **No contract change** — every field shipped in v4, `api/` is untouched, so no cross-repo obligation |
| 0032 | Does the decision cache need an admission policy? | **Conditional — it asks a question and may answer "no".** 0022 left the cache with a cliff rather than a slope: past `control.cache.max_entries` a strict poll cycle is LRU's worst case (measured 100% at the bound, **0%** just past it, where the pre-0022 freeze gave 59%), so a fleet outgrowing its cache by 1% costs 46% more Control calls. This phase asks the four deployment questions that decide whether that matters, builds an offline policy simulator — freeze, LRU, sampled-random, SLRU, TinyLFU over uniform-cycle, hot-set, Zipf and churn traces — validated against the two measured points, and decides against criteria written before the numbers. It changes no policy: a "yes" queues the implementation, a "no" is written up and the prompt deleted (as 0021 was) |
| 0033 | Chain identity rejection                 | the defect 0025 fixed on the proxy→target leg, still live on the proxy→proxy one: `handshakeNextHop` reports a next hop **refusing this proxy's chain identity key** (D11) as *"the next proxy in the chain could not be reached"*, sending the operator to the network when the network is the part that works. Classifies it as its own stage, discloses it on §4.3's terms, and records it critically with the key's fingerprint — reusing 0025's single copy of x/crypto's wording rather than adding a second. **Conditional in one part:** whether it should also be *contained* is a question this phase must answer and write down, because the blast radius that justified 0025's breaker (an OpenSSH target penalising the proxy's source address) does not exist when the far end is another Hoplock proxy. Added by 0025 |
| 0034 | Does the MFA challenge disclose the first factor? | **Conditional — it asks a question and may answer "no", as 0032 does.** Phase 0026 drove `password-mfa` with a real client and found that the denial discloses nothing but the *flow* does: a correct password is answered with an MFA challenge and a wrong one never is, so the challenge's presence is a first-factor oracle, and its duration says the same thing more quietly. The proxy cannot fix it alone — Control decides when a challenge is issued (D2) — so the phase decides whose problem it is, whether a decoy challenge is worth what it costs in Control load and in an unclosable timing channel, and whether it belongs to the prototype at all (§12 puts a real IdP, where enumeration defences usually live, out of scope). A "yes" closes it in `api/`, `cmd/mock-control` and a scenario; a "no" is written up and the prompt deleted, as 0021 was. Added by 0026 |
| 0035 | Hold the ephemeral UID floor off the target | the residual 0027 left, raised in review on its PR: the uid high-water mark lives on the **target**, so a proxy RESTART — no attacker needed — leaves a fresh process with only the target's word for the floor, and a replaced proxy or a second proxy on one target has no continuity at all. Worse, a target that can store nothing (§5.3's devices; an ordinary Linux host with a read-only root filesystem) is refused outright by 0027 on a route that worked before it. Holds the floor at Hoplock Control as an **exclusive per-proxy uid-block lease** — which closes the multi-proxy case by construction, is safe to hold across a Control outage because the block cannot have been granted to anyone else, and costs one call per BLOCK rather than per session, so 0022 and 0023's 3.17 → 1.17 per-connection budget is untouched. The target-side mark is demoted to an optional signal that may only ever RAISE the floor, and its absence stops being an outage. **Two things it must not do, both settled in 0027's learnings:** put the floor on the authorize response (that decision is cacheable and served during a Control outage, so a replayed floor is a lowered one), and assume the proxy can write anything on the target. Contract change — carries a cross-repo obligation |
| 0036 | Per-platform access profile             | `auth.target.ephemeral_account.access_profile` is one string for every platform a proxy serves, and it is FortiOS-shaped: FortiOS documents three built-in profiles and FortiSwitchOS documents one, so a proxy fronting both estates cannot express a correct value. Phase 0029 worked around it — the switch driver is built with no default when the configured profile is a FortiOS built-in, so a route naming `enforcement.platform_role` is served and one relying on the default is refused outage-class — and queued the fix. The question is where a created administrator's scope comes from when the route names none: per-platform configuration (no contract change), a route-named default decoupled from 0019's rung (a contract change, weighed against D2), or driver-declared defaults (which 0015 explicitly refused). Must run before the collapse, because one candidate answer revises `api/` (new prompt, added by phase 0029 and raised by the user on its PR) |
| 0037 | Drop the superseded contract vocabularies | remove the support the phased build accumulated for *older* vocabularies — the superseded singular `target_auth`, the shape normalisation, the version-history prose — leaving one live vocabulary. The versioning mechanism (`policy_version`, `PolicyVersion`, the MUST-NOT-answer-above rule) is **kept**: it is how the contract evolves after release. Runs **last**: it must follow every phase that revises the contract, which now includes 0023's host-key cache hint — and its number says so, after the revisions below moved it from 0029 and, most recently, from 0036 to make room for 0029's follow-up |

Prompts may add or re-order later phases; any prompt that introduces new queued
prompts MUST preserve the numbering invariants in `docs/PROTOCOL.md`.

### Resolving a number: the composed mapping

**Read this instead of composing the notes below.** Every renumbering note in
this section is a frozen record of *one* revision, and §6 of
`docs/PROTOCOL.md` asks you to compose them when resolving an old reference.
There are now **eleven**, the chain is up to six deep, and composing it by hand
is both expensive and the kind of task nobody gets right twice. So it is
composed **here, once**, mechanically, from the mappings those notes state.
The notes stay as the record of *why* each move happened; this table is the
record of *what resolves to what*.

Only phases whose number has ever moved appear. Anything absent has held its
number since it was written. **⊘ marks a withdrawn number**, retired for good
and never reused (§6).

| Today | Previously (oldest → newest) | Phase |
| --- | --- | --- |
| **0007** | `0006` | Target credentials |
| **0008** | `0007` | Multi-hop / next-hop routing |
| **0009** | `0008` | Channel allow-list + inspection pipeline |
| **0010** | `0009` | Command filtering + policy actions |
| **0011** | `0010` | Logging & telemetry pipeline |
| **0012** | `0011` | Full E2E topology + CI gate + hardening |
| **0018** | `0013` → `0015` → `0016` | Enforcement points — contract v4 |
| **0019** | `0014` → `0016` → `0017` | Target-side enforcement |
| **0020** | `0017` → `0018` *(new at privileged-access)* | Scale harness & sizing evidence |
| **0021** ⊘ | `0018` → `0019` *(new at privileged-access)* | Machine-identity connection model |
| **0022** | `0031` | The decision cache under fan-out |
| **0023** | `0032` | Host-key report reuse |
| **0024** | `0022` → `0023` → `0025` | Session deadline & lifetime |
| **0025** | `0019` → `0020` → `0022` | Target credential rejection |
| **0026** | `0020` → `0021` → `0023` | e2e coverage: MFA & concurrency |
| **0027** | `0021` → `0022` → `0024` | Ephemeral UID allocation |
| **0028** | `0023` → `0024` → `0026` | Close the login fallback |
| **0029** | `0024` → `0025` → `0027` | FortiSwitchOS driver |
| **0030** ⊘ | `0025` → `0026` → `0028` | FortiLink-mediated administration |
| **0031** | `0030` | The other three session bounds |
| **0037** | `0033` → `0032` → `0033` → `0034` → `0035` → `0036` | Drop the superseded contract vocabularies |

**The name is the disambiguator, not the number.** Almost every number in this
repository is *both* a live phase and a historical alias of a different one —
**30 of 37** are, on today's queue. `0031` is the session-bounds prompt today
and is what the decision cache (now `0022`) was called before the run-order
revision; `0025` is target-credential rejection today and is what the session
deadline (now `0024`) was called. So a bare number in a frozen document is
genuinely ambiguous, and resolving it by number alone is guesswork.

Resolve it this way instead:

1. Take **what the citation says the phase is about**, not its digits.
2. Find that phase in the table above, or in the phase table at the top of this
   section — which remains the only current statement of what a number means.
3. Use the `Previously` column to confirm the cited number is one this phase
   actually held. If it is not, the citation means the *live* phase of that
   number.

**Two caveats, stated rather than smoothed over.** The contract collapse
(`0037`) really did move to `0032` and back to `0033` — the run-order revision
promoted it, and the admission-policy phase pushed it out again; that is churn,
not a transcription error. And some pre-run-order documents call it **`0029`**,
an alias no recorded renumbering explains, so it is listed here as attested by
the run-order note rather than derived. Every other chain in the table was
cross-checked against the notes' own explicit statements and agrees with them.

**When you renumber, regenerate this table in the same PR** — it is a live
reference under §3, and a stale composed mapping is worse than none, because it
will be believed.

---

> **Queue note (phase 0030), newest — this one is NOT a renumbering, and
> nothing below needs recomposing for it.** Phase 0030 was **withdrawn**: the
> estate it was queued for — FortiLink-managed switches deliberately kept
> unroutable from the proxy — is served by a deployment rather than by a
> mechanism, and §5.3 ("As settled (phase 0030)") carries the reasoning and
> what building it would have cost. Nothing was built and `api/` is untouched.
>
> **No prompt was renumbered**, so there is no mapping to compose. **0030 is
> retired** and must never be reused (`docs/PROTOCOL.md` §6), which makes it
> the *second* such gap after 0021; the queue is otherwise contiguous and now
> runs **0031–0037**.
>
> Two statements in the notes below were true when written and are superseded
> here rather than rewritten, on §3's rule for a historical record. The
> access-profile note says the queue is "contiguous at **0030–0037**"; it is
> now 0031–0037 with 0030 retired. The phase-0029 queue note says a reference
> to "0030" "resolves to whatever `prompts/queued/0030-…` says today" —
> **that file no longer exists**, and a reference to 0030 now resolves to this
> note, to §5.3's "As settled (phase 0030)", and to
> `docs/learnings/0030-fortilink-mediated-administration-learnings.md`.
>
> Live references updated in place: this section's phase table (the 0030 and
> 0014 rows), §5.3's "As decided (phase 0029)" block, `docs/PROTOCOL.md` §6 and
> `docs/learnings/README.md` (both named 0021 as the only retired number),
> `docs/FORTIOS-DOC-VERIFICATION.md`'s FortiLink section (which was written
> forward, for 0030 to act on), and two code comments that pointed at the phase
> as future work — `device.CreateRequest.Fields` in
> `internal/auth/target/device/driver.go` and `control.ParamDeviceFieldPrefix`
> in `internal/control/policy.go`, the second of which still described a
> managed switch as administered *through* its FortiGate and was therefore
> already stale from 0029. `prompts/queued/0030-…` was **deleted**;
> `docs/learnings/` and `prompts/implemented/` were not rewritten, and
> `docs/learnings/0029-…` carries a one-line pointer instead.
>
> **Renumbering note (the per-platform access profile), newest — compose it
> with the ones below.** Phase 0029 shipped a second device platform and found
> that `auth.target.ephemeral_account.access_profile` — one string for every
> platform — is FortiOS-shaped and simply wrong for a FortiSwitch, which
> documents one built-in profile where FortiOS documents three. It worked
> around that (§5.3, "A note on the proxy-wide access profile") and the user
> asked on its PR for the fix to be queued. Because one of its two candidate
> answers revises `api/` — a route-named default decoupled from 0019's rung —
> it must run **before** the contract collapse, so it was inserted at **0036**
> and the collapse moved **0036 → 0037**. That is the whole mapping —
> **0036→0037**, one prompt — and the queue is contiguous at **0030–0037**.
>
> Live references updated in place: this section's phase table, the collapse
> prompt's own title, number history, blocker list and hand-off paths, and the
> stale FortiOS-expiry comment on the first device route in
> `deploy/control/fixtures.template.yaml` (which phase 0015 disproved and 0017
> acted on; it now also records that **no** fixture route asks for
> `target-enforced`, so the topology does not exercise 0017's schedule path end
> to end — a pre-existing coverage gap, named rather than closed).
> `docs/learnings/` and `prompts/implemented/` were **not** rewritten and must
> be read through this mapping.
>
> **Queue note (phase 0029) — this one is NOT a renumbering.** 0029
> shipped the FortiSwitch driver its prompt asked for and settled the
> target-identity question, but against the opposite premise (§5.3, "As decided
> (phase 0029)"). That delivered what queued prompt **0030** — "Standalone
> FortiSwitchOS driver … nearly the FortiGate driver under another platform
> name" — was for, while leaving a real gap its own decision opens: estates
> that keep their switches unroutable from the proxy. So **0030 was rewritten
> in place** as the FortiLink-mediated phase rather than withdrawn or
> renumbered. **No number moved, nothing was retired, and the queue stays
> contiguous at 0030–0036** — so there is no mapping to compose here, and a
> reference to "0030" resolves to whatever `prompts/queued/0030-…` says today,
> which is the mediated path and no longer the standalone driver. Live
> references updated in place: this section's phase table and run-order
> paragraph, and §5.3.
>
> **Renumbering note (the Control-held uid floor) — compose it with the
> ones below.** Phase 0027 made uid allocation non-reusing and left the
> high-water mark on the target. Review of its PR asked why security state sits
> on the untrusted side; the answer is that the restart case, the replaced-proxy
> case and a target that can store nothing all need the floor held elsewhere,
> and that "elsewhere" is Hoplock Control. Because it revises `api/`, it must run
> **before** the contract collapse, so it was inserted at **0035** and the
> collapse moved **0035 → 0036**. That is the whole mapping — **0035→0036**, one
> prompt — and the queue is contiguous at **0028–0036**.
>
> Live references updated in place: this section's run-order paragraph and phase
> table, the run-order notes in `prompts/queued/0032-…`, `0033-…` and `0034-…`,
> and the collapse prompt's own title and number history. **One dangling
> reference predating this revision was fixed in the same sweep:**
> `test/e2e/scenarios_test.go` pointed at
> `prompts/queued/0035-mfa-challenge-first-factor-oracle.md`, a path that has
> never existed — phase 0026 queued that prompt at **0034** and moved the collapse
> to 0035, and the citation took the wrong one of the two. It is exactly the
> failure `docs/PROTOCOL.md` §3 describes, and it is why that section asks for a
> whole-repository grep rather than a grep of the package you were working in.
>
> `docs/learnings/` and `prompts/implemented/` were **not** rewritten and must be
> read through this mapping — `docs/learnings/0026-…` carries a pointer note
> saying so, and `docs/learnings/0027-…` describes the phase that queued this
> one.
>
> **Renumbering note (the MFA disclosure question) — compose it with the
> ones below.** Phase 0026 gave the password+MFA flow its first end-to-end
> coverage and found, while asserting that a denial names no factor, that the
> *challenge* names one: it is issued only when the password was right. That was
> queued as **0034**, which meant moving the contract collapse
> **0034 → 0035** so it stays the highest-numbered queued prompt — the same
> reason, and the same shape, as the note below. The new phase may end up
> revising the contract and may end up revising nothing; either way "the
> collapse runs last" is an invariant the plan relies on, and it is cheaper to
> keep it literally true than to make a future session reason about when it is
> not. That is the whole mapping — **0034→0035**, one prompt, and the queue is
> contiguous at 0027–0035. Live references were updated in place (this section's
> run-order paragraph and phase table, `prompts/queued/0032-…`'s and
> `0033-…`'s run-order notes, and the collapse prompt's own title and number
> history).
> **`docs/learnings/` and `prompts/implemented/` were not rewritten:** anything
> written before this revision that calls the contract collapse "0034" — phase
> 0025's learnings among them — means what is now **0035**. Nothing else moved,
> and no number was reused.

> **Renumbering note (hop credential rejection) — compose it with the
> ones below.** Phase 0025 fixed a refused proxy→**target** credential being
> reported as an unreachable host, and found the same defect one function away
> on the proxy→**proxy** leg (`handshakeNextHop`), outside its own scope. That
> was queued as **0033**, which meant moving the contract collapse
> **0033 → 0034** so it stays the highest-numbered queued prompt: it must follow
> every phase that revises the contract, and its own prompt asks any later
> session to renumber for that. The new phase revises no contract, so it could
> in principle have gone after — it is placed before because "the collapse runs
> last" is an invariant the plan relies on, and a queue where that stops being
> literally true is one a future session has to reason about instead of read.
> That is the whole mapping — **0033→0034**, one prompt, and the queue is
> contiguous at 0026–0034. Live references were updated in place (this section's
> run-order paragraph and phase table, `prompts/queued/0032-…`'s run-order note,
> and the collapse prompt's own title and number history).
> **`docs/learnings/` and `prompts/implemented/` were not rewritten:** anything
> written before this revision that calls the contract collapse "0033" — the
> note below, `prompts/implemented/0023-host-key-report-reuse.md`, and phase
> 0025's learnings, which record that queueing this work would need exactly this
> renumber — means what is now **0034**. Nothing else moved, and no number was
> reused.

> **Renumbering note (admission-policy question) — compose it with the ones
> below.** Phase 0022 shipped LRU eviction and, with it, a cliff at the
> bound it could not close within its own scope (§9.1, "The same runs after
> phase 0022"). The question of whether that needs an admission policy was
> queued as **0032**, which meant moving the contract collapse **0032 → 0033**
> so it stays the highest-numbered queued prompt: it must follow every phase
> that revises the contract, and its own prompt asks any later session to
> renumber for that. That is the whole mapping — **0032→0033**, one prompt, and
> the queue is contiguous at 0023–0033. Live references were updated in place
> (this section's run-order paragraph and phase table, the host-key report reuse
> prompt — then `prompts/queued/0023-…`, since implemented and so now
> `prompts/implemented/0023-host-key-report-reuse.md` — and the collapse
> prompt's own number history). **`docs/learnings/` and `prompts/implemented/` were not
> rewritten:** anything written before this revision that calls the contract
> collapse "0032" — including phase 0022's learnings and the note below —
> means what is now **0033**. Nothing else moved, and no number was reused.

> **Renumbering note (run-order revision).** The queued block was renumbered so
> that a number states **position**, not arrival: the frozen implemented prompts
> keep the lowest numbers (0001–0020), and the queue runs contiguously above
> them (0022–0032) in the order it is meant to be worked. Phases **0031**
> (the decision cache) and **0032** (host-key report reuse) were promoted to
> **0022** and **0023** because they are the cheaper answer that replaced the
> withdrawn 0021 (D17), and **0025** (the session deadline) to **0024** because
> the same withdrawal leans on the `SessionDeadline` it enforces. The full
> mapping is — **0031→0022, 0032→0023, 0025→0024, 0022→0025, 0023→0026,
> 0024→0027, 0026→0028, 0027→0029, 0028→0030, 0030→0031, 0033→0032** — while
> implemented prompts 0001–0020 keep their frozen names. **0021 stays retired**
> (withdrawn, never reused; see `docs/learnings/0021-…`), which is why the queue
> starts at 0022 rather than closing that gap. Live references were updated in
> place (`docs/PLAN.md`, the queued prompts, `docs/PROTOCOL.md`, `api/`,
> `deploy/README.md`, and the Go comments that hand work forward).
> **`docs/learnings/` and `prompts/implemented/` were not rewritten:** anything
> written before this revision refers to phases by their **old** numbers — most
> importantly **0020's learnings** and **0021's**, which call the decision cache
> "0031" (now **0022**) and the host-key report "0032" (now **0023**), and 0021's
> which calls the session deadline "0025" (now **0024**) and the contract
> collapse "0033"/"0029" (now **0032**). Resolve them through this mapping, and
> compose it with the frozen notes below, which record *earlier* revisions of the
> same numbers.
>
> > **Renumbering note (device-completion revision).** Phase 0015 deferred two
> capabilities it deliberately declined — multi-VDOM support and target-enforced
> expiry — and queued them at the **end**, after the FortiSwitch drivers. That was
> the convenient placement, not the correct one, and it has been fixed: they are
> now **0016** and **0017**, ahead of everything that builds on what a device
> driver can do. Three dependencies decide it:
>
> - **What a target is when one device is many** is one question asked in three
>   places. 0016 asks it in the simplest shape (a FortiGate partitioned into
>   virtual domains), 0027 asks it in the hardest (a switch behind a FortiGate),
>   and **0018 is the contract revision that has to describe the answer**. Asking
>   it after the contract was revised would mean a fifth revision for one field,
>   or two parallel answers — so it is asked first, once.
> - **0018's survey advertises what each enforcement point can do**, and whether a
>   FortiGate can expire an account on the device is exactly such a capability.
>   0015 established that FortiOS *has* the mechanism and this repository declines
>   it; a survey written before 0017 settles that would record "the platform
>   cannot", which is the precise error 0015 was queued to correct.
> - **0019 renders a rung onto "a device account"**, which on a multi-VDOM unit is
>   an account in a scope. Running 0016 first means 0019 writes that rendering
>   once.
>
> 0017 follows 0016 because a schedule object on a unit with virtual domains
> lives in a scope 0016 defines. Under `docs/PROTOCOL.md` §6 the queued prompts
> were renumbered to keep implementation order — **0016→0018, 0017→0019,
> 0018→0020, 0019→0021, 0020→0022, 0021→0023, 0022→0024, 0023→0025, 0024→0026,
> 0025→0027, 0026→0028**, with the two deferred phases taking **0016** and
> **0017** — while implemented prompts 0001–0015 keep their frozen names. Live
> references were updated in place (this file, the queued prompts, and the Go and
> config comments that hand work forward).
> **`docs/learnings/` and `prompts/implemented/` were not rewritten:** most
> importantly **0015's learnings**, which queue multi-VDOM as "0027" (now
> **0016**) and target-enforced expiry as "0028" (now **0017**), and which hand
> the access-profile survey to "0016" (now **0018**) and the enforcement default
> to "0017" (now **0019**).
>
> Resolve them through this mapping, and **compose it with the notes below**,
> which are frozen records of *earlier* revisions of the same numbers. Applying
> it to the nearest one: where the FortiOS-corrections note says the
> access-profile survey is "now 0016" it is now **0018**, where it says the
> enforcement default is "now 0017" it is now **0019**, and where it says the
> FortiSwitch work is "now 0025/0026" it is now **0027**/**0028**. The chain is
> three revisions deep at this point; when in doubt, the phase **table above** is
> the only current statement of what a number means.
>
> **Renumbering note (FortiOS-corrections revision).** Phase **0015** is new: it
> acts on `docs/FORTIOS-DOC-VERIFICATION.md`, which re-checked phase 0014's
> FortiOS claims against Fortinet's own documentation once those sites were
> reachable and found three of them wrong. Two are facts the contract reasons
> about — FortiOS *does* have per-administrator expiry (`set schedule`), and
> `prof_admin_readonly` appears not to exist — so the corrections must land
> before the phases that build on them. Under `docs/PROTOCOL.md` §6 the queued
> prompts were renumbered to keep implementation order — **0015→0016, 0016→0017,
> 0017→0018, 0018→0019, 0019→0020, 0020→0021, 0021→0022, 0022→0023, 0023→0024,
> 0024→0025, 0025→0026** — while implemented prompts 0001–0014 keep their frozen
> names. Live references were updated in place (`docs/PLAN.md`, the queued
> prompts, and the Go, config and deploy comments that hand work forward).
> **`docs/learnings/` and `prompts/implemented/` were not rewritten:** anything
> written before this revision refers to phases by their **old** numbers — most
> importantly 0014's learnings, which hand the access-profile survey to "0015"
> (now **0016**), the enforcement default to "0016" (now **0017**), and the
> FortiSwitch work to "0024"/"0025" (now **0025**/**0026**). Resolve them through
> this mapping. Note also that the privileged-access note below is a frozen
> record of an *earlier* revision: the enforcement-point contract it calls
> **0015** is now **0016**, and the target-side enforcement it calls **0016** is
> now **0017**.
>
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
posture, config-change noise), phases 0013–0017, with the device enforcement
rung named by **0018** (`platform-authorized`, and `platform-attested` for the
gear this product does not administer) and rendered by **0019**.

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

Served by: existing D5a/D12 vocabulary, sharpened by 0018's rungs — this is the
use case `no-interactive-shell` beside `restricted_exec` was written for, and
the one whose concurrency caps (§6.5, "Session bounds") bound an automation
fleet.

Phase 0020 measured how large an estate connection-per-check survives (§9.1),
and the answer is larger than D17 assumed: it stays viable well past the estate
size that motivated D17, which is why **D17 is withdrawn and phase 0021 was
never built**. What does **not** scale to this access pattern is the decision
cache — one subject against very many targets gets a hit rate of `4,096 / N`,
because the cache is bounded there and never evicts. This is the use case that
finding is about, and phase **0022** is the fix, with **0023** taking the
host-key report out of the residue. After both, this use case costs Hoplock
Control one authentication per check and nothing else that is not a
configuration (§9.1).

The bound on how long any one connection may hold its snapshot — including a
client multiplexing checks over `ControlMaster` — is 0018's `SessionDeadline`,
enforced locally by phase **0024**, plus §6.4's revocation stream. That is the
guarantee D17 wanted, and it is already contracted.

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
for the stop path, and phase **0018** for the contract — which landed the four
fields (§6.5, "Session bounds"). Phase 0024 enforces the deadline.
