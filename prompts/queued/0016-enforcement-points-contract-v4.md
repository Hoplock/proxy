# 0016 — Enforcement points: survey & contract v4

> Renumbered from 0013 by the privileged-access revision (PLAN §10) and widened
> there. It comes **after** the prototype gate because the question it answers is
> comparative — "which of the available enforcement points is strongest" is only
> answerable once the credential methods (0007, 0014), all three policy axes
> (0009), and both exec tiers (0010) exist to compare against. It now waits for
> the **device** method too (0013, 0014), because a device platform's own RBAC is
> a candidate rung and a survey that omits it would be answering a smaller
> question than the product asks. It comes **before** 0017 for the reason 0006
> came before 0009: the vocabulary is revised before anything is built against
> it.
>
> It also carries the **session-bounds vocabulary** for UC3 (PLAN §13) — deadline,
> grant context, required capture (D16). Those are not enforcement points, but
> they are contract fields on the same object in the same revision, and splitting
> them into a fourth contract bump would cost Control a third sync for no gain.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/CROSS-REPO-PROTOCOL.md` — **required**: this phase changes `api/`, which
  is a shared surface. Section 2 (upstream merges first), Section 4 (the
  Cross-repo impact section this PR owes), Section 5 (sync PR conventions).
- `docs/PLAN.md` — especially §2 (**D12**, **D16**, D5a, D6a, D13), §5.1 (what
  the ephemeral provisioner already does to a target), §5.3 (what a device
  driver controls and what it declares), §6.3 (the three tiers), §13 (UC2 and
  UC3, which this phase serves).
- `docs/learnings/` — read summaries; open `0006` (how a contract revision is
  shaped and versioned), `0007` (what the ephemeral provisioner controls on the
  target: the account, its `authorized_keys`, its shell, its home), `0010`
  (the restricted-exec policy object and what it can and cannot promise), and
  `0013`/`0014` (what a device driver declares, and what a FortiOS access
  profile can actually constrain).

## Objective
Answer, and write down, **where** each policy claim is actually enforced — then
give Hoplock Control the vocabulary to choose an enforcement point per route,
and the proxy the vocabulary to say which points it can provide.

Enforce nothing. This phase revises `docs/PLAN.md`, `api/control.yaml`, and
`internal/control`; 0017 implements what it names.

## Why this phase exists

D12 already draws the line between a guardrail and a boundary, and restricted
exec is on the right side of it. But restricted exec is enforced **in the proxy,
at the `exec` request** — and D12 says the quiet part itself: *"reliable
interception of an unrestricted shell command is still an unrestricted shell."*
A route that permits `shell` hands the user a shell, and there is no request for
the proxy to parse. Everything the filter engine promises evaporates the moment
a pty is permitted.

The proxy already has, on `ephemeral-user` routes, the strongest lever in the
system and does not pull it: **it creates the account**. It writes that account's
`authorized_keys`, chooses its shell, owns its home directory, and holds root on
the target for the duration. An account that can only execute two binaries
cannot be talked out of that by any string the user types — through the proxy or
around it.

So the product's enforcement story is not one line, it is a **ladder**, and
which rung a route stands on is a policy decision that belongs to the PDP
(D2) — exactly as the credential method does (D6a).

And it is not one ladder either. "What a session may run" and "what it may
reach" are separate questions with separate mechanisms, and the second one is
the one an automated health-check account actually turns on: an account that can
run exactly `uptime` and `cat`, and can also open a socket to anything in the
estate, is a pivot point wearing an allow-list. This phase surveys **both
axes** and lets the server choose a rung on each.

## In scope

### 1. The survey, recorded in `docs/PLAN.md`

Enumerate the candidate enforcement points and, for each, state **four** things
in a table a reviewer can audit: what it guarantees, what it does not, what the
target must already provide, and how it fails. The candidates fall on two axes
and the survey keeps them apart, because a route can stand on a different rung
of each. At minimum:

**Axis 1 — what the session may execute:**

| Candidate | Where it runs |
| --- | --- |
| Pattern rule list (filtered exec) | proxy, per `exec` request |
| Restricted exec, argv-parsed (D12) | proxy, per `exec` request |
| **Denying `shell`/`pty-req` outright** (D5a axis 2, already shipped) | proxy, per in-channel request |
| `command=` / `ForceCommand` dispatcher in the ephemeral `authorized_keys` | target, sshd, per connection |
| `restrict` key options (no pty, agent, port, X11 forwarding) | target, sshd |
| Restricted shell + a curated `PATH` directory | target, shell |
| Per-session `noexec`/`nosuid` home, or a mount namespace | target, kernel |
| systemd sandboxing — `ProtectSystem=strict`, `ProtectHome=`, `NoNewPrivileges=`, `SystemCallFilter=`, `RestrictSUIDSGID=` — applied by a drop-in on the session's `user-<uid>.slice`, or by a `systemd-run` wrapper behind `command=` | target, systemd + cgroup v2 |
| MAC confinement (SELinux type, AppArmor profile) | target, kernel |
| **Device RBAC** — the platform's own command authorization bound to the ephemeral account (a FortiOS access profile, an IOS privilege level or parser view, a Junos login class) | target, vendor, **per session** (D13) |
| Nothing | — |

**Axis 2 — what the session may reach:**

| Candidate | Where it runs |
| --- | --- |
| `permitted_forwards`, `permitted_global_requests` (D5a axis 3, already shipped) | proxy, per channel open and global request — **SSH-channel forwarding only** |
| `no-port-forwarding` / `restrict` in the ephemeral `authorized_keys` | target, sshd, per connection |
| systemd `IPAddressDeny=any` plus an `IPAddressAllow=` allow-list on the session's slice | target, systemd + eBPF, cgroup v2 |
| systemd `PrivateNetwork=yes` — the session's processes get a namespace with loopback and nothing else | target, kernel netns |
| Per-uid packet filter: `iptables -m owner --uid-owner`, nftables `meta skuid` | target, netfilter |
| MAC network rules (SELinux socket classes, AppArmor `network` rules) | target, kernel |
| The target's own ACL, role, or privilege level, **pre-provisioned** | target, vendor |
| **Trusted-host / source-address pinning on the ephemeral device account** — where the driver declares the platform supports it (§5.3) | target, vendor, **per session** (D13) |
| Nothing | — |

`systemd` deserves its two rows rather than a footnote: on a modern Linux fleet
it is the only rung on either axis that needs no policy module, no custom MAC,
and no binary installed — it is a drop-in file and a `daemon-reload`. It is
likely the best cost-to-strength ratio in the whole table, and the survey should
say so if it agrees.

Five findings the survey must reach rather than assume, because each one
changes what the tiers can be:

- **Denying the interactive shell is itself an enforcement point, and it is
  free.** A route permitting `exec` but not `shell`/`pty-req` turns restricted
  exec from "a boundary for the commands it sees" into "a boundary, full stop".
  The axis already exists (0006, 0009). If that is the cheapest strong rung, say
  so — a ladder whose first rung is already shipped is a better product story
  than one that starts with a target-side agent.
- **An allow-list containing an interpreter is not an allow-list.** `find`,
  `awk`, `less`, `vi`, `tar`, `python`, and most editors hand back a shell
  (GTFOBins). Whether that is the policy author's problem, the contract's
  problem (a documented rule), or the proxy's problem (a refusal) is a decision
  this phase makes and writes down.
- **Enforcement point and credential method are coupled.** `brokered-key` (D6a)
  changes nothing on the target by definition, so **no target-side rung is
  available on those routes** — the ladder there stops at the proxy. The
  contract must make that expressible and the mismatch must be an error, not a
  surprise. Since D14 the route names an *ordered list* of methods, so the
  coupling is now conditional: a route whose ladder is
  `[ephemeral-user, brokered-key]` can reach a target-side rung on its first
  entry and not on its second. Decide, and write down, whether a rung is
  therefore a property of the route (and a degraded method makes it
  unavailable — refuse, or run without it?) or a property of each ladder entry.
  Either answer is defensible; an unstated one produces a session whose audit
  record claims a rung that was never applied, which is the failure this whole
  phase exists to prevent.
- **A device's own RBAC may be the strongest rung in the system, and it is not
  Linux.** On the `ephemeral-account` method (D13) the proxy creates the
  administrator, so it chooses that administrator's access profile, role, or
  privilege level — enforcement by the platform's own command authorizer, ahead
  of anything the proxy could parse, and effective against a connection that
  never went through a proxy at all. The survey must fill all four columns for it
  as for any other candidate, and must be specific about the failure mode that
  has no Linux analogue: vendor RBAC is **coarse and named**, so "the profile
  that permits diagnostics" is only as good as the vendor's grouping, and the
  survey should say where that grouping leaks (a diagnostic command with a shell
  escape, a profile that includes configuration write). Read 0014's learnings
  before writing this row; do not characterise FortiOS access profiles from
  memory.
- **Egress is a second axis, and the forwarding policy does not cover it.**
  `permitted_forwards` governs what may be tunnelled *through SSH channels*; a
  process the session starts on the target opens its own sockets and never
  touches a channel, so the proxy cannot see it, let alone deny it. A survey
  that lists the forwarding policy as the answer to "can this account reach the
  database" would be wrong in the most expensive direction, and an operator
  reading the console would believe it. State the boundary of that field
  explicitly, next to the rungs that do cover it.

  One hazard the survey must record because it lands on 0007's teardown: a
  per-uid packet filter is only per-session while the uid is, and `useradd`
  reuses a freed uid. A rule that outlives its account silently attaches to
  whoever gets that uid next. Any rung that keys on uid therefore makes the
  filter rule part of the teardown contract and part of what the orphan reaper
  looks for — the same guarantee as the account itself, or it is not a rung.

- **Some rungs are attested, not applied — and that is what makes appliances
  reachable.** The bullet above says no target-side rung is available on a
  `brokered-key` route, and as written that is too absolute: it is true only of
  rungs the *proxy applies per session*. A router, a firewall, or a filer
  typically enforces its own command authorisation natively and permanently —
  IOS privilege levels and RBAC views, Junos login classes with
  `allow-commands`/`deny-commands`, per-account ACLs — configured once by the
  network team, not by this product. The session's account already stands
  behind a boundary at least as strong as anything a Linux rung provides.

  So the ladder has two kinds of rung: **applied** (the proxy configures it,
  per session, and tears it down) and **attested** (the target enforces it
  already; the proxy configures nothing and the record says which). Attested
  rungs are how the appliance estate gets a real enforcement claim instead of
  "none available", and they are the only kind `brokered-key` can offer.
  Decide, and write down, what an attestation is worth without verification —
  an unverified claim in an audit record is a liability, so at minimum name who
  asserts it and where that assertion lives.

Land the result as an **amendment to D12** (D12 is the decision this refines;
do not invent a new decision id if the existing one covers it) plus a new
`docs/PLAN.md` subsection under §6.3 holding the table.

### 2. The contract (`api/control.yaml`, `api/README.md`)

The authorize response gains a **server-chosen enforcement point** for the
connection. Decide and document:

- **Where it hangs.** The recommendation to evaluate first: it belongs on
  `filter_policy` rather than beside `target_auth`, because it selects *where the
  existing `restricted_exec` policy is enforced* rather than naming a different
  policy — one policy object, several enforcement points. Reject the
  recommendation if the survey says otherwise, and say why in the PR.
- **The value set**, named after what each rung *guarantees*, never after its
  mechanism: an operator reading an audit record must not have to know what
  `rbash` is. Mechanism belongs in the proxy's local config and in this repo's
  docs.
- **The absent-value default must be exactly today's behaviour** — proxy-side
  enforcement only. A v2 server that never heard of this field must keep
  working unchanged, and `policy_version` moves to 4 (0006 set that pattern:
  see `control.PolicyVersion`).
- **Capability advertisement, per target and not only per proxy.** A server
  cannot sensibly choose a rung that cannot be provided, and what is available
  depends on the *target* far more than on the proxy: whether it runs systemd,
  whether cgroup v2 is mounted, whether SELinux is enforcing, whether netfilter
  is reachable, whether it is a Linux host at all. The proxy is the only party
  positioned to find that out, because it is the only one that logs in.

  This has an ordering problem worth solving in this phase rather than
  discovering in 0017: authorize happens **before** the proxy has ever touched
  the target, so per-target capabilities cannot simply ride on
  `AuthorizeRequest` for a first-ever connection. The precedent that fits is
  `/v1/hostkeys/report` (D7): the proxy learns something about a target by
  connecting and reports it, and the server accumulates it. Evaluate a
  capability report on the same shape, with the proxy's own capabilities on
  `AuthorizeRequest` alongside `policy_version` (0006's pattern) and the
  target's discovered by probe and reported. Decide what a *stale* or *absent*
  capability record means, and make that answer fail safe.

  Whatever is chosen, a server that ignores all of it must still be safe,
  because of the next point.
- **A rung the proxy cannot provide is an outage-class denial** (PLAN §4.3),
  naming the session id — never a silent downgrade to a weaker rung. This is
  D6a's rule for credential methods applied unchanged, and for the same reason:
  a session that runs at a weaker tier than the audit record claims is worse
  than a session that does not run.
- **The audit record carries the rung that was actually in force**, not the one
  requested. The whole point is that the claim differs per rung.

### 2a. Session bounds and access context (D16, UC3)

Four fields on the authorize response, unrelated to *where* policy is enforced
but bounding *how long* and *on what grounds* a session exists. They ride this
revision because they are the same object and the same version bump.

- **A session deadline.** Today nothing expresses one: `CacheHint.ttl_seconds`
  bounds decision *reuse* and `ephemeral-user`'s `lifetime_seconds` bounds the
  *credential*, but an already-open session outlives both. Add an absolute
  deadline the **proxy enforces locally**, so it holds when the revocation
  stream is down — which is exactly when an immortal root session is least
  acceptable, and the reason this is not "just use revocation". Decide and
  document: absolute instant or duration-from-authorize (prefer the instant —
  a duration re-anchors on every hop of a chained route, which silently
  multiplies the window); what the user is told at expiry (§4.3 says the close
  is explained, and this one is not a denial); and whether a warning precedes
  it. Applies to any route, not only privileged ones.
- **Required session capture.** A route may demand that the session is recorded,
  and a proxy that cannot record refuses it (outage-class, §4.3). Buffering to
  local disk **counts** as recording — the 0011 pipeline's disk buffer is a
  resilience path, not a degraded mode — so the refusal triggers only when there
  is no path at all. This is the compensating control that makes D16's
  unbounded-privilege grant defensible, so name it after what it guarantees, and
  make the check happen before the target leg is dialled rather than after.
- **Grant context.** Structured: the external system, its reference (ticket,
  scan, incident), and the window it asserted. Plus an `additional_context`
  admitting either a string or an object, because the systems on the other end
  differ more than a fixed schema can absorb. **The proxy treats all of it as
  opaque**: it is copied to every log record for the session, never parsed,
  never matched against, never the basis of a proxy-side decision. Say that on
  the field, in the contract, in those words — the next reader's instinct will
  be to make policy out of it, and D2 says that decision was already made
  upstream. It is not shown to the user on denial (§4.3: a denial stays vague).
- **Concurrency caps** (UC2). A per-subject and/or per-target ceiling on live
  sessions, enforced by the proxy against its own `SessionRegistry` — live
  session count is knowable *only* to the proxy, which is why this is a field
  here rather than a decision Control can make alone from `ConnMeta`. Exceeding
  it is a **policy denial** (vague, §4.3), not an outage. Both scopes are
  optional and independent; absent means uncapped, which is today's behaviour.

Absent-value defaults for all four are "today's behaviour", per the rule below.

### 3. `internal/control`

Types, `Clone`, validation, and the mock server, following 0006's shape exactly:
every new field gets its JSON tag, its absent-value default, and its consuming
phase documented on the field. `cmd/mock-control` fixtures gain the new key so
0017 and 0012's topology can select rungs; `fixtures.example.yaml` and
`api/README.md`'s fixture table move with them.

## Out of scope
- **Enforcing anything.** No provisioning changes, no scripts, no shell
  configuration, no mount work — all 0017.
- Authoring SELinux or AppArmor policy for customer fleets. The survey records
  what the rung requires; shipping fleet policy modules is not this product.
- Changing `target_auth`'s methods or ladder semantics (0007, 0013) or the
  filter engine (0010).
- **Building anything that consumes the grant context.** The push receiver, the
  probe providers, the Qualys and BMC Helix integrations, and the provider
  registry are all Control's and Enterprise's (D15, PLAN §12). This phase adds
  the field the proxy carries and logs, and nothing else. If you find yourself
  writing an HTTP client to ask an external system anything, you are in the
  wrong repository.
- **Enforcing the session deadline.** The field and its validation land here;
  the timer that closes a live session belongs to the proxy engine and is
  **phase 0023**, which also answers the two questions this phase leaves open —
  what the user is told at expiry, and whether a warning precedes it. 0023
  cannot start until this phase merges, so leaving the field unusable blocks it:
  if you change the field's shape from what is specified above, say so plainly
  in the learnings, because 0023 is written against it.

## Acceptance criteria
- `docs/PLAN.md` carries the survey tables — **both axes** — with all four
  columns filled for every candidate, and D12 is amended rather than duplicated.
- The survey states, in the text and not only in a table cell, what
  `permitted_forwards` does **not** cover, and which rungs cover it instead.
- Applied and attested rungs are distinguished in the vocabulary itself, and a
  `brokered-key` route can carry an attested rung while being refused an applied
  one.
- `make openapi-check` passes; `api/README.md` documents the new field, its
  absent-value default, its value set, and the refusal rule, in the style of the
  existing "Absent-value defaults, in one table".
- `internal/control` tests: the new fields round-trip; an absent field means
  today's behaviour; `Clone` deep-copies them (a cached decision shared between
  sessions must not be mutable through it); an unknown value is refused rather
  than coerced; a policy naming an **applied** rung on a `brokered-key` route is
  refused as a contract violation; a rung on either axis can be set
  independently of the other.
- The mock server serves the fields from fixtures, and a fixture exercising each
  rung on each axis exists, including an attested rung on a `brokered-key`
  route.
- The capability mechanism has a test for the **absent and stale** cases, and
  both fail safe.
- The session-bounds fields (§2a) each round-trip, each default to today's
  behaviour when absent, and each have a documented row in `api/README.md`'s
  absent-value table. `additional_context` accepts both a string and an object
  and survives `Clone` without aliasing.
- A test asserts the grant context is **not** consulted by any decision path:
  the type carries no comparison or matching helper, and nothing outside
  `internal/logging`'s record construction reads its fields.
- The device-RBAC row is written from 0014's learnings, and the PR says which
  FortiOS behaviour it relied on.
- **No behaviour change**: `go test ./...` passes with no test in
  `internal/proxy`, `internal/auth/target`, or `internal/filter` modified.

## The e2e topology obligation

This phase writes a contract and connects to nothing, so it owes no scenario in
0012's `test/e2e` suite. It does owe the rig two things, and they are easy to
miss because nothing fails to compile:

- `cmd/mock-control` must **accept** the new vocabulary — `fixtures.go`,
  `fixtures.example.yaml`. Fixture decoding is strict, so an unknown key is a
  startup failure, not a warning.
- `deploy/control/fixtures.template.yaml` must still load. That file is the mock
  Control's fixtures inside this repository's test rig — not the sibling Control
  repo, which vendors only `api/control.yaml`. `make e2e-up` fails loudly if it
  does not, but only if somebody runs it, so run it.

The phase that consumes this vocabulary owes the scenarios.

## Cross-repo impact

This phase changes `api/`, which `hoplock/control` vendors read-only (D3).
Per `docs/CROSS-REPO-PROTOCOL.md` §2 **this PR merges first**, and per §3.1 the
session that merges it then opens the Control sync PR. The obligations, and
draft text for both Control artifacts, are in the appendix below — the appendix
exists so that the sync has nothing left to invent, which is the failure §3.2
warns about.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`, plus the Cross-repo impact section above filled in with
what you actually found (§4: "None" is a finding and must be written down).
Move to `implemented/`; add
`docs/learnings/0016-enforcement-points-contract-v4-learnings.md`. Summary block
MUST document the rung vocabulary for **both axes** and each rung's guarantee in
one line, which rungs are applied and which attested, the absent-value default,
the capability-advertisement mechanism (proxy-level and per-target), the refusal
rule, and the audit field — 0017 builds from that summary alone.

---

## Appendix — the Control-side obligations

Neither artifact below may be opened in `hoplock/control` **before this PR
merges** (`docs/CROSS-REPO-PROTOCOL.md` §2): a downstream PR describing a
contract field that does not exist yet is indistinguishable, to a reviewer, from
one describing a field that does.

### A. The sync PR (text only, immediately after this merges)

Branch `claude/sync-enforcement-points`, commit
`docs(sync): follow proxy contract v4 enforcement points`. It changes prompts,
plan, and docs — never code, never a vendored artifact (§5, §6). It must:

- re-vendor `contract/` by Control's own `make contract-sync` (never by hand);
- state which upstream PR it follows and that the PR is merged;
- record, in **the Control prompt that will implement this** and not only in
  Control's plan, that the authorize response must now be able to name an
  enforcement rung per route **on each of the two axes** (what may execute, what
  it may reach), that the absent value on both means proxy-side enforcement
  only, that an *applied* rung must never be chosen for a `brokered-key` route
  while an *attested* one may be, and that Control now receives and must store
  per-target capability reports;
- say **how it searched** for stale references — the grep, not the adjective.

### B. The Control-side work — which is mostly *already queued*

**A sync PR queues no prompt.** `docs/CROSS-REPO-PROTOCOL.md` §5 is explicit:
"a sync adds, renames, and renumbers **no** prompt. If it appears to need to, it
is not a sync." An earlier draft of this appendix told the sync to queue a
Control implementation prompt, which contradicts that rule; it is corrected
here.

It is also unnecessary. The privileged-access revision already landed these
obligations in the Control prompts that will implement them, per §5's DoD
("every new obligation landed **in the prompt that will implement it**, not only
in the plan"). Locate them **by title**, not by number — Control renumbers its
own queue:

| Obligation | Lands in Control's prompt titled |
| --- | --- |
| Storing the proxy's declared capabilities and constraining authoring by them | *Fleet registry, health & config distribution* (M17) |
| Emitting the rung, the deadline, the caps and the grant context on `/v1/authorize` | *South-bound authorize & route* |
| The rung and the method actually in force as audit records | *Audit ingest & tamper-evident store* |
| Authoring validation and the operator-facing refusals | *North-bound API, inventory & policy lifecycle* |

So the sync's job here is the normal one: re-vendor `contract/`, and sharpen
that existing text from "when the contract carries a deadline" to the field's
real name, shape, and absent-value default. If — and only if — you find work
that fits none of those prompts, that is a **roadmap revision** in Control with
its own PR, not a sync and not an appendix to this one.

The draft below is retained as *content* for sharpening that text, not as a
prompt to create:

> **Objective.** Let an operator choose, per policy, *where* a command
> restriction is enforced, and emit that choice on `/v1/authorize`.
>
> **In scope.**
> - The policy model gains an enforcement rung **per axis** alongside the
>   existing restricted-exec command list: one for what a session may execute,
>   one for what it may reach. They are properties of the policy, not of the
>   target: the same target is reached by a break-glass route and an automation
>   route, and they do not deserve the same rungs.
> - Control stores the **per-target capability reports** the proxy now sends, and
>   uses them to constrain what an author may choose. This is the half that
>   makes the appliance estate work: a router advertises no applied rung and an
>   attested one, and the console must show that as a real enforcement claim
>   rather than as "unsupported".
> - **Validation is the substance of this phase, not the field.** Control must
>   refuse, at policy-authoring time and with an error naming the reason:
>   an *applied* rung on a route whose `target_auth` is `brokered-key` (the
>   proxy cannot administer that target); a rung the proxies serving that route,
>   or the target itself, have not advertised as available; an egress rung
>   naming destinations the target's reported mechanism cannot express; and an
>   executable allow-list containing a known interpreter when the rung's
>   guarantee depends on the list — the proxy refuses these at runtime, but a
>   policy that can only fail at connect time is a policy that fails in front of
>   a user.
> - The console surfaces the rung as a **guarantee**, in the words the contract
>   uses, and the audit view shows the rung that was in force for a session.
> - Conformance tests against the vendored contract for every rung, the absent
>   value, and each refusal above.
>
> **Out of scope.** Anything the proxy does with the rung; minting target
> credentials; fleet MAC policy.
>
> **Acceptance criteria.** Every rung and the absent value round-trip through
> `/v1/authorize`; each refusal above has a test naming the operator-facing
> message; the vendored contract is untouched by hand.
