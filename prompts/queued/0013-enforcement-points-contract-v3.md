# 0013 — Enforcement points: survey & contract v3

> New phase, queued after 0012. It comes **after** the prototype gate rather
> than before it because the question it answers is comparative — "which of the
> available enforcement points is strongest" is only answerable once both
> credential methods (0007), all three policy axes (0009), and both exec tiers
> (0010) exist to compare against. It comes **before** 0014 for the reason 0006
> came before 0009: the vocabulary is revised before anything is built against
> it.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/CROSS-REPO-PROTOCOL.md` — **required**: this phase changes `api/`, which
  is a shared surface. Section 2 (upstream merges first), Section 4 (the
  Cross-repo impact section this PR owes), Section 5 (sync PR conventions).
- `docs/PLAN.md` — especially §2 (**D12**, D5a, D6a), §5.1 (what the ephemeral
  provisioner already does to a target), §6.3 (the three tiers).
- `docs/learnings/` — read summaries; open `0006` (how a contract revision is
  shaped and versioned), `0007` (what the ephemeral provisioner controls on the
  target: the account, its `authorized_keys`, its shell, its home) and `0010`
  (the restricted-exec policy object and what it can and cannot promise).

## Objective
Answer, and write down, **where** each policy claim is actually enforced — then
give Hoplock Control the vocabulary to choose an enforcement point per route,
and the proxy the vocabulary to say which points it can provide.

Enforce nothing. This phase revises `docs/PLAN.md`, `api/control.yaml`, and
`internal/control`; 0014 implements what it names.

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
| The target's own ACL, role, or privilege level | target, vendor, **pre-provisioned** |
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
  surprise.
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
  working unchanged, and `policy_version` moves to 3 (0006 set that pattern:
  see `control.PolicyVersion`).
- **Capability advertisement, per target and not only per proxy.** A server
  cannot sensibly choose a rung that cannot be provided, and what is available
  depends on the *target* far more than on the proxy: whether it runs systemd,
  whether cgroup v2 is mounted, whether SELinux is enforcing, whether netfilter
  is reachable, whether it is a Linux host at all. The proxy is the only party
  positioned to find that out, because it is the only one that logs in.

  This has an ordering problem worth solving in this phase rather than
  discovering in 0014: authorize happens **before** the proxy has ever touched
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

### 3. `internal/control`

Types, `Clone`, validation, and the mock server, following 0006's shape exactly:
every new field gets its JSON tag, its absent-value default, and its consuming
phase documented on the field. `cmd/mock-control` fixtures gain the new key so
0014 and 0012's topology can select rungs; `fixtures.example.yaml` and
`api/README.md`'s fixture table move with them.

## Out of scope
- **Enforcing anything.** No provisioning changes, no scripts, no shell
  configuration, no mount work — all 0014.
- Authoring SELinux or AppArmor policy for customer fleets. The survey records
  what the rung requires; shipping fleet policy modules is not this product.
- Changing `target_auth` (0007) or the filter engine (0010).

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
- **No behaviour change**: `go test ./...` passes with no test in
  `internal/proxy`, `internal/auth/target`, or `internal/filter` modified.

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
`docs/learnings/0013-enforcement-points-contract-v3-learnings.md`. Summary block
MUST document the rung vocabulary for **both axes** and each rung's guarantee in
one line, which rungs are applied and which attested, the absent-value default,
the capability-advertisement mechanism (proxy-level and per-target), the refusal
rule, and the audit field — 0014 builds from that summary alone.

---

## Appendix — the Control-side obligations

Neither artifact below may be opened in `hoplock/control` **before this PR
merges** (`docs/CROSS-REPO-PROTOCOL.md` §2): a downstream PR describing a
contract field that does not exist yet is indistinguishable, to a reviewer, from
one describing a field that does.

### A. The sync PR (text only, immediately after this merges)

Branch `claude/sync-enforcement-points`, commit
`docs(sync): follow proxy contract v3 enforcement points`. It changes prompts,
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

### B. The Control implementation prompt (queued by the sync PR)

Numbered by `hoplock/control`'s own `docs/PROTOCOL.md` — take the next free
number in its queue; **do not** reuse a proxy number. Draft body:

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
