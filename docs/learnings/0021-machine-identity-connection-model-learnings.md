# 0021 — Machine-identity connection model — Learnings

> **Pointer, added by phase 0023 (this file is otherwise unchanged).** The
> comparison this withdrawal rests on was a projection when it was written and
> is now **measured**. Both phases it named have shipped — read **0031** below
> as phase **0022** (delivered) and **0032** as phase **0023** (delivered); the
> renumbering mapping is in the run-order notes at the end of `docs/PLAN.md`
> §10. The "~1.17 calls per check / ~1,365 req/s" row is measured at **1.173**
> calls per connection (`docs/PLAN.md` §9.1, "The same table after phase 0023",
> scenarios 02 vs 09), so the leg of the argument that said the leftover Control
> load has a cheaper answer than amending D2 no longer rests on arithmetic.

## Summary
- **Verdict: withdrawn. Nothing was built, and that is the deliverable.** The
  prompt was explicitly conditional on 0020's measurements and named deletion as
  a possible outcome. The condition was met on every leg, so D17 is marked
  withdrawn and **D2 is not amended**: one decision per connection stands, the
  connection stays short, and the unit of audit stays the connection.
- **The comparison made** (the prompt required naming it): against phases
  **0031 + 0032**, not against today's behaviour. They take Hoplock Control
  from ~3.16 calls per check at UC2's fan-out to **~1.17** — ~3,690 → ~1,365
  req/s at the real five-minute interval — with no contract amendment for 0031
  and no change to D2 for either, and for every route rather than only machine
  ones.
- **The finding that decided it.** After 0031 and 0032, what is left is
  `POST /v1/auth/cert` at 1.00 per check plus `logs/batch` at 0.17 (a
  `logging.batch_size` setting). A persistent connection removes the 1.00 only
  by **not authenticating each check** — which is §6.4's "authentication is
  never cached" rule under another name, and moves certificate-revocation
  enforcement onto the revocation stream alone. D17's slogan bounds
  *authorization* and is silent about that. It is a security-model change, not
  an optimisation, and must be argued as one.
- **The mechanism D17 proposed already exists, twice.** §6.4's `CacheHint` TTL
  is a server-owned, clamp-down-only, revocation-aware, fail-closed lifetime on
  a policy snapshot reused across connections; 0018's `SessionDeadline`,
  enforced locally by queued phase **0025**, bounds how long one connection may
  hold a snapshot — a `ControlMaster`-multiplexed client included. Together
  they *are* "bound the snapshot, not the connection", already contracted.
- **No code changed.** Docs and prompts only. Nothing under `internal/`, `cmd/`,
  `api/` or `deploy/`, so no cross-repo obligation
  (`docs/CROSS-REPO-PROTOCOL.md` §1) and no e2e scenario is owed — see "The e2e
  obligation" below, which the prompt asked to have answered explicitly.
- **Key files:** `docs/PLAN.md` (**D17** rewritten to withdrawn, **§9.1** new
  subsection "What the Control rate becomes after 0031 and 0032", §10 table,
  §13 UC2); `prompts/queued/{0025,0029,0031,0032}` (dangling references);
  `docs/learnings/{0020,README}`; `prompts/queued/0021-…` **deleted**.
- **What the NEXT session must know:** the number **0021 is retired** — never
  reuse it (`docs/PROTOCOL.md` §6). **0031 and 0032 are now load-bearing**, not
  tidy-ups: they are the answer that replaced this phase, and 0032 is the last
  queued phase that revises the contract, which is what 0029 waits on.

> **Pointer (this file is otherwise unchanged, and its numbers are the old
> ones).** The queue was renumbered after this phase so that a number states run
> order (`docs/PROTOCOL.md` §6; full mapping in the run-order note at the end of
> `docs/PLAN.md` §10). Read this file through it: the decision cache called
> **0031** here is now **0022**, host-key report reuse called **0032** is now
> **0023**, the session deadline called **0025** is now **0024**, and the
> contract collapse called **0029** is now **0032**. Those first three were
> promoted to run next precisely because this phase's argument leans on them.
> **0021 itself stays retired and is never reused.**

## Details

### What the prompt asked, and why the answer is "don't"

0021 was queued to implement D17: let a machine identity hold one long-lived
connection carrying many channels, with a server-owned maximum snapshot age and
re-authorization on expiry. Its own header, rewritten after phase 0020 landed,
told this session to test the premise first and to delete the phase if
connection-per-check turned out to be comfortably within budget.

Three arguments were available for the phase. All three fail.

**1. Connection volume — already dead before this session started.** 0020
measured 2.6 ms of proxy CPU and 118 KiB of RSS per connection. At the interval
the customer confirmed — five minutes — a 350,000-target estate is 1,167 conn/s,
which is **one to two proxies**; at the retained sixty-second worst case it is
four to nine. That is a deployment, not an architecture. Per-check provisioning
is not a wall either: one target sustains 58 `ephemeral-user` cycles/s against
the 0.017/s a poll of it asks for. Nothing here needed re-deriving; it is
`docs/PLAN.md` §9.1.

**2. Hoplock Control load — the residual argument, and the one this session had
to weigh.** The numbers, all from 0020's measured call table (`load/results/`),
projected at 1,167 checks/s:

| Model | Calls/check | Control req/s | |
| --- | --- | --- | --- |
| Today, at UC2 fan-out (~1.4% hit rate) | ~3.16 | ~3,690 | derived |
| + **0031** (cache evicts, works at fan-out) | 2.17 | ~2,530 | derived from the measured cache-hit figure |
| + **0032** (host-key decision reused) | **~1.17** | **~1,365** | derived |
| + 0021 on top (5-min poll, 1-hour snapshot) | ~0.25 | ~290 | derived — see below |

0021 would take ~1,365 → ~290 req/s. That is a real 4.7×, and it is the honest
case for the phase. It is not enough, for two reasons.

First, **1,365 req/s is not a problem that justifies amending D2.** It is a
normal API rate for a PDP built to serve a 350,000-target estate, spread over
one to two proxies, and 0031 + 0032 get there with no standing authorization, no
new audit unit, no in-flight-channel narrowing rule, and — for 0031 — no
contract change at all.

Second, and decisively: **look at what the 1.17 is made of.** `auth/cert` 1.00 +
`logs/batch` 0.17. Logs are a `logging.batch_size` knob. So the residual *is*
the authentication rate, and 0021's remaining 4.7× comes almost entirely from
authenticating once per connection instead of once per check.

§6.4 says authentication is never cached, for two stated reasons: an MFA
approval is a per-session assertion, and **certificate validation is where
revocation is enforced**. A machine connection living for days validates its
certificate once; a revoked certificate is then caught only by the revocation
stream, until the next snapshot renewal. D17's resolution — "bound the snapshot,
not the connection" — bounds the *authorization* decision and says nothing about
this. The phase's largest remaining benefit is therefore a weakening the phase's
own framing does not name, and the prompt's §2 (audit granularity) was already
disclaimed by its header as a cost rather than a motivation. There was no leg
left to stand on.

**3. The safety property — already contracted, twice.** This is the part worth
carrying forward, because it is not in 0020 and it is what makes the withdrawal
safe rather than merely affordable.

D17 wants a policy snapshot with a bounded, server-owned lifetime. That is
§6.4's `CacheHint`: an opaque server key plus a TTL, which the proxy may clamp
down but never up and never invent, which the revocation stream can invalidate,
and which the fail-closed rule disables entirely when the stream goes unheard
(`CacheOptions.StaleAfter`, 30 s). It amortises one decision across many short
connections — the same amortisation 0021 wanted, without holding the transport
open. Phase 0031 is what makes it work at fan-out.

D17 also worries, correctly, about a connection that outlives its decision. But
that exposure **exists today and is not machine-specific**: any client holding a
connection open — `ControlMaster`, an interactive session left running overnight
— holds its snapshot for the connection's life, bounded only by revocation. 0025
says this in its own words ("today an established session has no upper bound at
all except revocation") and closes it with 0018's `SessionDeadline`, enforced
locally so it holds with Control unreachable. That is a better answer than 0021
for the same problem: it is server-owned, it applies to every route, and it
needs no new contract field.

So the two halves of D17's sentence are already deliverable from parts that
exist. Building 0021 would have been a third mechanism for a property two
mechanisms already provide.

### What was deliberately *not* preserved

- **Per-channel audit records.** The prompt's own header calls this a cost the
  change incurs, not an independent motivation — it exists because a persistent
  connection carries many checks. With connections staying short, one connection
  is one check is one record, and today's granularity is already per check. If
  0021 ever revives, this revives with it; there is nothing to queue now.
- **A `max_snapshot_age` contract field.** Not added. Had it been needed, the
  prompt's own cross-repo question ("can 0003's cache hint carry it instead?")
  answers itself — the hint *is* a server-owned snapshot lifetime — which is a
  further sign the phase was rediscovering an existing mechanism. `api/` is
  untouched, so `docs/CROSS-REPO-PROTOCOL.md` does not engage.

### The e2e obligation

The prompt requires an explicit answer rather than silence. **No scenario is
owed:** no behaviour changed, so there is nothing for a real SSH client to
survive. `deploy/control/fixtures.template.yaml` and `TestTopology` are
untouched, and the ordering hazards the prompt warns about (telemetry subtests
reading earlier scenarios' output, the outage scenario's position, the shared
`sshBaseArgs`) were not disturbed. Those warnings remain accurate and useful for
whoever next adds a scenario.

### Dangling references cleaned up (`docs/PROTOCOL.md` §3)

Withdrawing a phase leaves the same debris a rename does. Live references
updated: `prompts/queued/0025` (both its §5.1 prose bullet and its out-of-scope
list, which pointed at 0021 for machine-identity connection lifetimes),
`prompts/queued/0031` and `0032` (their out-of-scope/motivation blocks, which
now also record that they are the answer that replaced 0021),
`prompts/queued/0029` (it waited on "any contract revision 0021 turns out to
need"; with 0021 gone, **0032** is the last contract-revising phase and 0029
waits on that instead — this was the one genuinely load-bearing dangling
reference), `docs/PLAN.md` §10 and §13 UC2, and `docs/learnings/README.md`
(a file here need not have a matching implemented prompt).

Left as historical record, per §3: `prompts/implemented/0020-*`,
`docs/learnings/0020-*` (given a one-line pointer at the top of its Details, not
a rewrite), and the D17 references in `load/README.md`, `load/scenarios/*.yaml`
and `cmd/loadgen/*.go` — D17 still exists, now marked withdrawn, and those files
describe what they measured and why, which stays true.

`prompts/queued/0022` says "nothing in 0013–0021 depends on it". That is a range
and still accurate; it was left alone.

### What would revive this phase

Not a bigger estate — that arithmetic scales with proxies, and 0020 showed how
gently. It comes back when the **authentication** rate is the binding
constraint: an estate and poll interval whose one-`auth/cert`-per-check floor
exceeds what a real Hoplock Control can serve (0020's ran on loopback in tens of
microseconds; a real PDP is a network hop and a database away — re-measure with
`control.latency` before believing any of this about production), **and** a
customer who accepts certificate revocation being enforced only by the
revocation stream between snapshot renewals.

Write it as a new, higher-numbered prompt when that happens. **Do not reuse the
number 0021.**
