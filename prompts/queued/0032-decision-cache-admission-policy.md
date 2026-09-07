# 0032 — Does the decision cache need an admission policy?

> **A conditional phase. It may end in "no", and that is a result.** Like phase
> **0021** (`docs/learnings/0021-machine-identity-connection-model-learnings.md`),
> this prompt asks a question and builds the evidence to answer it. It does
> **not** change the cache's policy. If the answer is "no", the deliverable is a
> learnings file saying so and the prompt is deleted rather than moved to
> `implemented/` (`docs/learnings/README.md`). If the answer is "yes", the
> deliverable is a self-contained implementation prompt for the *next* session,
> naming the policy the evidence picked.
>
> **▶ Run order.** It is queued ahead of the contract collapse because that one
> must stay last (`prompts/queued/0033-collapse-contract-to-one-version.md`),
> and behind everything else because nothing depends on it: an operator's fix
> for the problem it studies — raise `control.cache.max_entries` — already
> shipped in **0022**. It was inserted at **0032** by the revision that moved
> the collapse to **0033**; the mapping is in the note at the end of
> `docs/PLAN.md` §10.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` **§6.4** (who owns a cached decision) and **§9.1**, especially
  "The same runs after phase 0022" — the measured before/after and the trade
  this phase re-examines.
- `docs/learnings/0022-decision-cache-under-fanout-learnings.md` — what the
  cache does today, why LRU was chosen, and the follow-up this prompt is.
- `docs/learnings/0020-scale-harness-and-sizing-learnings.md` (summary block) —
  where the fan-out numbers come from.
- `load/scenarios/08-uc2-fanout-evicting.yaml` and
  `load/results/08-uc2-fanout-evicting.json` — the measured cliff.
- `internal/control/cache.go` — `store`, `lookup`, `evictOldestLocked`.

## The finding to evaluate

Phase 0022 gave the authorize cache LRU eviction and a settable bound. Below
the bound it is a strict improvement, and it is why a fan-out estate can reach
§6.4's cached figure at all. Above the bound it has a shape nobody chose:

| Working set vs. bound | Hit rate | |
| --- | --- | --- |
| 4,096 targets, `max_entries: 4096` | 100% | measured (scenario 08) |
| 8,192 targets, `max_entries: 4096` | **0%** | measured (scenario 08) |
| 8,192 targets, same bound, **before 0022** | 59% | measured (0020, reproduced) |

A strict poll cycle is LRU's worst case: every entry is evicted about one visit
before it is wanted. So the hit rate does not *slope* as a fleet outgrows the
cache, it *steps*. At the shipped default a working set of 32,768 is ~100% and
one of 33,000 is ~0%, taking Hoplock Control from 2.17 to 3.17 calls per
connection — **+46% PDP load for a fleet that grew by 1%**, with nothing else
in the estate having changed. The proxy says so in `CacheStats.Evicted`, and
the operator's fix is to raise `control.cache.max_entries` at ~1 KiB of heap
per entry.

A scan-resistant **admission** policy (TinyLFU-style: admit a candidate only
when it looks hotter than the victim it would displace) is the known answer.
Under a uniform cycle it holds the incumbent set and degrades to `bound / N` —
the pre-0022 behaviour, but by design rather than by refusing to store —
while keeping LRU's adaptation when the traffic actually has a hot set.

**Whether that is worth having is a question about deployments and about
numbers, and this phase answers both before anybody writes a sketch.**

## Step 1 — ask, do not assume

Phase 0020 established the habit: a question a benchmark cannot settle gets
**asked**, in the session, verbatim. Ask these before writing any code, and
record the answers — or that they went unanswered — in the learnings.

1. **Can operators size the cache?** For the estates this product is sized for,
   can a proxy be given ~1 KiB of heap per (subject, target) pair it serves —
   about **300 MiB for a 300,000-target estate** — or is there a memory ceiling
   that will force `control.cache.max_entries` below the working set?
2. **What shape is the traffic?** Does an automation sweep its whole estate in
   a fixed cycle, or is there a hot subset polled far more often than the tail?
   If both, roughly what fraction of connections go to the hot subset?
3. **How stable is a proxy's working set?** Does it churn between restarts —
   targets added and retired, subjects rotating — or is it essentially fixed?
4. **Is the cliff itself acceptable?** Given that `Evicted` names the cause and
   the bound is a config line, is "the hit rate steps down when the fleet
   outgrows the cache" tolerable, or must the degradation be gradual?

**An answer can end the phase.** If operators can always size the cache to the
estate and the traffic has a hot subset, the honest result is "not needed" and
a short learnings file. Do not build the simulator to justify having started.

## Step 2 — the simulator, and the traces that make it evidence

If Step 1 leaves the question open, build an **offline** comparison. No
production code changes: the point is to find out whether a policy change earns
its place, and a simulation is two orders of magnitude cheaper than a load run.

Create `internal/control/admission_sim_test.go` — a test-only, table-driven
simulation, run explicitly (`go test ./internal/control -run AdmissionSimulation -v`)
and skipped in `-short`, in the style of `BenchmarkCachedEntryFootprint`: it
prints a matrix and asserts the invariants below rather than a wall-clock
figure. It must not import anything the proxy does not already depend on.

**Policies to compare** (each behind one small interface — a candidate, a
victim, and a verdict — so adding one is a function, not a rewrite):

- `freeze` — refuse new entries when full. The pre-0022 behaviour, present as
  the baseline the cliff is measured against.
- `lru` — what ships today.
- `random-sampled` — evict the least recently used of *k* randomly sampled
  entries (k = 2, 5). The cheap middle: ~10 lines in the real cache, no sketch.
- `slru` — segmented LRU, probation and protected segments.
- `tinylfu` — frequency-sketch admission over LRU, with a doorkeeper and a
  reset window. The full answer, and the most expensive.

**Traces to run them against** (working set N, bound M):

- **uniform cycle** at N/M ∈ {0.5, 0.9, 1.0, 1.1, 2, 4, 10} — the poll shape
  scenarios 04/05/08 measure, and the one that produces the cliff.
- **hot set + cold sweep** — a small repeatedly-visited set plus a long tail of
  one-off targets, at hot-traffic fractions of 50%, 80% and 95%. This is the
  pattern `TestCachingClientCachesAWorkingSetItMeetsAfterFilling` protects and
  the one LRU is expected to win; a policy that loses badly here is disqualified
  however well it does elsewhere.
- **Zipf** over N targets (α ≈ 0.9 and 1.2) — the shape real estates usually
  have when nobody has said which of the two above they are.
- **churn** — a working set that drifts, replacing 1% and 10% of its members
  per cycle, which is Q3 turned into a trace.

**The simulator is not evidence until it reproduces the measurements.** Before
any conclusion is drawn from it, it must land within a few points of both
measured points at N = 8,192, M = 4,096, uniform cycle: **`freeze` ≈ 59%** and
**`lru` ≈ 0%**. Assert both in the test. If it cannot, the simulator is wrong —
fix it, do not reinterpret the load results.

Report, per (trace, policy, N/M): hit rate, and the Hoplock Control calls per
connection it implies (2.17 on a hit, 3.17 on a miss, from §9.1's measured
table), so the matrix speaks in the units the decision is made in.

## Step 3 — decide against criteria written before the numbers

State these in the learnings and apply them. **Build only if all four hold:**

1. **A deployment needs it.** Step 1 produced either an estate that cannot be
   sized (Q1) or an explicit "the cliff is unacceptable" (Q4). "Somebody might"
   does not count.
2. **It wins where that deployment lives.** On the traces matching the answers
   to Q2 and Q3, the candidate beats `lru` by **≥ 10 percentage points** of hit
   rate at the N/M ratios the estate would actually run at.
3. **It does not lose where LRU wins.** On the hot-set traces it gives up
   **≤ 2 percentage points** against `lru`.
4. **The saving is worth the code.** Convert the win to Hoplock Control req/s
   at §9.1's 1,167 conn/s five-minute row and say the number. If the honest
   figure is a few percent of PDP load against a frequency sketch in the one
   component the security story leans on, that is a "no" and should be written
   as one.

If two candidates pass, prefer the simpler: `random-sampled` before `slru`
before `tinylfu`. Complexity here is paid forever by every future session
reading `internal/control/cache.go`.

## Deliverables

- The four questions asked verbatim, with their answers (or "unanswered", and
  the assumption made instead), in the learnings.
- `internal/control/admission_sim_test.go`, validated against the two measured
  points, plus the comparison matrix reproduced in the learnings. **Keep it
  whichever way the decision goes** — it is the evidence, and a later session
  asking this again should re-run it rather than re-derive it.
- A written decision with the criteria above applied, in the learnings summary
  block, in one line a future session can read without opening the file.
- **If "yes":** a self-contained implementation prompt queued as the next free
  number (renumber so the contract collapse stays last, `docs/PROTOCOL.md` §6),
  naming the chosen policy, the parameters the simulation picked, the added
  memory per entry, the unit tests it must keep passing (the four in
  `internal/control/cache_test.go` that pin today's behaviour), and the load
  scenarios that must be re-run to confirm it — 04, 05 and 08.
- **If "no":** delete this prompt rather than moving it, and add one line to
  `docs/PLAN.md` §9.1 recording that the question was asked and answered, so
  nobody re-opens it from the same standing start.

## Out of scope
- **Changing the cache's policy.** Not in this phase, whatever the answer. The
  implementation is the next prompt, if there is one.
- The contract, the cache key, the TTL, and who owns a decision's lifetime
  (§6.4, D2) — none of this touches `api/`, so there is no cross-repo
  obligation (`docs/CROSS-REPO-PROTOCOL.md` §1). Confirm that in the PR.
- `control.cache.max_entries`, its default, and `CacheStats` — 0022 shipped
  those and they are not re-opened here.
- Host-key decision caching (**0023**), which may add a second cached shape per
  connection. If it has landed, say what it did to the working set an operator
  must size for; do not re-litigate it.

## Acceptance criteria
- The questions of Step 1 are asked in the session and their answers recorded.
- If the phase proceeds: the simulator exists, reproduces `freeze` ≈ 59% and
  `lru` ≈ 0% at N = 8,192 / M = 4,096 uniform cycle as asserted tests, and
  covers every policy and trace listed.
- `go build ./...`, `go vet ./...`, `go test ./...` and the linter pass; the
  simulation itself does not run in the default `go test ./...` path (it is
  skipped in `-short` and gated behind its own `-run`), because CI is a gate
  and this is a study.
- The decision is stated with the four criteria applied and the Control req/s
  figure named.
- Either a follow-on implementation prompt is queued (numbering invariants
  intact, collapse still last) or this prompt is deleted and §9.1 records the
  answer.
- No change to `api/`.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`, with the conditional-phase exception above: add
`docs/learnings/0032-decision-cache-admission-policy-learnings.md` whichever way
the decision goes. The summary block must carry, in this order: the answers to
Step 1, the decision, the single number that decided it (hit-rate delta and the
Control req/s it is worth), and — if the answer is "no" — what would have to
change about a deployment for the answer to become "yes".
