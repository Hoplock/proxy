# 0032 — Does the decision cache need an admission policy? — Learnings

## Summary
- **Step 1's four questions, asked in the session and answered by the operator:**
  **Q1 sizing —** "usually, but not always": most estates can set
  `control.cache.max_entries` to cover the working set, some constrained ones
  cannot. **Q2 traffic shape —** mixed, Zipf-like; not a strict sweep and not a
  pure hot set. **Q3 churn —** environment-dependent: very high on cloud with
  ephemeral machines, low on-prem. **Q4 is the cliff acceptable —** deferred to
  the numbers ("let the simulator decide") after a clarification exchange.
- **Verdict: NO. Nothing was built, and that is the deliverable.** LRU stands,
  `internal/control/cache.go` is unchanged, and **0032 is retired and must
  never be reused**. Criteria 2 and 4 fail; criterion 3 additionally
  disqualifies the two cheap candidates.
- **The single number that decided it.** On the traces matching Q2 *and* Q3
  together, the best candidate beats LRU by **1.6 percentage points of hit
  rate** — 84.3% → 85.9%, worth **~18 Hoplock Control req/s out of 2,715** at
  §9.1's five-minute row, **0.7% of PDP load** — against a bar of ≥10 points.
  At Q3's high-churn (cloud) end LRU **wins** by 1.7 points, so the honest
  figure is not even one-signed.
- **What would make it "yes":** an estate that sweeps its whole fleet in a
  **strict uniform cycle** *and* cannot size its cache. There the same
  simulator measures TinyLFU at 49.2% against LRU's 0% — **~574 req/s, 15% of
  PDP load** — which would clear every criterion. The cliff is real; it is a
  property of that access pattern, and this estate does not have it.
- **Key files:** `internal/control/admission_sim_test.go` (new, test-only),
  `docs/PLAN.md` (§9.1 new subsection, §10 phase table + composed mapping +
  queue note), `docs/PROTOCOL.md` §6 and `docs/learnings/{README,0022-…}`
  (retired-number lists and a one-line pointer);
  `prompts/queued/0032-…` **deleted**. **No production code changed**; nothing
  under `api/`, so no cross-repo obligation (`docs/CROSS-REPO-PROTOCOL.md` §1).
- **What the NEXT session must know:** the simulator is kept on purpose — re-run
  it, do not re-derive it: `go test ./internal/control -run AdmissionSimulation -v`.
  Its calibration against the two measured points runs in ordinary `go test ./...`.

## Details

### The four questions, verbatim, and what came back

Phase 0020 established the habit: a question a benchmark cannot settle gets
asked, in the session, verbatim. These were asked before any code was written.

> **1. Can operators size the cache?** For the estates this product is sized
> for, can a proxy be given ~1 KiB of heap per (subject, target) pair it serves
> — about **300 MiB for a 300,000-target estate** — or is there a memory ceiling
> that will force `control.cache.max_entries` below the working set?

**"Usually, but not always."** Most estates can size it; some constrained
deployments (small VM, container memory limit) would be forced to run with
`max_entries` below the working set.

The question was put with 0023 folded in, as this prompt's out-of-scope section
requires: a server hinting **both** decisions gives a proxy two lookup paths per
connection sharing one bound, so the 300 MiB above is **~600 MiB** for the same
300,000 targets, and an estate sized to its target count under 0022 covers half
as many targets now. That is the figure the operator answered against.

> **2. What shape is the traffic?** Does an automation sweep its whole estate in
> a fixed cycle, or is there a hot subset polled far more often than the tail?
> If both, roughly what fraction of connections go to the hot subset?

**"Both / mixed (Zipf-like)."** Some hot targets plus a long sweep. Neither a
pure cycle nor a pure hot set.

> **3. How stable is a proxy's working set?** Does it churn between restarts —
> targets added and retired, subjects rotating — or is it essentially fixed?

**"Dependent on the environment. On cloud with ephemeral machines the churn is
very high, on-prem there is low churn."** Both ends are therefore in the matrix
(1%/cycle and 10%/cycle), and neither is treated as the default.

> **4. Is the cliff itself acceptable?** Given that `Evicted` names the cause and
> the bound is a config line, is "the hit rate steps down when the fleet outgrows
> the cache" tolerable, or must the degradation be gradual?

**Deferred to the evidence: "let the simulator decide."** The operator first
asked what the difference between a cliff and a slope actually is in
implementation terms, and whether a slope would start degrading *before*
`max_entries` is reached. The answer given, and the one that matters for
anyone reading this later:

- **Neither shape does anything below the bound.** Nothing is evicted while the
  working set fits, so every policy is 100% and identical. A slope does *not*
  start early.
- Above the bound, LRU **collapses** rather than sagging, because a strict poll
  cycle evicts each entry about one visit before it is next wanted. It is a
  property of the access pattern, not of the size of the overshoot — which is
  why 1% of fleet growth costs 46% more PDP load.
- A slope is `≈ M/N`: 99% at N/M = 1.01, 50% at 2, 10% at 10.
- **Every slope policy produces its slope by protecting incumbents**, which is
  precisely the wrong instinct for Q3's cloud answer: a working set that has
  legitimately turned over has to fight its way back in.

That last point is what the numbers then confirmed, and it is the shape of the
whole result.

### The simulator

`internal/control/admission_sim_test.go`. Test-only, standard library only,
deterministic (seeded PCG), no production code touched. Policies sit behind one
three-part seam — a candidate, a victim, and a verdict — so adding one is a
function rather than a rewrite.

**Calibration is what makes it evidence**, and it runs in ordinary
`go test ./...` rather than only under the study's own `-run`:

| At N = 8,192, M = 4,096, uniform cycle | Measured | Simulated |
| --- | --- | --- |
| `freeze` (pre-0022) | 59% (0020, reproduced) | **59.0%** |
| `lru` (ships today) | 0% (scenario 08) | **0.0%** |

**Why 59% and not `M/N` = 50%.** This took working out and is worth recording.
`cmd/loadgen`'s connection index is monotonic across the warmup — `driver.reset()`
deliberately does not reset `nextIndex` — so the measured window starts partway
through a sweep rather than at target 0. At scenario 08's 40 s warmup and 9,999
measured connections that offset is 1,808, and it yields 59.04% and **exactly
4,096 misses**. The simulator reproduces it by modelling the same continuous
stream. `TestAdmissionSimulationCycleSteadyStateIsMOverN` pins the steady state
of the same trace at 50% so a reader of the matrix is not left thinking the two
figures disagree.

### The matrix

Bound M = 4,096 lookup paths throughout, so N/M is the only thing moving.
Each cell is **hit% | Hoplock Control calls/connection | Control req/s** at
§9.1's five-minute row (1,167 conn/s), using §9.1's measured 2.17 calls on a hit
and 3.17 on a miss.

```
trace                               freeze                  lru                     random-2                random-5                slru                    tinylfu
uniform-cycle N/M=0.50              100.0  2.17    2532       100.0  2.17    2532       100.0  2.17    2532       100.0  2.17    2532       100.0  2.17    2532       100.0  2.17    2532
uniform-cycle N/M=0.90              100.0  2.17    2532       100.0  2.17    2532       100.0  2.17    2532       100.0  2.17    2532       100.0  2.17    2532       100.0  2.17    2532
uniform-cycle N/M=1.00              100.0  2.17    2532       100.0  2.17    2532       100.0  2.17    2532       100.0  2.17    2532       100.0  2.17    2532       100.0  2.17    2532
uniform-cycle N/M=1.10               90.9  2.26    2638         0.0  3.17    3699        74.7  2.42    2827        55.7  2.61    3049         0.0  3.17    3699        90.6  2.26    2642
uniform-cycle N/M=2.00               50.0  2.67    3116         0.0  3.17    3699         8.3  3.09    3602         0.5  3.16    3693         0.0  3.17    3699        49.2  2.68    3125
uniform-cycle N/M=4.00               25.0  2.92    3408         0.0  3.17    3699         0.1  3.17    3698         0.0  3.17    3699         0.0  3.17    3699        19.2  2.98    3475
uniform-cycle N/M=10.00              10.0  3.07    3583         0.0  3.17    3699         0.0  3.17    3699         0.0  3.17    3699         0.0  3.17    3699         9.9  3.07    3584
hot-set 50% hot, one-off tail        36.2  2.81    3277        36.1  2.81    3278        32.7  2.84    3317        35.1  2.82    3290        50.0  2.67    3116        50.0  2.67    3116
hot-set 80% hot, one-off tail        78.5  2.38    2783        78.8  2.38    2780        72.1  2.45    2858        76.5  2.40    2806        80.1  2.37    2765        80.1  2.37    2765
hot-set 95% hot, one-off tail        95.0  2.22    2591        95.0  2.22    2591        93.2  2.24    2612        94.7  2.22    2594        95.0  2.22    2591        95.0  2.22    2591
zipf a=0.9 N/M=1.1                   97.6  2.19    2560        97.7  2.19    2559        97.3  2.20    2564        97.5  2.20    2562        97.8  2.19    2559        97.7  2.19    2559
zipf a=0.9 N/M=2.0                   84.8  2.32    2710        84.7  2.32    2711        83.0  2.34    2730        84.1  2.33    2718        86.6  2.30    2689        86.4  2.31    2691
zipf a=0.9 N/M=4.0                   72.0  2.45    2859        72.0  2.45    2859        70.1  2.47    2881        71.4  2.46    2866        76.5  2.40    2806        75.3  2.42    2821
zipf a=1.2 N/M=1.1                   98.0  2.19    2556        98.0  2.19    2556        98.0  2.19    2556        98.0  2.19    2556        98.0  2.19    2556        98.0  2.19    2556
zipf a=1.2 N/M=2.0                   96.2  2.21    2577        96.2  2.21    2577        95.7  2.21    2583        96.0  2.21    2579        96.5  2.21    2574        96.3  2.21    2576
zipf a=1.2 N/M=4.0                   93.1  2.24    2612        93.1  2.24    2613        92.3  2.25    2622        92.9  2.24    2615        94.2  2.23    2600        93.4  2.24    2609
churn 1%/cycle N/M=1.1               78.8  2.38    2780         0.0  3.17    3699        71.2  2.46    2868        54.3  2.63    3065         0.0  3.17    3699        86.8  2.30    2686
churn 1%/cycle N/M=2.0               43.6  2.73    3190         0.0  3.17    3699         8.2  3.09    3604         0.5  3.17    3694         0.0  3.17    3699        48.3  2.69    3136
churn 10%/cycle N/M=1.1              25.4  2.92    3403         0.0  3.17    3699        54.5  2.63    3064        45.1  2.72    3174         0.0  3.17    3699        52.6  2.64    3085
churn 10%/cycle N/M=2.0              13.9  3.03    3537         0.0  3.17    3699         7.4  3.10    3613         0.5  3.17    3694         0.0  3.17    3699        38.8  2.78    3247
zipf a=0.9 + churn 1% N/M=2.0        67.4  2.50    2913        84.3  2.33    2715        82.8  2.34    2733        83.8  2.33    2721        85.9  2.31    2697        85.2  2.32    2705
zipf a=0.9 + churn 10% N/M=2.0       22.4  2.95    3438        81.8  2.35    2745        79.5  2.38    2772        81.1  2.36    2753        80.1  2.37    2765        76.9  2.40    2802
zipf a=1.2 + churn 1% N/M=2.0        89.0  2.28    2661        95.9  2.21    2581        95.2  2.22    2589        95.7  2.21    2583        96.0  2.21    2579        95.8  2.21    2581
zipf a=1.2 + churn 10% N/M=2.0       37.2  2.80    3265        93.5  2.23    2608        92.7  2.24    2618        93.3  2.24    2611        92.6  2.24    2618        92.4  2.25    2621
```

**The last four rows are the ones the decision rests on, and they are not in the
prompt's list.** The prompt asked for uniform-cycle, hot-set, Zipf and churn
traces — but Q2 answered "Zipf-like" and Q3 answered "churning", and criterion 2
is to be applied "on the traces matching the answers to Q2 and Q3". No listed
trace is both: `zipf` has a fixed population and `churn` is a strict cycle that
drifts, and a strict cycle is the one shape that pins LRU at zero. Deciding from
the `churn` rows alone would have credited an admission policy with beating LRU
by 38–87 points on an access pattern the operator had just said they do not
have. `zipfChurn` — Zipf popularity over a population that retires uniformly at
random — is that estate, and it is where the answer flips.

### The criteria, written before the numbers and applied to them

Build only if **all four** hold.

1. **A deployment needs it — MET (weakly).** Q1 was not an unqualified yes:
   "usually, but not always" concedes constrained deployments that cannot size
   the cache. Q4 produced no independent "the cliff is unacceptable". So this
   criterion passes on Q1 alone, and it is the only one that does.
2. **It wins where that deployment lives — FAILS, by a factor of six.**
   Bar: ≥ 10 points over `lru` on the traces matching Q2 and Q3.

   | Trace (Q2 + Q3) | `lru` | best candidate | delta |
   | --- | --- | --- | --- |
   | zipf α=0.9 + churn 1% | 84.3% | `slru` 85.9% | **+1.6** |
   | zipf α=0.9 + churn 10% | 81.8% | `slru` 80.1% | **−1.7** |
   | zipf α=1.2 + churn 1% | 95.9% | `slru` 96.0% | **+0.1** |
   | zipf α=1.2 + churn 10% | 93.5% | `random-5` 93.3% | **−0.2** |

   The best delta anywhere on this estate is +1.6 points, and half the rows are
   negative. On the plain Zipf traces (no churn) the picture is the same: the
   largest win is `slru` at +4.5 points (α=0.9, N/M=4), still less than half the
   bar.
3. **It does not lose where LRU wins — FAILS for the cheap candidates.**
   Bar: give up ≤ 2 points on the hot-set traces.
   `random-2` gives up **6.7** points at 80% hot and 3.4 at 50%; `random-5`
   gives up **2.3** at 80% hot. Both are **disqualified**, as the prompt says,
   however well they do elsewhere — and they are the only candidates cheap
   enough to have been worth it. `slru` and `tinylfu` pass (+13.9 at 50% hot,
   +1.3 at 80%, level at 95%), which leaves only the expensive options standing
   in front of criterion 2, where they fail.
4. **The saving is worth the code — FAILS, and this is the line to quote.**
   +1.6 points is 2.33 → 2.31 Control calls per connection: **2,715 → 2,697
   req/s** at §9.1's 1,167 conn/s five-minute row. **~18 req/s, 0.7% of PDP
   load** — and −20 req/s on the high-churn row. The price is a count-min
   sketch, a doorkeeper and a reset window living in
   `internal/control/cache.go` forever, in the one component the security story
   leans on. The prompt named this case in advance: "if the honest figure is a
   few percent of PDP load against a frequency sketch … that is a 'no' and
   should be written as one."

**Memory was never the objection.** The sketch sized for a 4,096-entry cache
costs **3.0 bytes per cached entry** (4-bit counters packed two per byte, plus
the doorkeeper) against the ~1,024 bytes an entry already costs — **+0.3%**.
The cost is complexity, and complexity here is paid by every future session
reading that file.

### What a later session should do instead of re-deriving this

Re-run the simulator: `go test ./internal/control -run AdmissionSimulation -v`.
It is kept for exactly this. Add a trace or a policy to the tables in
`simCases()` / `simPolicies()` — a policy is one `admission` implementation —
and the matrix recomputes. If the calibration test fails, **the simulator is
wrong; fix it rather than reinterpreting the load results.**

Reopen the decision if an estate appears that **sweeps its whole fleet in a
strict uniform cycle and cannot size its cache**. That is the row where the
answer changes sign: at N/M = 2, `tinylfu` 49.2% against `lru` 0.0% is
3,699 → 3,125 req/s, **~574 req/s or 15% of PDP load**, which clears criterion 4
outright. Everything else in the matrix says "size the cache".

### Deviation from the prompt

**The calibration test runs in the default `go test ./...` path; the matrix does
not.** The prompt asked for the whole simulation to be skipped in `-short` and
gated behind its own `-run`, "because CI is a gate and this is a study". The
matrix is gated exactly so (`requireExplicitRun`, which checks `-test.run` as
well as `-short`, because this repository's CI runs `go test -race ./...` with
no `-short` and a `-short` check alone would not have kept it out).

The two calibration assertions are deliberately **not** gated. They take
milliseconds, and they are not the study — they are the check that the study's
instrument is still calibrated. A calibration check nobody runs is not a check,
and this file is meant to be picked up by a session months from now.

### Notes for whoever touches the plan's indexes next

Not acted on here, because it is outside this phase's scope and this phase
changed nothing that made it wrong: §10's mapping prose says "Almost every
number in this repository is *both* a live phase and a historical alias of a
different one — **29 of 37** are." 29 is the count of numbers that are a
historical alias; the count that is *simultaneously* a live phase and an alias
is 27 (26 after this withdrawal). Either the figure or the sentence wants a word
changed, and `test/docs/indexes_test.go` does not check it.

### What was deliberately not modelled

- **TTL expiry.** The load runs cache for an hour and measure for forty seconds,
  so nothing expires in them either; adding expiry would make the simulation and
  the measurement disagree for a reason unrelated to policy.
- **The shape → decision indirection.** `MaxEntries` bounds lookup paths
  (0022's gotcha), and a lookup path is exactly what every policy here holds, so
  the reference-counted decision table underneath does not change any hit rate.
- **Wall-clock cost.** This compares hit rates. A policy that wins on hit rate
  can still lose on the code a future session has to read, and in this phase
  that consideration did not have to be invoked — the hit rates decided it.
