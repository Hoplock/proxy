# 0022 — The decision cache under fan-out — Learnings

## Summary
- **What shipped:** the authorize cache now **evicts the least recently used**
  lookup path instead of refusing new decisions when full; the bound is
  `control.cache.max_entries` (validated, wired, documented); the default is
  **4,096 → 32,768**, derived from a measured **1.0 KiB of live heap per
  cached entry** (`BenchmarkCachedEntryFootprint`, ~1.7 KiB of RSS with GC
  headroom); `CacheStats` gained `Evicted` and `Shapes`.
- **Before/after, measured on this repo's harness** (04/05, one subject,
  250 conn/s, 40 s warmup, per-target and shared key — both runs identical at
  every step):

  | Distinct targets | Before (bound 4,096) | After (default 32,768) |
  | --- | --- | --- |
  | 512 / 2,048 / 4,096 | 100% / 100% / 100% | 100% / 100% / 100% |
  | 8,192 | **59%** | **100%** |

  Control calls per connection at 8,192 targets: 2.58 → **2.17**, §6.4's cached
  figure reached at fan-out for the first time.
- **The number a future session must not miss:** at a working set *larger* than
  the bound, LRU is **worse** than the old freeze under a strict poll cycle.
  New scenario `08-uc2-fanout-evicting.yaml` pins `max_entries: 4096` and
  measures **0%** at 8,192 targets where the pre-0022 code gave 59%. Eviction
  buys a *changing* working set; **sizing** buys a fan-out. Both statements are
  in `docs/PLAN.md` §9.1, and whether that cliff needs an admission policy is
  the question queued as **0032** (see "Follow-up" below).
- **Key files:** `internal/control/cache.go` (+`cache_test.go`,
  new `cache_bench_test.go`), `internal/config/config.go` (+test),
  `cmd/proxy/main.go`, `config.example.yaml`, `cmd/loadgen/{scenario,proxyproc,connrun,report}.go`,
  `load/scenarios/{04,05,08}*.yaml`, `load/results/{04,05,08}*.json`,
  `docs/PLAN.md` (§6.4, §9.1, D17, §10 table).
- **Interfaces/types:** `CacheStats.Evicted`, `CacheStats.Shapes`;
  `config.Cache.MaxEntries` / `control.cache.max_entries`; scenario knob
  `proxy.cache_max_entries` and result field `proxy_cache_max_entries`.
  `CacheOptions.MaxEntries` keeps its name and now bounds **lookup paths**.
- **Decisions:** D2 and §6.4 unchanged — the server still owns the key, the
  lifetime and the sharing scope. **No change to `api/`**, so no cross-repo
  obligation (`docs/CROSS-REPO-PROTOCOL.md` §1).
- **Gotcha:** `MaxEntries` bounds shapes, not decisions. A decision lives while
  some shape names it (reference counted), so a server sharing one key across
  10,000 targets stores **one** decision and **10,000** lookup paths — and it
  is the 10,000 that has to fit. `Stats().Shapes` is the number to compare
  against the setting; `Entries` is not.

## Details

### What was wrong, restated from the code

`store` refused to cache once either map was full: `len(entries) >= maxEntries`
or `len(shapes) >= maxEntries` returned without storing, and nothing but expiry
ever removed anything. A proxy whose working set exceeded 4,096 cached the first
4,096 shapes it happened to see and served every other connection from the
server for as long as those TTLs kept renewing. Phase 0020 measured it: exactly
4,096 authorize calls at 8,192 targets, identical whether the server issued a
key per target or one key for the whole estate, because the *shape* map carried
the same constant.

### What replaced it

One bound, over the lookup paths, with a recency list:

- `shapes` maps a request shape to a `shapeMapping{key, elem}`, where `elem` is
  the shape's place in a `container/list` ordered most-recently-used first.
- `entries` holds decisions by the server's key, each with a `refs` count of
  how many shapes name it. Dropping the last shape that names a decision drops
  the decision; that is what keeps two tables bounded by one number, and it is
  why neither can wedge the other (the old failure mode: a full shape map
  refusing entries the entry map had room for).
- A hit moves its shape to the front. A store that needs room prunes expired
  entries first (free, and nobody wanted them) and then evicts from the back,
  counting `CacheStats.Evicted`.

`Evicted` is deliberately a separate counter from `Expired`: "the cache is too
small" and "the server's TTLs are shorter than my revisit interval" are
different operator actions and both used to look like a miss.

### The default, and what it assumes

`BenchmarkCachedEntryFootprint` fills a cache with a realistic decision (a
route, a channel allow-list, a request policy, four filter rules, a deadline,
a decision id) and reports heap bytes per lookup path:

| Sharing | Bytes per lookup path | |
| --- | --- | --- |
| Key per (subject, target) | **1,022–1,039 B** | measured, 20k–100k working sets |
| One key for the whole subject | **203–212 B** | measured |

32,768 × 1.0 KiB ≈ **32 MiB of live heap**, ~55 MiB RSS with default GC pacing.
That is the RSS of ~470 live connections at §9.1's 118 KiB, or 5% of a 1 GiB
proxy — and only paid by a proxy that has actually seen 32,000 distinct pairs.
The assumption is stated in the constant's comment: a working set of at most
~32,000 distinct (subject, login, target, port, method, hop trail) shapes
between restarts. **UC2's 300,000-target estate is not that** and sets
`control.cache.max_entries: 300000`, paying ~300 MiB for it deliberately.

The process-level cross-check is in the load results: at 8,192 targets peak RSS
went 25.6 MiB → 33.2 MiB with the key-per-target run holding twice as many
entries (~1.7 KiB per entry, the gap to 1.0 KiB being GC headroom), and only
+0.5 KiB per target on the shared-key run — the first measurable benefit a
server gets from sharing a key widely.

### The evidence, including the part that is not flattering

Re-ran 04 and 05 against a binary built from `origin/main` (before) and from
this branch (after), same container, same hardware as §9.1. The before-run
reproduced 0020 to the entry: 100/100/100/59% and exactly 4,096 authorize calls
at 8,192 targets, on both scenarios.

After: 100% at every step of both, zero authorize calls, 2.17 Control calls per
connection.

`08-uc2-fanout-evicting.yaml` is new and exists to keep the honest half
reproducible: the same sweep with `max_entries` pinned at 4,096 gives 100% at
4,096 targets and **0%** at 8,192 — worse than the 59% the same bound gave
before this phase. A strict cycle over a working set larger than the cache is
LRU's worst case: every entry is evicted about one visit before it is wanted,
where refusing to store held on to whichever 4,096 shapes arrived first.

That trade was made with eyes open and is the phase's one real caveat:

- eviction is what makes a **changing** working set cacheable at all — before
  this phase a cache filled by a cold sweep refused everything that came after
  it, permanently, which is what
  `TestCachingClientCachesAWorkingSetItMeetsAfterFilling` pins;
- for a working set larger than the cache, the fix is the cache's **size**,
  which before this phase was not something an operator could change;
- `CacheStats.Evicted` is how a running proxy says which case it is in.

### Follow-up: the question, queued as 0032

A scan-resistant **admission** policy (TinyLFU-style: admit a candidate only
when it looks hotter than the victim) would get both behaviours — LRU's
adaptation *and* the incumbent-set stability that gives `MaxEntries / N` under
a uniform cycle. It was not built here: it changes the eviction policy this
phase's acceptance criteria pin, it needs a frequency sketch and its own
measurements, and an operator has a direct fix today (raise `max_entries`,
which `Evicted` tells them to do).

What is *not* obvious is whether it is needed at all, so the **question** was
queued rather than the answer:
`prompts/queued/0032-decision-cache-admission-policy.md`. It is conditional in
the way 0021 was — it asks four deployment questions (can operators size the
cache to the estate; is the traffic a uniform sweep or a hot set with a tail;
does the working set churn; is the cliff itself acceptable), builds an offline
policy simulator validated against **both** of this phase's measured points
(`freeze` ≈ 59% and `lru` ≈ 0% at 8,192 targets against a 4,096 bound), and
decides against criteria written before the numbers. A "no" is a legitimate
outcome and is written up rather than built. Queuing it moved the contract
collapse from 0032 to **0033**, which must stay last; the mapping is the newest
note at the end of `docs/PLAN.md` §10.

The arithmetic that made this a question rather than a task, for whoever picks
it up: at UC2's 300,000 targets against the shipped 32,768-entry default, an
admission policy would restore `bound / N` ≈ 10.9% — worth ~120 Control req/s
of the ~3,690 at §9.1's five-minute row, about 3%. Sizing `max_entries` to the
estate instead is worth ~1,160 req/s, about 31%. **The argument for the phase
is the cliff, not the throughput:** the step from ~100% to ~0% as a fleet grows
past the bound is an operational surprise met in production rather than in a
config file.

### Test notes

- `TestCachingClientEvictsTheLeastRecentlyUsed` — recency, not insertion order,
  picks the victim; `Evicted` counts it.
- `TestCachingClientCachesAWorkingSetItMeetsAfterFilling` — the regression
  test the acceptance criteria asked for: a cold sweep of four times the bound,
  then a repeating working set of eight, which must cost eight authorize calls
  over ten rounds. Against the pre-0022 code it costs eighty.
- `TestCachingClientBoundsSharedShapes` — three times the bound of distinct
  shapes under **one** server key: shapes stay bounded, the single decision
  survives, neither table wedges the other.
- `TestCachingClientDropsADecisionWithItsLastShape` — the reference counting.
- `TestParseCacheSize` / `TestValidate` cases — the setting round-trips and
  rejects a negative.
- `BenchmarkCachedEntryFootprint` is a measurement, not a throughput
  benchmark: `-benchtime 20000x` makes b.N the working set. Re-run it before
  changing the default, and re-run 04/05/08 before quoting a hit rate.
