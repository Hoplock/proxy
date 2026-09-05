# 0020 — Scale harness & sizing evidence — Learnings

## Summary
- **Verdict on D17 — read this line first.** Its premise does **not** survive
  contact with measurement. A connection costs this proxy **2.6 ms of CPU** and
  a live one **118 KiB**, so even its own worst-case 5,800 conn/s is 4–9
  proxies: a deployment, not an architecture. At the interval the customer
  actually confirmed — five minutes — it is **one to two**. Per-check
  provisioning is not the wall D17 calls it either: one target sustains **58
  account cycles/s** against the 0.017/s a 60-second poll asks of it. **0021
  must be argued from audit granularity and Control load, not from the
  connection arithmetic**, and its author should read `docs/PLAN.md` §9.1
  before deciding it is needed at all.
- **The finding that replaces it:** the authorize cache holds a fixed **4,096**
  entries with **no eviction policy**, so UC2's fan-out gets a hit rate of
  `MaxEntries / N` — ~1.4% at 300,000 targets. A server sharing one key across
  every target changes nothing, because the proxy's *shape* map is bounded by
  the same constant. Queued as **0031**.
- **Hardware for every number:** one Intel Xeon @ 2.10GHz, 4 logical cores,
  16 GiB, Linux, Go 1.26 — generator, target and proxy sharing those cores.
- **What shipped:** `cmd/loadgen`, a scenario-driven harness running the real
  proxy binary as a child process against an instrumented Hoplock Control and a
  cheap in-process target; seven committed scenarios and their raw results;
  `make load` / `load-one` / `load-provisioning`; a **manually triggered** CI
  workflow that gates nothing; `docs/PLAN.md` **§9.1**.
- **No behaviour changed.** Nothing under `internal/`, `cmd/proxy`,
  `cmd/mock-control`, `api/` or `deploy/` was touched, so there is no
  cross-repo obligation (`docs/CROSS-REPO-PROTOCOL.md` §1).
- **Key files:** `cmd/loadgen/*.go`, `load/{README.md,scenarios/,results/}`,
  `Makefile`, `.github/workflows/load.yml`, `README.md`, `docs/PLAN.md`
  (**§9.1 new**, §5.1, §6.4, §9, §10 table, §13 UC2, D17),
  `prompts/queued/0031-decision-cache-under-fanout.md`.
- **The customer question was asked and answered:** health checking **is** over
  SSH, at a **five-minute** interval, with sixty seconds kept as a worst case.
  At five minutes the estate is 1,167 conn/s — **one to two proxies** — so the
  connection-volume argument for D17 does not survive at the real interval
  either. §9.1 sizes both rows.

## Details

### The headline numbers

Everything is in `docs/PLAN.md` §9.1 with its methodology; this is the short
form.

| | | |
| --- | --- | --- |
| Proxy CPU per connection (at 600–900 conn/s) | 2.6–2.9 ms | measured |
| Establishment rate sustained | 716 conn/s | measured, a **floor** |
| Establishment rate, CPU-bound | ~1,500 conn/s on 4 cores | derived |
| RSS per live connection | 118 KiB | measured |
| Descriptors per live connection | 2 | measured |
| Control calls per connection, uncached / cached | 3.17 / 2.17 | measured |
| Cache hit rate at 512 / 2,048 / 4,096 / 8,192 targets | 100 / 100 / 100 / 59 % | measured |
| Per-target `ephemeral-user` ceiling | 58 cycles/s | measured |
| One serial provision/teardown cycle | 25.6 ms | measured |

**What saturated, per the acceptance criterion.** Connection establishment:
**CPU**. At the top step the proxy held 121 descriptors of a 20,000 limit and
this run's Control answered in tens of microseconds, so neither was close.
Provisioning: **the target's account-database lock**, and specifically not the
filesystem — removing the home directory and key write moves the cycle by
1.9 ms — and not the NSS backend, which was flat files and is recorded as such
in every result.

### The cache-key finding, stated as the prompt asks

**The key shape is not the problem; the entry bound is.** `authorizeShape` keys
on (subject, login, target, port, auth method, hop trail), which is genuinely
per-target — but the server owns the *cache key* and may share it as widely as
it likes, and scenario 05 gave it the widest scope the contract permits: one key
per subject, covering every target. **The result was identical at every step,
including exactly 4,096 authorize calls at 8,192 targets.**

The reason is in `store`: both `entries` and `shapes` are capped at
`DefaultMaxEntries` (4,096), and when either is full the decision is **dropped**
rather than replacing an older one. There is no eviction policy — only expiry
pruning. So a proxy whose working set exceeds the bound caches the first 4,096
shapes it happens to see and refuses the rest for the life of their TTL. The
bound is also not reachable from `config.yaml`.

Proposed change, written up as **prompt 0031**: LRU eviction, a
`control.cache.max_entries` setting, a default re-derived from the measured
per-entry cost, and a regression test that drives more shapes than the bound.
No contract change — the fix is entirely in `internal/control`, which is what
scenario 05 establishes.

### The customer question, asked and answered

D17's chain rests on an assumption a benchmark cannot settle: that large estates
health-check network devices **over SSH, every sixty seconds**. The question was
put in this session, verbatim:

> For the estate this product is being sized for, what fraction of routine
> health checking runs over SSH rather than SNMP or streaming telemetry, and at
> what interval?

**Answer: it is SSH, at a five-minute interval. Sixty seconds is retained as a
worst case, not as the design target.**

So the row to size against is 1,167 conn/s: **one to two proxies**, and ~3,700
Hoplock Control requests per second. `docs/PLAN.md` §9.1 keeps the 60-second row
beside it, because a worst case worth naming is worth sizing and because a poll
interval changes without anyone re-reading that section.

**What this settles for 0021.** Its connection-volume argument is gone at the
real interval and is single digits even at the worst case. What is left is
Control load and the audit-granularity question — and Control load is the number
that does not amortise, because the cache does not work at this fan-out. 0021
has to stand on those two or not at all.

### Two other findings, not fixed here

- **The host-key report is per connection and never cached.** After caching it
  is a third of the residual Control load, and a proxy reconnecting to a known
  target re-reports the same key every time. It is a *report* rather than a
  decision, so §6.4's caching rules do not cover it; changing that is a contract
  question and deliberately not queued off one measurement.
- **Three connections in ~14,300 failed with an EOF during `exec`**, only at the
  overloaded 900 conn/s step and never at a rate the box could serve. Not
  root-caused and not reproduced below saturation. Recorded so a future run that
  sees it below saturation knows it has something real.

### How the harness is built, and why

- **The proxy is a child process, not a goroutine.** RSS is per process; a
  harness sharing a heap with what it measures cannot say what a live connection
  costs. It also means each run exercises the real startup path — config
  decoding, the revocation subscription, the logging pipeline.
- **Hoplock Control is instrumented in-harness, not `cmd/mock-control`.** That
  server is fixture-driven and exists to make behaviour testable; a fixture with
  8,192 routes is a fixture nobody can read. Both are built from the same
  `internal/control` contract types, so neither can drift from the wire format
  without failing to compile.
- **One in-process target answers for the whole fleet.** The fleet is the
  distinct target *names*, because that is what the cache keys on.
- **Every reported figure is tagged measured or derived**, and a derived one
  prints its arithmetic. The phase exists because §9's predecessor text carried
  derived figures that read like measured ones; a report that repeated the trick
  would be worse than none.
- **Separate from `deploy/` on purpose.** That topology is the acceptance gate
  and must stay fast and deterministic on a shared runner. Separate binary,
  separate make targets, and a `workflow_dispatch`-only job.

### Traps a future session will hit

- **`POST /v1/logs/batch` requires HTTP 202, not 200.** A 200 makes every batch
  fail into the proxy's resilience buffer and turns "Control calls per
  connection" into a measurement of retry behaviour. Cost an hour; there is now
  a test (`TestLogBatchUsesTheStatusTheClientRequires`).
- **`AuthorizeResponse.FilterPolicy` is a value, not a pointer**, so an
  unset one serialises as `{"mode":""}` and the client refuses the whole
  response as a contract violation. Use an empty blacklist, which filters
  nothing. `TestAuthorizeResponseSatisfiesTheContract` catches it.
- **A fan-out warmup must sweep the whole working set.** Below `targets / rate`
  seconds of warmup, a "miss" only means "first visit" and the hit rate is an
  artefact of the run length. The scenarios set warmup accordingly and
  `load/README.md` says so.
- **A target sweep needs `restart_between_steps`.** Cached decisions and warm
  heap carry across steps; without a restart (and the disjoint target names the
  harness assigns per step) a later step measures an entry table an earlier one
  filled. The scenario loader refuses the combination.
- **`make lint` may not run in your sandbox, and `gofmt` is not a substitute.**
  golangci-lint refuses a module whose `go` directive is newer than the Go it
  was built with ("the Go language version (go1.25) used to build golangci-lint
  is lower than the targeted Go version (1.26.0)"), so a sandbox with an older
  binary silently skips the whole lint gate. `gofmt` does **not** cover it:
  goimports with `local-prefixes` wants third-party and local imports in
  separate groups, and gofmt only sorts within a block, so a misgrouped import
  passes gofmt and fails CI. This cost a cycle. The check that does run
  anywhere:

  ```sh
  go run golang.org/x/tools/cmd/goimports@latest -local github.com/hoplock/proxy -l ./cmd/ ./internal/ ./test/
  ```

- **Memory per live connection is a hold-mode measurement only.** Rate-mode
  connections do not overlap long enough to form a plateau; the harness now
  refuses to emit the figure at all outside hold mode rather than emitting noise
  that looks like data.

### Follow-ups created

- **0031 — The decision cache under fan-out.** The change this phase proposes
  and deliberately did not make.

No other prompt was renumbered: 0031 depends on nothing in 0021–0030 and nothing
there depends on it, so it appends. `docs/PLAN.md` §10's table also gained the
**0030** row it had been missing since that prompt was queued.
