# 0031 — The decision cache under fan-out

> **Finding from phase 0020, not a new idea.** 0020 measured the authorize
> cache against UC2's access pattern — one subject, very many targets — and
> found that it stops working at a fixed, undocumented, unconfigurable size.
> This phase is the change 0020 proposed and deliberately did not make.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — **§6.4** (server-authorised caching and the revocation
  stream), **§10.1** (the measurements this phase acts on), **§13 UC2**, D2.
- `docs/learnings/0003-policy-caching-and-session-revocation-learnings.md` —
  the cache's key semantics, which this phase does not change.
- `docs/learnings/0020-scale-harness-and-sizing-learnings.md` — the numbers.
- `load/scenarios/04-uc2-fanout.yaml` and `05-uc2-fanout-shared-key.yaml` —
  the two runs that establish the behaviour. Re-running them is how this phase
  proves it fixed something.

## The finding

`internal/control/cache.go` bounds the cache at `DefaultMaxEntries = 4096`
entries **and** 4096 shape mappings. When either is full, `store` returns
without caching. There is no eviction policy: expired entries are pruned, and
nothing else is ever removed. So a proxy whose working set exceeds 4096
distinct (subject, target) pairs caches the first 4096 it sees and then serves
every other connection from the server, permanently.

0020 measured the hit rate at a fixed offered rate as the working set crossed
that bound. It is ~100% at and below 4096 distinct targets and falls as
`4096 / N` above it. Extrapolated to UC2's stated estate — one automation
against 300,000 targets — that is a hit rate near 1%, so the cache effectively
does not exist for the use case it matters most for.

Two things this is **not**:

- It is not the key shape. The server owns the key and may share it as widely
  as it likes; 0020 measured a run where one key covered every target of a
  subject, and the hit rate was unchanged, because the proxy's *shape* map is
  bounded by the same constant. **No server-side key choice can reach this.**
  The bound is in the proxy, which is why the fix is here and not in the
  contract.
- It is not a memory decision anybody took with these numbers in view. A shape
  mapping is two strings; the bound was a sensible guard against unbounded
  growth, chosen in phase 0003 when no proxy existed and no fan-out figure did
  either.

## Objective

Make the decision cache degrade gracefully instead of freezing, and make its
size an operator's choice with a stated cost — without changing who owns a
decision's lifetime, which is still the server (§6.4).

## In scope

1. **Eviction.** When the cache is full, a new decision must displace the
   least recently used one rather than being dropped. A full cache that
   refuses new entries is worse than one that forgets old ones: it makes the
   hit rate depend on which targets a poller happened to visit first.
   `CacheStats` grows an `Evicted` counter beside `Expired`, because "the cache
   is too small" and "the TTLs are too short" have different fixes and today
   both look like a miss.
2. **Configuration.** `control.cache.max_entries` in `internal/config`, wired
   into `CacheOptions.MaxEntries` in `cmd/proxy/main.go`, documented in
   `config.example.yaml` with the memory each entry costs. Zero keeps
   `DefaultMaxEntries`. It must appear in `config.example.yaml` and the struct
   in the same change — the decoder is strict.
3. **A defensible default.** `DefaultMaxEntries` was never sized against a
   measurement. Re-derive it from 0020's measured per-entry cost and say what
   it assumes, in a comment, in the same terms §10.1 uses.
4. **Evidence.** Re-run `load/scenarios/04-uc2-fanout.yaml` and
   `05-uc2-fanout-shared-key.yaml` and record the before/after hit rates in the
   learnings. A cache change whose effect on the measured pattern is not
   reported has not been shown to work.

## Out of scope
- The contract. `CacheHint`, the key's opacity, the server's ownership of the
  lifetime, and the fail-closed stale rule are all unchanged (§6.4, D2).
- The revocation stream, and anything about `InvalidateSubject` /
  `InvalidateAll` semantics.
- The connection model. Whether a machine identity should hold a connection at
  all is 0021; this phase makes the *existing* model behave as documented.
- Any change to what is cached. Authentication is still never cached.

## Acceptance criteria
- A full cache evicts the least recently used entry, and both `entries` and
  `shapes` respect the same bound without either being able to wedge the other.
- `CacheStats.Evicted` counts evictions and is covered by a unit test.
- `control.cache.max_entries` is decoded, validated (non-negative), wired, and
  documented; a config naming it round-trips through `internal/config`'s tests.
- A unit test drives more distinct shapes than the bound and asserts the hit
  rate for a repeating working set, so the regression this phase fixes cannot
  come back silently.
- The 04 and 05 scenarios are re-run and their hit rates recorded in the
  learnings, before and after.
- No change to `api/`, so `docs/CROSS-REPO-PROTOCOL.md` §1's shared surfaces
  are untouched. Confirm that explicitly in the PR.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0031-decision-cache-under-fanout-learnings.md`. The summary
block must carry the before/after hit rates at each working-set size, the new
default and what it was derived from, and whether the eviction policy changed
any figure in `docs/PLAN.md` §10.1 — the next session sizing a fleet reads that
line.
