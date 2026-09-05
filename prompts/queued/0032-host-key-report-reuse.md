# 0032 — Stop re-reporting a host key the server already ruled on

> **Finding from phase 0020, not a new idea.** With decision caching working,
> the host-key report is **46% of the remaining Hoplock Control calls** — a
> proxy reconnecting to a target it has seen ten thousand times reports the same
> key ten thousand times, and asks for the same answer every time.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- **`docs/CROSS-REPO-PROTOCOL.md`** — this phase changes `api/`, which is a
  shared surface (its §1), so the ordering rules, the downstream-impact check
  and the sync kickoff it requires all apply. Read it before writing any code.
- `docs/PLAN.md` — **§6.4** (server-authorised caching, the revocation stream,
  and the fail-closed rule), **§9.1** (the measurement this phase acts on), D7
  (trust-on-first-use), D2.
- `docs/learnings/` — read summaries; open **`0003`** (the cache's key
  semantics, `CacheHint`, and the revocation subscription — this phase reuses
  all of it), **`0005`** (where `ReportHostKey` sits in the connection
  lifecycle), and **`0020`**.

## The finding

`POST /v1/hostkeys/report` runs **once per connection**, unconditionally, and
its response is never reused. Measured: 1.00 calls per connection, which is 46%
of the 2.17 that survive a cache hit — the joint-largest item, level with
authentication, which is uncacheable by design and will stay that way.

Unlike authentication, this one has no reason to be per connection. The proxy
reports (target, host key) and the server answers accept or reject. For an
unchanged key on an unchanged target that is the same question with the same
answer, every time.

## Objective

Let the **server** authorise reuse of a host-key decision, on exactly the
mechanism §6.4 already defines for authorize decisions — so the security
properties are the ones already argued for, rather than new ones.

## The design, and why it is safe

Add an optional `CacheHint` to `HostKeyReportResponse`, and cache the decision
client-side keyed on a request shape that **includes the key fingerprint**.
That last clause is the whole security argument and must not be softened:

- **Same target, same key** → cache hit, no call. The server has already ruled
  on this exact pair.
- **Same target, DIFFERENT key** → a different shape → **miss** → reported. The
  MITM case, the key-rotation case and the rebuilt-host case all still reach the
  server on the first connection that sees the new key. This is the case D7
  exists for and it must never be served from cache.
- **Server changes its mind** → `cache_invalidate` on the existing revocation
  stream. No new mechanism.
- **Stream unheard beyond `stale_after`** → the existing fail-closed rule stops
  serving cached host-key decisions too, and every connection reports again.
- **Proxy restart** → cold cache, everything re-reported. Correct and cheap.

The server stays in charge of whether any of this happens at all: absent hint
means report every time, exactly as today.

## In scope

1. **`api/control.yaml`** — `cache` on `HostKeyReportResponse`, reusing the
   existing `CacheHint` schema. Document that the proxy's reuse is keyed on the
   fingerprint, so a server author can reason about what it is authorising.
2. **`internal/control`** — the contract type, and reuse in `CachingClient`
   alongside the authorize path. A `hostKeyShape` that includes target, port
   **and fingerprint**. `CacheStats` should make host-key reuse separately
   visible from authorize reuse: one number that mixes them cannot answer "which
   call is my Control load".
3. **Invalidation** — host-key entries participate in `Invalidate`,
   `InvalidateAll` and the stale-stream rule. Decide and document what
   `InvalidateSubject` means for an entry that is not keyed on a subject; the
   safe reading is that it does not match, and the reasoning belongs in a
   comment rather than in a reviewer's head.
4. **Evidence** — re-run `load/scenarios/02-cached-decisions.yaml` and record
   Control calls per connection before and after. The claim is a call-rate
   reduction; a phase that does not measure it has not shown it.

## Out of scope
- Caching authentication. Never (§6.4).
- The 4,096-entry bound and its missing eviction policy — that is **0031**, and
  this phase inherits whatever bound it leaves. If 0031 has not landed, say so
  in the learnings: host-key entries share the table and make the bound bite
  sooner.
- Any change to what the proxy does with a `reject`, or to TOFU itself.
- Trusting a locally remembered key without the server ever having ruled on it.
  The proxy must never invent trust; it may only reuse trust the server granted.

## Acceptance criteria
- A second connection to the same target with the same host key makes **no**
  `POST /v1/hostkeys/report` call when the server sent a hint, and the measured
  calls per connection fall from ~2.17 to ~1.17.
- A connection to the same target presenting a **different** key **does** call,
  proven by a unit test. This is the test that matters most in the phase.
- No hint, a zero TTL, or a missing key means report every time.
- `cache_invalidate` and the fail-closed stale rule both drop host-key entries,
  each with a test.
- `api/control.yaml` still validates (`make openapi-check`), and the contract
  version rules in `internal/control` are respected.
- **`docs/CROSS-REPO-PROTOCOL.md` §4's downstream-impact check is done**, and
  the PR carries the ready-to-run sync kickoff for each affected repository.
- `docs/PLAN.md` §6.4 and §9.1 updated with the new measured call rate.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`, **plus `docs/CROSS-REPO-PROTOCOL.md`** — upstream merges
first. Move to `implemented/`; add
`docs/learnings/0032-host-key-report-reuse-learnings.md`. The summary block must
carry the before/after calls per connection, the shape the reuse is keyed on,
and confirmation that a changed key still reports — the next session sizing
Hoplock Control reads the first, and anyone auditing D7 reads the last.
