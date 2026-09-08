# 0023 — Host-key report reuse — Learnings

## Summary
- **The numbers, measured on this repo's harness** (02 vs 09, identical but for
  one knob; Intel Xeon @2.10GHz, 4 cores, 16 GiB): Control calls per connection
  **2.173 → 1.173**, `POST /v1/hostkeys/report` **1.000 → 0.000/conn**, host-key
  cache hit rate **0% → 100%**. The 02 re-run reproduced the pre-phase 2.17 to
  three decimals, so this is a comparison and not two unrelated runs. What is
  left is `auth/cert` at 1.000 and `logs/batch` at 0.173 — **one
  authentication per connection**, which §6.4 never caches by design.
- **The shape the reuse is keyed on:** `target`, `target_port` **and
  `host_key.fingerprint`** (plus key type and the certificate flag), never the
  target alone. `hostKeyShape` in `internal/control/cache.go`.
- **A changed key still reports — this is the audited claim.**
  `TestCachingClientAlwaysReportsAChangedHostKey`: same target, same port,
  different fingerprint ⇒ different shape ⇒ miss ⇒ reported, however long the
  old decision is valid. Two answers are never reused whatever the server hints:
  a `reject`, and a first sighting (`known: false`).
- **What shipped:** optional `cache` on `HostKeyReportResponse` (**contract
  4.1**; `policy_version` stays **4**), reuse in `CachingClient` beside the
  authorize path, per-kind `CacheStats`, mock-control `host_keys.cache`, a
  loadgen knob and scenario 09.
- **Key files:** `api/control.yaml`, `api/README.md`,
  `internal/control/{contract,clone,cache}.go` (+`cache_test.go`),
  `internal/config/config.go`, `config.example.yaml`,
  `cmd/mock-control/{server,fixtures,fixtures.example.yaml}`,
  `cmd/loadgen/{scenario,control,connrun,report}.go`,
  `load/scenarios/09-cached-hostkey-decisions.yaml`,
  `load/results/{02,09}*.json`, `Makefile`, `docs/PLAN.md` (§6.4, §9.1, D17, §10).
- **Interfaces/types:** `HostKeyReportResponse.Cache *CacheHint`,
  `(*HostKeyReportResponse).Clone`; `CacheStats.{HostKeyHits,HostKeyMisses,HostKeyStored}`;
  unexported `entryKind`/`entryKey`/`hostKeyShape`. `CacheHint` is unchanged and
  now rides two responses.
- **Decisions:** D2, D7 and §6.4 unchanged in substance — the server still owns
  the key, the lifetime and the sharing scope, and D7's report-on-a-new-key is
  intact by construction. **`api/` changed, so this carried a cross-repo
  obligation** (`docs/CROSS-REPO-PROTOCOL.md`): `hoplock/control` owes a sync;
  `hoplock/enterprise` does not consume `api/` and owes nothing.
- **What the NEXT session must know:** a server hinting both decisions gives a
  proxy **two cached lookup paths per connection**, and they share
  `control.cache.max_entries`. An estate sized to its target count under 0022
  now covers half as many targets, and nothing in the setting's name says so.

## Details

### Why the fingerprint is in the shape and nothing may soften it

The whole security argument is one clause: the proxy reuses a decision only for
the exact `(target, port, fingerprint)` the server ruled on. A cache hit
therefore means "the server has already answered *this* question", never "the
server has answered *a* question about this target". The three cases D7 exists
for — a man in the middle, a rotated key, a rebuilt host — all present a
fingerprint this proxy has no entry for, so all three miss and are reported on
the first connection that sees the new key.

The server cannot widen that. It owns *whether* reuse happens (the hint) and
*for how long* (the TTL) and *what invalidation groups with what* (the key). The
shape is the proxy's, and no value in the contract changes it. That split is
what let this phase reuse §6.4's argument wholesale instead of making a new one.

A report the proxy cannot key that way — no fingerprint, or no target — is never
cached at all. The alternative would be keying on the target alone, which is
precisely the reuse D7 forbids, so the absence fails towards reporting.

### The two answers that are never reused, and why they are the proxy's rule

Both could have been left to the server ("just don't hint those"). They are
enforced client-side instead, because in each case reusing the response would
make the proxy say something untrue:

- **`reject`.** Symmetry with the authorize path, which never caches a deny: a
  deny is as revocable as an allow and the server re-decides it for free. The
  sharper reason here is evidence — a rejected host key is a security event, and
  a proxy that stopped reporting repeat attempts would be withholding exactly
  the signal a SOC wants.
- **`known: false`.** This one is easy to miss and it bites the audit log, not
  just the console. The proxy records `resp.Known` on the session's host-key log
  record and logs "trusted on first use, reported to Hoplock Control". Replaying
  a first-sighting response would put that on every later connection — a claim
  that a report was made when none was. Normalising `Known` to `true` in the
  cache was the alternative and was rejected: the proxy would be inventing a
  contract value. Declining to reuse costs exactly one extra report per
  (target, key) per process, and the connection after it is free.

Consequence worth stating plainly, because it reads like a gap in the
acceptance criteria: with a server that has **already** ruled on the key —
which is the steady state the 46% figure is about — the *second* connection is
free. With a genuinely new key it is the *third*. The load runs measure the
first case because the warmup sweeps every target past its first sighting, which
every cache scenario already had to do for the authorize decision.

### One table, two kinds

Authorize and host-key decisions share `CachingClient`'s tables. The entries map
is keyed by `entryKey(kind, serverKey)`, and shapes are prefixed by kind, so a
server that issued one key string for both cannot have one served in answer to
the other; `Invalidate` still matches on the raw server key and drops both,
which is the safe direction for that ambiguity to fall
(`TestOneKeyForTwoKindsIsNeverCrossServed`).

Sharing the table means sharing `MaxEntries`, and that is the operational cost
of this phase. It is written into `config.example.yaml`, `config.Cache.MaxEntries`,
`CacheStats.Shapes` and PLAN §6.4/§9.1, because an operator will otherwise meet
it as a hit-rate regression with no name on it.

**`InvalidateSubject` deliberately does not match host-key entries.** A
host-key decision is not made for a subject — the question is about the target's
identity and the answer is the same for everyone — so dropping it when one
user's access is withdrawn would protect nobody and would make the next
connection by an unaffected user re-report a key the server has already ruled
on. Withdrawing host-key trust is what `cache_invalidate` **with the key** and
`resync` are for. The entries carry `subject: ""` anyway, so the rule would hold
without the explicit `kind` check; the check is there so the next reader does
not have to derive it (`TestInvalidateSubjectLeavesHostKeyDecisionsAlone`).

### Contract 4.1, and why `policy_version` did not move

`policy_version` numbers what `/v1/authorize` may answer with. That response is
decoded **strictly** — an unknown field is a contract violation, because an
unknown field there may be a restriction and a dropped restriction is a widened
session. `HostKeyReportResponse` is decoded non-strictly, the new field grants
rather than restricts, and its absent value is precisely what every server does
today. A proxy that has never heard of it ignores it and keeps reporting, which
is correct behaviour rather than a dropped restriction. So the document version
goes `4.0.0 → 4.1.0` (the same precedent phase 0016 set at 3.0.0 → 3.1.0) and
`control.PolicyVersion` stays `4`.

Phase **0033** now has its blocker cleared: 0023 was the last queued phase that
revises the contract. Its prompt has been updated to say so, and to say which
part of the 4.1 prose is live reasoning to keep rather than history to delete.

### Evidence: how the before/after was produced

Two committed scenarios differing in **one knob**, so the difference is
attributable:

| | `02-cached-decisions.yaml` | `09-cached-hostkey-decisions.yaml` |
| --- | --- | --- |
| `control.cache_hint` | true | true |
| `control.host_key_cache_hint` | — | **true** |
| everything else | identical | identical |

`control.host_key_cache_hint` is a separate knob rather than a widening of
`cache_hint` for exactly this reason: authenticate and report-host-key were the
joint-largest items in the residue (§9.1), and one flag covering both would have
made their contributions inseparable. `StepResult` gained `host_key_calls` and
`host_key_cache_hit_rate_pct` beside the authorize pair, derived the same way
and exact for the same reason — one connection reports one host key, so a
connection that produced no report was served from cache.

The instrumented server hints only a key it has already ruled on and accepted,
mirroring what the proxy will actually reuse. `cmd/mock-control` gained the same
under `host_keys.cache`, so a fixture-driven test or a manual run can exercise
reuse too.

### Fixed in passing: the load make targets grouped scenarios by number

`LOAD_SCENARIOS` was `0[1-5]-*.yaml` and `LOAD_PROVISIONING` was `0[6-9]-*.yaml`,
so phase 0022's `08-uc2-fanout-evicting.yaml` — a **connection** scenario — sat
in the group that requires root and creates real local accounts, and `make load`
never ran it. Adding a connection scenario at 09 would have compounded that, so
both variables now select on the scenario's own `kind:` line. This was in the
way of the work rather than an unrelated cleanup, and it is the sort of thing a
number-range wildcard will do again.

### Follow-ups

- **No new prompts queued.** The remaining Control call is one
  `POST /v1/auth/cert` per connection, and driving *that* down means
  authenticating less often, which §6.4 and D17 both treat as a security
  argument rather than a capacity one. There is nothing to queue until somebody
  wants to make that argument.
- **Phase 0032** (the admission-policy question) inherits a working set that is
  now two shapes per connection where the server hints both. Its prompt has been
  updated: its traces reach any given bound at half the target count.
- **Not measured here:** what host-key reuse does at fan-out. Scenarios 04/05/08
  do not set the new knob, so their hit rates are unchanged and comparable to
  0022's. A session that wants the fan-out figure should add the knob to a copy
  rather than change those files, for the same reason 09 exists beside 02.
