# 0046 — A bounded log buffer, and a refused record that no longer blocks the rest — Learnings

## Summary
- What shipped: the disk buffer is **bounded** — `logging.buffer_max_bytes` (bytes; absent/0 = **1 GiB**, below **16 MiB** refused, **bootstrap** under D18, not in `fleet.go`); a record the server refuses is **set aside, not retried**; both are reported as **`logging.gap`** records. D8 amended in place, D16 not.
- Eviction: whole files, first class that has one, oldest first — **set-aside → stream → other batch → priority**; the append counts as the newest of its class (evicted itself before it displaces anything ranked above). **Never evicted:** a pinned session's files, gap records, the file in flight.
- Pinning: `requireCapture` pins after `Deliverable()`; a constrained mapping event pins its session. `.pinned` marker, synced, adopted on restart, released after `session_end` ships. **`Deliverable()` = pinned bytes < window** (no buffer: unchanged).
- Refusal = exactly **400 or 413** (`isRefusal`), never `ErrBadRequest` (every 4xx but 401). Bisection, ≤`2·⌈log2 n⌉+1` requests for one bad record; set-aside files `<seq>.refused.jsonl`, never resent, evicted first.
- `logging.gap` (`kind: error`, critical iff `gap_critical>0`, else warn), one per session and cause: `gap_cause`, `gap_records`, `gap_bytes`, `gap_first_at`/`gap_last_at`, `gap_kinds`, `gap_critical`, refused only `gap_record_ids`(≤64)+`_truncated`, `refusal_code`/`refusal_message`.
- Contract: `session_id: ""` = no session and **a server MUST accept it on any kind**; `400` stores nothing and is not retried. `info.version` **4.6.0**, `policy_version` still **6**. Mock accepts `""`, adds `POST /debug/logs/refuse`.
- Gotchas: a **sent** gap record is never rewritten (server dedups on `record_id`) and reports drain **last** in each pass; a spill file is **≤ one batch**. Details below.
- Follow-ups: replay of the set-aside area; ending a running pinned session over the window; largest-session-first eviction (the owner's alternative).
- **What Control must change** (the sync): see "What Control must change" below — accept `""` on every kind (rewrite its 0014 item 1), store/index `logging.gap`, say in PLAN §7 what a gap is, revisit two §7 claims that assumed infinite retry.

## Details

### Where the code is

| File | What |
| --- | --- |
| `internal/logging/buffer.go` | The window, byte accounting, eviction classes, pins, set-aside, gap-record storage and coalescing, adoption. **Its header comment is the on-disk layout specification.** |
| `internal/logging/gap.go` | `gapTally` — the report before it is a record — its rendering, and parsing it back. |
| `internal/logging/refusal.go` | `isRefusal`, `deliverBatch` (bisection), set-aside and the refusal reports. |
| `internal/logging/shipper.go` | Classification wired into `sendBatch`/`sendPriority`/the drain, `Deliverable`, `pin`, pin release, `Stats`. |
| `internal/logging/record.go` | `EventLoggingGap`, the `AttrGap*`/`AttrRefusal*` keys, `GapCause*`, `SessionRecorder.Pin`. |
| `internal/logging/device.go` | `AccountMapping` pins a constrained session before writing the event. |
| `internal/proxy/bounds.go` | `requireCapture` pins after `Deliverable()`; a failed pin is `ErrCaptureUnavailable`. |
| `internal/config/config.go` | `Logging.BufferMaxBytes`, `MinLogBufferBytes`, its validation. |
| `cmd/mock-control/server.go` | `""` accepted; `POST /debug/logs/refuse`; reset clears it. |

### The on-disk layout, in one table

`<dir>/<session>/` holds `<seq>.batch.jsonl`, `<seq>.stream.jsonl`, `<seq>.priority.jsonl` (owed), `<seq>.gap-evicted.jsonl` / `<seq>.gap-refused.jsonl` (one report each, owed by its severity), `<seq>.refused.jsonl` (set aside, never owed), and `.pinned`. An **older binary** delivers `batch`/`priority` exactly as before and ignores the rest — it never mis-delivers a set-aside record, which it would resend, have refused, and stall on. On a downgrade it therefore strands `stream` segments rather than delivering them; that is the accepted price of reading the class from the name at adoption instead of opening every file. A pre-0046 segment may mix capture and metadata; it reads as `batch`, the class that loses nothing by the mistake.

The pin marker lives **inside** the session directory, not in a top-level `.pins/`: it keeps "what happened to session X" one `ls -a` of one directory, and it cannot collide with `sessionDirName`'s output either way.

### Refinements the prompt did not spell out, and why

Each of these was found by a test or by working a case through; none reverses a decision the prompt took.

1. **A gap record that has been sent is never rewritten.** The prompt says one undelivered report per session and cause, updated in place. But a send that times out after the server committed leaves the server holding that `record_id`, and it de-duplicates on it — so an in-place update would be dropped **silently**, the exact failure the feature exists to prevent. So a report is coalesced into only until it is first claimed by the drain; after that (and for any report adopted from a previous run, whose history is unknown) it stays byte-for-byte, and the next eviction starts another. Bound: **two** undelivered reports per session and cause (the one being retried, and the live one), not one — still bounded by sessions, not outage length. A spilled refused-cause report is coalesced only if it was never sent (`putGap(rec, sent)`).
2. **Reports drain last in each pass**, after every ordinary file in the pass was delivered. Found by `TestGapRecordsCoalesceOverALongEvictionRun`: during a long flood every segment older than the report gets evicted, so the report becomes the **oldest** owed file — and every drain retry during the outage would claim it first, freeze it (rule 1), and start another: one report per retry, i.e. bounded by the outage's length. Going last means a report is never the probe that finds out whether the server is back. It still arrives "once delivery resumes", after the surviving records it reports on.
3. **A spilled file holds at most a batch.** Found by `TestTheWindowHoldsAndTheNewestRecordsArrive`: `Flush` and the priority path `drainQueue` the whole queue into one batch, and one segment of it (324 KB against a 48 KB window) was evicted whole, **newest records included**. A file is the unit of eviction, so its size is bounded by `batchSize` — which is also what the prompt's own sizing assumed ("one segment of 64 stream records ≈ 3 MiB").
4. **The append is the newest file of its class**, and when everything ranked below it cannot make the room it is evicted **alone** — nothing lower is evicted first "on the way", since dropping the append frees all the room it needed. The prompt's "if nothing evictable is left, an unpinned append is itself evicted" is the special case of this.
5. **A report an eviction creates is not counted when planning that eviction**; growth of an existing report is. Counting creation would evict records to make room for the report of their own eviction, and with many tiny files from many sessions (a report ≈ 700 B can outweigh the file it reports) it could evict everything, or drop a metadata append to make room for reports about capture — inverting the class order. So a new report is written like any pinned append (possibly over the window, by one report) and the next append makes room for it. The flood tests assert the window holds once the run is over.
6. **A gap record never begets another, in either direction.** Refused, it is set aside and counted in `Refused`; evicted from the set-aside area, it is counted in `Evicted` and reported by nothing. So `Stats.Evicted` = Σ `gap_records` of the evicted reports **plus** any evicted gap records (zero in every ordinary case).
7. **Pin release.** The API is `Pin()` only; release is internal. `session_end` is a session's last record (`internal/proxy` records it after teardown), so once it has shipped — delivered or spilled — only a critical record still in the priority channel can be in transit (the delivery goroutine picks among ready channels at random), and, for an end that overtook a full queue, the queue too. `releaseEnded` waits for exactly those. What the session left on disk stays pinned; the marker goes with its last file.
8. **`Pin()` with no buffer succeeds** (nothing to make durable, nothing evictable): `Deliverable()` keeps meaning "nothing dropped" there, as the prompt requires. **A failed pin in `AccountMapping`** is logged and the event still written — the administrator already exists, and `DeviceEventSink` has no error to return.
9. **Refusal reports ride the ordinary path** (`enqueue`, without counting as `Queued`), so `Flush` and shutdown run a second queue round after draining — otherwise a report of a refusal met in the drain would wait for the next flush.
10. **The eviction plan reads each victim** (a minimal decode that skips the payload) to count it. A victim that cannot be read is removed and counted in `Dropped`, not reported — the one way an eviction is not reported.
11. An eviction **episode** is logged once (`Logf`), not per eviction; the gap records are the report, and the operator's log needs to say only that it started.

### What was verified, and how

- `internal/logging`: `window_test.go` (byte accounting, class order step by step, self-eviction, pins live and adopted, eviction at start over a lowered window, pin release, coalescing, crash durability, the in-flight rule under a concurrent flood with `-race`, never rewriting a sent report, no recursion), `refusal_test.go` (the status table through the **real REST client** against `httptest`: 400/413 isolate; 401/403/404/408/409/422/429/5xx/200/transport keep and retry; the bisection bound; all refused = `2n−1`; partial failure live and in the drain with the segment rewritten; priority refusal; no recursion; no buffer), `pin_test.go`.
- `internal/proxy`: pins on success (pre-admission records under the pin), refused as an outage when the window is full of pinned records while an unbound route runs, refused when the pin cannot be made durable. **Mutation check:** removing the `Pin` call fails two of them.
- `cmd/mock-control`: `""` on both endpoints for every kind; the refusal set; and `logging_gap_e2e_test.go` — refusal live and in the drain, a refused block reported critically on the priority path, capture eviction (suffix of chunks arrives, `gap_records` = the missing prefix), a pinned session surviving a flood then a pinned flood over the window refusing a new capture-bound session while an unbound one runs, and session-less records stored.
- `go test -race ./...`, `go vet`, `golangci-lint` **v2.13.2** (CI's pin, installed into the scratchpad: the image's v2.5.0 predates Go 1.26), `make license-check`, `make openapi-check` (`openapi-spec-validator` pip-installed) all clean. **`make e2e` was not run** — no Docker here (as 0040 recorded); CI's `e2e` job is where it runs. Nothing in `deploy/` changed; the topology's proxies take the 1 GiB default.

### What Control must change

The sync's obligations, verified against `hoplock/control` at `3228138`:

1. **Re-vendor** the contract at `info.version` **4.6.0** (its M1). `policy_version` is unchanged at 6. (Its vendored copy is at 4.1.0, so this re-vendor carries 4.2–4.5 too.)
2. **Accept `session_id: ""` on every `kind`.** Its `audit.Parse` accepts `""` only for `error` (`internal/audit/record.go`), and its queued **0014, item 1**, would widen that to exactly `device.config.change` and keep every other kind refused — that item must be rewritten to the contract's rule. It also calls the sweep failure an `error` record; this proxy emits `device.account.sweep_failed` as **`policy_decision`, `critical`**, on the priority path, so today's Control refuses the one record D13 relies on to surface a standing administrator. Its PLAN §7 sentence "an `error` record for a sweep failure" is wrong and must be corrected. (Until it syncs, a refused sweep failure is not lost silently: this proxy sets it aside and reports it in a critical `logging.gap`, which today's Control accepts — `kind: error`.)
3. **Store and index `logging.gap`** (`kind: error`) by session, `gap_cause` and span; every key in the summary is query surface. `api/README.md`, "When records do not arrive", is the specification.
4. **Say in its PLAN §7 what a gap in a proxy's stream looks like:** `evicted` means Control never received the records; `refused` means Control refused them itself, and the proxy keeps them only up to its window, evicting them first of all classes. A session can carry two reports of one cause (rule 1 above).
5. **Revisit two PLAN §7 claims that assumed a refused batch is retried forever:** the reason given for its `""` rule ("the proxy retries the oldest segment … until the server takes it"), and the reason it refuses an unknown kind loudly ("the proxy keeps the record and an operator sees an error"). A `400` now costs exactly the refused record — set aside, kept only up to the window, reported in a `logging.gap` — so "loud" now means that record. Its 0014 obligation to accept the sweep's `device.config.change` stands, subsumed by item 2.

`hoplock/enterprise`: **none** — it consumes Control's `ext/`, not `api/`; its retention and SIEM-export prompts read Control's store, where a `logging.gap` arrives under an existing kind.

### Follow-ups (not built, no prompt queued)

- **Replay of the set-aside area** — the follow-up that closes the residual risk: a server that refuses everything now has every record set aside and kept only up to the window, where it used to halt the stream with everything retained. The files are plain `LogRecord` JSON lines on purpose, so replay is a re-post.
- **Ending a running pinned session** whose records no longer fit — today pinned records may take the buffer over the window as far as the sessions admitted while it had room, until they end.
- **Largest-session-first eviction** — the owner's alternative to oldest-first within a class: a terminal flood would then evict its own capture rather than other sessions' replay. Considered and not built because the request asked for oldest-first.
