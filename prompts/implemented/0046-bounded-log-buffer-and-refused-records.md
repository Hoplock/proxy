# 0046 — A bounded log buffer, and a refused record that no longer blocks the rest

## Read first

- `docs/PROTOCOL.md` — session workflow, especially **§3** (scope discipline,
  the rename/dangling-reference sweep, and the table of plan indexes that go
  stale in the same PR that makes them wrong), **§7** and **§8**.
- `docs/PLAN.md`:
  - **§7** (logging & telemetry), **in full**. This phase rewrites its
    "**The buffer is a buffer**" paragraph, so read that one twice: "an outage
    costs latency, never fidelity or ordering" is the sentence the phase amends.
    Also "**Severity decides the endpoint**" (and why a service outage is `warn`,
    not `critical`), "**Every record says why access was granted**" (it lists the
    records a session recorder does not build, and this phase adds one), and
    "**Batch or priority, for the device path**" (the records a sweep emits, which
    have no session id).
  - **§6.5** — "**Session bounds (D16)**" and "**The other three bounds, as
    enforced (phase 0031)**": the `require_session_capture` row in each table.
    Both say "a disk buffer is a logging path", and after this phase that is
    true only while the buffer has room for a pinned session (§3 below).
  - **§5.3** — only "**What is true today**", the paragraph "**Attribution is
    the log**". It turns on the same predicate D16 does.
  - **§4.3** — only enough to confirm that refusing a D16 route for want of a
    recording path stays the **outage** it already is. This phase adds no user
    message.
  - **§8** — config conventions: YAML bootstrap, and `config.example.yaml`'s
    `[fleet: …]` markers.
  - **§2's register**, then these decisions in full:
    - **D8** — logs batch to Control, a priority path, disk is a buffer only.
      **This phase amends it.**
    - **D16** — "a proxy that cannot record — not even to its disk buffer —
      refuses it". **This phase must keep that sentence true**, and it is where
      the request's shape needs correcting (§3 below).
    - **D18** — the line between bootstrap and fleet-owned settings. It already
      decides where the new setting lives, so do not re-derive it.
    - **D13** — the constrained-naming attribution rule (§5.3). It depends on
      the buffer the same way D16 does.
    - **D3** — this repository owns the contract.
    - **D2** — the window is configuration, not policy. Nothing here lets
      Control or config change **what** is recorded.
  - **§10** — this phase's row.
- `api/README.md` — "**Ground rules**" (what `401`, `5xx` and a transport
  failure each mean), "**Logs: two paths, on purpose**", "**Mock-only
  endpoints**", and "**Changing the contract**" (the recipe you follow; this
  phase uses steps 1–3, 5 and 6, and not step 4).
- `api/control.yaml` — `/v1/logs/batch`, `/v1/logs/priority`, `ErrorResponse`,
  `LogRecord` (the `session_id` and `kind` descriptions), `LogBatchResponse`.
- Code, read before designing anything:
  - `internal/logging/shipper.go`: `sendBatch`, `sendPriority`, `drainBuffer`,
    `deliverSegment`, `spill`, `Deliverable`, `Stats`.
  - `internal/logging/buffer.go`: the whole file. Its header comment is the
    layout specification, and this phase extends it.
  - `internal/logging/record.go`: the attribute keys, the event names, and
    `SessionRecorder.Deliverable`.
  - `internal/logging/device.go`: `AccountMapping` and `SweepFailure`. Note
    that the second sets **no** `SessionID`, and its `Kind` is
    `policy_decision`.
  - `internal/control/errors.go` and `rest.go`'s `statusError`: every 4xx
    except `401` becomes `ErrBadRequest`. That is the classification trap in §4.
  - `internal/proxy/bounds.go` (`requireCapture`) and
    `internal/auth/target/deviceaccount.go` (the `Deliverable()` check before a
    constrained-naming route provisions).
  - `internal/config/config.go` (`Logging`, `validateLogging`),
    `internal/config/fleet.go`, `config.example.yaml`'s `logging:` block,
    `cmd/proxy/main.go` (where `logging.Options` is built).
  - `cmd/mock-control/server.go`: `handleIngestLogBatch`,
    `handleIngestPriorityLog` (both refuse `session_id: ""` with a `400` today),
    and `handleDebugLogSink`.
- `docs/learnings/` — read the summaries, then open
  `0011-logging-telemetry-pipeline-learnings.md` in full: it built everything
  this phase changes. Also read the summaries of
  `0031-session-bounds-enforcement-learnings.md` (why `Deliverable()` is the
  capture predicate), `0042-fleet-config-distribution-learnings.md` (the fleet
  list and its test) and `0043-algorithm-profile-and-device-events-learnings.md`
  (sweep records with no session id).
- `docs/CROSS-REPO-PROTOCOL.md` — **§1, §2, §4.1, §5**. This phase answers an
  upstream request, so §5's "The PR that answers an upstream request is not a
  sync" binds it. Once merged it owes a **downstream sync to every consuming
  repository, including the one that raised the request**.

## Depends on

- **Nothing hard.** 0043 is implemented; it is where the session-less sweep
  records come from.
- **0044 and 0045: ordering only.** Each moves `info.version`. Take the **next
  minor above whatever it is when you start**, and do not hard-code a number
  from this prompt. Neither of them touches `policy_version` on this phase's
  behalf, and this phase does not touch it at all (§6). 0045 also adds attribute
  keys and an event name to `internal/logging/record.go`, so add yours beside
  them rather than over them.

## Where this came from

An **upstream request** from `hoplock/control` (`docs/CROSS-REPO-PROTOCOL.md`
§3.2), raised in [Hoplock/control#39](https://github.com/Hoplock/control/pull/39)
by a docs sync that followed this repository's #66 (phase 0043). The request
says outright that nothing in #39 waits on it. It lands on two surfaces:

- `internal/logging` (D8, §7);
- the text of `api/control.yaml` for `/v1/logs/batch` and `/v1/logs/priority`.
  Control vendors that file read-only (its **M1**) and stores what the pipeline
  delivers in its audit store (its **M8**).

**The gap, in this repository's words.** The shipper has **one failure
branch**, and it cannot tell "try again later" from "this will never be
accepted":

- `sendBatch` and `sendPriority` spill **any** error to disk.
- While anything is on disk the shipper is `degraded()`, and every new record,
  priority ones included, joins the back of that queue.
- `drainBuffer` retries the **oldest segment** and stops at the first one the
  server will not take.

So one batch the server refuses with a `400` is resent unchanged forever, and
every record behind it waits forever, critical ones included. Nothing bounds
the disk either, so the same stall also fills the host until writes fail. From
then on, records are counted in `Stats.Dropped` and lost.

**The shape requested**, quoted from the request:

> 1. **A bounded log window that evicts the oldest records when it is full.**
>    […] a window, measured in bytes, in age, or both (the proxy's call), and
>    once it is full the oldest buffered records are evicted first, so delivery
>    always moves. **Eviction is never silent.** It is counted, and once
>    delivery resumes the proxy reports what it evicted (how many records, over
>    what span, from which sessions) as a record Control stores. […] The event
>    name and its fields are the proxy's to define. **Open question for the
>    proxy's plan:** are priority (`critical`) records evicted by age like
>    everything else, or only once no batch records are left? D8 exists to keep
>    them. My suggestion is to evict batch records first.
> 2. **A refused record does not hold up the rest.** […] on a `400`, isolate
>    the record or records the server refuses, deliver the rest, and set the
>    refused ones aside, counted and reported rather than retried. `5xx`,
>    timeouts and network failures keep today's retry, and `401` is unchanged.
>    […] isolating means splitting the batch until the bad record is found,
>    unless the contract gains a field that names it. Which of the two is the
>    proxy's call.

The request also names what it reverses: eviction trades fidelity for liveness,
so it **amends D8**, and it affects `require_session_capture`. That is the
owner's decision, taken in this phase. The owner asked for the first part.

**What downstream cannot do until this lands.** Control cannot keep receiving a
proxy's audit stream once it has refused a single record. A `400` for any
reason stops all of that proxy's delivery to Control, critical records
included, and the proxy's disk then fills until writes fail. Control's store
also has no way to show where a proxy's stream has a hole. Nothing tells it
records are missing, so its PLAN §7 cannot say what a gap looks like. Control
built nothing in its place and approximated nothing. It cannot change how this
proxy retries.

**Two findings the requester could not see.** The request names one trigger: a
sweep's `device.config.change` with `session_id: ""`, which Control's 0014 will
accept. There are two more, and the second is in this repository:

- **Control's ingest refuses `session_id: ""` unless `kind` is `error`.** Its
  plan describes this as accepting "an `error` record for a sweep failure", but
  this proxy emits the sweep failure (`device.account.sweep_failed`, in
  `device.go`'s `SweepFailure`) as `kind: policy_decision` and `critical`, with
  no session id. So today's Control refuses it **on the priority path**. That
  is the record D13 calls the only way anybody finds a standing administrator
  left on a device. Nobody has a fix for this trigger yet.
- **This repository's own mock refuses `session_id: ""` on both log
  endpoints.** The reference server disagrees with the records 0043 emits, so
  in this repository's own topology one sweep that changed something stalls the
  shipper.

Both come from one gap in the contract: it never says what `""` means. §6 fixes
that once, rather than once per kind.

**Treat the request as a need, not a specification** (§3.2). **Taken as
asked:**

- a window;
- eviction that is counted and reported as a stored record;
- priority records evicted after batch ones;
- refusals isolated by splitting the batch;
- `5xx`, transport and `401` handling unchanged.

**Corrected**, for reasons below that the requester could not see from
Control's side:

- the window is **bytes, not age** (§1);
- eviction has **classes**, and some records are **never** evicted (§2, §3);
- the classification is **exactly `400` (and a middlebox's `413`)**, never
  "any 4xx" (§4);
- **no contract field** names the refused record (§4);
- the report is one record **per affected session**, under an **existing**
  `kind` (§5).

## Objective

Bound the disk buffer. When the bound is reached, evict what matters least
first, and never evict what D16 or §5.3 depends on. Stop a record the server
refuses from blocking any record behind it. Report every eviction and every
refusal as a record Control stores in the affected session's own timeline.
Make the contract say what a `400` on the log endpoints means, what a proxy
does after one, and what `session_id: ""` means.

## What this phase must settle

### 1. The window: bytes, not age

**Bytes.** The two liveness failures in the request are disk exhaustion and
head-of-line refusal. A byte bound fixes the first and §4 fixes the second. An
**age** bound would fix neither. It would delete records during an outage while
the disk still had room, trading fidelity for no liveness at all. The age of
what was lost is still reported, on the gap record (§5), where it tells an
operator something.

- **Config:** `logging.buffer_max_bytes` (int64 bytes) in `internal/config`'s
  `Logging` struct.
  - Absent or `0` means the default, **1 GiB**.
  - `validateLogging` refuses a negative value and a value below **16 MiB**.
    One segment of 64 stream records at the default payload cap is about 3 MiB
    once base64 and JSON are added, so a window smaller than a few segments
    evicts on every spill.
  - There is **no unbounded setting**. An unbounded buffer is the defect this
    phase fixes, and an operator who wants more room sets a larger number.
- **It is bootstrap, not fleet-owned, and D18 already says so.** A new setting
  stays bootstrap until a phase lists it. This one is a budget on the host's
  own disk, the same material `buffer_dir` names, so leave it out of
  `internal/config/fleet.go`. Its `config.example.yaml` comment has no
  `[fleet: …]` marker and says why in one line. The test that keeps the fleet
  list and the example equal will hold you to that.
- **`logging.Options.BufferMaxBytes int64`.** Zero means
  `DefaultBufferMaxBytes`. `Options` is **not** held to the 16 MiB minimum:
  tests need small windows, and the minimum protects operators, not the
  package.
- **What counts:** every byte the buffer holds on disk. That covers segments of
  every class, set-aside records (§4) and gap records (§5). Keep the count
  incrementally rather than walking the directory on each append. Recompute it
  from disk when a previous run's buffer is adopted at start. If an adopted
  buffer is already over the window (the window was lowered), evict down to it
  at start, by §2's rules, and write the gap records for what was evicted.

### 2. What is evicted, in what order

Eviction runs when an append would take the buffer over the window. It removes
**whole segments**, taking the first class that has one and the oldest segment
(lowest `seq`) within that class:

1. **Set-aside records** (§4). The server has refused them, and they are kept
   only so an operator can inspect them.
2. **Stream-capture segments**: `stream` records, which are bulky and serve
   replay only.
3. **Other batch segments**: the metadata every query is written against (who,
   where, which command, which decision).
4. **Priority segments.** This answers the request's open question as it
   suggested: D8 exists to keep them, so they go last.

**Never evicted:**

- a **pinned** segment (§3);
- a **gap record** (§5);
- the segment the drain is delivering at that moment.

The drain and eviction coordinate under the buffer's lock. `Record` can spill
from a capture goroutine, so eviction does not run only on the delivery
goroutine.

If nothing evictable is left:

- a **pinned** append is written anyway, over the window. §3 bounds how far
  over.
- an **unpinned** append is itself evicted. It is counted and reported exactly
  like any other eviction, because it is now the oldest record in its class
  that can go.

**Stream before metadata needs segments of one class.** `spill` today groups a
batch by session. Group it by session **and** by whether the record is `stream`,
so no segment mixes the two. Write a session's two segments in the order their
first records appeared. This gives up ordering between the two classes, but
only within one spill: a chunk's position is its `seq` and `offset_ms`, and a
metadata record's is its `timestamp`. §7 must say exactly that, because it
narrows "never fidelity or ordering".

**The attack this ordering exists for, stated in §7.** During an outage, anyone
with a session can flood their terminal and fill the window. Without classes,
that flood evicts other sessions' commands and policy decisions, and the
blocked commands on the priority path go last of all. With classes, a flood can
evict only stream capture, oldest first, until none is left. Other sessions'
**replay** can still be lost, and the gap record names each session that lost
some. Evicting the **largest** session first would make a flood evict its own
capture instead. It was considered and not built, because the request asked for
oldest-first. Record it in the learnings as the owner's alternative.

### 3. D16 and §5.3 survive: pinning, and what `Deliverable()` means now

**This is the correction that matters most.** D16 says an unbounded-privilege
session is bounded "by the record", and that a proxy that cannot record, "not
even to its disk buffer", refuses the route. If a bounded window could evict
that session's records, a buffered capture would no longer count as recorded,
as the request warns. D16 would then quietly mean "recorded, unless the outage
outlasts the window". §5.3's constrained-naming rule is the same case. On such
a device, the account-mapping event is the only attribution that exists, and
the route is refused when there is nowhere to put it. So:

- **A pinned session's records are never evicted.** A session is pinned:
  - when its route carries `require_session_capture` and admission passes.
    `bounds.go`'s `requireCapture` pins the session, **before the target leg is
    dialled**, right after it checks `Deliverable()`;
  - when a device account-mapping event with `name_constrained=true` is
    recorded for it. `device.go`'s `AccountMapping` pins the event's session
    before it writes the event.
- **Pinning covers the whole session:** records spilled **before** the pin (the
  handshake and authentication records), the session's own set-aside records
  (§4), and everything after it.
- **A pin survives a restart.** An adopted pinned segment is still pinned. The
  on-disk encoding is yours, under three constraints:
  - it cannot collide with `sessionDirName`, which never produces a name
    starting with `.`;
  - an older binary that **ignores** the new layout is acceptable, one that
    **mis-delivers** it is not;
  - it is documented in `buffer.go`'s header comment beside the existing
    layout.
- **API:** `(*SessionRecorder).Pin() error`, delegating to the shipper. It
  never refuses on window grounds, because `Deliverable()` is the gate. It
  fails only when the pin cannot be made durable, and `requireCapture` then
  refuses the session with `ErrCaptureUnavailable`, the outage class it already
  has. A nil recorder's `Pin` fails, just as its `Deliverable` answers false.
- **`Deliverable()` gains one condition.**
  - With a buffer configured, it is true while the **pinned bytes are below the
    window**.
  - With no buffer, nothing changes: it is true while nothing has been dropped.
  - A proxy whose window is full of records it may not evict cannot promise a
    new pinned session its record. So D16 routes and constrained-naming device
    routes are refused, as the outage they already are. **Every other route
    keeps running.**
- **How far over the window pinned records can go:** only as far as the
  sessions admitted while it had room, and only for as long as they run. That
  is the price of keeping D16's claim, and §7 states it. The host disk stays
  the hard limit, as today: a failed write is counted in `Dropped`. Ending a
  running pinned session whose records no longer fit is **out of scope**.
  Record it as a follow-up.

**D16 is not amended.** Its sentence stays true. What changes is how §6.5
renders it: both `require_session_capture` rows now read "a disk buffer is a
logging path **while its window has room for a pinned session**".

### 4. A refused record does not hold up the rest

**Classification, and the trap.** On the two log endpoints, a **refusal** is
an `*control.APIError` whose `StatusCode` is exactly **`400`**, or **`413`**.

- **Do not use `errors.Is(err, control.ErrBadRequest)`.** `statusError` puts
  every 4xx except `401` under it, so a `404` from a wrong base URL, a `408`,
  a `409` or a `429` would each be read as "discard these records", and a
  misconfiguration would quietly throw away the audit stream.
- `413` is not a contract response. It is what a middlebox in front of Control
  answers to a body that is too large. Splitting cures it, and a single record
  that is still refused on its own is set aside like any other.
- Everything else stays on today's retry path: `429` and every other 4xx,
  every `5xx`, every transport failure. `401` is unchanged.
- Put the predicate in `internal/logging`, its only consumer, and test it over
  every status the client can produce.

**Isolation is by bisection, with no contract field.** On a refusal, split the
batch in half and resend each half. Recurse until each refusal is down to a
single record. The server names the refused record in prose only (the
request says so, and `ErrorResponse` carries only `code` and `message`), so
there is no field to read. This repository does not add one, for three
reasons:

- the proxy must bisect anyway for any server that does not send the field, so
  a field would only speed up a rare path;
- bisection sets aside only a record the server has refused **on its own**, so
  a server bug in an index field could never make the proxy discard a record
  the server would have taken;
- bisection needs no contract change, where a field would be a contract
  revision.

The cost is at most `2n−1` requests for `n` records, and about `2·log2(n)` for
one bad record: roughly 12 for a batch of 64.

**This relies on a `400` storing nothing.** Control's M8 ingest already works
that way: a batch is all or nothing, as its PLAN §7 says, and the mock checks
every record before it stores any. The contract now states it (§6). Even a
server that stored part of a batch loses nothing when the rest is resent,
because it de-duplicates on `record_id`. The rule matters only for the
`accepted` count.

**Where isolation runs:**

- **Live batch** (`sendBatch`): isolate. Deliver what the server takes, set
  aside what it refuses, and put nothing on disk that the server has already
  taken.
- **Live priority** (`sendPriority`): the request is one record, so a refusal
  sets that record aside directly.
- **Drain** (`drainBuffer` / `deliverSegment`): a refused batch segment is
  isolated the same way. A priority segment is delivered one record at a time
  as today, and a refused record is set aside. The drain then **continues**
  with the next segment. It still **stops** at the first segment that fails
  for any other reason, which keeps today's ordering promise for an outage.
- **Failure partway through:** a half that gets a `5xx` or a transport
  failure. What was delivered stays delivered and what was refused stays set
  aside. The rest goes back to the buffer: on the live path it spills, and in
  the drain its segment is **rewritten atomically** to hold only what is still
  owed. Nothing is counted twice, and nothing goes to an endpoint it was not
  owed to.

**Set aside means kept, not deleted and not retried.**

- A refused record moves to the buffer's **set-aside area** on disk. It is
  never resent, and it is not drained on restart. It is counted
  (`Stats.Refused`) and reported (§5).
- It is kept until §2 evicts it, first of all classes, unless its session is
  pinned.
- The layout is documented in `buffer.go`, so an operator can read it with
  `ls` and `jq`. **Replaying it is out of scope** (follow-up).
- With **no** buffer configured, a refused record is counted and reported but
  not kept. Today the whole batch would have been dropped with it.
- The shipper's operational log (`Logf`) names every isolation: how many
  records it delivered, how many it set aside, and the server's `code`.

**The residual risk, stated in §7 rather than hidden.** A server that refuses
**everything**, for example a Control regression or a validation change after
an upgrade, used to halt the stream with every record retained. Now it sets
every record aside, and they are retained only up to the window. The change is
visible, through `Logf`, `Stats.Refused` and the gap records, but it is a
change. Replay is the follow-up that closes it. Do **not** add a heuristic to
guess "server-wide" from a refusal rate. A batch made entirely of one kind the
server refuses (a quiet period with only sweep records in it) looks exactly
like that, and it is the case the request exists for.

### 5. The gap record

One event reports both halves: **`logging.gap`**, as
`logging.EventLoggingGap`, beside 0043's event names in `record.go`.

- **`kind: error`, an existing kind, on purpose.** Control's ingest refuses an
  unknown kind (its M8 store, as its PLAN §7 states). A new kind would be
  refused by the very server this record reports to. `error` is also the one
  kind today's Control accepts with `session_id: ""`.
- **One record per affected session and cause, carrying that session's
  `session_id`.** The gap then appears in the session's own timeline, and
  asking "what happened to session X" returns "N records evicted between T1
  and T2" from an ordinary session query. Records that belonged to no session,
  such as sweeps, get a gap record with `session_id: ""`. Copy `subject`,
  `login` and `target` from the first missing record that carries them.
- **Attributes** (all strings, because `attributes` is a string map). Each is
  query surface, so add a constant in `record.go` for each:

  | Key | Value |
  | --- | --- |
  | `event` | `logging.gap` |
  | `gap_cause` | `evicted` \| `refused` |
  | `gap_records` | how many records |
  | `gap_bytes` | their size on the proxy's disk |
  | `gap_first_at`, `gap_last_at` | the earliest and latest `timestamp` among them, RFC 3339 UTC |
  | `gap_kinds` | their distinct `kind`s, sorted, comma-joined |
  | `gap_critical` | how many of them were `critical` |
  | `gap_record_ids` | **refused only**: their `record_id`s, comma-joined, at most 64 |
  | `gap_record_ids_truncated` | `true` when there were more than 64; absent otherwise |
  | `refusal_code`, `refusal_message` | **refused only**: the server's `ErrorResponse` for the last single-record refusal, copied verbatim (the contract already forbids credentials in it) |

  Evicted records are not listed by id: Control never saw them, so the ids mean
  nothing to it.
- **Severity decides the endpoint, unchanged.** The gap record is `critical`
  when `gap_critical > 0`, because a security event (a blocked command, a
  kill, a mapping event) is then missing from Control's store, and that is
  itself a security fact. Otherwise it is `warn`, on §7's rule that losing
  telemetry is outage-class.
- **Evictions are accounted durably.** A crash between an eviction and its
  report must not turn a reported gap into a silent one. So the gap record is
  written into the buffer, pinned, **in the same critical section as the
  eviction**.
  - There is **at most one undelivered gap record per (session, cause)**, and
    a later eviction updates it in place, atomically. That bounds gap records
    by the number of affected sessions, not by the length of the outage.
  - It drains in `seq` order like any record, so it reaches Control after the
    surviving records that came before it. That is the request's "once
    delivery resumes".
- **Refusals are reported when they happen**, since delivery is working at
  that moment, through the ordinary path, with one gap record per session per
  isolation.
- **No recursion.** A gap record that is itself refused is set aside and
  counted, and produces **no** further gap record. A gap record is never
  evicted.
- **A session recorder does not build it**, so it carries no grant context.
  Add it to §7's list of records a session recorder does not build (today that
  list is the two device-sink events), with the reason: it describes the
  pipeline, not something the session did.

`Stats` gains `Evicted`, `EvictedBytes`, `Refused`, `BufferedBytes` and
`PinnedBytes`. `Dropped` keeps its meaning and its "must stay zero" comment: a
record lost **without** a report (no buffer, a failed write, an unreadable
segment). Evicted and refused records are **not** dropped. They are accounted
for and reported.

### 6. The contract text

All of this is description text in `api/control.yaml` and `api/README.md`:

- **`/v1/logs/batch`, `400`:** the server refuses the whole request and
  **stores none of it**. The proxy then isolates the refused records by
  resending halves, sets aside any record refused on its own, and never resends
  a set-aside record. A `413` from anything in the path is handled the same
  way. On a `429`, any other 4xx, a `5xx` or a transport failure, the proxy
  keeps the batch and retries. `401` is unchanged.
- **`/v1/logs/priority`, `400`:** the record is set aside and not retried.
- **`LogRecord.session_id`:** `""` means the record belongs to no session: a
  sweep's records, and a gap record reporting on them. **A server MUST accept
  `""` on any `kind`.** Refusing it fails the request, and the refused record
  is then set aside and never delivered. This is the rule that removes both of
  the triggers named above.
- **`api/README.md`:** a subsection beside "Logs: two paths, on purpose", named
  "**When records do not arrive**". It covers the window and its eviction order
  and what is never evicted, what a refusal is and what it costs, and the
  `logging.gap` record with its keys. That is what Control builds its "gap in a
  proxy's stream" view against.
- **Versioning:** `info.version` moves one **minor** above whatever it is when
  you start, because the contract now puts new obligations on the server.
  `policy_version` does **not** move: it governs `/v1/authorize` and nothing
  else. No Go contract type changes. `LogRecord` gains no field, and no `kind`
  is added.

### 7. D8, amended in place, and what §7 says now

- **D8** keeps its entry and gains a paragraph, as D13 did when it was amended:
  - disk is a **bounded** buffer, and past its window it evicts in §2's order;
  - a record the server refuses is set aside, not retried;
  - every eviction and every refusal is reported as a `logging.gap` record;
  - a session whose record is a bound (D16) or the only attribution (§5.3) is
    never evicted.

  Update D8's register row: **Status** "live, **amended by 0046**: bounded,
  and reports what it could not deliver". **No new `D`.** This is still D8's
  question, namely where logs go and what the disk is for.
- **§7:** rewrite "The buffer is a buffer" to say:
  - an outage costs latency, and past the window it costs the oldest records
    that are not pinned, in class order, reported;
  - a refused record costs only itself, reported;
  - neither ever costs the records behind it.

  Add the ordering caveat from §2, the flood attack and what the classes buy
  against it, the pinned overshoot from §3 and the residual risk from §4.
  Extend the implemented-shape bullets with the window, the set-aside area
  and the gap record.
- **§6.5:** both `require_session_capture` rows, as §3 says.
- **§5.3:** "Attribution is the log" changes meaning: a constrained-naming
  route is now also refused when the window is full of pinned records. Record
  that as an `As bounded (phase 0046)` layer, recompose "What is true today",
  and refresh its layer count. `test/docs` checks the count.

## In scope

- `internal/logging`:
  - `shipper.go`: classification, isolation, set-aside, `Deliverable`, `Stats`,
    `Pin`;
  - `buffer.go`: the window, byte accounting, eviction classes, pinning,
    set-aside area, gap-record storage and coalescing, adoption, and the header
    comment;
  - `record.go`: the event name, the attribute constants, and
    `SessionRecorder.Pin`;
  - `device.go`: `AccountMapping` pins a constrained session;
  - tests beside each.
- `internal/proxy/bounds.go`: `requireCapture` pins after `Deliverable()`.
- `internal/config`: `Logging.BufferMaxBytes` and its validation. It is **not**
  added to `fleet.go`.
- `config.example.yaml`, `cmd/proxy/main.go`.
- `cmd/mock-control`:
  - accept `session_id: ""` on both log endpoints;
  - add `POST /debug/logs/refuse`, body `{"kinds": [...], "events": [...],
    "record_ids": [...]}`. While any list is non-empty, a batch containing a
    matching record is refused whole with `400 invalid_record`, and the message
    names the index and the id, as Control's does. A matching priority record is
    refused the same way. Empty lists clear it, and `POST /debug/reset` clears
    it too;
  - document the endpoint in `api/README.md`'s mock-only table.
- `api/control.yaml`, `api/README.md` (§6).
- `docs/PLAN.md`: D8 and its register row, §7, §6.5's two rows, the §5.3 layer
  and "What is true today", and §10's row for 0046, updated with what was
  delivered.

## Out of scope

- **Control's side**: storing and indexing `logging.gap`, accepting `""` on
  every kind, and its console's view of a gap. This phase emits the records;
  Control consumes them in its own numbered work, and the sync hands the work
  over.
- **Replaying set-aside records.** Note it as the follow-up that closes §4's
  residual risk.
- **Ending a running pinned session** whose records no longer fit (§3).
  Follow-up.
- **Letting priority records overtake buffered batch records** during recovery.
  §7's ordering, where a blocked command's context arrives no later than the
  block, is D8's and stays as it is.
- **A contract field naming the refused record** (§4 explains why).
- **An age bound**, and any fleet-owned version of the window (§1, D18).
- **A `5xx` that recurs for one record.** From the proxy's side it cannot be
  told apart from an outage. The window is what eventually frees it, unless its
  session is pinned. State that in §7 as the remaining case.
- **Changing the kind of the sweep-failure record.** A kind is query surface,
  and the contract rule for `""` (§6) is the fix.

## Acceptance criteria

- **One refused record no longer stalls anything.** With the mock refusing one
  `kind`, a session's other records all arrive, and the refused ones do not. A
  `warn` `logging.gap` record (`gap_cause=refused`) for that session names their
  `record_id`s and the server's `code`. A **later** session's records arrive
  too. The buffer holds no segment for either session.
- **The same holds in the drain.** Take the sink down, run a session, bring
  the sink back with a refusal set, and flush. The drain sets aside the refused
  records and delivers every other segment. Before this phase it would have
  stopped at the first one.
- **A refused critical record** is set aside, and its gap record is `critical`
  and arrives on the priority endpoint.
- **Classification:** `400` and `413` isolate. `404`, `408`, `409`, `429` and
  every `5xx` keep the records and retry. `401` behaves as today. A table test
  covers each status through the real REST client against an `httptest`
  server.
- **Bisection:** with one bad record in a batch of 64, every other record is
  delivered exactly once and the number of requests stays within
  `2·⌈log2 64⌉ + 1`. With every record bad, all 64 are set aside. With a
  `5xx` partway through, the rest go back to the buffer (the segment is
  rewritten in the drain), and a later flush delivers them. Nothing is counted
  twice and nothing is set aside twice.
- **The window holds:**
  - with the sink down and a window of a few segments, a session producing
    far more capture than the window keeps the buffer at or below it, as long
    as nothing is pinned;
  - eviction takes stream segments before metadata and batch before priority,
    oldest first within a class;
  - when the sink returns, the newest records arrive, and one `logging.gap`
    (`gap_cause=evicted`) per affected session carries the correct count,
    bytes, span, kinds and critical count;
  - `Stats.Evicted` equals the sum of `gap_records` over those records.
- **Gap records coalesce:** a long eviction run leaves one undelivered gap
  record per (session, cause), not one per segment.
- **Evictions survive a crash:** evict, stop the shipper without flushing,
  start a new one on the same directory, and flush. The gap record still
  arrives, and the adopted buffer's byte count matches the disk.
- **Pinned is never evicted:**
  - a `require_session_capture` session's records, including its
    pre-admission handshake records, survive a flood from an unpinned session
    that evicts everything else;
  - once pinned bytes reach the window, `Deliverable()` is false. A new D16
    route is refused at the capture stage as an outage, and an unpinned route
    still runs;
  - when the sink returns, every pinned record arrives in full;
  - a constrained-naming mapping event's session is pinned the same way.
- **Pins survive a restart:** they are adopted pinned, and an adopted buffer
  over a lowered window is evicted at start, pinned segments excepted.
- **Session-less records arrive:** a sweep's `device.config.change` and a
  `device.account.sweep_failed` with `session_id: ""` are accepted by the mock
  and stored. This is a regression test for both triggers.
- **No recursion:** a refused gap record is set aside and counted, and no
  further gap record follows it.
- **Config:** `buffer_max_bytes` below 16 MiB or negative is refused by
  `validateLogging`; absent means 1 GiB; it is not in `fleet.go`; and the fleet
  and example consistency test passes.
- `make build vet test lint`, the licence-header check, `go test ./test/docs/...`
  and the e2e topology all pass.

## Required tests

- `internal/logging`:
  - buffer tests for byte accounting, class-ordered eviction, pinning (live
    and adopted), set-aside storage, gap-record coalescing and durability, and
    the never-evict-in-flight rule under a concurrent drain (run with `-race`);
  - shipper tests for classification, bisection counts, the three partial-failure
    shapes, priority refusal, no recursion, and the `Stats` fields.
- `internal/proxy`: `requireCapture` pins on success and refuses as an outage
  when `Deliverable()` is false or `Pin` fails.
- `internal/config`: validation of the new key and its absence from the fleet
  list.
- `cmd/mock-control`: `""` accepted on both endpoints, and
  `/debug/logs/refuse` refuses a batch whole.
- An in-process end-to-end test beside `cmd/mock-control/logging_e2e_test.go`
  covering the refusal, eviction and pinned scenarios above, driven through
  the real client, `/debug/logs/sink` and `/debug/logs/refuse`.

## Definition of Done & hand-off

Per `docs/PROTOCOL.md` §4, plus what this phase owes because of where it came
from and what it touches:

- **`docs/PLAN.md`'s indexes** (§3's table):
  - D8's register row;
  - §5.3's "What is true today" and its layer count;
  - §10's row, updated with what was delivered.
- **`## Cross-repo impact`** (`docs/CROSS-REPO-PROTOCOL.md` §4.1) names
  `hoplock/control` **and** `hoplock/enterprise`. Enterprise consumes `ext/`,
  not `api/`, so "None" is the likely answer there, but check before you write
  it down. Hand over a ready-to-run sync kickoff for each repository with
  obligations.
- **Control is owed that sync even though Control asked for this** (§5, "The
  PR that answers an upstream request is not a sync"). It is the easiest to
  skip, because Control is already waiting and knows what it asked for, but
  the session there that re-vendors the contract is a fresh one that knows
  nothing. The kickoff must list these obligations:
  - **Re-vendor** the contract at the new `info.version` (its M1).
    `policy_version` is unchanged.
  - **Accept `session_id: ""` on every `kind`**, as the contract now requires.
    Today its ingest accepts `""` only for `error`, which refuses this proxy's
    `device.account.sweep_failed` (`policy_decision`, `critical`, priority
    path) as well as 0043's sweep `device.config.change`. Its PLAN §7 sentence
    saying a sweep failure arrives as an `error` record is wrong and must be
    corrected.
  - **Store and index `logging.gap`** (`kind: error`) by session, `gap_cause`
    and span. Every key in §5's table is query surface.
  - **Say in its PLAN §7 what a gap in a proxy's stream looks like.**
    `evicted` means Control never received the records. `refused` means
    Control refused them itself, and the proxy keeps them only up to its
    window, then evicts them first of all classes.
  - **Revisit two claims in its PLAN §7 that assumed a refused batch is
    retried forever.** One is the reason given for its ingest rule on `""`.
    The other is the reason it refuses an unknown kind loudly ("the proxy keeps
    the record and an operator sees an error"). After this phase a `400` costs
    exactly the refused record: the proxy sets it aside, keeps it only up to
    its window, and reports it with a `logging.gap` record. "Loud" now means
    that record. Its 0014 obligation to accept the sweep's
    `device.config.change` stands unchanged.
- **The learnings summary** names:
  - the window (key, default, minimum, bootstrap);
  - the eviction classes and what is never evicted;
  - how a session is pinned and what `Deliverable()` now means;
  - the refusal classification (and the `ErrBadRequest` trap);
  - bisection and the set-aside area;
  - the `logging.gap` record and its keys;
  - the contract rule for `""` and the new `info.version`;
  - the follow-ups (replay, ending a pinned session over the window,
    largest-session-first);
  - what Control must change. That last item is what the sync session reads.
