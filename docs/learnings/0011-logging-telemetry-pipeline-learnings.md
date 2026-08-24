# 0011 — Logging & telemetry pipeline — Learnings

## Summary
- What shipped: `internal/logging` — the session recorder, the batching/priority
  shipper, and the local disk buffer (PLAN §7, D8) — plus every capture point
  wired into `internal/proxy`. The interim log-line audit sink from 0010 is
  gone. **No contract change** (`api/control.yaml` untouched): 0002 already
  defined `LogRecord`, `/v1/logs/batch` and `/v1/logs/priority`.
- Key packages/files: `internal/logging/{doc,record,shipper,buffer,capture,
  audit}.go` (+ tests); `internal/proxy/logging.go` (new: all capture points) and
  `{session,channel,hostkey,nexthop,proxy}.go`; `internal/config/config.go` +
  `config.example.yaml` (new `logging:` section); `cmd/proxy/main.go`;
  `cmd/mock-control/logging_e2e_test.go` (new) + `proxy_e2e_test.go`;
  `docs/PLAN.md` §7; `README.md`.
- Key types: `logging.{Shipper,New,Options,Stats,SessionRecorder,SessionInfo,
  Event,Attrs,StreamCapture,NewStreamCapture,Register}`; `Shipper.{Session,
  Record,RecordPriority,Flush,Close,Stats,MaxPayloadBytes}`;
  `SessionRecorder.{Identify,Record,AuditSink,CommandPolicy,Start,Auth,
  Authorize,HostKey,Provisioning,ChannelOpen,ChannelClose,Request,Denied,
  Stream,Failure,End}`; `proxy.Options.Recorder`; `config.Logging`.
- **Record schema.** Wire shape is `control.LogRecord`; `kind` uses only the
  values `api/control.yaml` documents. Structured detail lives in `attributes`
  under the `logging.Attr*` constants (see `record.go` — they are the query
  surface and must not be renamed casually). Kind mapping: in-channel and global
  requests → `command` (`attributes.request` discriminates, `scope` says
  channel vs connection); `pty-req` additionally writes a `stream` **replay
  header**; captured bytes → `stream` (`capture=chunk`,
  `capture_format=raw-chunk`, `stream=stdin|stdout|stderr`, `offset_ms`, `seq`);
  refusals and command policy → `policy_decision`.
- **Batch vs immediate.** `severity` decides the endpoint and nothing else does:
  `critical` → `/v1/logs/priority`, everything else → `/v1/logs/batch`. A
  critical record does **both** halves of D8 — the delivery goroutine flushes
  the in-flight batch first, then posts the record — so a blocked command's
  context is never delivered after the block. `RecordPriority` is non-blocking:
  "immediate" is one channel handoff, not a synchronous round trip.
- **Disk buffer.** `<buffer_dir>/<session-id>/<20-digit-seq>.<batch|priority>.jsonl`,
  one JSON record per line, written to `.partial` and renamed. While anything is
  pending the shipper is *degraded* and new records join the buffer instead of
  overtaking it; the drain sends oldest-first and stops at the first failure.
  A previous run's segments are adopted on start.
- Decisions made/affected: D8 (implemented), D2, D6a, D11, D12, PLAN §7 (gained
  an "Implemented shape" subsection). No decision changed.
- Gotchas: registering the recorder puts a stream inspector on every `session`
  channel, so 0009's zero-wrapper path now applies only to sessions with **no**
  recorder (or to non-`session` channels). `filter.LogSink` is unused by the
  engine now — it survives for tests. `session.commandInspectors` was renamed
  `sessionInspectors`.
- What the NEXT session must know: 0012's compose topology needs
  `logging.buffer_dir` on a writable volume per proxy, and can assert the whole
  pipeline through `GET /debug/logs` on the mock. Nothing in this phase makes
  the destination tamper-evident — that is still out of scope (PLAN §12).

## Details

### Why the recorder, the shipper, and the buffer are three things

The prompt asks for four properties that pull in different directions:
reconstructable records, batched throughput, immediate delivery of critical
events, and survival of an outage. Putting them in one object would mean every
test of one of them starts an HTTP server.

So: `SessionRecorder` knows the schema and nothing else (its tests assert record
shapes with no network in sight); `Shipper` knows delivery and nothing about
what a record means (its tests assert batching and ordering against a fake
client with no SSH in sight); `diskBuffer` knows files. The proxy sees only
`Shipper.Session(...)` and a set of named capture points.

### The one rule that replaced a pile of decisions

Every capture point could have decided which endpoint its event belonged on.
Instead **severity decides**, in `SessionRecorder.Record`:

```go
if ev.Severity == control.SeverityCritical {
    r.shipper.RecordPriority(rec)
    return
}
r.shipper.Record(rec)
```

This also keeps `api/control.yaml`'s own sentence true — "`critical` records are
the ones shipped via `/v1/logs/priority`" — which would have quietly stopped
being true the moment one capture point took the priority path for a
non-critical record.

**Deviation from 0010's hand-off note.** 0010's learnings say to route
`priority: immediate` to the priority endpoint, and every `filter.AuditEvent`
carries that marker — including `allow_and_log`. Routing an *allowed* command
to a dedicated single-record endpoint would flush the batch on every logged
command, which is the opposite of what the endpoint is for. `logging/audit.go`
therefore maps the action the policy **named** to a severity —
`block_command`/`kill_session` → critical, `warn_and_continue` → warn,
`allow_and_log` → info — and the marker is preserved verbatim in
`attributes.priority` so the producer's intent survives. The one place this is
deliberately generous: an interactive-tier match is critical when the action
named was block or kill, even though `enforced=false`. "Someone typed the thing
policy would have stopped" is the signal, and D12 is explicit that the
interactive tier is an audit signal rather than a boundary.

### Where the capture points are

All of them are in `internal/proxy/logging.go`, so "what does a session record"
is one file rather than a grep through the transport. The transport calls them;
none can fail, block, or change what the session does.

| Point | Called from | Record |
| --- | --- | --- |
| `recordStart` | `session.setup` after identify | `session_start` + `auth` |
| `recordAuthorize` | `session.setup` after resolve | `authorize` (route, permissions, decision id, exec mode, filter mode, credential method, hop direction) |
| `recordHopLeg` | `openNextHop` | `authorize` with `hop_connection` (D11) |
| `recordCredential` | `session.setup` after provision | `provisioning` (D6a method + account) |
| `recordHostKey` | `hostKeyCallback` | `host_key` (D7) |
| `recordChannel` | `session.openChannel` | `channel_open`, or critical `policy_decision` on a refusal |
| `recordChannelClose` | end of `pump` | `channel_close` + exit status |
| `recordRequest` | `policeRequest` | `command`, plus a `stream` replay header for `pty-req` |
| `recordGlobalRequest` | `serveGlobalRequests` | `command` with `scope=connection` |
| `recordKill` | `session.kill` | critical `policy_decision` |
| `recordFailure` | `failSetup` | `error` with the setup stage |
| `recordEnd` | `session.close` | `session_end` + duration |
| stream bytes | `logging.StreamCapture` on the `session` channel | `stream` chunks |

Two details worth keeping:

- **The forward destination is parsed from the payload, not from the
  inspection.** A refused channel has no `*channel.Inspection`, and a refused
  forward is exactly the one whose destination has to be in the record.
- **`recordChannelClose` runs after `all.Wait()`**, so a stream chunk can never
  be recorded after the channel it belongs to closed.

### Capture is observation, and only of session channels

`StreamCapture` returns a reader that copies through unchanged and records a
copy. It registers on `session` only. Two reasons, and the second is the one
that matters: a port forward's audit value is its destination (recorded at open,
D5a axis 3a), and capturing tunnelled bytes would turn every backup running over
a forward into proxy telemetry.

One record per read, split at `max_payload_bytes`. The chunk boundaries are the
boundaries the bytes actually arrived on, which is what makes the timing
replayable. Coalescing keystrokes into fewer records would cost that timing; the
batching layer already amortises the volume. If chunk count ever becomes a
problem, coalescing with a small time window is the fix — noted here rather than
built.

The format is deliberately **not** asciinema's own JSON. Re-encoding terminal
bytes into JSON strings at capture time would make the proxy responsible for
being right about encodings, and a chunk that failed to encode would be a hole
in an audit record. `payload` is raw bytes (base64 on the wire) and the reader
does the framing.

### The buffer's ordering rule

The non-obvious part is not writing to disk, it is what happens to records made
*during* an outage. Sending them straight to a recovered server would deliver a
session's later records before its earlier ones. So the shipper is **degraded**
while anything is pending on disk, and everything joins the buffer until it is
empty. `TestRecordsMadeDuringAnOutageDoNotOvertakeBufferedOnes` pins it.

An unreadable segment is discarded and counted in `Stats().Dropped` rather than
retried forever — otherwise one corrupt file blocks every later record
permanently. `Stats().Dropped` is the number that must stay zero; it also counts
records lost when no `buffer_dir` is configured, and `cmd/proxy` logs a warning
at startup in that case.

### Config

New `logging:` section (the decoder is strict — struct and
`config.example.yaml` move together): `buffer_dir`, `batch_size`,
`flush_interval`, `queue_size`, `send_timeout`, `retry_min`, `retry_max`,
`max_payload_bytes`. All optional except that leaving `buffer_dir` empty means
an outage loses records.

There is deliberately **no** knob for what is captured. What a session records
is the architecture's answer, not an operator's: a proxy that could be
configured to capture less would be a proxy whose audit trail is a local setting
(D2).

### Test notes

- `internal/logging` tests use a fake `control.Client`; the e2e tests in
  `cmd/mock-control` use the real REST client against the real mock.
- `cmd/mock-control/logging_e2e_test.go` introduces a `controlGate` in front of
  the mock's handler that **hijacks and closes the connection** for `/v1/`
  paths, so an outage is a real transport failure rather than an HTTP status.
  `/debug/` stays up: it is the test's window, not something the proxy talks to.
- The e2e stack uses a 1-minute flush interval and a 64-record batch, so
  anything that arrives without a deliberate flush arrived because it was
  critical. `TestABlockedCommandArrivesImmediately` asserts exactly that, plus
  that the batch in front of it was flushed with it.
- `startE2E` now takes an `e2eOptions` struct (was `permittedChannels []string`).
- The proxy harness (`internal/proxy/fakes_test.go`) now wires a real `Shipper`
  to the fake client, with `h.records()`, `h.awaitRecord(...)`,
  `h.recordOfKind(...)` and `recordedOnPriorityPath(h, id)`. 0010's audit
  assertions moved from log-line substrings to these.
- Password authentication in the e2e test goes over **keyboard-interactive**,
  not `ssh.Password`: that is the flow the out-of-band second factor needs
  (PLAN §4.1). This is easy to get wrong and costs a confusing
  "no supported methods remain".
- A test that opens a session channel and requests a pty must then send
  something the stand-in target finishes (an `exec`), or the target's session
  handler stays open and the harness teardown blocks.

### Follow-ups (not done here, no new prompts added)

- Tamper-evident/append-only storage at the destination — still PLAN §12.
- Coalescing keystroke-sized stream chunks, if record volume ever justifies it.
- A metrics surface for `Stats()`; today it is reachable only in-process and
  through the operator log lines the shipper writes on an outage or a drop.
