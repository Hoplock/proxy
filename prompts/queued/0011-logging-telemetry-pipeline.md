# 0011 — Logging & telemetry pipeline

> Renumbered from 0010 (`docs/PLAN.md` §10, renumbering note).

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — especially §2 (D8), §7 (full logging requirements),
  §4 (redaction).
- `docs/learnings/` — read summaries; open `0010` (audit-event shape, priority
  flag, and the tier marker), `0002` (log ingest endpoints), `0005` (basic
  session logging today).

## Objective
Replace the basic session logging with the full **telemetry pipeline**:
structured records, **batched** shipment to Hoplock Control, **immediate**
shipment for critical events, a **local disk buffer** for network-outage
resilience, and correct **redaction**.

## In scope
- `internal/logging`:
  - **Session capture** sufficient to reconstruct a session (PLAN §7): metadata
    (session id, identity + source, target, route/hop path **and the connection
    direction of each leg** (D11), auth method, target-credential method (D6a),
    timestamps, channel types, in-channel requests, forwarding destinations,
    policy decisions **and the tier that decided** (D12)) plus replay-friendly stream
    capture for pty sessions (asciinema/ttyrec-style).
  - **Batching**: efficient batched delivery to Hoplock Control's batch
    ingest endpoint (0002). Configurable batch size/flush interval.
  - **Priority/immediate path**: blocked commands and other critical events
    (0010's flagged events) are delivered immediately — either flush the in-flight
    batch or use the dedicated priority endpoint (D8). Bound the added latency.
  - **Resilience buffer**: when the server is unreachable, persist to a local
    per-session area and **drain on recovery** with retry/backoff. Local storage
    is a buffer, not the destination.
  - **Redaction**: initial-auth password never written (already true; assert it
    end-to-end here). Session-typed passwords may be captured (per user decision).
- Wire capture points in `internal/proxy` / `internal/channel` / `internal/filter`
  to feed this pipeline; remove the interim basic logging from 0005/0010.

## Out of scope
- Tamper-evident/append-only storage (later; note it in learnings). Real
  management-server storage (mock stores for assertions).

## Acceptance criteria
- Integration tests: a full session produces reconstructable records at the mock;
  a batch is delivered on flush; a blocked command arrives **immediately**
  (before the normal flush interval) — assert timing/ordering.
- Outage test: with the mock down, records buffer to disk; when it returns, the
  buffer drains and nothing is lost.
- Redaction test: initial-auth password never appears in any record or on disk.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0011-logging-telemetry-pipeline-learnings.md`. Summary block MUST
document the record schema, batch vs immediate delivery semantics, the disk-buffer
location/format and drain behavior, and the capture points wired into the proxy.
