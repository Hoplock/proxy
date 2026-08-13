# 0007 — Channel allow-list & inspection pipeline

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — especially §2 (D5), §6.2 (channel enforcement + inspection
  pipeline; low-latency requirement).
- `docs/learnings/` — read summaries; open `0004` (how channels/requests are
  pumped today).

## Objective
Turn the coarse channel handling from 0004 into a proper **inspection pipeline**:
enforce the per-connection permitted-channel allow-list, and provide a pluggable,
**low-latency** framework where inspectors can attach to any channel type. Ship
the framework with **no heavy inspectors yet** (command filtering is 0008).

## In scope
- `internal/channel`: 
  - An `Inspector` interface (or a small set) that can observe/transform channel
    open requests, channel requests (`pty-req`, `exec`, `shell`, `subsystem`,
    `window-change`, …), and the byte streams in each direction. Design so an
    inspector can **allow / deny / mutate / flag** without the transport core
    knowing specifics.
  - A registry mapping channel types → ordered inspector chains, populated from
    config/policy.
  - **Performance**: when a channel has no registered inspectors, the data path
    must be effectively pass-through (no per-byte copies/allocations beyond what
    0004 already does). Add a benchmark demonstrating negligible overhead for the
    no-inspector case.
  - Move the permitted-channel allow-list enforcement out of `internal/proxy`
    into this layer cleanly.
- Refactor `internal/proxy` to route channels through the pipeline instead of the
  inline handling from 0004, preserving all existing behavior and tests.

## Out of scope
- Actual command filtering logic and policy actions (0008). Logging pipeline (0009).

## Acceptance criteria
- All 0004/0005/0006 integration tests still pass unchanged in behavior.
- Unit tests: an allow inspector, a deny inspector, and a passthrough path.
- Channel allow-list denial now happens in `internal/channel` and is tested.
- A benchmark shows the no-inspector path adds negligible latency/allocations vs.
  0004's direct pump.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0007-channel-inspection-pipeline-learnings.md`. Summary block MUST
give the `Inspector` interface signature, how inspectors register per channel
type, and exactly how 0008's command filter should attach to `exec` and `shell`.
