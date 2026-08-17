# 0009 — Channel allow-list & inspection pipeline

> Renumbered from 0008 (`docs/PLAN.md` §10, renumbering note). Scope grew: this
> phase now enforces **all three policy axes** from D5a, not just channel types.
> Learnings written before that revision call this phase "0008".

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — especially §2 (D5, **D5a**), §6.2 (the three axes and where
  SSH decides each one; low-latency requirement).
- `docs/learnings/` — read summaries; open `0006` (the field names and their
  absent-value defaults) and `0005` (how channels, requests and global requests
  are pumped today).

## Objective
Turn the coarse channel handling from 0005 into a proper **inspection
pipeline**, and make it enforce the vocabulary 0006 added: channel types,
in-channel requests, forwarding destinations, and connection-level global
requests. Ship the framework with **no heavy inspectors yet** (command filtering
is 0010).

This is the phase where the product stops being a bastion with an allow-list and
starts being an SSH firewall, so the acceptance criteria are written around
policy statements a customer would recognise, not around internal structure.

## In scope
- `internal/channel`:
  - An `Inspector` interface (or a small set) that can observe/transform channel
    open requests, channel requests (`pty-req`, `exec`, `shell`, `subsystem`,
    `window-change`, …), and the byte streams in each direction. Design so an
    inspector can **allow / deny / mutate / flag** without the transport core
    knowing specifics.
  - A registry mapping channel types → ordered inspector chains, populated from
    config/policy.
  - **Axis 1 — channel types.** Move the permitted-channel allow-list
    enforcement out of `internal/proxy` into this layer cleanly, keeping
    both-directions enforcement (a channel the session may not open is not one
    the target may hand it).
  - **Axis 2 — in-channel requests.** Enforce at the *request*, not the open:
    a `session` channel is opened before anyone knows what it is for. Deny
    `pty-req`, `shell`, `exec`, `subsystem` (by subsystem name) and the rest per
    policy. A denied request is refused with a reply and an explanation on
    stderr per PLAN §4.3 — the channel is already open, so a bare close is the
    one thing it must not be.
  - **Axis 3a — forwarding destinations.** Parse the host/port out of
    `direct-tcpip` (and `forwarded-tcpip`) channel-open payloads and match them
    against the route's destination list. Parse defensively: the payload is
    attacker-controlled, and a malformed one is a denial, not a panic.
  - **Axis 3b — global requests.** `serveGlobalRequests` in
    `internal/proxy/channel.go` currently relays every connection-level request
    unpoliced, including `tcpip-forward`. Consult the allow-list and refuse a
    denied request with `req.Reply(false, nil)` instead of forwarding it.
    Denying `forwarded-tcpip` is **not** a substitute: the listener would still
    be created on the target.
  - **Performance**: when a channel has no registered inspectors, the data path
    must be effectively pass-through (no per-byte copies/allocations beyond what
    0005 already does). Add a benchmark demonstrating negligible overhead for the
    no-inspector case. Policy checks happen at open/request time, not per byte.
- Refactor `internal/proxy` to route channels through the pipeline instead of the
  inline handling from 0005, preserving all existing behavior and tests.

## Out of scope
- Actual command filtering logic and policy actions (0010). Logging pipeline (0011).
- Contract changes: 0006 defined these fields. If one is unusable as specified,
  stop and raise it (PROTOCOL §9) rather than redesigning it here.

## Acceptance criteria
Each of these is a policy sentence proven end to end:
- **"May open a shell, may not copy files off the box."** `shell` succeeds;
  `sftp` (subsystem) and `scp` (as an `exec`, if the policy denies it) are
  refused with a user-visible reason.
- **"CI may run commands but never gets an interactive terminal."** `exec`
  succeeds; `pty-req` is refused and the client is told why.
- **"May tunnel to the database and nowhere else."** `direct-tcpip` to the
  permitted host:port succeeds; another host, and another port on the same host,
  are refused.
- **"May never open a listener."** `tcpip-forward` is refused at the global
  request, and no listener exists on the target afterwards.
- All 0005/0007/0008 integration tests still pass unchanged in behavior.
- Unit tests: an allow inspector, a deny inspector, and a passthrough path;
  malformed `direct-tcpip` payloads are denied without panicking.
- Channel allow-list denial now happens in `internal/channel` and is tested.
- A benchmark shows the no-inspector path adds negligible latency/allocations vs.
  0005's direct pump.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0009-channel-inspection-pipeline-learnings.md`. Summary block MUST
give the `Inspector` interface signature, how inspectors register per channel
type, where each of the three axes is enforced, and exactly how 0010's command
filter should attach to `exec` and `shell`.
