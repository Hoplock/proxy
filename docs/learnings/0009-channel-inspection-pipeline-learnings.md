# 0009 — Channel allow-list & inspection pipeline — Learnings

## Summary
- What shipped: `internal/channel`, the SSH inspection pipeline. It enforces all
  three D5a axes where SSH decides each one, and hosts ordered per-channel-type
  inspector chains. `internal/proxy` now asks the pipeline for every channel,
  request, destination, and global request; no policy call is left in the
  transport. No inspectors are registered yet (0010/0011 attach).
- Key packages/files: `internal/channel/{doc,inspector,registry,forward,reason,
  pipeline}.go` (+ `pipeline_test.go`, `inspector_test.go`, `forward_test.go`,
  `registry_test.go`, `bench_test.go`); `internal/proxy/{channel,session,proxy,
  feedback}.go` + `policy_test.go`; `internal/sshtest/target.go`.
- **Inspector interface — a base plus three capability interfaces.** Only the
  capabilities an inspector implements are used, which is what lets a channel
  with no *stream* inspector skip stream wrapping entirely:
  ```go
  type Inspector        interface{ Name() string }
  type OpenInspector    interface{ Inspector; InspectOpen(context.Context, *OpenEvent) Decision }
  type RequestInspector interface{ Inspector; InspectRequest(context.Context, *RequestEvent) Decision }
  type StreamInspector  interface{ Inspector; InspectStream(context.Context, *StreamEvent) io.Reader }
  ```
  `Decision{Action, Reason, Detail, Payload, By}` with `ActionAllow` (the zero
  value) / `ActionFlag` / `ActionMutate` / `ActionDeny`, built by `Allow()`,
  `Deny(reason)`, `DenyWithDetail`, `Flag(detail)`, `Mutate(payload)`.
- **Registration:** `reg := channel.NewRegistry(); reg.Register(channelType,
  inspectors...)`, in chain order; `channel.AnyChannel` ("*") applies to every
  type and runs *after* the type-specific chain. Hand the registry to the engine
  as `proxy.Options.Inspectors`; nil registers nothing. `channel.New(Options{
  Policy, Inspectors, SessionID, Logf})` is built per session in
  `session.setup`, right after `s.route`, before `ready` closes.
- **Where each axis is enforced** — all inside `internal/channel`, none in
  `internal/proxy`:

  | Axis | Field | Enforced in | Reached from |
  | --- | --- | --- | --- |
  | 1 channel types (both directions) | `permitted_channels` | `Pipeline.Open` | `session.openChannel`, for client- and target-opened channels |
  | 2 in-channel requests | `permitted_requests{types,subsystems}` | `Inspection.Request` | `session.policeRequest`, on the queued replay *and* in `pump` |
  | 3a forwarding destinations | `permitted_forwards` | `Pipeline.Open` (after `ParseForward`) | same as axis 1 |
  | 3b global requests | `permitted_global_requests` | `Pipeline.GlobalRequest` | `session.serveGlobalRequests(..., policeRequests)` |

- **How 0010's command filter attaches.** Implement `RequestInspector` and
  register it for `"session"`. `exec` arrives as `RequestEvent{Type:
  control.RequestExec, Command: "<the parsed command>"}` — the pipeline
  unmarshals it, so do not re-parse the payload. Return `Deny(reason)` for
  `block_command`, `Flag(detail)` for `warn_and_continue`, `Allow()` for
  `allow_and_log`. For interactive `shell`, also implement `StreamInspector`:
  the `shell` request is the signal to arm keystroke inspection, and the
  `FromClient` stream is the keystrokes. `kill_session` needs a session handle
  the pipeline does not carry — see Details.
- Decisions made/affected: D5, **D5a** (all three axes now enforced), PLAN §4.3
  (a denied request is answered, explained, and only ended when there is nothing
  left to do), §6.2. **No `docs/PLAN.md` change** — nothing deviated.
- Gotchas: a denied **request** is not a denied channel (refusing `pty-req`
  leaves the channel able to run a command); ancillary requests bypass the
  policy and an inspector's denial of one is downgraded to a flag; a malformed
  forwarding payload is a *denial*, never a pass and never a panic.
- What the NEXT session must know: `Inspection.Reader` returns the very reader
  it was handed when no stream inspector is registered — `BenchmarkStreamCopy`
  holds that identity, so do not put anything unconditional on the byte path.

## Details

### Why a base interface plus three capability interfaces

One wide `Inspector` would have forced every inspector to carry no-op open and
stream methods, and — worse — would have made "does this channel have a stream
inspector?" unanswerable. The pipeline sorts a channel's chain into request and
stream slices **once, at open**, so the per-byte question is `len(i.streams)==0`
rather than a chain of no-op wrappers. That is the whole performance story:

```
BenchmarkStreamCopy/direct-4      9453 ns/op  3466 MB/s  32784 B/op  2 allocs/op
BenchmarkStreamCopy/pipeline-4    8657 ns/op  3785 MB/s  32784 B/op  2 allocs/op
BenchmarkStreamCopy/inspected-4   9999 ns/op  3277 MB/s  32888 B/op  4 allocs/op
```

`direct` is phase 0005's pump; `pipeline` is the same copy with the reader taken
from `Inspection.Reader` first. Identical allocations, times within noise. The
benchmark deliberately hides `io.Copy`'s `WriterTo`/`ReaderFrom` shortcuts
(`plainReader`, `sink`), because an `ssh.Channel` has neither and a
`bytes.Reader` → `io.Discard` pair would have measured a memory move that never
happens in the proxy.

Policy costs are paid at open and request time instead: `BenchmarkOpen` is
~130 ns for a session channel and ~900 ns for a `direct-tcpip` matched against a
three-entry destination list, once per channel.

### Policy and inspectors are deliberately not the same mechanism

`Pipeline` consults the three axes **first, always**, and only then runs the
chain. An inspector can therefore only narrow what Hoplock Control already
allowed, and no registration order can put local code in front of server policy.
That is also why `ActionAllow` is the zero value: an inspector that looked at an
event and had nothing to say must not deny a session by accident, and nothing
fails open as a result.

Within a chain: the **first denial wins and stops the chain** (a decision
already made cannot be widened by what comes next), `ActionMutate` replaces the
payload for the inspectors that follow *and* for the caller
(`Decision.PayloadOr`), and `ActionFlag` logs and proceeds.

### Axis 2 is at the request, and a denial is not always an ending

`session.policeRequest` runs in two places, because a request can arrive on
either side of the target leg coming up: over the queued replay in
`handleSessionChannel`, and over `forwardClientRequests` inside `pump`. Both
call `Inspection.Request`, so there is one enforcement point and two feeds.

`channel.RequestStartsExecution(name)` (`shell`, `exec`, `subsystem`) splits the
two shapes of denial:

- **not** execution-starting (`pty-req`, `env`, `x11-req`, `auth-agent-req`) →
  `Reply(false)` + the clause on stderr, and the channel stays alive. This is
  what makes "CI may run commands but never gets an interactive terminal" a
  working session rather than a broken one.
- execution-starting → `Reply(false)` + the clause on stderr + `exit-status`
  254 + close, so a script sees a failure rather than an empty success.

Only requests **the client made** are policed. A channel the target opened has
its requests relayed: the axis is about what this session may ask its target
for, and the channel-type axis has already decided that channel may exist.

**Ancillary requests** (`window-change`, `signal`, `exit-status`, `exit-signal`,
`break`, `eow@openssh.com`, `xon-xoff` — `control.IsAncillaryChannelRequest`)
skip the policy check entirely. Inspectors still see them, because a session
recorder needs the resizes to replay a session, but a `Deny` on one is logged
and **downgraded to a flag**: PLAN §6.2 says these are always relayed, and
denying a terminal resize is a broken session, not an enforced one.

### Axis 3a: parsing a payload written by the other side

`ParseForward(channelType, payload)` reads the RFC 4254 §7.2 four-field payload
with `ssh.Unmarshal`, which is strict in both directions — short *and* long
payloads fail. Anything unreadable is `ErrMalformedForward`, which the pipeline
turns into a denial: a destination the proxy cannot read is one it cannot
police. Ports above 65535 and an empty host are malformed too, because clamping
would silently turn `70000` into a port some policy might permit.

`matchHost` keeps the two naming worlds apart, which is the rule PLAN §6.2 spends
a sentence on:

- `*` matches anything;
- a CIDR matches **only IP literals** (a name would have to be resolved, and a
  DNS answer is not a decision the PDP made);
- `*.suffix` matches **only names** (a wildcard is a DNS statement, so letting
  it match an IP literal would make `*.internal` a wildcard over the estate);
- otherwise exact — two IP literals compared as addresses so the many spellings
  of one IPv6 address are one host, everything else case-insensitively with a
  trailing dot trimmed.

`matchPort`: an exact `port`, an inclusive `port_range`, or neither (any port).
An entry naming **both**, or an inverted range, matches nothing — those are
contract violations, and fail-closed is the only reading that cannot widen a
policy by being written wrong.

`forwarded-tcpip` gets its own list and is matched on the *listening* address,
which is the same address seen from the other end.

### Axis 3b: why the global request had to be its own check

`serveGlobalRequests` grew a `policing` flag. It is `policeRequests` only for
the client's request stream (`session.run`); the target's own requests
(`dialTarget`, `openNextHop`) are relayed. The check happens **after** `dst()`
returns, which is deliberate: `dst` is `legConnWhenReady`, so waiting for the
far connection is also what makes the route — and therefore the pipeline —
available. Denying `forwarded-tcpip` is not a substitute for denying
`tcpip-forward`: the listener is created on the target either way.

### What the user is told

`internal/channel` produces a **clause**, never a message. `Decision.Reason` is
a sentence naming only what the client itself asked for ("An interactive
terminal is not available on this session.", "Forwarding to db.internal:22 is
not available on this session."), and `proxy.deniedText` renders it behind
`user.DenyMessage`. The deny/outage split (PLAN §4.3) keeps exactly one
implementation in `internal/auth/user`. All the clauses live in
`internal/channel/reason.go`.

The **session channel** is the exception: it is accepted before the policy
exists, so a denial there arrives through `failChannel` and renders as the bare
`Access denied.` — the pre-existing 0005 behaviour, and the deliberately vague
one for a session-level denial. A global request has no channel to write to at
all, so its denial is the `false` reply and a log line, with an empty `Reason`.

### Changes outside the two packages

- `internal/sshtest/target.go`: records `Subsystems()` and `GlobalRequests()`
  (the latter is how a test tells "the client was refused" from "the listener
  was never created"), serves the `subsystem` request, and keeps answering
  requests **while a shell or subsystem runs** — a real sshd answers a resize
  mid-session, and a fake that stopped reading hung any client that sent one.
- `internal/proxy/proxy_test.go`: `TestPermittedChannelOtherThanSessionIsProxied`
  now opens `direct-tcpip` with a **real** payload. It previously passed `nil`,
  which 0009 correctly denies. The route it runs under polices no destinations,
  so the test's claim is unchanged.

### Follow-ups for later phases

- **0010** registers the command filter; see the Summary for the exact seam.
  `kill_session` (D5-answers 12–14) needs to reach `proxy.Server.KillSession`,
  which the pipeline does not carry today. Either give `channel.Options` a
  killer callback, or have 0010's inspector hold the `control.SessionRegistry`
  it was constructed with and the session id from `RequestEvent.Channel.SessionID`
  — the id is already on every event for exactly this reason.
- **0011** will want `AnyChannel` and the `Flag` action; `Decision.Detail` and
  `Decision.By` exist to become audit-event fields. `StreamEvent` already
  distinguishes stderr from the main stream and carries the direction.
- Nothing populates the registry from **config** yet: `proxy.Options.Inspectors`
  is nil in `cmd/proxy`. The first phase that ships an inspector adds the config
  key that turns it on.
- `Pipeline.GlobalRequest` runs no inspectors — the axis needed no chain here.
  If a later phase wants to observe global requests, that is the seam to widen.
