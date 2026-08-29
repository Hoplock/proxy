# 0023 — The session deadline: enforce it, and tell the user before it bites

> New prompt. Phase **0016** adds the deadline *field* and explicitly defers the
> rest: *"the timer that closes a live session belongs to the proxy engine.
> Queue it if no phase covers it."* No phase covered it. This is that prompt.
>
> **It cannot start before 0016 has merged** — the contract field it enforces
> does not exist until then. Everything else here is proxy-local.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — **§4.3 (the disclosure rule)**, §5.1 (teardown kills the
  account's processes), §6.4 (revocation, and why a local bound is not "just use
  revocation"), §13 UC2/UC3.
- `prompts/implemented/0016-*` — the deadline field it defined, its shape
  (absolute instant vs duration), and the two questions it left open.
- `docs/learnings/` summaries: **0005** (the session lifecycle and failure
  reporting), **0011** (capture points), **0012** (the topology you owe
  scenarios), **0003** (revocation — the kill path this must not duplicate).

## Two facts that are currently confused, and must stay unconfused

1. **`lifetime_seconds` is an *authentication* bound.** It becomes OpenSSH's
   `expiry-time` in the ephemeral account's `authorized_keys`, so it stops the
   key opening a **new** connection. It does **not** end an established session.
2. **`CacheHint.ttl_seconds` bounds decision *reuse*,** not session length.

So today an established session has no upper bound at all except revocation
(§6.4), which needs the stream to be up — and an immortal privileged session is
least acceptable exactly when the stream is down. That is the hole 0016's field
describes and this phase closes.

Write those two sentences into the code where the timer lives. Someone will
otherwise "simplify" the deadline into one of the other two lifetimes.

## Objective

Enforce the route's session deadline locally, end the session cleanly when it
arrives, and make sure nobody's work dies without warning.

## In scope

### 1. The timer (`internal/proxy`)

- Armed at session setup from the route's deadline; enforced by the proxy
  **locally**, so it holds with Hoplock Control unreachable.
- On a chained route (D11), every hop enforces the same **instant**. A hop whose
  own authorize returns a *later* deadline than the one the session arrived
  with must not extend it: a session's deadline can only ever shorten along the
  chain. Assert this in a test — it is the failure mode an instant was chosen to
  avoid, and it is invisible until someone chains three hops.
- Expiry ends the session through the **normal** path: the engine's teardown, so
  `internal/auth/target`'s account removal, the reaper's bookkeeping and the
  telemetry flush all behave exactly as they do on a user-initiated close. Do
  not add a second teardown route.
- No deadline in the route means no timer. Absent is not zero.

### 2. What the user is told — 0016 left this open, and it is the point

An expiry is **neither a denial nor an outage**. §4.3's two branches do not cover
it and must not be stretched: this is a session ending exactly as authorized. It
needs its own wording, and the wording is the deliverable, not a detail.

- **A warning before it**, at a configurable lead time, on the session channel's
  stderr with the proxy's own prefix — so it is distinguishable from the output
  of whatever is running. Default the lead time to something a person can act
  on, and say in the learnings what you chose and why.
- **A message at expiry** naming the session id, saying plainly that the session
  reached its authorized end, and that reconnecting is the remedy — which is
  true here and is the opposite of what an outage message says.
- It must disclose nothing else: not the policy, not who set the deadline, not
  how long the route allows.
- A session with no channel open gets no message; that is the §4.3 limitation
  already recorded for `SSH_MSG_DISCONNECT`, not a new one.

### 3. Say the quiet part in the docs

Today a user discovers the lifecycle rules when their job dies. Add to
`docs/PLAN.md` §5.1 (next to the reattach trade-off it already records):

- teardown runs `pkill -KILL -u`, so **anything detached — `nohup`, `setsid`,
  `tmux`, a backgrounded job — dies with the session**. That is deliberate: no
  residue is the design;
- so work that must outlive a human's session is **not a human's session**. It
  is a machine identity (UC2, D17, 0019) or a job handed to something on the
  target that owns its own lifecycle — a systemd unit, a batch scheduler —
  started by an approved argv under restricted exec;
- and this is the same trade-off as reattachability, from the other side: the
  proxy can only record what flows through it, so capture and detached
  persistence are mutually exclusive by construction.

Three short paragraphs. The reason it belongs in the plan rather than only in a
release note is that it is a *consequence of the architecture*, and the next
person to propose "let's just let them nohup it" needs to find the answer where
they are already reading.

### 4. Record it

A session ended by its deadline is a distinct outcome in the telemetry (0011's
capture points), not an error and not a user close. An operator asking "why did
this session stop" must get the answer without inference.

### 5. Prove it

`test/e2e` plus `deploy/control/fixtures.template.yaml` (0012 owns both; that
file is the **mock** Control's fixtures in this repository's rig, not the sibling
Control repo). Subtests go in `TestTopology` — ordering is deliberate, put them
before the outage scenario — and do not touch the shared `sshBaseArgs`.

- A route with a short deadline: the client sees the warning, then the expiry
  message, then the session ends; the exit status distinguishes it from a
  policy kill.
- The account is gone afterwards and nothing is left behind — same assertion the
  ephemeral-leak check already makes, reached by a different path.
- A backgrounded process on the target does not survive the expiry. This is the
  scenario that makes §3's documentation true rather than aspirational.
- With Hoplock Control **stopped**, a live session still expires on time. This
  is the whole reason the deadline is enforced locally; without this scenario
  the feature is untested where it matters.

## Out of scope

- `api/control.yaml` — 0016 owns the field. Do not amend the contract; if it
  turns out to be unusable as specified, stop and ask (`docs/PROTOCOL.md` §9)
  rather than changing it here.
- Revocation (§6.4). A deadline is a bound known at authorize time; a kill is an
  event. They share the teardown path and nothing else.
- Session *extension*, renewal, or "just five more minutes". If it is worth
  having it is a contract change and a Control feature, and it belongs in a
  prompt of its own — note it in the learnings rather than building a hook.
- Machine-identity connection lifetimes — 0019.

## Acceptance criteria

- A session with a deadline ends at it, within a stated tolerance, through the
  normal teardown path.
- It holds with Hoplock Control unreachable, proven end to end.
- A chained session's deadline never extends at a hop.
- The user gets a warning and then an expiry message; neither is worded as a
  denial or as an outage, and neither discloses the policy.
- The telemetry distinguishes deadline expiry from every other ending.
- `docs/PLAN.md` §5.1 carries the detached-work consequence.
- `go build ./...`, `go vet ./...`, `go test ./...`, `golangci-lint run`,
  `make e2e` all pass.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0023-session-deadline-and-lifetime-learnings.md`. The summary
block MUST record: the warning lead time and why; the exact wording of both
messages and where each is written; the tolerance the timer guarantees and what
it depends on; the chain-shortening rule and its test; and the telemetry
attribute that identifies a deadline expiry — an operator dashboard will be
built from that name.
