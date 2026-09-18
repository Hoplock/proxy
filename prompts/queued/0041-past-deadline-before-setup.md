# 0041 — A deadline already past ends the session before setup goes on

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — **§2 (D2, D16, D11)**; **§4.3** (what the user is told: the
  three cases, and why an expiry is neither a denial nor an outage); **§6.4**
  (policy caching and session revocation — the path that makes an already-past
  deadline ordinary rather than exotic); **§6.5**, its "Session bounds (D16)"
  subsection (what `session_deadline` is, and the two lifetimes it is not).
- `docs/learnings/` — read summaries; open **0024** (the deadline: the timer,
  the two user messages, `ShortenDeadline`, `end_reason`) and **0022** and
  **0032** (the decision cache, and why it has no admission policy). Skim
  **0031** for the setup-stage ordering this check sits in front of.

## Objective
`session_deadline` is an **absolute instant** (D16) and a decision may be
**reused** (D2, §6.4). Those two facts together mean a route can legitimately
arrive carrying a deadline that has already passed, and the proxy must have a
defined answer for it.

Today it has an answer, but by accident rather than by design. `armDeadline`
spawns a goroutine; `waitUntil` returns immediately on `d <= 0`; `expire` runs.
That is the right outcome, reached by a path nobody specified and no test
covers.

Make it deliberate: detect a past deadline **synchronously**, before setup goes
on to capture, concurrency, provisioning and the target dial — and cover the
behaviour, including the chained case.

This is a small phase. It changes no contract field, no configuration key and no
user-visible text, and in the normal case (a deadline in the future) it changes
nothing at all.

## Why this is not hypothetical

Hoplock Control issues a cache hint with a lifetime of its own, and the snapshot
it hinted carries an absolute instant. So a decision reused `ttl_seconds` later
replays the instant it was computed with. Where that instant came from a
just-in-time grant's expiry, the replayed decision's deadline can be in the past
before the connection it serves is even opened — which is the *desirable*
property (an instant cannot be re-anchored the way a duration would be), and it
is exactly why this path is reachable in normal operation rather than only under
a misbehaving server.

It is therefore **not a contract violation and must not be treated as one.** Do
not answer it with a denial, an outage, or a refusal to serve the response. The
session ends because it reached its authorized end, which is §4.3's third case,
and it must read that way in the record and to the user.

## In scope

### The check (`internal/proxy/deadline.go`, `internal/proxy/session.go`)

`armDeadline` currently returns nothing and always spawns the timer goroutine.
Give it a synchronous first step and a result the caller acts on:

```go
// armDeadline starts this session's local deadline timer, reporting whether
// setup may continue. A deadline already reached ends the session here rather
// than racing the rest of setup, and false means the caller must return.
func (s *session) armDeadline(deadline *time.Time) bool
```

- `deadline == nil` → `true`, unchanged: no bound, no timer.
- `!s.srv.now().Before(*deadline)` → end the session on the spot, through the
  same `expire` path the timer uses, and return `false`.
- otherwise → arm the warning and the timer exactly as today, and return `true`.

At the call site in `session.go`, immediately after
`deadline := routing.ShortenDeadline(...)` and `s.recordAuthorize(route, deadline)`:

```go
if !s.armDeadline(deadline) {
    return
}
```

Three things this must get right, and each is a way of getting it wrong:

- **The authorize record is still written.** `recordAuthorize` runs before the
  check, as it does now. A session that ended on arrival is still a session that
  was authorized, and an operator resolving its id must find the decision that
  produced the deadline.
- **`warnDeadline` must not fire.** There is nothing to warn about and, before
  the first channel, nobody to warn. Today's `warn` predicate
  (`warnAt.After(now)`) already excludes it; keep it excluded structurally by
  returning before the goroutine exists, rather than relying on that predicate.
- **This is not a setup failure.** Do not route it through `failSetup` and do not
  add a `stage` constant for it. Those produce a denial or an outage in the
  record and in what the user is told; this is neither (§4.3). The end reason
  stays `logging.EndReasonDeadline`.

### What the user gets, and why it is still right

Before the first channel is open there is no stderr to write to, so `expire`'s
loop over `s.channelsLocked()` writes nothing and `lingerUntilClosed` is
correctly skipped. The expiry text reaches the client through
`session.disconnect`'s `SSH_MSG_DISCONNECT` description instead. Keep the text
the same — it is the expiry message 0024 settled, it already says nothing was
denied, and a second wording for the same ending would be a second thing to keep
in step.

Say this in the code rather than leaving it to be rediscovered: the reason the
message survives having no channel is the disconnect description, and that is
not obvious from `expire` alone.

### Is the current race actually harmful?

Probably not, and the prompt says so rather than overstating it: `expire` closes
the connection, so setup's next operation fails and `close()` runs, which is the
path that removes provisioned credentials (D6, §5.1). But the ordering is
**unspecified** — `expire` calls `endLeg()` at a moment when the leg may not
exist yet, and whether anything provisioned afterwards is torn down depends on
that timing rather than on a rule. Establishing the ordering is most of the
value here; do not spend the phase hunting for a leak to justify it, and do not
claim one in the learnings if you do not find one.

## The tests (`internal/proxy/deadline_test.go`, `test/e2e/scenarios_test.go`)

The harness already supports this with no change: `harnessOptions.sessionDeadline`
is a duration added to the moment authorize is answered, so a **negative**
duration produces a past instant. Widen its doc comment to say so — a field whose
negative case is load-bearing should say it is.

Required cases:

1. **A past deadline ends the session at once.** `sessionDeadline:
   -time.Minute`. The client's connection closes without the session running,
   and the record carries `end_reason=deadline` — not `setup_failed`, not
   `revoked`.
2. **Nothing is provisioned and the target is never touched.** Assert
   `len(h.target.Logins()) == 0`. This is the assertion that makes the phase
   worth doing: it is what "before setup goes on" means, and it fails today
   whenever the race goes the other way.
3. **The dial is never attempted.** Run the same case with `noTarget: true`, so
   a dial would fail if one happened. The session must still end with
   `end_reason=deadline` rather than with a setup failure — proving the ordering
   rather than inferring it from timing.
4. **No warning is emitted.** Assert the warning text is absent, with
   `DeadlineWarning` left at its default so the lead time is longer than the
   (negative) remaining time.
5. **The chained case.** A hop whose inherited deadline has already passed —
   `routing.ShortenDeadline` picking the earlier of an expired inherited instant
   and this hop's own future one — ends the same way. A chained session must not
   be able to outlive the bound the first hop was given (D11, D2).
6. **The future case is untouched.** The existing
   `TestSessionEndsAtItsDeadline` and the warning tests must pass unchanged. If
   any of them needs editing, that is a signal the change went wider than it
   should have.
7. **An e2e scenario** beside `testSessionDeadline` in
   `test/e2e/scenarios_test.go`: a fixture route whose deadline is already past
   produces a session that ends immediately with the expiry record, through the
   real topology. `cmd/mock-control` blocks this in **two** places today, and
   both would have to move together: its fixture validation rejects a negative
   `session_deadline_seconds`, and its `deadline()` helper returns nil for
   anything `<= 0`, so a negative value would produce no deadline at all rather
   than a past one. There is also a test asserting the validation rejects it.
   Decide and record which you did: allow a negative value for this purpose, or
   express the scenario another way. If you allow it, say in the field's doc
   comment that it is a fixture affordance for exercising a real proxy
   behaviour — `session_deadline_seconds` is not a knob an operator sets.

## Out of scope
- **Any contract change.** `session_deadline` already says what it needs to say;
  `api/` is untouched and there is no cross-repo obligation
  (`docs/CROSS-REPO-PROTOCOL.md` §1). If you find yourself wanting a field,
  stop and say so rather than adding one.
- **Cache admission.** Whether a decision whose deadline has passed should be
  evicted or never served is the decision cache's business (0022, 0032, which
  answered "no admission policy" with measurement). This phase makes the proxy
  correct when it *is* served one.
- **Hoplock Control's side.** Whether Control should warn an author that a cache
  hint can outlive what gated it is Control's own phase 0014. Nothing here
  depends on it and it must not be waited for.
- **Changing the expiry or warning text**, the exit status (253), the warning
  lead time, or `end_reason`'s vocabulary.

## Acceptance criteria
- `armDeadline` reports whether setup may continue, and a past deadline ends the
  session before capture, concurrency, provisioning or the dial — asserted by the
  target recording no login and by the `noTarget` case ending as a deadline
  rather than as a setup failure.
- The authorize record is still written for a session that ended on arrival.
- The end reason is `deadline`; no setup-failure stage is introduced.
- No warning is emitted for a deadline that has already passed.
- An inner hop with an expired inherited deadline ends the same way.
- Every existing deadline test passes unmodified.
- An e2e scenario covers it, and the mock-control fixture change it needed (if
  any) is documented in the field's doc comment.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0041-past-deadline-before-setup-learnings.md`. The summary block
MUST give `armDeadline`'s new signature and its three outcomes, what the user
receives when no channel is open yet, and whether the previous ordering was
found to leak anything — including a plain "no leak found" if that is the
answer, since the next session should not have to look again.
