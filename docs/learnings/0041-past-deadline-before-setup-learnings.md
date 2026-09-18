# 0041 — A deadline already past ends the session before setup goes on — Learnings

## Summary
- **What shipped:** the proxy now detects a `session_deadline` that has
  **already passed synchronously**, where the deadline is resolved, and ends the
  session there — before capture, concurrency, provisioning and the target dial.
  Same ending as every other expiry (`logging.EndReasonDeadline`, PLAN §4.3's
  third case), never a denial and never an outage. **No contract change** —
  `api/` untouched, so no cross-repo obligation
  (`docs/CROSS-REPO-PROTOCOL.md` §1). No config key, no new user-visible text,
  and in the normal case (a deadline in the future) nothing changes at all.
- **`armDeadline` now reports whether setup may continue:**
  `func (s *session) armDeadline(deadline *time.Time) bool`, with three
  outcomes — `nil` → `true`, no timer, no bound; `!now.Before(*deadline)` →
  `expire` runs on the spot and it returns **`false`**, meaning the caller
  returns; otherwise the warning and the timer are armed exactly as before and
  it returns `true`. The one call site (`session.go`, right after
  `recordAuthorize`) is `if !s.armDeadline(deadline) { return }`.
- **What the user receives when no channel is open yet: nothing.** `expire`'s
  loop over `channelsLocked()` writes to no channel and `lingerUntilClosed` is
  skipped; the expiry text is passed to `session.disconnect`, where
  `SSH_MSG_DISCONNECT`'s description *would* carry it — but `x/crypto/ssh`
  exposes no way to send a disconnect (the duck-typed assertion in `disconnect`
  never fires), so it goes nowhere. That is PLAN §4.3's recorded limitation, not
  a new one, and the prompt's expectation that the text "survives having no
  channel" does **not** hold today. The same text is still passed, deliberately:
  a second wording would be a second thing to keep in step, and if the library
  ever exports a disconnect the right words are already there.
- **Did the previous ordering leak anything? No leak found**, and it was
  measured rather than assumed: over 20 runs of a past-deadline session on the
  old code the target was dialled in **14**, and credential teardown ran in
  **20/20**. `expire` closes the connection, setup's next operation fails, and
  `close()` runs the ordinary teardown — so what the race decided was whether
  anything was provisioned *at all*, never whether it was removed. On the new
  code both numbers are **0/20**. The value of the phase is the ordering, not a
  leak.
- **Key files:** `internal/proxy/deadline.go` (the check, and the comment on
  `expire` saying why the no-channel case still has an explanation to give) and
  `internal/proxy/session.go` (the call site); tests in
  `internal/proxy/{deadline,fakes}_test.go`, `cmd/mock-control/server_test.go`,
  `test/e2e/scenarios_test.go`; `cmd/mock-control/fixtures.go` and
  `deploy/control/fixtures.template.yaml` for the e2e fixture;
  `docs/PLAN.md` §6.5 (a fourth bullet under "Session bounds (D16)") and §10.
- **`cmd/mock-control` now accepts a NEGATIVE `session_deadline_seconds`.** Both
  blocks moved together — fixture validation no longer rejects it, and
  `fixtureRoute.deadline` treats only **zero** as absent — because allowing the
  value while the helper still returned `nil` would produce an *unbounded*
  session, the opposite of the case under test. It is a **fixture affordance**,
  said so in the field's doc comment: `session_deadline_seconds` is not a knob
  an operator sets, and the behaviour it reaches is one a *reused decision*
  produces in ordinary operation.
- **Decisions:** D2, D11, D16 unchanged in substance; §6.5 gained the rule, §10
  the delivery. §2's register is untouched — D16 is neither amended nor newly
  rendered.
- **What the NEXT session must know:** `armDeadline` returns a `bool` now and
  **false means return** — a new caller that ignores it puts the rest of setup
  back in a race with `expire`. And the deterministic proof that the check runs
  first is the `noTarget` test, not the target-login count: the login count
  passed on the old code more often than not.

## Details

### Why this path is reachable at all

`session_deadline` is an **absolute instant** (D16) and an authorize decision
may be **reused** for as long as the server's cache hint allows (D2, PLAN §6.4).
A decision replayed `ttl_seconds` later therefore replays the instant it was
computed with. Where that instant came from a just-in-time grant's expiry, the
replayed decision's deadline can be behind the proxy's clock before the
connection it serves is opened.

That is the *desirable* property, not a defect: an instant cannot be
re-anchored the way a duration would be, which is exactly why the field is an
instant and why a chained route cannot multiply its own window. So an
already-past deadline is **not a contract violation**, and it must not be
answered with a denial, an outage, or a refusal to serve the response. The
session ends because it reached its authorized end.

The old behaviour reached that outcome by accident: `armDeadline` spawned the
timer goroutine, `waitUntil` returned immediately on `d <= 0`, and `expire` ran
— racing the rest of setup for it. Nothing specified the ordering and nothing
tested it.

### The three things the check had to get right

- **The authorize record is still written.** `recordAuthorize` runs *before* the
  check, unchanged. A session that ended on arrival was still authorized, and an
  operator resolving its id must find the decision that produced the deadline.
  Covered by `TestADeadlineAlreadyPassedStillRecordsTheAuthorizeDecision`, which
  also asserts the informational `session.deadline_reached` record.
- **No warning fires.** Today's `warn` predicate (`warnAt.After(now)`) would
  already exclude it, but the exclusion is now **structural**: the function
  returns before the goroutine exists. `TestADeadlineAlreadyPassedWarnsNobody`
  asserts on the proxy's own log — no `deadline armed` line, no
  `deadline warning delivered` line, and the new
  `deadline already reached on arrival` line instead.
- **It is not a setup failure.** No `failSetup`, no new `stage` constant. Either
  would put a denial or an outage in the record and in what the user is told,
  about a session that ended exactly as authorized.

### Testing the ordering rather than inferring it from timing

The obvious assertion — the target recorded no login — is the weaker one.
Measured on the old code (20 past-deadline sessions, each watched until the
session was deregistered) the target was dialled in **14 of 20**, so an
assertion made at that moment would have held only 6 times; made immediately
after the client's connection closed, as the headline test makes it, it held
more often still, because the racing dial had not finished yet. Either way, a
suite relying on it alone would have been flaky-green rather than red.

The assertion that fails deterministically is `noTarget: true`: with no target
to dial, a dial that happened ends the session as a **setup failure at stage
`dial`**, which is exactly what the old code produced on every run. That test
(`TestADeadlineAlreadyPassedNeverDialsTheTarget`) is the one that pins the
ordering; it also asserts that no record for the session carries a `stage` at
all.

The chained case (`TestAChainedSessionInheritingAnExpiredDeadlineEndsOnArrival`)
has this hop answer a deadline an hour away while the inbound hop trail carries
an inherited instant a minute in the past. `routing.ShortenDeadline` takes the
earlier one, so the inner hop ends on arrival — a chained session must not be
able to outlive the bound the first hop was given (D11, D2).

`harnessOptions.sessionDeadline` needed no code change: it is a duration added
to the moment authorize is answered, so a negative value is already a past
instant. Its doc comment now says so, because a field whose negative case is
load-bearing should.

Every pre-existing deadline test passes **unmodified**.

### The mock-control fixture decision

The e2e scenario needed Hoplock Control to answer with an instant already
behind the proxy's clock, and `cmd/mock-control` blocked that in two places:
fixture validation rejected a negative `session_deadline_seconds`, and
`fixtureRoute.deadline` returned `nil` for anything `<= 0`.

**Chosen: allow the negative value**, in both places, rather than inventing a
second field. A second field would have been a second way to say the same thing
and would still have needed the same anchoring logic. Allowing it keeps one
field with one meaning — a duration anchored once, by the server that made the
decision — and the sign is simply which side of `now` the instant lands on.

Three consequences worth knowing:

- The field's doc comment now says it is a **fixture affordance for exercising a
  real proxy behaviour**, not a knob an operator sets. A real Hoplock Control
  has no reason to compute an instant behind its own clock; a reused decision
  gets there without anyone asking for it.
- `deploy/control/fixtures.template.yaml` gained
  **`expired.company.com`** (`session_deadline_seconds: -1`), beside
  `expiring.company.com`. It uses `ephemeral-user` on purpose: "nothing was
  provisioned" is only a claim on a route where something would have been.
- `cmd/mock-control/server_test.go`'s rejection case for a negative value is
  **replaced**, not deleted, by
  `TestANegativeFixtureDeadlineIsAnInstantAlreadyPast` — which asserts the value
  is accepted, that it yields an instant in the past, and that **zero still
  means absent**. The two blocks have to stay moved together, and that test is
  what says so.

The e2e subtest sits at the end of `testSessionDeadline` and costs no wall
clock, so that group's doc comment now says "every subtest here **but the
last**" holds a session open past its deadline. It asserts from outside the
proxy what the unit tests assert from inside: the command never ran, the client
is told nothing (there is no channel), and for that session's id the records
carry `end_reason=session_deadline` with **no `provisioning` record** (the
topology's version of "the target was never touched") and **no `error` record**.

### One correction to the prompt, recorded so it is not re-derived

The prompt asked for a code comment saying "the reason the message survives
having no channel is the disconnect description". It does not survive:
`golang.org/x/crypto/ssh` v0.56.0 still exposes no way to send an
`SSH_MSG_DISCONNECT` (`connection.go` lists it as a TODO), so
`session.disconnect`'s duck-typed assertion never fires and the description is
never sent. PLAN §4.3 and `docs/learnings/0024-…` both already say a session
with no channel open is told nothing, and PROTOCOL §9 makes the plan
authoritative — so the comment on `expire` says what is actually true, names the
limitation, and explains why the text is passed anyway.

### Out of scope, and left alone

- **Cache admission.** Whether a decision whose deadline has passed should be
  evicted or never served is the decision cache's business
  (`docs/learnings/0022-…`, `0032-…`, which answered "no admission policy" with
  measurement). This phase makes the proxy correct when it *is* served one.
- **Hoplock Control's side.** Whether Control should warn an author that a cache
  hint can outlive what gated it is Control's own phase 0014. Nothing here
  waits for it.
- The expiry and warning text, exit status 253, the warning lead time, and
  `end_reason`'s vocabulary are all unchanged.

### Verification

`go build ./...`, `go vet ./...`, `go test ./...` and `golangci-lint run` (with
the e2e build tag, v2.13.2 — the version CI pins, since the binary preinstalled
in this environment is built with Go 1.25 and refuses a module targeting 1.26)
all pass. The **e2e suite was not run**: it needs the Docker topology, which
this session had no way to bring up. Its scenario compiles and vets under the
`e2e` tag.
