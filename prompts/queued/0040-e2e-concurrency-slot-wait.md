# 0040 — Wait for the slot, not for the account

## Read first

- `docs/PROTOCOL.md` — session workflow, especially §3 (scope discipline) and §8.
- `docs/PLAN.md` — **§6.5** and its two "Session bounds" tables (the concurrency
  cap is enforced against the proxy's **own live-session registry**, in one
  critical section, and exceeding it is a **policy denial**, never an outage).
  **§4.3** for the disclosure rule, because the refusal's class and vagueness
  are half of what the scenario asserts and nothing here may change either.
  **§9** for the test topology this suite drives. Decisions **D16** (unbounded
  privilege is bounded by time and the record — the concurrency caps are one of
  its four bounds) and **D12 as amended** (§6.5 is where enforcement landed).
- `docs/learnings/` — read summaries; open
  `0031-session-bounds-enforcement-learnings.md` (the caps, the registry, and
  the refusal record's attributes),
  `0039-observable-liveness-and-durability-learnings.md` (the section "A
  pre-existing e2e race, found while driving this PR" — this prompt exists
  because of it), and `0012-e2e-topology-and-ci-learnings.md` for the harness.
- Files: `test/e2e/scenarios_test.go` (`testSessionBounds`),
  `test/e2e/harness_test.go` (`waitFor`, `waitUpTo`, `ssh`, `wantExit`,
  `result`), `internal/proxy/session.go`, `internal/proxy/proxy.go`,
  `internal/proxy/bounds.go`.

## The bug

`TestTopology/session_bounds/a subject at its ceiling is denied, and the slot
comes back` fails intermittently on CI. It failed on the first run of phase
0039's PR and passed on the re-run; the diff there touched nothing it exercises.

The scenario waits for the held session's ephemeral account to disappear from the
target and then, in the very next statement, opens the session that proves the
slot came back:

```go
waitFor(t, "the capped session's account to be removed", func() bool {
    return len(ephemeralAccountsOn(t)) == 0
})
third := aliceOn(proxyDirect, cappedSubjectTarget)
third.command = "/bin/true"
wantExit(t, ssh(t, third), "the next session after the slot was freed", 0)
```

**The account and the slot are released at different moments, and the account
goes first.** In `session.close()` the ephemeral account is removed by
`s.access.Close(ctx)` (`internal/proxy/session.go`); the session then records its
end and returns, `run()` unwinds, and only then does `Server.remove` call
`s.release(sess.id)` (`internal/proxy/proxy.go`). So "no accounts on the target"
is strictly **earlier** than "the slot is free", and on a loaded runner the third
session lands inside the gap and is refused — correctly, as a policy denial:

```
scenarios_test.go:2128: the next session after the slot was freed: exit status 254, want 0
    Access denied.
```

The in-process test of the same property does not have this race:
`TestAnEndedSessionFreesItsSlot` (`internal/proxy/bounds_test.go`) waits on
`h.server.liveSessions() == 0` — the slot itself — and its comment says why.
The e2e suite has no equivalent observable from outside the container, which is
what this phase has to work around.

## Objective

Make the e2e session-bounds scenarios wait for the condition they actually
depend on, so the suite stops failing on a property that is not broken — without
weakening what it asserts and without changing what a user is told.

## In scope

### 1. The assertion becomes the wait

Where a scenario needs a freed slot, the next session **succeeding** is the wait
rather than a single attempt asserted after a proxy signal. Use the suite's own
bounded-wait idiom so a slot that genuinely never comes back still fails, and
still fails legibly:

```go
// The slot comes back, and it comes back strictly AFTER the account does:
// close() removes the account, remove() releases the slot. So the third
// session succeeding IS the wait, not something asserted once after it.
var r result
waitFor(t, "the freed slot to admit the next session", func() bool {
    third := aliceOn(proxyDirect, cappedSubjectTarget)
    third.command = "/bin/true"
    r = ssh(t, third)
    return r.code == 0
})
wantExit(t, r, "the next session after the slot was freed", 0)
```

The shape matters more than the lines: a timeout must still name the property
("the freed slot to admit the next session"), and the final `wantExit` must still
run on a real result so a failure prints the client's output.

### 2. Fix the class, not the one line

The same "account count stands in for slot state" assumption appears at **four**
places in `testSessionBounds`, and three of them are not the one that failed:

- the precondition wait before the subject-ceiling scenario ("the target to be
  free of ephemeral accounts before the ceiling") — a previous scenario's slot
  may still be held, which would make the scenario's own `hold` session be
  denied and the whole subtest fail for the wrong reason;
- the precondition wait before the target-ceiling scenario ("…before the target
  ceiling");
- the trailing wait at the end of the target-ceiling scenario ("the capped
  target's account to be removed"), which is what the *next* scenario inherits.

Decide, per site, what it is really waiting for and make it wait for that. Some
of these legitimately are about accounts (nothing may be provisioned on the
target) — say so in the comment where that is the case rather than changing it.
**Do not** convert the account waits that belong to other scenarios
(`waitForNoEphemeralAccounts`, the uid-allocation and provisioning scenarios):
those are about accounts on purpose, and the comment above
`waitForNoEphemeralAccounts` explains why.

### 3. Keep the scenario's teeth

Nothing about what the scenarios assert may soften:

- the second session is still refused while the ceiling is held;
- the refusal is still `Access denied.`, still **not** "not a permissions
  problem", and still leaks none of `ceiling`, `concurren`, `limit`, or the
  target name (PLAN §4.3);
- the refusal record still carries `concurrency_scope`, `concurrency_limit: 1`,
  `concurrency_live: 1`, and is still `policy_decision`/`critical`;
- the held session still exits 0.

Watch one interaction while you are here: a retry loop opens **more** sessions,
each refused attempt writing another `policy_decision` record. Check that the
record assertions still find the record they mean — `findRecord` by
`concurrency_scope` — and that the subject-scope and target-scope scenarios
cannot pick up each other's refusals.

## Out of scope

- **Changing the teardown ordering in `internal/proxy`.** Releasing the slot
  earlier, or moving the account removal later, is a production change with its
  own consequences for what the cap means, and it is not what this phase is for.
  If you finish the analysis and conclude the ordering itself is wrong — that a
  user reconnecting the instant their account disappears *should* be admitted —
  **stop and say so** (PROTOCOL §9) rather than changing it here. That is a
  separate phase, and it would need its own answer about what the cap counts.
- **Adding a production observable** for the live-session count (a debug
  endpoint, a log line on release) so the test can wait on it. It would make the
  test easier by putting a testing surface on the proxy, which is the wrong way
  round — and §1's fix needs nothing from the proxy at all.
- **Retiming or relaxing anything else in the suite**, including
  `concurrentHold`, `readyTimeout`, and the deadline scenarios.
- Anything in `api/`, `internal/control`, or `docs/PLAN.md` §6.5's behaviour.
  This phase changes **tests only**; if you find yourself editing production
  code, re-read the first bullet.

## Acceptance criteria

- `testSessionBounds` no longer treats "no ephemeral accounts on the target" as
  proof that a concurrency slot is free, at any of the four sites, and each
  remaining account wait says in a comment what it is really waiting for.
- Every assertion listed under "Keep the scenario's teeth" still holds, verbatim
  where it is a string the user is or is not shown.
- A slot that never comes back still fails the scenario, with a timeout naming
  the property rather than an exit status.
- `go build ./...`, `go vet ./...`, `go vet -tags e2e ./...`, `go test ./...`
  and `golangci-lint run` pass.
- `make e2e` passes locally. Run the session-bounds scenarios **repeatedly** —
  the failure was roughly 1 in N on a loaded runner, so a single green run is
  not evidence. Say in the PR how many times you ran them and on what.
- No production code changed, and no contract change, so there is **no
  cross-repo obligation** (`docs/CROSS-REPO-PROTOCOL.md` §1: this touches none
  of the shared surfaces). State that as "None" in the PR anyway — §4 requires
  the finding to be written down.

## Definition of Done & hand-off

Per `docs/PROTOCOL.md`. Move this prompt to `prompts/implemented/`; add
`docs/learnings/0040-e2e-concurrency-slot-wait-learnings.md`. The summary block
MUST give: the ordering fact (account removed in `session.close()`, slot
released in `Server.remove`) in one line, which sites you changed and which
account waits you deliberately left alone, how you convinced yourself the flake
is gone, and — if you concluded the production ordering is worth revisiting —
the reasoning, so the next session does not have to re-derive it.
