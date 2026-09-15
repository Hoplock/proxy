# 0040 — Wait for the slot, not for the account — Learnings

## Summary
- **What shipped:** test-only. `testSessionBounds` no longer reads "no ephemeral
  accounts on the target" as "a concurrency slot is free".
- **The ordering fact:** `session.close()` removes the ephemeral account
  (`internal/proxy/session.go`), and only after `run()` unwinds does
  `Server.remove` call `s.release()` (`internal/proxy/proxy.go`) — so the
  account is gone strictly BEFORE the slot is free, and a session opened in that
  gap is refused, correctly, as a policy denial.
- **Key files:** `test/e2e/scenarios_test.go` only. New helper
  `holdTheOnlySlot(t, session, what) func() []result`.
- **Sites changed:** the prompt's four account waits, plus the two holding
  sessions those scenarios open. Both ceiling scenarios now take their holding session
  through `holdTheOnlySlot`, which retries until the proxy ADMITS one; the
  subject scenario's "the slot comes back" is now a bounded `waitFor` whose
  condition is the next session succeeding. The two preconditions and the
  trailing wait remain ACCOUNT waits — nothing may be provisioned on the target
  while a scenario counts accounts — and each now says so in a comment.
- **Left alone on purpose:** `waitForNoEphemeralAccounts` and its callers (the
  uid-allocation and provisioning scenarios). Those are about accounts by
  design; its own comment says why.
- **Also:** both refusal records are now found by the REFUSED SESSION'S OWN ID
  (`sessionIDOf`), not by `concurrency_scope` alone. A retry loop writes one
  `policy_decision` record per refused attempt, so scope alone no longer
  identifies one refusal.
- **Decisions affected:** none. D16 and §6.5 behaviour are untouched; no
  production code, no contract change, **no cross-repo obligation**.
- **The production ordering is right as it stands** — do not re-derive this:
  releasing the slot last makes a cap count *sessions this proxy still has*,
  which is the conservative reading. Reasoning in Details.
- **What the NEXT session must know:** `make e2e` cannot run in a Claude Code
  web session — the egress policy denies every Debian archive host, so the
  `target` and `user` images cannot build. CI's `e2e` job is the only place
  these scenarios run.

## Details

### Why an account wait was never evidence of a free slot

The concurrency cap is counted against the proxy's own live-session registry in
one critical section (`internal/proxy/bounds.go`, PLAN §6.5). A session leaves
that registry in exactly one place, `Server.remove` → `Server.release`, and that
runs after `run()` has unwound. Teardown of the *target* credential happens
earlier, inside `session.close()`. Both facts are deliberate, and together they
mean the target's account database transitions to "empty" while the slot is
still taken.

`TestAnEndedSessionFreesItsSlot` (`internal/proxy/bounds_test.go`) is the
in-process test of the same property and does not race, because it waits on
`h.server.liveSessions() == 0` — the slot itself. From outside the container
there is no such observable, and adding one would put a testing surface on the
proxy (explicitly out of scope for this phase, and the wrong way round in
general).

### The shape: admission is the wait

Two different waits, for two different needs.

**A session that must HOLD the only slot** goes through `holdTheOnlySlot`. It
starts the session with `overlapping`, watches for exactly one ephemeral account
to appear within `concurrentHold`, and — if none does — collects the attempt and
tries again, bounded by `readyTimeout`. An admitted session provisions an
account; a refused one is turned away before anything is provisioned, so the
account IS the admission signal. Each retry first waits for the target to hold
no account again, so a retry cannot mistake its predecessor's lingering account
for its own.

**A session that must PROVE the slot came back** is simply retried until it
succeeds:

```go
var next result
waitFor(t, "the freed slot to admit the next session", func() bool {
    third := aliceOn(proxyDirect, cappedSubjectTarget)
    third.command = "/bin/true"
    next = ssh(t, third)
    return next.code == 0
})
wantExit(t, next, "the next session after the slot was freed", 0)
```

A slot that genuinely never comes back still fails, and fails legibly: the
timeout names the property ("the freed slot to admit the next session") instead
of printing an exit status, and the trailing `wantExit` still runs on a real
`result`, so a failure prints what the client was told.

### Every wait in the two ceiling scenarios, and what it really waits for

The prompt names four sites — the four account waits. Converting the holding
sessions is the fifth change and is what makes two of those four safe to keep.

| Site | Before | After |
| --- | --- | --- |
| Precondition, subject ceiling | "the target to be free of ephemeral accounts before the ceiling" | unchanged **as a wait** — the scenario proves liveness by counting exactly one account, so nothing else may be provisioned — with a comment saying it is about accounts and says nothing about the slot |
| The holding session, both scenarios | `overlapping` + `waitUpTo(concurrentHold, … == 1)` | `holdTheOnlySlot`, which retries until admitted |
| Precondition, target ceiling | "…before the target ceiling" | same as the first row |
| "the slot comes back" | account wait, then one attempt asserted | bounded `waitFor` whose condition is the next session succeeding |
| Trailing, target ceiling | "the capped target's account to be removed" | unchanged as a wait; the comment now says it is a courtesy to whatever counts accounts next and is **not** a claim about the slot |

`waitForNoEphemeralAccounts` and the uid/provisioning scenarios that call it are
untouched: their claim ("the uid was not reused") is genuinely about accounts,
and converting them would make it pass for the wrong reason.

### The interaction the prompt asked to watch: extra refusal records

A retry loop opens more sessions, and every refused attempt writes another
`policy_decision` record. `findRecord` returns the *first* match, so
`concurrency_scope == "subject"` alone would have been satisfied by a retry's
refusal rather than by the one the client above was refused on — and in the
target-scope scenario that is not cosmetic: a retry there is `alice`, and the
assertion is that the refusal is attributed to `svc-deploy`. A stray record
would have read as a bug in the record.

Both lookups therefore match on `rec.SessionID == sessionIDOf(r)` as well as the
scope. This is strictly *more* teeth, not less: the record now has to belong to
the session the real client saw refused. It is available because the session id
rides the pre-auth banner (`user.BannerMessage`) and `sshBaseArgs` deliberately
leaves `LogLevel` at its default so OpenSSH prints it — the same mechanism the
outage scenarios already use.

The two scopes also cannot pick up each other's refusals for a structural
reason, which the session-id match now makes explicit: `concurrency_scope` is
written by whichever cap refused, and only the `capped-target.company.com`
routes carry `max_sessions_per_target`.

### Nothing about what the scenarios assert has softened

Verbatim and unchanged: the second session is still refused while the ceiling is
held; the refusal is still `Access denied.`, still not "not a permissions
problem", and still leaks none of `ceiling`, `concurren`, `limit`, or the target
name (PLAN §4.3); the refusal record still carries `concurrency_scope`,
`concurrency_limit: 1`, `concurrency_live: 1`, and is still
`policy_decision`/`critical`; the held session still exits 0.

### Why the production ordering stays (PROTOCOL §9, and the out-of-scope bullet)

The prompt asks for a stop-and-say-so if the analysis concludes the teardown
ordering itself is wrong. It does not. Releasing the slot in `Server.remove`,
after everything the session does, is what makes a cap of *N* mean "*N* sessions
this proxy still has" rather than "*N* sessions currently holding a target
account". The earlier release would let a new session provision on the target
while the previous one is still writing its `session_end` record and unwinding
its channels — so a cap of one would, for a moment, have two sessions' teardown
and setup overlapping on the same target, which is exactly the thing the cap is
sold as preventing. The current ordering is the conservative one, `release` has
the property its comment claims (one call site, so *every* ending frees the
slot), and the cost is a gap measured in milliseconds that only a test ever
observed. No follow-up phase is proposed.

### Verification, and what could not be verified here

- `go build ./...`, `go vet ./...`, `go vet -tags e2e ./...`, `go test ./...`
  and `golangci-lint run` (v2.13.2, the version CI pins; the config lints the
  `e2e` tag) all pass.
- **`make e2e` does not run in a Claude Code web session.** The topology's
  `target` and `user` images install packages with `apt-get`, and the
  environment's egress policy answers `403 Forbidden` for `deb.debian.org`,
  `ftp.debian.org`, `ftp.us.debian.org` and `cloudfront.debian.net` alike. (The
  Docker Hub blob CDN is denied too; that one has an allowed mirror,
  `mirror.gcr.io`, and re-tagging `debian:stable-slim` from it locally is enough
  to get the three binary-only images built — but no mirror gets `apt-get`
  through.) A policy denial is reported, not worked around.
- The evidence is therefore **CI's `e2e` job, run repeatedly on this PR**: see
  the PR description for the count and the run links. A future session that can
  reach a Docker host should prefer running `make e2e` in a loop.
