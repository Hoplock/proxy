# 0024 — The session deadline: enforce it, and tell the user before it bites — Learnings

## Summary
- **What shipped:** the proxy now **ends a session at the route's
  `session_deadline`**, on its own timer, with no call to Hoplock Control at any
  point. Warned first, explained at expiry, torn down through the ordinary path,
  and recorded as its own outcome. **No contract change** — `api/` is untouched,
  so no cross-repo obligation (`docs/CROSS-REPO-PROTOCOL.md` §1).
- **Key files:** `internal/proxy/deadline.go` (new: the timer, and the two
  lifetimes it is NOT) + `{session,logging,feedback,proxy}.go`;
  `internal/routing/deadline.go` (new: `ShortenDeadline`) + `{resolve,hop}.go`;
  `internal/logging/record.go`; `internal/config/config.go` +
  `config.example.yaml`; `cmd/proxy/main.go`;
  `deploy/control/fixtures.template.yaml`, `deploy/proxy/proxy-{direct,nexthop,zone}.yaml`;
  `test/e2e/scenarios_test.go`; `docs/PLAN.md` (§4.3, §5.1, §6.1, §6.5, §7, §10).
- **Types/identifiers added:** `routing.Route.SessionDeadline *time.Time`;
  `routing.Chain.Deadline *time.Time`; `routing.ShortenDeadline`;
  `proxy.Options.DeadlineWarning`, `proxy.DefaultDeadlineWarning` (**1m**),
  unexported `exitSessionExpired` (**253**), `session.armDeadline/warnDeadline/expire`;
  `logging.AttrEndReason` (**`end_reason`**), `logging.AttrSessionDeadline`,
  `logging.EndReason{ClientClose,SetupFailed,Revoked,Deadline}`;
  config key **`session.deadline_warning`**.
- **The warning lead time is 1 minute** (`session.deadline_warning`, negative
  disables it). Chosen to be *actionable*: long enough to write a file out,
  finish a sentence in an editor, or let a short command complete; short enough
  that someone who stepped away does not return to a warning that has scrolled
  off. **A lead longer than the whole deadline warns nobody rather than warning
  at once** — §4.3's "explaining too early is the same as not explaining".
- **The two messages, verbatim, both on the session channel's stderr with the
  `Hoplock Proxy: ` prefix** (`internal/proxy/feedback.go`):
  - warning — `Hoplock Proxy: This session reaches its authorized end in <d> and
    will then be closed. Finish up and save your work; reconnecting starts a new
    session.`
  - expiry — `Hoplock Proxy: This session has reached its authorized end and is
    now closing. Nothing is wrong and nothing was denied; reconnect to start a
    new session. Session <id>.`

    Neither is a denial or an outage (§4.3's third case). Neither names the
    policy, the target, who set the deadline, or how long the route allows. A
    session with no channel open is told nothing — the limitation §4.3 already
    records, not a new one.
- **Exit status 253** (`exitSessionExpired`), deliberately not the **254** a
  policy kill reports: a pipeline can tell "time ran out" from "policy stopped
  you" without parsing text.
- **Tolerance: the close is *initiated* at the instant, plus Go timer latency**
  (single-digit ms idle, tens of ms under load) — the timer never fires early,
  and nothing new is served after it. The client's connection is gone within
  **≤1s** after that (`failureLinger`, spent letting the client read the exit
  status), and the credential is removed within **`teardownTimeout` = 30s**. It
  depends on **the proxy's own clock only** — never on Control, proven with
  Control stopped — and, across a chain, on the hops' clocks agreeing: an
  absolute instant is only as good as NTP on the proxies.
- **Chain rule: a deadline can only ever SHORTEN along a chain.** The resolved
  instant travels to the next hop on `hop-trail@hoplock.io` beside the trail and
  the cap; each hop takes `ShortenDeadline(inherited, its own answer)`. Tests:
  `routing.TestPlanHopNeverExtendsTheDeadline` (a hop answered a *later*
  deadline declares the earlier one) and
  `proxy.TestAChainedSessionCannotExtendItsDeadline` (an inbound hop leg with a
  short inherited deadline ends at it, while this hop's own answer is an hour
  away).
- **The telemetry name an operator dashboard is built on: `end_reason` on the
  `session_end` record**, valued `session_deadline` for an expiry (and
  `client_close` / `revoked` / `setup_failed` otherwise). The instant itself is
  `session_deadline`, on the authorize record **and** on the informational
  `session.deadline_reached` record.
- **Decisions:** D2, D11, D16 and §6.5 unchanged in substance. §4.3 gained a
  **third case** (an expiry is neither branch), §5.1 gained the detached-work
  consequence, §6.1 the deadline on the hop trail, §7 the `end_reason` field.
- **What the NEXT session must know:** the hop-trail payload gained a field, so
  a chain of **mixed proxy builds refuses the hop** rather than dropping the
  deadline (fail-closed, deliberate — see *Details*). And `end_reason` is now
  the single answer to "why did this session stop": a phase that invents a new
  way for a session to end owes it a value.

## Details

### What was actually confused, and now is not

`internal/proxy/deadline.go` opens with the distinction the prompt asked to be
written into the code, because all three lifetimes are on the same route and two
of them look like this one:

- **`lifetime_seconds`** is an *authentication* bound. It becomes OpenSSH's
  `expiry-time` in the ephemeral account's `authorized_keys` (§5.1), so it stops
  the key opening a **new** connection and says nothing about an established
  session.
- **`CacheHint.ttl_seconds`** bounds decision *reuse* (§6.4) — how long this
  proxy may serve another connection from a decision it already holds.
- **`session_deadline`** is the only one that ends a live session.

Before this phase an established session had no upper bound except revocation,
and revocation needs the event stream up — which is exactly when an immortal
privileged session is least acceptable. That sentence is the whole justification
for a local timer, and it is in the file so the next "simplification" has to
argue with it.

### Where the timer lives, and why there

`session.armDeadline` is called from `setup`, immediately after `recordAuthorize`
and **before** anything is provisioned or dialled, for **both** route types. A
next-hop session is bounded too — that is what makes the chain rule mean
anything — and a session that dies between authorize and the target leg still
had a deadline while it existed.

The instant is resolved once, in `setup`:

```go
deadline := routing.ShortenDeadline(s.chain().Deadline, route.SessionDeadline)
s.recordAuthorize(route, deadline)
s.armDeadline(deadline)
```

so the audit record and the timer cannot disagree about which instant this
session was given. `PlanHop` resolves the same way for the value it declares to
the next hop, through the same function.

Waiting is done against `s.srv.now()` rather than counted down from arming, so
the deadline stays an *instant* end to end: the value a hop declares is the value
it waits for. Both waits select on `s.ctx.Done()`, so a session that ends first
leaves no goroutine behind (`TestSessionsDoNotLeakGoroutines` covers the general
case).

### Expiry is `kill`'s sibling, not `kill`

`expire` shares `kill`'s *ending* — take the `killed` flag so two endings cannot
contradict each other, close the channels, close the connection, and let
`session.close` run the ordinary teardown — and differs in the three things that
matter: the wording, the exit status, and the record. There is deliberately **no
second teardown route**: `TestDeadlineExpiryTearsDownThroughTheNormalPath`
asserts the credential plane's teardown ran exactly once and the session was
deregistered, which is the property that keeps the reaper's bookkeeping and the
telemetry flush honest.

One difference from `kill` worth knowing: `expire` lingers (up to
`failureLinger`, 1s) before closing the connection, because here **the exit
status is part of the message** — it is what distinguishes an expiry from a
policy kill in a pipeline — and pulling the socket out from under a client that
has not read it yet would waste it.

### Both messages go to every open channel, including non-interactive ones

§4.3 suppresses *progress* chatter on channels with no pty, because writing into
an `scp`/`sftp` stream corrupts it. These two are not progress: they go to
**stderr**, which those tools do not parse, and a transfer about to be cut off
is precisely the case where the user needs to know. This follows what `kill`
already does for a revocation.

### The lead-time rule that surprised the tests

With a lead time longer than the deadline itself, `warnAt` is already in the
past when the timer is armed. Warning "immediately" there would write into a
channel the client has not asked anything on yet, which §4.3 says is the same as
not warning at all — so the warning is **skipped** and only the expiry message
is sent (`TestDeadlineWarningIsSkippedWhenItsLeadHasPassed`). This is why the
e2e topology sets `session.deadline_warning: 8s` against a 30-second fixture
deadline: with the 1-minute default no scenario could observe a warning.

### The hop-trail payload gained a field

`hopTrailPayload` now carries `DeadlineUnixMilli` (0 = none, UTC by
construction). `ssh.Unmarshal` **errors on trailing bytes**, so a proxy that
predates the field neither sends nor accepts one and a mixed-version chain
refuses the hop (reported as an outage with the session id, §4.3). That is
deliberate and it is the fail-closed direction: an unbounded chained session is
the outcome worth refusing a hop over. It also means **a fleet must be upgraded
before it can chain across the change** — worth saying out loud in a release
note. Milliseconds rather than a formatted instant because both ends are
machines and an integer cannot be ambiguous about its zone; a deadline at or
before the Unix epoch is treated as none rather than wrapping.

### Telemetry: one field, four values

`end_reason` on `session_end` is the query surface, and `session.endReason()`
resolves it: `revoked` and `session_deadline` are set by whichever path ended
the session, `setup_failed` when the session never reached the target, and
`client_close` otherwise. The expiry also emits an **informational** record
(`event=session.deadline_reached`, kind `authorize`, severity `info`) carrying
the instant — deliberately not a `policy_decision` (which is `critical` and
would put every expiry on a refusal dashboard) and not an error record (which
would put it on an outage one).

The instant is on the **authorize** record too, so a proxy that died mid-session
still shows an auditor the bound the session was given.

### Test notes

- Unit tests use real short durations (500ms deadline, 250ms warning) rather
  than a fake clock: what is under test is the engine's own timer and the order
  the user is told things in, and a fake clock proves neither.
- `harnessOptions.sessionDeadline` is a *duration* only because a test cannot
  know the authorize instant in advance; what reaches the proxy is the absolute
  instant the contract defines.
- e2e: `t.Run("session deadline", …)` sits **before** the outage scenario and
  holds four sessions past a 30-second deadline, so the group costs ~2½ minutes
  of wall clock. A deadline cannot be demonstrated faster than it elapses. Its
  last subtest stops Hoplock Control, proves the session still expires on time,
  restarts it, and waits for the expiry's records to drain from the proxy's disk
  buffer — which also leaves the outage scenario below a delivered history to
  compare against, as that scenario requires.
- The fixture route is `expiring.company.com` (`session_deadline_seconds: 30`,
  `ephemeral-user`). It is ephemeral-user on purpose: the account-removal and
  detached-process assertions need an account to have been created.

### What could not be run in this session

`make e2e` needs a Docker daemon and this session had none, so the four e2e
subtests are **compiled and vetted (`go vet -tags e2e`) but not executed
locally**; CI's `e2e topology` job is the gate. `golangci-lint` could not run
either — the sandbox's v2.5.0 refuses a module targeting Go 1.26, the exact
mismatch `.github/workflows/ci.yml` documents; the `lint` job pins v2.13.2.
Everything else (`go build ./...`, `go vet ./...`, `go test ./...`, `gofmt -l`)
passes locally.

### Deliberately not built

- **Session extension / renewal / "just five more minutes".** Out of scope by
  the prompt, and correctly: it is a contract change and a Control feature, not
  a proxy hook. Nothing here is shaped to accommodate one — no "extend" seam, no
  mutable deadline — and adding it later means a new field, a new prompt, and a
  cross-repo sync, not a change to this timer.
- **Anything machine-identity-specific.** Phase 0021 was withdrawn (D17) and D2
  stands: one decision per connection. The deadline enforced here is what bounds
  how long *any* connection may hold its policy snapshot — a client multiplexing
  over `ControlMaster` included — and it needs no special case to do it. This
  phase is what makes 0021's withdrawal argument true rather than merely written
  down.
- **A second teardown path, and any interaction with revocation.** A deadline is
  a bound known at authorize time; a kill is an event. They share
  `session.close` and nothing else.

### Follow-ups

None queued. The queue is unchanged and contiguous at 0025–0033.
