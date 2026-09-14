# 0038 — A channel request is answered before its channel closes — Learnings

## Summary
- **What shipped:** a real proxy bug fixed, found as a 1-in-70 test flake.
  `pump` could close the client's half of a channel while a request the client
  was blocked on had been accepted by the target but not yet relayed back, so a
  permitted `exec` reached the client as `EOF` instead of `true`. A `relayGate`
  now sequences the client's in-flight requests against teardown, bounded by
  `exitGrace`.
- **Key files:** `internal/proxy/channel.go` (`relayGate`, `pump`'s teardown,
  `forwardClientRequests`, `exitGrace`); `internal/proxy/teardown_test.go`
  (new). Nothing else changed — no contract, no config, no plan.
- **Identifiers added:** `relayGate` with `newRelayGate`, `hold`, `holdBefore`,
  `release`. `forwardClientRequests` gained a `relayGate` parameter.
  `exitGrace` is now a `var` (same value) so the bound test can shorten it.
- **Decisions affected:** none. This is PLAN §4.3's disclosure rule and §6.2's
  axis-2 delivery path rendered correctly; D5/D5a are unchanged and no index in
  `docs/PLAN.md` describes `pump`'s teardown, so the plan is untouched.
- **Gotcha:** moving `all.Wait()` above the closes **deadlocks** — see Details.
  It is the first fix anyone proposes, and it is wrong.
- **What the NEXT session must know:** the gate is held across the *whole* of
  one client request — policy decision, relay, and answer — and teardown takes
  it *after* replaying the exit status and *before* `near.Close()`. A change to
  either end of that window reopens the defect or introduces the deadlock.

## Details

### The defect

`pump` gated teardown on the **output** being drained, then closed both halves
and only afterwards ran `all.Wait()` — which is what would have waited for
`forwardClientRequests`. So the near-side request forwarder could be sitting
between `dst.SendRequest` returning the target's answer and `req.Reply` handing
that answer to the client when `near.Close()` ran, and the answer was lost.

The window opens whenever a command finishes faster than the proxy can relay
the reply for the request that started it — every `true`, `uptime`, or failed
one-liner on a fast target. OpenSSH tolerates it (a closed channel reads as "the
command ran"), but a client that distinguishes "exec refused" from "exec
accepted, then the channel ended" sees the wrong one — and a refusal is exactly
what the proxy says when policy denies a command (PLAN §6.3). Losing the
affirmative reply makes a permitted command indistinguishable on the wire from a
denied one, which is the confusion PLAN §4.3 exists to prevent.

`pump` already held this ordering guarantee for the exit status — captured
rather than forwarded as it arrives, replayed once the output has drained. The
request reply simply never got the same treatment.

### The primitive, and why this one

`relayGate` is a one-token buffered channel used as a mutex with a bounded
acquire. The two candidates the prompt named were a completion signal for the
forwarder and a lock teardown also takes; this is the second, and it was chosen
for two reasons:

- **It covers the whole request, not just the reply.** The gate is taken before
  `policeRequest` and released after `forwardRequest`, so a denial's stderr text
  and exit status — PLAN §4.3's disclosure sequence, which phase 0009 argued —
  are protected by the same window as the relayed answer. A completion signal
  raised only when the reply settles would have left the denial path exposed.
- **It has no re-open window.** An "is anything in flight?" signal that teardown
  samples can be false at the instant it is read and true a microsecond later.
  A lock cannot: whoever holds it, holds it.

It is a channel rather than a `sync.Mutex` because **teardown must be able to
give up**. `sync.Mutex` has no bounded acquire, and an unbounded wait is exactly
what `exitGrace` exists to prevent.

### Why `all.Wait()` above the closes deadlocks

`forwardClientRequests` ranges over `nearReqs`. `nearReqs` is closed by
`x/crypto` when the channel is closed — that is, by the very `near.Close()` the
move was meant to delay. So waiting for the forwarder to **return** before
closing waits for something only the close can cause. The `TestATargetThatNever
AnswersDoesNotHoldTheChannelOpen` test is what pins this down: it hangs forever
under that "fix" and passes under this one.

The corollary is the release **after** the closes: teardown hands the gate back
once `near` and `far` are closed, so a request that was queued during teardown
still unwinds — it relays into a closed channel, is answered there, and the
forwarder returns when `nearReqs` closes. Without that release, a queued request
would block on the gate forever and `all.Wait()` would hang.

### Where teardown takes the gate, and why there

Order is: `<-drained` → wait for `reqsDone` (or grace) → **take the gate** →
replay the exit status → `near.Close()` → `far.Close()` → release.

The gate sits **before** the exit-status replay on purpose. The client's
contract is `ok == true`, then the command's output, then the exit status; with
the gate after the replay, a stalled relay would let "the command finished"
overtake the answer to the request that started it, which is the same class of
inversion the exit status's own capture-and-replay exists to prevent. Taking it
first costs nothing in the normal case — the target answers a request long
before it produces output — and keeps the order true in the pathological one.

`exitGrace` bounds the new wait, reusing the constant rather than inventing a
second number. The two waits are separate `time.After(exitGrace)` calls, so a
pathological channel can spend two graces in teardown; that is deliberate, since
they bound two different promises (the target's last word, and the client's
outstanding answer) and sharing one deadline would let a silent target consume
the budget for the answer.

### The tests, and why they are shaped like that

`internal/proxy/teardown_test.go` tests `pump` directly, with a **real** client
half (a loopback SSH connection, because a lost answer is only observable as
what the client's own `SendRequest` returns) and a **hand-driven** target half
(`stalledTarget`). A real target answers as fast as its scheduler allows, which
is why the original flake was a race the test could only watch; `stalledTarget`
lets the test decide when the output drains and when the answer arrives, so the
ordering is *driven*.

Two notes for anyone extending it:

- `net.Pipe()` **does not work** for the SSH pair: the version exchange has both
  ends writing before either reads, and an unbuffered pipe deadlocks. Use a
  loopback socket.
- A `*channel.Inspection` may be `nil` and inspects nothing, and
  `&session{ctx: ctx, id: ...}` is enough session for `pump` — every capture
  point tolerates a nil recorder. That is what keeps the test at pump level
  instead of needing the whole harness.
- `roundTrip` is the barrier the regression test is ordered against: once a
  request has gone the whole way to the far end of the client's connection and
  back, the proxy has had a complete round trip in which to run the two
  statements of a teardown. Against the pre-fix ordering the new tests fail
  40/40; after the fix they pass 50/50, and `-race -count=5` is clean.

`exitGrace` became a `var` (same value) only so the bound test can shorten it to
200ms. Nothing outside a test writes it.

**Exit-status ordering needed no new test.** `TestExecExitStatusIsPreserved`
(`internal/proxy/proxy_test.go`) and `TestAProxiedSessionRunsACommand` drive
`ssh.Session.Run`/`Output`, which sends the exec, *fails unless it is answered
affirmatively*, then reads the output and waits for the exit status — the exact
order the criterion names. They were flaking on this defect too.

### The same shape elsewhere: checked, and no prompt queued

- **`serveGlobalRequests`** has the same *shape* — relay, wait for the far
  reply, answer the client — but not the same *defect*. The close that could
  pre-empt its reply is the client connection's, and `session.run` returns only
  once `s.chans` closes (the client itself ended the connection) or the session
  was deliberately killed. A request lost to a kill is correct behaviour: the
  session ended. So there is nothing to fix, and queuing a prompt for it would
  cost a future session a phase to reach the same conclusion.
- **The nexthop path** reaches `serveGlobalRequests` and `pump` and adds no
  relay of its own; it inherits this fix.
- **`internal/relay`** answers its own requests locally and never relays a
  reply across a teardown.
- One residual, deliberately out of scope: `pump`'s *target-opened* channel
  branch (`forwardRequests(nearReqs, far, nil)`) is ungated, so a request the
  **target** makes on a channel it opened could lose its reply to
  `near.Close()`. That answer goes to the target, not to the user, so PLAN
  §4.3's disclosure argument does not apply, and this phase was scoped to the
  client-facing close.

### Verification not runnable here

`golangci-lint` v2.13.2 (the version CI pins) reports 0 issues; the container's
preinstalled v2.12.x refuses the module outright, which `.github/workflows/
ci.yml` already documents. The **e2e topology** (`make e2e-up`) needs Docker,
which this session's container does not have — CI's `e2e topology` job is what
covers it.
