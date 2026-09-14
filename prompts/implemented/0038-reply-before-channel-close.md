# 0038 — A channel request is answered before its channel closes

> **This is a real proxy bug, found as a test flake.** Two tests in
> `internal/proxy` fail intermittently — roughly **1 run in 70** each — with
> `exec request: EOF`. The flake is the symptom; the defect is that the proxy
> can close a client channel while a request the client is still waiting on has
> been answered by the target but not yet relayed back. Do not "fix the tests".

## Read first
- `docs/PROTOCOL.md` — session workflow. **§3**'s rename rule barely applies
  here (this phase renames little), but its **index-refresh table** does if you
  touch a decision's rendering.
- `docs/PLAN.md` — **§4.3** (the disclosure rule: what the user is told, and
  that a failure must never look like a crash), **§6.2** (channels,
  `internal/channel`), **§6.3** (command filtering, for how a denied request is
  answered), and decisions **D5** (the channel allow-list) and **D5a** (the
  three policy axes — this phase is entirely inside axis 2's delivery path).
  You do not need §5, §9, or §11.
- `docs/learnings/` summaries: **0005** (the proxy engine and the original
  channel pump), **0009** (the in-channel request axis, which added
  `policeRequest` and `forwardClientRequests`) and **0031** (the session bounds,
  which added the deadline teardown that shares this close path).
- `internal/proxy/channel.go` — **as it stands on `main` when you start**. In
  particular `pump`, `forwardClientRequests`, `forwardRequest`, and the
  `exitGrace` constant.

## The defect, with the evidence

`pump` (`internal/proxy/channel.go`) moves bytes and requests between the client
channel (`near`) and the target channel (`far`), then tears both down. Teardown
is gated on the **output** being drained:

```go
<-drained                       // both far → near io.Copy goroutines returned
select {
case <-reqsDone:                // the far-side request forwarder finished
case <-time.After(exitGrace):
case <-s.ctx.Done():
}
... replay the captured exit status ...
_ = near.Close()
_ = far.Close()
all.Wait()                      // <- the near-side request forwarder is only waited on HERE
```

`all.Wait()` is what would wait for `forwardClientRequests`, and it runs **after**
`near.Close()`. So a client request that is mid-relay when the output drains has
its channel closed out from under it. `forwardRequest` sends to the target,
waits for the target's reply, and only then answers the client:

```go
ok, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
...
if req.WantReply {
    _ = req.Reply(ok, nil)      // <- can land after near.Close()
}
```

Instrumenting those three points and running the test in a loop until it fails
produces this, from a single failing run:

```
TRACE forwardRequest send exec
TRACE target req exec
TRACE target handleSession-exit
TRACE forwardRequest got-reply exec ok=true err=<nil>   <- the target said YES
TRACE pump-close drained                                 <- pump closed near and far
TRACE forwardRequest replied-to-client exec err=EOF      <- the reply was lost
--- FAIL: TestCIMayRunCommandsButNeverGetsATerminal
    policy_test.go:125: exec request: EOF
```

The ordering is the whole bug: the target **accepted** the exec, and the client
was told nothing rather than told yes.

### Why it is not just a test artifact

The window opens whenever a command finishes faster than the proxy can relay the
reply for the request that started it — a `true`, an `uptime`, a failed
one-liner, any `exec` on a fast target. The client sees the channel close
instead of an answer to a request it is blocked on. OpenSSH tolerates this
(it treats a closed channel as the command having run), which is why it has
never been reported from a real session, but:

- a client that distinguishes "exec refused" from "exec accepted, then the
  channel ended" sees the wrong one, and a **refusal is what the proxy says when
  policy denies the command** (§6.3). Losing the affirmative reply makes a
  permitted command indistinguishable from a denied one on the wire, which is
  precisely the confusion §4.3 exists to prevent;
- the proxy already holds exactly this ordering guarantee for the exit status —
  `pump`'s own comment says it is "captured rather than forwarded as it arrives,
  and replayed once the target's output has been drained, so a client cannot see
  'the command finished' before the output the command produced." The request
  reply simply never got the same treatment.

So this is the existing invariant applied to the one message that was missed:
**nothing the client is waiting on may be lost to teardown.**

### Reproducing it

```
go test ./internal/proxy/ -run 'TestCIMayRunCommandsButNeverGetsATerminal|TestAPTYRequestRecordsTheReplayHeader' -count=200
```

Roughly 6 failures per 400 runs on an idle 4-core container. Both tests fail the
same way and for the same reason — each sends `pty-req` then `exec` on one
channel, and the target exits the moment the exec completes. Reproduce **before**
you change anything, so you can show the same command clean afterwards.

## Objective

Make the proxy answer an outstanding client channel request before it closes
that channel, and prove it with a test that fails reliably against today's code.

## In scope

### 1. `internal/proxy/channel.go`

- **`pump`'s teardown.** `near.Close()` must not run while a client request is
  in flight. The shape of the fix is yours, but it must hold under the
  constraints below. Two approaches that fit the file's existing idiom:
  - give the near-side request forwarder its own completion signal (a `done`
    channel closed when the in-flight request settles, in the same style as
    `drained` and `reqsDone`) and wait on it — **bounded by `exitGrace`**,
    beside the existing `reqsDone` wait — before the closes; or
  - have `forwardRequest` answer the client under a lock or sequencing
    primitive that teardown also takes, so the close cannot interleave.

  What it must **not** do: wait unbounded. A target that never answers a
  request must not hold the channel open forever — that is what `exitGrace`
  exists for, and it is why "just move `all.Wait()` above the closes" is the
  wrong fix: `forwardClientRequests` ranges over `nearReqs`, which does not
  close until the channel does, so waiting for it before closing deadlocks.
  Say in your learnings that you considered and rejected that, because it is
  the first thing the next reader will suggest.
- **`forwardRequest`** may need to report whether it answered the client, or to
  take the sequencing primitive. Keep its two existing behaviours exactly: a
  transport error answers the client `false`, and a target reply is relayed
  verbatim.
- Leave `policeRequest` alone. A denied request is already answered before the
  channel is closed, deliberately and in the right order — see its comment about
  `decision.CommandFailure`.

### 2. What must not change

- The exit-status ordering already in `pump`: captured, replayed after output
  drains, so "the command finished" never precedes the command's output.
- `exitGrace` as the bound on every teardown wait. If you need a second bounded
  wait, reuse it rather than introducing a second constant with a different
  number and no reason for the difference.
- The denial path's ordering (`policeRequest` → reply → stderr text → exit
  status → close) — that sequence is §4.3's disclosure rule rendered, and phase
  0009 argued it.
- The `far` side. Only the client-facing close is racy; `far.Close()` after
  `near.Close()` is fine.

## Out of scope

- The channel-setup loop above `pump` (the `queued` / `replay` path). It answers
  its requests synchronously and is not implicated — the failing trace shows the
  loss happening inside `pump`.
- Making the fake target in `internal/sshtest` slower, sleeping in a test, or
  retrying an assertion. Any of those hides the defect rather than fixing it,
  and the flake would come back on a faster machine.
- `t.Skip`, `-count` tuning, or quarantining either test. `docs/PROTOCOL.md`
  and every review rule this repository has forbid it, and the tests are
  correct: they assert exactly what the contract promises.
- Global requests (`serveGlobalRequests`) and the nexthop path. If you find the
  same shape there, **note it in your learnings and queue a prompt** — do not
  widen this one.
- The deadline and revocation teardowns (`s.kill`). They close every channel on
  purpose and a client request lost to a kill is correct behaviour: the session
  ended.

## Acceptance criteria

- [ ] `go build ./...`, `go vet ./...`, `go test ./...`, `golangci-lint run` all
      pass.
- [ ] `go test ./internal/proxy/ -run 'TestCIMayRunCommandsButNeverGetsATerminal|TestAPTYRequestRecordsTheReplayHeader' -count=400`
      passes with **zero** failures. Put the command and its output in the PR.
- [ ] `go test -race ./internal/proxy/ -count=5` passes.
- [ ] A new test fails against unmodified `main` and passes after the fix — see
      "Required tests". Show both in the PR: the failure on a stashed working
      tree, and the pass after.
- [ ] A client `exec` on a target that exits immediately receives `ok == true`,
      the command's output, and the exit status — in that order, every time.
- [ ] A target that never answers a relayed request still closes within
      `exitGrace`; the fix introduces no unbounded wait. Prove it with a test.
- [ ] No test was skipped, weakened, retried, or made slower to pass.
- [ ] The e2e topology (`deploy/`) comes up and its scenarios pass.

## Required tests

Put them in `internal/proxy`, beside the tests that were flaking.

- **The regression, made deterministic.** Today's flake depends on losing a
  race ~1.5% of the time, which is not a test. Drive the ordering instead: a
  target whose exec handler replies and then immediately closes the channel,
  with the assertion that the client's `SendRequest` returns `(true, nil)` and
  never `EOF`. `internal/sshtest`'s target already exits immediately after
  `exec`; if you need a sharper ordering, add an option to that harness rather
  than a sleep. The test must **fail on unmodified `main`** — verify that, and
  say so in the PR; a regression test that passes before the fix is testing
  nothing.
- **The bound.** A target that accepts a request and never replies: the channel
  closes within `exitGrace` and the client is answered (`false`) rather than
  left hanging. This is what stops the fix from becoming a deadlock.
- **The exit-status ordering is unchanged**: output, then exit status, then
  close. The existing tests may already cover this — if so, say which, and add
  nothing.
- Keep `-race` clean: the fix adds cross-goroutine coordination, which is
  exactly where a sloppy one shows up.

## Deliverables

1. The fix in `internal/proxy/channel.go`, with the tests above.
2. `prompts/queued/0038-reply-before-channel-close.md` moved to
   `prompts/implemented/` (same filename) in this PR.
3. `docs/learnings/0038-reply-before-channel-close-learnings.md` with the
   summary block `docs/PROTOCOL.md` §5 requires. It must record: **which
   ordering primitive you chose and why**, that moving `all.Wait()` above the
   closes deadlocks and why, and whether `serveGlobalRequests` or the nexthop
   path has the same shape (with a queued prompt if it does).
4. `docs/PLAN.md` updated **only if** the fix changes something the plan
   describes. A teardown ordering detail inside `internal/proxy` probably is not
   — if so, say in the PR that you checked and found nothing to change.
5. A PR whose description states the prompt implemented, the before/after of the
   `-count=400` run, the new test failing on `main` and passing after, and the
   Definition of Done checklist.
