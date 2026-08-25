# 0020 — Two e2e coverage holes: password+MFA, and concurrent provisioning

> New prompt, added after 0012. It closes the only two gaps in that phase's
> "known gaps" list that are **not** deliberate prototype deferrals: everything
> else on that list is `docs/PLAN.md` §12 out-of-scope (host-key pinning policy,
> geo/anycast, AD/Okta/OIDC, tamper-evident storage) or already queued as 0019.
>
> Appended rather than inserted. It depends on nothing 0013–0019 change, and
> nothing they do depends on it — but it is small, and it is the cheapest
> remaining increase in confidence in the prototype, so it is a reasonable one
> to pull forward if the queue stalls.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — §4.1 and **§4.3** (the MFA flow and what the user is told),
  §5.1 (the ephemeral principal and why it carries a token), §9 (the topology).
- `docs/learnings/` summaries: **0012** (the topology, the harness, and the
  ordering rule for `TestTopology`), **0004** (the `password-mfa` flow, the
  keyboard-interactive prompter, and the fixture shape it needs), **0007**
  (`ephemeral-user` provisioning, teardown, and the orphan reaper).

## Objective

Add end-to-end coverage for the two things 0012 could not reach:

1. **password + out-of-band MFA**, which has never run against a real SSH
   client — the topology's proxies are certificate-only;
2. **two concurrent sessions provisioning on one target**, which is the exact
   situation the ephemeral principal's uniqueness token exists for and which no
   test in the tree exercises.

Change no production behaviour. If either scenario finds a defect, that is a
finding: fix it if it is small and obviously correct, otherwise write it up and
queue a prompt (`docs/PROTOCOL.md` §6) rather than growing this one.

## Why these two and not the rest of that list

Every other gap 0012 recorded is deferred **by the plan**, not by oversight:
host-key pinning policy has no policy to enforce yet (D7 is TOFU-with-report),
geo/anycast needs real infrastructure, AD/Okta/OIDC is Control's federation
problem and the proxy never talks to an IdP, and tamper-evident storage belongs
to Control's audit store. These two are different: the code exists, it is
reachable from the topology, and nothing but effort is stopping it being tested.

## In scope

### 1. password + MFA, end to end

**Topology.** Enable `password-mfa` alongside `cert` on **one** proxy — likely
`proxy-direct`, `deploy/proxy/proxy-direct.yaml`, `auth.user.methods`.

> **Do not change `sshBaseArgs` in `test/e2e/harness_test.go`.** It pins
> `PreferredAuthentications=publickey` and `BatchMode=yes`, which is what keeps
> every existing scenario on the certificate path when a second method appears.
> The MFA scenarios pass their own client options instead. A change there is a
> change to every scenario in the suite at once.

**Fixtures.** Add two users to `deploy/control/fixtures.template.yaml`, and give
them routes. `cmd/mock-control/fixtures.example.yaml` has both shapes already —
`alice` (approve after a pending poll) and `mallory` (always deny) — copy them
rather than inventing a shape. The approving user needs `pending_polls` ≥ 1, or
the "still waiting" path is never exercised.

**Driving keyboard-interactive from OpenSSH is the hard part.** MFA rides
keyboard-interactive precisely because it is the only flow with an
`instruction` field (PLAN §4.3), and that flow wants a terminal.
`SSH_ASKPASS` with `SSH_ASKPASS_REQUIRE=force` (OpenSSH ≥ 8.4) is the most
likely mechanism — a tiny script in the `user` image that echoes the fixture
password, plus `-o PreferredAuthentications=keyboard-interactive` and
`-o BatchMode=no`.

**Establish this before building on it; do not assume it.** Check it by hand
against the running topology first (`make e2e-up`, then one `docker compose exec
user ssh …`). If `SSH_ASKPASS` does not carry keyboard-interactive prompts on
the image's OpenSSH, find the mechanism that does and **write down in the
learnings which one worked and which did not** — the next person will otherwise
repeat the search. Do not silently drop the scenario.

**Scenarios.**
- Approval: the fixture's `prompt` text reaches the user, the session succeeds,
  and the command's output arrives.
- The wait is explained: with `pending_polls` ≥ 1 the user sees the proxy's
  progress line at least once. This is the whole reason the flow is
  keyboard-interactive rather than plain password auth — assert it, or the
  design rationale is untested.
- Denial: the MFA-denying user gets exactly the generic denial, and **nothing
  that says which factor failed**. A message distinguishing "wrong password"
  from "MFA denied" is an oracle; assert its absence explicitly, the way the
  existing `denial disclosure` scenario asserts against leaking the target.
- The audit trail records the authentication with the `password-mfa` method.

### 2. concurrent ephemeral provisioning

**Scenarios**, on the existing `ephemeral-user` route:

- Two sessions for the **same login and target**, overlapping in time, both
  succeed, and each reports a **different** `hl-<tag>-<login>-<token>` account.
- **Prove the overlap is real.** While both are live, the target's own account
  database shows *both* accounts at once. Without this the scenarios could have
  run one after the other and proven nothing — a slower copy of a test that
  already exists.
- After both end: no `hl-` account and no `hl-` home directory remains. Neither
  teardown removed the other's account, and neither leaked.
- The same for `brokered-key`: two overlapping sessions share one standing
  account, both succeed, and the target is byte-identical afterwards.

`sshE` in `test/e2e/harness_test.go` is the entry point — it takes no
`*testing.T` precisely so it can run on another goroutine (0012 added it for the
outage scenario). `t.Fatalf` off the test goroutine is illegal; collect results
and assert on the test goroutine.

The topology's reaper runs on `interval: 1m` with `grace: 5m`
(`deploy/proxy/*.yaml`), so it will not remove a live account underneath these
scenarios. If you change either value, say why in the learnings — the grace
period is what protects a session the proxy does not know about yet (PLAN §5.1).

### 3. Placement in the suite

`TestTopology`'s subtests are **ordered on purpose**
(`test/e2e/scenarios_test.go`): the telemetry assertions read what earlier
scenarios produced, the outage scenario stops Hoplock Control, and the
ephemeral-leak check runs last so it sees everything. Put both new groups
**before** the outage scenario. Say in a comment why they are where they are, so
the next person does not "tidy" them into alphabetical order.

## Out of scope

- Load, soak, or throughput. Two concurrent sessions is a correctness assertion
  about the uniqueness token; **0017** owns measurement, deliberately outside
  this topology.
- Any real identity provider. The proxy authenticates against Hoplock Control,
  which is the component that federates (PLAN §12) — the mock is the whole of
  the IdP surface this repository ever sees.
- Changing the MFA flow, the prompter, or the principal-naming scheme. This
  phase tests them.
- `api/control.yaml`. Nothing here needs a contract change; if you think it
  does, stop and ask (`docs/PROTOCOL.md` §9).

## Acceptance criteria

- A password+MFA session succeeds against a real OpenSSH client, the user is
  shown the challenge prompt and at least one progress line, and the run is
  attributed to `password-mfa` in the audit trail.
- An MFA denial is the generic denial and discloses no factor.
- Every pre-existing scenario still runs on the certificate path, unchanged:
  `sshBaseArgs` is untouched.
- Two overlapping ephemeral sessions get distinct accounts, are **demonstrated**
  to overlap, and leave nothing behind.
- Two overlapping brokered sessions succeed and leave the target unmodified.
- `make e2e` passes locally and the `e2e topology` job passes in CI;
  `go build ./...`, `go vet ./...`, `go test ./...` and `golangci-lint run` pass.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0020-e2e-coverage-mfa-and-concurrency-learnings.md`. The summary
block MUST record: **which client mechanism actually drove keyboard-interactive
and which were tried and failed**; the fixture shape for an approving and a
denying MFA user; how overlap was demonstrated rather than assumed; and any
defect the concurrency scenarios exposed, including ones you fixed in passing.
