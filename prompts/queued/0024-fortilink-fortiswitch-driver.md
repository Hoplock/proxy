# 0024 — FortiLink FortiSwitch: a target administered through another device

> Deferred from phase 0014. That prompt asked its session to settle the
> FortiSwitch management-mode fork before designing a switch driver, and the
> answer was "both modes exist in the estate, and **FortiLink is the priority**".
> A FortiLink-managed switch has no independent administrative plane the proxy
> can SSH into: it is administered *through* its managing FortiGate. That is not
> a driver detail — it is a different **target identity**, and therefore a
> contract question before it is a Go question. It is why this is its own phase
> rather than a second `Register` call in 0014.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — **D1** (target identity is encoded in the SSH username, and
  why), **D13**/**D14**, §4.2 (the `ephemeral-account` parameters), §5.3 in
  full, §13 UC1.
- `docs/learnings/0014-…` — the `Driver` seam as it is actually used, the
  verified FortiOS facts (they hold for the managing FortiGate here), the
  prompt/response state machine, and the naming generalisation.
- `docs/learnings/0013-…` — the contract shapes and the registry's failure
  modes.
- `docs/CROSS-REPO-PROTOCOL.md` — **required if you change `api/`**, and §3.2 in
  particular. Section 1 tells you to stop reading if you touch no shared
  surface; this prompt probably does touch one, so do not skip that check.

## Objective
A session whose target is a FortiLink-managed FortiSwitch gets a short-lived
administrator that exists only for its duration, is attributable to the user who
opened it, and is removed afterwards — even though the switch itself never
accepts the proxy's connection.

## The design question this phase owns

The proxy connects to the **FortiGate**, and the switch is a *parameter* of that
connection. Everything downstream follows from how that is expressed, and there
is more than one defensible answer:

- the route's `target` is the FortiGate and a new parameter names the switch;
- the route's `target` is the switch and a new parameter names the FortiGate
  that manages it;
- the platform value encodes the relationship (`fortiswitch-via-fortigate`) and
  a parameter carries the peer.

**Decide this first, with the user, and write the reasoning into `docs/PLAN.md`
before writing code.** The question is not stylistic. It decides what the audit
record says the target was, what a policy author writes in Hoplock Control, what
the revocation stream keys on, and whether a customer who moves a switch between
FortiGates has to rewrite policy. Note also that `execute switch-controller`
sessions on a FortiGate reach the switch's own CLI, which is a *third* shape:
one SSH connection, two devices, and a mode change in between.

Whatever you choose, two rules from D13 hold unchanged: the platform is
**named** by the route and never inferred, and an unregistered platform is an
outage-class denial rather than the nearest driver.

## Before writing code: verify, do not remember

Phase 0014's prompt required FortiOS behaviour to be established from Fortinet's
current documentation rather than from memory, and that discipline found a fact
that contradicted `docs/PLAN.md`. Do the same here. At minimum: how an
administrator is created on a FortiLink-managed switch (or whether one can be at
all); whether `execute switch-controller` reaches a switch CLI that accepts
`config system admin`; what a managed switch's administrator table looks like to
the FortiGate; whether removing the switch from FortiLink management strands an
account this proxy created; and the administrator-name limit on FortiSwitchOS,
which is what selects the naming scheme (PLAN §5.3). Record what you found, with
the doc reference, in your learnings.

If verification shows a FortiLink-managed switch **cannot** carry a short-lived
administrator at all, that is a finding and not a failure: say so plainly, and
the phase becomes the contract work plus a route that falls through to
`brokered-key` on D14's ladder.

## In scope
- The management-mode question above, settled and recorded in `docs/PLAN.md`.
- Any contract change it implies, upstream first, per
  `docs/CROSS-REPO-PROTOCOL.md` §3.2 — including the sync kickoff its §4 asks
  you to hand the user for each affected repository.
- The driver itself in `internal/auth/target/device/fortios`, reusing 0014's CLI
  state machine and value validation rather than forking them.
- The fake device in `internal/sshtest` extended to model a FortiGate with
  managed switches behind it, including the failure a real one has: the switch
  is unreachable or not yet joined.
- A scenario in `test/e2e`, per the topology obligation below.

## Out of scope
- The standalone (directly-managed) FortiSwitch driver: that is **0025**, and it
  is nearly the FortiGate driver under another platform name.
- Any enforcement rung. Which access profile a route gets is 0015's vocabulary
  and 0016's application.
- The declarative driver document and the subprocess contract (D13).

## Acceptance criteria
- The target-identity decision is in `docs/PLAN.md` with its reasoning, and the
  contract expresses it.
- Against the fake device: a session provisions on the switch through its
  FortiGate, connects, and tears down; a crash leaves an account the reaper
  removes; a switch that is unreachable through its FortiGate is a retryable
  failure and never a silent success.
- The audit record and the mapping event name **both** devices, because a
  reviewer asking "what did this session touch" must not have to know the
  FortiLink topology to answer it.
- `go build ./... && go vet ./... && go test ./...` and `golangci-lint run` pass.

## The e2e topology obligation
Phase 0012 built the topology in `deploy/` and phase 0014 added the `device`
node (`cmd/fake-device`) to it. Extend that node rather than adding another, add
the route to `deploy/control/fixtures.template.yaml`, and add a subtest to
`TestTopology` in `test/e2e/scenarios_test.go`. Two things that will bite are
recorded in 0014's learnings: `TestTopology`'s subtests are ordered
deliberately (new groups go before the outage scenario, and the ephemeral-leak
check runs last), and `sshBaseArgs` is shared by every scenario — pass
per-scenario options instead.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0024-fortilink-fortiswitch-driver-learnings.md`. The summary
block MUST carry: the target-identity decision and why, the verified FortiLink
facts and their sources, the declared `Capabilities` for the switch platform,
and whether 0025 can reuse any of this.
