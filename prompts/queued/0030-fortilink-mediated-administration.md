# 0030 — FortiLink-mediated administration: a switch the proxy cannot reach

> **This prompt was rewritten in place by phase 0029, and the number did not
> move.** It used to be "Standalone FortiSwitchOS driver — a directly-managed
> switch, which is nearly the FortiGate driver under another platform name",
> deferred from 0014 and deliberately ordered *after* the FortiLink phase
> because it was the easier half.
>
> **Phase 0029 delivered that.** It set out to administer a FortiLink-managed
> switch *through* its managing FortiGate and found, in Fortinet's own
> documentation, that the premise was wrong: `config switch-controller
> security-policy local-access` configures a managed switch's own allowaccess
> list and `ssh` is in the default for both its interfaces. A managed switch
> keeps its own SSH administrative plane. So the switch became **its own
> endpoint**, FortiLink became a deployment fact rather than a target identity,
> and the driver 0030 was queued to write is the driver 0029 shipped —
> `fortios.SwitchDriver`, platform `fortiswitchos`, serving both management
> modes under one name. `docs/PLAN.md` §5.3 ("As decided (phase 0029)") carries
> the decision and the alternatives it rejected.
>
> What 0029's decision does **not** serve is the estate this prompt is now
> about. Nothing was renumbered and no number was retired: see the queue note
> at the end of `docs/PLAN.md` §10.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — **D1**, **D13**, **D14**, §4.2 (the `ephemeral-account`
  parameters and `ProvisionedAccess`), §5.3 in full — especially "As extended
  (phase 0016)" and "As decided (phase 0029)" — and §6.5.
- `docs/learnings/0029-fortilink-fortiswitch-driver-learnings.md` — the driver
  you are extending, the target-identity decision you are working *within*,
  and the two facts below that phase established and could not act on.
- `docs/FORTIOS-DOC-VERIFICATION.md`, the section "FortiSwitchOS and
  FortiLink" — every FortiLink fact this prompt cites, with its page.
- `docs/learnings/0014-…` and `0016-…` — the `Driver` seam as it is actually
  used, the CLI state machine, and the device-field namespace.
- `docs/CROSS-REPO-PROTOCOL.md` — **required if you change `api/`**, and §3.2
  in particular. This phase probably does touch a shared surface, so do not
  skip its §1 check.

## Objective

A session whose target is a FortiSwitch **the proxy has no route to** gets the
same short-lived administrator phase 0029 provides — provisioned, connected to,
and removed — by going through the switch's managing FortiGate.

This is the deployment 0029 deliberately did not serve: an estate that keeps
its FortiLink management subnet unroutable from the proxy, on purpose. For
every estate that *does* route to its switches, 0029 already works and this
phase must not become the path they take.

## What phase 0029 established, so you do not re-derive it

All of it is sourced in `docs/FORTIOS-DOC-VERIFICATION.md`.

- **Two documented ways into a managed switch's CLI from its FortiGate.**
  `execute switch-controller ssh <user> <switch>` reaches the switch's own CLI
  and needs **the switch's own credentials**. `config switch-controller
  custom-command` + `execute switch-controller custom-command <cmd-name>
  <target-switch>` needs no switch credential but requires a **persisted
  command object on the FortiGate** (`command` max 4095 chars, `command-name`
  max 35) and **returns nothing** — so it supports no enumerate for the reaper,
  no existence check, and no way to distinguish success from a silently
  unreachable switch. On the password credential kind it would also write
  credential material into a config object that `cfg-save automatic` commits to
  flash.
- **Every hop that leaves a Fortinet unit is password-only.** FortiOS's client
  is documented as a "Simple SSH client" whose only settings are
  `execute ssh-options interface|source`; FortiSwitchOS's takes a destination
  and nothing else. No identity file, no client key store, no port forwarding —
  so no key on the nested hop, and a switch-initiated reverse tunnel is not
  expressible either.
- **The FortiGate has no view of the switch's administrator table.**
  `config switch-controller managed-switch` has no administrator fields;
  `switch-profile`'s `login-passwd-override` overrides the built-in `admin`
  account's password only.
- **Deauthorization strands.** `set-standalone` and `factory-reset` both
  factory-reset the switch and therefore destroy an account this proxy created.
  Plain deauthorization does not touch the switch's configuration — and on a
  switch reachable only through its FortiGate, it removes the proxy's only
  route to an account it is responsible for.

## The three problems this phase owns

**1. Target identity, again — and 0029's answer constrains you.** 0029 decided
the switch is its own endpoint. Here the proxy cannot dial it, so something has
to name the FortiGate. 0016's rule still holds — the endpoint is the device the
proxy connects to, and a route field names something about it — which points at
the FortiGate as endpoint with a field naming the switch. But that is the shape
0029 rejected *on the audit argument*: `host:port` would name a unit the
administrator does not live on. Both readings cannot be right for the same
estate, so this is a decision to settle **with the user** and write into
`docs/PLAN.md` before writing code. Note also that whatever you choose has to
coexist with `fortiswitchos` rather than replace it: the same physical switch
may be directly reachable from one proxy and not from another.

**2. The session leg, which the proxy engine cannot currently express.** The
administrator lives on the switch; the proxy dials the FortiGate. There is no
account on the FortiGate for it to log in as — and logging the user in as the
proxy's privileged administrator is not an option, on a firewall least of all.
So this phase needs both:

- a **second ephemeral account on the managing FortiGate**, scoped as narrowly
  as the platform allows, with its own teardown and its own orphan class; and
- a seam for a **reach preamble**: `target.ProvisionedAccess` hands back an
  `*ssh.ClientConfig` and nothing else, so there is nowhere to say "dial, then
  drive `execute switch-controller ssh`, answer the password prompt, *then*
  hand the channel to the user". It has to run per channel, and 0009's
  inspection pipeline and 0010's command filtering both sit behind it — which
  is right (they should filter the inner CLI) and is the part to design
  carefully.

If the seam turns out to be the whole phase, split it: say so, ship the seam
with the FortiGate-side account, and queue the driver work. A smaller correct
PR is the point (`docs/PROTOCOL.md` §3).

**3. The reaper, which sweeps from an endpoint.** 0016 wrote that fields ride
on creation only and the reaper sweeps a device it reaches from an endpoint;
0029 left that intact because it introduced no device-selecting field. This
phase is where that breaks. `device.CreateRequest.Fields` will have to reach
`RemoveRequest`, `ListRequest` and `CredentialRequest`, and `target.deviceReaper`
will have to key `live`, `firstAt`, `firstResidueAt` and `seen` on more than
`host:port`.

**Do not partition that bookkeeping on all fields.** `device_field.vdom` does
*not* select a different device — a FortiGate's administrator table is one
global table whatever a VDOM-scoped account is scoped to — so a reaper that
swept once per field set would see one route's live account as another's orphan
and remove it after the grace period. The distinction has to be **declared**:
`device.Field` needs to say whether a field selects a subordinate device, and
only those fields may partition a sweep.

Also decide what a sweep does when the switch is **gone from the FortiGate's
managed list**. An enumerate that returns nothing there must be a sweep
**failure** on D8's priority path, never an empty result — the deauthorization
hazard above is exactly this case, and "no accounts found" would report a clean
device while a privileged administrator stays on it.

## In scope
- The target-identity decision, settled with the user and recorded in
  `docs/PLAN.md` with its reasoning.
- Any contract change it implies, upstream first, per
  `docs/CROSS-REPO-PROTOCOL.md` §3.2 — including the sync kickoff its §4 asks
  you to hand the user for each affected repository.
- The reach mechanism, and the credential the nested hop uses. Note that the
  proxy has one privileged device credential
  (`auth.target.ephemeral_account.admin_user` + `password_env`); whether the
  switch is expected to carry the same account is an operator prerequisite to
  decide and document, not to assume. A proxy configured with `key_path` only
  has **no local material** for a password-only hop, which makes such a route a
  **skipped rung** (D14, PLAN §4.2) rather than a failure.
- The driver work in `internal/auth/target/device/fortios`, reusing
  `SwitchDriver` and the `cliSession` helpers rather than forking them.
- Carrying fields onto the other three operations, and the reaper bookkeeping,
  on the terms above.
- The fake device in `internal/sshtest` extended to model a FortiGate with
  managed switches behind it — including the failures a real one has: the
  switch is unreachable, not yet joined, or no longer authorized.
- A scenario in `test/e2e`, per the topology obligation below.

## Out of scope
- Changing how a directly-reachable FortiSwitch is administered. 0029's
  `fortiswitchos` platform stays exactly as it is.
- Any enforcement rung (0018's vocabulary, 0019's application).
- The declarative driver document and the subprocess contract (D13).

## Acceptance criteria
- The target-identity decision is in `docs/PLAN.md` with its reasoning, said
  against 0029's, and the contract expresses it.
- Against the fake device: a session provisions on a switch through its
  FortiGate, **connects**, and tears down both accounts; a crash leaves
  accounts the reaper removes on both devices; a switch that is unreachable
  through its FortiGate is a retryable failure and never a silent success; and
  a sweep of a switch the FortiGate no longer manages is a reported failure
  rather than a clean result.
- A VDOM-scoped FortiGate route and a switch route on the same unit do not
  sweep each other's live accounts — the declared-field rule above, with a test
  that fails if the reaper partitions on every field.
- The audit record and the mapping event name **both** devices, because a
  reviewer asking "what did this session touch" must not have to know the
  FortiLink topology to answer it.
- `go build ./... && go vet ./... && go test ./...` and `golangci-lint run` pass.

## The e2e topology obligation
Extend the `device` node (`cmd/fake-device`) rather than adding another; it
already serves three units, including phase 0029's FortiSwitch on `:2223`. Add
the route to `deploy/control/fixtures.template.yaml` and a subtest to
`TestTopology` in `test/e2e/scenarios_test.go`. Two things that will bite are
recorded in 0014's learnings: `TestTopology`'s subtests are ordered
deliberately (new groups go before the outage scenario, and the ephemeral-leak
check runs last), and `sshBaseArgs` is shared by every scenario — pass
per-scenario options instead.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0030-fortilink-mediated-administration-learnings.md`. The
summary block MUST carry: the target-identity decision and how it sits beside
0029's, the reach mechanism and the credential it needs, the shape of the
`ProvisionedAccess` seam if you built one, and what the reaper now remembers
per endpoint.
