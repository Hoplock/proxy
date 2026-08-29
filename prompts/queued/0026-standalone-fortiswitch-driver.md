# 0026 — Standalone FortiSwitchOS driver

> Deferred from phase 0014, and deliberately ordered **after** 0025. The estate
> has both management modes and the user ranked FortiLink first; this is the
> easier half and it should not jump the queue ahead of the one with a design
> question in it.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — **D13**, **D14**, §5.3.
- `docs/learnings/0014-…` — the FortiGate driver, its CLI state machine, its
  value validation, the verified FortiOS facts, and the `Options.Platform`
  field that exists precisely so this driver can be the same type under another
  name.
- `docs/learnings/0025-…` — whether the FortiLink phase left anything reusable
  here, and what it learned about FortiSwitchOS.

## Objective
A session to a **directly-managed** FortiSwitch — one that accepts SSH with its
own administrator accounts — gets the same short-lived administrator the
FortiGate driver provides.

## Before writing code: verify, do not remember
FortiSwitchOS is close to FortiOS and is not identical, and "close" is what
makes this worth checking rather than assuming. At minimum: the
administrator-name limit (it selects the naming scheme, PLAN §5.3, and it is the
single most consequential number in the driver); whether `config system admin`
takes the same fields, `accprofile` and `trusthost` included; whether an
administrator can carry an SSH public key; whether the platform can expire an
account (FortiOS **can** — `set schedule` against a `config firewall schedule
onetime` entry — and the FortiGate driver still declares `EnforcesExpiry: false`
by decision rather than by absence, which phase 0015 recorded in `docs/PLAN.md`
§5.3 and deferred to **0028**; inherit neither the fact nor the declaration,
establish both); and whether configuration is written to
non-volatile storage the same way, which decides `PersistsAcrossReload` and its
required `PersistenceReason`. Record each with its doc reference in your
learnings.

## In scope
- The driver in `internal/auth/target/device/fortios`, under its own platform
  name, **reusing** the existing CLI state machine, value validation and command
  tables. If it turns out to be the FortiGate driver with different declarations,
  say so and ship it as that — a second copy of a prompt/response state machine
  is a second thing to fix when a device surprises us.
  Two pieces of that inheritance are FortiGate-specific and must be
  re-established rather than reused: the driver reads `get system status` and
  refuses any unit whose "Virtual domain configuration" is not `disable`
  (phase 0015 — a FortiSwitch reporting no such line at all would be refused
  by it), and it requires an access profile because no FortiOS built-in is a
  safe default.
- Registration into `device.Shipped()` and into `newDriverRegistry`, and the
  platform name in `config.example.yaml`.
- Fake-device coverage for whatever differs, and a scenario in `test/e2e`.

## Out of scope
- The FortiLink case (0025).
- Any enforcement rung (0016/0017), and the declarative driver document (D13).

## Acceptance criteria
- The declared `Capabilities` match what verification found, with the doc
  reference in the learnings — in particular the name limit, since a value
  below 32 puts this platform on the constrained naming scheme, which nothing
  shipped uses yet.
- Against the fake device: provision, connect, tear down, reap, and a collision
  that retries rather than adopting.
- A ladder naming this platform on a proxy without the driver still falls
  through (D14).
- `go build ./... && go vet ./... && go test ./...` and `golangci-lint run` pass.

## The e2e topology obligation
As 0025: extend the `device` node, add the route to
`deploy/control/fixtures.template.yaml`, add a subtest to `TestTopology` before
the outage scenario, and do not change `sshBaseArgs`.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0026-standalone-fortiswitch-driver-learnings.md`, whose summary
block carries the verified FortiSwitchOS facts and the declared `Capabilities`.
