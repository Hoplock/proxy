# 0028 — FortiOS: make `target-enforced` expiry real

> Phase **0014** declared `Capabilities.EnforcesExpiry: false` for FortiOS on the
> grounds that "there is no `set expiry`, and `config system admin` has no
> schedule". `docs/FORTIOS-DOC-VERIFICATION.md` found the second half flatly
> wrong. Phase **0015** kept the declaration false — deliberately, with the user
> — because taking the mechanism means creating and tearing down a **second
> object per session** on a customer's firewall, with its own name, its own
> teardown, and its own orphan class for the reaper. That is a phase, and this is
> it.
>
> Nothing here is a correction. The facts are settled and sourced; what is open
> is whether the mechanism is worth its cost, and if so how the second object is
> made as safe as the first.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — **D13** (including the phase 0015 amendment about what a
  `Capabilities` declaration means), **D14**, §4.2 on `expiry_posture`, §5.3 in
  full — the naming scheme under a constrained limit applies to the schedule
  object too, and "As corrected (phase 0015)" is where this deferral is recorded.
- `docs/FORTIOS-DOC-VERIFICATION.md` — **claim 2**, which carries the fields, the
  KB showing the denial, and the precise statement of what the mechanism does and
  does not give you.
- `docs/learnings/0015-fortios-driver-corrections-learnings.md` — in full; its
  hardware list item 3 is this phase's central unknown.
- `docs/learnings/0014-…` — the driver's shape, the reaper's changed role, and
  the ladder walk.

## What is already established

- `config system admin` has `set schedule {string}` — "Firewall schedule used to
  restrict when the administrator can log in. No schedule means no restrictions",
  maximum length **35**.
- The schedule it names can be a one-time schedule with an absolute end:
  `config firewall schedule onetime` / `set start {hh:mm yyyy/mm/dd}` /
  `set end {hh:mm yyyy/mm/dd}`.
- FortiOS enforces it **at authentication**. Fortinet's KB shows the denial
  logged as `reason="out_of_schedule"`.
- It **denies login; it does not delete the account.** The reaper is still
  required for removal and `PersistsAcrossReload` is unaffected.
- `password-expire` is a forced password change, **not** an account expiry. Do
  not use it as one, and do not describe it as one.
- The naming-rules KB gives 32 characters for "schedule names" where the CLI
  reference gives 35 for `system admin`'s `schedule` field. Take the smaller
  unless you can establish otherwise; the difference is one character of token.

## The design questions this phase owns

Settle these **with the user before writing code**, and record them in
`docs/PLAN.md`.

1. **Does denying login meet the bar for `EnforcesExpiry`?** The field means the
   DEVICE ends the account's usefulness whether or not the proxy is alive. Note
   the closest analogue in this system: OpenSSH's `expiry-time` in
   `authorized_keys` (PLAN §5.1) also refuses new authentications and also does
   not disturb an established session — so the semantics may already be the ones
   the contract is written around. Decide explicitly rather than by analogy
   alone, because of the next question.
2. **What happens to an already-established session when the window closes?**
   Fortinet documents nothing either way. If a target-enforced posture is meant
   to cut a live session and this does not, that is a gap the audit record must
   not paper over. It needs hardware (below); until then the honest options are
   to declare what is verified or to make the claim conditional in the
   provisioning record.
3. **How is the schedule object named, torn down, and swept?** It needs the same
   three properties the account name has (PLAN §5.3): a reaper prefix so one
   proxy never deletes another's, a uniqueness token, and a length that fits.
   Teardown must remove **both** objects, and the reaper must find an orphaned
   schedule whose account is already gone — which is a sweep over a table the
   device reaper has never read.
4. **What does a route get when the schedule object cannot be created?** D13's
   rule says an attempt that fails fails the session rather than degrading. A
   route asking for `target-enforced` that silently became proxy-enforced is the
   audit record saying the device holds a deadline nothing holds.

## In scope

- The decisions above, recorded in `docs/PLAN.md`.
- `internal/auth/target/device/fortios`: the schedule object's create and delete
  sequences, `set schedule` on the administrator, value validation for the
  datetime and the object name (the far end is a configuration parser — see
  `value.go`'s opening comment), and `Capabilities.EnforcesExpiry`.
- `internal/auth/target`: whatever the reaper needs to sweep an orphaned
  schedule, and whatever the provisioning record needs to state the posture
  honestly.
- `internal/sshtest/fortios.go`: model `config firewall schedule onetime` — the
  object, its fields, and the failure a `set schedule` naming an absent one
  draws. A test must assert that teardown removes **both** objects and that the
  reaper sweeps an orphaned schedule.
- The lifetime the driver currently accepts and discards
  (`CreateAccount`'s `_ = req.Lifetime`).

## Out of scope

- Multi-VDOM — **0027**. If it has merged, the schedule object lives in a scope
  and you must say which; if it has not, single-VDOM units are the whole surface.
- Ending the **session** at its deadline, which is phase 0023's. This phase ends
  the account's usefulness on the device; the two were deliberately not
  conflated in 0014 and should not be here either.
- `password-expire`.

## What needs hardware

1. **Whether an established session survives its administrator's schedule window
   closing.** This is question 2 and it cannot be answered by documentation or by
   a fake device. Do not model an answer in `internal/sshtest`; leave the comment
   naming the open question, as phase 0015 did elsewhere in that file.
2. Whether a schedule object can be deleted while an administrator still
   references it, or whether teardown has to unset `set schedule` first — the
   `object is in use` failure `cli.go` already matches suggests it may not.

## Acceptance criteria

- `EnforcesExpiry` is whatever the decision says, and the reasoning is in
  `docs/PLAN.md` and in the driver's own comment — not one without the other.
- If it becomes true: a route asking for `control.ExpiryPostureTargetEnforced` on
  FortiOS is served rather than skipped; teardown removes both objects; the
  reaper sweeps an orphaned schedule; and a test fails if either is left behind.
- If it stays false: the reasoning has changed from 0015's, and this prompt says
  what changed.
- `go build ./... && go vet ./... && go test ./...` and `golangci-lint run` pass.

## Definition of Done & hand-off

Per `docs/PROTOCOL.md`. Move this prompt to `implemented/`; add
`docs/learnings/0028-fortios-target-enforced-expiry-learnings.md`. The summary
block MUST carry: the decisions and their reasoning; the corrected
`Capabilities` and what each value now rests on; what teardown and the reaper now
remove; and the hardware list.
