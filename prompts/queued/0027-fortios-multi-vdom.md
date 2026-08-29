# 0027 — FortiOS: administer a unit running virtual domains

> Phase **0015** found that the FortiGate driver's command sequences are written
> for a single-VDOM unit and are wrong on any other, and it closed the hole the
> only way a correction phase honestly could: the driver reads `get system
> status` when it opens a session and **refuses** anything but `Virtual domain
> configuration: disable`. That is a clear failure instead of a silent mismatch,
> and it is still a refusal. On the estate `docs/PLAN.md` §13 UC1 describes — a
> telco running ~300,000 FortiGates and FortiSwitches — a multi-VDOM unit is
> likely the common case rather than the exception, so the refusal is a large
> hole in the product's reach.
>
> This phase serves those units. It is a contract question before it is a driver
> change, and that question is shared with **0025**, so read the ordering note
> below before writing anything.

## Read first
- `docs/PROTOCOL.md` — session workflow, and §6 on prompt numbering.
- `docs/PLAN.md` — **D13**, **D14**'s ladder, §4.2's `ephemeral-account`
  parameters, §5.3 in full (particularly "As corrected (phase 0015)", which is
  where the refusal and its reasoning are recorded), §13 UC1.
- `docs/learnings/0015-fortios-driver-corrections-learnings.md` — in full,
  including the hardware list: **item 2 is this phase's central unknown.**
- `docs/FORTIOS-DOC-VERIFICATION.md` — its closing section, "Beyond the ten
  claims — multi-VDOM", carries the documented sequence and the three
  consequences, with the Fortinet pages they came from.
- `docs/learnings/0013-…` and `0014-…` summaries — the contract shapes, the
  registry's failure modes, and the CLI state machine you will be extending.
- `docs/CROSS-REPO-PROTOCOL.md` — **required**: if a VDOM name becomes a
  contract parameter, `api/` changes and §3.2 and §4 both apply.

## The ordering question, settled first

**0025** (the FortiLink FortiSwitch driver) owns the same question in another
shape: what a *target* is when a switch is administered through its managing
FortiGate. Here it is: what a target is when one FortiGate holds many virtual
domains. Whichever of the two phases runs first **answers it for both**, and the
second follows that answer rather than inventing a parallel one.

If 0025 has already merged, read its learnings before deciding anything below;
its answer is binding on you. If it has not, yours is binding on it, and your
learnings must say so in the summary block.

## Objective

A FortiGate running virtual domains is administered correctly, or is refused for
a reason that is still true after this phase. `fortios.ErrMultiVDOM` either stops
being reachable for the shapes this phase supports, or names precisely the
narrower shape that remains unsupported.

## What is already established

`docs/FORTIOS-DOC-VERIFICATION.md` carries the sources; do not re-derive these.

- The Administration Guide's CLI recipe for a per-VDOM administrator is:

  ```
  config global
      config system admin
          edit <name>
              set vdom <VDOM_name>
              set accprofile <admin_profile>
              ...
          next
      end
  end
  ```

- `vdom` is a real field on `config system admin`: "Virtual domain(s) that the
  administrator can access", string, maximum length 79.
- Per-VDOM administrators "must use either the `prof_admin` administrator
  profile, or a custom profile", and "when creating an administrator at the VDOM
  level, the `super_admin` administrator profile cannot be used".
  `super_admin_readonly` is the *global* read-only profile, so **there appears to
  be no built-in read-only profile usable for a per-VDOM account** — which makes
  a custom `accprofile` an operator prerequisite rather than an option. Say so in
  the docs whichever way you go.
- Detection is documented: `get system status` reports `Virtual domain
  configuration:` with `disable` or `multiple`; the Administration Guide adds
  split-task mode as a third shape. Phase 0015 already reads this
  (`fortios.vdomConfigurationPattern`) and refuses everything but `disable`.
- `cliSession.Close` sends `end\nend\nexit`, a fixed depth that is correct only
  because the driver refuses the deeper nesting. It is one of the places that
  must change, and its comment says so.

## The design questions this phase owns

Settle these **with the user before writing code**, and write the reasoning into
`docs/PLAN.md`.

1. **Where does a VDOM name come from?** A new
   `auth.target.ephemeral_account` parameter, the route's target (a
   `host/vdom` form, say), or the platform value. It decides what the audit
   record says the target was and what a policy author writes in Hoplock
   Control. A new parameter is a contract change: upstream first, per
   `docs/CROSS-REPO-PROTOCOL.md` §3.2, with the sync kickoff its §4 asks for.
2. **Global-scope or VDOM-scoped administrators, or both?** A global
   administrator on a multi-VDOM unit needs the `config global` wrapper but no
   `set vdom`, and can keep using an immutable global profile — it is the
   smaller change and the *more* privileged account. A VDOM-scoped one is the
   point of the feature and needs a profile the customer built. Serving only one
   of them is a defensible scope; serving neither is what ships today.
3. **What happens when the VDOM the route names does not exist?** An
   outage-class denial (D13), and the question is how it is detected — before
   creating anything, or as a command failure the driver reads.

## In scope

- The three decisions above, settled with the user and recorded in
  `docs/PLAN.md`, plus any `api/` change they imply, upstream first.
- `internal/auth/target/device/fortios`: the `config global` wrapper, `set vdom`
  where the answer above calls for it, matching unwinding in `cliSession.Close`
  and in `Driver.abandon`, and the enumerate path — `show system admin` inside
  `config global` is a different table from the one at top level, and the reaper
  reads it.
- `internal/sshtest/fortios.go`: the fake already models a VDOM mode and already
  rejects `config system admin` outside `config global` in it
  (`TestTheFakeDeviceRejectsAnUnwrappedAdminTable` pins that). Extend it with the
  VDOMs themselves, so that `set vdom` naming one that does not exist fails the
  way a device fails.
- The e2e topology, if the appliance node can carry a multi-VDOM unit without
  becoming a second node.

## Out of scope

- The schedule/expiry mechanism — **0028**.
- Which access profile a route *gets* — 0016's vocabulary, 0017's application.
  This phase may need to say that a custom profile is a prerequisite; it does not
  choose one.
- The FortiSwitch drivers, except for the shared identity answer above.

## What needs hardware

Carry these forward rather than letting them evaporate; the first two are
inherited from 0015's list.

1. **What `config system admin` at the top level of a multi-VDOM unit actually
   does** — a parse error, or something quieter. The fake models it as an error
   because that is the strictest reading, and its comment says the real
   behaviour is unverified. If it turns out to be quiet, 0015's refusal was
   load-bearing in a way nobody could prove.
2. Whether a FortiGate's SSH server truly refuses a non-interactive `exec`
   request.
3. Whether `show system admin` inside `config global` returns the same table
   this driver's parser expects, or a different rendering of it.

## Acceptance criteria

- A multi-VDOM unit is either provisioned correctly against the fake device or
  refused for a reason narrower than "the unit is running virtual domains".
- A test fails if the `config global` wrapper is dropped, and a test fails if the
  session is left in configuration mode because the unwinding did not follow the
  nesting.
- Teardown removes everything provisioning created, on both unit shapes.
- Single-VDOM units behave exactly as they do today; the existing tests pass
  unmodified or their changes are explained.
- `go build ./... && go vet ./... && go test ./...` and `golangci-lint run` pass.

## Definition of Done & hand-off

Per `docs/PROTOCOL.md`. Move this prompt to `implemented/`; add
`docs/learnings/0027-fortios-multi-vdom-learnings.md`. The summary block MUST
carry: the three decisions and their reasoning; the target-identity answer and
whether you set it or inherited it from 0025; which unit shapes the driver now
serves and which it still refuses; and the remaining hardware list.
