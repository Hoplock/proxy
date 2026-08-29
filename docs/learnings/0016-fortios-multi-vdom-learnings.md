# 0016 — FortiOS multi-VDOM — Learnings

## Summary
- **What shipped:** a FortiGate running virtual domains is now administered
  instead of refused. The driver reads `get system status` once per session and
  serves `disable`, `multiple` and `split-task`; on the two partitioned shapes
  every global table — create, delete, credential, and the enumerate path the
  reaper reads — goes through `config global`, and teardown unwinds the depth
  the session opened rather than a fixed two levels. A route can now scope the
  administrator to one virtual domain.
- **Key files:** `api/control.yaml` + `api/README.md` (contract **v3.1**),
  `internal/control/{policy.go,validate.go}`,
  `internal/auth/target/{params.go,deviceaccount.go}`,
  `internal/auth/target/device/driver.go`,
  `internal/auth/target/device/fortios/{fortigate.go,cli.go,value.go}`,
  `internal/logging/{record.go,device.go}`, `internal/sshtest/fortios.go`,
  `cmd/fake-device/main.go`, `deploy/{compose.yaml,proxy/proxy-direct.yaml,
  control/fixtures.template.yaml}`, `docs/PLAN.md` (§4.2, §5.3, §10),
  `docs/FORTIOS-DOC-VERIFICATION.md`.
- **Types/identifiers added:** `control.ParamDeviceFieldPrefix`
  (`device_field.`), `control.TargetAuth.DeviceFields()`,
  `device.Field` + `Capabilities.Fields` + `Capabilities.AcceptsField`,
  `device.CreateRequest.Fields`, `target.AccountMapping.Fields`,
  `logging.AttrDeviceFieldPrefix`, `fortios.FieldVDOM`,
  `fortios.ErrUnknownVDOM`, `sshtest.FortiOSOptions.VDOMs` +
  `FakeFortiOS.StrandedSessions()`.
- **The three decisions.** (1) **Target identity: the endpoint stays the device
  and the route names the partition**, through an open `device_field.<name>`
  namespace declared per driver — not a `host/vdom` target, not proxy-local
  config, not a FortiOS-specific parameter. (2) **Both administrator scopes are
  served**: no field means a global administrator, the field means a VDOM-scoped
  one. (3) **An unknown VDOM is refused before anything is created**, and a
  refused `set vdom` still fails the attempt.
- **Decisions affected:** D13 (an unsupported configuration is an outage-class
  denial — narrowed, not weakened), D14 (an undeclared field is a skipped rung),
  contract v3 → **v3.1**, additive, `policy_version` unchanged at 3.
- **The target-identity answer is BINDING on 0018 and 0027**, and this phase set
  it rather than inheriting it (0027 has not run). Both prompts now carry it.
- **Gotchas:** there is **no built-in read-only profile a per-VDOM account can
  hold**, so a custom profile is an operator prerequisite; the driver refuses
  `super_admin`/`super_admin_readonly` for a VDOM-scoped route. Device fields
  ride on `CreateRequest` only — 0027 is what carries them onto removal and
  enumeration, and onto the reaper.
- **Cross-repo:** `api/` changed, so `hoplock/control` owes a **sync PR**
  (`docs/CROSS-REPO-PROTOCOL.md` §3.1); the kickoff is in the PR body under
  **Cross-repo impact**. `hoplock/enterprise`: none.

## Details

### Why the namespace, and not the four alternatives

The question phase 0015 deferred is "what is a target when one device is many?",
and it had four candidate answers. Three were rejected for reasons that are
properties of the system rather than taste:

- **In the target string (`host/vdom`).** The target is what DNS resolves, what
  the host key is pinned to (D7), what `target.deviceReaper` keys its per-device
  state on, and what the audit record names. Overloading it makes one unit look
  like several hosts that do not exist, in four subsystems, to save one
  parameter.
- **Proxy-local configuration.** §4.2 is explicit that the method and its
  parameters are Control's decision per route, "never proxy-local config,
  because one proxy routinely fronts estates that need different methods". A
  VDOM is exactly such a per-route fact.
- **A FortiOS-specific `vdom` parameter.** It would work, and 0027 would then
  need `switch` — two parallel answers to one question, which is precisely the
  outcome the renumbering of 0016 ahead of 0018 and 0027 existed to prevent.

What is left is a namespace, and the user's shaping of it is the reason it is a
namespace rather than a single `device_scope` parameter: platform-specific
routing data is not going to be one string forever, and a bag with a checked
shape costs nothing now and saves a contract revision later.

Two properties make it safe rather than merely open:

1. **A field the driver does not declare is a skipped rung** (`ErrRungUnsatisfiable`),
   not a field dropped. This is the same rule as `ErrUnknownParam`, reached from
   the driver's declarations instead of the method's parameter list — a field may
   be a *constraint*, and honouring part of a route is how a session lands in a
   scope nobody named. It is also why the revision is additive: a proxy built
   before v3.1 refuses the rung rather than creating an unscoped account.
2. **Fields are audit facts.** `AccountMapping.Fields` reaches D8's priority path
   as `device_field.<name>` attributes, one per field so an operator can filter
   rather than substring-search. On a partitioned unit `host:port` is the same
   string whether the administrator was global or scoped to one customer's VDOM,
   and the difference is the entire scope of a privileged account.

The contract checks the **shape** only — name is an identifier (≤64), value
non-empty (≤256), at most 16 fields. Which fields exist is the driver's, for the
same reason the set of platforms is open: D13 makes customer-written drivers a
first-class case.

### What changed in the driver

- `cliSession` carries the unit's `vdomMode` (a session property: one driver
  serves every unit of its kind, and two of them can be in different modes) and
  a `depth` counter maintained in `send`. `Close` unwinds `depth+1`, floored at
  the two 0014 always sent.
- `enterAdminTable`/`leaveAdminTable` are written as a pair, next to each other,
  because "opens two levels, closes one" is the bug and it is invisible in a
  transcript where every command succeeded.
- `showGlobal` wraps the two reads (`show system admin`, `show system vdom`) and
  leaves the scope with a `defer`, so a read that fails half way does not leave
  the session in `config global` — where the next command means something else.
- `abandon` re-enters through the same nesting; a rollback that ran at the top
  level of a partitioned unit would delete nothing, quietly, on the one path
  whose whole job is to leave no administrator behind.
- `checkVDOMProfile` refuses the two documented global built-ins for a
  VDOM-scoped account. Only those two: a custom profile is the customer's and
  this driver cannot know what is in it.

**On the depth counter, honestly:** with the maximum nesting this driver opens
today (two levels), a fixed two `end`s would still unwind, because every
sequence either completes its own unwinding or `abort`s. The counter is not
load-bearing *yet*; it is what keeps the property true when the nesting grows
(0027), and `FakeFortiOS.StrandedSessions()` is what makes "the session was left
in configuration mode" a testable claim at all —
`TestTheFakeDeviceCountsAStrandedSession` pins the counter so that
`TestTheSessionIsNeverLeftInConfigurationMode` staying green means something.

### The fake device

The fake refuses `show system admin` and `show system vdom` outside
`config global` in VDOM mode, models the unit's VDOMs (`set vdom` naming an
absent one fails as `Entry not found in datasource`), and counts sessions that
end inside a configuration block. That last one is a detector rather than a
behaviour: a real unit holds an object lock under workspace mode, and a fake
that tidied up after the driver would make an under-unwinding driver look
correct.

Phase 0015's lesson holds and was applied again: **where the real device is known
to be strict, so is this**, and where the real behaviour is unknown the fake says
so in a comment rather than inventing one.

### The e2e topology

The appliance node now serves a **second listener** (`-vdom-listen 0.0.0.0:2222`,
`-vdoms root,customer-a`) rather than becoming a second node — a multi-VDOM
FortiGate is one box partitioned, and a topology that modelled it as two would
describe an estate nobody has. `deploy/control/fixtures.template.yaml` gains a
route to it carrying `device_field.vdom: customer-a`, and the scenario asserts
the account-mapping record carries the field and that teardown removes the
administrator from that unit too.

`deploy/proxy/proxy-direct.yaml` moved from `super_admin_readonly` to
`prof_admin`, because one proxy config serves both unit shapes and a VDOM-scoped
account cannot hold the global read-only profile. That is the operator
prerequisite above, showing up in the topology exactly where a customer will
meet it.

**This session could not run the e2e suite** — no Docker in the environment — so
the topology changes are verified by compilation (`go vet -tags e2e`) and by CI.

### Documentation read this phase

`docs/FORTIOS-DOC-VERIFICATION.md` gained a section recording what was looked up
and **how**: the documentation site did not render its body text to this
session's fetcher, so three of the four sources are search-result summaries
rather than direct reads, and they are labelled as such. That is weaker evidence
than phase 0015's, and the affected claims are: split-task mode having per-VDOM
administrators (which is why the driver serves it), and `config system vdom`
being an ordinary table (which is why `show system vdom` is the enumeration).

### What still needs hardware

Carried forward, with two new entries:

1. **What `config system admin` at the top level of a multi-VDOM unit actually
   does** — a parse error, or something quieter. The fake models it as an error
   because that is the strictest reading. Still unverified, and now it matters
   less: the driver no longer sends it there.
2. **Whether a FortiGate's SSH server truly refuses a non-interactive `exec`
   request.** Unchanged from 0014/0015.
3. **Whether `show system admin` inside `config global` returns the same table
   this driver's parser expects.** The driver and the fake both assume it does.
   This is the highest-value item on the list: if the rendering differs, the
   reaper's enumerate path on a partitioned unit reads a table it cannot parse.
4. **NEW: whether `show system vdom` inside `config global` lists the unit's
   virtual domains in `edit "<name>"` form.** The alternative (`diagnose sys vd
   list`) was rejected because a tightly scoped management account may not be
   able to run `diagnose` at all (7.4+).
5. **NEW: what `get system status` reports for split-task mode.** The driver
   serves the literal `split-task`; a unit reporting something else falls into
   the narrowed `ErrMultiVDOM` refusal, which is fail-closed but would mean the
   shape is unserved.

### Follow-ups, and what this phase deliberately did not do

- **Which access profile a route gets is still 0018's vocabulary and 0019's to
  apply.** This phase needed to say that a custom profile is a prerequisite on a
  partitioned unit; it did not choose one, and there is still no default.
- **`set schedule`/target-enforced expiry is 0017**, untouched here.
- **Fields on removal, enumeration and the reaper are 0027's**, and its prompt
  now says so with the reasoning.
- No new prompts were queued. The numbering invariants hold: 0016 moves to
  `implemented/`, nothing was renamed or renumbered.
