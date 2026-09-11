# 0029 — FortiLink FortiSwitch driver — Learnings

> **Pointer, added by phase 0030 (this file is otherwise unchanged).** Every
> reference below to 0030 as queued work is now historical: **0030 was withdrawn
> and its number retired.** The estate this phase named as the one it does not
> serve — switches deliberately kept unroutable from the proxy — is answered by
> a deployment (route a proxy to the switch, or administer it from an ordinary
> FortiGate session) rather than by the nested reach 0030 was queued to build.
> The hazard this phase "recorded in 0030 as a hazard that phase has to answer"
> was answered by not taking it on: the proxy provisions nothing on a device it
> has no route to. See `docs/PLAN.md` §5.3, "As settled (phase 0030)", and
> `docs/learnings/0030-fortilink-mediated-administration-learnings.md`. This
> phase's own shipped behaviour is unchanged.

## Summary
- **The prompt's premise was wrong, and correcting it is this phase's main
  deliverable.** 0029 assumed a FortiLink-managed switch "has no independent
  administrative plane the proxy can SSH into". Fortinet's `config
  switch-controller security-policy local-access` configures a **managed
  switch's own** allowaccess list and has **`ssh` in the default** for both its
  interfaces. So the switch is **its own endpoint**, FortiLink is a deployment
  fact rather than a target identity, **no `device_field` is declared**, and
  0016's answer is left intact rather than stretched.
- **What shipped:** `fortios.SwitchDriver`, platform **`fortiswitchos`** — a
  full `ephemeral-account` lifecycle on a FortiSwitch, reusing 0014's CLI state
  machine and value validation through helpers moved onto `cliSession`. Plus a
  FortiSwitch mode in the fake device, a `TestTopology` subtest, and the
  documentation record. **No contract change** — `api/` untouched, so no
  cross-repo obligation (`docs/CROSS-REPO-PROTOCOL.md` §1).
- **Key files:** `internal/auth/target/device/fortios/{fortiswitch.go,
  fortiswitch_test.go}` (new) + `{fortigate.go,schedule.go,value.go}`;
  `internal/auth/target/registry.go`; `internal/sshtest/fortios.go`;
  `cmd/fake-device/main.go`; `deploy/{compose.yaml,
  control/fixtures.template.yaml}`; `test/e2e/{harness,scenarios}_test.go`;
  `docs/PLAN.md` (§5.3, §10), `docs/FORTIOS-DOC-VERIFICATION.md` (new second
  half), `config.example.yaml`, `README.md`.
- **Types/identifiers added:** `fortios.{PlatformFortiSwitch, SwitchDriver,
  SwitchOptions, NewSwitch, RegisterSwitch, SwitchAcceptsProfile,
  ErrNotAFortiSwitch}`; unexported `maxSwitchAccountNameLen` (**35**),
  `validateAccountNameWithin`, `checkSwitchProfile`, `switchStatusCommand`;
  `sshtest.{FortiOSOptions.Platform, FortiOSPlatformFortiGate,
  FortiOSPlatformFortiSwitch, FortiSwitchBuiltinProfiles,
  FortiSwitchMaxNameLen, FortiOSFaults.HideIdentity}`. Moved onto `cliSession`:
  `run`, `showGlobal`, `listAccounts`, `accountExists`.
- **Declared `Capabilities`:** `MaxAccountNameLen` **35** (undocumented —
  assumed), `EnforcesExpiry` **false** (a documentation *contradiction*, not an
  absence), `PersistsAcrossReload` **true** (`cfg-save`), both credential
  kinds, `PinsSourceAddress` true, `CommandAuthorization` declared, **`Fields`
  nil**.
- **What the NEXT session must know:** 0030 was **rewritten in place**, not
  renumbered — it is now the FortiLink-*mediated* phase for estates that keep
  switches unroutable. Nothing else moved and no number was retired. And
  `auth.target.ephemeral_account.access_profile` is under-specified — one
  FortiOS-shaped value for every platform — and the fix is queued as **0036**,
  which moved the contract collapse to **0037**.

## Details

### The finding, and why it changed the design

The prompt asked for 0016's answer extended one level out: the managing
FortiGate as the endpoint, `device_field.switch` naming the switch behind it.
It also — explicitly, and twice — required the FortiLink facts to be
established from Fortinet's current documentation rather than from memory, on
the grounds that the same discipline in 0014/0015 had already found a fact that
contradicted the plan. It did so again, and this time against the prompt.

`config switch-controller security-policy local-access` on the FortiGate is
documented as "Configure allowaccess list for **mgmt and internal interfaces on
managed FortiSwitch units**", with `internal-allowaccess` and
`mgmt-allowaccess` both defaulting to `https ping ssh`. A FortiLink-managed
switch therefore keeps its own SSH administrative plane, on both management
interfaces, enabled by default — and the managing FortiGate's role is that it
*can close* it. Whether this proxy can reach that address is a routing and
firewall-policy question in the customer's deployment.

That is not a smaller version of the prompt's shape; it is a different one, and
the difference decides everything downstream. The user was given the finding
with the evidence and chose to follow it.

**Why this does not stretch 0016.** 0016's rule is that the endpoint stays the
**device** and a route field names a **partition** of one device. A FortiSwitch
is not a partition of its FortiGate — separate host key, separate administrator
table, separate configuration, separate serial number. Making it a field would
have made `host:port` name a unit the account does not live on, which is
exactly what 0016 rejected `host/vdom` for. So 0016's forward-looking sentence
— "a platform where a field selects a genuinely different managed device —
0029's switch — is the phase that carries them onto the other operations" — is
left **unspent**: no such platform arrived, `CreateRequest.Fields` still ride
on creation only, and the reaper is untouched. `docs/PLAN.md` §5.3 records the
three alternatives and why each was rejected.

**What the phase lost by being right.** Two acceptance criteria as written no
longer describe anything: "a session provisions on the switch through its
FortiGate" and "the audit record names **both** devices". There is one device.
The spirit of the second is met — the mapping event names the switch, which is
the device the administrator is on, and a reviewer needs to know nothing about
FortiLink to read it.

### Verified FortiSwitchOS facts, and their sources

All of them, with pages and wording, are in `docs/FORTIOS-DOC-VERIFICATION.md`
under **"FortiSwitchOS and FortiLink (phase 0029)"**. The short list:

| Fact | Verdict |
| --- | --- |
| `config system admin` with `accprofile`, `password`, `ssh-public-key1..3`, `trusthost1..10`, `ip6-trusthost1..10` | documented |
| Built-in access profiles | **one**: `super_admin` |
| Administrator-name limit | **undocumented** |
| Per-administrator expiry | **contradictory** |
| `cfg-save {automatic\|manual\|revert}` | documented, as FortiOS |
| `get system status` identifies the unit | documented, **with an example** |
| Creating administrators needs read-write `admingrp` | documented |

Three deserve more than a row.

**`EnforcesExpiry` is false on a contradiction, not an absence.** `config
system admin` *does* have `set schedule <schedule-name>`, described as
"Restrict times that an administrator can log in. **Defined in config firewall
schedule**." FortiSwitchOS has no `config firewall schedule` — its schedule
tables are `config system schedule onetime|recurring|group` under `config
system`, and there is no `config firewall` chapter at all. The field exists and
the table its own description names does not. Phase 0017 settled what the bit
must mean — the device ends the account's usefulness whether or not the proxy
is alive — and that cannot be established from a contradiction, so a route
asking for `target-enforced` here is a **skipped rung** and the reaper is the
only removal path. This is the highest-value item on the hardware list: if a
real unit resolves `set schedule` against `config system schedule onetime`, the
declaration flips and the driver grows the residue sweep it deliberately lacks.

**The name limit is the one number nobody publishes.** FortiSwitchOS's CLI
reference uses the older Variable/Description/Default table with no width
column, so `<admin_name>` has no documented size — where FortiOS's gives 64
(claim 1). The driver declares **35**, the naming-rules KB's general figure.
That is the same number that was *wrong* for FortiOS, used here for the
opposite reason: with no field-specific figure to prefer, the general one is
the conservative choice and costs nothing, because 35 still clears PLAN §5.3's
threshold of 32. `internal/sshtest.FortiSwitchMaxNameLen` is deliberately the
same constant and `TestSwitchNameLimitIsTheDeclaredOne` asserts they agree, so
a correction from hardware moves both.

**One built-in profile, and it is the all-access one.** `super_admin` "cannot
be deleted or modified"; `prof_admin` and `super_admin_readonly` are FortiOS
profiles that do not exist here. `checkSwitchProfile` refuses those two before
dialling, on 0016's `checkVDOMProfile` reasoning: a refused `set accprofile` is
a failure *after* the entry has been created, so the difference between
checking and not checking is a rollback on a customer's switch. Only those two
are refused — a custom profile is the customer's to scope.

### Two design decisions inside the driver

**It is a separate Go type, and that is load-bearing.** `*Driver` implements
`device.ResidueSweeper`, and `target.deviceReaper` discovers that by **type
assertion**. A switch served by the same type would have its `config firewall
schedule onetime` sweep run against a platform with no such table — a reported
sweep failure on a customer's switch every two minutes, for an object class
that does not exist. `TestSwitchIsNotAResidueSweeper` pins it. The FortiGate
driver's `Options.Platform` field, added by 0014 precisely so "the standalone
switch driver is expected to be this driver under another name", turns out to
be the wrong shape for that reason; it is left in place and unused by this
phase.

Sharing still happened, just not through the type: `run`, `showGlobal`,
`listAccounts` and `accountExists` were **moved off `*Driver` onto
`*cliSession`**, which is where they belonged — none of them read a single
field from the driver. `enterAdminTable`/`leaveAdminTable` were already there.
`cliSession.vdomMode` stays at its zero value on a switch, so every table
helper takes the unpartitioned path, which is correct rather than incidental:
FortiSwitchOS has no virtual domains.

**The unit's identity is confirmed before anything is configured.** This is the
check that matters most here, because the failure it prevents is silent. `config
system admin`, `edit`, `set accprofile`, `set password` and `show system admin`
are valid on **both** platforms — the very thing that made the reuse possible —
so a route naming `fortiswitchos` against a FortiGate would create a privileged
administrator on somebody's **firewall** and report success, with an audit
record naming a switch. `confirmSwitch` reads `get system status` once per
session and requires a `Version: FortiSwitch…` line; `ErrNotAFortiSwitch` is an
outage-class denial and deliberately **not** `device.ErrUnsupported`, on 0015's
reasoning — skipping the rung would answer a misrouted route by serving the
session on a credential the server ranked lower. An unreadable answer is
refused too.

The pattern only matches the product word, not the model or the release: a
driver that refused next quarter's firmware over a version string would be
refusing for a reason unrelated to the question it is asking.

### The access-profile gap this opens, and how it is handled

`auth.target.ephemeral_account.access_profile` is **one value for every
platform a proxy serves**, and it is FortiOS-shaped. A FortiGate estate
acquiring its first switch has `super_admin_readonly` or `prof_admin`
configured, neither of which exists on FortiSwitchOS.

`newDriverRegistry` builds the switch driver with **no default profile** when
the configured one is a FortiOS built-in (`fortios.SwitchAcceptsProfile`
answers the question without dialling). That is a state the driver already
supports: a route naming its own scope via `enforcement.platform_role` is
served, and a route relying on the proxy-wide default is refused outage-class
with nothing provisioned and an error naming the platform.

The two alternatives were worse. Passing it anyway means `set accprofile`
refused half way through a sequence that has already created the administrator
— a rollback per session on a customer's switch. Refusing at **startup** means
every FortiGate-only deployment stops booting the day this driver ships, over a
platform it does not serve; `platforms: []` means "every driver this build
ships", so that is most of them.

Nothing is weakened and nothing is substituted; what is lost is a default that
was never valid on this platform. **A per-platform default is the real answer**
and belongs to whichever phase next touches that setting. The e2e route names
its profile through `enforcement.platform_role: super_admin`, which is also the
first fixture to exercise `platform-authorized` on a device.

### The leak class this phase names and cannot close

`execute switch-controller switch-action set-standalone` and `execute
switch-controller factory-reset` both return the switch to factory defaults,
which **destroys** an account this proxy created. Plain **deauthorization**
does not: it removes the switch from FortiLink management, and Fortinet
documents nothing about it touching the switch's own configuration.

On a switch the proxy reaches directly — which, after this phase, is all of
them — that changes nothing: the reaper still sweeps it. On one reachable only
*through* its FortiGate it would strand the account beyond recovery. That is a
second, independent argument for the switch being its own endpoint, and it is
written into 0030 as a hazard that phase has to answer.

### Follow-ups and the queue

**0030 was rewritten in place, not renumbered.** Its old content ("Standalone
FortiSwitchOS driver … nearly the FortiGate driver under another platform
name") is what this phase delivered. Its new content is the estate this
phase's decision does *not* serve: switches deliberately unroutable from the
proxy. No number moved for it, nothing was retired, and there is therefore
**no mapping to compose** for that half — a reference to "0030" resolves to
whatever `prompts/queued/0030-…` says today. The queue note at the end of
`docs/PLAN.md` §10 says the same. (The queue itself has since grown to
**0030–0037**: the access-profile follow-up below *is* a renumbering, and it
has its own note above that one.)

That prompt carries this session's findings so its author does not re-derive
them: both documented ways into a managed switch's CLI and what each costs;
that **every hop leaving a Fortinet unit is password-only** (both platforms'
SSH clients take a destination and nothing else — no identity file, no key
store, no port forwarding, so no key on the nested hop and no
switch-initiated reverse tunnel either); that `ProvisionedAccess` has no seam
for a reach preamble and the phase needs one plus a **second** ephemeral
account on the FortiGate; and that if it does introduce a device-selecting
field, the reaper must partition its bookkeeping on **declared** such fields
only — partitioning on all of them would make a VDOM route's live account look
like another route's orphan.

**The access-profile gap is queued as 0036**, on the user's instruction after
review of this PR. Nothing in the queue touched
`auth.target.ephemeral_account.access_profile`, so
`prompts/queued/0036-per-platform-access-profile.md` is new, and the contract
collapse moved **0036 → 0037** to stay last — one candidate answer (a
route-named default decoupled from 0019's rung) revises `api/`. That prompt
carries the three defensible answers, this phase's workaround and why it is a
workaround, and the two alternatives already rejected so it does not
re-litigate them. Mapping and updated live references are in the newest
run-order note at the end of `docs/PLAN.md` §10.

Two smaller things:

- **Fixed on the same instruction:** `deploy/control/fixtures.template.yaml`'s
  first device route said "FortiOS has no per-administrator expiry field",
  which phase 0015 disproved and 0017 acted on. The route's *choice* of
  `proxy-enforced` was always fine; only the stated reason was stale. Writing
  the correction surfaced something else worth knowing: **no** fixture route
  asks for `target-enforced`, so the topology does not exercise 0017's schedule
  path end to end at all. That is a pre-existing coverage gap and the comment
  now names it rather than closing it — adding such a route is its own change,
  not a comment fix.
- The hardware list in `docs/FORTIOS-DOC-VERIFICATION.md` gained three items:
  the schedule contradiction, the name limit, and whether deauthorization
  really leaves `config system admin` intact.

### Testing, and what could not be run

`go build ./...`, `go vet ./...`, `go test ./...` and `golangci-lint run` all
pass. New unit coverage in `fortiswitch_test.go`: the full lifecycle against
the fake switch; a public-key credential **logged in with**, not merely
asserted present; refusal of a FortiGate and of an unidentifiable unit, with
nothing created on either; refusal of the FortiOS built-in profiles at three
layers; `EnforcesExpiry` false and a lifetime refused as `ErrUnsupported`; the
residue-sweeper type assertion; route fields refused; the name limit agreeing
with the fake; never adopting an existing account; and an unreachable switch
being retryable — including that **enumerate fails rather than returning an
empty table**, which is the half that would otherwise tell the reaper a switch
is clean.

**The e2e suite could not be run in this session**: there is no Docker daemon
in this environment. `go vet -tags e2e ./test/e2e/` passes and
`test/topology/config_test.go` passes, so the scenario compiles and the
fixtures parse, but the topology itself runs for the first time in CI. The new
subtest goes before the outage scenario and passes per-scenario options rather
than touching `sshBaseArgs`, per 0014's warning, and the ephemeral-leak check
at the end of the suite now covers the switch as well.

### Deviations from the prompt

1. **The target-identity decision is the opposite of the one the prompt
   framed**, on documented evidence, settled with the user. §5.3 carries it.
2. **No contract change**, where the prompt expected one ("this prompt probably
   does touch a shared surface"). Because the switch is its own endpoint with
   no device field, `api/` is untouched — so `docs/CROSS-REPO-PROTOCOL.md` §1
   applies and there is no downstream obligation and no sync kickoff to hand
   over.
3. **Two acceptance criteria are met in spirit rather than to the letter**:
   "provisions on the switch through its FortiGate" and "the audit record names
   both devices". There is one device to name.
4. **0030 was rewritten rather than left alone**, because this phase delivered
   its content. That is the §6 obligation to keep the queue meaningful, and it
   needed no renumbering.
