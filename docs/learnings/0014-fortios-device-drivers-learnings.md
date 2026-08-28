# 0014 — FortiOS device drivers — Learnings

## Summary
- What shipped: the **FortiGate driver** (`internal/auth/target/device/fortios`),
  the **`ephemeral-account` provisioner** and its device reaper
  (`internal/auth/target`), **D14's ladder walk** in `Selector`, the naming
  generalisation over a declared limit, a **fake FortiOS device** in
  `internal/sshtest`, and an appliance node in the e2e topology. No contract
  change (`api/` untouched).
- **The FortiSwitch drivers are NOT here.** The user was asked the FortiLink
  question this prompt requires and answered "both modes, FortiLink first": a
  FortiLink-managed switch is administered *through* its FortiGate, which is a
  different target identity and a contract question. Queued as **0024**
  (FortiLink) and **0025** (standalone).
- **Verified FortiOS facts** (sources in Details — Fortinet's own docs were
  unreachable from this session's egress policy; see "How these were verified"
  before trusting any of them further):
  | Fact | Finding | What it decided |
  | --- | --- | --- |
  | Administrator name length | **35** characters | `MaxAccountNameLen: 35`, so FortiOS gets the **readable** §5.1 scheme; the constrained scheme is exercised only by tests |
  | Per-account expiry | **none exists** | `EnforcesExpiry: false`; `target-enforced` is a **skipped rung**; the reaper is the primary removal path |
  | Password *and* SSH key | both, together, per administrator | `CredentialKinds: [password, publickey]`; `admin-ssh-password` is device-wide, so the driver never touches it |
  | Access profile at creation | yes, `set accprofile` in the same `edit` | profile set on create; the default is `super_admin_readonly` (see below) |
  | `trusthost` | yes, `trusthost1..10` | `PinsSourceAddress: true`, pinned as a /32 |
  | Persistence | **`end` writes to flash** under the default `cfg-save automatic` | `PersistsAcrossReload: **true**` — and D13 had to be amended |
  | Failure reporting | **output text**, no exit status | the driver is a prompt/response state machine, not a command pipe |
  | Paging | `set output more` is the default and is **permanent, not per-session** | the driver pages through `--More--` rather than turning paging off on a customer's device |
- **D13 amended, with the user's decision.** D13 forbade a shipped driver from
  declaring `PersistsAcrossReload`. That is unsatisfiable on the platform D13
  names as its own example, so the rule is now "may declare it when the platform
  leaves no choice, **and must say which mechanism forces it**"
  (`Capabilities.PersistenceReason`, enforced by `CheckShipped`, recorded on
  every session). Persistence *by choice* is still forbidden. `docs/PLAN.md` D13
  and §5.3 updated in this PR.
- **What an access profile can and cannot constrain** (0015's survey depends on
  this and nothing else): it assigns **read / write / no access per FortiOS
  feature area**, so it *can* bound which subsystems an administrator touches
  and whether it may change them. It **cannot** bound anything below that
  granularity — no per-command rules, no argument shapes, no per-object scoping,
  no "may edit this policy but not that one". Rank it accordingly: it is a
  coarse capability gate, roughly the strength of a Unix group, not a command
  filter.
  There are **four built-ins**: `super_admin` and `prof_admin` (read-write;
  `prof_admin` excludes routing, system settings and endpoint control), and
  `super_admin_readonly` and `prof_admin_readonly`. `super_admin` and
  `super_admin_readonly` are documented as undeletable and unmodifiable; the
  other two are editable, so their contents are whatever the customer has made
  them.
  The shipped default is **`super_admin_readonly`**
  (`fortios.DefaultAccessProfile`) — the most restrictive built-in that cannot
  be edited out from under us. `prof_admin_readonly` is narrower but editable,
  and a default that silently widens when an operator edits a profile is worse
  than one that reads more and cannot drift. **A read-only default is wrong for
  any route whose purpose is to change the device**, which is most of UC1: those
  set `auth.target.ephemeral_account.access_profile` until 0016 makes it policy.
  This is the fixed default 0016 replaces.
- **The naming generalisation**: `newNaming(proxyID, limit)` in `principal.go`
  picks the scheme and carries the reaper prefix with it. At limit ≥ 32 it calls
  the *existing* `newPrincipal` unchanged, so the POSIX path is byte-identical
  and 0007's tests pass unmodified. Below 32 it is `hl-` + a 4-char base36 proxy
  tag + an (X−7)-char base36 token, no separator; below 11 it is
  `ErrNameLimit`, a refusal, never a truncation.
- **The reaper's changed role**: where the platform cannot expire an account,
  the sweep is the **only** removal path, not a crash backstop. Hence tighter
  defaults (2m/10m against the POSIX 10m/30m), age measured from **this
  process's first sighting** when the platform reports no creation time, and a
  failed sweep reported on D8's priority path rather than logged.
- **A pre-existing bug fixed in passing**, because it made CI hang a third of
  the time and blocked this phase's DoD: `internal/proxy`'s session `close()`
  closed the target leg *before* waiting for setup, so a kill arriving mid-setup
  leaked a live connection to the target. Measured at 9 hangs in 25 runs on
  `origin/main`; 15/15 with the fix. Details below.
- **What the NEXT session must know:** `Target` gained `Ladder`, `SessionID` and
  `Rung`; `ProvisionedAccess` gained `Method` and `Rung`; `routing.Route` gained
  `TargetAuthLadder`; `device.Endpoint` gained `HostKeyCallback`;
  `Capabilities` gained `PersistenceReason`. `internal/logging` now imports
  `internal/auth/target` (as it already imported `internal/filter`) to implement
  `DeviceEventSink`.

## Details

### How these were verified, and the caveat that goes with it

The prompt required Fortinet's current documentation rather than memory, and it
was right to: the persistence finding contradicts `docs/PLAN.md` and would not
have been found by recalling how a FortiGate "obviously" works.

**But `docs.fortinet.com` and `community.fortinet.com` are blocked by this
session's egress policy** (403 at the proxy's CONNECT, confirmed against
`$HTTPS_PROXY/__agentproxy/status`), as are the mirrors that carry the same CLI
reference. The facts above were therefore established through **web search
results summarising those pages**, not by reading the pages. That is weaker
evidence than the prompt asked for and it is recorded as such rather than
presented as a clean citation. The pages themselves, for the next author on a
network that can reach them:

- `config system admin` — https://docs.fortinet.com/document/fortigate/7.6.6/cli-reference/390485493/config-system-admin
- Naming rules and character restrictions (the 35-character figure, and the
  7.4/7.6 homoglyph restrictions on administrator names) —
  https://community.fortinet.com/t5/FortiGate/Technical-Tip-Naming-rules-and-character-restrictions/ta-p/196911
- Using configuration save mode (`cfg-save automatic|manual|revert`) —
  https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/228450/using-configuration-save-mode
- Public key SSH access (a key and a password coexist; `admin-ssh-password` is
  global) — https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/813125/public-key-ssh-access
- Administrator profiles (the four built-ins; `super_admin` and
  `super_admin_readonly` immutable, `prof_admin` and `prof_admin_readonly`
  editable) — https://docs.fortinet.com/document/fortigate/latest/administration-guide/294491/administrator-profiles

  A note on this one, because it is the fact 0015 leans on hardest: the first
  search for it returned only `super_admin` and `prof_admin` and read as though
  no read-only built-in existed, and that wrong reading briefly became the
  driver's default. A second, differently worded search surfaced
  `super_admin_readonly` and `prof_admin_readonly`. Absence of evidence in a
  search summary is not evidence of absence — check this list against the
  version in front of you before 0015 ranks it.
- `config system console` output mode (paging default, permanent not
  per-session) — https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/141236613/config-system-console

**Two of these deserve a second look on real hardware before a customer sees
them**, because they are the ones the driver would fail loudly on: the exact
name-length limit (35 is the general name-field figure; if the administrator
field is shorter, FortiOS moves onto the constrained naming scheme and the
mapping event becomes load-bearing), and whether `abort` discards an
uncommitted `config system admin` block on every supported version, since the
create path's failure isolation relies on it.

### Why the persistence finding forced a plan change

D13 reasoned that a device administrator is a configuration change, and
concluded that Hoplock's drivers would avoid the worst of it by never persisting
the account: "a reload is then a free reaper". That conclusion needs a platform
with a runtime-only write. FortiOS has none — `end` commits, and `cfg-save
manual`/`revert` are `config system global` settings governing every change on
the unit, so choosing one on a customer's firewall to suit our credential method
would be a far larger intervention than the account itself.

Three options were put to the user: declare the truth and relax the rule;
declare the truth and register the driver outside `Shipped()` so the rule never
applies; or refuse to serve a FortiGate whose `cfg-save` is `automatic` (honest,
and it makes the method unservable on most real units). The user chose the
first. The relaxation is deliberately narrow — a **written platform reason**,
checked by `CheckShipped`, recorded on every session — because the failure the
original rule guarded against was a driver quietly flipping the flag to make one
stubborn platform work, and a sentence naming a vendor mechanism is not
something that gets added by accident.

`TestPersistenceIsAllowedOnlyWithAWrittenReason` and the existing
`TestShippedDriversDoNotPersistAccounts` now cover both halves, and
`TestShippedDeclarationMeetsTheHoplockRule` runs `CheckShipped` over the
registry this repository *actually* ships — without it, the invariant passed
vacuously over an empty registry, which it had been doing since 0013.

### The driver is a state machine, and each part of it earns its place

`cli.go` reads to a prompt, answers the pager, and hands text back; it
interprets nothing. `fortigate.go` decides what the text means. Three
platform properties force that split and each is commented where it bites:

- **Paging.** `--More--` must be answered with a space, not `q`: `q` quits the
  pager and truncates, and on the enumerate path a truncated answer is a sweep
  that silently misses the accounts on later screens.
- **Modes.** A command sent in the wrong mode is not an error the device reports
  usefully; it is a different command. Hence the explicit `config system
  admin` / `edit` / `next` / `end` sequence and the `end\nend\nexit` on close,
  which also releases an object lock on units running workspace mode.
- **Errors as output.** `checkOutput` runs against **every** command's output,
  including the ones that "cannot fail", because a success and a failure are the
  same shape on this platform. `notFoundPattern` is separated from the rest so
  removal stays idempotent: "entry not found" on a `delete` is the outcome
  teardown wanted.

Two things in the create path are defensive rather than required, and would be
easy to remove without noticing why they were there:

- **The placeholder password.** `device.Driver` splits creation from the
  credential, so an account exists for a moment before `InstallCredential` runs
  — and a FortiOS administrator with no password can be logged into with an
  empty one. `CreateAccount` therefore sets a throwaway that is generated
  in-driver, never returned, never logged, and overwritten a step later.
- **`abort` on failure.** It discards an uncommitted configuration block
  outright, so a sequence that fails before `next` commits nothing. The delete
  that follows is for the case where it failed after.

### What the seam needed that 0013 did not give it

`device.Endpoint` gained `HostKeyCallback`. A driver opens the most privileged
connection this proxy makes, and 0013's seam gave it no way to learn the host-key
policy — so it would have had to invent one. The field is typed on SSH, which is
honest rather than tidy: every driver in this repository speaks SSH, and a
future driver on another transport has its own trust decision to describe rather
than an `ssh.HostKeyCallback` to ignore politely.

The provisioner wraps the session's callback in a `hostKeyWatcher` and pins the
key it approved, exactly as `sshAdminDialer.Dial` does for the POSIX path.
Without it, teardown would re-run the session's callback — which calls Hoplock
Control and fails closed — with the session's context already cancelled, and an
account would be left behind because a *different* component was down.

### Three config changes per session, not §5.3's two

PLAN §5.3 says two configuration changes land per session, per device (create
and delete). It is three: create, credential, delete, because the `Driver` seam
splits creation from the credential and each `end` commits. This is a real
discrepancy with the plan's prose and it is recorded rather than papered over —
it does not change the argument (the answer is still the reconciliation feed,
not suppression), but a customer counting objects in a backup diff will count
three.

### The device reaper is a separate type, and why that is not duplication

The POSIX `Reaper` and `deviceReaper` share their guarantees and not their
mechanics. The POSIX one reads a timestamp off the target and ages against the
*target's* clock. Most device platforms record no creation time —
`device.Account.CreatedAt` is zero, and 0013 says that must read as "age
unknown" rather than "created at the epoch, sweep it now" — so the device reaper
ages an untracked account from **when this process first saw it**. A restarted
proxy therefore waits one full grace period before touching what it inherited,
which is the safe direction: the alternative removes another proxy's live
session, or its own, on the first sweep after a restart.

`Reaper` could be generalised over an interface later. It was not done here
because it would have meant refactoring 0007's tested code to serve a caller
with genuinely different aging semantics, and the risk was not worth the
saved lines.

### The ladder walk, and the one distinction that is a security bug to invert

`Selector.Provision` walks the rungs top-down. The distinction it turns on is
0013's driver-error taxonomy:

- a rung this proxy **cannot satisfy** — unknown platform, a credential kind the
  driver does not accept, a posture it cannot meet — is **skipped**;
- a rung whose **attempt failed** — device unreachable, command refused — fails
  the **session**.

Inverting either is a security bug: the first turns a device outage into a
silent downgrade, the second turns a permanent limitation into a session that
never connects. `TestFailedAttemptDoesNotDropToAWeakerRung` and
`TestLadderFallsThroughToTheNextEntry` are the pair that pins it.

`RungChecker` exists so the check happens **without connecting**: a rung about
to be skipped has nothing to connect to, and a check that dialled would make
walking past an entry cost a round trip to the device that entry names.

An exhausted ladder is `ErrLadderExhausted`, but the error also wraps every
rung's own cause (`ladderError.Unwrap() []error`). That is what keeps a
one-entry ladder behaving exactly as D6a's original single method did —
`ErrMethodUnavailable` and `ErrUnknownMethod` still answer `errors.Is` — and it
is why 0007's selector tests pass unmodified.

### `identity.Login` was not given a new reader

The prompt was explicit and it was right to be. `ephemeral-account` requires
`username` on the route (contract v3), so `resolve` refuses a route without one
rather than falling back. `newNaming(...).name(login)` takes the account name it
is handed and threads it through; the shared `newPrincipal` was not given a
default. `TestRouteNeverFallsBackToTheTypedLogin` asserts the refusal, so 0023
inherits one fewer call site rather than one more.

### The mapping event, and what "no logging path" means

`DeviceEventSink` is declared in `internal/auth/target` and implemented in
`internal/logging`, mirroring `filter.Sink`. It is hung off the `Shipper`
rather than a `SessionRecorder` because neither event is really a session's: the
mapping event carries its session id as a *field* (it has to — on a constrained
platform it is the only thing tying an administrator name to a person), and a
sweep failure belongs to no session at all.

`Shipper.Deliverable()` is the predicate the fail-closed rule turns on, and its
definition matters: **a disk buffer is a logging path**. A record written to it
is owed to the server, not lost. Refusing sessions during a Control outage on a
proxy that is faithfully spooling to disk would be failing closed against the
wrong failure — which is exactly the distinction the acceptance criteria asked
for, and `TestConstrainedNameRefusesWithoutALoggingPath` has both halves.

Note that FortiOS's 35-character limit means **no shipped platform currently
takes the constrained path**. It is reached in tests through a `limitedDriver`
wrapper that declares a tighter limit than it has. That is worth knowing before
anyone reads the constrained scheme as dead code: it is the path every tighter
platform will take, and 0025 may well be the first real one.

### Proxy-enforced expiry removes the account, not the session

Under `expiry_posture: proxy-enforced` the provisioner schedules the account's
removal at its deadline (`enforceExpiry`). It removes the **account**, which is
what this method provisioned. Ending the **session** at the same moment is
prompt **0022**'s, and the two were deliberately not conflated: after the
deadline the session survives with a credential that no longer exists, which is
honest and incomplete, and 0022 is where it is completed.

### The e2e topology gained a node

`cmd/fake-device` serves `internal/sshtest`'s fake FortiOS on a real port. The
alternative was to declare this phase unrepresentable in the topology, and that
would have been the wrong call: "the devices are physical" is a permanent excuse
on a product whose entire claim is reaching gear nobody can put in CI.

It publishes `/debug/accounts` on loopback, in the shape `cmd/mock-control`
already uses, because an appliance has no account database to read and driving
its CLI to check the proxy's cleanup would mean asserting on the thing under
test. `testNoEphemeralLeak` now sweeps it too — where a leftover is a privileged
administrator rather than a shell account.

Two fixture routes were added: `fortigate.company.com` (a one-entry
`ephemeral-account` ladder — which since D14 is how a PDP says "this credential
or nothing") and `ladder.company.com`, whose first entry names a platform this
proxy has no driver for, so the fall-through is proven end to end.

**Two things the first CI run caught that no local check could**, both worth
knowing before adding a node to this topology:

- **A published port on an `internal` network is not reachable from the host.**
  The appliance debug endpoint was originally published as `127.0.0.1:18081`,
  the way `control` publishes its `/debug/logs` — but `control` is on `edge`
  *and* `core`, and the appliance is on `core` alone, which is `internal`. The
  fix is emphatically NOT to put the appliance on a routable network: that is
  the isolation the device scenarios depend on. Instead `cmd/fake-device` has a
  client mode (`-dump`) and the suite runs the same binary inside the container,
  which needs no network of its own and no `curl` in the image.
- **The device scenario used `ssh host cmd`, and the fake device refuses exec** —
  deliberately, because that is what many appliance SSH servers do and it is the
  reason the driver asks for a shell. The scenario now drives a shell with
  stdin, which is what an operator's session actually looks like. The fake also
  now sends an `exit-status`, without which an OpenSSH client reports 255 and
  every device session looks like a connection failure.

  Both are now pinned by unit tests in the `fortios` package
  (`TestAUserShellSessionReachesTheCLI`, `TestAnExecRequestIsRefused`) rather
  than only by the e2e suite, precisely because those run without Docker and
  would have caught this in the session that wrote it.

- **The fake device accepted only the management login**, so a driver could
  create an administrator it could never log in as — and every unit test in this
  phase asserted the account EXISTED without ever connecting as it, so nothing
  caught it. The proxy provisioned fine and then failed at `stageDial`: "the
  target could not be reached". The fake now also accepts any account in its own
  table with the credential that table holds, for both credential kinds, and
  `TestTheProvisionedAccountCanActuallyLogIn` dials the device with the
  `ClientConfig` the provisioner returned. **"The account exists" is not "the
  account works"** — worth remembering for 0024 and 0025, which will build the
  same kind of fake.

**The suite was not run locally.** Docker is unavailable in this session's environment,
as it was for phase 0013. The obligation was met the same way 0013 met it and
further: the whole `deploy/control/fixtures.template.yaml` was rendered and
loaded by the real `cmd/mock-control` binary, which decodes fixtures strictly
and reported `serving 2 users and 17 routes` (15 before this phase);
`test/topology/config_test.go` loads the changed proxy config with the proxy's
own loader and passes; and `go vet -tags e2e` covers the scenario code. What
has **not** been executed is the containers themselves — running `make e2e` is
the first thing the next session with Docker should do.

### A pre-existing bug this phase had to fix to get CI green

`internal/proxy/session.go`'s `close()` closed the target-leg connection
**before** waiting on `<-s.ready`, and `setup()` runs concurrently. A kill that
lands between a session registering and its target leg coming up therefore
found `legConn()` nil, waited for setup, and setup then established a leg that
**nothing ever closed**. The credential was still torn down — `access.Close`
runs after the wait — so the leaked connection was credential-less, but it was
live: a revoked session went on holding an SSH connection to the host it had
just been revoked from, and "the session was killed" has to mean the connection
is gone, not only the account.

`close()` now closes the leg on both sides of the wait, via an idempotent
`closeLeg()`.

It is **not** this phase's bug and it was not introduced here. It was found
because `TestAKilledSessionSaysSoImmediately` hangs when it happens — the fake
target's `Close()` waits on a handler goroutine that never exits — and measured
at **9 hangs in 25 runs on `origin/main`** against 15/15 passes with the fix. It
is fixed here rather than merely reported because it blocks this phase's
Definition of Done: a test that hangs a third of the time makes CI red for
whatever lands next, and the fix is two lines with no design question in it.

Worth knowing for whoever profiles this next: the first measurement of the same
test on `origin/main` came back 10/10 passing, which nearly filed this as
"introduced by 0014". Ten samples is not a flake rate.

### Follow-ups and loose ends

- **0024 and 0025 are queued** for the two FortiSwitch modes, in the order the
  user ranked them. 0024 owns a design question (what the target *is* when a
  switch is administered through a FortiGate) that is a contract change before
  it is a driver.
- **`docs/PLAN.md`'s phase table was missing a row for 0023**, which had been
  queued since 0013 without one. Adding 0024 and 0025 would have left a visible
  gap, so 0023's row was added at the same time.
- **The management password is read once at startup from the environment.** A
  device fleet with per-device credentials needs the `CredentialSource` seam
  `brokered-key` already has; nothing here precludes it, and no route needs it
  yet.
- **`RemoveAccount` cannot delete an administrator that is currently logged in
  on some FortiOS versions.** Not reproduced, not modelled in the fake device,
  and worth checking on hardware: if true, a session whose SSH connection
  outlives its teardown attempt would leave an account for the reaper — which
  finds it, but a cycle later than it should.
