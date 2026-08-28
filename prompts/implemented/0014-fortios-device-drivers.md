# 0014 — FortiOS device drivers: FortiGate and FortiSwitch

> New phase (privileged-access revision, PLAN §10). It implements what 0013's
> contract and seam describe. It comes **before** the enforcement-point survey
> (0015) because that survey ranks a FortiOS access profile against every other
> rung, and ranking it from memory is exactly the failure 0015 exists to avoid.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — **D13** (the method, the driver layer, the three replaced
  properties), **D14** (the ladder), §5.3 in full (the lifecycle, the
  declarations table, the naming rules, collision behaviour, the mapping event,
  the config-change position), §13 UC1.
- `docs/learnings/0013-…` — the `Driver` and `Capabilities` signatures, the
  registry's failure modes, the contract params. **Written from this summary
  alone**: if something you need is not in it, that is a finding for your own
  learnings, not a licence to guess.
- `docs/learnings/0007-…` — the POSIX provisioner, `ProvisionedAccess`,
  teardown guarantees, the reaper's contract, `principal.go`'s three-part
  naming and why each part exists. This phase mirrors its structure and must
  not diverge from it without saying so.

## Objective
Ship the first two drivers and the device provisioner: a session to a FortiGate
or FortiSwitch gets a short-lived administrator that exists only for its
duration, is attributable to the user who opened it, and is removed afterwards
whether or not this proxy survives.

## Before writing code: two things to establish, not assume

**Verify FortiOS behaviour against Fortinet's current documentation, not from
memory.** Every one of the following changes the driver, and each is cheap to
check and expensive to get wrong: the maximum administrator-name length; whether
an administrator can carry an SSH public key as well as a password; whether an
access profile can be assigned at creation; whether `trusthost` can pin the
account to the proxy's source address; which commands are needed to create and
delete an administrator and what each returns on failure; and whether the change
lands in running configuration only or is persisted. Record what you found, with
the doc reference, in your learnings — the next driver author and 0015's survey
both read it as fact.

**Ask the user about FortiSwitch management mode before designing its driver.**
A FortiSwitch in FortiLink mode is administered *through* its managing
FortiGate, not by direct SSH to the switch, which makes it a different driver
with a different target identity — possibly a route whose real target is the
FortiGate with the switch named as a parameter. A directly-managed switch is
nearly the FortiGate driver. This is a design fork, not a detail; `docs/PLAN.md`
§13 UC1 does not settle it and neither does this prompt. Per `PROTOCOL.md` §9,
stop and ask rather than guessing. If the answer is "FortiLink", it is
legitimate to ship the FortiGate driver in this phase and queue the switch as
its own prompt — say so in the PR rather than half-building it.

## In scope

### 1. The drivers (`internal/auth/target/device/fortios`)

One driver per platform value, each implementing 0013's `Driver` and declaring
its `Capabilities` from what you verified above. Requirements that come from
this being a CLI over SSH rather than a shell:

- **A prompt/response state machine**, not a command pipe. Paging, a
  configuration mode with its own prompt, and error text that arrives as output
  rather than as an exit status all have to be handled explicitly. Borrow the
  discipline in `internal/auth/target/script.go`: every value interpolated into
  a command is validated and quoted at the boundary, belt and braces, because
  the target is a configuration parser and a mis-escaped value is a
  configuration change nobody asked for.
- **Never persist the account to saved configuration** (D13). This is an
  invariant with a test, not a convention: the driver declares
  `PersistsAcrossReload: false` and 0013's registry test enforces that a shipped
  driver may not declare otherwise, so a change that starts writing memory must
  fail loudly.
- **Idempotent removal.** Teardown runs on normal close, error, panic, and
  signal (§5.1's rule, unchanged), so removing an account that is already gone
  is success, and removing one that cannot be reached is a retryable failure the
  reaper will find again.

### 2. The device provisioner (`internal/auth/target`)

A `TargetAuthenticator` for `ephemeral-account`, structured like the
`ephemeral-user` provisioner and sharing everything shareable with it:

- **Naming under a declared limit**, exactly as PLAN §5.3 specifies: the §5.1
  scheme at *X* ≥ 32; `hl-` + 4-char proxy tag + (*X*−7)-char token, base36, for
  11 ≤ *X* < 32; refusal below 11. `principal.go` currently hard-codes
  `maxPrincipalLen = 32` and a 14-character login segment — generalise it over a
  declared limit without changing what it produces on Linux, and keep its
  existing tests green as the proof.

  **Do not entrench where the login segment's value comes from.** Today
  `ephemeral.go` resolves it as `p.str(ParamUsername, id.Login)` and hands the
  result to `newPrincipal`, and that `id.Login` fallback is a **known defect**:
  `internal/identity/identity.go` says `Login` is what the user typed at their
  SSH client and "must never be the basis of an authorization decision", which
  choosing an account name is. **Prompt 0023 owns closing it**, for every method
  at once, and it closes it here too precisely because you are about to share
  this function rather than fork it.

  So: take the account name you are handed, thread it through, and **add no
  second reader of `id.Login`** — not in the device provisioner, not in a
  generalised `newPrincipal`, not as a "temporary" default. `ephemeral-account`
  already requires `username` on the route (contract v3), so nothing you write
  needs a fallback at all. If you find yourself wanting one, that is the finding
  0023 exists for: say so in your learnings rather than writing it.
- **Collision retry, never adoption** (§5.3). The POSIX path's idempotent
  "already exists" is unsafe here: verify non-existence, retry with a fresh
  token on collision, refuse after a small budget.
- **The expiry posture** from the route (D13): target-enforced where the driver
  declares it can, proxy-enforced where it cannot, `accepted-risk` only when the
  route says so. A posture the driver cannot satisfy is a **skipped ladder
  entry**, not a downgrade — the proxy moves to the next `target_auth` entry and
  records which one it used.
- **The mapping event on the priority path** (§5.3, D8): account name, session
  id, subject, target, platform, method used, expiry posture. On a constrained
  platform this is the only place attribution exists, so a route whose driver
  declares a constrained limit is **refused when no logging path is available at
  all**, disk buffer included.
- **Credential handling** follows §5.2's rule, generalised: a generated password
  never touches disk, never appears in a log, an error, or a config file, and is
  zeroed on teardown. It *will* appear in the device's own configuration and
  AAA logs — that is the device's record, it is out of our control, and the
  learnings should say so plainly rather than implying otherwise.

### 3. The device reaper

The orphan reaper (§5.1) extended over the driver's enumerate operation. Its
existing guarantees hold unchanged — the proxy-tag prefix scopes a sweep to this
proxy's accounts, a live account is never swept whatever its age, an untracked
one is swept past a grace period, and the first successful provisioning on a
target triggers a rate-limited background sweep of it.

Two things are new and both are consequences of D13, not new policy:

- On a platform where expiry is not target-enforced, **the reaper is the primary
  removal path**, not a crash-recovery backstop. Its cadence and its failure
  reporting should be sized for that: a reaper that quietly fails on a device
  leaves a live privileged account, and nobody finds out.
- A customer driver may declare `PersistsAcrossReload`. Sweeping such a platform
  cannot rely on a reload having cleaned up, which is the assumption a Hoplock
  driver is allowed to make.

### 4. Test support

A **fake FortiOS device** in `internal/sshtest`, in the spirit of the existing
in-process SSH target: it speaks enough of the CLI to accept, reject, and
enumerate administrators, and can be told to fail in the ways the real thing
does (an unreachable device mid-teardown, a name-length rejection, a collision,
a config-mode error). CI must not need a real appliance.

## Out of scope
- The declarative driver document and the subprocess contract (D13). Structure
  the two drivers so their command sequences are *data* where that is natural —
  the declarative format is meant to be extracted from them later, not
  retrofitted against them — but do not build the format here.
- Any enforcement rung, including access profiles as a *policy* choice. This
  phase may set an access profile because an administrator needs one; **which**
  profile a route gets is 0015's vocabulary and 0016's application. Use the
  most restrictive workable profile as a fixed default and say so in the
  learnings, so 0016 knows what it is replacing.
- Any driver beyond FortiOS.
- Contract changes. If you need a field, it is 0013's and per
  `CROSS-REPO-PROTOCOL.md` §3.2 that is upstream work with its own prompt — not
  a favour done in passing.

## Acceptance criteria
- Both drivers (or the FortiGate driver plus a queued prompt for the switch, per
  the FortiLink question above) implement `Driver`, and their declared
  `Capabilities` match what the verification step found, with the doc reference
  in the learnings.
- Against the fake device: a session provisions, connects, and tears down; a
  crash between create and connect leaves an account the reaper removes; two
  concurrent sessions for one login get different accounts and neither teardown
  affects the other; a collision retries and succeeds; a name that cannot fit
  the declared limit refuses the route rather than truncating.
- The naming generalisation produces byte-identical names on the Linux path —
  `internal/auth/target`'s existing principal tests pass **unmodified**.
- A route whose driver declares a constrained limit is refused when logging is
  entirely unavailable, and served when only the network destination is down
  (the disk buffer counts).
- A ladder of `[ephemeral-account, brokered-key]` falls through to
  `brokered-key` when the platform is unknown or the posture unsatisfiable, and
  the audit record names the entry that was used (D14).
- No credential material appears in any log line, error string, or test golden
  file. Add the assertion, do not rely on review.
- `go build ./... && go vet ./... && go test ./...` and `golangci-lint run` pass.

## The e2e topology obligation

Phase 0012 built the five-node topology in `deploy/` and the scenario suite in
`test/e2e` (see its learnings, and `deploy/README.md`). **A phase that changes
what a session can do owes it a scenario there** — a change proven only by unit
tests is a change nobody has watched a real SSH client survive.

Concretely: add the route to `deploy/control/fixtures.template.yaml` (that file
is the **mock** Hoplock Control's fixtures inside this repository's test rig —
it is not the sibling Control repo, which vendors only `api/control.yaml`), and
add a subtest to `TestTopology` in `test/e2e/scenarios_test.go`. Each fixture
route names the scenarios it backs, so a failing scenario leads to one rule
rather than to a search — keep that up.

Two things that will bite:

- `TestTopology`'s subtests are **ordered deliberately**. The telemetry
  assertions read what earlier scenarios produced, the outage scenario stops
  Hoplock Control, and the ephemeral-leak check runs last so it sees everything.
  New groups go before the outage scenario.
- `sshBaseArgs` in `test/e2e/harness_test.go` is shared by every scenario.
  Changing it changes all of them at once; pass per-scenario options instead.

If this phase genuinely cannot be represented in the topology, **say so
explicitly in the learnings and say why**. "No e2e scenario" is a finding worth
writing down; an omission is indistinguishable from an oversight.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0014-fortios-device-drivers-learnings.md`. The summary block MUST
carry: the verified FortiOS facts and where they came from, the declared
`Capabilities` for each platform, what an access profile can and cannot
constrain (0015's survey depends on this and on nothing else), the naming
generalisation's shape, and the reaper's changed role where expiry is not
target-enforced.
