# 0026 — FortiOS driver: correct what 0014 could not verify

> Phase 0014 established its FortiOS behaviour from **web-search summaries**,
> because `docs.fortinet.com` and `community.fortinet.com` were blocked by that
> session's egress policy. It said so honestly in its learnings and asked the
> next author on a reachable network to re-check the list. That check has now
> been done and is in **`docs/FORTIOS-DOC-VERIFICATION.md`**: six of ten claims
> hold, three are wrong, one is true but undocumented — and reading the same
> pages surfaced a gap none of the claims covered, **multi-VDOM**, which the
> driver does not handle at all.
>
> This phase acts on that report. It is not a rewrite: the CLI state machine,
> the value validation and the provisioner seam were all built on claims that
> survived. What changes is a set of declared facts that turned out to be false,
> two of which the contract reasons about.

**Ordering.** This prompt is numbered after the existing queue, but its findings
feed **0015** (whose access-profile survey the 0014 learnings say "depends on
this and nothing else"), **0016** (which replaces the fixed access-profile
default), and **0024**/**0025** (which inherit 0014's FortiOS facts wholesale
and reuse its CLI state machine). Running it late means those phases build on
the errors this one removes. Per `docs/PROTOCOL.md` §6, ask the user whether to
renumber the queue so this runs first, and do not begin until that is settled.

## Read first
- `docs/PROTOCOL.md` — session workflow, and §6 on prompt numbering.
- **`docs/FORTIOS-DOC-VERIFICATION.md`** — the evidence base for this entire
  phase. Every finding below is stated there with the Fortinet page it came
  from, the FortiOS versions it was checked against, and an explicit note where
  the evidence is circumstantial rather than documented. Read it before the
  code; it will save you re-deriving all of it.
- `docs/PLAN.md` — **D13** (and the amendment 0014 made to it), **D14**'s
  ladder, §4.2 `ephemeral-account` parameters, §5.3 in full, §13 UC1, §14 (the
  target estate — it is why multi-VDOM matters).
- `docs/learnings/0014-fortios-device-drivers-learnings.md` — in full, including
  its "How these were verified, and the caveat that goes with it" section, which
  this phase closes out.
- `docs/learnings/0013-…` — the contract shapes and the registry's failure modes.
- `docs/CROSS-REPO-PROTOCOL.md` — **required if you change `api/`**, §3.2 in
  particular. Two of the design questions below may reach the contract; do not
  skip the Section 1 check on the assumption that they will not.

## Objective

The FortiGate driver declares only things that are true of FortiOS, and works on
a multi-VDOM unit or says plainly that it does not. Where a corrected fact opens
a capability the driver previously declared it lacked, the decision to take that
capability — or to decline it — is made deliberately, with the user, and written
down.

## What is already established

Do not re-derive these; `docs/FORTIOS-DOC-VERIFICATION.md` carries the sources
and the version coverage (7.0.17, 7.2.11, 7.4.9, 7.6.6, 8.0.0 unless noted).

**Wrong, and the contract reasons about it:**

- **`config system admin` has per-administrator expiry controls.** Both
  `set password-expire {datetime}` and `set schedule {string}` exist. `schedule`
  is enforced at authentication — Fortinet's own KB shows the denial logged as
  `reason="out_of_schedule"` — and it can point at a `config firewall schedule
  onetime` entry carrying an absolute `set end {hh:mm yyyy/mm/dd}`. So a
  FortiGate **can** time-bound an administrator by itself. It denies *login*; it
  does not delete the account, and `password-expire` is a forced password change
  rather than an account expiry.
- **`prof_admin_readonly` could not be found in any Fortinet source.** Three
  built-ins are documented, not four: `super_admin` (immutable), `prof_admin`
  (editable), `super_admin_readonly` (immutable, assignable, absent from the GUI
  profile list). Also unrecorded by 0014: **from v7.4.x an administrator with
  `super_admin_readonly` cannot run `diagnose` commands.**

**Wrong, but inert:**

- **The administrator name field is 64 characters, not 35.** The 35 came from a
  naming KB's general "most name fields" line; it is the correct figure for
  `accprofile` and `schedule`, not for the admin name. Both clear PLAN §5.3's
  threshold of 32, so the naming-scheme choice is unaffected.
- **Two error-string details.** `-3` is not a documented return code, and the
  guide's canonical parse error is `Command parse error before '…'`. Both are
  comment-level; `errorPatterns` already matches what the device actually sends.

**Correct, and needs no work:** the password-and-three-keys model with
device-wide `admin-ssh-password`; paging (`set output more` by default, global,
permanent, no per-session override — netmiko saves and restores it for exactly
this reason); `cfg-save automatic` writing to flash; `abort` semantics,
*including* the boundary the driver already handles correctly at
`fortigate.go:238`; and `trusthost1` with its `0.0.0.0 0.0.0.0` default.

**A gap no claim covered — multi-VDOM.** `vdom` appears nowhere in the package.
The Administration Guide's recipe for creating an administrator on a multi-VDOM
unit is not the sequence the driver sends:

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

Three consequences, in descending confidence: the `config global` wrapper is
missing and `cliSession.Close` (`cli.go:251`, `"end\nend\nexit\n"`) unwinds one
level shallower than that nesting needs; `set vdom` is never sent, though the
public-key procedure lists it as required under multi-VDOM; and per-VDOM
administrators "must use either the `prof_admin` administrator profile, or a
custom profile", which the shipped default is not.

**A second restriction that is IPv4-only.** `ip6-trusthost1..10` exist and
default to `::/0`. The driver writes only `set trusthost1`, so an administrator
"pinned to the proxy's address" is reachable from any IPv6 address on a unit
with IPv6 management access. Worse, `trustHost()` renders an IPv6 source as
`<addr>/128` and `Provision` writes it unconditionally into `set trusthost1`,
which is an `ipv4-classnet` field.

## Before writing code: check whether you can reach the sources

The verification session could reach both Fortinet sites. Yours may not — that
is exactly how 0014 got here. Check first, and say in your learnings which
situation you were in.

- **If reachable:** re-verify anything whose answer changes behaviour you are
  about to write, particularly the multi-VDOM sequence and the schedule
  mechanism. The report names the pages.
- **If blocked:** treat `docs/FORTIOS-DOC-VERIFICATION.md` as the durable record
  and work from it. Do **not** fall back to web-search summaries to fill gaps —
  that is the failure mode this phase exists to correct. An unanswerable
  question becomes a recorded open question, not a guess.

## The design questions this phase owns

Settle these **with the user before writing code**, and write the reasoning into
`docs/PLAN.md`. Each changes what the contract means, not just what the driver
types.

### 1. Does FortiOS now qualify for `EnforcesExpiry: true`?

`deviceaccount.go:353` turns a route asking for
`control.ExpiryPostureTargetEnforced` into a skipped rung when
`caps.EnforcesExpiry` is false. That gate was correct given a false premise.
The honest answer is now genuinely arguable, and the argument has a cost on both
sides:

- The schedule mechanism **denies login after T**, which is what a target-enforced
  posture is usually bought for. But it does not remove the account, so the
  reaper stays mandatory and `PersistsAcrossReload` is untouched.
- Taking it means the driver must **create a second object per session** — a
  `config firewall schedule onetime` entry — then reference it from the
  administrator. That is a new object to name (the field caps schedule names at
  35, so PLAN §5.3's naming scheme applies to it too), a new object to tear
  down, and a **new leak class** for the reaper to sweep. An orphaned schedule
  object on a customer's firewall is a smaller problem than an orphaned
  administrator, but it is not nothing.
- Fortinet documents the denial at authentication time and says nothing about
  what happens to an **already-established** session when the window closes. If
  target-enforced expiry is meant to cut a live session, that is unverified.

Decide, and record it. `EnforcesExpiry: false` remains defensible — but it must
be false *because you decided the mechanism does not meet the bar*, with that
reasoning written down, not because the field was believed not to exist.

### 2. Is a VDOM part of target identity?

This is the same shape as **0024**'s question and should be answered
consistently with it. A VDOM name has to come from somewhere: a new
`auth.target.ephemeral_account` parameter, the route's target, or the platform
value. It decides what the audit record says the target was, and what a policy
author writes in Hoplock Control.

Answer the prior question first, though: **does this phase support multi-VDOM at
all, or does it detect and refuse it?** A driver that fails clearly on a
multi-VDOM unit is far better than today's silent mismatch, and may be the right
scope here with full support deferred to its own phase. Note that D13's rule
holds either way — an unsupported configuration is an outage-class denial, never
a best-effort attempt.

### 3. What is the default access profile, per unit shape?

`DefaultAccessProfile = "super_admin_readonly"` (`fortigate.go:47`) is sound on a
single-VDOM unit and its stated rationale survives verification. On a multi-VDOM
unit it does not fit a VDOM-scoped account, and the obvious narrower substitute
is the profile that appears not to exist. There may be **no built-in read-only
profile usable for a per-VDOM account**, which would make a custom `accprofile`
a prerequisite rather than an option — a real operator burden that belongs in
the docs whichever way you go. Coordinate with 0016, which replaces this default
with policy.

## In scope

- The three decisions above, settled with the user and recorded in `docs/PLAN.md`.
- Any contract change they imply — upstream first, per
  `docs/CROSS-REPO-PROTOCOL.md` §3.2, including the sync kickoff its §4 asks you
  to hand the user for each affected repository.
- **Corrections to the declared facts**, wherever they appear:
  `internal/auth/target/device/fortios/{doc.go,fortigate.go,value.go}`,
  `docs/learnings/0014-fortios-device-drivers-learnings.md` (including its
  verification caveat, which this phase closes), and `docs/PLAN.md` D13/§5.3.
  The comments in this package carry unusual weight — they are the reason
  another author trusts a declared capability — so correct the *reasoning*, not
  only the value.
- **The IPv6 trusthost gap.** Either set `ip6-trusthost1` alongside
  `trusthost1`, or refuse an IPv6 `SourceAddress` explicitly. What is not
  acceptable is today's behaviour: writing a `/128` into an IPv4 field, and
  leaving `::/0` standing while the provisioner believes the account is pinned.
- **The fake device**, per the obligation below.
- `maxAccountNameLen`: correct the stated fact. Keeping 35 as a deliberate
  narrowing is fine — say so, and say why, rather than citing a limit that is not
  the limit.

## Out of scope

- The FortiSwitch drivers — **0024** and **0025**.
- Which access profile a route *gets*: 0015's vocabulary, 0016's application.
  This phase fixes the default and the facts under it, not the policy.
- The declarative driver document and the subprocess contract (D13).
- Anything requiring real hardware. Record it (below); do not simulate it and
  call it verified.

## The fake device obligation

`internal/sshtest/fortios.go` accepts every sequence this report faults. That is
the sharpest lesson available here: **the tests passed the whole time.** A fake
that is more permissive than the device it stands in for converts a driver bug
into a green build.

Tighten it so the corrected behaviour is actually pinned:

- Model multi-VDOM as a mode the fake can be put into, and in that mode **reject
  `config system admin` outside `config global`** — so a driver that forgets the
  wrapper fails a test instead of a customer's firewall.
- Enforce the real name limit on `edit`, and the real error text on breach.
- If the expiry decision takes the schedule mechanism, model
  `config firewall schedule onetime` and let a test assert that teardown removes
  **both** objects and that the reaper sweeps an orphaned schedule.
- Keep it honest about what it does not know: where the report says the real
  behaviour is unverified, the fake should not invent one — leave a comment
  naming the open question rather than encoding a guess as fact.

## Acceptance criteria

- Every claim `docs/FORTIOS-DOC-VERIFICATION.md` marks wrong is either corrected
  in the code and docs, or deliberately retained with the reasoning recorded.
  No declared fact in the package contradicts the report.
- The three decisions are in `docs/PLAN.md` with their reasoning.
- Against the fake device: a multi-VDOM unit either provisions correctly or is
  refused with a clear, outage-class error — never a silent mismatch; an IPv6
  `SourceAddress` either pins IPv6 or is refused; teardown removes everything
  provisioning created.
- A test fails if the `config global` wrapper is dropped, and a test fails if the
  name limit regresses.
- `go build ./... && go vet ./... && go test ./...` and `golangci-lint run` pass.

## What needs hardware, and must survive this phase as an open question

Three things no amount of documentation or fake-device work can settle. Carry
them forward explicitly rather than letting them evaporate:

1. Whether a FortiGate's SSH server truly refuses a non-interactive `exec`
   request. Every Fortinet-documented client uses an interactive shell and
   forces a PTY, and the driver's design is right either way — but the absolute
   claim in `doc.go`/`cli.go` is an inference, and should be worded as one until
   tested.
2. What `config system admin` at the top level of a multi-VDOM unit actually
   does — parse error, or something worse.
3. Whether an established session survives its administrator's schedule window
   closing.

Put these in your learnings summary as a named list, so the first session with
access to a real FortiGate knows exactly what to try.

## Definition of Done & hand-off

Per `docs/PROTOCOL.md`. Move this prompt to `implemented/`; add
`docs/learnings/0026-fortios-driver-corrections-learnings.md`. The summary block
MUST carry: the three decisions and their reasoning; the corrected
`Capabilities` and what each value now rests on; whether you could reach
Fortinet's documentation; the hardware list above; and a plain statement of what
0015, 0016, 0024 and 0025 must now assume differently from what 0014's learnings
told them.
