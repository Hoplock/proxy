# 0015 — FortiOS driver corrections — Learnings

## Summary
- **What shipped:** the FortiGate driver's declared facts now match Fortinet's
  documentation. Three decisions were settled with the user; the driver refuses a
  multi-VDOM unit rather than mis-editing it; an IPv4 pin no longer leaves IPv6
  wide open; there is no default access profile; the name limit is 64. No
  contract change — `api/` untouched, so no cross-repo obligation
  (`docs/CROSS-REPO-PROTOCOL.md` §1: none of the shared surfaces is touched).
- **Key files:** `internal/auth/target/device/fortios/{doc.go,fortigate.go,cli.go,value.go,fortigate_test.go}`,
  `internal/sshtest/fortios.go`, `internal/config/config.go`,
  `config.example.yaml`, `deploy/proxy/proxy-direct.yaml`, `docs/PLAN.md`
  (D13, §5.3, §10).
- **The three decisions, and their reasoning:**
  1. **`EnforcesExpiry` stays FALSE — by decision, not by absence.** FortiOS
     *can* time-bound an administrator (`set schedule` → `config firewall
     schedule onetime`, denied at authentication). Taking it means a **second
     object per session** with its own name, teardown and orphan class; it denies
     login rather than removing the account, so it retires neither the reaper nor
     `PersistsAcrossReload`; and whether it cuts an established session is
     undocumented. Queued as **0028**.
  2. **A multi-VDOM unit is detected and REFUSED.** `get system status` is read
     when the CLI session opens and only `Virtual domain configuration: disable`
     is served — an unreadable answer is refused too. `fortios.ErrMultiVDOM` is
     deliberately **not** `device.ErrUnsupported`: that would skip the ladder rung
     and answer the shape of one unit with a weaker credential. Support is queued
     as **0027**, which shares 0025's target-identity question.
  3. **There is no default access profile.** The old default was chosen by
     ranking `super_admin_readonly` against `prof_admin_readonly`, which appears
     in no Fortinet source. `auth.target.ephemeral_account.access_profile` is now
     **required and checked at startup**.
- **Corrected `Capabilities`, and what each value now rests on:**
  `MaxAccountNameLen: 64` (the CLI reference's `name` parameter, read directly —
  was 35, a KB line about "most name fields"); `EnforcesExpiry: false` (decision
  1, not "the field does not exist"); `PersistsAcrossReload: true` +
  `PersistenceReason` (unchanged, re-verified); `CredentialKinds:
  [password, publickey]` (unchanged, re-verified); `PinsSourceAddress: true`
  (unchanged, but the driver now writes `ip6-trusthost1` too and refuses an IPv6
  source address).
- **Fortinet's documentation was REACHABLE from this session**, unlike phase
  0014's. `docs.fortinet.com` needed retries — the first CONNECT was reset — and
  `community.fortinet.com` answers on its redirect target. Its search endpoint is
  behind CloudFront and returns 403; fetch article URLs directly.
- **Hardware list — carried forward, in this phase's own words:** below, under
  "What still needs a real FortiGate". Four items.
- **What 0016, 0017, 0025 and 0026 must now assume differently:** see "What the
  next phases inherit". All four prompts were updated in place.

## Details

### The evidence, and why the re-check mattered

`docs/FORTIOS-DOC-VERIFICATION.md` is the durable record and this phase did not
re-derive it. What it *did* do, because the prompt asks the reachable case to
re-verify anything that changes behaviour, was read the pages behind claims 1, 2,
8, 9 and the multi-VDOM section again:

- `config system admin` (7.6.6 CLI reference) — `name` "Maximum length: 64";
  `schedule` "Maximum length: 35"; `accprofile` "Maximum length: 35";
  `password-expire` datetime; `trusthost1..10` `ipv4-classnet` default
  `0.0.0.0 0.0.0.0`; `ip6-trusthost1..10` `ipv6-prefix` default `::/0`;
  `vdom <name>` "Virtual domain(s) that the administrator can access", 79.
- "Create per-VDOM administrators" (7.6.4 Administration Guide) — the `config
  global` / `config system admin` / `set vdom` recipe verbatim, plus "must use
  either the `prof_admin` administrator profile, or a custom profile" and "when
  creating an administrator at the VDOM level, the `super_admin` administrator
  profile cannot be used".
- "Technical Tip: Admin user with super_admin_readonly Profile" — "From v7.4.x,
  the diagnostic commands cannot be run by the admin user with the
  `super_admin_readonly` profile, as this has been disabled under CLI permits",
  and the workaround is a custom profile.
- "Technical Tip: How to check for VDOM Enablement on a FortiGate" — this is
  where the detection mechanism comes from: `get system status` displays the
  "Virtual domain configuration" status, `disable` or `multiple`. Without this
  page the driver would have had to *probe* (send `config global` and see), which
  is a mutation-shaped question asked of a customer's firewall.
- The naming-rules KB — the 7.4/7.6 homoglyph restrictions (`a-z A-Z 0-9 _ -`,
  cannot begin with `-`, dots re-allowed in 7.4.5/7.6.1), which `accountNamePattern`
  sits inside, and `The string contains XSS vulnerability characters` with
  `Command fail. Return code -173`.

### Why the multi-VDOM answer is a refusal and not a fix

The prompt offered both and the user chose refusal, and the reasoning is worth
keeping because it is not "the fix is hard". The fix is a contract question: a
VDOM name has to come from somewhere, and where it comes from decides what the
audit record says the target *was*. Answering that inside a corrections phase
would have front-run 0025, which owns the same question for a FortiLink-managed
switch, and produced two answers to one question.

What the refusal is, precisely: `Driver.open` sends `get system status` and
`checkSingleVDOM` reads the "Virtual domain configuration" line. Anything but
`disable` is `ErrMultiVDOM`, and so is a line it cannot find at all. The
fail-closed direction on an unreadable answer is the whole lesson of this phase
applied to itself — the driver was previously *certain* about a device shape it
had never asked about, and a unit whose status output does not match is another
shape nobody has asked about.

It costs one command per CLI session, before anything is configured, on every
operation including the reaper's sweeps. That is deliberate: `edit`, `delete` and
`show system admin` at the top level of a multi-VDOM unit are all pointed at a
table this driver cannot vouch for, and a *removal* that succeeded against the
wrong scope is worse than a create that failed — it reads as success and leaves a
live privileged administrator that nothing will look for again.

### The fake device was the bug

`internal/sshtest/fortios.go` accepted every sequence the verification report
faults, which is why **the tests passed the whole time**. That is the sharpest
thing in this phase and it generalises: a fake more permissive than the device it
stands in for converts a driver bug into a green build.

What changed:

- A **VDOM mode** (`FortiOSOptions.VDOMMode`), and in it `config system admin` at
  the top level is refused while `config global` / `config system admin` works.
  The CLI's nesting is a **stack** now rather than a flag, which is what lets it
  tell those two apart at all.
- `get system status`, reporting the documented line.
- The name limit is 64, and `TestTheDeclaredNameLimitIsTheDocumentedOne` asserts
  the fake's constant and the driver's declaration are the same number — so a
  change to one is a failure rather than a drift.
- `trusthost1` is typed as `ipv4-classnet` and `ip6-trusthost1` as
  `ipv6-prefix`; both reject the other family. 0014's `<addr>/128`-into-an-IPv4-field
  would now fail a test.
- Three built-in profiles, not four. `prof_admin_readonly` was in this list,
  which meant the driver's default resolved happily against a profile the fake
  had invented.
- `Command fail. Return code -3` → `-1`. `-3` is not on Fortinet's documented
  table; the driver never branches on the code, but an invented example in the
  one place a reader takes one from is still an invented example.

**Where the real behaviour is unknown, the fake says so rather than guessing.**
Two comments in that file name their open question and are marked `UNVERIFIED`;
`grep -n UNVERIFIED internal/sshtest/fortios.go` finds them. The important one is
that nothing establishes what a real multi-VDOM unit does with `config system
admin` at the top level — the fake refuses it because that is the strictest
reading and the one that fails a driver bug rather than hiding it.

`TestTheFakeDeviceRejectsAnUnwrappedAdminTable` drives the fake directly over
SSH rather than through the driver. It has to: this driver now declines a
multi-VDOM unit, so nothing else here would notice if the fake went back to
accepting the unwrapped table, and phase 0027 inherits that strictness or
inherits nothing.

### The IPv6 gap, and the one value that is an inference

An account "pinned to the proxy's address" was pinned on IPv4 only.
`ip6-trusthost1..10` are parallel fields defaulting to `::/0`, so on any unit with
IPv6 management access the restriction the provisioner believed it applied did
not exist. Two changes:

- Pinning now writes `set ip6-trusthost1 ::/128` alongside `set trusthost1`.
- An IPv6 `SourceAddress` is **refused** with a sentence naming the limitation,
  rather than rendered as `<addr>/128` into an `ipv4-classnet` field.

`::/128` is the unspecified address and nothing else, so no host that can connect
matches it. That follows from what a /128 prefix means rather than from a
Fortinet statement about closing this field, and it is on the hardware list
below. It is the only value in this phase that is not quoted from a page.

The refusal is the honest half of the choice the report left open. Supporting an
IPv6-fronted proxy properly means writing the real address into `ip6-trusthost1`
*and* closing `trusthost1` against IPv4 — and the value that closes an
`ipv4-classnet` field is not documented anywhere this phase could check. Guessing
one is exactly the failure mode this phase exists to correct.

### Removing the default access profile

The user chose this over keeping `super_admin_readonly` with corrected
reasoning, and it is the more consequential of the two: it makes the method
refuse to start until an operator names a scope.

The layering is worth recording. `fortios.New` still **builds** with no profile —
a route may name its own, and phase 0017 is where that becomes the normal case,
so refusing at construction would turn a future normal into a startup failure.
`CreateAccount` refuses when neither the request nor the driver has one, before
anything is dialled. And `internal/config` refuses at **startup** when
`ephemeral_account` is configured without `access_profile`, because the
alternative is every session failing with the same error and nobody reading the
first one.

The error is a plain error, not `device.ErrUnsupported`. The platform scopes
administrators perfectly well; this proxy was never told which scope to use, and
a rung skipped over a configuration gap would serve the session on a credential
the server ranked lower.

`deploy/proxy/proxy-direct.yaml` had `access_profile: ""` with a comment saying
it was "deliberately left at the driver's default so the topology exercises what
a proxy actually ships with". What a proxy ships with is now "you choose", so the
topology names `super_admin_readonly`.

### What the next phases inherit

- **0016** — its access-profile survey was told it depends on 0014's learnings
  "and nothing else". It now depends on 0014's *as corrected*: three built-ins,
  not four; `prof_admin_readonly` is not real; `super_admin_readonly` cannot run
  `diagnose` from 7.4.x, which is a material limit on what a read-only session
  can actually do and belongs in the survey. The prompt was updated.
- **0017** — it was told to replace "the fixed access-profile default". There is
  no default to replace; what it replaces is a required proxy-wide setting. The
  prompt was updated.
- **0025** — its target-identity question is now explicitly shared with 0027, and
  whichever runs first binds the other. The prompt was updated.
- **0026** — it was told "FortiOS cannot expire an account, do not inherit that
  answer". FortiOS *can*; the driver declines to. It also inherits two
  FortiGate-specific behaviours it must re-establish rather than reuse: the VDOM
  check (a FortiSwitch reporting no such line would be refused by it) and the
  required access profile. The prompt was updated.

### Two things found in passing

- **PLAN §5.3's declaration table still said Hoplock drivers "must answer no" to
  persistence**, which D13 stopped being true of in phase 0014 and contradicts
  the same section's own prose two paragraphs later. Corrected — one line, and it
  is the kind of stale row a future session would have taken at face value.
- **There is no PLAN §14.** `docs/FORTIOS-DOC-VERIFICATION.md` and this phase's
  prompt both cite "§14 (the target estate)"; the estate is §13, UC1. Noted in
  the verification file rather than left to be rediscovered.

### What still needs a real FortiGate

No amount of documentation or fake-device work settles these. They are listed
here so the first session with hardware knows exactly what to try.

1. **Does a FortiGate's SSH server actually refuse a non-interactive `exec`
   request?** Every Fortinet-documented client uses an interactive shell and
   forces a PTY (`ssh -t -t`), paramiko needs `invoke_shell()`, and netmiko
   drives a shell throughout — so the driver's design is right either way. But
   Fortinet states nothing, and `doc.go`/`cli.go` now word it as the inference it
   is: **FortiOS requires a PTY and Fortinet documents only interactive-shell
   usage.** Test: open an exec channel and see whether it is rejected, accepted
   and silent, or served.
2. **What does `config system admin` do at the top level of a multi-VDOM unit?**
   A parse error, or something quieter that resolves somewhere unintended. The
   fake models it as an error, which is the strictest reading. If the real answer
   is "quietly succeeds against some other scope", phase 0015's refusal was
   load-bearing in a way nobody could prove and phase 0027 must know it.
3. **Does an established session survive its administrator's schedule window
   closing?** Fortinet documents the denial at authentication and says nothing
   about a live session. It decides whether the mechanism phase 0028 is queued for
   is a real target-enforced expiry or only a "no new logins after T".
4. **Does `set ip6-trusthost1 ::/128` actually close IPv6 access?** The reading is
   sound and it is a reading, not a quotation. Test: pin an account this way and
   try to reach it over IPv6. While you are there, find out what closes
   `trusthost1` against IPv4, which is what an IPv6-fronted proxy needs before
   `trustHost` can stop refusing.

Two more from 0014's own list are still open and were not touched here: whether
`RemoveAccount` can delete an administrator that is currently logged in, and
whether `abort` discards an uncommitted `config system admin` block on every
supported version (the *documentation* half of that one now checks out — the
Administration Guide's Subcommands table says `abort` "exits the command without
saving", and the `next`-commits boundary the driver already handles is explicit).

### Verification of this phase's own work

`go build ./...`, `go vet ./...`, `go vet -tags e2e ./...`, `go test ./...` and
`golangci-lint run` all pass locally (`golangci-lint`: 0 issues). The e2e
topology needs Docker, which is unavailable in this session as it was for 0013
and 0014, so `test/e2e` was not run; `test/topology`'s config test — which loads
the real `deploy/proxy/proxy-direct.yaml` through the proxy's own loader — passes,
and that is what would catch the `access_profile` change breaking the topology.
CI runs the rest.

Each new test was **mutation-checked** rather than assumed: removing the
`checkSingleVDOM` call and the `set ip6-trusthost1` step turns
`TestLifecycleAgainstTheDevice`, `TestAMultiVDOMUnitIsRefusedRatherThanMisconfigured`,
`TestEveryOperationRefusesAMultiVDOMUnit` and `TestAUnitThatWillNotSayIsRefused`
red. A test that cannot be made to fail is a test that was not checking anything —
which is, in one sentence, how phase 0014's fake device came to pass.
