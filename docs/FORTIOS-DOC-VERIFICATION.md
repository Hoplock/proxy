# FortiOS driver claims — verification against Fortinet's documentation

Phase 0014 shipped `internal/auth/target/device/fortios` with its FortiOS facts
established from **web-search summaries** of Fortinet's documentation, because
`docs.fortinet.com` and `community.fortinet.com` were blocked by that session's
egress policy. `docs/learnings/0014-fortios-device-drivers-learnings.md` records
that caveat honestly and asks the next author on a reachable network to check
the list.

This is that check. Both sites were reachable from this session and every page
below was read directly. **Findings only — no code was changed.**

> **Acted on by phase 0015.** Every finding below has been either corrected in
> the code and docs or deliberately declined with the reasoning recorded; see
> `docs/learnings/0015-fortios-driver-corrections-learnings.md` and
> `docs/PLAN.md` §5.3 ("As corrected (phase 0015)"). This file stays as the
> evidence base — the pages, the versions and the wording — and is not rewritten
> as the driver changes. Phase 0015 re-read the pages behind claims 1, 2, 8, 9
> and the multi-VDOM section from a session that could also reach both sites,
> and every one of them held as written here.
>
> Two corrections to this file's own text, neither affecting a verdict: the
> estate it attributes to "PLAN §14" is **PLAN §13, UC1** — there is no §14 —
> and the naming-rules KB gives **32** characters for "schedule names" where the
> CLI reference gives 35 for `system admin`'s `schedule` field, which phase 0028
> will have to reconcile.

Unless a row says otherwise, each finding was checked in the FortiGate CLI
reference / Administration Guide for **7.0.17, 7.2.11, 7.4.9, 7.6.6 and 8.0.0**
and is identical in all five. FortiOS 6.4 and earlier are end-of-support and
were not checked.

## Verdicts

| # | Claim | Verdict |
| --- | --- | --- |
| 1 | Admin name ≤ **35** chars | ❌ **Wrong** — the field is **64** |
| 2 | No per-admin expiry or schedule field | ❌ **Wrong** — both `password-expire` and `schedule` exist |
| 3 | Password + up to 3 SSH keys; `admin-ssh-password` device-wide | ✅ Correct |
| 4 | Console defaults to `more`; permanent, device-wide, no per-session override | ✅ Correct |
| 5 | Failures as output text, no exit status | ✅ Correct in substance; two string details off |
| 6 | `cfg-save automatic` writes to flash on `end`; `manual`/`revert` device-wide | ✅ Correct |
| 7 | `abort` discards the uncommitted block | ✅ Correct, with a boundary worth naming |
| 8 | Four built-in profiles incl. `super_admin_readonly` / `prof_admin_readonly` | ⚠️ **Partly wrong** — three documented, the fourth unverifiable |
| 9 | `trusthost1` pins source; unset defaults to `0.0.0.0 0.0.0.0` | ✅ Correct |
| 10 | FortiGate SSH does not serve a non-interactive exec request | ⚠️ **Almost certainly true, but not documented by Fortinet** |

The two claims that change the design are **2** and **8**. Claim **1** is wrong
but harmless. Claims **7** and **10**, which the author flagged as least
certain, both hold up.

Reading the same pages also turned up something none of the ten claims covers
and the driver does not handle at all: **multi-VDOM**. It is written up after
claim 10, and on the estate PLAN §14 describes it is likely to outrank
everything in the table above.

---

## 1 — Administrator name length: **wrong (35 → 64)**

`config system admin`, parameter table:

```
name | User name. | string | Maximum length: 64
```

Source: [`config system admin`, FortiOS 7.6.6 CLI reference](https://docs.fortinet.com/document/fortigate/7.6.6/cli-reference/390485493/config-system-admin)
— identical in 7.0.17, 7.2.11, 7.4.9 and 8.0.0.

The **35** figure comes from the naming-rules KB, which says "Most name fields
accept 35 characters" and then lists exceptions
([Technical Tip: Naming rules and character restrictions](https://community.fortinet.com/t5/FortiGate/Technical-Tip-Naming-rules-and-character-restrictions/ta-p/196911)).
That is general guidance about *most* fields, not this field. Where 35 *is*
right is `accprofile` (`Maximum length: 35`) and `schedule` (`Maximum length:
35`) — so `value.go`'s `profilePattern` cap of 35 happens to be exactly correct
for the profile name.

**Consequence: none for behaviour.** `maxAccountNameLen = 35` is merely
conservative. Both 35 and 64 clear PLAN §5.3's threshold of 32, so FortiOS still
gets the readable naming scheme and the constrained scheme is still exercised
only by tests. What is wrong is the stated fact in `value.go`, `doc.go` and the
learnings table, not the code's behaviour.

**Version-dependent detail the driver gets right for the wrong reason:**
character restrictions on administrator names were added in **7.4.0 / 7.6.0** to
defeat homoglyph attacks (`a-z A-Z 0-9 _ -`), are enforced on new and renamed
accounts but not on pre-upgrade ones, and dots were re-allowed in **7.4.5 /
7.6.1**. `accountNamePattern` sits inside every one of those rule sets, as
`value.go` claims.

## 2 — Per-administrator expiry: **wrong, and this one matters**

`config system admin` has **both** of the fields the driver says do not exist:

```
password-expire | Password expire time.                              | datetime | default 0000-00-00 00:00:00
schedule        | Firewall schedule used to restrict when the        | string   | Maximum length: 35
                | administrator can log in. No schedule means no
                | restrictions.
```

Source: [`config system admin`, 7.6.6 CLI reference](https://docs.fortinet.com/document/fortigate/7.6.6/cli-reference/390485493/config-system-admin).
Both are present in 7.0.17 through 8.0.0.

`set schedule` is **enforced by the device**, not advisory. Fortinet's KB
([Technical Tip: Configure a schedule for FortiGate administrator](https://community.fortinet.com/t5/FortiGate/Technical-Tip-Configure-a-schedule-for-FortiGate-administrator/ta-p/388195),
scope v6.4–v7.6) shows the configuration and the resulting authentication
failure:

```
config system admin
    edit "administrator"
        set schedule "Schedule_9_to_16"
    next
end
```
```
logdesc="Admin login failed" user="midnight" action="login" status="failed"
reason="out_of_schedule"
msg="Administrator midnight login failed ... because of wrong time schedule"
```

And the schedule it points at can be a **one-time** schedule with an absolute
end date and time:

```
config firewall schedule onetime
    edit <name>
        set start {hh:mm yyyy/mm/dd}
        set end   {hh:mm yyyy/mm/dd}     # "Schedule end date and time, format hh:mm yyyy/mm/dd"
    next
end
```

Source: [`config firewall schedule onetime`, 7.4.1 CLI reference](https://docs.fortinet.com/document/fortigate/7.4.1/cli-reference/265620/config-firewall-schedule-onetime).

So a FortiGate **can** time-bound an administrator by itself.

**What this does and does not give you — stated precisely, because the
distinction is the whole design question:**

- It **denies login** after the window closes. It does **not** delete the
  account, so the reaper is still required for removal and
  `PersistsAcrossReload` is unaffected.
- Fortinet documents the failure at authentication time. Nothing in the
  documentation says an *already-established* session is torn down when the
  window closes; that would need testing on hardware.
- `password-expire` is **not** an account expiry. Password expiration forces a
  password change at next login — "If your password does not meet the
  requirements, you must change your password before you can log in to the GUI
  or CLI" ([Password policy, 8.0.0](https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/364729/password-policy)).
  It blocks *use of the old password*, which for a proxy-held ephemeral
  credential is close to expiry in effect, but it is a different mechanism and
  should not be described as one.

**What rests on this being wrong:** `Capabilities.EnforcesExpiry: false`, the
comment at `fortigate.go:114` ("there is no `set expiry`, and `config system
admin` has no schedule" — the second half is flatly contradicted), the decision
to accept and discard `req.Lifetime` at `fortigate.go:196`, the treatment of
`control.ExpiryPostureTargetEnforced` as a **skipped ladder rung**, and the
learnings claim that the reaper is the *primary* removal path rather than a
backstop. A target-enforced expiry posture appears to be reachable on FortiOS
via `config firewall schedule onetime` + `set schedule`, at least in the
"device refuses new logins after T" sense. Whether that meets the contract's bar
for `EnforcesExpiry` is a design decision, not a documentation question — but it
should be made knowing the field exists.

## 3 — Password *and* SSH keys: **correct**

- Three key slots: `set ssh-public-key1|2|3 {user}` in `config system admin`,
  present 7.0.17 → 8.0.0. Nothing marks them mutually exclusive with `password`.
- They coexist by design. Fortinet's own procedure sets both in one `edit`, and
  says so: "A password must be set for backup. Since the objective is to login
  with a private key, you may want to assign a long random string as the
  password."
  ([Public key SSH access, 7.6.6](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/813125/public-key-ssh-access))
- Disabling password login is device-wide: `config system global` /
  `set admin-ssh-password disable` "disables SSH password-based access to ALL
  admin accounts, not only specific ones", and does not affect console access
  ([Technical Tip: How to limit the authentication mechanism that SSH uses to only use 'key-files'](https://community.fortinet.com/t5/FortiGate/Technical-Tip-How-to-limit-the-authentication-mechanism-that-SSH/ta-p/252976)).
  The driver never touching it is right.

Key types accepted: RSA, ECDSA and **EdDSA** (`ssh-ed25519`). Worth noting
against `value.go`'s `validatePublicKey`, which accepts `ssh-` and `ecdsa-`
prefixes — that covers `ssh-rsa`, `ssh-ed25519` and the `ecdsa-sha2-*` forms, so
it is correct, but by prefix accident rather than by the documented list.

Not mentioned in the driver: `set ssh-certificate` also exists, for
certificate-based administrative authentication.

## 4 — Paging: **correct**

- Default is `more`: `config system console` / `set output [standard|more]`,
  parameter table gives default **`more`**
  ([`config system console`, 8.0.0](https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/141236613/config-system-console)).
- The pager and its marker are documented: "By default, the CLI will pause after
  displaying each page worth of text… When the display pauses and shows
  `--More--`…", with `config system console` / `set output standard` given as
  the only way to turn it off
  ([CLI basics, 8.0.0](https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/896276/cli-basics)).
- Device-wide and persistent, in Fortinet's own words: "This setting is **global**
  and, as such, can have unintended consequences for other administrators,
  especially on a serial console."
  ([Technical Tip: CLI command console output mode](https://community.fortinet.com/t5/FortiGate/Technical-Tip-CLI-command-console-output-mode/ta-p/190475))

No per-session override is documented in any version checked. Independent
corroboration that this is a real constraint rather than an oversight: netmiko's
FortiOS driver reads the global value, sets `standard`, and **restores the
original on disconnect** precisely because it is global state it has borrowed
([`netmiko/fortinet/fortinet_ssh.py`](https://github.com/ktbyers/netmiko/blob/develop/netmiko/fortinet/fortinet_ssh.py)).
The driver's decision to page through `--More--` instead of mutating a
customer's device is well founded.

Two details `cli.go` does not record and might want to:

- The setting governs `show`, `get` and `?` output. **Debug and sniffer output
  are not affected** (same KB) — so a future `diagnose`-driving path cannot
  assume the pager is the only framing.
- Changing it requires a sufficiently privileged profile; netmiko notes it "is
  only available with specific roles so it may fail". An account created with
  this driver's default profile could not turn paging off even if it wanted to.

## 5 — Failure reporting: **correct in substance, two string details off**

Correct and documented verbatim:

> "CLI error codes are shown in the command line if the command execution fails.
> The message includes a summary, followed by `Command fail. Return code -X`."

([CLI error codes, 8.0.0](https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/257686/cli-error-codes))

Two corrections:

- **`-3` is not a documented return code.** The table lists `1, -1, -4, -5, -8,
  -37, -56, -61, -160, -553, -651`. `doc.go` and the learnings file both use
  "Return code -3" as their example. Harmless — `cli.go` reports the code and
  never branches on it, which the same page justifies — but the example is
  invented.
- The documented parse-error example is **`Command parse error before 'test'`**,
  not `value parse error before …`. Both strings are real: `value parse error
  before '<x>'` appears in Fortinet KBs, normally preceded by `node_check_object
  fail! for <field> <value>` (e.g.
  [HA management IP as source IP](https://community.fortinet.com/t5/FortiGate/Technical-Tip-Expected-behavior-when-email-server-uses-HA/ta-p/197120)).
  `cli.go`'s `errorPatterns` matches both, so the code is fine; the doc comment
  presents the less canonical of the two as the canonical one.

`entry not found in datasource` is confirmed as a real FortiOS CLI failure by
several Fortinet KBs (e.g.
[adding an address object via CLI](https://community.fortinet.com/t5/FortiGate/Troubleshooting-Tip-Error-Entry-not-found-in-datasource-when/ta-p/387358)).
Fortinet writes it capitalised as "Entry not found in datasource"; the driver's
patterns are case-insensitive, so this is a non-issue.

"No SSH exit status" is **not** documented by Fortinet either way. It follows
from claim 10: inside one interactive shell channel there is no per-command exit
status to read, only text. That reasoning is sound.

One gap: the naming-rules KB documents `The string contains XSS vulnerability
characters` as the rejection for an invalid name, which is not in
`errorPatterns`. In practice it should arrive alongside a `Command fail. Return
code` line (which *is* matched), and `accountNamePattern` excludes the
characters that trigger it, so this is a belt-and-braces observation rather than
a live bug.

## 6 — Persistence: **correct**

> "When Configuration save mode is set to **Automatic (default)**, configuration
> changes are automatically saved to both memory and flash. When … set to
> Manual, configuration changes are saved to memory, but not to flash… Unsaved
> changes are reverted when the device is rebooted."

([Using configuration save mode, 7.6.5](https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/228450/using-configuration-save-mode))

`set cfg-save {automatic | manual | revert}` lives in `config system global`, so
it is device-wide and not a per-command choice — exactly as
`Capabilities.PersistenceReason` states. `PersistsAcrossReload: true` is right,
and the D13 amendment it forced is justified.

One pedantic note: the documentation attributes the flash write to the
configuration change being saved, not specifically to the `end` token. `next`
also commits a table entry (see claim 7). Saying "`end` writes to flash" is a
fair shorthand and does not change the conclusion.

## 7 — `abort`: **correct, and the boundary is worth naming**

Documented in the Administration Guide's Subcommands table:

| subcommand | meaning |
| --- | --- |
| `next` | "Save changes to the table entry and exit the edit command so that you can configure the next table entry." |
| `abort` | **"Exit the command without saving."** |
| `end` | "Save the configuration and exit the current config command." |

([Subcommands, 8.0.0](https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/627485/subcommands);
FortiPortal's CLI reference phrases `abort` as "ends and discards the last
config".) It is listed among the **field** subcommands, i.e. available inside an
`edit` scope.

So the claim holds. The boundary the docs make explicit is that `abort` discards
only what has **not already been committed by a `next` or `end`** — `next` saves
the table entry there and then. The driver's create sequence is `config system
admin` → `edit` → `set`… → `next` → `end`, so a failure *after* `next` leaves a
real administrator on the device that `abort` will not remove.

`fortigate.go` already handles this correctly and says why — the comment at
`:238` explains that the `delete` after `abort` is "for the case where it failed
after". The narrower comment at `:392` ("`abort` discards an uncommitted
configuration block outright") is true as written, because it says
*uncommitted*. No change needed; the reasoning is sound and matches the
documentation.

## 8 — Access profiles: **partly wrong — three documented, not four**

| Profile | Documented? | Editable? |
| --- | --- | --- |
| `super_admin` | ✅ Administration Guide | No — "cannot be deleted or modified" |
| `prof_admin` | ✅ Administration Guide | **Yes** — "you can edit the setting in the `prof_admin` profile but not the `super_admin` profile" |
| `super_admin_readonly` | ✅ Fortinet KBs (not the Admin Guide page) | No — "cannot be edited from the GUI… From the CLI, the changes cannot be made" |
| `prof_admin_readonly` | ❌ **No Fortinet source found** | — |

Sources: [Administrator profiles, 8.0.0](https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/294491/administrator-profiles);
[Technical Tip: Unable to run diagnostic commands … super_admin_readonly](https://community.fortinet.com/t5/FortiGate/Technical-Tip-Admin-user-with-super-admin-readonly-Profile/ta-p/396784);
[Technical Tip: How to access the GLOBAL VDOM with read-only access permission](https://community.fortinet.com/t5/FortiGate/Technical-Tip-How-to-access-to-the-GLOBAL-VDOM-with-read-only/ta-p/192017).

`super_admin_readonly` is real, assignable (`set accprofile "super_admin_readonly"`),
and immutable — so **the driver's default and its stated rationale are sound**.
Note it does not appear under *System → Admin profiles* in the GUI, which is why
it is easy to miss.

`prof_admin_readonly` could not be confirmed. No page on `docs.fortinet.com` or
`community.fortinet.com` contains the string; every assertion of it traces to
third-party blogs and study sites. Notably, Fortinet's own KB for "create an
admin user with read-only access" tells you to **build a custom accprofile**,
which is not what you would document if a ready-made `prof_admin_readonly`
existed. The `fortigate.go:27` claim that "FortiOS ships four built-ins", and
the comparative claim that `prof_admin_readonly` "is narrower — it excludes
routing, system settings and endpoint control" (a property inherited from
`prof_admin`'s description, not verified for a readonly variant), are both
unsupported. The learnings file already warns that this exact list was the one a
bad search summary got wrong once; it was right to warn.

**A version-dependent restriction the driver does not record, and probably
should:** from **v7.4.x**, an administrator with `super_admin_readonly` **cannot
run `diagnose` commands** — "this has been disabled under CLI permits". For a
just-in-time read-only troubleshooting session on 7.4+, that is a material
restriction on what the shipped default can actually do, and the documented
workaround is a custom profile with "permit usage of CLI commands" enabled.
(Source: the same KB, ta-p/396784.)

## 9 — `trusthost`: **correct**

```
trusthost1 | Any IPv4 address or subnet address and netmask from which the
           | administrator can connect to the FortiGate unit. Default allows
           | access from any IPv4 address.
           | ipv4-classnet | default: 0.0.0.0 0.0.0.0
```

`trusthost1`–`trusthost10`, present 7.0.17 → 8.0.0
([`config system admin`, 7.6.6](https://docs.fortinet.com/document/fortigate/7.6.6/cli-reference/390485493/config-system-admin)).
Both halves of the claim check out.

**But the same table exposes a gap the claim's framing hides.** There are ten
parallel IPv6 fields, `ip6-trusthost1`–`ip6-trusthost10`, of type `ipv6-prefix`,
each defaulting to **`::/0`** — "Default allows access from any IPv6 address".
The driver writes only `set trusthost1`, so an administrator "pinned to the
proxy's address" remains reachable from **any IPv6 address** on any unit with
IPv6 management access. `value.go`'s own comment argues that a silently weaker
restriction than the provisioner believes it applied is the thing to avoid; this
is that, arriving through the field the driver does not set rather than through
a widened mask.

Relatedly: `trustHost()` in `value.go` renders an IPv6 source as `<addr>/128`,
but the step in `fortigate.go` writes it unconditionally into `set trusthost1`,
which is an `ipv4-classnet` field. An IPv6 `SourceAddress` would be rejected by
the device rather than routed to `set ip6-trusthost1`.

Both are reported here as documentation findings, not fixed.

## 10 — Non-interactive exec: **almost certainly true; not documented either way**

No Fortinet page states whether the FortiOS SSH server honours an `exec` channel
request. What the documentation shows is that **every** Fortinet-published way
of driving a FortiGate over SSH uses an interactive shell:

- Fortinet's own scripting example pipes commands into a **PTY-forced** shell:
  `… | ssh -t -t admin@10.100.23.40 > FG5101C-Monitor.txt`. `-t -t` forces
  pseudo-terminal allocation even when stdin is not a terminal — the flag you
  reach for precisely when the far end will not work without a PTY.
  ([Configuration Example: FortiGate remote monitoring and logging CLI command output into a file](https://community.fortinet.com/t5/FortiGate/Configuration-Example-FortiGate-remote-monitoring-and-logging/ta-p/189892))
- Forum answers use `ssh host < file` and `ssh host << EOF`. Both are *shell*
  requests with redirected stdin, **not** exec requests; the transcripts show
  "Pseudo-terminal will not be allocated because stdin is not a terminal"
  followed by ordinary FortiOS prompts.
  ([Send command via ssh script](https://community.fortinet.com/t5/Support-Forum/Send-command-via-ssh-script/m-p/110950))
- Not one Fortinet document uses the `ssh admin@fgt "get system status"` form.

Independent corroboration that the missing piece is the PTY: Fortinet devices
return nothing to paramiko's `exec_command()` and require `invoke_shell()` (or
`get_pty=True`); netmiko drives FortiOS through an interactive shell throughout.

**Verdict:** the driver's decision to hold an interactive shell channel is
correct and matches how every documented client does it. The *phrasing* in
`doc.go` and `cli.go` — that FortiOS "does NOT serve" an exec request — is a
reasonable inference from strong circumstantial evidence, not something
Fortinet states. What is actually established is: **FortiOS requires a PTY, and
Fortinet documents only interactive-shell usage.** If the absolute claim matters
to a customer conversation, it needs a test against hardware.

Worth knowing: FortiOS does document `execute batch start` / `execute batch end`
for feeding a block of commands into a session, which is a Fortinet-sanctioned
batching mechanism inside the same shell.

---

## Beyond the ten claims — multi-VDOM

None of the ten claims mentions VDOMs, and neither does the driver: `vdom`
appears nowhere in the package. That is a gap rather than a wrong claim, and on
the estate PLAN §14 describes — a telco running ~300,000 FortiGates and
FortiSwitches — it is likely to be the common case rather than the exception.

The Administration Guide's own CLI recipe for creating an administrator on a
multi-VDOM unit is **not** the sequence the driver sends:

```
config global
    config system admin
        edit <name>
            set vdom <VDOM_name>
            set password <password>
            set accprofile <admin_profile>
            ...
        next
    end
end
```

Source: [General configurations → Create per-VDOM administrators, 7.6.4](https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/32293/general-configurations),
repeated verbatim in [Technical Tip: Configuring per-VDOM administrators](https://community.fortinet.com/t5/FortiGate/Technical-Tip-Configuring-per-VDOM-administrators/ta-p/197736).
The `vdom` field is real and documented in `config system admin`: "Virtual
domain(s) that the administrator can access", string, maximum length 79.

Three things follow, in descending order of confidence:

1. **The `config global` wrapper is missing.** The driver opens with
   `config system admin` at the top level. Every Fortinet document that shows
   this table on a multi-VDOM unit nests it inside `config global`, and the same
   nesting appears for other global tables (`config global` / `config system
   global` / `set management-vdom`). The driver's `end`-unwinding in
   `cliSession.Close` (`end\nend\nexit`) also assumes a fixed nesting depth that
   would be one level short.
2. **`set vdom` is never sent.** The public-key procedure lists it among the
   requirements — "When multi-vdom mode is enabled, a VDOM must be specified" —
   and the per-VDOM recipe above sets it explicitly. A global-scope administrator
   may not need it; a VDOM-scoped one does.
3. **The shipped default profile does not fit a per-VDOM account.** Per-VDOM
   administrators "must use either the `prof_admin` administrator profile, or a
   custom profile", and "when creating an administrator at the VDOM level, the
   `super_admin` administrator profile cannot be used".
   `super_admin_readonly` is the *global* read-only profile — it is exactly what
   [ta-p/192017](https://community.fortinet.com/t5/FortiGate/Technical-Tip-How-to-access-to-the-GLOBAL-VDOM-with-read-only/ta-p/192017)
   recommends for global read-only access — so it suits a global administrator
   and not a VDOM-scoped one. The obvious narrower substitute would be
   `prof_admin_readonly`, which is the profile claim 8 could not find evidence
   for. The two findings meet here: on a multi-VDOM unit there appears to be **no
   built-in read-only profile usable for a per-VDOM account**, so a custom
   accprofile becomes necessary rather than optional.

What is **not** established here is the exact failure mode of sending
`config system admin` at the top level of a multi-VDOM unit — whether it is a
parse error, or silently resolves somewhere unintended. Fortinet documents the
correct sequence but not what the incorrect one does, and this is the kind of
question a fake device cannot answer. It belongs on the same hardware-test list
as claim 10 and the session-teardown half of claim 2.

---

## Summary of what should change

Nothing here breaks the driver on a single-VDOM unit. In rough order of
consequence:

1. **Multi-VDOM is unhandled**, and on PLAN §14's estate it is probably the
   common case. The documented sequence wraps `config system admin` in
   `config global` and sets `set vdom`; the driver does neither, and its
   `end`-unwinding assumes the shallower nesting. Confirm the failure mode on
   hardware before deciding how much of this is a driver change and how much is
   a contract question about what a target's identity means when a device holds
   many.
2. **Claim 2 is the real one among the ten.** `set schedule` + `config firewall schedule
   onetime` gives device-enforced, time-bounded administrator login. Revisit
   `EnforcesExpiry: false`, the skipped `target-enforced` rung, the discarded
   `req.Lifetime`, and the "reaper is the primary removal path" framing —
   knowing the field exists, and knowing it denies login rather than deleting
   the account.
3. **Claim 8's fourth profile is not real** as far as Fortinet documents it. Drop
   `prof_admin_readonly` from the three places that assert it, and record the
   7.4+ `diagnose` restriction on `super_admin_readonly`, which constrains what
   the shipped default can do.
4. **Claim 9's IPv6 gap.** `ip6-trusthost1..10` default to `::/0`, so the source
   pin is IPv4-only; and an IPv6 `SourceAddress` would be written into an IPv4
   field.
5. **Claim 1 is wrong but inert** — the field is 64, not 35. Correct the stated
   fact; `maxAccountNameLen = 35` can stay as a deliberate narrowing if that is
   what it is.
6. **Claim 5's two string details** — `-3` is not a documented return code, and
   the canonical parse error is `Command parse error before …`.

Claims 3, 4, 6, 7 and 10 need no change. Claims 7 and 10, the two the author
flagged as least certain alongside claim 1, both survive verification —
claim 10 as a sound inference rather than a documented fact.
