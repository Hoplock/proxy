# 0036 — per-platform access profile — Learnings

## Summary
- **What shipped:** `auth.target.ephemeral_account.access_profile` is now a
  **map keyed on the contract's `platform`** (a scalar still means "every
  platform this proxy serves"), so a proxy fronting FortiOS and FortiSwitchOS
  can name a correct scope for each. A platform with no scope, a scope its
  platform cannot hold, and a scope named for a platform the proxy does not
  serve are all **startup** refusals. Phase 0029's workaround is removed.
- **The decision, and its two alternatives:** per-platform proxy configuration,
  with 0019's `enforcement.platform_role` staying **exactly where it was**
  (beside `platform-authorized`). *A route-named default decoupled from the
  rung* was rejected — it breaks 0019's property that a scope in the record is
  one the route chose, and a route naming nothing would still have needed a
  default, so it was additional to this change rather than instead of it.
  *Driver-declared defaults* was rejected — 0015 refused it ("a guess with a
  comment") and on FortiSwitchOS the only built-in is the all-access one.
- **Contract change: NO.** `api/` is untouched, so no cross-repo obligation
  (`docs/CROSS-REPO-PROTOCOL.md` §1).
- **A route naming no scope, on a platform the proxy-wide setting does not
  match:** that state no longer exists at run time. It is caught at startup and
  the proxy refuses to boot, naming the platform, the profile and two remedies
  (add a map entry, or narrow `platforms:`). Before this phase it was a
  per-session outage-class denial on FortiSwitchOS.
- **Key files:** `internal/config/config.go` (`AccessProfiles`),
  `internal/auth/target/{registry,deviceaccount}.go`,
  `internal/auth/target/device/driver.go` (`RoleValidator`, `ValidateRole`),
  `internal/auth/target/device/fortios/{fortigate,fortiswitch}.go`,
  `config.example.yaml`, `deploy/{proxy/proxy-direct.yaml,control/fixtures.template.yaml}`,
  `test/topology/config_test.go`, `test/e2e/scenarios_test.go`,
  `docs/PLAN.md` (§5.3 new layer + "What is true today", §10).
- **Types/identifiers:** `config.AccessProfiles` + `AccessProfileEverywhere`,
  `AccessProfilePerPlatform`, `.For`, `.Platforms`, `.IsZero`;
  `device.RoleValidator` + `device.ValidateRole`; `(*fortios.Driver).ValidateRole`,
  `(*fortios.SwitchDriver).ValidateRole`; `target.DeviceAccountOptions.AccessProfiles`
  (was `AccessProfile string`). **Removed:** `fortios.SwitchAcceptsProfile`.
- **Gotcha for operators:** a proxy running `platforms: []` (every shipped
  driver) with a FortiOS built-in as its single profile **no longer starts**.
  That is deliberate, and the error names both fixes.
- **What the NEXT session must know:** a new device driver must implement
  `device.RoleValidator` — `TestEveryShippedDriverAnswersForItsOwnScope` fails
  otherwise — and `deploy/proxy/*.yaml` must name a scope for every platform it
  registers, which `test/topology` pins.

## Details

### The problem, and why the setting could not report it

`access_profile` was one string. FortiOS documents three built-in profiles
(`super_admin`, `prof_admin`, `super_admin_readonly`); FortiSwitchOS documents
one (`super_admin`) and does not have the other two at all. So a proxy fronting
both estates had no correct value to write, and — this is the part that made it
worse than an ordinary misconfiguration — **its own validation could not tell an
operator they had made the mistake**, because there was no correct configuration
to compare against. Whatever they wrote was as valid as anything else.

Phase 0029 answered it per session: the switch driver was built with no default
when the configured profile was a FortiOS built-in, so a route naming its own
`enforcement.platform_role` was served and a route relying on the default was
refused outage-class with nothing provisioned. Nothing was weakened and nothing
substituted, but the operator's only signal was an outage, and it got worse with
each platform added.

Making the setting per-platform is what turns it into something validation can
check. The map is not primarily an expressiveness feature; it is what gives the
proxy a correct configuration to compare an operator's against.

### Why the route override did not move

0019 tied `platform_role` to `platform-authorized` deliberately: the rung's whole
claim is *the device's own authorizer decided, under the role the route named*,
and the audit record carries both. Reading the role on every device route would
put a scope in the record beside a rung that is not enforcing it, and "which
grouping did the device decide under" stops being answerable from the record
alone. The record's meaning was the load-bearing objection, and this phase found
no way to decouple the two that preserved it.

The second objection is more mundane and just as decisive: decoupling does not
answer this phase's question. A route that names nothing still needs a default,
so the contract change would have been *in addition to* the per-platform map,
not instead of it — a `api/` revision and a cross-repo sync bought nothing that
proxy configuration did not already buy.

Where the two now sit is worth stating plainly, because it is the whole model:

| The route | Where the scope comes from | What the record says |
| --- | --- | --- |
| names `platform-authorized` + `platform_role` | the route | the device's authorizer decided, under this grouping |
| names `platform-authorized` and no role | — | **refused** (0019, unchanged) |
| names any other rung, or none | `access_profile[<platform>]` | nothing about a scope the route chose |

### Why driver-declared defaults stayed refused

0015's sentence has not weakened, and on the platform 0029 added it is sharper:
FortiSwitchOS's only built-in is the all-access one, so a driver-declared default
would be *the widest scope on the platform, chosen by Hoplock*. What this phase
does is orthogonal to that decision — the value is still the operator's, and all
that changed is that they can write one per platform. The driver holds the value
the operator chose; it does not supply one.

### `device.RoleValidator`, and what nil means

The unusable-scope check needed a driver-side answer that costs no connection.
It is an **optional interface** beside `ResidueSweeper`, for the same reason:
most of what a driver knows belongs in `Capabilities`, which is data, and this
cannot be. A platform's answer is a *rule over names* ("`prof_admin` is a FortiOS
profile and does not exist here"), not a list — an allow-list would be wrong on
every platform that lets a customer build a custom profile, which is all of them,
and would refuse exactly the configuration Fortinet's own guidance recommends.

It is asked of the **declaration-only driver in `device.Shipped()`**, which is
what makes the check free: those instances exist so `CheckShipped` can read
`Platform()` and `Capabilities()` without a device, and a role rule is the same
kind of question.

`ValidateRole` answering nil means only *nothing this driver declares rules this
name out*. It is **not** a statement that the role exists on any particular unit
— no driver can say that without dialling, and one that could would be answering
for a device the caller has not named. The device's own refusal at create time is
still the last check, and the FortiOS rule that depends on the route
(`checkVDOMProfile`: a VDOM-scoped account may hold neither global built-in)
deliberately stays there, because it is not a rule about the name alone.

`TestEveryShippedDriverAnswersForItsOwnScope` requires a shipped driver to
implement it. Without that, a third platform with a fourth profile vocabulary
silently opts out of the startup check and repeats this whole argument — which
the prompt named as the thing it was trying to stop.

### Strictness, and the upgrade it breaks

The user chose strict validation over a lenient variant. The consequence, stated
because it is a real upgrade break: a proxy running `platforms: []` — "every
driver this build ships" — with `access_profile: prof_admin` **no longer starts**
once a second driver exists. One line fixes it, either way:

```yaml
access_profile:
  fortigate: "prof_admin"
  fortiswitchos: "super_admin"
```

or `platforms: ["fortigate"]`, which is the honest statement for an estate with
no switches.

0029's argument against a startup refusal was that a FortiGate-only deployment
must not stop booting the day a second driver ships. That argument is answered
rather than overruled: `platforms:` is what says which estates a proxy fronts, and
a deployment that lists them keeps booting. What no longer boots is a proxy that
registers a driver it has no valid scope for — a proxy that was going to fail
those sessions anyway, discovering it one session at a time.

There is deliberately **no fleet-wide fallback under the mapping form**. A
fallback would put the scope of a platform the operator did think about onto one
they did not, which is the substitution this phase removes.

### The two error messages, and why they are two

They are different mistakes with different fixes, so they are worded separately:

- *no scope for a platform this proxy serves* — the upgrade case. The message
  names the platform, shows the mapping form, and offers narrowing `platforms:`
  as the other remedy.
- *this platform cannot hold the scope named for it* — the sharper one, and the
  message wraps the driver's own words, which on FortiSwitchOS already say what
  the platform does have and that anything narrower is a custom profile.

A scope named for a platform the proxy does **not** serve is refused in the same
pass. That one exists because an operator who narrowed `platforms:` and forgot to
remove the entry, or who misspelled a platform name, is otherwise told only that a
*different* platform is uncovered — with the reason sitting two lines above in
their own file.

### The topology, and where `platform-authorized` went

`deploy/control/fixtures.template.yaml`'s FortiSwitch route named
`enforcement.platform_role: super_admin`, not because the route wanted the
device's own authorizer but because the proxy-wide default could not reach that
platform. That is policy covering for configuration, and a reader could not tell
it from a route that meant it. It now names no scope at all.

Removing it revealed that this was the **only** route in the topology naming
`platform_role`, so the e2e would have stopped covering 0019's rung entirely.
`platform-authorized` therefore moved to the `fortigate.company.com` route, where
it is a genuine policy statement — on a FortiGate the session's real command
boundary *is* its access profile — with `prof_admin`, the same scope the proxy's
own default names, so what the route buys is the record rather than a different
account.

Two `test/topology` tests pin the arrangement:
`TestEveryRoutedPlatformHasAScopeOnItsProxy` runs the same resolution the proxy
runs at startup over every `deploy/proxy/*.yaml`, and
`TestTheFortiSwitchRouteNamesNoScopeOfItsOwn` fails both if the workaround comes
back and if `platform_role` disappears from the fixtures altogether.

### Test notes

- `internal/auth/target/deviceprofile_test.go` uses a `ShellDialer` that returns
  an error rather than connecting. Every check in that file is answered from a
  declaration, and the dialer is how that stays true if somebody later adds a
  check that dials.
- The e2e switch scenario asserts on the **mapping record's** `access_profile`
  rather than on the switch's administrator table: by the time the assertion
  runs the session has closed and teardown has probably removed the account, and
  the record is what an auditor reads anyway.

### Deviations and follow-ups

None. No plan deviation: §5.3 gained an `As settled (phase 0036)` layer and its
"What is true today" header was recomposed (the layer count and the
authorization-scope paragraph), §10's row was rewritten as delivered, and 0029's
"note on the proxy-wide access profile" is marked resolved in place rather than
rewritten — it is that phase's reasoning for the workaround this one replaced.

`prompts/queued/0037`'s blocker note said 0036 "may still revise `api/`"; it is
updated in the same PR to record that it did not, and that 0037 is now the only
queued prompt.

`golangci-lint` could not be run in the implementing session — the installed
binary (built with Go 1.25) refuses this module's Go 1.26 target. CI's own
`lint` job is the check.
