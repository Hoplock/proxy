# 0036 — The access profile is one value for every platform, and it should not be

> **New prompt, added by phase 0029 and raised by the user on its PR.** 0029
> shipped a second device platform and, in doing so, turned a setting that had
> always been FortiOS-shaped into a setting that is *wrong* for one of the two
> platforms the build ships. It worked around that rather than fixing it,
> deliberately and with the reasoning recorded — the fix is a design question
> about where a privileged account's scope comes from, which is bigger than the
> phase that found it.
>
> It is queued **before** the contract collapse (now **0037**) because one of
> its two candidate answers revises `api/`.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — **D2** (the proxy never originates policy), **D13**, §4.2,
  §5.3 in full — especially "As corrected (phase 0015)" decision 3, "As
  extended (phase 0016)" decision 2, and "A note on the proxy-wide access
  profile, which is now under-specified" — and **§6.5** for the enforcement
  axes 0018 defined and 0019 rendered.
- `docs/learnings/0015-…` — why there is no default access profile at all, and
  why that absence was itself the decision.
- `docs/learnings/0019-…` — `enforcement.platform_role`, which is the
  route-level answer that already exists, and the rung it is tied to.
- `docs/learnings/0029-…` — the platform that broke the assumption, and the
  workaround this phase replaces.

## The problem, precisely

`auth.target.ephemeral_account.access_profile` is **one string for every
platform a proxy serves**. It is required at startup (phase 0015: no FortiOS
built-in is a safe default, so an operator picks), and it is the scope every
created administrator gets on every route that does not name its own.

Phase 0019 gave a route a way to name its own scope —
`enforcement.platform_role` — but tied it to **one rung**: it is read only when
`enforcement.execution` is `platform-authorized`, and a route naming that rung
with no role is refused. So a route that wants an ordinary session on a device,
under the default `proxy-inspected` rung, has no way to say which scope its
administrator should hold. It gets the proxy-wide one.

That was fine while every device was a FortiGate. It is not fine now:

- FortiOS documents three built-in profiles (`super_admin`, `prof_admin`,
  `super_admin_readonly`).
- FortiSwitchOS documents **one** (`super_admin`). `prof_admin` and
  `super_admin_readonly` do not exist there at all.

So a proxy fronting both estates cannot express a correct value. A FortiGate
estate that acquires its first switch has a profile configured that the switch
will reject — and it will reject it *half way through a sequence that has
already created the administrator entry*, which is a rollback on a customer's
switch, per session.

**What 0029 did about it, and why that is a workaround and not a fix.**
`newDriverRegistry` builds the FortiSwitch driver with **no default profile**
when the configured one is a FortiOS built-in (`fortios.SwitchAcceptsProfile`
answers that without dialling). A route naming `platform_role` is served; a
route relying on the proxy-wide default is refused, outage-class, nothing
provisioned, with an error naming the platform. Nothing is weakened and nothing
is substituted.

The two alternatives were both worse and are recorded so this phase does not
re-litigate them: passing the profile anyway buys the mid-sequence rollback
above, and refusing at **startup** stops every FortiGate-only deployment from
booting the day a second driver ships, because `platforms: []` means "every
driver this build ships".

But the workaround leaves three things wrong:

1. A whole class of route — any device route not naming `platform-authorized` —
   is **unservable** on FortiSwitchOS for a proxy configured the normal way,
   and the operator's only signal is a per-session outage.
2. The setting is still required at startup and still describes one platform,
   so its own validation cannot tell an operator they have made this mistake.
3. It gets worse with each platform added. A third driver with a fourth profile
   vocabulary repeats the whole argument.

## The design question this phase owns

**Where does a created administrator's scope come from when the route does not
name one?** There is more than one defensible answer and they are not
equivalent — decide **with the user** and write the reasoning into
`docs/PLAN.md` before writing code.

- **Per-platform proxy configuration.** `access_profile` becomes a map keyed by
  platform (with the current scalar accepted as the single-platform form, or
  migrated). Proxy-local, **no contract change**, validated at startup against
  the registered drivers — so the mistake above becomes a boot error naming the
  platform and the profile, which is where an operator can act on it. It keeps
  the scope an operator's choice, which is what 0015 decided it should be.
- **A route-named default, decoupled from the rung.** `platform_role` (or a
  sibling) becomes readable on every device route rather than only beside
  `platform-authorized`. This is a **contract change** and it is the one that
  must be weighed against D2 and against 0019's own reasoning: 0019 tied the
  two together deliberately, so that a scope in the audit record is one the
  route actually chose. Read that reasoning before overriding it — and if you
  do, say what the record now means when a route names a scope but not the rung
  that enforces it.
- **Driver-declared defaults.** Each driver declares a safe default for its own
  platform. Cheapest, and it is the one phase 0015 explicitly refused: "a
  default that is wrong for the common case, quietly weaker than advertised on
  7.4+, and inapplicable on a whole class of unit is not a safe default; it is
  a guess with a comment." Taking it now means overturning that decision
  explicitly, with a reason, not quietly.

A hybrid is legitimate — for example per-platform configuration for the default
plus the route override staying where 0019 put it — but say which problem each
half solves.

## In scope
- The decision, settled with the user and recorded in `docs/PLAN.md` §5.3 with
  its alternatives.
- Whatever configuration or contract change it implies. If it touches `api/`,
  `docs/CROSS-REPO-PROTOCOL.md` §3.2 applies — upstream first, and the sync
  kickoff its §4 asks you to hand the user for each affected repository.
- **Removing 0029's workaround** in `internal/auth/target/registry.go`, or
  keeping it deliberately and saying why. `fortios.SwitchAcceptsProfile` exists
  only to serve it and should go with it if it goes.
- Startup validation that can actually catch the misconfiguration, whatever
  shape the answer takes.
- `config.example.yaml`, which currently carries the problem as a long comment
  rather than a mechanism.

## Out of scope
- New enforcement rungs or changes to §6.5's vocabulary (0018/0019).
- New device drivers.
- The declarative driver document and the subprocess contract (D13).

## Acceptance criteria
- A proxy serving both `fortigate` and `fortiswitchos` can express a correct
  scope for each, and a route that names no scope of its own is served on both.
- A misconfiguration is caught where an operator can act on it — at startup, or
  by Hoplock Control refusing the route — rather than as a per-session outage.
- No platform is ever handed a profile it cannot hold, and no account is
  created with a scope nobody chose. Both are the invariants phase 0015 set and
  neither may be relaxed to make this easier.
- Whatever an audit record says about the scope in force remains true: if the
  route did not choose it, the record must not imply it did.
- `go build ./... && go vet ./... && go test ./...` and `golangci-lint run` pass.

## The e2e topology obligation
`deploy/proxy/proxy-direct.yaml` configures `prof_admin`, and the FortiSwitch
route added by 0029 works around it by naming `enforcement.platform_role:
super_admin`. Whatever this phase decides, that fixture should end up
expressing the *normal* arrangement rather than the workaround — and
`test/topology`'s `TestEveryRoutedPlatformHasADriverOnItsProxy` is the pattern
to follow for pinning the config and the fixtures together.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0036-per-platform-access-profile-learnings.md`. The summary
block MUST carry: the decision and its alternatives, whether it changed the
contract, and what happens now to a route that names no scope on a platform
whose vocabulary the proxy-wide setting does not match.
