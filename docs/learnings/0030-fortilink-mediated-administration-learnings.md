# 0030 — FortiLink-mediated administration — Learnings

## Summary
- **Verdict: withdrawn. Nothing was built, and that is the deliverable.** The
  estate 0029 named as the one it does not serve — FortiLink-managed switches
  deliberately kept unroutable from the proxy — is served by a **deployment**,
  not by a mechanism in the product. `docs/PLAN.md` §5.3 carries the decision
  under "As settled (phase 0030)".
- **The target-identity question the prompt required to be settled is
  therefore not answered, and must not be.** 0016's rule stands exactly as 0029
  left it: the endpoint is the device the proxy connects to, and a route field
  names a **partition** of that device, never a different device behind it.
  There is now one answer to "what is a target", not two.
- **The two deployments that serve the estate.** (1) Put a proxy where it can
  reach the switch; 0029's `fortiswitchos` then works unchanged, with the
  switch's own host key, its own ephemeral administrator, its own reaper sweep
  and `set ssh-public-key1` as the session credential. (2) Administer the switch
  from an ordinary `fortigate` session — the FortiGate administrator is
  ephemeral and the session is captured, but **the switch login is a standing
  credential Hoplock does not broker**, which is option 2's real and stated
  limit.
- **What the seam would have cost, and why neither option is the lesser
  answer:** a second ephemeral account on a customer's **firewall** per switch
  session with its own orphan class; a **password-only** user hop (FortiOS's
  "Simple SSH client" has no identity file), losing the stronger credential kind
  on the least auditable path; a strand-with-no-sweep leak class on plain
  deauthorization; and a per-channel reach preamble in front of **every**
  session's inspection pipeline to serve one topology.
- **No code behaviour changed.** Docs, prompts, and two stale code **comments**.
  `api/` is untouched, so there is **no cross-repo obligation**
  (`docs/CROSS-REPO-PROTOCOL.md` §1) and **no sync kickoff is owed** — the
  prompt required that check because it expected a contract change. No e2e
  scenario is owed either; see "The e2e obligation" below.
- **Key files:** `docs/PLAN.md` (§5.3 new "As settled (phase 0030)" block, §10
  table rows 0014/0030, §10 queue note); `docs/PROTOCOL.md` §6;
  `docs/FORTIOS-DOC-VERIFICATION.md` (FortiLink section reframed);
  `docs/learnings/{0029,README}`; `internal/auth/target/device/driver.go` and
  `internal/control/policy.go` (comments); `prompts/queued/0030-…` **deleted**.
- **What the NEXT session must know:** the number **0030 is retired** — never
  reuse it (`docs/PROTOCOL.md` §6, which now names two retired numbers). The
  queue is **0031–0037** and **nothing was renumbered**. `device.Field` gains no
  notion of a field that selects a subordinate device, and
  `device.CreateRequest.Fields` still ride on **creation only** — 0016's
  sentence about "the phase that carries them onto the other operations" stays
  unspent, and no phase is queued to spend it.

## Details

### What the prompt asked, and why the answer is "don't"

0030 was queued to give a session whose target is a FortiSwitch **the proxy has
no route to** the same short-lived administrator 0029 provides, by going through
the switch's managing FortiGate. It named three problems it owned: the target
identity (again), a session leg the proxy engine cannot express, and a reaper
that sweeps from an endpoint. It required the first to be settled **with the
user** and written into `docs/PLAN.md` before any code.

Put to the user, the premise did not survive. A customer who needs to
administer a switch the proxy cannot reach has two answers already, and the
phase's job was to build a third and more expensive one.

**1. Route a proxy to the switch.** 0029's `fortiswitchos` platform then
administers it with the full ephemeral model and nothing special about it: the
switch's own `host:port`, its own host key pinned under D7, its own short-lived
administrator, its own reaper sweep, and `set ssh-public-key1` usable as the
session credential. A proxy is a process, not an appliance — §9.1 measures one
at 2.6 ms of CPU and 118 KiB of RSS per connection, and 0020's whole finding was
that proxy count is a deployment variable rather than an architectural one. An
operator is already expected to place proxies deliberately for geo-routing (D1);
placing one inside a management segment is the same kind of decision.

Note what this option costs the customer that the withdrawn phase's premise
implied it could not pay: **nothing about the management subnet's reachability
from anywhere else**. A proxy in the segment does not route the segment. The
premise conflated "the switch is unroutable from the proxies I have" with "the
switch must stay unroutable from every proxy", and only the first is what
unroutable management subnets are for.

**2. Administer the switch from a FortiGate session.** The operator takes an
ordinary `fortigate` route to the managing FortiGate and reaches the switch's
CLI from inside that session with `execute switch-controller ssh`. This is the
vendor's own stated posture (`docs/FORTIOS-DOC-VERIFICATION.md`, "A standing
instruction"), and on that path Hoplock still provides what it provides on any
FortiGate route: the administrator is ephemeral, the session is captured, and
the FortiGate's own access profile decides whether `execute switch-controller
ssh` may run at all — §6.5's `platform-authorized` rung doing exactly what it
says, on the device that holds the route.

**Its limitation is real and is stated rather than implied**, in §5.3 and here:
the switch login uses the switch's **own standing credential**, which Hoplock
does not broker, rotate, or remove. The product's claim on option 2 covers the
FortiGate leg and stops there. An estate that wants no standing credentials on
its switches takes option 1. (The inner CLI rides inside the captured FortiGate
session and is therefore recorded. What does not reach it is the proxy's
`exec`-level filtering — for §6.5's ordinary reason, an interactive shell, not
for anything FortiLink-specific.)

### What building it would have cost

Four costs, and the first is on its own decisive. All four are the phase's own
material, from its prompt and from `docs/FORTIOS-DOC-VERIFICATION.md`; none of
them needed re-deriving.

**1. A second ephemeral account on a customer's firewall, per switch session.**
The administrator lives on the switch; the proxy dials the FortiGate; there is
no account on the FortiGate for it to log in as, and logging the user in as the
proxy's privileged administrator is not an option on a firewall. So the phase
needed a second ephemeral account on the FortiGate, scoped as narrowly as the
platform allows, with its own teardown, its own orphan class and its own reaper
bookkeeping. That is a **new leak class on the highest-value device in the
estate**, taken on in order to reach a lower-value one. Weighed against option
1, whose cost is a process.

**2. The user's hop would be password-only.** FortiOS's outbound client is
documented as a "Simple SSH client" whose only settings are `execute ssh-options
interface|source` — no identity file, no client key store, no forwarding. So
`set ssh-public-key1`, the stronger of the two credential kinds and the one
connecting directly keeps usable, is unavailable on exactly the path that is
hardest to audit. The phase would have delivered a weaker credential than the
deployment it was meant to improve on.

**3. Deauthorization strands, and nothing sweeps it.** Plain deauthorization
removes a switch from management **without touching its configuration**, and the
FortiGate has no view of the switch's administrator table (`config
switch-controller managed-switch` carries no administrator fields;
`switch-profile`'s `login-passwd-override` reaches the built-in `admin` account
only). On a switch reachable only through its FortiGate, deauthorization
therefore removes the proxy's only route to a privileged account it is
responsible for, and nothing on either device reconciles it away. A leak class
with no sweep is a leak — the reasoning `device.ResidueSweeper` exists for — and
this one has no sweep available even in principle. The prompt asked the phase to
*answer* this hazard; the answer is that the proxy provisions nothing on a
device it has no route to, so there is nothing to strand.

**4. A per-channel reach preamble on the data path of every session.**
`ProvisionedAccess` hands back an `*ssh.ClientConfig` and nothing else. Driving
`execute switch-controller ssh` and answering its password prompt *before* the
user's bytes flow needs a seam that runs **per channel**, sitting in front of
0009's inspection pipeline and 0010's filtering. That is new machinery in front
of every session this proxy serves, for one topology — and the prompt itself
flagged it as the part to design carefully and the plausible whole of the phase.

### The target-identity question, and why leaving it unanswered is the point

The prompt required this settled with the user before code, and named the bind
honestly: 0016's rule points at the FortiGate as endpoint with a field naming
the switch, but that is the shape 0029 rejected on the audit argument, and "both
readings cannot be right for the same estate".

They cannot, and the resolution is that **only one estate exists**. The decisive
fact is one the prompt recorded in passing and did not follow through: *the same
physical switch may be directly reachable from one proxy and not from another*.
An endpoint or platform identity that depends on **which proxy is asking** is
policy that cannot be authored once in Hoplock Control — and D2 requires exactly
that, since the proxy originates no policy and Control's authorize response is
where a route's identity is decided. Whatever 0030 chose, a route would have
meant one thing to a proxy inside the management segment and another to a proxy
outside it, for the same device. Both candidate shapes had this problem; it is
not an argument between them.

So 0016's answer is left standing verbatim, and there is one answer to "what is
a target" rather than two:

> the endpoint is the device the proxy connects to, and a route field names a
> **partition** of that device.

### What this leaves in the code, deliberately

- **`device.Field` gains nothing.** The prompt would have added a declaration
  saying whether a field selects a subordinate device, so that only such fields
  may partition a reaper sweep. No field selects one, so there is nothing to
  declare. The hazard that declaration was for is real and is now recorded in
  the `CreateRequest.Fields` comment instead: a reaper partitioning on **every**
  field would see one VDOM-scoped route's live account as another's orphan and
  remove it after the grace period, because a FortiGate's administrator table is
  one global table whatever an account is scoped to. Whoever introduces a
  device-selecting platform needs that paragraph; it should not be lost with the
  phase.
- **`CreateRequest.Fields` still ride on creation only**, and `RemoveRequest`,
  `ListRequest` and `CredentialRequest` still carry none.
- **`target.deviceReaper` is untouched.** It still keys on `host:port` and
  sweeps a device it reaches from an endpoint.
- **`target.ProvisionedAccess` still hands back an `*ssh.ClientConfig` and a
  teardown.** No reach seam exists, and none is queued.

0016's sentence — "a platform where a field selects a genuinely different
managed device … is the phase that carries them onto the other operations" —
was left unspent by 0029 and **stays unspent**. It is now a conditional about a
platform nobody has, not a pointer to queued work.

### The e2e obligation

The prompt required a scenario and named the two hazards that bite
(`TestTopology`'s deliberate subtest ordering, and the shared `sshBaseArgs`).
**No scenario is owed:** no behaviour changed, so there is nothing for a real
SSH client to survive. `cmd/fake-device`, `deploy/control/fixtures.template.yaml`
and `TestTopology` are untouched, including 0029's FortiSwitch on `:2223`. Those
two warnings remain accurate for whoever next adds a scenario.

### The cross-repo obligation

The prompt said "this phase probably does touch a shared surface, so do not skip
its §1 check". The check was run and the answer is **no**: `api/` is untouched,
nothing under `deploy/` changed, and `docs/CROSS-REPO-PROTOCOL.md` §1 therefore
does not engage. **No sync kickoff is owed for any repository**, and Hoplock
Control needs no change — there is no new `platform`, no new `device_field`, and
no new parameter, so a PDP that could author routes before can author exactly
the same ones now.

### Dangling references cleaned up (`docs/PROTOCOL.md` §3)

Withdrawing a phase leaves the same debris a rename does. Live references
updated:

- `docs/PLAN.md` §5.3 — the "As decided (phase 0029)" block, in two places: the
  paragraph that queued this estate as 0030, and the deauthorization hazard
  "recorded in 0030 as a hazard that phase has to answer".
- `docs/PLAN.md` §10 — the 0030 row (now a withdrawal, on 0021's pattern) and
  the 0014 row (which pointed forward at "0029/0030").
- `docs/PROTOCOL.md` §6 — named **0021** as the only retired number. It now
  names both, and states plainly that withdrawal is a real outcome of a session
  whose prompt file is deleted rather than moved, since this is the second time
  and the rule was written from a single example.
- `docs/learnings/README.md` — same correction.
- `docs/FORTIOS-DOC-VERIFICATION.md` — its FortiLink section was written
  *forward*, for 0030 to act on ("phase 0030 has to choose between them", "worth
  knowing before phase 0030 designs anything"). The **facts are unchanged and
  still sourced**; the framing now says they are the evidence for the
  withdrawal. Its hardware-list item 3 (deauthorization) is marked lower-value,
  because the hazard only bites a proxy administering a switch it cannot reach.
- `internal/auth/target/device/driver.go` — `CreateRequest.Fields` said a
  FortiLink switch behind its FortiGate "needs them on the rest too, and that is
  the phase that adds them". There is no such phase; the comment now carries the
  reaper hazard described above and says nothing is pending.
- `internal/control/policy.go` — `ParamDeviceFieldPrefix` still said "a
  FortiLink-managed FortiSwitch is administered THROUGH the FortiGate in front
  of it". **That was already stale from 0029**, which disproved it; this phase
  found it while sweeping for its own references and fixed it.

Left as historical record, per §3: `prompts/implemented/0029-…` and
`docs/learnings/0029-…` (given a one-line pointer at the top, not a rewrite),
and the FortiLink comments in `internal/auth/target/device/fortios/`,
`cmd/fake-device/main.go` and `test/e2e/scenarios_test.go`, which describe
0029's shipped behaviour and stay true.

Two range references were checked and left alone, on the precedent of 0021's
`prompts/queued/0022` hit: `prompts/queued/0031` ("depends on nothing 0020–0030
change" — still true, and more so) and `prompts/queued/0037` ("phases 0017–0030
will have added to it" — a range over what landed, and 0030 adds nothing to the
contract).

### What would revive this phase

Not a request to reach a switch — both deployments above do that, and one of
them is the vendor's own posture. It comes back for a customer whose management
subnet **genuinely cannot host a proxy** *and* who **will not accept a standing
credential on the switch** for the FortiGate path, because that is the only
combination neither option serves. If that customer appears, the four costs
above are what the phase has to be worth, and the identity problem above is what
it has to solve first — probably by making reachability a property of the
**proxy's** configuration rather than of the route, which is the one shape this
session did not have a reason to work out.

Write it as a new, higher-numbered prompt when that happens. **Do not reuse the
number 0030.**
