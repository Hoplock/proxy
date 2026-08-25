# 0016 — Target-side enforcement: confining the ephemeral account

> Renumbered from 0014 by the privileged-access revision (PLAN §10) and widened
> there to cover device accounts as well as POSIX ones. Queued after 0015 for
> the reason 0009 came after 0006: the vocabulary lands first, then the thing
> that enforces it.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — especially §2 (**D12**, as amended by 0015; **D13** for what
  a device driver controls), §5.1 (the ephemeral lifecycle and its teardown
  guarantees), §5.3 (the device lifecycle and its declarations), §6.3 (the
  enforcement-point table 0015 recorded), §4.3 (what the user is told).
- `docs/learnings/` — read summaries; open **`0015`** (the rung vocabulary,
  capability advertisement, and refusal rule — this phase implements exactly
  what that summary names), `0007` (the provisioning and teardown scripts, the
  naming convention, the orphan reaper, and the target-side prerequisites),
  `0010` (the restricted-exec policy object, which is the policy this phase
  renders onto the target) and **`0014`** (what a FortiOS access profile can
  actually constrain — the device rung is rendered from that, not from
  memory).

## Objective
Make the enforcement rungs Hoplock Control chose real on the target: confine the
ephemeral account so that what it *can* execute — and what it can *reach* — is
bounded by the OS, not by what the proxy managed to parse on the way past.

## Why it is worth the complexity

Everything the proxy enforces, it enforces on a string in flight. That is a real
boundary for `exec` and no boundary at all for an interactive shell (D12).
Confining the account moves the same policy behind sshd and the kernel, where it
holds for a pty, for a shell escape out of an editor, for an uploaded script —
and for a session that reaches the host **without going through the proxy at
all**, which is the one failure mode nothing else in this system covers.

The reach axis is not the same argument repeated; it is the one that matters for
the automation accounts this feature was asked for. An account confined to
`uptime` and `cat` that can still open a socket to the rest of the estate is a
pivot point with an allow-list on it, and the proxy's forwarding policy does not
see that traffic at all (0015 records why). Egress confinement is the half that
turns "this account cannot run anything interesting" into "this account cannot
do anything interesting".

The ephemeral method is the only place this is cheap, and it is cheap only
because the account is per session: a confinement that would be a fleet-wide
change for a standing account is, here, four lines written into a file the proxy
already writes.

## In scope

### Rendering a rung onto the account (`internal/auth/target`)
The provisioner gains, per rung named by 0015's contract **on each axis**, the
target-side mechanism that implements it. A route can sit on a different rung
per axis, so these compose rather than nest. Expect at least:

- **`authorized_keys` options.** The proxy already writes that file and already
  writes `expiry-time=` into it (0007). A `command=` dispatcher plus `restrict`
  is therefore the highest-value rung per line of code in this repository, and
  it is the only one that also holds against a direct connection with that key.
  The dispatcher receives the client's request in `SSH_ORIGINAL_COMMAND`,
  validates it against the same allow-list the filter engine holds, and
  `exec`s the approved argv **directly — never through a shell**, which is the
  property D12 requires of restricted exec.
- **Shell and `PATH` confinement** for the rung whose guarantee is a guardrail
  rather than a boundary: a restricted shell plus a curated directory of
  symlinks as the account's whole `PATH`. Document it as a guardrail in the code
  and in the learnings, in the words 0015 chose. Do not let it drift into being
  described as a boundary.
- **Filesystem confinement** where 0015's table says a rung requires it: a
  per-session home mounted `noexec,nosuid,nodev`, or a mount namespace. Only
  build this if 0015 named a rung that needs it.
- **systemd confinement**, if 0015 ranked it where it looks like it ranks: a
  drop-in on the session's `user-<uid>.slice` (or a `systemd-run` wrapper
  invoked from the `command=` dispatcher) carrying the sandbox directives for
  the execution rung and the `IPAddress*` / `PrivateNetwork=` directives for the
  egress one. It is the rung with no policy module, no MAC, and nothing
  installed — a file and a `daemon-reload` — so it is likely the one most
  deployments actually get. Treat "systemd is present, cgroup v2 is mounted, and
  the directives this rung needs exist in *this* systemd version" as a
  capability to probe and report (0015), not as an assumption: the directives
  landed across many releases and a silently-ignored one is a rung that claims a
  guarantee it is not delivering.
- **Egress confinement** for the reach axis, by whichever mechanism 0015 chose:
  the systemd directives above, or a per-uid netfilter rule
  (`iptables -m owner --uid-owner`, nftables `meta skuid`), or a network
  namespace. Two things this rung must get right, both of which are teardown
  problems rather than setup problems — see below.

Two rules that are not optional:

- **The policy is not re-authored here.** The allow-list is the one already in
  the authorize response (`filter_policy.restricted_exec`, 0006/0010). This
  phase *renders* it; it never derives, widens, or defaults it. Two places that
  each decide what may run is the bug this whole architecture exists to avoid
  (D2).
- **A rung the proxy cannot provide on this target is an outage-class denial**
  naming the session id (PLAN §4.3), and nothing is provisioned. Never a silent
  downgrade — the audit record would then claim a guarantee the session did not
  have. The proxy advertises what it can provide (0015); this is what happens
  when the answer was wrong anyway, and it *will* sometimes be wrong, because
  the proxy learns what a target supports only by touching it.

### Rendering a rung onto a device account (`internal/auth/target/device`)

The `ephemeral-account` method (D13) reaches a class of target where the rungs
above do not exist — there is no `authorized_keys`, no shell, no systemd, no
netfilter — and where the platform's **own** authorizer is available instead,
per session, because the proxy creates the account.

- **Command authorization** is the platform's: an access profile, a privilege
  level, a role, a login class. 0015's vocabulary names rungs by what they
  guarantee rather than by mechanism, so the driver maps a named rung onto its
  platform's construct, and refuses (outage-class, §4.3) when it has nothing
  that delivers that guarantee. Take the mapping from 0014's learnings; do not
  characterise a vendor's RBAC from memory.
- **Reach** is the same story: where the driver declares source-address pinning,
  a rung on the reach axis can restrict the ephemeral account to the proxy's
  address, which is a genuinely strong control — the credential stops working
  from anywhere else, including from a copy of it.
- **The failure mode is coarseness, and it must be recorded.** Vendor RBAC
  groups commands the vendor's way, so a profile permitting diagnostics may
  include a command with a shell escape or a configuration write. Where 0015's
  survey found such a leak, the rung's audit record should carry what it is
  actually enforcing, not the name of the guarantee it was asked for.
- **Pre-provisioned rungs stay pre-provisioned.** A profile that the customer
  defined on the device is attested, not applied, and 0015's contract already
  distinguishes those — a device rung is *applied* only where this phase creates
  or configures it as part of the session.

### Teardown, the reaper, and the parts that get forgotten
Teardown currently verifies that the account and its home are gone (0007). Every
rung that creates state must extend it, and the extension must be **verified the
same way**:

- a mount must be unmounted before the home is removed, and a teardown that
  cannot unmount must fail loudly rather than report success;
- a packet-filter rule keyed on uid must be removed **before** the account is,
  and this ordering is not cosmetic: `useradd` reuses freed uids, so a rule that
  outlives its account silently attaches to whoever gets that uid next — an
  egress boundary quietly transplanted onto an unrelated session, or worse, an
  allow-list transplanted onto one that was supposed to have none. Removal is
  verified like everything else here, and the reaper knows how to find a rule
  whose account is already gone;
- a systemd drop-in must be removed and the manager reloaded, and a lingering
  user slice (`loginctl enable-linger` semantics, or a slice that outlives its
  session) must not keep the confinement — or the absence of it — attached to a
  recycled uid for the same reason;
- the orphan reaper must handle a session that died **mid-rung** — a mounted
  home whose account no longer exists, or an account whose dispatcher was
  written but whose key never was;
- teardown stays idempotent and stays safe to run from the reaper, from the
  session's normal close, and from a panic unwind.

### Audit
The rung actually in force is on the session's audit record (0015 defined the
field; 0011 ships it). A record that says "boundary" for a session that ran at a
weaker rung is the only outcome here worse than not shipping the feature.

### Topology and CI (`deploy/`)
Extend 0012's topology: a target and fixtures exercising each rung, including an
automation-style route whose account may run exactly two binaries.

The target image is `deploy/target/` — 0012 folded the old `deploy/sshd/` into
it, and it now backs both `make test-sshd` and the full topology. Routes go in
`deploy/control/fixtures.template.yaml` (the **mock** Hoplock Control's fixtures
inside this repository's rig — not the sibling Control repo, which vendors only
`api/control.yaml`), and scenarios go in `TestTopology`
(`test/e2e/scenarios_test.go`). Two things that will bite: those subtests are
ordered deliberately — the outage scenario stops Hoplock Control and the
ephemeral-leak check runs last — so new groups go before the outage one; and
`sshBaseArgs` in `test/e2e/harness_test.go` is shared by every scenario, so pass
per-scenario client options rather than changing it.

Two settings in that image are load-bearing and must survive whatever you add:
`UsePAM yes` (without it sshd refuses every account `useradd` created, before it
looks at the key) and `PerSourcePenalties no` (a proxy is one source address, so
its own failed authentications get it blocked from the target). Both are
explained in `deploy/README.md`.

## Out of scope
- **Applying any rung on a `brokered-key` route.** The target is unmodifiable by
  definition (D6a); 0015's contract makes an *applied* rung on such a route an
  error, and this phase inherits that rather than working around it. An
  **attested** rung — the appliance enforcing its own roles or privilege levels,
  which 0015 defines — is not this phase's to apply either: nothing is
  configured for it. What this phase owes it is narrower and must not be
  skipped: the session must run, the audit record must carry the attested rung
  rather than "none", and no target-side provisioning may be attempted. A test
  covers exactly that.
- Shipping SELinux/AppArmor policy modules for customer fleets. If 0015 named a
  MAC rung, implement the hook that *uses* an existing profile and document the
  prerequisite; authoring fleet policy is not this product.
- Changing the filter engine (0010) or the credential methods (0007).

## Acceptance criteria
- A device rung is rendered onto an `ephemeral-account` session against the fake
  FortiOS device from 0014, refused cleanly where the platform cannot deliver
  the named guarantee, and recorded with what it actually enforces.
Against a real `sshd` (extend `deploy/target/` and `make test-sshd`, 0007 — the
image 0012 unified), for each rung 0015 named:

- **The bypass test, per rung.** With an allow-list naming only `cat`, assert
  that `cat` works and that `sh -c 'cat /etc/shadow'`, an uploaded script, and —
  where the rung claims to cover it — a shell escape from an interactive
  session all fail **on the target**. This is 0010's bypass test moved one layer
  down and it is the executable form of the rung's marketing claim: if it fails,
  either the rung broke or the claim was never true.
- **The egress test, per reach rung.** From inside a confined session, assert
  that a connection to a destination the rung forbids fails **on the target**,
  that a permitted destination still works where the rung allows one, and that
  the failure mode is a refused connection rather than a hang. Assert it with a
  binary the execution rung permits, so the two axes are shown to be
  independent — a session confined on one axis and open on the other is the
  configuration this phase exists to make expressible, and it must behave.
- **The uid-reuse test.** Provision, tear down, then provision again until the
  uid is reused (or force it), and assert the new session inherits **no** rule,
  slice, or mount from the old one. This is the one failure here that is silent
  in every other test.
- **The direct-connection test** for the `authorized_keys` rung: connecting to
  the target with the ephemeral key *without going through the proxy* is still
  confined. No other rung in this system can pass this test, and it is why the
  rung is worth having.
- A route whose rung the proxy cannot provide is denied as an outage naming the
  session id, and **nothing is left on the target** — asserted the way 0007
  asserts it, by listing accounts and homes after the failure.
- Teardown removes every artifact of every rung, verified; a crash mid-rung
  leaves an orphan the reaper removes, including any mount.
- No leftover accounts, homes, mounts, or dispatchers after the suite.
- The audit record names the rung that was in force **on each axis**, and a test
  asserts it matches what the target actually enforced rather than what the
  route asked for.
- A `brokered-key` route carrying an attested rung connects, provisions nothing,
  and is recorded at that rung.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0016-target-side-enforcement-learnings.md`. Summary block MUST
document, per rung and per axis: the exact mechanism, what teardown must undo,
what the reaper must recognise, the target-side prerequisites (so a deployment
can meet them, including the systemd version and cgroup mode where a rung
depends on them), and — in one sentence each, in the contract's words — what the
rung guarantees and what it does not. Say explicitly which rungs were probed as
capabilities and how, because 0012's topology has to reproduce it.
