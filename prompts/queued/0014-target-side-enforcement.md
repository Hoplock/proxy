# 0014 — Target-side enforcement: confining the ephemeral account

> New phase, queued after 0013 for the reason 0009 came after 0006: the
> vocabulary lands first, then the thing that enforces it.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — especially §2 (**D12**, as amended by 0013), §5.1 (the
  ephemeral lifecycle and its teardown guarantees), §6.3 (the enforcement-point
  table 0013 recorded), §4.3 (what the user is told).
- `docs/learnings/` — read summaries; open **`0013`** (the rung vocabulary,
  capability advertisement, and refusal rule — this phase implements exactly
  what that summary names), `0007` (the provisioning and teardown scripts, the
  naming convention, the orphan reaper, and the target-side prerequisites) and
  `0010` (the restricted-exec policy object, which is the policy this phase
  renders onto the target).

## Objective
Make the enforcement rung Hoplock Control chose real on the target: confine the
ephemeral account so that what it *can* execute is bounded by the OS, not by
what the proxy managed to parse on the way past.

## Why it is worth the complexity

Everything the proxy enforces, it enforces on a string in flight. That is a real
boundary for `exec` and no boundary at all for an interactive shell (D12).
Confining the account moves the same policy behind sshd and the kernel, where it
holds for a pty, for a shell escape out of an editor, for an uploaded script —
and for a session that reaches the host **without going through the proxy at
all**, which is the one failure mode nothing else in this system covers.

The ephemeral method is the only place this is cheap, and it is cheap only
because the account is per session: a confinement that would be a fleet-wide
change for a standing account is, here, four lines written into a file the proxy
already writes.

## In scope

### Rendering a rung onto the account (`internal/auth/target`)
The provisioner gains, per rung named by 0013's contract, the target-side
mechanism that implements it. Expect at least:

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
  and in the learnings, in the words 0013 chose. Do not let it drift into being
  described as a boundary.
- **Filesystem confinement** where 0013's table says a rung requires it: a
  per-session home mounted `noexec,nosuid,nodev`, or a mount namespace. Only
  build this if 0013 named a rung that needs it.

Two rules that are not optional:

- **The policy is not re-authored here.** The allow-list is the one already in
  the authorize response (`filter_policy.restricted_exec`, 0006/0010). This
  phase *renders* it; it never derives, widens, or defaults it. Two places that
  each decide what may run is the bug this whole architecture exists to avoid
  (D2).
- **A rung the proxy cannot provide on this target is an outage-class denial**
  naming the session id (PLAN §4.3), and nothing is provisioned. Never a silent
  downgrade — the audit record would then claim a guarantee the session did not
  have. The proxy advertises what it can provide (0013); this is what happens
  when the answer was wrong anyway, and it *will* sometimes be wrong, because
  the proxy learns what a target supports only by touching it.

### Teardown, the reaper, and the parts that get forgotten
Teardown currently verifies that the account and its home are gone (0007). Every
rung that creates state must extend it, and the extension must be **verified the
same way**:

- a mount must be unmounted before the home is removed, and a teardown that
  cannot unmount must fail loudly rather than report success;
- the orphan reaper must handle a session that died **mid-rung** — a mounted
  home whose account no longer exists, or an account whose dispatcher was
  written but whose key never was;
- teardown stays idempotent and stays safe to run from the reaper, from the
  session's normal close, and from a panic unwind.

### Audit
The rung actually in force is on the session's audit record (0013 defined the
field; 0011 ships it). A record that says "boundary" for a session that ran at a
weaker rung is the only outcome here worse than not shipping the feature.

### Topology and CI (`deploy/`)
Extend the 0012 topology and `deploy/sshd`: a target and fixtures exercising each
rung, including an automation-style route whose account may run exactly two
binaries.

## Out of scope
- **`brokered-key` routes.** The target is unmodifiable by definition (D6a);
  0013's contract makes a rung on such a route an error, and this phase inherits
  that rather than working around it.
- Shipping SELinux/AppArmor policy modules for customer fleets. If 0013 named a
  MAC rung, implement the hook that *uses* an existing profile and document the
  prerequisite; authoring fleet policy is not this product.
- Changing the filter engine (0010) or the credential methods (0007).

## Acceptance criteria
Against a real `sshd` (extend `deploy/sshd` and `make test-sshd`, 0007), for
each rung 0013 named:

- **The bypass test, per rung.** With an allow-list naming only `cat`, assert
  that `cat` works and that `sh -c 'cat /etc/shadow'`, an uploaded script, and —
  where the rung claims to cover it — a shell escape from an interactive
  session all fail **on the target**. This is 0010's bypass test moved one layer
  down and it is the executable form of the rung's marketing claim: if it fails,
  either the rung broke or the claim was never true.
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
- The audit record names the rung that was in force, and a test asserts it
  matches what the target actually enforced rather than what the route asked
  for.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0014-target-side-enforcement-learnings.md`. Summary block MUST
document, per rung: the exact mechanism, what teardown must undo, what the
reaper must recognise, the target-side prerequisites (so a deployment can meet
them), and — in one sentence each, in the contract's words — what the rung
guarantees and what it does not.
