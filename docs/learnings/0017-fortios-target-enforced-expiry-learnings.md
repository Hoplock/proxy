# 0017 — FortiOS target-enforced expiry — Learnings

## Summary
- **What shipped:** a FortiGate now holds its own administrator's deadline.
  `Capabilities.EnforcesExpiry` is **true**, a route asking for
  `expiry_posture: target-enforced` is served rather than skipped, and the
  driver creates a `config firewall schedule onetime` entry, references it with
  `set schedule`, tears both objects down together, and sweeps an orphaned
  schedule through a new optional interface. The window is computed from the
  **device's** clock, not the proxy's.
- **Key files:** `internal/auth/target/device/{driver.go,registry.go}`,
  `internal/auth/target/device/fortios/{schedule.go (new),fortigate.go,value.go,cli.go,doc.go}`,
  `internal/auth/target/{deviceaccount.go,devicereaper.go}`,
  `internal/logging/{record.go,device.go}`, `internal/sshtest/fortios.go`,
  `docs/PLAN.md` (D13, §5.3 "As taken (phase 0017)", §10),
  `docs/FORTIOS-DOC-VERIFICATION.md`.
- **Types/identifiers added:** `device.Residue`, `device.ResidueSweeper`
  (`ListResidue`/`RemoveResidue`), `device.Capabilities.ExpiryMechanism`,
  `target.AccountMapping.ExpiryMechanism`, `target.SweepFailure.ObjectKind`,
  `logging.AttrExpiryMechanism`, `logging.AttrDeviceObjectKind`,
  `sshtest.FortiOSSchedule` + `FakeFortiOS.{Schedules,AddSchedule,SetNow}`.
- **The four decisions.** (1) **Denying login MEETS the bar**: the analogue is
  OpenSSH's `expiry-time` (PLAN §5.1), which the contract was already written
  around — it also refuses new authentications, also leaves a live session
  running, also leaves the object for the reaper. Taken **conditional on the
  window closing every door into the account**, which is hardware item 1.
  (2) **What the device does is DECLARED** in `ExpiryMechanism`, required of a
  shipped driver by `CheckShipped` and recorded on every session, because the
  bit alone overstates it. (3) **The schedule takes the administrator's own
  name** — it inherits the reaper prefix and the uniqueness token, and the
  naming scheme never exceeds the 32-character schedule limit; teardown removes
  the administrator **first**, and the residue sweep catches the orphan whose
  account never existed. (4) **Only a target-enforced route gets a device
  deadline**: the provisioner passes `CreateRequest.Lifetime` only then, so a
  proxy-enforced route still writes one object.
- **Corrected `Capabilities`:** `EnforcesExpiry: true` + `ExpiryMechanism`
  (decision 1+2, and it rests on the conditional in hardware item 1);
  `MaxAccountNameLen: 64`, `PersistsAcrossReload: true` + `PersistenceReason`,
  `CredentialKinds`, `PinsSourceAddress`, `Fields` — all unchanged.
- **Teardown/reaper now remove:** the administrator **and** the schedule of the
  same name, on every removal (teardown does not know which posture created what
  it removes); plus, on each sweep, any prefixed schedule no account references,
  after the same first-seen grace period an untracked account gets.
- **Gotchas:** `set end` is an absolute datetime in the **unit's local time** —
  a window from the proxy's clock is wrong by the offset and the dangerous
  direction is silent; sub-minute lifetimes cannot be expressed and are refused
  rather than rounded up; the schedule's datetimes are the **one** value this
  driver sends unquoted.
- **What the NEXT session must know:** **Fortinet's documentation was NOT
  reachable from this session** (the same egress block phase 0014 hit). This
  phase added **no new sourced facts**; everything it could not check is built to
  fail loudly, and the hardware list below is longer and more load-bearing than
  usual. No `api/` change, so no cross-repo obligation
  (`docs/CROSS-REPO-PROTOCOL.md` §1: no shared surface touched).

## Details

### The hardware list, decisive item first

1. **Does the schedule gate EVERY authentication path, or only password login?**
   The declaration was made conditional on this by the user, in those words. The
   field description is about the administrator — "Firewall schedule used to
   restrict when the administrator can log in" — and the denial is logged at
   authentication; but Fortinet's worked example is a password login and this
   driver also installs `ssh-public-key1`. **If a public-key login bypasses the
   schedule, `EnforcesExpiry` is wrong and comes back out**, and the route that
   most needs it is the one that would be least protected.
2. **Does an already-established session survive its window closing?** Still
   unanswered, still undocumented, and inherited unchanged from 0015. It is not
   modelled in `internal/sshtest`; it is *declared* in `ExpiryMechanism`, which
   says the account is not deleted and a live session may outlive the deadline.
   Ending the session at its deadline is 0025's.
3. **Is `config firewall schedule onetime` reached through `config global` on a
   partitioned unit?** Firewall objects are ordinarily per-VDOM; the prompt
   settles it as global and this phase could not check. Mitigated by ordering:
   the schedule is created **before** `set schedule` names it, so a wrong scope
   fails the reference and fails the attempt rather than leaving an
   administrator whose deadline the device ignores.
4. **Does `get system status` carry a readable system time, and in what
   rendering?** `systemTimePattern` plus four layouts. Unreadable ⇒ the expiring
   route is refused (a failed attempt, never `ErrUnsupported`), and every route
   that needs no schedule is still served on the same unit.
5. **Can a schedule an administrator still references be deleted?** The fake
   refuses it (`object is in use`, the string `cli.go` already matched), which
   is the strictest reading; the driver removes the administrator first, so the
   answer does not change its behaviour — it changes whether the ordering was
   luck.
6. **Is the `end` minute inclusive?** The driver truncates, so its window can
   only be shorter than the lifetime asked for, never longer. If `end` is
   inclusive through :59, a window can run up to 59 seconds past its nominal
   minute — still bounded by the truncation, worth confirming.

### Why the schedule shares the account's name

It was the alternative to a second uniqueness token, and it wins on the
properties that matter rather than on brevity. The prefix and token are the two
things PLAN §5.3 says a name cannot give up; sharing the name inherits both. And
it makes "is this an orphan" answerable **from a device read alone** — no
correlation table, so nothing a crashed process could have lost. The constraint
it has to clear is the schedule-name limit, where the naming KB (32) and the
`schedule` field (35) disagree: the smaller is taken, and
`internal/auth/target`'s scheme never emits a name over 32 characters on any
platform, so it fits with nothing to spare and nothing needed.
`validateScheduleName` is where that stops being an argument and becomes a
check.

### Why `ResidueSweeper` is optional rather than a fifth `Driver` method

D13 makes customer-written drivers first class and says the declarative driver
document and the subprocess contract arrive as implementations of `Driver`. A
fifth operation would put an object nearly every platform does not have into
both of those formats, and every such driver would implement a no-op. As an
optional interface the cost falls only on drivers that create residue, and the
reaper asks. The split of responsibility is the part worth keeping: the driver
decides what "unreferenced" means, because only it knows what the reference is;
the reaper decides **whether to remove**, because a schedule is legitimately
unreferenced for one round trip while another session is creating it, and the
grace period is what keeps a sweep from failing that session's provisioning.

### Why the provisioner, not the driver, decides to render a lifetime

`CreateRequest.Lifetime` is now set only under `target-enforced`. The
alternative — the driver rendering whatever lifetime it is handed — puts a
second object on a customer's firewall for every proxy-enforced route as well,
and leaves a device deadline behind an audit record that says `proxy-enforced`.
D13 wants those decisions in one place against a uniform description; this is
that place (`deviceRoute.deviceLifetime`).

### What the fake device now models, and at which reading

`internal/sshtest/fortios.go` grew the schedule table, `set schedule` as a
checked **reference**, a per-unit clock, and enforcement of the window at both
authentication callbacks. Two of those are the strictest reading of something
undocumented (hardware items 1 and 5) and both are labelled in the source — the
standard phase 0015 set for this file, because a fake more permissive than the
device it stands in for turns a driver bug into a green build. `SetNow` is how a
test closes a window without touching the account, which is the only way to
assert that the **device** is what stops honouring the credential.

Mutation-checked while writing: dropping `set schedule`, computing the window
from the proxy's clock, and skipping the schedule in teardown each fail three,
three and two tests respectively.

### Follow-ups (not done here, deliberately)

- **The e2e topology does not exercise `target-enforced`.** `deploy/` was out of
  this prompt's scope and its fixtures are all `proxy-enforced`; a route through
  the compose topology would prove the two objects against a device the proxy
  reaches over a real network. Worth a small prompt, or a line in 0023's.
- **`cmd/mock-control/fixtures.example.yaml` names `platform: fortios`** where
  the driver registers `fortigate`, so that example route resolves to a skipped
  rung. Pre-existing, untouched here, and harmless in an example — but it is a
  fixture somebody will copy.
- **An account created for a public-key route keeps its placeholder password.**
  Pre-existing and deliberate: `InstallCredential` sets `ssh-public-key1` and
  leaves the 40-character throwaway in place, because a FortiOS administrator
  with **no** password can be logged into with an empty one. It is worth
  re-reading alongside hardware item 1, since both are about how many doors an
  account has.
