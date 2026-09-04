# 0019 — Target-side enforcement — Learnings

## Summary
- **What shipped:** the rungs of `docs/PLAN.md` §6.5 are now real on the target.
  `internal/auth/target` probes what a target can enforce, refuses a rung it
  cannot (outage-class, nothing provisioned), renders the rest onto the ephemeral
  POSIX account and onto a device account, tears every artefact down in an order
  the uid hazard dictates, sweeps residue whose account is already gone, and puts
  the rung **in force** on the audit record. **No contract change** — `api/` is
  untouched, so no cross-repo obligation (`docs/CROSS-REPO-PROTOCOL.md` §1).
- **Key files:** `internal/auth/target/{enforcement,confine,confinescript,probe}.go`
  (new) + `{script,ephemeral,reaper,selector,statickey,brokered,deviceaccount,auth,registry}.go`;
  `internal/auth/target/device/{driver,registry}.go` + `device/fortios/fortigate.go`;
  `internal/routing/resolve.go`; `internal/proxy/{session,logging}.go`;
  `internal/logging/{record,device}.go`; `internal/config/config.go` +
  `config.example.yaml`; `cmd/proxy/main.go`; `deploy/{compose.yaml,README.md,
  target/Dockerfile,target/compose.yaml,control/fixtures.template.yaml}`;
  `test/e2e/scenarios_test.go`; `docs/PLAN.md` (§5.1, §5.3, **§6.5 new
  subsection**, §10).
- **Types/identifiers added:** `target.{Enforcement,EnforcementResult,
  EnforcementFrom,ProxyCapabilities,ErrRungUnavailable,DefaultEnforcementBase}`;
  `target.Target.Enforcement`, `target.ProvisionedAccess.Enforcement`;
  `routing.Route.Enforcement` + `EnforcedExecution()`/`EnforcedReach()`;
  `routing.ResolverOptions.Capabilities`; `target.{EphemeralOptions,Options}.Reporter`;
  `EphemeralOptions.EnforcementBase`; `device.Capabilities.{CommandAuthorization,
  AuthorizationCaveat,AuthorizesCommands()}`; `target.AccountMapping.Enforcement`;
  `logging.EnforcementAttrs` + `AttrEnforcement{Execution,Reach,Verified,
  AttestedBy,Attestation,MechanismExec,MechanismReach,Caveat}`; config key
  `auth.target.ephemeral_user.enforcement_base`.
- **Mechanism, per rung and per axis** (the full table with the reasoning is
  `docs/PLAN.md` §6.5, *What this proxy actually renders*):

  | Rung | Mechanism | What teardown must undo | What the reaper must recognise |
  | --- | --- | --- | --- |
  | `account-restricted` | `authorized_keys` `command=` **dispatcher** over the route's own `restricted_exec` list + `restrict` (or the `no-*` options); the dispatcher is also the account's **login shell**; curated `PATH` directory (a **guardrail**) | `<enforcement_base>/<account>/` | a confinement directory whose account is gone |
  | `account-confined` | the above + home bind-mounted `noexec,nosuid,nodev` + `setpriv --no-new-privs` on every `exec` | the **mount, before the home is removed** | a mount over `<home_base>/hl-*` |
  | `account-egress-restricted` | per-uid `iptables`/`ip6tables -m owner --uid-owner` allow rules + default REJECT **on both families** | the rules, **before the account** | a rule whose `--comment hoplock:<account>` names a gone account |
  | `account-network-isolated` | the same filter: loopback allowed, everything off-host rejected on both families | as above | as above |
  | `platform-authorized` | the platform's own authorizer under the route's `enforcement.platform_role` (FortiOS: `set accprofile`) | the account itself (unchanged) | unchanged (0014/0017 sweeps) |
  | `platform-attested`, both proxy-side defaults | nothing is rendered | nothing | nothing |

- **What each rung guarantees, and what it does not** — one sentence each, in the
  contract's words, is in *Details → The guarantee sentences*.
- **Decisions/affected:** D12 (as amended by 0018), D13 (a new declared
  capability), D6a, D14, D16 untouched. Two deliberate mechanism deviations from
  §6.5's candidate rows (restricted shell, systemd) are recorded in PLAN and
  argued in Details.
- **Gotchas:** teardown order is a guarantee, not tidiness — key, processes,
  **rules before the account**, mount before the home; a `case` pattern in POSIX
  `sh` is a WORD, so the blanks in the dispatcher's character set are
  backslash-escaped or `dash` refuses the script outright; `iptables`/`mount`
  need `NET_ADMIN`/`SYS_ADMIN` in a container.
- **What the NEXT session must know:** phase **0024** owns uid allocation and the
  two phases are halves of one fix — read *What a confined account can still
  leave behind* below. Three of 0018's follow-ups (`require_session_capture`,
  `concurrency`, `grant_context` into records) are **not** in prompt 0019's scope
  and now have a prompt: `prompts/queued/0030-session-bounds-enforcement.md`.

## Details

### The guarantee sentences

Each rung, what it guarantees and what it does not, in one sentence each. They
are the sentences the code comments and the audit record use, deliberately:

- **`account-restricted`** — *guarantees* the account can execute only the
  executables `restricted_exec` names, for every login to it, including one that
  never went through this proxy. *Does not guarantee* the strength of the list:
  an allow-list containing an interpreter is not an allow-list, and the rung is a
  claim about the mechanism rather than about the policy author's judgement.
- **`account-confined`** — *guarantees* that, in addition, the session's
  processes cannot gain privilege and cannot execute anything the session itself
  wrote. *Does not guarantee* anything about which of the system's own binaries
  it runs, nor anything a permitted binary chooses to do.
- **`account-egress-restricted`** — *guarantees* that the session's own
  processes reach only the destinations the policy names, whether or not the
  traffic went through an SSH channel. *Does not guarantee* anything about
  loopback unless the policy names it, anything about a destination written as a
  name rather than an address (which is refused), and nothing about traffic that
  does not originate locally from that uid.
- **`account-network-isolated`** — *guarantees* the session's processes reach
  nothing off the host at all. *Does not guarantee* that the session can do
  anything useful with the network: it is all or nothing, and being too strong
  for a route is a policy-authoring failure rather than a security one.
- **`platform-authorized`** — *guarantees* the device's own authorizer decides
  every command, ahead of anything the proxy could parse, under the role the
  route names. *Does not guarantee* fineness: vendor RBAC is coarse and named,
  and the guarantee is exactly the vendor's grouping and no finer (the driver's
  `AuthorizationCaveat` is on the record for that reason).
- **`platform-attested`** (either axis) — *guarantees* nothing this system
  applied or verified; it records an attributable claim that the target enforces
  something already. *Does not guarantee* that the claim is true, and the record
  says so (`enforcement_verified=false`).

### Which rungs were probed as capabilities, and how

The probe (`probe.go`) runs over the management login **before anything is
created**, and every line of it measures rather than infers. A version number is
not an answer: "systemd is present" is not "this systemd honours the directive
this rung needs", and a silently-ignored directive is a rung claiming a guarantee
it is not delivering. `deploy/target/` reproduces all of it.

| Probe key | How it is measured | Which rung reads it |
| --- | --- | --- |
| `sshd_key_options` | `sshd -T` parses, and its effective `pubkeyauthentication` is not `no`. **An sshd this probe could not run answers "unknown", which is treated as yes** — see the note below | `account-restricted`, `account-confined` |
| `sshd_restrict` | the version string, `OpenSSH_7.2+` | neither: it selects `restrict` vs the individual `no-*` options |
| `restricted_shell` | the first of `/bin/rbash`, `/usr/bin/rbash`, `/bin/rksh`, `/usr/bin/rksh` that is executable | neither: recorded, and its absence narrows the guardrail only |
| `no_new_privs` | `setpriv --no-new-privs /bin/true` actually runs | `account-confined` |
| `bind_mount` | a scratch `mktemp -d` is bind-mounted, remounted `noexec,nosuid,nodev`, unmounted, removed | `account-confined` |
| `ipv4_owner_filter`, `ipv6_owner_filter` | a throwaway `-A OUTPUT -m owner --uid-owner 2147483646 -m comment --comment hoplock-probe -j ACCEPT` is installed **and removed** | **both** reach rungs need **both** keys |
| `systemd`, `cgroup2` | `systemctl --version` with `/run/systemd/system`, and `/sys/fs/cgroup/cgroup.controllers` | nothing reads them; they are operator detail |

Two details worth keeping:

- the filter probe names a uid no account holds (2³¹−2), so a probe interrupted
  between the insert and the delete leaves a rule matching **nobody** rather than
  a rule matching somebody;
- `sshd_key_options` is the one place the probe fails *open*, deliberately. The
  check is redundant — an sshd that ignores key options ignores the dispatcher,
  and the rung's own first login fails immediately and visibly — while refusing
  on "could not run `sshd -T`" would refuse every target whose provisioning
  account cannot execute the sshd binary, which is most fleets that do not
  provision as root.

The observation is cached per target for `control.DefaultCapabilityTTL` (15m),
reported on `POST /v1/capabilities/report` in the background, and **re-checked
against the live target at provisioning time**. A report grants nothing, so the
worst a stale record can cause is a refused session.

### Target-side prerequisites, so a deployment can meet them

- an sshd honouring `authorized_keys` options (any OpenSSH; `restrict` needs
  7.2+, older ones get the individual `no-*` options and the same fence);
- `util-linux`'s `setpriv`, and a kernel/namespace where the provisioning account
  may bind-mount and remount (in a container: `CAP_SYS_ADMIN`) — for
  `account-confined`;
- `iptables` **and** `ip6tables` with the `owner` and `comment` matches, and the
  privilege to install rules (in a container: `CAP_NET_ADMIN`) — for either reach
  rung. Both families are required for both rungs;
- a writable `auth.target.ephemeral_user.enforcement_base` (default
  `/var/lib/hoplock`), which must be **outside** the account's home;
- no systemd version and no cgroup mode is required by anything shipped here.
  They are probed and recorded because a future rung would need them, and because
  their absence is the commonest reason a target cannot take one.

### Two mechanism deviations from §6.5's candidate rows, and why

**A restricted shell is not the login shell.** §6.5 row 6 pairs `rbash` with a
curated `PATH`. A restricted shell refuses to execute a command name containing
`/`, and sshd runs a forced command as `<login shell> -c "<command= value>"` —
so `rbash` as the login shell would refuse the dispatcher, whose path must be
absolute and must be outside the home (which `account-confined` mounts `noexec`).
Every session on the rung would fail. What replaces it is strictly stronger: the
**dispatcher is the login shell**, so `su`, `cron`, and a second key land on the
same boundary. The curated `PATH` survives and is described as a **guardrail**
everywhere it appears, in 0018's words. Do not let a later change promote it.

**systemd is not the mechanism for `account-confined`, and `IPAddressAllow=` is
not the mechanism for the reach axis.** A `.slice` unit carries resource-control
settings; `NoNewPrivileges=`, `ProtectSystem=` and `RestrictSUIDSGID=` are
exec-context settings a slice does not carry, and systemd logs an unknown key and
proceeds — precisely the silently-ignored directive §6.5 says a probe exists to
catch. The `systemd-run` alternative needs a user manager the session under
`command=` does not have. `setpriv` plus a `noexec` home delivers the same two
sentences with nothing to misread. On the reach axis `IPAddressAllow=` speaks
addresses and prefixes only, and a route's destinations carry **ports**; the
packet filter renders the port, so nothing has to be silently widened.

### Rules the implementation holds, each for a specific failure

- **The policy is not re-authored here.** The dispatcher's allow-list is the
  route's `filter_policy.restricted_exec`, rendered element for element
  (including "arguments not covered by a spec are denied"). An
  `account-restricted` route carrying no list is refused rather than defaulted.
  A policy argument containing a shell pattern character is refused too: a
  literal `*` in a policy would become a wildcard on the target and **widen** the
  allow-list the proxy holds.
- **The dispatcher accepts an allow-list of characters, not a deny-list of shell
  syntax.** A deny-list is incomplete on the day it ships. The set is
  ``[A-Za-z0-9_=/.:,+@%-]`` plus space and tab, and **the two blanks are
  backslash-escaped**: a `case` pattern is a *word*, an unquoted blank ends it,
  and `dash` rejects the unescaped form outright ("word unexpected"). That cost
  an hour; it will cost the next reader nothing.
- **The dispatcher never interposes a shell.** `set -f`, `IFS` of space and tab,
  `set -- $cmd`, match, `exec "$@"`. Nothing re-expands what was approved.
- **Both address families are always closed**, even when the destination list
  names only IPv4 — the mistake 0015 found on the device side.
- **REJECT, never DROP.** The rung's failure mode has to be a refused connection
  rather than a hang: a hang reads as a broken network and hides the boundary.
- **The interpreter problem is warned about and never refused** (0018's
  decision). `interpretersIn` is a reporting list that lands in
  `enforcement_caveat` and a `WARNING` log line; a proxy-side refusal would be a
  blacklist masquerading as a boundary.
- **A destination named by hostname or wildcard is refused** (outage-class): a
  filter resolves a name once, at insert time, and a rule that drifts from its
  policy is a boundary nobody can audit.

### Refusal vs. skipped rung — the rule, and where each one lives

The class is decided by whether a connection was needed to find out:

- a rung a **declaration** rules out — this build does not implement it, this
  driver's platform has no authorizer — is a **skipped ladder rung**
  (`ErrRungUnsatisfiable`, D14, and 0018's explicit "an entry that cannot carry
  the route's rung is a skipped rung"). The proxy walks on; exhausting the ladder
  is the outage-class denial it already was. This is the device path
  (`DeviceAccountAuthenticator.resolveEnforcement`, answerable inside
  `CanSatisfy`, which must not dial anything);
- a rung the **live target** turns out not to support is `ErrRungUnavailable`,
  outage-class, with nothing provisioned — the POSIX path, after the probe.

**This is a deliberate reading of prompt 0019**, which says the device case
"refuses (outage-class)". Making it outage-class there would break D14's ladder
walk: a one-entry ladder is indistinguishable either way, and on a longer ladder
the skipped-rung reading is the one 0018's contract states. The net user-visible
behaviour on a route with no alternative is identical — an outage naming the
session id — because ladder exhaustion is itself outage-class.

The third case: an **applied** rung on a method that provisions nothing
(`brokered-key`, `static-key`) is refused **before** the method runs, so the
target is untouched. An **attested** rung there runs normally and is recorded at
that rung rather than at "none", which is the whole point of the distinction.

### Audit

One record per session, `event=enforcement.applied`, carrying 0018's four fields
(`enforcement_execution`, `enforcement_reach`, `enforcement_verified`,
`enforcement_attested_by`) plus `enforcement_attestation`,
`enforcement_mechanism_execution`, `enforcement_mechanism_reach` and
`enforcement_caveat`. The device method's `AccountMapping` carries the same
`EnforcementResult`, so a constrained-platform session's only attribution record
also carries its rung. `logging.EnforcementAttrs` is the single renderer, so the
two producers cannot drift.

The record names the rung **in force**. Everything that could have made it weaker
than the route asked for has already failed the session by that point.

### What a confined account can still leave behind — for phase 0024

0019 and 0024 are halves of one fix and neither may assume the other has landed.
What this phase does *not* remove, and what 0024's author has to plan for:

- **Anything the session wrote outside its home.** The `noexec,nosuid,nodev`
  mount covers the home only. `/tmp`, `/var/tmp`, `/dev/shm`, and any
  world-writable directory the allow-listed binaries can write survive teardown
  with the **old uid's ownership**, and a reused uid inherits them. That is the
  precise gap 0024 closes from the other end; the filesystem rung here stops
  there being anything *inside* the home to inherit.
- **Anything a permitted binary created as a side effect** — a lock file, a
  socket, a log entry — for the same reason.
- **Nothing else.** The account, its home, its key, its packet-filter rules, its
  mount and its confinement directory are all removed and all **verified**, and
  a residue whose account is already gone is swept without a grace period
  (safe because provisioning creates the account first, so a residue with no
  account can only be a session that died mid-rung).

`useradd` reuses the lowest free uid, so on a quiet target the very next session
gets the previous one's uid. The teardown ordering here means it inherits no
*rule*, no *mount* and no *dispatcher*; it may still inherit *files*.

### Testing

- `internal/auth/target/confine_test.go` runs against the fake host, which now
  models `usermod`, `mount`/`umount`, `iptables`/`ip6tables`, `setpriv` and
  `sshd` as **working** commands over real files — so "teardown removed the rule"
  is asserted against a rule that was really there. The generated dispatcher is
  executed under a real `/bin/sh` with a real allow-list, which is the bypass
  test one layer down.
- One fake-host rule worth keeping: a test that wants "this target cannot do
  that" calls `breakCommand`, which **replaces** the fake with a failing stub. An
  earlier version removed it, which exposed whatever the machine running the
  tests had on its own `PATH` — a unit test that would have edited the firewall
  of whoever ran it.
- `internal/auth/target/sshdenforcement_test.go` (`make test-sshd`) is the only
  place the claims that need a real sshd and a real kernel are executable: the
  **direct-connection** test (a client holding the session key, not going through
  the proxy, still confined), the egress test with its "refused, not hung"
  assertion, uid reuse, teardown verification on the target itself, and the
  mid-rung residue sweep.
- `test/e2e/scenarios_test.go` gained `target-side enforcement`, placed **before**
  the outage group per 0012's ordering rule, plus residue checks in the leak
  scenario. `deploy/control/fixtures.template.yaml` gained four routes: the
  two-binary automation account, the isolated one, an attested `brokered-key`
  route, and one whose rung cannot be rendered (a destination named by hostname).

### What could not be run in this session

`golangci-lint` and the container suites. The installed linter is built with Go
1.25 and the module targets 1.26, which it refuses outright (CI pins v2.13.2 for
exactly this reason — see `.github/workflows/ci.yml`); and the Docker daemon is
unavailable, so `make e2e` and `make test-sshd` are CI's `e2e` job. `go build`,
`go vet`, `go test -race ./...`, `gofmt` and `goimports` all pass locally, and
the rendered `fixtures.yaml` was loaded by a real `cmd/mock-control` (22 routes)
to prove the new fixture keys parse.

### Follow-ups this phase does not do

- **`prompts/queued/0030-session-bounds-enforcement.md`** (new): the three D16
  bounds 0018's learnings assigned to 0019 that prompt 0019's own scope does not
  name — `require_session_capture` before the target leg is dialled, the
  `concurrency` caps against the `SessionRegistry`, and the grant context into
  `internal/logging`'s records. It is independent of 0020–0029 and can run any
  time after 0018.
- **0024** — the non-reusing uid range (see above).
- **Attestation verification** — reading a device's configuration back to check
  an attested claim. Still a real feature, still needs no contract change.
- **A MAC rung.** 0018 named none, so nothing here uses SELinux or AppArmor. If
  one is ever added, the hook is `planConfinement` and the prerequisite is an
  existing profile: authoring fleet policy is not this product.
