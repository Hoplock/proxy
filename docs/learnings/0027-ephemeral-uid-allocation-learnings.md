# 0027 — Ephemeral UID allocation — Learnings

## Summary
- **What shipped:** the uid of an ephemeral account is now the **proxy's** choice,
  not the target's. It is allocated from a dedicated range, **strictly above
  everything the target has ever handed out**, passed as an explicit `useradd -u`,
  recorded on the target so the invariant survives teardown/restart/a second
  proxy, put on the audit record, and **refused as an outage** wherever it cannot
  be guaranteed. No contract change (`api/` untouched, so no cross-repo
  obligation).
- **Key files:** `internal/auth/target/uid.go` (new) + `uid_test.go` (new);
  `internal/auth/target/{script,ephemeral,auth,registry,confinescript}.go`;
  `internal/{config/config.go,logging/record.go}`;
  `internal/proxy/{feedback,session,logging}.go` + `internal/proxy/uid_test.go`
  (new); `config.example.yaml`; `README.md`; `docs/PLAN.md` §5.1/§6.5/§10;
  `deploy/control/fixtures.template.yaml`; `test/e2e/scenarios_test.go`;
  `test/topology/config_test.go`; tests in
  `internal/auth/target/{fakehost,ephemeral,confine,sshdenforcement}_test.go`.
- **Types/identifiers added:** `target.{DefaultUIDMin,DefaultUIDMax,
  ErrUIDUnavailable}`, `target.ProvisionedAccess.AccountUID`,
  `target.EphemeralOptions.{UIDMin,UIDMax}`; unexported `uidAllocator`,
  `uidCensus`, `uidPlan`, `parseUIDCensus`, `parseProvisionedUID`,
  `uidWatermarkName`; `config.{DefaultEphemeralUIDMin,DefaultEphemeralUIDMax,
  MinEphemeralUID,MaxEphemeralUID}` + `EphemeralUserAuth.{UIDMin,UIDMax}`;
  `logging.AttrTargetAccountUID`; `proxy.stageProvisionUID` (`"provision-uid"`).
- **The range: `2000000-2999999`.** Above every distribution's own `UID_MAX`
  (`login.defs` ships 60000, nothing mainstream above 65535), above systemd's
  dynamic users and `nobody`, at the top of SSSD's default id-mapping range, and
  far below 2^31 so every uid is a positive int32. It unavoidably overlaps
  systemd-nspawn's container range, which is why availability is **measured** and
  not assumed (*Details → the range*).
- **The allocation rule:** `next = max(highest in-range uid an account holds now,
  the target's own high-water mark, the highest this process has handed out) + 1`.
  Not the lowest free uid — that is what the target does and is the defect.
- **Wrap-around: it REFUSES and does not wrap.** Not configurable; a pressure
  warning fires from nine tenths of the range. Justification, rejected
  alternatives and the operator's remedy: *Details → The wrap-around decision*.
- **`useradd` flags, measured not assumed** (shadow **4.13**, Ubuntu 24.04 and
  Debian stable): `-u` takes a uid far above `UID_MAX`; a uid already held exits
  **4** where a duplicate name exits **9**. **`-K UID_MIN=…` is NOT the fix** — it
  moves the range searched and still hands a freed uid straight back (2000002 →
  delete → 2000002). Full table: *Details → What was measured*.
- **What is still inheritable — the honest scope of the fix:** anything a session
  writes **outside its home** (`/tmp`, `/var/tmp`, `/dev/shm`, shared storage)
  still survives it, and this phase deletes none of it. 0019's confinement is the
  other half and has landed, but only a route that *names* a confining rung gets
  it. What 0027 guarantees is that no **later session** inherits ownership.
- **What the NEXT session must know:** `enforcement_base` (default
  `/var/lib/hoplock`) is now a prerequisite on **every** ephemeral target, not
  only ones rendering a rung — it holds the uid mark, and a target that cannot
  write it refuses the session. `make e2e`, `make test-sshd` and
  `golangci-lint run` could **not** be run in this session (no Docker; the
  installed linter predates the module's Go version) — see *Details → What could
  not be run*.

## Details

### The defect, and why the fix has to be in allocation

`provisionScript` created the account with `useradd -m -d "$h" -s <shell> "$p"` —
no uid. Teardown removes the account, its processes and its home, and
deliberately does not walk the filesystem, so every file the session wrote
outside its home keeps the bare number. Reuse then hands that number, and with it
ownership of those files, to the next session — a different person, who can read,
rewrite and `chmod` them.

The prompt's framing was "the target's allocator hands out the lowest free UID".
On shadow-utils the mechanism is slightly different and the consequence is
identical, which is worth writing down because a future reader will check:
shadow's `find_new_uid` takes the **highest in-range uid in use and adds one**,
falling back to a hole scan only when that exceeds `UID_MAX`. Delete the account
holding the highest uid and "highest + 1" *is* the uid you just freed. Measured
below.

So the invariant — *a uid this system has allocated on a target is never allocated
there again* — needs a monotonic mark, and the mark has to outlive the account,
the process, and this proxy. Sweeping the filesystem at teardown is the wrong
fix for the four reasons the prompt settles and `docs/PLAN.md` §5.1 now records
(time, blast radius, races, and that it cannot be complete).

### What was measured

On this session's machine — Ubuntu 24.04.4, shadow-utils **4.13**
(`passwd 1:4.13+dfsg1-4ubuntu3.2`), the same shadow generation as
`deploy/target`'s Debian stable-slim image:

| What | Result |
| --- | --- |
| `useradd -u 2000001 …` | exit **0**, plus `useradd warning: … uid 2000001 outside of the UID_MIN 1000 and UID_MAX 60000 range.` on **stderr**. A warning, not a refusal — the provisioning script sends useradd's stderr to `/dev/null` for exactly this. |
| `useradd -u <uid already held>` | exit **4**, `useradd: UID 2000001 is not unique` |
| `useradd <name already held>` | exit **9** (unchanged from 0007) |
| create → `userdel -r` → create, no `-u` | uid **1001** both times. **The defect, reproduced.** |
| create → `userdel -r` → create, with `-K UID_MIN=2000000 -K UID_MAX=2999999` | uid **2000002** both times. **`-K` does not fix it.** |

That last row is the one that decided the design. `-K` looked like the cheap
answer and is not an answer at all: it relocates the range the target's allocator
searches without changing that the allocator reuses inside it. Only choosing the
uid off-target and passing `-u` delivers the invariant, and `-u` is also the more
portable of the two flags — `-K KEY=VALUE` is shadow-only, while an explicit uid
is what every `useradd`-alike takes.

The exit statuses are load-bearing and are now named in `script.go`
(`uidInUseFailed = 4`), because the provisioning loop branches on 4 and treats
every other failure as this account's own rather than retrying it seven times.

### Where the mark lives, and why it is a directory

`<enforcement_base>/uid-watermark/`, whose **entry names are the uids**. The
watermark is the largest of them.

- On the **target**, not in the proxy: it has to survive a teardown (which is when
  the uid becomes reusable), a proxy restart (which has no memory of what it
  allocated), and a second proxy on the same fleet (which shares the range but
  not the process).
- Under `enforcement_base` (0019's directory) because that directory already has
  the properties needed: root-owned, outside every account's home, not writable by
  any session. It is a **sibling** of the per-account confinement directories that
  teardown removes, so it survives them. `confineDiscoverFragment` globs
  `<base>/hl-*`, so the mark is never mistaken for residue.
- A **directory of names** rather than a file holding a number, and this is the one
  design detail that came out of a failing test rather than out of reasoning
  first. The first implementation wrote a single file (`read`, compare, write,
  rename) and `TestEphemeralConcurrentSessionsForOneLogin` failed immediately on a
  shared `.tmp` name. Fixing the temp name would have left the real problem: a
  read-modify-write between two provisioners, whose interleaving moves the mark
  **backwards** over a uid that is still in use — the reuse this phase closes,
  reintroduced by its own fix. Creating a file named after the uid reads nothing
  and is atomic, so the maximum can only rise. Each allocation prunes entries
  **below** its own, never above, so a racer's higher mark is never erased and the
  directory converges to one entry.

The mark is part of the guarantee, so a target that cannot write it **fails the
session** (`exitUIDMarkFailed = 97` → `ErrUIDUnavailable`). That makes
`enforcement_base` a prerequisite on every ephemeral target rather than only on
the ones that render a rung; `README.md` §"What `ephemeral-user` needs on a
target" is the operator-facing version.

### The wrap-around decision

**At the top of the range, allocation refuses. It does not wrap, and there is no
setting to make it wrap.**

Why:

- Wrapping is the **only** moment reuse becomes possible again. A wrap that
  "accepts with a recorded warning" reintroduces the cross-user flow silently, at
  the one moment nobody is looking, and a warning in a log is not a boundary.
- "Wrap after a bounded check of the paths a session can actually write" was the
  serious alternative, and it was the option the prompt leaned toward — the top of
  the range genuinely is the one place a bounded check is affordable. It loses on
  **completeness**, for the same four reasons PLAN §5.1 gives for not sweeping at
  teardown: unmounted filesystems, snapshots and backups, ACLs and xattrs naming
  the uid, and files inside containers. A check that can be wrong converts a hard,
  visible stop into a soft, silent one exactly where the guarantee is at stake,
  and it puts a filesystem walk back on a session's critical path.
- The refusal's cost is bounded and the remedy is cheap: raise `uid_max`. That is
  a configuration change with nothing at risk, and the range is a million uids —
  at the 58 provision/teardown cycles per second §9.1 measured, nearly five hours
  of *continuously saturated* provisioning, and years of ordinary use.
- The objection that survives is "a refusal is a target-wide outage for this
  method". It is answered by the **pressure warning**: from nine tenths of the
  range on, every allocation logs how many uids are left and what to raise. An
  outage nobody was warned about would be indefensible; one warned about for the
  last hundred thousand sessions is a deadline the operator chose not to meet.
- An operator who decides reuse is acceptable on their fleet can remove the mark
  directory on the target. That is deliberate, local, and auditable as an act —
  which is where the decision belongs, rather than invisible as a default.

**Not configurable, on purpose.** A `wrap: true` setting would have exactly one
effect — reintroducing the defect — and `uid_max` is already the honest knob for
an operator who needs more uids. Per the prompt: make it configurable only if both
settings can be justified, and the second cannot.

### Fail closed, and the new stage

Everything that cannot establish the invariant returns `ErrUIDUnavailable`:
an unreadable uid census, an exhausted range, every candidate uid taken, a mark
that could not be written, and a provisioning script that reported no uid. The
engine maps it to **`stageProvisionUID`** (`"provision-uid"`), reusing 0025's
`provisionError` seam, and the user is told *"the target could not be given an
isolated account for this session"* — an outage, never a denial, naming the
guarantee that failed and nothing about the target, the range, or the account.

It is its own stage rather than a flavour of `stageProvision` for 0025's reason:
"credentials for the target could not be provisioned" sends an operator to the
provisioning account on the target, and nothing on the target failed — the fix is
this proxy's uid range.

Every refusal happens **before** anything is created, or is followed by
`cleanUpFailedProvision`, so a refused session leaves the target as it found it.
`test/e2e` and `internal/auth/target` both assert that.

### The census, and the round trip it does not add

`discoverScript` — the reaper's — now also prints `uid\t<n>` for every account
whose uid falls inside the range (**every** account, not only this proxy's: a uid
is available because *nothing* holds it) and `uidmark\t<n>` for the high-water
mark. `Provision` runs that same script on the management connection it already
has, so the provisioning path gains one `admin.Run` rather than a second script to
keep correct. The reaper reads orphans out of the same output and ignores the two
new keys, because neither starts with the proxy's account prefix.

The provisioning script prints `uid\t<n>` for the account it ended up with, read
back with `parseProvisionedUID`. It has to be read rather than assumed, for two
reasons: an account **adopted** from a crashed session keeps the uid it already
had (0007's idempotency), and a lost race lands on a fallback candidate. The
audit record must name the uid that exists.

The candidate list (8 uids) exists for one case only — another provisioner taking
the allocation between this census and this `useradd`. The target tries them in
order, so a lost race costs a retry inside one script instead of a refused
session. Only the **first** candidate advances the allocator's per-target
high-water cache; advancing by the whole list would burn eight uids per session.

### Tests, and the one that fails without the fix

- `internal/auth/target/uid_test.go` — the allocator: the rule, the **wrap-around
  refusal** (with the bottom of the range deliberately free, because "it is free"
  is exactly the insufficient reasoning), the pressure warning, the fail-closed
  census, in-process non-repetition, the parse of both script outputs, and the
  range validation.
- `internal/auth/target/ephemeral_test.go` — against a real `/bin/sh` and the fake
  host's account database: allocation inside the range, **four sequential sessions
  never sharing a uid**, a *restarted* proxy not repeating the last one's uid (the
  mark, not memory), four concurrent sessions never colliding, an exhausted range
  refusing with nothing provisioned, an adopted account reporting its own uid, a
  taken candidate falling through to the next, and an unwritable mark failing the
  session.
- `TestTwoSequentialSessionsDoNotShareAUID` was checked against the defect: drop
  `-u` from the provisioning script and it fails with *"session 1 was handed uid
  1001 again after it had been torn down"*. A test for an invariant that passes
  before the fix is not a test for that invariant.
- The **fake host's `useradd` now honours `-u` and returns 4 for a uid in use**,
  which is what makes any of the above meaningful. Its old behaviour — one uid for
  every account — is kept for the no-`-u` case, so a provisioning path that ever
  stops passing `-u` fails these tests immediately.
- `internal/proxy/uid_test.go` — the engine's half: outage not denial, disclosing
  nothing (asserted against the host, the range, and the words "uid", "exhausted",
  "wrap"), the stage, and the uid on the provisioning record.
- `test/e2e` — `TestTopology/uid allocation`, between concurrency and the outage
  scenario: two sequential sessions get different uids inside the range; **a file
  alice writes in `/tmp` survives her session and svc-deploy's session does not
  own it** (ownership asserted from the target's own `stat`, not absence); and the
  uid reaches the delivered audit record. `testNoEphemeralLeak` now also asserts
  the mark **survives** the suite — a mark swept with the accounts would hand the
  whole range back.
- New fixture route `svc-deploy` → `inherit.company.com` (same target node, no
  enforcement rung), because the cross-login claim needs two logins on one target
  and a confined session could not write the probe. `test/topology` pins the range
  at its default and pins that route's existence.

### Two tests whose premise this phase removed

Both are named after uid **reuse**, and reuse is no longer reachable on the
provisioning path. Neither was deleted, because the claim underneath each is
independent and still worth asserting:

- `TestANewSessionInheritsNothingFromAReusedUID` (fake host) — kept, with its
  comment rewritten to say why the name is now historical. It asserts teardown
  removes every rung artefact whether or not the uid is recycled, which is what
  holds if a range is ever widened onto uids something else has held.
- `TestSSHDUIDReuseInheritsNothing` → **`TestSSHDUIDAllocationInheritsNothing`**
  (real sshd). It used to provision up to six times waiting for the target to hand
  a uid out twice, and skipped if it never did — which after this phase is *always*,
  so it would have become a permanently skipped test. It now asserts the pair that
  replaced it: three sequential sessions never share a uid, and teardown still
  leaves no rule or mount behind.

### What could not be run in this session

- **`make e2e`** and **`make test-sshd`**: no Docker daemon in this environment
  (`docker info` fails; there is no socket). The e2e scenarios and the real-`sshd`
  tests are therefore **written and vetted but not executed** — `go vet -tags e2e`
  and `staticcheck -tags e2e` pass over them, and CI's `e2e` and
  `target credentials (real sshd)` jobs are what will run them.
- **`golangci-lint run`**: the installed binary (built with Go 1.25) refuses a
  module targeting `go 1.26.0`, which is this repository's pin and not something
  this phase changed. Substituted with `go vet ./...`, `staticcheck ./...` and
  `errcheck ./...` (all with `-tags e2e` over `test/e2e` as well) — clean, with only
  the pre-existing `cmd/loadgen` `fmt.Fprintf` findings that `.golangci.yml`'s
  `std-error-handling` preset excludes.
- `go build ./...`, `go vet ./...` and `go test ./...` pass.

### Follow-ups (not queued — deliberately)

Nothing new is queued. Two things a future phase may want, recorded here rather
than as prompts, because neither is a defect and both are cheap to reconsider:

1. **The pressure warning is a log line.** It could be a `LogRecord` so an
   operator's dashboard sees it rather than a proxy's stderr. That is a telemetry
   decision (§7) and belongs with whatever phase next revisits capacity signals,
   not to this one.
2. **The mark is per target, keyed by `host:port`.** A fleet where many names
   resolve to one host would keep several marks for one account database. It is
   harmless — every mark is still monotonic and the census closes the gap for
   anything live — but a target-identity phase (0029's question) is where that
   would be tidied, if ever.
