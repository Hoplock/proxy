# 0043 — The record says what the proxy actually did — Learnings

## Summary
- What shipped: `algorithm_profile` is **applied** to every connection a route causes to its target (session leg, management login, driver CLI, both reapers' sweeps), then stamped as `algorithm_profile` on the provisioning record and the device mapping event, **always, `default` included**. `default` is now the library's **secure set** (a break: `info.version` **4.3.0**, `policy_version` still **4**). A stranded target is `stageAlgorithmPolicy` + a `warn` batch record `target.algorithm_policy_unmet`. Drivers return `[]device.Change`, and every completed device change becomes one `device.config.change` record (`info`, **batch**).
- Key files: `internal/control/algorithms.go`, `internal/sshalg/` (new), `internal/auth/target/{algpolicy.go,auth.go,admin.go,deviceaccount.go,devicereaper.go,reaper.go}`, `device/{driver.go,shell.go}`, `device/fortios/{fortigate,fortiswitch,schedule}.go`, `internal/logging/{record,device}.go`, `internal/proxy/{session,logging,feedback}.go`, `internal/routing/resolve.go`, `api/{control.yaml,README.md}`.
- Types/ids: `control.Algorithms`, `AlgorithmProfile.{Algorithms,Resolve}`; `sshalg.{Apply,Complete,Signer}`; `routing.Route.{AlgorithmProfile,Algorithms()}`; `target.Target.{AlgorithmProfile,Algorithms}`, `device.Endpoint.Algorithms`; `device.Change`/`ChangeOp`; `target.DeviceConfigChange`, `DeviceEventSink.ConfigChange`; `target.{IsAlgorithmPolicyUnmet,AlgorithmPolicyUnmet,AlgorithmAxis*}`; `logging.Attr{AlgorithmProfile,DeviceChangeOp,AlgorithmAxis,TargetAlgorithmsOffered}`, `logging.Event{DeviceConfigChange,AlgorithmPolicyUnmet}`.
- Profiles now expand to: `default` = `ssh.SupportedAlgorithms()` per axis (pinned; keeps `hmac-sha1`); `legacy-rsa-sha1` adds `ssh-rsa-cert-v01`,`ssh-rsa` host keys + `ssh-rsa` pubkey auth; `legacy-device` adds that + SHA-1 kex ×3, `aes128-cbc`,`3des-cbc`, `hmac-sha1-96`, `ssh-dss-cert-v01`,`ssh-dss` host keys — all after the secure entries.
- Decisions: D13 seam changed (drivers **return** changes, never emit); D8 held (feed on batch, mapping/sweep failure stay priority; `ErrNoLoggingPath` not widened). **Naming verdict: keep `credential_method`/`credential_rung` (1-based)** — the split came from `api/`'s own text publishing `target_auth_*` (0-based), now corrected.
- Gotchas: a driver reports every change it **completed**, even on failure, never one merely attempted; deleting what is already gone is no change. A sweep's records carry **no session id**. x/crypto has no client pubkey-auth field — the axis is applied by wrapping signers (`sshalg.Signer`), and a new session-leg authenticator must do the same.
- What Control must change (the sync): index `device.config.change` (batch, `info`), read `algorithm_profile` knowing it is always present (absent = not a target leg), index `credential_method`/`credential_rung` only and drop `target_auth_*`, and tell policy authors that `default` no longer reaches SHA-1-kex / `ssh-rsa` / `ssh-dss` devices — find them via `target.algorithm_policy_unmet`.

## Details

### Why "apply, then record"

The request asked only for the attribute. Nothing applied the profile before
this phase: it stopped in `internal/control`, `dialTarget` never set an
algorithm, and `SSHShellOptions`' algorithm fields had no caller. Stamping the
attribute alone would have named weakenings the proxy never performed — §6.5's
silent downgrade in reverse. So the phase carries the profile down the same
path as the host-key callback (D7) and records the profile **in force** from
the same route the dial reads, so the two cannot drift (a test asserts both on
one route: `TestLegacyDeviceIsScopedToTheRoute`).

### Where the profile is applied

| Connection | Where | How it gets the lists |
| --- | --- | --- |
| Session leg | `internal/proxy/session.go` `dialTarget` | `sshalg.Apply(&cfg, s.route.Algorithms())`; authenticators wrap their signer with `sshalg.Signer(…, tgt.Algorithms)` |
| POSIX management login | `internal/auth/target/admin.go` | `tgt.Algorithms` |
| Device privileged CLI | `internal/auth/target/device/shell.go` | `ep.Algorithms`, else `SSHShellOptions` fallback, else default |
| Device teardown / deadline removal | `deviceaccount.go` | the session's endpoint |
| Device reaper sweep | `devicereaper.go` `observe` | the bare endpoint keeps a **copy of the lists**, refreshed on each provisioning |
| POSIX reaper sweep | `reaper.go` `observe` | the bare target keeps them too |

Not applied: the hop leg and relay registration (out of scope — a hop peer is a
Hoplock proxy). `internal/sshalg` exists because the expansion must stay out of
`x/crypto` (`internal/control`) and the appliers live in packages that cannot
import each other.

### The pubkey-auth axis

`ssh.ClientConfig` has no `PublicKeyAuthAlgorithms` (it is server-only).
Left alone, x/crypto signs RSA with SHA-1 (`ssh-rsa`) whenever the server does
not send `server-sig-algs` — so even `default` would sign with SHA-1 against old
firmware. `sshalg.Signer` wraps the signer with `ssh.NewSignerWithAlgorithms`
in the route's order; a key the route permits nothing for gets an empty list
(the handshake then fails) rather than being passed through unrestricted.
Certificate signers work (tested), which is what 0044's brokered certificate
needs — its prompt now says so.

### The break

`default` changed from "library client defaults" to "library secure set". Per
0028's precedent: `policy_version` does not move (no field changes meaning to a
parser), `info.version` 4.2.0 → **4.3.0**, stated in both documents' Versioning
text, present tense. It costs nothing deployed (proxy and Control ship together,
0037). What an operator sees when it bites: the outage text *"the target does
not support the algorithms this route allows"* and a `warn` record with
`algorithm_axis` and `target_algorithms_offered`.

The classifier (`target.IsAlgorithmPolicyUnmet`) uses `errors.As` on
`*ssh.AlgorithmNegotiationError` — no text match — with one table mapping
x/crypto's `What` strings to axis names. It runs **after** the host-key branch
and **before** `DialOutcome`/the rejection branch in `dialTarget`, and it is
never scored against the credential (`TestASHA1KeyExchangeTargetFailsUnderDefault`
uses a threshold-1 breaker to prove it). It also classifies a **provisioning**
failure (`provisionError`): on a device route the stranded device fails at the
management login, before any session leg, and should read the same. The device
shell now wraps an `AlgorithmNegotiationError` into its otherwise-opaque login
error (it names algorithms, never the credential) so that classification can
happen.

### The drift feed

Record shape: `kind: provisioning`, `severity: info`, `event:
device.config.change`, `platform`, `device_change_op` (create/modify/delete),
`target_account` (the object's name — the spelling a sweep failure already uses,
even for a schedule), `device_object_kind` when not an administrator, session
id where there is one, `device_field.<name>` from the route. No credential:
install is a `modify` of the admin with nothing about what was installed.

**Failed create — decided: it emits for what it completed.** A FortiGate create
that committed the schedule and failed on the administrator reports `create
schedule` then the rollback's `delete schedule` (`rolledBack` in
`fortigate.go`: a confirmed rollback deletion of an object the sequence had not
reported creating implies the create, since the name was verified absent). The
same rule for install failures (the rollback's deletions) and removals
(`runRemoval` tells a real delete from "not found"). One function,
`DeviceAccountAuthenticator.recordChanges`, emits for every path.

Sweeps clear `SessionID` on the endpoint (`Sweep` is often triggered by a
session's `sweepInBackground`, and attributing someone's orphan removal to that
session would be wrong).

### The naming verdict

Kept `credential_method` / `credential_rung` (the default answer; nothing argued
otherwise). The finding the request could not see: **`api/control.yaml` and
`api/README.md` themselves published `target_auth_method` and
`target_auth_rung` "(the 0-based index)"** while the code emitted the other
pair, 1-based. That is where Control's names came from. The contract text is
corrected (a description change, no version move of its own); the
`contract_test` vocabulary list now requires `credential_rung`.
`TestExactlyOneNamePerFieldIsEmitted` (logging) and
`TestEverySessionRecordUsesOneNamePerField` (proxy, over a whole session's
records) hold it.

### Tests worth knowing

- `internal/control/algorithms_test.go` — `TestDefaultIsTheLibrarysSecureSet`
  (tripwire vs `ssh.SupportedAlgorithms()`) and the pinned literal lists.
- `internal/proxy/algorithms_test.go` — real handshakes: DSA-only, `ssh-rsa`-only,
  SHA-1-kex-only and legacy-only targets, positive and negative per profile.
- `internal/auth/target/devicechange_test.go` — a `countingDriver` over the real
  FortiGate driver: one record per reported change for proxy- and
  target-enforced sessions, the deadline removal, a failed install, reaper
  account + residue sweeps, and `TestTheDriverAndTheSweepUseTheRoutesProfile`
  (legacy-only fake device: default can't even log in; the reaper's own bare
  endpoint sweeps under legacy-device; a bare endpoint with no lists fails).
- `cmd/mock-control/logging_e2e_test.go` — the existing redaction test now also
  runs a device session and scans every record and the disk buffer for every
  password the driver sent the device, and requires three change records.
- `sshtest` gained `GenerateDSAHostKey`, `GenerateRSASHA1HostKey` and a
  `Negotiation` option on both the target and the fake FortiOS.
- e2e: the `fortigate.company.com` route now names `legacy-device`, and a new
  `testDeviceCredentials` subtest asserts the mapping record's profile and the
  create/modify/delete feed on the batch path. It runs in CI only
  (`make e2e` cannot build its images from a web session — 0040).

### Also fixed, test-only

`cmd/mock-control`'s `TestAReplayedConfigChangedDoesNotApplyAStaleDocument`
(phase 0042) failed ~2 in 50 on `main`: the mock notices a closed event stream
only on its next write, so the "away" proxy could still receive the
notification. It now waits until a probe event reaches no subscriber. 200/200
after.

### Verification

`go build`, `go vet`, `go test ./...` (incl. `./test/docs/...`),
`go vet -tags e2e ./test/e2e/`, `make license-check`, and `golangci-lint run`
with v2.13.2 installed into the scratchpad (the preinstalled binary is built
with Go 1.25 and refuses the module, as earlier phases recorded): 0 issues.
`make openapi-check` needs a Python module this session lacks; CI's `openapi`
job runs it.

### Follow-ups

None queued. 0045 (floor, bans) extends `AlgorithmProfile.Algorithms`,
`stageAlgorithmPolicy` and `target.algorithm_policy_unmet`; its prompt was
updated to name the identifiers built here and to drop its "default expands to
nothing" assumption.
