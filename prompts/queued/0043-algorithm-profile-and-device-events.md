# 0043 — The record says what the proxy actually did

## Read first
- `docs/PROTOCOL.md` — session workflow, especially **§3** (scope discipline,
  the rename rule, and the table of plan indexes that go stale in the same PR
  that makes them wrong), **§7** and **§8**.
- `docs/PLAN.md` — **§7** (logging & telemetry: the three layers, **severity
  decides the endpoint**, what is `critical` and why a service outage is not,
  "the buffer is a buffer", structural redaction, and the rule that an attribute
  key is **query surface** and as load-bearing as any other name here).
  **§4.2** — the `algorithm_profile` paragraph beginning "One field beside the
  credential travels with the route": per route rather than proxy-wide, a named
  preset rather than an algorithm list, and **an audit fact, not a user-facing
  one**. **§5.3** — read its **"What is true today"** block first, then the
  layers for the account-mapping event, the reaper as the primary removal path,
  and the residue objects a FortiGate carries a deadline in. **§6.5** — the rule
  this phase is really an application of: a record names what was **in force**,
  never what the route asked for. **§12** — the "drift reconciliation feed"
  entry, which already states that the proxy's job here is "to emit the device
  configuration-change event as a distinct, queryable audit kind (§7)".
  **§10** — this phase's row.
  Decisions: **D8** (log shipping, batch vs priority path — the decision this
  phase must not dilute), **D13** (the driver seam, and that a driver
  *declares data* rather than performing behaviour), **D14** (the ladder, and
  the rung in force as an audit fact), **D6a** (the credential-method
  vocabulary this repository names its record attributes after), **D7** (host
  trust on the driver's own privileged connection, which the algorithm question
  rides beside), **D2** (the proxy originates no policy — nothing here changes
  what a route is allowed to do).
- `api/README.md` — **"Algorithm profile (`algorithm_profile`, phase 0014)"**,
  **"Absent-value defaults, in one table"**, and **"Changing the contract"**.
- `api/control.yaml` — `AuthorizeResponse.algorithm_profile`, whose description
  contains the sentence this phase makes true: "Anything other than `default`
  is a **weakening and emits its own audit event** (`algorithm_profile` in the
  record) … an operator learns that a route runs on SHA-1 from the record, not
  by reading policy."
- `docs/learnings/` — read summaries; open
  `0011-logging-telemetry-pipeline-learnings.md` (the recorder/shipper/buffer
  seam and the attribute vocabulary), `0013-device-provisioning-contract-v3-learnings.md`
  (the phase that put `algorithm_profile` on the wire — and note what its
  "What 0014 must know" says about fields that land in the contract without a
  consumer), `0014-fortios-device-drivers-learnings.md` and
  `0017-fortios-target-enforced-expiry-learnings.md` (the driver seam, the
  reaper, and the schedule object that is the second thing this proxy writes to
  a customer's firewall).
- `docs/CROSS-REPO-PROTOCOL.md` — **§1, §2, §3.2, §4.1, §5**. This phase answers
  an upstream request, so §5's "The PR that answers an upstream request is not a
  sync" binds it: once merged it owes a **downstream sync to every consuming
  repository, including the one that raised the request**.

## Where this came from

An **upstream request** from `hoplock/control` (`docs/CROSS-REPO-PROTOCOL.md`
§3.2), raised by its phase 0010 in
[Hoplock/control#32](https://github.com/Hoplock/control/pull/32) — the phase
that built its tamper-evident audit store (its **M8**) and ingested both log
paths. It named the surface precisely: **the record attributes this
repository's `internal/logging` package emits**, not `api/control.yaml` —
`attributes` is an open string map, so **none of this is a contract schema
change**.

Three shapes, quoted in the request's own words:

1. **`algorithm_profile` on records** — "an attribute `algorithm_profile`,
   whose value is the authorize response's `algorithm_profile` for the session,
   stamped by the session recorder alongside the existing
   `AttrCredentialMethod`."
2. **The device configuration-change event** — "an attribute `event` with the
   value `device.config.change`, on a `kind: provisioning` record, emitted per
   device configuration change the driver makes (creation and teardown alike),
   carrying the same `device_field.<name>` namespace the mapping event carries."
3. **One name per field** — the proxy emits `credential_method` and
   `credential_rung`; Control's plan names the same two fields
   `target_auth_method` and `target_auth_rung`, after the contract's
   `target_auth_ladder` the rung indexes into. "One name per field, either way
   round."

**What downstream cannot do until this lands** (in its words, and this is the
part that makes it a phase rather than a tidy-up):

- The degradation query has a column, an index and a projection that read
  `algorithm_profile` if it arrives, and it never arrives — so the sentence
  `api/control.yaml` already publishes, that an operator learns a route runs on
  SHA-1 from the record, "is only true of a hand-written record".
- `audit.EventDeviceConfigChange`, the indexed `event` column and
  `Reader.DeviceConfigChanges` exist downstream with **no producer**: "the
  drift-reconciliation feed — a customer's NCM or SIEM auto-closing the alerts
  Hoplock's own provisioning raises — has a store and a query and no producer."
  This repository's §12 already promises that producer.
- Control absorbed the naming split by reading **both** names into one column,
  and says why that is not a fix: "a store that quietly accepts two names for
  one field is a store where the third name nobody told it about is invisible."

Nothing downstream was approximated and nothing there is blocked; what is
broken is that three claims this product makes are answerable only in part.

**Treat the request as a need, not a specification** (§3.2). Item 1 in
particular asks for less than it needs: see below.

## Objective

Make the audit record name what the proxy actually did on the target leg —
the algorithm profile it **applied**, and every configuration change it made on
a device — and settle the two-names divergence so exactly one name per field
leaves this proxy.

## What this phase must settle

### 1. Apply the profile, then record it

**The request asks only for the attribute, and the attribute alone would be a
lie.** Establish this before building: nothing in this repository applies
`algorithm_profile` today. It is parsed and validated in `internal/control`
(0013), and from there it stops — `routing.Route` has no field for it,
`internal/proxy/session.go`'s `dialTarget` never sets an algorithm on the
target leg's `ssh.ClientConfig`, and `device.SSHShellOptions`'
`HostKeyAlgorithms`, `KeyExchanges` and `Ciphers` — whose own comment says "a
fleet of appliances too old for them is what the route's algorithm profile is
for" — have no caller anywhere. So a record stamped with `legacy-device` today
would name a weakening the proxy never performed, which is precisely what §6.5
forbids for the credential rung and forbids here for the same reason.

So the phase is **apply, then record**, and the recording is the cheap half:

- **Carry it.** `routing.Route` gains the profile, deep-copied from the response
  in `internal/routing/resolve.go` beside the other fields (the decision may be
  a cached one shared with other sessions). Read it through
  `AuthorizeResponse.Profile()`, which is what resolves absent to `default`.
- **Expand it in one place.** The preset → algorithm-lists mapping is a single
  exported function on `control.AlgorithmProfile` (a new
  `internal/control/algorithms.go`), returning key exchanges, ciphers, MACs,
  host-key algorithms and public-key auth algorithms as plain string slices —
  `internal/control` stays free of `x/crypto/ssh`. It is one place because
  `internal/proxy` and `internal/auth/target/device` both need it and neither
  may import the other. `default` expands to the library's **secure set** on
  every axis, as an explicit list; see "Decided in 0045's review" below. No
  profile ever leaves a config field empty.
- **Apply it to every connection the session causes to that target**: the
  session leg in `internal/proxy/session.go` (`dialTarget`), the POSIX
  management login in `internal/auth/target/admin.go`, and the driver's
  privileged CLI connection in `internal/auth/target/device/shell.go`. The
  dialer there is built once at startup (`internal/auth/target/registry.go`), so
  the per-route profile reaches it on `device.Endpoint` — which is already the
  per-session carrier for exactly this kind of borrowed decision (D7's host-key
  callback rides there for the same reason) — with `SSHShellOptions` remaining
  the fallback for a connection that has none. `target.Target` carries it down
  from the engine, as `Enforcement` and `HostKeyCallback` already do.
- **Do not lose it at teardown or at a sweep.** `deviceReaper.observe` rebuilds
  a **bare** endpoint that deliberately keeps the host-key callback and drops
  the rest; the profile must survive that copy for the same reason the callback
  does. A device that needs SHA-1 to be provisioned needs it to be swept, and a
  sweep that cannot dial leaves a standing privileged administrator on a
  customer's firewall (§5.3) — the failure D13 names.
- **Record it.** `AttrAlgorithmProfile = "algorithm_profile"` in
  `internal/logging/record.go`, stamped in `internal/proxy/logging.go`'s
  `recordCredential` beside `AttrCredentialMethod`, and on the device
  account-mapping event in `internal/logging/device.go`, which is the only
  record a constrained device session leaves. Stamp the profile **in force** —
  the one the dial used — and state in `docs/PLAN.md` §7 whether `default` is
  stamped or omitted, and what absence therefore means. Either answer is
  defensible; an unstated one leaves a downstream reader unable to tell
  "`default`" from "this proxy does not stamp it", which is the ambiguity the
  request is trying to remove.
- **Say how the promise is rendered.** `api/control.yaml` and `api/README.md`
  say a non-default profile "emits its own audit event". If the phase renders
  that as an attribute on the provisioning record rather than as a record of its
  own, say so in both documents and in §4.2. `policy_version` does not move.
  `info.version` moves once, for the `default` tightening below, and not for
  this description edit. If the phase concludes a
  distinct record is the better rendering, that is a legitimate answer: build it
  and write down why.

### 2. The device configuration-change event

The event is the one §12 already promises. What the request could not specify is
**where it is emitted from**, and that is a D13 question.

- **Drivers report data; the provisioner emits.** A driver that held a telemetry
  sink would put audit in the credential plane and would make the declarative
  driver document and subprocess contract D13 defers carry a sink too. So the
  driver seam reports what it changed by **returning** it —
  `device.Change{Op, ObjectKind, Name}` with `Op` one of create / modify /
  delete, returned from `CreateAccount`, `InstallCredential`, `RemoveAccount`
  and `ResidueSweeper.RemoveResidue` — and
  `target.DeviceAccountAuthenticator` and `deviceReaper` turn those into
  records through a third method on `target.DeviceEventSink`
  (`ConfigChange(DeviceConfigChange)`), implemented in
  `internal/logging/device.go` exactly as the other two are. Changing four
  driver signatures is the cost; there are two drivers, the seam is internal,
  and the alternative — a driver that emits — is the one D13 rules out.
- **Record shape:** `kind` `provisioning`, `event` `device.config.change`, the
  platform, the object's name and `device_object_kind` (the existing attribute,
  empty for an administrator, "firewall schedule" for the object 0017 creates),
  the operation, the session id where there is one, and the route's
  `device_field.<name>` namespace exactly as the mapping event carries it —
  because on a partitioned unit the target string does not say which partition
  was changed (§5.3). **No credential material**: an installed public key is
  named by fingerprint or not at all (§7's redaction is structural, and this is
  the first new producer since it was written).
- **It rides the batch path, at `info`.** This is the decision most easily got
  wrong: the account-mapping event is `critical` because on a constrained
  platform it is the only attribution that exists, and a reconciliation feed
  emitted several times per session at that severity would dilute the path
  exactly as §7 says a service outage would. The mapping event and sweep
  failures stay where they are.
- **The fail-closed rule is not widened.** `ErrNoLoggingPath` refuses a route
  whose driver declares a constrained name limit because **attribution** would
  otherwise be lost (§5.3). A drift feed is not attribution: a proxy with no
  logging path must not start refusing routes it serves today. Assert it.
- **Creation and teardown alike, and that is where this bites.** One record per
  change, on every path that changes a device: provisioning, the credential
  install, teardown, the proxy-enforced deadline removal, `removeQuietly` after
  a failed provisioning, the reaper's account sweep, and residue removal. A
  change that failed is already a sweep failure on the priority path and is not
  re-reported here; decide and state whether a failed *create* emits one, and
  make the answer the same everywhere.

### 3. One name per field

This repository owns what it emits, so the divergence is settled here and
Control is told the answer. Both names are currently read downstream, so
nothing is blocked either way and the phase is free to choose on the merits.

**The default answer is to keep `credential_method` and `credential_rung`**, and
the phase adopts it unless it finds a reason the register and §7 do not already
carry: the words are D6a's and D14's, two producers emit them today
(`internal/proxy/logging.go` and `internal/logging/device.go`), §3's rename rule
makes a rename expensive here, and records already stored downstream carry the
old name, so a rename is not free on the other side of the wire either.

Whichever way it goes:

- exactly **one** name per field leaves this proxy, and the other appears in no
  emitted attribute anywhere in the repository;
- `docs/PLAN.md` §7 states the names and says that they are this repository's
  query surface, so the next reader of either plan finds one answer;
- the sync (below) carries the verdict to Control, whose store must then index
  one name and whose own plan carries the other today. Changing Control's store
  or its plan is **not** this phase's work (§3.2 step 5).

## In scope

- `internal/control` — the profile → algorithm-lists expansion, in one place.
- `internal/routing/resolve.go` — the profile on `routing.Route`.
- `internal/proxy` — `session.go` (`dialTarget`, and the profile onto
  `target.Target`), `logging.go` (`recordCredential`).
- `internal/auth/target` — `auth.go` (`Target`), `admin.go`, `deviceaccount.go`,
  `devicereaper.go`, `registry.go`, and `device/driver.go`, `device/shell.go`
  plus both drivers under `device/fortios/` for the change-reporting return
  values and the per-endpoint algorithms.
- `internal/logging` — `record.go` (the new attribute keys and event name),
  `device.go` (the third sink method), and the `Shipper` path it delivers on.
- `docs/PLAN.md` — §4.2, §7, §5.3, §12's drift-feed entry, §10's row.
- `api/control.yaml` and `api/README.md` — only if the phase changes how the
  promised audit event is described (see 1 above).
- `cmd/mock-control` — fixtures that exercise a non-default profile already
  exist (`fixtures.example.yaml`); extend the e2e topology so a route with a
  profile is actually dialled.
- Tests, per the acceptance criteria below.

## Decided in 0045's review: `default` is the library's secure set

**The finding.** `api/control.yaml` and `api/README.md` call `default` "nothing
beyond the library defaults" and "the only profile that is not a weakening",
and describe `legacy-rsa-sha1` as *adding* `ssh-rsa`. But x/crypto's **client
defaults** (checked at v0.56.0) already offer:
- `diffie-hellman-group14-sha1`, a SHA-1 key exchange;
- `hmac-sha1-96`, which the library itself classes as insecure;
- `ssh-rsa` and `ssh-dss` host keys, plus their certificate forms.

Nothing here sets `KeyExchanges`, `Ciphers`, `MACs` or `HostKeyAlgorithms`
today, so every target leg on `default` offers all of these now.

**The decision (the repository owner, on PR #64):** `default` means the
library's **secure set**, and the contract's sentence becomes true. Build it
exactly like this; do not reopen the choice.

- **`default` expands to an explicit list on every axis**: the `ssh.SupportedAlgorithms()`
  field for that axis, in the library's order. That covers `KeyExchanges`,
  `Ciphers`, `MACs`, `HostKeys` and `PublicKeyAuths`. Never an empty config
  field, which is what lets the library's insecure defaults back in.
  - At v0.56.0 this removes `diffie-hellman-group14-sha1`, `hmac-sha1-96`,
    `ssh-rsa`, `ssh-dss` and the RSA-SHA1/DSA certificate forms. It adds
    `diffie-hellman-group16-sha512` and `diffie-hellman-group-exchange-sha256`,
    which the library supports but does not offer by default.
  - It **keeps `hmac-sha1`**: the library classes it as supported, and HMAC
    with SHA-1 is not broken the way a SHA-1 signature is. Say so in the
    contract rather than leave a reader to find it; 0045's bans are how an
    administrator removes it.
  - The rule for the future is "`default` follows the library's secure
    classification". A library upgrade that moves an algorithm between its
    supported and insecure lists changes `default`. So pin the expansion with a
    test that asserts the exact lists per axis, so such a change fails the build
    and is reviewed, not absorbed.
- **The legacy profiles now add exactly what they say, on top of that:**
  - `legacy-rsa-sha1` adds `ssh-rsa` (and `ssh-rsa-cert-v01@openssh.com`) as a
    host-key algorithm, and `ssh-rsa` as a public-key auth algorithm.
  - `legacy-device` adds that, plus the library's insecure SHA-1 key exchanges
    (`ssh.InsecureAlgorithms().KeyExchanges`), its **CBC** ciphers (not RC4:
    the contract promises CBC, and nothing more), and `hmac-sha1-96`. Each goes
    after every secure entry on its axis; 0045 depends on that ordering.
  - **`ssh-dss`** is in no profile today. The recommendation is to add DSA host
    keys (and their certificate form) to `legacy-device`, because firmware old
    enough to need SHA-1 key exchange is where DSA-only host keys live, and
    without it that population has no profile at all. Decide, and write the
    answer into the contract's `legacy-device` description either way.
- **It is a tightening, so it is announced as a break**, following phase 0028's
  precedent (its learnings, "The version decision"):
  - `policy_version` does **not** move, because no field changes meaning to a
    parser;
  - `info.version` moves to the next **minor**, with the break stated in
    `api/README.md`'s "Versioning" paragraph beside `params.username`. That
    paragraph says "the one such break", and it now has two;
  - write it in the present tense, per 0037.
  
  The cost is low: proxy and Control ship together and nothing has been
  deployed (0037), so no running estate depends on SHA-1 through `default`.
  Say that in the PR too.
- **Make the break visible when it bites.** A target that can only connect with
  something `default` no longer offers now fails the handshake with
  `*ssh.AlgorithmNegotiationError`. Today that is reported as a generic dial
  failure, which sends an operator to the network. Add:
  - **one classifier**, beside 0025's `IsAuthRejection` in
    `internal/auth/target`: `IsAlgorithmPolicyUnmet(err) bool`, using
    `errors.As`, with one table mapping the error's `What` (`key exchange`,
    `host key`, `client to server cipher`, and so on) to an axis name;
  - **a stage of its own**, `stageAlgorithmPolicy` in
    `internal/proxy/feedback.go`, classified after the host-key branch and
    before the rejection branch in `dialTarget`, never scored against the
    credential (0025). The user sees the outage branch of §4.3 saying the
    target does not support the algorithms this route allows;
  - **a `warn` batch record**, `event` `target.algorithm_policy_unmet`, carrying
    `algorithm_profile`, `target_addr`, `algorithm_axis` and the target's
    offered list for that axis (`target_algorithms_offered`, from
    `RequestedAlgorithms`).
  
  The operator reads the offered list and moves the route to the right legacy
  profile. 0045 extends this same classifier, stage and event to floors and
  bans; build it so that is an extension and not a rewrite.

## Out of scope

- **A floor or bans** (`algorithm_floor`, a minimum rather than a weakening,
  and `algorithm_bans`, a per-route removal list). That is **0045**, which narrows the expansion you build here and rides the same path to
  every connection — so keep that expansion the one place a connection's lists
  come from, and keep the reaper's bare-endpoint copy carrying whatever the
  endpoint's algorithms are rather than the profile alone.
- **Control's side** (its M8 store, its projections, its queries, its plan's
  field names). This phase emits; that repository stores, and it is a numbered
  phase there.
- **Proxy→proxy legs**: the hop leg (`internal/proxy/nexthop.go`) and relay
  registration (`internal/relay`). A hop peer is another Hoplock proxy, not
  appliance firmware; a route's profile is about the device on the far end.
- **New contract schema fields.** `attributes` is an open map and the profile is
  already on the wire. If a schema change looks necessary, stop and ask
  (`docs/PROTOCOL.md` §9) — it would change the versioning answer entirely.
- **A configurable algorithm list.** The preset is a preset on purpose (§4.2);
  do not add a proxy-wide knob, and do not let config widen a preset.
- Anything about retention, verification, or export of these records once
  delivered.

## Acceptance criteria

- Under `default`, the applied `ssh.ClientConfig` carries explicit lists on
  every axis equal to `ssh.SupportedAlgorithms()`, and a test pins the exact
  lists. `diffie-hellman-group14-sha1`, `hmac-sha1-96`, `ssh-rsa` and
  `ssh-dss` appear on no axis.
- A target offering only `diffie-hellman-group14-sha1` fails under `default`
  with `stageAlgorithmPolicy`: the outage-branch message, a `warn`
  `target.algorithm_policy_unmet` record naming the key-exchange axis and the
  target's offered list, and the 0025 breaker untouched. The same target
  connects under `legacy-device`.
- A target offering only an `ssh-rsa` host key fails under `default` and
  connects under `legacy-rsa-sha1`.
- Under each legacy profile, every added algorithm comes after every secure one
  on its axis.
- A route naming `legacy-device` completes a session against a target offering
  only the algorithms that profile adds, and the **same route under `default`
  fails to handshake** — the negative half is what proves the weakening is
  scoped to the route rather than applied to the fleet.
- The provisioning record names the profile that was applied, and a test
  constructs a route whose profile is non-default and asserts both the applied
  client configuration and the recorded attribute, so the two cannot drift.
- The driver's privileged connection and the **reaper's sweep** connection use
  the same profile as the session leg. Test the sweep path specifically: it
  outlives the session, and it is the one that leaves a standing administrator
  behind when it cannot dial.
- One full device session emits exactly one `device.config.change` record per
  change — create, credential install, teardown — with none missing and none
  duplicated, asserted against a fake driver that counts what it was asked to
  do; and the reaper's account and residue removals emit them too.
- Those records ride the **batch** path; the account-mapping event and sweep
  failures still ride the **priority** path. Asserted, because the priority
  path's meaning is what this change could quietly dilute.
- A proxy with no logging path still serves every route it serves today; only
  the constrained-naming refusal is unchanged (`ErrNoLoggingPath`).
- No new record carries credential material — extend the existing end-to-end
  redaction assertion rather than writing a second one beside it.
- Exactly one of `credential_method` / `target_auth_method` (and of the rung
  pair) is emitted anywhere, asserted by a test over the emitted attributes, not
  by a grep in a reviewer's head.
- `make build vet test lint`, the licence-header check, `go test ./test/docs/...`
  and the e2e topology all pass.

## Definition of Done & hand-off

Per `docs/PROTOCOL.md` §4, plus what this phase owes because of where it came
from and what it touches:

- **`docs/PLAN.md`'s indexes** (§3's table): §7 gains the new attribute keys,
  the event name, and the batch-vs-priority rule; §4.2's `algorithm_profile`
  paragraph stops describing a field nothing consumes; §12's drift-feed entry
  points at the event that now exists. If the phase adds an
  `As <verb> (phase 0043)` layer to §5.3, **recompose "What is true today" and
  refresh the layer count in its header** in the same PR —
  `go test ./test/docs/...` fails otherwise, which is the point.
- **`## Cross-repo impact`** (`docs/CROSS-REPO-PROTOCOL.md` §4.1) naming
  `hoplock/control` **and** `hoplock/enterprise`, with "None" written down where
  that is the finding, and a ready-to-run sync kickoff for each repository that
  has obligations.
- **Control is owed that sync even though Control asked for this.** §5's "The
  PR that answers an upstream request is not a sync" says why it is the easiest
  one to skip: the repository already waiting is the one it is tempting to
  assume needs no telling, and the session there that indexes the new event and
  drops the second field name is a fresh one that knows nothing. Its obligations
  are concrete — whether `default` is stamped, the event's delivery path, the
  naming verdict, and the **`default` tightening**. `default` now means the
  secure set, it is announced as a break in the contract, and Control's policy
  guidance must say that a device which only speaks SHA-1 key exchange or
  `ssh-rsa`/`ssh-dss` host keys needs a legacy profile. The
  `target.algorithm_policy_unmet` event is how an operator finds those devices.
- The **learnings summary** names the attribute keys added, the event name and
  its delivery path, where the profile is applied, what each profile now
  expands to (and the `ssh-dss` answer), the break and its `info.version`, the naming verdict, and what
  Control must change — that last line is what the sync session reads.
