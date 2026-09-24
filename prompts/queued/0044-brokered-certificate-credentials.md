# 0044 — Brokered certificates: a credential Hoplock Control mints per session

## Read first

- `docs/PROTOCOL.md` — session workflow, especially **§3** (scope discipline,
  the rename/dangling-reference sweep, and the table of plan indexes that go
  stale in the same PR that makes them wrong), **§7** and **§8**.
- `docs/PLAN.md`:
  - **§4.2** (proxy → target) — the `TargetAuthenticator` interface, the ladder
    walk, "As written down (phase 0013)", "As finished (phase 0028)" (how each
    method resolves its account, and that `username` is required on every method
    the contract defines), and "As collapsed (phase 0037)" (one live vocabulary,
    what `policy_version` does and does not carry, and what 0037 kept).
  - **§4.3** — the disclosure rule and what makes a failure **outage-class**
    rather than a denial. Every failure this phase can produce is one or the
    other and the prompt says which.
  - **§5.2** (`brokered-key`) — the closest sibling, and the section that
    already names this phase in advance: "a Hoplock Control server that mints
    per-session credentials later (the same credential object grows a method,
    D6a)" and "A Hoplock Control that mints per-session credentials **implements
    this interface**". That second sentence is the one this phase has to decide
    about rather than inherit; see "The seam §5.2 promised" below.
  - **§5.1** — only its `lifetime_seconds` and `key_type` vocabulary, which this
    method reuses, and its rule that a fleet unable to express expiry is
    refused.
  - **§6.4** (policy caching & session revocation) — **the section that decides
    the shape of this phase.** An authorize decision may be reused across
    connections on a server-set TTL, so anything carried on it is replayed.
  - **§6.5** — a record names what was **in force**, and the APPLIED/ATTESTED
    split that decides which enforcement rungs a non-provisioning method can
    carry.
  - **§7** — logging & telemetry: severity decides the endpoint, and an
    attribute key is query surface.
  - **§10** — this phase's row, which you are adding.
  - Decisions: **D6a** (two credential methods chosen by the server, and its own
    closing sentence that a Control which mints credentials "slots in as another
    method rather than another breaking change" — **this phase is that sentence
    coming true, and it is why no new `D` is needed**), **D14** (the ladder, what
    is skipped and what is not), **D2** (the proxy originates no policy, and the
    reuse rule §6.4 renders), **D3** (this repository owns the contract),
    **D6** and **D13** (the two provisioning methods this one is deliberately
    unlike), **D12 as amended** (an enforcement rung is not silently downgraded),
    **D7** (target host-key policy, unchanged here), **D8** (which log path the
    new record attribute takes).
- `api/README.md` — **"Versioning: one live vocabulary, and a proxy that fails
  closed"** (in particular "The number governs `/v1/authorize` and nothing
  else", which is why one half of this change bumps `control.PolicyVersion` and
  the other half does not), **"Target credentials (`target_auth_ladder`)"**,
  **"The credential ladder"**, **"Absent-value defaults, in one table"**,
  **"Ephemeral uid blocks"** (the prose half of the precedent below), and
  **"Changing the contract"** — the recipe you follow, step by step.
- `api/control.yaml` — the `TargetAuth` and `TargetAuthLadder` schemas, and the
  **`POST /v1/uids/lease`** path. Read that path's description in full: its
  "**Why a lease, and not a field on the authorize decision**" is the argument
  this phase applies a second time, to a second kind of per-session artifact,
  and you should not re-derive it.
- `docs/learnings/` — read the summaries; open
  `0007-brokered-credentials-learnings.md` (the `CredentialSource` seam and the
  rule that credential material is held for one session and zeroed),
  `0014-credential-ladder-and-device-provisioning-learnings.md` (the ladder
  walk, the selector, and what a skipped rung is),
  `0035-control-held-uid-floor-learnings.md` (the one existing proxy→Control
  call on the session path: why it is not cacheable, how it is wired through
  `Options`, and how it fails), and
  `0037-collapse-contract-to-one-version-learnings.md` (the versioning mechanism
  you are about to use for the first time since it was cleaned up).
- `docs/CROSS-REPO-PROTOCOL.md` — **§1, §2, §3.2, §4.1, §5**. This phase edits
  `api/`, a shared surface, and it is **the phase that answers an upstream
  request**, which §5's "The PR that answers an upstream request is not a sync"
  governs.

## Where this came from

An **upstream request** from `hoplock/control` (`docs/CROSS-REPO-PROTOCOL.md`
§3.2), raised by its phase 0011 in
[Hoplock/control#35](https://github.com/Hoplock/control/pull/35).

Control's 0011 built a complete per-tenant SSH certificate authority: it
ensures, describes, issues, verifies, rotates and revokes, it keeps a retired
key trusted for a rotation overlap, it drops a compromised key from the bundle
at once, and its issuing call already takes exactly one input — **the public key
of a pair somebody else generated**. No private key crosses its API by
construction.

What it could not build is the way any of that reaches a proxy, and it did not
invent one: `contract/` is vendored read-only there (control M1), the ladder's
`method` enum names four values and none of them is a certificate, and this
repository's proxy refuses an authorize response it cannot read exactly. So
Control shipped the authority behind a seam that **refuses on purpose**
(`internal/credential/seam.go`, an outage-class error and never a denial —
control M11), plus a tripwire test that fails their build the day this method
appears in the vendored document.

**What stays impossible until this phase lands:** no route in the product can
name a brokered certificate. Every appliance and standing-account route keeps
using `brokered-key` — a credential an operator provisioned once, standing,
shared across sessions, and attributable only through this system's own records
(§5.2). The certificate authority Control built is exercised by its own tests
and its own CLI and by nothing on a session path.

## What was asked for — and the one part of it that changes

The request has two parts. **Part two is taken as asked. Part one is met with a
different parameter list, and the difference is the substance of this phase.**

Asked for, verbatim in shape:

1. A new `TargetAuth.method` value `brokered-certificate`, with params
   `username` (**required**), `certificate` (the `authorized_keys`-form
   certificate), `certificate_serial`, and `ca_public_keys` (optional).
2. A south-bound issuance endpoint, because a certificate must be signed over a
   key the proxy generated per session and `AuthorizeRequest` has nowhere to
   carry a public key. Suggested:
   `POST /v1/credentials/certificate`, `{session_id, decision_id, public_key}`
   answering `{certificate, serial, valid_before, ca_public_keys}`.

**Why part one cannot carry those three parameters.** `certificate`,
`certificate_serial` and `ca_public_keys` are all **per-session artifacts of one
issuance**, and `target_auth_ladder` rides on the authorize response, which is
**reusable** on a server-set TTL (D2, §6.4). A certificate on a cached decision
is replayed to every connection that decision serves — outliving its own
`valid_before`, naming one serial in many sessions' records, and carrying a
trust bundle from before a rotation. That is the argument `POST /v1/uids/lease`
already makes about a uid floor, in this repository's own words: *anything
cacheable is disqualified.* The same conclusion follows here and it follows
harder, because a certificate has an expiry of its own and a floor does not.

There is a second, independent reason, and it is in the request itself: the
certificate is signed over a key **that does not exist when the authorize call
is answered**. Part two exists precisely because the proxy generates that key
per session. A route parameter cannot carry a value that is produced after the
route is decided; the two halves of the request cannot both be right.

So the ladder entry carries **policy only**, the issuance response carries the
**artifacts**, and `api/README.md`'s existing sentence — *no credential material
travels on this API* — stays literally true of `target_auth_ladder`.

**Nothing Control needs is lost.** It asked for `certificate_serial` so "the
proxy names it in its own records and an operator matches a session to a row":
the proxy still records the serial, from the issuance response, which is the
only place it can be correct. It asked for `ca_public_keys` as "the trust bundle
for a proxy that administers the target": a `brokered-certificate` session
administers nothing (see "What this method is not", below), so the bundle is
answered on the endpoint, fresh, where a rotation reaches it.

**This is a change to what Control's `credential.LadderEntry` renders**, and the
sync (below) is what tells them.

## What this method is, and what it is not

The lifecycle mirrors §5.2, not §5.1: **nothing is created on the target and
nothing is removed.** The target already trusts the tenant's CA and already has
the account; the proxy generates a key pair for one session, has Control sign
the public half, logs in with the certificate, and zeroes the private half on
teardown. There is no remote state to undo, which is exactly why the method
reaches devices the proxy cannot administer.

Three consequences, and each is a decision this phase makes rather than an
observation:

- **It does not provision.** `TargetAuthMethod.Provisions()` returns `false`, as
  for `brokered-key`: the proxy configures nothing on the target, so no
  **applied** enforcement rung is reachable on such a route and only **attested**
  rungs are (§6.5, D12 as amended). Do not special-case this anywhere; the
  existing `RequiresProvisioning` check does the whole job once `Provisions()`
  answers.
- **It requires `username`,** like every method the contract defines (§4.2 "As
  finished (phase 0028)"). The route names the account or there is no route; it
  is never defaulted to `identity.Login`, and — like `brokered-key` and for the
  same reason — it never consults `identity.Principals`.
- **It is the first method whose credential is attributable on the target's own
  audit trail.** A certificate can name who it was minted for, where
  `brokered-key`'s standing account cannot. Say so in §5.2's successor section,
  and say it carefully: *what* a certificate asserts is Control's to decide and
  this repository must not claim it. What this repository can state is the shape
  — a per-session credential, minted for one session, expiring on its own.

## In scope

1. The contract: the `brokered-certificate` method and its params, and the
   `POST /v1/credentials/certificate` endpoint.
2. `internal/control`: the method constant and its validation, the Go types for
   the new endpoint, the client call, and the caching client's pass-through.
3. `internal/auth/target`: a new authenticator, registered in the selector.
4. `internal/proxy`: `decision_id` reaching the authenticator, and the serial
   reaching the record.
5. `cmd/mock-control`: a working certificate authority good enough to drive the
   proxy end to end, and the `vocabularyVersion` tiering that the first
   `policy_version` revision since 0037 requires.
6. The e2e topology: material, a target that trusts the CA, and a scenario.
7. `docs/PLAN.md` and `api/README.md`, including the indexes §3 requires.

## Out of scope

- **Revoking a certificate mid-session.** Control's CA can revoke; this
  contract's revocation stream already kills sessions (`session_kill`, §6.4),
  which is the coarser answer and the one that exists. Do not add a certificate
  revocation event, and do not make the proxy check a revocation list on the
  session path. Note it as a follow-up.
- **Publishing a CA trust bundle to a target.** `ca_public_keys` is decoded and
  carried, and nothing acts on it. A proxy that configures a target's trusted
  user CA keys is a provisioning act on a method that provisions nothing; if it
  is ever wanted, it belongs to `ephemeral-user`/`ephemeral-account`, as its own
  phase.
- **Host certificates.** This is a *user* certificate on the proxy→target leg.
  Target host keys stay on D7 and phase 0023's footing, untouched.
- **Any change to `brokered-key`,** its `CredentialSource` implementations, or
  its local material. The two methods coexist.
- **Retrying a failed issuance, or falling back to another rung after one.** See
  the failure rule below.

## The contract change

Work in the order `api/README.md`'s "Changing the contract" gives, and take
`POST /v1/uids/lease` as the model for the new path: it is the existing
proxy→Control call on the session path, and its description carries the
reasoning a new one is expected to carry.

### 1. The method and its params (`api/control.yaml`)

Add `brokered-certificate` to `TargetAuth.method`'s enum, documented in the
present tense (0037: a revision **replaces** the vocabulary; no "since version
N" annotation anywhere).

Documented params, and these three only:

| Param | Required | Meaning |
| --- | --- | --- |
| `username` | **yes** | the account on the target the certificate is presented for |
| `key_type` | no | the key algorithm the proxy generates for this session (e.g. `ed25519`); absent leaves the proxy's default |
| `lifetime_seconds` | no | an **upper bound** the route puts on the certificate's validity; absent leaves it unbounded by the route |

`key_type` and `lifetime_seconds` are the same two names `ephemeral-user`
already uses for the same two questions (§5.1). Reuse them rather than inventing
synonyms: one vocabulary is the point of a contract.

`certificate`, `certificate_serial` and `ca_public_keys` are **not** params.
State in `api/control.yaml` why, in one or two sentences, pointing at the same
cacheability argument `/v1/uids/lease` makes — a server author who put a
certificate on a cacheable decision would have shipped a replayed credential,
and the document is where that is prevented.

### 2. `POST /v1/credentials/certificate`

Request (all strings; `target`/`username` let the server bind the certificate to
what the route named and cross-check it against its own decision):

```json
{
  "session_id": "…",
  "decision_id": "…",
  "target": "host.example.com",
  "username": "netadmin",
  "public_key": "ssh-ed25519 AAAA… hoplock-session"
}
```

`session_id` and `public_key` are required. `decision_id` is sent when the
decision carried one (it is `omitempty` on `AuthorizeResponse`, so the proxy
cannot promise it); a server that requires it refuses the call, which the proxy
treats like any other refusal.

Response:

```json
{
  "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA… ",
  "serial": "10427",
  "valid_before": "2026-09-22T11:04:00Z",
  "ca_public_keys": ["ssh-ed25519 AAAA… ca"]
}
```

- `certificate` — one OpenSSH certificate in `authorized_keys` form, over the
  submitted public key.
- `serial` — a **decimal string**, not a JSON number. An SSH certificate serial
  is a `uint64` and JSON numbers are not safely integral above 2^53; a serial
  that silently loses its low digits is a join key that stops joining. Say this
  in the schema so a server author does not "fix" it to an integer.
- `valid_before` — RFC 3339, the same shape `session_deadline` uses.
- `ca_public_keys` — optional, `authorized_keys` form, one per element.

Errors: `400`, `401`, `500`, and `503` for a server with no authority
configured for this tenant. **The proxy treats every non-200 identically** —
outage-class, nothing provisioned — so the codes are for the operator reading a
server log, not for proxy behaviour. Say that in the path description.

### 3. Which half moves `policy_version`, and which does not

This matters and is easy to get backwards.

- **The endpoint does not.** `api/README.md` already says the number "governs
  `/v1/authorize` and nothing else… A whole new endpoint, `POST /v1/uids/lease`
  among them, is outside it too."
- **The enum value does.** It appears inside the strictly-decoded authorize
  response, and an unknown `method` is "a contract violation that refuses the
  whole response, not a rung to skip". A proxy that does not know
  `brokered-certificate` must never be sent it, and the version number is the
  only thing that can tell a server so.

So: `control.PolicyVersion` **4 → 5**, `info.version` to the next **minor** above
whatever it is when you start (0042 may have moved it first; do not hard-code a
number from this prompt), and the `api/README.md` prose that states the current
value updated with it. This is the first `policy_version` revision since 0037
cleaned the mechanism up — follow "Changing the contract" exactly, including
`clone.go` and the mutation test.

## The proxy change

### `internal/control`

- `policy.go`: `TargetAuthBrokeredCertificate TargetAuthMethod =
  "brokered-certificate"`; add it to `requiresUsername()` (**true**) and leave
  `Provisions()` answering **false** for it — but add the `case` explicitly
  rather than letting it fall into `default`, on that function's own stated
  reason: "a method added later declares its own answer here instead of
  inheriting one nobody chose."
- `validate.go`: accept the method in `TargetAuth.validate`, requiring
  `username` and permitting `key_type` and `lifetime_seconds`. Keep the existing
  split — the contract package validates **vocabulary**, and
  `internal/auth/target` refuses an **unknown parameter** at provision time
  (`ErrUnknownParam`). Do not duplicate either check in the other place; the
  comment in `policy.go` says why.
- New types and call, beside the lease (`lease.go` is the template):
  `CertificateRequest`, `CertificateResponse`, a `PathIssueCertificate`
  constant, a `CertificateIssuer` interface with one method, and the REST
  client's implementation.
- `cache.go`: the caching client **passes this call straight through**, exactly
  as it does the lease, and a test asserts it. A certificate answered from
  memory is a certificate replayed into a session whose key it does not match.
- `contract_test.go` cross-checks paths and enums against `control.yaml` and
  `api/README.md`; the new path and enum value must be picked up by it, not
  worked around.

### `internal/auth/target`

New file `brokeredcert.go`, one `TargetAuthenticator` implementation:

- `Name()` returns `"brokered-certificate"`.
- `Provision` reads `username` (refusing its absence, outage-class per §4.3,
  nothing provisioned), generates a key pair for **this session only** according
  to `key_type` (default `ed25519`), calls the issuer with the session id, the
  decision id, the target and the username, and parses the answer.
- It then **verifies what it was given before using it**, because a credential
  the proxy cannot check is one it is trusting a network answer about:
  - the certificate parses as an `*ssh.Certificate` and is a **user**
    certificate;
  - it certifies **the public key just submitted** — anything else means the
    proxy would be presenting a certificate for a key it does not hold;
  - `valid_before` is in the future and, when the route set
    `lifetime_seconds`, does not exceed that bound. A server may shorten a
    route's bound and may not widen it; widening is refused.
  Each failure is outage-class, nothing provisioned, and the error names the
  check — never the certificate and never the key.
- It returns a `ProvisionedAccess` whose `ClientConfig` uses
  `ssh.PublicKeys` over an `ssh.NewCertSigner` — restricted to the route's
  algorithm profile with `sshalg.Signer(…, tgt.Algorithms)`, as every
  session-leg signer is since phase 0043 (a certificate signer is restricted by
  its underlying key's algorithms) — with `User` set to the route's
  `username`, and whose `Teardown` zeroes the private key and closes the leg —
  there is no remote state to undo (§5.2). Teardown stays safe to call twice.
- Add `CertificateSerial string` to `ProvisionedAccess`, beside `Method`.

Wiring:

- `registry.go`: an `Issuer control.CertificateIssuer` field on `Options`,
  documented the way `Leaser` is — **the REST client and never the caching
  one**, and for the same kind of reason. A **nil** `Issuer` means this build has
  no material for the method, so `NewFromConfig` does not construct it and the
  rung is **skipped** by the ordinary D14 walk.
- `selector.go`: dispatch the new method.
- `auth.go`: `Target.DecisionID string`, documented as correlation for the
  issuance call and for nothing else.

**The failure rule, and it is the one judgement call in the phase.** A rung is
*skipped* when this build structurally cannot satisfy it — the method is not
implemented, or there is no local material (here: no issuer). **A failed
issuance is not that.** A transient Control failure, a refusal, or a certificate
that fails a check above is **outage-class and ends the session** (§4.3); it
never walks on to the next rung. Walking on would connect with a weaker standing
credential the server did not choose for this attempt, which is the silent
downgrade D12-as-amended and D14 both forbid — and it would do it precisely when
the server is unreachable and least able to say otherwise. Put that reasoning in
the code, not only here.

### `internal/proxy`

- `session.go`: pass `DecisionID: route.DecisionID` into the `target.Target`
  literal.
- `logging.go`: `recordCredential` sets a new attribute when the authenticator
  reported a serial. Name it `credential_certificate_serial`
  (`logging.AttrCredentialCertificateSerial`), beside `AttrCredentialMethod`. It
  rides the ordinary authorize record on the batch path (D8) — it is a
  correlation fact, not a security event — and it is what an operator joins to
  Control's own certificate row. Never record the certificate itself.

## The mock server and the e2e topology

`cmd/mock-control` must be able to **actually issue**, or nothing on the proxy
side is proved end to end.

- A minimal authority: load an ed25519 CA private key from the material
  directory at start, sign the submitted public key with the route's `username`
  as the sole principal, a monotonic serial, and a validity bounded by the
  route's `lifetime_seconds` where it set one. No revocation, no rotation — the
  mock is a reference, not a second product.
- A fixture affordance to make a **deliberately wrong** certificate, in the
  spirit of `cmd/mock-control`'s existing ones: at minimum one that exceeds the
  route's `lifetime_seconds`, so the proxy's refusal is provable against a real
  server answer rather than a hand-built struct.
- `vocabularyVersion` — **read its comment before editing it.** It returns
  `control.PolicyVersion` for every response today, and with the version at 5
  that would refuse a v4 proxy **every** route, including routes with no
  certificate anywhere in them, which is the opposite of what the function is
  for ("a proxy one revision behind still gets every route it CAN read"). So the
  baseline stops being `control.PolicyVersion`: name it explicitly, return 5
  only for a response whose ladder contains `brokered-certificate`, and update
  the comment, which currently claims every response the mock can build is
  expressible at the baseline.
- `deploy/gen-material.sh`: generate the CA pair; mount the private half where
  the mock reads it and the public half where the target does.
- `deploy/target/entrypoint.sh`: install the CA public key as sshd's
  `TrustedUserCAKeys` for the existing standing account, alongside the two keys
  it already installs. Follow the file's own conventions, including its warning
  about `.ssh` ownership and `StrictModes`.
- `test/e2e`: one scenario — a route whose ladder names `brokered-certificate`,
  a session that succeeds, and the authorize record carrying the method and a
  non-empty serial.

## Plan and index updates (`docs/PROTOCOL.md` §3)

- **New `docs/PLAN.md` §5.4**, `brokered-certificate` — the section this
  repository will be navigated to. Cover: the lifecycle (nothing created,
  nothing removed), the per-session key pair and why the private half never
  leaves the proxy, why the artifacts are not route parameters, the failure rule
  above, that it does not provision and what that costs it on §6.5's ladder, and
  the attribution point made carefully.
- **§5.2**: its "A Hoplock Control that mints per-session credentials
  **implements this interface**" is about to be wrong. It is a live reference,
  so update it rather than leaving it to rot — and the same sentence appears in
  `internal/auth/target/credentials.go`'s doc comment on `CredentialSource`
  ("THIS IS THE SEAM Hoplock Control's own plan expects to implement"). Grep for
  both. **The seam §5.2 promised is the right question and the wrong answer
  here:** `CredentialSource` asks "what material do I already hold for this
  reference", takes no public key and no session correlation, and returns
  material the proxy did not generate. This flow inverts every one of those. Do
  not widen `CredentialSource` for it — that changes every implementation of an
  interface for something it does not do — and say so where the promise was
  made, so the next reader gets the reasoning rather than a silent edit.
- **§4.2**: an "As extended (phase 0044)" paragraph and a fourth row in its
  method table.
- **§2's register**: D6a keeps its status (this phase renders it, it does not
  amend it — that is the finding, not an omission). Add §5.4 to its **Mainly
  in** column. **No new `D`,** and therefore no change to the decision range
  (`D1–D18` since phase 0042) that `test/docs/indexes_test.go` pins across three
  files.
- **§10**: a `0044` row. `TestEveryPhaseHasAPromptOrIsWithdrawn` requires it.
- **`api/README.md`**: the method's row in "Target credentials", rows in the
  absent-value defaults table for `key_type` and `lifetime_seconds` on this
  method, an "Ephemeral uid blocks"-style subsection for the issuance endpoint,
  and the updated `policy_version` prose.

**One landmine, and it will not announce itself as one.**
`test/docs/indexes_test.go`'s `TestDeviceSeamHeaderCountsItsLayers` scans from
`### 5.3 ` to `## 6.`, so a new `### 5.4` **inside that window** puts any
`**As <verb> (phase NNNN)**` layer you write in §5.4 into §5.3's count and fails
the build with a message about the device seam. Fix it where it is wrong: change
that test's end prefix to `### 5.4 `. Do not avoid the failure by keeping §5.4
thin, and do not touch §5.3's composed count to make a number agree.

## Acceptance criteria

- A route whose ladder names `brokered-certificate` with a `username` results in
  a session logged in under a certificate Control minted for that session, over
  a key pair the proxy generated and never sent anywhere.
- No private key, certificate, or public key appears in any log, error string,
  audit record, or file on disk. The serial does, and only the serial.
- A cached authorize decision reused across connections produces a **new
  issuance per session** — the certificate is never replayed. Prove it with a
  test that reuses one decision for two sessions and asserts two distinct
  serials.
- The authorize record names the method and the certificate serial.
- A certificate that does not certify the submitted key, is expired, or exceeds
  the route's `lifetime_seconds` ends the session as an **outage**, with nothing
  provisioned, and never by walking to the next rung.
- An unreachable or refusing Control ends the session as an outage, never as a
  denial and never as a downgrade.
- A build with no issuer **skips** the rung and walks on, exactly as a method
  with no local material does.
- A route naming the method with no `username`, or with a parameter the proxy
  does not know, is refused before anything is generated.
- A proxy declaring `policy_version: 4` is answered a `500` by the mock for a
  route that uses the method — and is still served every route that does not.
- `make build vet test lint`, the OpenAPI validator, the licence header check,
  `go test ./test/docs/...`, and the e2e topology all pass.

## Required tests

- `internal/control`: the enum and path cross-checks; `requiresUsername` and
  `Provisions` for the new method; validation of the three params and refusal of
  a missing `username`; `CachingClient` passing the issuance call through;
  `clone.go`'s mutation test covering any new response field.
- `internal/auth/target`: a table over the four verification failures (wrong
  key, malformed certificate, already expired, longer than the route's bound),
  each asserting outage-class and that the next rung was **not** tried; a
  success path asserting the `ClientConfig` presents a cert signer for the
  route's `username`; teardown zeroing the private key and being safe to call
  twice; a nil issuer skipping the rung.
- `internal/proxy`: `decision_id` reaching the issuer; the record carrying the
  method and serial and carrying no certificate.
- `cmd/mock-control`: the endpoint end-to-end through the real client; the
  `vocabularyVersion` tiering, including the case that a v4 proxy still gets a
  route without the method.
- `test/e2e`: the scenario above.

## Definition of Done & hand-off

Per `docs/PROTOCOL.md` §4, plus the two this phase owes because of where it came
from:

- The PR carries `## Cross-repo impact` with a ready-to-run sync kickoff for
  **`hoplock/control`** (`docs/CROSS-REPO-PROTOCOL.md` §4.1). Control is the
  repository that **raised** this request, which makes it the easiest of all to
  skip — it already knows what it asked for, so it feels like it needs no
  telling. It does: the session there that re-vendors `api/`, deletes the seam's
  refusal and wires the issuance endpoint is a **fresh session that knows
  nothing** (§5, "The PR that answers an upstream request is not a sync"). Check
  `hoplock/enterprise` too and write **"None"** if that is the answer; an
  omitted section is indistinguishable from never having looked.
- The sync kickoff must say plainly that **the ladder entry does not carry
  `certificate`, `certificate_serial` or `ca_public_keys`**, so
  `credential.LadderEntry` and the tripwire test that fires when the method
  lands are changed rather than merely un-refused, and that the serial now
  reaches the proxy on the issuance response.
- The learnings summary names the method, the endpoint, the `policy_version`
  bump, the failure rule, the `CredentialSource` question and how it was
  answered, and what Control must change — that last one is what the sync
  session reads.
