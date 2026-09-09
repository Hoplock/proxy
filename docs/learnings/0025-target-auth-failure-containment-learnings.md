# 0025 — Target credential rejection: classify, contain, disclose — Learnings

## Summary
- What shipped: a refused proxy→target credential is now its own classified
  failure instead of a network fault. `target.IsAuthRejection` is the single
  place that knows x/crypto's wording; a per-credential circuit breaker in
  `internal/auth/target` withholds a credential after a run of rejections, from
  *before* provisioning so no TCP connection is made; the user gets an outage
  that names the side the credential belongs to and nothing else; and each event
  is a **critical** `error` record. No contract change.
- Key packages/files: `internal/auth/target/{reject,breaker}.go` (+ tests),
  `{auth,selector,registry,brokered,ephemeral,statickey,admin}.go`,
  `internal/proxy/{feedback,session,logging}.go` +
  `internal/proxy/reject_test.go`, `internal/logging/record.go`,
  `internal/config/config.go` + `config.example.yaml`,
  `internal/sshtest/target.go` (`Options.AuthorizedKeys`), `README.md`
  ("Target prerequisites"), `docs/PLAN.md` §5 + §10, `deploy/`
  (`gen-material.sh`, `control/fixtures.template.yaml`,
  `proxy/proxy-direct.yaml`, `target/entrypoint.sh`, `README.md`),
  `test/e2e/scenarios_test.go`, `test/topology/config_test.go`.
- **The error text the classifier matches**, exactly as
  `golang.org/x/crypto/ssh@v0.56.0` builds it in `client_auth.go`:
  `ssh: unable to authenticate, attempted methods [none publickey], no
  supported methods remain`. `IsAuthRejection` requires **both**
  `"ssh: unable to authenticate"` and `"no supported methods remain"` — the
  prefix alone also opens a partial-success error. **The tripwire test is
  `TestIsAuthRejectionOnARealRejection` in
  `internal/auth/target/reject_test.go`**: it drives a real handshake through
  `ssh.NewClientConn` against an `internal/sshtest` target that refuses the key.
  It must never become a string comparison against a literal.
- **Breaker:** keyed on **(target `host:port`, method, credential handle)** —
  never on the user, the subject, or the route. Handles: the route's
  `credential_ref` for `brokered-key` (`(by target)` when it names none), the
  **SHA256 fingerprint of the management key** for `ephemeral-user`, the key's
  fingerprint for `static-key`. Config `auth.target.rejection.{threshold,
  window,cooldown}`, defaults **5 / 5m / 5m**; `threshold: 0` disables it, and
  the field is a `*int` because absent and zero are different answers.
- **New stages and wording** (`internal/proxy/feedback.go`): `target-auth` →
  *"the proxy's own credential for this target was refused"*;
  `target-auth-withheld` → the same plus *"…refused repeatedly, so it is not
  attempting the connection at present"*. Both are **outages** (§4.3) carrying
  the session id; neither names the credential, the reference, the account, or
  the method. The `takeHostKeyErr` branch still runs first.
- **New records:** two critical `error` records, `target.credential_rejected`
  and `target.credential_withheld` (`logging.AttrEvent`), with `target_addr`,
  `credential_method`, `credential_handle`, `rejection_count`,
  `rejection_breaker` (`open`/`closed`) and `rejection_open_until`. New
  recorder method `logging.SessionRecorder.CriticalFailure`.
- **Yes, there is another place a far-side refusal reads as a network fault**
  — `handshakeNextHop` in `internal/proxy/nexthop.go`. Queued as
  **`prompts/queued/0033-hop-credential-rejection.md`**, which moved the
  contract collapse to **0034**; details below.
- What the NEXT session must know: `ProvisionedAccess.DialOutcome(err)` is the
  seam. Anything that opens a leg with provisioned credentials reports the
  handshake through it and gets back the credential's state; phase 0014's device
  dial path should adopt it rather than have containment retrofitted. A method
  that cannot implement `target.CredentialIdentifier` gets **no** containment,
  deliberately.

## Details

### Why this is not policy (D2)

A reviewer will ask, so the answer is in the code as well as here
(`breaker.go`, `config.go`, PLAN §5). The breaker passes the same test that
already licenses `chain.max_hops` and `control.cache.max_ttl`: it can only make
the proxy attempt **less** than Hoplock Control authorised, never more, and it
never turns a denial into an allow. A session it stops is an outage — the
proxy's own problem, which no user can fix with different credentials — and
never a denial.

The keying is the other half of the argument. Keying on the subject would make
containment a per-user fact, which is both wrong (a wrong credential is wrong
for everybody) and exploitable: any user who can reach a target could withhold
it from the next user by failing on it repeatedly. `RejectionKey` has three
fields and none of them comes from the authenticated identity.

### Where the check happens, and why it is before provisioning

`Selector.provisionOne` consults the breaker **before** calling
`method.Provision`. That ordering is the point: on `ephemeral-user`, running the
method means opening the management login — the most privileged connection this
proxy makes, and exactly the connection a target's per-source defences count.
Checking after provisioning would already have made it.

The credential handle therefore has to be knowable before anything is
provisioned, which is what `CredentialIdentifier` is for. `EphemeralAuthenticator`
gets its handle from the `AdminDialer` through an unexported optional interface
(`credentialNamer`), so a test dialer needs nothing and a dialer that cannot
name its credential simply gets no containment.

### A withheld credential is not a skipped rung

D14's ladder falls through rungs this proxy has no material for. Containment
deliberately does **not** fall through: a transient local condition must not
quietly serve the session on a weaker credential than the one Hoplock Control
put first. That is a downgrade nobody authorised, decided by the proxy.
`TestSelectorDoesNotFallThroughAWithheldRung` holds it.

### Two gotchas found while building it

- **`Check` must not reset the count it is reading.** The first version deleted
  a "closed but counting" entry, so any call to `Check` between two rejections
  wiped the run and the breaker could never open past two. Caught by
  `TestDialOutcomeScoresOnlyRejections`, which interleaves a *dial* failure
  (correctly not scored) between two rejections — the exact shape that hid it.
- **`internal/sshtest`'s target accepted any public key**, so it could not
  produce a real rejection at all. `Options.AuthorizedKeys` was added; nil keeps
  the old behaviour, which is what every other test wants. The attempt is
  recorded before it is judged, so `Target.Keys()` counts refused offers too —
  which is how `TestRepeatedRejectionsStopReachingTheTarget` asserts containment
  without looking at a clock.

### The other place a target-side failure reads as a network fault

`handshakeNextHop` (`internal/proxy/nexthop.go:135`) tags **every** handshake
failure that is not a host-key failure as `stageHopDial` — *"the next proxy in
the chain could not be reached"*. A next hop that refuses this proxy's **chain
identity key** (an unrecognised fingerprint at the far hop's Hoplock Control,
D11) produces the identical x/crypto error this phase learned to classify, and
is reported as an unreachable proxy. It is the same defect on the other leg, and
the containment argument applies to it too: an edge proxy is one source address
to a hub exactly as it is to a target.

It was left alone deliberately — this prompt scopes itself to the proxy→target
credential plane, and the chain key is a different credential with a different
lifecycle and a different operator remedy. It is now
**`prompts/queued/0033-hop-credential-rejection.md`**, added by this phase at
the user's request, which required renumbering the contract collapse
**0033 → 0034** so it stays last (`docs/PROTOCOL.md` §6; the mapping is the
newest run-order note at the end of `docs/PLAN.md` §10).

**One thing that phase must not copy from this one.** Containment here was
justified by a property of the *far end*: an OpenSSH target scores failed
authentications against the proxy's source address, so one stale credential got
the proxy blocked for everybody. The far end of a chain leg is **another Hoplock
proxy**, built on `x/crypto/ssh`, which has no such defence — so that blast
radius does not exist there, and the two hop directions differ again (a `relay`
hop opens no new connection at all; it rides a registration the downstream
already made). The prompt therefore makes classification, disclosure and the
record **required**, and makes containment a question it must answer with
reasoning rather than a mechanism to copy across. Reuse `RejectionBreaker` if
the answer is yes; do not write a second one.

Two lesser cases, both out of this prompt's scope and neither claiming a network
fault:

- the **management login** for `ephemeral-user` (`admin.go`) surfaces a refused
  management certificate as `stageProvision`, *"credentials for the target could
  not be provisioned"*. That is honest, and the breaker does not score it: only
  the target-leg handshake is scored today.
- the **device dialer** (`device.SSHShellDialer`, phase 0014) has its own dial
  path and is explicitly out of scope. It should adopt `DialOutcome` rather than
  grow its own containment. `DeviceAccountAuthenticator` implements no
  `CredentialIdentifier`, so today it is simply uncontained — visible rather
  than silently keyed on something meaningless.

### e2e

`deploy/gen-material.sh` now generates a second brokered credential,
`stale-fleet`, whose public half is installed **nowhere**; the one route naming
it is `refused.company.com`. `test/topology` asserts both facts without Docker,
because the containment scenarios leave that credential's breaker **open** for
the rest of the run, and a second route on the same credential would inherit an
outage nobody asked for.

`proxy-direct` sets `threshold: 2` and a **ten-minute** window and cooldown. The
threshold is low so a scenario reaches it in two sessions; the cooldown is long
so that no assertion in a run can be overtaken by it — the prompt is right that
a timing-dependent assertion here would be a flake waiting to happen. The
consequence is that re-running `TestTopology/target_credential_rejection`
against an already-used rig needs `make e2e-down && make e2e-up` first;
`deploy/README.md` says so.

Containment is asserted against **the target's own log** — `sshd` says
"authenticating user" only about a connection that reached authentication and
did not complete it — and the scenario proves the marker moves before it relies
on it not moving.

`PerSourcePenalties no` stays in the target image, as the prompt requires: the
proxy's behaviour is what these scenarios are evidence about, not the target
giving up on it.

### Deviations

None. The branch name is the one the session was given (`docs/PROTOCOL.md` §2
says that is not a deviation).

`golangci-lint` could not be run locally in this session's container — the
installed binary is built with Go 1.25 and refuses a module targeting Go 1.26
(`can't load config: the Go language version (go1.25) used to build
golangci-lint is lower than the targeted Go version (1.26.0)`). It is a
pre-existing environment mismatch, not something this change introduced; CI's
`lint` job is the gate.

### Follow-ups

- **`prompts/queued/0033-hop-credential-rejection.md`** — `handshakeNextHop`'s
  classification, and the containment question, above. Queued by this phase;
  the contract collapse moved to `0034` for it.
- `brokered-key` still falls back to `identity.Login` for its username
  (0013's known gap, prompt 0028). Unchanged by this phase, but note that a
  route naming no `credential_ref` gets the handle `(by target)` — the source
  keys on the target, and the target is already a field of the breaker's key, so
  one placeholder is not one shared identity.
