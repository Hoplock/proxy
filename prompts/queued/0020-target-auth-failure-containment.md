# 0020 — Target credential rejection: classify, contain, disclose

> New prompt, added by phase 0012. It is appended rather than inserted: nothing
> in 0013–0019 depends on it, and it depends on nothing they change. Pull it
> forward if a fleet hits this before then — it is a live defect, not a
> refinement.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — §4.2 (proxy→target auth), **§4.3 (the disclosure rule)**,
  §5.1/§5.2 (the two credential methods), §7 (logging), D2, D6, D6a.
- `docs/learnings/` summaries: **0012** (where this was found, and the e2e
  topology you must extend), **0007** (both credential methods and their local
  material), **0005** (the proxy engine's `setupError`/`stage` mechanism),
  **0011** (the logging capture points).

## The observation this comes from

Phase 0012's first CI run failed with every scenario on one proxy reporting
`connection reset by peer` from the target. The target's own log said why:

```
Connection closed by authenticating user netadmin 172.19.0.2 port 50018 [preauth]
drop connection #0 from [172.19.0.2] on [172.19.0.4]:22 penalty: failed authentication
```

The proximate cause was mundane and is already fixed — a `.ssh` directory owned
by root, so `StrictModes` refused the brokered key. **What generalises is the
blast radius.** A decrypting proxy is a *single source address* to every target
it fronts. That is the deployment model, not an accident of the test rig. So
OpenSSH ≥ 9.8's `PerSourcePenalties` (on by default) scores a rejected
credential against **the proxy**, not against the user who happened to trigger
it, and after a handful of them the target stops answering the proxy at all.

Three things are wrong, and each is separately worth fixing:

1. **The proxy keeps trying.** Every new session for that target re-attempts the
   credential that just failed, at whatever rate users arrive. Nothing notices
   that the last twenty attempts were rejected for the same reason.
2. **One route's misconfiguration becomes every user's outage.** Once the target
   penalises the proxy's address, sessions that would have worked — a different
   route, a different credential, a different user — are refused too.
3. **The proxy says the wrong thing.** `dialTarget` in
   `internal/proxy/session.go` tags the rejection `stageDial`, so `outageDetail`
   renders *"the target could not be reached"*. The target is reachable. Our credential was refused. The user is
   told an outage (correctly — this is not their permissions problem) but the
   operator reading the audit log is pointed at the network, which is the one
   thing that is fine.

**What this is NOT.** An earlier reading of the same evidence — that the proxy
abandons target connections mid-handshake whenever a user is refused at the
proxy — is wrong, and 0012's green run refutes it: zero `[preauth]` closes and
zero penalty drops across the whole suite, including every scenario where the
user was denied a pty, a channel, or a command. Those refusals happen after the
target leg is already up. Do not go looking for connection churn; the exposure
is credential failure.

## Objective

Make a rejected proxy→target credential a **classified, contained, and legible**
condition instead of an unbounded retry that reads as a network fault.

## Design note: this does not violate D2

D2 says the proxy originates no policy. A circuit breaker looks like policy and
is not, by the same test that already licenses `chain.max_hops` and
`control.cache.max_ttl`: it can only ever make the proxy attempt **less** than
Hoplock Control authorised, never more, and it never turns a denial into an
allow. It is self-protection, and it belongs in proxy-local config for the same
reason those two do. Say so in the code comment; a reviewer will ask.

## In scope

### 1. Classify the rejection

`ssh.NewClientConn` reports a refused credential as
`ssh: unable to authenticate, attempted methods [none publickey], no supported
methods remain`. `x/crypto/ssh` exports no typed error for it, so classification
has to match on that text — and the honest way to do that is to isolate the
coupling and put a tripwire on it.

- Add `target.IsAuthRejection(error) bool` in `internal/auth/target/` (new file,
  e.g. `reject.go`). The string sentinel appears **exactly once in the tree**.
- Add a test that drives a **real** rejection — `internal/sshtest` target, wrong
  key — through `ssh.NewClientConn` and asserts `IsAuthRejection` returns true.
  That test is the point: it fails loudly on an `x/crypto` upgrade that reworded
  the error, instead of silently reclassifying every rejection back to
  `stageDial`. Comment it as such, or someone will "simplify" it into a string
  equality check on a literal.
- Add `stageTargetAuth` to `internal/proxy/feedback.go` and return it from
  `dialTarget` in `internal/proxy/session.go` when `IsAuthRejection` matches.
  Order matters: the existing host-key branch (`takeHostKeyErr`) must still win,
  because a host-key failure also surfaces as a handshake error.

### 2. Contain it

A per-credential circuit breaker in `internal/auth/target`.

- Key on **(target address, method, credential identity)** — the brokered
  `credential_ref`, or the management key's fingerprint for `ephemeral-user`.
  **Not** on the user or the route: a wrong credential is wrong for everybody,
  and a right one must keep working while another is failing. Never key on
  anything derived from the authenticated subject.
- After `threshold` consecutive rejections inside `window`, open for `cooldown`.
  While open, fail fast with a distinct error — no TCP connection to the target
  at all, which is the entire point.
- Any success closes it and resets the counter.
- New config block `auth.target.rejection` in `internal/config/config.go` and
  `config.example.yaml`: `threshold`, `window`, `cooldown`, all optional with
  documented defaults, and a `threshold: 0` escape hatch that disables it.
  Remember 0001's gotcha — decoding is **strict**, so every field must land in
  the struct *and* the example file.
- A tripped breaker is an **outage**, never a denial (§4.3). It is the proxy's
  own problem and no user can fix it with different credentials.

### 3. Disclose it

- A new `outageDetail` branch for `stageTargetAuth`. Wording must stay
  non-disclosing: it may say the proxy's own credential for the target was
  refused; it must not name the credential, the reference, the account, the
  method, or whether the target exists. "This is not a permissions problem" and
  the session id stay, exactly as every other outage.
- A distinct branch (or clearly-commented shared one) for the tripped breaker,
  so an operator can tell "we just tried and were refused" from "we are not
  currently trying".

### 4. Record it

- A capture point in `internal/proxy/logging.go` emitting a **critical**
  record — so it takes D8's immediate path, like every other security-relevant
  event — with `control.LogKindError`. Attributes: target, method, the
  credential **handle**, the consecutive-failure count, and the breaker state.
- **No credential material, ever** — not the key, not a passphrase, not a path
  that would let a reader find one. `credential_ref` is an opaque handle and is
  the most that may appear.

### 5. Write the deployment note

- A "Target prerequisites" section in `README.md` (cross-referenced from
  `docs/PLAN.md` §5): a proxy is one source address, so targets need
  `PerSourcePenalties`, `MaxStartups`, and `MaxSessions` considered, and here is
  what happens if they are not. `deploy/README.md` already says this for the
  test target — the operator-facing version is what is missing.

### 6. Prove it end to end

Extend `deploy/` and `test/e2e` (0012 owns both). Routes go in
`deploy/control/fixtures.template.yaml` — the **mock** Hoplock Control's
fixtures inside this repository's rig, not the sibling Control repo — and each
route names the scenarios it backs. Scenarios go in `TestTopology`
(`test/e2e/scenarios_test.go`), whose subtests are ordered deliberately: put
these before the outage scenario, which stops Hoplock Control. Do not change the
shared `sshBaseArgs`.

- A route whose `brokered-key` `credential_ref` names material the target does
  **not** accept. Assert the client is told an outage naming a refused
  credential — *not* "the target could not be reached", and *not*
  "Access denied." — and that a critical record names the target and method.
- After `threshold` attempts, assert the breaker is open: further attempts fail
  fast and **the target sees no new connection** (assert on the target's own
  log, or on a connection count — not on timing, which is a flake waiting to
  happen).
- Assert a *different* credential to the *same* target still works while that
  breaker is open. This is the assertion that catches the tempting wrong key.
- Leave `PerSourcePenalties no` in the target image. Containment must be proven
  by the proxy's own behaviour, not by the target giving up on it.

## Out of scope

- How credentials are **sourced**, rotated, or refreshed. This phase makes a
  rejection visible and bounded; fixing the credential is the operator's job.
- The device drivers (0014) and their dial path. The same containment should
  reach them; that phase owns its own connection code and should adopt this
  seam rather than have it retrofitted here.
- **`api/control.yaml`.** This is proxy-local self-protection and the server
  does not need to know. Do not touch the contract; if you believe it must
  change, stop and ask (`docs/PROTOCOL.md` §9).
- Any general-purpose retry/backoff framework. One breaker, one job.

## Acceptance criteria

- A refused proxy→target credential is classified as its own stage, not as a
  dial failure, and the host-key branch still wins where it applies.
- `IsAuthRejection` has a test that reproduces a real rejection, so an
  `x/crypto` upgrade that changes the wording fails CI rather than silently
  regressing the classification.
- Repeated rejections for one credential stop reaching the target; a different
  credential to the same target is unaffected; the first success resets it.
- The user is told an outage that says a credential was refused, discloses
  nothing about it, and carries the session id. A denial is still
  `Access denied.` and nothing else.
- A critical audit record names target, method, credential handle, and failure
  count, and contains **no** credential material.
- `README.md` documents the target prerequisites and what happens without them.
- e2e scenarios cover all of the above and pass in CI; `make e2e` passes
  locally.

## Definition of Done & hand-off

Per `docs/PROTOCOL.md`. Move this file to `implemented/`; add
`docs/learnings/0020-target-auth-failure-containment-learnings.md`. The summary
block MUST record: the exact `x/crypto` error text the classifier matches and
where the tripwire test lives; the breaker's key, defaults, and config keys; the
new stage and its user-facing wording; the new record's attributes; and whether
you found any other place a target-side failure is reported as a network fault.
