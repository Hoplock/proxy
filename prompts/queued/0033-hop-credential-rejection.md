# 0033 — Chain identity rejection: classify it, and decide whether to contain it

> **New prompt, added by phase 0025.** It is the same defect 0025 fixed on the
> proxy→target leg, still live on the proxy→proxy leg. It is inserted **before**
> the contract collapse (now `prompts/queued/0036-…`) because that one must stay
> the highest-numbered queued prompt; the mapping is in the newest run-order note
> at the end of `docs/PLAN.md` §10. Nothing in 0026–0032 depends on this, and it
> depends on nothing they change — pull it forward if a fleet hits it first.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — **§4.3 (the disclosure rule)**, §6.1 (routing and the chain),
  **D11** (the two hop connection directions), §7 (logging), D2.
- `docs/learnings/0025-target-auth-failure-containment-learnings.md` — **read
  this one in full.** It is the same problem solved once already, and most of
  what this phase needs already exists and is meant to be reused.
- `docs/learnings/0008-multi-hop-routing-learnings.md` — the chain trust model,
  and which key is presented to which hop.

## The observation this comes from

Phase 0025 made a refused proxy→**target** credential its own classified,
contained and legible failure. While doing it, the same shape turned up one
function away and was left alone as out of scope:

`handshakeNextHop` in `internal/proxy/nexthop.go` tags **every** handshake
failure that is not a host-key failure as `stageHopDial`, whose `outageDetail`
renders *"the next proxy in the chain could not be reached"*. But a next hop
that **refuses this proxy's chain identity key** — a fingerprint the far hop's
Hoplock Control does not recognise as one of its proxies (D11), a key rotated on
one proxy and not registered, a certificate whose principals do not name this
proxy id — produces exactly the `x/crypto` error 0025 taught this repository to
recognise, and is reported as an unreachable proxy.

The next proxy is reachable. It answered. It refused us. The user is told an
outage (correctly — this is not their permissions problem) and the operator
reading the audit log is pointed at the network, which is the one thing that is
fine. That is 0025's third finding, word for word, on the other leg.

**What this is NOT.** It is not a claim that the chain is insecure, and it is
not a contract question. The far hop refusing an unrecognised proxy key is the
trust model **working** (§6.1: no hop takes an upstream's word for who is
connecting). What is wrong is only how this proxy reports and repeats it.

## Objective

Make a refused chain identity a **classified and legible** condition rather than
a network fault — and answer, with the reasoning written down, whether it should
also be a **contained** one.

## In scope

### 1. Classify the rejection (required)

- Reuse `target.IsAuthRejection` (`internal/auth/target/reject.go`). Do **not**
  add a second matcher: it is deliberately the only place in the tree that knows
  x/crypto's wording, and it carries a tripwire test that exists to fail loudly
  on an upgrade that rewords the error. If importing `internal/auth/target` from
  the chain path reads wrong, move the classifier to a package both planes can
  import — but there must still be exactly **one** copy of the string, and the
  tripwire test must move with it.
- Add `stageHopAuth` to `internal/proxy/feedback.go` and return it from
  `handshakeNextHop` in `internal/proxy/nexthop.go`.
- **Order matters, exactly as it does in `dialTarget`:** the existing
  `takeHostKeyErr` branch must still win. A rejected host key also surfaces as a
  handshake error, it is a different failure with a different fix, and nothing
  about our credential was refused.

### 2. Disclose it (required)

- A new `outageDetail` branch for `stageHopAuth`. Wording must stay
  non-disclosing on §4.3's terms: it may say the proxy was not accepted by the
  next proxy in the chain; it must not name the next proxy, its id, its address,
  the key, or how far along the chain the session got. "This is not a
  permissions problem" and the session id stay, exactly as every other outage.
- The neighbouring wording is the calibration: `stageHopDial` says *"the next
  proxy in the chain could not be reached"* and `stageRelay` says *"the next
  proxy in the chain is not currently connected"*. This is the third member of
  that family and should read like one.

### 3. Record it (required)

- A capture point in `internal/proxy/logging.go`, alongside 0025's
  `recordCredentialRejected`, emitting a **critical** record with
  `control.LogKindError` so it takes D8's immediate path.
- Attributes: the next proxy id and the hop direction (both already have
  attribute constants — `logging.AttrHopNextProxy`, `logging.AttrHopConnection`
  — and both are already audit facts on this session's other records), the
  credential **handle**, and the stage. Follow 0025's naming: an
  `logging.AttrEvent` of `chain.identity_rejected` beside its
  `target.credential_rejected`.
- The handle is the **SHA256 fingerprint** of `chain.identity_key_path`'s public
  half, for the reason 0025 uses one for the management key: it is what an
  operator already reads in `ssh-keygen -lf` output and what the far hop's own
  logs will show them, so the two sides can be joined. **Never the key itself**,
  and never a path that would let a reader find one.

### 4. Decide on containment (required — the deliverable is the decision)

0025's breaker (`target.RejectionBreaker`) is reusable as it stands: it is keyed
on `(target, method, credential handle)`, and a chain leg has all three (the
next hop's address, a method name like `chain-identity`, the key fingerprint).
Wiring it in is small. **Do not do it because it is small.** Decide first,
because the argument that justified it on the target leg does not transfer, and
a phase that copies a mechanism past the reasoning that earned it is how a
codebase accumulates machinery nobody can later justify.

What made containment necessary on the target leg was a property of the *far
end*: an OpenSSH target scores failed authentications against the **proxy's**
source address (`PerSourcePenalties`, on by default since 9.8), so one route's
stale credential got the proxy blocked for every user of that target. **The far
end of a chain leg is another Hoplock proxy**, built on `x/crypto/ssh`, which
has no such defence — so that specific blast radius does not exist here.

So the phase must answer, and write the answer into its learnings:

- Is there a blast radius at all? Consider what a refused chain key actually
  costs when retried at the rate users arrive: load and log noise at the far
  hop, and — on the **`dial`** direction only — a TCP connection through
  whatever the estate put in front of that proxy (D11's "single firewall
  punch-through per hop" is a firewall, and a firewall may well be counting).
- Does the **`relay`** direction differ? It opens no new connection: the
  downstream registered outbound and the handshake rides that registration
  (`relay.Hub.Open`). If the argument for containment is "stop opening
  connections", it is weaker or absent there, and a breaker that treats the two
  directions alike would be claiming something untrue about one of them.
- Is a refused chain key **permanent** in a way a refused target credential is
  not? A fingerprint the far hop's Control does not know stays unknown until
  somebody registers it. That cuts both ways: it makes retrying more clearly
  futile, and it makes withholding more clearly a *second* outage stacked on the
  first, with a cooldown between an operator's fix and service returning.

**Either answer is a result.** If it is yes, reuse `RejectionBreaker` — do not
write a second one — add the `stageHopWithheld` stage and its wording on 0025's
pattern, key it in a way that is honest about the direction, and give it its own
config under `chain.` (not `auth.target.`, which is the other plane). If it is
no, say so in the learnings with the reasoning above, and ship sections 1–3
alone; that is a complete phase and the prompt still moves to `implemented/`.

### 5. Prove it

- Unit tests in `internal/proxy`, on the pattern of `internal/proxy/reject_test.go`:
  a next hop that refuses this proxy's identity is reported as a refused
  credential and **not** as an unreachable proxy; the host-key branch still wins
  when both failures are live at once; and the record is critical and carries no
  key material.
- Extend the e2e topology (`deploy/`, `test/e2e`) with a chain route whose
  upstream presents an identity the far hop's fixtures do not recognise. The
  fixtures are `deploy/control/fixtures.template.yaml` — the **mock** Hoplock
  Control inside this repository's rig, not the sibling Control repo — and
  `deploy/gen-material.sh` generates the material. Each route names the
  scenarios it backs. Put the scenarios **before** the outage scenario, which
  stops Hoplock Control. Do not change the shared `sshBaseArgs`.
- If containment ships, assert it the way 0025 does: on the far hop's own
  evidence that no new connection arrived, **never on timing**. Read 0025's
  learnings on why the cooldown in `deploy/proxy/*.yaml` is deliberately long.

## Out of scope

- **The proxy→target plane.** Phase 0025 owns it and it is done.
- **The management login** for `ephemeral-user` (`internal/auth/target/admin.go`).
  A refused management certificate surfaces as `stageProvision`, *"credentials
  for the target could not be provisioned"* — which is honest, if coarse, and is
  not the network-fault defect this phase is about.
- **The device drivers' dial path** (0014). It should adopt
  `ProvisionedAccess.DialOutcome` rather than have containment retrofitted; that
  is that phase's to do, and it is the target plane besides.
- **The trust model itself.** Do not change which key is presented, who
  authenticates whom, or what Hoplock Control is asked (§6.1, D11). This phase
  changes how a refusal is reported, and possibly how often it is retried.
- **`api/control.yaml`.** Nothing here is the server's business. Do not touch
  the contract; if you believe it must change, stop and ask
  (`docs/PROTOCOL.md` §9).

## Acceptance criteria

- A next hop refusing this proxy's chain identity is classified as its own
  stage, not as a hop-dial failure, and the host-key branch still wins where it
  applies.
- The classifier is still the single copy of x/crypto's wording, and its
  tripwire test still exists and still drives a real rejection.
- The user is told an outage that says the proxy was not accepted, discloses
  nothing about the next hop or the key, and carries the session id. A denial is
  still `Access denied.` and nothing else.
- A critical audit record names the next proxy id, the hop direction, and the
  key's fingerprint, and contains **no** key material.
- The containment question is answered in the learnings with reasoning, and the
  answer is implemented (or deliberately not) accordingly.
- e2e scenarios cover the above and pass in CI; `make e2e` passes locally.

## Definition of Done & hand-off

Per `docs/PROTOCOL.md`. Move this file to `implemented/`; add
`docs/learnings/0033-hop-credential-rejection-learnings.md`. The summary block
MUST record: the new stage and its user-facing wording; the new record's
attributes; **the containment decision and the reasoning behind it**, including
how the two hop directions differ; and whether any other place still reports a
far-side refusal as a network fault.
