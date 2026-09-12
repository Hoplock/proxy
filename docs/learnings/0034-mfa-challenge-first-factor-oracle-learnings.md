# 0034 — Does the MFA challenge disclose the first factor? — Learnings

## Summary
- **The answer is NO — evaluated, not built.** The signal is real: a correct
  password is answered with an MFA challenge and a wrong one never is, so the
  challenge's presence confirms the first factor without any message saying so.
  It is **accepted for this product**, and the number **0034 is retired**.
- Why: the decision is Hoplock Control's, not the proxy's (D2) — and the
  contract does not merely permit the oracle, it **requires** it, because a
  `200` on `/v1/auth/password` is documented as "the password was accepted".
- What a decoy would cost: one failed guess goes from **1 Control call to ~121**
  and from a stateless rejection to a **connection held for the challenge's
  life**, so the anti-enumeration measure is an amplifier handed to the
  attacker. It is safe only behind the rate limiting this prompt scopes out —
  which is also the control that actually blunts enumeration.
- The timing channel does **not** close: a decoy narrows a single-probe 1-bit
  oracle to a statistical one. Narrowing, not closure.
- Key files: `docs/PLAN.md` §4.3 (the accepted limit) + §10 (withdrawal row and
  ⊘ in the composed mapping), `test/e2e/scenarios_test.go` (0026's finding
  comment replaced by the decision). **No production code, no `api/` change**,
  so no cross-repo obligation.
- What the NEXT session must know: a future "yes" starts in `api/control.yaml`,
  at the `200` description on `/v1/auth/password` — until that sentence is
  relaxed a decoy is a contract violation. The proxy side needs nothing.

## Details

### What was asked

Phase 0026 drove `password-mfa` against a real OpenSSH client and asserted that
a denial names no factor. It does not. What happens *before* the denial does:
`bob` with the right password and a refused approval sees a challenge, waits,
and is told "Access denied."; `bob` with a wrong password is told "Access
denied." and nothing else. Both end identically — §4.3's requirement — and the
two runs are still trivially distinguishable by the one bit an attacker wants.

0026 wrote it up rather than changing the flow under the heading of a test, and
queued the question as 0034. This phase answers it.

### 1. Whose decision is it?

**Control's, and the contract's — not the proxy's.**

`PasswordMFAAuthenticator.AuthenticatePassword` relays the password and switches
on the status it is handed: `authenticated`, `mfa_required`, or an error
(`internal/auth/user/passwordmfa.go`). It has no input into whether a challenge
is issued, and by D2 it must not acquire one — a proxy that fabricated a second
factor would be originating policy, which the prompt's own out-of-scope list
also forbids outright.

So a fix is a Control behaviour. **Proxy work for a "yes": none.** That is
confirmed rather than assumed, on two paths that already exist:

- A decoy that resolves as a refusal takes the poll → `401` → `classify` →
  `ErrDenied` → `user.FailureMessage` path, which is exactly what a *real*
  refused approval takes. The e2e scenario "a denied second factor discloses no
  factor" drives it end to end today (`mallory`: correct password, refused
  approval), and a decoy is indistinguishable from her run at the proxy.
- A decoy that nobody ever answers takes `awaitMFA`'s deadline branch, which
  reports `ErrDenied` — "no second-factor approval before the challenge
  expired" — and so ends in the same "Access denied.".

**The finding that matters, and it was not in the prompt:** the oracle is not an
accident of `cmd/mock-control`'s fixtures. It is written into `api/`. The `200`
response on `POST /v1/auth/password` is described as *"The password was
accepted. Either `status` is `authenticated` … or `status` is `mfa_required`
…"*. A Control that answered a **wrong** password with `200 mfa_required` would
be violating that sentence. The contract as it stands does not merely leave the
oracle in place; it requires it. Any "yes" therefore begins with a contract
change here, and carries the obligation in `docs/CROSS-REPO-PROTOCOL.md` §4.

That the contract and the decision now agree is the reason this phase changes no
`api/` file: we are accepting the behaviour the contract already describes.
Relaxing the sentence *without* building the mitigation would have spent a
cross-repo sync on an option nobody had decided to take.

### 2. What does the estate lose?

The prompt frames the decoy as costing "a full MFA wait per guess" for the
attacker and "nothing" for a real user. Both halves are wrong in the direction
that decides this.

**Control-side.** At the shipped defaults (`config.example.yaml`:
`min_poll_interval: 500ms`, `max_wait: 2m`) a decoy that lives as long as a real
push-approval window — say 60s, since a decoy shorter than a real challenge is
its own oracle — is polled ~120 times. Each rejected guess therefore costs
Control **~121 requests where it costs 1 today** (derived: 60s ÷ 500ms + the one
`/v1/auth/password` call; at the proxy's own 2-minute cap it is ~241). §9.1
measures a whole *successful* connection at **3.17** Control calls uncached and
**1.17** after phase 0023. So the mitigation makes one failed password guess
roughly **100× more expensive to Control than a successful login**, and the
attacker pays one TCP connection for it. An enumeration defence whose cost curve
favours the enumerator this steeply is a denial-of-service lever wearing a
security hat.

**Proxy-side.** Today a wrong password is a stateless rejection: one Control
round trip and the connection is gone. A decoy converts it into a connection
**held for the challenge's whole life**. §9.1 measures 2 descriptors per live
connection against the run's 20,000 soft limit — ~10,000 concurrent connections
before descriptors bind. At a 60s decoy, **170 guesses/s fills that ceiling**
(derived: 170 × 60 = 10,200), and 170/s is under a quarter of the measured 716
conn/s establishment floor. The memory is cheap (118 KiB per live connection);
the descriptors are not.

**Real users.** Not nothing. A user who mistypes their password is shown the
challenge text and told to approve something on a phone that will never buzz,
then denied a minute later. That is a help-desk ticket per typo, and it trains
users to ignore the one prompt the whole scheme depends on them reading.

The common thread: the decoy is only safe behind a rate limit. Rate limiting,
lockout and anti-automation are explicitly out of this prompt's scope — and they
are also the control that blunts enumeration *directly*, without amplifying
anything. Deferring the signal and shipping the rate is the better ordering.

### 3. Is the timing channel closable at all?

**No.** A decoy closes the *presence* signal and leaves at least three:

- **Distribution.** To be indistinguishable, a decoy must resolve at a time
  drawn from the same distribution as a real challenge — which is a human on a
  phone: bimodal (approve in seconds / ignore to expiry), per-user, and
  time-of-day dependent. For an **unknown login** — the enumeration case that
  matters most — Control has no user whose distribution it could imitate, so it
  must invent one, and an invented one is a distribution of its own.
- **Outcome.** A decoy must never approve. A login that never resolves as
  approved over many probes is separable from one that sometimes does, however
  the denial timing is shaped.
- **Repetition.** The attacker chooses the sample size; the defender does not.

What a decoy genuinely buys is worth stating fairly rather than dismissing: it
turns a **single-probe, one-bit oracle into a statistical one**, which for an
attacker with one candidate password per account is a real reduction. But that
is narrowing, not closure, and the prompt asks specifically not to ship half a
mitigation described as a whole one. A "yes" would have had to be sold as
"harder to read", not "closed".

### 4. Does this belong to the prototype?

**No — and the argument holds, though not in its strongest form.**

§12 puts AD/Okta/OIDC out of scope and states the shape directly: *"The proxy
never talks to an IdP: it authenticates against Hoplock Control, which is the
component that federates."* In production the password is verified one layer
beyond where this repository stops. Deciding to answer a bad password with a
decoy is a decision taken at, or immediately above, that verifier — which is
also where enumeration defences conventionally live, and where the rate limit
that makes a decoy safe would have to live too. Building the behaviour into
`cmd/mock-control` would be modelling a component that, in production, does not
verify the password itself.

**The refutation, taken seriously:** the *contract* is not a prototype artifact.
It ships now, the sibling repository vendors it read-only (D3), and a Control
implementer reading that `200` description today will build the oracle in
because the contract tells them the password was accepted. "Out of scope for the
prototype" does not excuse a contract that forecloses the mitigation for good.

That refutation is why this phase does not simply file the question away. It
names the exact sentence a future "yes" must relax, in §4.3 and here, so the
option stays open at the cost of one paragraph rather than one rediscovery.

### What changed

- `docs/PLAN.md` §4.3 — a paragraph beside the deny/outage split recording the
  accepted limit. §4.3 is the paragraph a reader checks to learn what a denial
  discloses, and it promised more than the flow delivers; it now says where the
  flow stops and why that was accepted.
- `docs/PLAN.md` §10 — 0034's row becomes a withdrawal, and the composed mapping
  gains its ⊘ row (`test/docs/indexes_test.go` requires both).
- `test/e2e/scenarios_test.go` — 0026's closing comment pointed at
  `prompts/queued/0034-…`, which no longer exists. It now carries the decision,
  so the next reader of that scenario finds the answer instead of the finding.
- `prompts/queued/0034-mfa-challenge-first-factor-oracle.md` — **deleted**, the
  way 0021, 0030 and 0032 were (`docs/PROTOCOL.md` §6).
- `docs/learnings/0026-…` — a pointer note only. It is the record of what phase
  0026 shipped and its body is not rewritten (§3).

No `internal/`, `cmd/` or `api/` file changed, so there is **no cross-repo
obligation** (`docs/CROSS-REPO-PROTOCOL.md` §1: none of the four shared surfaces
is touched).

### One unrelated observation, recorded so it is not first-sighted twice

`TestEveryOperationAddressesTheGlobalAdminTable`
(`internal/auth/target/device/fortios`) failed **once**, on the first full
`go test ./...` of this session, at its closing
`assertAdminTableIsWrapped` — reporting an unwrapped `config system admin` on a
partitioned unit. It did not reproduce: the package passed on the pre-change
tree, three times after, twice more in full-suite runs, and twenty times under
`-race` with that test alone. This phase changed no Go production code — its
only code edit is a comment in `test/e2e/scenarios_test.go` — so it is not from
this diff. Not chased, and no prompt queued on one unreproducible sighting; it
is written down here so a second sighting starts from two data points rather
than one.

### If a later phase revisits this

The order that makes it worth doing, and none of these steps is this phase's:

1. **Rate limiting first** (a different phase, deliberately). Without it the
   decoy is an amplifier; with it, the oracle is already much less useful, which
   may well close the question a second time.
2. **`api/control.yaml`** — relax the `200` description on
   `/v1/auth/password` so a challenge no longer asserts the password was
   accepted, and say explicitly that a challenge MAY be issued for a login that
   will never be approved. Contract change, cross-repo obligation.
3. **`cmd/mock-control`** — a fixture shape for a decoy: a login whose challenge
   is issued regardless of the password and always resolves as a refusal.
4. **The scenario** — assert the two runs are *indistinguishable*, not merely
   identically worded. Note that the honest assertion is about the challenge's
   presence and wording; an assertion about timing would be a flake, which is
   itself evidence for the answer in question 3.
