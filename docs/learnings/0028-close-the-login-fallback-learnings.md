# 0028 — Close the `identity.Login` fallback — Learnings

## Summary
- **What shipped:** no account name the proxy presents to a target can come from
  `identity.Identity.Login` any more, on any path. **Contract v4.2** makes
  `username` required on `brokered-key` too — so on every method the contract
  defines — and the three remaining call sites each resolve the account in a
  fixed order ending in a **refusal** (outage-class, PLAN §4.3, nothing
  provisioned, no target leg dialled). Contract change ⇒ cross-repo obligation.
- **The three resolution orders, verbatim:**
  - `brokered-key`: route `username` → `auth.target.brokered_key.username` → **refuse**
  - `static-key`: route `username` → `auth.target.static_key.username` → **refuse**
  - `ephemeral-user`: route `username` → `identity.Principals` → **refuse**
- **Multi-principal rule chosen:** exactly one ⇒ use it; **several ⇒ refuse**
  unless the route named one (picking the first would make a server's
  serialisation order into policy); none ⇒ refuse. `brokered-key` reads
  `Principals` **not at all** — its account is standing and shared (PLAN §5.2).
  No method cross-checks a route-named `username` against `Principals` (D2).
- **Policy version: NOT bumped.** `control.PolicyVersion` stays **4**. The
  document version moves `4.1 → 4.2`. Reasoning in "The version decision" below.
- **The grep that proves it** (re-runnable in one command; every surviving hit
  is a log, a prompt, the wire encoding, `Validate`, or a test asserting the
  login is *not* used):

  ```
  grep -rn 'id\.Login\|identity\.Login' --include='*.go' internal/ cmd/
  ```
- **Key files:** `internal/auth/target/{account.go (new),brokered.go,statickey.go,
  ephemeral.go,deviceaccount.go}`, `internal/identity/identity.go`,
  `internal/control/{policy.go,validate.go}`, `api/control.yaml` + `api/README.md`,
  `internal/config/config.go` + `config.example.yaml`,
  `deploy/proxy/proxy-nexthop.yaml`, `deploy/control/fixtures.template.yaml`,
  `docs/PLAN.md` (§4.2, §5.1, §5.2, §10).
- **Types/identifiers added:** `target.ErrNoAccountName`; unexported
  `target.noAccountName`, `target.accountFromPrincipals`.
- **What the NEXT session must know:** a test identity that provisions anything
  now needs `Principals`, and `internal/auth/target`'s `testIdentity()` sets a
  principal (`alice-svc`) deliberately **different** from its login (`alice`) so
  an assertion can tell them apart. `internal/proxy` has the same split as
  `testTargetAccount` vs `testLogin`. `static-key` now reads its route and
  refuses an unknown parameter, which it never did before.

## Details

### The defect, and the part of it that was worse than a fallback

Three code paths could turn `Login` — the string the user typed at their own SSH
client — into the account the proxy logs into a target as:

| Where | What it did | Reachable when |
| --- | --- | --- |
| `brokered.go` | `if username == "" { username = id.Login }` | the route omitted `username` (v3 still permitted it here) or named no method at all |
| `statickey.go` | same | `auth.target.static_key.username` unset |
| `ephemeral.go` | `login := p.str(ParamUsername, id.Login)` | no `target_auth`/`target_auth_ladder` — the locally-configured v1 path |

`static-key` was the worst of the three, and not because of the fallback.
**It never called `newParams`/`p.rest()` at all.** Since contract v3 the document
*requires* a `username` on a `static-key` route and `internal/control` *enforces*
it — and the authenticator then discarded it and used `a.username` or the login.
A route that says one thing while the proxy does another is worse than either
behaviour alone, and the same omission meant an unknown parameter on such a
route was silently ignored rather than refused (`ErrUnknownParam`, 0007) — the
one case every other method treats as a possibly dropped constraint.

### `Principals` was designed for this and had never been wired up

`Identity.Principals` carried, in its own doc comment, "the target-side
provisioner (0006) draws the ephemeral account name from here." Nothing did:
before this phase `grep -rn 'Principals' --include='*.go' internal/ cmd/` found
the field, its clone, its wire decoding and `HasPrincipal`, and **no consumer**.
The sentence had been false since it was written, and false in the direction
that matters — it described the correct design, which was then not built, so a
reader checking "is `Login` really the only option here?" was told it was not
and found no evidence either way. It now describes what actually draws from it.

`Principals` is the right source for exactly one reason: it is
**server-established**. Hoplock Control puts it on the authenticate/authorize
response, and an `Identity` is immutable once returned (PLAN D2) — the proxy
never adds to it. That is precisely the property `Login` lacks.

### The multi-principal rule, and why refusing beats picking

- **One** ⇒ use it. It is the identity's account.
- **Several** ⇒ refuse, unless the route named one. Picking `Principals[0]`
  would make the order a server happened to serialise a JSON array in into
  policy, and nothing about that order is contractual. A server that wants a
  particular one of several says so on the route.
- **None** ⇒ refuse. There is nothing to pick, and the alternative is a guess.

`brokered-key` deliberately does not consult `Principals` at all, and this is a
decision rather than an omission: the account it logs into is **standing and
shared across sessions** (PLAN §5.2), chosen by an operator, so a per-identity
principal is the wrong shape for it and using one would imply an attribution the
method explicitly does not provide — the same trade §5.2 already names as the
reason session capture is not optional on those routes.

### Not cross-checking the route against `Principals`

A route naming an account the identity's principal list does not contain is
**served**, and there is a test pinning that
(`TestEphemeralDoesNotCrossCheckTheRouteAgainstThePrincipals`). The PDP naming
an account is the PDP's decision to make; a proxy that overrode it would be
originating policy (D2) — the same rule that stops the proxy *widening* an
identity stops it narrowing one. `HasPrincipal`'s existing role is to answer a
question, not to veto a decision, and nothing in the contract says `Principals`
is the exhaustive set of accounts a route may name.

### The version decision

`control.PolicyVersion` stays **4**. `policy_version` declares what the proxy
can **read**, so a server can avoid answering in vocabulary the proxy would fail
closed on; it has never expressed what the proxy **requires**, and a tightening
is not expressible through it — no field is added, none changes meaning, and an
older proxy parses the route exactly as it always did. Phase 0013 made three
methods' `username` required without a gate and announced it as a break in the
versioning section; this does the same, in the same place, in the same words.

The **document** version does move, `info.version: 4.1.0 → 4.2.0`, with a
matching `## Contract 4.2 (phase 0028)` section in `api/control.yaml` and a
`### The v4.1→v4.2 revision` section in `api/README.md`. Nothing additive landed
beside it, so 4.2 is a tightening and nothing else.

### The tests that pinned the old behaviour

Three tests asserted the fallback and had to become their opposite. Each
replacement asserts the **refusal**, so the fallback cannot be reintroduced
against a green suite:

- `TestStaticKeyProvisionUsesTheAuthenticatedLogin` →
  `TestStaticKeyProvisionUsesTheRoutesUsername`, plus
  `TestStaticKeyRefusesWhenNothingNamesAnAccount` and
  `TestStaticKeyRefusesAnUnknownParameter` (the parameter half is new coverage,
  not a replacement — nothing tested it because nothing did it).
- `TestBrokeredKeyFallsBackToTheTargetAndLogin` →
  `TestBrokeredKeyFallsBackToTheTarget` (the *target* half is unrelated and
  stays) plus `TestBrokeredKeyRefusesWhenNothingNamesAnAccount`, which also
  asserts the credential source is **never asked**: the refusal is before the
  fetch, so nothing is held to zero.
- `TestBrokeredKeyKeepsItsV2Username` (0013 wrote it specifically so that
  leaving `brokered-key` out would be a *visible* decision rather than an
  accidental one) → `TestBrokeredKeyNeedsAUsernameToo`, covering the ladder
  shape with the rung named, the single-object shape, and the accepted case.
  0013's mechanism worked exactly as intended: the decision was visible, it was
  argued, and it was reversed on the argument.

### The fixture split that makes these tests able to fail

`internal/auth/target`'s `testIdentity()` now carries
`Principals: []string{"alice-svc"}` beside `Login: "alice"`, and `internal/proxy`
gained `testTargetAccount = "svc-target"` beside `testLogin = "alice"`. **The
two strings are deliberately different.** A fixture whose login and principal
were the same string cannot tell a passing test from a regression — every
assertion would hold under the old fallback too. One existing assertion was
tightened for the same reason: `TestEphemeralProvisionsAndTearsDown` checked
`strings.Contains(principal, "alice")`, which `alice-svc` satisfies, so it now
checks for the principal and against the login.

### The e2e scenario, and why the topology had to change to host it

The obligation was a scenario where a route's credential method has **no account
name available anywhere**. With the contract closed, that state is no longer
expressible on a route: every method requires `username`, so the mock refuses
such a fixture at startup (which is itself asserted, in
`cmd/mock-control/server_test.go`). The only remaining shape is a **v1-style
route naming no `target_auth` at all**, served by a proxy whose local method
also configures no account.

So `deploy/proxy/proxy-nexthop.yaml` now leaves
`auth.target.brokered_key.username` **deliberately unset** — the only proxy in
the topology that does — and the fixtures gained `unnamed.company.com`, scoped
to that proxy and naming no `target_auth`. `resolved_target` points at the real
target, so a session that got past the refusal would reach a host that is up and
answering: a green run means the refusal happened, not that the connection
failed anyway.

Nothing else depends on that key, and this was **verified rather than assumed**:
every `brokered-key` route in `cmd/mock-control/fixtures.example.yaml` and
`deploy/control/fixtures.template.yaml` names its own `username` (they have
since 0013), the other two proxy configs still set `netadmin`, and a next-hop
route never provisions a target credential at all (`internal/proxy/session.go`
returns before the credential machinery for `route.IsNextHop()`).

`test/topology/config_test.go` pins the whole arrangement in the ordinary
`go test ./...`, because it spans two files and is invisible in either alone:
break either half — add a username to proxy-nexthop, or a `target_auth` to the
route — and the scenario would pass vacuously against a proxy that had an
account all along.

**The ephemeral path needs no new local config key**, and none was added:
`config.EphemeralUserAuth` has never had a `username`, and the answer for a
route that names none is now `Principals` or a refusal.

### What could not be run in this session

`make e2e` and `make e2e-up`. Docker is installed in the session container but
no daemon is running, so the compose topology cannot come up. What *was* run
locally instead: the rendered fixture template (placeholders substituted) parsed
through `cmd/mock-control`'s real `parseFixtures`, which is the same validator
that would refuse it at container start, and `go test ./test/topology/`, which
loads all three proxy configs with the proxy's own loader. CI's e2e job is the
gate for the scenario itself.

`golangci-lint` from `$PATH` in this container is built against Go 1.25 and
refuses a module targeting 1.26 — the exact failure CI's lint job documents in
its own comment. It was run at the pinned CI version instead
(`go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2 run`):
**0 issues**.

### Follow-ups and stale references found on the way

No new prompts queued. Two **live references in queued prompts** were corrected
in this PR, per PROTOCOL §3:

- `prompts/queued/0035-control-held-uid-floor.md` told its session to bump the
  contract `4.1 → 4.2`. This phase took 4.2, so it now says `4.2 → 4.3` and
  tells the session to re-read `info.version` on `main` rather than trust the
  line.
- `prompts/queued/0036-collapse-contract-to-one-version.md` listed the revision
  sections to delete (now including 4.2's, in both files) and claimed "nothing
  queued today revises it again, so this phase's blocker is cleared". **That
  claim was already false before this phase** — 0035 revises `api/` and was
  queued above it precisely for that reason — and is now false twice over. It is
  corrected in place rather than deleted, with the reason it was written, since
  it is the kind of claim that gets re-derived. Its "4.1 carries a live reason"
  note gained a sibling: 4.2's reasoning about why a *tightening* is a break
  rather than a version gate is live and must survive the collapse.

### Deviations from the plan

None. `docs/PLAN.md` was extended, not contradicted: §4.2 gained an "As finished
(contract v4.2, phase 0028)" paragraph beside the v3/v3.1 ones, §5.1's "the
account name is the registry" bullet now says where the `<login>` segment comes
from, §5.2 says who the brokered account is and why it does not read
`Principals`, and §10's row for this phase carries what it delivered.
