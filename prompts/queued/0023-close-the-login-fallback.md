# 0023 — Close the `identity.Login` fallback: an account name is never client-typed

> New prompt, queued last on purpose. It closes the **final** path by which a
> string the user typed at their SSH client can become the account the proxy
> logs into a target as.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/CROSS-REPO-PROTOCOL.md` — **required**: this phase changes `api/`, a
  shared surface. §2 (upstream merges first), §4 (the Cross-repo impact section
  this PR owes, including a ready-to-run sync kickoff), §5.
- `docs/PLAN.md` — **§4.1** (why an identity is a claims model), **§4.2** (the
  credential methods and the wire vocabulary), **§5.1** (the ephemeral
  lifecycle and *the account name is the registry*), **§5.2** (`brokered-key`:
  the account is standing and chosen by an operator), **§5.3** (device account
  names), §4.3 (what the user is told).
- `internal/identity/identity.go` — read the doc comments on `Identity`,
  `Login`, and `Principals` **before** touching anything. They are the whole
  argument, and one of them is currently a false statement (see below).
- `docs/learnings/` — read every summary; open **0007** in full (the three
  authenticators, `params`, the reaper) and **0013** in full (contract v3, which
  made `username` required on three of four methods and recorded this phase's
  work as its named follow-up). Also open **0014** and **0016** if they exist by
  the time you run: both name accounts on a target.

## Why it is queued here, and not earlier

Recorded because it was argued, and because the obvious objection ("this is a
correctness defect, run it first") deserves an answer a future session can check
rather than take on trust.

**It is not blocked by, and does not block, the phases ahead of it.** There is
exactly one account-naming path — `newPrincipal(prefix, login)` in
`internal/auth/target/principal.go`, fed from `ephemeral.go`. 0014 *shares* that
function rather than forking it (its prompt says to generalise it "without
changing what it produces on Linux"), and 0016 and 0021 operate on an account
that is already named. So no phase ahead invents a second answer, and fixing the
source once fixes every consumer whenever it happens. An earlier draft of this
prompt claimed the opposite — that closing the fallback under 0014–0021 would be
"closing a moving target" — and that was wrong; it is corrected here rather than
quietly deleted, because it is the kind of reasoning that gets re-derived.

**What actually keeps it late is the cost of moving it.** Inserting before 0014
renumbers nine queued prompts, and `0014`–`0022` are cited roughly seventy times
across `docs/PLAN.md`, the other queued prompts, and `docs/learnings/`. PROTOCOL
§3 makes chasing every one of those references mandatory, and a queued prompt
pointing at a number that no longer exists is the exact failure that section was
written about. That is a large, error-prone change to buy ordering that nothing
technically requires.

**And the defect has no live exploit path.** `Login` is not an arbitrary
attacker-chosen string: it must be a login Hoplock Control authenticated. What
is wrong is narrower and still real — the account is selected by an input this
system's own rules say never to key a decision on, and `Login` is explicitly not
guaranteed stable across logins, so the same person can map to different target
accounts and different people can map to the same one. Design integrity, not an
open door.

**The one thing that could not wait has been handled without moving anything:**
0014's prompt now carries an explicit instruction not to entrench the login
segment's source or add a second `id.Login` reader while it generalises
`principal.go`. That is where the session doing the work will read it, which the
plan alone would not guarantee.

> The contract already forbids the dangerous half — phase 0013 made `username`
> required on `ephemeral-user`, `ephemeral-account`, and `static-key`. What
> survives is the local-configuration path and one method the contract still
> lets omit, and "closed except when the server says nothing" is not closed.

## The defect

`identity.Identity.Login` says of itself, in `internal/identity/identity.go`:

> Login is the SSH login name the client offered, with the target segment
> already stripped (D1). It is what the user typed, so it is useful in logs and
> prompts but **must never be the basis of an authorization decision**.

Choosing which account the proxy logs into a target as is an authorization
decision — arguably the most consequential one the proxy makes, because the
account is where the target's own audit trail, its file ownership, its
`authorized_keys`, and (on a password credential) half the credential pair live.
Three code paths still make it from `Login`:

| Where | Line, as of contract v3 | Reachable when |
| --- | --- | --- |
| `internal/auth/target/brokered.go` | `if username == "" { username = id.Login }` | the route omits `username` (the contract still permits it for this method) **or** no route names a method at all |
| `internal/auth/target/statickey.go` | `if username == "" { username = id.Login }` | `auth.target.static_key.username` is unset |
| `internal/auth/target/ephemeral.go` | `login := p.str(ParamUsername, id.Login)` | no `target_auth`/`target_auth_ladder` at all — the locally-configured v1 path |

Phase 0013 closed the contract half for three methods and **deliberately left
`brokered-key` alone**, on the reasoning that it logs into a standing account an
operator chose rather than one the proxy provisions. That reasoning is sound as
far as it goes and it does not reach the code: the fallback is still there, and
an operator who leaves `auth.target.brokered_key.username` unset gets an account
name typed by whoever is connecting.

There is a fourth thing, and it is worse than a fallback. **`static-key` never
reads the route's parameters at all**: it takes `a.username` from config or
`id.Login`, and it never calls `newParams`/`p.rest()`. So since contract v3 the
document *requires* a `username` on a `static-key` route, the contract gate
*enforces* it — and the authenticator then **discards it** and uses something
else. A route that says one thing while the proxy does another is worse than
either behaviour alone, and it also means an unknown parameter on such a route
is silently ignored rather than refused, which every other method treats as a
possible dropped constraint (`ErrUnknownParam`, 0007).

## The seam that was designed for this and never wired up

`Identity.Principals` carries, in its own doc comment:

> Principals are the principals this identity may assume on a target. **The
> target-side provisioner (0006) draws the ephemeral account name from here.**

Nothing does. `grep -rn 'Principals' --include='*.go' internal/ cmd/` finds the
field, its clone, its wire decoding, and `HasPrincipal` — and no consumer. The
sentence has been false since it was written, and it is false in the direction
that matters: it describes the correct design, which was then not built, so a
reader checking "is `Login` really the only option here?" is told it is not and
finds no evidence either way.

`Principals` is **server-established** — Hoplock Control puts it in the
authorize/authenticate response, the proxy never adds to it (an `Identity` is
immutable once returned, PLAN D2) — which is precisely the property `Login`
lacks.

## Objective

No account name the proxy presents to a target may originate from
`identity.Identity.Login`, on any path, including the paths taken when Hoplock
Control names nothing. Where no server-established and no operator-configured
name exists, the route is **refused** (outage-class, PLAN §4.3) rather than
served on a guess.

`Login` keeps every other job it has — logs, prompts, the SSH username split
(D1), the `login` field in an authorize request. This phase is about one
question only: what name do we log in as.

## In scope

### 1. The contract (`api/control.yaml`, `api/README.md`)

`username` becomes **required on `brokered-key`** as well, which makes it
required on every method the contract defines. Update:

- the `TargetAuth.params` description (`api/control.yaml`) — the "documented
  parameters today" list currently says of `brokered-key`: "`username` (the
  standing account to log in as; absent derives it from the identity's login,
  unchanged from v2)". That clause is what this phase deletes;
- the same exclusion in `api/README.md` — the target-credentials table's
  `brokered-key` row, **and** the "The v2→v3 revision" section, which spells out
  in a sentence why `brokered-key` was left out. Do not delete that sentence's
  reasoning silently: replace it with what is now true and why the earlier
  scoping was narrower;
- `internal/control/policy.go` — `TargetAuthMethod.requiresUsername()` and the
  comment block above it, which names this exact follow-up.

**On the policy version.** Work out what `control.PolicyVersion` is on `main`
when you start (contract v4 lands in 0015) and decide whether this needs a bump.
**Recommend: no.** `policy_version` declares what the proxy can *read*, so a
server can avoid sending vocabulary the proxy would refuse; it has never
expressed what the proxy *requires*, and a tightening is not expressible through
it. Phase 0013 made three methods' `username` required without a gate and
announced it as a break in the versioning section — do the same, in the same
place, in the same words. Bump only if you land something additive beside it,
and say which in the PR either way.

### 2. `internal/auth/target` — the three call sites

For each, the resolution order ends in a refusal and never in `Login`:

- **`brokered.go`** — route `username` → `auth.target.brokered_key.username` →
  **refuse**. Do *not* reach for `Principals` here: the account is standing and
  shared across sessions (PLAN §5.2), so a per-identity principal is the wrong
  shape for it and would imply an attribution this method explicitly does not
  provide.
- **`statickey.go`** — first make it read the route at all: `newParams(tgt.Auth)`,
  consume `ParamUsername`, and call `p.rest()` so an unknown parameter is
  refused like everywhere else. Then route `username` →
  `auth.target.static_key.username` → **refuse**. This is the development
  placeholder, so keep the change small; the point is that it stops disagreeing
  with the contract.
- **`ephemeral.go`** — route `username` → **`id.Principals`** → **refuse**.
  This is the one place the replacement is a *better* answer rather than only a
  safer one, because the account name is the attribution (PLAN §5.1) and
  `Principals` is the server's statement of which accounts this identity may
  assume.

  Decide and justify the multi-principal rule. **Recommend:** exactly one
  principal ⇒ use it; several ⇒ refuse unless the route named one, because
  picking the first would make link order into policy; none ⇒ refuse. Say in
  the PR what you chose.

  **Recommend NOT cross-checking** a route-named `username` against
  `Principals` in this phase, and say why: the PDP naming an account the
  identity's principal list does not contain is the PDP's decision to make, and
  a proxy that overrode it would be originating policy (D2). If you disagree
  after reading `HasPrincipal`'s existing use, argue it in the PR — do not do it
  silently either way.

- Fix `internal/identity/identity.go`'s `Principals` comment so it stops naming
  phase 0006 and starts describing what actually draws from it. This is the
  dangling-reference rule in PROTOCOL §3 applied to a sentence rather than a
  path.

### 3. The tests that currently assert the old behaviour

These **pin the fallback** and will fail. Replacing them is part of the work,
not an obstacle to it — and each replacement should assert the refusal, so the
next session cannot reintroduce the fallback and get a green suite:

- `internal/auth/target/statickey_test.go` — `TestStaticKeyProvisionUsesTheAuthenticatedLogin`;
- `internal/auth/target/brokered_test.go` — `TestBrokeredKeyFallsBackToTheTargetAndLogin`
  (only the login half; the target half is unrelated and stays);
- `internal/control/ladder_test.go` — `TestBrokeredKeyKeepsItsV2Username`, which
  0013 wrote **specifically so that this decision would be visible rather than
  accidental**. It becomes its opposite.
- `internal/auth/target/ephemeral_test.go` — `TestEphemeralUsesTheRoutesUsername`
  stays and still passes; add the principal-derived and refusal cases beside it.

### 4. Configuration, fixtures, and the mock

- `cmd/mock-control` — fixture validation for a `brokered-key` route with no
  `username` (the client's own `Validate` will now refuse it; check the fixture
  layer says so at startup too, as it does for the other methods).
- `cmd/mock-control/fixtures.example.yaml` and
  `deploy/control/fixtures.template.yaml` — every `brokered-key` route in both
  already carries a `username` as of 0013. **Verify that rather than assuming
  it**, and check the same for any route added by 0014–0022.
- `config.example.yaml` and `deploy/proxy/*.yaml` — the three deploy configs
  already set `auth.target.brokered_key.username: netadmin` for the local
  fallback method. Again: verify, do not assume. If the ephemeral path now needs
  no local username key, say so rather than adding one.

## Out of scope
- Anything about `Login` outside account naming. It stays in logs, prompts, the
  D1 username split, and the authorize request. Do not "clean it up".
- The credential ladder's walk, device drivers, enforcement rungs, UID
  allocation, session deadlines — 0014–0022 own those. If one of them added a
  fourth path from `Login` to an account name, closing it **is** in scope; the
  grep below is what finds it.
- Any change to `Identity` itself beyond the one comment. Adding a field, or
  making `Principals` required, is a contract and identity-model change with its
  own argument.

## Acceptance criteria
- `grep -rn 'id\.Login\|identity\.Login' --include='*.go' internal/ cmd/`
  returns **no** site where the value can become an SSH client's `User`, a
  provisioned account name, or an account name handed to a device driver. Sites
  in logs, prompts, and the authorize request are expected and stay. Put the
  actual grep and its output in the PR, not an adjective.
- Every credential method refuses cleanly, as an **outage** and not a denial
  (PLAN §4.3), when no account name is available: a test per method asserting
  the error, and — for at least one method — an end-to-end assertion that the
  user is told the outage wording and not a policy denial.
- `static-key` reads the route's `username` and refuses an unknown parameter,
  like every other method.
- `internal/control`: a `brokered-key` entry with no `username` is refused, in
  both the single-object and the ladder shape, with the rung named.
- `make openapi-check` passes; `api/README.md` documents the requirement in the
  target-credentials table **and** as a break in the versioning section, in the
  style of 0013's `username` note.
- `go build ./...`, `go vet ./...`, `go test ./...`, `golangci-lint run`, and
  `make license-check` pass.

## The e2e topology obligation

This phase changes what a misconfigured proxy does, so it owes the rig two
things:

- `make e2e-up` must still come up, and `make e2e` must still pass — the deploy
  fixtures and proxy configs already name every account explicitly, so a red rig
  here means one of them did not, which is exactly what this phase exists to
  surface.
- One scenario in `test/e2e`: a route whose credential method has **no** account
  name available anywhere fails as an **outage**, with the user shown the outage
  text and the session id, and nothing on the target created. Model it on the
  existing refusal scenarios rather than inventing a shape.

## Cross-repo impact

Requiring `username` on `brokered-key` is an obligation on Hoplock Control:
its policy authoring and its own fixtures must carry one on every
`brokered-key` route, and a route that omits it is now refused by the proxy.
Per `docs/CROSS-REPO-PROTOCOL.md` §2 **this PR merges first**; per §3.1 the
session that merges it opens the Control sync PR, and per §4 the PR body carries
the ready-to-run kickoff.

Locate the home for it by title, since Control renumbers its own queue:
*South-bound authorize & route* already carries the v3 `username` requirement
for the other three methods — this extends that same text rather than adding
anything new, so the sync **queues no prompt** (§5). Check *Contract vendoring &
conformance harness* too, in case its conformance suite asserts a `brokered-key`
response shape without a `username`.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`, plus the Cross-repo impact section. Move to
`implemented/`; add `docs/learnings/0023-close-the-login-fallback-learnings.md`.
The summary block MUST carry: the final resolution order for each of the three
methods verbatim, the multi-principal rule you chose and why, whether the policy
version moved and why, and the exact grep that proves no path remains — a future
session re-checking this claim should be able to re-run one command.
