# 0013 — Device provisioning: method, driver seam, contract v3 — Learnings

## Summary
- What shipped: **contract v3**. `/v1/authorize` gained D14's ordered credential
  ladder, D13's `ephemeral-account` method with its device-driver parameters, and
  a per-route algorithm profile; `username` became required on every
  provisioning method. Plus `internal/auth/target/device` — the `Driver` seam,
  its `Capabilities` declarations, and a platform registry, **with no driver and
  no network code**. Nothing walks the ladder yet; 0014 does.
- Key files: `api/control.yaml`, `api/README.md`,
  `internal/control/{policy,contract,validate,clone}.go` (+ `ladder_test.go`,
  `contract_test.go`), `internal/auth/target/device/{doc,driver,registry}.go`
  (+ `registry_test.go`), `cmd/mock-control/{fixtures,server}.go` +
  `fixtures.example.yaml` + `server_test.go`,
  `deploy/control/fixtures.template.yaml`, `docs/PLAN.md` §4.2 + §5.3.
- **The ladder shape: a plural field beside the old one.** `target_auth_ladder`
  is a JSON array of exactly the v2 `target_auth` objects; the single object is
  untouched. Both present is **refused** (`Validate`). Go type is
  `*TargetAuthLadder` (pointer to a named slice) — the pointer is the only thing
  that keeps **absent** (use local config) apart from **`[]`** (a denial). Read
  both shapes through **`AuthorizeResponse.Ladder() (rungs []TargetAuth, named
  bool)`**: a v2 single object comes back as a **one-entry ladder**, which is
  D6a's original behaviour. `TargetAuthLadder.MarshalJSON` emits `[]` for a nil
  slice so a denial can never re-encode as an absence.
- **`ephemeral-account` params, all required, no absent-value defaults:**
  `username`, `platform` (never inferred; lowercase/digits/single hyphens, ≤64),
  `credential_kind` (`password`|`publickey`), `expiry_posture`
  (`target-enforced`|`proxy-enforced`|`accepted-risk`), and `lifetime_seconds`
  (required unless the posture is `accepted-risk`). Constants:
  `control.Param{Username,Platform,CredentialKind,ExpiryPosture,LifetimeSeconds,
  KeyType,CredentialRef}`, `control.CredentialKind{Password,PublicKey}`,
  `control.ExpiryPosture{TargetEnforced,ProxyEnforced,AcceptedRisk}`.
- **Algorithm profile:** `algorithm_profile`, a top-level string on
  `AuthorizeResponse`, **named presets** — `default` (absent-value default),
  `legacy-rsa-sha1`, `legacy-device` — resolved by
  `AuthorizeResponse.Profile()`. Per route, never proxy-wide; anything but
  `default` is a weakening that emits its own audit event.
- **`username` is now required** on `ephemeral-user`, `ephemeral-account`, and
  `static-key`. **`brokered-key` was deliberately left alone** and still falls
  back to `identity.Login` in `internal/auth/target/brokered.go` — same leak,
  out of this prompt's scope. See "Follow-ups".
- Decisions made/affected: **D13**, **D14** (both implemented on the wire and in
  types), amends D6a's single-method rule. `control.PolicyVersion` is **3**.
  `docs/PLAN.md` §4.2 and §5.3 updated to record the wire names and the seam.
- **What 0014 must know:** the ladder is parsed, validated, and cloned but **not
  walked** — `internal/routing`, `internal/proxy`, and `internal/auth/target`
  were not touched, so a v3 server's ladder currently reaches
  `routing.Route.TargetAuth` as `nil` and the proxy falls back to local config.
  Wiring `Ladder()` through `resolve.go` into the selector is 0014's first job,
  and it is the one place where this phase's version bump is visible.

## Details

### Why a plural field rather than a polymorphic one

The prompt recommended the plural field and the round-trip tests agreed, so the
recommendation stands. A `oneOf` accepting object-or-array makes every consumer
— Control's authoring code included — branch on the runtime type of a value
that is policy, and Go's strict decoder cannot express it without a custom
`UnmarshalJSON` that would then own the absent/empty distinction as well. Two
named fields make the v2 shape unambiguous, and `policy_version` already tells
the server which one to send.

Refusing "both present" rather than preferring one is 0010's precedent
(`restricted_exec` beside a non-empty `rules` list). Preferring the ladder would
make the proxy the author of a policy the server wrote twice; preferring the
single object would silently discard rungs.

### The three states, and the pointer that carries them

This is the field most likely to be "simplified" by a later reader, so it is
worth stating why it looks the way it does:

| Wire | Go | Means |
| --- | --- | --- |
| absent | `nil` | the proxy's locally configured method (v1/v2) |
| `[]` | non-nil, empty | **a denial** |
| `[…]` | non-nil, non-empty | walk it top-down |

`[]TargetAuth` with `omitempty` collapses the first two: an empty ladder
serialises as an absent one, and a denial becomes a connection on the proxy's
own credential. Hence `*TargetAuthLadder`. `MarshalJSON` on the named slice type
closes the other half of the same hole — a non-nil pointer to a *nil* slice
would otherwise emit `null`, which decodes back to an absent ladder.
`TestEmptyLadderIsADenialNotLocalConfig` and `TestCloneIsolatesTheLadder` both
assert on this directly; do not delete them.

### Read versus satisfy

D14 says an unsatisfiable rung is skipped. That is **not** the same as a rung the
proxy cannot read. `Validate` refuses the **whole response** on an unknown
method, a malformed `platform`, an unknown credential kind or posture, or a
missing required parameter — anywhere in the ladder, and the error names the
rung (`target_auth_ladder[1].params.platform …`). Only a rung the proxy
understands but cannot satisfy is skipped, and that judgement is 0014's.

Getting this backwards would let a server hide a constraint in a rung the proxy
drops without saying so, which is the same defect class the strict decoder
exists to prevent.

### Where validation was deliberately *not* put

`internal/control` checks the contract's **vocabulary**: values this document
enumerates, and parameters it requires. It does **not** check whether the proxy
implements every parameter an entry carries — `internal/auth/target/params.go`
already refuses an unknown parameter at provision time (`ErrUnknownParam`), and
two almost-correct copies of one rule eventually disagree. There is a comment
saying so on the `Param*` block; it also notes that `internal/auth/target`
declares the same parameter names as its own constants today, and that 0014 can
collapse them onto `control.Param*` when it is already in that package.

Nor does it check that a driver for the named `platform` exists. D13 makes
customer-written drivers first-class, so the platform set is open and the
contract cannot enumerate it. What `Validate` can do — and does — is refuse a
`platform` value that is not a platform *name*, before it is used to select
anything. The unknown-driver half is `device.ErrUnknownPlatform`.

### The driver seam, verbatim

```go
type Driver interface {
    Platform() string
    Capabilities() Capabilities
    CreateAccount(ctx context.Context, req CreateRequest) (*Account, error)
    InstallCredential(ctx context.Context, req CredentialRequest) error
    RemoveAccount(ctx context.Context, req RemoveRequest) error
    ListAccounts(ctx context.Context, req ListRequest) ([]Account, error)
}

type Capabilities struct {
    MaxAccountNameLen    int
    EnforcesExpiry       bool
    PersistsAcrossReload bool
    CredentialKinds      []control.CredentialKind
    PinsSourceAddress    bool
}

func (c Capabilities) Accepts(kind control.CredentialKind) bool
```

Requests all embed `Endpoint{Host, Port, SessionID}` rather than the driver
holding a connection: a driver describes a *platform*, not a session, and the
reaper reaches devices no session is using. `CreateRequest` adds
`{Name, Profile, SourceAddress, Lifetime}`; `CredentialRequest` adds
`{Name, Kind, Password, PublicKey}`; `RemoveRequest` adds `{Name}`;
`ListRequest` adds `{Prefix}` — the reaper prefix, so one proxy's sweep can
never select another's live accounts. `Account` is `{Name, Profile, CreatedAt}`,
and **`CreatedAt` is zero when the platform does not record it**, which most do
not: the reaper must read zero as "age unknown", not as "created at the epoch".

Errors, and the distinction 0014 branches on:

- `ErrUnsupported` — **this platform cannot**, ever. Makes the rung
  unsatisfiable; the proxy walks to the next one. Build one with
  `Unsupported(platform, what)` so the log names the limitation.
- `ErrAccountExists` — the name is taken. The device path **never adopts** an
  existing account (unlike §5.1's idempotent POSIX path, because a short
  uniqueness token makes a collision plausibly another live session's); the
  provisioner retries with a fresh token, on its own budget.
- anything else — **this attempt failed**. Fails the session; it is *not* a
  reason to drop to a weaker rung the server ranked lower.

`MaxAccountNameLen` of 0 means undeclared and must be refused rather than
assumed generous. `Capabilities` must be answerable **without connecting**: the
provisioner reads them to decide whether a rung is servable at all, including
one it is about to skip, where there is nothing to connect to.

### Registry failure modes

- `Register(nil)` / a driver with an empty `Platform()` — plain error.
- `Register` of a platform already registered — `ErrDuplicatePlatform`. Refused
  at registration rather than resolved by order, because otherwise which driver
  a route gets depends on link order and the loser is a driver somebody
  installed on purpose.
- `Lookup(unknown)` — `ErrUnknownPlatform`, **outage-class (§4.3), never a
  guess**. The error names the platforms this proxy does carry, so an operator
  can tell a policy typo from a missing driver. A nil `*Registry` answers the
  same way rather than panicking.
- `Platforms()` — sorted; this is what a proxy advertises to Control so Control
  never names a platform the proxy has no driver for.
- `Shipped()` is the registry of drivers **this repository** ships (empty in
  0013; 0014 registers FortiOS into it). `CheckShipped(*Registry)` enforces
  D13's rule that a Hoplock driver may not declare `PersistsAcrossReload`;
  `TestShippedDriversDoNotPersistAccounts` runs it over `Shipped()` **and** over
  a fixture registry holding a persisting driver, so the passing assertion is
  not vacuous. The failure message says why, and says that a *customer* driver
  may declare it.

### Where the declarative driver format lands

D13 defers the declarative driver document and the subprocess contract. Both
become **implementations of `Driver`**: a document interpreter is one driver, a
subprocess supervisor is another, each registering under the platform its
document names. That is why the operations are named and typed here rather than
being a command list — a command list would have made the document format the
seam, and the compiled path a special case of it.

### Verification notes

`go build`, `go vet`, `go test ./...` (race), `golangci-lint run` (0 issues),
`make license-check`, and `make openapi-check` all pass. **`make e2e-up` could
not be run** — Docker is not available in this session's environment — so the
obligation it stands in for was met directly instead: the phase's own change to
`deploy/control/fixtures.template.yaml` was rendered (placeholders substituted)
and loaded by the real `cmd/mock-control` binary, which decodes fixtures
strictly and reported `serving 2 users and 15 routes`. That is the failure mode
the obligation exists to catch; the containers around it are unchanged by this
phase.

### Follow-ups

> **Update:** follow-up 1 below is now queued as
> `prompts/queued/0023-close-the-login-fallback.md`, which closes the fallback
> on every method and every path rather than only on the contract. The body of
> this section is left as it was written.

No new prompts were queued. Two things are recorded here instead:

1. **`brokered-key` still falls back to `identity.Login` for its username**
   (`internal/auth/target/brokered.go`, `statickey.go`). The prompt scoped the
   v3 requirement to the three methods where the proxy *provisions* the account,
   and `brokered-key` logs into a standing one an operator chose — but the
   client-typed-string objection is the same, and closing it is a second
   contract break somebody should decide on deliberately rather than have
   smuggled in here. `TestBrokeredKeyKeepsItsV2Username` pins the current
   behaviour so the decision is visible rather than accidental.
2. **The ladder is not wired through `internal/routing`.** `routing.Route` still
   carries only `TargetAuth`, so 0014 must add the ladder there (and clone it)
   before the selector can walk it. Until it does, `PolicyVersion = 3` advertises
   a vocabulary the engine does not yet act on — the same gap 0006 left between
   `target_auth` landing and 0007 consuming it, and it closes the same way.
