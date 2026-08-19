# 0004 — Identity model & user→proxy auth — Learnings

## Summary
- What shipped: the proxy's identity/claims model (`internal/identity`), the
  `UserAuthenticator` plane with `cert` + `password-mfa` implementations, a
  config-driven registry that orders them certificate-first, and the SSH server
  auth adapter that speaks to the user (banner, keyboard-interactive MFA
  instructions, deny-vs-outage failure text). No proxying, no target leg.
- Key packages/files: `internal/identity/{identity,wire}.go`,
  `internal/auth/user/{auth,cert,passwordmfa,prompt,registry,feedback,ssh}.go`,
  `internal/config/config.go` (+ `config.example.yaml`). New dependency:
  `golang.org/x/crypto v0.44.0` (pinned: v0.45+ requires Go ≥ 1.25 and CI pins
  1.24).
- Types (exact shapes below in Details): `identity.Identity{Subject, Login,
  DisplayName, Source, Principals, Groups, Claims, Method, AuthenticatedAt}`,
  `identity.Claims map[string]string`, `identity.Method` (`cert` |
  `password-mfa`); `user.UserAuthenticator` (PLAN §4.1, unchanged),
  `user.ConnMeta`, `user.Options`, `user.Registry`, `user.ServerAuth`,
  `user.MFAPrompter`, `user.FlowSupport`.
- Config keys: `auth.user.methods` (**set**, not order — default both),
  `auth.user.mfa.{min_poll_interval,progress_interval,max_wait}` (durations,
  zero = package default).
- Error contract: `ErrDenied` (only `control.IsUnauthorized`) vs `ErrUnavailable`
  (everything else) vs `ErrMethodNotSupported`. `user.FailureMessage(err,
  sessionID)` renders the PLAN §4.3 split; **0005 must reuse it**, not
  re-implement it.
- Decisions made/affected: D2, D4, D7 (redaction), PLAN §4.1/§4.3. **No
  `docs/PLAN.md` change** — nothing deviated from it.
- What the NEXT session (0005) must know: build a `user.Registry` with
  `NewFromConfig`, wrap it in `ServerAuth`, call `Apply(*ssh.ServerConfig)`, and
  read the identity back with `IdentityFromPermissions(conn.Permissions)`. The
  `ConnMeta` function is yours to supply — it is where the D1 username split
  belongs. `cmd/proxy` still does not load its config; that lands with the
  listener in 0005.

## Details

### The identity model (`internal/identity`)

```go
type Method string // "cert" | "password-mfa"; Valid(); WireMethod() control.AuthMethod

type Claims map[string]string // Get/Value/Has/Clone

type Identity struct {
    Subject         string    // stable unique id at the source — audit/policy key on this
    Login           string    // SSH username with the target segment stripped (D1)
    DisplayName     string    // may be empty
    Source          string    // "fixture" | "ad" | ...; SourceUnknown when unset
    Principals      []string  // principals assumable on targets (0006 draws from here)
    Groups          []string  // policy keys on these
    Claims          Claims
    Method          Method    // how it was proven on THIS connection
    AuthenticatedAt time.Time
}
// HasGroup / HasPrincipal (exact string match) / Clone (deep) / Validate / String
```

Three properties later phases depend on:

- **Never key policy on `Login`.** It is what the user typed. `Subject` is the
  only field stable across logins, so routing, revocation (`KillSubject`), and
  audit correlate on it.
- **Comparisons are exact.** Case folding and domain-qualification belong to the
  identity source. If AD arrives with `ENGINEERING` and Okta with `engineering`,
  that is the adapter's problem to normalise, not every consumer's.
- **An Identity is immutable after authentication.** Nothing in the proxy adds
  a group, principal, or claim: widening an identity locally would be
  originating policy (D2). `Clone` exists for handing it to code that might.

`Validate` requires `Subject`, `Login`, and a known `Method`; an empty `Source`
is defaulted to `"unknown"` rather than failing, because it is cosmetic while
the others are not. `String` deliberately omits claims so no log line
accidentally prints a source-controlled attribute.

**Conversion lives in `internal/identity/wire.go`**, not in `internal/control`:
`FromWire(*control.Identity, Method, time.Time) (*Identity, error)` and
`(*Identity).ToWire() *control.Identity`, plus `Method.WireMethod()` for
`AuthorizeRequest.AuthMethod`. The direction (identity → control) keeps the
contract package a pure description of the wire; 0005/0006/0007 must use these
two functions rather than copying fields, so a contract change lands in one
place. Both copy slices and maps — neither side can alias the other.

`FromWire` validating is a security property, not tidiness: a server that
answers "authenticated" without a subject has violated the contract, and the
proxy must refuse a session it could not attribute in an audit log. That
failure is classified `ErrUnavailable`, never `ErrDenied`.

### The authenticator plane (`internal/auth/user`)

The PLAN §4.1 interface is implemented verbatim:

```go
type UserAuthenticator interface {
    Name() string
    AuthenticateCert(ctx context.Context, meta ConnMeta, key ssh.PublicKey) (*identity.Identity, error)
    AuthenticatePassword(ctx context.Context, meta ConnMeta, password string) (*identity.Identity, error)
}

type ConnMeta struct {
    SessionID, ProxyID, Login, Target string
    ClientAddr, ServerAddr, ClientVersion string
    HopTrail []string
}

type Options struct {           // shared by both implementations
    Client control.Client           // required
    Logger *log.Logger           // nil discards; never given a password
    Now    func() time.Time      // nil means time.Now
}
```

Constructors: `NewCertAuthenticator(Options)`,
`NewPasswordMFAAuthenticator(Options, PasswordMFAOptions{MinPollInterval,
ProgressInterval, MaxWait})`.

**The error contract is the load-bearing part.** `classify` maps
`control.IsUnauthorized(err)` → `ErrDenied` and *everything else* → `ErrUnavailable`,
with an explicit default arm so a new failure mode degrades to "unknown" rather
than to "denied". Only `ErrDenied` may ever be shown to a user as a permissions
answer. Both outcomes refuse the connection — failing closed and failing
silently are not the same thing.

`ErrMethodNotSupported` is a routing condition inside the registry (a
certificate authenticator asked for a password), never an outcome the user sees.

### MFA: the polling loop and how the user hears about it

`PasswordMFAAuthenticator.AuthenticatePassword` relays the password, and on
`mfa_required` runs the wait itself (not the SSH layer — the pacing and expiry
belong to the decision, not the transport):

1. Show `MFAChallenge.Prompt` once, via the context's `MFAPrompter`.
2. Sleep `max(challenge.PollAfter(), MinPollInterval)`, then `PollMFA`.
3. Re-read pacing from each response; emit a "still waiting (Ns)" line at most
   every `ProgressInterval`.
4. Stop at the earliest of `challenge.ExpiresAt`, `MaxWait`, and `ctx`.

**The prompter travels in the context** (`WithMFAPrompter`), because the PLAN
§4.1 signature is fixed and `ConnMeta` is connection *data* that gets converted
to the wire, whereas the prompter is a live callback into an open
keyboard-interactive exchange whose lifetime must not exceed that callback. A
missing prompter is normal (certificate flow, tests) and silently no-ops.

**An unapproved challenge is `ErrDenied`, not a timeout error.** A user who
never approves gets the same generic "access denied" as a wrong password. It is
also why the MFA wait must never be cached (PLAN §6.4): the approval is a
per-session assertion.

A prompter error (the client hung up) is `ErrUnavailable` — nobody was left to
approve, and no server decision was made.

### Registry, ordering, and config

`Registry` presents an ordered set as one `UserAuthenticator`. Within a flow it
skips `ErrMethodNotSupported`, returns the first success, and otherwise applies
**"unavailable beats denied"**: if any authenticator could not reach a decision,
the failure is an outage. That is what stops an estate-wide management-server
outage from being reported to every user as "access denied".

`NewFromConfig(config.UserAuth, Options)` is the factory. `auth.user.methods` is
a **set**; the ordering (certificate first, password+MFA second) is imposed by
this function, not by the file — a deployment that listed password first would
prompt every user for a password before looking at the key their client already
offered. An empty list is rejected at config validation; an absent key defaults
to both.

Method names have exactly one source of truth: `identity.MethodCert` /
`identity.MethodPasswordMFA`, re-exported as `user.MethodCert` /
`user.MethodPasswordMFA` and validated in `config.validateAuth`. This is why
`internal/config` imports `internal/identity`.

`FlowSupport` (optional interface, `SupportsCert`/`SupportsPassword`) is how the
SSH layer knows which methods to advertise. An authenticator that does not
implement it is assumed to do both: offering an unsupported method costs a
wasted round trip, withholding a supported one locks people out.

### The SSH adapter (what 0005 wires up)

```go
sa, err := user.NewServerAuth(user.ServerAuthOptions{
    Authenticator: registry,             // required
    ConnMeta:      myConnMetaFunc,       // required — see below
    BaseContext:   listenerCtx,          // callbacks get no ctx from x/crypto
    Banner:        nil,                  // nil = user.BannerMessage(sessionID)
})
sa.Apply(serverConfig)                   // installs Banner/PublicKey/KeyboardInteractive
// after the handshake:
id, err := user.IdentityFromPermissions(serverConn.Permissions)
sid := user.SessionIDFromPermissions(serverConn.Permissions)
```

- **`ConnMetaFunc` is deliberately the caller's.** Splitting `alice#host` into
  login + target is routing's job (D1); this phase must not grow a second
  implementation of it. `user.ConnMetaFromSSH(base, conn)` fills only the
  transport fields (addresses, client version) and never touches Login/Target.
- **Identity crosses into the connection through `ssh.Permissions.Extensions`**
  (`hoplock-identity` as JSON, plus `-auth-method` and
  `-session-id`). Extensions are server-side only — x/crypto never sends them to
  the client — and this avoids a side table that would need its own lifecycle.
- `Apply` forces `NoClientAuth = false` and installs only the callbacks the
  authenticator supports.
- Per-connection cancellation is not wireable here: x/crypto gives auth
  callbacks no context. `BaseContext` is the listener's, and bounding an
  individual connection is 0005's to solve if it needs to.

### What the user is told (PLAN §4.3), and where it lives

`internal/auth/user/feedback.go` is the single implementation of the rule:

| Case | API | Text |
| --- | --- | --- |
| Before auth | `BannerMessage(sessionID)` | "checking your access with the policy service", + session id |
| Deny | `DenyMessage` | `"Access denied."` — names neither login, target, nor which was wrong |
| Anything else | `OutageMessage(sessionID)` | says explicitly it is **not a permissions problem**, quotes the session id |
| Either | `FailureMessage(err, sessionID)` | picks the branch via `IsDenied(err)` |

`IsDenied` accepts a raw `control` error as well as this package's sentinels, so a
caller cannot get the disclosure wrong by forgetting to translate first.
`FailureMessage(nil, ...)` renders the **outage** text: "I do not know why this
failed" is never safely rendered as "you are not allowed".

The text reaches the client as `*ssh.BannerError` returned from the auth
callback — that is what makes x/crypto emit `SSH_MSG_USERAUTH_BANNER` before the
failure. A rejected key therefore also produces the generic deny line before the
client falls back to keyboard-interactive; that repetition is accepted, because
the alternative (silence on a certificate-only proxy) is the thing PLAN §4.3
exists to prevent.

**0005 must reuse `FailureMessage`** for post-auth failures (session stderr,
disconnect reason) rather than writing its own strings, or the two branches will
converge by accident. The same applies to the `SessionRegistry.Kill*` reason
text from 0003.

### Redaction (PLAN §7)

The password exists in exactly one place: the argument passed straight into
`control.AuthenticatePasswordRequest` (which redacts itself when formatted). It is
never logged, never wrapped into an error, never handed to a prompter.
`TestPasswordNeverReachesLogsOrErrors` runs the whole flow to a deny with
logging on, first asserts the password **was** on the wire (so the assertion is
not vacuous), then searches the log buffer, the returned error, every
user-visible message, and `FailureMessage`'s output for it.

### Test notes

- Tests drive a per-test `httptest` server **through the real
  `control.RESTClient`**, so contract + client + authenticator are exercised
  together; `fakeClient` covers what HTTP cannot express (dead transport,
  cancelled context).
- `TestHandshake*` run a **real SSH handshake** over a loopback socket. Use
  `loopbackPair`, not `net.Pipe`: net.Pipe is unbuffered and synchronous, and
  the SSH transport deadlocks on it (x/crypto's own handshake tests do the
  same).
- The handshake tests are what prove the acceptance criteria that cannot be
  observed from the functions alone: the fallback from a rejected key to
  keyboard-interactive, the server's MFA prompt arriving in the `instruction`
  field, "still waiting" pings during the wait, and the pre-auth banner.

### Follow-ups (not done here, not blocking)

- **No new prompts were added**; numbering invariants (PROTOCOL §6) hold —
  0004 moved to `implemented/`, 0005–0011 remain queued.
- `cmd/proxy` still ignores `-config`. The real startup path (load config →
  build `control` client → build registry → listen) belongs with the listener in
  **0005**. The proxy→server bearer token still has no config field (noted in
  0002's learnings); whichever phase constructs the real `control.RESTClient` must
  add it to `internal/config` *and* `config.example.yaml` together, because the
  decoder is strict.
- `Options.Logger` is a `*log.Logger` stop-gap. When `internal/logging` lands
  (0010), auth events should become structured `control.LogRecord`s
  (`LogKindAuth`) — the call sites already log only redaction-safe fields.
- Certificate *contents* (principals, validity, CA) are never inspected locally,
  by design (D2). If a later phase wants local pre-validation, it needs a plan
  decision first: two policies that can disagree is worse than one round trip.

### Deviations

- Branch name is `claude/queued-prompt-implementation-5aimx4` rather than
  PROTOCOL §2's `claude/NNNN-short-description`, because the session was started
  with that branch pre-assigned (same as 0001–0003). Nothing else in §2 changed.
- `go.mod` now reads `go 1.24.0` with `toolchain go1.24.7` (added by `go mod
  tidy` because `golang.org/x/crypto v0.44.0` requires ≥ 1.24.0). CI's
  `GO_VERSION: "1.24"` resolves to a newer 1.24.x, so nothing is downloaded.
