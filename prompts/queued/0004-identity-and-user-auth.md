# 0004 — Identity model & user→bastion authentication

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — especially §2 (D4), §4.1 (user→bastion interface), §4.3
  (what the user is told), §7 (redaction).
- `docs/learnings/` — read summaries; open `0002` learnings (mgmt client +
  auth endpoints) and `0001` learnings (config).

## Objective
Define the AD/Okta-ready **identity/claims model** and implement the
**user→bastion** authentication plane as a pluggable interface with two
implementations (certificate-first, password+MFA fallback), delegating decisions
to the management server.

## In scope
- `internal/identity`: `Identity` (subject/username, principals, groups, claims
  map, source method) and any supporting types. This is the seam that lets AD/
  Okta/OIDC be added later without changing callers — design accordingly (D4).
- `internal/auth/user`: the `UserAuthenticator` interface from PLAN §4.1, plus:
  - `cert` authenticator: validates the client-offered public key/cert by calling
    the management server's **authenticate (cert)** endpoint; returns `Identity`.
  - `password-mfa` authenticator: calls the **authenticate (password + MFA)**
    endpoint; returns `Identity`. **Never log the password** (D7/redaction).
  - A registry/factory that selects enabled authenticators from config, with
    **certificate-first, password+MFA fallback** ordering (per user answers).
- Wire these into the SSH server auth callbacks in a small, testable way
  (`ssh.ServerConfig` `PublicKeyCallback` / keyboard-interactive), but **do not**
  build the full proxy yet — expose functions the proxy phase (0005) will call.
- Config additions (in `internal/config`) to enable/disable methods.
- **User-facing feedback during auth (PLAN §4.3).** A failed setup must never be
  a silent disconnect:
  - Use `ssh.ServerConfig.BannerCallback` to tell the user what is happening
    while the bastion talks to the management server.
  - **Run the password+MFA flow over keyboard-interactive, not plain password
    auth**: it is the only flow with an `instruction` field, which is where the
    server's `MFAChallenge.Prompt` ("approve on your phone") is shown. While
    polling, send zero-prompt info requests as "still waiting" pings so a slow
    approval does not look like a hang. Respect the challenge's
    `PollAfter()` between polls, and stop at `ExpiresAt`.
  - Apply the disclosure split when auth fails: a deny (`mgmt.IsUnauthorized`)
    produces only a generic "access denied", while any other error
    (`ErrTransport`, `ErrServer`, `ErrProtocol`) says plainly that this is an
    outage rather than a permissions problem and quotes the session id as a
    support reference. **The two must not be collapsed into one message.**

## Out of scope
- Target-side auth (0006). Proxying/channels (0005). Real AD/Okta backends.

## Acceptance criteria
- `UserAuthenticator` interface + both implementations compile and are unit-
  tested against the mock management server (`httptest` or `cmd/mock-management`).
- Tests cover: cert accepted → Identity; cert rejected → fall back to password;
  password+MFA accepted → Identity; password+MFA rejected → auth failure.
- A test asserts the initial-auth password never appears in emitted logs.
- Tests cover the disclosure split (PLAN §4.3): a deny yields a generic message
  that names neither the login nor the target, while a management-server outage
  yields a distinct message that says it is not a permissions problem and
  carries the session id. Assert on the actual text handed to the SSH layer.
- A test drives the MFA path over keyboard-interactive and asserts the server's
  prompt reaches the `instruction` field and that waiting emits progress rather
  than silence.
- Identity/claims shape is documented well enough for routing/policy phases.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move this prompt to `implemented/`; add
`docs/learnings/0004-identity-and-user-auth-learnings.md`. Summary block MUST
give the exact `Identity`/`Claims` type shapes, the `UserAuthenticator`
signature, the factory/config keys, and how the proxy phase should invoke auth.
