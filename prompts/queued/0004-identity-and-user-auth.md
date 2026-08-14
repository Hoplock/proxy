# 0004 — Identity model & user→bastion authentication

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — especially §2 (D4), §4.1 (user→bastion interface), §7
  (redaction).
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

## Out of scope
- Target-side auth (0006). Proxying/channels (0005). Real AD/Okta backends.

## Acceptance criteria
- `UserAuthenticator` interface + both implementations compile and are unit-
  tested against the mock management server (`httptest` or `cmd/mock-management`).
- Tests cover: cert accepted → Identity; cert rejected → fall back to password;
  password+MFA accepted → Identity; password+MFA rejected → auth failure.
- A test asserts the initial-auth password never appears in emitted logs.
- Identity/claims shape is documented well enough for routing/policy phases.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move this prompt to `implemented/`; add
`docs/learnings/0004-identity-and-user-auth-learnings.md`. Summary block MUST
give the exact `Identity`/`Claims` type shapes, the `UserAuthenticator`
signature, the factory/config keys, and how the proxy phase should invoke auth.
