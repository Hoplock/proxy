# 0007 — Target credentials — Learnings

## Summary
- What shipped: both production proxy→target credential methods behind the 0005
  seam. `ephemeral-user` (D6) provisions a short-lived OS account + key over a
  management-certificate login and removes it, with an orphan reaper for the
  sessions whose proxy died; `brokered-key` (D6a) holds a session-scoped
  credential in memory for devices the proxy cannot administer. A `Selector`
  dispatches per route on 0006's `target_auth`; `static-key` stays as the dev
  placeholder. No contract change.
- Key packages/files: `internal/auth/target/{ephemeral,reaper,script,principal,
  admin,params,brokered,credentials,selector,registry}.go` (+ tests, incl.
  `fakehost_test.go` and `sshd_test.go`), `internal/config/config.go`,
  `config.example.yaml`, `internal/proxy/session.go` (one call site),
  `internal/sshtest/target.go` (`Keys()`), `deploy/sshd/`, `Makefile`
  (`test-sshd`), `docs/PLAN.md` §5.1/§5.2.
- Key types: `EphemeralAuthenticator`, `BrokeredKeyAuthenticator`, `Selector`,
  `Reaper`, `Lifecycle`, `AdminDialer`/`AdminSession`/`NewSSHAdminDialer`,
  **`CredentialSource`** + `CredentialRequest`/`Credential` +
  `DirCredentialSource`/`EnvCredentialSource`, `RemoteCommandError`. Sentinels
  `ErrMethodUnavailable`, `ErrUnknownParam`, `ErrInvalidParam`,
  `ErrNoCredential`, `ErrInvalidPrincipal`, `ErrInvalidScriptValue`.
  `target.Target` gained `Auth *control.TargetAuth` and `HostKeyCallback`.
- **Teardown guarantees:** `ProvisionedAccess.Close` runs `Teardown` exactly once
  (0005's `sync.Once`) from `session.close`, which runs on normal close, error,
  kill, panic, and signal. The teardown script is idempotent **and verifies** —
  it exits 91/92 if the account or its home survives — and it re-dials with the
  host key **pinned** from provisioning, so it never depends on Hoplock Control
  being reachable. A failed teardown still releases the account from the live
  set, which converts it into an orphan the reaper retries.
- **Orphan reaper / naming convention:** accounts are
  `hl-<4-hex proxy tag>-<login≤14>-<8-hex token>` (≤32 chars). The reaper lists
  them off the target (`getent passwd`), ages them by the target's own clock,
  and removes any that are **not tracked live** and **older than
  `reaper.grace`** (default 30m). Sweeps run after each provisioning on that
  target (rate-limited, background — the only way a crashed *process*'s orphans
  are found) and on `reaper.interval` (default 10m) over targets seen this
  lifetime. The proxy tag stops two proxies reaping each other's live sessions.
- **Concurrency:** unique principals, not coordination — the token makes two
  sessions for one login on one target independent, so neither teardown can
  touch the other's account. Same for a server-supplied `username`.
- Decisions made/affected: D6, D6a (both implemented), D2 (method is never
  proxy-chosen), D7 (provisioner borrows the session's host-key callback, pins
  it afterwards). PLAN §5.1/§5.2 gained an "As built" note each; no decision
  changed.
- Gotchas: **a lifetime the proxy cannot enforce is refused**
  (`key_expiry: false` + a route's `lifetime_seconds` ⇒ outage), unknown
  `params` are refused, and there is **never** a fallback to another method.
  `session.setup`'s call site changed by one struct literal (the prompt hoped
  for zero) because the route's method and the host-key policy both have to
  reach the provisioner.
- What the NEXT session must know: the credential plane is now a `*Selector`,
  not a single authenticator; it implements `target.Lifecycle` and `cmd/proxy`
  starts/stops it. 0012 must give targets a **privileged provisioning account
  reachable with the management certificate** (`deploy/sshd` does: root) and,
  for brokered routes, an **account that already exists** (`netadmin`) — see
  "For phase 0012" below.

## Details

### The shape of the plane after this phase

`target.NewFromConfig` no longer returns "the" authenticator. It builds every
method this proxy has **local material** for and wraps them in a `Selector`:

```go
Selector.Provision → resolve(route.TargetAuth) → the named method
```

- absent `target_auth`, or `method: ""` ⇒ `auth.target.method` (the fallback);
- a method this build lacks ⇒ `ErrUnknownMethod`;
- a method with no local material ⇒ `ErrMethodUnavailable`.

Both errors reach the user as an **outage** naming the session id
(`stageProvision` → "credentials for the target could not be provisioned"), and
neither is ever a fallback to another method — serving a route with credentials
the server did not choose is the one thing this type exists to prevent. The
fallback method must be constructible at startup, so a misconfigured proxy fails
to start rather than at its first connection.

`config.TargetAuth` therefore validates **every method the operator wrote
anything about**, not just the fallback: since contract v2 a proxy is normally
configured for methods it does not default to.

### ephemeral-user: how it works on the target

Three POSIX `/bin/sh` scripts, run over one management login, built in
`script.go` and quoted through `shellQuote` after every interpolated value has
been validated (`validatePrincipal`, `validatePath`, `validateScriptValue`):

1. **provision** — `id -u` guard, `useradd -m -d <home> -s <shell>`, `mkdir`,
   truncating write of `authorized_keys`, `chmod 700/600`, `chown`. Idempotent
   over a leftover account, and the truncating write is deliberate: a leftover
   account must end up holding *this* session's key and nothing else.
2. **teardown** — `pkill -KILL -u`, `userdel -r` (with a bare `userdel`
   fallback), `rm -rf <home>`, then **verify** both are gone.
3. **discover** — the target's clock on line 1, then `name<TAB>mtime<TAB>home`
   per account matching this proxy's prefix, read from `getent passwd` (not from
   `/home`, so a half-created account with no home is still found — it reports
   age 0, which reads as "old" and gets it removed).

The scripts are handed to `auth.target.ephemeral_user.shell`, default `sh -c`.
A non-root provisioning account sets it to `sudo -n sh -c`, which runs the whole
script — redirects included — inside one privileged shell.

`lifetime_seconds` becomes OpenSSH's `expiry-time="…Z"` option on the
`authorized_keys` line: enforcement lives on the target, not in this process's
memory. `key_expiry: false` is for fleets whose sshd predates 8.2, and a route
that asks for a lifetime on such a proxy is refused.

### Host keys, and why teardown pins

`Target.HostKeyCallback` carries the session's TOFU-and-report callback (D7)
into the provisioner's own management login, so host trust stays one decision in
one place. But that callback calls Hoplock Control and **fails closed**, and the
session's context is already cancelled when teardown runs — so teardown and
every sweep re-dial with `ssh.FixedHostKey` set to the key the provisioning
login already saw. Removing an account must not depend on a *different*
component being up.

### brokered-key: the seam Control implements

`CredentialSource` is the interface a future credential-minting Hoplock Control
implements (PLAN §5.2 names it now):

```go
type CredentialSource interface {
    Name() string
    Credential(ctx context.Context, req CredentialRequest) (*Credential, error)
}
type CredentialRequest struct{ Target Target; Ref, Username, Subject string }
type Credential struct{ PrivateKey, Passphrase, Password []byte } // Zero()
```

Local implementations: `DirCredentialSource` (`<dir>/<ref><suffix>`) and
`EnvCredentialSource` (`<prefix><REF>`), both keyed by the route's
`credential_ref` and falling back to the target host, both read **on demand and
never cached** — material this process is not using is material it should not be
holding. References are validated before they become a path or a variable name.

Material handling: a private key's PEM is zeroed the moment it parses; a
password is held (there is no parsed form) and zeroed by teardown, which is
`sync.Once`-guarded. Nothing logs, echoes, or writes material — the log line
carries the *reference* and the source name, which is what makes a session
traceable to the credential it used without disclosing it.

### Tests, and what each one is for

- `fakehost_test.go` builds a **real POSIX host in a temp directory**: /bin/sh
  runs the actual scripts, with `useradd`/`userdel`/`id`/`getent`/`pkill`/`chown`
  replaced by shell scripts over a text `passwd` file, faithful down to exit
  statuses (9 = exists, 6 = no such user). The SSH leg is real too
  (`internal/sshtest` + the production `sshAdminDialer`). Stubbing
  `AdminSession.Run` instead would only assert that this package sends the
  strings it sends.
- Covered: create → login as the account with the installed key → teardown
  removes it; teardown idempotent and verifying; provisioning failure **after**
  `useradd` leaves nothing; four concurrent sessions for one login get four
  accounts and four clean teardowns; a crashed process's account is reaped by a
  fresh authenticator; live and young accounts are never swept; another proxy's
  accounts are never swept; a leftover account's key is replaced not appended;
  parameter refusals; brokered leaves the target byte-identical; the credential
  appears in no log, error, or on-disk artifact; the selector's dispatch and its
  two refusals; and, in `internal/proxy`, a route naming an unimplemented method
  is an outage with the session id **and nothing is provisioned**, plus a whole
  brokered session whose credential never reaches the proxy's log.
- `sshd_test.go` is the same lifecycle against a **real sshd**
  (`deploy/sshd`, `make test-sshd`). It is deliberately not behind a build tag —
  it skips unless `HOPLOCK_TEST_SSHD_ADDR` is set — because a test excluded from
  the build stops compiling without anyone noticing. **It was written but not
  executed in the session that wrote it: that environment had a docker CLI but
  no daemon.** Running it is the first thing to do when touching this package.

### For phase 0012 (target-side prerequisites)

`deploy/sshd` is the minimal version of what the e2e topology owes a target:

| Prerequisite | For | In `deploy/sshd` |
| --- | --- | --- |
| privileged provisioning account reachable with the management certificate | `ephemeral-user` | `root`, management key in `authorized_keys` |
| an account that already exists, with no provisioning rights | `brokered-key` | `netadmin` + its own key |
| `useradd`/`userdel`/`pkill`/`getent`/`stat` on the target | `ephemeral-user` | stock `debian:stable-slim` |

Keys are generated per run into `deploy/sshd/keys/` (gitignored). The proxy
config needs `auth.target.ephemeral_user.{management_key_path,provisioning_user}`
and, for brokered routes, `auth.target.brokered_key.{source,dir}` — and the mock
Control's `routes[].target_auth` decides which route uses which.

### Follow-ups (not done here, deliberately)

- **Reaping targets a restarted proxy has not touched again.** Orphans are found
  the next time the proxy provisions on that target, or on the periodic tick for
  targets seen since startup. A proxy that restarts and is never asked for that
  target again leaves the account until it is. Fixing it properly means a
  durable list of targets (or asking Hoplock Control for one), which is a
  contract question rather than a code one.
- **The management login is opened per operation** (provision, teardown, each
  sweep). Correct and simple; a pooled connection would cut a round trip off
  session setup if profiling ever says it matters.
- **Confining the ephemeral account itself** — queued as **0015** (survey +
  contract) and **0016** (implementation; renumbered from 0013/0014 by the
  privileged-access revision, PLAN §10). The provisioner writes the account's
  `authorized_keys`, chooses its shell, and owns its home, so it can bound what
  that account may execute at the OS rather than at the proxy: the only
  enforcement point in the system that survives an interactive shell, and the
  only one that holds for a connection that bypasses the proxy entirely. Nothing
  in this phase was built to preclude it — `authorizedKeyLine` is already the
  single place options are written, and the teardown script already verifies
  rather than assumes.
- **Ephemeral certificates.** D6 says "keypair/cert"; this ships a keypair plus
  `expiry-time`. A short-lived certificate signed by a CA the fleet already
  trusts would remove the `authorized_keys` write entirely — a natural follow-up
  once management certificates are deployed as certificates.
