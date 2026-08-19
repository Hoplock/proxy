# 0005 — Core proxy engine & direct route — Learnings

## Summary
- What shipped: the first working end-to-end proxy. `internal/routing` (D1
  username split + authorize/route), `internal/proxy` (the SSH engine: generic
  channel passthrough, session lifecycle, TOFU host keys, user-facing failure
  reporting, `control.SessionRegistry`), `internal/auth/target` (interface +
  `static-key` **placeholder**), `internal/sshtest` (in-process target for
  tests), and a real `cmd/proxy` that listens.
- Key packages/files: `internal/routing/{username,resolve}.go`,
  `internal/proxy/{proxy,session,channel,feedback,hostkey,registry}.go`,
  `internal/auth/target/{auth,statickey,registry}.go`,
  `internal/sshtest/{target,keys}.go`, `cmd/proxy/main.go`,
  `internal/config/config.go` (+ `config.example.yaml`),
  `internal/auth/user/feedback.go` (one new function).
- Key types: `routing.ParseUsername`/`NormalizeTarget`, `routing.Route`
  (`RequireDirect`, `ChannelPermitted`, `Addr`), `routing.Resolver`;
  `target.TargetAuthenticator`/`Target`/`ProvisionedAccess` (with `Close`),
  `target.StaticKeyAuthenticator`, `target.NewFromConfig`; `proxy.Server`
  (`Serve` + `KillSession`/`KillSubject`/`KillAll`/`Sessions`), `proxy.Options`;
  `user.FailureMessageFor`/`OutageMessageFor`/`OutageDetailPolicyService`.
- New config keys (decoder is strict — struct and example move together):
  `proxy.id` (**required**), `management.token`,
  `management.cache.{max_ttl,stale_after}`, `auth.target.method` +
  `auth.target.static_key.{key_path,username}`,
  `proxy.{dial_timeout,default_target_port}`.
- **Seams for the next phases:** 0006 replaces `static-key` by implementing
  `target.TargetAuthenticator` and adding a `case` to `target.NewFromConfig` —
  nothing in the proxy changes. 0007 replaces `session.setup`'s
  `route.RequireDirect()` call with a dispatch on `route.Type`; `Resolve`
  already returns next-hop routes intact, hop metadata included.
- **Ordering rule, load-bearing:** the client's session channel is accepted
  *before* authorize/provision/dial, and a failure is reported only once the
  client has sent `shell`/`exec`/`subsystem`. Both halves are required for the
  user to actually see anything (details below).
- Decisions affected: D1, D2, D5, D7, PLAN §4.3 (amended — x/crypto has no
  `SSH_MSG_DISCONNECT`), §3 (tree gained `internal/sshtest`). No other plan
  change.

## Details

### The username split (`internal/routing`)

`ParseUsername(username, delimiter) (login, target, error)` is pure and is
called twice per connection — once in the SSH auth callbacks (so the login
presented for authentication is the login, not "login+target") and once in the
engine after the handshake. Passing a parse result between them would have meant
state keyed on a connection that x/crypto gives no handle for; re-parsing is
cheaper than that bookkeeping.

It rejects two delimiters as hard as zero: splitting `alice#a#b` requires
guessing, and a wrong guess connects the user to a host they did not ask for.
`NormalizeTarget` lowercases and drops the root dot so one host is one string in
policy and audit, and validates RFC 1123 labels — the target reaches a dial, a
policy request, and a log line, so whitespace or control characters in it are a
log-forging primitive, not a cosmetic problem.

`Resolve` wraps the management client's error **unchanged** (`fmt.Errorf
("authorize: %w", err)`), so `control.IsUnauthorized` still classifies a deny after
the wrap. Everything the user is told depends on that classification surviving;
a `routing.ErrDenied` of its own would have been a second, drifting copy.

### The engine (`internal/proxy`)

One `session` per client connection. Its shape:

- `run` starts `setup` (authorize → provision → dial), a global-request pump,
  and one goroutine per client channel, then blocks on the channel stream.
- `setup` writes `route`, `setupErr`, and the leg **before** closing `ready`,
  and everything else reads them only after `<-ready`. That is the whole
  synchronisation story for those fields; `identity`, `leg`, and the open-channel
  set are mutex-guarded instead because the revocation stream touches them on its
  own goroutine at any time.
- `close` (deferred in `run`) cancels, closes both legs, waits for `ready`, and
  runs teardown. Waiting for `ready` is what stops teardown racing the
  provisioning it undoes when a client hangs up mid-dial.

**Channel pumping** (`channel.go`). Both directions of channel opens are
forwarded (the target opens `forwarded-tcpip`, `x11`, `auth-agent`), and the
allow-list applies in both. Per channel: four copies (stdout and stderr, each
way) and a request pump each way. Two things are not naive relays:

- `exit-status`/`exit-signal` from the target are **captured, not forwarded**,
  and replayed once the target's output has drained, so a client cannot see
  "finished" before the bytes the program produced. A five-second grace stops a
  server that never closes from pinning the channel.
- Requests arriving before the target leg exists are **queued and replayed in
  order**, with their replies deferred. The client is waiting anyway; what it
  must not get is a `pty-req` refused because the far side was not up yet. A test
  asserts the pty and env really reach the target.

**Channel allow-list.** `Route.ChannelPermitted` is exact-match and an empty list
denies everything (a truncated response must not read as "allow all"). Non-session
channels are refused at open with `ssh.Prohibited` + the generic denial. A
session channel cannot be refused that way — it was accepted before the policy
was known — so it is refused with an explanation on stderr and a non-zero exit.
That is enforcement either way and strictly more informative.

### What the user is told, and the two ordering rules

`user.FailureMessageFor(err, detail, sessionID)` is reused, not re-implemented
(0004's instruction). The only thing this phase adds is `detail`: "the policy
service is unavailable" is a lie when the target is down, and a user told the
wrong thing raises the wrong ticket, which is exactly what PLAN §4.3 exists to
prevent. `setupError{stage, err}` tags the failure and `outageDetail` maps stage
→ phrase. A deny renders as `user.DenyMessage` whatever the stage, so no caller
can make one denial more informative than another.

Two ordering rules, both discovered by tests failing:

1. **Accept the session channel before the target leg exists** (PLAN §4.3, known
   going in) — otherwise there is nowhere to write.
2. **Report the failure only after the client has asked for something.** An SSH
   client starts reading a channel after it sends `shell`/`exec`; a message
   written before that goes into a stream nobody reads. The first version failed
   as soon as authorize failed, and the client saw an empty stderr and `EOF`.
   The engine now holds the failure until the start request arrives (or a 3s
   grace expires).

**`SSH_MSG_DISCONNECT` is not available.** `golang.org/x/crypto/ssh` does not
expose it — `ssh.Conn` has only `Close`, and sending a disconnect is on the
library's own TODO list. The prompt asked for it; PLAN §4.3 now records the gap
and the substitute: the ordering above means the explanation goes over the
session channel, anything opened after a failure is **rejected with the reason**
in the rejection message (which OpenSSH prints), and `session.disconnect`
duck-types `interface{ Disconnect(uint32, string) error }` so the engine picks it
up for free if x/crypto ever exports it. Only a client that opens no channel at
all (`ssh -N`) gets an unexplained close.

### Host keys (D7)

Every connection reports the target's key to Hoplock Control and obeys the
answer; the proxy keeps no known-hosts file, because a local trust store is a
second policy diverging per proxy. A report failure is **fail-closed** — an
unverifiable host key is what a man-in-the-middle looks like. The refusal reason
is stashed on the session (`hostKeyErr`) rather than parsed back out of
x/crypto's handshake error, so classification does not depend on another
library's error formatting.

### SessionRegistry (the 0003 hand-off)

`proxy.Server` implements it. `KillSubject` matches on `Identity.Subject`, never
`Login` — the login is what the user typed. A kill writes the operator's reason
to every open channel, sends a non-zero exit status, and closes; a kill for an
unknown session returns nil, because the server broadcasts to a fleet and does
not know which proxy holds which session. `Serve` also calls `KillAll` on
shutdown: a proxy going away owes users the same explanation a revocation does.

### The target plane (`internal/auth/target`) — placeholder warning

`static-key` logs into every target with one preloaded key and tears nothing
down. It exists only so the engine could be built and tested before 0006. Two
properties of the interface are already real and 0006 must keep them:

- `ProvisionedAccess.Close` wraps `Teardown` in a `sync.Once`, so idempotent
  teardown is a property of the type rather than a rule each implementation
  re-implements.
- `Provision` must leave `HostKeyCallback` **nil**. Host trust is the proxy's
  (D7); x/crypto refuses to dial without a callback, so forgetting to set one
  fails closed rather than trusting anything.

`config.TargetAuthMethodStaticKey` lives in `internal/config` (like the user
methods in `internal/identity`) so config validation and the authenticator
cannot spell the name differently.

### Testing

- `internal/sshtest` is a real in-process SSH server standing in for a target:
  pty/env/exec/shell, exit statuses, and an echo channel for non-session types.
  It is a package, not a helper, because two test packages need it — and 0011's
  containerised sshd replaces it for scenario testing, not for these.
- `internal/proxy` tests drive a **real SSH client** through a real proxy into
  it, with a fake `control.Client` so each decision is a field: exec, shell+pty,
  exit status, deny vs outage text, target-unreachable, host-key report and
  rejection, allow-list both directions, next-hop refusal, malformed username,
  kills, and a goroutine-count check for leaks.
- `cmd/mock-control/proxy_e2e_test.go` is the acceptance test: the same
  engine against the **real contract over HTTP**, with fixtures built in-test
  (the shipped fixture fingerprints cannot match a generated key). Follow that
  pattern for 0006/0007 end-to-end tests — the mock is a `main` package and can
  only be used from inside it.
- Every test key is generated (`sshtest.GenerateKeyPair`). No private key,
  however labelled, belongs in the repository.

### Follow-ups (not done here, not blocking)

- **No new prompts**; numbering invariants hold — 0005 moved to `implemented/`,
  0006–0011 remain queued.
- `cmd/proxy` now wires `CachingClient` + `RevocationStream` + the proxy, which
  closes 0003's follow-up. The bearer token finally has a config field
  (`management.token`).
- Logging is still `*log.Logger` lines. 0010 turns the session start/end,
  channel, host-key, and kill events into `control.LogRecord`s; the call sites
  already log only redaction-safe fields.
- `serveGlobalRequests` blocks the first global request until the leg is up
  rather than refusing it. That is right for `tcpip-forward` and harmless for
  keepalives, but if a client ever sends a global request it needs answered
  during setup, this is the place.
- The engine enforces the channel allow-list directly. 0008 should move that
  behind `internal/channel`'s pipeline without changing where the answer comes
  from (`Route.PermittedChannels`).
