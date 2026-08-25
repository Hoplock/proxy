# 0012 — Full end-to-end topology & CI gate — Learnings

## Summary
- What shipped: the prototype's acceptance gate. `deploy/` is a `docker compose`
  topology of the whole system on networks that make its segmentation claims
  checkable; `test/e2e` drives it with a **real OpenSSH client** and asserts on
  what that client was actually told; two new CI jobs (`e2e`, `govulncheck`) gate
  every PR. No production code changed — nothing in `internal/`, `cmd/`, or
  `api/` was touched.
- Key packages/files: `deploy/{compose.yaml,gen-material.sh,README.md}`,
  `deploy/{control,proxy,target,user}/*`, `test/e2e/{harness,scenarios}_test.go`
  (build tag `e2e`), `test/topology/config_test.go` (no tag, runs in
  `go test ./...`), `.github/workflows/ci.yml`, `Makefile` (`e2e`, `e2e-up`,
  `e2e-down`, `e2e-build`, `vulncheck`; `test-sshd` rewritten),
  `.golangci.yml` (`run.build-tags: [e2e]`), `docs/PLAN.md` §8 + §9, `README.md`.
  `deploy/sshd/` is gone — folded into `deploy/target/`.
- **Run it:** `make e2e` (up, suite, down). `make e2e-up` leaves it running and
  `go test -tags e2e -count=1 -v -run 'TestTopology/routing' ./test/e2e/`
  re-runs a slice against it; `make e2e-down` cleans up. Needs Docker, Go and
  `ssh-keygen`. `deploy/README.md` is the operator's guide.
- **Six containers, five node roles** — a deliberate deviation from PLAN §9's
  table, and §9 now says so. `dial` needs a downstream that accepts an inbound
  connection; the entire point of `relay` is a downstream that accepts none. One
  container cannot demonstrate both, and a relay scenario run against a proxy
  that does listen proves nothing.
- Decisions affected: none changed. D5a, D6/D6a, D8, D11, D12 and §4.3 all now
  have end-to-end evidence rather than unit-test evidence.
- Gotchas: the target image must keep **`UsePAM yes`** (or every
  `ephemeral-user` session fails) and **`PerSourcePenalties no`** (or sshd blocks
  the proxy after a handful of refused sessions — see below, it is a real
  operational finding, not a test artefact); the fixtures are **rendered**, not
  committed; `govulncheck` needs `vuln.go.dev` and is deliberately **not** in the
  Definition of Done.
- What the NEXT session must know: a phase that changes routing, policy, or
  credentials owes a scenario here. Add the route to
  `deploy/control/fixtures.template.yaml` (each route names the scenarios it
  backs) and a subtest to `TestTopology` — its subtests are **ordered on
  purpose**, and the outage one must stay second-to-last.

## Details

### The topology, and why the networks are the test

| Service | Role | Networks |
| --- | --- | --- |
| `control` | mock Hoplock Control | edge, core |
| `user` | the OpenSSH client | edge |
| `proxy-direct` | edge proxy that reaches the target itself; far end of the `dial` chain | edge, core |
| `proxy-nexthop` | edge proxy that reaches the target only by chaining; the relay hub | edge, relay |
| `proxy-zone` | proxy in a protected zone; no inbound listener | core, relay |
| `target` | real `sshd` | core |

The claims are structural, not asserted by convention:

- **the user node is not on `core`**, so "the target is reachable only through a
  proxy" is a property of the topology. The first scenario checks that the user
  node can resolve a proxy and cannot resolve the target — the control case
  matters, or the check would pass on a broken resolver;
- **`proxy-nexthop` is not on `core` either**, so a chained session that reached
  the target cannot have been served locally;
- **`proxy-zone` binds its SSH listener to loopback inside its own container**,
  publishes no port, and the route that reaches it names
  `proxy-zone.no-inbound.invalid`. A relayed session that arrives has provably
  travelled over the registration `proxy-zone` opened outbound. The loopback
  bind is asserted twice — in `test/topology` (so a config change that published
  it fails fast) and by the scenario that shows the zone proxy is unresolvable
  from where users are.

`core` and `relay` are `internal`. `edge` is not, because `control` publishes
`127.0.0.1:18080` for the scenario driver's `/debug/logs` reads. Nothing inside
the topology reaches Hoplock Control that way.

### Where the scenarios run, and where they are driven from

Every SSH invocation runs **inside the `user` container**; the driver runs on
the host. That split is what allows the outage scenario to stop a node, and it
keeps the client on a network with no route to the target.

The client is **OpenSSH, not a Go SSH library**. The acceptance criteria are
about what a person at a terminal is told (PLAN §4.3), so banners, channel
rejection reasons and exit statuses are asserted as a real client renders them.
Three consequences that cost time to discover:

- **Do not lower `LogLevel`.** OpenSSH prints a server's `USERAUTH_BANNER` only
  at `INFO` or above. `-o LogLevel=ERROR` silently deletes the outage message
  the disclosure scenario exists to assert.
- **OpenSSH escapes non-ASCII in banners.** The em dash in the outage message
  arrives as `\342\200\224`, so no assertion may contain one. (Text that arrives
  over a *channel* is not escaped — the warn-action message keeps its em dash.)
- **The client discards some of what the proxy says.** The proxy writes its
  denial clause to the channel's stderr for a refused in-channel request
  (`internal/proxy/channel.go`), but `ssh -tt` and `sftp` both abandon the
  channel on a failed request first, so the user sees only OpenSSH's own
  *"PTY allocation request failed"* / *"subsystem request failed"*. The clause
  is therefore asserted where it reliably lands — the priority audit record —
  and the scenarios assert the client's real output. Same for an empty channel
  allow-list: the engine accepts the session channel before anything can fail
  (§4.3's ordering), so the user gets the generic `Access denied.` and the
  channel type is only in the audit record.

### The scenarios, and what each proves

| Scenario | Proves |
| --- | --- |
| network isolation | the user node cannot reach the target or the zone proxy, but can reach a proxy |
| direct exec / shell | the everyday path, with `ephemeral-user` credentials |
| nexthop `dial` exec / shell | chaining, over a leg the upstream opened |
| nexthop `relay` exec / shell | **D11**: a hop reached over a connection the downstream opened, to a proxy nothing can dial |
| relay with no registration | the route names a *dialable* address, and is still refused as an outage — a relay hop is never quietly downgraded to a dial |
| loop / hop cap | the hop trail makes both detectable, and both render as the same deliberately vague outage |
| empty channel allow-list | axis 1 (D5a) |
| sftp denied while shell succeeds | axis 2 — both ride one `session` channel |
| pty denied while exec succeeds | axis 2, the other way round |
| forward to permitted / other port / other host | axis 2 for `direct-tcpip`: the destination in the payload is the policy |
| `tcpip-forward` refused, no listener on the target | axis 3 — a connection-level request the channel allow-list never sees |
| restricted exec: approved argv, unapproved argv, shell wrapper | **D12**'s enforced tier |
| the same wrapper under filtered exec | the guardrail tier's rule for `/bin/ls *` stops the bare command and demonstrably cannot stop the wrapper — the tiers differ in the product, not only in unit tests |
| block / warn / kill / allow+log | the four match actions |
| `ephemeral-user` | logs in as `hl-<tag>-alice-<token>`, an account it created |
| `brokered-key` | logs into a standing account and leaves the target byte-identical |
| denial disclosure | `Access denied.`, naming neither target, method, nor permission set |
| outage disclosure + drain | see below |
| no ephemeral accounts left behind | runs last, after every session that could have leaked one |

### The outage scenario needs a session that outlives the outage

The first attempt was to stop Hoplock Control and connect. That covers the
disclosure half and proves **nothing** about buffering: the proxy never caches
an authentication (D2), so a connection attempted during an outage fails at
authentication and produces no session records at all. The disk buffer stays
empty and the assertion is vacuous.

So the scenario opens a session first, holds it open (`sleep 30` down the
channel) across the stop, and lets it end before the restart. Its records had
nowhere to go but `logging.buffer_dir`. The mock's ingested state dies with its
container, so after the restart a record carrying **that session's id** can only
have been drained. The id is parsed out of the proxy's own banner — the support
reference §4.3 promises, doubling as a handle on one session's audit trail.

The session runs on its own goroutine, which is why the harness has `runE`/`sshE`
(no `*testing.T`) beside `run`/`ssh`: `t.Fatalf` off the test goroutine is
illegal.

### The target image, and the trap in it

`deploy/target/` replaces `deploy/sshd/` and backs both `make test-sshd` and the
topology. Keys are mounted and installed by an entrypoint rather than baked in
(material in an image is material shared by everyone who has it), and host keys
are generated at start for the same reason.

**Two sshd settings are load-bearing.**

`UsePAM yes`: `useradd` leaves a new account with a locked
password; with `UsePAM no`, `sshd` refuses it — *"not allowed because account is
locked"* — before it ever looks at the key the proxy just installed, and every
`ephemeral-user` session fails with an unhelpful *"unable to authenticate"* on
the proxy side. The stock Debian `sshd_config` has it; the risk is someone
"hardening" it away.

`PerSourcePenalties no` — and this one is a **product finding, not a test
artefact**. The first CI run failed with every proxy-direct scenario after the
first fifteen or so reporting `connection reset by peer` from the target. The
target's own log said why:

```
Connection closed by authenticating user netadmin 172.19.0.2 port 50018 [preauth]
drop connection #0 from [172.19.0.2] on [172.19.0.4]:22 penalty: failed authentication
```

A decrypting proxy is a *single source address* to every target it fronts. When
a user is refused at the proxy — a denied pty, a denied channel, a blocked
command — the proxy abandons the target connection it had already started,
sometimes mid-handshake, and OpenSSH ≥ 9.8's `PerSourcePenalties` (on by
default) scores that as a failed authentication against the proxy's address.
After enough of them sshd drops the proxy outright, and at the proxy it looks
like a network fault. `proxy-zone`, which served three sessions, was unaffected;
`proxy-direct`, which serves most of the suite, was blocked within seconds.

The topology turns it off, applying each directive only if this `sshd`
understands it (`sshd -t` after appending each), so an older or newer base image
still boots. See the known gaps below for what this means beyond the test rig.

A third one is not a setting but a file mode: **`.ssh` must be owned by its
account**, not only the `authorized_keys` inside it. `useradd -m` creates the
home; a later `mkdir -p /home/netadmin/.ssh` as root does not, and `StrictModes`
then refuses every key under it. The target says so in its own log and the proxy
sees only `ssh: unable to authenticate` — so the symptom points at the
credential, which is the one thing that is fine. `install_key` in the entrypoint
now chowns the directory alongside the file.

### Fixtures are rendered, not committed

`deploy/gen-material.sh` generates every key into `deploy/keys/` and renders
`deploy/control/fixtures.yaml` from `fixtures.template.yaml`, substituting
SHA256 fingerprints — which cannot be written down before their keys exist. Both
are gitignored. `test/topology` keeps the two in step: it fails if the template
stops using a placeholder the script still substitutes, or vice versa.

`test/topology` also loads all three proxy configs with the real
`config.Load`. Bootstrap decoding is strict, so a typo is otherwise found only
when a container fails to start several minutes into the e2e job.

### The `govulncheck` gate

`golang.org/x/crypto/ssh` is this project's SSH implementation, not an
incidental dependency, and the v0.44.0 → v0.55.0 bump alone crossed 15 fixed
advisories — around six of them server-side DoS and panic issues in
`x/crypto/ssh` itself, in exactly the paths 0005–0009 build on. The job runs
`govulncheck ./...` with default symbol-level analysis, so it reports only
vulnerabilities reachable from this module's code.

**When it goes red with no code change**, a new advisory has landed against a
dependency already in `go.mod`. That is the signal working. Upgrade the
dependency; if no fix exists yet, record an explicit dated justification in this
repository. Do not delete the job.

`make vulncheck` exists for local use and prints
`cannot reach vuln.go.dev — this check runs in CI` when the database fetch
fails, because the failure is an opaque `403` that reads like a broken tool. It
is deliberately **not** in `docs/PROTOCOL.md`'s Definition of Done.

**The gate has been seen failing** — "a gate nobody has seen fail is not known
to be a gate". The sandbox this phase was implemented in cannot reach
`vuln.go.dev` at all (the egress gateway answers `403`), so the verification ran
in CI: commit `96ad70f` downgraded `golang.org/x/crypto` to v0.44.0, the
`govulncheck` job failed with exit code 3 reporting **9 vulnerabilities
reachable from this module's code**, all in `x/crypto/ssh`, and the next commit
reverted it. Every trace landed in a path this repository actually owns:

```
GO-2025-4134  Unbounded memory consumption
  #1: internal/proxy/proxy.go:297: proxy.Server.handleConn calls ssh.NewServerConn
GO-2026-5017  Client can cause server deadlock on unexpected responses
  #6: internal/proxy/channel.go:559: proxy.session.serveGlobalRequests calls ssh.mux.SendRequest
GO-2026-5015  Server panic during CheckHostKey/Authenticate
  #1: internal/relay/authz.go:111: relay.Authorizer.Authenticate calls ssh.CertChecker.Authenticate
GO-2026-5020  Infinite loop on large channel writes
  #1: internal/auth/target/admin.go:171: target.sshAdminDialer.Dial calls ssh.NewClientConn
```

It also found "1 vulnerability in packages you import and 6 vulnerabilities in
modules you require" that it did **not** fail on, because this module's code
never calls into them. That is the symbol-level analysis doing exactly the job
it was chosen for: nine real findings, seven suppressed as unreachable, no
judgement call left to a human deciding whether to care.

### Hardening/cleanup

There were no leftover TODOs to clear: the only two `TODO` mentions in the tree
(`internal/proxy/session.go`, `docs/PLAN.md` §4.3) refer to *x/crypto's* own
backlog for exporting `SSH_MSG_DISCONNECT`, and the engine already reaches for
it if a future version exports one. `deploy/sshd/`'s duplicate target image is
gone. `.golangci.yml` now lints the `e2e`-tagged files, which nothing else in
the repository would have looked at.

An intermittent failure was observed once in
`internal/proxy.TestMalformedForwardingPayloadIsDenied` (`Output after malformed
opens: EOF`) on a machine loaded with other processes; it did not reproduce in
30 runs, including under `-race`. Worth watching rather than acting on.

### Known gaps, to seed later prompts

- **Host-key pinning policy.** The topology runs on D7's trust-on-first-use.
  There is no scenario for a *changed* target host key, because there is no
  policy to enforce yet — that is the per-target policy D7 defers.
- **Real distribution.** Geo/anycast, latency, and scale are out of scope by
  construction: this validates behavior, not distribution. Phase 0017 owns
  sizing with a synthetic harness outside this topology.
- **AD/Okta/OIDC.** Only the fixture identity source is exercised; D4's
  pluggability has no second implementation to test against.
- **Tamper-evident logs.** Records are asserted to *arrive*; nothing proves they
  were not altered in transit or at rest.
- **Password + MFA.** The topology's proxies are certificate-only, so the
  keyboard-interactive MFA flow (0004) has no e2e coverage; its unit and mock
  tests remain the only evidence.
- **Per-source abuse defences on real targets.** The finding above is not
  confined to the test rig: any target running OpenSSH ≥ 9.8 with default
  `PerSourcePenalties` will eventually start dropping a busy proxy, because the
  proxy is one address making many connections and abandoning some of them
  mid-handshake. Two halves to it, and neither is in this phase's scope: the
  proxy could stop abandoning target connections it has begun (tear down after
  the handshake completes rather than during it), and the deployment guide will
  have to tell operators what their targets need configured. Worth its own
  prompt.
- **Concurrency.** Every scenario is sequential. Two sessions provisioning on
  one target at the same time is exactly what the ephemeral principal's token
  exists for (PLAN §5.1), and nothing here exercises it.
