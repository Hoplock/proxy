# Hoplock Proxy

Identity-aware SSH proxy with multi-hop routing, command and channel controls,
and policy enforcement at every hop.

Hoplock Proxy is a **decrypting** SSH proxy: a user's SSH client connects to it,
it terminates that SSH connection, authenticates the user, opens a **fresh**
connection to the target, and proxies traffic between the two legs. Because both
legs are decrypted inside the proxy, it can log everything and filter or inspect
commands and channels — which is what a jump host tunnelling an end-to-end
encrypted session cannot do.

It is deliberately thin. Hoplock Proxy is the policy **enforcement** point (PEP);
[Hoplock Control](https://github.com/hoplock/control) is the policy **decision**
point (PDP). This repository has no dependency on Hoplock Control's
implementation — only on the API contract in [`api/`](api/README.md), which it
owns.

## Where this fits

| Component | Role |
| --- | --- |
| **Hoplock Proxy** (this repo) | Data plane. Enforces access: SSH proxying, channel and command controls, port-forward policy, multi-hop relay, audit events. |
| **Hoplock Control** | Open-source control plane. Manages access: proxies, targets, identities, routes, policies, audit ingest, API and console. |
| **Hoplock Enterprise** | Commercial extensions to Control: governance, compliance, advanced audit, approval workflows, SIEM/SOAR, HA. |

Hoplock Proxy never depends on Hoplock Control's code, and never on Enterprise.

The architecture — end-to-end flow, decisions D1–D17, package layout, and the
phased delivery plan — lives in **[`docs/PLAN.md`](docs/PLAN.md)**. Read it
before reading the code.

> Status: early, but end to end. The proxy authenticates a user, authorizes
> the connection against Hoplock Control, and proxies a **direct** route
> to a target, passing every SSH channel through generically. Both production
> target-credential methods are in: **ephemeral-user**, which creates a
> short-lived account and key on the target for the session and removes them
> afterwards (with an orphan reaper for the sessions whose proxy died), and
> **brokered-key**, a credential held in memory for one session. A third,
> **ephemeral-account**, takes the ephemeral model onto gear that has no
> `useradd` at all: it creates a short-lived *administrator* on a device through
> a per-platform driver — FortiGate and FortiSwitch today — and removes it
> afterwards. Hoplock
> Control chooses between them per route, and since contract v3 it sends an
> ordered **ladder** rather than a single method: the proxy walks it top-down,
> stops at the first entry it can satisfy, and records which one that was. It
> never invents an entry. `auth.target` in `config.example.yaml` holds only the
> local material each method needs. Chaining is in too: a session can traverse
> several proxies, each authenticating, authorizing and routing for itself, and
> a proxy in a protected zone is reached over a connection **it** opened to its
> upstream — so an enclave needs no inbound firewall rule at all. Channels are
> policed on all three policy axes, and commands on two tiers that are named
> apart on purpose: **restricted exec**, a default-deny list of parsed argument
> vectors that is sold as enforcement, and **filtered exec**, a pattern rule
> list that is a guardrail — plus best-effort inspection of interactive
> sessions, which reports and never enforces. Everything a session does is now
> recorded and shipped: metadata, in-channel requests, policy decisions and
> replay-friendly stream capture go to Hoplock Control in **batches**, a blocked
> command goes **immediately** on its own endpoint, and an outage buffers to
> local disk and drains in order when the link returns. Next is the full
> end-to-end topology and its CI gate. See `docs/PLAN.md` §10 for the order.

## Requirements

- Go **1.26** or newer (CI builds and tests on the latest stable release)
- [`golangci-lint`](https://golangci-lint.run) v2 (for `make lint`)
- Python 3 with `openapi-spec-validator` (for `make openapi-check` only)
- Docker with `compose`, and `ssh-keygen` (for `make e2e` and `make test-sshd`)

## Build and run

```sh
make build                      # binaries into ./bin
make test                       # unit tests with -race
make test-sshd                  # credential + enforcement tests against a real
                                # sshd (needs docker); gated in CI, and
                                # test-sshd-up / -run / -down split it up
make vet                        # go vet
make lint                       # golangci-lint
make license-check              # every .go file carries the license header
make vulncheck                  # vulnerabilities reachable from this module (see below)

./bin/hoplock-proxy --version
./bin/mock-control --version
```

To run from source:

```sh
cp config.example.yaml config.yaml   # then edit
make run-proxy CONFIG=config.yaml
make run-mock LISTEN=127.0.0.1:8080
```

## Target prerequisites

A decrypting proxy is a **single source address** to every target it fronts.
That is the deployment model, not a detail of any one topology: every session
for every user of a target arrives from the same handful of proxy addresses.
Targets are normally configured on the opposite assumption — that many source
addresses means many distinct clients, and that a burst from one of them is an
attacker — so three sshd settings need a decision before a fleet goes behind
this proxy.

| Setting | Default | What happens if it is left alone |
| --- | --- | --- |
| `PerSourcePenalties` | **on** since OpenSSH 9.8 | Any failed authentication is scored against the **proxy's** address, not against the user who triggered it. One route's stale credential, retried as users arrive, gets the proxy blocked from the target: `drop connection #0 from [proxy] on [target]:22 penalty: failed authentication`. At the proxy that surfaces as a bare "connection reset by peer" — every user of that target loses a working session to a credential that was never theirs. |
| `MaxStartups` | `10:30:100` | Unauthenticated connections are counted per **server**, and a proxy opens one per session. Ten concurrent session setups through one proxy start being dropped at random; the users see a connection that failed for no reason they can act on. |
| `MaxSessions` | `10` | Channels per connection. The proxy opens a fresh connection per session, so this bites only where one session opens many channels — a multiplexed client, or forwarding — but it is the same shape of limit. |

For a target reachable **only** through the proxy, turning `PerSourcePenalties`
off is the right call: the defence exists to tell distinct attackers apart, and
behind an enforcement point there are no distinct sources left to tell apart.
For a target that also accepts direct connections, raise the thresholds instead
and leave the defence on for everyone else. Either way it is a decision
somebody made, and `deploy/target/entrypoint.sh` shows what it looks like
applied.

The proxy does its half of this and does not rely on the target's settings for
it. A credential the target refuses is classified as a refused credential
rather than as an unreachable host, recorded as a critical audit event naming
the credential's **handle** (never material), and — after
`auth.target.rejection.threshold` consecutive rejections — withheld for
`auth.target.rejection.cooldown`, so the proxy stops opening connections that
would be scored against it. Containment is keyed on the credential and the
target, never on the user or the route: a different credential to the same
target keeps working throughout. See `auth.target.rejection` in
[`config.example.yaml`](config.example.yaml).

### What `ephemeral-user` needs on a target

Two things beyond the provisioning account itself, both because of how an
ephemeral account's **uid** is chosen.

The proxy allocates the uid rather than letting `useradd` do it. Left to itself,
`useradd` hands a torn-down account's uid straight back to the next caller, and
teardown deliberately does not walk the filesystem — so every file a session
wrote **outside its home** keeps the bare number, and the next session, belonging
to a different person, would own it. So:

- **`enforcement_base`** (default `/var/lib/hoplock`) must exist or be creatable
  by the provisioning account, and be writable by it, on **every** target — not
  only on the ones that render an enforcement rung. It holds the uid high-water
  mark, which is what makes the guarantee survive a teardown, a proxy restart,
  and a second proxy on the same fleet. A target where the mark cannot be written
  refuses the session as an outage rather than provisioning an account whose uid
  nothing has recorded. The proxy sets that directory root-owned and mode `700`
  on every provisioning, and treats what it reads there as evidence that may only
  ever **raise** the next uid — so a tampered mark costs uids out of the range,
  loudly, and can never hand a session a uid a previous one held.

  Note the shape this rules out: a host with a **read-only root filesystem** can
  run `useradd -m` and hold an `authorized_keys` in a writable `/home`, but cannot
  take `/var/lib`. Point `enforcement_base` at a writable path on such a fleet.
  Appliances reached with `ephemeral-account` — firewalls, switches — are
  unaffected: the proxy allocates no uid and writes no files there.
- **The uid range** (`auth.target.ephemeral_user.uid_min`/`uid_max`, default
  `2000000-2999999`) must be free on the fleet. It sits above every
  distribution's own `UID_MAX`, so the target's allocator never enters it; move
  it only for a fleet that already allocates there, and keep it wide.
  **Allocation does not wrap** — reaching the top refuses every ephemeral session
  on that target until `uid_max` is raised, and the proxy warns on every
  allocation past nine tenths of the range so that raising it is still a cheap
  change when it matters.

## The end-to-end topology

The whole system runs in containers — Hoplock Control, an SSH client, three
proxies, and a real `sshd` — on networks that make its segmentation claims
checkable: the client node has no route to the target, and the proxy in the
protected zone accepts no inbound connection at all. The scenario suite in
`test/e2e` drives it with a real OpenSSH client and asserts on what that client
was actually told.

```sh
make e2e        # up, run the scenario suite, tear down
make e2e-up     # up, and leave it running to debug a failure
make e2e-down   # stop it and delete everything it generated
```

It is the prototype's acceptance gate and runs on every pull request.
[`deploy/README.md`](deploy/README.md) explains the nodes, the networks, the
fixtures, and how to debug a failing scenario.

## Scale measurements

**Roughly what one proxy handles.** Measured on a 4-core Intel Xeon @ 2.10GHz
with 16 GiB of RAM, running Linux — with the load generator and the stand-in
target sharing those same four cores, so the rates are a floor rather than a
ceiling.

| | |
| --- | --- |
| New connections per second | **716 sustained** (~1,500 CPU-bound, derived) |
| Connect latency, p50 / p99 at 600 conn/s | 6.3 ms / 16.2 ms |
| CPU per connection | 2.6 ms |
| Memory per live connection | 118 KiB, so ~35,000 concurrent in 4 GiB |
| File descriptors per live connection | 2 |
| Hoplock Control calls per connection | 3.17, or 2.17 on a cached decision |
| `ephemeral-user` provisioning, per target | 58 create/teardown cycles per second |

For scale: a 350,000-target estate polled every five minutes is 1,167 conn/s —
**one to two proxies**. Full methodology, what each figure is derived from, and
what these numbers cannot say are in `docs/PLAN.md` §9.1. Re-run them on your
own hardware before treating any of it as a capacity plan.

`cmd/loadgen` produces them: establishment rate, memory per live connection,
Control requests per connection, the decision cache under fan-out, and the
per-target cost of `ephemeral-user` provisioning.

```sh
make load                                     # every connection scenario (~20 min)
make load-one SCENARIO=load/scenarios/04-uc2-fanout.yaml
sudo make load-provisioning                   # ROOT; creates real local accounts
```

It is **not** part of CI: a load run is neither fast nor deterministic, and
gating a pull request on a shared runner's variance would measure the runner.
[`load/README.md`](load/README.md) explains what it runs and how to read a
report; the numbers and the sizing they support are in `docs/PLAN.md` §9.1.

## Supply-chain check

`make vulncheck` reports vulnerabilities **reachable from this module's code**
(`govulncheck`'s default symbol-level analysis, not a plain dependency scan).
`golang.org/x/crypto/ssh` is this proxy's SSH implementation rather than an
incidental dependency, so the `govulncheck` CI job gates every pull request.

It needs network access to `https://vuln.go.dev`. Some development sandboxes
deny it with an opaque `403`, which the target reports as a skip rather than as
a broken tool — CI is where this check must pass, and it is deliberately not a
required local step in `docs/PROTOCOL.md`'s Definition of Done.

The job **can go red with no code change**, when a new advisory lands against a
dependency already in `go.mod`. That is the signal working: upgrade the
dependency, or record an explicit dated justification. Never delete the job.

## Control API

The contract between the proxy and Hoplock Control lives in
[`api/`](api/README.md): `api/control.yaml` (OpenAPI 3, the source of truth)
and a human-readable companion. `internal/control` is the typed Go client — the
only package that talks to Hoplock Control — and `cmd/mock-control`
serves the contract from a fixture file for development and tests. `make
openapi-check` validates the document.

**This repo owns the contract; it does not implement the production Hoplock Control.** That component — policy authoring and simulation, identity
federation, JIT access and approvals, the tamper-evident audit store — lives in
its own repository, which vendors `api/control.yaml` from here read-only and
proves conformance against it (D3). A contract change starts here.

## Configuration

The proxy reads a YAML bootstrap file; see
[`config.example.yaml`](config.example.yaml) for the annotated set of fields.
It holds only what is needed to start and reach Hoplock Control — every
authentication, authorization, routing, and filtering decision is made remotely,
per connection (`docs/PLAN.md`, D2).

## Repository layout

| Path                | What lives there                                              |
| ------------------- | ------------------------------------------------------------- |
| `cmd/proxy`       | the proxy daemon                                              |
| `cmd/mock-control` | reference/mock Control API for dev and CI                |
| `cmd/loadgen`       | the scale harness (see `load/README.md`)                      |
| `internal/`         | the implementation packages (see `docs/PLAN.md` §3)           |
| `api/`              | Control API contract — source of truth                     |
| `deploy/`           | the end-to-end container topology (see its README)            |
| `test/`             | the e2e scenario suite and the topology's config checks       |
| `load/`             | load scenarios and the raw measurements they produced         |
| `docs/`             | plan, session protocol, and per-phase learnings               |
| `prompts/`          | queued and implemented phase prompts                          |

## Contributing

**Read [`docs/PROTOCOL.md`](docs/PROTOCOL.md) in full before doing any work.**
It defines how a session picks up a prompt, branches, what "done" means, and how
work is handed off to the next session. `docs/KICKOFF.md` has the exact prompts
to start a session with, including the downstream sync a cross-repo change owes. If your change touches a surface another Hoplock
repository consumes, `docs/CROSS-REPO-PROTOCOL.md` covers that too.

Every `.go` file must carry the license header in
[`docs/LICENSE-HEADER.md`](docs/LICENSE-HEADER.md).

## License

Proprietary and confidential. Copyright (c) 2026 Mauro Silva. All rights
reserved. See [`LICENSE`](LICENSE).
