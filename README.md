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

The architecture — end-to-end flow, decisions D1–D12, package layout, and the
phased delivery plan — lives in **[`docs/PLAN.md`](docs/PLAN.md)**. Read it
before reading the code.

> Status: early, but end to end. The proxy authenticates a user, authorizes
> the connection against Hoplock Control, and proxies a **direct** route
> to a target, passing every SSH channel through generically. Both production
> target-credential methods are in: **ephemeral-user**, which creates a
> short-lived account and key on the target for the session and removes them
> afterwards (with an orphan reaper for the sessions whose proxy died), and
> **brokered-key**, a credential held in memory for one session for the
> appliances and network gear the proxy cannot administer. Hoplock Control
> chooses between them per route; `auth.target` in `config.example.yaml` holds
> only the local material each needs. Chaining is in too: a session can traverse
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

- Go **1.25** or newer (CI builds and tests on the latest stable release)
- [`golangci-lint`](https://golangci-lint.run) v2 (for `make lint`)
- Python 3 with `openapi-spec-validator` (for `make openapi-check` only)
- Docker with `compose`, and `ssh-keygen` (for `make e2e` and `make test-sshd`)

## Build and run

```sh
make build                      # binaries into ./bin
make test                       # unit tests with -race
make test-sshd                  # credential tests against a real sshd (needs docker)
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
| `internal/`         | the implementation packages (see `docs/PLAN.md` §3)           |
| `api/`              | Control API contract — source of truth                     |
| `deploy/`           | the end-to-end container topology (see its README)            |
| `test/`             | the e2e scenario suite and the topology's config checks       |
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
