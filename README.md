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
> upstream — so an enclave needs no inbound firewall rule at all. Next are
> channel inspection, command filtering, and the logging pipeline. See
> `docs/PLAN.md` §10 for the order.

## Requirements

- Go **1.25** or newer (CI builds and tests on the latest stable release)
- [`golangci-lint`](https://golangci-lint.run) v2 (for `make lint`)
- Python 3 with `openapi-spec-validator` (for `make openapi-check` only)
- Docker with `compose`, and `ssh-keygen` (for `make test-sshd` only)

## Build and run

```sh
make build                      # binaries into ./bin
make test                       # unit tests with -race
make test-sshd                  # credential tests against a real sshd (needs docker)
make vet                        # go vet
make lint                       # golangci-lint
make license-check              # every .go file carries the license header

./bin/hoplock-proxy --version
./bin/mock-control --version
```

To run from source:

```sh
cp config.example.yaml config.yaml   # then edit
make run-proxy CONFIG=config.yaml
make run-mock LISTEN=127.0.0.1:8080
```

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
| `deploy/`           | container fixtures: `sshd/` today, the full e2e topology in the final phase |
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
