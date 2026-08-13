# SecureCommandProxy

SecureCommandProxy is a **decrypting SSH bastion** — a policy-enforcing SSH
proxy. A user's SSH client connects to the bastion; the bastion terminates that
SSH connection, authenticates the user, opens a **fresh** SSH connection to the
target, and proxies traffic between the two legs. Because both legs are
decrypted inside the bastion, it can log everything and filter or inspect
commands and channels. The bastion itself is deliberately thin: it is the policy
*enforcement* point, while a central management server is the policy *decision*
point.

The architecture — end-to-end flow, decisions D1–D10, package layout, and the
phased delivery plan — lives in **[`docs/PLAN.md`](docs/PLAN.md)**. Read it
before reading the code.

> Status: early scaffold. No SSH handling yet; see `docs/PLAN.md` §10 for the
> phase order.

## Requirements

- Go **1.24** or newer
- [`golangci-lint`](https://golangci-lint.run) v2 (for `make lint`)

## Build and run

```sh
make build                      # binaries into ./bin
make test                       # unit tests with -race
make vet                        # go vet
make lint                       # golangci-lint
make license-check              # every .go file carries the license header

./bin/bastion --version
./bin/mock-management --version
```

To run from source:

```sh
cp config.example.yaml config.yaml   # then edit
make run-bastion CONFIG=config.yaml
make run-mock LISTEN=127.0.0.1:8080
```

## Configuration

The bastion reads a YAML bootstrap file; see
[`config.example.yaml`](config.example.yaml) for the annotated set of fields.
It holds only what is needed to start and reach the management server — every
authentication, authorization, routing, and filtering decision is made remotely,
per connection (`docs/PLAN.md`, D2).

## Repository layout

| Path                | What lives there                                              |
| ------------------- | ------------------------------------------------------------- |
| `cmd/bastion`       | the proxy daemon                                              |
| `cmd/mock-management` | reference/mock management API for dev and CI                |
| `internal/`         | the implementation packages (see `docs/PLAN.md` §3)           |
| `api/`              | management API contract — source of truth (phase 0002)        |
| `deploy/`           | docker-compose e2e topology and fixtures (phase 0010)         |
| `docs/`             | plan, session protocol, and per-phase learnings               |
| `prompts/`          | queued and implemented phase prompts                          |

## Contributing

**Read [`docs/PROTOCOL.md`](docs/PROTOCOL.md) in full before doing any work.**
It defines how a session picks up a prompt, branches, what "done" means, and how
work is handed off to the next session. `docs/KICKOFF.md` has the exact prompt to
start a session with.

Every `.go` file must carry the license header in
[`docs/LICENSE-HEADER.md`](docs/LICENSE-HEADER.md).

## License

Proprietary and confidential. Copyright (c) 2026 Mauro Silva. All rights
reserved. See [`LICENSE`](LICENSE).
