# 0001 — Project scaffold & conventions

## Read first
- `docs/PROTOCOL.md` — how to run this session (branch, PR, learnings, DoD).
- `docs/PLAN.md` — architecture. Especially §3 (layout), §8 (conventions), §2 (decisions D9, D10).
- `docs/learnings/` — read each summary block (likely empty for this first phase).

## Objective
Stand up the Go project skeleton, conventions, and CI so every later phase drops
into a consistent structure. **No SSH or business logic yet.**

## In scope
- `go.mod` with module path `github.com/hoplock/proxy`, Go **1.24**.
- Directory skeleton per PLAN §3. Create packages as empty-but-compiling stubs
  (a `doc.go` with the package clause + one-line purpose comment) for:
  `internal/config`, `internal/identity`, `internal/control`, `internal/auth/user`,
  `internal/auth/target`, `internal/routing`, `internal/proxy`,
  `internal/channel`, `internal/filter`, `internal/logging`.
- `cmd/proxy/main.go` and `cmd/mock-control/main.go` as minimal programs
  that build, print a version/usage line, and exit 0. Wire a `--version` flag.
- `internal/config`: a YAML bootstrap config loader with a typed struct and an
  example file `config.example.yaml`. Include only fields we already know are
  needed: listen address, management-server base URL, proxy identity/host-key
  path, target-username delimiter (default `#`, per D1). Loader validates and
  returns typed errors. Unit-tested.
- **License (D10):** `LICENSE` file — proprietary, all rights reserved,
  confidential. Add the per-file header from PLAN §8 to every `.go` file.
  Provide the exact header text in a short `docs/` note or the README so later
  phases copy it verbatim.
- `Makefile` targets: `build`, `test`, `vet`, `lint`, `run-proxy`,
  `run-mock`, `tidy`. `lint` uses `golangci-lint`.
- `.golangci.yml` with a reasonable baseline (govet, staticcheck, errcheck,
  ineffassign, gofmt/goimports).
- `.github/workflows/ci.yml`: on push/PR, run `go build ./...`, `go vet ./...`,
  `go test ./... -race`, and `golangci-lint`. Pin Go 1.24.
- `.gitignore` for Go.
- Expand `README.md`: one-paragraph product summary (point to `docs/PLAN.md`),
  build/run instructions, and the "read `docs/PROTOCOL.md` before contributing"
  note.

## Out of scope
- Any SSH handling, Control API calls, auth, proxying, or logging logic.
- The API contract (that's 0002).

## Acceptance criteria
- `make build`, `make vet`, `make test`, `make lint` all succeed.
- Both binaries build and run `--version`.
- `internal/config` loads `config.example.yaml` in a unit test and rejects a
  malformed config in another test.
- CI workflow is present and green.
- Every `.go` file carries the license header.

## Definition of Done & hand-off
Follow `docs/PROTOCOL.md` §4–§5: move this file to `prompts/implemented/`, add
`docs/learnings/0001-project-scaffold-learnings.md` (with a Summary block noting
the module path, the config struct fields, the exact license header text, and
the Make/CI entry points later phases will rely on), open the PR, iterate to
merge.
