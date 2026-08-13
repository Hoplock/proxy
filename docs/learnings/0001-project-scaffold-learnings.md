# 0001 — Project scaffold & conventions — Learnings

## Summary
- What shipped: Go module skeleton, per-file license headers + `LICENSE`, YAML
  bootstrap config loader with typed errors, two scaffold binaries, Makefile,
  `.golangci.yml` (schema v2), and a 3-job CI workflow. No SSH/business logic.
- Key packages/files: `internal/config/config.go`, `config.example.yaml`,
  `cmd/bastion/main.go`, `cmd/mock-management/main.go`, `Makefile`,
  `.golangci.yml`, `.github/workflows/ci.yml`, `docs/LICENSE-HEADER.md`.
- Key interfaces/types added: `config.Config` (`Bastion`, `Management`,
  `Routing`), `config.Load`/`config.Parse`/`(*Config).Validate`,
  `config.FieldError`, `config.ValidationError`, sentinels `ErrMissing`,
  `ErrInvalid`, `ErrMalformed`, const `DefaultTargetDelimiter = "#"`.
- Decisions made/affected: D1 (delimiter is config, validated), D9 (Go 1.24,
  YAML bootstrap), D10 (proprietary license + SPDX headers). No plan changes.
- Gotchas: config decoding is **strict** (`KnownFields(true)`) — every new field
  must be added to the struct *and* `config.example.yaml`, or configs break.
  `golangci-lint` here is **v2**; `gofmt`/`goimports` live under `formatters`.
- What the NEXT session must know: add the two-line header from
  `docs/LICENSE-HEADER.md` to every new `.go` file (CI job `license` enforces
  it via `make license-check`); each `internal/` package already exists as a
  `doc.go` stub — extend it, don't recreate it.

## Details

### Module & layout
Module path is `github.com/mauroasilva/securecommandproxy` (PLAN §8), Go 1.24.
Only dependency: `gopkg.in/yaml.v3`. Every `internal/` package from PLAN §3
exists as a `doc.go` containing just the header plus a package comment naming
the package's responsibility and the PLAN section/decision it implements. Keep
that convention when a package gains real code — move the package comment to the
primary file only if `doc.go` is deleted, otherwise leave it in `doc.go` (Go
allows exactly one package comment per package; `internal/config` keeps its
comment in `config.go` and has no `doc.go`).

`api/` and `deploy/` exist as empty directories with `.gitkeep` — they are filled
by phases 0002 and 0010 respectively.

### Config contract (what later phases consume)
```go
type Config struct {
    Bastion    Bastion    `yaml:"bastion"`     // listen_addr, host_key_path
    Management Management `yaml:"management"`  // base_url
    Routing    Routing    `yaml:"routing"`     // target_delimiter
}
```
- `Load(path)` → open + `Parse`; `Parse(io.Reader)` → strict decode → defaults →
  `Validate`. Add new defaults in `applyDefaults`, new checks in `Validate`.
- `Validate` reports **all** problems at once as a `*ValidationError` whose
  `Unwrap() []error` exposes each `*FieldError`, so `errors.Is(err, ErrMissing)`
  and `errors.As(err, &verr)` both work. `FieldError.Field` is the YAML path
  (e.g. `bastion.listen_addr`) — keep that convention for new fields.
- Delimiter validation rejects anything that is not exactly one character, and
  rejects alphanumerics plus `.`, `-`, `_`, so splitting `alice#host.example.com`
  is unambiguous (D1). Phase 0003/0006 should split on the configured delimiter
  rather than hardcoding `#`.
- Only bootstrap settings belong here. Anything policy-related is fetched from
  the management server per connection (D2) and must **not** be added to this
  struct.

### Binaries
Both `cmd` mains are scaffolds: they parse flags via a `flag.FlagSet` with a
custom `Usage`, support `-version`/`--version` (printing a `var version = "dev"`
overridden by `-ldflags "-X main.version=..."`, which the Makefile sets from
`git describe`), and exit 0. `bastion` also accepts `-config` and
`mock-management` accepts `-listen`; neither does anything with them yet — 0002
wires the mock API, 0004 wires the bastion's listener and config load.

### Tooling
- `make all` = `build vet test lint`. Other targets: `fmt` (`golangci-lint fmt`),
  `license-check`, `tidy`, `run-bastion CONFIG=...`, `run-mock LISTEN=...`,
  `clean`. `make test` runs with `-race`.
- `.golangci.yml` is **schema v2** (`version: "2"`). Linters: errcheck, govet,
  ineffassign, staticcheck, unused; formatters gofmt + goimports with
  `local-prefixes` set to the module path. `errcheck` is relaxed in `_test.go`.
  Note staticcheck's `QF1002` fires on a `switch { case x == "": ... default: }`
  shape — use `if/else` there.
- `make license-check` scans tracked *and* untracked `.go` files, so it catches a
  missing header before the file is committed.
- CI (`.github/workflows/ci.yml`) has three jobs: `build-test`
  (`go build`/`go vet`/`go test -race`), `lint`
  (`golangci/golangci-lint-action@v8`, pinned `v2.5.0` — v8 of the action is
  required for schema-v2 configs), and `license`. Go version is pinned via the
  `GO_VERSION: "1.24"` env. Phase 0010 adds the e2e job alongside these.

### Deviations
- Branch name is `claude/queued-prompt-implementation-ee8r8a` instead of the
  `claude/NNNN-short-description` form in PROTOCOL §2, because the session was
  started with that branch pre-assigned. Nothing else about §2 changed
  (branched off `main`, never pushed elsewhere).
- `docs/LICENSE-HEADER.md` was added to hold the verbatim header text; the prompt
  allowed either a `docs/` note or the README, and a standalone file is easier to
  copy from and to point CI at.

### Follow-ups (not done here, not blocking)
- No new prompts were added; numbering invariants (PROTOCOL §6) are unchanged —
  0001 moved to `prompts/implemented/`, 0002–0010 remain queued.
- A `--config` that actually loads and validates the file will land with the
  bastion's real startup path (0004); `internal/config` is ready for it.
