# 0049 — Tell Control which relay registrations a proxy holds — Learnings

## Summary
- What shipped: `POST /v1/proxies/{proxy_id}/relay-registrations/report` (tag `relay`). `RelayRegistrationReport{registered_proxy_ids}` is required, never `null`, a complete replacement set. `RelayRegistrationReportResponse{accepted, report_after_seconds}`. `info.version` **4.8.0**, `policy_version` still **6**. Only the **hub** (`chain.accept`) reports.
- Key files: `internal/control/relayreport.go`, `internal/relay/hub.go`, `cmd/proxy/main.go` (`startRelayHub`), `cmd/mock-control/relayreport.go`, `api/{control.yaml,README.md}`, `docs/PLAN.md` (§2 D11 row and note, §3, §6.1, §10).
- Types: `control.{PathRelayRegistrationReport, RelayRegistrationReportPath, RelayRegistrationReport, RelayRegistrationReportResponse(.ReportAfter), RelayReportSink, RelayReporter, RelayReporterOptions{Sink, ProxyID, Registrations, Interval, Logger, After}, DefaultRelayReportInterval, RelayFinalReportTimeout}`, `(*RESTClient).ReportRelayRegistrations`, `relay.HubOptions.OnChange`. `Hub.Registrations()` is now sorted.
- When: at `Run`, on `Changed()` (non-blocking, coalescing), and every `min(20s, report_after_seconds)`. **20s is a ceiling: the server can shorten it and never lengthen it.** Retry 1s doubling to that interval, and at once on a change. One report in flight. On stop: one `[]`, bounded at **2s**.
- `OnChange` fires outside `h.mu` on every add or remove, a keepalive lapse included. It does not fire on a same-id replacement. **At shutdown it fires once per removal**, because each keepalive loop drops its own registration while `closeAll` races it.
- Decisions: **no new `D`. D11 rendered**, not amended (register row and an "As rendered (phase 0049)" note). D2 and D18's not-on-the-data-path rule hold. The never-dial rule and `ErrNoRegistration` are untouched.
- What Control must change (the sync): re-vendor at 4.8.0. Serve the endpoint south-bound, attributing it to the proxy the credential names and refusing another proxy's id with `401`. Record it with `ReplaceForUpstream`, **not** an empty `Heartbeat`, and decide under M6 whether it is a liveness signal. Answer `report_after_seconds` ≤ ⅓ of `fleet.relay_registration_ttl`. Add conformance cases. Retire the seeded row and the `8760h` TTL. Mark 0061's dependency met. Details below.

## Details

### Why the reporter never waits on a sink that ignores its context

`RelayReporter.call` runs the sink in a goroutine and returns when its context
ends, whether or not the sink has. A conformant sink (`*RESTClient`) has aborted
by then, so "at most one report in flight" holds for it. A non-conformant one
cannot wedge `Run`, or hold shutdown past the final report's 2s bound. Each call
is also bounded at 10s (`relayReportCallTimeout`). A report that slow has been
overtaken by the next one anyway.

What this does **not** buy is server-side ordering of a request that was already
on the wire when the client gave up. That is inherent to any timeout. It is
harmless here: the next report replaces the set, and the server ages out what
is not re-reported.

### The clock seam

`RelayReporterOptions.After` replaces `time.After`, and nothing else in the
reporter reads time. The tests use a fake clock whose waits fire only when the
test fires them. So "no report was sent" means the reporter chose not to send
one, not that the test was quick. That is also how the interval cases (20s,
5s, 300s → 20s) are asserted without sleeping: they read the duration the
reporter asked to wait. The final report's 2s bound is real time and is tested
in real time (`TestRelayReporterFinalReportIsBounded`, about 2s).

### Wiring (`cmd/proxy`)

The hub pokes the reporter and the reporter reads the hub, so `startRelayHub`
builds both. The reporter's `Registrations` is a closure over a `hub` variable
assigned right after. It is first called by `Run`, which starts after.

`Run` gets its own context (`WithoutCancel` of the process context). The hub's
`Serve` goroutine cancels it on the way out (`defer stopReports()`), so the
final `[]` follows `closeAll`. `run()` waits for both. The cmd/mock-control chain
test copies this wiring by hand, because `cmd/proxy` is `package main` and
cannot be imported. A change to one should be made to the other.

### Logging

One line per transition: the first failure after a success (the reporter
starts out treated as healthy, so the very first failure logs), and the first
success after a failure. Each line names the proxy id and an error class from
`relayErrorClass`: `unreachable`, `unauthorized`, `refused`, `server failure`,
`contract violation`, `timed out`. The HTTP status and the error-envelope code
follow when the server sent them, e.g. `refused, HTTP 404 not_enrolled`. A
failed final report logs only if the reporter was healthy. Nothing is an audit
record.

### Mock

The mock's `proxy_token` is one shared token that names no proxy. So rule 5
("where that credential names a proxy, refuse another proxy's id") has nothing
to bite on, and the mock attributes a report by its path alone. Its comment and
`api/README.md` say so. A refused report records nothing, so a malformed report
cannot blank a hub's last good set.

### e2e

`test/e2e/relayreport_test.go` reads `GET /debug/relay-registrations`. One
subtest in the routing scenarios, after the two relay sessions, waits for
`proxy-nexthop` to report `proxy-zone` and checks that `proxy-zone` reported
nothing. It could not be run in this session: no Docker, and `make e2e` cannot
build its images here (0040's note). CI's `e2e` job runs it.

### Cross-repo obligation

Owed to `hoplock/control`, including because Control asked
(`docs/CROSS-REPO-PROTOCOL.md` §5). The PR's `## Cross-repo impact` section
lists the obligations, and the sync is queued in
`prompts/downstream/queued/`. `hoplock/enterprise`: **None**. It consumes
Control's public Go API and not `api/`, and nothing in it talks to a proxy
(`docs/CROSS-REPO-PROTOCOL.md` §4.3). This session could not attach either
sibling repository, so that rests on the protocol and on the prompt's check at
`hoplock/control@2a3de41`. It was not re-grepped.

### Follow-ups (not queued)

- A general proxy heartbeat (session count, last error) stays out of scope. If
  Control wants one, it is a new endpoint and not a field on this one.
- Registration metadata (since when, from where) would go **beside**
  `registered_proxy_ids` if anyone asks.
