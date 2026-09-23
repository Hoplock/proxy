# 0042 — Fleet configuration distribution — Learnings

## Summary
- What shipped: **D18**. Control can distribute a configuration document; a
  proxy fetches it, applies it whole or not at all, and reports what it runs.
  Contract **4.2.0**, `policy_version` still **4**.
- Wire: event `config_changed` {`version`,`hash`} (never the document);
  `GET /v1/proxies/{proxy_id}/config` → `200` doc / `204` none published /
  `304` on `If-None-Match` = held hash / `404 not_enrolled`;
  `POST /v1/proxies/{proxy_id}/config/report` → `running_*`, `desired_*`,
  `state` (`applied|pending_restart|rejected|fetch_failed`), `restart_required`,
  `last_error`, `reported_at`.
- Key files: `internal/control/{fleetconfig,configsync}.go`,
  `internal/config/fleet.go`, `cmd/proxy/main.go`,
  `cmd/mock-control/fleetconfig.go`, `config.example.yaml` (`[fleet: …]` marks).
- Key types: `ConfigChangedEvent`, `ProxyConfigDocument`, `ProxyConfigReport`,
  `FleetConfigSource`, `ConfigNotifier` (`StreamOptions.Config`), `ConfigSync`,
  `ConfigApplier`; `config.Fleet`, `(*Config).WithFleet`, `FleetSettings`;
  `CachingClient.SetMaxTTL`, `proxy.Server.SetDeadlineWarning`.
- Bootstrap/fleet line: reach/identify Control, host material, listeners and
  `control.cache.stale_after` are bootstrap. 17 fleet-owned keys; only
  `control.cache.max_ttl` and `session.deadline_warning` are **live**.
- Gotcha: a document needing a restart applies **nothing** (one document per
  process); the running document is not persisted across restarts.
- NEXT (Control sync): wire `fleet.ConfigPublisher` to emit `config_changed`,
  serve the fetch with the hash as ETag, and read drift from the report.

## Details

### The four questions, answered

1. **Which settings.** The rule is in D18 and at the top of
   `internal/config/fleet.go`. The list is opt-in: a setting is bootstrap unless
   `fleetSettings` names it, so a new setting cannot become remotely settable by
   accident. `TestEveryFleetSettingIsARealKey` keeps each key a real YAML path;
   `TestTheExampleFileMarksEveryFleetSetting` keeps `config.example.yaml`'s
   `# [fleet: live|restart]` marks equal to the table. `stale_after` stays
   bootstrap for the same reason the heartbeat advertisement is tighten-only: it
   is the proxy's judgement of whether Control can be heard.
2. **How it arrives.** A notification plus a conditional fetch of the current
   document. `ConfigSync` drops a notification whose hash it already holds, and
   fetches on every stream connect and on `resync`, so a missed or replayed event
   costs at most a `304`. `TestAReplayedConfigChangedDoesNotApplyAStaleDocument`
   (in `cmd/mock-control`) drives this through the real `last_event_id` replay:
   v1 and v2 are published while the proxy is away, both are replayed, and v1 is
   never applied.
3. **The report and "running".** `Fleet.ApplyConfig` compares the new effective
   config with the one the process was **built from**. If a non-live key
   differs, it returns those keys and applies nothing. `running_*` therefore always
   names exactly one document whose every setting is in force. Startup fetches
   before building components (bounded at 5s), which is why a restart clears
   `pending_restart`.
4. **Bad documents.** Rejected whole (`ErrNotFleetOwned`, type errors, or
   `Validate`), logged, and reported with `last_error`. Error text names keys and
   never values; no fleet-owned setting is a secret anyway. A failed fetch is
   retried every 30s (`DefaultConfigRetryInterval`) and on the next
   connect or notification. The stream handler only calls the non-blocking
   notifier, so kills are never queued behind a fetch.

### Why 404 and not 401 for an unenrolled proxy

`401` is a deny *decision* throughout this contract. An unenrolled id is a
registry fact. Answering it with 401 would also make it indistinguishable from
a rejected token, which is the one case where `Subscribe` stops retrying.

### Versioning check (asked for by the prompt)

`api/control.yaml`'s `RevocationEvent.type` already said "A proxy ignores a type
it does not recognise, so the server may add types without breaking older
proxies". That sentence makes the event additive.
`TestAProxyWithoutTheTypeIgnoresConfigChanged` asserts it: a stream with no
configuration handler behaves as a pre-0042 proxy, consuming the event, staying
connected, and applying the kill that follows it.

### Mock

One document is served to every enrolled proxy. It is published only through
`POST /debug/config`, which derives the hash from the served bytes and emits the
event from the stored document. `/debug/revoke` refuses `config_changed`, so the
mock cannot announce a version it does not serve (0039's standard).
`/debug/reset` clears reports but keeps the document: rewinding it silently would
leave proxies holding a document nobody serves. `fixtures.example.yaml`
publishes one; `deploy/control/fixtures.template.yaml` publishes none, so the
e2e topology starts on `204`.

### e2e

`test/e2e/fleetconfig_test.go` ("fleet configuration", after telemetry) walks
through live applied → pending_restart → rejected (a `control.base_url`
document, followed by a session that still succeeds) → restored. It checks
`proxy-direct` and `proxy-zone`. Every value equals the proxies' bootstrap
value, so the scenario leaves the rest of the suite unaffected. **It could not
be run in this session** (no Docker daemon). CI's `e2e` job runs it first.

### Follow-ups (not queued)

- **Persisting the running document** so a restart during a Control outage
  does not fall back to the bootstrap values. It needs a new bootstrap path
  setting and a rule for trusting a stale file.
- **More live settings.** `control.cache.max_entries` (resize the LRU in place)
  and the `logging.*` knobs could apply live with work in `CachingClient` and
  `logging.Shipper`. Today they are restart-only, and they are reported that
  way.
- `cmd/loadgen`'s stand-in control does not serve the fetch, so a proxy under
  it logs a failed fetch every 30s. That is harmless, and it is the
  fail-open-to-bootstrap path working as designed.
