# 0049 — Tell Control which relay registrations a proxy holds

## Read first

- `docs/PROTOCOL.md`: the session workflow, especially **§3** (scope
  discipline, the dangling-reference sweep, and the table of plan indexes that
  go stale in the same PR that makes them wrong), **§4**, **§7** and **§8**.
- `docs/PLAN.md`:
  - **§2's register**, then these decisions in full:
    - **D11**: a hop is reached over a connection the *downstream* proxy
      opened, and "the route says which applies … neither proxy infers it".
      This phase is what lets the party that writes the route know which
      registrations exist. It **renders** D11; it does not amend it.
    - **D2**: the proxy originates no policy. The report is an observation. It
      grants nothing, and it never changes what this proxy does with a relay
      hop that has no live registration.
    - **D3**: this repository owns the contract and Hoplock Control vendors it
      read-only. This phase is a contract change, so it is a shared-surface
      change.
    - **D9**: JSON over HTTPS, one POST per report.
    - **D18**: only its register row and the "a bad document never takes a
      proxy out of service" rule. The configuration report is the precedent for
      a proxy→server report that is not on the data path.
  - **§3**: "Component responsibilities", the `internal/control` and
    `internal/relay` bullets. `internal/control` is the only package that talks
    to Control. `internal/relay` "decides nothing", and that stays true.
  - **§6.1**: "Connection direction (D11)", "How a hop is actually opened"
    (skim it), and "**Relay registration**" in full. The last says the
    registration "is proxy-to-proxy plumbing and not part of the Control API".
    That stays true of the registration itself. It is no longer the whole
    story, and this phase rewrites the paragraph to say what Control is told.
  - **§6.4**: only the paragraph on `config_changed` and the fail-closed rule
    under it. A failed report must not reach a session, a registration or a
    cached decision.
  - **§4.3**: only to confirm that the outage a relay hop with no registration
    produces is unchanged.
  - **§8**: conventions (licence header, contract-first).
  - **§9**: the test topology's relay nodes (`proxy-nexthop`, `proxy-zone`).
  - **§10**: this phase's row.
- `api/README.md`: "Ground rules", "Versioning" (a whole new endpoint is
  outside `policy_version`), "Hop connection direction", "Fleet configuration",
  "Mock server" with its "Fixture format" and "Mock-only endpoints" tables, and
  "Changing the contract". This phase follows steps 1–3, 5 and 6, and **not**
  step 4.
- `api/control.yaml`: `/v1/capabilities/report` and
  `CapabilityReportResponse.report_after_seconds` (the interval precedent),
  `/v1/proxies/{proxy_id}/config/report` with `ProxyConfigReport` and
  `ProxyConfigReportResponse` (the path and acceptance precedent),
  `HopMetadata.connection` and `HopMetadata.next_proxy_id`, `proxyToken`, and
  `components/responses`.
- Code, read before designing anything:
  - `internal/relay/hub.go`: `HubOptions`, `Hub`, `register`, `deregister`,
    `drop`, `closeAll`, `Registrations`, `Serve`. Also `internal/relay/doc.go`
    and `internal/relay/authz.go`'s `ProxyIDOf`. The id a registrant is
    authenticated as is the id `hop.next_proxy_id` names.
  - `internal/control/fleetconfig.go`: the path constants, `ProxyConfigPath`,
    `ReportProxyConfig`. `internal/control/configsync.go`: `ConfigSync`'s
    `poke`/`Run` loop, which is the pattern the reporter follows.
  - `internal/control/rest.go`: `post`, `statusError`, `protocolError`.
  - `internal/control/contract_test.go`: `TestSpecDocumentsEveryClientPath`
    and `TestReadmeDocumentsTheContract`.
  - `cmd/proxy/main.go`: `startRelayHub` and its caller.
  - `cmd/mock-control/fleetconfig.go`: the `enrolled` check and
    `GET /debug/config/reports`. `cmd/mock-control/server.go`: the mux and
    `handleDebugReset`. `cmd/mock-control/chain_e2e_test.go`.
  - `test/e2e/scenarios_test.go`, the relay subtests, and
    `test/e2e/fleetconfig_test.go`'s helper that reads a mock debug endpoint.
- `docs/learnings/`: read the summaries, then open
  `0008-multi-hop-routing-learnings.md` and
  `0042-fleet-config-distribution-learnings.md` in full.
- `docs/CROSS-REPO-PROTOCOL.md`: **§1, §2, §3.2, §4.1, §4.3, §5**. This phase
  answers an upstream request, so §5's "The PR that answers an upstream request
  is not a sync" binds it. Once merged, it owes a **downstream sync to every
  consuming repository, including the one that raised the request**.

## Depends on

- **Nothing hard.** 0008 built `internal/relay`, and 0042 built the report
  pattern this follows. Both are implemented.
- **0048: ordering only.** It changes no contract, so it does not move
  `info.version`. Take the **next minor above whatever `info.version` is when
  you start** (4.8.0 when this prompt was written), and do not hard-code a
  number from this prompt.

## Where this came from

An **upstream request** from `hoplock/control` (`docs/CROSS-REPO-PROTOCOL.md`
§3.2). It was raised in the `## Upstream request` section of
[Hoplock/control#162](https://github.com/Hoplock/control/pull/162), Control's
phase 0061, which built a cross-repository end-to-end topology around a real
proxy at `hoplock/proxy@97e97de`. The request file is
`prompts/upstream/queued/control-PR#162-relay-registration-report.md` in
`hoplock/control`.

**The shape requested**, quoted from #162:

> **Shape:** a proxy-to-Control report of the relay registrations a proxy
> holds. It would be sent by the *upstream* proxy, which is the one accepting
> the registration (`chain.accept`). It carries the set of downstream proxy ids
> that currently hold an outbound relay registration with it. The set
> **replaces** the previous one, so an id that is no longer reported has
> dropped. It is sent on every change, and at an interval below Control's
> `fleet.relay_registration_ttl` (default 60s). An endpoint of its own, or a
> member on an existing report, are both fine as long as it is authenticated by
> the reporting proxy's own south-bound credential (M22).
>
> **Why:** today nothing in the contract tells Control that a registration
> exists. `relay_registrations` is written only by `hoplock-control seed`, and
> `fleet.Registry.Heartbeat` (which already models `RelayRegistrations` as a
> replacement set) has no production caller.

**What downstream cannot do until it lands**, in the request's words: "in any
real deployment, a `relay` route works for one TTL (60s) after a seed and is
then refused as an outage. A registration that drops is invisible to routing."
Control's topology works around it by seeding the registration and setting
`fleet.relay_registration_ttl: 8760h`. The seam it left is
`fleet.HeartbeatReport.RelayRegistrations`.

**Why only Control can be told this, and only by the hub.** D11 has Control
choose `relay`, and Control's M6 says the same thing from its side: only Control
can choose `relay` correctly, "because only this server knows which downstream
proxies currently have a live outbound registration". It knows nothing of the
kind, because the only party holding that fact is the proxy that accepted the
registration (`chain.accept`), and nothing on this contract carries it. That
proxy's view is also the one routing needs. It is the side that opens a
`relay-session@hoplock.io` channel when a route says `relay`, so "this hub holds
a registration for X" is exactly "a relay hop from here to X can be opened". The
downstream's belief that it is registered can be wrong in the case that matters
most: a half-open connection that is still alive on its end after the hub has
dropped it.

**Checked when this prompt was written**, against `hoplock/control` at
`2a3de41` and this repository at `97e97de`:

- Control's `fleet.Registry.Heartbeat` records a `HeartbeatReport` whose
  `RelayRegistrations` it writes with `RelayRegistrations().ReplaceForUpstream`.
  The same call also stamps the proxy's health row: liveness, `SessionCount`
  and `LastError`. Nothing outside tests and `seed` calls it.
- Control's graph (`internal/fleet/graph.go`) uses a registration only to make
  a relay **edge an operator authored** usable: "The far proxy must hold a live
  outbound registration with THIS proxy. No registration, no hop — and never a
  dial instead." A registration never creates an edge.
- Control's proxy liveness does **not** depend on this. The event
  subscription is a second liveness signal (`fleet.WithSubscriptionState`), so
  a proxy holding its stream open stays routable without a heartbeat. Only the
  relay registrations have no source.
- Control's `fleet.relay_registration_ttl` defaults to 60s, and its
  `fleet.capability_report_after` is answered to proxies as
  `report_after_seconds`.
- In this repository, `relay.Hub` keeps one registration per authenticated id,
  replaces a second registration for the same id, and exposes
  `Registrations()` (unsorted). Nothing in it can say when that set changes.

## Objective

A proxy that accepts relay registrations reports the set of proxy ids
registered with it to Hoplock Control. It reports when it starts, on every
change, and at least every 20 seconds. The report never touches a session or a
registration, whether it is delivered or not. Control can then route `relay`
hops on what is true now, and stop relying on a seeded row it has to keep
believing for a year.

## The shape

### Contract (`api/control.yaml`)

**One new endpoint**, under a new tag `relay` ("the relay registrations a proxy
holds (PLAN D11)"):

```yaml
  /v1/proxies/{proxy_id}/relay-registrations/report:
    post:
      tags: [relay]
      operationId: reportRelayRegistrations
      summary: Say which proxies hold a relay registration with this one.
      parameters:
        - name: proxy_id
          in: path
          required: true
          description: The proxy making the report — the one accepting registrations.
          schema:
            type: string
          example: proxy-nexthop
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/RelayRegistrationReport'
      responses:
        '200':  # RelayRegistrationReportResponse
        '400':  # BadRequest
        '401':  # Unauthorized
        '404':  # not_enrolled, as on /config/report
        '500':  # ServerError
```

```yaml
    RelayRegistrationReport:
      type: object
      required: [registered_proxy_ids]
      properties:
        registered_proxy_ids:
          type: array
          uniqueItems: true
          items:
            type: string
            minLength: 1
          example: [proxy-zone-b]

    RelayRegistrationReportResponse:
      type: object
      required: [accepted]
      properties:
        accepted:
          type: boolean
        report_after_seconds:
          type: integer
          format: int32
          minimum: 0
```

The endpoint's description and the field descriptions must state these rules.
Each is a decision, so write it as a rule:

1. **Who sends it.** A proxy that accepts relay registrations (D11's upstream)
   sends it. A proxy that only registers with an upstream sends nothing, for
   the reason given under "Where this came from". A proxy that does both, in
   the middle of a chain, reports only the registrations it accepts.
2. **What it carries.** `registered_proxy_ids` is the **complete** set of
   proxy ids with a live registration at the reporting proxy. It is the id
   each registrant was authenticated as, which is the id a `relay` hop's
   `next_proxy_id` names. The set **replaces** the previous one: an id it no
   longer names has dropped. `[]` means the proxy holds none. The list is
   required and never `null`, so an empty set and a malformed report cannot be
   confused. Order carries no meaning, and the proxy sends it sorted.
3. **When.** When the registration listener starts, so that a restarted proxy
   clears what its previous process reported. Then on every change to the set,
   and otherwise at least every **20 seconds**. The server may shorten that
   interval with `report_after_seconds` and can never lengthen it. The ceiling
   is the proxy's: a broken server announcing a long interval would otherwise
   age every relay out of its own routing without any error being raised.
   Absent or `0` leaves the proxy on 20 seconds.
4. **What the server may do with it.** A report is an observation and grants
   nothing. A server **MUST NOT** create a relay hop from a report alone. A
   reported registration only makes usable a relay hop the server already
   models, between those two proxies. The proxy goes on refusing a `relay` hop
   it holds no registration for as an outage (PLAN §4.3), whatever the server
   believes. A server **SHOULD** stop believing a registration that has not
   been re-reported within three intervals of the one it asks for (60 seconds
   at the default). So one lost report is not a dropped relay, and a proxy
   that has gone silent is not routed through for long.
5. **Whose report it is.** The server **MUST** attribute a report to the proxy
   its credential identifies. Where that credential names a proxy, the server
   **MUST** refuse (`401`) a report whose `proxy_id` is another one. Without
   this rule, one hub could withdraw another hub's relays.
6. **Not on the data path.** No answer to this call, and no failure to make
   it, ends a session, drops a registration, refuses a connection or touches a
   cached decision. `accepted: false` is a contract violation. The proxy
   reports again on its next attempt.
7. **Versioning.** The endpoint is outside `policy_version` ("the number
   governs `/v1/authorize` and nothing else"). `info.version` moves one
   minor.

### Go (`internal/control`, `internal/relay`, `cmd/proxy`)

- **`internal/control/relayreport.go`** (new):
  - `PathRelayRegistrationReport = "/v1/proxies/{proxy_id}/relay-registrations/report"`
    and `RelayRegistrationReportPath(proxyID string) string`, built like
    `ProxyConfigReportPath` (path-escaped).
  - `RelayRegistrationReport{RegisteredProxyIDs []string}` with JSON tag
    `registered_proxy_ids`. It marshals `[]`, never `null`, for an empty set.
  - `RelayRegistrationReportResponse{Accepted bool; ReportAfterSeconds int32}`
    with tags `accepted` and `report_after_seconds,omitempty`.
  - `(*RESTClient).ReportRelayRegistrations(ctx, proxyID string, report
    *RelayRegistrationReport) (*RelayRegistrationReportResponse, error)`, shaped
    like `ReportProxyConfig`. Decoding is lenient (`post`, not `postStrict`),
    because this is not the authorize response. `accepted: false` is
    `protocolError`, and an empty `proxyID` is `ErrBadRequest`.
  - `RelayReportSink`, the one-method interface `RelayReporter` depends on, so
    it can be tested without HTTP. `*RESTClient` satisfies it.
  - `RelayReporter`, built by `NewRelayReporter(RelayReporterOptions)`:
    - options: `Sink RelayReportSink`, `ProxyID string`,
      `Registrations func() []string`, `Interval time.Duration` (zero means
      `DefaultRelayReportInterval = 20 * time.Second`), `Logger *log.Logger`,
      and an injectable clock or timer for tests, following what `ConfigSync`
      does;
    - `Changed()` is a non-blocking poke, safe from any goroutine, and
      coalesces: any number of pokes while a report is in flight cause exactly
      one more report after it;
    - `Run(ctx)` reports once at start, then on each poke, and otherwise when
      the effective interval has passed since the last **successful** report.
      The effective interval is `min(Interval, report_after_seconds)` when the
      last answer carried a non-zero value, and `Interval` otherwise.
      **At most one report is in flight.** That is what keeps a slow older
      report from landing after a newer one without adding a sequence field to
      the wire. A failed report is retried after 1s, doubling, capped at the
      effective interval. A poke triggers an attempt at once, whatever the
      backoff says;
    - every report sends the set as `Registrations()` returns it **at send
      time**, sorted and de-duplicated, and never a set queued earlier;
    - when `ctx` ends, it makes one best-effort report of `[]` on a fresh
      context bounded at **2 seconds**. The hub has closed every registration
      by then, and this saves Control waiting out three intervals. It never
      delays shutdown past that bound;
    - logging: the first failure after a success, and the first success after
      a failure, each produce one line naming the proxy id and the error class.
      Retries in between do not log. No report and no failure is an audit
      record: this is fleet plumbing, not a session event (D8).
- **`internal/relay/hub.go`**:
  - `HubOptions.OnChange func()`, optional. It is called after the **set of
    registered ids** changes: an id added, an id removed, or `closeAll`.
    Replacing the registration for an id that is already registered does not
    change the set and may call it or not. It is called **outside** `h.mu`,
    and it must not block. `RelayReporter.Changed` is non-blocking by
    construction.
  - `Registrations()` returns its ids **sorted**, so logs and tests are
    deterministic.
  - The package still imports nothing from `internal/control`. The hub reports
    a change and the reporter reads the set, which keeps "it decides nothing"
    (PLAN §3) true.
- **`cmd/proxy/main.go`**: when `startRelayHub` returns a hub, build a
  `RelayReporter` from the REST client, `cfg.Proxy.ID` and `hub.Registrations`,
  pass its `Changed` as `HubOptions.OnChange`, and run it for the life of the
  process. Start it once the registration listener is bound, and stop it after
  the hub's `Serve` has returned, so the final `[]` follows the last
  registration closing. A proxy with no hub builds no reporter.
- **No new configuration key.** The interval is the constant, and the server
  can shorten it. A key would be one more setting to classify under D18 for no
  operational gain. `config.example.yaml`'s `chain.accept` block gains one
  comment line saying a hub reports its registrations to Hoplock Control.

### Mock (`cmd/mock-control`)

- Serve `POST` on the new path. Refuse an unknown body field, a missing or
  `null` `registered_proxy_ids`, an empty id and a duplicate id with `400`, and
  an id outside `fleet_config.enrolled` with `404 not_enrolled`, on the same
  rule as the configuration endpoints. Keep the **last report per reporting
  proxy id** with the time it arrived. Answer `accepted: true`, plus
  `report_after_seconds` when the fixture sets it.
- Fixture key `relay_registrations.report_after_seconds` (absent or `0`:
  answer none).
- Mock-only `GET /debug/relay-registrations` returns the last report per proxy
  id: `{"<proxy_id>": {"registered_proxy_ids": [...], "received_at": "<RFC
  3339>"}}`. `POST /debug/reset` clears them.
- Document all three in `api/README.md`'s fixture and mock-only tables.

### Docs

- `api/README.md`: a new section, "**Relay registrations (D11, phase
  0049)**", beside "Hop connection direction". It gives the seven rules above
  in prose, with the reasoning for rules 1, 3 and 4. List the endpoint under
  "Endpoints".
- `docs/PLAN.md`:
  - **§6.1, "Relay registration"**: keep "the registration is proxy-to-proxy
    plumbing", and add a paragraph, "**What Control is told (phase 0049)**".
    It covers the hub reporting its set, when it reports, that a report can
    only make an authored relay hop usable, and that the proxy's own refusal of
    a relay hop without a registration is unchanged.
  - **D11**: add a one-paragraph "**As rendered (phase 0049)**" note at the end
    of the entry. Do not rewrite the entry.
  - **§2's register**: the D11 row. Status `new (0008)` gains "**rendered** by
    0049's relay-registration report", and **Mainly in** gains `api/`.
  - **§3**: the `internal/control` bullet gains the reporter. The
    `internal/relay` bullet gains "reports a change, never decides one".
  - **§10**: this phase's row, updated with what was delivered.

## In scope

- The endpoint, its two schemas, the `relay` tag and the `info.version` minor
  bump.
- The client method, the reporter, the hub's change hook and sorted
  `Registrations()`, and the wiring in `cmd/proxy`.
- The mock endpoint, its fixture key and its debug endpoint.
- `api/README.md` and the `docs/PLAN.md` edits listed above.
- Tests (below).

## Out of scope

- **A general proxy heartbeat** carrying session count, last error, contract
  version or declared capabilities. Control's `HeartbeatReport` models those
  fields, but its proxy liveness already has the event subscription as a
  signal, and nobody has asked for the rest. The `/config/report` description
  says Control's "enrollment and heartbeat surfaces are outside this
  contract", and that stays true: this report is not a heartbeat. If you find
  you need one, stop and say so. Do not widen this endpoint into it.
- **A report from the registering side.** See "Where this came from".
- **Registration metadata on the wire**, such as when an id registered or
  from which address. Control's seam takes ids, and nothing has asked for
  more. A later field goes beside `registered_proxy_ids`, not inside it.
- **Any change to how a relay hop fails.** `ErrNoRegistration`, the outage
  wording and the never-dial rule are untouched.
- **Making the interval a fleet-owned or bootstrap setting** (D18).
- **Anything Control does with the report** beyond the MUST/SHOULD rules the
  contract states. That is the sync's to land in Control (below).
- **0048**, or any other queued prompt.

## Acceptance criteria

- `api/control.yaml` has the endpoint, both schemas and the tag, with the seven
  rules in its descriptions. `info.version` is one minor above what you found,
  and `control.PolicyVersion` is unchanged.
- `TestSpecDocumentsEveryClientPath` lists `PathRelayRegistrationReport`
  answering `200`. The README checks name the new section and endpoint.
- A hub with `OnChange` set calls it on every add and every removal, including
  a registration dropped by keepalive, and on `closeAll`. It never calls it
  while holding `h.mu`.
- The reporter's first report goes out at start and carries `[]` when nothing
  is registered.
- A registration arriving produces a report naming it. A registration dropping
  produces a report without it. Both happen without waiting for the interval.
- Twenty pokes during one in-flight report produce **one** further report, and
  it carries the set at send time.
- With no change, a report goes out every `Interval`. With
  `report_after_seconds: 5` it goes out every 5s. With
  `report_after_seconds: 300` it still goes out every 20s.
- A failing sink (transport error, `401`, `404`, `500`, `accepted: false`)
  never drops a registration and never ends or refuses a session. A relay
  session opened while reports are failing still succeeds. Failures log once
  per transition, not per retry.
- Cancelling `Run` sends one final `[]` within 2 seconds, and returns even if
  the sink hangs.
- The mock refuses each malformed body listed above with `400`, refuses an
  unenrolled reporter with `404 not_enrolled`, and returns the last report from
  `GET /debug/relay-registrations`. `POST /debug/reset` clears it.
- In the e2e topology, `GET /debug/relay-registrations` names `proxy-zone`
  under `proxy-nexthop` once the relay scenarios run, without any fixture
  seeding it.

## Required tests

- `internal/control`: the reporter against a fake sink and a fake clock. Cover
  the start report, change-driven reports, coalescing, the interval and both
  directions of `report_after_seconds`, backoff with a poke overriding it, the
  failure classes, the final `[]` and its 2s bound, and log-once-per-transition.
  Also the client method against an `httptest` server, covering the
  `accepted: false` and `404` answers and the path escaping.
- `internal/relay`: the change hook on add, remove, keepalive drop, same-id
  replacement and shutdown, plus sorted `Registrations()`. Run it under
  `-race`.
- `cmd/mock-control`: the endpoint's validation table and the debug endpoint.
  In `chain_e2e_test.go`, a real hub, a real registrar and the real client
  with the reporter wired as `cmd/proxy` wires it. Assert the mock sees the
  registrant appear, and then disappear when the registrar stops.
- `test/e2e`: one assertion in the relay scenarios, through a helper shaped
  like `fleetconfig_test.go`'s.
- `go test ./test/docs/...` stays green.

## Definition of Done & hand-off

Per `docs/PROTOCOL.md` §4, plus what this phase owes because of where it came
from and what it touches:

- **`docs/PLAN.md`'s indexes** (§3's table): the D11 register row and §10's
  row. No decision is new, amended or withdrawn. Say so in the PR.
- **`## Cross-repo impact`** (`docs/CROSS-REPO-PROTOCOL.md` §4.1) names
  `hoplock/control` **and** `hoplock/enterprise`. Enterprise consumes Control's
  public Go API and not `api/`, and nothing in it talks to a proxy (its PLAN
  §7), so "None" is the likely answer there. Check before you write it down.
  Queue the sync as `prompts/downstream/queued/proxy-PR#<n>-relay-registration-report.md`
  (§4.3) once the PR is open.
- **Control is owed that sync even though Control asked for this** (§5, "The
  PR that answers an upstream request is not a sync"). It is the easiest one
  to skip, because Control is already waiting and knows what it asked for. But
  the session there that re-vendors the contract is a fresh one that knows
  nothing. Until it runs, Control's relay routes still live on a seeded row.
  The kickoff must list these obligations:
  - **Re-vendor** the contract at the new `info.version` (its M1).
    `policy_version` is unchanged.
  - **Serve** `POST /v1/proxies/{proxy_id}/relay-registrations/report`
    south-bound. Authenticate it with the reporting proxy's own credential,
    attribute it to the proxy that credential names, and refuse another
    proxy's id with `401` (its M22, and the contract's rule 5).
  - **Record it as the replacement set for that upstream**
    (`RelayRegistrations().ReplaceForUpstream`). Do **not** do it by calling
    `fleet.Registry.Heartbeat` with an otherwise-empty `HeartbeatReport`:
    that would stamp `SessionCount: 0` and `LastError: ""` over whatever the
    health row holds. A relay report is not a heartbeat. Whether it counts as a
    liveness signal is Control's decision under its M6. Make it, and say which.
  - **Answer `report_after_seconds`** from `fleet.relay_registration_ttl`, at
    most a third of it, so that a TTL configured below 60s still holds three
    reports.
  - **Keep the edge rule** the contract now states (a report only makes an
    authored relay edge usable). It is already true in
    `internal/fleet/graph.go`. Add a case for it, and for the endpoint's
    answers, to the conformance suite.
  - **Retire the workaround** once `deploy/PROXY_REVISION` names a proxy that
    reports: the seeded registration and `fleet.relay_registration_ttl: 8760h`
    in the e2e topology. Then add an e2e scenario where the registration ages
    out after the zone proxy stops.
  - Update its PLAN and learnings records that name this as a cross-repo
    dependency (0061's row in §10, and the "Known gaps" in its 0061 learnings)
    to say it is met, citing this repository's PR.
  - Land each obligation in the Control prompt that will implement it. If none
    is queued, say so: the sync adds no prompt (§5).
- **The learnings summary** names: the endpoint and both types, the reporter and
  its options, the hub's `OnChange`, the 20s ceiling and the server's ability to
  shorten it only, the final `[]` on shutdown, the new `info.version`, and what
  Control must change. That last item is what the sync session reads.
