# proxy-PR#83 — the relay-registration report (0049)

Queued by [proxy#83](https://github.com/Hoplock/proxy/pull/83), phase 0049. It
answered the upstream request in control#162 by adding
`POST /v1/proxies/{proxy_id}/relay-registrations/report`. Through it, a relay hub
reports the complete set of proxy ids registered with it, as a replacement: at
start, on every change, and at least every 20s, an interval the server may
shorten and never lengthen. Contract **4.8.0**, `policy_version` still 6. The
sync is owed to `hoplock/control`, the repository that asked. It is not owed to
`hoplock/enterprise` ("None"). The obligations are those in the PR's
`## Cross-repo impact` section.

```
Read docs/CROSS-REPO-PROTOCOL.md and follow it. You are doing a downstream
sync following https://github.com/Hoplock/proxy/pull/83. Do not implement any queued prompt in this
session.

Before anything else, confirm that upstream change is MERGED; if it is not,
stop and say so (§2). Then update this repository's prompts, plan, and
protocol so the next session builds against what is now true.

A sync changes text, not behaviour: it implements, enforces, and vendors
nothing, hand-edits no vendored artifact, and adds, renames, or renumbers no
prompt. Land each obligation in the prompt that will implement it, not only in
the plan. If the work seems to need something the upstream repository does not
have, that is §3.2 — never approximate it, and do not stop at telling me: name
the exact shape and queue the "Upstream request" kickoff from docs/KICKOFF.md,
filled in, in this repository's prompts/upstream/queued/ (§4.3).

The obligations to land are in the upstream PR's "## Cross-repo impact"
section: (1) re-vendor at info.version 4.8.0, policy_version unchanged at 6
(M1); (2) serve POST /v1/proxies/{proxy_id}/relay-registrations/report
south-bound, authenticated by the reporting proxy's own credential, attributed
to the proxy that credential names, refusing another proxy's id with 401 (M22,
contract rule 5), with 404 not_enrolled for an unknown proxy and 400 for a
missing or null registered_proxy_ids, an empty id or a duplicate; (3) record
each report as the replacement set for that upstream with
RelayRegistrations().ReplaceForUpstream — NOT by calling
fleet.Registry.Heartbeat with an otherwise-empty HeartbeatReport, which would
stamp SessionCount 0 and LastError "" over the health row; a relay report is
not a heartbeat, and whether it counts as a liveness signal is Control's
decision under M6 — make it and say which; (4) answer report_after_seconds from
fleet.relay_registration_ttl, at most a third of it, so a TTL below 60s still
holds three reports (the proxy ignores any value above 20s); (5) keep the edge
rule the contract now states — a report only makes an authored relay edge
usable and never creates one — which internal/fleet/graph.go already does, and
add a conformance case for it and for the endpoint's answers; (6) once
deploy/PROXY_REVISION names a proxy that reports, retire the seeded
registration and fleet.relay_registration_ttl: 8760h from the e2e topology, and
add an e2e scenario where the registration ages out after the zone proxy stops
(an orderly stop sends a final [], so a scenario meant to exercise the TTL must
kill the proxy rather than stop it); (7) mark the cross-repo dependency met in
PLAN §10's 0061 row and in the 0061 learnings' "Known gaps", citing proxy#83;
(8) land each obligation in the Control prompt that will implement it, and if
none is queued, say so — the sync adds no prompt (§5).

Work on the branch this session was given, whatever it is named — if the name
is yours to choose, claude/sync-<short-description>. Commit with the `sync`
scope, and open one PR whose body names the upstream PR, confirms it is merged,
names the request file this sync answers, and says how you searched for stale
references — the actual grep, not "I looked carefully".
```
