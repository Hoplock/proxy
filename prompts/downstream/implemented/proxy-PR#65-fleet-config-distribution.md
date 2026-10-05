# proxy-PR#65 — fleet configuration distribution (0042)

Backfilled from [proxy#65](https://github.com/Hoplock/proxy/pull/65), which
predates the request queues: the kickoff its `## Cross-repo impact` section
handed over, verbatim. Answered by
[control#37](https://github.com/Hoplock/control/pull/37) and
[control#38](https://github.com/Hoplock/control/pull/38) (three gaps left for
0014).

```
Read docs/CROSS-REPO-PROTOCOL.md and follow it. You are doing a downstream
sync following https://github.com/Hoplock/proxy/pull/65. Do not implement any queued prompt in this
session.

Before anything else, confirm that upstream change is MERGED; if it is not,
stop and say so (§2). Then update this repository's prompts, plan, and
protocol so the next session builds against what is now true.

A sync changes text, not behaviour: it implements, enforces, and vendors
nothing, hand-edits no vendored artifact, and adds, renames, or renumbers no
prompt. Land each obligation in the prompt that will implement it, not only in
the plan. If the work seems to need something the upstream repository does not
have, that is §3.2 — stop and tell me rather than approximating it.

The obligations to land are in the upstream PR's "## Cross-repo impact"
section: re-vendor contract 4.2.0; wire fleet.ConfigPublisher to emit config_changed {version, hash} and serve GET /v1/proxies/{proxy_id}/config (ETag = hash; 304 on If-None-Match; 204 none published; 404 not_enrolled); record POST /v1/proxies/{proxy_id}/config/report and drive drift/last_error from running_* and state; publish only D18 fleet-owned keys; add pdpconform cases for the fetch answers and the report.

Work on the branch this session was given, whatever it is named — if the name
is yours to choose, claude/sync-<short-description>. Commit with the `sync`
scope, and open one PR whose body names the upstream PR, confirms it is merged,
and says how you searched for stale references — the actual grep, not "I looked
carefully".
```
