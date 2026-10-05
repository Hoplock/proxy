# proxy-PR#53 — one contract version

Backfilled from [proxy#53](https://github.com/Hoplock/proxy/pull/53), which
predates the request queues: the kickoff its `## Cross-repo impact` section
handed over, verbatim. Answered by
[control#19](https://github.com/Hoplock/control/pull/19).

```
Read docs/CROSS-REPO-PROTOCOL.md and follow it. You are doing a downstream
sync following <this PR's URL>. Do not implement any queued prompt in this
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
section: the singular `target_auth` field is removed (emit `target_auth_ladder`
only); `policy_version` is now REQUIRED on an authorize request with no
absent-value default; `info.version` is 4.0.0, not 4.3.0; the version-history
sections are gone from api/control.yaml and api/README.md, so prompts reasoning
about v3.1/4.1/4.2/4.3 cite sections that no longer exist. AND, explicitly:
`policy_version` SUPPORT STAYS — this removes superseded vocabularies, not
versioning. Control keeps reading and honouring policy_version and keeps
refusing to answer above the version a proxy declares.

Work on the branch this session was given, whatever it is named — if the name
is yours to choose, claude/sync-<short-description>. Commit with the `sync`
scope, and open one PR whose body names the upstream PR, confirms it is merged,
and says how you searched for stale references — the actual grep, not "I looked
carefully".
```
