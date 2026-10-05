# proxy-PR#60 — the upstream-request flow

Backfilled from [proxy#60](https://github.com/Hoplock/proxy/pull/60), which
predates the request queues: the kickoffs its `## Cross-repo impact` section
handed over, verbatim. Answered by
[control#28](https://github.com/Hoplock/control/pull/28),
[enterprise#9](https://github.com/Hoplock/enterprise/pull/9) and
[enterprise#11](https://github.com/Hoplock/enterprise/pull/11) (finished the one
sentence enterprise#9 missed).

## hoplock/control

```
Read docs/CROSS-REPO-PROTOCOL.md and follow it. You are doing a downstream
sync following https://github.com/Hoplock/proxy/pull/60. Do not implement any
queued prompt in this session.

Before anything else, confirm that upstream change is MERGED; if it is not,
stop and say so (§2). Then update this repository's prompts, plan, and
protocol so the next session builds against what is now true.

A sync changes text, not behaviour: it implements, enforces, and vendors
nothing, hand-edits no vendored artifact, and adds, renames, or renumbers no
prompt. Land each obligation in the prompt that will implement it, not only in
the plan. If the work seems to need something the upstream repository does not
have, that is §3.2 — stop and tell me rather than approximating it.

The obligations to land are in the upstream PR's "## Cross-repo impact"
section: mirror the protocol verbatim; add an "Upstream request" kickoff block
to docs/KICKOFF.md written for a repository that both sends and receives
requests; update docs/PROTOCOL.md §3, docs/learnings/README.md,
prompts/audit/cross-repo-impact.md, docs/KICKOFF.md's audit block, and
prompts/queued/0018-single-contract-version.md, all of which describe §3.2 as
stopping at telling the user.

Work on the branch this session was given, whatever it is named — if the name
is yours to choose, claude/sync-<short-description>. Commit with the `sync`
scope, and open one PR whose body names the upstream PR, confirms it is merged,
and says how you searched for stale references — the actual grep, not "I looked
carefully".
```

## hoplock/enterprise

```
Read docs/CROSS-REPO-PROTOCOL.md and follow it. You are doing a downstream
sync following https://github.com/Hoplock/proxy/pull/60. Do not implement any
queued prompt in this session.

Before anything else, confirm that upstream change is MERGED; if it is not,
stop and say so (§2). Then update this repository's prompts, plan, and
protocol so the next session builds against what is now true.

A sync changes text, not behaviour: it implements, enforces, and vendors
nothing, hand-edits no vendored artifact, and adds, renames, or renumbers no
prompt. Land each obligation in the prompt that will implement it, not only in
the plan. If the work seems to need something the upstream repository does not
have, that is §3.2 — stop and tell me rather than approximating it.

The obligations to land are in the upstream PR's "## Cross-repo impact"
section: mirror the protocol verbatim; add an "Upstream request" kickoff block
to docs/KICKOFF.md written for a repository that only ever sends requests
(nothing is downstream of it); update docs/PROTOCOL.md's cross-repo section and
the learnings README on the same terms; and sweep prompts/ and docs/PLAN.md for
text describing §3.2 as stopping at telling the user — E14's need is one of the
two cases that prompted this change, so such text is likely.

Work on the branch this session was given, whatever it is named — if the name
is yours to choose, claude/sync-<short-description>. Commit with the `sync`
scope, and open one PR whose body names the upstream PR, confirms it is merged,
and says how you searched for stale references — the actual grep, not "I looked
carefully".
```
