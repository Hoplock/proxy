# proxy-PR#8 — a runnable sync kickoff

Backfilled from [proxy#8](https://github.com/Hoplock/proxy/pull/8), which
predates the request queues: the kickoffs its `## Cross-repo impact` section
handed over, verbatim. Answered by
[control#4](https://github.com/Hoplock/control/pull/4) and
[enterprise#3](https://github.com/Hoplock/enterprise/pull/3).

## hoplock/control

```
Read docs/CROSS-REPO-PROTOCOL.md and follow it. You are doing a downstream
sync following https://github.com/Hoplock/proxy/pull/8. Do not implement any
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
section: mirror docs/CROSS-REPO-PROTOCOL.md verbatim, and add a "Downstream
sync" section to this repository's docs/KICKOFF.md carrying the same fenced
prompt, with the surrounding prose adjusted — a sync does run here, and this
repository is upstream of enterprise, so it emits kickoffs as well.

Branch claude/sync-runnable-sync-kickoff, commit with the `sync` scope, and
open one PR whose body names the upstream PR, confirms it is merged, and says
how you searched for stale references — the actual grep, not "I looked
carefully".
```

## hoplock/enterprise

```
Read docs/CROSS-REPO-PROTOCOL.md and follow it. You are doing a downstream
sync following https://github.com/Hoplock/proxy/pull/8. Do not implement any
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
section: mirror docs/CROSS-REPO-PROTOCOL.md verbatim, and add a "Downstream
sync" section to this repository's docs/KICKOFF.md carrying the same fenced
prompt, with the surrounding prose adjusted — this repository is the most
downstream of the three, so a sync always runs here and it emits none.

Branch claude/sync-runnable-sync-kickoff, commit with the `sync` scope, and
open one PR whose body names the upstream PR, confirms it is merged, and says
how you searched for stale references — the actual grep, not "I looked
carefully".
```
