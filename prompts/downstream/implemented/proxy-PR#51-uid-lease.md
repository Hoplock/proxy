# proxy-PR#51 — contract 4.3: the uid lease

Backfilled from [proxy#51](https://github.com/Hoplock/proxy/pull/51), which
predates the request queues: the kickoff its `## Cross-repo impact` section
handed over, verbatim. Answered by
[control#16](https://github.com/Hoplock/control/pull/16).

```
Read docs/CROSS-REPO-PROTOCOL.md and follow it. You are doing a downstream
sync following https://github.com/Hoplock/proxy/pull/51. Do not implement any
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
section: contract 4.3 adds POST /v1/uids/lease (UIDLeaseRequest /
UIDLeaseResponse); Control must hold a per-target uid allocation cursor,
advanced under a lock on grant, that ONLY EVER ADVANCES — a granted block is
never granted again, used, abandoned or expired alike, so there is no release
call and nothing is ever reclaimed; a Control that does not implement the
endpoint refuses every ephemeral-user route, because the proxy fails closed;
and the reasoning that must survive into this repository's documents is why the
uid floor is NOT a field on the cacheable authorize response.

Work on the branch this session was given, whatever it is named — if the name
is yours to choose, claude/sync-<short-description>. Commit with the `sync`
scope, and open one PR whose body names the upstream PR, confirms it is merged,
and says how you searched for stale references — the actual grep, not "I looked
carefully".
```
