# proxy-PR#41 — contract 4.2: username required

Backfilled from [proxy#41](https://github.com/Hoplock/proxy/pull/41), which
predates the request queues: the kickoff its `## Cross-repo impact` section
handed over, verbatim. Answered by
[control#17](https://github.com/Hoplock/control/pull/17).

```
Read docs/CROSS-REPO-PROTOCOL.md and follow it. You are doing a downstream
sync following https://github.com/Hoplock/proxy/pull/41. Do not implement any
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
section: contract v4.2 makes `username` REQUIRED on `brokered-key`, so it is
now required on every method the contract defines; a route omitting it is
refused by the proxy at the first authorize call, in both the single-object
and the ladder shape. `policy_version` stays 4 — this is a break announced in
the versioning section, not a gated addition. Land it in "South-bound
authorize & route", which already carries the v3 `username` requirement for
ephemeral-user/ephemeral-account/static-key: this extends that text, it adds
nothing new, so queue no prompt. Also check "Contract vendoring & conformance
harness" for a conformance case asserting a `brokered-key` response shape with
no `username`.

Work on the branch this session was given, whatever it is named — if the name
is yours to choose, claude/sync-<short-description>. Commit with the `sync`
scope, and open one PR whose body names the upstream PR, confirms it is merged,
and says how you searched for stale references — the actual grep, not "I looked
carefully".
```
