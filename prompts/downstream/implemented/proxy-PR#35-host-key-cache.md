# proxy-PR#35 — contract 4.1: the host-key cache hint

Backfilled from [proxy#35](https://github.com/Hoplock/proxy/pull/35), which
predates the request queues: the kickoff its `## Cross-repo impact` section
handed over, verbatim. Answered by
[control#12](https://github.com/Hoplock/control/pull/12).

```
Read docs/CROSS-REPO-PROTOCOL.md and follow it. You are doing a downstream
sync following https://github.com/Hoplock/proxy/pull/35. Do not implement any
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
section: HostKeyReportResponse gains an optional `cache` CacheHint (contract
4.1); the proxy keys reuse on target + target_port + host_key.fingerprint and
nothing wider; a `reject` and a `known: false` response are never reused
however they are hinted; a subject-scoped cache_invalidate does not drop
host-key decisions, so use the decision's key or resync; the contract document
version moves 4.0.0 -> 4.1.0 while policy_version stays 4; nothing was renamed
or removed.

Work on the branch this session was given. Commit with the `sync` scope, and
open one PR whose body names the upstream PR, confirms it is merged, and says
how you searched for stale references — the actual grep, not "I looked
carefully".
```
