# proxy-PR#36 — the branch rule and the protocol's own direction rule

Backfilled from [proxy#36](https://github.com/Hoplock/proxy/pull/36), which
predates the request queues: the kickoff its `## Cross-repo impact` section
handed over, verbatim. It handed over the same kickoff twice, once per
repository. Answered by [control#11](https://github.com/Hoplock/control/pull/11)
and [enterprise#5](https://github.com/Hoplock/enterprise/pull/5).

```
Read docs/CROSS-REPO-PROTOCOL.md and follow it. You are doing a downstream
sync following https://github.com/Hoplock/proxy/pull/36. Do not implement any
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
section: mirror the updated docs/CROSS-REPO-PROTOCOL.md verbatim (its header
note, §1, §2, §4, §5 and §6 changed — two fixes, the branch-name rule and the
removal of the "same change-set" instruction that contradicted §2 and §3.1);
make the equivalent edit to this repository's own docs/PROTOCOL.md §2 — a
session uses the branch it was given, that is not a deviation and is not
written up as one, the chosen-name form stays for when a name is actually
chosen, and the never-push-to-main / never-stack-on-merged-history invariants
are unchanged; and update this repository's own docs/KICKOFF.md sync block and
any other kickoff text that asks for a branch name a session cannot set.

Work on the branch this session was given. Commit with the `sync` scope, and
open one PR whose body names the upstream PR, confirms it is merged, and says
how you searched for stale references — the actual grep, not "I looked
carefully".
```
