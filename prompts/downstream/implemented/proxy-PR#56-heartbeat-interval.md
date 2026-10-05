# proxy-PR#56 — the heartbeat interval and what the contract cannot grade

Backfilled from [proxy#56](https://github.com/Hoplock/proxy/pull/56), which
predates the request queues: the kickoff its `## Cross-repo impact` section
handed over, verbatim. Answered by
[control#23](https://github.com/Hoplock/control/pull/23).

```
Read docs/CROSS-REPO-PROTOCOL.md and follow it. You are doing a downstream
sync following https://github.com/hoplock/proxy/pull/56. Do not implement any
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
section: re-vendor contract/control.yaml and contract/UPSTREAM via
`make contract-sync REF=<merge commit>`; add
RevocationEvent.HeartbeatIntervalSeconds plus its absent-value resolver to
internal/contract (resolve.go); change cmd/pdpconform's heartbeat case to read
the advertised interval off the stream, fall back to the expectation file only
when the server advertises nothing, and assert both that heartbeats arrive
within the advertised interval and that the advertised interval is within the
10s ceiling; remove the open-ambiguity paragraph from cmd/pdpconform/README.md;
and update cmd/pdpconform/README.md and
docs/learnings/0002-contract-vendoring-and-conformance-learnings.md so the
second ambiguity (no publish/read-back surface) cites the contract's answer
instead of reporting a gap.

Work on the branch this session was given, whatever it is named — if the name
is yours to choose, claude/sync-<short-description>. Commit with the `sync`
scope, and open one PR whose body names the upstream PR, confirms it is merged,
and says how you searched for stale references — the actual grep, not "I looked
carefully".
```
