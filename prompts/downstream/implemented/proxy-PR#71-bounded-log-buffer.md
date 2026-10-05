# proxy-PR#71 — the bounded log buffer and refused records (0046)

Backfilled from [proxy#71](https://github.com/Hoplock/proxy/pull/71), which
predates the request queues: the kickoff its `## Cross-repo impact` section
handed over, verbatim. Answered by
[control#42](https://github.com/Hoplock/control/pull/42).

```
Read docs/CROSS-REPO-PROTOCOL.md and follow it. You are doing a downstream
sync following https://github.com/Hoplock/proxy/pull/71. Do not implement any queued prompt in this
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
section: (1) re-vendor at info.version 4.6.0, policy_version unchanged at 6 —
update 0014's re-vendor step (written for 4.5.0) and 0018's "at least 4.5.0";
(2) accept session_id "" on EVERY kind, as the contract now requires — rewrite
0014 item 1, which widens audit.Parse's exemption only to device.config.change,
and correct PLAN §7's "an error record for a sweep failure": the proxy's
device.account.sweep_failed is policy_decision, critical, priority path, and
today's Control refuses it; (3) store and index logging.gap (kind: error) by
session, gap_cause and span — every key in api/README.md's "When records do
not arrive" is query surface; (4) say in PLAN §7 what a gap in a proxy's
stream looks like: evicted = Control never received the records, refused =
Control refused them itself and the proxy keeps them only up to its window,
evicting them first of all classes, and a session may carry two reports of
one cause; (5) revisit the two PLAN §7 claims that assumed a refused batch is
retried forever — the reason for the "" rule and the reason an unknown kind is
refused "loudly": a 400 now costs exactly the refused record, set aside and
reported in a logging.gap, and "loud" now means that record. Likely homes:
0014 (1, 2, 3), PLAN §7 (2, 4, 5), 0016 (the audit view of a gap), 0018 (1).

Work on the branch this session was given, whatever it is named — if the name
is yours to choose, claude/sync-<short-description>. Commit with the `sync`
scope, and open one PR whose body names the upstream PR, confirms it is merged,
and says how you searched for stale references — the actual grep, not "I looked
carefully".
```
