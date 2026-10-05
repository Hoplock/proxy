# proxy-PR#72 — the per-profile offer declaration (0047)

Backfilled from [proxy#72](https://github.com/Hoplock/proxy/pull/72), which
predates the request queues: the kickoff its `## Cross-repo impact` section
handed over, verbatim. Answered by
[control#43](https://github.com/Hoplock/control/pull/43).

```
Read docs/CROSS-REPO-PROTOCOL.md and follow it. You are doing a downstream
sync following https://github.com/Hoplock/proxy/pull/72. Do not implement any queued prompt in this
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
section: (1) re-vendor at info.version 4.7.0, policy_version unchanged at 6 —
update 0014's re-vendor step and its "re-vendored at 4.6.0", 0018's "at least
4.6.0" and PLAN's "Upstream is at 4.6.0"; 0014 item 1's contract types gain
AlgorithmProfileCapability, whose profile enum joins TestEnumsMatchContract;
(2) wire 0014 item 4's seam ("each build's offer per profile and per axis") to
capabilities.algorithm_profiles and algorithm_floors by the rule in
api/README.md "Capability advertisement", the curve25519 step included —
"unknown" only for a proxy whose declaration omits the profile or the field,
legacy-device judged from its own entry; if 0014 is implemented by then, land
it in the queued prompt that owns the seam; (3) refuse exactly what the proxy
refuses, per proxy, since declarations are per build — decide under M17
whether the author sees a refusal or a per-build finding, and say which; never
copy the lists into code; (4) record the declaration per proxy within M5
beside algorithm_floors if the fleet view (0016) shows per-build offers; (5)
answer 0014 item 2's Declares() question for a profiles-only declaration the
same way as for a floor-only one; (6) mark the cross-repo dependency met in
PLAN §5.2 and §10's 0014 row, citing the upstream PR.

Work on the branch this session was given, whatever it is named — if the name
is yours to choose, claude/sync-<short-description>. Commit with the `sync`
scope, and open one PR whose body names the upstream PR, confirms it is merged,
and says how you searched for stale references — the actual grep, not "I looked
carefully".
```
