# proxy-PR#69 — the algorithm floor and bans (0045)

Backfilled from [proxy#69](https://github.com/Hoplock/proxy/pull/69), which
predates the request queues: the kickoff its `## Cross-repo impact` section
handed over, verbatim. Answered by
[control#41](https://github.com/Hoplock/control/pull/41).

```
Read docs/CROSS-REPO-PROTOCOL.md and follow it. You are doing a downstream
sync following https://github.com/Hoplock/proxy/pull/69. Do not implement any queued prompt in this
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
section: (1) re-vendor at info.version 4.5.0 / policy_version 6 — update
0014's re-vendor step and 0018's version expectations — and never serve a
floor or ban to a proxy declaring < 6, nor strip one to fit; (2) algorithm_floor is a ranked ladder
modern-kex < pq-hybrid-kex whose nesting is the rule for new levels, and
pq-hybrid-kex is mlkem768x25519-sha256 only, never sntrup761 — fix any text
promising "either"; (3) never send a level the proxy did not declare in
capabilities.algorithm_floors, whose key_exchanges (and
capabilities.algorithms) are per-build truth; (4) TargetCapabilities.kex
comes from every method as its own report, merged by presence beside the rung
observation, and with the declarations feeds a planned impact preview and
fleet coverage view; (5) the attribute is target_kex_algorithm, not
kex_algorithm, plus algorithm_floor (omitted when none), the negotiated
target_* keys, algorithm_bans.<axis>, algorithm_bans_unmatched, the
target.algorithms_negotiated event, and algorithm_policy_cause and the
public_key_auth axis on target.algorithm_policy_unmet; (6) algorithm_bans is
per route and per axis, applied last, a ban always wins — refuse what the
proxy refuses, warn on a name no proxy declared; (7) plan the emergency
runbook (ban → cache_invalidate all → session_kill); (8) legacy-rsa-sha1 +
floor is accepted and legacy-device + floor refused — match, do not reject
more; (9) 0019's upstream-dependency section is now something to wire, not a
gap to work around.

Work on the branch this session was given, whatever it is named — if the name
is yours to choose, claude/sync-<short-description>. Commit with the `sync`
scope, and open one PR whose body names the upstream PR, confirms it is merged,
and says how you searched for stale references — the actual grep, not "I looked
carefully".
```
