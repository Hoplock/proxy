# proxy-PR#66 — the algorithm profile and device configuration events (0043)

Backfilled from [proxy#66](https://github.com/Hoplock/proxy/pull/66), which
predates the request queues: the kickoff its `## Cross-repo impact` section
handed over, verbatim. Answered by
[control#39](https://github.com/Hoplock/control/pull/39).

```
Read docs/CROSS-REPO-PROTOCOL.md and follow it. You are doing a downstream
sync following https://github.com/Hoplock/proxy/pull/66. Do not implement any queued prompt in this
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
section: re-vendor api/ 4.3.0 (policy_version 4); index device.config.change (batch, info; platform, device_change_op, target_account, device_object_kind, device_field.*; empty session id for sweeps); algorithm_profile is always stamped on provisioning + device.account.mapping records; index credential_method/credential_rung (1-based) only and drop target_auth_*; policy guidance: default is the secure set, SHA-1-kex / ssh-rsa / ssh-dss-only devices need a legacy profile, found via target.algorithm_policy_unmet.

Work on the branch this session was given, whatever it is named — if the name
is yours to choose, claude/sync-<short-description>. Commit with the `sync`
scope, and open one PR whose body names the upstream PR, confirms it is merged,
and says how you searched for stale references — the actual grep, not "I looked
carefully".
```
