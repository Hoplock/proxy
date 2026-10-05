# proxy-PR#21 — contract v3.1: device fields

Backfilled from [proxy#21](https://github.com/Hoplock/proxy/pull/21), which
predates the request queues: the kickoff its `## Cross-repo impact` section
handed over, verbatim. Answered by
[control#6](https://github.com/Hoplock/control/pull/6).

```
Read docs/CROSS-REPO-PROTOCOL.md and follow it. You are doing a downstream
sync following https://github.com/Hoplock/proxy/pull/21. Do not implement any
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
section: contract v3.1 adds an open "device_field." + field-name namespace to
ephemeral-account params — platform-specific route fields, opaque to the
contract, shape-validated (identifier name <=64, non-empty value <=256, <=16
per entry), declared per driver on the proxy, where a field the driver does not
declare is a SKIPPED RUNG rather than a dropped field; policy_version stays 3;
"device_field.vdom" on a FortiGate scopes an administrator to one virtual
domain, and its absence means a global administrator.

Branch claude/sync-device-fields, commit with the `sync` scope, and open
one PR whose body names the upstream PR, confirms it is merged, and says how
you searched for stale references — the actual grep, not "I looked carefully".
```
