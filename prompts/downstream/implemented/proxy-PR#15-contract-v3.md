# proxy-PR#15 — contract v3

Backfilled from [proxy#15](https://github.com/Hoplock/proxy/pull/15), which
predates the request queues: the kickoff its `## Cross-repo impact` section
handed over, verbatim. It never had a sync PR of its own. Answered by
[control#17](https://github.com/Hoplock/control/pull/17) (the username) and
[control#21](https://github.com/Hoplock/control/pull/21) (the rest, found by the
cross-repo audit).

```
Read docs/CROSS-REPO-PROTOCOL.md and follow it. You are doing a downstream
sync following https://github.com/hoplock/proxy/pull/15. Do not implement
any queued prompt in this session.

Before anything else, confirm that upstream change is MERGED; if it is not,
stop and say so (§2). Then update this repository's prompts, plan, and
protocol so the next session builds against what is now true.

A sync changes text, not behaviour: it implements, enforces, and vendors
nothing, hand-edits no vendored artifact, and adds, renames, or renumbers no
prompt. Land each obligation in the prompt that will implement it, not only in
the plan. If the work seems to need something the upstream repository does not
have, that is §3.2 — stop and tell me rather than approximating it.

The obligations to land are in the upstream PR's "## Cross-repo impact"
section: contract v3 is now real, so replace the placeholder wording with the
field's real name, shape, and absent-value default in each prompt that already
covers it — Contract vendoring & conformance harness (policy_version is now 3;
the low-version conformance assertion covers v2 as well as v1), Fleet registry,
health & config distribution (a proxy advertises its device platforms and
Control must not name one it has not advertised), South-bound authorize & route
(target_auth_ladder is an ORDERED ARRAY of the existing target_auth objects
beside the single object; absent means "use local config", [] is a DENIAL, both
present is REFUSED, and a one-entry ladder is how a policy refuses degradation;
ephemeral-account requires username, platform, credential_kind, expiry_posture
and lifetime_seconds with NO defaults; algorithm_profile is a named preset —
default, legacy-rsa-sha1, legacy-device; username is now REQUIRED on every
provisioning method, which changes Control's own fixtures and policy authoring),
and Audit ingest & tamper-evident store (the rung in force is recorded as
target_auth_method + target_auth_rung, plus algorithm_profile; both are
audit-only and never disclosed to the user). docs/PLAN.md §5.2 carries the same
placeholder wording and moves with the authorize prompt. Queue no new prompt: if
you find work that fits none of these, that is a roadmap revision with its own PR.

Branch claude/sync-contract-v3, commit with the `sync` scope, and open
one PR whose body names the upstream PR, confirms it is merged, and says how
you searched for stale references — the actual grep, not "I looked carefully".
```
