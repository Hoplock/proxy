# proxy-PR#25 — contract v4: enforcement points and session bounds

Backfilled from [proxy#25](https://github.com/Hoplock/proxy/pull/25), which
predates the request queues: the kickoff its `## Cross-repo impact` section
handed over, verbatim. The kickoff was handed over with its upstream-URL blank
unfilled; control#8 matched it to this PR by its obligations. Answered by
[control#8](https://github.com/Hoplock/control/pull/8).

```
Read docs/CROSS-REPO-PROTOCOL.md and follow it. You are doing a downstream
sync following <this PR's URL>. Do not implement any queued prompt in this
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
section: the authorize response can now name an enforcement rung per route on
each of two axes (what may execute, what it may reach), the absent value on
both is proxy-side enforcement only, an *applied* rung must never be chosen for
a brokered-key route while an *attested* one may be, Control now receives and
must store per-target capability reports (POST /v1/capabilities/report), and
the four session-bound fields (session_deadline as an absolute instant,
require_session_capture, grant_context, concurrency) are now real. policy_version
is 4. Re-vendor contract/ with Control's own `make contract-sync`, never by hand.

Branch claude/sync-enforcement-points, commit with the `sync` scope, and open
one PR whose body names the upstream PR, confirms it is merged, and says how
you searched for stale references — the actual grep, not "I looked carefully".
```
