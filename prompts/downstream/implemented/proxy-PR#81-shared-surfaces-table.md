# proxy-PR#81 — Control's public Go API in the shared-surfaces table

Queued by [proxy#81](https://github.com/Hoplock/proxy/pull/81), phase 0048. It
answered the upstream request in control#56 (which folds in enterprise#8) by
listing `ext/` and `server/` as Control's public Go API in §1 of
`docs/CROSS-REPO-PROTOCOL.md`. It also rewrote the paragraph under that table
so it states nothing about what exists or when, and made §2 say "a signature in
Control's public Go API". The change is to `docs/CROSS-REPO-PROTOCOL.md`, so the
sync is owed to `hoplock/control` and `hoplock/enterprise` both: one sync PR in
each. The obligations are its `## Cross-repo impact` section's.

```
Read docs/CROSS-REPO-PROTOCOL.md and follow it. You are doing a downstream
sync following https://github.com/Hoplock/proxy/pull/81. Do not implement any queued prompt in this
session.

Before anything else, confirm that upstream change is MERGED; if it is not,
stop and say so (§2). Then update this repository's prompts, plan, and
protocol so the next session builds against what is now true.

A sync changes text, not behaviour: it implements, enforces, and vendors
nothing, hand-edits no vendored artifact, and adds, renames, or renumbers no
prompt. Land each obligation in the prompt that will implement it, not only in
the plan. If the work seems to need something the upstream repository does not
have, that is §3.2 — never approximate it, and do not stop at telling me: name
the exact shape and queue the "Upstream request" kickoff from docs/KICKOFF.md,
filled in, in this repository's prompts/upstream/queued/ (§4.3).

The obligations to land are in the upstream PR's "## Cross-repo impact"
section: hoplock/control — (1) mirror docs/CROSS-REPO-PROTOCOL.md verbatim from
proxy#81's merge commit, and show the check in the sync PR: cmp against
hoplock/proxy's copy at that commit; (2) grep this repository's prompts, plan
and protocol for live text the new §1 makes stale, and land what it finds.
Decide about docs/PROTOCOL.md §3's "owns `ext/`, which Hoplock Enterprise
imports (M15)", since §1 now names `ext/` and `server/`. If nothing beyond the
mirror is needed, write "None beyond the mirror" in the PR: that is a finding.
hoplock/enterprise — (1) the same verbatim mirror, checked with cmp; (2) the
same grep. Decide about docs/PROTOCOL.md §3's "what to do when `ext` does not
yet expose what you need (its Section 3.2 …)", and about the E2 bullet below it,
"If `ext` does not expose what you need, raise an upstream request". That one is
about extension points, which only `ext` has, so it may already be right. If
nothing beyond the mirror is needed, write "None beyond the mirror" in the PR.

Work on the branch this session was given, whatever it is named — if the name
is yours to choose, claude/sync-<short-description>. Commit with the `sync`
scope, and open one PR whose body names the upstream PR, confirms it is merged,
names the request file this sync answers, and says how you searched for stale
references — the actual grep, not "I looked carefully".
```
