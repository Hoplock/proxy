# proxy-PR#78 — the move PR opens as a draft

Queued by [proxy#78](https://github.com/Hoplock/proxy/pull/78), which made the PR
that moves a request to `implemented/` a draft until what answered it has merged.
It changed `docs/CROSS-REPO-PROTOCOL.md`, so the sync is owed to
`hoplock/control` and `hoplock/enterprise` both: one sync PR in each. The
obligations are its `## Cross-repo impact` section's.

```
Read docs/CROSS-REPO-PROTOCOL.md and follow it. You are doing a downstream
sync following https://github.com/Hoplock/proxy/pull/78. Do not implement any queued prompt in this
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
hoplock/proxy's main; (2) in docs/KICKOFF.md's "Next cross-repo request" block,
replace the passage from "Then, in the repository the request came from"
through "never answered here." with hoplock/proxy's wording, byte for byte, so
the block stays the same in all three repositories; (3) in
prompts/downstream/README.md and prompts/upstream/README.md, the "Moved to
`implemented/`" bullet says the PR is opened as a draft and marked ready only
once the PR that answered it has merged (§4.3). hoplock/enterprise — (1) and (2)
the same; (3) in prompts/upstream/README.md, the same change to its "Moved to
`implemented/`" bullet, keeping its following sentences about Control phase
numbers; its prompts/downstream/README.md is always empty and has no such
bullet.

Work on the branch this session was given, whatever it is named — if the name
is yours to choose, claude/sync-<short-description>. Commit with the `sync`
scope, and open one PR whose body names the upstream PR, confirms it is merged,
names the request file this sync answers, and says how you searched for stale
references — the actual grep, not "I looked carefully".
```
