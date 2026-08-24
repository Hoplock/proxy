# Kickoff — starting an implementation session

Copy one of the prompts below into a **fresh** Claude Code session (the repo is
cloned fresh per session). The prompts in `prompts/queued/` are self-contained;
`docs/PROTOCOL.md` tells the session how to pick up and deliver the work.

## Default: implement the next queued prompt

```
Read docs/PROTOCOL.md and follow it. Implement the lowest-numbered prompt
in prompts/queued/. Do not start any other prompt in this session.
```

## Specific prompt (run out of order)

```
Read docs/PROTOCOL.md and follow it. Implement prompts/queued/<NNNN-name>.md.
Do not start any other prompt in this session.
```

## Downstream sync (no prompt, no number)

A **sync** is the follow-up a merged change to a shared surface owes another
repository: it updates that repository's prompts, plan, and protocol so the next
session there builds against what is now true
(`docs/CROSS-REPO-PROTOCOL.md` §3.1). It is not a phase, so it has no prompt
file and no `NNNN` — which is exactly why it needs a kickoff of its own rather
than one of the two above.

This repository is the most upstream of the three
(`docs/CROSS-REPO-PROTOCOL.md` §2: proxy → control → enterprise), so a sync
session never runs **here**. The prompt below is what a
proxy PR hands you to run in `hoplock/control` or `hoplock/enterprise`, in a
**fresh session with that repository checked out**. An upstream PR whose
`## Cross-repo impact` section names obligations is required to emit it already
filled in (that protocol's §4), so normally you paste what the PR gave you
rather than composing this by hand.

```
Read docs/CROSS-REPO-PROTOCOL.md and follow it. You are doing a downstream
sync following <upstream PR URL>. Do not implement any queued prompt in this
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
section: <the obligations, or "see the PR">.

Branch claude/sync-<short-description>, commit with the `sync` scope, and open
one PR whose body names the upstream PR, confirms it is merged, and says how
you searched for stale references — the actual grep, not "I looked carefully".
```

Fill in `<upstream PR URL>`, the obligations, and `<short-description>`. Leave
everything else alone: each remaining line is a Definition-of-Done item from
`docs/CROSS-REPO-PROTOCOL.md` §5, and dropping one is how a sync quietly turns
into an unreviewable feature PR.

## Rules of thumb

- **One session = one prompt = one PR.** Start a fresh session for each queued
  prompt. The session ends when its PR is merged (see `docs/PROTOCOL.md`).
- **Respect dependencies / ordering.** Prompts are numbered in implementation
  order and later ones assume earlier ones are merged (e.g. 0002 needs 0001).
  A fresh session branches off `main`, so it only sees **merged** work — kick off
  the next prompt after the previous PR merges. Only run prompts in parallel when
  they genuinely don't depend on each other.
- **A sync is not a phase.** One upstream change means one sync PR per affected
  repository, each in its own fresh session against that repository. Never sync
  from a session that is implementing a prompt — the two are separately
  reviewable and separately revertible.
- **Don't paste prompt bodies.** Point the session at the file in the repo so it
  reads the canonical version (numbers can change under the invariants in
  `docs/PROTOCOL.md` §6; the file is always current).
