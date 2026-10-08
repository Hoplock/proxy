# Kickoff — starting an implementation session

Copy one of the prompts below into a **fresh** Claude Code session (the repo is
cloned fresh per session). The prompts in `prompts/queued/` are self-contained;
`docs/PROTOCOL.md` tells the session how to pick up and deliver the work.

Three of the blocks below are not phases, and `docs/CROSS-REPO-PROTOCOL.md` —
not `docs/PROTOCOL.md` — governs all three. A **downstream sync** and an
**upstream request** have no numbered prompt: a PR that owes one fills its block
in and queues it as a file (that protocol's §4.3), and nobody pastes them. The
**next cross-repo request** is the block you paste, and it answers the oldest of
those files across all three repositories. None of the three is ever "next" in
`prompts/queued/`.

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

## Next cross-repo request (all three repositories)

Every sync and request `docs/CROSS-REPO-PROTOCOL.md` owes waits as a file in one
of the three repositories' `prompts/downstream/queued/` or
`prompts/upstream/queued/`, named after the PR that raised it (that protocol's
§4.3). This kickoff answers the **oldest** of them, in a **fresh session with
`hoplock/proxy`, `hoplock/control` and `hoplock/enterprise` all checked out** —
which is why it is the same block in all three repositories' copies of this file.

```
Read docs/CROSS-REPO-PROTOCOL.md and follow it — §4.3 above all. This
session has hoplock/proxy, hoplock/control and hoplock/enterprise checked
out. Answer the OLDEST queued cross-repo request across the three, and only
that one. Do not implement any numbered prompt in this session.

Find it with §4.3's command: every file in prompts/upstream/queued/ and
prompts/downstream/queued/ on main of each repository, oldest first by when
it reached main. Skip any that an open PR is already answering, and say
which. If none is left, say so and stop.

Where the file is names the work: the repository it is in raised it, and
§4.3's table turns that and its folder into the repository the work is done
in — the target. The file is a kickoff written for a session in the target,
so "this repository" in it means the target, and every rule it points to is
the target's.

Do what the file says, in the target, and open there the PRs it asks for —
a sync PR per repository it names, or one PR that queues one prompt — each
naming the request file. Then, in the repository the request came from, open
one PR that moves the file from queued/ to implemented/ (same name, contents
unchanged), names the PRs that answered it, and says to merge it last. A
need you turn up on the way is queued as §4.2 says, never answered here.

Work on the branch this session was given in each repository, whatever it is
named.
```

Paste it as is: it has no blanks, because the queue says what to do. To answer
one request out of order, replace its second paragraph with that file's
repository and path. One request per session, for the same reason as one prompt
per session — then run it again for the next.

## Downstream sync (no number — queued, never pasted)

A **sync** is the follow-up a merged change to a shared surface owes another
repository: it updates that repository's prompts, plan, and protocol so the next
session there builds against what is now true
(`docs/CROSS-REPO-PROTOCOL.md` §3.1). It is not a phase, so it has no numbered
prompt and no `NNNN` — which is exactly why it needs a block of its own rather
than one of the two at the top.

This repository is the most upstream of the three
(`docs/CROSS-REPO-PROTOCOL.md` §2: proxy → control → enterprise), so a sync is
never answered **here** — only owed from here. A proxy PR whose
`## Cross-repo impact` section names obligations fills the block below in and
queues it as `prompts/downstream/queued/proxy-PR#<n>-<short-description>.md`
(that protocol's §4.1, §4.3), committed once the PR is open, since the name
carries its number. The kickoff above then answers it in `hoplock/control` — and
in `hoplock/enterprise` too, when the change is to
`docs/CROSS-REPO-PROTOCOL.md`.

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
have, that is §3.2 — never approximate it, and do not stop at telling me: name
the exact shape and queue the "Upstream request" kickoff from docs/KICKOFF.md,
filled in, in this repository's prompts/upstream/queued/ (§4.3).

The obligations to land are in the upstream PR's "## Cross-repo impact"
section: <the obligations, or "see the PR">.

Work on the branch this session was given, whatever it is named — if the name
is yours to choose, claude/sync-<short-description>. Commit with the `sync`
scope, and open one PR whose body names the upstream PR, confirms it is merged,
names the request file this sync answers, and says how you searched for stale
references — the actual grep, not "I looked carefully".
```

Fill in `<upstream PR URL>` and the obligations — each repository's under its
name, when the PR owes both. Leave everything else alone: each remaining line is
a Definition-of-Done item from `docs/CROSS-REPO-PROTOCOL.md` §5, and dropping
one is how a sync quietly turns into an unreviewable feature PR.

The branch line has no blank to fill: a sync session is normally started with a
branch already assigned, and renaming it is neither possible nor worth a
paragraph in the PR (`docs/CROSS-REPO-PROTOCOL.md` §5, `docs/PROTOCOL.md` §2).
What identifies the sync is the PR body naming the upstream change and the
request file it answers.

## Upstream request (arrives here from downstream)

The mirror of the block above, and the one answered here. A **request** is what
a downstream repository owes upstream when it needs a shape that does not exist
yet: `hoplock/control` needs a contract field the proxy has not defined, or
`hoplock/enterprise` needs a seam Control has not exposed
(`docs/CROSS-REPO-PROTOCOL.md` §3.2, §4.2).

This repository is the most upstream of the three, so requests only ever
**arrive** here, and only from `hoplock/control` — Enterprise's go to Control
even when they turn out to be the proxy's (that protocol's §4.3). A Control PR
whose `## Upstream request` section names a need fills the block below in and
queues it as `prompts/upstream/queued/control-PR#<n>-<short-description>.md` in
its own repository; the "Next cross-repo request" kickoff above answers it here.

**What it produces is a queued prompt, not the change.** What arrives is a *need*,
described by somebody who navigated this repository's plan only far enough to be
blocked by it. Turning that into a specified phase is this repository's own work,
and it is why the session below stops at the prompt: a downstream author who wrote
the prompt too would be specifying a phase against an architecture they have not
read.

```
Read docs/PROTOCOL.md and follow it. You are turning an upstream request from
<requesting repo> into a queued prompt. The request is in <downstream PR URL>,
under "## Upstream request". Do not implement any queued prompt in this session,
and do not implement this one.

Read that section, then this repository's docs/PLAN.md — its section headings and
its decision register — far enough to place the work: which sections and which D
decisions the phase touches, and whether an existing decision already settles
part of it. The requester could not do this, which is the whole reason the
request stops at a need.

Write ONE self-contained prompt into prompts/queued/ per docs/PROTOCOL.md §7 —
a "Read first" block naming plan sections by § and decisions by D id, in-scope
and out-of-scope items, the exact files and shapes, acceptance criteria and
required tests. Cite the requesting repository's decision ids by id (M* for
control, E* for enterprise), never restated (docs/CROSS-REPO-PROTOCOL.md §1).

Queue it where it should run, never simply last: the default kickoff takes the
lowest-numbered prompt, so its number is when it runs. Read the queued prompts
and put it in the best order to run them in — after everything it depends on,
before everything that depends on it, and early when nothing queued has a
better claim, since the requesting repository is waiting on it. Renumber the
queued prompts after it as docs/PROTOCOL.md §6 says, in this PR. The other
repositories cite these numbers: grep them, and name every citation the
renumbering leaves stale under "## Cross-repo impact", with its sync queued
(docs/CROSS-REPO-PROTOCOL.md §4.1).

Two things the prompt MUST carry, because they are what the request is for:
- the exact shape asked for, in this repository's own vocabulary, and what
  downstream is unable to do until it exists;
- that the phase implementing it owes a downstream sync to EVERY consuming
  repository once merged — including the one that raised the request, which is
  the one most easily forgotten because it is already waiting
  (docs/CROSS-REPO-PROTOCOL.md §5, "The PR that answers an upstream request is
  not a sync").

If the request cannot be met as asked — it contradicts a D decision, or the
shape is wrong for reasons the requester could not see — say so and propose the
alternative rather than queueing a prompt you expect to be wrong. A request is a
need, not an instruction, and the answer "not like that, like this" is a real
outcome.

Work on the branch this session was given, whatever it is named — if the name is
yours to choose, claude/NNNN-short-description matching the prompt you add. Open
one PR whose body names the downstream PR the request came from and the request
file this answers, quotes the shape requested, and says where in the queue you
put it and why.
```

Fill in `<requesting repo>` and `<downstream PR URL>` and leave the rest alone. The
two most droppable paragraphs are the two that matter: reading the plan before
writing the prompt, and the reminder that the phase owes a sync **back**. Dropped,
you get a prompt specified from outside this repository's architecture, and a
change that lands here and is never vendored by the repository that asked for it.

## Rules of thumb

- **One session = one prompt = one PR.** Start a fresh session for each queued
  prompt. The session ends when its PR is merged (see `docs/PROTOCOL.md`).
- **Respect dependencies / ordering.** Prompts are numbered in implementation
  order and later ones assume earlier ones are merged (e.g. 0002 needs 0001).
  A prompt you add is numbered where it should run, never simply last
  (`docs/PROTOCOL.md` §6). A fresh session branches off `main`, so it only sees
  **merged** work — kick off the next prompt after the previous PR merges. Only
  run prompts in parallel when they genuinely don't depend on each other.
- **A request is not a phase either, and it produces one rather than being one.**
  An upstream request arrives as a need and leaves as a queued prompt; the phase
  that implements it is a later, separate session. Never let the two collapse —
  a session that writes the prompt and then implements it has reviewed its own
  specification.
- **A sync is not a phase.** One upstream change means one sync PR per affected
  repository, opened by the session that answers its queued request — never by
  a session that is implementing a prompt: the two are separately reviewable and
  separately revertible.
- **Cross-repo work is answered oldest first, one request per session.** Queue
  it from the PR that owes it; never paste a kickoff out of a PR body or a chat
  reply instead. A request that skips the queue is one nothing will list when it
  is still undone.
- **Don't paste prompt bodies.** Point the session at the file in the repo so it
  reads the canonical version (numbers can change under the invariants in
  `docs/PROTOCOL.md` §6; the file is always current).
