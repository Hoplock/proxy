# Hoplock Proxy — Session Protocol

> **Every implementation session MUST read this file first, in full.** It is
> short by design. It tells a fresh Claude Code session exactly how to pick up
> work, implement one prompt, and hand off cleanly to the next session.

This protocol exists to keep sessions consistent, keep context windows small
(target **< 60% context per session**), and reduce hallucination by grounding
every session in the same durable artifacts.

To start a session, see `docs/KICKOFF.md` for the exact kickoff prompt to paste.

---

## 0. TL;DR of a session

1. Read this protocol.
2. Navigate `docs/PLAN.md` (the architecture source of truth) — its section
   index, then the sections and decisions your prompt names. Not front to back
   (§1).
3. Read the **summary block** of each file in `docs/learnings/` (read a full
   learnings file only if it's relevant to your prompt).
4. Take the **lowest-numbered** prompt in `prompts/queued/` (unless the user
   names a specific one). That prompt is your entire task.
5. Create a fresh branch off the default branch.
6. Implement the prompt. Keep it in scope. Meet the Definition of Done.
7. Move the prompt file from `prompts/queued/` to `prompts/implemented/`
   (unchanged name) **in the same PR**.
8. Write a learnings file to `docs/learnings/`.
9. Open a PR. Iterate with the user until they are happy — and once it is green
   and mergeable, **go idle and wait** rather than polling it (§8).
10. **The session ends when the PR is merged** — confirm it in a line and stop.
    Say each thing once: the learnings file and the PR description are the
    records, and chat is not a third copy of them (§8).

---

## 1. Startup reading order (context budget)

Read in this order and **stop reading as soon as you have what you need**:

1. `docs/PROTOCOL.md` — this file, always, in full. It is the **only** file on
   this list you read whole; it is short by design so that it can be.
2. `docs/PLAN.md` — the architecture, and never re-derived. It is ~50k tokens,
   so it is read by **navigation, not front to back**:
   - `grep -n "^#\{1,3\} " docs/PLAN.md` prints the section index (~270 tokens).
     Start there, every time.
   - Read the sections and decisions your prompt's "Read first" names — a
     decision by id (`grep -n '^- \*\*D13 ' docs/PLAN.md`), a section by range
     (`sed -n '/^### 5.3/,/^## 6/p' docs/PLAN.md`).
   - **Three indexes inside the plan answer most questions without the body**,
     and each says what it does not cover. §2's **decision register** — what
     each `D` settles, whether it still says that, and where it is rendered.
     §5.3's **"What is true today"** — the composed current state of the device
     seam, which is otherwise eight append-only layers deep. §10's **composed
     mapping** — what an old prompt number resolves to, so you never compose
     the renumbering notes by hand. Use them the way you use a learnings
     summary: read the index, open the body only when you are changing that
     area or need the reasoning.
   - **Widen whenever you are about to make an architectural choice and cannot
     find that the plan already made it.** Budget is never a reason to guess: a
     re-derived decision is the exact failure this file exists to prevent, and
     §9 makes the plan authoritative over your memory.
   - A prompt that names no sections is a **defective prompt** (§7), not a
     licence to read everything. Say so, and navigate from the index.
3. `docs/learnings/*` — read **only the summary block** at the top of each file
   first. Open the full body of a learnings file **only** when its summary shows
   it's relevant to your prompt (e.g. you touch the same package or interface).
4. Your target prompt in `prompts/queued/`.

**Why PLAN.md is navigated rather than read.** This said "always, in full"
until the plan outgrew it. §5 alone is now ~12k tokens and §6 another ~12k, so
obeying that literally spends most of a session's budget before the prompt is
even opened, on sections the phase will never touch — and a session that has
burned its budget reading is exactly the one that then does thin work. What the
rule was protecting is the **authority** of the plan, not its page count, and
that survives navigation intact: §7 already requires every prompt to name the
sections it needs, and they do.

Do **not** read the whole codebase either. Read the specific files your prompt
names, plus what those files import. If you find yourself reading broadly, stop
and re-scope — the prompt or a learnings file should already point you at the
right places. Staying under ~60% context is a hard goal; if you're approaching
it, prefer finishing a smaller, correct slice over reading more.

**Know what step 3 costs you.** With PLAN.md navigated, the summary blocks are
the largest fixed cost at startup — ~17k tokens across 30 files today, and one
file longer every phase. They are still worth it (that is the whole hand-off
channel, §5), but keep yours **tight**: a summary block that sprawls is charged
to every session that follows, forever.

---

## 2. Branching

- Branch off the **latest default branch** (`main`): 
  `git fetch origin main && git checkout -B <branch> origin/main`.
- **Use the branch the session was given.** These sessions are normally started
  with one already assigned — `claude/queued-prompt-implementation-<suffix>` or
  similar — and it is not yours to rename. **That is not a deviation and must
  not be written up as one.** Phases 0001, 0002 and 0004 each recorded it as a
  deviation before this rule said otherwise, which is three sessions spending a
  reviewer's attention on a fact about the harness rather than about the change.
- **When the name *is* yours to choose**, use `claude/NNNN-short-description`
  matching the prompt (e.g. `claude/0003-user-auth`), or
  `claude/sync-<short-description>` for a cross-repo sync
  (`docs/CROSS-REPO-PROTOCOL.md` §5).
- **The PR carries what the name was meant to carry.** §8 already requires the
  PR description to state which prompt it implements, and that is the link a
  reviewer and a future session actually follow. A name that cannot be chosen
  cannot be relied on to identify anything, so nothing relies on it.
- **Never push to `main`.** Never push to another prompt's or another session's
  branch.
- If a prior PR for your branch name was already merged, start fresh from `main`
  (do not stack on merged history).

---

## 3. Doing the work

- **Scope discipline.** Implement exactly what the prompt specifies. If you
  discover work that belongs to a later phase, do **not** do it here — note it in
  your learnings file and/or add a new queued prompt (Section 6).
- **Follow the plan.** Match `docs/PLAN.md`: package layout, interfaces, naming,
  decisions (D1–D17, including D5a and D6a). If reality forces a deviation,
  update `docs/PLAN.md` in the **same PR** and call it out in the PR description
  and learnings.
- **Cross-repo changes follow `docs/CROSS-REPO-PROTOCOL.md`.** This repo owns
  the contract Hoplock Control vendors (D3), so a change under `api/` creates an
  obligation in another repository — and that work has no prompt number, so
  nothing in *this* file covers it. That one does: the ordering (upstream merges
  first), the downstream-impact check your PR owes — including the ready-to-run
  sync kickoff it must hand the user for each affected repository (§4) — and the
  conventions for a sync PR. It lists the shared surfaces in its Section 1; if
  your change touches none of them, you do not need to read it.
- **A rename is not done until nothing points at the old name.** Renaming or
  deleting a path, file, exported identifier, config key, or make target leaves
  dangling references that nothing fails to compile over. A queued prompt that
  sends a future session to a directory you deleted costs that session more than
  the rename saved it. So before requesting merge, grep the **whole repository**
  for the old name — `prompts/`, `docs/`, `README.md`, `Makefile`, the
  workflows, and code comments — not just the package you were working in.

  Two kinds of hit, handled differently:
  - a **live reference** — anything a future session would follow — is updated;
  - a **historical record** is not rewritten. A learnings file describes what
    its phase shipped and stays true to that; give it a one-line pointer to the
    new name instead of editing its body.

  `docs/CROSS-REPO-PROTOCOL.md` §4 asks for the same grep across consuming
  repositories, but only for a change to a **shared surface** — and its §1 tells
  you to stop reading when your change touches none. This rule is the local half
  and it applies to **every** rename. Phase 0012 renamed `deploy/sshd/` to
  `deploy/target/`, touched no shared surface, and left a queued prompt and two
  test comments pointing at a directory it had just deleted.

- **Match the codebase.** Mirror existing structure, naming, error handling, and
  test style. Add the per-file license header (see PLAN §8).
- **No secrets in code or logs.** Never log the initial-auth password. Never
  commit keys, tokens, or real hostnames.

---

## 4. Definition of Done (all must hold before requesting merge)

- [ ] The prompt's stated deliverables and acceptance criteria are met.
- [ ] `go build ./...`, `go vet ./...`, and `go test ./...` pass locally.
- [ ] Linter (`golangci-lint run`) passes, or new findings are justified.
- [ ] New/changed behavior has unit tests; integration tests updated if relevant.
- [ ] `docs/PLAN.md` updated if the architecture changed.
- [ ] Anything renamed or deleted leaves no dangling references (Section 3).
- [ ] The prompt file moved from `prompts/queued/` → `prompts/implemented/`
      (same filename) in this PR.
- [ ] A learnings file added to `docs/learnings/` (Section 5).
- [ ] Prompt-numbering invariants still hold (Section 6).
- [ ] Every prompt this PR **adds or modifies** names the `docs/PLAN.md`
      sections and decisions it needs, by `§` and `D`, in its "Read first"
      (Section 7). §1's context budget depends on it.
- [ ] CI is green on the PR.

---

## 5. Learnings file (the hand-off to future sessions)

Before opening the PR, add `docs/learnings/NNNN-short-description-learnings.md`
where `NNNN-short-description` **matches the prompt you implemented**.

It MUST begin with a **summary block** so future sessions can decide whether to
read further without spending tokens on the whole file:

```markdown
# 0003 — user→proxy auth — Learnings

## Summary
- What shipped: <1–3 lines>
- Key packages/files: <paths>
- Key interfaces/types added or changed: <names>
- Decisions made/affected: <D-ids, or new decisions>
- Gotchas / non-obvious constraints: <1–3 lines>
- What the NEXT session must know: <1–3 lines>

## Details
<Everything else: rationale, how to extend, test notes, follow-ups, deviations.>
```

Keep the summary block tight (aim ≤ ~12 lines). Put depth in Details. If you
created follow-up prompts, list them here.

---

## 6. Prompt numbering invariants

Prompts are named `NNNN-short-description.md` with a **4-digit** zero-padded
prefix indicating implementation order.

- **Uniqueness:** no number may repeat across `queued/` **or** `implemented/`.
  Every prompt is uniquely identified for all time.
- **Implemented names are frozen:** never rename a file in `prompts/implemented/`.
- **The queue is contiguous, and a number states position.** Implemented prompts
  are frozen and therefore always hold the **lowest** numbers; the queued block
  runs contiguously above them, in the order the prompts are meant to be worked.
  So **whenever the intended run order changes, renumber the queued prompts to
  match** — to promote work that merely *should* go first, not only to fix a
  prompt that *must*. The payoff is that §0's rule needs no exception: the
  lowest-numbered queued prompt is always the right one to start.
- **A renumber is only done with its mapping written down.** Renumbering is
  expensive — §3 makes chasing every stale citation mandatory, and these numbers
  are cited from the other prompts, `docs/PLAN.md`, `api/`, `deploy/` and Go
  comments — so every revision records its old→new mapping as a **Renumbering
  note** at the end of `docs/PLAN.md` §10, says which live references it updated,
  and states that `docs/learnings/` and `prompts/implemented/` were **not**
  rewritten and must be read through the mapping.
  **Do not compose those notes by hand.** They stack, there are eleven, and the
  chain is six deep — so §10 carries the **composed mapping** above them, and a
  renumbering PR regenerates it as part of the same change. Resolve an old
  reference by the phase's *subject* against that table, never by its digits
  alone: 30 of the 37 numbers in use are simultaneously a live phase and a
  historical alias of a different one.
- **A withdrawn number is retired for good** — never reused, even though nothing
  occupies it (**0021** and **0030** today; see `docs/learnings/0021-…` and
  `docs/learnings/0030-…`). Those are the gaps the contiguity rule above does not
  close, and they are deliberate: each number names its withdrawn phase
  everywhere in the history, so reusing one would make two different phases
  answer to the same citation.
  **Withdrawal is a real outcome of a session, not a failure to deliver.** Both
  phases so far ended in a reasoned decision not to build, written up in
  `docs/learnings/` exactly as a shipped phase would be — the reasoning is the
  deliverable, and it is what stops the next session re-deriving it. The prompt
  file is **deleted** rather than moved to `implemented/` (nothing was
  implemented), and §3's dangling-reference sweep applies in full: a withdrawn
  phase leaves the same debris a rename does, including forward references in
  code comments and in docs written for it to act on.
- **When you add new prompts:** if your PR introduces new prompts into
  `queued/`, verify ordering still makes sense. If a new prompt must run before
  existing queued prompts, **renumber the queued prompts** (only queued ones) so
  order is correct and numbers stay unique. Never collide with any number that
  already exists in `implemented/`.
- Each new prompt must be **self-contained** (Section 7).

---

## 7. Writing a self-contained prompt

Any prompt (existing or newly added) must be runnable by a **fresh** session with
no prior context. It must:

- State its objective, in-scope and out-of-scope items.
- **Name the exact `docs/PLAN.md` sections and decisions the phase needs**, by
  `§` number and `D` id, in a "Read first" block at the top — together with the
  relevant `docs/learnings/` summaries and this file. Not "see `docs/PLAN.md`":
  the plan is ~50k tokens and §1 has the session **navigate** it rather than
  read it, so a prompt that names no sections leaves the next session choosing
  between reading 50k tokens it mostly does not need and guessing at an
  architecture the plan already settled. **Both outcomes are the failure §1's
  budget exists to prevent, and this line is what makes that budget
  achievable** — it is a load-bearing requirement, not a courtesy to the reader.
  Name a section you are unsure about rather than omitting it; an unnecessary
  section costs tokens once, a missing one costs a re-derived decision.
- This applies to a prompt you **modify** exactly as it does to one you add. If
  your PR changes what a queued prompt will have to read — you moved a decision,
  renamed a section, added a `D`, or shifted work between phases — update that
  prompt's "Read first" in the same PR, on §3's rule that a live reference is
  updated rather than left to rot.
- Name the exact packages/files to create or change.
- Specify interfaces/types precisely enough to implement without guessing.
- Define acceptance criteria and required tests.
- Assume nothing about session history beyond the durable docs.

---

## 8. Commits & PR

- **Commit style:** Conventional Commits — `type(scope): summary` in the
  imperative mood. Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`,
  `ci`, `build`. Scope = package or phase (e.g. `feat(auth/user): ...`). Keep the
  subject ≤ 72 chars; explain the "why" in the body when non-obvious.
- **One prompt = one PR.** The PR description states which prompt it implements,
  summarizes changes, lists any plan deviations, and confirms the Definition of
  Done checklist.
- **Iterate on the PR** with the user's review feedback until they're happy.
- **The session's job is done when the PR is merged.** Do not start the next
  prompt in the same session.
- Do not create a PR for work the user hasn't asked to be turned into a PR; the
  normal implementation flow above does open one.

### Say each thing once

A phase writes three records, and they have three different readers: the
**learnings file** (the next session, forever), the **PR description** (the
reviewer, for the life of the PR), and **what the session says in chat** (the
user, once). Only the third is not a record, and it is the one that costs the
most — every restatement is output the user pays for *and* input that every
later turn in the session carries.

So each fact goes in exactly **one** of the first two, and the session says only
what neither can deliver. At the three moments a session is tempted to
summarise:

- **Opening the PR** — post the link and nothing the description already says.
  Add only what it cannot carry: a decision you need, an assumption you took
  that they might reject, something worth their attention before they read.
- **Green and mergeable** — one line, then idle (below).
- **Merged** — the session is over, and nothing downstream reads a closing
  summary: the learnings file is the hand-off, not your last message. Say only
  what the user must **act** on — the sync kickoff
  `docs/CROSS-REPO-PROTOCOL.md` §4 owes them, a follow-up they agreed to — and
  otherwise confirm the merge in one line and stop.

The test: if a sentence would still be true and worth finding after this
session's scrollback is gone, it belongs in the learnings file or the PR
description. If it would not, it probably did not need saying.

This is the same discipline §3 and §5 already apply to the durable artifacts —
one home per fact, a pointer rather than a second copy — applied to the one
channel that was never given it.

### Waiting for review is waiting, not polling

Once the PR is open, **green and mergeable**, the session's remaining job is to
wait. Hand it over in one line — "green, mergeable, waiting on your review" —
and then **go idle**.

- **Do not schedule recurring check-ins** on the PR, and cancel any you already
  scheduled once it goes green. No timers, no hourly re-reads, no "still green"
  status messages.
- A healthy PR only changes when a human acts on it or CI reports something, and
  **both of those arrive as events** that wake the session on their own. Polling
  for them discovers nothing a wake-up would not have delivered.
- Every unnecessary wake costs the user real money and tells them nothing. Ten
  check-ins reporting "no change" are ten times the cost of zero.

Two exceptions, and only two:

- **CI is red, or the branch has a merge conflict.** That is work, not waiting:
  diagnose it, fix it, push. Only a *green, mergeable* head waits for a human —
  a broken one is never "waiting on review".
- **The user asked for a specific check** ("tell me when CI finishes"). Do that
  one check, report it, and go idle again.

The next thing the user hears from a waiting session should be a reply to
something they said — not a heartbeat.

---

## 9. Guardrails (reduce hallucination)

- The durable truth is: this protocol, `docs/PLAN.md`, and `docs/learnings/`.
  Trust them over memory. If they conflict, the plan wins for architecture and
  the protocol wins for process — and you flag the conflict to the user.
- If a prompt seems to contradict the plan, **stop and ask the user** rather than
  guessing.
- Never invent management-server API shapes: the contract in `api/` is
  authoritative once phase 0002 lands.
- Don't expand scope to "be helpful" — smaller, correct, well-documented PRs are
  the point.
