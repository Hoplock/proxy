# SecureCommandProxy — Session Protocol

> **Every implementation session MUST read this file first, in full.** It is
> short by design. It tells a fresh Claude Code session exactly how to pick up
> work, implement one prompt, and hand off cleanly to the next session.

This protocol exists to keep sessions consistent, keep context windows small
(target **< 60% context per session**), and reduce hallucination by grounding
every session in the same durable artifacts.

---

## 0. TL;DR of a session

1. Read this protocol.
2. Read `docs/PLAN.md` (the architecture source of truth).
3. Read the **summary block** of each file in `docs/learnings/` (read a full
   learnings file only if it's relevant to your prompt).
4. Take the **lowest-numbered** prompt in `prompts/queued/` (unless the user
   names a specific one). That prompt is your entire task.
5. Create a fresh branch off the default branch.
6. Implement the prompt. Keep it in scope. Meet the Definition of Done.
7. Move the prompt file from `prompts/queued/` to `prompts/implemented/`
   (unchanged name) **in the same PR**.
8. Write a learnings file to `docs/learnings/`.
9. Open a PR. Iterate with the user until they are happy.
10. **The session ends when the PR is merged.**

---

## 1. Startup reading order (context budget)

Read in this order and **stop reading as soon as you have what you need**:

1. `docs/PROTOCOL.md` — this file (always, in full).
2. `docs/PLAN.md` — always. This is the architecture. Do not re-derive it.
3. `docs/learnings/*` — read **only the summary block** at the top of each file
   first. Open the full body of a learnings file **only** when its summary shows
   it's relevant to your prompt (e.g. you touch the same package or interface).
4. Your target prompt in `prompts/queued/`.

Do **not** read the whole codebase. Read the specific files your prompt names,
plus what those files import. If you find yourself reading broadly, stop and
re-scope — the prompt or a learnings file should already point you at the right
places. Staying under ~60% context is a hard goal; if you're approaching it,
prefer finishing a smaller, correct slice over reading more.

---

## 2. Branching

- Branch off the **latest default branch** (`main`): 
  `git fetch origin main && git checkout -B <branch> origin/main`.
- Branch name: `claude/NNNN-short-description` matching the prompt (e.g.
  `claude/0003-user-auth`).
- **Never push to `main`.** Never push to another prompt's branch.
- If a prior PR for your branch name was already merged, start fresh from `main`
  (do not stack on merged history).

---

## 3. Doing the work

- **Scope discipline.** Implement exactly what the prompt specifies. If you
  discover work that belongs to a later phase, do **not** do it here — note it in
  your learnings file and/or add a new queued prompt (Section 6).
- **Follow the plan.** Match `docs/PLAN.md`: package layout, interfaces, naming,
  decisions (D1–D10). If reality forces a deviation, update `docs/PLAN.md` in the
  **same PR** and call it out in the PR description and learnings.
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
- [ ] The prompt file moved from `prompts/queued/` → `prompts/implemented/`
      (same filename) in this PR.
- [ ] A learnings file added to `docs/learnings/` (Section 5).
- [ ] Prompt-numbering invariants still hold (Section 6).
- [ ] CI is green on the PR.

---

## 5. Learnings file (the hand-off to future sessions)

Before opening the PR, add `docs/learnings/NNNN-short-description-learnings.md`
where `NNNN-short-description` **matches the prompt you implemented**.

It MUST begin with a **summary block** so future sessions can decide whether to
read further without spending tokens on the whole file:

```markdown
# 0003 — user→bastion auth — Learnings

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
- Reference `docs/PROTOCOL.md`, `docs/PLAN.md`, and the relevant
  `docs/learnings/` summaries at the top ("Read first").
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
