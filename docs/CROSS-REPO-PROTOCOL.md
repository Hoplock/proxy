# Hoplock — Cross-Repository Protocol

> **This file is identical in all three Hoplock repositories.** `hoplock/proxy`
> owns it; `hoplock/control` and `hoplock/enterprise` carry copies. A change is
> made in the proxy first and mirrored into the other two in the same
> change-set, so the three can never disagree about how they talk to each other.

Read this **only when your change touches a shared surface** (Section 1). If it
does not, your repository's own `docs/PROTOCOL.md` is the whole process, and
this file costs you context you need for the work.

---

## 0. What this covers

Three repositories, one product. Each has its own `docs/PROTOCOL.md`, and each
describes exactly one kind of work: implement the lowest-numbered queued prompt,
in this repository, and merge it. That is the right default and it covers almost
everything.

What it does not cover is work that **starts in one repository and creates an
obligation in another**. That work has no prompt number, so it has no branch
name, no learnings file, and no Definition of Done — and, more importantly, no
owner. Left undefined it gets done ad hoc or, far more often, not at all: the
repository that needed updating is simply never opened, and a session weeks
later builds confidently against a shape that stopped being true.

This file is the missing definition.

---

## 1. The shared surfaces

| Surface | Owned by | Consumed by | How a change reaches the consumer |
| --- | --- | --- | --- |
| `api/control.yaml`, `api/README.md` — the PEP↔PDP wire contract | proxy (D3) | control | vendored read-only into `contract/` and re-synced (control M1) |
| `ext/` — Control's extension interfaces | control (M15) | enterprise | a pinned, released module version (enterprise E1, E3) |
| `docs/CROSS-REPO-PROTOCOL.md` — this file | proxy | control, enterprise | mirrored copy |
| Decision ids — `D*` proxy, `M*` control, `E*` enterprise | each repository owns its own | cited by the others | cited by id, never restated |

**If your change touches none of these, stop reading.** A change to one
repository's internals, prompts, plan, or tests is not a cross-repo change,
however interesting it is.

Two of those surfaces do not exist yet: `contract/` and `make contract-sync`
land with Control phase 0002, and `ext/` with Control phase 0004. Until then a
consuming repository's obligation is to its **prompts and plan** — the text a
future session will build from. That obligation is exactly as real as a code
one and considerably easier to miss, because nothing fails to compile.

---

## 2. The direction rule

Dependencies run one way, and so do changes:

```
hoplock/proxy  ->  hoplock/control  ->  hoplock/enterprise
```

**Upstream merges first. Always.** A downstream pull request that describes a
contract field, an `ext` signature, or a path not yet merged upstream is a
description of something that does not exist — and it is indistinguishable, to
a reviewer, from a description of something that does. If the upstream change is
then revised in review, which is the entire point of review, the downstream
lands wrong and nothing catches it.

There is no such thing as a matched pair merged together. Merge upstream, then
open downstream.

The reverse direction is never a dependency: Control does not import Enterprise
(M15), and the proxy depends on neither. When a downstream repository needs
something it does not have, that is Section 3.2 — not an exception to this rule.

---

## 3. The two flows

### 3.1 Downstream sync — upstream landed, downstream must catch up

**Owner: whoever merged the upstream change.** Not the next session in the
downstream repository, which has no way of knowing the change happened.

1. Before merging, the upstream PR names every affected repository under a
   **Cross-repo impact** heading (Section 4).
2. It merges.
3. One **sync PR** per affected repository (Section 5), opened against its
   `main`, run in a fresh session from the kickoff the upstream PR handed over
   (Section 4).
4. Each sync PR names the upstream PR it follows and confirms it is merged.

A sync PR **changes text, not behaviour**. It updates the prompts, plan, and
protocol of the downstream repository so the next session builds against what is
now true. It implements, enforces, and vendors nothing — those are that
repository's own numbered phases.

### 3.2 Upstream-blocked — downstream needs something upstream does not have

1. **Stop.** Do not approximate the missing shape, do not edit a vendored
   artifact, do not copy a file out of the upstream repository, and do not add a
   `replace` directive to turn a build green.
2. **Tell the user**, naming the exact field, signature, or endpoint.
3. The change is **normal work in the upstream repository** — its own prompt,
   its own PR, its own review — not a favour done in passing on the way to
   something else.
4. Record it in your learnings summary as a named cross-repo dependency, so the
   next session in your repository finds it by reading rather than by being
   blocked.

Approximating is the specific failure this exists to prevent. It makes CI green
in one repository while the two components quietly stop agreeing, which is the
defect class that survives every test either repository can write alone.

---

## 4. The upstream author's obligation: look downstream

Before requesting merge on a change to a shared surface, **check each consuming
repository and put the answer in the PR**, under a heading spelled exactly:

```
## Cross-repo impact
```

State, per consuming repository, either the concrete obligations or **"None"**.

**"None" is a finding and must be written down.** An omitted section is
indistinguishable from never having looked, and a reviewer cannot tell the
difference — which is how the check silently stops happening.

What to actually check, at minimum:

- every renamed identifier, path, filename, and enum value — by grep, across
  `prompts/`, `docs/`, and `README.md`;
- every new obligation the consumer must now meet: a field it must send, an
  answer it must give, a check it must run;
- whether a queued prompt already covers the area. If one does, the obligation
  belongs **in that prompt**, not only in the plan — a session reads its prompt
  closely and skims the plan.

### Hand over a runnable sync kickoff

An obligation that is written down but not runnable is one somebody has to
reconstruct later, from a merged PR body, in a repository they have not opened.
That reconstruction is the step that silently does not happen. So the impact
section does not stop at naming the work — **for each repository with
obligations it ends with a ready-to-run sync kickoff, already filled in**:

- the prompt is the "Downstream sync" block in `docs/KICKOFF.md`, verbatim
  except for its blanks;
- `<upstream PR URL>` is this PR, `<short-description>` is the branch suffix the
  sync should use, and the obligations line carries the obligations just stated
  above it;
- a repository answered **"None"** gets no kickoff — there is nothing to run.

The session that opens the upstream PR **also puts each kickoff in its reply to
the user**, naming the repository to run it in and saying plainly that it needs
a **fresh session with that repository checked out**. The PR body is the durable
copy; the reply is what actually gets pasted, and a sync that is never started
is indistinguishable from one that was never owed.

Neither the kickoff nor the reply makes the sync the upstream session's to do.
The ordering in §2 is unchanged: upstream merges first, and the sync runs
afterwards, in its own session, against the downstream repository.

---

## 5. Sync PR conventions

These exist because a sync PR fits none of the per-repo conventions: with no
prompt there is no number, and the defaults quietly stop applying.

- **Branch:** `claude/sync-<short-description>` — deliberately not
  `claude/NNNN-…`, because there is no NNNN and inventing one collides with a
  real prompt.
- **Commit:** Conventional Commits with the scope `sync`, e.g.
  `docs(sync): follow proxy contract v2`. The body names the upstream change.
- **One upstream change, one sync PR per repository.** Do not batch two
  unrelated upstream changes: they will be reviewed, and possibly reverted, as
  one.

### Definition of Done for a sync PR

- [ ] Names the upstream PR or commit it follows, and that upstream change is
      **merged**.
- [ ] Every stale reference updated, and the PR says **how you searched** — the
      grep, not the adjective. A reviewer cannot re-derive "I looked carefully".
- [ ] Every new obligation landed **in the prompt that will implement it**, not
      only in the plan.
- [ ] `docs/PLAN.md` updated if the architecture changed.
- [ ] Prompt-numbering invariants hold — a sync adds, renames, and renumbers
      **no** prompt. If it appears to need to, it is not a sync (Section 3.2).
- [ ] No vendored artifact hand-edited.
- [ ] CI green.

### What a sync PR does not owe

- **No `prompts/queued/` → `prompts/implemented/` move.** It implements no
  prompt.
- **No learnings file.** Learnings are the hand-off for a completed phase and
  are named after one; a learnings file named after nothing is a file nobody
  will find.

  A sync's durable record is **the prompt and plan text it changes** — that is
  what the next session actually reads. So put the reasoning *into those
  documents*, inline, and not only into the PR description. A rationale that
  lives only in a merged PR body has been archived, not communicated.

---

## 6. Guardrails

- **Never edit a vendored artifact** to make a downstream build or test pass. It
  turns CI green while the components diverge, which is the exact failure
  vendoring exists to prevent (control M1).
- **Never invent an upstream shape.** If a field, endpoint, or enum value is not
  in the contract, it does not exist (Section 3.2).
- **A sync PR enforces nothing.** If you find yourself writing code in one, you
  have found a phase rather than a sync — queue it as a prompt.
- **Do not fold a cross-repo sync into a feature PR.** It is separately
  reviewable and separately revertible, and it is the half most likely to need a
  second pass.
- **Changing this file:** change it in `hoplock/proxy` first, mirror it verbatim
  into the other two in the same change-set, and say in each PR which repository
  the change originated in.
