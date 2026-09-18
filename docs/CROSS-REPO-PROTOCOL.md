# Hoplock — Cross-Repository Protocol

> **This file is identical in all three Hoplock repositories.** `hoplock/proxy`
> owns it; `hoplock/control` and `hoplock/enterprise` carry copies. It is a
> shared surface like any other (Section 1), so a change to it takes the same
> route: made in the proxy, **merged there first** (Section 2), then mirrored
> verbatim into the other two by **one dedicated sync session per repository**
> (Section 3.1).
>
> Between that merge and those syncs the copies lag, and pretending otherwise is
> what an earlier version of this line did — it claimed the mirror happened "in
> the same change-set", which no session can do, because a session is checked
> out against one repository at a time. The window is real and is made visible
> instead: the upstream PR names **both** consuming repositories under
> `## Cross-repo impact` and hands over a ready-to-run kickoff for each
> (Section 4), so the lag is a tracked obligation rather than a silent
> divergence.

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

This file is the missing definition, and it covers **both directions**. A change
that has landed obliges its consumers to catch up (3.1). A change that is *needed*
and does not exist obliges somebody to raise it where it belongs (3.2). The second
direction is the newer half of this file and the easier one to leave as prose,
because a session that hits it is mid-phase, has a workaround in reach, and can
always write the problem down and move on — which reads like diligence and leaves
the work unowned.

---

## 1. The shared surfaces

| Surface | Owned by | Consumed by | How a change reaches the consumer |
| --- | --- | --- | --- |
| `api/control.yaml`, `api/README.md` — the PEP↔PDP wire contract | proxy (D3) | control | vendored read-only into `contract/` and re-synced (control M1) |
| `ext/` — Control's extension interfaces | control (M15) | enterprise | a pinned, released module version (enterprise E1, E3) |
| `docs/CROSS-REPO-PROTOCOL.md` — this file | proxy | control, enterprise | one sync PR per repository, mirroring it verbatim |
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

**Nothing is an exception, this file included.** `docs/CROSS-REPO-PROTOCOL.md`
is owned by the proxy and mirrored downstream, and it travels exactly this
route — merged here, then one sync session per consuming repository
(Section 6). It is the one that most invites a "just copy it everywhere at
once", which is why it is named here.

The reverse direction is never a dependency: Control does not import Enterprise
(M15), and the proxy depends on neither. When a downstream repository needs
something it does not have, that is Section 3.2 — not an exception to this rule.

---

## 3. The two flows

One per direction. Both are named for where the *work* ends up, not for where it
was noticed: a downstream sync is work done downstream, and an upstream request
is work done upstream. Neither is ever done by the session that discovered it was
owed.

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

### 3.2 Upstream request — downstream needs something upstream does not have

The mirror of 3.1, and for a long time the leg that had a rule but no
machinery. 3.1 carries a **merged** upstream change down; this carries an
**unmet need** up.

**Owner: the session that found the gap.** Not the user, who cannot know a shape
was missing until somebody names it, and not the next session in the upstream
repository, which has no way of knowing either.

1. **Stop.** Do not approximate the missing shape, do not edit a vendored
   artifact, do not copy a file out of the upstream repository, and do not add a
   `replace` directive to turn a build green.
2. **Build everything the gap does not block**, behind a seam named for what is
   missing, and say plainly that it is unwired. A phase that downed tools at the
   first absent field would deliver nothing; one that shipped *around* the gap
   would ship a lie. The seam, its default, and the visible fact that nothing is
   yet flowing through it are the deliverable.
3. **Name the shape** — the exact field, endpoint, enum value, or signature — in
   your PR under a heading spelled exactly `## Upstream request` (Section 4.2),
   and in your learnings summary as a named cross-repo dependency, so the next
   session in your repository finds it by reading rather than by being blocked.
4. **Hand over a runnable kickoff** for the upstream repository, already filled
   in (Section 4.2). This is the step that used to be missing, and it is the
   whole reason this section is a flow rather than a prohibition.
5. **The user runs it there.** The change is **normal work in the upstream
   repository** — its own number, its own prompt, its own PR, its own review —
   never a favour done in passing on the way to something else, and never done
   from the session that found it: that session is checked out against the wrong
   repository and is in the middle of implementing something else (Section 6).
6. **The loop closes downward.** When that upstream change merges it is an
   ordinary 3.1, owed to every consuming repository *including the one that
   asked*. A request is therefore **three legs** — up as a kickoff, across as a
   phase, back down as a sync — and until this revision only the middle one was
   written down.

Approximating is one of the two failures this exists to prevent. It makes CI
green in one repository while the two components quietly stop agreeing, which is
the defect class that survives every test either repository can write alone.

**Silence is the other, and it is the one that actually happened.** Twice a
downstream repository has needed a shape its upstream did not have, and each time
the need was recorded honestly and then went nowhere:

- `hoplock/enterprise` needed the seams for a multi-instance supervisory plane
  (its E14). Control absorbed it as a new phase and its `docs/PLAN.md` §10 calls
  the revision "downstream-driven" — a correct outcome reached with no flow, so
  nothing says how the next one gets raised.
- `hoplock/control` phase 0006 needed an event type on the revocation stream that
  could carry a configuration change. It did everything the rule then asked —
  named the shape in its learnings summary and its PR body, built the seam
  unwired, approximated nothing — and still produced **nothing anybody could
  run**. It is the case this revision was written from, and the section it now
  owes was added to that PR afterwards, by hand, which is exactly the
  reconstruction step 4 exists to remove.

Neither case was careless; both followed the text as it stood. That is the
evidence that the text was the problem: a dependency only a PR body remembers has
been archived, not raised. And two occurrences in the two different directions the
chain has is why this is a general flow rather than a courtesy owed to one pair of
repositories.

**What makes the diagnosis certain is that the same traffic already works when
nothing is blocked.** Proxy phases 0039 and 0041 were both raised from
`hoplock/control` — 0002 found two obligations the contract stated but did not
make observable, 0005 found an untested path in how a past deadline is handled —
and both became numbered upstream phases promptly, with no flow in this file to
thank for it. The difference is not care and it is not seniority. It is that
neither one **blocked** the session that found it: Control noticed something about
the proxy, its own phase was unaffected, so saying it out loud cost nothing and
carried no temptation.

A blocked session is the opposite case in every respect. It has a phase to finish,
a workaround within reach, and a genuine reason to keep going — and writing the
problem down and moving on *reads like diligence*, which is what makes it so
durable a failure. So the flow was missing at exactly the point where the pressure
to skip it is highest, which is the only place a flow is worth anything. That is
also why step 2 is an obligation to **build** rather than permission to stop: the
answer to "I am blocked" is not "down tools" and not "ship around it", and a
section that did not say so would be read as licence for whichever of the two the
reader already preferred.

---

## 4. The two hand-over obligations

Both flows in Section 3 end the same way: a session in one repository knows
something a session in another repository needs, and the two never meet. So both
end with the same duty — **put the obligation in the PR, and hand over a kickoff
somebody can actually run.** 4.1 is that duty looking downstream, 4.2 looking up.

They are one section because the failure is one failure. An obligation that is
described but not runnable has to be reconstructed later, from a merged PR body,
in a repository nobody has opened — and that reconstruction is the step that
silently does not happen, whichever direction it was owed in.

### 4.1 Looking downstream: what your change obliges a consumer to do

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

#### Hand over a runnable sync kickoff

An obligation that is written down but not runnable is one somebody has to
reconstruct later, from a merged PR body, in a repository they have not opened.
That reconstruction is the step that silently does not happen. So the impact
section does not stop at naming the work — **for each repository with
obligations it ends with a ready-to-run sync kickoff, already filled in**:

- the prompt is the "Downstream sync" block in `docs/KICKOFF.md`, verbatim
  except for its blanks;
- `<upstream PR URL>` is this PR, and the obligations line carries the
  obligations just stated above it. There is no branch blank to fill: the sync
  session uses whatever branch it was given (§5);
- a repository answered **"None"** gets no kickoff — there is nothing to run.

The session that opens the upstream PR **also puts each kickoff in its reply to
the user**, naming the repository to run it in and saying plainly that it needs
a **fresh session with that repository checked out**. The PR body is the durable
copy; the reply is what actually gets pasted, and a sync that is never started
is indistinguishable from one that was never owed.

Neither the kickoff nor the reply makes the sync the upstream session's to do.
The ordering in §2 is unchanged: upstream merges first, and the sync runs
afterwards, in its own session, against the downstream repository.

### 4.2 Looking upstream: what you need that does not exist yet

The mirror duty, owed by a session that hit 3.2. Before requesting merge, put it
in the PR under a heading spelled exactly:

```
## Upstream request
```

**An absent section means you needed nothing**, the same way "None" does under
4.1 — and for the same reason, if you *did* need something and left the section
out, a reviewer cannot tell that from never having looked.

State, for each thing you need:

- **the repository** it is owed by, and the surface it lands on (§1);
- **the exact shape**, concretely enough to implement without a conversation: the
  field and its type, the endpoint and its method, the enum value, the signature.
  A sketch in the target document's own syntax is worth more than a paragraph
  about it — and if you cannot write the shape down, you have not finished
  understanding what you need, which is itself the finding;
- **what you built instead**, and where the seam is — so a reviewer can see that
  nothing was approximated (3.2 step 2);
- **what stays broken until it lands**, in user-visible terms. "Config rollout is
  staged but never delivered" is a decision somebody can weigh; "blocked on
  upstream" is not.

#### Hand over a runnable upstream kickoff

Then end the section with a **ready-to-run kickoff for the upstream repository,
already filled in** — the "Upstream request" block in that repository's
`docs/KICKOFF.md`, verbatim except for its blanks. And, exactly as 4.1 requires,
**put it in the reply to the user too**, naming the repository to run it in and
saying plainly that it needs a **fresh session with that repository checked out**.

The kickoff's job is to produce a **queued prompt** upstream, not to produce the
change: what arrives upstream is a need, and turning a need into a specified
phase is upstream's own work, done by somebody reading upstream's plan. A
downstream session that wrote the upstream prompt itself would be specifying a
phase against an architecture it navigated only far enough to be blocked by.

Two things this obligation is **not**:

- **Not a licence to do the upstream work.** Same rule as 4.1 in reverse (3.2
  step 5, §6).
- **Not a reason to hold your own PR.** Your phase merges with the gap named and
  the seam unwired; it does not wait. Waiting would make every upstream
  turnaround a downstream stall, and the thing that makes not-waiting safe is
  that the seam fails visibly rather than silently — which is what 3.2 step 2
  buys.

---

## 5. Sync PR conventions

These exist because a sync PR fits none of the per-repo conventions: with no
prompt there is no number, and the defaults quietly stop applying.

- **Branch:** the one the session was given, whatever it is named. A sync
  session is normally started with a branch already assigned and does not
  rename it; **that is not a deviation and is not written up as one** (each
  repository's own `docs/PROTOCOL.md` §2 says the same). When the name *is*
  yours to choose, use `claude/sync-<short-description>` — deliberately not
  `claude/NNNN-…`, because there is no NNNN and inventing one collides with a
  real prompt. Either way what identifies a sync is the PR body naming the
  upstream change it follows, below, and never the branch: a name that cannot
  be chosen cannot be relied on to identify anything.
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

### The PR that answers an upstream request is not a sync

Nothing above applies to it, and the distinction is worth stating because the two
arrive through the same door. A sync **changes text to match something that is
already true**. A PR answering an upstream request (3.2) **makes something true
that was not** — so it is an ordinary numbered phase in the upstream repository,
governed by that repository's own `docs/PROTOCOL.md` and nothing here:

| | Sync PR (3.1) | The phase answering a request (3.2) |
| --- | --- | --- |
| Number | none | its own `NNNN`, from the upstream queue |
| Prompt | none | one, self-contained, moved to `implemented/` |
| Learnings | none | one, like any phase |
| Changes behaviour | never | that is the entire point |
| Owes a sync | it *is* one | **yes — to every consumer, once merged** |

That last row is the one to get right. The phase that closes a request is itself a
change to a shared surface, so 4.1 binds it in full: it names every consuming
repository under `## Cross-repo impact` and emits their kickoffs, including one
back to the repository whose request started it. **The repository that asked is a
consumer like any other and is easy to forget precisely because it is the one
already waiting** — it knows what it asked for, so it is tempting to assume it
needs no telling, and the session there that finally vendors the change is a fresh
one that knows nothing.

---

## 6. Guardrails

- **Never edit a vendored artifact** to make a downstream build or test pass. It
  turns CI green while the components diverge, which is the exact failure
  vendoring exists to prevent (control M1).
- **Never invent an upstream shape.** If a field, endpoint, or enum value is not
  in the contract, it does not exist. Raise it as an upstream request and build
  the seam unwired (Section 3.2); naming what is missing is the deliverable, and
  it is not the same thing as being blocked.
- **Never do the upstream work from the session that found it needed.** It is
  checked out against the wrong repository and is implementing something else,
  and the upstream change deserves its own prompt, plan reading, and review
  rather than a corner of a downstream PR (Sections 3.2, 4.2). Hand over the
  kickoff instead.
- **A sync PR enforces nothing.** If you find yourself writing code in one, you
  have found a phase rather than a sync — queue it as a prompt.
- **Do not fold a cross-repo sync into a feature PR.** It is separately
  reviewable and separately revertible, and it is the half most likely to need a
  second pass.
- **Changing this file:** it is a shared surface (Section 1) and gets no special
  flow. Change it in `hoplock/proxy`, **merge there first** (Section 2), then
  mirror it verbatim into the other two through **one dedicated sync session per
  repository** (Section 3.1) — never a hand-copy folded into some other change.
  Say in each PR which repository the change originated in.

  This bullet used to say "in the same change-set". That contradicted Sections 2
  and 3.1 outright and was not compliable: a session is checked out against one
  repository at a time, so the instruction could only ever be reported as a
  deviation. Where the two readings differ, the direction rule wins — upstream
  merges first, always.
