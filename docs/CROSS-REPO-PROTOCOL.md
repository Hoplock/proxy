# Hoplock — Cross-Repository Protocol

> **This file is identical in all three Hoplock repositories.** `hoplock/proxy`
> owns it; `hoplock/control` and `hoplock/enterprise` carry copies. It is a
> shared surface like any other (Section 1), so a change to it takes the same
> route: made in the proxy, **merged there first** (Section 2), then mirrored
> verbatim into the other two by **one sync PR per repository** (Section 3.1),
> answering the sync the proxy PR queued (Section 4.3).
>
> Between that merge and those syncs the copies lag, and pretending otherwise is
> what an earlier version of this line did — it claimed the mirror happened "in
> the same change-set", which no session can do: three repositories merge three
> PRs, never one, and the proxy's merges first. The window is real and is made
> visible instead: the upstream PR names **both** consuming repositories under
> `## Cross-repo impact` and queues a ready-to-run sync for them (Sections 4.1,
> 4.3), so the lag is a tracked obligation rather than a silent divergence.

Read this **only when your change touches a shared surface** (Section 1), or
when you are answering a queued cross-repo request (Section 4.3). Otherwise your
repository's own `docs/PROTOCOL.md` is the whole process, and this file costs
you context you need for the work.

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

And it gives both directions a **place to wait** (4.3). An obligation that lives
in a PR body is owned and even runnable, and still listed nowhere: it ran only if
somebody remembered which merged PR still owed something, and pasted it. So each
one is now a file in a queue in the repository that raised it, and one kickoff
answers the oldest of them across all three.

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
route — merged here, then one sync PR per consuming repository (Sections 3.1,
6). It is the one that most invites a "just copy it everywhere at once", which
is why it is named here.

The reverse direction is never a dependency: Control does not import Enterprise
(M15), and the proxy depends on neither. When a downstream repository needs
something it does not have, that is Section 3.2 — not an exception to this rule.

---

## 3. The two flows

One per direction. Both are named for where the *work* ends up, not for where it
was noticed: a downstream sync is work done downstream, and an upstream request
is work done upstream. Neither is ever done by the session that discovered it was
owed. Both are **queued where they are noticed** and answered where they end up
(Section 4.3).

### 3.1 Downstream sync — upstream landed, downstream must catch up

**Owner: the upstream change's own PR**, which queues the sync before it merges.
Not the next session in the downstream repository, which has no way of knowing
the change happened.

1. Before merging, the upstream PR names every affected repository under a
   **Cross-repo impact** heading (Section 4), and queues the sync in its own
   `prompts/downstream/queued/` (Section 4.3).
2. It merges — and that is what puts the queued sync on `main`, where it can be
   taken.
3. One **sync PR** per affected repository (Section 5), opened against its
   `main` by the session that answers the queued sync (Section 4.3).
4. Each sync PR names the upstream PR it follows, confirms it is merged, and
   names the request file it answers.
5. Once every one of them has merged, the request moves to
   `prompts/downstream/implemented/` in the upstream repository, by a PR
   opened as a draft alongside them and marked ready only then (Section 4.3).

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
4. **Queue a runnable kickoff** for the upstream repository, already filled in,
   in your repository's `prompts/upstream/queued/` (Sections 4.2, 4.3). This is
   the step that used to be missing, and it is the whole reason this section is
   a flow rather than a prohibition.
5. **The session that answers it runs it there** (Section 4.3). The change is
   **normal work in the upstream repository** — its own number, its own prompt,
   its own PR, its own review — never a favour done in passing on the way to
   something else, and never done from the session that found it: that session
   is checked out against the wrong repository and is in the middle of
   implementing something else (Section 6).
6. **The loop closes downward.** When that upstream change merges it is an
   ordinary 3.1, owed to every consuming repository *including the one that
   asked*. A request is therefore **three legs** — up as a queued request,
   across as a phase, back down as a queued sync — and each leg waits in a queue
   of its own: `prompts/upstream/` in the repository that asked, then
   `prompts/queued/` in the one that answers, then that one's
   `prompts/downstream/`.

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
end with the same duty — **put the obligation in the PR, and queue a kickoff
somebody can actually run.** 4.1 is that duty looking downstream, 4.2 looking up,
and 4.3 is the queue both of them write to.

They are one section because the failure is one failure. An obligation that is
described but not runnable has to be reconstructed later, from a merged PR body,
in a repository nobody has opened — and that reconstruction is the step that
silently does not happen, whichever direction it was owed in. A runnable one
fares little better when it lives only in that PR body and a chat reply: nothing
lists it, so it runs only if somebody remembers it. That is why it is now a file.

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

#### Queue a runnable sync kickoff

An obligation that is written down but not runnable is one somebody has to
reconstruct later, from a merged PR body, in a repository they have not opened.
That reconstruction is the step that silently does not happen. So the impact
section does not stop at naming the work — **the PR queues a ready-to-run sync
kickoff, already filled in**, as a request file in its own
`prompts/downstream/queued/` (4.3):

- the prompt is the "Downstream sync" block in `docs/KICKOFF.md`, verbatim
  except for its blanks;
- `<upstream PR URL>` is this PR, and the obligations line carries the
  obligations just stated above it — each repository's under its name, when
  there are two. There is no branch blank to fill: the sync session uses
  whatever branch it was given (§5);
- a repository answered **"None"** is left out of it — there is nothing to
  run — and a PR that answers "None" for every repository queues nothing;
- the impact section ends by naming the file.

The file replaces both copies this used to ask for — one in the PR body, one in
the reply to the user — because it is the durable copy and the runnable one at
once. The reply says in one line that a sync is queued, and nobody pastes
anything: the "Next cross-repo request" kickoff in `docs/KICKOFF.md` finds the
file. A sync that is never started is indistinguishable from one that was never
owed — unless it is queued, where it stays in plain sight until somebody does.

Queueing the sync does not make it the upstream session's to do. The ordering in
§2 is unchanged — upstream merges first, and the sync runs afterwards, in a
session of its own — and the queue now enforces it: the file reaches `main` only
when this PR merges, and nothing that is not on `main` is queued (4.3).

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

#### Queue a runnable upstream kickoff

Then queue a **ready-to-run kickoff for the upstream repository, already filled
in** — the "Upstream request" block in that repository's `docs/KICKOFF.md`,
verbatim except for its blanks — as a request file in your own
`prompts/upstream/queued/` (4.3), one file per need, and end the section by
naming it. Exactly as in 4.1, the file replaces the copies in the PR body and the
reply: the reply says in one line what is queued.

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

### 4.3 The request queues: where a kickoff waits

Every kickoff 4.1 and 4.2 owe is a **file in a queue**, in the repository that
raised it — never in the repository it is for, which the raising session does
not have checked out:

```
prompts/
  upstream/      needs this repository raised for the one above it (4.2)
    queued/
    implemented/
  downstream/    syncs its merged changes owe the ones below it (4.1)
    queued/
    implemented/
```

All three repositories carry both, so all three are searched the same way, even
though two of the six folders never hold anything (the table below). Neither is
part of `prompts/queued/`: nothing in them has a number, and "the lowest-numbered
queued prompt" never reaches them.

**Name.** `<repository>-PR#<n>-<short-description>.md` — for example
`control-PR#46-access-context-seam.md`:

- `<repository>` is `proxy`, `control` or `enterprise`: the repository the file
  is in, which is the one that raised it;
- `<n>` is the number of the PR whose `## Cross-repo impact` or
  `## Upstream request` section raised it, unpadded, as GitHub writes it;
- `<short-description>` is lowercase words joined by hyphens, as in a prompt's
  name.

The number is the PR's own, so the file is committed **after the PR is opened**:
open it, then add the file to it. A PR that owes a sync queues one file, covering
every repository its impact section names obligations for. A PR that raises
requests queues one file per need, since each need becomes its own prompt
upstream; two from one PR differ in their descriptions. The file holds the
filled-in block under a one-line heading that names it —
`# control-PR#46 — the access-context seam`.

**Target.** Nothing in the file says where the work happens; where the file is
says it. The repository it is in raised it, and the folder says which way along
the chain (Section 2) it travels:

| The file is in | The work is done in |
| --- | --- |
| `hoplock/proxy`, `prompts/downstream/` | `hoplock/control` — and `hoplock/enterprise` too when the change is to this file, the one proxy surface Enterprise carries (Section 1) |
| `hoplock/control`, `prompts/upstream/` | `hoplock/proxy` |
| `hoplock/control`, `prompts/downstream/` | `hoplock/enterprise` |
| `hoplock/enterprise`, `prompts/upstream/` | `hoplock/control` |
| `hoplock/proxy`, `prompts/upstream/`; `hoplock/enterprise`, `prompts/downstream/` | nothing, ever: nothing is upstream of the proxy, or downstream of Enterprise |

Enterprise's requests go to Control even when the shape turns out to be the
proxy's. Nothing in Enterprise talks to a proxy directly (its `docs/PLAN.md`
§7), so it can name the need but not the contract shape; Control, answering it,
queues its own request to the proxy if meeting the need takes one.

**Order: oldest first, across all three.** A request waits from the moment its
file reaches `main` — when the PR that raised it merges — and the oldest is the
one that has waited longest. Within one repository that is nearly always the
lowest PR number; across repositories PR numbers do not compare, so time
decides. Only `main` counts: a file on an unmerged branch is not queued yet,
which is what keeps a sync from running before the change it follows has merged
(Section 2). From the directory holding the three clones:

```sh
for repo in proxy control enterprise; do
  git -C "$repo" fetch -q origin main
  git -C "$repo" ls-tree -r --name-only origin/main -- \
      prompts/upstream/queued prompts/downstream/queued |
    grep '\.md$' |
    while read -r f; do
      printf '%s %s/%s\n' "$(git -C "$repo" log --first-parent --format=%ct \
          origin/main -- "$f" | tail -n 1)" "$repo" "$f"
    done
done | sort -n
```

Each line starts with when its file reached `main`, in seconds, and the first
line is the oldest. A shallow clone cannot see that far back — every file older
than the clone appears to arrive at its edge, all at once — so wherever
`git rev-parse --is-shallow-repository` says `true`, run
`git fetch --unshallow origin` first.

**In flight.** A request stays in `queued/` until the PR that moves it merges, so
one being answered still looks queued. Before taking one, look for an open PR —
in the repository the work is done in, or in the one that raised it — that names
its file. If there is one, the request is in flight: leave it, say so, and take
the next.

**Answering.** One session per request, with all three repositories checked
out, started from the "Next cross-repo request" kickoff in `docs/KICKOFF.md` —
the same block in every repository's copy. It is never the session that raised
the request, which is implementing a phase in one repository (Section 6), and a
need it turns up on the way is queued (4.2), never answered by it. The file was
written for a session in its target, so "this repository" in it means the
target, and every rule it points to — protocol, numbering, branch convention — is
the target's. What it opens there is what the file asks for: a sync PR per
repository it names (Section 5), or the one PR that queues a prompt (4.2) — each
naming the request file.

**Leaving the queue.** Then, in the repository that raised it, the same session
opens one more PR, **as a draft**: the file moved from `queued/` to
`implemented/`, same name, contents unchanged, naming the PRs that answered it —
committed with the scope `requests`, e.g.
`docs(requests): control-PR#46 answered by enterprise#12`. That PR **merges
last**. A request is implemented once what answers it has merged and not before,
whichever way along the chain that points — it orders bookkeeping, not a build,
so Section 2 has nothing to say about it. Moved early, a request is marked done
while nobody has done it, which is the one way this queue can lose track of
something.

**The draft is what holds that order.** GitHub will not merge a draft, so the
order no longer depends on whoever merges reading the PR body first. A body that
said "merge this last" was the whole mechanism before, and it failed the first
time the two PRs were merged together: enterprise#20, the move, merged 88
seconds before control#60, the PR that answered it.

- **The body's first line says what it waits on**: every PR it names, and that
  it stays a draft until each one has merged.
- **It is marked ready for review only once every PR it names has merged.** An
  approval or a green CI is not enough. Whoever marks it ready checks each PR
  first: the session that opened it, if that session is still running when the
  last one merges, and otherwise the person merging them.
- **If what it waits on changes, the draft changes with it.** An answering PR
  closed unmerged leaves the request queued, so the draft is closed. One that
  merges changed, so that it no longer answers the request as named, means the
  draft is rewritten to say what did answer it. Neither is ever marked ready as
  it stands.

A request answered "not like that, like this" (4.2) leaves the same way, once the
alternative the user agreed to is queued. One the user withdraws is **deleted**
rather than moved — nothing was implemented — by a PR in the repository that
raised it, whose body says why. That PR waits on nothing, so it is not a draft.

---

## 5. Sync PR conventions

These exist because a sync PR fits none of the per-repo conventions: with no
numbered prompt there is no number, and the defaults quietly stop applying.

- **Branch:** the one the session was given, whatever it is named. A sync
  session is normally started with a branch already assigned and does not
  rename it; **that is not a deviation and is not written up as one** (each
  repository's own `docs/PROTOCOL.md` §2 says the same). When the name *is*
  yours to choose, use `claude/sync-<short-description>` — deliberately not
  `claude/NNNN-…`, because there is no NNNN and inventing one collides with a
  real prompt. Either way what identifies a sync is the PR body naming the
  upstream change it follows and the request file it answers, below, and never
  the branch: a name that cannot be chosen cannot be relied on to identify
  anything.
- **Commit:** Conventional Commits with the scope `sync`, e.g.
  `docs(sync): follow proxy contract v2`. The body names the upstream change.
- **One upstream change, one sync PR per repository.** Do not batch two
  unrelated upstream changes: they will be reviewed, and possibly reverted, as
  one.

### Definition of Done for a sync PR

- [ ] Names the upstream PR or commit it follows, and that upstream change is
      **merged**.
- [ ] Names the request file it answers (4.3).
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

- **No move of its own.** It implements no prompt of its repository's, so
  nothing in its `prompts/` moves. The request it answers moves in the
  repository that raised it, in a PR of its own that stays a draft until this
  one has merged (4.3).
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
| Request queue (4.3) | answers a file queued upstream | queues one, in its own `prompts/downstream/` |
| Owes a sync | it *is* one | **yes — to every consumer, once merged** |

That last row is the one to get right. The phase that closes a request is itself a
change to a shared surface, so 4.1 binds it in full: it names every consuming
repository under `## Cross-repo impact` and queues their sync, including the
part owed back to the repository whose request started it. **The repository that
asked is a consumer like any other and is easy to forget precisely because it is
the one already waiting** — it knows what it asked for, so it is tempting to
assume it needs no telling, and the session there that finally vendors the change
is a fresh one that knows nothing.

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
  rather than a corner of a downstream PR (Sections 3.2, 4.2). Queue the
  kickoff instead (4.3). The session that answers a request is bound the same
  way: it answers that one, and queues any need it turns up.
- **Take a request only from `main`, and move it only after what answers it has
  merged** (4.3). A file on a branch is a request nobody has merged yet; a file
  moved early is one marked done that nobody did. So the PR that moves it opens
  as a draft and is marked ready only once what it names has merged: a rule
  that only asks whoever merges to remember has already failed once.
- **A sync PR enforces nothing.** If you find yourself writing code in one, you
  have found a phase rather than a sync — queue it as a prompt.
- **Do not fold a cross-repo sync into a feature PR.** It is separately
  reviewable and separately revertible, and it is the half most likely to need a
  second pass.
- **Changing this file:** it is a shared surface (Section 1) and gets no special
  flow. Change it in `hoplock/proxy`, **merge there first** (Section 2), then
  mirror it verbatim into the other two: the proxy PR queues the sync (4.3), and
  it is answered with **one sync PR per repository** (Section 3.1) — never a
  hand-copy folded into some other change. Say in each PR which repository the
  change originated in.

  This bullet used to say "in the same change-set". That contradicted Sections 2
  and 3.1 outright and was not compliable: three repositories merge three PRs,
  never one — as true for a session that can reach all three (4.3) as for one
  checked out against a single repository — so the instruction could only ever
  be reported as a deviation. Where the two readings differ, the direction rule
  wins — upstream merges first, always.
