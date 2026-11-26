# 0048 — Control's public Go API in the shared-surfaces table

## Read first

- `docs/PROTOCOL.md`: the session workflow, especially **§3** (scope discipline
  and the dangling-reference sweep), **§4** (the Definition of Done applies in
  full, even though nothing here compiles), **§5** and **§8**.
- `docs/PLAN.md`:
  - **§2's register**, then **D3** in full. This repository owns the contract
    Control vendors, and it owns `docs/CROSS-REPO-PROTOCOL.md` on the same
    footing. The first row of the table this phase edits is D3's, and it does
    not change.
  - **§3**, only the layout tree's `docs/` lines, where
    `CROSS-REPO-PROTOCOL.md` is "shared with control + enterprise; this repo
    owns it".
  - **§10**: this phase's row.
  - Nothing else. This phase changes no code, no contract and no decision. If
    you find yourself opening another section, re-read "Out of scope".
- `docs/CROSS-REPO-PROTOCOL.md`, **in full**. It is the file this phase
  changes. **§1** and **§2** are what change. **§3.1, §4.1, §4.3 and §5**
  govern the sync this phase owes.
- `docs/KICKOFF.md`: the "Downstream sync" block, which this phase fills in and
  queues.
- `docs/learnings/`: the summaries only. None is about this file. Earlier
  changes to it were docs PRs, not phases: proxy#36, #60 and #73. How each was
  mirrored is in `prompts/downstream/implemented/proxy-PR#36-…`,
  `proxy-PR#60-…` and `proxy-PR#73-…`.

## Where this came from

An **upstream request** from `hoplock/control` (`docs/CROSS-REPO-PROTOCOL.md`
§3.2), raised in the `## Upstream request` section of
[Hoplock/control#56](https://github.com/Hoplock/control/pull/56). That PR is
Control's phase 0015. It added `server/`, a second public Go package that
Enterprise consumes, and released it as `v0.2.0` (Control's M23). The request
file is `prompts/upstream/queued/control-PR#56-shared-surfaces-table.md` in
`hoplock/control`.

The request carries a second need, raised earlier by `hoplock/enterprise` in
[Hoplock/enterprise#8](https://github.com/Hoplock/enterprise/pull/8). It was
folded into Control's request so that §1 is edited once. Its file,
`enterprise-PR#8-protocol-surfaces-exist.md`, is in Enterprise's
`prompts/upstream/implemented/`.

Neither repository may fix its own copy. The file is mirrored verbatim, and
§6's last bullet forbids the hand-copy. So the change is made here, once, and
travels down as syncs.

**The shape requested**, quoted from #56's `## Upstream request`:

> 1. **List `server/`.** The `ext/` row becomes Control's public Go API:
>    ```
>    | `ext/`, `server/` — Control's public Go API: the extension interfaces, and the package a host starts Control with | control (M15) | enterprise | a pinned, released module version (control M23; enterprise E1, E3) |
>    ```
> 2. **Rewrite the paragraph under the table.** It still says `contract/`,
>    `make contract-sync` and `ext/` "do not exist yet". They have existed since
>    Control phases 0002 and 0004, and `server/` since 0015. The paragraph's
>    point still holds and should stay: a consumer's obligation is to its
>    prompts and plan as well as its code.

**What stays broken until it lands**, in the request's words: "a session in
any of the three repositories that reads §1 sees `ext/` as the only Control
surface Enterprise consumes. It can conclude that a change to `server/` owes no
downstream sync, which is how an Enterprise build breaks without a sync
queued. And §1 still tells every reader that the contract and `ext/` do not
exist."

**Checked when this prompt was written**, against `hoplock/control` at
`1680091` and `hoplock/enterprise` at `c88e8ba`:

- In Control, `contract/`, `ext/` and `server/` exist, `make contract-sync` is
  a Makefile target, and `v0.1.0` and `v0.2.0` are tagged.
- Control's register has **M1** (the contract is owned upstream and vendored
  read-only), **M15** (Enterprise extends Control and never forks it; 0015
  revised it in place to name `server/`) and **M23** (Control is released as
  immutable tags of one module).
- Enterprise's register has **E1** (Enterprise imports Control; Control never
  imports Enterprise) and **E3** (Control's version is pinned and explicit).
- Enterprise has **no code yet**: docs and prompts only, with its 0001 still
  queued.

Recheck all of it before you rely on it. The row cites these ids, and §1's
last row says they are cited, never restated.

## Objective

Make §1 state what is true: Control's public Go API is two packages that
Enterprise consumes, and the surfaces the paragraph under the table calls
future already exist. Then hand the change down as one verbatim mirror per
consuming repository, queued as one sync.

## The change

All of it is in `docs/CROSS-REPO-PROTOCOL.md`.

1. **§1's table, second row.** Replace it with the requested row, verbatim.
   The owner stays `control (M15)` and the consumer stays `enterprise`. The
   proxy consumes neither package.
2. **§1's paragraph under the table** ("Two of those surfaces do not exist
   yet: …"). Rewrite it. Keep its point and drop its tense:
   - **It states no fact that a later merge in another repository can make
     false.** No "yet", no "until phase N", and no list of what exists today.
     That is how this paragraph went stale. It was true when written and false
     after Control's 0002. Correcting it then took an upstream request and two
     syncs, because a sentence in this file changes only through a proxy PR
     and its mirrors. A paragraph that needs no edit when a downstream phase
     merges is the requirement, not a style choice.
   - **It keeps the obligation.** A consuming repository's obligation to a
     surface is to its **prompts and plan** as well as its code. That
     obligation is as real as a code one, and it is easier to miss because
     nothing fails to compile.
   - **It still covers the case the old paragraph was written for**, without
     naming a repository. A consumer that has no code against a surface yet
     (Enterprise, today) owes its prompts and plan alone.

   A sketch to improve on, not to copy:

   > A consuming repository's obligation to a surface is to its **prompts and
   > plan** as well as its code: the text a future session builds from. It is
   > exactly as real as a code obligation and considerably easier to miss,
   > because nothing fails to compile. A queued prompt that describes a shape
   > which has since changed is wrong in a way no build reports. Where a
   > consumer has no code against the surface yet, its prompts and plan are the
   > whole obligation.
3. **§2: one sentence the request did not name.** "A downstream pull request
   that describes a contract field, an `ext` signature, or a path not yet
   merged upstream…" names `ext` as the only Go surface. Make it name both
   packages, for example "a signature in Control's public Go API". This is the
   same fact as item 1. §2 is the direction rule, and a `server` signature
   described before it merges upstream is exactly the case that rule is about.
   Leave the rest of §2 alone.
4. **Nothing else in the file.** Run these two commands and put every hit in
   the PR, saying whether you changed it and why:

   ```sh
   grep -nw 'ext\|server\|contract\|contract-sync' docs/CROSS-REPO-PROTOCOL.md
   grep -n 'exist' docs/CROSS-REPO-PROTOCOL.md
   ```

   When this prompt was written, the hits beyond items 1–3 were these, and
   none is about which surfaces exist:
   - the first row (`contract/`, M1), which is correct as it stands;
   - §0's "does not exist" and §2's, about a need and a description;
   - §3.2's history of Control's phases;
   - §4.2's heading, about a need;
   - §4.3's "not the contract shape";
   - §5's "These exist because" and its commit example;
   - §6's "it does not exist".

## In scope

- `docs/CROSS-REPO-PROTOCOL.md`: items 1–3 above.
- `docs/PLAN.md` §10: this phase's row, updated with what was delivered.
- The prompt move, the learnings file, and the sync request file (below).

## Out of scope

- **Any other change to `docs/CROSS-REPO-PROTOCOL.md`.** Every sentence changed
  here is a sentence two syncs must mirror. An unrelated fix folded in would be
  reviewed and reverted together with this one (§5: "One upstream change, one
  sync PR per repository"). If you find something else wrong in the file, name
  it in the learnings and to the user. It is a change of its own.
- **This repository's `docs/PROTOCOL.md` and `docs/KICKOFF.md`.** They point
  at §1 and say nothing about which packages Control exports. Check that this
  is still so, then leave them alone.
- **The other two copies.** You edit only this repository's file. Mirroring
  it is the syncs' work, in sessions of their own, after this PR merges (§2,
  §6).
- **A new decision.** This is process, not architecture: `docs/PROTOCOL.md` §9
  says the protocol wins for process. The register does not change. Say so in
  the PR.
- **§3.2's account** of Control's phase 0006 and Enterprise's E14. It is
  history and correct as written.
- `api/`, code, and tests. The only test involvement is running them.

## Acceptance criteria

- §1's second row is the requested row, byte for byte. `git diff` shows one
  row replaced.
- The paragraph under the table makes no claim about what exists or when. It
  keeps the obligation's three parts: prompts and plan as well as code, just as
  real, easier to miss.
- The §2 sentence that item 3 quotes names both packages.
- `docs/CROSS-REPO-PROTOCOL.md` has no other hunk.
- The PR carries item 4's grep, with what was done about each hit.
- `go build ./...`, `go vet ./...` and `go test ./...` pass. `test/docs` is the
  part this phase can break, through §10's row.

## Required tests

None new. This phase changes prose that no test reads, and
`go test ./test/docs/...` is what checks that §10 still parses with this
phase's row updated. **Do not add a test that pins §1's wording.** The file is
mirrored into two repositories that do not run this repository's tests, so
such a test would pin only this copy, and it would read as a guarantee about
all three.

## Definition of Done & hand-off

Per `docs/PROTOCOL.md` §4, in full: move this prompt to `implemented/`, add
`docs/learnings/0048-shared-surfaces-table-learnings.md`, and get CI green.
Beyond that, this phase owes the following because of where it came from and
what it touches:

- **`## Cross-repo impact`** (`docs/CROSS-REPO-PROTOCOL.md` §4.1) names
  **both** consuming repositories. The change is to this file, the one proxy
  surface Enterprise carries (§4.3's table), so both are owed a sync:
  - **`hoplock/control`, the repository that asked.** It is a consumer like
    any other (§5, "The PR that answers an upstream request is not a sync").
    It knows what it asked for, but its copy keeps the old text until a sync
    mirrors the new one, and the session that does that is a fresh one.
  - **`hoplock/enterprise`**, whose copy is the one that told it `ext/` did
    not exist.

  Each owes the same two things:
  - **Mirror `docs/CROSS-REPO-PROTOCOL.md` verbatim** from this PR's merge
    commit, checked byte for byte. The sync PR shows the check: `cmp` against
    this repository's copy at that commit. enterprise#11 exists because
    enterprise#9 mirrored all but one sentence.
  - **Grep its own prompts, plan and protocol** for live text that the new §1
    makes stale, and land what it finds. When this prompt was written, the
    grep found nothing that depends on §1 listing `ext/` alone. It did find
    two sentences that name `ext` where §1 will name both packages:
    - Control's `docs/PROTOCOL.md` §3: "owns `ext/`, which Hoplock Enterprise
      imports (M15)";
    - Enterprise's `docs/PROTOCOL.md` §3: "what to do when `ext` does not yet
      expose what you need".

    Name both in the obligations so each sync decides about them rather than
    missing them. If neither sync needs more than the mirror, write "None
    beyond the mirror" down: that is a finding.
- **Queue the sync** as
  `prompts/downstream/queued/proxy-PR#<n>-shared-surfaces-table.md`. Commit it
  once the PR is open, since the name carries the PR number. Its content is
  the "Downstream sync" block from `docs/KICKOFF.md`, verbatim except for its
  blanks, with each repository's obligations under its name (§4.1, §4.3). End
  the impact section by naming the file.
- **The learnings summary** names:
  - the row as merged;
  - the paragraph as merged;
  - the §2 sentence;
  - the rule item 2 follows: nothing in this file states what exists or when.

  The next session that edits §1 reads it there.

## Who runs the syncs

Not you. This PR merges first. The queued file is answered afterwards, in a
session of its own, by the "Next cross-repo request" kickoff (§2, §4.3).
