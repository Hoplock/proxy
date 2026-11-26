# 0048 — Control's public Go API in the shared-surfaces table — Learnings

## Summary
- What shipped: three hunks in `docs/CROSS-REPO-PROTOCOL.md` and nothing else; no
  code, contract or `D`. Owes a mirror to `hoplock/control` and `hoplock/enterprise`.
- §1's second row, as merged: `` | `ext/`, `server/` — Control's public Go API: the extension interfaces, and the package a host starts Control with | control (M15) | enterprise | a pinned, released module version (control M23; enterprise E1, E3) | ``
- §1's paragraph under the table, as merged: "A consuming repository's obligation
  to a surface is to its code and to its **prompts and plan** — the text a future
  session will build from. The second is exactly as real as the first and
  considerably easier to miss, because nothing fails to compile: a queued prompt
  that describes a shape which has since changed is wrong in a way no build
  reports. Where a consumer has no code against a surface, its prompts and plan
  are the whole of the obligation."
- §2's direction rule now says "a contract field, **a signature in Control's
  public Go API**, or a path not yet merged upstream" (was "an `ext` signature").
- **Rule for the next edit to §1: nothing in this file states what exists, or
  when** (no "yet", no "until phase N"). The old paragraph went stale on a
  downstream merge, and fixing one sentence here costs a proxy phase and two syncs.

## Details

### The edits

All three are in `docs/CROSS-REPO-PROTOCOL.md`; `git diff` shows one table row
replaced, one paragraph rewritten, one paragraph rewrapped.

1. **§1, second row.** The row Control's request asked for, byte for byte. The
   owner stays `control (M15)` and the consumer stays `enterprise`: the proxy
   consumes neither package. The first row (`contract/`, M1) is correct as it
   stands and did not change.
2. **§1, the paragraph under the table.** The old one listed `contract/`,
   `make contract-sync` and `ext/` as future surfaces. The new one keeps the
   obligation's three parts (prompts and plan as well as code; just as real;
   easier to miss because nothing fails to compile) and adds one sentence
   saying *why* it is easy to miss (a stale queued prompt is wrong in a way no
   build reports). The case the old paragraph was written for, a consumer with
   no code against a surface (Enterprise as of this phase), is its last
   sentence, and it names no repository.
3. **§2's direction rule.** "an `ext` signature" → "a signature in Control's
   public Go API". It refers to §1's term instead of listing packages, so it
   stays right if a third public package is ever added and §1's row is updated.
   The paragraph is rewrapped; `git diff --word-diff` shows that phrase as the
   only word change in it.

### The greps the prompt required

Run after the edit:

```sh
grep -nw 'ext\|server\|contract\|contract-sync' docs/CROSS-REPO-PROTOCOL.md
grep -n 'exist' docs/CROSS-REPO-PROTOCOL.md
```

| Line | Where | Hit | Done |
| --- | --- | --- | --- |
| 59 | §1, first row | `contract/`, the wire contract | unchanged: correct |
| 60 | §1, second row | `ext/`, `server/` | item 1 |
| 86–87 | §2 | "Control's public Go API"; "does not exist" about a description | item 3 |
| 41 | §0 | "does not exist", about a need | unchanged |
| 179 | §3.2 | "this exists to prevent", the flow's purpose | unchanged |
| 197 | §3.2 | "step 4 exists to remove", a step's purpose | unchanged |
| 207 | §3.2 | Control's phase 0002 and "the contract", history | unchanged (out of scope) |
| 298 | §4.2 heading | "does not exist yet", about a need | unchanged |
| 403 | §4.3 | "not the contract shape" | unchanged |
| 488 | §5 | "These exist because" | unchanged |
| 502 | §5 | the `docs(sync): follow proxy contract v2` example | unchanged |
| 569 | §6 | "vendoring exists to prevent" | unchanged |
| 571 | §6 | "in the contract, it does not exist" | unchanged |

Lines 179, 197 and 569 were not on the prompt's list. Each says what something
is *for*, not whether a surface exists, so none needed a change. The old
paragraph's `contract-sync` hit is gone with the paragraph.

### What was rechecked, and how

The prompt asked for its facts to be rechecked before they were relied on.

- **`hoplock/enterprise`**, cloned read-only at `341c994`: still no code (only
  `docs/`, `prompts/`, `LICENSE`, `README.md`, `.gitignore`); 0001 still in
  `prompts/queued/`, `prompts/implemented/` empty; **E1** and **E3** in its
  register, live, and E3 cites Control's **M23** for what a release is. Its
  `docs/CROSS-REPO-PROTOCOL.md` was byte-identical to this one before the edit
  (`cmp`).
- **`hoplock/control` could not be attached to this session** (the request to
  add it was refused), so its facts were not checked at the source. They were
  checked through Enterprise's docs, which cite them at length: `ext/` "as of
  Control's phase 0004 (control#25)", `server/` "as of Control's phase 0015
  (control#56, release `v0.2.0`)", M15 and M23 by id, and Control releases up
  to `v0.35.0`. The sync session, which has all three repositories checked out,
  is where the Control side is checked directly.
- **This repository's `docs/PROTOCOL.md` and `docs/KICKOFF.md`** point at §1
  and name no Control package (`grep -nw 'ext\|server/\|M15\|M23'` finds
  nothing). Left alone, as the prompt asked.

### Two sentences the syncs must decide about

Both use `ext` where §1 now names two packages. The sync request names both so
neither is missed:

- Control's `docs/PROTOCOL.md` §3: "owns `ext/`, which Hoplock Enterprise
  imports (M15)". Not rechecked from here (see above).
- Enterprise's `docs/PROTOCOL.md` §3: "what to do when `ext` does not yet expose
  what you need (its Section 3.2 …)". Still there at `341c994`. So is E2's "If
  `ext` does not expose what you need, **raise an upstream request**" a few
  lines below it. That one is about extension points, which only `ext` has, so
  it may be right as it stands; the sync decides.

### No test pins the wording

On purpose, as the prompt said. The file is mirrored into two repositories that
do not run this repository's tests, so a test here would pin only one copy and
read as a guarantee about all three. `go test ./test/docs/...` checks only that
§10 still parses with this phase's row updated.

### Nothing else found wrong in the file

Reading it in full turned up nothing else that needed changing.
