# proxy-PR#73 — the request queues

Backfilled from [proxy#73](https://github.com/Hoplock/proxy/pull/73), which
predates the request queues and handed over no kickoff: its `## Cross-repo
impact` section, verbatim. It queued no file on purpose: it introduced the
queues, and its syncs were opened straight from the same session. Answered by
[control#49](https://github.com/Hoplock/control/pull/49) and
[enterprise#13](https://github.com/Hoplock/enterprise/pull/13).

> **`hoplock/control`** and **`hoplock/enterprise`** have the same obligations:
> 1. Mirror `docs/CROSS-REPO-PROTOCOL.md` verbatim.
> 2. Add `prompts/upstream/` and `prompts/downstream/`, each with `queued/`, `implemented/`, and a README stating the target.
> 3. Add the "Next cross-repo request" block to `docs/KICKOFF.md`, and turn the sync and request blocks from pasted into queued.
> 4. Update every live reference that tells a session to paste a kickoff into a reply or into a fresh single-repository session:
>    - control: `docs/PROTOCOL.md`, `README.md`, the cross-repo-impact audit, and queued prompts 0018, 0020 and 0021;
>    - enterprise: `docs/PROTOCOL.md` and `README.md`.
> 5. Add the same queue-shape test, checking each repository's own prefix. Enterprise's version also keeps `downstream/` empty.
>
> Both are already prepared on `claude/cross-repo-protocol-org-vkjf20` in each repository, with the mirror as a separate `docs(sync)` commit. As requested, they open one at a time after this merges: control first, then enterprise.
>
> **No request file is queued here for them.** This PR introduces the queue, and the syncs are being opened directly from this session. A queued file would only need a fourth PR to move it to `implemented/`.
