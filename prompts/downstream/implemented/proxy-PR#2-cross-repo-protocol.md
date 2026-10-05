# proxy-PR#2 — the cross-repository protocol

Backfilled from [proxy#2](https://github.com/Hoplock/proxy/pull/2), which
predates the request queues and handed over no kickoff: its `## Cross-repo
impact` section, verbatim. The three PRs were opened together, as the protocol
then required. Answered by
[control#2](https://github.com/Hoplock/control/pull/2) and
[enterprise#1](https://github.com/Hoplock/enterprise/pull/1).

> - **`hoplock/control`** — Hoplock/control#2 carries the mirrored file and its own `PROTOCOL.md` bullet, scoped to Control sitting in the middle of the chain (consumes the contract, owns `ext/`).
> - **`hoplock/enterprise`** — Hoplock/enterprise#1, same file, bullet scoped to the end of the chain: following a Control change rather than causing one, which is the work most likely to be skipped because nothing fails until someone builds against a moved `ext` signature.
>
> Both are mirrors of this PR. Merge this one first; §6 has the file changed here and mirrored in the same change-set, which is why all three are open at once rather than waiting on each other in the §2 order that governs every *other* shared surface.
