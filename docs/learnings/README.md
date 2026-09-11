# Learnings

One file per implemented prompt, named `NNNN-short-description-learnings.md`
matching the prompt it corresponds to (see `docs/PROTOCOL.md` §5).

Each file **must** open with a `## Summary` block so future sessions can decide
whether to read the full body. Sessions read every summary block here at startup
and only open a full file when it's relevant to their prompt.

This folder is the durable hand-off channel between otherwise-independent fresh
sessions. Keep summaries tight; put depth under `## Details`.

A file here does **not** always have a matching prompt in `prompts/implemented/`.
A phase whose prompt made it conditional can end in a reasoned decision **not**
to build it, and that decision is exactly the kind of thing a future session must
not have to re-derive — so it is written up here and the prompt is deleted rather
than moved. `0021` and `0030` are those files today. Their numbers stay retired:
the uniqueness rule in `docs/PROTOCOL.md` §6 covers a withdrawn phase like any
other.

## A note on the Hoplock rename

Every file in this folder predates the rename from `SecureCommandProxy` to
**Hoplock Proxy** and was rewritten by it: `internal/mgmt` reads as
`internal/control`, "the bastion" as "the proxy", "the management server" as
"Hoplock Control". The rewrite was deliberate — these files are reference
material future sessions rely on, and a learnings file naming packages that no
longer exist is worse than one whose git history shows an edit.

Names on the wire (`bastion_id`, `/v1/bastions/…`) were **not** renamed. See
`docs/PLAN.md` §11 for the full mapping and why.
