# proxy-PR#5 — the privileged-access revision, D13–D17

Backfilled from [proxy#5](https://github.com/Hoplock/proxy/pull/5), which
predates the request queues and handed over no kickoff: its `## Cross-repo
impact` section, verbatim. Both answers were roadmap revisions, not syncs: they
added decisions and phases, which a sync may not. Answered by
[control#3](https://github.com/Hoplock/control/pull/3) and
[enterprise#2](https://github.com/Hoplock/enterprise/pull/2).

> **`hoplock/control`** — D15 places the integration framework there and D17 gives its decision path a magnitude to design against. A branch is prepared (`claude/protocol-privileged-access-usecases-wk94ly`) adding M16 (external access context, with a declarative HTTP provider as the real default M15 requires), M17 (the fleet graph carries capabilities, not just reachability), amendments to M5 and M10, a new phase for the seam, and the obligations landed in the prompts that will implement them. **Per §2 it must not merge before this PR does**, and it is not open yet for that reason.
>
> **`hoplock/enterprise`** — D15 places the shipped Qualys and BMC Helix integrations there. A branch is prepared adding E13 (packaged integrations are packaging, not capability — external access context must never become an Enterprise-only feature, or M15's seam has become a hole), an amendment to E7 (granting access is a larger privilege than ending a session, with a quieter failure mode), and a phase for the two integrations. It follows Control, so it merges third.
>
> No `api/` change in this PR — the contract fields arrive with 0013 and 0015, and each of those carries its own sync appendix.
