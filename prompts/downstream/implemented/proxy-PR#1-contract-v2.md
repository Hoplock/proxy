# proxy-PR#1 — contract v2: proxy_id and policy_version

Backfilled from [proxy#1](https://github.com/Hoplock/proxy/pull/1), which
predates the request queues and handed over no kickoff: its `## Note for the
sibling repos` section, verbatim. Answered by
[control#1](https://github.com/Hoplock/control/pull/1).

> `Hoplock/control`'s plan already anticipated this vocabulary, but three spots go stale the moment it re-vendors the contract (`prompts/queued/0009:10`, `prompts/queued/0006:26`, `docs/PLAN.md:312` — all still `bastion_id` / `/v1/bastions/`), and nothing there covers the new `policy_version` obligation. `Hoplock/enterprise` is unaffected: it reaches Control through its `ext/` package and touches the contract nowhere. A follow-up PR against Control is queued behind this one.
