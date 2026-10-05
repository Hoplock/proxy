# proxy-PR#6 — multi-hop chains: the chain leg and hop_trail

Backfilled from [proxy#6](https://github.com/Hoplock/proxy/pull/6), which
predates the request queues and handed over no kickoff: its `## Cross-repo
impact` section, verbatim. Answered by
[control#5](https://github.com/Hoplock/control/pull/5).

> Per `docs/CROSS-REPO-PROTOCOL.md` §4. `api/control.yaml` is **unchanged**; `api/README.md` gained a section describing how a chained hop uses the existing endpoints, so this touches a shared surface.
>
> **hoplock/control** — two behavioural obligations, no new fields:
>
> 1. `POST /v1/auth/cert` must recognise a key belonging to one of the fleet's own proxies as a **chain leg** and answer with the identity of the `login` in the request, established by Control itself. Without this, a chained hop cannot authenticate at all. (`cmd/mock-control` models it with its new `proxies[]` fixtures.)
> 2. `POST /v1/authorize` should read `conn.hop_trail` (already in the contract since 0002) — it is the proxies' view of the chain and the server's only way to see one.
>
> How I checked: `grep -rn 'hop_trail\|hop\.connection\|next_proxy_id\|auth/cert'` across `api/`, `docs/`, `prompts/`, and `README.md` in this repo; the contract schema is byte-identical to `main`, so nothing vendored downstream changes shape. A sync PR against `hoplock/control` follows this merge, per §3.1.
>
> **hoplock/enterprise** — None. It consumes `ext/`, which this does not touch.
