# 0010 — Full end-to-end topology & CI gate

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — especially §9 (5-node topology inside one GitHub Actions
  runner), and the learnings summaries from **all** prior phases.
- `docs/learnings/` — read summaries; open any whose setup you must wire
  (esp. `0005` target prerequisites, `0006` chained hops, `0009` log assertions).

## Objective
Assemble the complete **5-node integration topology** and a CI job that exercises
the whole system, then do prototype hardening/cleanup. This is the acceptance
gate for the prototype.

## In scope
- `deploy/`: a `docker compose` topology with the five nodes (PLAN §9):
  1. **management** — `cmd/mock-management` with fixtures covering direct route,
     nexthop route, 401, whitelist & blacklist policies, all four match actions,
     and channel allow-lists.
  2. **user** — image running the scenario SSH client(s).
  3. **bastion-direct** — `cmd/bastion` configured for direct routing.
  4. **bastion-nexthop** — `cmd/bastion` configured to chain to bastion-direct.
  5. **target** — an `sshd` image preloaded with the management cert /
     provisioning account required by 0005.
  All on a shared Docker network; the target reachable **only** via the bastions.
- **Scenario suite** run against the topology:
  - direct route: exec + interactive shell succeed;
  - nexthop route: exec + interactive shell succeed through both hops;
  - authorization denied (401) is refused;
  - channel not on allow-list is refused;
  - blacklisted / non-whitelisted command handled per action
    (block / warn / kill / allow+log);
  - ephemeral user created then removed (assert none left behind);
  - loop / max-hop refused;
  - logs: batch delivered, blocked-command event delivered immediately, outage
    buffering + drain.
- **CI**: a GitHub Actions job that builds images, brings the topology up, runs
  the scenario suite, and tears it down. Gate PRs on it (keep it reasonably fast).
- **Hardening/cleanup**: address TODOs left by earlier phases that block a
  coherent prototype; tidy configs; ensure `README`/`docs/PLAN.md` reflect the
  final prototype state and how to run the topology locally.

## Out of scope
- Real geo/anycast/scale testing (needs real infrastructure — note as future
  work). Production management server.

## Acceptance criteria
- `docker compose` topology comes up cleanly and the full scenario suite passes
  locally and in CI.
- The target is not reachable except through the bastion chain.
- No ephemeral users/keys leak after the suite.
- `docs/PLAN.md` §9 matches what was built; README documents local e2e run.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0010-e2e-topology-and-ci-learnings.md`. Summary block MUST
document how to run the topology locally, the fixture layout, each scenario and
what it proves, and any remaining known gaps to seed the next set of prompts
(e.g. host-key pinning policy, AD/Okta, tamper-evident logs, real distribution).
