# 0012 — Full end-to-end topology & CI gate

> Renumbered from 0011 (`docs/PLAN.md` §10, renumbering note). Scope grew with
> the phases before it: relay-mode hops (D11), all three policy axes (D5a), both
> target-credential methods (D6a), and both exec tiers (D12).

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — especially §9 (5-node topology inside one GitHub Actions
  runner), and the learnings summaries from **all** prior phases.
- `docs/learnings/` — read summaries; open any whose setup you must wire
  (esp. `0007` target prerequisites for **both** credential methods, `0008`
  chained hops in both direction modes, `0009` the three policy axes, `0011` log
  assertions).

## Objective
Assemble the complete **5-node integration topology** and a CI job that exercises
the whole system, add the supply-chain gate (`govulncheck`), then do prototype
hardening/cleanup. This is the acceptance gate for the prototype.

## In scope
- `deploy/`: a `docker compose` topology with the five nodes (PLAN §9):
  1. **management** — `cmd/mock-management` with fixtures covering direct route,
     nexthop route in both connection directions, 401, whitelist & blacklist
     policies, all four match actions, restricted-exec policies, channel
     allow-lists, in-channel request policies, forwarding destination lists,
     global-request allow-lists, and both `target_auth` methods.
  2. **user** — image running the scenario SSH client(s).
  3. **bastion-direct** — `cmd/bastion` configured for direct routing.
  4. **bastion-nexthop** — `cmd/bastion` configured to chain to bastion-direct.
  5. **target** — an `sshd` image preloaded with the management cert /
     provisioning account required by 0007's `ephemeral-user`, plus a
     pre-existing unprivileged account standing in for an appliance that
     `brokered-key` reaches without administering it.
  All on a shared Docker network; the target reachable **only** via the bastions.
- **Scenario suite** run against the topology:
  - direct route: exec + interactive shell succeed;
  - nexthop route in `dial` mode: exec + interactive shell succeed through both
    hops;
  - nexthop route in `relay` mode (D11): the same, with the downstream bastion
    **accepting no inbound connections at all** — enforce it in the compose
    network, so the scenario fails if anything but the registered outbound relay
    carried the session. This is the one that proves the architecture's claim
    about not punching inbound holes;
  - a `relay` route with no live registration is refused as an outage, not
    dialled;
  - authorization denied (401) is refused;
  - channel not on allow-list is refused;
  - in-channel request policy (D5a): `sftp` denied while `shell` succeeds;
    `pty-req` denied while `exec` succeeds;
  - forwarding destinations (D5a): a tunnel to the permitted host:port succeeds,
    another host and another port are refused;
  - global requests (D5a): `tcpip-forward` is refused and no listener exists on
    the target afterwards;
  - restricted exec (D12): an approved argv runs, an unapproved one is denied,
    and `sh -c '<denied command>'` is denied under restricted exec while the
    filtered-exec policy lets it through — the tiers are demonstrated to be
    different things, in the product, not only in unit tests;
  - blacklisted / non-whitelisted command handled per action
    (block / warn / kill / allow+log);
  - `ephemeral-user`: user created then removed (assert none left behind);
  - `brokered-key`: session succeeds against the appliance-like account and the
    target is provably unmodified afterwards;
  - loop / max-hop refused;
  - logs: batch delivered, blocked-command event delivered immediately, outage
    buffering + drain.
- **CI**: a GitHub Actions job that builds images, brings the topology up, runs
  the scenario suite, and tears it down. Gate PRs on it (keep it reasonably fast).
- **CI: a `govulncheck` job** (`golang.org/x/vuln/cmd/govulncheck`), running
  `govulncheck ./...` over the module and **failing the build** on any finding.
  - *Why this project specifically:* `golang.org/x/crypto/ssh` is not an
    incidental dependency, it is the bastion's SSH implementation, and its
    advisory rate is high. The v0.44.0 → v0.55.0 bump alone (see the Go 1.26
    chore, `main` history) crossed **15** fixed advisories, of which roughly six
    were server-side DoS/panic issues in `x/crypto/ssh` itself — unbounded
    memory growth, a leak when rejecting channels, a client-triggered server
    deadlock, an infinite loop on large channel writes. Those land in exactly
    the paths 0005–0009 build on, so "is our SSH stack currently vulnerable?"
    must be a CI answer, not a periodic human chore.
  - Prefer `govulncheck`'s default symbol-level analysis over a plain dependency
    scan: it reports only vulnerabilities **reachable** from this module's code,
    which keeps the gate from crying wolf about (say) `ssh/agent` advisories
    that the bastion never calls into.
  - **Network requirement, and the trap it sets:** govulncheck downloads the
    vulnerability database from `https://vuln.go.dev` at run time. GitHub-hosted
    runners can reach it; some development sandboxes cannot, and the failure is
    an opaque `Forbidden`/403 that reads like a broken tool. So: add a
    `make vulncheck` target, have it print an explicit "cannot reach
    vuln.go.dev — this check runs in CI" message on a fetch failure rather than
    a raw error, and do **not** make it a required local step in
    `docs/PROTOCOL.md`'s Definition of Done. CI is where it must pass.
  - Note in the job (a comment) that this check can go red with **no code
    change**, when a new advisory lands against an existing dependency. That is
    the intended signal, not a flake: the fix is to upgrade the dependency, or —
    if no fix exists yet — to record an explicit, dated justification rather
    than deleting the job.
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
- A scenario covers the disclosure rule (PLAN §4.3) end to end: with the
  management server stopped, a connecting user gets a message saying this is an
  outage rather than a permissions problem, carrying the session id — not a
  silent disconnect. A denied user gets the generic "access denied" and nothing
  that reveals the target or the policy. Assert on the client's actual output.
- No ephemeral users/keys leak after the suite.
- The `govulncheck` job runs on every PR, passes on the tree as it stands, and
  demonstrably fails on a known-vulnerable input — verify once by temporarily
  downgrading `golang.org/x/crypto` to v0.44.0 and confirming the job reports
  the `x/crypto/ssh` findings, then revert. A gate nobody has seen fail is not
  known to be a gate.
- `docs/PLAN.md` §9 matches what was built; §8's CI list names every job that
  now gates a PR, including `govulncheck`; README documents local e2e run and
  `make vulncheck` (including that it needs network access to `vuln.go.dev`).

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0012-e2e-topology-and-ci-learnings.md`. Summary block MUST
document how to run the topology locally, the fixture layout, each scenario and
what it proves, how the `govulncheck` gate is wired (and what to do when it goes
red without a code change), and any remaining known gaps to seed the next set of
prompts (e.g. host-key pinning policy, AD/Okta, tamper-evident logs, real
distribution).
