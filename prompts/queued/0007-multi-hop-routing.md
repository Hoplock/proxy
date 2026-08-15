# 0007 — Multi-hop / next-hop routing

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — especially §1 (nexthop flow), §2 (D2), §6.1 (multi-hop, loop
  detection, hop limits).
- `docs/learnings/` — read summaries; open `0005` (routing entry points + proxy
  seam for nexthop) and `0002` (route payload shape).

## Objective
Implement **next-hop chaining** so a connection can traverse multiple bastions —
one firewall punch-through per hop — while the target stays reachable only via the
chain. Each hop independently authenticates, authorizes, and routes.

## In scope
- `internal/routing`: handle `route_type == "nexthop"` from the authorize+route
  response. Dial the **next bastion** as an SSH client and hand the session
  through so the next hop repeats the full flow (auth → authorize → route).
- **Chain identity propagation**: define how the user's identity/authorization is
  carried to the next hop. Prefer having each hop authenticate the *previous
  hop/user* per the API contract rather than blindly trusting upstream. Document
  the trust model chosen and reflect it in `docs/PLAN.md` if it refines D2/§6.1.
- **Loop & depth protection**: carry a hop trail; enforce a configurable **max
  hop count**; detect and reject loops with a clear error and audit log.
- Ensure logging captures the hop path (each hop logs its own leg).
- Config: max hops, next-hop dial settings, this bastion's identity as presented
  to downstream hops.

## Out of scope
- Channel inspection/filtering internals (0008/0009). Full logging pipeline (0010).

## Acceptance criteria
- Integration test with two bastions: user → bastion A (nexthop) → bastion B
  (direct) → target. An `exec` and an interactive `shell` both work end to end.
- A loop scenario (A routes to B, B routes back to A) is detected and refused.
- Exceeding max hop count is refused with a clear audit event.
- Each hop performs its own authorize+route call (asserted against the mock).

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0007-multi-hop-routing-learnings.md`. Summary block MUST document
the chain trust model, how identity is propagated between hops, the loop/hop-limit
mechanism, and what the e2e topology (0011) needs to configure two chained hops.
