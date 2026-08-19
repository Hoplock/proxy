# 0008 — Multi-hop / next-hop routing

> Renumbered from 0007 (`docs/PLAN.md` §10, renumbering note). Scope grew: hops
> are reached over **outbound relay registrations** as well as by dialling
> (D11).

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — especially §1 (nexthop flow), §2 (D2, **D11**), §6.1
  (multi-hop, connection direction, loop detection, hop limits), §6.4 (why the
  revocation stream is outbound — D11 is the same argument one layer down).
- `docs/learnings/` — read summaries; open `0006` (hop direction in the
  contract), `0005` (routing entry points + proxy seam for nexthop) and `0002`
  (route payload shape).

## Objective
Implement **next-hop chaining** so a connection can traverse multiple proxies
while the target stays reachable only via the chain — and so a proxy in a
protected zone needs **no inbound firewall rule at all**. Each hop
independently authenticates, authorizes, and routes.

## In scope
- `internal/routing`: handle `route_type == "nexthop"` from the authorize+route
  response. Reach the **next proxy** and hand the session through so that hop
  repeats the full flow (auth → authorize → route).
- **Connection direction (D11)**, from 0006's hop metadata:
  - `dial` — open a connection to the next proxy, as before.
  - `relay` — use a connection the **downstream proxy already opened to this
    one**, and open a channel over it. This is what removes the inbound rule per
    enclave, and it is the mode that matters for segmented estates.
  - A `relay` hop with no live registration fails as an **outage** (PLAN §4.3)
    naming the session id. It is never downgraded to `dial` — that would punch
    through the boundary the mode exists to preserve.
- **Relay registration** (the other half of `relay`): a proxy configured with
  an upstream opens a long-lived outbound connection to it and registers under
  its proxy id; the upstream keeps one registration per id and multiplexes
  sessions over it. Reconnect with backoff; a dropped registration must not kill
  sessions already flowing over it beyond what the transport forces. Model it on
  `internal/control`'s revocation stream (§6.4) — same problem, same direction,
  and its reconnect/heartbeat behaviour is already proven.
  - The upstream **authenticates the registering proxy** — a registration is
    an inbound path into this proxy's routing, so an unauthenticated one is a
    way to receive other people's sessions. Reuse the host-key/cert machinery
    rather than inventing a scheme; document the trust model.
- **Chain identity propagation**: define how the user's identity/authorization
  is carried to the next hop. Prefer having each hop authenticate the *previous
  hop/user* per the API contract rather than blindly trusting upstream. Document
  the trust model chosen and reflect it in `docs/PLAN.md` if it refines D2/§6.1.
- **Loop & depth protection**: carry a hop trail; enforce a configurable **max
  hop count**; detect and reject loops with a clear error and audit log.
- Ensure logging captures the hop path **and the direction of each leg** (each
  hop logs its own leg).
- Config: max hops, next-hop dial settings, upstream to register with (and
  whether to accept registrations), this proxy's identity as presented to
  other hops.

## Out of scope
- Channel inspection/filtering internals (0009/0010). Full logging pipeline (0011).
- Choosing the direction: that is Hoplock Control's decision, delivered in
  the route. This phase implements both and obeys.

## Acceptance criteria
- Integration test with two proxies in `dial` mode: user → proxy A (nexthop)
  → proxy B (direct) → target. An `exec` and an interactive `shell` both work
  end to end.
- The same test in `relay` mode, with **proxy B accepting no inbound
  connections** (assert this — bind B's listener such that A genuinely cannot
  reach it, so the test fails if the relay path is not what carried the
  session). This is the acceptance criterion that proves D11.
- A relay-registration reconnect test: the link drops, B re-registers, a new
  session succeeds.
- A `relay` route with no registration is refused as an outage, with the session
  id in what the user sees, and is never dialled.
- A loop scenario (A routes to B, B routes back to A) is detected and refused.
- Exceeding max hop count is refused with a clear audit event.
- Each hop performs its own authorize+route call (asserted against the mock).

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0008-multi-hop-routing-learnings.md`. Summary block MUST document
the chain trust model, how identity is propagated between hops, the relay
registration protocol and how the upstream authenticates a registering proxy,
the loop/hop-limit mechanism, and what the e2e topology (0012) needs in order to
configure a chained pair in **each** direction mode.
