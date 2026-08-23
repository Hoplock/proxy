# 0008 — Multi-hop / next-hop routing — Learnings

## Summary
- What shipped: chaining. A session can traverse several proxies, each running
  the whole flow (authenticate → authorize → route) for itself, in **both**
  connection directions (D11): `dial`, and `relay` over a connection the
  downstream proxy opened to its upstream — so a protected zone needs no inbound
  firewall rule. Plus hop trail, loop detection, hop cap, and the relay
  registration protocol. **No contract change** (`api/control.yaml` untouched).
- Key packages/files: `internal/routing/hop.go`, `internal/relay/*` (new
  package: `hub.go`, `registrar.go`, `authz.go`, `conn.go`, `protocol.go`),
  `internal/proxy/{nexthop.go,session.go,proxy.go,channel.go,feedback.go}`,
  `internal/config/config.go` + `config.example.yaml` (new `chain:` section),
  `cmd/proxy/main.go`, `cmd/mock-control/{fixtures,server}.go` +
  `fixtures.example.yaml`, `cmd/mock-control/chain_e2e_test.go`,
  `docs/PLAN.md` §3 + §6.1, `api/README.md`.
- Key types: `routing.{Chain,HopTrail,HopPlan,PlanHop,MarshalChain,ParseChain,
  IsHopPeer,HopClientVersion,RequestHopTrail,DefaultMaxHops}` + `ErrHopLoop`,
  `ErrHopLimit`, `ErrHopContract`; `relay.{Hub,Registrar,Authorizer,
  ErrNoRegistration,ChannelSession}`; `proxy.{RelayOpener,Server.ServeConn}` and
  `Options.{HopSigner,RelayOpener,MaxHops}`. `routing.Route` gained
  `IsNextHop`/`FinalTarget`/`MaxHops`; **`RequireDirect` is gone** — the engine
  dispatches on the type, which was that seam's documented fate.
- **Chain trust model.** Every hop
  authenticates the hop in front of it *through Hoplock Control*: the upstream
  proxy connects as `login<delimiter>final_target` and offers **its own chain
  identity key** (`chain.identity_key_path`), never the user's. Control
  recognises the key as one of its own proxies and answers with the **user's**
  identity, which it establishes itself. No proxy asserts an identity and none
  takes one on trust: a compromised proxy can only offer its own key, and the
  PDP decides what that key may assert.
- **Hop trail / loops / cap.** After authenticating and before opening any
  channel, the upstream sends the connection-level request
  `hop-trail@hoplock.io` (trail, final target, cap). The receiving proxy knows
  to wait for it because the peer's SSH client version is
  `SSH-2.0-Hoplock_Proxy_hop`; a peer that announces itself and sends no trail
  within 10s is refused, never served with an empty one. The trail carries **no
  authority** — every entry can only cause a refusal — and reaches Control as
  `conn.hop_trail`. Refuse on: own id in the incoming trail, `next_proxy_id` in
  the trail, or exceeding the strictest of (inherited cap, route `max_hops`,
  local `chain.max_hops`, `DefaultMaxHops` = 4). Both refusals are **outages**
  with the session id plus an `audit=hop_refused` log line.
- **Relay registration.** Downstream keeps one outbound SSH connection to the
  upstream's registration listener (backoff modelled on the revocation stream);
  the upstream opens a `relay-session@hoplock.io` channel over it per session
  and hands the byte stream to `Server.ServeConn`. The upstream authenticates
  registrations with an `authorized_keys` file **whose comment names the proxy
  id that key may claim**, or a trusted CA whose user certificate must name the
  claimed id as a principal. One registration per id; a re-registration replaces
  the old one. A `relay` hop with no registration is an outage and is **never**
  dialled.
- Decisions made/affected: D11 (implemented, and §6.1 refined in this PR), D2,
  D7 (the next hop's host key is reported like any other), PLAN §4.3.
- What the NEXT session must know: `internal/proxy` now dispatches on
  `route.Type`; `RequireDirect` no longer exists. `serveGlobalRequests` takes an
  `intercept` func and it runs **before** the far connection is resolved — do
  not move that, it is what stops the hop trail from deadlocking against setup.
  The mock's route fixtures now match on `proxy_id`, which is how one fixture
  file describes a chain.

## Details

### Why the trail rides an SSH global request, and why the version string gates it

The trail has to reach the next hop **before** it authorizes, and SSH gives no
pre-authentication field a peer controls except the identification string.
Global requests are the only in-band connection-level mechanism after that, so
the trail is one — but a proxy cannot block every session waiting for a request
most clients will never send. Hence the split: the client version says "expect a
trail", the global request carries it, and `session.setup` waits only for peers
that announced themselves.

Spoofing the version string buys nothing. A user that claims to be a hop must
then send a trail or be refused, and any trail they do send can only shorten
their own chain or trip loop detection. The authority on a chain leg is the
previous hop's key, which Control validates — see the trust model above.

`serveGlobalRequests` consults `intercept` before calling `dst()`. That ordering
is load-bearing: `dst()` for the client direction is `legConnWhenReady`, which
blocks on setup, which is blocking on the trail. Resolving the destination first
would deadlock the session against its own precondition.

### Why the relay is SSH rather than a bespoke framing

The registration needed authentication, multiplexing, keepalives, and a
bidirectional byte stream. That is SSH, and the fleet already has SSH keys and
(optionally) a CA. Reusing it means `ssh.CertChecker` does the certificate work,
`Conn.OpenChannel` runs server→client without ceremony, and a relayed session is
a `net.Conn` the existing engine serves unchanged — the whole reason
`Server.ServeConn` exists.

The one inexact part of the `net.Conn` adaptation is deadlines: an SSH channel
has none, so `channelConn.SetDeadline` arms a watchdog that **closes** the
channel when it fires. Both callers (the unauthenticated-connection bound and
the handshake bound) want a close at the deadline anyway.

### Direction is obeyed, never inferred

`PlanHop` refuses a `relay` hop with no `next_proxy_id` (`ErrHopContract`) and
the engine refuses one whose registration is missing (`stageRelay` → "the next
proxy in the chain is not currently connected"). There is deliberately no
fallback path from `relay` to `dial` anywhere in the code: the whole value of
the mode is the boundary it preserves, and a downgrade would breach it exactly
when nobody is watching. The `dial` failure is a separate stage (`stageHopDial`)
so an operator can tell "not connected" from "not reachable".

### New config (`chain:`)

```yaml
chain:
  identity_key_path: /etc/hoplock/chain_identity   # presented to other proxies
  identity_cert_path: ""                            # optional, CA fleets
  max_hops: 4
  upstream:                                         # register with an upstream
    address: ""                                     # empty disables
    host_key_path: ""                               # REQUIRED when address is set
    dial_timeout: 15s
    keepalive_interval: 10s
    min_backoff: 1s
    max_backoff: 30s
  accept:                                           # host registrations
    listen_addr: ""                                 # empty disables
    host_key_path: ""                               # defaults to proxy.host_key_path
    authorized_keys_path: ""                        # comment = proxy id
    trusted_ca_path: ""
    keepalive_interval: 10s
```

Validation: registering requires the upstream's host key (**no TOFU between
proxies** — fleet keys are known at deployment time, unlike a target's, D7) and
an identity key; accepting requires at least one trust source. Timing-only
values with the feature disabled are not treated as "configured", so the
documented defaults can stay in `config.example.yaml`.

There is deliberately no separate "next-hop dial timeout": a hop leg is bounded
by `dial.dial_timeout`, the same bound as a target leg, because it is the same
thing from the user's point of view — time spent waiting at a prompt. The relay
side has its own timings because a registration is long-lived and reconnects,
which a session dial never does.

Note the delimiter: a proxy asks the next hop for `login<delimiter>final_target`
using **its own** `routing.target_delimiter`, so a chained fleet must agree on
it. Making it per-hop config would just be a second place to get it wrong.

### What phase 0012 (e2e topology) needs

The compose topology already lists a "Proxy (next-hop)" node. To configure a
chained pair:

**Both directions, on both proxies:** a `chain.identity_key_path` keypair each,
and `proxies:` entries in the mock fixtures listing each proxy's public-key
fingerprint (that is what makes a chain leg authenticate). Routes must carry
`proxy_id` so the edge proxy is answered `nexthop` and the far proxy `direct`
for the same login and target.

**`dial`:** the edge proxy's route sets `next_hop` + `target_port` to the far
proxy's listener; the far proxy needs its normal `proxy.listen_addr` reachable
from the edge container.

**`relay`:** the edge proxy sets `chain.accept.listen_addr` plus an
`authorized_keys_path` whose single line is the far proxy's identity public key
with the comment `<far proxy id>`; the far proxy sets `chain.upstream.address`
to that listener and `chain.upstream.host_key_path` to the edge proxy's host
public key. The route sets `hop_connection: relay` and `next_proxy_id`.
`next_hop` is still required by the fixture schema and should be pointed at
something **unreachable** (`cmd/mock-control/chain_e2e_test.go` uses
`b.no-inbound.invalid`), which is what makes the test prove the relay carried
the session. In compose, the far proxy should publish no ports and ideally sit
on a network the edge cannot route to.

### Cross-repo (docs/CROSS-REPO-PROTOCOL.md)

`api/control.yaml` is unchanged; `api/README.md` gained a description of how a
chained hop uses the **existing** endpoints. The obligation this creates for
`hoplock/control` is behavioural, not structural, and is listed in the PR's
`## Cross-repo impact` section: recognise a fleet proxy's own key on
`POST /v1/auth/cert` and answer with the user's identity, and read
`conn.hop_trail` on `POST /v1/authorize` (the mock models both).

### Test notes

- `cmd/mock-control/chain_e2e_test.go` runs the same two-proxy body for `dial`
  and `relay`: exec and an interactive shell end to end, plus an assertion that
  each hop called authorize for itself with the right trail. The relay case
  asserts up front that the address in the route is unreachable, so a session
  arriving at the target can only have travelled the registration.
- Also there: relay reconnect (`Hub.Drop` then a fresh session), a relay hop
  naming an unregistered id, a loop (B routed back to A), and the hop cap.
- `internal/relay/relay_test.go` covers the registration round trip, an
  unauthorized key, a key claiming another proxy's id, certificate
  registration, reconnect, re-registration replacing the previous, and a fatal
  vs. retryable handshake failure.
- `internal/proxy/nexthop_test.go` covers the engine's refusals (missing
  registration, no relay at all, loop, cap, no chain identity) and the audit
  lines.

### Follow-ups (not done here, deliberately)

- Nothing in this phase inspects or filters what crosses a hop — that is
  0009/0010, and it applies per hop because each hop enforces its own policy
  snapshot.
- The hop leg's own logging is `log.Printf` like the rest of the engine; 0011
  turns these into structured records, and the hop path and per-leg direction
  are the fields to keep.
