# The end-to-end topology

The whole system, in containers, on Docker networks that make its segmentation
claims checkable rather than merely stated. This is the prototype's acceptance
gate (`docs/PLAN.md` §9): the scenario suite in `test/e2e` drives it, and CI runs
both on every pull request.

```
make e2e          # up, run the scenario suite, tear down
make e2e-up       # up, and leave it running (for debugging a failure)
go test -tags e2e -count=1 -v ./test/e2e/          # re-run against a live topology
go test -tags e2e -count=1 -v -run 'TestTopology/routing' ./test/e2e/
make e2e-down     # stop it and delete everything it generated
```

You need Docker (with the compose plugin), Go, and `ssh-keygen`. Nothing else,
and nothing outside this repository.

## The nodes

| Service | Role | Networks |
| --- | --- | --- |
| `control` | the mock Hoplock Control (`cmd/mock-control`) — every decision comes from here (D2, D3) | edge, core |
| `user` | the OpenSSH client the scenarios drive | edge |
| `proxy-direct` | an edge proxy that reaches the target itself, and the far end of the `dial` chain | edge, core |
| `proxy-nexthop` | an edge proxy that reaches the target ONLY by chaining, and the relay hub | edge, relay |
| `proxy-zone` | a proxy in a protected zone: no inbound listener at all, reached over the relay registration it opens (D11) | core, relay |
| `target` | a real `sshd` with the prerequisites both credential methods need (D6, D6a) | core |
| `device` | a fake FortiOS appliance (`cmd/fake-device`): a CLI over SSH with no `useradd` and no `authorized_keys`, which is what `ephemeral-account` exists for (D13) | core |

The `device` node was added by phase 0014. There is no way to put real network
gear in CI, and without a stand-in the device credential method would be the one
part of the system no real SSH client ever exercises — on a product whose first
claim is reaching the gear nothing else reaches. It speaks the CLI
`internal/sshtest` models, paging and failure modes included, and it is on
`core` for the same reason the target is: reachable through a proxy and by
nothing else.

`docs/PLAN.md` §9 names five node *roles*. There are two proxies playing the
downstream role because the two hop directions make incompatible demands on one:
`dial` needs a downstream that accepts an inbound connection, and the whole
point of `relay` is a downstream that accepts none. One container cannot
demonstrate both, and a relay scenario run against a proxy that *does* listen
proves nothing.

### What the networks are load-bearing for

- `edge` — the user node, the two reachable proxies, and Hoplock Control.
- `core` — `internal`, and **the user node is not on it**. The target is
  reachable only through a proxy; that is a property of the topology rather than
  a promise, and the first scenario asserts it.
- `relay` — `internal`. `proxy-zone`'s outbound path to `proxy-nexthop`'s
  registration listener, and nothing else.

`proxy-nexthop` is deliberately absent from `core`: a chained session that
reached the target cannot have been served locally.

`proxy-zone` binds its SSH listener to loopback inside its own container
(`proxy/proxy-zone.yaml`, asserted in `test/topology`), publishes no port, and
the route that reaches it names `proxy-zone.no-inbound.invalid` — an address
that cannot resolve. A relayed session that arrives has provably travelled over
the registration `proxy-zone` opened outbound.

## Key material and fixtures

`gen-material.sh` generates every key into `keys/` and renders
`control/fixtures.yaml` from `control/fixtures.template.yaml`. Neither is
committed: the fixtures name keys by SHA256 fingerprint, so they cannot be
written before the keys exist. Everything is mounted at run time rather than
baked into an image — material inside an image is material shared by everyone
who has the image — so regenerating never requires a rebuild.

`control/fixtures.template.yaml` is where the scenarios' behaviour is decided.
Each route says which scenarios it backs, so a failing scenario leads to one
rule rather than to a search.

## Three things the target image must not change

- **`UsePAM yes`.** `useradd` leaves a new account with a locked password, and
  with `UsePAM no` `sshd` refuses it outright — *"not allowed because account is
  locked"* — before it ever looks at the key the proxy just installed. Every
  `ephemeral-user` session (D6) would fail. The stock Debian `sshd_config`
  already has it; the point is not to "harden" it away.
- **`root` reachable with the management key.** That is the privileged
  provisioning account D6 needs, and `netadmin` is the account that already
  exists for `brokered-key` (D6a) — the appliance the proxy cannot administer. A
  scenario that finds `netadmin` modified has found a bug.

- **`PerSourcePenalties no`.** A decrypting proxy is a *single source address*
  to every target it fronts — that is the deployment model, and it collides with
  sshd's per-source abuse defences, which exist to slow down many distinct
  attackers rather than one trusted enforcement point. Anything that makes the
  proxy's credential fail against a target is scored against the **proxy's**
  address, not the user who triggered it, so on OpenSSH ≥ 9.8 a handful of
  failures gets the proxy dropped outright —
  `drop connection #0 from [proxy] ... penalty: failed authentication` — which
  surfaces at the proxy as a bare `connection reset by peer` and reads like a
  network fault. Phase 0012 hit exactly this, from a `.ssh` directory owned by
  root, and one misconfigured route took out every scenario on that proxy.

  Turning it off is right for a target reachable only through a proxy: the
  defence has no distinct sources left to distinguish. It also keeps this suite
  honest — prompt 0019's containment scenarios have to be proven by the proxy's
  own behaviour, not by the target giving up on it. The entrypoint applies each
  directive only if this `sshd` understands it. **A real fleet has to make the
  same decision deliberately**; `prompts/queued/0019-*` is the proxy-side half.

`make test-sshd` runs the phase-0007 credential tests against this same image
on its own (`target/compose.yaml`), published on a host port.

## Debugging a failed scenario

`make e2e-up` leaves everything running, so:

```
docker compose -p hoplock-e2e -f deploy/compose.yaml logs proxy-direct
docker compose -p hoplock-e2e -f deploy/compose.yaml exec target getent passwd
curl -s http://127.0.0.1:18080/debug/logs | jq '.priority'
curl -s http://127.0.0.1:18081/debug/accounts | jq
```

`http://127.0.0.1:18080` is the mock's debug view, published on loopback for the
scenario driver. Nothing in the topology reaches Hoplock Control that way.

`http://127.0.0.1:18081/debug/accounts` is the appliance's administrator table,
on the same terms. It exists because an appliance has no account database to
read the way `getent passwd` reads the target's — and asserting the proxy's
cleanup by driving the same CLI the proxy used to do it would be asserting on
the thing under test. An `hl-` account still listed after a run is a device
administrator that was not removed.
