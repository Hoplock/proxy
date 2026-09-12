# 0033 — Chain identity rejection — Learnings

## Summary
- What shipped: a next hop refusing this proxy's **chain identity key** (D11) is
  now its own classified failure instead of a network fault. Sections 1–3 of the
  prompt in full; section 4's containment question is answered **NO**. No
  contract change, no new mechanism, `RejectionBreaker` untouched.
- Key packages/files: `internal/proxy/{nexthop,feedback,logging}.go` +
  `internal/proxy/hopreject_test.go` (new), `internal/auth/target/reject.go`
  (doc only), `cmd/mock-control/chain_e2e_test.go`, `docs/PLAN.md` §6.1 + §10,
  `deploy/` (`compose.yaml`, `gen-material.sh`, `proxy/proxy-stranger.yaml`
  (new), `control/fixtures.template.yaml`, `README.md`), `test/e2e/*`,
  `test/topology/config_test.go`.
- **New stage and wording** (`feedback.go`): `hop-auth` → *"this proxy was not
  accepted by the next proxy in the chain"* — an **outage** (§4.3) with the
  session id, naming neither the next proxy, its address, the key, nor how far
  the chain got. Third member of the family beside `hop-dial` and `relay`; the
  `takeHostKeyErr` branch still runs first.
- **New record:** one critical `error` record, `chain.identity_rejected`, with
  `hop_next_proxy`, `hop_connection`, `stage`, and `credential_handle` — the
  **SHA256 fingerprint of `chain.identity_key_path`'s public half**, which is
  what joins this record to the far hop's own. Never material, never a path.
- **Containment: NO, deliberately.** 0025's breaker was bought by a property of
  an OpenSSH *target*; the far end here is another Hoplock proxy with no such
  defence, a `relay` hop opens **no** connection to withhold, and a refused
  chain key is permanent until registered — so a cooldown stacks a second outage
  between the operator's fix and service returning. Reasoning in Details, short
  form in `docs/PLAN.md` §6.1, and the trigger for revisiting it is there too.
- **`target.IsAuthRejection` is still the tree's single copy of x/crypto's
  wording** and did not move; its doc says "far side" now, its tripwire test
  stayed put. No other place still reports a far-side refusal as a network fault.
- What the NEXT session must know: `deploy/` gained a fourth proxy,
  **`proxy-stranger`**, whose chain key `gen-material.sh` generates and the
  fixtures deliberately never register. **Registering it anywhere breaks the
  scenarios** — `test/topology` asserts the absence.

## Details

### Why the classifier did not move

The prompt offered a move to a package both planes could import "if importing
`internal/auth/target` from the chain path reads wrong". It does not read wrong
enough to pay for it: `internal/proxy` already imports that package (it takes
`ProvisionedAccess`, `RejectionKey` and `WithheldError` from it), the function
is named `IsAuthRejection` rather than `IsTargetRejection`, and a new package
would be a `docs/PLAN.md` §3 layout change carrying the tripwire test with it —
the one test in the tree whose whole job is to fail loudly on an x/crypto
upgrade that rewords the error. Moving it would have risked that for a naming
preference.

What did change is the doc comment: the function is about **the far side of an
SSH handshake refusing what this proxy offered**, on either leg, and the file
header now says why it lives where it lives. A future reader asking "is there a
second copy of this string" gets the answer in the file itself.

### The ordering, and why it is worth a test

`handshakeNextHop` now asks three questions in order — host key, rejection, then
everything else — and that is the same order `dialTarget` asks them in. A
rejected host key also surfaces as a handshake error from `ssh.NewClientConn`,
and it is a different failure with a different fix: nothing about our credential
was refused. `TestAHopHostKeyFailureStillWinsOverTheRejectionBranch` drives both
failures at once and asserts the host-key wording wins *and* that no
`chain.identity_rejected` record was produced. On the target leg the equivalent
mistake would also have scored a breaker; here it would only have misfiled a
record, which is exactly why it is easier to get wrong and worth pinning.

### The containment decision, in full

The prompt is explicit that either answer is a result and that the reasoning is
the deliverable. Four things decide it.

**1. The blast radius that justified 0025 does not exist.** That breaker was
bought by a property of the *far end*: an OpenSSH target scores failed
authentications against the connecting address (`PerSourcePenalties`, on by
default since 9.8), and a decrypting proxy is one address for every user it
fronts — so one route's stale credential got the proxy blocked for everybody,
including users whose own credentials were fine. The far end of a chain leg is
**another Hoplock proxy**, built on `x/crypto/ssh`. It has no per-source penalty
mechanism, nothing in this repository implements one, and a refused chain leg
therefore costs exactly the sessions that were going to fail anyway. There is no
population of innocent sessions being protected.

**2. The two directions are not alike, and a breaker would have to lie about
one.** On `dial` the retry costs a TCP connection to the far hop, through
whatever the estate put in front of it — D11's "single firewall punch-through
per hop" is a firewall, and a firewall may well be counting. On `relay` it costs
**no new connection at all**: the downstream proxy already registered outbound
and the handshake rides that registration (`relay.Hub.Open` opens a channel over
an existing transport). If the argument for containment is "stop opening
connections", it is simply absent on half of D11. A breaker keyed alike across
both would be asserting something untrue about the relay direction; a breaker
keyed only on `dial` would be a mechanism that is on for half the architecture,
with a config knob operators have to reason about per route. Neither is worth
what is being bought.

**3. What is left on `dial` is small and self-limiting.** The rate is "sessions
routed through this hop", set by user arrivals, and every one of them fails
either way. The connection is refused at authentication rather than held open.
The far hop's own Hoplock Control sees one authenticate call per failing
session — the same call it makes for a successful one, so there is no
amplification there either. It is load and log noise at the far hop, which is a
real cost and not one a cooldown is the right instrument for.

**4. The cost side is *worse* here than on the target leg, and this is the part
that decides it.** A fingerprint the far hop's Control does not know stays
unknown until somebody registers it. That cuts both ways, as the prompt says:
retrying is more clearly futile, and withholding is more clearly a **second
outage stacked on the first**. The moment an operator registers the key, service
should return; a breaker would hold the chain down for up to a cooldown longer,
with nothing the operator can read that explains why their fix did not take. On
the target leg that cost was worth paying because not paying it blocked the
target wholesale. Here it buys nothing and is charged to the person fixing the
problem.

So: classification, disclosure and the record, which are what actually shorten
the remedy loop. An operator now sees a **critical** record on D8's immediate
path naming the far hop, the direction, and the fingerprint they can join
against the far hop's own logs — the three things they need to register the
right key on the right server. Retries are what keeps that signal arriving.

**If this is ever revisited**, the trigger to watch for is the first one of these
becoming true: a Hoplock proxy growing a per-source defence of its own (at which
point the far end starts behaving like an OpenSSH target), or a measured case of
a firewall in front of a `dial` hop penalising the connection rate. Either would
change fact 1 or fact 3, and the mechanism is already in the tree — reuse
`RejectionBreaker` keyed on `(next hop address, "chain-identity", fingerprint)`,
add `stageHopWithheld` on 0025's pattern, and put the config under `chain.` and
not `auth.target.`, which is the other plane.

### Is anywhere else still reporting a far-side refusal as a network fault?

No. The sweep this phase did:

- `dialTarget` — fixed by 0025.
- `handshakeNextHop` — this phase.
- `admin.go`'s management login for `ephemeral-user` — surfaces a refused
  management certificate as `stageProvision`, *"credentials for the target could
  not be provisioned"*. Coarse but honest, and 0025 scoped it out for that
  reason. Unchanged.
- `device.SSHShellDialer` (0014) — its own dial path, still uncontained and
  still not claiming a network fault of its own; it should adopt
  `ProvisionedAccess.DialOutcome` rather than grow anything, which stays that
  phase's to do.
- `relay` registration (`internal/relay/registrar.go`) — a downstream proxy
  whose registration the *upstream* refuses. It is not a session failure at all:
  it is a background reconnect loop with bounded backoff and no user waiting on
  it, and it is already reported as a registration failure rather than as an
  unreachable upstream. Left alone.

### The e2e topology, and the node that is defined by an absence

The mock Hoplock Control in `deploy/` is one instance shared by every proxy, and
the `proxies:` list is global — so "a chain identity the far hop does not
recognise" cannot be arranged by editing an existing proxy's fixtures without
breaking every chain scenario that proxy already backs. The topology therefore
gained a fourth proxy, **`proxy-stranger`**:

- `gen-material.sh` generates `hostkey_proxy_stranger` (ordinary — users
  authenticate to it normally) and `chain_proxy_stranger`, whose fingerprint is
  **never substituted into the fixtures**;
- `proxy/proxy-stranger.yaml` presents that key on `edge` only, so the node can
  reach no target of its own: anything it serves went through a chain leg;
- one route, `stranger.company.com`, a `dial` hop to `proxy-direct` — the *same*
  leg `deep.company.com` uses successfully from `proxy-nexthop`, which is what
  makes the refusal attributable to the key and to nothing else in the topology.
  A scenario asserts that leg still works.

The absence is the fragile part, so `test/topology` asserts it directly
(`TestTheStrangerProxysChainKeyIsNeverRegistered`): the key must be generated
and its fingerprint must never be taken. Registering it would turn the scenario
into one that fails several minutes into the e2e job for a reason that reads
like a proxy bug.

`requireTopology` waits for `proxy-stranger` to **speak at all** — the
pre-authentication banner (`user.BannerMessage`), which means the container is
up, its listener is answering, and a session got far enough to be told something
— rather than for the refusal wording. There is no successful session on that
node to wait for, by construction, and a readiness check that asserted the
scenario's own claim would make the scenario pass by having already happened.

The scenarios run directly after `target credential rejection`, which is the
defect they mirror, and before the outage scenario that stops Hoplock Control —
they read the priority record their own session produced. They open no breaker
and leave nothing behind, so unlike 0025's they do not make a re-run against a
used rig behave differently.

### Test notes

- `internal/proxy/hopreject_test.go` mirrors `reject_test.go` deliberately, and
  for the same reason: the far side is a **real** SSH server (`internal/sshtest`
  with `AuthorizedKeys` set) that really refuses the key we offer, because the
  classification is a text match on what x/crypto produces and a stubbed error
  would only assert on our own copy of it.
- The relay direction is covered by a `RelayOpener` that dials the refusing
  server (`dialingOpener`). The engine only ever sees a `net.Conn`, so that is a
  faithful stand-in for a registration, and it is what shows the classification
  is direction-agnostic while the record still names the direction.
- `cmd/mock-control/chain_e2e_test.go` gained
  `TestChainIdentityRejectionIsNotAnUnreachableProxy`, run in **both**
  directions: two real proxies, the real contract over HTTP, and the edge
  proxy's chain key simply left out of the fixtures (`chainOptions.
  unregisteredEdge`). It is the closest thing to the Docker scenario that runs
  in `go test ./...`, and it is what gave this phase confidence in the e2e
  fixtures without Docker.

### Deviations

None. The branch name is the one the session was given (`docs/PROTOCOL.md` §2
says that is not a deviation).

Two things could not be run in this session's container and are left to CI:

- **`make e2e`** — there is no Docker in the container. The e2e job is the gate.
  The in-process chain test above covers the same refusal through the same mock
  Control and the same engine code, in both hop directions, which is why the
  fixture and scenario changes are not being sent up unexercised.
- **`golangci-lint`** — the installed binary is built with Go 1.25 and refuses a
  module targeting Go 1.26 (`the Go language version (go1.25) used to build
  golangci-lint is lower than the targeted Go version (1.26.0)`). The same
  pre-existing environment mismatch phase 0025 recorded; CI's `lint` job is the
  gate. `go build`, `go vet`, `go test ./...`, `gofmt` and `make license-check`
  all pass locally.

### Follow-ups

None queued. The containment question is answered rather than deferred, and the
"if this is ever revisited" trigger above is deliberately *not* a queued prompt:
there is nothing to build until one of the two facts it names changes, and a
prompt sitting in the queue for a condition nobody has observed is work the
queue's contiguity rule (`docs/PROTOCOL.md` §6) would have to keep reordering.
