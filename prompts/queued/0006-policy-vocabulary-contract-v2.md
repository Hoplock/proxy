# 0006 — Policy vocabulary: management contract v2

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — especially **§2 (D5a, D6a, D11, D12)**, §4.2 (the two target
  credential methods), §6.1 (hop connection direction), §6.2 (the three policy
  axes), §6.3 (the three filtering tiers).
- `api/README.md` — "Changing the contract" is the procedure this prompt
  follows; `api/management.yaml` is the source of truth.
- `docs/learnings/` — read summaries; open `0002` (contract + client + mock) and
  `0005` (how `Route` is consumed today).

## Objective
Revise the management API contract so it can **express** the policy this product
claims to sell, before the phases that enforce it are built against the old
shape. Today the entire protocol policy is one flat list of channel **types**
(`permitted_channels: [session, direct-tcpip]`), and every remaining phase —
target credentials (0007), hop direction (0008), the inspection pipeline (0009),
filtering (0010) — needs vocabulary the contract does not have.

**This phase changes `api/`, `internal/mgmt`, and `cmd/mock-management` only.**
No enforcement is implemented here; the phases that consume each field are named
per field below. A field with no consumer yet is still added here, because the
alternative is four separate breaking contract changes spread across four PRs.

## In scope

### 1. In-channel request policy (D5a, consumed by 0009)
`session` carries `scp`, `sftp`, interactive shells, and one-shot commands
alike, so a channel-type allow-list cannot say "may log in, may not copy files".
Add a per-connection **request policy**: which of `pty-req`, `shell`, `exec`,
`subsystem`, `env`, `x11-req`, `auth-agent-req` are permitted, with
**subsystems named individually** (`sftp` deniable while `shell` stays).

Decide and document the default when the object is absent — it must be
**backwards-compatible with a v1 server** (a server that never heard of this
field must not accidentally deny every shell) while an *empty* object stays a
deny, exactly as `permitted_channels: []` does. Say which is which in the
schema description; a truncated response must never read as "allow all".

### 2. Forwarding destination policy (D5a, consumed by 0009)
`direct-tcpip` carries the host and port it wants in its channel-open payload.
Replace allow/deny-by-type with a destination allow-list: host (exact, wildcard,
or CIDR) + port (exact or range), evaluated against the payload. Model
`forwarded-tcpip` (target-opened) too — it is the same channel type in the other
direction and needs its own list.

### 3. Global request policy (D5a, consumed by 0009)
Remote forwarding is a **connection-level global request** (`tcpip-forward`),
not a channel open, so it is invisible to a channel-type allow-list — and
denying the resulting `forwarded-tcpip` channel is not equivalent, because the
listener is still created on the target. Add an allow-list for connection-level
request types. `internal/proxy/channel.go`'s `serveGlobalRequests` currently
relays every global request unpoliced; note in the schema that 0009 is where it
starts consulting this list.

### 4. Target credential method (D6a, consumed by 0007)
Add a `target_auth` object to `AuthorizeResponse`: a `method` name
(`ephemeral-user`, `brokered-key`, `static-key`) plus a method-specific
parameters object. The **server** chooses per route; `auth.target.method` in
`config.yaml` becomes local material only (which key, which provisioning
account), not the selection. Make the parameters object explicitly extensible so
a future management server that mints per-session target credentials is another
method, not another breaking change.

Document that a method the bastion cannot perform is an **outage-class denial**
(PLAN §4.3), never a fallback to a different method.

### 5. Hop connection direction (D11, consumed by 0008)
Add a direction to `HopMetadata`: `dial` (this bastion connects to the next) or
`relay` (the next bastion has registered an outbound connection with this one;
open a channel over it). Include whatever the upstream needs to select a
registration (the downstream bastion's id). Document that a `relay` hop with no
live registration is an outage, never silently downgraded to `dial`.

### 6. Filtering tiers (D12, consumed by 0010)
`FilterPolicy` gains a **mode for exec enforcement**: the existing pattern rule
list (a guardrail) plus **restricted exec** — an allow-list of permitted
executables with the shape of their permitted arguments. Specify the argument
shape precisely enough to implement without guessing: at minimum an exact argv
match and a prefix/positional form, and say what happens to arguments that are
not covered (denied). Restricted exec and the rule list are alternatives per
connection, not layers; a policy that sets both is a contract violation the
client rejects.

### 7. Versioning
Decide and document how a bastion and a server that disagree about this
vocabulary behave. Recommended: keep the `/v1` prefix (the endpoints and their
semantics do not change) and treat every new field as additive with a documented
absent-value default, so a v2 bastion works against a v1 server. Whatever you
choose, `api/README.md` must state it plainly and the client must **fail closed
on a field it does not understand** rather than ignoring it.

### Code changes
- `api/management.yaml` first, then `api/README.md`.
- `internal/mgmt`: types for every new payload, with the same care as 0002
  (named constants for enums, contract test asserting they match the document).
- `internal/mgmt/cache.go`: the deep copy that protects cached decisions from
  caller mutation must cover every new slice and map. This is easy to miss and
  the existing test (`cache_test.go`) shows the pattern.
- `cmd/mock-management`: fixture keys for all of the above, with defaults that
  keep every existing fixture file valid, and `fixtures.example.yaml` extended
  to demonstrate each new field.
- `internal/routing`: carry the new fields through `Route` so 0007–0010 have
  them. Accessors only where they are trivially right (`ChannelPermitted` has a
  natural sibling per axis); **no enforcement**.

## Out of scope
- Enforcing any of it (0007 target auth, 0008 hop direction, 0009 channels and
  forwarding and global requests, 0010 filtering tiers).
- Bastion↔bastion relay registration itself (0008 builds it; this phase only
  says which direction a route wants).
- Config-file changes beyond what `target_auth` makes local-material-only.

## Acceptance criteria
- `make openapi-check` passes.
- The `internal/mgmt` contract test asserts every new enum value and path
  against `api/README.md`, as 0002's does.
- Round-trip tests: a full v2 authorize response survives JSON encode/decode
  with every field intact, and the cache's deep copy is proven against mutation
  of every new slice/map.
- A **v1-server compatibility test**: an authorize response containing none of
  the new fields still yields a working, documented-default `Route` — no field
  silently becomes "deny everything" or "allow everything" by accident.
- A **rejection test**: a response setting both restricted exec and a rule list
  is rejected as a contract violation, not silently resolved.
- `cmd/mock-management` serves fixtures exercising each new field, and
  `fixtures.example.yaml` documents them.
- `docs/PLAN.md` §6.2/§6.3 match the shipped field names exactly.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0006-policy-vocabulary-contract-v2-learnings.md`. Summary block
MUST give: every new type and field name with its JSON tag, the absent-value
default for each one, the fixture keys that drive them, and a one-line pointer
per field naming the phase that consumes it (0007–0010). Those four phases are
written against this vocabulary and will read this summary first.
