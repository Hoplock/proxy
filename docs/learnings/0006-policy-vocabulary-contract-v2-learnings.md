# 0006 — Policy vocabulary: management contract v2 — Learnings

## Summary
- What shipped: **contract v2**. `/v1/authorize` gained the two channel policy
  axes a type allow-list cannot express, a server-chosen target credential
  method, a hop connection direction, and an exec enforcement mode — plus the
  versioning rule that makes all of it safe. Nothing is enforced here; 0007–0010
  consume it. The wire rename PLAN §11 assigned to this phase landed too.
- Key files: `api/control.yaml`, `api/README.md`,
  `internal/control/{policy,validate,clone,contract,rest,cache}.go` (+
  `policy_test.go`), `cmd/mock-control/{fixtures,server}.go` +
  `fixtures.example.yaml`, `internal/routing/resolve.go`.
- **Every new field, its JSON tag, its absent-value default, and its consumer:**

  | JSON tag (in `AuthorizeResponse` unless noted) | Go type | Absent means | Consumed by |
  | --- | --- | --- | --- |
  | `permitted_requests` `{types, subsystems}` | `*RequestPolicy` | **not policed** (v1) | 0009 |
  | `permitted_forwards` `{direct_tcpip, forwarded_tcpip}` | `*ForwardPolicy` of `ForwardDestination{host, port, port_range{from,to}}` | **not policed** (v1) | 0009 |
  | `permitted_global_requests` `{types}` | `*GlobalRequestPolicy` | **relayed unpoliced** (v1) | 0009 |
  | `target_auth` `{method, params}` | `*TargetAuth` | proxy's **local** `auth.target.method` | 0007 |
  | `filter_policy.exec_mode` | `ExecMode` | `filtered` | 0010 |
  | `filter_policy.restricted_exec` `{commands[]}` | `*RestrictedExecPolicy` | — (forbidden unless `restricted`) | 0010 |
  | `hop.connection` | `HopConnection` | `dial` | 0008 |
  | `hop.next_proxy_id` | `string` | — (**required** for `relay`) | 0008 |
  | `policy_version` (on `AuthorizeRequest`) | `int` | `1`; client sends `control.PolicyVersion` = 2 | — |

- **Absent ≠ empty, everywhere.** Absent = "this server does not speak this
  axis" = v1 behaviour. Present-but-empty = "permit nothing", exactly like
  `permitted_channels: []`. The Go types encode it as nil pointer vs non-nil
  empty, so do not "simplify" any of these to a value type.
- **Fixture keys** (`cmd/mock-control`, all optional, all defaulting to absent):
  `routes[].permitted_requests`, `.permitted_forwards`,
  `.permitted_global_requests`, `.target_auth`, `.hop_connection`,
  `.next_proxy_id`, `.filter_policy.exec_mode`, `.filter_policy.restricted_exec`.
- **Wire rename (PLAN §11, breaking, batched here):** `bastion_id` → `proxy_id`;
  `GET /v1/bastions/{bastion_id}/events` → `GET /v1/proxies/{proxy_id}/events`.
- Decisions affected: D5a, D6a, D11, D12 (all now have shipped field names);
  PLAN §4.2, §6.1, §6.2, §6.3, §11 updated to match exactly.
- **What the NEXT session must know:** the authorize response is decoded
  **strictly** — an unknown field is `ErrProtocol`, never a deny — and
  `AuthorizeResponse.Validate()` is the single gate both the client and the mock
  run. Add a field to any policy type and you must also add it to `clone.go`,
  to the mutation test, and to `PolicyVersion`.

## Details

### Why a contract phase at all

Four queued phases (0007 target credentials, 0008 hop direction, 0009 channels,
0010 filtering) each needed vocabulary `/v1/authorize` did not have. Adding it
per phase would have been four breaking contract changes in four PRs, each
requiring a coordinated release with the sibling Hoplock Control repo (D3). One
revision, before anything is built against the old shape, is one coordination.

### The versioning rule, which is two halves

Read this before touching `internal/control/rest.go`.

1. **Additive with a documented absent-value default.** Every default is the
   behaviour a v1 server already produced, so a v2 proxy works unchanged
   against a v1 server. `TestAbsentPolicyIsTheV1Default` and
   `TestRouteFromAV1ServerIsUnpoliced` pin it, and
   `TestAuthorizeStillServesAV1Fixture` pins it at the mock.
2. **The proxy fails closed on a field it does not understand.** `Authorize`
   uses `postStrict`, which sets `DisallowUnknownFields`. An unrecognised field
   is `ErrProtocol` — an outage-class failure, never a deny (PLAN §4.3).

Rule 2 alone would make every server upgrade a fleet-wide outage, so it is
paired with `AuthorizeRequest.policy_version`: the proxy declares the highest
vocabulary it implements (`control.PolicyVersion`, filled in by `Authorize` if
the caller left it zero), and the server must not answer outside it. The mock
implements the server half — it returns `500` naming `policy_version` rather
than sending v2 policy to a proxy that declared v1.

The reasoning worth keeping: ignoring an unknown field is the *forgiving*
behaviour and it is wrong here, because every field in this response is policy,
an unknown one may be a **restriction**, and a dropped restriction is a silently
widened session. Endpoints and semantics did not change, so the prefix stays
`/v1`; the vocabulary is versioned separately from the URL.

### Where the two "not layers" rules live

`restricted_exec` beside a non-empty `rules` list is refused, not resolved
(`validate.go`, `FilterPolicy.validate`). So is `restricted_exec` under
`exec_mode: filtered`, and `exec_mode: restricted` with no `restricted_exec`.
The mock runs the same `Validate()` over each fixture route at startup, so a
policy the proxy would reject cannot start the mock — there is deliberately no
second copy of these rules.

### Argument shapes (what 0010 must implement)

`restricted_exec.commands[]` is a default-deny allow-list. `executable` is
matched against `argv[0]` **exactly as written**: no `PATH` search, no symlink
resolution, no basename comparison — each would accept a name the server did not
write. Then either `form: exact` with `argv` (element-by-element, length must
match) or `form: positional` with `args[]` specs of `kind`
`literal`/`prefix`/`oneof`/`any`, plus `optional` for trailing positions.

Three constraints that are load-bearing rather than stylistic:

- **Anything not covered by a spec is denied.** No trailing allowance, no
  wildcard tail. A vector longer than `args` never matches.
- **`prefix` with an empty value is rejected** — that is `any` in disguise, and
  the point of naming `any` is that every unconstrained position stays greppable
  in the policy and the audit record.
- **A required spec may not follow an optional one**, or the argument at that
  index belongs to either spec.

0010 also owes: parse with POSIX word splitting and quote removal; deny before
matching anything containing `;`, `|`, `&`, a backquote, `$(`, `${`, `<`, `>`, a
newline, or an unterminated quote (shell syntax, no argv means it); and run the
approved vector directly, never through `sh -c`.

### Requests and global requests that are not policy

`RequestPolicy` governs only what decides *what a channel is*. `window-change`,
`signal`, `exit-status`, `exit-signal`, `break`, `eow@openssh.com`, `xon-xoff`
are relayed regardless (`control.IsAncillaryChannelRequest`) — denying a
terminal resize is a broken session, not an enforced one. Likewise
`keepalive@openssh.com`, `no-more-sessions@openssh.com`, and the
`hostkeys-*@openssh.com` pair are outside the global request policy
(`control.IsUnpolicedGlobalRequest`); `no-more-sessions` is a restriction the
*client* asks for, so refusing it would be perverse. Use those two predicates in
0009 rather than re-deriving the lists.

`subsystem` is deliberately **not** a member of `permitted_requests.types` — a
subsystem is permitted by name in `subsystems`, which is the only way `sftp` is
deniable while `shell` stays. `Validate` rejects `subsystem` as a type with an
error naming the fix, because accepting it would quietly mean "sftp and
everything else". `auth-agent-req` in a policy covers the wire name
`auth-agent-req@openssh.com` too; `RequestPolicy.RequestPermitted` normalises it.

### Forwarding destinations

`host` is exact (case-insensitive), a `*.`-prefixed wildcard, a bare `*`, or a
CIDR. **A CIDR never matches a hostname and a hostname never matches an IP
literal**: the proxy must not resolve names to decide policy, because a DNS
answer is not a decision the PDP made. `port` and `port_range` are mutually
exclusive (both set is refused); neither set permits any port on a matching
host, which is an entry the server wrote deliberately.

The axes are **conjunctive**: a channel type absent from `permitted_channels`
stays denied however permissive `permitted_forwards` is. `forwarded-tcpip` gets
its own list because it is the same channel type in the other direction — a
route that may tunnel out to the database must not thereby accept arbitrary
channels pushed back.

### Cloning — the thing that is silent when it breaks

`clone.go` is the single deep copy, used by `CachingClient` **and**
`routing.Resolver` (which previously had its own partial copy; that is gone).
A cached decision is handed to many sessions, so anything shared is one session
able to rewrite another's policy. `PortRange` is a pointer inside a slice of
structs and `TargetAuth.Params` is a map — both are easy to miss.

**When you add a field to any policy type:** add a line to `clone.go`, add a
mutation to `TestCloneIsolatesEveryMutableField` (which mutates every slice,
map, and pointer of a full v2 response and asserts the original is untouched),
and bump `control.PolicyVersion`.

### What `Route` gained (for 0007–0010)

`routing.Route` carries `PermittedRequests`, `PermittedForwards`,
`PermittedGlobalRequests`, and `TargetAuth`, with accessors that are trivially
right and resolve the absent-value defaults: `RequestPermitted`,
`SubsystemPermitted`, `GlobalRequestPermitted`, `ForwardDestinations`
(returns `(dests, policed)`), `ExecMode()`, `HopDirection()`. Host/port matching
is **not** here — it is real logic and belongs to 0009.

### Deviations and out-of-scope work done anyway

- **The wire rename.** The prompt does not mention it; PLAN §11 explicitly
  assigns it to this phase ("0006 carries it, and nothing on the wire moves
  before then"), so it landed here, batched with a change that was breaking
  anyway. `bastion_id` → `proxy_id` on `ConnMeta`; `/v1/bastions/` →
  `/v1/proxies/` for the revocation stream. §11 now records it as done.
- **`internal/control/errors.go` sentinel wording.** `golangci-lint` was failing
  on `main` with five pre-existing `ST1005` findings (error strings starting
  with "Hoplock Control", introduced by the rename commit). They are unrelated to
  this phase but block the green-CI requirement, so the five sentinels were
  rephrased to start lower-case. No behaviour and no `errors.Is` classification
  changed; only the human-readable text.
- **`config.example.yaml` / `internal/config`.** `auth.target.method` is now
  documented as **local material plus a fallback**, not the selection (D6a). The
  struct and validation are unchanged; only the comments moved.

### Follow-ups for later phases (not new prompts)

- 0007: `target_auth.params` names are method-scoped and a proxy implementing a
  method must **refuse a parameter it does not know** (same fail-closed
  reasoning as the top-level fields). The contract states it; only 0007 knows
  each method's key set, so only 0007 can enforce it.
- 0009: `internal/proxy/channel.go`'s `serveGlobalRequests` still relays
  everything. That is where it starts consulting `permitted_global_requests`.
