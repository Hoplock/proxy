# proxy-PR#68 — brokered-certificate credentials (0044)

Backfilled from [proxy#68](https://github.com/Hoplock/proxy/pull/68), which
predates the request queues: the kickoff its `## Cross-repo impact` section
handed over, verbatim. Answered by
[control#40](https://github.com/Hoplock/control/pull/40).

```
Read docs/CROSS-REPO-PROTOCOL.md and follow it. You are doing a downstream
sync following https://github.com/Hoplock/proxy/pull/68. Do not implement any queued prompt in this
session.

Before anything else, confirm that upstream change is MERGED; if it is not,
stop and say so (§2). Then update this repository's prompts, plan, and
protocol so the next session builds against what is now true.

A sync changes text, not behaviour: it implements, enforces, and vendors
nothing, hand-edits no vendored artifact, and adds, renames, or renumbers no
prompt. Land each obligation in the prompt that will implement it, not only in
the plan. If the work seems to need something the upstream repository does not
have, that is §3.2 — stop and tell me rather than approximating it.

The obligations to land are in the upstream PR's "## Cross-repo impact"
section: the six under "hoplock/control" — re-vendor api/ at 4.4.0
(policy_version 5); credential.LadderEntry for brokered-certificate renders
ONLY username/key_type/lifetime_seconds, never certificate,
certificate_serial or ca_public_keys, and the tripwire test is CHANGED to that
shape rather than un-refused; the seam's refusal is replaced by
POST /v1/credentials/certificate over the CA's issue call (sign exactly the
submitted key, user certificate, bounded by lifetime_seconds, never forever,
valid_before equal to the certificate's own, serial as a decimal string,
cross-check decision_id/target/username, 503 with no authority); the serial
now arrives on the issuance response and the proxy records it as
credential_certificate_serial; never send the method to a proxy declaring
policy_version below 5; one issuance per session, never cached.

Work on the branch this session was given, whatever it is named — if the name
is yours to choose, claude/sync-<short-description>. Commit with the `sync`
scope, and open one PR whose body names the upstream PR, confirms it is merged,
and says how you searched for stale references — the actual grep, not "I looked
carefully".
```
