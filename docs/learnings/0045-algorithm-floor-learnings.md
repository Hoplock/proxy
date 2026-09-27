# 0045 — A floor under the target leg: `algorithm_floor` — Learnings

## Summary
- What shipped: two siblings of `algorithm_profile` on the authorize response. **`algorithm_floor`**, an ordered ladder compared by rank: `modern-kex` (rank 1) < `pq-hybrid-kex` (rank 2), absent = rank 0. **`algorithm_bans`**, per route and per axis: `key_exchanges`, `ciphers`, `macs`, `host_keys`, `public_key_auth`. Both reach every connection the profile reaches: session leg, management login, driver CLI, both sweeps.
- Members in this build: `modern-kex` = `ssh.SupportedAlgorithms().KeyExchanges` (`mlkem768x25519-sha256`, `curve25519-sha256` + its `@libssh.org` alias, `ecdh-sha2-nistp256/384/521`, `diffie-hellman-group14-sha256`, `diffie-hellman-group16-sha512`, `diffie-hellman-group-exchange-sha256`). `pq-hybrid-kex` = **`mlkem768x25519-sha256` only**; x/crypto has no sntrup761. The nesting invariant is the rule for adding a level, and FIPS-like regimes are not rungs.
- Declared and reported: `capabilities.algorithm_floors` (each level + its exact wire key exchanges) and `capabilities.algorithms` (every offerable name per axis). The server must not send an undeclared level; the mock answers `500`. `TargetCapabilities.kex {floor_met, negotiated, offered, observed_at}` is sent by `target.KexReporter` as its **own** report, off the session path, from every method, only when news. **Merge rule:** the rung observation is replaced iff `observed_at` is present, and `kex` iff `kex` is present.
- Bans: applied **last** (profile → floor intersects → bans subtract); a ban never adds and always wins. **Refused:** emptying an axis, removing every key exchange of the floor's level, an empty name, a duplicate. **Unmatched, accepted:** a name this build cannot offer, recorded as `algorithm_bans_unmatched` (`axis:name`). Runbook: ban → `cache_invalidate` `all` → `session_kill` of the sessions found by `target_cipher_out` and the like.
- Records: `algorithm_floor` (**omitted when none**), `algorithm_bans.<axis>`, `algorithm_bans_unmatched`; `target.algorithms_negotiated` (provisioning, `info`, batch) with `target_kex_algorithm`, `target_host_key_algorithm`, `target_cipher_out`/`_in`, `target_mac_out`/`_in`, `target_public_key_algorithms_offered`. `target.algorithm_policy_unmet` (`warn`, batch) gains `algorithm_policy_cause` (`profile`|`floor`|`ban`) and a new axis value, `public_key_auth`.
- Failure: 0043's `stageAlgorithmPolicy`. It is the outage branch, never a deny, never a ladder walk, never scored by the 0025 breaker. **Profile × floor by axis:** `legacy-device` + floor is refused, `legacy-rsa-sha1` + floor and `default` + floor are accepted (`control.ProfileWidensKeyExchange`).
- Version: **`policy_version` 5 → 6**, `info.version` **4.5.0**, mock tier `vocabularyAlgorithmFloor = 6`. Register unchanged.
- Key code: `internal/control/{algorithms,policy,validate,enforcement}.go` (`AlgorithmFloor`, `AlgorithmBans`, `AlgorithmPolicy{Algorithms, Cause, CauseWhere, FloorMet, UnmatchedBans}`), `internal/sshalg` (`NegotiatedOn`, `PublicKeys`, `Permitted`, `SignatureUnmet`), `internal/auth/target/{algpolicy,kexreport}.go`, `internal/proxy/session.go`, `internal/logging/algorithms.go`, `internal/sshtest/kexinit.go`.
- Gotcha: x/crypto adds `curve25519-sha256@libssh.org` on the wire by itself, so every list, declaration and ban handles both spellings as one exchange. A signing failure has **no type**; it is matched by text with a real-handshake tripwire.
- Next session: `TestConcurrentSessionsDoNotShareAUID` is flaky under `-race` because of a **pre-existing** uid-allocator race (not this phase's code). Root cause and patch are under Details.
- **What Control must change:** re-vendor at `policy_version` 6, and send a floor or ban only to a proxy declaring 6. Rank floors, and never promise sntrup761. Never send an undeclared level. Merge `kex` beside the rungs, and plan the impact preview and runbook. Read `target_kex_algorithm` (not `kex_algorithm`) and the keys above. Refuse what the proxy refuses, and **warn** on a ban name no proxy declared. Accept `legacy-rsa-sha1` + floor.

## Details

### The three corrections, as built

- **sntrup761.** `x/crypto/ssh` v0.56.0 implements `mlkem768x25519-sha256` and
  not `sntrup761x25519-sha512`. So `pq-hybrid-kex` is defined by a property: a
  hybrid exchange **this proxy implements**. A target on OpenSSH 9.0–9.8, which
  offers sntrup761 and classical exchanges, does not meet it. This was checked
  against a real OpenSSH 9.6 in the session. With a `pq-hybrid-kex` floor the
  handshake fails as `key_exchange`/`floor`, the offered list starts with
  `sntrup761x25519-sha512@openssh.com`, and `floor_met` is `modern-kex`. When the
  library gains sntrup761 it joins the level (`pqHybridKeyExchanges`), which is a
  description change and not a vocabulary revision. The nesting test and the
  wire test cover it, and the declaration follows by construction.
- **`target_kex_algorithm`**, not `kex_algorithm`: a record here can describe
  three SSH legs, and target-leg facts carry the `target_` prefix.
- **Profile × floor is by axis.** The rule is `ProfileWidensKeyExchange`, not a
  list of names, so the next profile added is placed by rule.

### Deviations and additions beyond the prompt's wording (each deliberate)

- **Two capability reports, not one.** The ephemeral-user probe's rung
  observation is unchanged. The key-exchange observation is a separate,
  kex-only report whose `observed_at` is omitted (`omitzero`). The contract's
  merge rule is by **presence**: the server replaces the rung observation only
  when `observed_at` is present, and `kex` only when `kex` is present. That kept
  probe output byte-identical and let the kex report come from every credential
  method without the probe's cost.
- **A sixth axis value, `public_key_auth`.** A `public_key_auth` ban can leave the
  proxy's key no signature algorithm the target accepts. So can a profile
  against a server that sends no `server-sig-algs`, which is 0043's latent case.
  x/crypto reports this untyped ("ssh: no common public key signature
  algorithm…"), and it used to surface as `stageDial`. `sshalg.SignatureUnmet`
  recognises it, and `TestASignatureFailureIsRecognisedOnARealHandshake` is the
  tripwire. `AlgorithmPolicy.CauseWhere` names the step that left the key
  nothing. The record has no `target_algorithms_offered` on that axis, because
  the library does not report the server's list.
- **`target_public_key_algorithms_offered`** on the negotiated record. The
  library does not say which signature algorithm authentication used, so the
  record names what was offered and says so in the key.
- **Extension signals are stripped** from a target's offered key-exchange list
  (`ext-info-*`, `kex-strict-*-v00@openssh.com`). They are markers, not
  exchanges, and no level could contain them.
- **The mock keys capability observations by `host[:port]`** (`capabilityKey`;
  port 22 is omitted, so existing keys are unchanged) and serves them at
  `GET /debug/capabilities`. The e2e classical sshd shares its host with the main
  one on port 2222, and host-only keys would have merged two targets into one.
- **A failed key-exchange negotiation is also a report.** The error carries the
  target's whole list, which is an exact observation. A success is only a lower
  bound, sound because every offer is ordered highest level first
  (`orderByLevel`). A success under a key-exchange **ban** is not an
  observation, because the ban may have removed what the target would have
  picked. `AlgorithmPolicy.FloorMet` is the one place this rule lives.

### How it is wired

- One expansion: `control.AlgorithmPolicy.Algorithms()` (profile, then the
  floor's intersection and order, then bans, with the curve25519 alias
  coupling). `routing.Route`, `target.Target` and `device.Endpoint` carry the
  result exactly as they carried the profile's. `WireKeyExchanges()` is the
  alias-complete form the declaration uses.
- Validation is in `validateAlgorithmPolicy`: unknown floor, profile × floor, and
  the ban refusals. All are `ErrProtocol`, outage-class. The mock's fixture
  validation calls the same client-side checks
  (`TestFloorAndBanFixturesAreCheckedLikeTheClientChecksThem`).
- The engine calls `observeKex` at leg-up and on a key-exchange failure.
  `KexReporter.ObserveKex` returns at once; the report runs on a detached
  context. A target is reported when there is no fresh observation or when
  `floor_met` changed, and the server's `report_after_seconds` sets freshness. A
  failed report clears freshness, so the next handshake retries.
- Sweeps: `changedUnderTheProxy` makes a sweep's algorithm failure read "the
  target has changed under the proxy". It names the axis and what the target
  offers now, or what it no longer accepts on `public_key_auth`.
- `device.Endpoint.Negotiated` is a callback the shell dialer calls after the
  handshake. It feeds the mapping event's `target_kex_algorithm`. The target
  report itself is made from the session leg, for device routes too.

### Test notes

- `internal/sshtest/kexinit.go` is a KEXINIT advertiser and recorder. It pins
  what the proxy **puts on the wire** under every profile × floor × ban, which
  asserting on the expansion function alone could not. It closes the connection
  right after recording; holding it open made the suite take 90s instead of
  0.7s.
- The runbook is an integration test against the mock with a real decision cache
  and revocation stream (`TestTheEmergencyRunbookWorksAsWritten`).
- **The e2e scenario (`test/e2e/floor_test.go`) was not run in this session.**
  The environment's egress policy refused `deb.debian.org` (403), so the
  topology's images could not install packages, and Docker Hub returned 429 for
  the base image. What was checked instead: the topology config test, a rendered
  copy of `deploy/control/fixtures.template.yaml` loaded by the mock (43 routes),
  the classical sshd's options against a real `sshd -T`, and the real-OpenSSH
  probe above. CI's e2e job is the scenario's first full run. The target image
  is `debian:stable-slim`, currently Debian 13 with OpenSSH 10, which offers
  ML-KEM hybrid by default.
- Lint: golangci-lint **v2.13.2** (CI's pin) reports 0 issues, including the
  `e2e` tag. The preinstalled v2.5.0 was built with Go 1.25 and refuses the
  module.

### Found, not fixed: the uid allocator hands concurrent sessions the same uid

Pre-existing (phase 0027/0035 code; this branch does not touch `uid.go`) and out
of scope. It surfaced as one `-race` failure of
`TestConcurrentSessionsDoNotShareAUID` in a whole-tree run. It then passed 20/20
alone and in 8/8 whole-package runs on this branch, and 6/6 on base.

- **Root cause.** `uidAllocator.allocate` calls `observedFloor`, which takes and
  **releases** `a.mu`, and then takes `a.mu` again to compute
  `next = floor + 1` and advance `a.high`. Two sessions can both read the same
  `a.high` before either advances it, so both get the same first candidate. A
  scratch test on base commit 4582c39 (8 goroutines, `-race`) saw a duplicate in
  **2202 of 5000** rounds.
- **Why production is not reusing uids.** A real `useradd -u` locks the account
  database and refuses a uid already held (exit 4), so the loser falls to the
  next of its 8 fallback candidates. The fake host's `useradd`
  (`fakehost_test.go`) checks and then appends without a lock, so both succeed
  and the test sees a shared uid. The cost in production is a wasted candidate
  and a lost-race retry that should never happen within one process.
- **Proposed patch.** Hold `a.mu` once across both steps: make `observedFloor`
  an unlocked helper that `allocate` calls with the lock held. Optionally make
  the fake `useradd` take a lock (`flock` on the passwd file) so the fake models
  the real serialisation.

### Follow-ups (not built, per the prompt's out-of-scope list)

- **Bans and floors on the user→proxy listener and the hop leg.** These are
  fleet configuration, 0042's area, and should reuse `control.AlgorithmBans`'
  per-axis shape. Proxy→proxy legs should **not** become route policy: a
  route's floor is about the device at the far end, and the chain's posture is
  the operator's.
- **A construct for non-nested regimes** (FIPS and the like).
- **sntrup761** when x/crypto implements it (see above).
- **Floors on other axes.** The level names carry `-kex`, so a sibling ladder
  can be added without renaming this one; none is added.
- **Control's console:** the impact preview ("raising this route to X breaks
  these targets") and fleet coverage ("these proxies cannot enforce X yet").
  This phase supplies the data (`kex` reports and `algorithm_floors`
  declarations).
