# 0044 — Brokered certificates: a credential Hoplock Control mints per session — Learnings

## Summary
- What shipped: the `brokered-certificate` method (route carries `username` **required**, `key_type`, `lifetime_seconds` — policy only) and `POST /v1/credentials/certificate` (`{session_id, decision_id, target, username, public_key}` → `{certificate, serial (decimal STRING), valid_before, ca_public_keys}`). **`policy_version` 4 → 5** (the enum value is vocabulary), `info.version` 4.4.0; the endpoint moved nothing. Mock tiers it: `baselineVocabulary = 4`, `vocabularyBrokeredCertificate = 5`.
- Key files: `internal/control/certificate.go`, `internal/auth/target/brokeredcert.go`, `internal/sshtest/ca.go` (test CA + `Options.TrustedUserCAKeys`), `cmd/mock-control/certificate.go`, `docs/PLAN.md` §5.4 (new).
- Key types: `control.{TargetAuthBrokeredCertificate, CertificateRequest, CertificateResponse(.SerialNumber), CertificateIssuer, PathIssueCertificate}`; `target.{BrokeredCertificateAuthenticator, ErrCertificateUnavailable, CertificateClockSkew, Options.Issuer, Target.DecisionID, ProvisionedAccess.CertificateSerial}`; `logging.AttrCredentialCertificateSerial` (`credential_certificate_serial`, provisioning record, batch).
- **Failure rule:** a failed issuance or a refused certificate (a `401` included) is an **outage** and never a walk to the next rung; only a build with **no issuer** skips the rung.
- **`CredentialSource` question: answered NO, not widened** — it looks up held material by reference; a minted certificate inverts that. §5.2 and `credentials.go` now say so. D6a rendered, not amended; no new `D`.
- Gotcha: `CachingClient` does **not implement** `CertificateIssuer` (the lease's pattern, not the pass-through the prompt described). `test/docs`' §5.3 layer scan now stops at `### 5.4 `.
- What Control must change (the sync): `credential.LadderEntry` renders **no** `certificate`/`certificate_serial`/`ca_public_keys` — the tripwire test is changed, not just un-refused; the serial arrives on the issuance response; wire the seam to the CA's issue call; never send the method to a proxy declaring `policy_version` < 5.

## Details

### The one part of the request that changed, and why

Control asked for the certificate, its serial and the CA bundle as `params` on
the ladder entry. They are per-session **artifacts** of one issuance, and the
entry rides a **cacheable** decision (D2, §6.4): a certificate there is replayed
to every connection the decision serves. The certificate is also signed over a
key that does not exist when authorize is answered. So the entry carries policy
and the endpoint carries artifacts — `POST /v1/uids/lease`'s argument, applied a
second time. `TestAReusedDecisionIsIssuedANewCertificatePerSession`
(`internal/proxy`) is the proof: one authorize call, one cache hit, two
issuances over two keys, two distinct serials accepted by a target that trusts
only the CA.

### Deviations from the prompt's wording (each deliberate)

- **The caching client does not pass the call through; it does not implement it
  at all.** The prompt said "passes this call straight through, exactly as it
  does the lease" — but `CachingClient` does not pass `LeaseUIDs` through either;
  it implements no `UIDLeaser`, so wiring the cache in is a compile error. The
  certificate follows the lease's actual pattern.
  `TestACachingClientCannotIssueCertificates` asserts it, and `cache.go` now
  names the three deliberately absent calls in one place.
- **The serial is on the provisioning record**, the one `recordCredential` writes
  and the one naming `credential_method` as *used* — the prompt's instruction.
  The kind-`authorize` record is written before issuance and cannot carry it; the
  prompt's "authorize record" wording means the former.
- **Three checks beyond the four named**, all cheap and all about not trusting a
  network answer: the response's `valid_before` must equal the certificate's own
  (the certificate's field is what the target enforces, so a response stating
  another is answering a different question — and checking only the JSON field
  would let a forever certificate through under a short stated expiry); a
  certificate that never expires is refused (the method's premise); a host
  certificate is refused (the prompt's "is a user certificate"). The bound
  allows **`CertificateClockSkew` = 30s**: the bound is on the proxy's clock and
  the certificate on Control's, and refusing every certificate from a CA a second
  ahead is an outage caused by NTP. The contract documents all of it.
- **Breaker handle `principal:<username>`.** Not asked for, and it fixes a real
  gap: without `CredentialIdentifier` the rejection record would carry an empty
  method and handle, and a target that does not trust the CA would be hammered
  from the proxy's single address with no containment. The per-session
  certificate cannot be the handle; what a target keeps refusing is "a
  certificate from this CA for this account".
- **`key_type` accepts `ed25519` (default) and `rsa`**, `ephemeral-user`'s
  vocabulary exactly. Teardown overwrites every private component reachable
  through the key's API (ed25519 bytes; RSA `D`, primes, CRT values via
  `big.Int.Bits()`, since `SetInt64(0)` alone leaves the words in memory). The
  standard library's derived copies (ed25519's expanded-key cache, RSA's
  precomputed FIPS key) are unreachable and go away with the session — the same
  limit `brokered.go` states for a parsed key.
- **The mock requires `decision_id`** and cross-checks target and username
  against the decision (`401` otherwise), as the prompt permits a server to.
- `TestHeartbeatIntervalDidNotMoveThePolicyVersion` pinned `PolicyVersion == 4`
  as a snapshot; it now pins 5 and says why the number moved.

### Where the reasoning lives

§5.4 is the section to navigate to; §5.2 carries the corrected `CredentialSource`
promise; §4.2 has "As extended (phase 0044)" and a table row; §7 names the
attribute; §2's D6a row now lists §5.4. `test/docs`' landmine was real: with the
old `## 6.` window, §5.4's "As built (phase 0044)" layer was counted as §5.3's
(10 claimed vs 11 found) — verified before fixing.

### Test notes

- `internal/sshtest` gained `CertificateAuthority` (implements the issuer, with
  faults) and `Options.TrustedUserCAKeys` (an `ssh.CertChecker`; a target that
  trusts a CA refuses plain keys), plus `Target.CertificateSerials()`. Every
  success test is a real login, not a struct comparison.
- The mock's faults (`routes[].certificate_fault`: `exceeds-lifetime`,
  `wrong-key`, `expired`, `malformed`) are driven through the real REST client
  and the real authenticator in `cmd/mock-control/certificate_test.go`.
- **`make e2e` was not run here** (no Docker, no `ssh-keygen` in this session).
  The rendered fixture template was loaded by the real mock binary with dummy
  fingerprints and a generated CA key (39 routes, CA loaded); `go vet -tags e2e`
  compiles the scenario; `test/topology` pins the four-file CA wiring. CI's e2e
  job is the first real run of `TrustedUserCAKeys` on the target.

### Follow-ups (not queued)

- Revoking a certificate mid-session (a revocation event or a KRL check) — out of
  scope; `session_kill` is today's answer.
- An e2e assertion that the target's **own** sshd log names the serial (the
  attribution claim end to end). Left out because the log format could not be
  verified in this session.
- **A pre-existing flake, fixed here at the owner's request:**
  `TestTheDeadlineRemovalAndAFailedProvisioningEmitToo`
  (`internal/auth/target/devicechange_test.go`, phase 0043) failed under
  `go test -race` about 6 runs in 20 on an untouched `main` (measured here with
  `-count=20`), and once in this PR's CI. It waited for the account to vanish
  from the fake device and then asserted the `delete` change record — but the
  device drops the account while the driver's `Delete` is still running, before
  the provisioner records the change. It now waits on the asserted condition
  (three change records) as well as the device's table: 0 failures in 110
  `-race` runs. Test-only; the provisioner was right, and its second half
  (the rollback) is synchronous and never raced.
