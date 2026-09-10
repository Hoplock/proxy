# 0026 — e2e coverage: password+MFA and concurrent provisioning — Learnings

> **Pointer note (added by 0027).** The renumbering this file records — the
> contract collapse moved to **0035** — has been superseded: phase 0027 queued the
> Control-held uid floor at 0035, so the collapse is now
> `prompts/queued/0036-collapse-contract-to-one-version.md`. The MFA question this
> phase queued is unaffected and is still **0034**. Compose the mappings through
> the renumbering notes at the end of `docs/PLAN.md` §10, newest first. Nothing
> else in this file changed — it stays the record of what phase 0026 shipped.

## Summary
- What shipped: the two gaps phase 0012 recorded that were **not** plan-level
  deferrals. `proxy-direct` now offers `password-mfa` beside `cert`, and the
  suite drives keyboard-interactive with the real OpenSSH client — approval,
  progress lines, a denial, and `auth_method=password-mfa` in the audit trail.
  Two overlapping ephemeral sessions on one login are asserted to hold **two
  different accounts at the same instant**, with the `brokered-key` mirror. **No
  production code changed:** nothing in `internal/`, `cmd/` or `api/`.
- Key packages/files: `test/e2e/{harness,scenarios}_test.go`,
  `test/topology/config_test.go` (two new pinning tests),
  `deploy/proxy/proxy-direct.yaml`, `deploy/control/fixtures.template.yaml`,
  `deploy/user/{Dockerfile,askpass.sh}` (new), `deploy/README.md`,
  `docs/PLAN.md` §9 + §10.
- **The client mechanism that worked: `SSH_ASKPASS` + `SSH_ASKPASS_REQUIRE=force`
  (OpenSSH ≥ 8.4), with `BatchMode=no`.** It worked first try. Three
  alternatives were then driven against the running topology to confirm they do
  not, so nobody repeats the search — see *What does not drive
  keyboard-interactive* below. All three fail, and two of them fail **as a wrong
  password rather than as an error**, which is the trap.
- Harness: `mfaBaseArgs` sits **beside** `sshBaseArgs`, which is untouched — it
  is what keeps every other scenario on the certificate path now that a second
  method exists. `session` gained `baseArgs` and `env`; new `execArgsEnv`,
  `mfaOn`, `waitUpTo`, `overlapping`.
- Fixture shapes: `bob` (password, `mfa.decision: approve`, `pending_polls: 3`)
  and `mallory` (password, `decision: deny`) — copied from
  `cmd/mock-control/fixtures.example.yaml`. Mallory **has a route**, on purpose.
  New brokered route `standing.company.com` for the overlapping brokered pair.
- **Overlap is observed, not assumed:** the target's own `getent passwd` is read
  while both sessions are held open and must show two `hl-` accounts at once;
  for `brokered-key`, where there is only ever one account, it is two live
  processes under `netadmin`. Without that the scenarios would be a slower copy
  of tests that already exist.
- **No defect found in the concurrency path.** One finding elsewhere, queued as
  **0034**: the MFA *challenge* discloses that the first factor was right — the
  denial does not, but only a correct password is ever answered with one.
- Decisions made/affected: none changed. PLAN §4.1, §4.3 and §5.1 now have
  end-to-end evidence instead of unit-test evidence.
- Renumbering: **0034 → 0035** (the contract collapse), to keep it last. Mapping
  in `docs/PLAN.md` §10's newest note.
- What the NEXT session must know: `make e2e` grew ~35s (two 15-second holds).
  Anything that touches `auth.user.methods` on a deploy proxy, or
  `auth.user.mfa.progress_interval`, is pinned by `test/topology` and will fail
  in seconds rather than minutes into the e2e job.

## Details

### What does not drive keyboard-interactive

All four were run against the live topology (`make e2e-up`, then one
`docker compose exec user ssh …`). Write these down rather than re-deriving them:
two of the three failures are indistinguishable from a wrong password.

| Mechanism | Result |
| --- | --- |
| `SSH_ASKPASS` + `SSH_ASKPASS_REQUIRE=force`, `BatchMode=no` | **works** — challenge, progress lines, session |
| password piped on stdin, no askpass | fails: `Access denied.` |
| `SSH_ASKPASS` with **no** `SSH_ASKPASS_REQUIRE` | fails: `Access denied.` |
| askpass forced, but `BatchMode=yes` | fails: **no banner at all** |

The mechanics behind each:

- **stdin does not reach the prompt.** OpenSSH answers a keyboard-interactive
  prompt through `read_passphrase`, which opens `/dev/tty`. Under
  `docker compose exec -T` there is none, so it falls through to askpass; with no
  askpass configured it returns the **empty string** and the client answers the
  prompt with it. The proxy sees a wrong password and denies — so this failure
  looks exactly like a fixture with the wrong password in it, and reads as
  "the scenario is wrong" rather than "the mechanism is wrong".
- **`SSH_ASKPASS` alone is not enough.** Without `SSH_ASKPASS_REQUIRE=force` the
  client only uses an askpass program when `DISPLAY` is set, which in a
  headless container it is not. Same empty answer, same misleading denial.
  `SSH_ASKPASS_REQUIRE` is the OpenSSH 8.4 knob that drops the X11 condition;
  the `user` image runs OpenSSH 10.0p2, comfortably past it.
- **`BatchMode=yes` removes the method entirely.** `userauth_kbdint` returns
  immediately under batch mode — batch mode means "never ask a person anything",
  and this method is by definition asking. The client never offers it, so the
  proxy's authentication callback never runs and **nothing is printed**: no
  `Access denied.`, no banner. That absence is the tell.
- `PubkeyAuthentication=no` and `NumberOfPasswordPrompts=1` are not required for
  the flow to work. The first removes the ambiguity about which method PLAN §4.1
  landed on; the second stops OpenSSH repeating the whole exchange three times on
  a denial, which would otherwise be three MFA waits and three audit records per
  denial scenario.

### Why `sshBaseArgs` is untouched, and why it matters more now

`sshBaseArgs` pins `PreferredAuthentications=publickey` and `BatchMode=yes`.
Before this phase that was belt and braces: no proxy in the topology offered a
second method, so nothing could fall back. `proxy-direct` now does, which makes
that pin load-bearing — it is the only reason the other ~40 scenarios are still
demonstrably on the certificate path. `mfaBaseArgs` is therefore a second set
rather than an edit, and `session.baseArgs` selects between them.

`proxy-nexthop` and `proxy-zone` stay certificate-only, and `test/topology` pins
that too. The fallback **order** is only observable while a proxy exists that
gives a client with no acceptable key no second chance.

### The two settings that make the wait visible

The `pending_polls: 3` in the fixture and `progress_interval: 200ms` in
`proxy-direct.yaml` exist together. The proxy emits a "still waiting" line only
when `ProgressInterval` has elapsed since the last one, and the shipped default
is 5s; a fixture challenge that resolves in under a second would produce **no**
progress line at all, and the scenario asserting on it would pass against a proxy
that had none to print. The e2e run shows three lines, counting up from `(0s)`.

This is the assertion that makes the design rationale testable rather than
merely written down: PLAN §4.3 says MFA rides keyboard-interactive *because* it
is the only flow with an `instruction` field to explain the wait in. Plain
password auth has nowhere to say it.

### The denial, and the disclosure line this phase drew

The MFA denial is asserted to be exactly `Access denied.`, to leak neither the
word "password" nor "MFA" nor "second factor", and — the assertion that carries
the claim — to **end identically to a wrong password**. `endingOf` compares the
last thing the proxy said, discarding the client's own `Permission denied` line,
the per-run session id, and the host-key warning, all of which differ between any
two runs whatever the proxy did.

What this does **not** claim, and what became prompt **0034**: the two runs are
still distinguishable. A correct password is answered with an MFA challenge and a
wrong one never is, so the challenge's presence is a first-factor oracle, and its
duration says the same thing more quietly. That is not the proxy's to fix —
Hoplock Control decides when a challenge is issued (D2), and the proxy cannot
tell a real challenge from a decoy — so 0026 asserted what is true today, left a
comment in the scenario pointing at the prompt, and queued the question rather
than changing the flow under the heading of a test. 0034 is conditional in 0032's
style: it may answer "no" and be deleted.

### Demonstrating the overlap

The scenarios hold each session open with `id -un; sleep 15` and assert on the
*target* while they run:

- **`ephemeral-user`:** `getent passwd` must show **two** `hl-…` accounts at one
  instant, both `hl-<tag>-alice-<token>`, and the two names the clients printed
  must be the same two names (sorted). That last comparison is what stops the
  scenario passing on two observations of one session.
- **`brokered-key`:** there is only ever one account — that is the method — so
  the overlap is counted in processes instead: `pgrep -u netadmin -x sleep` must
  reach 2. `who` would not do; an exec channel opens no pty and writes no utmp
  record, so these sessions are invisible to it.

Then both must exit 0, and afterwards no `hl-` account and no `hl-` home may
remain — two independent teardowns, neither of which took the other's account
and neither of which leaked. The suite-wide leak check still runs last; this one
exists so that a leak is *attributed* to the overlap rather than to the run.

The reaper is untouched (`interval: 1m`, `grace: 5m`). It never sweeps an
account it knows is live, so the hold is safe by construction; `test/topology`
pins the grace above a minute anyway, because a grace shorter than a held
session would make these scenarios flaky in a way that reads as a provisioning
bug rather than as a setting.

`concurrentHold` is 15 seconds. It has to outlast provisioning both sessions plus
the 500ms polls that observe the overlap, and stay well inside the harness's
60-second `commandTimeout`: a session killed for running long is torn down
because the *client* went away, which is a different path from the one under
test. Fifteen seconds is roughly 600× the measured provisioning cycle (§9.1) and
costs the suite ~35 seconds in total.

### Placement in `TestTopology`

The subtests are ordered on purpose and both new groups say why in a comment:

- `concurrent provisioning` sits directly after `target credentials` — the same
  subject under load — and before the outage scenario, which stops Hoplock
  Control and would make provisioning impossible.
- `password and out-of-band MFA` sits next to `denial disclosure`, because half
  of it is the same claim on a second axis, and before `telemetry` and the outage
  scenario because it reads the audit record its own session produced.

### Fixtures

`bob` and `mallory` have **no key fingerprints at all**, which is what puts them
on the fallback method: there is no certificate for them to offer. Both get a
`direct`/`ephemeral-user` route to `host.company.com` identical to alice's but
for the login, so a difference in outcome can only have come from the
authentication method.

Mallory's route is deliberate and is worth keeping: without it her denial would
be explicable as "she was not authorized for that target", which is a different
assertion wearing the same message.

`standing.company.com` is new, for the overlapping brokered pair. Every other
brokered route in the fixtures constrains what may run — `appliance.company.com`
to two exact binaries, `filtered` and `allowlist` to their own patterns — and a
scenario about the *credential* should not have to satisfy a command filter to
hold a session open.

### Follow-ups

- **`prompts/queued/0034-mfa-challenge-first-factor-oracle.md`** — the finding
  above. Conditional; it may end in a written "no".
- Nothing else. The remaining entries on 0012's gap list are `docs/PLAN.md` §12
  deferrals, exactly as that phase recorded.
