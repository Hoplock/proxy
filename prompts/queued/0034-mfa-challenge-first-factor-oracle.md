# 0034 — Does the MFA challenge itself disclose the first factor?

> **New prompt, added by phase 0026, and conditional: it may answer "no".**
> 0026 put the password+MFA flow in front of a real OpenSSH client for the first
> time and found this while asserting that a denial names no factor. The denial
> does not. What happens *before* the denial does: a correct password is answered
> with an MFA challenge and a wrong one never is, so anyone who can reach the
> proxy can test passwords one at a time and read the answer off whether a
> challenge appeared. 0026 asserted what is true today and wrote this up rather
> than changing the flow under the heading of a test.
>
> It is inserted **before** the contract collapse (now
> `prompts/queued/0035-…`) because that one must stay the highest-numbered
> queued prompt; the mapping is in the newest run-order note at the end of
> `docs/PLAN.md` §10. Nothing in 0027–0033 depends on this and it depends on
> nothing they change.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — **§4.3 (the disclosure rule)** and §4.1 (the method order).
- `docs/learnings/` summaries: **0026** (what was observed, and the scenario
  that draws the line where it is today), **0004** (the `password-mfa`
  authenticator, the prompter, and the `ErrDenied`/`ErrUnavailable` split).
- `api/control.yaml` — `POST /v1/auth/password` and `POST /v1/auth/mfa/poll`,
  which are where a challenge is decided and therefore where any answer lives.

## The observation, precisely

Against the e2e topology (`test/e2e/scenarios_test.go`, "a denied second factor
discloses no factor"):

- `bob` with the right password and a refused approval sees the challenge text,
  waits, and is told **"Access denied."**;
- `bob` with a wrong password is told **"Access denied."** and nothing else —
  no challenge, no wait.

Both end identically, which is what §4.3 requires and what 0026 asserts. But the
two runs are still distinguishable, and the distinguishing signal is exactly the
one an attacker wants: *the password was right*. Timing says the same thing more
quietly — a refused password returns in one round trip, an approval wait takes
as long as the second factor does.

## Objective

Decide whether this matters for the product, and write the decision down. If it
does, close it. If it does not, say why, in a place the next person will find,
and delete this prompt (as **0021** was withdrawn).

**Answer these before proposing anything:**

1. **Whose decision is it?** The proxy relays: Hoplock Control returns `401` or
   `mfa_required`, and the proxy has no way to tell a real challenge from a
   decoy. So a fix is either a Control behaviour this repository only has to
   tolerate, or a contract change this repository owns (D3) — and which one it
   is decides whether there is any proxy work at all.
2. **What does the estate lose?** A decoy challenge for an unknown or wrong
   login costs a real user nothing and costs an attacker a full MFA wait per
   guess. It also means the proxy waits on challenges that can never resolve,
   which is Control-issued load on every failed login attempt (§9.1 for what the
   proxy's per-connection call budget currently is).
3. **Is the timing channel closable at all?** If it is not, a fix that closes
   only the challenge signal buys less than it looks like it does. Say so
   plainly rather than shipping half a mitigation described as a whole one.
4. **Does this belong to the prototype?** §12 puts federation with a real IdP
   out of scope, and a real IdP is where enumeration defences usually live. That
   is an argument for "no" — make it or refute it, do not leave it unstated.

## In scope

- The written decision, either way, in `docs/learnings/` per §5 — and, if the
  answer changes what the product promises, in `docs/PLAN.md` §4.3 beside the
  deny-vs-outage split, which is the paragraph a reader will check.
- **If the answer is yes:** the contract's account of when Control issues a
  challenge (`api/control.yaml` — a change here carries the cross-repo
  obligation in `docs/CROSS-REPO-PROTOCOL.md`), `cmd/mock-control` growing the
  fixture shape that lets a decoy be tested, and an e2e scenario that asserts
  the two runs are indistinguishable rather than merely identically worded. The
  proxy's own wait already handles a challenge that resolves as a deny; confirm
  that rather than assuming it.
- **If the answer is no:** replace 0026's comment in the scenario with the
  reason, so the next reader finds the decision instead of the finding again.

## Out of scope

- Rate limiting, lockout, or any other anti-automation measure. Those are worth
  having and they are a different phase; this one is about a signal, not a rate.
- Changing the MFA flow's mechanism (keyboard-interactive, the prompter, the
  polling bounds). PLAN §4.3 fixes those and nothing here needs them moved.
- The proxy inventing a challenge of its own. A proxy that fabricates a second
  factor is a proxy making a policy decision, which D2 forbids outright.

## Acceptance criteria

- The four questions above are answered explicitly, with the reasoning, in the
  learnings file.
- Either the signal is closed end to end and a scenario proves it, or the prompt
  is withdrawn with the argument written down and this file deleted.
- `go build ./...`, `go vet ./...`, `go test ./...`, `golangci-lint run` and
  `make e2e` pass. A contract change also passes the cross-repo checks in
  `docs/CROSS-REPO-PROTOCOL.md` §4.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. If the answer is yes, move this file to `implemented/`
and add `docs/learnings/0034-mfa-challenge-first-factor-oracle-learnings.md`. If
the answer is no, the learnings file is still written — a question answered "no"
with evidence is the deliverable — and this prompt is deleted rather than moved,
the way **0021** was.
