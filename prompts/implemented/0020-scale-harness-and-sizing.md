# 0020 — Scale harness: replace the arithmetic with measurement

> New phase (privileged-access revision, PLAN §10). It runs **before** 0021
> deliberately: 0021 changes the connection model to solve a load problem, and
> whether that problem exists at the claimed magnitude is a measurement nobody
> has taken. A phase that reshapes D2 on the strength of a spreadsheet is the
> wrong order.

## Read first
- `docs/PROTOCOL.md` — session workflow.
- `docs/PLAN.md` — **D17** (the arithmetic and the assumption under it), D2 and
  §6.4 (what a connection costs and what caching and revocation already do),
  §9 (why the compose topology is not this), §13 UC2.
- `docs/learnings/` — read summaries; open `0003` (the decision cache's key
  shape and the revocation subscription), `0005` (the connection lifecycle and
  what happens per connection), and `0012` (the compose topology, so you can be
  precise about why this harness is separate).

## Objective
Produce **measured** numbers for what a proxy and a Hoplock Control cost per
connection, so that sizing guidance in `docs/PLAN.md` stops being arithmetic,
and so 0021 is justified by evidence or dropped.

Change no behaviour. If the harness reveals a defect, that is a finding and, if
it is not a one-line fix, a queued prompt — not scope.

## Why this phase exists

D17's numbers are a chain of assumptions: an estate of 350,000 targets, polled
every 60 seconds, all of it over SSH, all of it through this proxy. That yields
~5,800 connections per second and a set of conclusions that reshape the
architecture. Every link in the chain is plausible and not one of them is
measured.

Two of them are worth attacking directly, because they are the ones that could
collapse the whole problem:

- **Is the health checking even SSH?** Large network estates are commonly polled
  by SNMP or streaming telemetry, and the subset checked over SSH is usually
  checked every five to fifteen minutes rather than every minute. If that holds,
  the real figure is two or three orders of magnitude lower and 0021 is
  unnecessary. This is a question for the customer, not for a benchmark — ask it,
  and record the answer in the learnings whatever it is.
- **What does a connection actually cost?** Three sequential round trips is what
  §6.4 says; nobody has measured the handshake, the authorize, the provisioning,
  or the memory a live connection holds.

## In scope

### 1. The harness (`deploy/` or a sibling, not the compose topology)

A load generator that opens real SSH connections through a real proxy against a
cheap in-process target, driven by a scenario file. It is **not** an addition to
0012's compose topology: that topology validates behaviour on one runner and
must stay fast and deterministic, and a load run is neither. Keep them separate
processes, separate make targets, and separate CI treatment.

It must be able to vary, independently: connections per second; concurrent live
connections; the credential method (`static-key` first — provisioning cost is a
separate measurement, not a confounder); whether decisions are cacheable; and
the number of distinct subjects and targets, because a cache keyed one way and a
workload shaped another way is exactly the interaction being measured.

### 2. The measurements

At minimum, and each reported with its methodology so a later run is comparable:

- **Per-proxy connection establishment rate**, and where it saturates — CPU,
  file descriptors, or Control latency. Report which, because the three have
  different fixes.
- **Memory per live connection**, measured rather than estimated, and the
  resulting ceiling on concurrent connections per proxy at a stated memory
  budget.
- **Control request rate per connection**, broken down by call, with and without
  a cache hint. This is the number the sibling repository is being sized by.
- **The cache's behaviour under fan-out.** Verify what key shape 0003 actually
  implemented and measure the hit rate for the UC2 access pattern — one subject
  against very many targets. A cache keyed per (subject, target) has a hit rate
  approaching zero for a one-minute poll of 300,000 distinct targets, and that
  fact would be invisible in any test written so far. If the shape is wrong for
  this pattern, that is a **finding with a proposed change**, not a change made
  here.
- **The provisioning cost** of `ephemeral-user`, measured separately, so the
  claim in D17 that per-check provisioning is infeasible is a number rather than
  an assertion. Two distinct numbers, not one:
  - the cost of a single provision/teardown cycle, which is what D17's
    arithmetic needs;
  - **the ceiling on concurrent provisioning against one target.** `useradd`
    and `userdel` serialise on the target's account-database lock, so a target
    fronted by a busy proxy has a per-target ceiling that no amount of proxy
    capacity moves — a different limit from every other measurement here, which
    are all per-proxy. `docs/PLAN.md` §5.1 records this ceiling as unmeasured
    and names this phase as the one that measures it, so leaving it out means
    going back and amending the plan.

    Report what saturates: the lock, home-directory creation, or the NSS
    backend. A fleet on a directory-backed NSS will not behave like one on flat
    files, and the sizing guidance has to say which was measured.

### 3. Sizing guidance in `docs/PLAN.md`

A short subsection stating what was measured, on what hardware, and what it
implies: connections per second per proxy, concurrent connections per proxy,
Control requests per second per 1,000 targets at a stated poll interval, and the
number of proxies a 350,000-target estate implies at each interval. Every figure
labelled measured or derived — never presented as the other.

## Out of scope
- Any change to the connection model — that is 0021, and it is *this* phase's
  output that decides whether 0021 happens.
- Tuning. If a measurement is bad, the fix is a finding and probably a prompt.
  A benchmark that is quietly optimised until it looks good measures the
  optimisation, not the system.
- Distribution, geo-routing, and anycast (PLAN §12 — still out of scope).
- Running the harness in the normal CI path. It may exist as a manually
  triggered or scheduled job; it must not gate a pull request on a shared
  runner's variance.

## Acceptance criteria
- `make load` (or equivalent) runs the harness against a locally built proxy and
  mock Control, and completes without special hardware.
- Each measurement above is reported with its methodology, and the raw output is
  reproducible from a committed scenario file.
- `docs/PLAN.md` carries the sizing subsection, each figure labelled measured or
  derived.
- The cache-key finding is stated explicitly — either "the shape suits the UC2
  pattern, here is the hit rate" or "it does not, here is the proposed key and
  the prompt that would change it".
- The per-target concurrent-provisioning ceiling is a measured number with its
  saturation point named, and `docs/PLAN.md` §5.1's "it has not been measured"
  is replaced by it.
- The customer question about SSH-versus-SNMP health checking is asked and its
  answer recorded, including "not yet known".
- **No behaviour change**: no file outside the harness, `docs/`, and the
  Makefile is modified.

## Definition of Done & hand-off
Per `docs/PROTOCOL.md`. Move to `implemented/`; add
`docs/learnings/0020-scale-harness-and-sizing-learnings.md`. The summary block
MUST carry the headline numbers, the hardware they were taken on, the cache-key
finding, the per-target provisioning ceiling and what saturated, and a one-line
verdict on whether D17's premise survived contact with measurement — 0021's
author reads that line first and may reasonably stop there.
