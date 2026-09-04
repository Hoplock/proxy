# The scale harness

`cmd/loadgen` measures what a Hoplock Proxy and a Hoplock Control cost per
connection, and what an `ephemeral-user` account cycle costs a target. It exists
because `docs/PLAN.md` D17 reshapes the architecture on the strength of
arithmetic — an estate of 350,000 targets, polled every 60 seconds, all of it
over SSH, all of it through this proxy — and not one link in that chain had a
number behind it.

The results this harness produced, and the sizing guidance they support, are in
`docs/PLAN.md` §9.1. Raw output is in `load/results/`.

## It is not the e2e topology

`deploy/` (phase 0012) is the prototype's acceptance gate: the whole system in
containers, on one runner, gating every pull request. It has to stay fast and
deterministic. A load run is neither, so this is a separate binary, separate
make targets, and a separate, **manually triggered** workflow
(`.github/workflows/load.yml`). Nothing here gates a pull request.

## Running it

```sh
make load                 # every connection scenario, ~20 minutes; writes load/results/
make load-one SCENARIO=load/scenarios/04-uc2-fanout.yaml
sudo make load-provisioning   # ROOT; creates and removes real local accounts
```

`make load` builds `bin/hoplock-proxy` first and runs each scenario against it.
Requirements: Go, Linux (the process sampler reads `/proc`), and — for
`load-provisioning` only — root, `useradd` and `userdel`.

**`make load-provisioning` creates and deletes real local accounts** named
`hl-load-*` on the machine it runs on, and removes them again as it goes. Run it
on a throwaway host or in a container, never on a workstation. A crashed run
leaves accounts behind under that prefix; `userdel -r` them by hand.

## What it actually runs

```
┌────────── loadgen process ──────────┐        ┌── hoplock-proxy (child process) ──┐
│  SSH clients ─────────────────────────SSH──▶ │  the real, locally built binary   │
│  in-process target (internal/sshtest) ◀─SSH──│  with a generated config.yaml     │
│  instrumented Hoplock Control ◀───────HTTP───│                                   │
└─────────────────────────────────────┘        └───────────────────────────────────┘
                                                  sampled from /proc/<pid>/{status,stat,fd}
```

Three decisions are worth knowing about before reading a number off it:

- **The proxy is a child process, not a goroutine.** RSS is per process, and a
  harness sharing a heap with the thing it measures cannot say what a live
  connection costs. It also means every run exercises the real startup path —
  config decoding, the revocation subscription, the logging pipeline.
- **Hoplock Control is instrumented, not `cmd/mock-control`.** That server is
  fixture-driven and exists to make behaviour testable; a fixture with 8,192
  routes is a fixture nobody can read. This one answers from the scenario,
  counts every call with its handling time, and can inject latency. Both are
  built from the same `internal/control` contract types, so neither can drift
  from the wire format without failing to compile.
- **One in-process target stands in for the whole fleet.** The *fleet* is the
  distinct target **names** in the request, because that is what the proxy's
  decision cache keys on. Where they resolve to is not what is being measured,
  and 8,192 real sshd processes on one box would measure the box.

Every credential is `static-key`: it provisions nothing, so establishment cost
is not confounded by a credential method. Provisioning is measured on its own,
because it saturates a **target** rather than a proxy.

## Reading a report

Every figure is tagged `[measured]` or `[derived]`, and a derived one prints
the arithmetic beside it. That is not decoration: the reason this phase exists
is that the plan carried derived figures which read like measured ones.

Two limits are structural and are stated rather than worked around:

- **The generator, the target and the proxy share the machine's cores.** An
  achieved connection rate from this harness is therefore a **floor** on what
  the proxy can do, not its ceiling. The ceiling reported is derived from the
  proxy process's own measured CPU-seconds per connection, and assumes perfect
  core scaling — which is why it is labelled derived.
- **Memory per live connection needs a plateau.** Rate-mode connections do not
  overlap long enough to form one, so that figure comes from a hold-mode
  scenario (`03-live-connections`) and rate-mode reports say so instead of
  printing a number they cannot support.

## Scenarios

| File | Answers |
| --- | --- |
| `01-establishment.yaml` | What one connection costs with nothing cached, swept over offered rate |
| `02-cached-decisions.yaml` | The same, with the server authorising reuse — the difference is what caching buys |
| `03-live-connections.yaml` | Memory and descriptors per **live** connection, from a held plateau |
| `04-uc2-fanout.yaml` | Cache hit rate for one subject against a working set that crosses the cache's entry bound |
| `05-uc2-fanout-shared-key.yaml` | The same with the server sharing one key across every target — can a better server key fix it? |
| `06-provisioning-ceiling.yaml` | Provision/teardown cycles per second against **one target**, swept over concurrency |
| `07-provisioning-accountdb-only.yaml` | The same without a home directory, separating the account-database lock from filesystem cost |

### Writing a scenario

The schema is `cmd/loadgen/scenario.go`, and unknown keys are rejected — a
misspelt knob that silently does nothing is a measurement of the wrong thing.
The two sweep axes are mutually exclusive:

- `run.rate_steps` sweeps offered rate against a fixed working set, on **one**
  proxy process. A sweep whose steps each got a fresh process would compare a
  warm proxy against a cold one and call the difference saturation.
- `workload.target_steps` sweeps the working set at a fixed rate, and requires
  `run.restart_between_steps`. Cached decisions carry across steps, so a later
  step would otherwise measure an entry table an earlier one filled. Each step
  also gets a disjoint set of target names, for the same reason.

Set `run.warmup` to at least `targets / rate` on a fan-out scenario. Without a
full sweep of the working set before the measured window, a "miss" only means
"first visit" and the reported hit rate is an artefact of the run length.

`control.cache_scope` is the **server's** choice of sharing scope, not the
proxy's: the proxy never builds a cache key (PLAN §6.4), so the widest sharing
the contract permits is something only the server can offer, and `per-subject`
is the run that offers it.
