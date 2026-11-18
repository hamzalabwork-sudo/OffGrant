# Simulator

`prototype/offsim.py` simulates 30 days of industrial sites whose uplinks fail. It compares OffGrant with
baselines and ablations on **identical traces**: within one run, every protocol sees the same outages, power
losses, requests, clock drifts and decisions by headquarters. Every run draws its own trace, so runs are
independent of one another.

- [What is simulated](#what-is-simulated)
- [Protocols compared](#protocols-compared)
- [Metrics](#metrics)
- [Parameters and grid](#parameters-and-grid)
- [Running it](#running-it)
- [Output format](#output-format)

## What is simulated

**Sites and links.** There are three sites. Each uplink has three kinds of outage:

| Outage | Rate | Duration |
|---|---|---|
| satellite-like micro-outages | about 0.8 per hour | lognormal, median 0.9 s, at most 31 s |
| minute-long outages | about 2 per day | 50–75 s |
| long outages (stress parameter) | about 1 per week | uniform in `[L/2, L]` |

Sites also **lose power** about once a week, for 5 minutes to 4 hours. During a power loss the site is down, its
link is down and its TPM clock stops.

**Clocks.** Each site's clock runs at `1 + drift`. The drift is drawn uniformly in `[−ρ, ρ]` (`clock="uniform"`),
or every site is at the slow limit `−ρ` (`clock="slow"`, the worst case for leases).

**Workload per site.**

- **Permits (X).** Each of 10 objects per site receives about 10 requests a day at its intended holder. Each
  request asks for a hold of 10 minutes to 2 hours.
- **Credentials (V).** Each of 50 operators per site checks in about 4 times a day. A revoked operator (an
  insider) keeps trying, four times as often, for 3 days.
- **Consumption (B).** About 50 parts a day are consumed per site, against a global cap of 95% of expected
  demand. Shares cover 80% of the cap; the rest is a reserve that connected sites draw on.
- **Logs (C).** One record per minute.

**Headquarters.** About 3 reassignment decisions a day in total, at least 7 days apart per object, and about 1
credential revocation a day. These decisions are the same for every protocol.

**Timing.** Renewals are sent every 60 s while connected, with a 0.5 s round trip. A grant reaches finality 15 s
after it is made (`F`). `G`'s timestamps err by up to 2 s (`ε_G`).

## Protocols compared

| Name | Kind | Behaviour |
|---|---|---|
| `ours` | OffGrant | send-time leases (`A = D(1+ρ)`), epochs, holds inside the lease, fresh check at execution after `F`, wait `W = A/(1−ρ) + 2ε_G`, shares with a reserve |
| `global` | baseline | one ledger across sites: a cut-off site can do nothing |
| `crdt` | baseline | accepts everything offline and merges later (Vegvisir-style) |
| `timestamp` | baseline | accepts offline, then drops conflicting operations by timestamp (SWORD-style) |
| `discard` | baseline | accepts offline, then discards the whole offline period if anything in it conflicts (DTNB-style) |
| `waitrel` | baseline | wait for release: no expiry; an object moves only once its old holder acknowledges, and a revocation reaches a site only on reconnection |
| `nodrift` | ablation | `A = D` and `G` waits `D + 1 s`: ignores clock drift |
| `noepoch` | ablation | no epochs: after a power loss the lease resumes |
| `nofresh` | ablation | no fresh check at execution: a hold runs for its full length from its delayed execution |

The simulator follows each protocol's rules with **correct** validators. For OffGrant this means zero conflicts
follow from the rules by design; the simulation checks that the timing rules hold on realistic traces. Its
informative outputs are the **costs** (availability, reassignment delay, idle time) and what goes wrong in the
baselines and ablations. Safety against faulty validators is covered by the proofs, the TLA+ models and the
attacks in the PureChain runs.

## Metrics

| Field | Meaning |
|---|---|
| `X_avail_out` | share of permit requests accepted while the site is cut off (denominator: requests by the intended holder) |
| `X_conflicts` | holds that were in effect while another site held the object |
| `X_overlap_max` | longest such overlap (s) |
| `X_reassign_delay_mean`, `X_reassign_delay_max` | time from a decision to the moment the new holder may act (s) |
| `X_idle_mean` | time during which neither site may use a moved object (s) |
| `X_authority_after` | for each decision, how long the old holder could still act (s) |
| `V_avail_out`, `V_stale_acc`, `V_stale_max`, `V_window` | credential availability offline; acceptances after revocation (count and longest delay); per-revocation window |
| `B_avail_out`, `B_over` | consumption availability offline; units consumed beyond the cap |
| `rolled_back` | operations rolled back on reconnection (`discard`, `timestamp`) |
| `offline_frac` | fraction of time a site's link is down |
| `W_bound` | OffGrant's wait `W` for that run (s) |

## Parameters and grid

All parameters are fields of the `Cfg` dataclass at the top of `offsim.py`. The default grid has 720 runs:

| Parameter | Values |
|---|---|
| clock | 100 ppm uniform; TPM bound `ρ = 0.15` uniform; `ρ = 0.15` all slow |
| longest outage `L` | 2.5 h, 24 h, 72 h |
| offline tolerance `D` | 1 h, 6 h, 24 h, 72 h |
| runs per point | 20 |

## Running it

```sh
pip install -r requirements.txt
# full grid (720 runs) in parallel; about 30-40 minutes on 10 cores
python prototype/offsim.py --out experiments/results/offsim_v4.jsonl --workers 10
# one 5-day run to try it out (a few seconds)
python prototype/offsim.py --quick --workers 1 --out /tmp/quick.jsonl
# summaries
python prototype/analyze.py experiments/results/offsim_v4.jsonl > experiments/results/offsim_v4_summary.txt
```

`analyze.py` first prints, over all runs, how many runs each protocol had a conflict or over-consumption in, and
how many exceeded `W`. Then, for every grid point, it prints each protocol's mean ± 95% confidence half-width
(Student t over the independent runs) and the maximum.

## Output format

One JSON object per line (values shortened and illustrative):

```json
{"cfg": {"seed": 3, "trace": 17, "rho": 0.15, "clock": "uniform", "L": 259200.0, "D": 86400.0, "...": "..."},
 "ours":   {"X_avail_out": 0.43, "X_conflicts": 0, "X_reassign_delay_mean": 52000.1, "...": "..."},
 "global": {"...": "..."}}
```

`cfg` holds every parameter of the run. Each protocol's object holds the metrics above. Earlier simulator
versions' results (`offsim_v1` to `offsim_v3`) are kept, compressed, in `experiments/results/` for comparison.
