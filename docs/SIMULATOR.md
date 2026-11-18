# Simulator

`prototype/offsim.py` (version 5) simulates 30 days of industrial sites whose uplinks fail. It compares OffGrant
with baselines and ablations on **identical traces**: within one run, every protocol sees the same outages, power
losses, requests, clock drifts, message delays, finality delays, G timestamp errors and decisions by
headquarters. Every run draws its own trace, so runs are independent of one another.

- [What is simulated](#what-is-simulated)
- [Protocols compared](#protocols-compared)
- [What the simulation can and cannot show](#what-the-simulation-can-and-cannot-show)
- [Metrics](#metrics)
- [Parameters and grid](#parameters-and-grid)
- [Changes in v5](#changes-in-v5)
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
link is down and its TPM clock stops. Overlapping outages and power losses **merge**, so a continuous offline
period can be much longer than `L`; `analyze.py` reports the longest one per `L` and the offline fraction.

**Clocks.** Each site's clock runs at `1 + drift`. The drift is drawn uniformly in `[−ρ, ρ]` (`clock="uniform"`),
or every site is at the slow limit `−ρ` (`clock="slow"`, the worst case for leases). The drift is constant per
site and run, and the protocol's `ρ` equals the true bound.

**Messages.**

- *Renewal requests* leave every 60 s while the site's link is up. A request reaches `G` after 0.25 s (half the
  0.5 s round trip) if the link is still up; otherwise it is lost and `G` issues nothing.
- *Messages from `G` to a site* are renewal responses, stops (move or revocation) and move notices to the new
  holder. Each is delivered after a delay drawn from a mixture (an assumed stress model, not fitted to a measured
  trace):

  | Share | Delay |
  |---|---|
  | 95% | uniform in [0.3 s, 1 s] |
  | 4% | log-uniform in [1 s, 60 s] |
  | 1% | log-uniform in [60 s, 30 min] |

  A message whose nominal arrival falls into an outage of the site is delivered when the outage ends
  (store-and-forward, as with a persistent message-queue session). So a response can arrive hours after it was
  issued, after the outage that held it.
- A site learns of a decision from the decision's own message **or** from the first renewal response `G` issued
  after it, whichever arrives first.
- With epochs, a response whose request was sent before a power loss that happened before the response arrived
  is useless: its send lies in an older epoch.
- An acknowledgement (the old holder confirming that its holds have ended) reaches `G` 0.25 s after it is sent,
  and it can be sent only while the old holder's link is up.

**G timestamp error.** Every `G` timestamp errs uniformly in `[−ε_G, +ε_G]`, with `ε_G = 2 s`. This applies to
the stamp of each renewal it issues and to the stamp of each move. `G` counts its wait from the **last renewal it
issued** to the old holder before the decision. It does not know whether that renewal was delivered.

**Finality delay `F`.** `F` is sampled per operation (grant to final checkpoint to gateway execution). It is
`15 s × lognormal(0, 0.3)`, which is about 8–27 s for 95% of operations. With probability 1%, a consensus stall
adds a delay uniform in [1 min, 15 min]. This is an assumed model, not a measurement. The stalls make late
executions happen, for example one after the hold end or at the edge of the allowance, and the fresh check
exists for exactly these cases.

**Workload.**

- **Permits (X).** There are 10 objects per site. For every object and site there is a Poisson stream of 10
  requests per day. A site asks only while it **believes** it holds the object, that is, its last move to it that
  it has learned of is newer than its last move away from it that it has learned of. So the holder sees about 10
  requests per object per day (measured value: see the summary header). Each request asks for a hold of 10
  minutes to 2 hours. **20% are "max-fit" requests**: if the requested hold does not fit in the remaining
  allowance, the site grants a hold that ends 1 s (on its clock) before the allowance ends, provided it is at least
  60 s long. This is the workload of the end-to-end PureChain run (`until = reading + min(WINDOW, rem − 1)`). It
  places hold ends at the allowance edge, where the hold-end, send-time, `2ε_G` and fresh-check rules matter.
  Without such requests, the uniformly drawn holds almost never end within seconds of that edge.
- **Credentials (V).** Each of 50 operators per site checks in about 4 times a day. A revoked operator (an
  insider) keeps trying for 3 days, four times as often.
- **Consumption (B).** About 50 parts a day are consumed per site, against a global cap of 95% of expected
  demand. Shares cover 80% of the cap. The rest is a reserve that connected sites draw on.
- **Logs (C).** One record per minute.

**Headquarters.** `G` decides only during the first 27 days (90%) of the run, so that the effects of its
decisions fall inside it.

- **Moves.** About 3 reassignment decisions per day of that window (about 81 per run). Each picks an object
  uniformly among those not moved in the last 7 days, and a new holder uniformly among the other two sites.
- **Revocations.** About 1 credential revocation per day of the window (about 27 per run).

These decisions are the same for every protocol. The measured rates are printed in the summary header.

## Protocols compared

| Name | Kind | Behaviour |
|---|---|---|
| `ours` | OffGrant | send-time leases (`A = D(1+ρ)`), epochs, holds must end inside the allowance, fresh check at execution after `F`, wait `W = ⌈A/(1−ρ)⌉ + 2ε_G`, shares with a reserve |
| `global` | baseline | one ledger across sites: a cut-off site can do nothing |
| `crdt` | baseline | accepts everything offline and merges later (Vegvisir-style) |
| `timestamp` | baseline | accepts offline, then drops conflicting operations by timestamp (SWORD-style) |
| `discard` | baseline | accepts offline, then discards the whole offline period if anything in it conflicts (DTNB-style) |
| `waitrel` | baseline | wait for release: no expiry. An object moves only once its old holder acknowledges, and a revocation reaches a site only through a message |
| `nodrift` | ablation | `A = D` and `W = ⌈D⌉ + 2ε_G`: a lease that ignores clock drift (not a specific published configuration) |
| `noepoch` | ablation | no epochs: after a power loss the lease resumes |
| `nofresh` | ablation | no fresh check at execution: a hold runs for its full length from its delayed execution |
| `nohold` | ablation | no hold-end rule: a hold may start anywhere inside the allowance and runs its full requested length |
| `receipt` | ablation | the allowance is counted from the **receipt** of the renewal response instead of the request's send |
| `eps1` | ablation | `G` waits `⌈A/(1−ρ)⌉ + ε_G` (one `ε_G` only) |

Each ablation drops exactly one OffGrant rule and keeps the others. `crdt`, `timestamp` and `discard` behave
identically while running. They differ only in what they roll back, so the simulator runs them once.

**OffGrant's rules as simulated.**

- A site may grant an object only within its allowance `A = D(1+ρ)`. The allowance is measured on the site clock
  from the send of the latest renewal request whose response the site has received, in the same power epoch.
  That renewal must have been issued after the site became the holder and before the move away.
- A hold must end inside the allowance.
- The gateway executes a grant after its sampled `F`, and only if a fresh clock reading is still inside the hold
  end and the allowance. Otherwise the grant lapses.
- `G` moves an object `W` after its last renewal to the old holder (on `G`'s clock). Alternatively, the fast path
  moves it once the old holder's acknowledgement arrives, whichever comes first.

**Handover, the same for every protocol (v5).**

- *Old holder connected at the decision.* Holds already running are treated alike by every site-local protocol:
  the merging baselines, wait-for-release and the leases' fast path. The stop reaches the old holder, which then
  grants nothing more. Its acknowledgement reaches `G` once every hold it granted before the stop has ended and
  its link is up. Only then may the new holder act.
- *Old holder cut off at the decision.* The merging baselines know only the holds the old holder granted while
  it was connected. They wait for those. The holds it grants while cut off are invisible, and the new holder acts
  at once. That is inherent to merging.
- *Global chain.* The chain orders the decision before any later grant of the old holder, and it knows every hold
  (a cut-off site can finalize nothing). So the new holder acts once the old holder's holds end.
- *Lease protocols.* The new holder may act at the earlier of the slow path (`W`) and the fast path.
- *Ordering.* A move never completes before the previous move of the same object did.

## What the simulation can and cannot show

- **OffGrant's zero violations are a consistency check, not independent evidence.** The simulator implements the
  rules of Proposition 1(b). With `|drift| ≤ ρ` and `G` errors within `ε_G`, a violation is impossible in this
  model. `run()` asserts zero authority overlaps, zero double use, zero rights beyond the move, zero credential
  effects beyond `G`'s bound and zero over-consumption for `ours`. It asserts zero authority overlaps and zero
  double use for `global`.
- **Each ablation can produce violations in this model.** A local check on the grid with 4 runs per point (144
  runs) found violations for every ablation; the full-grid counts are in the summary file.
  - `nodrift`, `noepoch` and `nohold` violate often.
  - `nofresh` violates through max-fit holds that execute after `F` and so outlast the allowance by `F`, and
    through holds whose execution is delayed by a stall.
  - `receipt` violates when the response to the last renewal before an outage is delayed by more than the margin
    `rtt/2 + 2ε_G + (G error) + ceiling slack`, a few seconds. Such delays come from the heavy tail and from
    store-and-forward. Its violations show mostly in the rights metric, rarely as hold overlaps.
  - `eps1` can violate only when the clock runs at the slow limit and the two `G` errors fall against the old
    holder. The margin is then below 0 by at most about one `ε_G`, a few seconds. Only a slow-path move whose
    allowance is still running qualifies, and an actual hold overlap also needs a max-fit hold ending at that
    edge. So `eps1` violations are **rare** and seconds long. The rights metric shows them more often than the
    hold metrics do.
- **Not simulated.**
  - Faulty validators.
  - Clocks outside their stated bound, or drift that varies with temperature.
  - Anchoring before renewal, and `λ`.
  - Adversarial request timing beyond max-fit requests.
  - More than 3 sites.

  Holds by one site on one object may overlap (they are not double use). Safety against faulty validators is
  covered by the proofs, the TLA+ models and the attacks in the PureChain runs.

## Metrics

| Field | Meaning |
|---|---|
| `X_avail_out` | share of permit requests accepted (and executed) while the site is cut off. Denominator: requests by the site that believes it holds the object. Max-fit grants count as accepted |
| `X_avail_out_fixed` | the same, over fixed-length (non-max-fit) requests only |
| `X_conflicts` | **authority overlaps**: holds in effect while another site held the object |
| `X_overlap_max` | longest such overlap (s) |
| `X_double` | **double use**: pairs of executed holds of two different sites on one object that overlap in time |
| `X_double_max` | longest such overlap (s) |
| `X_lapsed` | lease protocols: grants that lapsed at execution (fresh check failed, or gateway down) |
| `X_reassign_delay_mean`, `X_reassign_delay_max` | time from a decision to the moment the new holder may act (s) |
| `X_fast_frac` | share of moves completed by the acknowledged handover. For leases this is the fast path rather than `W`; for merges, the share with the old holder connected at the decision |
| `X_idle_mean` | time during which neither site may use a moved object (s) |
| `X_authority_after` | for each decision, how long after it the old holder could still grant (s). Leases: its allowance end, at most the stop's arrival |
| `X_rights_beyond`, `X_rights_excess_max` | decisions in which the old holder could still grant after the new holder became entitled, and the largest excess (s) |
| `V_avail_out` | share of credential check-ins accepted while cut off. Revoked operators' check-ins count as requests for every protocol, so no protocol reaches 1 |
| `V_stale_acc`, `V_stale_max` | acceptances taking effect after revocation (count, and longest delay after the revocation) |
| `V_window` | per revocation, how long the site could still accept |
| `V_late` | lease protocols: acceptances that took effect after `G`'s bound for that revocation (`G`'s last renewal to the site + `W`) |
| `B_avail_out`, `B_over` | consumption availability offline; units consumed beyond the cap |
| `rolled_back_excl` | exclusive, credential and consumption operations rolled back on reconnection (`discard`: all such operations of a discarded offline period; `timestamp`: the conflicting ones) |
| `rolled_back_log` | commutative log records rolled back (`discard` only) |
| `rolled_back` | the sum of the two (kept for comparison with v4) |
| `offline_frac` | fraction of time a site's link is down |
| `W_bound` | OffGrant's wait `W` for that run (s) |

Each run also has a protocol-independent `trace` object with the measured rates:

- `permit_req_per_obj_day`;
- `decisions` and `decisions_per_day` (per day of the decision window);
- `revocations` and `revocations_per_day`;
- `longest_offline_h`, the longest continuous offline period of any site;
- `offline_frac`;
- `F_mean` and `F_frac_over_60s`;
- `resp_frac_over_1s`, `resp_frac_over_60s` and `resp_max_delay_h`, the renewal response delays from issue to
  arrival, including store-and-forward.

## Parameters and grid

All parameters are fields of the `Cfg` dataclass at the top of `offsim.py`. The default grid has 720 runs:

| Parameter | Values |
|---|---|
| clock | 100 ppm uniform; TPM bound `ρ = 0.15` uniform; `ρ = 0.15` all slow |
| longest single outage drawn, `L` | 2.5 h, 24 h, 72 h |
| offline tolerance `D` | 1 h, 6 h, 24 h, 72 h |
| runs per point | 20 |

## Changes in v5

These changes follow review round 3 (R06 M1–M3, R09 M4, R05 M2–M3).

1. **Fair handover (R06 M1).** Holds running at a decision are treated alike by every protocol, as described in
   [Handover](#protocols-compared). Conflicts are now computed for the global chain too, and asserted to be 0.
   - In v4, the merging baselines switched at the decision even when the old holder was connected, so they were
     charged for preempting running holds.
   - In v4, the global chain was exempt from the conflict count.
2. **Two conflict metrics (R09 M4.3).** `X_conflicts` (authority overlap) is kept, and `X_double` (double use)
   is added.
3. **Rollbacks split (R09 M4.2).** `rolled_back_excl` and `rolled_back_log` are now separate fields.
4. **Every OffGrant rule can be tested.**
   - New ablations: `nohold`, `receipt` and `eps1`.
   - `G` timestamp error is now simulated (`ε_G = 2 s`).
   - Message delays are heavy-tailed, with store-and-forward delivery.
   - `G` counts its wait from the last renewal it **issued**, not the last one delivered (R06 minor 5).
   - `F` is sampled, with stalls.
   - 20% of permit requests are max-fit requests.
   - `W` now has the ceiling (R06 minor 17). `nodrift` now waits `⌈D⌉ + 2ε_G`, so it drops only the drift rule.
   - The fresh check now does exactly what §4 states: it checks the hold end and the allowance in the current
     epoch. v4 also lapsed grants executed after the stop's arrival (R06 minor 6), and v5 removes that.
   - The fast path now needs the old holder's link to be up when the acknowledgement is sent (R06 minor 4).
5. **Calibrated rates (R06 M3).** The stated and implemented rates now match. v4 requests were spread over all
   three sites and filtered, which gave 6.65 per object per day; v4 had about 1.37 moves per day.
   - Requests are generated at 10 per object per day at the believing holder.
   - Moves are 3 per day of the decision window, among eligible objects.
   - The measured rates, the offline fraction and the longest continuous offline period per `L` are written per
     run and printed by `analyze.py`.
6. **Reporting.** `analyze.py` reports the following:
   - offline credential availability per grid point (R05 M2);
   - the no-drift ablation at 100 ppm separately (R09 M4.4);
   - violation counts per clock regime;
   - the share of fast-path moves (R06 minor 3).

## Running it

```sh
pip install -r requirements.txt
# full grid (720 runs) in parallel; about 10 minutes on 10 idle cores
python prototype/offsim.py --out experiments/results/offsim_v5.jsonl --workers 10
# one 5-day run to try it out (a few seconds)
python prototype/offsim.py --quick --workers 1 --out /tmp/quick.jsonl
# summaries
python prototype/analyze.py experiments/results/offsim_v5.jsonl > experiments/results/offsim_v5_summary.txt
```

`analyze.py` prints the following, in order:

1. the measured workload;
2. the offline fraction and the longest offline period per `L`;
3. per protocol, over all runs and per clock regime, the number of runs with each kind of violation;
4. the no-drift ablation at 100 ppm;
5. offline credential availability;
6. for every grid point, each protocol's mean ± 95% confidence half-width (Student t over the independent runs)
   and the maximum.

## Output format

One JSON object per line (values shortened and illustrative):

```json
{"cfg": {"seed": 3, "trace": 17, "rho": 0.15, "clock": "uniform", "L": 259200.0, "D": 86400.0, "...": "..."},
 "trace": {"permit_req_per_obj_day": 9.9, "decisions_per_day": 3.0, "longest_offline_h": 131.2, "...": "..."},
 "ours":   {"X_avail_out": 0.43, "X_conflicts": 0, "X_double": 0, "X_reassign_delay_mean": 52000.1, "...": "..."},
 "global": {"...": "..."}}
```

- `cfg` holds every parameter of the run.
- `trace` holds the protocol-independent measurements.
- Each protocol's object holds the metrics above.

Earlier simulator versions' results (`offsim_v1` to `offsim_v4`) are kept in `experiments/results/` for
comparison.
