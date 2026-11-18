# Simulator

`prototype/offsim.py` (version 6) simulates 30 days of industrial sites whose uplinks fail. It compares OffGrant
with baselines and ablations on **identical traces**: within one run, every protocol sees the same outages, power
losses, requests, clock drifts, message delays, finality delays, G timestamp errors and decisions by
headquarters. Every run draws its own trace, so runs are independent of one another.

> **What the simulation is evidence of.** The simulator *enforces* each protocol's rules as stated. For OffGrant
> these are the rules of Proposition 1(b), with every clock inside its drift bound and every `G` timestamp inside
> `ε_G`. OffGrant's zero conflicts therefore hold **by construction**: `run()` asserts them, so a completed grid
> can only contain zeros. They are a consistency check of the implementation against the proposition, not
> independent evidence of safety. What the simulation **measures** is the price of the rules (availability while
> cut off and while connected, hand-over delays, idle time, refused locks, the hold-end rule's cost) and the
> violations that the baselines and the ablations actually produce.

- [What is simulated](#what-is-simulated)
- [Protocols compared](#protocols-compared)
- [What the simulation can and cannot show](#what-the-simulation-can-and-cannot-show)
- [Metrics](#metrics)
- [Parameters and grid](#parameters-and-grid)
- [Changes in v6](#changes-in-v6)
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
- **Locks on open-class objects (O, v6).** Each site also has 3 isolation points (open class, for example
  lockout points). For every such object and site there is a Poisson stream of 2 lock requests per day, filtered
  like permit requests (only the believing holder asks). A lock, once executed, stays on until its crew releases
  it, after a duration drawn from a lognormal distribution with median 2 h and σ = 1 (mean about 3.3 h), capped at
  24 h. The duration is real time: a physical lock survives power losses. Several crews may hold locks on one
  object at once. The open-class trace comes from its own random stream, so the rest of a run's trace is exactly
  the v5 trace for the same seed and grid point.
- **Credentials (V).** Each of 50 operators per site checks in about 4 times a day. A revoked operator (an
  insider) keeps trying for 3 days, four times as often.
- **Consumption (B).** About 50 parts a day are consumed per site, against a global cap of 95% of expected
  demand. Shares cover 80% of the cap. The rest is a reserve that connected sites draw on.
- **Logs (C).** One record per minute.

**Headquarters.** `G` decides only during the first 27 days (90%) of the run, so that the effects of its
decisions fall inside it.

- **Moves.** About 3 reassignment decisions per day of that window (about 81 per run). Each picks an object
  uniformly among those not moved in the last 7 days, and a new holder uniformly among the other two sites.
- **Moves of open-class objects (v6).** About 1 decision per day of the window, by the same rule (at least
  7 days between moves of one object), so about 24 per run once ineligible draws are skipped.
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

**Open-class objects (v6).**

| Protocol | Applying a lock | Hand-over |
|---|---|---|
| `ours` and every ablation | a lock is a grant: only inside a valid allowance, executed after `F` if a fresh clock reading is still inside the allowance (`nofresh`: no fresh check); no hold end | **never by expiry.** `G` moves the object only on the old holder's acknowledgement, which it gives once the stop has reached it, no lock is on and its link is up. A cut-off holder's move waits until it reconnects and acknowledges |
| `waitrel` | always (no expiry) | the same acknowledgement rule |
| `global` | only while connected (a cut-off site finalizes nothing) | once every lock granted before the decision is released and the release is recorded, which needs the old holder's link |
| `crdt`, `timestamp`, `discard` | always | **at once** at the decision: a merging design has no notion of a lock that must be released first, so a lock still on (or applied before the stop arrives) conflicts |

Locks are physical, so they end only when their crew releases them, not with the gateway's power. Releases are
local and always allowed. For lease protocols the run also records a counterfactual: the moves for which `G`'s
wait `W` would have ended while a lock of the old holder was still on (`O_expiry_moves`). This is what the rule
"never move an open-class object by expiry" prevents. No ablation drops this rule, and none drops the
acknowledgement, so no ablation can conflict on open-class objects; the ablations differ there only in
availability.

## What the simulation can and cannot show

- **OffGrant's zero violations hold by construction: they are a consistency check, not independent evidence.**
  The simulator enforces each protocol's rules; for OffGrant these are the rules of Proposition 1(b). With
  `|drift| ≤ ρ` and `G` errors within `ε_G`, a violation is impossible in this model. `run()` asserts zero
  authority overlaps, zero double use (bounded and open class), zero rights beyond the move, zero credential
  effects beyond `G`'s bound and zero over-consumption for `ours`. It asserts zero authority overlaps and zero
  double use for `global`. A violating run would stop the grid, so a completed grid can only contain zeros for
  these. The simulation's evidence lies in what it measures: availability, hand-over delays, idle time, refused
  locks, the hold-end rule's cost, and the failures of the baselines and ablations. `analyze.py` gives 95%
  one-sided upper bounds for the zero counts, which hold only within the model.
- **For open-class objects OffGrant's hand-over is not bounded.** It equals wait-for-release, except that OffGrant
  grants fewer locks while cut off (only inside the allowance), so its acknowledgements can come earlier. The
  bounded hand-over delay (`W`) applies to bounded-class objects only. For open-class objects OffGrant adds the
  recorded, attributable acknowledgement, not a bound.
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
  - Lockout/tagout as shared locks against an exclusive energize right, locks of several sites on one isolation
    point, the binding of a release to the crew that applied the lock, emergency overrides (`forceReassign`) and
    gateway reboots that lose in-memory hold tables. Open-class objects are exclusive per site, as in the
    contracts.
  - Sealing of acknowledgements and quorum delay on the fast path: the acknowledgement reaches `G` `rtt/2` after
    the old holder's link is up.

  Holds by one site on one object may overlap (they are not double use). Safety against faulty validators is
  covered by the proofs, the TLA+ models and the attacks in the PureChain runs.

## Metrics

| Field | Meaning |
|---|---|
| `X_avail_out` | share of permit requests accepted (and executed) while the site is cut off. Denominator: requests by the site that believes it holds the object. Max-fit grants count as accepted |
| `X_avail_out_fixed` | the same, over fixed-length (non-max-fit) requests only |
| `X_avail_conn` | (v6) the same while the site is connected |
| `X_holdend_refused_conn`, `X_holdend_refused_out` | (v6) lease protocols: requests refused by the hold-end rule (the hold would end after the allowance), while connected and while cut off |
| `X_truncated_conn`, `X_truncated_out` | (v6) accepted max-fit requests whose hold was shortened to fit the allowance |
| `X_refused_allow_conn`, `X_refused_allow_out` | (v6) requests refused for want of a valid allowance |
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

Open-class fields (v6):

| Field | Meaning |
|---|---|
| `O_req`, `O_req_out`, `O_acc`, `O_acc_out` | lock requests and accepted (executed) locks, overall and while cut off |
| `O_avail_out`, `O_avail_conn` | share of lock requests accepted while cut off and while connected |
| `O_refused_allow`, `O_refused_allow_out` | locks refused because the allowance lapsed (no valid allowance at the request, or it ended before execution), overall and while cut off |
| `O_lapsed` | locks not executed because the gateway was down at execution |
| `O_conflicts`, `O_overlap_max` | authority overlaps: locks on while another site held the object; longest overlap (s) |
| `O_double`, `O_double_max` | locks of two sites on one object at once |
| `O_decisions`, `O_handover`, `O_handover_mean`, `O_handover_max` | moves of open-class objects and their hand-over delays (decision to the moment the new holder may act, s) |
| `O_idle_mean` | time during which neither site may use a moved open-class object (s) |
| `O_locked_at_decision` | moves for which a lock of the old holder was on at the decision |
| `O_expiry_moves`, `O_expiry_locks` | lease protocols, counterfactual: moves for which `W` would have ended while a lock of the old holder was still on, and those locks |
| `O_rights_beyond` | as `X_rights_beyond`, for open-class objects |

Each run also has a protocol-independent `trace` object with the measured rates:

- `permit_req_per_obj_day`;
- (v6) `lock_req_per_obj_day`, `lock_mean_h`, `lock_frac_capped`, `open_decisions` and `open_decisions_per_day`;
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

## Changes in v6

These changes follow review round 4 (R06 M3, M4, M6, M7; R05 M1, M4; R09 M2).

1. **Open-class objects (R06 M4a, R05 M1d, R09 M2.6).** Three isolation points per site, with locks that stay on
   until released, as described above. OffGrant never moves them by expiry; wait-for-release behaves the same;
   merging baselines move them at once. New `O_*` metrics, including refused locks and the counterfactual
   "move by expiry".
2. **By construction, stated (R06 M3, R09 M2).** The module docstring, this file and the `analyze.py` header and
   output state that the simulator enforces each protocol's rules, so OffGrant's zero conflicts hold by
   construction and are checked by assertions (kept, and extended to the open class).
3. **Statistics (R06 M6).** `analyze.py` reports, for the headline tables, the mean with a 95% percentile
   bootstrap confidence interval (10,000 resamples of the runs, fixed seed) and the median, instead of a Student-t
   interval. Every maximum names its scope: "max over the n runs of this grid point" or "max over all N runs".
   Zero counts get a 95% one-sided upper bound, and counts get the number of runs with a non-zero value.
4. **Hold-end cost while connected (R06 M4b, R05 M4).** Connected availability, and the requests refused or
   shortened by the hold-end rule while connected and while cut off.
5. **Unchanged.** Everything else, including the trace: the bounded-class, credential and consumption results of
   a run are those of v5 for the same seed and grid point (checked on the quick run). Only the rollback counts
   of `discard` and `timestamp` change, because locks are now among the operations they roll back.

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
# full grid (720 runs) in parallel; about 10-15 minutes on 10 cores
python prototype/offsim.py --out experiments/results/offsim_v6.jsonl --workers 10
# one 5-day run to try it out (a few seconds)
python prototype/offsim.py --quick --workers 1 --out /tmp/quick.jsonl
# summaries (UTF-8)
python prototype/analyze.py experiments/results/offsim_v6.jsonl > experiments/results/offsim_v6_summary.txt
```

`analyze.py` prints the following, in order:

1. the by-construction note and the statistics used;
2. the measured workload, including the open class;
3. the offline fraction and the longest offline period per `L`;
4. per protocol, over all runs, the number of runs with each kind of violation (bounded and open class), with
   maxima "over all N runs"; upper bounds for zero counts; the counterfactual move by expiry; the same counts per
   clock regime;
5. the merging baselines per `L` and the no-drift ablation at 100 ppm;
6. offline credential availability;
7. the hold-end rule's cost while connected, and the open class per grid point;
8. for every grid point, each protocol's bounded (X), credential and consumption (V, B) and open-class (O)
   results: mean [95% bootstrap CI] md median mx max over the runs of the grid point.

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

Earlier simulator versions' results (`offsim_v1` to `offsim_v5`) are kept in `experiments/results/` for
comparison.
