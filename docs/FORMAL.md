# Formal models (TLA+)

Two TLA+ models check OffGrant's two core claims with the TLC model checker. TLC explores *every* reachable
state of a small instance, so a "no error" result means no execution of that instance breaks the property. A
violation comes with a concrete counterexample trace.

| Model | Checks | Model version |
|---|---|---|
| `formal/LeaseV3.tla` | the lease bound (Proposition 1) and which rules it depends on | v3 (current, used with contract versions 5 and 6) |
| `formal/RightsV3.tla` | site-ledger safety and accountability (Theorem 1 (i)–(ii)) | v3 (current, used with contract versions 5 and 6) |
| `formal/Lease.tla`, `formal/Rights.tla` | earlier versions, kept for reference with their outputs | v1/v2 |

## LeaseV3: the lease bound

**What it models.** There is one exclusive object, held by site S1 through renewals from `G`. `G` may decide at any
moment to move it to S2, which then uses it at once. Nondeterministically:

- S1's uplink is cut and restored;
- requests are lost;
- renewals are delivered arbitrarily late;
- S1 loses power: its clock stops while it is off, and the TPM starts a new epoch when it comes back.

Real time advances in steps of `K`. While powered, the site clock advances `K−R .. K+R` per step, so the drift is
`ρ = R/K`. `G`'s timestamps are off by up to `EG`. S1 grants a hold: the shortest one, which ends one clock unit
after the grant, or the longest one its lease allows. The gateway executes the grant an arbitrary time later,
standing in for ledger finality.

Before contract version 5, the model's shortest grant was an instant that ended at its own reading. With `Fresh`,
such a grant could never execute, because a fresh reading is never before the grant's own. It now ends one clock
unit later, so it can execute and is checked like any other hold.

**Switches** (constants) that turn individual rules on or off:

| Constant | Meaning |
|---|---|
| `Mode` | `"send"`: count the lease from the request's send (OffGrant); `"receipt"`: from the renewal's receipt |
| `Epochs` | `TRUE`: a lease holds only in the epoch of its renewal (OffGrant) |
| `Fresh` | `TRUE`: the gateway executes only with a fresh reading still inside the hold (OffGrant) |
| `HoldInside` | `TRUE`: a hold must end inside the lease (OffGrant); `FALSE`: a hold may also run one real-time step past it |
| `Wait` | how long `G` waits after the last renewal before moving the object |

**Properties.**

- `Safe`: S1's hold is never in effect after the object moved to S2.
- `Tolerance`: S1 may grant for real time `D` after sending the request answered by its latest renewal.

`Safe` is expected to hold exactly when `Mode = "send"`, `Epochs`, `Fresh` and `HoldInside` are all on and
`Wait ≥ A·K/(K−R) + 2·EG`. Each configuration that violates `Safe` breaks exactly one of these conditions.

**Two instances.** The large instance finds the counterexamples; the small one is explored completely to show
that the full protocol is safe.

**Large instance** (`formal/lease_v3_*.cfg`), all with `K=5, R=1` (`ρ = 0.2`, site clock steps of 4, 5 or 6 per
real step of 5), `D=20`, `A=24`, `Wait=40`, `EG=5`, `Tmax=50`, at most one power loss, unless the table says
otherwise:

| Config | Change from OffGrant | Result |
|---|---|---|
| `lease_v3_ok` | none: `A=24=D(1+ρ)`, `Wait=40=⌈A/(1−ρ)⌉+2·EG` | no violation in 325 million distinct states; stopped at depth 20 because the queue outgrew the disk (`results/lease_v3_ok_D20_stopped.out`) |
| `lease_v3_eps1` | `Wait=35`: only one `EG` of slack | `Safe` violated (13-state counterexample): both of `G`'s timestamps can err |
| `lease_v3_stale` | `Fresh=FALSE`: execute at finality without a fresh reading | `Safe` violated (14 states): a late execution outlasts the lease |
| `lease_v3_noepoch` | `Epochs=FALSE` | `Safe` violated (17 states): the clock stops during power loss and the lease resumes |
| `lease_v3_receipt` | `Mode="receipt"` | `Safe` violated (14 states): a late renewal extends authority |
| `lease_v3_short` | `A=18 < D(1+ρ)` | `Tolerance` violated (7 states): a fast clock ends the lease too early |
| `lease_v3_nohold` | `HoldInside=FALSE` | `Safe` violated (14 states): a hold that runs past the lease outlasts `Wait` |

**Small instance** (`formal/lease_v3_*_s.cfg`): `K=5, R=1`, `D=10`, `A=12`, `Wait=19`, `EG=2`, `Tmax=30`, at
most one power loss.

| Config | Change from OffGrant | Result |
|---|---|---|
| `lease_v3_ok_s` | none: `A=12=D(1+ρ)`, `Wait=19=⌈A/(1−ρ)⌉+2·EG` | `Safe` and `Tolerance` hold in all 85,250,972 distinct states (depth 23, complete) |
| `lease_v3_stale_s`, `_noepoch_s`, `_receipt_s`, `_nohold_s` | as above | `Safe` violated (11–13 states) |
| `lease_v3_eps1_s` | `Wait=17` | no violation (87.5 million states, complete): see below |
| `lease_v3_short_s` | `A=9` | no violation (85.0 million states, complete): see below |

**Why two instances.** Clocks advance in steps of `K=5`. On the small instance, the margins that `eps1` and
`short` remove (one `EG=2`, and three clock units of allowance) are finer than one step, so no execution can
expose them, and those two configurations pass. The large instance has margins wider than a step, and there every
ablation fails; its safe configuration, however, is too large to finish. The paper therefore reports the complete
check of the small instance and the counterexamples of the large one. An earlier instance with every constant
doubled (`K=10, R=2`) passed 537 million distinct states without an error before the server's disk filled.

## RightsV3: site-ledger safety and accountability

**What it models.** A site ledger has four validators (`F = 1`), of which the set `Byz` is faulty. They seal
checkpoints over `H` heights while the site is cut off.

- **Checkpoints.** Each checkpoint names a parent at the previous height and consumes 1 or 2 units of a resource
  whose share is `Cap`. Its running total is computed along its parent chain, not looked up from a label.
- **Validators.** A correct validator seals at most one checkpoint per height, only one that extends the last
  checkpoint it sealed, and only if the running total is within `Cap`. Faulty validators seal anything.
- **Finality and blame.** A checkpoint is final with `2F+1` seals. On reconnection `G` blames every sealer of a
  final over-share checkpoint, and every validator that sealed two final checkpoints at one height.

**Properties.**

- `Safety`: with at most `F` faulty validators, there is no final over-share checkpoint and no fork.
- `NoFraming`: only faulty validators are ever blamed.
- `Accountable`: every violation blames at least `F+1` validators.

**Configurations** (`formal/rights_v3_byz*.cfg`): from zero to four faulty validators. `H=3, Cap=3` for up to two
faulty; `H=2, Cap=2` for three and four faulty, which keeps the state space tractable. With more than `F` faulty
validators `Safety` is vacuous, and `NoFraming` and `Accountable` are what matter.

| Config | Faulty | Result |
|---|---|---|
| `rights_v3_byz0` | none | all properties hold (57,122 distinct states) |
| `rights_v3_byz1` | 1 | all properties hold (4.5 million distinct states) |
| `rights_v3_byz2` | 2 | no violation in 288 million distinct states (partial: the run continues past depth 17) |
| `rights_v3_byz3` | 3 | all properties hold (2.6 million distinct states) |
| `rights_v3_byz4` | 4 | all properties hold (33.6 million distinct states) |

## Running TLC

You need Java 11 or later and `tla2tools.jar` from the
[TLA+ releases](https://github.com/tlaplus/tlaplus/releases).

```sh
cd formal
java -XX:+UseParallelGC -jar tla2tools.jar -workers auto -deadlock -config lease_v3_eps1.cfg LeaseV3.tla
java -XX:+UseParallelGC -jar tla2tools.jar -workers auto -deadlock -config rights_v3_byz1.cfg RightsV3.tla
```

`-deadlock` turns off deadlock checking: the models stop at `Tmax` on purpose.

Three scripts run many configurations, one output file each in `formal/results/`. Set `TLA2TOOLS` to the jar's
path.

| Script | Runs |
|---|---|
| `run_v3.sh` | the lease configurations `eps1`, `stale`, `noepoch`, `receipt`, `short` and `ok`, then `rights_v3_byz0` to `byz4`, one after another (`WORKERS` sets the TLC workers, default 16) |
| `run_lease_v3.sh` | the six lease configurations that drop one rule (including `lease_v3_nohold`), then `lease_v3_ok`. If `WAIT_PID` is set, `lease_v3_ok` starts only after that process has exited, so that two large runs do not compete for disk |
| `run_more.sh WORKERS cfg1 [cfg2 ...]` | the named configurations, each with its own state folder, so that they can run in parallel with another runner |

```sh
TLA2TOOLS=/path/to/tla2tools.jar ./run_lease_v3.sh
TLA2TOOLS=/path/to/tla2tools.jar ./run_more.sh 8 rights_v3_byz2
```

**How long each takes.** The violated configurations stop within a minute at their first counterexample.
`lease_v3_ok` and `rights_v3_byz2` explore their whole state spaces, hundreds of millions of states; give them
many cores, a large heap (for example `-Xmx24g -workers 16`) and tens of gigabytes of free disk, where TLC keeps
its queue.

**Parallel runs need separate state folders.** By default every TLC run keeps its queue in a subfolder of one
shared `states` folder in the current directory. `run_v3.sh` and `run_lease_v3.sh` pass `-cleanup`, which
deletes that whole folder, so that a finished run frees its disk. If two runs share the folder, one run's
`-cleanup` also deletes the queue of the other, which then fails. `run_more.sh` therefore gives each run its own
folder (`-metadir scratch/<config>`), does not pass `-cleanup`, and removes the folder itself when the run ends.
Use it, or another separate `-metadir` per run, whenever runs go in parallel.

**Reading the output.** A run ends with either `Model checking completed. No error has been found.` or
`Invariant <name> is violated.` followed by the counterexample trace, state by state. The outputs of every run
are in `formal/results/`.
