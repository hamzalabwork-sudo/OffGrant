# Formal models (TLA+)

Two TLA+ models check OffGrant's two core claims with the TLC model checker. TLC explores *every* reachable
state of a small instance, so a "no error" result means no execution of that instance breaks the property. A
violation comes with a concrete counterexample trace.

| Model | Checks | Current version |
|---|---|---|
| `formal/LeaseV3.tla` | the lease bound (Proposition 1) and which rules it depends on | v3 |
| `formal/RightsV3.tla` | site-ledger safety and accountability (Theorem 1 (i)–(ii)) | v3 |
| `formal/Lease.tla`, `formal/Rights.tla` | earlier versions, kept for reference with their outputs | v1/v2 |

## LeaseV3: the lease bound

**What it models.** There is one exclusive object, held by site S1 through renewals from `G`. `G` may decide at any
moment to move it to S2, which then uses it at once. Nondeterministically:

- S1's uplink is cut and restored;
- requests are lost;
- renewals are delivered arbitrarily late;
- S1 loses power: its clock stops while it is off, and the TPM starts a new epoch when it comes back.

Real time advances in steps of `K`. While powered, the site clock advances `K−R .. K+R` per step, so the drift is
`ρ = R/K`. `G`'s timestamps are off by up to `EG`. S1 grants a hold: an instant, or the longest hold its lease
allows. The gateway executes the grant an arbitrary time later, standing in for ledger finality.

**Switches** (constants) that turn individual rules on or off:

| Constant | Meaning |
|---|---|
| `Mode` | `"send"`: count the lease from the request's send (OffGrant); `"receipt"`: from the renewal's receipt |
| `Epochs` | `TRUE`: a lease holds only in the epoch of its renewal (OffGrant) |
| `Fresh` | `TRUE`: the gateway executes only with a fresh reading still inside the hold (OffGrant) |
| `Wait` | how long `G` waits after the last renewal before moving the object |

**Properties.**

- `Safe`: S1's hold is never in effect after the object moved to S2.
- `Tolerance`: S1 may grant for real time `D` after sending the request answered by its latest renewal.

**Configurations** (`formal/lease_v3_*.cfg`), all with `K=10, R=2` (`ρ = 0.2`), `D=40`, `EG=10`, `Tmax=100`, at
most one power loss:

| Config | Change from OffGrant | Expected result |
|---|---|---|
| `lease_v3_ok` | none: `A=48=D(1+ρ)`, `Wait=80=A/(1−ρ)+2·EG` | `Safe` and `Tolerance` hold |
| `lease_v3_eps1` | `Wait=70`: only one `EG` of slack | `Safe` violated: both of `G`'s timestamps can err |
| `lease_v3_stale` | `Fresh=FALSE`: execute at finality without a fresh reading | `Safe` violated: a late execution outlasts the lease |
| `lease_v3_noepoch` | `Epochs=FALSE` | `Safe` violated: the clock stops during power loss and the lease resumes |
| `lease_v3_receipt` | `Mode="receipt"` | `Safe` violated: a late renewal extends authority |
| `lease_v3_short` | `A=44 < D(1+ρ)` | `Tolerance` violated: a fast clock ends the lease too early |

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
faulty; `H=2, Cap=2` for three and four faulty, which keeps the state space tractable. All three properties are
expected to hold in every configuration. With more than `F` faulty validators `Safety` is vacuous, and
`NoFraming` and `Accountable` are what matter.

## Running TLC

You need Java 11 or later and `tla2tools.jar` from the
[TLA+ releases](https://github.com/tlaplus/tlaplus/releases).

```sh
cd formal
java -XX:+UseParallelGC -jar tla2tools.jar -workers auto -deadlock -config lease_v3_eps1.cfg LeaseV3.tla
java -XX:+UseParallelGC -jar tla2tools.jar -workers auto -deadlock -config rights_v3_byz1.cfg RightsV3.tla
# all configurations, one output file each in formal/results/ (set TLA2TOOLS to the jar's path)
TLA2TOOLS=/path/to/tla2tools.jar ./run_v3.sh
```

`-deadlock` turns off deadlock checking: the models stop at `Tmax` on purpose.

**How long each takes.** The violated configurations stop within seconds at their first counterexample.
`lease_v3_ok` explores the whole state space, which runs to hundreds of millions of states; give it many cores and
a large heap (for example `-Xmx24g -workers 16`).

**Reading the output.** A run ends with either `Model checking completed. No error has been found.` or
`Invariant <name> is violated.` followed by the counterexample trace, state by state. The outputs of every run
are in `formal/results/`.
