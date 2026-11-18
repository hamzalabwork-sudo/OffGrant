# OffGrant concepts

This guide explains what OffGrant is for, the assumptions it makes, every protocol rule, and exactly what it
guarantees. No blockchain or distributed-systems background beyond the basics is assumed.

- [1. The setting](#1-the-setting)
- [2. Kinds of operations](#2-kinds-of-operations)
- [3. System model and trust assumptions](#3-system-model-and-trust-assumptions)
- [4. Leases on a trusted clock](#4-leases-on-a-trusted-clock)
- [5. Holds, finality and the gateway](#5-holds-finality-and-the-gateway)
- [6. Checkpoints and anchor-before-renew](#6-checkpoints-and-anchor-before-renew)
- [7. Moving objects and revoking credentials](#7-moving-objects-and-revoking-credentials)
- [8. Fraud proofs and sanctions](#8-fraud-proofs-and-sanctions)
- [9. Guarantees](#9-guarantees)
- [10. Limitations](#10-limitations)

## 1. The setting

A company runs several **sites** and a **headquarters**. Headquarters keeps the global ledger `G` and decides who
may do what. Every site runs its own small blockchain (a PureChain ledger with, for example, four validators on
site), so the site keeps working when its uplink to headquarters is down.

Uplinks fail at every timescale:

- satellite links drop for seconds, many times an hour;
- links drop for a minute or two a few times a day;
- disasters can keep a site offline for days.

The question OffGrant answers is: **what may a cut-off site still do, and how do we keep two sites from using the
same exclusive right?**

## 2. Kinds of operations

Not every operation is dangerous offline. OffGrant treats four classes differently:

| Class | Example | Offline rule | Conflict if handled naively |
|---|---|---|---|
| Commutative record | sensor log, maintenance note | always accepted | none |
| Bounded consumption | spare parts, energy quota | accepted while the site's running total stays within its **share** | more consumed than exists |
| Exclusive object | switching window, crane slot, isolation point | accepted while the site holds a valid **lease** | two sites use it at once |
| Credential | an operator allowed at several sites | accepted while the credential's **lease** is valid | a revoked operator keeps acting |

Shares are issued so that their sum never exceeds the global cap. Then no combination of offline sites can
overspend, as long as each stays within its share. Leases are the subject of the next sections.

## 3. System model and trust assumptions

- **G** is correct. It acts on its own blocks only once they are final, and its block timestamps are within
  `ε_G` of real time.
- **Links** are up or down for unknown periods. Delivered messages may be delayed by any amount.
- **Each site** has `n ≥ 3f+1` validators. Any number of them, and of the site's operators, may be faulty, but no
  one can forge signatures.
- **Each site has a gateway** with a TPM 2.0 chip:
  - its clock runs at a rate within `[1−ρ, 1+ρ]` of real time while powered, and stops while unpowered;
  - every attested reading carries an **epoch** (the TPM's reset and restart counters) that changes after every
    power loss;
  - readings flagged by the TPM as possibly repeated are rejected, and changing the clock rate is locked by
    platform policy.

  The gateway executes grants on equipment and is trusted for safety. It holds the clock, so it decides which
  operations the clock attests.
- **What is not trusted:** a faulty gateway can misuse equipment it physically controls. OffGrant cannot prevent
  that. It can only make whatever is recorded on the ledger attributable.

## 4. Leases on a trusted clock

### Counting from the send

While connected, the site sends a renewal request every few seconds. One request covers all the objects and
credentials the site holds, and `G` answers it with one certificate. The request carries a TPM-attested reading
`(e, c_q)`: epoch `e` and clock value `c_q` at the moment of **sending**. When `G` answers, the site may grant
each object while its clock, still in epoch `e`, is below `c_q + A`.

Counting from the send is what removes any need to bound message delay. A renewal that arrives very late still
expires at `c_q + A`, which may already have passed. Counting from the *receipt* instead would let a delayed
renewal extend the site's authority. The TLA+ model finds exactly that counterexample
([FORMAL.md](FORMAL.md)).

### How long to wait

Let `D` be the real time a cut-off site should be able to keep working (the **offline tolerance**). The site
cannot tell a fast clock from a slow one, so:

- to guarantee `D` of real time even on a fast clock, the lease must be `A = D(1+ρ)` clock units;
- on a slow clock, `A` clock units can take up to `A/(1−ρ)` of real time to elapse.

So `G` must wait at least `A/(1−ρ) = D(1+ρ)/(1−ρ)` after the request was sent. This is the classical lease
bound, and no protocol can do better. `G` only knows the send happened before its own issue timestamp, and each
of its two timestamps (issue and reassignment) can be off by `ε_G`. Hence:

```
W = ceil(A / (1 − ρ)) + 2·ε_G        (RightsRegistry.waitSeconds)
```

Example: `ρ = 0.15` (the TPM 2.0 bound), `D = 24 h`. Then `A = 27.6 h` on the site clock, and `W ≈ 32.5 h` (plus
`2ε_G`). A site that is cut off can keep working for at least 24 h; headquarters can reassign its objects after
32.5 h.

### Power loss and epochs

A TPM clock stops while the gateway is unpowered. If the lease were tied only to clock values, it would *resume*
after power returns and outlast `W`. Binding every lease to the epoch of its renewal makes a power loss end it
instead. The site then needs a fresh renewal in the new epoch.

## 5. Holds, finality and the gateway

A grant is not instantaneous in practice:

- the **site ledger** must first make it final;
- the grant then lasts for a while (a **hold**).

The lease bound must cover the whole *effect*, not just the moment the grant was recorded.

- **Bounded hold** (switching window, crane slot): has an end on the site clock. `SiteRights` accepts it only if
  that end is before `c_q + A`. A power loss ends it, because the gateway then executes nothing of the old epoch.
- **Open hold** (lockout/tagout on an isolation point): lasts until it is released. Several crews may each hold
  their own open hold on one object. Each hold's id is the reading of its grant, and a release names the hold it
  ends, so one crew's release cannot end another crew's lock. Such an object is never moved by expiry (see
  section 7).
- **Finality on Clique.** Clique has no finality of its own, so site validators sign a checkpoint only after a
  confirmation depth, at most once per height, and only one whose history contains the checkpoint they signed
  last. A checkpoint is final with `q = ⌊(n+f)/2⌋ + 1` signatures. Any two such quorums share `f+1` validators.
- **Execution.** The gateway executes a grant only once it is in a sealed checkpoint, and only if a *fresh* clock
  reading, in the same epoch, is still before the hold's end and the lease's end. Otherwise the grant **lapses**.
  Without this fresh check, a grant made just before the lease ends could take effect after the object has
  moved. The ablation `nofresh` and the TLA+ configuration `lease_v3_stale` show this happening.

### Attested operations

Every operation that uses a right carries the clock's attestation of its whole content: consumption (`CONSUME`),
grant (`USE`), release (`RELEASE`) and acknowledgement (`ACK`). The attestation binds the site, the epoch, the
reading and every field of the operation except the running total (which the ledger derives), inside a domain
unique to one deployment on one chain. On a site ledger the readings of attested operations strictly increase.
So:

- an attestation cannot be replayed, because the same reading cannot appear twice;
- operations cannot be reordered without breaking the order of readings;
- an attestation for one operation cannot be reused for another (for example a grant's attestation as an
  acknowledgement).

A grant names the renewal it uses (its base `c_q`), and a consumption names the share version it uses. A faulty
quorum can still seal operations the gateway never asked for, but it cannot attach a valid attestation to them.

Commutative records (`LOG`) need no right and are not attested. Neither is an applied share (`SHARE`), which
carries `G`'s certificate instead.

## 6. Checkpoints and anchor-before-renew

A checkpoint contains:

| Field | Purpose |
|---|---|
| `height` | the checkpoint's position in the site's history |
| `histRoot` | a fixed-depth Merkle accumulator of every earlier checkpoint (leaf `i` = the checkpoint at height `i`) |
| `opsRoot`, `opCount` | Merkle root of the operations since the previous checkpoint |
| `stateHash` | the site's state at the close: the newest attested reading, and every resource's running total and share version |
| `tip` | the last site-ledger block covered |
| `closeEpoch`, `closeReading`, `closeSig` | closing time, attested by the TPM over the checkpoint's content |

The history accumulator commits the whole history in one hash. One inclusion path shows that a checkpoint is an
ancestor of another, whatever the distance between them. This keeps every fraud proof's cost independent of the
length of the history (section 8).

**Anchor before renew.** `G` renews a site only if the site's anchored checkpoints cover its operations up to the
request's reading minus a lag `λ`, in the request's epoch. A site that withholds its checkpoints stops getting
renewals and loses its rights within `λ + A`. The closing time is attested by the TPM, so a faulty quorum cannot
claim coverage ahead of the site's real clock.

**Catch-up.** A checkpoint can be anchored if the last anchored checkpoint is in its history. After an outage of
any length, the relayer anchors only the newest checkpoint, in one transaction. Anyone may anchor. Anchoring an
older checkpoint first does no harm, because the newest one still contains it in its history.

## 7. Moving objects and revoking credentials

`G` stops renewing an object as soon as headquarters decides to move it (`stop`).

- **Slow path** (holder cut off): `G` moves an object with bounded holds once `W` has passed since its last
  renewal (`reassign`). Objects with open holds are refused (`HoldMayBeOpen`), because a lock may still be on.
- **Fast path** (holder reachable):
  1. The site applies the certified stop, which blocks new grants.
  2. Once nothing of the object is in effect (no hold running, no lock on, no grant awaiting execution), the
     gateway attests an `ACK` operation. The site ledger accepts it only after the stop, with no open hold and no
     bounded hold of the current epoch still running. The `ACK` names the stopped renewal.
  3. Once the `ACK` is in a sealed checkpoint, a quorum of the site's validators signs an acknowledgement of it.
  4. `G` checks the `ACK` attestation and the quorum, and moves the object at once (`reassignAcked`).

  `G` keeps every acknowledgement, keyed by object, site, epoch and reading. Entries are never overwritten, so the
  evidence survives later hand-overs. Later renewals must be newer than the acknowledged reading, so an old
  request cannot be replayed.
- **Credentials** are revoked the same way. An offline acceptance can happen at most `W` after the revocation.
- **Shares** can be raised at once. Share certificates are versioned, so an old, higher share cannot be replayed.
  Lowering a share works in two steps:
  1. The site applies the lower share as a `SHARE` operation on its ledger. It accepts it only if its running
     total already fits.
  2. `G` frees the capacity when a sealed checkpoint's state shows the new version applied and the total within
     it (`confirmShare`). Later consumption under the old version, or above the new amount, is provable.

**Recovery.** A site's clock key and validators never change, because every old attestation and seal is judged
against them. When a TPM is replaced or cleared, or validators are lost, headquarters retires the site
(`retireSite`: no further renewals) and registers a new site incarnation with the new clock and validator set. The
old incarnation's history stays judgeable, so faults in it are still provable and its honest signers still cannot
be framed. Its objects move to the new incarnation by the normal paths. As a last resort, `forceReassign` moves a
stopped object once the holder's allowance has run out (after `W`), for example a lockout whose holder site is
lost. It is logged, and for open holds it is **outside the safety guarantee**: the site must first clear the hold
physically.

## 8. Fraud proofs and sanctions

Anyone can submit to `G` a sealed checkpoint (signed by a quorum) together with Merkle proofs of a violation. Some
proofs also name an **ancestor**: an earlier checkpoint, its state, and its inclusion path in the later
checkpoint's history.

| Proof | Violation | Who is slashed |
|---|---|---|
| `proveOverspend` | a running total above the share version it names, or below its own amount | the checkpoint's signers |
| `proveBadOp` | an operation with an invalid attestation, a share `G` never certified, or an unknown kind | the checkpoint's signers |
| `proveOveruse` | a grant without a matching renewal, outside its lease, with a hold ending too late, in a new epoch, or of the wrong hold class | the checkpoint's signers |
| `proveInconsistent` | two operations of one checkpoint out of order: readings that do not increase, a running total that restarts lower, or an older share version | the checkpoint's signers |
| `proveStateMismatch` | a committed state that is malformed or below the checkpoint's own operations | the checkpoint's signers |
| `proveRegress` | a committed state below an ancestor's (a total, a version or the clock went back) | the later checkpoint's signers |
| `proveOpRegress` | an operation below an ancestor's state: a replayed or back-dated attestation, or consumption that restarts lower or uses an older version | the later checkpoint's signers |
| `proveUseAfterAck` | a grant, hold or release, under rights from before an acknowledgement, that runs past it | validators who both acknowledged and signed it |
| `proveFork` | two different sealed checkpoints at one height, or a checkpoint whose history holds a different one at a lower height | validators who signed both |

Every proof needs one checkpoint, at most one ancestor, and paths of bounded length, so its cost does not depend
on how long the site's history is. Slashed validators lose their collateral on `G` and no longer count towards
quorums for new anchors, acknowledgements and share confirmations. A site with `f+1` slashed validators loses all
rights.

## 9. Guarantees

**Proposition 1 (lease bound).** No protocol can let a site grant for `D` under every clock rate and move the
object sooner than `D(1+ρ)/(1−ρ)`. OffGrant's rules (send-time leases, epochs, holds inside the lease, fresh
execution, wait `W`) attain this bound without assuming anything about message delays.

**Theorem 1 (accountability).** For every pattern of outages and power losses:

1. if a site's gateway is correct and at most `f` of its validators are faulty, no two sites' holds of an object
   overlap, shares are respected, and no executed grant is rolled back;
2. every out-of-rights operation in a sealed checkpoint yields a proof naming at least `f+1` faulty validators,
   and no proof ever names a correct validator;
3. a site that stops anchoring loses its rights within `λ + A`, and silence alone is never punished.

## 10. Limitations

- **Unrecorded misuse.** A faulty gateway can misuse equipment without recording it; that is not attributable. A
  faulty quorum can also keep its rights while sealing a sanitized history, but everything it seals is then
  checked.
- **Clock-rate adjustment** must be locked. An insider with TPM owner rights could change the rate by up to
  32.5%.
- **TPM keys.** TPMs sign with P-256 or RSA keys. The prototype uses secp256k1 stand-ins, because on-chain P-256
  verification is not available in the PureChain client.
- **Emergency override.** `forceReassign` moves an object without waiting for `W` or an acknowledgement. Theorem
  1 does not cover a move made this way. It is logged on `G` and is meant only for a site's safety procedure.
- **Choosing `D`.** It is a policy choice. A larger `D` keeps cut-off sites working longer, at the cost of a
  longer reassignment and revocation delay `W`.
