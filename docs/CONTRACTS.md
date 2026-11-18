# Contracts

Three Solidity files (0.8.30, contract version 5) in `contracts/src/`:

| File | Runs on | Role |
|---|---|---|
| `RightsRegistry.sol` | the global ledger `G` | issues rights, renews leases, moves objects, anchors checkpoints, judges fraud proofs |
| `SiteRights.sol` | each site ledger | enforces the site's rights locally, also while the site is cut off |
| `OffLib.sol` | both (library) | data structures, digests, signature recovery, Merkle and history verification |

**Build.** `contracts/foundry.toml` compiles through the IR pipeline (`via_ir = true`) with the optimizer at 200
runs. The fraud proofs take many calldata arguments, which needs the IR pipeline. The runtime code of
`RightsRegistry` is 23,671 bytes, under the 24,576-byte limit of EIP-170. `SiteRights` is 9,565 bytes. The EVM
target is `paris`, which PureChain and other proof-of-authority chains accept.

**Signatures.** All signatures are 65-byte ECDSA (secp256k1) signatures with a low-`s` check. Every digest
contains the domain

```
dom = keccak256(abi.encode("OFFGRANT-v5", chainid, registry))
```

where `chainid` is the chain id of `G` and `registry` is the address of the `RightsRegistry`. Each digest also
has its own tag string and names the site and, where it applies, the object, epoch and reading. A signature for
one purpose, deployment or chain can never be replayed for another. `SiteRights` computes the same `dom` from
the registry address and `G`'s chain id given to its constructor.

- [Data formats](#data-formats)
- [RightsRegistry](#rightsregistry)
- [SiteRights](#siterights)
- [Errors](#errors)
- [Tests](#tests)
- [Changes in v5](#changes-in-v5)

## Data formats

### Operation (`OffLib.Op`)

Every accepted operation on a site ledger is emitted as an `OpRecorded` event. Validators batch the events into
checkpoints. An operation is the tuple
`(kind, key, epoch, reading, base, until, amount, total, version, clockSig)`. Fields a kind does not use are 0.

| Field | `CONSUME` (1) | `USE` (2) | `LOG` (3) | `RELEASE` (4) | `ACK` (5) | `SHARE` (6) |
|---|---|---|---|---|---|---|
| `key` | resource id | object or credential id | payload hash | object id | object id | resource id |
| `epoch`, `reading` | site clock time of the operation | same | 0 | same | same | 0 |
| `base` | 0 | `c_q` of the renewal the grant uses | 0 | id of the hold it ends (the reading of its grant) | `c_q` of the stopped renewal | 0 |
| `until` | 0 | end of the hold (site clock), or `OPEN = 2^64−1` for an open hold | 0 | 0 | 0 | 0 |
| `amount` | amount consumed | 0 | 0 | 0 | 0 | new share amount |
| `total` | running total after the operation | 0 | 0 | 0 | 0 | running total when applied |
| `version` | share version it consumes under | 0 | 0 | 0 | 0 | share version applied |
| `clockSig` | attestation | attestation | empty | attestation | attestation | empty |

**Attested operations.** `CONSUME`, `USE`, `RELEASE` and `ACK` carry the site clock's attestation

```
clockDigest(dom, site, epoch, reading, opTag(op))
opTag(op) = keccak256(abi.encode("OFFGRANT-OP", kind, key, base, until, amount, version))
```

So the attestation covers every field except the running total, which the ledger derives. On a site ledger the
`(epoch, reading)` of attested operations strictly increases. An attestation therefore cannot be replayed (the
same reading twice), reordered, or reused for different content. `LOG` and `SHARE` are not attested: a record
needs no rights, and a share is certified by `G`.

The Merkle leaf of an operation is
`keccak256(abi.encode(kind, key, epoch, reading, base, until, amount, total, version, keccak256(clockSig)))`.
The operations tree pairs an odd node with itself.

### Checkpoint header (`OffLib.Header`)

| Field | Meaning |
|---|---|
| `site`, `height` | the site and the checkpoint's height (the first checkpoint has height 1) |
| `histRoot` | root of the history accumulator: every earlier checkpoint of the site (see below) |
| `opsRoot`, `opCount` | Merkle root and number of the operations since the previous checkpoint |
| `stateHash` | hash of the site's `State` after the checkpoint's last operation |
| `tip` | hash of the last site-ledger block the checkpoint covers |
| `closeEpoch`, `closeReading` | the closing time on the site clock |
| `closeSig` | the site clock's attestation of the closing time, tagged with `contentTag(header)` |

`contentTag(h)` hashes the tag `"OFFGRANT-CLOSE"` and every field from `site` to `tip`.
`headerHash(h) = keccak256(abi.encode(contentTag(h), closeEpoch, closeReading))`, so it covers everything except
`closeSig`. Validators sign `checkpointDigest(dom, headerHash(h))`.

**History accumulator.** `histRoot` is the root of a fixed-depth Merkle tree with `2^20` leaves. Leaf `i` is the
header hash of the site's checkpoint at height `i`, for every `i < height`. All other leaves are zero. One
inclusion path of 20 hashes shows that a checkpoint is in another's history, however long the history is. So two
histories that differ anywhere can be told apart with one path.

### State (`OffLib.State`)

| Field | Meaning |
|---|---|
| `epoch`, `reading` | the newest attested clock reading on the ledger |
| `resources[]` | resource ids, strictly increasing |
| `totals[]`, `versions[]` | for each resource, its running total and its newest applied share version |

`stateHash = keccak256(abi.encode("OFFGRANT-STATE", epoch, reading, resources, totals, versions))`. A resource
missing from the state counts as total 0 and version 0. A correct ledger's state only grows: totals, versions and
the clock never go back.

### Digests

| Function | Signed by | Meaning |
|---|---|---|
| `clockDigest(dom, site, epoch, reading, tag)` | site clock (TPM) | "my clock read `reading` in `epoch`", bound to `tag` |
| `checkpointDigest(dom, headerHash)` | site validators | checkpoint seal |
| `renewalDigest(dom, site, objectsHash, epoch, cq, issued)` | `G`'s authorities | renewal certificate for a batch of objects |
| `stopDigest(dom, site, object, epoch, cq)` | `G`'s authorities | stop certificate, cancelling renewals up to `(epoch, cq)` |
| `ackDigest(dom, site, object, epoch, reading)` | site validators | "the `ACK` operation at this time is in a sealed checkpoint of our ledger" |
| `shareDigest(dom, site, resource, amount, version)` | `G`'s authorities | share certificate |
| `leaseDigest(dom, site, object, allowanceMs, openHold)` | `G`'s authorities | lease certificate (allowance and class) |

The clock attests with one of three tags:

| Tag | Attests |
|---|---|
| `opTag(op)` | an operation |
| `contentTag(header)` | a checkpoint close |
| `requestTag(objectsHash(objects))` | a renewal request for a batch of objects, at the moment it is **sent** |

## RightsRegistry

Constructor: `RightsRegistry(rhoPpm, gSlack, anchorLagMs)`. These are the drift bound in parts per million (below
1,000,000), `ε_G` in seconds, and the anchoring lag `λ` in milliseconds. The deployer becomes `admin`.

### Administration (admin only)

| Function | What it does |
|---|---|
| `registerSite(site, f, clockKey, validators, startEpoch, startReading)` | Registers a site with `n ≥ 3f+1` validators (at most 255) and its clock key. Each validator gets a bond. Coverage starts at the given clock time. Site id 0, a zero clock key, a zero validator and a repeated validator are rejected |
| `setCap(resource, amount)` | Sets the global cap of a resource, never below what is already allocated |
| `setShare(resource, site, amount)` | Issues the next share version and returns it. Raising takes effect at once. Lowering keeps the old amount reserved until `confirmShare` |
| `createLease(object, exclusive, openHold, allowanceMs)` | Creates an exclusive object or a credential with allowance `A`. The class is fixed here: an exclusive object with `openHold` takes only open holds. A credential cannot be open-hold |
| `permit(object, site)` | Sets the first holder of an exclusive object, or adds a site where a credential is valid |
| `stop(object, nextSite)` | Stops renewals. Names the next holder (exclusive object) or revokes (credential, `nextSite = 0`) |

### Recovery (admin only)

| Function | What it does |
|---|---|
| `rotateClock(site, clockKey, epoch, reading)` | Installs a new clock key (a replaced or cleared TPM). Coverage restarts at the new clock's reading |
| `replaceValidator(site, oldValidator, newValidator)` | Replaces a failed or slashed validator. The quorum size is unchanged |
| `forceReassign(object)` | Emergency override for a stopped exclusive object, for example a lockout whose holder site is lost. It emits `ForcedReassign`. It is **outside the safety guarantee**: the site must first clear the hold physically |

### Leases

| Function | Who calls | What it checks |
|---|---|---|
| `renew(site, objects, epoch, cq, clockSig)` | the site's relayer | One request for a batch of objects. Site not revoked; valid clock attestation of the request; anchored coverage in the same epoch reaches `cq − λ`; for each object: it exists, the site may hold it, it is not stopped, and `(epoch, cq)` is newer than the site's last renewal of it. Returns the issue time |
| `waitSeconds(object)` | anyone (view) | `ceil(A / (1 − ρ)) + 2·gSlack` |
| `releaseAt(object)` | anyone (view) | last renewal time plus `waitSeconds` |
| `mayRenew(object, site)` | anyone (view) | whether the site may renew the object |
| `reassign(object)` | anyone | Slow path: object stopped, not an open-hold object, and `now ≥ releaseAt` |
| `reassignAcked(object, epoch, reading, clockSig, acks)` | the site's relayer | Fast path: a valid clock attestation of the holder's `ACK` operation, whose `base` is the stopped renewal; `(epoch, reading)` newer than that renewal; a quorum of unslashed validators over `ackDigest`. The acknowledgement is stored, and later renewals must be newer than it |
| `confirmShare(resource, site, header, seals, state)` | the site's relayer | A pending lower share; a checkpoint sealed by a quorum of unslashed validators; `state` hashes to the header's `stateHash` and shows the pending version (or newer) applied, with the total within the new amount. This frees the capacity |
| `ackSignerCount(key)` | anyone (view) | number of validators in a stored acknowledgement |

**Stored acknowledgements.** `reassignAcked` stores the signers under
`ackKey(object, site, epoch, reading)`. Entries are only added, never overwritten, so a later hand-over of the
same object cannot erase the evidence that `proveUseAfterAck` needs.

### Checkpoints

`anchor(header, seals, histPath)` records a sealed checkpoint. It needs:

- a quorum of unslashed validators;
- a height above the last anchored one;
- the last anchored checkpoint in the header's history (`histPath` is its inclusion path; empty for the first
  anchor);
- a valid clock attestation of the close, not older than the current coverage.

The close then becomes the site's coverage, which renewals require (anchor before renew). After an outage of any
length, one transaction anchors the newest checkpoint. Anyone may anchor. Anchoring an older checkpoint first does
no harm: the newest one still anchors, because its history contains the older one.

### Fraud proofs

Each proof verifies a quorum of seals on the checkpoint, counting every registered validator (so that co-signers
of an already slashed validator are still caught), the Merkle paths, and the violation. It then slashes and
returns the number of newly slashed validators. On honest data it reverts with `NotAViolation` (or `BadProof` for
malformed input). Arguments are grouped:

- `OpProof(op, idx, path)`: an operation, its index and its Merkle path in the checkpoint's `opsRoot`.
- `Ancestor(p, state, histPath)`: an earlier checkpoint `p` of the same site, its `state` (must hash to
  `p.stateHash`) and the inclusion path of `p` in the later checkpoint's history.

| Function | Violation | Who is slashed |
|---|---|---|
| `proveOverspend(h, seals, o)` | a consumption whose running total is above the amount `G` certified for the version it names, or below its own amount | the checkpoint's signers |
| `proveBadOp(h, seals, o)` | an attested operation with an invalid attestation, a `SHARE` with a version or amount `G` never certified, or an unknown kind | the checkpoint's signers |
| `proveOveruse(h, seals, o)` | a grant not covered by its rights: no renewal issued for its base, a reading outside `[c_q, c_q + A)`, a bounded hold that does not end after the grant and inside the allowance, or the wrong hold class for the object | the checkpoint's signers |
| `proveInconsistent(h, seals, a, b)` | two operations `a` before `b` in one checkpoint that no correct ledger records in this order: attested readings that do not strictly increase, a running total that restarts below an earlier one, or a consumption under an older share version | the checkpoint's signers |
| `proveStateMismatch(h, seals, o, state)` | a committed state that is malformed, or below one of the checkpoint's own operations (total, version or clock) | the checkpoint's signers |
| `proveRegress(h, seals, state, a)` | a committed state below an ancestor's: a total, a version or the clock went back, or a resource was dropped | the later checkpoint's signers |
| `proveOpRegress(h, seals, o, a)` | an operation below an ancestor's state: an attested operation not newer than the ancestor's clock (replayed or back-dated), or a consumption that restarts below the ancestor's total or uses an older version | the later checkpoint's signers |
| `proveUseAfterAck(h, seals, o, ackEpoch, ackReading)` | a `USE` or `RELEASE` of the object, under rights from before a stored acknowledgement, that runs past it (a later reading, or a bounded hold of the same epoch that ends after it) | validators who both acknowledged and signed the checkpoint |
| `proveFork(h1, s1, h2, s2, leafAtH1, histPath)` | two different sealed checkpoints at one height, or a higher checkpoint `h2` whose history holds a different checkpoint (`leafAtH1`) at `h1`'s height | validators who signed both |

**Cost.** A proof needs one checkpoint, at most one ancestor named through the history accumulator, and Merkle
paths of fixed or logarithmic length. Its cost does not depend on the length of the site's history.

Slashing marks each validator as slashed, zeroes its bond, and emits `Slashed`. Slashed validators no longer count
towards anchor, acknowledgement or share quorums. When more than `f` validators of a site are slashed, the site is
revoked (`SiteRevoked`) and can no longer renew.

### Events

`SiteRegistered`, `ClockRotated`, `ValidatorReplaced`, `ShareSet`, `ShareConfirmed`, `LeaseCreated`, `Permitted`,
`Renewed`, `Stopped`, `Acknowledged`, `Reassigned`, `ForcedReassign`, `Anchored`, `Slashed`, `SiteRevoked`.

## SiteRights

Constructor: `SiteRights(site, registry, gChainId, clockKey, authorities, threshold)`. Certificates need
`threshold` distinct signatures from `G`'s authorities. Site id 0, a zero clock key and a zero authority are
rejected.

### Rights (relayed while connected)

| Function | What it does |
|---|---|
| `applyShare(resource, amount, version, sigs)` | Applies a newer share version. A lower share is accepted only if the running total already fits. Recorded as a `SHARE` operation, so checkpoints commit the version |
| `applyLease(object, allowance, isOpen, sigs)` | Learns an object's allowance and class |
| `applyRenewal(objects, epoch, cq, issued, sigs)` | Applies one renewal certificate for a batch of objects. Each object adopts it if it is newer than the object's current renewal and its last stop |
| `applyStop(object, epoch, cq, sigs)` | Cancels renewals up to `(epoch, cq)`. No new grants follow. Bounded holds run to their end; open holds stay until released |

### Operations (also while cut off)

Every attested operation needs a valid clock attestation of its content and a reading newer than every earlier
attested operation on the ledger (`StaleReading` otherwise).

| Function | What it does |
|---|---|
| `consume(resource, amount, version, epoch, reading, clockSig)` | Accepts if `version` is the applied share version and the new running total is within the share |
| `use(object, cq, epoch, reading, until, clockSig)` | Grants a hold under the renewal `(epoch, cq)`, which must be the newest applied one, with `cq ≤ reading < cq + A`. A bounded hold needs `reading < until < cq + A`. An open-hold object needs `until = OPEN`, and the hold's id is its reading. Several crews may hold open holds on one object at once |
| `release(object, holdId, epoch, reading, clockSig)` | Ends the open hold `holdId`. Allowed after a stop. A release cannot be replayed: the named hold is then gone (`NotHeld`) |
| `acknowledge(object, epoch, reading, clockSig)` | Fast path: records an `ACK` operation whose `base` is the stopped renewal. Accepted only after a stop has been applied, with no newer renewal, no open hold, and no bounded hold of this epoch still running at `reading`. Later grants need a renewal newer than the acknowledgement |
| `record(payloadHash)` | Appends a commutative record (`LOG`) |
| `remaining(object, epoch, reading)` | View: allowance left at that reading, 0 when expired |

### The gateway

The contract records grants. **Execution is the gateway's job.** The gateway holds the clock, so it attests only
operations it requests. It:

- executes a grant only once the grant is in a sealed checkpoint, and only with a fresh reading, in the same
  epoch, still before the hold's end and the allowance's end. Otherwise the grant lapses;
- attests an `ACK` only when nothing of the object is in effect: no bounded hold running, no lock on, and no grant
  awaiting execution. It executes nothing of the object afterwards.

Site validators sign `ackDigest` only for an `ACK` operation that is in a sealed checkpoint. See
[CONCEPTS.md](CONCEPTS.md#5-holds-finality-and-the-gateway). `experiments/offgrant/e2e.py` implements this in the
functions `gateway`, `gateway_quiescent` and `handle_stop`.

## Errors

| Error | Contract | Raised when |
|---|---|---|
| `NotAdmin`, `BadSite`, `BadLease`, `NotPermitted` | `RightsRegistry` | wrong caller; unknown, invalid or repeated site, clock key or validator; invalid lease; site not entitled to the object |
| `LeaseStopped`, `SiteRevokedErr` | `RightsRegistry` | renewal after a stop, or for a revoked site |
| `BadClockSig` | both | a clock attestation does not verify (requests, operations, acknowledgements, checkpoint closes) |
| `StaleRequest`, `StaleAck` | `RightsRegistry` | a renewal or acknowledgement not newer than the last renewal |
| `AnchorDebt(covered, needed)` | `RightsRegistry` | the site's anchored coverage is too old, or in another epoch, to renew |
| `TooEarly(releaseAt)`, `HoldMayBeOpen` | `RightsRegistry` | slow path before `W`, or for an open-hold object |
| `OverCap`, `NoPendingShare`, `ShareNotApplied` | `RightsRegistry` | shares would exceed the cap; no lower share awaits confirmation; the checkpoint does not show the lower share applied with the total within it |
| `NoQuorum`, `BadProof`, `NotAViolation` | `RightsRegistry` | too few valid seals; malformed or unlinked proof; the operation is within rights |
| `BadCertificate` | `SiteRights` | too few valid signatures from `G`'s authorities |
| `StaleReading`, `StaleShare`, `OverShare` | `SiteRights` | reading not newer than the last attested one; wrong or old share version; running total above the share |
| `NoRenewal`, `AllowanceExpired`, `BadHold`, `NotHeld` | `SiteRights` | no matching renewal; reading or hold end outside the allowance; wrong hold form; no such open hold |
| `NotStopped`, `StillHeld` | `SiteRights` | acknowledgement without an applied stop (or with a newer renewal); a hold of the object is still on |

## Tests

`contracts/test/Offgrant.t.sol` has 51 tests (`forge test`). All pass
(`experiments/results/forge_test_v5.log`). Every proof function has a test that it slashes a violation and a test
that it does not slash honest input. Tests named `*_v4exploit` are regression tests for exploits of the v4
contracts found in review.

| Group | Tests |
|---|---|
| Leases and renewals | `testFuzz_waitFormula`, `test_batchRenewalOneTransaction`, `test_staleRequestRejected`, `test_renewNeedsCoverageInEpoch`, `test_requestFromOtherDeploymentRejected`, `test_slowPathWaitsW`, `test_openHoldNeverMovedByExpiry`, `test_badRegistrationsRejected`, `test_credentialRevocation` |
| Site ledger rules | `test_grantInsideAllowanceOnly`, `test_attestationBindsContent_v4exploit`, `test_releaseReplayRejected_v4exploit`, `test_acknowledgeNeedsStopAndNoHold`, `test_newEpochEndsBoundedHolds`, `test_shareVersionedAndAttested` |
| Fast path and framing | `test_fastPathMovesObject`, `test_grantAttestationIsNoAck_v4exploit`, `test_honestReleaseNotFramed_v4exploit`, `test_useAfterAckSlashesBoth`, `test_holdRunningPastAckSlashes`, `test_ackEvidenceSurvivesLaterHandOver_v4exploit`, `test_honestUseAfterReturnNotFramed`, `test_staleAckRejected` |
| Fraud proofs on one checkpoint | `test_overspend`, `test_honestConsumptionNotSlashable`, `test_badOp`, `test_honestOpsNotBadOps`, `test_overuse`, `test_honestGrantsNotOveruse`, `test_inconsistentOrder`, `test_inconsistentStaleVersionAndUnderstate`, `test_stateMismatch`, `test_stateMalformedOrClockBehind` |
| Fraud proofs across history | `test_regressThroughEmptyCheckpoint_v4exploit`, `test_regressDroppedResourceOrClock`, `test_restartBelowAncestor_v4exploit`, `test_staleVersionAfterConfirmShare_v4exploit`, `test_replayedAttestationAcrossCheckpoints`, `test_honestHistoryNotSlashable`, `test_ancestorMustBeInHistory`, `test_forkSameHeight`, `test_forkAcrossHeights_v4exploit` |
| Anchoring, shares, quorums, recovery | `test_anchorCatchUpAndHistory`, `test_anchorRejectsForeignHistoryAndForgedClose`, `test_anchorGriefingHarmless`, `test_renewAfterAnchor`, `test_confirmShareNeedsAppliedVersion`, `test_slashedExcludedFromQuorums`, `test_largerSiteQuorum`, `test_recoveryByAdmin`, `test_proofCostIndependentOfHistory` |

The `v4exploit` tests cover these exploits:

| Test | Exploit of v4 that v5 closes |
|---|---|
| `test_attestationBindsContent_v4exploit` | a grant's attestation reused with a longer hold |
| `test_releaseReplayRejected_v4exploit` | one crew's release replayed, so the open-hold count fell to 0 while another crew's lock was on |
| `test_grantAttestationIsNoAck_v4exploit` | a grant's public attestation accepted as an acknowledgement reading |
| `test_honestReleaseNotFramed_v4exploit` | an acknowledgement at an old reading framed the honest signers of a release |
| `test_ackEvidenceSurvivesLaterHandOver_v4exploit` | the next hand-over overwrote the stored acknowledgement, erasing the evidence |
| `test_regressThroughEmptyCheckpoint_v4exploit` | a checkpoint without consumption lowered the committed total |
| `test_restartBelowAncestor_v4exploit` | consumption restarted below the anchored total |
| `test_staleVersionAfterConfirmShare_v4exploit` | consumption under the old, larger share version after `confirmShare` |
| `test_forkAcrossHeights_v4exploit` | a fork at different heights escaped, because forks were detected only at equal heights |

`test_proofCostIndependentOfHistory` checks that a proof against an ancestor 900 heights back costs within 3% of
one against the parent.

## Changes in v5

| Area | v4 | v5 |
|---|---|---|
| Clock attestations | a reading, tagged with the object | every attested operation, over its whole content (`opTag`); readings strictly increase on the site ledger |
| Domain | registry address in certificates and seals; clock attestations not bound to a deployment or chain | `dom = keccak256("OFFGRANT-v5", chainid, registry)` in every digest |
| Grants and releases | used the current renewal implicitly; one open-hold count | `use` and `consume` name the renewal or share version they use; `release` names the hold it ends; several open holds per object |
| Fast path | validators acknowledged a reading | the site ledger records an `ACK` operation; validators sign only a sealed one; `G` checks the `ACK` attestation and keeps every acknowledgement |
| Checkpoints | hash chain (`prev`), anchored base, Merkle root of totals | history accumulator (`histRoot`), committed `State` (`stateHash`), `tip` |
| Renewals | one object per request | a batch of objects per request and per certificate |
| Shares | quorum acknowledgement of the version | a `SHARE` operation on the site ledger; `confirmShare` from a sealed checkpoint's state |
| Fraud proofs | 7, some needing the parent checkpoint | 9, with `OpProof` and `Ancestor` arguments; cost independent of history length |
| Recovery | none | `rotateClock`, `replaceValidator`, `forceReassign` |
| Lease class | `setOpenHold` after creation | fixed by `createLease(object, exclusive, openHold, allowanceMs)` |
| Build | optimizer at 10,000 runs | IR pipeline, optimizer at 200 runs (EIP-170 size limit) |
