# Contracts

Three Solidity files (0.8.30) in `contracts/src/`:

| File | Runs on | Role |
|---|---|---|
| `RightsRegistry.sol` | the global ledger `G` | issues rights, renews leases, moves objects, anchors checkpoints, judges fraud proofs |
| `SiteRights.sol` | each site ledger | enforces the site's rights locally, also while the site is cut off |
| `OffLib.sol` | both (library) | data structures, digests, signature recovery, Merkle verification |

All signatures are 65-byte ECDSA (secp256k1) signatures over domain-separated digests. The domain tag, registry
address, site, object, epoch and reading are mixed into every digest, so a signature for one purpose can never be
replayed for another.

- [Data formats](#data-formats)
- [RightsRegistry](#rightsregistry)
- [SiteRights](#siterights)
- [Errors](#errors)
- [Tests](#tests)

## Data formats

### Operation (`OffLib.Op`)

Every accepted operation on a site ledger is emitted as an `Op` event. Validators batch the events into
checkpoints.

| Field | `CONSUME` (1) | `USE` (2) | `LOG` (3) | `RELEASE` (4) |
|---|---|---|---|---|
| `key` | resource id | object or credential id | payload hash | object id |
| `a` | amount | base `c_q` of the renewal | 0 | base `c_q` of the hold being released |
| `b` | running total after the op | clock reading of the grant | 0 | clock reading of the release |
| `c` | share version in force | end of the hold (`= b` for an instant use; `OPEN = 2^64−1` for an open hold) | 0 | 0 |
| `e` | 0 | clock epoch | 0 | clock epoch |
| `clockSig` | empty | TPM attestation of `(site, e, b)` tagged with the object | empty | TPM attestation tagged with `releaseTag(object)` |

The Merkle leaf of an operation is `keccak256(abi.encode(kind, key, a, b, c, e, keccak256(clockSig)))`. Trees pair
an odd node with itself.

### Checkpoint header (`OffLib.Header`)

| Field | Meaning |
|---|---|
| `site`, `height`, `prev` | the site, the checkpoint's height, and the hash of the previous checkpoint |
| `opsRoot`, `opCount` | Merkle root and number of the operations |
| `stateRoot` | Merkle root of `stateLeaf(resource, total)` for every resource at the close |
| `baseHeight`, `baseHash` | the site's latest checkpoint anchored on `G` |
| `closeEpoch`, `closeReading` | the closing time on the site clock |
| `closeSig` | TPM attestation of the closing time, tagged with `contentTag(header)` |

Validators sign `checkpointDigest(registry, headerHash(header))`. The header hash covers everything except
`closeSig`.

### Digests

| Function | Signed by | Meaning |
|---|---|---|
| `clockDigest(site, epoch, reading, tag)` | site TPM | "my clock read `reading` in `epoch`", bound to `tag` |
| `requestDigest(site, object, epoch, cq)` | site TPM | renewal request sent at `(epoch, cq)` |
| `renewalDigest(registry, site, object, epoch, cq, issued)` | `G`'s authorities | renewal certificate |
| `stopDigest(registry, site, object, epoch, cq)` | `G`'s authorities | stop certificate, cancelling renewals up to `(epoch, cq)` |
| `ackDigest(registry, site, object, epoch, reading)` | site validators | "the stop was executed and no hold is running at this reading" |
| `shareDigest(registry, site, resource, amount, version)` | `G`'s authorities | share certificate |
| `shareAckDigest(registry, site, resource, version)` | site validators | "we applied this share version and our total is within it" |
| `leaseDigest(registry, site, object, allowanceMs, openHold)` | `G`'s authorities | lease certificate (allowance and object class) |
| `checkpointDigest(registry, headerHash)` | site validators | checkpoint seal |

## RightsRegistry

Constructor: `RightsRegistry(rhoPpm, gSlack, anchorLagMs)`. These are the drift bound in parts per million, `ε_G`
in seconds, and the anchoring lag `λ` in milliseconds. The deployer becomes `admin`.

### Administration (admin only)

| Function | What it does |
|---|---|
| `registerSite(site, f, clockKey, validators, startEpoch, startReading)` | Registers a site with `n ≥ 3f+1` validators and its TPM key. Each validator gets a bond, and coverage starts at the given clock time |
| `setCap(resource, amount)` | Sets the global cap of a resource |
| `setShare(resource, site, amount)` | Issues the next share version. Raising takes effect at once. Lowering keeps the old amount reserved until `confirmShare` |
| `createLease(object, exclusive, allowanceMs)` | Creates an exclusive object or a credential with allowance `A` |
| `setOpenHold(object)` | Marks an exclusive object whose holds last until released (before its first holder is set) |
| `permit(object, site)` | Sets the first holder of an object, or adds a site where a credential is valid |
| `stop(object, nextSite)` | Stops renewals. Names the next holder (exclusive object) or revokes (credential, `nextSite = 0`) |

### Leases

| Function | Who calls | What it checks |
|---|---|---|
| `renew(site, object, epoch, cq, clockSig)` | the site's relayer | site not revoked; site may hold the object; not stopped; valid TPM signature; `(epoch, cq)` newer than the last renewal; anchored coverage in the same epoch reaches `cq − λ` |
| `waitSeconds(object)` | anyone (view) | `ceil(A / (1 − ρ)) + 2·gSlack` |
| `releaseAt(object)` | anyone (view) | last renewal time plus `waitSeconds` |
| `reassign(object)` | anyone | slow path: object stopped, not an open-hold object, and `now ≥ releaseAt` |
| `reassignAcked(object, epoch, reading, clockSig, acks)` | the site's relayer | fast path: valid TPM signature on the reading; reading not older than the last renewal; quorum of unslashed validators |
| `confirmShare(resource, site, acks)` | the site's relayer | quorum acknowledges the pending lower share version, which frees the capacity |

### Checkpoints and proofs

| Function | What it does |
|---|---|
| `anchor(header, seals)` | Records a sealed checkpoint that builds on the last anchored one. Needs a quorum of unslashed validators and a valid TPM signature on the close, and the close must not be older than the current coverage |
| `proveOverspend`, `proveUnderstate`, `proveUnderstateParent`, `proveStateMismatch`, `proveOveruse`, `proveUseAfterAck`, `proveFork` | Fraud proofs, see [CONCEPTS.md](CONCEPTS.md#8-fraud-proofs-and-sanctions). Each verifies a quorum of seals (counting all registered validators), the Merkle paths and the violation. It then slashes, and returns the number of newly slashed validators |

Slashing marks each validator as slashed, zeroes its bond, and emits `Slashed`. When more than `f` validators of a
site are slashed, the site is revoked (`SiteRevoked`) and can no longer renew.

### Events

`SiteRegistered`, `ShareSet`, `ShareConfirmed`, `LeaseCreated`, `Permitted`, `Renewed`, `Stopped`,
`Acknowledged`, `Reassigned`, `Anchored`, `Slashed`, `SiteRevoked`.

## SiteRights

Constructor: `SiteRights(site, registry, clockKey, authorities, threshold)`. Certificates need `threshold` distinct
signatures from `G`'s authorities.

| Function | What it does |
|---|---|
| `applyShare(resource, amount, version, sigs)` | Applies a newer share version. A lower share is accepted only if the running total already fits |
| `applyLease(object, allowance, isOpen, sigs)` | Learns an object's allowance and class |
| `applyRenewal(object, epoch, cq, issued, sigs)` | Adopts a renewal if it is newer than the current one and not cancelled by a stop |
| `applyStop(object, epoch, cq, sigs)` | Cancels renewals up to `(epoch, cq)`. No new grants follow; running holds continue |
| `consume(resource, amount)` | Accepts if the new running total is within the share |
| `use(object, epoch, reading, until, clockSig)` | Grants a hold. Needs a valid, non-decreasing TPM reading in the renewal's epoch, inside `[c_q, c_q + A)`. A bounded hold needs `until < c_q + A`; an open hold needs `until = OPEN` |
| `release(object, epoch, reading, clockSig)` | Ends an open hold (allowed after a stop) |
| `record(payloadHash)` | Appends a commutative record |
| `remaining(object, epoch, reading)` | View: allowance left at that reading |
| `quiescent(object, reading)` | View: no open hold and no bounded hold running at that reading. Validators acknowledge a stop only when this holds |

The contract records grants. **Execution is the gateway's job**: it executes a grant once the grant's checkpoint
is final, and only with a fresh reading inside the hold and the allowance (see
[CONCEPTS.md](CONCEPTS.md#5-holds-finality-and-the-gateway)). `experiments/offgrant/e2e.py` (function `gateway`)
implements this.

## Errors

| Error | Raised when |
|---|---|
| `NotAdmin`, `BadSite`, `BadLease`, `NotPermitted` | wrong caller, unknown site or lease, or site not entitled to the object |
| `LeaseStopped`, `SiteRevokedErr` | renewal after a stop, or for a revoked site |
| `BadClockSig` | a TPM attestation does not verify (requests, acknowledgements, checkpoint closes) |
| `StaleRequest`, `StaleAck` | a renewal or acknowledgement not newer than the last renewal |
| `AnchorDebt(covered, needed)` | the site's anchored coverage is too old to renew |
| `TooEarly(releaseAt)`, `HoldMayBeOpen` | slow path before `W`, or for an open-hold object |
| `OverCap`, `NoPendingShare` | shares would exceed the cap; no lower share awaits acknowledgement |
| `NoQuorum`, `BadProof`, `NotAViolation` | too few valid seals; malformed or unlinked proof; the operation is within rights |
| `BadCertificate`, `StaleShare`, `OverShare`, `NoRenewal`, `AllowanceExpired`, `BadHold`, `NotHeld`, `StaleReading` | `SiteRights` rejections |

## Tests

`contracts/test/Offgrant.t.sol` has 41 tests (`forge test`), grouped as follows.

| Group | Tests |
|---|---|
| Lease bound and reassignment | `test_waitFormula`, `testFuzz_waitCoversSlowClock`, `test_reassignOnlyAfterRelease`, `test_renewRejectsForgedClock` |
| Site enforcement offline | `test_siteEnforcesShare`, `test_siteEnforcesAllowance`, `test_siteRejectsUncertifiedRights`, `test_siteRejectsForgedOrStaleClock`, `test_clockResetExpiresAllowance`, `test_stopEndsAllowanceAtOnce`, `test_stopCannotCancelLaterRenewal` |
| Holds | `test_boundedHoldMustEndInsideAllowance`, `test_holdPastAllowanceIsSlashable`, `test_openHoldNeverMovesByExpiry`, `test_releaseAfterAckIsSlashable` |
| No framing of honest validators | `test_honestCheckpointIsNotSlashable`, `test_honestUseAfterReturnIsNotFramed`, `test_belowQuorumIsRejected`, `test_understateParentMustBeTheRealParent` |
| Attribution | `test_overspendSlashesSealers`, `test_firstConsumptionBelowItsAmountSlashes`, `test_understateWithinCheckpointSlashes`, `test_understateAgainstParentSlashesChildSealers`, `test_stateRootBelowOwnConsumptionSlashes`, `test_overusePastAllowanceSlashes`, `test_useWithoutRenewalSlashes`, `test_useInNewEpochIsSlashable`, `test_forkSlashesOnlyDoubleSealers`, `test_useAfterAckSlashesOnlyAckersThatSealedIt`, `test_slashingIsIdempotent` |
| Sanctions | `test_slashedValidatorsLoseQuorumAndSiteIsRevoked` |
| Anchoring and coverage | `test_renewNeedsAnchoredCoverage`, `test_anchorNeedsAttestedClose`, `test_anchorSkipsToNewestCheckpointAfterOutage` |
| Replay and fast path | `test_replayedOlderRequestIsRejected`, `test_ackRaisesRenewalFloor`, `test_staleAckIsRejected`, `test_fastPathReassignsAtOnce` |
| Shares | `test_sharesNeverExceedCap`, `test_shareReductionIsVersionedAndAcknowledged` |
| Quorums | `test_quorumForLargerSites` |
