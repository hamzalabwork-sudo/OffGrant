// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {OffLib} from "./OffLib.sol";

/// Site-ledger side of rights-scoped offline operation (version 5). Runs on the site's own BFT ledger, which
/// stays live while the site's uplink is cut. It accepts rights only with a certificate from the global
/// ledger's authorities and enforces them locally:
///   - resources: the running total stays within the newest applied share version;
///   - leases and credentials: a grant is valid while the trusted clock, in the epoch of the renewal, is below
///     cq + A, where cq is the reading at the SEND of the renewal request that G answered (Proposition 1). A
///     bounded hold must END before cq + A; an open hold (a lockout) lasts until it is released, and its
///     object is moved only after an acknowledgement;
///   - commutative records are always accepted.
/// Every attested operation carries the site clock's attestation of its full content (OffLib.opTag), and the
/// readings of attested operations strictly increase, so no attestation can be replayed or reordered.
/// The gateway, which holds the clock, attests an operation only when it requests it, and executes a grant
/// only once the grant is in a sealed checkpoint and a fresh reading is still before its end.
/// Every accepted operation is emitted as an OpRecorded event; validators batch them into sealed checkpoints.
contract SiteRights {
    uint64 public immutable site;
    address public immutable registry; // RightsRegistry on the global ledger
    bytes32 public immutable dom; // signature domain (chain id of G, registry)
    address public immutable clockKey;
    uint8 public immutable gThreshold;
    mapping(address => bool) public isAuthority; // global-ledger authorities

    struct Base {
        uint64 epoch;
        uint64 cq;
    }

    mapping(bytes32 => uint64) public share;
    mapping(bytes32 => uint64) public shareVersion;
    mapping(bytes32 => uint64) public total; // running consumption per resource
    mapping(bytes32 => uint64) public allowanceMs;
    mapping(bytes32 => bool) public openHold; // object class: holds last until released
    mapping(bytes32 => Base) public base; // newest applied renewal
    mapping(bytes32 => Base) public stoppedUpTo; // renewals up to this one are cancelled
    mapping(bytes32 => uint64) public heldEpoch; // epoch of the latest bounded hold
    mapping(bytes32 => uint64) public heldUntil; // its end (site clock); bounded holds end at power loss
    mapping(bytes32 => uint64) public openCount; // open holds not yet released
    mapping(bytes32 => mapping(uint64 => bool)) public openHolds; // object => hold id (grant reading) => held
    uint64 public lastEpoch;
    uint64 public lastReading;
    uint64 public opCount;

    event OpRecorded(uint64 indexed seq, OffLib.Op op);
    event RightApplied(bytes32 indexed key, uint8 what, uint64 value);

    error BadCertificate();
    error BadClockSig();
    error StaleReading();
    error StaleShare();
    error OverShare(uint64 total, uint64 share);
    error NoRenewal();
    error AllowanceExpired(uint64 reading, uint64 until);
    error BadHold();
    error NotHeld();
    error NotStopped();
    error StillHeld();

    constructor(
        uint64 site_,
        address registry_,
        uint256 gChainId,
        address clockKey_,
        address[] memory authorities,
        uint8 threshold
    ) {
        require(site_ != 0 && clockKey_ != address(0), "site");
        require(threshold > 0 && threshold <= authorities.length, "threshold");
        site = site_;
        registry = registry_;
        dom = OffLib.domain(registry_, gChainId);
        clockKey = clockKey_;
        gThreshold = threshold;
        for (uint256 i = 0; i < authorities.length; i++) {
            require(authorities[i] != address(0), "authority");
            isAuthority[authorities[i]] = true;
        }
    }

    function _certified(bytes32 digest, bytes[] calldata sigs) internal view {
        address[] memory seen = new address[](sigs.length);
        uint256 n;
        for (uint256 i = 0; i < sigs.length && n < gThreshold; i++) {
            address a = OffLib.recover(digest, sigs[i]);
            if (a == address(0) || !isAuthority[a]) continue;
            bool dup;
            for (uint256 j = 0; j < n; j++) {
                if (seen[j] == a) {
                    dup = true;
                    break;
                }
            }
            if (!dup) seen[n++] = a;
        }
        if (n < gThreshold) revert BadCertificate();
    }

    function _after(Base memory x, Base memory y) internal pure returns (bool) {
        return OffLib.after_(x.epoch, x.cq, y.epoch, y.cq);
    }

    /// Checks the attestation of an operation and that its reading is strictly newer than every earlier one.
    function _clock(OffLib.Op memory op) internal {
        if (OffLib.recover(OffLib.clockDigest(dom, site, op.epoch, op.reading, OffLib.opTag(op)), op.clockSig) != clockKey) {
            revert BadClockSig();
        }
        if (!OffLib.after_(op.epoch, op.reading, lastEpoch, lastReading)) revert StaleReading();
        lastEpoch = op.epoch;
        lastReading = op.reading;
    }

    function _emit(OffLib.Op memory op) internal {
        emit OpRecorded(opCount++, op);
    }

    // ---------------------------------------------------------------- rights (relayed while connected)
    /// Applies a share certificate; only a newer version replaces the current one, and a lower share only if the
    /// running total is already within it. Recorded as a SHARE operation, so checkpoints commit the version.
    function applyShare(bytes32 resource, uint64 amount, uint64 version, bytes[] calldata sigs) external {
        _certified(OffLib.shareDigest(dom, site, resource, amount, version), sigs);
        if (version <= shareVersion[resource]) revert StaleShare();
        if (total[resource] > amount) revert OverShare(total[resource], amount);
        share[resource] = amount;
        shareVersion[resource] = version;
        _emit(OffLib.Op(OffLib.SHARE, resource, 0, 0, 0, 0, amount, total[resource], version, ""));
    }

    /// A lease's class (bounded or open holds) is fixed when G creates it, so certificates cannot disagree.
    function applyLease(bytes32 object, uint64 allowance, bool isOpen, bytes[] calldata sigs) external {
        _certified(OffLib.leaseDigest(dom, site, object, allowance, isOpen), sigs);
        allowanceMs[object] = allowance;
        openHold[object] = isOpen;
        emit RightApplied(object, 2, allowance);
    }

    /// Applies one renewal certificate for a batch of objects (one request, one attestation, one transaction).
    function applyRenewal(bytes32[] calldata objects, uint64 epoch, uint64 cq, uint64 issued, bytes[] calldata sigs)
        external
    {
        _certified(OffLib.renewalDigest(dom, site, OffLib.objectsHash(objects), epoch, cq, issued), sigs);
        Base memory b = Base(epoch, cq);
        for (uint256 i = 0; i < objects.length; i++) {
            bytes32 o = objects[i];
            if (_after(b, base[o]) && _after(b, stoppedUpTo[o])) {
                base[o] = b;
                emit RightApplied(o, 3, cq);
            }
        }
    }

    /// Reassignment or revocation reaching a connected site: no new grants from then on. Bounded holds run to
    /// their end; open holds stay until released.
    function applyStop(bytes32 object, uint64 epoch, uint64 cq, bytes[] calldata sigs) external {
        _certified(OffLib.stopDigest(dom, site, object, epoch, cq), sigs);
        Base memory b = Base(epoch, cq);
        if (_after(b, stoppedUpTo[object]) || (stoppedUpTo[object].epoch == 0 && stoppedUpTo[object].cq == 0)) {
            stoppedUpTo[object] = b;
        }
        if (!_after(base[object], b)) delete base[object];
        emit RightApplied(object, 4, cq);
    }

    // ---------------------------------------------------------------- operations (also while cut off)
    /// Consumes `amount` under share `version`, which must be the one applied (the gateway attests it).
    function consume(bytes32 resource, uint64 amount, uint64 version, uint64 epoch, uint64 reading, bytes calldata clockSig)
        external
    {
        if (version != shareVersion[resource]) revert StaleShare();
        OffLib.Op memory op = OffLib.Op(OffLib.CONSUME, resource, epoch, reading, 0, 0, amount, 0, version, clockSig);
        _clock(op);
        uint64 t = total[resource] + amount;
        if (t > share[resource]) revert OverShare(t, share[resource]);
        total[resource] = t;
        op.total = t;
        _emit(op);
    }

    /// Grants an exclusive object or accepts a credential at trusted-clock time (epoch, reading) under the renewal
    /// (epoch, cq), which must be the newest applied one, as a hold that ends at `until` (a bounded hold,
    /// until > reading) or lasts until released (until = OffLib.OPEN).
    function use(bytes32 object, uint64 cq, uint64 epoch, uint64 reading, uint64 until, bytes calldata clockSig) external {
        Base memory b = base[object];
        if (b.cq == 0 || b.cq != cq || b.epoch != epoch || reading < cq) revert NoRenewal();
        OffLib.Op memory op = OffLib.Op(OffLib.USE, object, epoch, reading, cq, until, 0, 0, 0, clockSig);
        _clock(op);
        uint64 a = allowanceMs[object];
        if (reading - b.cq >= a) revert AllowanceExpired(reading, b.cq + a);
        if (openHold[object]) {
            if (until != OffLib.OPEN) revert BadHold();
            openHolds[object][reading] = true;
            openCount[object]++;
        } else {
            if (until <= reading) revert BadHold();
            if (until - b.cq >= a) revert AllowanceExpired(until, b.cq + a);
            if (epoch > heldEpoch[object]) {
                heldEpoch[object] = epoch;
                heldUntil[object] = until;
            } else if (until > heldUntil[object]) {
                heldUntil[object] = until;
            }
        }
        _emit(op);
    }

    /// Ends one open hold (named by its id, the reading of the grant that started it). Allowed after a stop.
    function release(bytes32 object, uint64 holdId, uint64 epoch, uint64 reading, bytes calldata clockSig) external {
        if (!openHolds[object][holdId]) revert NotHeld();
        OffLib.Op memory op = OffLib.Op(OffLib.RELEASE, object, epoch, reading, holdId, 0, 0, 0, 0, clockSig);
        _clock(op);
        delete openHolds[object][holdId];
        openCount[object]--;
        _emit(op);
    }

    /// Fast path: the site acknowledges a stop at trusted-clock time (epoch, reading). Accepted only after the
    /// stop, with no newer renewal, no open hold and no bounded hold running in this epoch. As the reading is
    /// newer than every earlier operation, and no grant of the object is possible afterwards under the stopped
    /// renewals, no correct ledger ever records a grant, hold or release of the object past it under them.
    function acknowledge(bytes32 object, uint64 epoch, uint64 reading, bytes calldata clockSig) external {
        Base memory s = stoppedUpTo[object];
        if (s.epoch == 0 && s.cq == 0) revert NotStopped();
        if (base[object].cq != 0) revert NotStopped();
        if (openCount[object] != 0) revert StillHeld();
        if (heldEpoch[object] == epoch && heldUntil[object] > reading) revert StillHeld();
        OffLib.Op memory op = OffLib.Op(OffLib.ACK, object, epoch, reading, s.cq, 0, 0, 0, 0, clockSig);
        _clock(op);
        stoppedUpTo[object] = Base(epoch, reading); // later grants need a renewal newer than the acknowledgement
        _emit(op);
    }

    function record(bytes32 payloadHash) external {
        _emit(OffLib.Op(OffLib.LOG, payloadHash, 0, 0, 0, 0, 0, 0, 0, ""));
    }

    /// Remaining allowance (ms) of an object at clock time (epoch, reading); 0 when expired.
    function remaining(bytes32 object, uint64 epoch, uint64 reading) external view returns (uint64) {
        Base memory b = base[object];
        uint64 a = allowanceMs[object];
        if (b.cq == 0 || b.epoch != epoch || reading < b.cq || reading - b.cq >= a) return 0;
        return a - (reading - b.cq);
    }
}
