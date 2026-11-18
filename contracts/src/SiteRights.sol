// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {OffLib} from "./OffLib.sol";

/// Site-ledger side of rights-scoped offline operation. Runs on the site's own BFT ledger, which stays
/// live while the site's uplink is cut. It accepts rights only with a certificate from the global ledger's
/// authorities and enforces them locally:
///   - bounded resources: the running total stays within the newest certified share version;
///   - leases and credentials: a grant is valid while the trusted clock, in the same clock epoch, is below
///     cq + A, where cq is the reading at the SEND of the renewal request that G answered (Proposition 1).
///     A bounded hold must also END before cq + A; an open hold (e.g. a lockout) lasts until it is released,
///     and an object with open holds is never moved by expiry, only after its release is acknowledged.
///     A clock reset (power loss) starts a new epoch and expires every allowance; a certified stop
///     (reassignment or revocation) ends it at once when it arrives;
///   - commutative records are always accepted.
/// A grant takes effect only when the site gateway executes it: once the grant is final, and only if a fresh
/// trusted-clock reading at execution is still before the end of the hold (checked by the gateway).
/// Every accepted operation is emitted as an Op event; validators batch them into sealed checkpoints.
contract SiteRights {
    uint64 public immutable site;
    address public immutable registry; // RightsRegistry on the global ledger (signature domain)
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
    mapping(bytes32 => uint64) public heldUntil; // latest end of a bounded hold (site clock)
    mapping(bytes32 => uint64) public openCount; // open holds not yet released
    mapping(bytes32 => uint64) public holdBase; // base cq of the newest open hold
    uint64 public lastEpoch;
    uint64 public lastReading;
    uint64 public opCount;

    event Op(uint64 indexed seq, uint8 kind, bytes32 key, uint64 a, uint64 b, uint64 c, uint64 e, bytes clockSig);
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

    constructor(uint64 site_, address registry_, address clockKey_, address[] memory authorities, uint8 threshold) {
        require(threshold > 0 && threshold <= authorities.length, "threshold");
        site = site_;
        registry = registry_;
        clockKey = clockKey_;
        gThreshold = threshold;
        for (uint256 i = 0; i < authorities.length; i++) {
            isAuthority[authorities[i]] = true;
        }
    }

    function _certified(bytes32 digest, bytes[] calldata sigs) internal view {
        address[] memory seen = new address[](sigs.length);
        uint256 n;
        for (uint256 i = 0; i < sigs.length && n < gThreshold; i++) {
            address a = OffLib.recover(digest, sigs[i]);
            if (!isAuthority[a]) continue;
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
        return x.epoch > y.epoch || (x.epoch == y.epoch && x.cq > y.cq);
    }

    function _clock(uint64 epoch, uint64 reading, bytes32 tag, bytes calldata sig) internal {
        if (OffLib.recover(OffLib.clockDigest(site, epoch, reading, tag), sig) != clockKey) revert BadClockSig();
        if (epoch < lastEpoch || (epoch == lastEpoch && reading < lastReading)) revert StaleReading();
        lastEpoch = epoch;
        lastReading = reading;
    }

    // ---------------------------------------------------------------- rights (relayed while connected)
    /// Applies a share certificate; only a newer version replaces the current one. A lower share can be
    /// applied only if the running total is already within it.
    function applyShare(bytes32 resource, uint64 amount, uint64 version, bytes[] calldata sigs) external {
        _certified(OffLib.shareDigest(registry, site, resource, amount, version), sigs);
        if (version <= shareVersion[resource]) revert StaleShare();
        if (total[resource] > amount) revert OverShare(total[resource], amount);
        share[resource] = amount;
        shareVersion[resource] = version;
        emit RightApplied(resource, 1, amount);
    }

    function applyLease(bytes32 object, uint64 allowance, bool isOpen, bytes[] calldata sigs) external {
        _certified(OffLib.leaseDigest(registry, site, object, allowance, isOpen), sigs);
        allowanceMs[object] = allowance;
        openHold[object] = isOpen;
        emit RightApplied(object, 2, allowance);
    }

    function applyRenewal(bytes32 object, uint64 epoch, uint64 cq, uint64 issued, bytes[] calldata sigs) external {
        _certified(OffLib.renewalDigest(registry, site, object, epoch, cq, issued), sigs);
        Base memory b = Base(epoch, cq);
        if (_after(b, base[object]) && _after(b, stoppedUpTo[object])) base[object] = b;
        emit RightApplied(object, 3, cq);
    }

    /// Reassignment or revocation reaching a connected site: no new grants from then on. Bounded holds run to
    /// their end; open holds stay until released.
    function applyStop(bytes32 object, uint64 epoch, uint64 cq, bytes[] calldata sigs) external {
        _certified(OffLib.stopDigest(registry, site, object, epoch, cq), sigs);
        Base memory b = Base(epoch, cq);
        if (_after(b, stoppedUpTo[object])) stoppedUpTo[object] = b;
        if (!_after(base[object], b)) delete base[object];
        emit RightApplied(object, 4, cq);
    }

    // ---------------------------------------------------------------- operations (also while cut off)
    function consume(bytes32 resource, uint64 amount) external {
        uint64 t = total[resource] + amount;
        if (t > share[resource]) revert OverShare(t, share[resource]);
        total[resource] = t;
        emit Op(opCount++, OffLib.CONSUME, resource, amount, t, shareVersion[resource], 0, "");
    }

    /// Grants an exclusive object or accepts a credential at trusted-clock time (epoch, reading), as a hold
    /// that ends at `until` (until = reading for an instantaneous use; OffLib.OPEN for an open hold).
    function use(bytes32 object, uint64 epoch, uint64 reading, uint64 until, bytes calldata clockSig) external {
        _clock(epoch, reading, object, clockSig);
        Base memory b = base[object];
        if (b.cq == 0 || b.epoch != epoch || reading < b.cq) revert NoRenewal();
        uint64 a = allowanceMs[object];
        if (reading - b.cq >= a) revert AllowanceExpired(reading, b.cq + a);
        if (openHold[object]) {
            if (until != OffLib.OPEN) revert BadHold();
            openCount[object]++;
            holdBase[object] = b.cq;
        } else {
            if (until < reading) revert BadHold();
            if (until - b.cq >= a) revert AllowanceExpired(until, b.cq + a);
            if (until > heldUntil[object]) heldUntil[object] = until;
        }
        emit Op(opCount++, OffLib.USE, object, b.cq, reading, until, epoch, clockSig);
    }

    /// Ends an open hold (e.g. the lock is removed). Allowed after a stop: releasing is always safe.
    function release(bytes32 object, uint64 epoch, uint64 reading, bytes calldata clockSig) external {
        if (openCount[object] == 0) revert NotHeld();
        _clock(epoch, reading, OffLib.releaseTag(object), clockSig);
        openCount[object]--;
        emit Op(opCount++, OffLib.RELEASE, object, holdBase[object], reading, 0, epoch, clockSig);
    }

    function record(bytes32 payloadHash) external {
        emit Op(opCount++, OffLib.LOG, payloadHash, 0, 0, 0, 0, "");
    }

    /// Remaining allowance (ms) of an object at clock time (epoch, reading); 0 when expired.
    function remaining(bytes32 object, uint64 epoch, uint64 reading) external view returns (uint64) {
        Base memory b = base[object];
        uint64 a = allowanceMs[object];
        if (b.cq == 0 || b.epoch != epoch || reading < b.cq || reading - b.cq >= a) return 0;
        return a - (reading - b.cq);
    }

    /// Whether a correct validator may acknowledge a stop of `object` at `reading`: no hold is still running.
    function quiescent(bytes32 object, uint64 reading) external view returns (bool) {
        return openCount[object] == 0 && heldUntil[object] <= reading;
    }
}
