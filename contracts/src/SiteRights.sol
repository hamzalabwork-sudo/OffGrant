// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {OffLib} from "./OffLib.sol";

/// Site-ledger side of rights-scoped offline operation. Runs on the site's own BFT ledger, which stays
/// live while the site's uplink is cut. It accepts rights only with a certificate from the global ledger's
/// authorities and enforces them locally:
///   - bounded resources: the running total stays within the site's share;
///   - leases and credentials: a use is valid while the trusted clock is below cq + A, where cq is the
///     clock reading at the SEND of the renewal request that G answered (send-time counting, Theorem 1);
///   - commutative records are always accepted.
/// Every accepted operation is emitted as an Op event; validators batch them into sealed checkpoints.
contract SiteRights {
    uint64 public immutable site;
    address public immutable registry; // RightsRegistry on the global ledger (signature domain)
    address public immutable clockKey;
    uint8 public immutable gThreshold;
    mapping(address => bool) public isAuthority; // global-ledger authorities

    mapping(bytes32 => uint64) public share;
    mapping(bytes32 => uint64) public total; // running consumption per resource
    mapping(bytes32 => uint64) public allowanceMs;
    mapping(bytes32 => uint64) public base; // cq of the newest applied renewal
    uint64 public lastReading;
    uint64 public opCount;

    event Op(uint64 indexed seq, uint8 kind, bytes32 key, uint64 a, uint64 b, bytes clockSig);
    event RightApplied(bytes32 indexed key, uint8 what, uint64 value);

    error BadCertificate();
    error BadClockSig();
    error StaleReading();
    error OverShare(uint64 total, uint64 share);
    error NoRenewal();
    error AllowanceExpired(uint64 reading, uint64 until);

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

    // ---------------------------------------------------------------- rights (relayed while connected)
    function applyShare(bytes32 resource, uint64 amount, bytes[] calldata sigs) external {
        _certified(OffLib.shareDigest(registry, site, resource, amount), sigs);
        share[resource] = amount;
        emit RightApplied(resource, 1, amount);
    }

    function applyLease(bytes32 object, uint64 allowance, bytes[] calldata sigs) external {
        _certified(OffLib.leaseDigest(registry, site, object, allowance), sigs);
        allowanceMs[object] = allowance;
        emit RightApplied(object, 2, allowance);
    }

    function applyRenewal(bytes32 object, uint64 cq, uint64 issued, bytes[] calldata sigs) external {
        _certified(OffLib.renewalDigest(registry, site, object, cq, issued), sigs);
        if (cq > base[object]) base[object] = cq;
        emit RightApplied(object, 3, cq);
    }

    // ---------------------------------------------------------------- operations (also while cut off)
    function consume(bytes32 resource, uint64 amount) external {
        uint64 t = total[resource] + amount;
        if (t > share[resource]) revert OverShare(t, share[resource]);
        total[resource] = t;
        emit Op(opCount++, OffLib.CONSUME, resource, amount, t, "");
    }

    /// Exercise an exclusive object or accept a credential at trusted-clock time `reading`.
    function use(bytes32 object, uint64 reading, bytes calldata clockSig) external {
        if (OffLib.recover(OffLib.clockDigest(site, reading), clockSig) != clockKey) revert BadClockSig();
        if (reading < lastReading) revert StaleReading();
        uint64 b = base[object];
        if (b == 0 || reading < b) revert NoRenewal();
        if (reading - b >= allowanceMs[object]) revert AllowanceExpired(reading, b + allowanceMs[object]);
        lastReading = reading;
        emit Op(opCount++, OffLib.USE, object, b, reading, clockSig);
    }

    function record(bytes32 payloadHash) external {
        emit Op(opCount++, OffLib.LOG, payloadHash, 0, 0, "");
    }

    /// Remaining allowance (ms) of an object at clock reading `reading`; 0 when expired.
    function remaining(bytes32 object, uint64 reading) external view returns (uint64) {
        uint64 b = base[object];
        uint64 a = allowanceMs[object];
        if (b == 0 || reading < b || reading - b >= a) return 0;
        return a - (reading - b);
    }
}
