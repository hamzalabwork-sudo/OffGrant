// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {OffLib} from "./OffLib.sol";

/// Global-ledger side of rights-scoped offline operation.
///
/// Issues rights before a partition (resource shares, leases on exclusive objects, credential leases),
/// records every lease renewal, delays reassignment and revocation by the offline-tolerance bound of
/// Theorem 1, and adjudicates fraud proofs against site checkpoints (Theorem 2): a checkpoint sealed by
/// a site quorum that contains an out-of-rights operation slashes its sealers; two sealed checkpoints at
/// one height slash the validators that sealed both.
contract RightsRegistry {
    using OffLib for OffLib.Header;

    // ---------------------------------------------------------------- configuration
    address public immutable admin;
    uint32 public immutable rhoPpm; // bound on site-clock drift, parts per million
    uint32 public immutable gSlack; // seconds: G block-timestamp uncertainty
    uint256 public constant BOND = 1 ether; // per site validator (accounting unit)

    struct Site {
        bool exists;
        uint8 f;
        address clockKey; // trusted clock (e.g. TPM 2.0) of the site
        uint64 anchoredHeight;
        bytes32 anchoredHash;
    }

    mapping(uint64 => Site) public sites;
    mapping(uint64 => mapping(address => bool)) public isValidator;
    mapping(uint64 => mapping(address => uint256)) public bond;

    // Bounded resources.
    mapping(bytes32 => uint64) public cap;
    mapping(bytes32 => uint64) public allocated;
    mapping(bytes32 => mapping(uint64 => uint64)) public share;

    // Leases: exclusive objects (one permitted site) and credentials (any number of sites).
    struct Lease {
        bool exists;
        bool exclusive;
        bool stopped; // renewals refused: reassignment pending or credential revoked
        uint64 allowanceMs; // A = D(1 + rho), in site-clock milliseconds
        uint64 lastIssue; // G time (s) of the last renewal of this object, any site
        uint64 holder; // exclusive objects: the one site that may renew
        uint64 nextSite; // exclusive objects: pending holder after a stop
    }

    mapping(bytes32 => Lease) public leases;
    mapping(bytes32 => mapping(uint64 => bool)) public permitted;
    mapping(bytes32 => uint64) public renewalIssued; // OffLib.renewalKey(site, object, epoch, cq) => G issue time (s)

    struct Base {
        uint64 epoch;
        uint64 cq;
    }

    mapping(bytes32 => mapping(uint64 => Base)) public lastRenewal; // last renewal issued per (object, site)

    // Fast path: the stopped holder's quorum acknowledged at trusted-clock time (epoch, reading).
    struct Ack {
        uint64 site;
        uint64 epoch;
        uint64 reading;
    }

    mapping(bytes32 => Ack) public lastAck;
    mapping(bytes32 => address[]) internal ackSigners;

    // ---------------------------------------------------------------- events
    event SiteRegistered(uint64 indexed site, uint8 f, address clockKey, address[] validators);
    event ShareSet(bytes32 indexed resource, uint64 indexed site, uint64 amount);
    event LeaseCreated(bytes32 indexed object, bool exclusive, uint64 allowanceMs);
    event Permitted(bytes32 indexed object, uint64 indexed site);
    event Renewed(uint64 indexed site, bytes32 indexed object, uint64 epoch, uint64 cq, uint64 issued);
    event Stopped(bytes32 indexed object, uint64 nextSite, uint64 releaseAt);
    event Acknowledged(bytes32 indexed object, uint64 indexed site, uint64 epoch, uint64 reading);
    event Reassigned(bytes32 indexed object, uint64 indexed site);
    event Anchored(uint64 indexed site, uint64 height, bytes32 headerHash);
    event Slashed(uint64 indexed site, address indexed validator, uint8 reason);

    uint8 internal constant R_OVERSPEND = 1;
    uint8 internal constant R_UNDERSTATE = 2;
    uint8 internal constant R_OVERUSE = 3;
    uint8 internal constant R_FORK = 4;
    uint8 internal constant R_USE_AFTER_ACK = 5;

    error NotAdmin();
    error BadSite();
    error BadLease();
    error NotPermitted();
    error LeaseStopped();
    error BadClockSig();
    error TooEarly(uint64 releaseAt);
    error OverCap();
    error NoQuorum();
    error BadProof();
    error NotAViolation();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    constructor(uint32 rhoPpm_, uint32 gSlack_) {
        require(rhoPpm_ < 1_000_000, "rho");
        admin = msg.sender;
        rhoPpm = rhoPpm_;
        gSlack = gSlack_;
    }

    // ---------------------------------------------------------------- administration
    function registerSite(uint64 site, uint8 f, address clockKey, address[] calldata validators) external onlyAdmin {
        if (sites[site].exists || validators.length < 3 * uint256(f) + 1 || clockKey == address(0)) revert BadSite();
        sites[site] = Site({exists: true, f: f, clockKey: clockKey, anchoredHeight: 0, anchoredHash: bytes32(0)});
        for (uint256 i = 0; i < validators.length; i++) {
            if (isValidator[site][validators[i]]) revert BadSite();
            isValidator[site][validators[i]] = true;
            bond[site][validators[i]] = BOND;
        }
        emit SiteRegistered(site, f, clockKey, validators);
    }

    function setCap(bytes32 resource, uint64 amount) external onlyAdmin {
        if (amount < allocated[resource]) revert OverCap();
        cap[resource] = amount;
    }

    /// Shares are issued while connected; their sum never exceeds the cap (invariant I_B).
    function setShare(bytes32 resource, uint64 site, uint64 amount) external onlyAdmin {
        if (!sites[site].exists) revert BadSite();
        uint64 next = allocated[resource] - share[resource][site] + amount;
        if (next > cap[resource]) revert OverCap();
        allocated[resource] = next;
        share[resource][site] = amount;
        emit ShareSet(resource, site, amount);
    }

    function createLease(bytes32 object, bool exclusive, uint64 allowanceMs) external onlyAdmin {
        if (leases[object].exists || allowanceMs == 0) revert BadLease();
        leases[object] = Lease(true, exclusive, false, allowanceMs, 0, 0, 0);
        emit LeaseCreated(object, exclusive, allowanceMs);
    }

    /// Exclusive object: sets its first holder (later moves only via stop + reassign).
    /// Credential: adds a site at which it may be accepted.
    function permit(bytes32 object, uint64 site) external onlyAdmin {
        Lease storage l = leases[object];
        if (!l.exists || !sites[site].exists) revert BadLease();
        if (l.exclusive) {
            if (l.holder != 0) revert BadLease();
            l.holder = site;
        } else {
            permitted[object][site] = true;
        }
        emit Permitted(object, site);
    }

    function mayRenew(bytes32 object, uint64 site) public view returns (bool) {
        Lease storage l = leases[object];
        return l.exclusive ? l.holder == site : permitted[object][site];
    }

    // ---------------------------------------------------------------- leases (Theorem 1)
    /// Wait after the last renewal before another site may hold the object, in G seconds:
    /// ceil(A / (1 - rho)) plus the G timestamp slack.
    function waitSeconds(bytes32 object) public view returns (uint64) {
        uint256 a = leases[object].allowanceMs;
        uint256 num = a * 1_000_000;
        uint256 den = uint256(1_000_000 - rhoPpm) * 1000;
        return uint64((num + den - 1) / den) + gSlack;
    }

    /// G time after which no site can still exercise the object (or accept the credential).
    function releaseAt(bytes32 object) public view returns (uint64) {
        Lease storage l = leases[object];
        return l.lastIssue == 0 ? 0 : l.lastIssue + waitSeconds(object);
    }

    /// A site's renewal request, relayed while its uplink is up. `cq` is the site's trusted-clock reading
    /// taken when the request was SENT, in clock epoch `epoch`; the site may exercise while its clock, in the
    /// same epoch, is below cq + A. Any clock reset (power loss) starts a new epoch and expires the allowance.
    function renew(uint64 site, bytes32 object, uint64 epoch, uint64 cq, bytes calldata clockSig)
        external
        returns (uint64 issued)
    {
        Lease storage l = leases[object];
        if (!l.exists) revert BadLease();
        if (!mayRenew(object, site)) revert NotPermitted();
        if (l.stopped) revert LeaseStopped();
        if (OffLib.recover(OffLib.requestDigest(site, object, epoch, cq), clockSig) != sites[site].clockKey) {
            revert BadClockSig();
        }
        issued = uint64(block.timestamp);
        renewalIssued[OffLib.renewalKey(site, object, epoch, cq)] = issued;
        lastRenewal[object][site] = Base(epoch, cq);
        l.lastIssue = issued;
        emit Renewed(site, object, epoch, cq, issued);
    }

    /// Exclusive object: stop renewals now and name the next holder. Credential: revoke (nextSite = 0).
    function stop(bytes32 object, uint64 nextSite) external onlyAdmin {
        Lease storage l = leases[object];
        if (!l.exists || l.stopped) revert BadLease();
        if (l.exclusive && !sites[nextSite].exists) revert BadSite();
        l.stopped = true;
        l.nextSite = nextSite;
        emit Stopped(object, nextSite, releaseAt(object));
    }

    /// Completes a reassignment once no site can still exercise the object (Theorem 1 upper bound).
    function reassign(bytes32 object) external {
        Lease storage l = leases[object];
        if (!l.exists || !l.exclusive || !l.stopped) revert BadLease();
        uint64 at = releaseAt(object);
        if (block.timestamp < at) revert TooEarly(at);
        _handOver(object, l);
    }

    /// Fast path while the old holder is connected: its quorum acknowledges that its ledger executed the stop
    /// at trusted-clock time (epoch, reading); the object moves at once. A later sealed use of the object at
    /// or after that reading is provable (proveUseAfterAck).
    function reassignAcked(
        bytes32 object,
        uint64 epoch,
        uint64 reading,
        bytes calldata clockSig,
        bytes[] calldata acks
    ) external {
        Lease storage l = leases[object];
        if (!l.exists || !l.exclusive || !l.stopped) revert BadLease();
        uint64 site = l.holder;
        if (OffLib.recover(OffLib.clockDigest(site, epoch, reading), clockSig) != sites[site].clockKey) {
            revert BadClockSig();
        }
        address[] memory s = _quorum(site, OffLib.ackDigest(address(this), site, object, epoch, reading), acks);
        lastAck[object] = Ack(site, epoch, reading);
        ackSigners[object] = s;
        emit Acknowledged(object, site, epoch, reading);
        _handOver(object, l);
    }

    function _handOver(bytes32 object, Lease storage l) internal {
        l.holder = l.nextSite;
        l.nextSite = 0;
        l.stopped = false;
        l.lastIssue = 0;
        emit Reassigned(object, l.holder);
    }

    // ---------------------------------------------------------------- checkpoints and fraud proofs (Theorem 2)
    /// Returns the distinct site validators whose seals over `h` are valid; reverts below a 2f+1 quorum.
    function _sealers(OffLib.Header calldata h, bytes[] calldata seals) internal view returns (address[] memory) {
        return _quorum(h.site, OffLib.checkpointDigest(address(this), OffLib.headerHash(h)), seals);
    }

    function _quorum(uint64 site, bytes32 digest, bytes[] calldata seals) internal view returns (address[] memory s) {
        Site storage st = sites[site];
        if (!st.exists) revert BadSite();
        s = new address[](seals.length);
        uint256 n;
        for (uint256 i = 0; i < seals.length; i++) {
            address v = OffLib.recover(digest, seals[i]);
            if (v == address(0) || !isValidator[site][v]) continue;
            bool dup;
            for (uint256 j = 0; j < n; j++) {
                if (s[j] == v) {
                    dup = true;
                    break;
                }
            }
            if (!dup) s[n++] = v;
        }
        if (n < 2 * uint256(st.f) + 1) revert NoQuorum();
        assembly {
            mstore(s, n)
        }
    }

    function _slash(uint64 site, address[] memory vs, uint8 reason) internal returns (uint256 count) {
        for (uint256 i = 0; i < vs.length; i++) {
            if (bond[site][vs[i]] != 0) {
                bond[site][vs[i]] = 0;
                count++;
                emit Slashed(site, vs[i], reason);
            }
        }
    }

    function _contains(OffLib.Header calldata h, OffLib.Op calldata op, uint256 idx, bytes32[] calldata proof)
        internal
        pure
    {
        if (idx >= h.opCount || !OffLib.verifyLeaf(h.opsRoot, OffLib.leaf(op), idx, proof)) revert BadProof();
    }

    /// Records the latest sealed checkpoint of a site (reconnection). Not required for the proofs below.
    function anchor(OffLib.Header calldata h, bytes[] calldata seals) external {
        _sealers(h, seals);
        Site storage st = sites[h.site];
        bytes32 hh = OffLib.headerHash(h);
        if (h.height != st.anchoredHeight + 1 || h.prev != st.anchoredHash) revert BadProof();
        st.anchoredHeight = h.height;
        st.anchoredHash = hh;
        emit Anchored(h.site, h.height, hh);
    }

    /// A sealed consumption whose running total exceeds the site's share.
    function proveOverspend(
        OffLib.Header calldata h,
        bytes[] calldata seals,
        OffLib.Op calldata op,
        uint256 idx,
        bytes32[] calldata proof
    ) external returns (uint256) {
        address[] memory s = _sealers(h, seals);
        _contains(h, op, idx, proof);
        if (op.kind != OffLib.CONSUME || op.b <= share[op.key][h.site]) revert NotAViolation();
        return _slash(h.site, s, R_OVERSPEND);
    }

    /// Two consumptions of one resource, i before j on the sealed chain, where j's running total minus its
    /// amount is below i's running total: the chain understates consumption. Every sealer of the checkpoint
    /// holding j committed to the whole chain (via prev hashes) and is faulty.
    function proveUnderstate(
        OffLib.Header[] calldata chain,
        bytes[] calldata sealsJ,
        OffLib.Op calldata opI,
        uint256 idxI,
        bytes32[] calldata proofI,
        OffLib.Op calldata opJ,
        uint256 idxJ,
        bytes32[] calldata proofJ
    ) external returns (uint256) {
        uint256 last = chain.length - 1;
        for (uint256 k = 1; k <= last; k++) {
            if (chain[k].site != chain[0].site || chain[k].prev != OffLib.headerHash(chain[k - 1])) revert BadProof();
        }
        if (last == 0 && idxI >= idxJ) revert BadProof();
        address[] memory s = _sealers(chain[last], sealsJ);
        _contains(chain[0], opI, idxI, proofI);
        _contains(chain[last], opJ, idxJ, proofJ);
        if (opI.kind != OffLib.CONSUME || opJ.kind != OffLib.CONSUME || opI.key != opJ.key) revert NotAViolation();
        if (opJ.b >= opJ.a && opJ.b - opJ.a >= opI.b) revert NotAViolation();
        return _slash(chain[0].site, s, R_UNDERSTATE);
    }

    /// A sealed use of a lease or credential that the rights do not cover: no renewal was issued for its
    /// base, the clock attestation is invalid, or the reading is outside [cq, cq + A).
    function proveOveruse(
        OffLib.Header calldata h,
        bytes[] calldata seals,
        OffLib.Op calldata op,
        uint256 idx,
        bytes32[] calldata proof
    ) external returns (uint256) {
        address[] memory s = _sealers(h, seals);
        _contains(h, op, idx, proof);
        if (op.kind != OffLib.USE) revert NotAViolation();
        bool covered = renewalIssued[OffLib.renewalKey(h.site, op.key, op.e, op.a)] != 0
            && OffLib.recover(OffLib.clockDigest(h.site, op.e, op.b), op.clockSig) == sites[h.site].clockKey
            && op.b >= op.a && op.b - op.a < leases[op.key].allowanceMs;
        if (covered) revert NotAViolation();
        return _slash(h.site, s, R_OVERUSE);
    }

    /// A sealed use of an object at or after the clock reading its site acknowledged releasing it at
    /// (fast-path reassignment). A correct validator acknowledges only after its ledger executed the stop and
    /// then never seals such a use, so the validators that did both are faulty (and are at least f+1).
    function proveUseAfterAck(
        OffLib.Header calldata h,
        bytes[] calldata seals,
        OffLib.Op calldata op,
        uint256 idx,
        bytes32[] calldata proof
    ) external returns (uint256) {
        address[] memory s = _sealers(h, seals);
        _contains(h, op, idx, proof);
        Ack storage ack = lastAck[op.key];
        // Strictly after the acknowledged reading: uses sealed before the stop have readings <= it.
        if (op.kind != OffLib.USE || ack.site != h.site || op.e != ack.epoch || op.b <= ack.reading) {
            revert NotAViolation();
        }
        address[] storage a = ackSigners[op.key];
        address[] memory both = new address[](s.length);
        uint256 n;
        for (uint256 i = 0; i < s.length; i++) {
            for (uint256 j = 0; j < a.length; j++) {
                if (s[i] == a[j]) {
                    both[n++] = s[i];
                    break;
                }
            }
        }
        assembly {
            mstore(both, n)
        }
        return _slash(h.site, both, R_USE_AFTER_ACK);
    }

    /// Two different sealed checkpoints at the same height: slash the validators that sealed both.
    function proveFork(
        OffLib.Header calldata h1,
        bytes[] calldata seals1,
        OffLib.Header calldata h2,
        bytes[] calldata seals2
    ) external returns (uint256) {
        if (h1.site != h2.site || h1.height != h2.height || OffLib.headerHash(h1) == OffLib.headerHash(h2)) {
            revert NotAViolation();
        }
        address[] memory a = _sealers(h1, seals1);
        address[] memory b = _sealers(h2, seals2);
        address[] memory both = new address[](a.length);
        uint256 n;
        for (uint256 i = 0; i < a.length; i++) {
            for (uint256 j = 0; j < b.length; j++) {
                if (a[i] == b[j]) {
                    both[n++] = a[i];
                    break;
                }
            }
        }
        assembly {
            mstore(both, n)
        }
        return _slash(h1.site, both, R_FORK);
    }
}
