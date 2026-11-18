// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {OffLib} from "./OffLib.sol";

/// Global-ledger side of rights-scoped offline operation.
///
/// Issues rights before a partition (versioned resource shares, leases on exclusive objects, credential
/// leases), records every lease renewal, delays slow-path reassignment and revocation by the lease bound of
/// Proposition 1, and adjudicates fraud proofs against site checkpoints (Theorem 1): a checkpoint sealed by
/// a site quorum that contains an out-of-rights operation slashes its sealers; two sealed checkpoints at
/// one height slash the validators that sealed both. Slashed validators no longer count towards quorums,
/// and a site with f+1 slashed validators loses all rights.
contract RightsRegistry {
    // ---------------------------------------------------------------- configuration
    address public immutable admin;
    uint32 public immutable rhoPpm; // bound on site-clock drift, parts per million
    uint32 public immutable gSlack; // seconds: bound on G block-timestamp error (epsilon_G)
    uint64 public immutable anchorLagMs; // renewals need anchored coverage up to (request reading - lag)
    uint256 public constant BOND = 1 ether; // per site validator: collateral held on G (accounting unit)

    struct Site {
        bool exists;
        bool revoked; // f+1 validators slashed: no further rights
        uint8 f;
        uint8 n; // number of site validators
        uint8 slashedCount;
        address clockKey; // trusted clock (e.g. TPM 2.0) of the site
        uint64 anchoredHeight;
        bytes32 anchoredHash;
        uint64 coveredEpoch; // trusted-clock time up to which every operation is in an anchored checkpoint
        uint64 coveredReading;
    }

    mapping(uint64 => Site) public sites;
    mapping(uint64 => mapping(address => bool)) public isValidator;
    mapping(uint64 => mapping(address => bool)) public slashed;
    mapping(uint64 => mapping(address => uint256)) public bond;
    mapping(uint64 => mapping(uint64 => bytes32)) public anchoredAt; // site => height => header hash

    // Bounded resources: versioned shares. Raising a share takes effect at once; lowering one frees capacity
    // only after the site's quorum acknowledges that it applied the lower version.
    mapping(bytes32 => uint64) public cap;
    mapping(bytes32 => uint64) public allocated;
    mapping(bytes32 => mapping(uint64 => uint64)) public share; // amount reserved for the site
    mapping(bytes32 => mapping(uint64 => uint64)) public shareVersion;
    mapping(bytes32 => mapping(uint64 => mapping(uint64 => uint64))) public certified; // version => amount
    mapping(bytes32 => mapping(uint64 => uint64)) public pendingVersion; // lower share awaiting acknowledgement

    // Leases: exclusive objects (one permitted site) and credentials (any number of sites).
    struct Lease {
        bool exists;
        bool exclusive;
        bool openHold; // holds last until released: moved only by acknowledgement, never by expiry
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

    /// Newest renewal issued per (object, site), raised to the acknowledged reading on a fast-path hand-over:
    /// renewals must be strictly newer, so old requests cannot be replayed.
    mapping(bytes32 => mapping(uint64 => Base)) public lastRenewal;

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
    event ShareSet(bytes32 indexed resource, uint64 indexed site, uint64 amount, uint64 version);
    event ShareConfirmed(bytes32 indexed resource, uint64 indexed site, uint64 amount, uint64 version);
    event LeaseCreated(bytes32 indexed object, bool exclusive, uint64 allowanceMs);
    event Permitted(bytes32 indexed object, uint64 indexed site);
    event Renewed(uint64 indexed site, bytes32 indexed object, uint64 epoch, uint64 cq, uint64 issued);
    event Stopped(bytes32 indexed object, uint64 nextSite, uint64 releaseAt);
    event Acknowledged(bytes32 indexed object, uint64 indexed site, uint64 epoch, uint64 reading);
    event Reassigned(bytes32 indexed object, uint64 indexed site);
    event Anchored(uint64 indexed site, uint64 height, bytes32 headerHash);
    event Slashed(uint64 indexed site, address indexed validator, uint8 reason);
    event SiteRevoked(uint64 indexed site);

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
    error AnchorDebt(uint64 covered, uint64 needed);
    error StaleAck();
    error StaleRequest();
    error SiteRevokedErr();
    error HoldMayBeOpen();
    error NoPendingShare();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    constructor(uint32 rhoPpm_, uint32 gSlack_, uint64 anchorLagMs_) {
        require(rhoPpm_ < 1_000_000, "rho");
        admin = msg.sender;
        rhoPpm = rhoPpm_;
        gSlack = gSlack_;
        anchorLagMs = anchorLagMs_;
    }

    // ---------------------------------------------------------------- administration
    /// (startEpoch, startReading) is the site clock's time at registration: coverage starts there.
    function registerSite(
        uint64 site,
        uint8 f,
        address clockKey,
        address[] calldata validators,
        uint64 startEpoch,
        uint64 startReading
    ) external onlyAdmin {
        if (sites[site].exists || validators.length < 3 * uint256(f) + 1 || validators.length > 255) revert BadSite();
        if (clockKey == address(0)) revert BadSite();
        Site storage st = sites[site];
        st.exists = true;
        st.f = f;
        st.n = uint8(validators.length);
        st.clockKey = clockKey;
        st.coveredEpoch = startEpoch;
        st.coveredReading = startReading;
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

    /// Issues share version v to a site; the sum of reserved shares never exceeds the cap (invariant I_B).
    /// The authorities certify (site, resource, amount, v) once this transaction is final on G.
    function setShare(bytes32 resource, uint64 site, uint64 amount) external onlyAdmin returns (uint64 v) {
        if (!sites[site].exists) revert BadSite();
        uint64 cur = share[resource][site];
        v = ++shareVersion[resource][site];
        certified[resource][site][v] = amount;
        if (amount >= cur) {
            uint64 next = allocated[resource] - cur + amount;
            if (next > cap[resource]) revert OverCap();
            allocated[resource] = next;
            share[resource][site] = amount;
            pendingVersion[resource][site] = 0;
        } else {
            pendingVersion[resource][site] = v; // capacity stays reserved until the site acknowledges
        }
        emit ShareSet(resource, site, amount, v);
    }

    /// The site's quorum acknowledges that it applied the lower share version (its total is within it).
    function confirmShare(bytes32 resource, uint64 site, bytes[] calldata acks) external {
        uint64 v = pendingVersion[resource][site];
        if (v == 0) revert NoPendingShare();
        _quorum(site, OffLib.shareAckDigest(address(this), site, resource, v), acks, false);
        uint64 amount = certified[resource][site][v];
        allocated[resource] -= share[resource][site] - amount;
        share[resource][site] = amount;
        pendingVersion[resource][site] = 0;
        emit ShareConfirmed(resource, site, amount, v);
    }

    function createLease(bytes32 object, bool exclusive, uint64 allowanceMs) external onlyAdmin {
        if (leases[object].exists || allowanceMs == 0) revert BadLease();
        leases[object] = Lease(true, exclusive, false, false, allowanceMs, 0, 0, 0);
        emit LeaseCreated(object, exclusive, allowanceMs);
    }

    /// Marks an exclusive object whose holds last until released (e.g. an isolation point under lockout).
    function setOpenHold(bytes32 object) external onlyAdmin {
        Lease storage l = leases[object];
        if (!l.exists || !l.exclusive || l.holder != 0) revert BadLease();
        l.openHold = true;
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

    // ---------------------------------------------------------------- leases (Proposition 1)
    /// Wait after the last renewal before another site may hold the object, in G seconds:
    /// ceil(A / (1 - rho)) plus twice the G timestamp error (issue and reassignment are both G timestamps).
    function waitSeconds(bytes32 object) public view returns (uint64) {
        uint256 a = leases[object].allowanceMs;
        uint256 num = a * 1_000_000;
        uint256 den = uint256(1_000_000 - rhoPpm) * 1000;
        return uint64((num + den - 1) / den) + 2 * uint64(gSlack);
    }

    /// G time after which no site can still exercise the object (or accept the credential).
    function releaseAt(bytes32 object) public view returns (uint64) {
        Lease storage l = leases[object];
        return l.lastIssue == 0 ? 0 : l.lastIssue + waitSeconds(object);
    }

    function _newer(uint64 e1, uint64 r1, uint64 e2, uint64 r2) internal pure returns (bool) {
        return e1 > e2 || (e1 == e2 && r1 > r2);
    }

    /// A site's renewal request, relayed while its uplink is up. `cq` is the site's trusted-clock reading
    /// taken when the request was SENT, in clock epoch `epoch`; the site may exercise while its clock, in the
    /// same epoch, is below cq + A. Any clock reset (power loss) starts a new epoch and expires the allowance.
    /// The authorities certify the renewal once this transaction is final on G.
    function renew(uint64 site, bytes32 object, uint64 epoch, uint64 cq, bytes calldata clockSig)
        external
        returns (uint64 issued)
    {
        Lease storage l = leases[object];
        Site storage st = sites[site];
        if (!l.exists) revert BadLease();
        if (st.revoked) revert SiteRevokedErr();
        if (!mayRenew(object, site)) revert NotPermitted();
        if (l.stopped) revert LeaseStopped();
        if (OffLib.recover(OffLib.requestDigest(site, object, epoch, cq), clockSig) != st.clockKey) {
            revert BadClockSig();
        }
        Base memory last = lastRenewal[object][site];
        if (!_newer(epoch, cq, last.epoch, last.cq)) revert StaleRequest();
        // Anchor before renew: a site that withholds checkpoints stops receiving rights. Coverage comes from
        // clock-attested checkpoint closes, so it cannot run ahead of the site's clock.
        if (st.coveredEpoch != epoch || st.coveredReading + anchorLagMs < cq) {
            revert AnchorDebt(st.coveredReading, cq > anchorLagMs ? cq - anchorLagMs : 0);
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

    /// Slow path: completes a reassignment once no site can still exercise the object (Proposition 1).
    /// Objects with open holds are never moved by expiry.
    function reassign(bytes32 object) external {
        Lease storage l = leases[object];
        if (!l.exists || !l.exclusive || !l.stopped) revert BadLease();
        if (l.openHold) revert HoldMayBeOpen();
        uint64 at = releaseAt(object);
        if (block.timestamp < at) revert TooEarly(at);
        _handOver(object, l);
    }

    /// Fast path while the old holder is connected: its quorum acknowledges that, at trusted-clock time
    /// (epoch, reading), its ledger had executed the stop and no hold of the object was running; the object
    /// moves at once. A sealed grant, hold or release of the object past that reading is provable.
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
        if (OffLib.recover(OffLib.clockDigest(site, epoch, reading, object), clockSig) != sites[site].clockKey) {
            revert BadClockSig();
        }
        Base memory b = lastRenewal[object][site];
        if (_newer(b.epoch, b.cq, epoch, reading)) revert StaleAck();
        address[] memory s = _quorum(site, OffLib.ackDigest(address(this), site, object, epoch, reading), acks, false);
        lastAck[object] = Ack(site, epoch, reading);
        ackSigners[object] = s;
        // Later renewals for this site must be newer than the acknowledgement (no replay of older requests).
        lastRenewal[object][site] = Base(epoch, reading);
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

    // ---------------------------------------------------------------- checkpoints and fraud proofs (Theorem 1)
    /// Distinct site validators whose signatures over `digest` are valid; reverts below the quorum
    /// floor((n+f)/2)+1. For fraud proofs every registered validator counts (so that co-signers of an already
    /// slashed validator are still caught); for new anchors and acknowledgements slashed validators do not.
    function _quorum(uint64 site, bytes32 digest, bytes[] calldata sigs, bool forProof)
        internal
        view
        returns (address[] memory s)
    {
        Site storage st = sites[site];
        if (!st.exists) revert BadSite();
        s = new address[](sigs.length);
        uint256 n;
        for (uint256 i = 0; i < sigs.length; i++) {
            address v = OffLib.recover(digest, sigs[i]);
            if (v == address(0) || !isValidator[site][v]) continue;
            if (!forProof && slashed[site][v]) continue;
            bool dup;
            for (uint256 j = 0; j < n; j++) {
                if (s[j] == v) {
                    dup = true;
                    break;
                }
            }
            if (!dup) s[n++] = v;
        }
        // Any two quorums share at least f+1 validators (2f+1 when n = 3f+1).
        if (n < (uint256(st.n) + st.f) / 2 + 1) revert NoQuorum();
        assembly {
            mstore(s, n)
        }
    }

    function _sealers(OffLib.Header calldata h, bytes[] calldata seals) internal view returns (address[] memory) {
        return _quorum(h.site, OffLib.checkpointDigest(address(this), OffLib.headerHash(h)), seals, true);
    }

    function _slash(uint64 site, address[] memory vs, uint8 reason) internal returns (uint256 count) {
        Site storage st = sites[site];
        for (uint256 i = 0; i < vs.length; i++) {
            if (!slashed[site][vs[i]]) {
                slashed[site][vs[i]] = true;
                bond[site][vs[i]] = 0;
                st.slashedCount++;
                count++;
                emit Slashed(site, vs[i], reason);
            }
        }
        if (!st.revoked && st.slashedCount > st.f) {
            st.revoked = true;
            emit SiteRevoked(site);
        }
    }

    function _contains(OffLib.Header calldata h, OffLib.Op calldata op, uint256 idx, bytes32[] calldata proof)
        internal
        pure
    {
        if (idx >= h.opCount || !OffLib.verifyLeaf(h.opsRoot, OffLib.leaf(op), idx, proof)) revert BadProof();
    }

    /// Records a sealed checkpoint of a site that builds on its last anchored one (one transaction after an
    /// outage of any length). Its close is attested by the site's trusted clock and advances the coverage that
    /// renewals require (anchor before renew).
    function anchor(OffLib.Header calldata h, bytes[] calldata seals) external {
        Site storage st = sites[h.site];
        bytes32 hh = OffLib.headerHash(h);
        _quorum(h.site, OffLib.checkpointDigest(address(this), hh), seals, false);
        if (h.height <= st.anchoredHeight || h.baseHeight != st.anchoredHeight || h.baseHash != st.anchoredHash) {
            revert BadProof();
        }
        if (
            OffLib.recover(OffLib.clockDigest(h.site, h.closeEpoch, h.closeReading, OffLib.contentTag(h)), h.closeSig)
                != st.clockKey
        ) revert BadClockSig();
        if (_newer(st.coveredEpoch, st.coveredReading, h.closeEpoch, h.closeReading)) revert BadProof();
        st.anchoredHeight = h.height;
        st.anchoredHash = hh;
        anchoredAt[h.site][h.height] = hh;
        st.coveredEpoch = h.closeEpoch;
        st.coveredReading = h.closeReading;
        emit Anchored(h.site, h.height, hh);
    }

    /// A sealed consumption whose running total exceeds the share version it was made under, or is below
    /// its own amount (impossible for a correct ledger).
    function proveOverspend(
        OffLib.Header calldata h,
        bytes[] calldata seals,
        OffLib.Op calldata op,
        uint256 idx,
        bytes32[] calldata proof
    ) external returns (uint256) {
        address[] memory s = _sealers(h, seals);
        _contains(h, op, idx, proof);
        if (op.kind != OffLib.CONSUME) revert NotAViolation();
        if (op.b <= certified[op.key][h.site][op.c] && op.b >= op.a) revert NotAViolation();
        return _slash(h.site, s, R_OVERSPEND);
    }

    /// Understatement inside one sealed checkpoint: consumption i precedes j, and j's running total minus its
    /// amount is below i's running total.
    function proveUnderstate(
        OffLib.Header calldata h,
        bytes[] calldata seals,
        OffLib.Op calldata opI,
        uint256 idxI,
        bytes32[] calldata proofI,
        OffLib.Op calldata opJ,
        uint256 idxJ,
        bytes32[] calldata proofJ
    ) external returns (uint256) {
        if (idxI >= idxJ) revert BadProof();
        address[] memory s = _sealers(h, seals);
        _contains(h, opI, idxI, proofI);
        _contains(h, opJ, idxJ, proofJ);
        if (opI.kind != OffLib.CONSUME || opJ.kind != OffLib.CONSUME || opI.key != opJ.key) revert NotAViolation();
        if (opJ.b >= opJ.a && opJ.b - opJ.a >= opI.b) revert NotAViolation();
        return _slash(h.site, s, R_UNDERSTATE);
    }

    /// Understatement against the parent: the sealers of `h` extended parent `p` (h.prev = hash(p)), whose
    /// state root commits a running total `total` for the resource, yet a consumption in `h` restarts below it.
    /// A correct validator extends only a checkpoint it verified, so the sealers of h are faulty. Constant
    /// cost, whatever the outage length.
    function proveUnderstateParent(
        OffLib.Header calldata h,
        bytes[] calldata seals,
        OffLib.Op calldata op,
        uint256 idx,
        bytes32[] calldata proof,
        OffLib.Header calldata p,
        uint64 total,
        uint256 sIdx,
        bytes32[] calldata sProof
    ) external returns (uint256) {
        if (h.site != p.site || h.prev != OffLib.headerHash(p)) revert BadProof();
        address[] memory s = _sealers(h, seals);
        _contains(h, op, idx, proof);
        if (!OffLib.verifyLeaf(p.stateRoot, OffLib.stateLeaf(op.key, total), sIdx, sProof)) revert BadProof();
        if (op.kind != OffLib.CONSUME || (op.b >= op.a && op.b - op.a >= total)) revert NotAViolation();
        return _slash(h.site, s, R_UNDERSTATE);
    }

    /// A sealed checkpoint whose state root commits a running total below one of its own consumptions.
    function proveStateMismatch(
        OffLib.Header calldata h,
        bytes[] calldata seals,
        OffLib.Op calldata op,
        uint256 idx,
        bytes32[] calldata proof,
        uint64 total,
        uint256 sIdx,
        bytes32[] calldata sProof
    ) external returns (uint256) {
        address[] memory s = _sealers(h, seals);
        _contains(h, op, idx, proof);
        if (!OffLib.verifyLeaf(h.stateRoot, OffLib.stateLeaf(op.key, total), sIdx, sProof)) revert BadProof();
        if (op.kind != OffLib.CONSUME || op.b <= total) revert NotAViolation();
        return _slash(h.site, s, R_UNDERSTATE);
    }

    /// A sealed grant that the rights do not cover: no renewal was issued for its base, the clock attestation
    /// is invalid, the grant reading is outside [cq, cq + A), or a bounded hold ends at or after cq + A.
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
        Lease storage l = leases[op.key];
        bool covered = renewalIssued[OffLib.renewalKey(h.site, op.key, op.e, op.a)] != 0
            && OffLib.recover(OffLib.clockDigest(h.site, op.e, op.b, op.key), op.clockSig) == sites[h.site].clockKey
            && op.b >= op.a && op.b - op.a < l.allowanceMs
            && (l.openHold ? op.c == OffLib.OPEN : (op.c >= op.b && op.c - op.a < l.allowanceMs));
        if (covered) revert NotAViolation();
        return _slash(h.site, s, R_OVERUSE);
    }

    /// Fast path: a sealed grant, hold or release of the object under a renewal from before the
    /// acknowledgement that runs past the acknowledged reading. A correct validator acknowledges only once no
    /// hold is running and then never seals such an operation, so the validators that did both are faulty
    /// (at least f+1 of them).
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
        uint64 r = ack.reading;
        if (ack.site != h.site || op.e != ack.epoch || op.a > r) revert NotAViolation();
        bool late;
        if (op.kind == OffLib.USE) late = op.b > r || (op.c != OffLib.OPEN && op.c > r);
        else if (op.kind == OffLib.RELEASE) late = op.b > r;
        if (!late) revert NotAViolation();
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
