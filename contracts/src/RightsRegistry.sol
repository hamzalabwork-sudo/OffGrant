// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {OffLib} from "./OffLib.sol";

/// Global-ledger side of rights-scoped offline operation (version 5).
///
/// Issues rights before a partition (versioned resource shares, leases on exclusive objects, credential
/// leases), records every lease renewal, delays slow-path reassignment and revocation by the lease bound of
/// Proposition 1, and adjudicates fraud proofs against sealed site checkpoints (Theorem 1). Every proof costs
/// the same whatever the length of the site's history: it needs one checkpoint, at most one ancestor named
/// through the checkpoint's history accumulator, and Merkle paths. Slashed validators no longer count towards
/// anchor, acknowledgement or share quorums, and a site with more than f slashed validators gets no renewals.
contract RightsRegistry {
    // ---------------------------------------------------------------- configuration
    address public immutable admin;
    bytes32 public immutable dom; // signature domain: (chain id, this registry)
    uint32 public immutable rhoPpm; // bound on site-clock drift, parts per million
    uint32 public immutable gSlack; // seconds: bound on G block-timestamp error (epsilon_G)
    uint64 public immutable anchorLagMs; // renewals need anchored coverage up to (request reading - lag)
    uint256 public constant BOND = 1 ether; // stake recorded per site validator (accounting unit)

    struct Site {
        bool exists;
        bool revoked; // more than f validators slashed: no further renewals
        uint8 f;
        uint8 n; // number of site validators
        uint8 slashedCount;
        address clockKey; // trusted clock (e.g. TPM 2.0) of the site's gateway
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

    // Resources: versioned shares. Raising a share takes effect at once; lowering one frees capacity only when
    // a sealed checkpoint of the site shows the lower version applied and the total within it.
    mapping(bytes32 => uint64) public cap;
    mapping(bytes32 => uint64) public allocated;
    mapping(bytes32 => mapping(uint64 => uint64)) public share; // amount reserved for the site
    mapping(bytes32 => mapping(uint64 => uint64)) public shareVersion;
    mapping(bytes32 => mapping(uint64 => mapping(uint64 => uint64))) public certified; // version => amount
    mapping(bytes32 => mapping(uint64 => uint64)) public pendingVersion; // lower share awaiting confirmation

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

    /// Fast-path acknowledgements, never overwritten: OffLib.ackKey(object, site, epoch, reading) => signers.
    mapping(bytes32 => address[]) internal ackSigners;

    // Proof arguments, grouped to keep the stack small.
    struct OpProof {
        OffLib.Op op;
        uint256 idx;
        bytes32[] path;
    }

    struct Ancestor {
        OffLib.Header p; // a checkpoint at a lower height that `h.histRoot` commits to
        OffLib.State state; // its state (must hash to p.stateHash)
        bytes32[] histPath; // inclusion of hash(p) at index p.height in h.histRoot
    }

    // ---------------------------------------------------------------- events
    event SiteRegistered(uint64 indexed site, uint8 f, address clockKey, address[] validators);
    event ClockRotated(uint64 indexed site, address clockKey, uint64 epoch, uint64 reading);
    event ValidatorReplaced(uint64 indexed site, address oldValidator, address newValidator);
    event ShareSet(bytes32 indexed resource, uint64 indexed site, uint64 amount, uint64 version);
    event ShareConfirmed(bytes32 indexed resource, uint64 indexed site, uint64 amount, uint64 version, uint64 height);
    event LeaseCreated(bytes32 indexed object, bool exclusive, bool openHold, uint64 allowanceMs);
    event Permitted(bytes32 indexed object, uint64 indexed site);
    event Renewed(uint64 indexed site, bytes32 objects, uint64 epoch, uint64 cq, uint64 issued);
    event Stopped(bytes32 indexed object, uint64 nextSite, uint64 releaseAt);
    event Acknowledged(bytes32 indexed object, uint64 indexed site, uint64 epoch, uint64 reading);
    event Reassigned(bytes32 indexed object, uint64 indexed site);
    event ForcedReassign(bytes32 indexed object, uint64 indexed fromSite, uint64 indexed toSite);
    event Anchored(uint64 indexed site, uint64 height, bytes32 headerHash);
    event Slashed(uint64 indexed site, address indexed validator, uint8 reason);
    event SiteRevoked(uint64 indexed site);

    uint8 internal constant R_OVERSPEND = 1;
    uint8 internal constant R_UNDERSTATE = 2;
    uint8 internal constant R_OVERUSE = 3;
    uint8 internal constant R_FORK = 4;
    uint8 internal constant R_USE_AFTER_ACK = 5;
    uint8 internal constant R_BAD_OP = 6;
    uint8 internal constant R_ORDER = 7;
    uint8 internal constant R_REGRESS = 8;

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
    error ShareNotApplied();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    constructor(uint32 rhoPpm_, uint32 gSlack_, uint64 anchorLagMs_) {
        require(rhoPpm_ < 1_000_000, "rho");
        admin = msg.sender;
        dom = OffLib.domain(address(this), block.chainid);
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
        if (site == 0 || sites[site].exists || clockKey == address(0)) revert BadSite();
        if (validators.length < 3 * uint256(f) + 1 || validators.length > 255) revert BadSite();
        Site storage st = sites[site];
        st.exists = true;
        st.f = f;
        st.n = uint8(validators.length);
        st.clockKey = clockKey;
        st.coveredEpoch = startEpoch;
        st.coveredReading = startReading;
        for (uint256 i = 0; i < validators.length; i++) {
            address v = validators[i];
            if (v == address(0) || isValidator[site][v]) revert BadSite();
            isValidator[site][v] = true;
            bond[site][v] = BOND;
        }
        emit SiteRegistered(site, f, clockKey, validators);
    }

    /// Recovery: a replaced or cleared TPM gets a new key, and coverage restarts at its first reading.
    function rotateClock(uint64 site, address clockKey, uint64 epoch, uint64 reading) external onlyAdmin {
        Site storage st = sites[site];
        if (!st.exists || clockKey == address(0)) revert BadSite();
        st.clockKey = clockKey;
        st.coveredEpoch = epoch;
        st.coveredReading = reading;
        emit ClockRotated(site, clockKey, epoch, reading);
    }

    /// Recovery: replaces a site validator (e.g. a slashed or failed one); the site's quorum size is unchanged.
    function replaceValidator(uint64 site, address oldV, address newV) external onlyAdmin {
        Site storage st = sites[site];
        if (!st.exists || !isValidator[site][oldV] || newV == address(0) || isValidator[site][newV]) revert BadSite();
        isValidator[site][oldV] = false;
        if (slashed[site][oldV]) {
            slashed[site][oldV] = false;
            st.slashedCount--;
        }
        isValidator[site][newV] = true;
        bond[site][newV] = BOND;
        emit ValidatorReplaced(site, oldV, newV);
    }

    function setCap(bytes32 resource, uint64 amount) external onlyAdmin {
        if (amount < allocated[resource]) revert OverCap();
        cap[resource] = amount;
    }

    /// Issues share version v to a site; the sum of reserved shares never exceeds the cap. The authorities
    /// certify (site, resource, amount, v) once this transaction is final on G.
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
            pendingVersion[resource][site] = v; // capacity stays reserved until confirmed
        }
        emit ShareSet(resource, site, amount, v);
    }

    /// Frees the capacity of a lower share: a checkpoint sealed by the site's (unslashed) quorum shows the
    /// version applied and the running total within it. Later consumption under an older version, or a total
    /// above it, is provable against this checkpoint (proveOpRegress, proveRegress, proveOverspend).
    function confirmShare(
        bytes32 resource,
        uint64 site,
        OffLib.Header calldata h,
        bytes[] calldata seals,
        OffLib.State calldata s
    ) external {
        uint64 v = pendingVersion[resource][site];
        if (v == 0) revert NoPendingShare();
        if (h.site != site) revert BadProof();
        _quorum(site, OffLib.checkpointDigest(dom, OffLib.headerHash(h)), seals, false);
        if (OffLib.stateHash(s) != h.stateHash) revert BadProof();
        (uint64 t, uint64 ver) = OffLib.lookup(s, resource);
        uint64 amount = certified[resource][site][v];
        if (ver < v || t > amount) revert ShareNotApplied();
        allocated[resource] -= share[resource][site] - amount;
        share[resource][site] = amount;
        pendingVersion[resource][site] = 0;
        emit ShareConfirmed(resource, site, amount, v, h.height);
    }

    /// The class of a lease (bounded or open holds) is fixed at creation.
    function createLease(bytes32 object, bool exclusive, bool openHold, uint64 allowanceMs) external onlyAdmin {
        if (leases[object].exists || allowanceMs == 0 || (openHold && !exclusive)) revert BadLease();
        leases[object] = Lease(true, exclusive, openHold, false, allowanceMs, 0, 0, 0);
        emit LeaseCreated(object, exclusive, openHold, allowanceMs);
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
        if (site == 0) return false;
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

    /// A site's renewal request for a batch of objects, relayed while its uplink is up. `cq` is the site's
    /// trusted-clock reading taken when the request was SENT, in clock epoch `epoch`; the site may grant while
    /// its clock, in the same epoch, is below cq + A. The authorities certify the renewal once it is final on G.
    function renew(uint64 site, bytes32[] calldata objects, uint64 epoch, uint64 cq, bytes calldata clockSig)
        external
        returns (uint64 issued)
    {
        Site storage st = sites[site];
        if (!st.exists) revert BadSite();
        if (st.revoked) revert SiteRevokedErr();
        bytes32 objs = OffLib.objectsHash(objects);
        if (OffLib.recover(OffLib.clockDigest(dom, site, epoch, cq, OffLib.requestTag(objs)), clockSig) != st.clockKey) {
            revert BadClockSig();
        }
        // Anchor before renew: a site that withholds checkpoints stops receiving rights. Coverage comes from
        // clock-attested checkpoint closes in the request's epoch, so it cannot run ahead of the site's clock.
        if (st.coveredEpoch != epoch || st.coveredReading + anchorLagMs < cq) {
            revert AnchorDebt(st.coveredReading, cq > anchorLagMs ? cq - anchorLagMs : 0);
        }
        issued = uint64(block.timestamp);
        for (uint256 i = 0; i < objects.length; i++) {
            bytes32 o = objects[i];
            Lease storage l = leases[o];
            if (!l.exists) revert BadLease();
            if (!mayRenew(o, site)) revert NotPermitted();
            if (l.stopped) revert LeaseStopped();
            Base memory last = lastRenewal[o][site];
            if (!OffLib.after_(epoch, cq, last.epoch, last.cq)) revert StaleRequest();
            renewalIssued[OffLib.renewalKey(site, o, epoch, cq)] = issued;
            lastRenewal[o][site] = Base(epoch, cq);
            l.lastIssue = issued;
        }
        emit Renewed(site, objs, epoch, cq, issued);
    }

    /// Exclusive object: stop renewals now and name the next holder. Credential: revoke (nextSite = 0).
    function stop(bytes32 object, uint64 nextSite) external onlyAdmin {
        Lease storage l = leases[object];
        if (!l.exists || l.stopped) revert BadLease();
        if (l.exclusive && (nextSite == 0 || !sites[nextSite].exists)) revert BadSite();
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

    /// Fast path while the old holder is connected. The site's ledger recorded an ACK operation at
    /// trusted-clock time (epoch, reading), attested by its clock, and a quorum of its unslashed validators
    /// signs that the operation is final. The object moves at once. Acknowledgements are kept for proofs.
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
        _checkAck(object, site, epoch, reading, clockSig);
        ackSigners[OffLib.ackKey(object, site, epoch, reading)] =
            _quorum(site, OffLib.ackDigest(dom, site, object, epoch, reading), acks, false);
        // Later renewals for this site must be newer than the acknowledgement (no replay of older requests).
        lastRenewal[object][site] = Base(epoch, reading);
        emit Acknowledged(object, site, epoch, reading);
        _handOver(object, l);
    }

    /// The ACK operation's attestation (its base is the stopped renewal) and that it is newer than that renewal.
    function _checkAck(bytes32 object, uint64 site, uint64 epoch, uint64 reading, bytes calldata clockSig)
        internal
        view
    {
        Base memory b = lastRenewal[object][site];
        OffLib.Op memory ackOp = OffLib.Op(OffLib.ACK, object, epoch, reading, b.cq, 0, 0, 0, 0, "");
        bytes32 d = OffLib.clockDigest(dom, site, epoch, reading, OffLib.opTag(ackOp));
        if (OffLib.recover(d, clockSig) != sites[site].clockKey) revert BadClockSig();
        if (!OffLib.after_(epoch, reading, b.epoch, b.cq)) revert StaleAck();
    }

    /// Emergency override by G's authorities, for a site's safety procedure (e.g. a lockout whose holder site is
    /// lost). Outside the guarantees of Theorem 1(i): the site must first clear the hold physically. Logged.
    function forceReassign(bytes32 object) external onlyAdmin {
        Lease storage l = leases[object];
        if (!l.exists || !l.exclusive || !l.stopped) revert BadLease();
        emit ForcedReassign(object, l.holder, l.nextSite);
        _handOver(object, l);
    }

    function _handOver(bytes32 object, Lease storage l) internal {
        l.holder = l.nextSite;
        l.nextSite = 0;
        l.stopped = false;
        l.lastIssue = 0;
        emit Reassigned(object, l.holder);
    }

    function ackSignerCount(bytes32 key) external view returns (uint256) {
        return ackSigners[key].length;
    }

    // ---------------------------------------------------------------- checkpoints
    /// Distinct site validators whose signatures over `digest` are valid; reverts below the quorum
    /// floor((n+f)/2)+1. For fraud proofs every registered validator counts (so that co-signers of an already
    /// slashed validator are still caught); for anchors, acknowledgements and shares slashed validators do not.
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
        return _quorum(h.site, OffLib.checkpointDigest(dom, OffLib.headerHash(h)), seals, true);
    }

    /// Records a sealed checkpoint whose history contains the site's last anchored checkpoint (one transaction
    /// after an outage of any length, and anyone may anchor). Its close is attested by the site's trusted clock
    /// and advances the coverage that renewals require (anchor before renew).
    function anchor(OffLib.Header calldata h, bytes[] calldata seals, bytes32[] calldata histPath) external {
        Site storage st = sites[h.site];
        bytes32 hh = OffLib.headerHash(h);
        _quorum(h.site, OffLib.checkpointDigest(dom, hh), seals, false);
        if (h.height <= st.anchoredHeight) revert BadProof();
        if (st.anchoredHeight != 0 && !OffLib.inHistory(h.histRoot, st.anchoredHash, st.anchoredHeight, histPath)) {
            revert BadProof();
        }
        if (
            OffLib.recover(OffLib.clockDigest(dom, h.site, h.closeEpoch, h.closeReading, OffLib.contentTag(h)), h.closeSig)
                != st.clockKey
        ) revert BadClockSig();
        if (OffLib.after_(st.coveredEpoch, st.coveredReading, h.closeEpoch, h.closeReading)) revert BadProof();
        st.anchoredHeight = h.height;
        st.anchoredHash = hh;
        anchoredAt[h.site][h.height] = hh;
        st.coveredEpoch = h.closeEpoch;
        st.coveredReading = h.closeReading;
        emit Anchored(h.site, h.height, hh);
    }

    // ---------------------------------------------------------------- fraud proofs (Theorem 1(ii))
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

    function _contains(OffLib.Header calldata h, OpProof calldata o) internal pure {
        if (o.idx >= h.opCount || !OffLib.verifyLeaf(h.opsRoot, OffLib.leaf(o.op), o.idx, o.path)) revert BadProof();
    }

    function _intersect(address[] memory a, address[] memory b) internal pure returns (address[] memory both) {
        both = new address[](a.length);
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
    }

    /// Checks that `a.p` is an ancestor of `h` (committed by h's history accumulator) with state `a.state`.
    function _ancestor(OffLib.Header calldata h, Ancestor calldata a) internal pure {
        if (a.p.site != h.site || a.p.height >= h.height) revert BadProof();
        if (!OffLib.inHistory(h.histRoot, OffLib.headerHash(a.p), a.p.height, a.histPath)) revert BadProof();
        if (OffLib.stateHash(a.state) != a.p.stateHash) revert BadProof();
    }

    /// A consumption whose running total exceeds the share version it names, or is below its own amount.
    function proveOverspend(OffLib.Header calldata h, bytes[] calldata seals, OpProof calldata o)
        external
        returns (uint256)
    {
        address[] memory s = _sealers(h, seals);
        _contains(h, o);
        OffLib.Op calldata op = o.op;
        if (op.kind != OffLib.CONSUME) revert NotAViolation();
        if (op.total <= certified[op.key][h.site][op.version] && op.total >= op.amount) revert NotAViolation();
        return _slash(h.site, s, R_OVERSPEND);
    }

    /// An operation that no correct ledger records: an attested kind whose attestation is invalid, a share whose
    /// (version, amount) G never certified, or an unknown kind.
    function proveBadOp(OffLib.Header calldata h, bytes[] calldata seals, OpProof calldata o)
        external
        returns (uint256)
    {
        address[] memory s = _sealers(h, seals);
        _contains(h, o);
        OffLib.Op calldata op = o.op;
        bool bad = false;
        if (OffLib.attested(op.kind)) {
            bad = OffLib.recover(
                OffLib.clockDigest(dom, h.site, op.epoch, op.reading, OffLib.opTag(op)), op.clockSig
            ) != sites[h.site].clockKey;
        } else if (op.kind == OffLib.SHARE) {
            bad = op.version == 0 || certified[op.key][h.site][op.version] != op.amount;
        } else {
            bad = op.kind != OffLib.LOG;
        }
        if (!bad) revert NotAViolation();
        return _slash(h.site, s, R_BAD_OP);
    }

    /// A grant that the rights do not cover: no renewal was issued for its base, the grant reading is outside
    /// [cq, cq + A), or the hold's form does not match the object (a bounded hold must end inside the
    /// allowance and after the grant; an open-hold object takes only open holds).
    function proveOveruse(OffLib.Header calldata h, bytes[] calldata seals, OpProof calldata o)
        external
        returns (uint256)
    {
        address[] memory s = _sealers(h, seals);
        _contains(h, o);
        OffLib.Op calldata op = o.op;
        if (op.kind != OffLib.USE) revert NotAViolation();
        Lease storage l = leases[op.key];
        bool covered = l.exists && renewalIssued[OffLib.renewalKey(h.site, op.key, op.epoch, op.base)] != 0
            && op.reading >= op.base && op.reading - op.base < l.allowanceMs
            && (l.openHold ? op.until == OffLib.OPEN : (op.until > op.reading && op.until - op.base < l.allowanceMs));
        if (covered) revert NotAViolation();
        return _slash(h.site, s, R_OVERUSE);
    }

    /// Two operations i < j of one checkpoint that no correct ledger records in this order: attested readings
    /// that do not strictly increase; a running total that restarts below an earlier one; or a consumption
    /// under a share version older than one already applied or used.
    function proveInconsistent(OffLib.Header calldata h, bytes[] calldata seals, OpProof calldata a, OpProof calldata b)
        external
        returns (uint256)
    {
        if (a.idx >= b.idx) revert BadProof();
        address[] memory s = _sealers(h, seals);
        _contains(h, a);
        _contains(h, b);
        OffLib.Op calldata x = a.op;
        OffLib.Op calldata y = b.op;
        bool bad = false;
        if (OffLib.attested(x.kind) && OffLib.attested(y.kind)) {
            bad = !OffLib.after_(y.epoch, y.reading, x.epoch, x.reading);
        }
        if (!bad && y.kind == OffLib.CONSUME && x.key == y.key && (x.kind == OffLib.CONSUME || x.kind == OffLib.SHARE)) {
            bad = y.version < x.version || (x.kind == OffLib.CONSUME && (y.total < y.amount || y.total - y.amount < x.total));
        }
        if (!bad) revert NotAViolation();
        return _slash(h.site, s, R_ORDER);
    }

    /// A checkpoint whose committed state is malformed, or below one of its own operations: a total or
    /// version below a consumption's, or a clock reading below an attested operation's.
    function proveStateMismatch(
        OffLib.Header calldata h,
        bytes[] calldata seals,
        OpProof calldata o,
        OffLib.State calldata st
    ) external returns (uint256) {
        address[] memory s = _sealers(h, seals);
        if (OffLib.stateHash(st) != h.stateHash) revert BadProof();
        bool bad = !OffLib.wellFormed(st);
        if (!bad) {
            _contains(h, o);
            OffLib.Op calldata op = o.op;
            if (OffLib.attested(op.kind)) bad = OffLib.after_(op.epoch, op.reading, st.epoch, st.reading);
            if (!bad && (op.kind == OffLib.CONSUME || op.kind == OffLib.SHARE)) {
                (uint64 t, uint64 v) = OffLib.lookup(st, op.key);
                bad = op.total > t || op.version > v;
            }
        }
        if (!bad) revert NotAViolation();
        return _slash(h.site, s, R_UNDERSTATE);
    }

    /// The committed state of `h` is below that of an ancestor: a running total, a share version or the clock
    /// went backwards (including a resource dropped from the state). Totals, versions and readings only grow on
    /// a correct ledger, and a correct validator seals only a checkpoint whose history it verified.
    function proveRegress(
        OffLib.Header calldata h,
        bytes[] calldata seals,
        OffLib.State calldata st,
        Ancestor calldata a
    ) external returns (uint256) {
        address[] memory s = _sealers(h, seals);
        _ancestor(h, a);
        if (OffLib.stateHash(st) != h.stateHash) revert BadProof();
        bool bad = OffLib.after_(a.state.epoch, a.state.reading, st.epoch, st.reading);
        for (uint256 i = 0; !bad && i < a.state.resources.length; i++) {
            (uint64 t, uint64 v) = OffLib.lookup(st, a.state.resources[i]);
            bad = t < a.state.totals[i] || v < a.state.versions[i];
        }
        if (!bad) revert NotAViolation();
        return _slash(h.site, s, R_REGRESS);
    }

    /// An operation of `h` below the committed state of an ancestor: a consumption that restarts below the
    /// ancestor's total or uses an older share version, or an attested operation not newer than the ancestor's
    /// clock (a replayed or back-dated attestation).
    function proveOpRegress(OffLib.Header calldata h, bytes[] calldata seals, OpProof calldata o, Ancestor calldata a)
        external
        returns (uint256)
    {
        address[] memory s = _sealers(h, seals);
        _ancestor(h, a);
        _contains(h, o);
        OffLib.Op calldata op = o.op;
        bool bad = false;
        if (OffLib.attested(op.kind)) bad = !OffLib.after_(op.epoch, op.reading, a.state.epoch, a.state.reading);
        if (!bad && op.kind == OffLib.CONSUME) {
            (uint64 t, uint64 v) = OffLib.lookup(a.state, op.key);
            bad = op.version < v || op.total < op.amount || op.total - op.amount < t;
        }
        if (!bad) revert NotAViolation();
        return _slash(h.site, s, R_REGRESS);
    }

    /// Fast path: a sealed grant, hold or release of the object under rights from before an acknowledgement
    /// (epoch, reading) that runs past it. A correct ledger accepts the ACK only after the stop with no hold
    /// left, and nothing of the object under those rights afterwards; so the validators that both acknowledged
    /// and sealed the operation (at least f+1) are faulty.
    function proveUseAfterAck(
        OffLib.Header calldata h,
        bytes[] calldata seals,
        OpProof calldata o,
        uint64 ackEpoch,
        uint64 ackReading
    ) external returns (uint256) {
        address[] memory s = _sealers(h, seals);
        _contains(h, o);
        OffLib.Op calldata op = o.op;
        address[] storage ackers = ackSigners[OffLib.ackKey(op.key, h.site, ackEpoch, ackReading)];
        if (ackers.length == 0) revert BadProof();
        if (op.kind != OffLib.USE && op.kind != OffLib.RELEASE) revert NotAViolation();
        // Made under rights from before the acknowledgement (for a release: a hold started before it).
        if (OffLib.after_(op.epoch, op.base, ackEpoch, ackReading)) revert NotAViolation();
        bool late = OffLib.after_(op.epoch, op.reading, ackEpoch, ackReading)
            || (op.kind == OffLib.USE && op.until != OffLib.OPEN && op.epoch == ackEpoch && op.until > ackReading);
        if (!late) revert NotAViolation();
        return _slash(h.site, _intersect(s, ackers), R_USE_AFTER_ACK);
    }

    /// Two sealed histories of one site that differ: two checkpoints at one height, or a higher checkpoint
    /// whose history accumulator holds a different checkpoint at the lower one's height (`leaf`, with its
    /// path). Slashes the validators that sealed both (at least f+1).
    function proveFork(
        OffLib.Header calldata h1,
        bytes[] calldata seals1,
        OffLib.Header calldata h2,
        bytes[] calldata seals2,
        bytes32 leafAtH1,
        bytes32[] calldata histPath
    ) external returns (uint256) {
        if (h1.site != h2.site) revert NotAViolation();
        bytes32 hash1 = OffLib.headerHash(h1);
        if (h1.height == h2.height) {
            if (hash1 == OffLib.headerHash(h2)) revert NotAViolation();
        } else {
            if (h1.height > h2.height || !OffLib.inHistory(h2.histRoot, leafAtH1, h1.height, histPath)) {
                revert BadProof();
            }
            if (leafAtH1 == hash1) revert NotAViolation();
        }
        address[] memory a = _sealers(h1, seals1);
        address[] memory b = _sealers(h2, seals2);
        return _slash(h1.site, _intersect(a, b), R_FORK);
    }
}
