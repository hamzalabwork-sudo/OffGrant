// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// Shared encodings for the global RightsRegistry and the per-site SiteRights contracts (version 6).
///
/// Every message is domain-separated by `dom = keccak256("OFFGRANT-v6", chainid, registry)`, so signatures and
/// clock attestations cannot be replayed across deployments or chains.
library OffLib {
    // Operation kinds recorded on a site ledger.
    uint8 internal constant CONSUME = 1; // key = resource; amount, total (running), version (share)
    uint8 internal constant USE = 2; // grant: key = object, base = renewal cq, reading, until = hold end or OPEN;
    // for an open hold: amount = crew id, total = running number of open holds ever applied to the object
    uint8 internal constant LOG = 3; // commutative record: key = payload hash (not attested)
    uint8 internal constant RELEASE = 4; // end of an open hold: key = object, base = hold id (the grant's reading),
    // until = the grant's epoch, amount = crew id, total = running number of releases of the object
    uint8 internal constant ACK = 5; // acknowledgement of a stop: key = object, base = cq of the stopped renewal,
    // amount = open holds ever applied, total = releases (equal on a correct ledger: nothing is held)
    uint8 internal constant SHARE = 6; // a share certificate applied: key = resource, amount, version (not attested)

    uint64 internal constant OPEN = type(uint64).max; // hold that lasts until it is released (e.g. a lockout)
    uint256 internal constant HIST_DEPTH = 32; // history accumulator: 2^32 heights (> 800 years at 6 s)
    uint256 internal constant MAX_STATE = 64; // at most 64 resources and objects in a committed state

    struct Op {
        uint8 kind;
        bytes32 key;
        uint64 epoch; // trusted-clock epoch (TPM resetCount << 32 | restartCount); 0 for LOG and SHARE
        uint64 reading; // trusted-clock reading (ms); 0 for LOG and SHARE
        uint64 base;
        uint64 until;
        uint64 amount;
        uint64 total;
        uint64 version;
        bytes clockSig; // attestation of (site, epoch, reading, opTag(op)) by the site's trusted clock
    }

    /// A site checkpoint. `histRoot` is the root of a depth-HIST_DEPTH Merkle tree whose leaf i is the hash of the
    /// site's checkpoint at height i, for every i < height (zero elsewhere). `stateHash` commits the state after
    /// the checkpoint's last operation, which has `stateLen` entries. `tip` is the hash of the last site block
    /// covered. The trusted clock attests (closeEpoch, closeReading) over the content.
    struct Header {
        uint64 site;
        uint64 height;
        bytes32 histRoot;
        bytes32 opsRoot;
        uint64 opCount;
        bytes32 stateHash;
        uint64 stateLen;
        bytes32 tip;
        uint64 closeEpoch;
        uint64 closeReading;
        bytes closeSig;
    }

    /// Site state after a checkpoint: the newest attested reading; for every resource (strictly increasing keys)
    /// its running total and applied share version; for every object with open holds (strictly increasing keys)
    /// the number of open holds ever applied and of releases. Missing entries count as zero.
    struct State {
        uint64 epoch;
        uint64 reading;
        bytes32[] resources;
        uint64[] totals;
        uint64[] versions;
        bytes32[] objects;
        uint64[] opens;
        uint64[] releases;
    }

    function domain(address registry, uint256 chainId) internal pure returns (bytes32) {
        return keccak256(abi.encode("OFFGRANT-v6", chainId, registry));
    }

    function contentTag(Header memory h) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                "OFFGRANT-CLOSE", h.site, h.height, h.histRoot, h.opsRoot, h.opCount, h.stateHash, h.stateLen, h.tip
            )
        );
    }

    function headerHash(Header memory h) internal pure returns (bytes32) {
        return keccak256(abi.encode(contentTag(h), h.closeEpoch, h.closeReading));
    }

    function stateHash(State memory s) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                "OFFGRANT-STATE", s.epoch, s.reading, s.resources, s.totals, s.versions, s.objects, s.opens, s.releases
            )
        );
    }

    function stateLen(State memory s) internal pure returns (uint256) {
        return s.resources.length + s.objects.length;
    }

    /// Whether a state is well formed: equal lengths, strictly increasing keys, no more releases than holds.
    function wellFormed(State memory s) internal pure returns (bool) {
        uint256 n = s.resources.length;
        if (s.totals.length != n || s.versions.length != n) return false;
        for (uint256 i = 1; i < n; i++) {
            if (s.resources[i] <= s.resources[i - 1]) return false;
        }
        uint256 m = s.objects.length;
        if (s.opens.length != m || s.releases.length != m) return false;
        for (uint256 i = 0; i < m; i++) {
            if (s.releases[i] > s.opens[i] || (i > 0 && s.objects[i] <= s.objects[i - 1])) return false;
        }
        return true;
    }

    /// (total, version) of a resource in a state; (0, 0) when absent.
    function lookup(State memory s, bytes32 resource) internal pure returns (uint64 total, uint64 version) {
        for (uint256 i = 0; i < s.resources.length; i++) {
            if (s.resources[i] == resource) return (s.totals[i], s.versions[i]);
        }
    }

    /// (opens, releases) of an object in a state; (0, 0) when absent.
    function lookupObj(State memory s, bytes32 object) internal pure returns (uint64 opens, uint64 releases) {
        for (uint256 i = 0; i < s.objects.length; i++) {
            if (s.objects[i] == object) return (s.opens[i], s.releases[i]);
        }
    }

    /// What the trusted clock attests for an operation: everything except the derived running total.
    function opTag(Op memory op) internal pure returns (bytes32) {
        return keccak256(abi.encode("OFFGRANT-OP", op.kind, op.key, op.base, op.until, op.amount, op.version));
    }

    function attested(uint8 kind) internal pure returns (bool) {
        return kind == CONSUME || kind == USE || kind == RELEASE || kind == ACK;
    }

    /// Whether an operation is a lock counter: an open-hold grant, a release, or an acknowledgement.
    function lockCounter(Op memory op) internal pure returns (bool) {
        return (op.kind == USE && op.until == OPEN) || op.kind == RELEASE || op.kind == ACK;
    }

    function leaf(Op memory op) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                op.kind,
                op.key,
                op.epoch,
                op.reading,
                op.base,
                op.until,
                op.amount,
                op.total,
                op.version,
                keccak256(op.clockSig)
            )
        );
    }

    /// (e1, r1) strictly after (e2, r2) in (epoch, reading) order.
    function after_(uint64 e1, uint64 r1, uint64 e2, uint64 r2) internal pure returns (bool) {
        return e1 > e2 || (e1 == e2 && r1 > r2);
    }

    // ---------------------------------------------------------------- domain-separated digests
    function checkpointDigest(bytes32 dom, bytes32 hh) internal pure returns (bytes32) {
        return keccak256(abi.encode("OFFGRANT-CKPT", dom, hh));
    }

    /// Trusted-clock attestation, as a TPM quote's qualifying data: binds the reading to one operation (or a
    /// checkpoint close, or a renewal request) of one site in one deployment.
    function clockDigest(bytes32 dom, uint64 site, uint64 epoch, uint64 reading, bytes32 tag)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode("OFFGRANT-CLOCK", dom, site, epoch, reading, tag));
    }

    function objectsHash(bytes32[] memory objects) internal pure returns (bytes32) {
        return keccak256(abi.encode(objects));
    }

    /// A renewal request for a batch of objects, attested by the site clock when it is SENT.
    function requestTag(bytes32 objs) internal pure returns (bytes32) {
        return keccak256(abi.encode("OFFGRANT-REQ", objs));
    }

    function renewalKey(uint64 site, bytes32 object, uint64 epoch, uint64 cq) internal pure returns (bytes32) {
        return keccak256(abi.encode(site, object, epoch, cq));
    }

    function renewalDigest(bytes32 dom, uint64 site, bytes32 objs, uint64 epoch, uint64 cq, uint64 issued)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode("OFFGRANT-RENEW", dom, site, objs, epoch, cq, issued));
    }

    /// Global certificate that a site must stop using an object or credential (reassignment or revocation).
    /// It cancels every renewal up to (epoch, cq), the last one G issued to the site.
    function stopDigest(bytes32 dom, uint64 site, bytes32 object, uint64 epoch, uint64 cq)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode("OFFGRANT-STOP", dom, site, object, epoch, cq));
    }

    /// Site validators acknowledge that the ACK operation at trusted-clock time (epoch, reading) is in a
    /// checkpoint they sealed (the ledger accepts it only after the stop, with no hold of the object left).
    function ackDigest(bytes32 dom, uint64 site, bytes32 object, uint64 epoch, uint64 reading)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode("OFFGRANT-ACK", dom, site, object, epoch, reading));
    }

    function ackKey(bytes32 object, uint64 site, uint64 epoch, uint64 reading) internal pure returns (bytes32) {
        return keccak256(abi.encode(object, site, epoch, reading));
    }

    /// Share certificates are versioned: a site applies only a newer version, so an old one cannot be replayed.
    function shareDigest(bytes32 dom, uint64 site, bytes32 resource, uint64 amount, uint64 version)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode("OFFGRANT-SHARE", dom, site, resource, amount, version));
    }

    function leaseDigest(bytes32 dom, uint64 site, bytes32 object, uint64 allowanceMs, bool openHold)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode("OFFGRANT-LEASE", dom, site, object, allowanceMs, openHold));
    }

    /// ecrecover with low-s and length checks; returns address(0) on any malformed signature.
    function recover(bytes32 digest, bytes memory sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) return address(0);
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        return ecrecover(digest, v, r, s);
    }

    /// Verifies that `leafHash` is the `index`-th leaf of a binary Merkle tree with root `root`
    /// (odd nodes are paired with themselves in the operations tree; the history tree has fixed depth).
    function verifyLeaf(bytes32 root, bytes32 leafHash, uint256 index, bytes32[] memory proof)
        internal
        pure
        returns (bool)
    {
        bytes32 h = leafHash;
        for (uint256 i = 0; i < proof.length; i++) {
            h = (index & 1) == 0 ? keccak256(abi.encode(h, proof[i])) : keccak256(abi.encode(proof[i], h));
            index >>= 1;
        }
        return h == root && index == 0;
    }

    /// Inclusion in a history accumulator (fixed depth).
    function inHistory(bytes32 histRoot, bytes32 leafHash, uint64 height, bytes32[] memory proof)
        internal
        pure
        returns (bool)
    {
        return proof.length == HIST_DEPTH && verifyLeaf(histRoot, leafHash, height, proof);
    }
}
