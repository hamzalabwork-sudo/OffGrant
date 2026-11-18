// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// Shared encodings for the global RightsRegistry and the per-site SiteRights contracts.
library OffLib {
    // Operation kinds recorded on a site ledger.
    uint8 internal constant CONSUME = 1; // bounded resource: key = resource, a = amount, b = running total after the op
    uint8 internal constant USE = 2;     // lease or credential: key = object, a = renewal base (clock ms), b = clock reading (ms), e = clock epoch
    uint8 internal constant LOG = 3;     // commutative record: key = payload hash

    struct Op {
        uint8 kind;
        bytes32 key;
        uint64 a;
        uint64 b;
        uint64 e; // USE only: trusted-clock epoch (TPM resetCount << 32 | restartCount); any reset expires allowances
        bytes clockSig; // USE only: trusted-clock signature over (site, epoch, reading)
    }

    /// A site checkpoint: one per batch of site-ledger operations, hash-chained.
    struct Header {
        uint64 site;
        uint64 height;
        bytes32 prev;
        bytes32 opsRoot;
        uint64 opCount;
    }

    function headerHash(Header memory h) internal pure returns (bytes32) {
        return keccak256(abi.encode(h.site, h.height, h.prev, h.opsRoot, h.opCount));
    }

    function leaf(Op memory op) internal pure returns (bytes32) {
        return keccak256(abi.encode(op.kind, op.key, op.a, op.b, op.e, keccak256(op.clockSig)));
    }

    // Domain-separated digests. `registry` is the RightsRegistry address on the global ledger.
    function checkpointDigest(address registry, bytes32 hh) internal pure returns (bytes32) {
        return keccak256(abi.encode("OFFGRANT-CKPT", registry, hh));
    }

    function clockDigest(uint64 site, uint64 epoch, uint64 reading) internal pure returns (bytes32) {
        return keccak256(abi.encode("OFFGRANT-CLOCK", site, epoch, reading));
    }

    function requestDigest(uint64 site, bytes32 object, uint64 epoch, uint64 cq) internal pure returns (bytes32) {
        return keccak256(abi.encode("OFFGRANT-REQ", site, object, epoch, cq));
    }

    function renewalKey(uint64 site, bytes32 object, uint64 epoch, uint64 cq) internal pure returns (bytes32) {
        return keccak256(abi.encode(site, object, epoch, cq));
    }

    function renewalDigest(address registry, uint64 site, bytes32 object, uint64 epoch, uint64 cq, uint64 issued)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode("OFFGRANT-RENEW", registry, site, object, epoch, cq, issued));
    }

    /// Global certificate that a site must stop using an object or credential (reassignment or revocation).
    /// It cancels every renewal up to (epoch, cq), the last one G issued to the site, so it cannot be replayed
    /// against renewals granted after a later re-assignment.
    function stopDigest(address registry, uint64 site, bytes32 object, uint64 epoch, uint64 cq)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode("OFFGRANT-STOP", registry, site, object, epoch, cq));
    }

    /// Site validators acknowledge that their ledger executed the stop at trusted-clock time (epoch, reading).
    function ackDigest(address registry, uint64 site, bytes32 object, uint64 epoch, uint64 reading)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode("OFFGRANT-ACK", registry, site, object, epoch, reading));
    }

    function shareDigest(address registry, uint64 site, bytes32 resource, uint64 amount)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode("OFFGRANT-SHARE", registry, site, resource, amount));
    }

    function leaseDigest(address registry, uint64 site, bytes32 object, uint64 allowanceMs)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode("OFFGRANT-LEASE", registry, site, object, allowanceMs));
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
    /// (odd nodes are paired with themselves).
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
        return h == root;
    }
}
