// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// Shared encodings for the global RightsRegistry and the per-site SiteRights contracts.
library OffLib {
    // Operation kinds recorded on a site ledger.
    uint8 internal constant CONSUME = 1; // bounded resource: key = resource, a = amount, b = running total, c = share version
    uint8 internal constant USE = 2; // grant of an object or credential: key = object, a = renewal base cq, b = grant
    // reading, c = end of the hold (site clock; c = b for an instantaneous use, OPEN for an open hold), e = epoch
    uint8 internal constant LOG = 3; // commutative record: key = payload hash
    uint8 internal constant RELEASE = 4; // end of an open hold: key = object, a = base cq of the hold, b = reading, e = epoch

    uint64 internal constant OPEN = type(uint64).max; // hold that lasts until it is released (e.g. a lockout)

    struct Op {
        uint8 kind;
        bytes32 key;
        uint64 a;
        uint64 b;
        uint64 c;
        uint64 e; // trusted-clock epoch (TPM resetCount << 32 | restartCount); any reset expires allowances
        bytes clockSig; // USE/RELEASE: trusted-clock attestation of (site, e, b) bound to the operation
    }

    /// A site checkpoint: one per batch of site-ledger operations, hash-chained. The trusted clock attests the
    /// closing reading (closeEpoch, closeReading) over the checkpoint's content, so the coverage a checkpoint
    /// claims cannot run ahead of the site's clock.
    /// `stateRoot` commits the running total of every resource at the close (leaves stateLeaf(resource, total)),
    /// so an understatement is always provable against one checkpoint or its parent. (`baseHeight`, `baseHash`)
    /// name the site's latest checkpoint anchored on G: a site can anchor its newest checkpoint directly after
    /// an outage of any length.
    struct Header {
        uint64 site;
        uint64 height;
        bytes32 prev;
        bytes32 opsRoot;
        uint64 opCount;
        bytes32 stateRoot;
        uint64 baseHeight;
        bytes32 baseHash;
        uint64 closeEpoch;
        uint64 closeReading;
        bytes closeSig;
    }

    function contentTag(Header memory h) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                "OFFGRANT-CLOSE", h.site, h.height, h.prev, h.opsRoot, h.opCount, h.stateRoot, h.baseHeight, h.baseHash
            )
        );
    }

    function stateLeaf(bytes32 resource, uint64 total) internal pure returns (bytes32) {
        return keccak256(abi.encode("OFFGRANT-STATE", resource, total));
    }

    function headerHash(Header memory h) internal pure returns (bytes32) {
        return keccak256(abi.encode(contentTag(h), h.closeEpoch, h.closeReading));
    }

    function leaf(Op memory op) internal pure returns (bytes32) {
        return keccak256(abi.encode(op.kind, op.key, op.a, op.b, op.c, op.e, keccak256(op.clockSig)));
    }

    function releaseTag(bytes32 object) internal pure returns (bytes32) {
        return keccak256(abi.encode("OFFGRANT-RELEASE", object));
    }

    // Domain-separated digests. `registry` is the RightsRegistry address on the global ledger.
    function checkpointDigest(address registry, bytes32 hh) internal pure returns (bytes32) {
        return keccak256(abi.encode("OFFGRANT-CKPT", registry, hh));
    }

    /// Trusted-clock attestation bound to what it is used for (`tag`), as a TPM quote's qualifying data, so a
    /// reading attested for one operation cannot be replayed for another.
    function clockDigest(uint64 site, uint64 epoch, uint64 reading, bytes32 tag) internal pure returns (bytes32) {
        return keccak256(abi.encode("OFFGRANT-CLOCK", site, epoch, reading, tag));
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
    /// It cancels every renewal up to (epoch, cq), the last one G issued to the site.
    function stopDigest(address registry, uint64 site, bytes32 object, uint64 epoch, uint64 cq)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode("OFFGRANT-STOP", registry, site, object, epoch, cq));
    }

    /// Site validators acknowledge that, at trusted-clock time (epoch, reading), their ledger had executed the
    /// stop and every hold of the object had ended.
    function ackDigest(address registry, uint64 site, bytes32 object, uint64 epoch, uint64 reading)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode("OFFGRANT-ACK", registry, site, object, epoch, reading));
    }

    /// Share certificates are versioned: a site applies only a newer version, so an old one cannot be replayed.
    function shareDigest(address registry, uint64 site, bytes32 resource, uint64 amount, uint64 version)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode("OFFGRANT-SHARE", registry, site, resource, amount, version));
    }

    /// Site validators acknowledge that their ledger applied share `version` and its running total is within it.
    function shareAckDigest(address registry, uint64 site, bytes32 resource, uint64 version)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode("OFFGRANT-SHARE-ACK", registry, site, resource, version));
    }

    function leaseDigest(address registry, uint64 site, bytes32 object, uint64 allowanceMs, bool openHold)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode("OFFGRANT-LEASE", registry, site, object, allowanceMs, openHold));
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
