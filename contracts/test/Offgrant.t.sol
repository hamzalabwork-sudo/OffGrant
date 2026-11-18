// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {OffLib} from "../src/OffLib.sol";
import {RightsRegistry} from "../src/RightsRegistry.sol";
import {SiteRights} from "../src/SiteRights.sol";

/// Tests for the v6 contracts. Every exploit reported against v4 and v5 has a regression test (named *_v4exploit
/// or *_v5exploit), and every proof function has both a violation test and a no-framing test on honest input.
contract OffgrantTest is Test {
    RightsRegistry reg;
    SiteRights siteC;
    bytes32 dom;

    uint64 constant SITE = 1;
    uint64 constant SITE2 = 2;
    uint32 constant RHO = 100; // ppm
    uint32 constant SLACK = 2; // s
    uint256[4] vk = [uint256(0xA1), 0xA2, 0xA3, 0xA4];
    address[4] va;
    uint256 constant CLOCK = 0xC1;
    uint256 constant CLOCK2 = 0xC2;
    uint256[3] gk = [uint256(0xB1), 0xB2, 0xB3];

    bytes32 constant PARTS = keccak256("spare-parts");
    bytes32 constant PERMIT = keccak256("switching-window:feeder-7");
    bytes32 constant LOTO = keccak256("isolation:pump-7");
    bytes32 constant CRED = keccak256("credential:operator-17");
    uint64 constant A = 99_000; // allowance, ms
    uint64 constant EPOCH = 1; // trusted-clock epoch (TPM resetCount/restartCount)
    uint64 constant LAG = 60_000; // anchor lag (ms)
    uint64 constant START = 5_000; // site clock reading at registration
    uint256 constant D = 32; // history depth

    bytes32[33] zeros;

    function setUp() public {
        vm.warp(1_000_000);
        reg = new RightsRegistry(RHO, SLACK, LAG);
        dom = reg.dom();
        address[] memory vs = new address[](4);
        for (uint256 i = 0; i < 4; i++) {
            va[i] = vm.addr(vk[i]);
            vs[i] = va[i];
        }
        reg.registerSite(SITE, 1, vm.addr(CLOCK), vs, EPOCH, START);
        address[] memory vs2 = new address[](4);
        for (uint256 i = 0; i < 4; i++) {
            vs2[i] = vm.addr(0xD1 + i);
        }
        reg.registerSite(SITE2, 1, vm.addr(CLOCK2), vs2, EPOCH, START);
        reg.setCap(PARTS, 100);
        reg.setShare(PARTS, SITE, 40); // version 1
        reg.setShare(PARTS, SITE2, 60);
        reg.createLease(PERMIT, true, false, A);
        reg.permit(PERMIT, SITE);
        reg.createLease(LOTO, true, true, A);
        reg.permit(LOTO, SITE);
        reg.createLease(CRED, false, false, A);
        reg.permit(CRED, SITE);
        reg.permit(CRED, SITE2);

        address[] memory auth = new address[](3);
        for (uint256 i = 0; i < 3; i++) {
            auth[i] = vm.addr(gk[i]);
        }
        siteC = new SiteRights(SITE, address(reg), block.chainid, vm.addr(CLOCK), auth, 2);
        for (uint256 d = 0; d < D; d++) {
            zeros[d + 1] = keccak256(abi.encode(zeros[d], zeros[d]));
        }
    }

    // ------------------------------------------------------------ signing helpers
    function _sig(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    function _cert(bytes32 d) internal view returns (bytes[] memory s) {
        s = new bytes[](2);
        s[0] = _sig(gk[0], d);
        s[1] = _sig(gk[2], d);
    }

    function _who(uint256 a, uint256 b, uint256 c) internal pure returns (uint256[] memory w) {
        w = new uint256[](3);
        (w[0], w[1], w[2]) = (a, b, c);
    }

    function _signAll(bytes32 d, uint256[] memory who) internal view returns (bytes[] memory s) {
        s = new bytes[](who.length);
        for (uint256 i = 0; i < who.length; i++) {
            s[i] = _sig(vk[who[i]], d);
        }
    }

    function _seal(OffLib.Header memory h, uint256[] memory who) internal view returns (bytes[] memory) {
        return _signAll(OffLib.checkpointDigest(dom, OffLib.headerHash(h)), who);
    }

    // ------------------------------------------------------------ operations
    function _att(OffLib.Op memory op) internal view returns (OffLib.Op memory) {
        op.clockSig = _sig(CLOCK, OffLib.clockDigest(dom, SITE, op.epoch, op.reading, OffLib.opTag(op)));
        return op;
    }

    function _consume(uint64 amount, uint64 total, uint64 version, uint64 reading)
        internal
        view
        returns (OffLib.Op memory)
    {
        return _att(OffLib.Op(OffLib.CONSUME, PARTS, EPOCH, reading, 0, 0, amount, total, version, ""));
    }

    /// A bounded grant (or a credential use).
    function _grant(bytes32 obj, uint64 epoch, uint64 cq, uint64 reading, uint64 until)
        internal
        view
        returns (OffLib.Op memory)
    {
        return _att(OffLib.Op(OffLib.USE, obj, epoch, reading, cq, until, 0, 0, 0, ""));
    }

    /// An open hold by `crew`, the `n`-th ever applied to the object.
    function _lock(bytes32 obj, uint64 cq, uint64 reading, uint64 crew, uint64 n) internal view returns (OffLib.Op memory) {
        return _att(OffLib.Op(OffLib.USE, obj, EPOCH, reading, cq, OffLib.OPEN, crew, n, 0, ""));
    }

    /// Release of hold `holdId` (granted in EPOCH) by `crew`, the `n`-th release of the object.
    function _release(bytes32 obj, uint64 holdId, uint64 crew, uint64 reading, uint64 n)
        internal
        view
        returns (OffLib.Op memory)
    {
        return _att(OffLib.Op(OffLib.RELEASE, obj, EPOCH, reading, holdId, EPOCH, crew, n, 0, ""));
    }

    function _ackOp(bytes32 obj, uint64 cq, uint64 reading, uint64 opens, uint64 rels)
        internal
        view
        returns (OffLib.Op memory)
    {
        return _att(OffLib.Op(OffLib.ACK, obj, EPOCH, reading, cq, 0, opens, rels, 0, ""));
    }

    function _log(bytes32 k) internal pure returns (OffLib.Op memory) {
        return OffLib.Op(OffLib.LOG, k, 0, 0, 0, 0, 0, 0, 0, "");
    }

    function _shareOp(uint64 amount, uint64 total, uint64 version) internal pure returns (OffLib.Op memory) {
        return OffLib.Op(OffLib.SHARE, PARTS, 0, 0, 0, 0, amount, total, version, "");
    }

    function _ops1(OffLib.Op memory a) internal pure returns (OffLib.Op[] memory o) {
        o = new OffLib.Op[](1);
        o[0] = a;
    }

    function _ops2(OffLib.Op memory a, OffLib.Op memory b) internal pure returns (OffLib.Op[] memory o) {
        o = new OffLib.Op[](2);
        (o[0], o[1]) = (a, b);
    }

    // ------------------------------------------------------------ states
    function _empty(uint64 reading) internal pure returns (OffLib.State memory s) {
        s.epoch = EPOCH;
        s.reading = reading;
        s.resources = new bytes32[](0);
        s.totals = new uint64[](0);
        s.versions = new uint64[](0);
        s.objects = new bytes32[](0);
        s.opens = new uint64[](0);
        s.releases = new uint64[](0);
    }

    function _st(uint64 reading, uint64 total, uint64 version) internal pure returns (OffLib.State memory s) {
        s = _empty(reading);
        s.resources = new bytes32[](1);
        s.totals = new uint64[](1);
        s.versions = new uint64[](1);
        (s.resources[0], s.totals[0], s.versions[0]) = (PARTS, total, version);
    }

    function _stLocks(uint64 reading, bytes32 obj, uint64 opens, uint64 rels) internal pure returns (OffLib.State memory s) {
        s = _empty(reading);
        s.objects = new bytes32[](1);
        s.opens = new uint64[](1);
        s.releases = new uint64[](1);
        (s.objects[0], s.opens[0], s.releases[0]) = (obj, opens, rels);
    }

    // ------------------------------------------------------------ Merkle trees
    function _root(bytes32[] memory leaves) internal pure returns (bytes32) {
        if (leaves.length == 0) return bytes32(0);
        bytes32[] memory lvl = leaves;
        while (lvl.length > 1) {
            bytes32[] memory up = new bytes32[]((lvl.length + 1) / 2);
            for (uint256 i = 0; i < up.length; i++) {
                bytes32 l = lvl[2 * i];
                bytes32 r = 2 * i + 1 < lvl.length ? lvl[2 * i + 1] : l;
                up[i] = keccak256(abi.encode(l, r));
            }
            lvl = up;
        }
        return lvl[0];
    }

    function _path(bytes32[] memory leaves, uint256 idx) internal pure returns (bytes32[] memory p) {
        uint256 depth;
        for (uint256 n = leaves.length; n > 1; n = (n + 1) / 2) depth++;
        p = new bytes32[](depth);
        bytes32[] memory lvl = leaves;
        for (uint256 d = 0; d < depth; d++) {
            uint256 sib = idx ^ 1;
            p[d] = sib < lvl.length ? lvl[sib] : lvl[idx];
            bytes32[] memory up = new bytes32[]((lvl.length + 1) / 2);
            for (uint256 i = 0; i < up.length; i++) {
                bytes32 l = lvl[2 * i];
                bytes32 r = 2 * i + 1 < lvl.length ? lvl[2 * i + 1] : l;
                up[i] = keccak256(abi.encode(l, r));
            }
            lvl = up;
            idx >>= 1;
        }
    }

    /// History accumulator: leaf i = hash of the checkpoint at height i (leaf 0 is zero), depth 32.
    function _histRoot(bytes32[] memory hist) internal view returns (bytes32) {
        bytes32[] memory lvl = hist;
        for (uint256 d = 0; d < D; d++) {
            uint256 n = (lvl.length + 1) / 2;
            if (n == 0) return zeros[D];
            bytes32[] memory up = new bytes32[](n);
            for (uint256 i = 0; i < n; i++) {
                bytes32 r = 2 * i + 1 < lvl.length ? lvl[2 * i + 1] : zeros[d];
                up[i] = keccak256(abi.encode(lvl[2 * i], r));
            }
            lvl = up;
        }
        return lvl[0];
    }

    function _histPath(bytes32[] memory hist, uint256 idx) internal view returns (bytes32[] memory p) {
        p = new bytes32[](D);
        bytes32[] memory lvl = hist;
        for (uint256 d = 0; d < D; d++) {
            uint256 sib = idx ^ 1;
            p[d] = sib < lvl.length ? lvl[sib] : zeros[d];
            uint256 n = (lvl.length + 1) / 2;
            bytes32[] memory up = new bytes32[](n);
            for (uint256 i = 0; i < n; i++) {
                bytes32 r = 2 * i + 1 < lvl.length ? lvl[2 * i + 1] : zeros[d];
                up[i] = keccak256(abi.encode(lvl[2 * i], r));
            }
            lvl = up;
            idx >>= 1;
        }
    }

    /// A checkpoint at height hist.length whose history is `hist` (hist[0] = 0).
    function _ckpt(bytes32[] memory hist, OffLib.Op[] memory ops, OffLib.State memory st, uint64 closeR)
        internal
        view
        returns (OffLib.Header memory h)
    {
        bytes32[] memory leaves = new bytes32[](ops.length);
        for (uint256 i = 0; i < ops.length; i++) {
            leaves[i] = OffLib.leaf(ops[i]);
        }
        h = OffLib.Header(
            SITE,
            uint64(hist.length),
            _histRoot(hist),
            _root(leaves),
            uint64(ops.length),
            OffLib.stateHash(st),
            uint64(OffLib.stateLen(st)),
            bytes32(uint256(0xB10C)),
            EPOCH,
            closeR,
            ""
        );
        h.closeSig = _sig(CLOCK, OffLib.clockDigest(dom, SITE, EPOCH, closeR, OffLib.contentTag(h)));
    }

    function _op(OffLib.Op[] memory ops, uint256 i) internal pure returns (RightsRegistry.OpProof memory) {
        bytes32[] memory leaves = new bytes32[](ops.length);
        for (uint256 k = 0; k < ops.length; k++) {
            leaves[k] = OffLib.leaf(ops[k]);
        }
        return RightsRegistry.OpProof(ops[i], i, _path(leaves, i));
    }

    function _hist1() internal pure returns (bytes32[] memory h) {
        h = new bytes32[](1); // height 1: no earlier checkpoint
    }

    function _push(bytes32[] memory hist, OffLib.Header memory h) internal pure returns (bytes32[] memory out) {
        out = new bytes32[](hist.length + 1);
        for (uint256 i = 0; i < hist.length; i++) {
            out[i] = hist[i];
        }
        out[hist.length] = OffLib.headerHash(h);
    }

    function _anc(bytes32[] memory histOfChild, OffLib.Header memory p, OffLib.State memory s)
        internal
        view
        returns (RightsRegistry.Ancestor memory)
    {
        return RightsRegistry.Ancestor(p, s, _histPath(histOfChild, p.height));
    }

    // ------------------------------------------------------------ protocol helpers
    function _objs(bytes32 o) internal pure returns (bytes32[] memory a) {
        a = new bytes32[](1);
        a[0] = o;
    }

    function _renewE(bytes32[] memory objs, uint64 epoch, uint64 cq) internal returns (uint64 issued) {
        bytes32 tag = OffLib.requestTag(OffLib.objectsHash(objs));
        issued = reg.renew(SITE, objs, epoch, cq, _sig(CLOCK, OffLib.clockDigest(dom, SITE, epoch, cq, tag)));
    }

    function _renew(bytes32 o, uint64 cq) internal returns (uint64) {
        return _renewE(_objs(o), EPOCH, cq);
    }

    /// Renews on G and applies the certified renewal on the site ledger.
    function _renewSite(bytes32 o, uint64 cq) internal {
        uint64 issued = _renew(o, cq);
        bytes32[] memory objs = _objs(o);
        siteC.applyRenewal(
            objs, EPOCH, cq, issued, _cert(OffLib.renewalDigest(dom, SITE, OffLib.objectsHash(objs), EPOCH, cq, issued))
        );
    }

    function _provision() internal {
        siteC.applyShare(PARTS, 40, 1, _cert(OffLib.shareDigest(dom, SITE, PARTS, 40, 1)));
        siteC.applyLease(PERMIT, A, false, _cert(OffLib.leaseDigest(dom, SITE, PERMIT, A, false)));
        siteC.applyLease(LOTO, A, true, _cert(OffLib.leaseDigest(dom, SITE, LOTO, A, true)));
        siteC.applyLease(CRED, A, false, _cert(OffLib.leaseDigest(dom, SITE, CRED, A, false)));
    }

    function _siteUse(bytes32 obj, uint64 cq, uint64 reading, uint64 until) internal {
        OffLib.Op memory op = _grant(obj, EPOCH, cq, reading, until);
        siteC.use(obj, cq, EPOCH, reading, until, 0, op.clockSig);
    }

    function _siteLock(bytes32 obj, uint64 cq, uint64 reading, uint64 crew) internal {
        OffLib.Op memory op = _lock(obj, cq, reading, crew, 0);
        siteC.use(obj, cq, EPOCH, reading, OffLib.OPEN, crew, op.clockSig);
    }

    function _siteRelease(bytes32 obj, uint64 holdId, uint64 crew, uint64 reading) internal {
        OffLib.Op memory op = _release(obj, holdId, crew, reading, 0);
        siteC.release(obj, holdId, crew, EPOCH, reading, op.clockSig);
    }

    function _siteStop(bytes32 obj, uint64 cq) internal {
        siteC.applyStop(obj, EPOCH, cq, _cert(OffLib.stopDigest(dom, SITE, obj, EPOCH, cq)));
    }

    function _acks(bytes32 obj, uint64 reading) internal view returns (bytes[] memory) {
        return _signAll(OffLib.ackDigest(dom, SITE, obj, EPOCH, reading), _who(0, 1, 2));
    }

    /// Full fast path: the site records an ACK operation, three validators sign, G moves the object.
    function _fastPath(bytes32 obj, uint64 stopCq, uint64 reading) internal {
        uint64 n = siteC.opens(obj);
        OffLib.Op memory ack = _ackOp(obj, stopCq, reading, n, n);
        siteC.acknowledge(obj, EPOCH, reading, ack.clockSig);
        reg.reassignAcked(obj, EPOCH, reading, n, ack.clockSig, _acks(obj, reading));
    }

    /// G-side fast path only (the site ledger is not modelled).
    function _ackOnG(bytes32 obj, uint64 stopCq, uint64 reading) internal {
        OffLib.Op memory ack = _ackOp(obj, stopCq, reading, 0, 0);
        reg.reassignAcked(obj, EPOCH, reading, 0, ack.clockSig, _acks(obj, reading));
    }

    function _site(uint64 s) internal view returns (uint64 ah, uint64 ce, uint64 cr, bool revoked, bool retired) {
        (, revoked,,,,, ah,, ce, cr, retired) = reg.sites(s);
    }

    // ============================================================ leases and renewals (Proposition 1)
    function testFuzz_waitFormula(uint64 aMs) public {
        aMs = uint64(bound(aMs, 1, 10 days * 1000));
        reg.createLease(keccak256("x"), true, false, aMs);
        uint256 w = reg.waitSeconds(keccak256("x"));
        uint256 den = uint256(1_000_000 - RHO) * 1000;
        uint256 expect = (uint256(aMs) * 1_000_000 + den - 1) / den + 2 * SLACK; // ceil(A/(1-rho)) + 2 eps_G
        assertEq(w, expect);
    }

    function test_batchRenewalOneTransaction() public {
        bytes32[] memory objs = new bytes32[](2);
        (objs[0], objs[1]) = (PERMIT, CRED);
        uint64 issued = _renewE(objs, EPOCH, 10_000);
        assertEq(reg.renewalIssued(OffLib.renewalKey(SITE, PERMIT, EPOCH, 10_000)), issued);
        assertEq(reg.renewalIssued(OffLib.renewalKey(SITE, CRED, EPOCH, 10_000)), issued);
    }

    function test_staleRequestRejected() public {
        _renew(PERMIT, 10_000);
        vm.expectRevert(RightsRegistry.StaleRequest.selector);
        _renew(PERMIT, 9_000); // replay of an older valid request
    }

    function test_renewNeedsCoverageInEpoch() public {
        vm.expectRevert(abi.encodeWithSelector(RightsRegistry.AnchorDebt.selector, START, START + 1));
        _renew(PERMIT, START + LAG + 1);
        bytes32 tag = OffLib.requestTag(OffLib.objectsHash(_objs(PERMIT)));
        bytes memory s = _sig(CLOCK, OffLib.clockDigest(dom, SITE, 2, 10_000, tag));
        vm.expectRevert(abi.encodeWithSelector(RightsRegistry.AnchorDebt.selector, START, 0));
        reg.renew(SITE, _objs(PERMIT), 2, 10_000, s); // a new epoch needs a new-epoch anchor
    }

    function test_requestFromOtherDeploymentRejected() public {
        RightsRegistry other = new RightsRegistry(RHO, SLACK, LAG);
        bytes32 tag = OffLib.requestTag(OffLib.objectsHash(_objs(PERMIT)));
        bytes memory s = _sig(CLOCK, OffLib.clockDigest(other.dom(), SITE, EPOCH, 10_000, tag));
        vm.expectRevert(RightsRegistry.BadClockSig.selector);
        reg.renew(SITE, _objs(PERMIT), EPOCH, 10_000, s);
    }

    function test_slowPathWaitsW() public {
        _renew(PERMIT, 10_000);
        reg.stop(PERMIT, SITE2);
        uint64 at = reg.releaseAt(PERMIT);
        vm.expectRevert(abi.encodeWithSelector(RightsRegistry.TooEarly.selector, at));
        reg.reassign(PERMIT);
        vm.warp(at);
        reg.reassign(PERMIT);
        (,,,,,, uint64 holder,) = reg.leases(PERMIT);
        assertEq(holder, SITE2);
    }

    function test_openHoldNeverMovedByExpiry() public {
        _renew(LOTO, 10_000);
        reg.stop(LOTO, SITE2);
        vm.warp(block.timestamp + 10 days);
        vm.expectRevert(RightsRegistry.HoldMayBeOpen.selector);
        reg.reassign(LOTO);
    }

    function test_badRegistrationsRejected() public {
        address[] memory vs = new address[](4);
        for (uint256 i = 0; i < 4; i++) {
            vs[i] = vm.addr(0xE1 + i);
        }
        vm.expectRevert(RightsRegistry.BadSite.selector);
        reg.registerSite(0, 1, vm.addr(CLOCK), vs, EPOCH, START); // site 0 is the "no holder" sentinel
        vs[2] = address(0);
        vm.expectRevert(RightsRegistry.BadSite.selector);
        reg.registerSite(3, 1, vm.addr(CLOCK), vs, EPOCH, START);
        vm.expectRevert(RightsRegistry.BadLease.selector);
        reg.createLease(keccak256("y"), false, true, A); // open holds only for exclusive objects
        vm.expectRevert(RightsRegistry.BadSite.selector);
        reg.stop(PERMIT, 0); // an exclusive object needs a next holder
    }

    function test_credentialRevocation() public {
        _provision();
        _renewSite(CRED, 10_000);
        _siteUse(CRED, 10_000, 11_000, 11_500);
        reg.stop(CRED, 0);
        vm.expectRevert(RightsRegistry.LeaseStopped.selector);
        _renew(CRED, 12_000);
        _siteStop(CRED, 10_000);
        OffLib.Op memory op = _grant(CRED, EPOCH, 10_000, 12_500, 13_000);
        vm.expectRevert(SiteRights.NoRenewal.selector);
        siteC.use(CRED, 10_000, EPOCH, 12_500, 13_000, 0, op.clockSig);
    }

    // ============================================================ site ledger rules
    function test_grantInsideAllowanceOnly() public {
        _provision();
        _renewSite(PERMIT, 10_000);
        _siteUse(PERMIT, 10_000, 11_000, 16_000);
        OffLib.Op memory late = _grant(PERMIT, EPOCH, 10_000, 12_000, 10_000 + A); // ends at cq + A
        vm.expectRevert(abi.encodeWithSelector(SiteRights.AllowanceExpired.selector, 10_000 + A, 10_000 + A));
        siteC.use(PERMIT, 10_000, EPOCH, 12_000, 10_000 + A, 0, late.clockSig);
        OffLib.Op memory zero = _grant(PERMIT, EPOCH, 10_000, 13_000, 13_000);
        vm.expectRevert(SiteRights.BadHold.selector);
        siteC.use(PERMIT, 10_000, EPOCH, 13_000, 13_000, 0, zero.clockSig);
    }

    function test_attestationBindsContent_v4exploit() public {
        _provision();
        _renewSite(PERMIT, 10_000);
        OffLib.Op memory g = _grant(PERMIT, EPOCH, 10_000, 11_000, 12_000);
        vm.expectRevert(SiteRights.BadClockSig.selector); // the same attestation with a longer hold
        siteC.use(PERMIT, 10_000, EPOCH, 11_000, 50_000, 0, g.clockSig);
    }

    /// v4: a faulty operator replayed crew 1's release; the open-hold count fell to 0 while crew 2's lock was on.
    function test_releaseReplayRejected_v4exploit() public {
        _provision();
        _renewSite(LOTO, 10_000);
        _siteLock(LOTO, 10_000, 11_000, 1); // crew 1
        _siteLock(LOTO, 10_000, 11_500, 2); // crew 2
        _siteRelease(LOTO, 11_000, 1, 12_000);
        OffLib.Op memory r = _release(LOTO, 11_000, 1, 12_000, 0);
        vm.expectRevert(SiteRights.NotHeld.selector);
        siteC.release(LOTO, 11_000, 1, EPOCH, 12_000, r.clockSig); // replay: that hold is gone
        OffLib.Op memory r2 = _release(LOTO, 11_500, 2, 12_000, 0);
        vm.expectRevert(SiteRights.StaleReading.selector);
        siteC.release(LOTO, 11_500, 2, EPOCH, 12_000, r2.clockSig); // equal reading
        assertEq(siteC.openCount(LOTO), 1);
        _siteStop(LOTO, 10_000);
        OffLib.Op memory ack = _ackOp(LOTO, 10_000, 13_000, 2, 1);
        vm.expectRevert(SiteRights.StillHeld.selector);
        siteC.acknowledge(LOTO, EPOCH, 13_000, ack.clockSig);
    }

    /// v5: a lock could be released by anyone with an attestation; now only the crew that applied it.
    function test_releaseOnlyByItsCrew_v5exploit() public {
        _provision();
        _renewSite(LOTO, 10_000);
        _siteLock(LOTO, 10_000, 11_000, 7);
        OffLib.Op memory wrong = _release(LOTO, 11_000, 8, 12_000, 0);
        vm.expectRevert(SiteRights.NotHeld.selector);
        siteC.release(LOTO, 11_000, 8, EPOCH, 12_000, wrong.clockSig);
        _siteRelease(LOTO, 11_000, 7, 12_500);
        assertEq(siteC.openCount(LOTO), 0);
    }

    function test_acknowledgeNeedsStopAndNoHold() public {
        _provision();
        _renewSite(PERMIT, 10_000);
        _siteUse(PERMIT, 10_000, 11_000, 20_000);
        OffLib.Op memory early = _ackOp(PERMIT, 0, 12_000, 0, 0);
        vm.expectRevert(SiteRights.NotStopped.selector);
        siteC.acknowledge(PERMIT, EPOCH, 12_000, early.clockSig);
        _siteStop(PERMIT, 10_000);
        OffLib.Op memory busy = _ackOp(PERMIT, 10_000, 15_000, 0, 0);
        vm.expectRevert(SiteRights.StillHeld.selector);
        siteC.acknowledge(PERMIT, EPOCH, 15_000, busy.clockSig);
        OffLib.Op memory ok = _ackOp(PERMIT, 10_000, 20_000, 0, 0);
        siteC.acknowledge(PERMIT, EPOCH, 20_000, ok.clockSig);
        OffLib.Op memory g = _grant(PERMIT, EPOCH, 10_000, 21_000, 22_000); // nothing under the stopped renewal
        vm.expectRevert(SiteRights.NoRenewal.selector);
        siteC.use(PERMIT, 10_000, EPOCH, 21_000, 22_000, 0, g.clockSig);
    }

    function test_newEpochEndsBoundedHolds() public {
        _provision();
        _renewSite(PERMIT, 10_000);
        _siteUse(PERMIT, 10_000, 11_000, 90_000);
        _siteStop(PERMIT, 10_000);
        OffLib.Op memory ack = _att(OffLib.Op(OffLib.ACK, PERMIT, 2, 1_000, 10_000, 0, 0, 0, 0, ""));
        siteC.acknowledge(PERMIT, 2, 1_000, ack.clockSig); // after a power loss the bounded hold has ended
    }

    function test_shareVersionedAndAttested() public {
        siteC.applyShare(PARTS, 40, 1, _cert(OffLib.shareDigest(dom, SITE, PARTS, 40, 1)));
        OffLib.Op memory c = _consume(30, 0, 1, 11_000);
        siteC.consume(PARTS, 30, 1, EPOCH, 11_000, c.clockSig);
        bytes[] memory lower = _cert(OffLib.shareDigest(dom, SITE, PARTS, 20, 2));
        vm.expectRevert(abi.encodeWithSelector(SiteRights.OverShare.selector, 30, 20));
        siteC.applyShare(PARTS, 20, 2, lower);
        bytes[] memory old = _cert(OffLib.shareDigest(dom, SITE, PARTS, 40, 1));
        vm.expectRevert(SiteRights.StaleShare.selector);
        siteC.applyShare(PARTS, 40, 1, old);
        vm.expectRevert(SiteRights.BadClockSig.selector);
        siteC.consume(PARTS, 5, 1, EPOCH, 12_000, c.clockSig); // consumption needs the gateway's attestation
    }

    // ============================================================ fast path and framing
    function test_fastPathMovesObject() public {
        _provision();
        _renewSite(PERMIT, 10_000);
        reg.stop(PERMIT, SITE2);
        _siteStop(PERMIT, 10_000);
        _fastPath(PERMIT, 10_000, 12_000);
        (,,,,,, uint64 holder,) = reg.leases(PERMIT);
        assertEq(holder, SITE2);
        assertEq(reg.ackSignerCount(OffLib.ackKey(PERMIT, SITE, EPOCH, 12_000)), 3);
    }

    /// v4: a grant's public attestation was accepted as an acknowledgement reading.
    function test_grantAttestationIsNoAck_v4exploit() public {
        _provision();
        _renewSite(LOTO, 10_000);
        OffLib.Op memory lock = _lock(LOTO, 10_000, 11_000, 1, 1);
        siteC.use(LOTO, 10_000, EPOCH, 11_000, OffLib.OPEN, 1, lock.clockSig);
        reg.stop(LOTO, SITE2);
        bytes[] memory acks = _acks(LOTO, 11_000);
        vm.expectRevert(RightsRegistry.BadClockSig.selector);
        reg.reassignAcked(LOTO, EPOCH, 11_000, 1, lock.clockSig, acks);
    }

    /// v4: an acknowledgement at an old reading framed the honest sealers of a later release. v5/v6: the ACK is an
    /// operation newer than every earlier one, so the honest release is never late.
    function test_honestReleaseNotFramed_v4exploit() public {
        _provision();
        _renewSite(LOTO, 10_000);
        _siteLock(LOTO, 10_000, 11_000, 1);
        _siteRelease(LOTO, 11_000, 1, 12_000);
        reg.stop(LOTO, SITE2);
        _siteStop(LOTO, 10_000);
        OffLib.Op memory old = _ackOp(LOTO, 10_000, 11_500, 1, 1);
        vm.expectRevert(SiteRights.StaleReading.selector); // an acknowledgement older than the release
        siteC.acknowledge(LOTO, EPOCH, 11_500, old.clockSig);
        _fastPath(LOTO, 10_000, 13_000);
        OffLib.Op[] memory ops = _ops2(_lock(LOTO, 10_000, 11_000, 1, 1), _release(LOTO, 11_000, 1, 12_000, 1));
        OffLib.Header memory h = _ckpt(_hist1(), ops, _stLocks(12_000, LOTO, 1, 1), 12_500);
        bytes[] memory s = _seal(h, _who(0, 1, 2));
        for (uint256 i = 0; i < 2; i++) {
            RightsRegistry.OpProof memory o = _op(ops, i);
            vm.expectRevert(RightsRegistry.NotAViolation.selector);
            reg.proveUseAfterAck(h, s, o, EPOCH, 13_000);
        }
    }

    /// v5: an acknowledgement given while a lock was still on could not be proven.
    function test_lockOnAtAckProvable_v5exploit() public {
        _renew(LOTO, 10_000);
        reg.stop(LOTO, SITE2);
        // a faulty quorum seals: lock #1, then an ACK claiming one open hold and one release
        OffLib.Op[] memory ops = _ops2(_lock(LOTO, 10_000, 11_000, 1, 1), _ackOp(LOTO, 10_000, 12_000, 1, 1));
        OffLib.Header memory h = _ckpt(_hist1(), ops, _stLocks(12_000, LOTO, 1, 1), 12_500);
        // the claimed release does not exist: the state says 1 release, but the honest count is 0 ... and an ACK that
        // admits the lock is on (1 open, 0 released) is a bad operation outright
        OffLib.Op[] memory ops2 = _ops2(_lock(LOTO, 10_000, 11_000, 1, 1), _ackOp(LOTO, 10_000, 12_000, 1, 0));
        OffLib.Header memory h2 = _ckpt(_hist1(), ops2, _stLocks(12_000, LOTO, 1, 0), 12_500);
        assertEq(reg.proveBadOp(h2, _seal(h2, _who(0, 1, 2)), _op(ops2, 1)), 3);
        // an ACK that understates the opens below an earlier lock in its checkpoint is inconsistent
        OffLib.Op[] memory ops3 = _ops2(_lock(LOTO, 10_000, 11_000, 1, 1), _ackOp(LOTO, 10_000, 12_000, 0, 0));
        OffLib.Header memory h3 = _ckpt(_hist1(), ops3, _stLocks(12_000, LOTO, 1, 0), 12_500);
        reg.proveInconsistent(h3, _seal(h3, _who(1, 2, 3)), _op(ops3, 0), _op(ops3, 1));
        assertTrue(reg.slashed(SITE, va[3]));
        h; // the first checkpoint is consistent on its face; a later checkpoint's release counter exposes it
    }

    /// An ACK in a later checkpoint that understates the opens below an ancestor's committed counter.
    function test_ackBelowAncestorLockCounter() public {
        OffLib.State memory s1 = _stLocks(11_000, LOTO, 1, 0);
        OffLib.Header memory c1 = _ckpt(_hist1(), _ops1(_lock(LOTO, 10_000, 11_000, 1, 1)), s1, 11_500);
        bytes32[] memory hist2 = _push(_hist1(), c1);
        OffLib.Op[] memory ops = _ops1(_ackOp(LOTO, 10_000, 12_000, 0, 0));
        OffLib.Header memory c2 = _ckpt(hist2, ops, _stLocks(12_000, LOTO, 1, 0), 12_500);
        assertEq(reg.proveOpRegress(c2, _seal(c2, _who(0, 1, 2)), _op(ops, 0), _anc(hist2, c1, s1)), 3);
    }

    function test_useAfterAckSlashesBoth() public {
        _renew(PERMIT, 10_000);
        reg.stop(PERMIT, SITE2);
        _ackOnG(PERMIT, 10_000, 12_000);
        OffLib.Op[] memory ops = _ops1(_grant(PERMIT, EPOCH, 10_000, 12_001, 12_500)); // under the old renewal
        OffLib.Header memory h = _ckpt(_hist1(), ops, _empty(12_001), 13_000);
        uint256 n = reg.proveUseAfterAck(h, _seal(h, _who(1, 2, 3)), _op(ops, 0), EPOCH, 12_000);
        assertEq(n, 2); // validators 1 and 2 both acknowledged and sealed
        assertTrue(reg.slashed(SITE, va[1]) && reg.slashed(SITE, va[2]) && !reg.slashed(SITE, va[3]));
    }

    function test_holdRunningPastAckSlashes() public {
        _renew(PERMIT, 10_000);
        reg.stop(PERMIT, SITE2);
        _ackOnG(PERMIT, 10_000, 12_000);
        OffLib.Op[] memory ops = _ops1(_grant(PERMIT, EPOCH, 10_000, 11_000, 30_000)); // granted before, ends after
        OffLib.Header memory h = _ckpt(_hist1(), ops, _empty(11_000), 13_000);
        assertEq(reg.proveUseAfterAck(h, _seal(h, _who(0, 1, 2)), _op(ops, 0), EPOCH, 12_000), 3);
    }

    /// v5: a release in a later epoch than its grant was compared with its own epoch; now with the grant's.
    function test_releaseAfterAckUsesGrantEpoch_v5exploit() public {
        _renew(LOTO, 10_000);
        reg.stop(LOTO, SITE2);
        OffLib.Op memory ack = _ackOp(LOTO, 10_000, 12_000, 0, 0);
        reg.reassignAcked(LOTO, EPOCH, 12_000, 0, ack.clockSig, _acks(LOTO, 12_000));
        // released in epoch 2 (after a reboot), of a hold granted in epoch 1 before the acknowledgement
        OffLib.Op memory rel = _att(OffLib.Op(OffLib.RELEASE, LOTO, 2, 500, 11_000, EPOCH, 1, 1, 0, ""));
        OffLib.Op[] memory ops = _ops1(rel);
        OffLib.State memory st = _stLocks(500, LOTO, 1, 1);
        st.epoch = 2;
        OffLib.Header memory h = _ckpt(_hist1(), ops, st, 13_000);
        assertEq(reg.proveUseAfterAck(h, _seal(h, _who(0, 1, 2)), _op(ops, 0), EPOCH, 12_000), 3);
    }

    /// v4: lastAck was overwritten by the next hand-over, erasing the evidence. v5/v6 keep every acknowledgement.
    function test_ackEvidenceSurvivesLaterHandOver_v4exploit() public {
        _renew(PERMIT, 10_000);
        reg.stop(PERMIT, SITE2);
        _ackOnG(PERMIT, 10_000, 12_000);
        bytes32[] memory objs = _objs(PERMIT);
        bytes32 tag = OffLib.requestTag(OffLib.objectsHash(objs));
        reg.renew(SITE2, objs, EPOCH, 10_000, _sig(CLOCK2, OffLib.clockDigest(dom, SITE2, EPOCH, 10_000, tag)));
        reg.stop(PERMIT, SITE);
        vm.warp(reg.releaseAt(PERMIT));
        reg.reassign(PERMIT); // a later hand-over of the same object
        OffLib.Op[] memory ops = _ops1(_grant(PERMIT, EPOCH, 10_000, 12_001, 12_500));
        OffLib.Header memory h = _ckpt(_hist1(), ops, _empty(12_001), 13_000);
        assertEq(reg.proveUseAfterAck(h, _seal(h, _who(0, 1, 2)), _op(ops, 0), EPOCH, 12_000), 3);
    }

    function test_honestUseAfterReturnNotFramed() public {
        _renew(PERMIT, 10_000);
        reg.stop(PERMIT, SITE2);
        _ackOnG(PERMIT, 10_000, 12_000);
        OffLib.Op[] memory ops = _ops1(_grant(PERMIT, EPOCH, 20_000, 21_000, 22_000)); // under a newer renewal
        OffLib.Header memory h = _ckpt(_hist1(), ops, _empty(21_000), 23_000);
        bytes[] memory s = _seal(h, _who(0, 1, 2));
        RightsRegistry.OpProof memory o = _op(ops, 0);
        vm.expectRevert(RightsRegistry.NotAViolation.selector);
        reg.proveUseAfterAck(h, s, o, EPOCH, 12_000);
    }

    function test_staleAckRejected() public {
        _renew(PERMIT, 10_000);
        reg.stop(PERMIT, SITE2);
        OffLib.Op memory ack = _ackOp(PERMIT, 10_000, 9_000, 0, 0);
        bytes[] memory acks = _acks(PERMIT, 9_000);
        vm.expectRevert(RightsRegistry.StaleAck.selector);
        reg.reassignAcked(PERMIT, EPOCH, 9_000, 0, ack.clockSig, acks);
    }

    // ============================================================ fraud proofs: single checkpoint
    function test_overspend() public {
        OffLib.Op[] memory ops = _ops1(_consume(45, 45, 1, 11_000));
        OffLib.Header memory h = _ckpt(_hist1(), ops, _st(11_000, 40, 1), 12_000);
        assertEq(reg.proveOverspend(h, _seal(h, _who(0, 1, 2)), _op(ops, 0)), 3);
    }

    function test_honestConsumptionNotSlashable() public {
        OffLib.Op[] memory ops = _ops2(_consume(30, 30, 1, 11_000), _consume(5, 35, 1, 11_500));
        OffLib.State memory st = _st(11_500, 35, 1);
        OffLib.Header memory h = _ckpt(_hist1(), ops, st, 12_000);
        bytes[] memory s = _seal(h, _who(0, 1, 2));
        for (uint256 i = 0; i < 2; i++) {
            RightsRegistry.OpProof memory o = _op(ops, i);
            vm.expectRevert(RightsRegistry.NotAViolation.selector);
            reg.proveOverspend(h, s, o);
            vm.expectRevert(RightsRegistry.NotAViolation.selector);
            reg.proveBadOp(h, s, o);
            vm.expectRevert(RightsRegistry.NotAViolation.selector);
            reg.proveStateMismatch(h, s, o, st);
        }
        RightsRegistry.OpProof memory o0 = _op(ops, 0);
        RightsRegistry.OpProof memory o1 = _op(ops, 1);
        vm.expectRevert(RightsRegistry.NotAViolation.selector);
        reg.proveInconsistent(h, s, o0, o1);
    }

    function test_badOp() public {
        OffLib.Op memory forged = _release(LOTO, 11_000, 1, 12_000, 1);
        forged.clockSig = _sig(CLOCK, bytes32(uint256(1))); // not an attestation of this release
        OffLib.Op[] memory ops = _ops1(forged);
        OffLib.Header memory h = _ckpt(_hist1(), ops, _stLocks(12_000, LOTO, 1, 1), 13_000);
        assertEq(reg.proveBadOp(h, _seal(h, _who(0, 1, 2)), _op(ops, 0)), 3);
        OffLib.Op[] memory ops2 = _ops1(_shareOp(90, 0, 7)); // version 7 was never certified
        OffLib.Header memory h2 = _ckpt(_hist1(), ops2, _st(0, 0, 7), 13_000);
        reg.proveBadOp(h2, _seal(h2, _who(0, 1, 3)), _op(ops2, 0));
        assertTrue(reg.slashed(SITE, va[3]));
    }

    function test_honestOpsNotBadOps() public {
        OffLib.Op[] memory ops = new OffLib.Op[](5);
        ops[0] = _shareOp(40, 0, 1);
        ops[1] = _log(keccak256("record"));
        ops[2] = _lock(LOTO, 10_000, 11_000, 1, 1);
        ops[3] = _release(LOTO, 11_000, 1, 12_000, 1);
        ops[4] = _ackOp(LOTO, 10_000, 12_500, 1, 1);
        OffLib.State memory st = _stLocks(12_500, LOTO, 1, 1);
        st.resources = new bytes32[](1);
        st.totals = new uint64[](1);
        st.versions = new uint64[](1);
        (st.resources[0], st.versions[0]) = (PARTS, 1);
        OffLib.Header memory h = _ckpt(_hist1(), ops, st, 13_000);
        bytes[] memory s = _seal(h, _who(0, 1, 2));
        for (uint256 i = 0; i < 5; i++) {
            RightsRegistry.OpProof memory o = _op(ops, i);
            vm.expectRevert(RightsRegistry.NotAViolation.selector);
            reg.proveBadOp(h, s, o);
            vm.expectRevert(RightsRegistry.NotAViolation.selector);
            reg.proveStateMismatch(h, s, o, st);
            if (i + 1 < 5) {
                RightsRegistry.OpProof memory o2 = _op(ops, i + 1);
                vm.expectRevert(RightsRegistry.NotAViolation.selector);
                reg.proveInconsistent(h, s, o, o2);
            }
        }
    }

    function test_overuse() public {
        _renew(PERMIT, 10_000);
        _renew(LOTO, 10_000);
        OffLib.Op[] memory ops = new OffLib.Op[](4);
        ops[0] = _grant(PERMIT, EPOCH, 9_000, 11_000, 12_000); // no such renewal
        ops[1] = _grant(PERMIT, EPOCH, 10_000, 10_000 + A, 10_000 + A + 5); // after the allowance
        ops[2] = _grant(PERMIT, EPOCH, 10_000, 11_000, 10_000 + A); // hold ends past the allowance
        ops[3] = _grant(LOTO, EPOCH, 10_000, 11_000, 12_000); // bounded hold of an open-hold object
        OffLib.Header memory h = _ckpt(_hist1(), ops, _empty(11_000), 12_000);
        bytes[] memory s = _seal(h, _who(0, 1, 2));
        assertEq(reg.proveOveruse(h, s, _op(ops, 0)), 3);
        for (uint256 i = 1; i < 4; i++) {
            assertEq(reg.proveOveruse(h, s, _op(ops, i)), 0); // already slashed, still a violation
        }
    }

    function test_honestGrantsNotOveruse() public {
        _renew(PERMIT, 10_000);
        _renew(LOTO, 10_000);
        _renew(CRED, 10_000);
        OffLib.Op[] memory ops = new OffLib.Op[](3);
        ops[0] = _grant(PERMIT, EPOCH, 10_000, 11_000, 10_000 + A - 1);
        ops[1] = _lock(LOTO, 10_000, 11_500, 1, 1);
        ops[2] = _grant(CRED, EPOCH, 10_000, 12_000, 12_001);
        OffLib.Header memory h = _ckpt(_hist1(), ops, _stLocks(12_000, LOTO, 1, 0), 13_000);
        bytes[] memory s = _seal(h, _who(0, 1, 2));
        for (uint256 i = 0; i < 3; i++) {
            RightsRegistry.OpProof memory o = _op(ops, i);
            vm.expectRevert(RightsRegistry.NotAViolation.selector);
            reg.proveOveruse(h, s, o);
        }
    }

    function test_inconsistentOrder() public {
        OffLib.Op memory g = _grant(PERMIT, EPOCH, 10_000, 11_000, 12_000);
        OffLib.Op[] memory ops = _ops2(g, g); // a replayed attestation: readings do not increase
        OffLib.Header memory h = _ckpt(_hist1(), ops, _empty(11_000), 13_000);
        assertEq(reg.proveInconsistent(h, _seal(h, _who(0, 1, 2)), _op(ops, 0), _op(ops, 1)), 3);
    }

    function test_inconsistentStaleVersionAndUnderstate() public {
        OffLib.Op[] memory ops = _ops2(_shareOp(20, 10, 2), _consume(5, 15, 1, 11_000)); // version 1 after v2
        OffLib.Header memory h = _ckpt(_hist1(), ops, _st(11_000, 15, 2), 12_000);
        assertEq(reg.proveInconsistent(h, _seal(h, _who(0, 1, 2)), _op(ops, 0), _op(ops, 1)), 3);
        OffLib.Op[] memory ops2 = _ops2(_consume(30, 30, 1, 11_000), _consume(5, 5, 1, 11_500)); // restarts at 0
        OffLib.Header memory h2 = _ckpt(_hist1(), ops2, _st(11_500, 5, 1), 12_000);
        reg.proveInconsistent(h2, _seal(h2, _who(1, 2, 3)), _op(ops2, 0), _op(ops2, 1));
        assertTrue(reg.slashed(SITE, va[3]));
    }

    function test_stateMismatch() public {
        OffLib.Op[] memory ops = _ops1(_consume(30, 30, 1, 11_000));
        OffLib.State memory st = _st(11_000, 10, 1); // understates 30
        OffLib.Header memory h = _ckpt(_hist1(), ops, st, 12_000);
        assertEq(reg.proveStateMismatch(h, _seal(h, _who(0, 1, 2)), _op(ops, 0), st), 3);
    }

    function test_stateMalformedOrClockBehind() public {
        OffLib.State memory bad = _st(11_000, 30, 1);
        bad.versions = new uint64[](0); // lengths differ
        OffLib.Op[] memory ops = _ops1(_consume(30, 30, 1, 11_000));
        OffLib.Header memory h = _ckpt(_hist1(), ops, bad, 12_000);
        assertEq(reg.proveStateMismatch(h, _seal(h, _who(0, 1, 2)), _op(ops, 0), bad), 3);
        OffLib.State memory behind = _st(10_000, 30, 1); // clock behind its own operation
        OffLib.Header memory h2 = _ckpt(_hist1(), ops, behind, 12_000);
        reg.proveStateMismatch(h2, _seal(h2, _who(1, 2, 3)), _op(ops, 0), behind);
        assertTrue(reg.slashed(SITE, va[3]));
    }

    /// v5: a state could be padded so that proofs needing it exceed the block gas limit. v6 bounds its length.
    function test_oversizedStateProvable_v5exploit() public {
        OffLib.Op[] memory ops = _ops1(_log(keccak256("x")));
        OffLib.Header memory h = _ckpt(_hist1(), ops, _empty(0), 12_000);
        h.stateLen = 1_000_000; // a committed state with a million entries
        h.closeSig = _sig(CLOCK, OffLib.clockDigest(dom, SITE, EPOCH, 12_000, OffLib.contentTag(h)));
        assertEq(reg.proveStateMismatch(h, _seal(h, _who(0, 1, 2)), _op(ops, 0), _empty(0)), 3);
    }

    /// v5: a committed total above the certified share was not provable on its own.
    function test_stateAboveShareProvable_v5exploit() public {
        OffLib.Op[] memory ops = _ops1(_log(keccak256("x")));
        OffLib.State memory st = _st(0, 55, 1); // version 1 is 40
        OffLib.Header memory h = _ckpt(_hist1(), ops, st, 12_000);
        assertEq(reg.proveStateMismatch(h, _seal(h, _who(0, 1, 2)), _op(ops, 0), st), 3);
    }

    // ============================================================ fraud proofs: history
    /// v4: a checkpoint with no consumption lowered the committed total, laundering an understatement.
    function test_regressThroughEmptyCheckpoint_v4exploit() public {
        OffLib.State memory s1 = _st(11_000, 30, 1);
        OffLib.Header memory c1 = _ckpt(_hist1(), _ops1(_consume(30, 30, 1, 11_000)), s1, 12_000);
        bytes32[] memory hist2 = _push(_hist1(), c1);
        OffLib.State memory s2 = _st(11_000, 0, 1); // no consumption, total lowered
        OffLib.Header memory c2 = _ckpt(hist2, _ops1(_log(keccak256("noop"))), s2, 13_000);
        assertEq(reg.proveRegress(c2, _seal(c2, _who(0, 1, 2)), s2, _anc(hist2, c1, s1)), 3);
    }

    function test_regressDroppedEntryOrClock() public {
        OffLib.State memory s1 = _st(11_000, 30, 1);
        OffLib.Header memory c1 = _ckpt(_hist1(), _ops1(_consume(30, 30, 1, 11_000)), s1, 12_000);
        bytes32[] memory hist2 = _push(_hist1(), c1);
        OffLib.State memory s2 = _empty(11_000); // resource dropped
        OffLib.Header memory c2 = _ckpt(hist2, _ops1(_log(keccak256("a"))), s2, 13_000);
        assertEq(reg.proveRegress(c2, _seal(c2, _who(0, 1, 2)), s2, _anc(hist2, c1, s1)), 3);
        OffLib.State memory s3 = _st(10_000, 30, 1); // clock went back
        OffLib.Header memory c3 = _ckpt(hist2, _ops1(_log(keccak256("b"))), s3, 13_000);
        reg.proveRegress(c3, _seal(c3, _who(1, 2, 3)), s3, _anc(hist2, c1, s1));
        assertTrue(reg.slashed(SITE, va[3]));
    }

    function test_regressLockCounter() public {
        OffLib.State memory s1 = _stLocks(11_000, LOTO, 2, 1);
        OffLib.Header memory c1 = _ckpt(_hist1(), _ops1(_lock(LOTO, 10_000, 11_000, 1, 2)), s1, 12_000);
        bytes32[] memory hist2 = _push(_hist1(), c1);
        OffLib.State memory s2 = _stLocks(11_000, LOTO, 1, 1); // an open hold forgotten
        OffLib.Header memory c2 = _ckpt(hist2, _ops1(_log(keccak256("a"))), s2, 13_000);
        assertEq(reg.proveRegress(c2, _seal(c2, _who(0, 1, 2)), s2, _anc(hist2, c1, s1)), 3);
    }

    /// v4: a faulty quorum anchored a checkpoint whose consumption restarted below the anchored base.
    function test_restartBelowAncestor_v4exploit() public {
        OffLib.State memory s1 = _st(11_000, 40, 1);
        OffLib.Header memory c1 = _ckpt(_hist1(), _ops1(_consume(40, 40, 1, 11_000)), s1, 12_000);
        reg.anchor(c1, _seal(c1, _who(0, 1, 2)), new bytes32[](0));
        bytes32[] memory hist = new bytes32[](1000); // hidden intermediate checkpoints
        hist[1] = OffLib.headerHash(c1);
        OffLib.Op[] memory ops = _ops1(_consume(40, 40, 1, 50_000)); // consumption restarts at zero
        OffLib.Header memory c = _ckpt(hist, ops, _st(50_000, 40, 1), 51_000);
        assertEq(reg.proveOpRegress(c, _seal(c, _who(0, 1, 2)), _op(ops, 0), _anc(hist, c1, s1)), 3);
    }

    /// v4: after confirmShare, a faulty quorum kept consuming under the old, larger share version.
    function test_staleVersionAfterConfirmShare_v4exploit() public {
        OffLib.Header memory c1 = _ckpt(_hist1(), _ops1(_consume(30, 30, 1, 11_000)), _st(11_000, 30, 1), 12_000);
        assertEq(reg.setShare(PARTS, SITE, 30), 2); // lower 40 -> 30, pending
        OffLib.State memory s2 = _st(11_000, 30, 2);
        bytes32[] memory hist2 = _push(_hist1(), c1);
        OffLib.Header memory c2 = _ckpt(hist2, _ops1(_shareOp(30, 30, 2)), s2, 13_000);
        reg.confirmShare(PARTS, SITE, c2, _seal(c2, _who(0, 1, 2)), s2);
        assertEq(reg.allocated(PARTS), 90);
        bytes32[] memory hist3 = _push(hist2, c2);
        OffLib.Op[] memory ops = _ops1(_consume(10, 40, 1, 14_000)); // claims version 1 (40)
        OffLib.Header memory c3 = _ckpt(hist3, ops, _st(14_000, 40, 1), 15_000);
        bytes[] memory s3 = _seal(c3, _who(0, 1, 2));
        RightsRegistry.OpProof memory o = _op(ops, 0);
        vm.expectRevert(RightsRegistry.NotAViolation.selector);
        reg.proveOverspend(c3, s3, o); // within version 1, so this proof alone cannot catch it
        assertEq(reg.proveOpRegress(c3, s3, o, _anc(hist3, c2, s2)), 3);
    }

    function test_replayedAttestationAcrossCheckpoints() public {
        OffLib.Op memory g = _grant(PERMIT, EPOCH, 10_000, 11_000, 12_000);
        OffLib.State memory s1 = _empty(11_000);
        OffLib.Header memory c1 = _ckpt(_hist1(), _ops1(g), s1, 12_000);
        bytes32[] memory hist2 = _push(_hist1(), c1);
        OffLib.Op[] memory ops = _ops1(g); // the same grant again
        OffLib.Header memory c2 = _ckpt(hist2, ops, _empty(11_000), 13_000);
        assertEq(reg.proveOpRegress(c2, _seal(c2, _who(0, 1, 2)), _op(ops, 0), _anc(hist2, c1, s1)), 3);
    }

    function test_honestHistoryNotSlashable() public {
        OffLib.State memory s1 = _st(11_000, 30, 1);
        OffLib.Header memory c1 = _ckpt(_hist1(), _ops1(_consume(30, 30, 1, 11_000)), s1, 12_000);
        bytes32[] memory hist2 = _push(_hist1(), c1);
        OffLib.Op[] memory ops = _ops2(_consume(5, 35, 1, 12_500), _grant(PERMIT, EPOCH, 10_000, 12_600, 13_000));
        OffLib.State memory s2 = _st(12_600, 35, 1);
        OffLib.Header memory c2 = _ckpt(hist2, ops, s2, 13_500);
        bytes[] memory s = _seal(c2, _who(0, 1, 2));
        RightsRegistry.Ancestor memory anc = _anc(hist2, c1, s1);
        vm.expectRevert(RightsRegistry.NotAViolation.selector);
        reg.proveRegress(c2, s, s2, anc);
        for (uint256 i = 0; i < 2; i++) {
            RightsRegistry.OpProof memory o = _op(ops, i);
            vm.expectRevert(RightsRegistry.NotAViolation.selector);
            reg.proveOpRegress(c2, s, o, anc);
        }
        bytes[] memory s1Seals = _seal(c1, _who(0, 1, 2));
        bytes32[] memory p = _histPath(hist2, 1);
        vm.expectRevert(RightsRegistry.NotAViolation.selector);
        reg.proveFork(c1, s1Seals, c2, s, OffLib.headerHash(c1), p);
    }

    function test_ancestorMustBeInHistory() public {
        OffLib.State memory s1 = _st(11_000, 30, 1);
        OffLib.Header memory c1 = _ckpt(_hist1(), _ops1(_consume(30, 30, 1, 11_000)), s1, 12_000);
        OffLib.State memory s2 = _empty(11_000);
        bytes32[] memory other = new bytes32[](2); // a history that does not contain c1
        other[1] = keccak256("another checkpoint");
        OffLib.Header memory c2 = _ckpt(other, _ops1(_log(keccak256("x"))), s2, 13_000);
        RightsRegistry.Ancestor memory anc = RightsRegistry.Ancestor(c1, s1, _histPath(other, 1));
        bytes[] memory s = _seal(c2, _who(0, 1, 2));
        vm.expectRevert(RightsRegistry.BadProof.selector);
        reg.proveRegress(c2, s, s2, anc);
    }

    function test_forkSameHeight() public {
        OffLib.Header memory h1 = _ckpt(_hist1(), _ops1(_log(keccak256("a"))), _empty(0), 12_000);
        OffLib.Header memory h2 = _ckpt(_hist1(), _ops1(_log(keccak256("b"))), _empty(0), 12_000);
        uint256 n = reg.proveFork(h1, _seal(h1, _who(0, 1, 2)), h2, _seal(h2, _who(1, 2, 3)), bytes32(0), new bytes32[](0));
        assertEq(n, 2);
    }

    /// v4: forks were detected only at equal heights; a branch at another height escaped.
    function test_forkAcrossHeights_v4exploit() public {
        OffLib.Header memory a1 = _ckpt(_hist1(), _ops1(_log(keccak256("a"))), _empty(0), 12_000);
        OffLib.Header memory b1 = _ckpt(_hist1(), _ops1(_log(keccak256("b"))), _empty(0), 12_000); // never shown
        bytes32[] memory histB = new bytes32[](1000);
        histB[1] = OffLib.headerHash(b1);
        OffLib.Header memory b999 = _ckpt(histB, _ops1(_log(keccak256("c"))), _empty(0), 50_000);
        bytes[] memory sa = _seal(a1, _who(0, 1, 2));
        bytes[] memory sb = _seal(b999, _who(1, 2, 3));
        assertEq(reg.proveFork(a1, sa, b999, sb, OffLib.headerHash(b1), _histPath(histB, 1)), 2);
    }

    /// v5: the depth-20 accumulator could not hold heights at or beyond 2^20 (about 73 days at 6 s).
    function test_historyBeyond2pow20_v5exploit() public {
        bytes32 leaf = keccak256("checkpoint at a height beyond 2^20");
        uint64 height = uint64(1) << 21;
        bytes32[] memory path = new bytes32[](D);
        bytes32 h = leaf;
        uint256 idx = height;
        for (uint256 d = 0; d < D; d++) {
            path[d] = zeros[d];
            h = (idx & 1) == 0 ? keccak256(abi.encode(h, zeros[d])) : keccak256(abi.encode(zeros[d], h));
            idx >>= 1;
        }
        assertTrue(OffLib.inHistory(h, leaf, height, path));
    }

    // ============================================================ anchoring, shares, quorums, recovery
    function test_anchorCatchUpAndHistory() public {
        OffLib.Header memory c1 = _ckpt(_hist1(), _ops1(_log(keccak256("1"))), _empty(0), 12_000);
        reg.anchor(c1, _seal(c1, _who(0, 1, 2)), new bytes32[](0));
        bytes32[] memory hist = new bytes32[](50);
        hist[1] = OffLib.headerHash(c1);
        OffLib.Header memory c50 = _ckpt(hist, _ops1(_log(keccak256("50"))), _empty(0), 90_000);
        reg.anchor(c50, _seal(c50, _who(0, 1, 2)), _histPath(hist, 1)); // one transaction, 48 heights later
        (uint64 ah, uint64 ce, uint64 cr,,) = _site(SITE);
        assertEq(ah, 50);
        assertEq(ce, EPOCH);
        assertEq(cr, 90_000);
    }

    function test_anchorRejectsForeignHistoryAndForgedClose() public {
        OffLib.Header memory c1 = _ckpt(_hist1(), _ops1(_log(keccak256("1"))), _empty(0), 12_000);
        reg.anchor(c1, _seal(c1, _who(0, 1, 2)), new bytes32[](0));
        bytes32[] memory other = new bytes32[](3);
        other[1] = keccak256("not c1");
        OffLib.Header memory c3 = _ckpt(other, _ops1(_log(keccak256("3"))), _empty(0), 20_000);
        bytes[] memory s3 = _seal(c3, _who(0, 1, 2));
        bytes32[] memory p3 = _histPath(other, 1);
        vm.expectRevert(RightsRegistry.BadProof.selector);
        reg.anchor(c3, s3, p3);
        bytes32[] memory hist = _push(_hist1(), c1);
        OffLib.Header memory c2 = _ckpt(hist, _ops1(_log(keccak256("2"))), _empty(0), 20_000);
        c2.closeReading = 9_000_000; // inflated coverage: the close is no longer attested
        bytes[] memory s2 = _seal(c2, _who(0, 1, 2));
        bytes32[] memory p2 = _histPath(hist, 1);
        vm.expectRevert(RightsRegistry.BadClockSig.selector);
        reg.anchor(c2, s2, p2);
    }

    /// Anyone may anchor an older checkpoint first; the newest still anchors because its history contains it.
    function test_anchorGriefingHarmless() public {
        OffLib.Header memory c1 = _ckpt(_hist1(), _ops1(_log(keccak256("1"))), _empty(0), 12_000);
        bytes32[] memory hist2 = _push(_hist1(), c1);
        OffLib.Header memory c2 = _ckpt(hist2, _ops1(_log(keccak256("2"))), _empty(0), 13_000);
        bytes32[] memory hist3 = _push(hist2, c2);
        OffLib.Header memory c3 = _ckpt(hist3, _ops1(_log(keccak256("3"))), _empty(0), 14_000);
        reg.anchor(c2, _seal(c2, _who(0, 1, 2)), new bytes32[](0));
        reg.anchor(c3, _seal(c3, _who(0, 1, 2)), _histPath(hist3, 2));
        (uint64 ah,,,,) = _site(SITE);
        assertEq(ah, 3);
    }

    function test_renewAfterAnchor() public {
        OffLib.Header memory c1 = _ckpt(_hist1(), _ops1(_log(keccak256("1"))), _empty(0), 70_000);
        reg.anchor(c1, _seal(c1, _who(0, 1, 2)), new bytes32[](0));
        _renew(PERMIT, 70_000 + LAG);
    }

    function test_confirmShareNeedsAppliedVersion() public {
        OffLib.Header memory c0 = _ckpt(_hist1(), _ops1(_log(keccak256("x"))), _empty(0), 1);
        vm.expectRevert(RightsRegistry.NoPendingShare.selector);
        reg.confirmShare(PARTS, SITE, c0, new bytes[](0), _empty(0));
        reg.setShare(PARTS, SITE, 30); // v2, pending
        OffLib.State memory old = _st(11_000, 35, 1); // still on v1 and above 30
        OffLib.Header memory c = _ckpt(_hist1(), _ops1(_consume(35, 35, 1, 11_000)), old, 12_000);
        bytes[] memory s = _seal(c, _who(0, 1, 2));
        vm.expectRevert(RightsRegistry.ShareNotApplied.selector);
        reg.confirmShare(PARTS, SITE, c, s, old);
        assertEq(reg.allocated(PARTS), 100);
    }

    function test_slashedExcludedFromQuorums() public {
        OffLib.Op[] memory ops = _ops1(_consume(45, 45, 1, 11_000));
        OffLib.Header memory h = _ckpt(_hist1(), ops, _st(11_000, 40, 1), 12_000);
        reg.proveOverspend(h, _seal(h, _who(0, 1, 2)), _op(ops, 0)); // 3 slashed: site revoked
        (,,, bool revoked,) = _site(SITE);
        assertTrue(revoked);
        OffLib.Header memory c = _ckpt(_hist1(), _ops1(_log(keccak256("1"))), _empty(0), 12_000);
        bytes[] memory s = _seal(c, _who(0, 1, 3));
        vm.expectRevert(RightsRegistry.NoQuorum.selector);
        reg.anchor(c, s, new bytes32[](0));
        vm.expectRevert(RightsRegistry.SiteRevokedErr.selector);
        _renew(PERMIT, 10_000);
    }

    function test_largerSiteQuorum() public {
        address[] memory vs = new address[](5);
        for (uint256 i = 0; i < 5; i++) {
            vs[i] = vm.addr(0xF1 + i);
        }
        reg.registerSite(5, 1, vm.addr(CLOCK), vs, EPOCH, START); // q = floor((5+1)/2)+1 = 4
        OffLib.Header memory h = _ckpt(_hist1(), _ops1(_log(keccak256("q"))), _empty(0), 12_000);
        h.site = 5;
        bytes32 d = OffLib.checkpointDigest(dom, OffLib.headerHash(h));
        bytes[] memory three = new bytes[](3);
        for (uint256 i = 0; i < 3; i++) {
            three[i] = _sig(0xF1 + i, d);
        }
        vm.expectRevert(RightsRegistry.NoQuorum.selector);
        reg.anchor(h, three, new bytes32[](0));
    }

    /// v5: rotateClock let anyone slash the honest sealers of old checkpoints, and replaceValidator broke quorum
    /// intersection. v6 retires the site instead: its key and validators stay, so old proofs and no-framing hold.
    function test_retireKeepsOldHistoryJudgeable_v5exploit() public {
        OffLib.Op[] memory ops = _ops1(_consume(30, 30, 1, 11_000));
        OffLib.State memory st = _st(11_000, 30, 1);
        OffLib.Header memory h = _ckpt(_hist1(), ops, st, 12_000);
        bytes[] memory s = _seal(h, _who(0, 1, 2));
        reg.retireSite(SITE);
        (,,,, bool retired) = _site(SITE);
        assertTrue(retired);
        RightsRegistry.OpProof memory o = _op(ops, 0);
        vm.expectRevert(RightsRegistry.NotAViolation.selector);
        reg.proveBadOp(h, s, o); // the old attestation is still judged against the site's own key
        vm.expectRevert(RightsRegistry.SiteRevokedErr.selector);
        _renew(PERMIT, 10_000); // a retired incarnation gets no renewals
    }

    /// v5: the emergency override did not wait out the holder's allowance.
    function test_forceReassignWaitsAllowance_v5exploit() public {
        _renew(LOTO, 10_000);
        reg.stop(LOTO, SITE2);
        uint64 at = reg.releaseAt(LOTO);
        vm.expectRevert(abi.encodeWithSelector(RightsRegistry.TooEarly.selector, at));
        reg.forceReassign(LOTO);
        vm.warp(at);
        reg.forceReassign(LOTO); // emergency override, logged
        (,,,,,, uint64 holder,) = reg.leases(LOTO);
        assertEq(holder, SITE2);
        vm.prank(address(0xBEEF));
        vm.expectRevert(RightsRegistry.NotAdmin.selector);
        reg.forceReassign(PERMIT);
    }

    /// A proof against an ancestor 900 heights back costs the same as one against the parent.
    function test_proofCostIndependentOfHistory() public {
        OffLib.State memory s1 = _st(11_000, 40, 1);
        OffLib.Header memory c1 = _ckpt(_hist1(), _ops1(_consume(40, 40, 1, 11_000)), s1, 12_000);
        bytes32[] memory near = _push(_hist1(), c1);
        bytes32[] memory far = new bytes32[](901);
        far[1] = OffLib.headerHash(c1);
        OffLib.Op[] memory ops = _ops1(_consume(40, 40, 1, 50_000));
        OffLib.Header memory cn = _ckpt(near, ops, _st(50_000, 40, 1), 51_000);
        OffLib.Header memory cf = _ckpt(far, ops, _st(50_000, 40, 1), 51_000);
        RightsRegistry.Ancestor memory an = _anc(near, c1, s1);
        RightsRegistry.Ancestor memory af = _anc(far, c1, s1);
        bytes[] memory sn = _seal(cn, _who(0, 1, 2));
        bytes[] memory sf = _seal(cf, _who(0, 1, 2));
        RightsRegistry.OpProof memory o = _op(ops, 0);
        uint256 snap = vm.snapshotState();
        uint256 g0 = gasleft();
        reg.proveOpRegress(cn, sn, o, an);
        uint256 gNear = g0 - gasleft();
        vm.revertToState(snap);
        g0 = gasleft();
        reg.proveOpRegress(cf, sf, o, af);
        uint256 gFar = g0 - gasleft();
        emit log_named_uint("proof gas, ancestor 1 height back", gNear);
        emit log_named_uint("proof gas, ancestor 900 heights back", gFar);
        // Both verify a 32-level path; they differ only in the byte content of the path.
        assertApproxEqRel(gNear, gFar, 0.03e18);
    }

    /// The largest state allowed (64 entries) keeps a regression proof well under a block's gas.
    function test_maxStateProofCost() public {
        OffLib.State memory big = _empty(11_000);
        big.resources = new bytes32[](64);
        big.totals = new uint64[](64);
        big.versions = new uint64[](64);
        for (uint256 i = 0; i < 64; i++) {
            big.resources[i] = bytes32(i + 1);
        }
        OffLib.Header memory c1 = _ckpt(_hist1(), _ops1(_log(keccak256("a"))), big, 12_000);
        bytes32[] memory hist2 = _push(_hist1(), c1);
        OffLib.State memory small = _empty(11_000);
        OffLib.Header memory c2 = _ckpt(hist2, _ops1(_log(keccak256("b"))), small, 13_000);
        bytes[] memory s = _seal(c2, _who(0, 1, 2));
        RightsRegistry.Ancestor memory anc = _anc(hist2, c1, big);
        uint256 g0 = gasleft();
        vm.expectRevert(RightsRegistry.NotAViolation.selector); // all zero totals: nothing dropped below zero
        reg.proveRegress(c2, s, small, anc);
        uint256 used = g0 - gasleft();
        emit log_named_uint("regress proof gas with a 64-entry ancestor state", used);
        assertLt(used, 3_000_000);
    }
}
