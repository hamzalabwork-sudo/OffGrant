// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {OffLib} from "../src/OffLib.sol";
import {RightsRegistry} from "../src/RightsRegistry.sol";
import {SiteRights} from "../src/SiteRights.sol";

contract OffgrantTest is Test {
    RightsRegistry reg;
    SiteRights siteC;

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
    bytes32 constant PERMIT = keccak256("loto:pump-7");
    uint64 constant A = 99_000; // allowance, ms

    function setUp() public {
        vm.warp(1_000_000);
        reg = new RightsRegistry(RHO, SLACK);
        address[] memory vs = new address[](4);
        for (uint256 i = 0; i < 4; i++) {
            va[i] = vm.addr(vk[i]);
            vs[i] = va[i];
        }
        reg.registerSite(SITE, 1, vm.addr(CLOCK), vs);
        address[] memory vs2 = new address[](4);
        for (uint256 i = 0; i < 4; i++) {
            vs2[i] = vm.addr(0xD1 + i);
        }
        reg.registerSite(SITE2, 1, vm.addr(CLOCK2), vs2);
        reg.setCap(PARTS, 100);
        reg.setShare(PARTS, SITE, 40);
        reg.setShare(PARTS, SITE2, 60);
        reg.createLease(PERMIT, true, A);
        reg.permit(PERMIT, SITE);

        address[] memory auth = new address[](3);
        for (uint256 i = 0; i < 3; i++) {
            auth[i] = vm.addr(gk[i]);
        }
        siteC = new SiteRights(SITE, address(reg), vm.addr(CLOCK), auth, 2);
    }

    // ------------------------------------------------------------ helpers
    function _sig(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    function _cert(bytes32 d) internal view returns (bytes[] memory s) {
        s = new bytes[](2);
        s[0] = _sig(gk[0], d);
        s[1] = _sig(gk[2], d);
    }

    function _seal(OffLib.Header memory h, uint256[] memory who) internal view returns (bytes[] memory s) {
        bytes32 d = OffLib.checkpointDigest(address(reg), OffLib.headerHash(h));
        s = new bytes[](who.length);
        for (uint256 i = 0; i < who.length; i++) {
            s[i] = _sig(vk[who[i]], d);
        }
    }

    function _idx(uint256 a, uint256 b, uint256 c) internal pure returns (uint256[] memory w) {
        w = new uint256[](3);
        (w[0], w[1], w[2]) = (a, b, c);
    }

    function _root(bytes32[] memory leaves) internal pure returns (bytes32) {
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

    function _proof(bytes32[] memory leaves, uint256 idx) internal pure returns (bytes32[] memory p) {
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

    function _consume(uint64 amount, uint64 runningTotal) internal pure returns (OffLib.Op memory) {
        return OffLib.Op(OffLib.CONSUME, PARTS, amount, runningTotal, "");
    }

    function _use(uint64 cq, uint64 reading) internal pure returns (OffLib.Op memory) {
        return OffLib.Op(OffLib.USE, PERMIT, cq, reading, _sig(CLOCK, OffLib.clockDigest(SITE, reading)));
    }

    function _header(uint64 height, bytes32 prev, OffLib.Op[] memory ops)
        internal
        pure
        returns (OffLib.Header memory h, bytes32[] memory leaves)
    {
        leaves = new bytes32[](ops.length);
        for (uint256 i = 0; i < ops.length; i++) {
            leaves[i] = OffLib.leaf(ops[i]);
        }
        h = OffLib.Header(SITE, height, prev, _root(leaves), uint64(ops.length));
    }

    function _renew(uint64 cq) internal returns (uint64) {
        return reg.renew(SITE, PERMIT, cq, _sig(CLOCK, OffLib.requestDigest(SITE, PERMIT, cq)));
    }

    // ------------------------------------------------------------ Theorem 1: wait and reassignment
    function test_waitFormula() public view {
        // ceil(99000 ms / (1 - 1e-4)) = 99.0099.. s -> 100 s, plus 2 s slack.
        assertEq(reg.waitSeconds(PERMIT), 102);
    }

    function testFuzz_waitCoversSlowClock(uint64 a, uint32 rho) public {
        a = uint64(bound(a, 1, 1e12));
        rho = uint32(bound(rho, 0, 999_999));
        RightsRegistry r = new RightsRegistry(rho, 0);
        r.createLease(PERMIT, true, a);
        uint256 w = r.waitSeconds(PERMIT);
        // A slow clock (1 - rho) needs A / (1 - rho) real time to advance A: the wait must cover it.
        assertGe(w * 1000 * (1_000_000 - uint256(rho)), uint256(a) * 1_000_000);
    }

    function test_reassignOnlyAfterRelease() public {
        uint64 issued = _renew(5_000);
        reg.stop(PERMIT, SITE2);
        vm.expectRevert();
        reg.renew(SITE, PERMIT, 6_000, _sig(CLOCK, OffLib.requestDigest(SITE, PERMIT, 6_000)));
        uint64 at = issued + reg.waitSeconds(PERMIT);
        vm.warp(at - 1);
        vm.expectRevert(abi.encodeWithSelector(RightsRegistry.TooEarly.selector, at));
        reg.reassign(PERMIT);
        vm.warp(at);
        reg.reassign(PERMIT);
        assertTrue(reg.mayRenew(PERMIT, SITE2));
        assertFalse(reg.mayRenew(PERMIT, SITE));
    }

    function test_renewRejectsForgedClock() public {
        vm.expectRevert(RightsRegistry.BadClockSig.selector);
        reg.renew(SITE, PERMIT, 5_000, _sig(vk[0], OffLib.requestDigest(SITE, PERMIT, 5_000)));
    }

    function test_sharesNeverExceedCap() public {
        vm.expectRevert(RightsRegistry.OverCap.selector);
        reg.setShare(PARTS, SITE, 41);
    }

    // ------------------------------------------------------------ site enforcement while cut off
    function _provisionSite(uint64 cq) internal {
        siteC.applyShare(PARTS, 40, _cert(OffLib.shareDigest(address(reg), SITE, PARTS, 40)));
        siteC.applyLease(PERMIT, A, _cert(OffLib.leaseDigest(address(reg), SITE, PERMIT, A)));
        siteC.applyRenewal(PERMIT, cq, 7, _cert(OffLib.renewalDigest(address(reg), SITE, PERMIT, cq, 7)));
    }

    function test_siteEnforcesShare() public {
        _provisionSite(5_000);
        siteC.consume(PARTS, 30);
        siteC.consume(PARTS, 10);
        vm.expectRevert(abi.encodeWithSelector(SiteRights.OverShare.selector, uint64(41), uint64(40)));
        siteC.consume(PARTS, 1);
    }

    function test_siteEnforcesAllowance() public {
        _provisionSite(5_000);
        siteC.use(PERMIT, 5_000 + A - 1, _sig(CLOCK, OffLib.clockDigest(SITE, 5_000 + A - 1)));
        vm.expectRevert();
        siteC.use(PERMIT, 5_000 + A, _sig(CLOCK, OffLib.clockDigest(SITE, 5_000 + A)));
    }

    function test_siteRejectsUncertifiedRights() public {
        bytes[] memory bad = new bytes[](2);
        bad[0] = _sig(gk[0], OffLib.shareDigest(address(reg), SITE, PARTS, 1000));
        bad[1] = _sig(gk[0], OffLib.shareDigest(address(reg), SITE, PARTS, 1000)); // same authority twice
        vm.expectRevert(SiteRights.BadCertificate.selector);
        siteC.applyShare(PARTS, 1000, bad);
    }

    function test_siteRejectsForgedOrStaleClock() public {
        _provisionSite(5_000);
        vm.expectRevert(SiteRights.BadClockSig.selector);
        siteC.use(PERMIT, 6_000, _sig(vk[0], OffLib.clockDigest(SITE, 6_000)));
        siteC.use(PERMIT, 7_000, _sig(CLOCK, OffLib.clockDigest(SITE, 7_000)));
        vm.expectRevert(SiteRights.StaleReading.selector);
        siteC.use(PERMIT, 6_500, _sig(CLOCK, OffLib.clockDigest(SITE, 6_500)));
    }

    // ------------------------------------------------------------ Theorem 2: no framing of honest checkpoints
    function test_honestCheckpointIsNotSlashable() public {
        _renew(5_000);
        OffLib.Op[] memory ops = new OffLib.Op[](3);
        ops[0] = _consume(30, 30);
        ops[1] = _use(5_000, 5_000 + A - 1);
        ops[2] = _consume(10, 40);
        (OffLib.Header memory h, bytes32[] memory lv) = _header(1, bytes32(0), ops);
        bytes[] memory s = _seal(h, _idx(0, 1, 2));
        vm.expectRevert(RightsRegistry.NotAViolation.selector);
        reg.proveOverspend(h, s, ops[2], 2, _proof(lv, 2));
        vm.expectRevert(RightsRegistry.NotAViolation.selector);
        reg.proveOveruse(h, s, ops[1], 1, _proof(lv, 1));
        OffLib.Header[] memory chain = new OffLib.Header[](1);
        chain[0] = h;
        vm.expectRevert(RightsRegistry.NotAViolation.selector);
        reg.proveUnderstate(chain, s, ops[0], 0, _proof(lv, 0), ops[2], 2, _proof(lv, 2));
        reg.anchor(h, s);
        assertEq(reg.bond(SITE, va[0]), reg.BOND());
    }

    function test_belowQuorumIsRejected() public {
        OffLib.Op[] memory ops = new OffLib.Op[](1);
        ops[0] = _consume(50, 50);
        (OffLib.Header memory h, bytes32[] memory lv) = _header(1, bytes32(0), ops);
        uint256[] memory two = new uint256[](2);
        (two[0], two[1]) = (0, 1);
        vm.expectRevert(RightsRegistry.NoQuorum.selector);
        reg.proveOverspend(h, _seal(h, two), ops[0], 0, _proof(lv, 0));
    }

    // ------------------------------------------------------------ Theorem 2: over-threshold site is attributed
    function test_overspendSlashesSealers() public {
        OffLib.Op[] memory ops = new OffLib.Op[](2);
        ops[0] = _consume(30, 30);
        ops[1] = _consume(25, 55); // share is 40
        (OffLib.Header memory h, bytes32[] memory lv) = _header(1, bytes32(0), ops);
        uint256 n = reg.proveOverspend(h, _seal(h, _idx(0, 1, 2)), ops[1], 1, _proof(lv, 1));
        assertEq(n, 3);
        assertEq(reg.bond(SITE, va[3]), reg.BOND()); // the validator that did not seal keeps its bond
    }

    function test_understateAcrossCheckpointsSlashesLaterSealers() public {
        OffLib.Op[] memory ops1 = new OffLib.Op[](1);
        ops1[0] = _consume(35, 35);
        (OffLib.Header memory h1, bytes32[] memory lv1) = _header(1, bytes32(0), ops1);
        OffLib.Op[] memory ops2 = new OffLib.Op[](2);
        ops2[0] = _consume(20, 20); // running total reset: claims 20 instead of 55
        ops2[1] = OffLib.Op(OffLib.LOG, keccak256("x"), 0, 0, "");
        (OffLib.Header memory h2, bytes32[] memory lv2) = _header(2, OffLib.headerHash(h1), ops2);
        OffLib.Header[] memory chain = new OffLib.Header[](2);
        (chain[0], chain[1]) = (h1, h2);
        uint256 n = reg.proveUnderstate(
            chain, _seal(h2, _idx(1, 2, 3)), ops1[0], 0, _proof(lv1, 0), ops2[0], 0, _proof(lv2, 0)
        );
        assertEq(n, 3);
        assertEq(reg.bond(SITE, va[0]), reg.BOND());
    }

    function test_overusePastAllowanceSlashes() public {
        _renew(5_000);
        OffLib.Op[] memory ops = new OffLib.Op[](1);
        ops[0] = _use(5_000, 5_000 + A); // one ms past the allowance
        (OffLib.Header memory h, bytes32[] memory lv) = _header(1, bytes32(0), ops);
        assertEq(reg.proveOveruse(h, _seal(h, _idx(0, 1, 2)), ops[0], 0, _proof(lv, 0)), 3);
    }

    function test_useWithoutRenewalSlashes() public {
        OffLib.Op[] memory ops = new OffLib.Op[](1);
        ops[0] = _use(5_000, 6_000); // no renewal with base 5000 was ever issued by G
        (OffLib.Header memory h, bytes32[] memory lv) = _header(1, bytes32(0), ops);
        assertEq(reg.proveOveruse(h, _seal(h, _idx(1, 2, 3)), ops[0], 0, _proof(lv, 0)), 3);
    }

    function test_forkSlashesOnlyDoubleSealers() public {
        OffLib.Op[] memory a = new OffLib.Op[](1);
        a[0] = _consume(10, 10);
        OffLib.Op[] memory b = new OffLib.Op[](1);
        b[0] = _consume(12, 12);
        (OffLib.Header memory h1,) = _header(1, bytes32(0), a);
        (OffLib.Header memory h2,) = _header(1, bytes32(0), b);
        uint256 n = reg.proveFork(h1, _seal(h1, _idx(0, 1, 2)), h2, _seal(h2, _idx(1, 2, 3)));
        assertEq(n, 2);
        assertEq(reg.bond(SITE, va[0]), reg.BOND());
        assertEq(reg.bond(SITE, va[3]), reg.BOND());
        assertEq(reg.bond(SITE, va[1]), 0);
    }

    function test_slashingIsIdempotent() public {
        OffLib.Op[] memory ops = new OffLib.Op[](1);
        ops[0] = _consume(50, 50);
        (OffLib.Header memory h, bytes32[] memory lv) = _header(1, bytes32(0), ops);
        bytes[] memory s = _seal(h, _idx(0, 1, 2));
        assertEq(reg.proveOverspend(h, s, ops[0], 0, _proof(lv, 0)), 3);
        assertEq(reg.proveOverspend(h, s, ops[0], 0, _proof(lv, 0)), 0);
    }
}
