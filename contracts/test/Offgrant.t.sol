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
    bytes32 constant PERMIT = keccak256("switching-window:feeder-7");
    bytes32 constant LOTO = keccak256("isolation:pump-7");
    uint64 constant A = 99_000; // allowance, ms
    uint64 constant EPOCH = 1; // trusted-clock epoch (TPM resetCount/restartCount)
    uint64 constant LAG = 60_000; // anchor lag (ms)
    uint64 constant START = 5_000; // site clock reading at registration

    function setUp() public {
        vm.warp(1_000_000);
        reg = new RightsRegistry(RHO, SLACK, LAG);
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
        reg.createLease(PERMIT, true, A);
        reg.permit(PERMIT, SITE);
        reg.createLease(LOTO, true, A);
        reg.setOpenHold(LOTO);
        reg.permit(LOTO, SITE);

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

    function _consumeV(uint64 amount, uint64 runningTotal, uint64 version) internal pure returns (OffLib.Op memory) {
        return OffLib.Op(OffLib.CONSUME, PARTS, amount, runningTotal, version, 0, "");
    }

    function _consume(uint64 amount, uint64 runningTotal) internal pure returns (OffLib.Op memory) {
        return _consumeV(amount, runningTotal, 1);
    }

    function _holdE(bytes32 obj, uint64 epoch, uint64 cq, uint64 reading, uint64 until)
        internal
        pure
        returns (OffLib.Op memory)
    {
        return OffLib.Op(OffLib.USE, obj, cq, reading, until, epoch, _sig(CLOCK, OffLib.clockDigest(SITE, epoch, reading, obj)));
    }

    function _useE(uint64 epoch, uint64 cq, uint64 reading) internal pure returns (OffLib.Op memory) {
        return _holdE(PERMIT, epoch, cq, reading, reading);
    }

    function _use(uint64 cq, uint64 reading) internal pure returns (OffLib.Op memory) {
        return _useE(EPOCH, cq, reading);
    }

    function _clk(uint64 epoch, uint64 reading) internal pure returns (bytes memory) {
        return _sig(CLOCK, OffLib.clockDigest(SITE, epoch, reading, PERMIT));
    }

    function _clkT(uint64 reading, bytes32 tag) internal pure returns (bytes memory) {
        return _sig(CLOCK, OffLib.clockDigest(SITE, EPOCH, reading, tag));
    }

    function _hdr(uint64 height, bytes32 prev, OffLib.Op[] memory ops, uint64 close)
        internal
        pure
        returns (OffLib.Header memory h, bytes32[] memory leaves)
    {
        leaves = new bytes32[](ops.length);
        for (uint256 i = 0; i < ops.length; i++) {
            leaves[i] = OffLib.leaf(ops[i]);
        }
        h = OffLib.Header(SITE, height, prev, _root(leaves), uint64(ops.length), EPOCH, close, "");
        h.closeSig = _sig(CLOCK, OffLib.clockDigest(SITE, EPOCH, close, OffLib.contentTag(h)));
    }

    function _header(uint64 height, bytes32 prev, OffLib.Op[] memory ops)
        internal
        pure
        returns (OffLib.Header memory h, bytes32[] memory leaves)
    {
        return _hdr(height, prev, ops, START);
    }

    function _renewO(bytes32 obj, uint64 cq) internal returns (uint64) {
        return reg.renew(SITE, obj, EPOCH, cq, _sig(CLOCK, OffLib.requestDigest(SITE, obj, EPOCH, cq)));
    }

    function _renew(uint64 cq) internal returns (uint64) {
        return _renewO(PERMIT, cq);
    }

    function _one(OffLib.Op memory op) internal pure returns (OffLib.Op[] memory ops) {
        ops = new OffLib.Op[](1);
        ops[0] = op;
    }

    // ------------------------------------------------------------ Proposition 1: wait and reassignment
    function test_waitFormula() public view {
        // ceil(99000 ms / (1 - 1e-4)) = 99.0099.. s -> 100 s, plus 2 x 2 s timestamp error.
        assertEq(reg.waitSeconds(PERMIT), 104);
    }

    function testFuzz_waitCoversSlowClock(uint64 a, uint32 rho) public {
        a = uint64(bound(a, 1, 1e12));
        rho = uint32(bound(rho, 0, 999_999));
        RightsRegistry r = new RightsRegistry(rho, 0, LAG);
        r.createLease(PERMIT, true, a);
        uint256 w = r.waitSeconds(PERMIT);
        // A slow clock (1 - rho) needs A / (1 - rho) real time to advance A: the wait must cover it.
        assertGe(w * 1000 * (1_000_000 - uint256(rho)), uint256(a) * 1_000_000);
    }

    function test_reassignOnlyAfterRelease() public {
        uint64 issued = _renew(5_000);
        reg.stop(PERMIT, SITE2);
        vm.expectRevert();
        reg.renew(SITE, PERMIT, EPOCH, 6_000, _sig(CLOCK, OffLib.requestDigest(SITE, PERMIT, EPOCH, 6_000)));
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
        reg.renew(SITE, PERMIT, EPOCH, 5_000, _sig(vk[0], OffLib.requestDigest(SITE, PERMIT, EPOCH, 5_000)));
    }

    function test_sharesNeverExceedCap() public {
        vm.expectRevert(RightsRegistry.OverCap.selector);
        reg.setShare(PARTS, SITE, 41);
    }

    // ------------------------------------------------------------ site enforcement while cut off
    function _provisionSite(uint64 cq) internal {
        siteC.applyShare(PARTS, 40, 1, _cert(OffLib.shareDigest(address(reg), SITE, PARTS, 40, 1)));
        siteC.applyLease(PERMIT, A, false, _cert(OffLib.leaseDigest(address(reg), SITE, PERMIT, A, false)));
        siteC.applyLease(LOTO, A, true, _cert(OffLib.leaseDigest(address(reg), SITE, LOTO, A, true)));
        _applyRenewal(PERMIT, EPOCH, cq);
        _applyRenewal(LOTO, EPOCH, cq);
    }

    function _applyRenewal(bytes32 obj, uint64 epoch, uint64 cq) internal {
        siteC.applyRenewal(obj, epoch, cq, 7, _cert(OffLib.renewalDigest(address(reg), SITE, obj, epoch, cq, 7)));
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
        siteC.use(PERMIT, EPOCH, 5_000 + A - 1, 5_000 + A - 1, _clk(EPOCH, 5_000 + A - 1));
        vm.expectRevert();
        siteC.use(PERMIT, EPOCH, 5_000 + A, 5_000 + A, _clk(EPOCH, 5_000 + A));
    }

    function test_siteRejectsUncertifiedRights() public {
        bytes[] memory bad = new bytes[](2);
        bad[0] = _sig(gk[0], OffLib.shareDigest(address(reg), SITE, PARTS, 1000, 1));
        bad[1] = _sig(gk[0], OffLib.shareDigest(address(reg), SITE, PARTS, 1000, 1)); // same authority twice
        vm.expectRevert(SiteRights.BadCertificate.selector);
        siteC.applyShare(PARTS, 1000, 1, bad);
    }

    function test_siteRejectsForgedOrStaleClock() public {
        _provisionSite(5_000);
        vm.expectRevert(SiteRights.BadClockSig.selector);
        siteC.use(PERMIT, EPOCH, 6_000, 6_000, _sig(vk[0], OffLib.clockDigest(SITE, EPOCH, 6_000, PERMIT)));
        siteC.use(PERMIT, EPOCH, 7_000, 7_000, _clk(EPOCH, 7_000));
        vm.expectRevert(SiteRights.StaleReading.selector);
        siteC.use(PERMIT, EPOCH, 6_500, 6_500, _clk(EPOCH, 6_500));
    }

    // ------------------------------------------------------------ holds (review round 2)
    function test_boundedHoldMustEndInsideAllowance() public {
        _provisionSite(5_000);
        // A hold that would outlast the allowance is refused, even though it starts inside it.
        vm.expectRevert(abi.encodeWithSelector(SiteRights.AllowanceExpired.selector, 5_000 + A, 5_000 + A));
        siteC.use(PERMIT, EPOCH, 6_000, 5_000 + A, _clk(EPOCH, 6_000));
        siteC.use(PERMIT, EPOCH, 6_000, 5_000 + A - 1, _clk(EPOCH, 6_000));
        assertFalse(siteC.quiescent(PERMIT, 5_000 + A - 2));
        assertTrue(siteC.quiescent(PERMIT, 5_000 + A - 1));
    }

    function test_holdPastAllowanceIsSlashable() public {
        _renew(5_000);
        OffLib.Op[] memory ops = _one(_holdE(PERMIT, EPOCH, 5_000, 6_000, 5_000 + A)); // ends 1 ms too late
        (OffLib.Header memory h, bytes32[] memory lv) = _header(1, bytes32(0), ops);
        assertEq(reg.proveOveruse(h, _seal(h, _idx(0, 1, 2)), ops[0], 0, _proof(lv, 0)), 3);
    }

    function test_openHoldNeverMovesByExpiry() public {
        _provisionSite(5_000);
        siteC.use(LOTO, EPOCH, 6_000, OffLib.OPEN, _clkT(6_000, LOTO));
        assertFalse(siteC.quiescent(LOTO, type(uint64).max - 1));
        // On G the slow path is closed for open-hold objects, however long the wait.
        uint64 issued = _renewO(LOTO, 5_000);
        reg.stop(LOTO, SITE2);
        vm.warp(issued + reg.waitSeconds(LOTO) + 1 days);
        vm.expectRevert(RightsRegistry.HoldMayBeOpen.selector);
        reg.reassign(LOTO);
        // The release ends the hold; then the site's quorum may acknowledge.
        siteC.release(LOTO, EPOCH, 7_000, _clkT(7_000, OffLib.releaseTag(LOTO)));
        assertTrue(siteC.quiescent(LOTO, 7_000));
    }

    function test_releaseAfterAckIsSlashable() public {
        _renewO(LOTO, 5_000);
        reg.stop(LOTO, SITE2);
        bytes32 d = OffLib.ackDigest(address(reg), SITE, LOTO, EPOCH, 8_000);
        bytes[] memory acks = new bytes[](3);
        for (uint256 i = 0; i < 3; i++) {
            acks[i] = _sig(vk[i], d);
        }
        reg.reassignAcked(LOTO, EPOCH, 8_000, _clkT(8_000, LOTO), acks);
        // The lock was still on when the quorum acknowledged: its release is recorded after the ack.
        OffLib.Op memory rel = OffLib.Op(
            OffLib.RELEASE, LOTO, 5_000, 9_000, 0, EPOCH, _sig(CLOCK, OffLib.clockDigest(SITE, EPOCH, 9_000, OffLib.releaseTag(LOTO)))
        );
        (OffLib.Header memory h, bytes32[] memory lv) = _header(1, bytes32(0), _one(rel));
        assertEq(reg.proveUseAfterAck(h, _seal(h, _idx(0, 1, 3)), rel, 0, _proof(lv, 0)), 2);
    }

    // ------------------------------------------------------------ Theorem 1: no framing of honest checkpoints
    function test_honestCheckpointIsNotSlashable() public {
        _renew(5_000);
        OffLib.Op[] memory ops = new OffLib.Op[](3);
        ops[0] = _consume(30, 30);
        ops[1] = _holdE(PERMIT, EPOCH, 5_000, 5_000 + A - 10, 5_000 + A - 1);
        ops[2] = _consume(10, 40);
        (OffLib.Header memory h, bytes32[] memory lv) = _header(1, bytes32(0), ops);
        bytes[] memory s = _seal(h, _idx(0, 1, 2));
        vm.expectRevert(RightsRegistry.NotAViolation.selector);
        reg.proveOverspend(h, s, ops[2], 2, _proof(lv, 2));
        vm.expectRevert(RightsRegistry.NotAViolation.selector);
        reg.proveOveruse(h, s, ops[1], 1, _proof(lv, 1));
        vm.expectRevert(RightsRegistry.NotAViolation.selector);
        reg.proveUnderstate(h, ops[0], 0, _proof(lv, 0), h, s, ops[2], 2, _proof(lv, 2));
        reg.anchor(h, s);
        assertEq(reg.bond(SITE, va[0]), reg.BOND());
    }

    function test_belowQuorumIsRejected() public {
        OffLib.Op[] memory ops = _one(_consume(50, 50));
        (OffLib.Header memory h, bytes32[] memory lv) = _header(1, bytes32(0), ops);
        uint256[] memory two = new uint256[](2);
        (two[0], two[1]) = (0, 1);
        vm.expectRevert(RightsRegistry.NoQuorum.selector);
        reg.proveOverspend(h, _seal(h, two), ops[0], 0, _proof(lv, 0));
    }

    // ------------------------------------------------------------ Theorem 1: over-threshold site is attributed
    function test_overspendSlashesSealers() public {
        OffLib.Op[] memory ops = new OffLib.Op[](2);
        ops[0] = _consume(30, 30);
        ops[1] = _consume(25, 55); // share is 40
        (OffLib.Header memory h, bytes32[] memory lv) = _header(1, bytes32(0), ops);
        uint256 n = reg.proveOverspend(h, _seal(h, _idx(0, 1, 2)), ops[1], 1, _proof(lv, 1));
        assertEq(n, 3);
        assertEq(reg.bond(SITE, va[3]), reg.BOND()); // the validator that did not seal keeps its bond
    }

    function test_firstConsumptionBelowItsAmountSlashes() public {
        OffLib.Op[] memory ops = _one(_consume(30, 5)); // a total below its own amount hides 25 units
        (OffLib.Header memory h, bytes32[] memory lv) = _header(1, bytes32(0), ops);
        assertEq(reg.proveOverspend(h, _seal(h, _idx(0, 1, 2)), ops[0], 0, _proof(lv, 0)), 3);
    }

    function test_understateAcrossAnchoredCheckpointsSlashesLaterSealers() public {
        OffLib.Op[] memory ops1 = _one(_consume(35, 35));
        (OffLib.Header memory h1, bytes32[] memory lv1) = _hdr(1, bytes32(0), ops1, 6_000);
        reg.anchor(h1, _seal(h1, _idx(0, 1, 2)));
        OffLib.Op[] memory ops2 = new OffLib.Op[](2);
        ops2[0] = _consume(20, 20); // running total reset: claims 20 instead of 55
        ops2[1] = OffLib.Op(OffLib.LOG, keccak256("x"), 0, 0, 0, 0, "");
        (OffLib.Header memory h2, bytes32[] memory lv2) = _hdr(2, OffLib.headerHash(h1), ops2, 7_000);
        uint256 n = reg.proveUnderstate(
            h1, ops1[0], 0, _proof(lv1, 0), h2, _seal(h2, _idx(1, 2, 3)), ops2[0], 0, _proof(lv2, 0)
        );
        assertEq(n, 3);
        assertEq(reg.bond(SITE, va[0]), reg.BOND());
    }

    function test_understateNeedsAnchoredEarlierCheckpoint() public {
        OffLib.Op[] memory ops1 = _one(_consume(35, 35));
        (OffLib.Header memory h1, bytes32[] memory lv1) = _hdr(1, bytes32(0), ops1, 6_000);
        OffLib.Op[] memory ops2 = _one(_consume(20, 20));
        (OffLib.Header memory h2, bytes32[] memory lv2) = _hdr(5, keccak256("elsewhere"), ops2, 7_000);
        bytes[] memory s2 = _seal(h2, _idx(1, 2, 3));
        bytes32[] memory p1 = _proof(lv1, 0);
        bytes32[] memory p2 = _proof(lv2, 0);
        // An unrelated header cannot be paired with h1 to frame the sealers of h2.
        vm.expectRevert(RightsRegistry.BadProof.selector);
        reg.proveUnderstate(h1, ops1[0], 0, p1, h2, s2, ops2[0], 0, p2);
    }

    function test_overusePastAllowanceSlashes() public {
        _renew(5_000);
        OffLib.Op[] memory ops = _one(_use(5_000, 5_000 + A)); // one ms past the allowance
        (OffLib.Header memory h, bytes32[] memory lv) = _header(1, bytes32(0), ops);
        assertEq(reg.proveOveruse(h, _seal(h, _idx(0, 1, 2)), ops[0], 0, _proof(lv, 0)), 3);
    }

    function test_useWithoutRenewalSlashes() public {
        OffLib.Op[] memory ops = _one(_use(5_000, 6_000)); // no renewal with base 5000 was ever issued by G
        (OffLib.Header memory h, bytes32[] memory lv) = _header(1, bytes32(0), ops);
        assertEq(reg.proveOveruse(h, _seal(h, _idx(1, 2, 3)), ops[0], 0, _proof(lv, 0)), 3);
    }

    function test_forkSlashesOnlyDoubleSealers() public {
        (OffLib.Header memory h1,) = _header(1, bytes32(0), _one(_consume(10, 10)));
        (OffLib.Header memory h2,) = _header(1, bytes32(0), _one(_consume(12, 12)));
        uint256 n = reg.proveFork(h1, _seal(h1, _idx(0, 1, 2)), h2, _seal(h2, _idx(1, 2, 3)));
        assertEq(n, 2);
        assertEq(reg.bond(SITE, va[0]), reg.BOND());
        assertEq(reg.bond(SITE, va[3]), reg.BOND());
        assertEq(reg.bond(SITE, va[1]), 0);
    }

    function test_slashingIsIdempotent() public {
        OffLib.Op[] memory ops = _one(_consume(50, 50));
        (OffLib.Header memory h, bytes32[] memory lv) = _header(1, bytes32(0), ops);
        bytes[] memory s = _seal(h, _idx(0, 1, 2));
        assertEq(reg.proveOverspend(h, s, ops[0], 0, _proof(lv, 0)), 3);
        assertEq(reg.proveOverspend(h, s, ops[0], 0, _proof(lv, 0)), 0);
    }

    // ------------------------------------------------------------ sanctions (review round 2)
    function test_slashedValidatorsLoseQuorumAndSiteIsRevoked() public {
        (OffLib.Header memory h, bytes32[] memory lv) = _header(1, bytes32(0), _one(_consume(50, 50)));
        reg.proveOverspend(h, _seal(h, _idx(0, 1, 2)), _consume(50, 50), 0, _proof(lv, 0));
        (bool exists, bool revoked,,,,,,,,) = reg.sites(SITE);
        assertTrue(exists && revoked); // f + 1 = 2 validators slashed
        vm.expectRevert(RightsRegistry.SiteRevokedErr.selector);
        _renew(5_000);
        // Slashed validators no longer form a quorum for new anchors.
        (OffLib.Header memory g,) = _header(1, bytes32(0), _one(OffLib.Op(OffLib.LOG, keccak256("y"), 0, 0, 0, 0, "")));
        vm.expectRevert(RightsRegistry.NoQuorum.selector);
        reg.anchor(g, _seal(g, _idx(0, 1, 2)));
    }

    // ------------------------------------------------------------ clock epochs, stops and the fast path
    function test_clockResetExpiresAllowance() public {
        _provisionSite(5_000);
        // After a power loss the TPM starts a new epoch: the old allowance no longer applies.
        vm.expectRevert(SiteRights.NoRenewal.selector);
        siteC.use(PERMIT, EPOCH + 1, 6_000, 6_000, _clk(EPOCH + 1, 6_000));
    }

    function test_useInNewEpochIsSlashable() public {
        _renew(5_000);
        OffLib.Op[] memory ops = _one(_useE(EPOCH + 1, 5_000, 6_000)); // base from epoch 1 used in epoch 2
        (OffLib.Header memory h, bytes32[] memory lv) = _header(1, bytes32(0), ops);
        assertEq(reg.proveOveruse(h, _seal(h, _idx(0, 1, 2)), ops[0], 0, _proof(lv, 0)), 3);
    }

    function test_stopEndsAllowanceAtOnce() public {
        _provisionSite(5_000);
        siteC.applyStop(PERMIT, EPOCH, 5_000, _cert(OffLib.stopDigest(address(reg), SITE, PERMIT, EPOCH, 5_000)));
        vm.expectRevert(SiteRights.NoRenewal.selector);
        siteC.use(PERMIT, EPOCH, 6_000, 6_000, _clk(EPOCH, 6_000));
    }

    function test_stopCannotCancelLaterRenewal() public {
        _provisionSite(5_000);
        siteC.applyStop(PERMIT, EPOCH, 5_000, _cert(OffLib.stopDigest(address(reg), SITE, PERMIT, EPOCH, 5_000)));
        _applyRenewal(PERMIT, EPOCH, 9_000); // granted again after a later re-assignment
        siteC.use(PERMIT, EPOCH, 9_500, 9_500, _clk(EPOCH, 9_500));
        // Replaying the old stop changes nothing.
        siteC.applyStop(PERMIT, EPOCH, 5_000, _cert(OffLib.stopDigest(address(reg), SITE, PERMIT, EPOCH, 5_000)));
        siteC.use(PERMIT, EPOCH, 9_600, 9_600, _clk(EPOCH, 9_600));
    }

    function _ack(uint64 reading, uint256[] memory who) internal view returns (bytes[] memory s) {
        bytes32 d = OffLib.ackDigest(address(reg), SITE, PERMIT, EPOCH, reading);
        s = new bytes[](who.length);
        for (uint256 i = 0; i < who.length; i++) {
            s[i] = _sig(vk[who[i]], d);
        }
    }

    function test_fastPathReassignsAtOnce() public {
        _renew(5_000);
        reg.stop(PERMIT, SITE2);
        uint256[] memory two = new uint256[](2);
        (two[0], two[1]) = (0, 1);
        vm.expectRevert(RightsRegistry.NoQuorum.selector);
        reg.reassignAcked(PERMIT, EPOCH, 8_000, _clk(EPOCH, 8_000), _ack(8_000, two));
        reg.reassignAcked(PERMIT, EPOCH, 8_000, _clk(EPOCH, 8_000), _ack(8_000, _idx(0, 1, 2)));
        assertTrue(reg.mayRenew(PERMIT, SITE2));
    }

    function test_useAfterAckSlashesOnlyAckersThatSealedIt() public {
        _renew(5_000);
        reg.stop(PERMIT, SITE2);
        reg.reassignAcked(PERMIT, EPOCH, 8_000, _clk(EPOCH, 8_000), _ack(8_000, _idx(0, 1, 2)));
        OffLib.Op[] memory ops = new OffLib.Op[](3);
        ops[0] = _use(5_000, 8_000); // at the acknowledged reading: before the stop, not a violation
        ops[1] = _use(5_000, 8_001); // granted after it
        ops[2] = _holdE(PERMIT, EPOCH, 5_000, 7_000, 8_500); // granted before, but still held after it
        (OffLib.Header memory h, bytes32[] memory lv) = _header(1, bytes32(0), ops);
        bytes[] memory seals = _seal(h, _idx(1, 2, 3));
        vm.expectRevert(RightsRegistry.NotAViolation.selector);
        reg.proveUseAfterAck(h, seals, ops[0], 0, _proof(lv, 0));
        assertEq(reg.proveUseAfterAck(h, seals, ops[2], 2, _proof(lv, 2)), 2);
        assertEq(reg.bond(SITE, va[0]), reg.BOND()); // acked but did not seal
        assertEq(reg.bond(SITE, va[3]), reg.BOND()); // sealed but did not ack
    }

    // ------------------------------------------------------------ review round 1 fixes
    function test_renewNeedsAnchoredCoverage() public {
        _renew(START + LAG); // within the lag after registration
        uint64 far = START + LAG + 1;
        vm.expectRevert(abi.encodeWithSelector(RightsRegistry.AnchorDebt.selector, START, far - LAG));
        reg.renew(SITE, PERMIT, EPOCH, far, _sig(CLOCK, OffLib.requestDigest(SITE, PERMIT, EPOCH, far)));
        // Anchoring a checkpoint whose clock-attested close is later restores renewals.
        (OffLib.Header memory h,) = _hdr(1, bytes32(0), _one(OffLib.Op(OffLib.LOG, keccak256("x"), 0, 0, 0, 0, "")), far);
        reg.anchor(h, _seal(h, _idx(0, 1, 2)));
        _renew(far);
    }

    function test_staleAckIsRejected() public {
        _renew(5_000);
        reg.stop(PERMIT, SITE2);
        // An acknowledgement older than the last renewal (e.g. replayed from an earlier hand-over) is refused.
        vm.expectRevert(RightsRegistry.StaleAck.selector);
        reg.reassignAcked(PERMIT, EPOCH, 4_999, _clk(EPOCH, 4_999), _ack(4_999, _idx(0, 1, 2)));
    }

    function test_quorumForLargerSites() public {
        uint64 S5 = 5;
        address[] memory v5 = new address[](5);
        uint256[5] memory k5 = [uint256(0xE1), 0xE2, 0xE3, 0xE4, 0xE5];
        for (uint256 i = 0; i < 5; i++) {
            v5[i] = vm.addr(k5[i]);
        }
        reg.registerSite(S5, 1, vm.addr(CLOCK2), v5, EPOCH, START);
        OffLib.Op[] memory ops = _one(_consume(50, 50)); // site 5 has no share
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = OffLib.leaf(ops[0]);
        OffLib.Header memory h = OffLib.Header(S5, 1, bytes32(0), _root(leaves), 1, EPOCH, 0, "");
        bytes32 d = OffLib.checkpointDigest(address(reg), OffLib.headerHash(h));
        bytes[] memory three = new bytes[](3);
        for (uint256 i = 0; i < 3; i++) {
            three[i] = _sig(k5[i], d);
        }
        // n = 5, f = 1: quorum floor(6/2)+1 = 4, so three seals are not enough.
        vm.expectRevert(RightsRegistry.NoQuorum.selector);
        reg.proveOverspend(h, three, ops[0], 0, _proof(leaves, 0));
        bytes[] memory four = new bytes[](4);
        for (uint256 i = 0; i < 4; i++) {
            four[i] = _sig(k5[i], d);
        }
        assertEq(reg.proveOverspend(h, four, ops[0], 0, _proof(leaves, 0)), 4);
    }

    // ------------------------------------------------------------ review round 2 regressions
    function test_anchorNeedsAttestedClose() public {
        (OffLib.Header memory h,) = _hdr(1, bytes32(0), _one(OffLib.Op(OffLib.LOG, keccak256("x"), 0, 0, 0, 0, "")), 900_000);
        h.closeReading = 9_000_000; // a faulty quorum inflates its coverage: the clock never attested it
        vm.expectRevert(RightsRegistry.BadClockSig.selector);
        reg.anchor(h, _seal(h, _idx(0, 1, 2)));
    }

    function test_replayedOlderRequestIsRejected() public {
        uint64 newer = START + 50_000;
        _renew(newer);
        // A relayer that withheld an older signed request cannot roll the last renewal back.
        vm.expectRevert(RightsRegistry.StaleRequest.selector);
        _renew(START + 10_000);
    }

    function test_ackRaisesRenewalFloor() public {
        _renew(5_000);
        reg.stop(PERMIT, SITE2);
        reg.reassignAcked(PERMIT, EPOCH, 8_000, _clk(EPOCH, 8_000), _ack(8_000, _idx(0, 1, 2)));
        // A request signed before the ack but never relayed cannot be used after the object comes back.
        (uint64 fe, uint64 fcq) = reg.lastRenewal(PERMIT, SITE);
        assertEq(fe, EPOCH);
        assertEq(fcq, 8_000); // the floor is the acknowledged reading
    }

    function test_honestUseAfterReturnIsNotFramed() public {
        _renew(5_000);
        reg.stop(PERMIT, SITE2);
        reg.reassignAcked(PERMIT, EPOCH, 8_000, _clk(EPOCH, 8_000), _ack(8_000, _idx(0, 1, 2)));
        // Later grant under a renewal newer than the ack (base 20000): not a use after the ack.
        OffLib.Op[] memory ops = _one(_use(20_000, 21_000));
        (OffLib.Header memory h, bytes32[] memory lv) = _header(1, bytes32(0), ops);
        vm.expectRevert(RightsRegistry.NotAViolation.selector);
        reg.proveUseAfterAck(h, _seal(h, _idx(0, 1, 2)), ops[0], 0, _proof(lv, 0));
    }

    function test_shareReductionIsVersionedAndAcknowledged() public {
        // Lower SITE's share from 40 to 20 (version 2): capacity stays reserved until the site acknowledges.
        reg.setShare(PARTS, SITE, 20);
        vm.expectRevert(RightsRegistry.OverCap.selector);
        reg.setShare(PARTS, SITE2, 61);
        // Consumption made under version 1 up to 40 stays honest: no framing after the reduction.
        OffLib.Op[] memory ops = _one(_consumeV(5, 40, 1));
        (OffLib.Header memory h, bytes32[] memory lv) = _header(1, bytes32(0), ops);
        vm.expectRevert(RightsRegistry.NotAViolation.selector);
        reg.proveOverspend(h, _seal(h, _idx(0, 1, 2)), ops[0], 0, _proof(lv, 0));
        // The site applies version 2 (its total must already be within 20) and cannot go back to version 1.
        siteC.applyShare(PARTS, 20, 2, _cert(OffLib.shareDigest(address(reg), SITE, PARTS, 20, 2)));
        vm.expectRevert(SiteRights.StaleShare.selector);
        siteC.applyShare(PARTS, 40, 1, _cert(OffLib.shareDigest(address(reg), SITE, PARTS, 40, 1)));
        bytes32 d = OffLib.shareAckDigest(address(reg), SITE, PARTS, 2);
        bytes[] memory acks = new bytes[](3);
        for (uint256 i = 0; i < 3; i++) {
            acks[i] = _sig(vk[i], d);
        }
        reg.confirmShare(PARTS, SITE, acks);
        reg.setShare(PARTS, SITE2, 80); // the freed capacity is now available
        // Under version 2, a total above 20 is provable.
        OffLib.Op[] memory ops2 = _one(_consumeV(5, 25, 2));
        (OffLib.Header memory h2, bytes32[] memory lv2) = _header(2, bytes32(0), ops2);
        assertEq(reg.proveOverspend(h2, _seal(h2, _idx(0, 1, 2)), ops2[0], 0, _proof(lv2, 0)), 3);
    }
}
