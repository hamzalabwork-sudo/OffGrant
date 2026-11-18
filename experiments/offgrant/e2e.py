"""End-to-end run of OffGrant on local PureChain networks (testbed/purechain/net_offgrant).

Global chain G (4 Clique signers, the authorities) and two site chains (4 signers each, the site validators).
Each site's relayer reaches G only through its uplink proxy container; cutting the proxy (netem loss 100%)
cuts the site's uplink while the site chain keeps running. Site clocks are TPM-like: drift (site 1 at the
-15% bound, site 2 at +5%), restart epochs, attested readings.

Scenario (seconds after start):
  20  cut site 1's uplink for CUT s
  35  G stops permit P11 (held by site 1, cut off) and names site 2: slow path, reassignment only at releaseAt
  45  G revokes credential C11 of site 1 (cut off): it stays usable at most until its allowance ends
  20+CUT  heal site 1; its relayer anchors the checkpoints of the outage and applies the stop/revocation
  +30 G stops permit P21 (held by site 2, connected): fast path, acknowledged reassignment
  +60 power loss at site 2 (clock epoch changes): its allowances end until renewed in the new epoch
Then fraud proofs against a Byzantine site quorum (fresh registries, so every slashing count is clean), and
no-framing checks against every honest anchored operation. Writes experiments/results/e2e_<tag>.json.
"""
import argparse
import json
import random
import secrets
import subprocess
import threading
import time
import traceback
from pathlib import Path

from eth_account import Account
from eth_utils import keccak

import chain as C

ROOT = C.ROOT
NET = ROOT / "testbed" / "purechain" / "net_offgrant"
RHO_PPM = 150_000      # TPM 2.0 bound: rate within 15% of UTC
D_S = 60               # offline tolerance (s), time-compressed for a real-time run
A_MS = int(D_S * 1000 * (1 + RHO_PPM / 1e6))
P_RENEW = 4.0          # renewal period while connected (s)
CKPT_EVERY = 12.0      # checkpoint period (s)
CONFIRM = 3            # site blocks a checkpoint waits for (Clique has no finality)
LAG_MS = 60_000        # anchor lag: renewals need anchored coverage up to (request reading - lag)
WARMUP = 25           # s of normal operation before the scenario events (anchors and renewals settle)


def obj(name):
    return keccak(text=name)


class Log:
    def __init__(self, t0):
        self.t0 = t0
        self.rows = []
        self.lock = threading.Lock()

    def add(self, kind, **kw):
        with self.lock:
            self.rows.append({"t": round(time.time() - self.t0, 3), "kind": kind, **kw})


def uplink(site, on):
    name = f"up{site}"
    subprocess.run(["docker", "exec", name, "tc", "qdisc", "del", "dev", "eth0", "root"], capture_output=True)
    if not on:
        subprocess.run(["docker", "exec", name, "tc", "qdisc", "add", "dev", "eth0", "root", "netem", "loss", "100%"],
                       check=True, capture_output=True)


class Site:
    def __init__(self, k, nodes, ctx):
        self.k = k
        self.ctx = ctx
        self.vals = nodes[f"s{k}"]
        self.vkeys = [v["key"] for v in self.vals]
        self.w3 = C.connect(self.vals[0]["rpc"])
        self.vw3 = [C.connect(v["rpc"]) for v in self.vals]
        self.clock = C.Clock("0x" + secrets.token_hex(32), k, ctx["drift"][k], ctx["t0"])
        self.relayer_key = "0x" + secrets.token_hex(32)
        self.operator_key = "0x" + secrets.token_hex(32)
        self.rel_s = C.Sender(self.w3, self.relayer_key)
        self.op_s = C.Sender(self.w3, self.operator_key)
        self.g = C.connect(8790 + k, timeout=3)          # through the uplink proxy
        self.rel_g = C.Sender(self.g, self.relayer_key)
        self.contract = None
        self.ckpts = []            # sealed checkpoints waiting for anchoring
        self.anchored = []
        self.height = 0
        self.prev = b"\x00" * 32
        self.ckpt_block = 0
        self.handled_stops = set()


def certify(ctx, digest):
    return [C.sign(k, digest) for k in ctx["gkeys"][:3]]


def setup(ctx, nodes):
    gadmin = C.Sender(C.connect(8700), nodes["g"][0]["key"])
    ctx["gadmin"] = gadmin
    reg, r = gadmin.deploy("RightsRegistry", RHO_PPM, 2, LAG_MS)
    ctx["reg"] = reg
    ctx["gas"]["deploy_registry"] = r.gasUsed
    ctx["gkeys"] = [n["key"] for n in nodes["g"]]
    auth = [Account.from_key(k).address for k in ctx["gkeys"]]
    parts = obj("spare-parts")
    gadmin.send(reg.functions.setCap(parts, 100))
    for s in ctx["sites"].values():
        gadmin.send(reg.functions.registerSite(s.k, 1, Account.from_key(s.clock.key).address,
                                               [v["address"] for v in s.vals], s.clock.read()))
        gadmin.send(reg.functions.setShare(parts, s.k, 40))
        s.close_next = s.clock.read()
        s.contract, r = s.rel_s.deploy("SiteRights", s.k, reg.address, Account.from_key(s.clock.key).address,
                                       auth, 3)
        ctx["gas"]["deploy_site"] = r.gasUsed
        s.rel_s.send(s.contract.functions.applyShare(parts, 40, certify(ctx, C.share_digest(reg.address, s.k, parts, 40))))
        s.ckpt_block = s.w3.eth.block_number
        for name, excl in [(f"P{s.k}1", True), (f"P{s.k}2", True), (f"C{s.k}1", False)]:
            o = obj(name)
            gadmin.send(reg.functions.createLease(o, excl, A_MS))
            gadmin.send(reg.functions.permit(o, s.k))
    # every site learns every lease's allowance (an object may move to it later)
    for s in ctx["sites"].values():
        for name in ctx["objects"]:
            o = obj(name)
            s.rel_s.send(s.contract.functions.applyLease(o, A_MS, certify(ctx, C.lease_digest(reg.address, s.k, o, A_MS))))
    ctx["parts"] = parts


# ------------------------------------------------------------------------------------------- relayer
def relay_once(ctx, s):
    reg_g = ctx["reg_at"](s.g)
    try:
        s.g.eth.block_number
    except Exception:
        return False
    while s.ckpts:   # anchor first: G renews only sites whose checkpoints are anchored (anchor before renew)
        h, sigs, ops = s.ckpts[0]
        r = s.rel_g.send(reg_g.functions.anchor(h, sigs))
        ctx["log"].add("anchor", site=s.k, height=h[1], ops=h[4], status=r.status, gas=r.gasUsed)
        s.anchored.append((h, sigs, ops))
        s.ckpts.pop(0)
    for name in ctx["objects"]:
        o = obj(name)
        lease = reg_g.functions.leases(o).call()   # exists, exclusive, stopped, allowance, lastIssue, holder, next
        exclusive, stopped, holder = lease[1], lease[2], lease[5]
        if stopped and (holder == s.k if exclusive else reg_g.functions.permitted(o, s.k).call()):
            if (name, lease[4]) not in s.handled_stops:
                handle_stop(ctx, s, name, o, exclusive, reg_g)
                s.handled_stops.add((name, lease[4]))
            continue
        if not reg_g.functions.mayRenew(o, s.k).call():
            continue
        t_send = time.time()
        cq = s.clock.read()
        sig = s.clock.attest(C.request_digest, s.k, o, s.clock.epoch, cq)
        try:   # a renewal G would refuse (e.g. AnchorDebt) is not sent; it is logged instead
            reg_g.functions.renew(s.k, o, s.clock.epoch, cq, sig).call({"from": s.rel_g.acct.address})
        except Exception as e:  # noqa: BLE001
            if "timed out" in str(e) or "Connection" in str(e) or "Max retries" in str(e):
                raise
            ctx["log"].add("renew_refused", site=s.k, obj=name, why=str(e)[:80])
            continue
        r = s.rel_g.send(reg_g.functions.renew(s.k, o, s.clock.epoch, cq, sig))
        if r.status != 1:
            continue
        ev = reg_g.events.Renewed().process_receipt(r)[0]["args"]
        cert = certify(ctx, C.renewal_digest(ctx["reg"].address, s.k, o, ev["epoch"], ev["cq"], ev["issued"]))
        r2 = s.rel_s.send(s.contract.functions.applyRenewal(o, ev["epoch"], ev["cq"], ev["issued"], cert))
        ctx["log"].add("renewal", site=s.k, obj=name, epoch=ev["epoch"], cq=ev["cq"], issued=ev["issued"],
                       t_send=round(t_send - ctx["t0"], 3), latency=round(time.time() - t_send, 3),
                       gas_g=r.gasUsed, gas_site=r2.gasUsed)
    while s.ckpts:
        h, sigs, ops = s.ckpts[0]
        r = s.rel_g.send(reg_g.functions.anchor(h, sigs))
        ctx["log"].add("anchor", site=s.k, height=h[1], ops=h[4], status=r.status, gas=r.gasUsed)
        s.anchored.append((h, sigs, ops))
        s.ckpts.pop(0)
    return True


def handle_stop(ctx, s, name, o, exclusive, reg_g):
    t = time.time()
    epoch, cq = reg_g.functions.lastRenewal(o, s.k).call()
    cert = certify(ctx, C.stop_digest(ctx["reg"].address, s.k, o, epoch, cq))
    r = s.rel_s.send(s.contract.functions.applyStop(o, epoch, cq, cert))
    ctx["log"].add("stop_applied", site=s.k, obj=name, latency_from_seen=round(time.time() - t, 3), gas=r.gasUsed)
    if not exclusive:
        return
    # Fast path: validators acknowledge once their own node shows the stop executed.
    reading = s.clock.read()
    csig = s.clock.attest(C.clock_digest, s.k, s.clock.epoch, reading, o)
    acks = []
    for vw, vk in zip(s.vw3, s.vkeys):
        sc = vw.eth.contract(address=s.contract.address, abi=s.contract.abi)
        for _ in range(20):
            if tuple(sc.functions.stoppedUpTo(o).call()) >= (epoch, cq):
                acks.append(C.sign(vk, C.ack_digest(ctx["reg"].address, s.k, o, s.clock.epoch, reading)))
                break
            time.sleep(0.25)
    r = s.rel_g.send(reg_g.functions.reassignAcked(o, s.clock.epoch, reading, csig, acks))
    ctx["log"].add("reassign_acked", site=s.k, obj=name, status=r.status, gas=r.gasUsed,
                   latency_from_seen=round(time.time() - t, 3))


def relayer(ctx, s, stop):
    up_prev = None
    while not stop.is_set():
        try:
            up = relay_once(ctx, s)
        except Exception as e:  # noqa: BLE001  (timeouts while the uplink is cut)
            up = False
            if "timed out" not in str(e) and "Max retries" not in str(e) and "Connection" not in str(e):
                ctx["log"].add("relayer_error", site=s.k, err=str(e)[:160])
        if up != up_prev:
            ctx["log"].add("uplink_seen", site=s.k, up=up)
            up_prev = up
        stop.wait(P_RENEW)


# ------------------------------------------------------------------------------------------- checkpoints
def checkpointer(ctx, s, stop):
    while not stop.wait(CKPT_EVERY):
        try:
            head = s.w3.eth.block_number - CONFIRM
            lo, hi = s.ckpt_block, head
            if hi <= lo:
                continue
            headers = []
            for vw in s.vw3:   # every validator builds the header from its own node
                sc = vw.eth.contract(address=s.contract.address, abi=s.contract.abi)
                logs = sc.events.Op().get_logs(from_block=lo, to_block=hi - 1)
                ops = [(l["args"]["kind"], l["args"]["key"], l["args"]["a"], l["args"]["b"], l["args"]["e"],
                        l["args"]["clockSig"]) for l in sorted(logs, key=lambda l: l["args"]["seq"])]
                root, _ = C.merkle([C.op_leaf(op) for op in ops])
                headers.append(((s.k, s.height + 1, s.prev, root, len(ops), s.close_next), ops))
            s.ckpt_block = hi
            s.close_next = s.clock.read()
            h, ops = headers[0]
            sigs = [C.sign(vk, C.checkpoint_digest(ctx["reg"].address, C.header_hash(hv)))
                    for (hv, _), vk in zip(headers, s.vkeys) if hv == h]
            s.height += 1
            s.prev = C.header_hash(h)
            s.ckpts.append((h, sigs, ops))
            ctx["log"].add("checkpoint", site=s.k, height=h[1], ops=h[4], agree=len(sigs), lo=lo, hi=hi)
        except Exception as e:  # noqa: BLE001
            ctx["log"].add("ckpt_error", site=s.k, err=str(e)[:160])


# ------------------------------------------------------------------------------------------- workload
def operator(ctx, s, stop):
    rnd = random.Random(s.k)
    parts = ctx["parts"]
    while not stop.wait(1.0):
        kind = rnd.choices(["use", "cred", "consume", "log"], [0.5, 0.2, 0.2, 0.1])[0]
        t = time.time()
        try:
            if kind in ("use", "cred"):
                names = [n for n in ctx["objects"] if (n.startswith("C") if kind == "cred" else n.startswith("P"))]
                held = [n for n in names if s.contract.functions.base(obj(n)).call()[1] != 0]
                if not held:
                    ctx["log"].add("op", site=s.k, op=kind, obj=None, ok=False, why="none held")
                    continue
                name = rnd.choice(held)
                reading = s.clock.read()
                fn = s.contract.functions.use(obj(name), s.clock.epoch, reading,
                                              s.clock.attest(C.clock_digest, s.k, s.clock.epoch, reading, obj(name)))
            elif kind == "consume":
                name, fn = "parts", s.contract.functions.consume(parts, 1)
            else:
                name, fn = "log", s.contract.functions.record(keccak(text=f"log{t}"))
            try:
                fn.call({"from": s.op_s.acct.address})
            except Exception as e:  # noqa: BLE001  rejected by the site contract
                ctx["log"].add("op", site=s.k, op=kind, obj=name, ok=False, why=str(e)[:60])
                continue
            r = s.op_s.send(fn)
            ctx["log"].add("op", site=s.k, op=kind, obj=name, ok=r.status == 1, latency=round(time.time() - t, 3),
                           gas=r.gasUsed, block=r.blockNumber)
        except Exception as e:  # noqa: BLE001
            ctx["log"].add("op_error", site=s.k, err=str(e)[:120])


# ------------------------------------------------------------------------------------------- scenario
def admin_wait_reassign(ctx, o, name):
    reg = ctx["reg"]
    w3 = ctx["gadmin"].w3
    while True:
        at = reg.functions.releaseAt(o).call()
        now = w3.eth.get_block("latest").timestamp
        if now >= at:
            r = ctx["gadmin"].send(reg.functions.reassign(o))
            ctx["log"].add("reassigned_slow", obj=name, release_at=at, g_time=now, status=r.status, gas=r.gasUsed)
            return
        time.sleep(1)


def scenario(ctx, cut_s):
    reg, admin, log = ctx["reg"], ctx["gadmin"], ctx["log"]
    t0 = ctx["t0"]

    def at(t):
        time.sleep(max(0.0, t0 + WARMUP + t - time.time()))

    at(20)
    uplink(1, False)
    log.add("uplink_cut", site=1)
    at(35)
    r = admin.send(reg.functions.stop(obj("P11"), 2))
    log.add("stop", obj="P11", next=2, release_at=reg.functions.releaseAt(obj("P11")).call(), gas=r.gasUsed,
            g_time=admin.w3.eth.get_block(r.blockNumber).timestamp)
    threading.Thread(target=admin_wait_reassign, args=(ctx, obj("P11"), "P11"), daemon=True).start()
    at(45)
    r = admin.send(reg.functions.stop(obj("C11"), 0))
    log.add("revoke", obj="C11", gas=r.gasUsed, release_at=reg.functions.releaseAt(obj("C11")).call(),
            g_time=admin.w3.eth.get_block(r.blockNumber).timestamp)
    at(20 + cut_s)
    uplink(1, True)
    log.add("uplink_heal", site=1)
    at(20 + cut_s + 30)
    r = admin.send(reg.functions.stop(obj("P21"), 1))
    log.add("stop", obj="P21", next=1, g_time=admin.w3.eth.get_block(r.blockNumber).timestamp, gas=r.gasUsed)
    at(20 + cut_s + 60)
    ctx["sites"][2].clock.reset()
    log.add("clock_reset", site=2, epoch=ctx["sites"][2].clock.epoch)
    at(20 + cut_s + 90)


# ------------------------------------------------------------------------------------------- attacks
def attacks(ctx, nodes):
    """Byzantine quorum (validators 1-3 of a site) seals out-of-rights checkpoints; fresh registries keep the
    slashing counts per attack independent. Returns gas and number of validators slashed per proof."""
    out = {}
    admin = ctx["gadmin"]
    s1, s2 = ctx["sites"][1], ctx["sites"][2]
    parts = obj("spare-parts")

    def fresh():
        reg, _ = admin.deploy("RightsRegistry", RHO_PPM, 2, LAG_MS)
        admin.send(reg.functions.setCap(parts, 100))
        for s in (s1, s2):
            admin.send(reg.functions.registerSite(s.k, 1, Account.from_key(s.clock.key).address,
                                                  [v["address"] for v in s.vals], s.clock.read()))
            admin.send(reg.functions.setShare(parts, s.k, 40))
        o = obj("P-attack")
        admin.send(reg.functions.createLease(o, True, A_MS))
        admin.send(reg.functions.permit(o, s1.k))
        return reg, o

    def sealed(reg, site, ops, signers, height=1, prev=b"\x00" * 32):
        root, proofs = C.merkle([C.op_leaf(op) for op in ops])
        h = (site.k, height, prev, root, len(ops), 0)
        sigs = [C.sign(site.vkeys[i], C.checkpoint_digest(reg.address, C.header_hash(h))) for i in signers]
        return h, sigs, proofs

    def run(name, reg, fn):
        r = admin.send(fn, gas=6_000_000)
        n = len(reg.events.Slashed().process_receipt(r))
        out[name] = {"status": r.status, "gas": r.gasUsed, "slashed": n}

    byz = [0, 1, 2]
    # Overspend: running total above the share.
    reg, o = fresh()
    ops = [(C.CONSUME, parts, 45, 45, 0, b"")]
    h, sigs, pr = sealed(reg, s1, ops, byz)
    run("overspend", reg, reg.functions.proveOverspend(h, sigs, ops[0], 0, pr[0]))
    # Understated running total (consumption reset to hide 30 units).
    reg, o = fresh()
    ops = [(C.CONSUME, parts, 30, 30, 0, b""), (C.CONSUME, parts, 5, 5, 0, b"")]
    h, sigs, pr = sealed(reg, s1, ops, byz)
    run("understate", reg, reg.functions.proveUnderstate([h], sigs, ops[0], 0, pr[0], ops[1], 1, pr[1]))
    # Use past the allowance (renewal exists, attested reading beyond cq + A).
    reg, o = fresh()
    cq = s1.clock.read()
    admin.send(reg.functions.renew(s1.k, o, s1.clock.epoch, cq,
                                   s1.clock.attest(C.request_digest, s1.k, o, s1.clock.epoch, cq)))
    rd = cq + A_MS
    ops = [(C.USE, o, cq, rd, s1.clock.epoch, s1.clock.attest(C.clock_digest, s1.k, s1.clock.epoch, rd, o))]
    h, sigs, pr = sealed(reg, s1, ops, byz)
    run("overuse", reg, reg.functions.proveOveruse(h, sigs, ops[0], 0, pr[0]))
    # Use after a clock reset (old base, new epoch).
    reg, o = fresh()
    admin.send(reg.functions.renew(s1.k, o, s1.clock.epoch, cq,
                                   s1.clock.attest(C.request_digest, s1.k, o, s1.clock.epoch, cq)))
    e2 = s1.clock.epoch + 1
    ops = [(C.USE, o, cq, cq + 10, e2, s1.clock.attest(C.clock_digest, s1.k, e2, cq + 10, o))]
    h, sigs, pr = sealed(reg, s1, ops, byz)
    run("use_after_reset", reg, reg.functions.proveOveruse(h, sigs, ops[0], 0, pr[0]))
    # Use after an acknowledged release: ack by validators 0-2, use sealed by 1-3 -> slashes 1, 2.
    reg, o = fresh()
    admin.send(reg.functions.renew(s1.k, o, s1.clock.epoch, cq,
                                   s1.clock.attest(C.request_digest, s1.k, o, s1.clock.epoch, cq)))
    admin.send(reg.functions.stop(o, s2.k))
    ra = cq + 1000
    acks = [C.sign(s1.vkeys[i], C.ack_digest(reg.address, s1.k, o, s1.clock.epoch, ra)) for i in [0, 1, 2]]
    admin.send(reg.functions.reassignAcked(o, s1.clock.epoch, ra, s1.clock.attest(C.clock_digest, s1.k, s1.clock.epoch, ra, o), acks))
    ops = [(C.USE, o, cq, ra + 1, s1.clock.epoch, s1.clock.attest(C.clock_digest, s1.k, s1.clock.epoch, ra + 1, o))]
    h, sigs, pr = sealed(reg, s1, ops, [1, 2, 3])
    run("use_after_ack", reg, reg.functions.proveUseAfterAck(h, sigs, ops[0], 0, pr[0]))
    # Fork: two checkpoints at height 1 sealed by {0,1,2} and {1,2,3} -> slashes 1, 2.
    reg, o = fresh()
    h1, sg1, _ = sealed(reg, s1, [(C.LOG, keccak(text="a"), 0, 0, 0, b"")], [0, 1, 2])
    h2, sg2, _ = sealed(reg, s1, [(C.LOG, keccak(text="b"), 0, 0, 0, b"")], [1, 2, 3])
    run("fork", reg, reg.functions.proveFork(h1, sg1, h2, sg2))

    # No framing: every honest anchored operation, every applicable proof, must revert.
    reg = ctx["reg"]
    tried = reverted = 0
    for s in (s1, s2):
        for h, sigs, ops in s.anchored:
            _, proofs = C.merkle([C.op_leaf(op) for op in ops])
            for i, op in enumerate(ops):
                fns = []
                if op[0] == C.CONSUME:
                    fns.append(reg.functions.proveOverspend(h, sigs, op, i, proofs[i]))
                if op[0] == C.USE:
                    fns.append(reg.functions.proveOveruse(h, sigs, op, i, proofs[i]))
                    fns.append(reg.functions.proveUseAfterAck(h, sigs, op, i, proofs[i]))
                for fn in fns:
                    tried += 1
                    try:
                        fn.call({"from": admin.acct.address})
                    except Exception:  # noqa: BLE001
                        reverted += 1
    out["no_framing"] = {"proof_attempts_on_honest_ops": tried, "reverted": reverted}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cut", type=int, default=150)
    ap.add_argument("--tag", default="v1")
    args = ap.parse_args()
    nodes = json.loads((NET / "nodes.json").read_text())
    for k in (1, 2):
        uplink(k, True)
    t0 = time.time()
    ctx = {"t0": t0, "drift": {1: -RHO_PPM / 1e6, 2: 0.05}, "gas": {}, "sites": {},
           "objects": ["P11", "P12", "C11", "P21", "P22", "C21"]}
    ctx["log"] = Log(t0)
    for k in (1, 2):
        ctx["sites"][k] = Site(k, nodes, ctx)
    setup(ctx, nodes)
    ctx["reg_at"] = lambda w3: w3.eth.contract(address=ctx["reg"].address, abi=ctx["reg"].abi)
    ctx["t0"] = ctx["log"].t0 = time.time()   # the scenario clock starts after setup
    for s in ctx["sites"].values():
        s.close_next = s.clock.read()
    stop = threading.Event()
    threads = []
    for s in ctx["sites"].values():
        for f in (relayer, checkpointer, operator):
            th = threading.Thread(target=f, args=(ctx, s, stop), daemon=True)
            th.start()
            threads.append(th)
    try:
        scenario(ctx, args.cut)
    finally:
        stop.set()
        for th in threads:
            th.join(timeout=30)
        for k in (1, 2):
            uplink(k, True)
    # Final anchoring of what is left, with both uplinks up.
    for s in ctx["sites"].values():
        try:
            relay_once(ctx, s)
        except Exception:  # noqa: BLE001
            traceback.print_exc()
    result = {"params": {"rho_ppm": RHO_PPM, "D_s": D_S, "A_ms": A_MS, "renew_period_s": P_RENEW,
                         "W_s": ctx["reg"].functions.waitSeconds(obj("P11")).call(), "cut_s": args.cut,
                         "drift": ctx["drift"]},
              "gas": ctx["gas"], "events": ctx["log"].rows}
    result["attacks"] = attacks(ctx, nodes)
    out = ROOT / "experiments" / "results" / f"e2e_{args.tag}.json"
    out.write_text(json.dumps(result, indent=1, default=lambda x: x.hex() if isinstance(x, bytes) else str(x)))
    print("wrote", out)


if __name__ == "__main__":
    main()
