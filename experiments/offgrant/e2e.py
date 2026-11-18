"""End-to-end run of OffGrant (contracts v5) on local PureChain networks (testbed/purechain/net_offgrant).

Global chain G (4 Clique signers, the authorities) and two site chains (4 signers each, the site validators).
Each site's relayer reaches G only through its uplink proxy container; cutting the proxy (netem loss 100%)
cuts the site's uplink while the site chain keeps running. Site clocks are TPM stand-ins: drift (site 1 at the
-15% bound, site 2 at +5%), power epochs, strictly increasing attested readings.

The gateway (which holds the clock) attests every operation it requests, executes a grant only once the grant is
in a checkpoint sealed by a site quorum and a fresh reading is still before the hold's end and the allowance
(otherwise the grant lapses), and attests an acknowledgement (ACK operation) only when no hold of the object is
in effect. Checkpoints commit the operations, the state (running totals, share versions, clock) and the history
of all earlier checkpoints, and carry a clock-attested close; after an outage the relayer anchors only the
newest one (one transaction).

Scenario (seconds after the warm-up):
  10  G lowers site 2's share of parts (40 -> 30); site 2 applies it and G frees the capacity once a sealed
      checkpoint shows the new version (confirmShare)
  20  cut site 1's uplink for CUT s (or, with --flap, make it alternate between cut and lossy/slow)
  35  G stops P11 (bounded holds, site 1 cut off) and L11 (open hold, site 1) in favour of site 2:
      P11 moves by the slow path at releaseAt; L11 is refused by the slow path (a lock may be on)
  45  G revokes credential C11 of site 1 (cut off)
  20+CUT  heal site 1: one anchor catches up; stops are applied; L11 moves by acknowledgement once released
  +30 G stops P21 (site 2, connected): fast path once every running hold of P21 has ended
  +60 power loss at site 2 (clock epoch changes)
Then fraud proofs by a faulty site quorum (fresh registries), and no-framing checks: every applicable proof
against every honest sealed operation, checkpoint pair and acknowledgement. Writes experiments/results/e2e_<tag>.json.
"""
import argparse
import json
import random
import secrets
import subprocess
import threading
import time
import traceback

from eth_account import Account
from eth_utils import keccak

import chain as C

ROOT = C.ROOT
NET = ROOT / "testbed" / "purechain" / "net_offgrant"
RHO_PPM = 150_000      # TPM 2.0 bound: rate within 15% of real time
G_SLACK = 2            # s, bound on G timestamp error (W adds 2 x this)
D_S = 60               # offline tolerance (s), time-compressed for a real-time run
A_MS = int(D_S * 1000 * (1 + RHO_PPM / 1e6))
P_RENEW = 4.0          # pause between relayer rounds while connected (s); one batch renewal per round
CKPT_EVERY = 6.0       # checkpoint period (s)
CONFIRM = 3            # site blocks a checkpoint waits for before validators sign it
CONFIRM_G = 2          # G blocks a renewal waits for before the authorities certify it (G's signers are correct)
LAG_MS = 60_000        # anchor lag: renewals need anchored coverage up to (request reading - lag)
WARMUP = 25            # s of normal operation before the scenario events
WINDOW_MS = 25_000     # hold window requested per grant (clock ms)
LOCK_S = 20            # an open hold (lock) stays on for this long once executed
G_TIMEOUT = 15         # s, RPC timeout through the uplink proxy (slow, lossy links)
OBJECTS = ["P11", "P12", "C11", "L11", "P21", "P22", "C21"]
ERRS = ("NotAViolation", "BadProof", "BadClockSig", "NoQuorum", "HoldMayBeOpen", "StaleAck", "NotHeld",
        "StaleReading", "StillHeld", "NotStopped", "NoRenewal")
SEL = {name: keccak(text=name + "()")[:4].hex() for name in ERRS}


def obj(name):
    return keccak(text=name)


def is_open(name):
    return name.startswith("L")


def is_excl(name):
    return not name.startswith("C")


def revert_reason(e):
    s = str(e) + " " + str(getattr(e, "data", ""))
    for name, sel in SEL.items():
        if sel in s:
            return name
    return "other:" + s[:60]


def op_tuple(x):
    """An OffLib.Op from a decoded event argument (tuple or dict-like)."""
    if isinstance(x, (list, tuple)):
        return tuple(x[:9]) + (bytes(x[9]),)
    return (x["kind"], x["key"], x["epoch"], x["reading"], x["base"], x["until"], x["amount"], x["total"],
            x["version"], bytes(x["clockSig"]))


class Log:
    def __init__(self, t0):
        self.t0 = t0
        self.rows = []
        self.lock = threading.Lock()

    def add(self, kind, **kw):
        with self.lock:
            self.rows.append({"t": round(time.time() - self.t0, 3), "kind": kind, **kw})


def uplink(site, on, degraded=False):
    """Uplink of a site's proxy: up, cut (netem loss 100%), or degraded (800+-400 ms delay, 20% loss)."""
    name = f"up{site}"
    subprocess.run(["docker", "exec", name, "tc", "qdisc", "del", "dev", "eth0", "root"], capture_output=True)
    if not on:
        subprocess.run(["docker", "exec", name, "tc", "qdisc", "add", "dev", "eth0", "root", "netem", "loss", "100%"],
                       check=True, capture_output=True)
    elif degraded:
        subprocess.run(["docker", "exec", name, "tc", "qdisc", "add", "dev", "eth0", "root", "netem",
                        "delay", "800ms", "400ms", "loss", "20%"], check=True, capture_output=True)


def flapper(ctx, until, stop):
    """Flapping, lossy uplink for site 1: cut for 3-15 s, then slow and lossy for 10-30 s, alternately."""
    rnd = random.Random(7)
    on = False
    while time.time() < until and not stop.is_set():
        on = not on
        uplink(1, on, degraded=True)
        ctx["log"].add("flap", site=1, up=on)
        stop.wait(min(rnd.uniform(10, 30) if on else rnd.uniform(3, 15), max(0.0, until - time.time())))


class Site:
    def __init__(self, k, nodes, ctx):
        self.k = k
        self.vals = nodes[f"s{k}"]
        self.vkeys = [v["key"] for v in self.vals]
        self.w3 = C.connect(self.vals[0]["rpc"])
        self.vw3 = [C.connect(v["rpc"]) for v in self.vals]
        self.clock = C.Clock("0x" + secrets.token_hex(32), k, ctx["drift"][k], ctx["t0"])
        self.relayer_key = "0x" + secrets.token_hex(32)
        self.operator_key = "0x" + secrets.token_hex(32)
        self.rel_s = C.Sender(self.w3, self.relayer_key)
        self.op_s = C.Sender(self.w3, self.operator_key)
        self.g = C.connect(8790 + k, timeout=G_TIMEOUT)    # through the uplink proxy
        self.rel_g = C.Sender(self.g, self.relayer_key)
        self.contract = None
        self.hist = [C.ZERO]       # hist[i] = hash of the sealed checkpoint at height i
        self.state = C.SiteState()  # state after the last sealed checkpoint
        self.sealed = []           # dict(h, sigs, ops, state, height) of every sealed checkpoint
        self.sealed_leaves = {}    # op leaf -> height of the sealed checkpoint containing it
        self.ckpt_block = 0
        self.final_block = 0       # blocks below this are in a sealed checkpoint
        self.pending = []          # grants awaiting execution: dict(op, name, block, t)
        self.bounded = {}          # name -> list of (epoch, until) of executed bounded holds
        self.locks = {}            # name -> {holdId: exec time} of executed open holds not yet released
        self.acked = set()         # objects acknowledged by this site's gateway (no more execution)
        self.stops = {}            # (name, stop epoch, stop cq) -> state of the fast path
        self.share_confirmed = set()
        self.glock = threading.Lock()


def certify(ctx, digest):
    return [C.sign(k, digest) for k in ctx["gkeys"][:3]]


def setup(ctx, nodes):
    gadmin = C.Sender(C.connect(8700), nodes["g"][0]["key"])
    ctx["gadmin"] = gadmin
    reg, r = gadmin.deploy("RightsRegistry", RHO_PPM, G_SLACK, LAG_MS)
    ctx["reg"] = reg
    ctx["gas"]["deploy_registry"] = r.gasUsed
    g_chain = gadmin.w3.eth.chain_id
    ctx["dom"] = C.domain(reg.address, g_chain)
    assert ctx["dom"] == bytes(reg.functions.dom().call())
    ctx["gkeys"] = [n["key"] for n in nodes["g"]]
    auth = [Account.from_key(k).address for k in ctx["gkeys"]]
    parts = obj("spare-parts")
    ctx["parts"] = parts
    gadmin.send(reg.functions.setCap(parts, 100))
    for s in ctx["sites"].values():
        gadmin.send(reg.functions.registerSite(s.k, 1, Account.from_key(s.clock.key).address,
                                               [v["address"] for v in s.vals], s.clock.epoch, s.clock.read()))
        gadmin.send(reg.functions.setShare(parts, s.k, 40))     # version 1
        s.contract, r = s.rel_s.deploy("SiteRights", s.k, reg.address, g_chain,
                                       Account.from_key(s.clock.key).address, auth, 3)
        ctx["gas"]["deploy_site"] = r.gasUsed
        s.rel_s.send(s.contract.functions.applyShare(parts, 40, 1,
                                                     certify(ctx, C.share_digest(ctx["dom"], s.k, parts, 40, 1))))
        s.ckpt_block = s.w3.eth.block_number
        for name in OBJECTS:
            if name[1] == str(s.k):
                o = obj(name)
                gadmin.send(reg.functions.createLease(o, is_excl(name), is_open(name), A_MS))
                gadmin.send(reg.functions.permit(o, s.k))
    for s in ctx["sites"].values():   # every site learns every lease (an object may move to it later)
        for name in OBJECTS:
            o = obj(name)
            s.rel_s.send(s.contract.functions.applyLease(
                o, A_MS, is_open(name), certify(ctx, C.lease_digest(ctx["dom"], s.k, o, A_MS, is_open(name)))))


# ------------------------------------------------------------------------------------------- relayer
def anchor_newest(ctx, s, reg_g):
    st = reg_g.functions.sites(s.k).call()
    ah = st[6]
    with s.glock:
        cands = [c for c in s.sealed if c["height"] > ah]
        if not cands:
            return
        c = cands[-1]
        path = C.hist_path(s.hist[:c["height"]], ah) if ah > 0 else []
    r = s.rel_g.send(reg_g.functions.anchor(c["h"], c["sigs"], path))
    ctx["log"].add("anchor", site=s.k, height=c["height"], covers=len(cands), status=r.status, gas=r.gasUsed,
                   close_epoch=c["h"][7], close_reading=c["h"][8])


def apply_shares(ctx, s, reg_g):
    parts = ctx["parts"]
    gv = reg_g.functions.shareVersion(parts, s.k).call()
    sv = s.contract.functions.shareVersion(parts).call()
    if gv > sv:
        amount = reg_g.functions.certified(parts, s.k, gv).call()
        cert = certify(ctx, C.share_digest(ctx["dom"], s.k, parts, amount, gv))
        try:
            s.contract.functions.applyShare(parts, amount, gv, cert).call({"from": s.rel_s.acct.address})
            r = s.rel_s.send(s.contract.functions.applyShare(parts, amount, gv, cert))
            ctx["log"].add("share_applied", site=s.k, version=gv, amount=amount, gas=r.gasUsed)
        except Exception as e:  # noqa: BLE001
            ctx["log"].add("share_refused", site=s.k, version=gv, why=str(e)[:80])
    pv = reg_g.functions.pendingVersion(parts, s.k).call()
    if pv and pv not in s.share_confirmed:
        amount = reg_g.functions.certified(parts, s.k, pv).call()
        with s.glock:
            cands = [c for c in s.sealed if C.lookup(c["state"], parts)[1] >= pv
                     and C.lookup(c["state"], parts)[0] <= amount]
        if cands:
            c = cands[-1]
            r = s.rel_g.send(reg_g.functions.confirmShare(parts, s.k, c["h"], c["sigs"], c["state"]))
            s.share_confirmed.add(pv)
            ctx["log"].add("share_confirmed", site=s.k, version=pv, amount=amount, height=c["height"],
                           status=r.status, gas=r.gasUsed)


def relay_once(ctx, s):
    reg_g = ctx["reg_at"](s.g)
    try:
        s.g.eth.block_number
    except Exception:
        return False
    anchor_newest(ctx, s, reg_g)   # anchor first: G renews only sites whose checkpoints are anchored
    renew = []
    for name in OBJECTS:
        o = obj(name)
        lease = reg_g.functions.leases(o).call()   # exists, exclusive, openHold, stopped, allowance, lastIssue, holder, next
        exclusive, stopped, holder = lease[1], lease[3], lease[6]
        mine = holder == s.k if exclusive else reg_g.functions.permitted(o, s.k).call()
        if stopped and mine:
            handle_stop(ctx, s, name, o, exclusive, reg_g)
        elif reg_g.functions.mayRenew(o, s.k).call() and not stopped:
            renew.append(name)
    apply_shares(ctx, s, reg_g)
    if renew:
        objs = [obj(n) for n in renew]
        t_send = time.time()
        epoch, cq = s.clock.epoch, s.clock.read()
        sig = C.sign(s.clock.key, C.clock_digest(ctx["dom"], s.k, epoch, cq, C.request_tag(C.objects_hash(objs))))
        try:   # a renewal G would refuse (e.g. AnchorDebt) is not sent; it is logged instead
            reg_g.functions.renew(s.k, objs, epoch, cq, sig).call({"from": s.rel_g.acct.address})
        except Exception as e:  # noqa: BLE001
            if "timed out" in str(e) or "Connection" in str(e) or "Max retries" in str(e):
                raise
            ctx["log"].add("renew_refused", site=s.k, objs=renew, why=str(e)[:80])
            return True
        r = s.rel_g.send(reg_g.functions.renew(s.k, objs, epoch, cq, sig), timeout=90)
        if r.status == 1:
            while s.g.eth.block_number < r.blockNumber + CONFIRM_G:   # certify only once final on G
                time.sleep(0.2)
            ev = reg_g.events.Renewed().process_receipt(r)[0]["args"]
            cert = certify(ctx, C.renewal_digest(ctx["dom"], s.k, C.objects_hash(objs), epoch, cq, ev["issued"]))
            r2 = s.rel_s.send(s.contract.functions.applyRenewal(objs, epoch, cq, ev["issued"], cert))
            ctx["log"].add("renewal", site=s.k, objs=renew, epoch=epoch, cq=cq, issued=ev["issued"],
                           t_send=round(t_send - ctx["t0"], 3), latency=round(time.time() - t_send, 3),
                           gas_g=r.gasUsed, gas_site=r2.gasUsed)
    anchor_newest(ctx, s, reg_g)
    return True


def gateway_quiescent(s, name):
    """Whether no hold of the object is in effect physically (as the gateway, which executes holds, knows)."""
    now_ep, now = s.clock.epoch, s.clock.read()
    with s.glock:
        busy = any(e == now_ep and u > now for e, u in s.bounded.get(name, []))
        busy = busy or bool(s.locks.get(name))
        busy = busy or any(g["name"] == name for g in s.pending)
    return not busy


def handle_stop(ctx, s, name, o, exclusive, reg_g):
    epoch, cq = reg_g.functions.lastRenewal(o, s.k).call()
    key = (name, epoch, cq)
    st = s.stops.get(key)
    if st is None:
        cert = certify(ctx, C.stop_digest(ctx["dom"], s.k, o, epoch, cq))
        r = s.rel_s.send(s.contract.functions.applyStop(o, epoch, cq, cert))
        st = s.stops[key] = {"block": r.blockNumber, "done": False, "seen": time.time()}
        ctx["log"].add("stop_applied", site=s.k, obj=name, gas=r.gasUsed)
    if st["done"] or not exclusive:
        return
    if s.final_block <= st["block"]:
        return   # the stop is not yet in a sealed checkpoint
    if "ack" not in st:
        if not gateway_quiescent(s, name):
            if not st.get("waiting"):
                ctx["log"].add("ack_wait", site=s.k, obj=name)
                st["waiting"] = True
            return
        a_epoch, reading = s.clock.epoch, s.clock.read()
        base = s.contract.functions.stoppedUpTo(o).call()[1]
        op = C.attest_op(s.clock, ctx["dom"], s.k, C.make_op(C.ACK, o, a_epoch, reading, base=base))
        try:
            s.contract.functions.acknowledge(o, a_epoch, reading, op[9]).call({"from": s.rel_s.acct.address})
        except Exception as e:  # noqa: BLE001
            ctx["log"].add("ack_refused", site=s.k, obj=name, why=revert_reason(e))
            return
        with s.glock:
            s.acked.add(name)    # the gateway executes nothing of the object from now on
        r = s.rel_s.send(s.contract.functions.acknowledge(o, a_epoch, reading, op[9]))
        st["ack"] = (a_epoch, reading, op)
        ctx["log"].add("ack_op", site=s.k, obj=name, status=r.status, gas=r.gasUsed, reading=reading)
        return
    a_epoch, reading, op = st["ack"]
    if C.op_leaf(op) not in s.sealed_leaves:
        return   # validators acknowledge only an ACK operation in a sealed checkpoint
    acks = [C.sign(vk, C.ack_digest(ctx["dom"], s.k, o, a_epoch, reading)) for vk in s.vkeys[:3]]
    r = s.rel_g.send(reg_g.functions.reassignAcked(o, a_epoch, reading, op[9], acks))
    st["done"] = r.status == 1
    ctx["log"].add("reassign_acked", site=s.k, obj=name, status=r.status, gas=r.gasUsed,
                   latency_from_stop_seen=round(time.time() - st["seen"], 3), ack_reading=reading, ack_epoch=a_epoch)
    if r.status == 1:
        ctx["acks"].append((name, s.k, a_epoch, reading))


def relayer(ctx, s, stop):
    up_prev = None
    while not stop.is_set():
        try:
            up = relay_once(ctx, s)
        except Exception as e:  # noqa: BLE001  (timeouts while the uplink is cut or lossy)
            up = False
            if "timed out" not in str(e) and "Max retries" not in str(e) and "Connection" not in str(e):
                ctx["log"].add("relayer_error", site=s.k, err=str(e)[:160])
        if up != up_prev:
            ctx["log"].add("uplink_seen", site=s.k, up=up)
            up_prev = up
        stop.wait(P_RENEW)


# ------------------------------------------------------------------------------------------- checkpoints
def checkpointer(ctx, s, stop):
    dom = ctx["dom"]
    while not stop.wait(CKPT_EVERY):
        try:
            head = s.w3.eth.block_number - CONFIRM
            lo, hi = s.ckpt_block, head
            if hi <= lo:
                continue
            views = []
            for vw in s.vw3:   # every validator reads the operations from its own node
                sc = vw.eth.contract(address=s.contract.address, abi=s.contract.abi)
                logs = sc.events.OpRecorded().get_logs(from_block=lo, to_block=hi - 1)
                views.append([op_tuple(l["args"]["op"]) for l in sorted(logs, key=lambda l: l["args"]["seq"])])
            ops = views[0]
            st = s.state.copy()
            for op in ops:
                st.apply(op)
            state = st.tuple()
            tip = bytes(s.w3.eth.get_block(hi - 1)["hash"])
            h, _ = C.make_header(s.clock, dom, s.k, s.hist, ops, state, tip)
            hh = C.header_hash(h)
            sigs = [C.sign(vk, C.checkpoint_digest(dom, hh)) for v_ops, vk in zip(views, s.vkeys) if v_ops == ops]
            if len(sigs) < 3:
                ctx["log"].add("ckpt_disagree", site=s.k, agree=len(sigs), lo=lo, hi=hi)
                continue
            with s.glock:
                s.ckpt_block = hi
                s.state = st
                s.hist.append(hh)
                height = len(s.hist) - 1
                s.sealed.append({"h": h, "sigs": sigs, "ops": ops, "state": state, "height": height})
                for op in ops:
                    s.sealed_leaves[C.op_leaf(op)] = height
                s.final_block = hi
            ctx["log"].add("checkpoint", site=s.k, height=height, ops=len(ops), agree=len(sigs), lo=lo, hi=hi,
                           close_epoch=h[7], close_reading=h[8])
            gateway(ctx, s)
        except Exception as e:  # noqa: BLE001
            ctx["log"].add("ckpt_error", site=s.k, err=str(e)[:160])


def gateway(ctx, s):
    """Executes grants that are in a sealed checkpoint, with a fresh clock reading; a grant whose window or
    allowance has passed, or that belongs to another epoch or an acknowledged object, lapses."""
    now_ep, now = s.clock.epoch, s.clock.read()
    keep = []
    with s.glock:
        pending, s.pending = s.pending, []
    rate = 1 + ctx["drift"][s.k]
    for g in pending:
        op = g["op"]
        if C.op_leaf(op) not in s.sealed_leaves:
            keep.append(g)
            continue
        cq, until, epoch = op[4], op[5], op[2]
        end = cq + A_MS if until == C.OPEN else min(until, cq + A_MS)
        ok = now_ep == epoch and now < end and g["name"] not in s.acked
        row = dict(site=s.k, obj=g["name"], grant_t=g["t"], reading=now, until=until, a=cq, epoch=epoch,
                   now_epoch=now_ep, height=s.sealed_leaves[C.op_leaf(op)])
        if ok and until != C.OPEN:
            row["hold_end_t"] = round(time.time() - ctx["t0"] + (until - now) / rate / 1000, 3)
            with s.glock:
                s.bounded.setdefault(g["name"], []).append((epoch, until))
        if ok and until == C.OPEN:
            with s.glock:
                s.locks.setdefault(g["name"], {})[op[3]] = time.time()
        ctx["log"].add("exec" if ok else "lapse", **row)
    with s.glock:
        s.pending = keep + s.pending


# ------------------------------------------------------------------------------------------- workload
def operator(ctx, s, stop):
    rnd = random.Random(s.k)
    parts, dom = ctx["parts"], ctx["dom"]
    while not stop.wait(1.0):
        kind = rnd.choices(["use", "cred", "lock", "consume", "log"], [0.4, 0.2, 0.1, 0.2, 0.1])[0]
        t = time.time()
        try:
            grant = None
            epoch = s.clock.epoch
            if kind == "lock":
                name = "L11"
                o = obj(name)
                with s.glock:
                    mine = dict(s.locks.get(name, {}))
                    waiting = any(g["name"] == name for g in s.pending)
                done = [hid for hid, et in mine.items() if time.time() - et >= LOCK_S]
                if done:   # the crew removes its lock: release names the hold it ends
                    hid = done[0]
                    reading = s.clock.read()
                    op = C.attest_op(s.clock, dom, s.k, C.make_op(C.RELEASE, o, epoch, reading, base=hid))
                    fn = s.contract.functions.release(o, hid, epoch, reading, op[9])
                    kind = "release"
                elif mine or waiting:
                    continue
                else:
                    b_epoch, cq = s.contract.functions.base(o).call()
                    if cq == 0 or b_epoch != epoch:
                        continue
                    reading = s.clock.read()
                    grant = C.attest_op(s.clock, dom, s.k, C.make_op(C.USE, o, epoch, reading, base=cq, until=C.OPEN))
                    fn = s.contract.functions.use(o, cq, epoch, reading, C.OPEN, grant[9])
            elif kind in ("use", "cred"):
                names = [n for n in OBJECTS if (n.startswith("C") if kind == "cred" else n.startswith("P"))]
                bases = {n: s.contract.functions.base(obj(n)).call() for n in names}
                held = [n for n in names if bases[n][1] != 0 and bases[n][0] == epoch]
                if not held:
                    ctx["log"].add("op", site=s.k, op=kind, obj=None, ok=False, why="none held")
                    continue
                name = rnd.choice(held)
                o = obj(name)
                cq = bases[name][1]
                reading = s.clock.read()
                rem = s.contract.functions.remaining(o, epoch, reading).call()
                until = reading + max(1, min(WINDOW_MS, rem - 1))
                grant = C.attest_op(s.clock, dom, s.k, C.make_op(C.USE, o, epoch, reading, base=cq, until=until))
                fn = s.contract.functions.use(o, cq, epoch, reading, until, grant[9])
            elif kind == "consume":
                name = "parts"
                version = s.contract.functions.shareVersion(parts).call()
                reading = s.clock.read()
                op = C.attest_op(s.clock, dom, s.k, C.make_op(C.CONSUME, parts, epoch, reading, amount=1, version=version))
                fn = s.contract.functions.consume(parts, 1, version, epoch, reading, op[9])
            else:
                name, fn = "log", s.contract.functions.record(keccak(text=f"log{t}"))
            try:
                fn.call({"from": s.op_s.acct.address})
            except Exception as e:  # noqa: BLE001  rejected by the site contract
                ctx["log"].add("op", site=s.k, op=kind, obj=name, ok=False, why=revert_reason(e))
                continue
            r = s.op_s.send(fn)
            ctx["log"].add("op", site=s.k, op=kind, obj=name, ok=r.status == 1, latency=round(time.time() - t, 3),
                           gas=r.gasUsed, block=r.blockNumber, until=grant[5] if grant else None)
            if r.status == 1 and grant is not None:
                with s.glock:
                    s.pending.append({"op": grant, "name": name, "block": r.blockNumber, "t": round(t - ctx["t0"], 3)})
            if r.status == 1 and kind == "release":
                with s.glock:
                    s.locks.get("L11", {}).pop(hid, None)
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
            try:
                reg.functions.reassign(o).call({"from": ctx["gadmin"].acct.address})
            except Exception as e:  # noqa: BLE001
                ctx["log"].add("reassign_refused", obj=name, why=revert_reason(e), release_at=at, g_time=now)
                return
            r = ctx["gadmin"].send(reg.functions.reassign(o))
            ctx["log"].add("reassigned_slow", obj=name, release_at=at, g_time=now, status=r.status, gas=r.gasUsed)
            return
        time.sleep(1)


def scenario(ctx, cut_s, flap=False):
    reg, admin, log = ctx["reg"], ctx["gadmin"], ctx["log"]
    t0 = ctx["t0"]

    def at(t):
        time.sleep(max(0.0, t0 + WARMUP + t - time.time()))

    at(10)
    r = admin.send(reg.functions.setShare(ctx["parts"], 2, 30))
    log.add("share_lowered", site=2, amount=30, gas=r.gasUsed)
    at(20)
    uplink(1, False)
    log.add("uplink_cut", site=1)
    fstop = threading.Event()
    if flap:
        threading.Thread(target=flapper, args=(ctx, t0 + WARMUP + 20 + cut_s, fstop), daemon=True).start()
    at(35)
    for name in ("P11", "L11"):
        r = admin.send(reg.functions.stop(obj(name), 2))
        log.add("stop", obj=name, next=2, release_at=reg.functions.releaseAt(obj(name)).call(), gas=r.gasUsed,
                g_time=admin.w3.eth.get_block(r.blockNumber).timestamp)
        threading.Thread(target=admin_wait_reassign, args=(ctx, obj(name), name), daemon=True).start()
    at(45)
    r = admin.send(reg.functions.stop(obj("C11"), 0))
    log.add("revoke", obj="C11", gas=r.gasUsed, release_at=reg.functions.releaseAt(obj("C11")).call(),
            g_time=admin.w3.eth.get_block(r.blockNumber).timestamp)
    at(20 + cut_s)
    fstop.set()
    time.sleep(0.5)
    uplink(1, True)
    log.add("uplink_heal", site=1)
    at(20 + cut_s + 30)
    r = admin.send(reg.functions.stop(obj("P21"), 1))
    log.add("stop", obj="P21", next=1, g_time=admin.w3.eth.get_block(r.blockNumber).timestamp, gas=r.gasUsed)
    at(20 + cut_s + 60)
    ctx["sites"][2].clock.reset()
    log.add("clock_reset", site=2, epoch=ctx["sites"][2].clock.epoch)
    at(20 + cut_s + 110)


# ------------------------------------------------------------------------------------------- attacks
def attacks(ctx):
    """A faulty quorum of site 1 seals out-of-rights checkpoints; fresh registries keep the slashing counts
    independent. Then no-framing checks on every honest sealed operation, checkpoint pair and acknowledgement."""
    out = {}
    admin = ctx["gadmin"]
    s1, s2 = ctx["sites"][1], ctx["sites"][2]
    parts = ctx["parts"]
    E = s1.clock.epoch

    def fresh():
        reg, _ = admin.deploy("RightsRegistry", RHO_PPM, G_SLACK, LAG_MS)
        admin.send(reg.functions.setCap(parts, 100))
        for s in (s1, s2):
            admin.send(reg.functions.registerSite(s.k, 1, Account.from_key(s.clock.key).address,
                                                  [v["address"] for v in s.vals], s.clock.epoch, s.clock.read()))
            admin.send(reg.functions.setShare(parts, s.k, 40))
        o, lk = obj("P-attack"), obj("L-attack")
        admin.send(reg.functions.createLease(o, True, False, A_MS))
        admin.send(reg.functions.permit(o, s1.k))
        admin.send(reg.functions.createLease(lk, True, True, A_MS))
        admin.send(reg.functions.permit(lk, s1.k))
        return reg, bytes(reg.functions.dom().call()), o, lk

    def att(dom, op):
        return C.attest_op(s1.clock, dom, s1.k, op)

    def ckpt(dom, hist, ops, state):
        h, proofs = C.make_header(s1.clock, dom, s1.k, hist, ops, state, b"\x00" * 32)
        return h, proofs

    def seal(dom, h, who):
        return [C.sign(s1.vkeys[i], C.checkpoint_digest(dom, C.header_hash(h))) for i in who]

    def opp(ops, proofs, i):
        return (ops[i], i, proofs[i])

    def st(reading, total, version):
        return (E, reading, [parts], [total], [version])

    def run(name, reg, fn):
        r = admin.send(fn, gas=8_000_000)
        out[name] = {"status": r.status, "gas": r.gasUsed, "slashed": len(reg.events.Slashed().process_receipt(r))}

    def renew(reg, dom, objs, cq):
        sig = C.sign(s1.clock.key, C.clock_digest(dom, s1.k, E, cq, C.request_tag(C.objects_hash(objs))))
        admin.send(reg.functions.renew(s1.k, objs, E, cq, sig))

    def acked(reg, dom, ob, cq, ra):
        admin.send(reg.functions.stop(ob, s2.k))
        ack = att(dom, C.make_op(C.ACK, ob, E, ra, base=cq))
        acks = [C.sign(s1.vkeys[i], C.ack_digest(dom, s1.k, ob, E, ra)) for i in (0, 1, 2)]
        admin.send(reg.functions.reassignAcked(ob, E, ra, ack[9], acks))

    byz = [0, 1, 2]
    H1 = [C.ZERO]
    base_r = s1.clock.read()   # readings for the forged history start here (the registries are fresh)
    R = lambda d: base_r + d   # noqa: E731

    reg, dom, o, lk = fresh()
    ops = [att(dom, C.make_op(C.CONSUME, parts, E, R(1), amount=45, total=45, version=1))]
    h, pr = ckpt(dom, H1, ops, st(R(1), 45, 1))
    run("overspend", reg, reg.functions.proveOverspend(h, seal(dom, h, byz), opp(ops, pr, 0)))

    reg, dom, o, lk = fresh()
    ops = [att(dom, C.make_op(C.CONSUME, parts, E, R(1), amount=30, total=30, version=1)),
           att(dom, C.make_op(C.CONSUME, parts, E, R(2), amount=5, total=5, version=1))]
    h, pr = ckpt(dom, H1, ops, st(R(2), 5, 1))
    run("understate", reg, reg.functions.proveInconsistent(h, seal(dom, h, byz), opp(ops, pr, 0), opp(ops, pr, 1)))

    reg, dom, o, lk = fresh()
    s_1 = st(R(1), 30, 1)
    c1, _ = ckpt(dom, H1, [att(dom, C.make_op(C.CONSUME, parts, E, R(1), amount=30, total=30, version=1))], s_1)
    hist2 = H1 + [C.header_hash(c1)]
    s_2 = st(R(1), 0, 1)
    c2, _ = ckpt(dom, hist2, [C.make_op(C.LOG, keccak(text="noop"))], s_2)
    run("state_regress", reg, reg.functions.proveRegress(c2, seal(dom, c2, byz), s_2, (c1, s_1, C.hist_path(hist2, 1))))

    reg, dom, o, lk = fresh()
    s_1 = st(R(1), 40, 1)
    c1, _ = ckpt(dom, H1, [att(dom, C.make_op(C.CONSUME, parts, E, R(1), amount=40, total=40, version=1))], s_1)
    admin.send(reg.functions.anchor(c1, seal(dom, c1, byz), []))
    hist = [C.ZERO] * 300
    hist[1] = C.header_hash(c1)
    ops = [att(dom, C.make_op(C.CONSUME, parts, E, R(50), amount=40, total=40, version=1))]
    h, pr = ckpt(dom, hist, ops, st(R(50), 40, 1))
    run("restart_below_anchor", reg, reg.functions.proveOpRegress(h, seal(dom, h, byz), opp(ops, pr, 0),
                                                                  (c1, s_1, C.hist_path(hist, 1))))

    reg, dom, o, lk = fresh()
    c1, _ = ckpt(dom, H1, [att(dom, C.make_op(C.CONSUME, parts, E, R(1), amount=30, total=30, version=1))], st(R(1), 30, 1))
    admin.send(reg.functions.setShare(parts, s1.k, 30))   # lower 40 -> 30 (version 2)
    s_2 = st(R(1), 30, 2)
    hist2 = H1 + [C.header_hash(c1)]
    c2, _ = ckpt(dom, hist2, [C.make_op(C.SHARE, parts, amount=30, total=30, version=2)], s_2)
    admin.send(reg.functions.confirmShare(parts, s1.k, c2, seal(dom, c2, byz), s_2))
    hist3 = hist2 + [C.header_hash(c2)]
    ops = [att(dom, C.make_op(C.CONSUME, parts, E, R(5), amount=10, total=40, version=1))]
    h, pr = ckpt(dom, hist3, ops, st(R(5), 40, 1))
    run("stale_share_version", reg, reg.functions.proveOpRegress(h, seal(dom, h, byz), opp(ops, pr, 0),
                                                                 (c2, s_2, C.hist_path(hist3, 2))))

    reg, dom, o, lk = fresh()
    ops = [att(dom, C.make_op(C.CONSUME, parts, E, R(1), amount=30, total=30, version=1))]
    bad_state = st(R(1), 10, 1)
    h, pr = ckpt(dom, H1, ops, bad_state)
    run("state_mismatch", reg, reg.functions.proveStateMismatch(h, seal(dom, h, byz), opp(ops, pr, 0), bad_state))

    reg, dom, o, lk = fresh()
    cq = R(1)
    renew(reg, dom, [o], cq)
    ops = [att(dom, C.make_op(C.USE, o, E, cq + A_MS, base=cq, until=cq + A_MS + 5))]
    h, pr = ckpt(dom, H1, ops, (E, cq + A_MS, [], [], []))
    run("overuse", reg, reg.functions.proveOveruse(h, seal(dom, h, byz), opp(ops, pr, 0)))

    reg, dom, o, lk = fresh()
    renew(reg, dom, [o], cq)
    ops = [att(dom, C.make_op(C.USE, o, E, cq + 10, base=cq, until=cq + A_MS))]   # ends past the allowance
    h, pr = ckpt(dom, H1, ops, (E, cq + 10, [], [], []))
    run("hold_past_allowance", reg, reg.functions.proveOveruse(h, seal(dom, h, byz), opp(ops, pr, 0)))

    reg, dom, o, lk = fresh()
    renew(reg, dom, [o], cq)
    ops = [att(dom, C.make_op(C.USE, o, E + 1, 10, base=cq, until=20))]          # new epoch, old renewal
    h, pr = ckpt(dom, H1, ops, (E + 1, 10, [], [], []))
    run("use_after_reset", reg, reg.functions.proveOveruse(h, seal(dom, h, byz), opp(ops, pr, 0)))

    reg, dom, o, lk = fresh()
    renew(reg, dom, [o], cq)
    g = att(dom, C.make_op(C.USE, o, E, cq + 10, base=cq, until=cq + 20))
    ops = [g, g]                                                                    # replayed attestation
    h, pr = ckpt(dom, H1, ops, (E, cq + 10, [], [], []))
    run("replayed_attestation", reg, reg.functions.proveInconsistent(h, seal(dom, h, byz), opp(ops, pr, 0),
                                                                     opp(ops, pr, 1)))

    reg, dom, o, lk = fresh()
    rel = C.make_op(C.RELEASE, lk, E, cq + 30, base=cq + 10, sig=C.sign(s1.clock.key, b"\x01" * 32))
    ops = [rel]                                                                     # release never attested
    h, pr = ckpt(dom, H1, ops, (E, cq + 30, [], [], []))
    run("forged_release", reg, reg.functions.proveBadOp(h, seal(dom, h, byz), opp(ops, pr, 0)))

    reg, dom, o, lk = fresh()
    renew(reg, dom, [o], cq)
    acked(reg, dom, o, cq, cq + 1000)
    ops = [att(dom, C.make_op(C.USE, o, E, cq + 1001, base=cq, until=cq + 1500))]
    h, pr = ckpt(dom, H1, ops, (E, cq + 1001, [], [], []))
    run("use_after_ack", reg, reg.functions.proveUseAfterAck(h, seal(dom, h, [1, 2, 3]), opp(ops, pr, 0), E, cq + 1000))

    reg, dom, o, lk = fresh()
    renew(reg, dom, [lk], cq)
    acked(reg, dom, lk, cq, cq + 1000)
    ops = [att(dom, C.make_op(C.RELEASE, lk, E, cq + 1500, base=cq + 10))]
    h, pr = ckpt(dom, H1, ops, (E, cq + 1500, [], [], []))
    run("release_after_ack", reg, reg.functions.proveUseAfterAck(h, seal(dom, h, [1, 2, 3]), opp(ops, pr, 0), E, cq + 1000))

    reg, dom, o, lk = fresh()
    h1, _ = ckpt(dom, H1, [C.make_op(C.LOG, keccak(text="a"))], (E, 0, [], [], []))
    h2, _ = ckpt(dom, H1, [C.make_op(C.LOG, keccak(text="b"))], (E, 0, [], [], []))
    run("fork", reg, reg.functions.proveFork(h1, seal(dom, h1, [0, 1, 2]), h2, seal(dom, h2, [1, 2, 3]), C.ZERO, []))

    reg, dom, o, lk = fresh()
    a1, _ = ckpt(dom, H1, [C.make_op(C.LOG, keccak(text="a"))], (E, 0, [], [], []))
    b1, _ = ckpt(dom, H1, [C.make_op(C.LOG, keccak(text="b"))], (E, 0, [], [], []))
    histb = [C.ZERO] * 500
    histb[1] = C.header_hash(b1)
    b500, _ = ckpt(dom, histb, [C.make_op(C.LOG, keccak(text="c"))], (E, 0, [], [], []))
    run("fork_across_heights", reg, reg.functions.proveFork(a1, seal(dom, a1, [0, 1, 2]), b500,
                                                            seal(dom, b500, [1, 2, 3]), C.header_hash(b1),
                                                            C.hist_path(histb, 1)))

    # Rejected outright (no slashing needed): a forged checkpoint close, and a grant attestation used as an ack.
    reg, dom, o, lk = fresh()
    c, _ = ckpt(dom, H1, [C.make_op(C.LOG, keccak(text="c"))], (E, 0, [], [], []))
    cf = c[:8] + (c[8] + 10_000_000,) + c[9:]
    try:
        reg.functions.anchor(cf, seal(dom, cf, byz), []).call({"from": admin.acct.address})
        out["forged_close"] = {"rejected": False}
    except Exception as e:  # noqa: BLE001
        out["forged_close"] = {"rejected": True, "reason": revert_reason(e)}
    renew(reg, dom, [lk], cq)
    admin.send(reg.functions.stop(lk, s2.k))
    lock = att(dom, C.make_op(C.USE, lk, E, cq + 5, base=cq, until=C.OPEN))
    acks = [C.sign(s1.vkeys[i], C.ack_digest(dom, s1.k, lk, E, cq + 5)) for i in (0, 1, 2)]
    try:
        reg.functions.reassignAcked(lk, E, cq + 5, lock[9], acks).call({"from": admin.acct.address})
        out["grant_attestation_as_ack"] = {"rejected": False}
    except Exception as e:  # noqa: BLE001
        out["grant_attestation_as_ack"] = {"rejected": True, "reason": revert_reason(e)}

    out["no_framing"] = no_framing(ctx)
    return out


def no_framing(ctx):
    """Every applicable proof against every honest sealed operation, consecutive and distant checkpoint pairs,
    and every recorded acknowledgement, on the run's registry: each must revert with NotAViolation."""
    reg, admin = ctx["reg"], ctx["gadmin"]
    tried, verdicts = 0, {}

    def attempt(fn):
        nonlocal tried
        tried += 1
        try:
            fn.call({"from": admin.acct.address})
            verdicts["accepted"] = verdicts.get("accepted", 0) + 1
        except Exception as e:  # noqa: BLE001
            k = revert_reason(e)
            verdicts[k] = verdicts.get(k, 0) + 1

    for s in ctx["sites"].values():
        acks = [(n, e, r) for (n, k, e, r) in ctx["acks"] if k == s.k]
        for c in s.sealed:
            h, sigs, ops, state, height = c["h"], c["sigs"], c["ops"], c["state"], c["height"]
            hist = s.hist[:height]
            _, proofs = C.merkle([C.op_leaf(op) for op in ops])
            ancestors = [a for a in (s.sealed[0] if height > 1 else None, s.sealed[height - 2] if height > 1 else None) if a]
            for i, op in enumerate(ops):
                p = (op, i, proofs[i])
                attempt(reg.functions.proveBadOp(h, sigs, p))
                attempt(reg.functions.proveStateMismatch(h, sigs, p, state))
                if op[0] == C.CONSUME:
                    attempt(reg.functions.proveOverspend(h, sigs, p))
                if op[0] == C.USE:
                    attempt(reg.functions.proveOveruse(h, sigs, p))
                if op[0] in (C.USE, C.RELEASE):
                    for (n, e, r) in acks:
                        if obj(n) == op[1]:
                            attempt(reg.functions.proveUseAfterAck(h, sigs, p, e, r))
                for a in ancestors:
                    attempt(reg.functions.proveOpRegress(h, sigs, p, (a["h"], a["state"], C.hist_path(hist, a["height"]))))
                if i + 1 < len(ops):
                    attempt(reg.functions.proveInconsistent(h, sigs, p, (ops[i + 1], i + 1, proofs[i + 1])))
            for a in ancestors:
                path = C.hist_path(hist, a["height"])
                attempt(reg.functions.proveRegress(h, sigs, state, (a["h"], a["state"], path)))
                attempt(reg.functions.proveFork(a["h"], a["sigs"], h, sigs, C.header_hash(a["h"]), path))
    return {"proof_attempts_on_honest_data": tried, "verdicts": verdicts}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cut", type=int, default=150)
    ap.add_argument("--tag", default="v5")
    ap.add_argument("--flap", action="store_true", help="site 1's uplink flaps and is lossy instead of cut")
    args = ap.parse_args()
    nodes = json.loads((NET / "nodes.json").read_text())
    for k in (1, 2):
        uplink(k, True)
    t0 = time.time()
    ctx = {"t0": t0, "drift": {1: -RHO_PPM / 1e6, 2: 0.05}, "gas": {}, "sites": {}, "acks": []}
    ctx["log"] = Log(t0)
    for k in (1, 2):
        ctx["sites"][k] = Site(k, nodes, ctx)
    setup(ctx, nodes)
    ctx["reg_at"] = lambda w3: w3.eth.contract(address=ctx["reg"].address, abi=ctx["reg"].abi)
    ctx["t0"] = ctx["log"].t0 = time.time()   # the scenario clock starts after setup
    stop = threading.Event()
    threads = []
    for s in ctx["sites"].values():
        for f in (relayer, checkpointer, operator):
            th = threading.Thread(target=f, args=(ctx, s, stop), daemon=True)
            th.start()
            threads.append(th)
    try:
        scenario(ctx, args.cut, args.flap)
    finally:
        stop.set()
        for th in threads:
            th.join(timeout=60)
        for k in (1, 2):
            uplink(k, True)
    for s in ctx["sites"].values():   # final anchoring with both uplinks up
        try:
            relay_once(ctx, s)
        except Exception:  # noqa: BLE001
            traceback.print_exc()
    result = {"params": {"rho_ppm": RHO_PPM, "D_s": D_S, "A_ms": A_MS, "renew_period_s": P_RENEW,
                         "ckpt_every_s": CKPT_EVERY, "window_ms": WINDOW_MS, "g_slack_s": G_SLACK,
                         "W_s": ctx["reg"].functions.waitSeconds(obj("P11")).call(), "cut_s": args.cut,
                         "drift": ctx["drift"], "flap": args.flap, "g_timeout_s": G_TIMEOUT},
              "gas": ctx["gas"], "events": ctx["log"].rows}
    result["attacks"] = attacks(ctx)
    out = ROOT / "experiments" / "results" / f"e2e_{args.tag}.json"
    out.write_text(json.dumps(result, indent=1, default=lambda x: x.hex() if isinstance(x, bytes) else str(x)))
    print("wrote", out)


if __name__ == "__main__":
    main()
