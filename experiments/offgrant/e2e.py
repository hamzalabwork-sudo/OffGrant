"""End-to-end run of OffGrant v3 on local PureChain networks (testbed/purechain/net_offgrant).

Global chain G (4 Clique signers, the authorities) and two site chains (4 signers each, the site validators).
Each site's relayer reaches G only through its uplink proxy container; cutting the proxy (netem loss 100%)
cuts the site's uplink while the site chain keeps running. Site clocks are TPM-like: drift (site 1 at the
-15% bound, site 2 at +5%), restart epochs, attested readings.

Every grant is a hold window [grant reading, until] inside the allowance; the site gateway executes it only
once its checkpoint is final and only if a fresh clock reading is still inside the window and the allowance
(otherwise the grant lapses). L11 is an open hold (a lockout): it lasts until released and is never moved by
expiry. Checkpoints commit running totals (state root), carry a clock-attested close, and name the last
anchored checkpoint, so after an outage the relayer anchors only the newest one (one transaction).

Scenario (seconds after the warm-up):
  20  cut site 1's uplink for CUT s
  35  G stops P11 (bounded holds, site 1 cut off) and L11 (open hold, site 1) in favour of site 2:
      P11 moves by the slow path at releaseAt; L11 is refused by the slow path (a lock may be on)
  45  G revokes credential C11 of site 1 (cut off)
  20+CUT  heal site 1: one anchor catches up; stops are applied; L11 moves once its lock is released (fast path)
  +30 G stops P21 (site 2, connected): fast path once every running hold of P21 has ended
  +60 power loss at site 2 (clock epoch changes)
Then fraud proofs against a Byzantine site quorum (fresh registries), and no-framing checks against every honest
sealed operation and consecutive checkpoint pair. Writes experiments/results/e2e_<tag>.json.
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
RHO_PPM = 150_000      # TPM 2.0 bound: rate within 15% of UTC
G_SLACK = 2            # s, bound on G timestamp error (W adds 2 x this)
D_S = 60               # offline tolerance (s), time-compressed for a real-time run
A_MS = int(D_S * 1000 * (1 + RHO_PPM / 1e6))
P_RENEW = 4.0          # renewal period while connected (s)
CKPT_EVERY = 6.0       # checkpoint period (s)
CONFIRM = 3            # site blocks a checkpoint waits for before validators sign it
CONFIRM_G = 2          # G blocks a renewal waits for before the authorities certify it
LAG_MS = 60_000        # anchor lag: renewals need anchored coverage up to (request reading - lag)
WARMUP = 25            # s of normal operation before the scenario events
WINDOW_MS = 25_000     # hold window requested per grant (clock ms)
LOCK_S = 20            # an open hold (lock) stays on for this long once executed
OBJECTS = ["P11", "P12", "C11", "L11", "P21", "P22", "C21"]
SEL = {name: keccak(text=name + "()")[:4].hex() for name in
       ("NotAViolation", "BadProof", "BadClockSig", "NoQuorum", "HoldMayBeOpen")}


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
    """Flapping, lossy uplink for site 1: alternately cut and degraded for random 3-15 s periods."""
    rnd = random.Random(7)
    on = False
    while time.time() < until and not stop.is_set():
        on = not on
        uplink(1, on, degraded=True)
        ctx["log"].add("flap", site=1, up=on)
        stop.wait(min(rnd.uniform(3, 15), max(0.0, until - time.time())))


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
        self.g = C.connect(8790 + k, timeout=3)          # through the uplink proxy
        self.rel_g = C.Sender(self.g, self.relayer_key)
        self.contract = None
        self.ckpts = []            # sealed checkpoints not yet covered by an anchor
        self.sealed = []           # every sealed checkpoint (header, sigs, ops)
        self.height = 0
        self.prev = b"\x00" * 32
        self.total = 0             # running total of parts at the last checkpoint
        self.known_anchor = (0, b"\x00" * 32)
        self.ckpt_block = 0
        self.final_block = 0       # blocks below this are in a sealed (final) checkpoint
        self.pending = []          # grants waiting for finality: dict(block, name, a, until, epoch, t)
        self.locks = {}            # name -> dict(exec_t or None) for open holds this site holds
        self.stops = {}            # (name, lastIssue) -> dict(block, done)
        self.glock = threading.Lock()


def certify(ctx, digest):
    return [C.sign(k, digest) for k in ctx["gkeys"][:3]]


def setup(ctx, nodes):
    gadmin = C.Sender(C.connect(8700), nodes["g"][0]["key"])
    ctx["gadmin"] = gadmin
    reg, r = gadmin.deploy("RightsRegistry", RHO_PPM, G_SLACK, LAG_MS)
    ctx["reg"] = reg
    ctx["gas"]["deploy_registry"] = r.gasUsed
    ctx["gkeys"] = [n["key"] for n in nodes["g"]]
    auth = [Account.from_key(k).address for k in ctx["gkeys"]]
    parts = obj("spare-parts")
    ctx["parts"] = parts
    gadmin.send(reg.functions.setCap(parts, 100))
    for s in ctx["sites"].values():
        gadmin.send(reg.functions.registerSite(s.k, 1, Account.from_key(s.clock.key).address,
                                               [v["address"] for v in s.vals], s.clock.epoch, s.clock.read()))
        gadmin.send(reg.functions.setShare(parts, s.k, 40))     # version 1
        s.contract, r = s.rel_s.deploy("SiteRights", s.k, reg.address, Account.from_key(s.clock.key).address,
                                       auth, 3)
        ctx["gas"]["deploy_site"] = r.gasUsed
        s.rel_s.send(s.contract.functions.applyShare(parts, 40, 1,
                                                     certify(ctx, C.share_digest(reg.address, s.k, parts, 40, 1))))
        s.ckpt_block = s.w3.eth.block_number
        for name in OBJECTS:
            if name[1] == str(s.k):
                o = obj(name)
                gadmin.send(reg.functions.createLease(o, is_excl(name), A_MS))
                if is_open(name):
                    gadmin.send(reg.functions.setOpenHold(o))
                gadmin.send(reg.functions.permit(o, s.k))
    for s in ctx["sites"].values():   # every site learns every lease (an object may move to it later)
        for name in OBJECTS:
            o = obj(name)
            s.rel_s.send(s.contract.functions.applyLease(
                o, A_MS, is_open(name), certify(ctx, C.lease_digest(reg.address, s.k, o, A_MS, is_open(name)))))


# ------------------------------------------------------------------------------------------- relayer
def anchor_newest(ctx, s, reg_g):
    st = reg_g.functions.sites(s.k).call()
    ah, ahash = st[6], st[7]
    with s.glock:
        s.known_anchor = (ah, ahash)
        cands = [c for c in s.ckpts if c[0][1] > ah and c[0][6] == ah and c[0][7] == ahash]
    if not cands:
        return
    h, sigs, ops = cands[-1]
    r = s.rel_g.send(reg_g.functions.anchor(h, sigs))
    covered = sum(1 for c in s.ckpts if c[0][1] <= h[1])
    ctx["log"].add("anchor", site=s.k, height=h[1], covers=covered, status=r.status, gas=r.gasUsed,
                   close_epoch=h[8], close_reading=h[9])
    if r.status == 1:
        with s.glock:
            s.known_anchor = (h[1], C.header_hash(h))
            s.ckpts = [c for c in s.ckpts if c[0][1] > h[1]]


def relay_once(ctx, s):
    reg_g = ctx["reg_at"](s.g)
    try:
        s.g.eth.block_number
    except Exception:
        return False
    anchor_newest(ctx, s, reg_g)   # anchor first: G renews only sites whose checkpoints are anchored
    for name in OBJECTS:
        o = obj(name)
        lease = reg_g.functions.leases(o).call()   # exists, exclusive, openHold, stopped, allowance, lastIssue, holder, next
        exclusive, stopped, holder = lease[1], lease[3], lease[6]
        mine = holder == s.k if exclusive else reg_g.functions.permitted(o, s.k).call()
        if stopped and mine:
            handle_stop(ctx, s, name, o, exclusive, reg_g, lease[5])
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
        while s.g.eth.block_number < r.blockNumber + CONFIRM_G:   # certify only once final on G
            time.sleep(0.2)
        ev = reg_g.events.Renewed().process_receipt(r)[0]["args"]
        cert = certify(ctx, C.renewal_digest(ctx["reg"].address, s.k, o, ev["epoch"], ev["cq"], ev["issued"]))
        r2 = s.rel_s.send(s.contract.functions.applyRenewal(o, ev["epoch"], ev["cq"], ev["issued"], cert))
        ctx["log"].add("renewal", site=s.k, obj=name, epoch=ev["epoch"], cq=ev["cq"], issued=ev["issued"],
                       t_send=round(t_send - ctx["t0"], 3), latency=round(time.time() - t_send, 3),
                       gas_g=r.gasUsed, gas_site=r2.gasUsed)
    anchor_newest(ctx, s, reg_g)
    return True


def handle_stop(ctx, s, name, o, exclusive, reg_g, last_issue):
    key = (name, last_issue)
    st = s.stops.get(key)
    if st is None:
        epoch, cq = reg_g.functions.lastRenewal(o, s.k).call()
        cert = certify(ctx, C.stop_digest(ctx["reg"].address, s.k, o, epoch, cq))
        t = time.time()
        r = s.rel_s.send(s.contract.functions.applyStop(o, epoch, cq, cert))
        st = s.stops[key] = {"block": r.blockNumber, "done": False, "seen": t, "epoch": epoch, "cq": cq}
        ctx["log"].add("stop_applied", site=s.k, obj=name, gas=r.gasUsed)
    if st["done"] or not exclusive:
        return
    # Fast path: validators acknowledge only once the stop is final on the site ledger and no hold is running.
    if s.final_block <= st["block"]:
        return
    reading = s.clock.read()
    acks = []
    for vw, vk in zip(s.vw3, s.vkeys):
        sc = vw.eth.contract(address=s.contract.address, abi=s.contract.abi)
        if tuple(sc.functions.stoppedUpTo(o).call()) >= (st["epoch"], st["cq"]) and \
                sc.functions.quiescent(o, reading).call():
            acks.append(C.sign(vk, C.ack_digest(ctx["reg"].address, s.k, o, s.clock.epoch, reading)))
    if len(acks) < 3:
        if not st.get("waiting"):
            ctx["log"].add("ack_wait", site=s.k, obj=name, acks=len(acks))
            st["waiting"] = True
        return
    csig = s.clock.attest(C.clock_digest, s.k, s.clock.epoch, reading, o)
    r = s.rel_g.send(reg_g.functions.reassignAcked(o, s.clock.epoch, reading, csig, acks))
    st["done"] = r.status == 1
    ctx["log"].add("reassign_acked", site=s.k, obj=name, status=r.status, gas=r.gasUsed,
                   latency_from_stop_seen=round(time.time() - st["seen"], 3), ack_reading=reading)


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
    parts = ctx["parts"]
    while not stop.wait(CKPT_EVERY):
        try:
            head = s.w3.eth.block_number - CONFIRM
            lo, hi = s.ckpt_block, head
            if hi <= lo:
                continue
            views = []
            for vw in s.vw3:   # every validator reads the operations from its own node
                sc = vw.eth.contract(address=s.contract.address, abi=s.contract.abi)
                logs = sc.events.Op().get_logs(from_block=lo, to_block=hi - 1)
                ops = [(l["args"]["kind"], l["args"]["key"], l["args"]["a"], l["args"]["b"], l["args"]["c"],
                        l["args"]["e"], l["args"]["clockSig"]) for l in sorted(logs, key=lambda l: l["args"]["seq"])]
                views.append(ops)
            ops = views[0]
            total = s.total
            for op in ops:
                if op[0] == C.CONSUME and op[1] == parts:
                    total = op[3]
            with s.glock:
                base = s.known_anchor
            h, proofs = C.make_header(s.clock, s.k, s.height + 1, s.prev, ops, C.state_leaf(parts, total), *base)
            sigs = [C.sign(vk, C.checkpoint_digest(ctx["reg"].address, C.header_hash(h)))
                    for v_ops, vk in zip(views, s.vkeys) if v_ops == ops]
            s.ckpt_block = hi
            s.height += 1
            s.prev = C.header_hash(h)
            s.total = total
            with s.glock:
                s.ckpts.append((h, sigs, ops))
            s.sealed.append((h, sigs, ops))
            if len(sigs) >= 3:
                s.final_block = hi
            ctx["log"].add("checkpoint", site=s.k, height=h[1], ops=h[4], agree=len(sigs), lo=lo, hi=hi,
                           close_reading=h[9])
            gateway(ctx, s)
        except Exception as e:  # noqa: BLE001
            ctx["log"].add("ckpt_error", site=s.k, err=str(e)[:160])


def gateway(ctx, s):
    """Executes final grants with a fresh clock reading; a grant whose window or allowance has passed lapses."""
    now_ep, now = s.clock.epoch, s.clock.read()
    keep = []
    with s.glock:
        pending, s.pending = s.pending, []
    for g in pending:
        if g["block"] >= s.final_block:
            keep.append(g)
            continue
        end = g["a"] + A_MS if g["until"] == C.OPEN else min(g["until"], g["a"] + A_MS)
        ok = now_ep == g["epoch"] and now < end
        rate = 1 + ctx["drift"][s.k]
        row = dict(site=s.k, obj=g["name"], grant_t=g["t"], reading=now, until=g["until"], a=g["a"],
                   epoch=g["epoch"], now_epoch=now_ep)
        if ok and g["until"] != C.OPEN:
            row["hold_end_t"] = round(time.time() - ctx["t0"] + (g["until"] - now) / rate / 1000, 3)
        ctx["log"].add("exec" if ok else "lapse", **row)
        if is_open(g["name"]):
            s.locks[g["name"]] = {"exec_t": time.time() if ok else None}
    with s.glock:
        s.pending = keep + s.pending


# ------------------------------------------------------------------------------------------- workload
def operator(ctx, s, stop):
    rnd = random.Random(s.k)
    parts = ctx["parts"]
    while not stop.wait(1.0):
        kind = rnd.choices(["use", "cred", "lock", "consume", "log"], [0.4, 0.2, 0.1, 0.2, 0.1])[0]
        t = time.time()
        try:
            until = None
            if kind == "lock":
                names = [n for n in OBJECTS if is_open(n)]
                name = names[0]
                o = obj(name)
                lk = s.locks.get(name)
                if s.contract.functions.openCount(o).call() > 0:
                    if lk is None or (lk["exec_t"] is not None and time.time() - lk["exec_t"] < LOCK_S):
                        continue      # the lock is still pending execution or in use
                    reading = s.clock.read()
                    fn = s.contract.functions.release(o, s.clock.epoch, reading, s.clock.attest(
                        C.clock_digest, s.k, s.clock.epoch, reading, C.release_tag(o)))
                    kind = "release"
                else:
                    if s.contract.functions.base(o).call()[1] == 0:
                        continue
                    reading = s.clock.read()
                    until = C.OPEN
                    fn = s.contract.functions.use(o, s.clock.epoch, reading, until,
                                                  s.clock.attest(C.clock_digest, s.k, s.clock.epoch, reading, o))
            elif kind in ("use", "cred"):
                names = [n for n in OBJECTS if (n.startswith("C") if kind == "cred" else n.startswith("P"))]
                held = [n for n in names if s.contract.functions.base(obj(n)).call()[1] != 0]
                if not held:
                    ctx["log"].add("op", site=s.k, op=kind, obj=None, ok=False, why="none held")
                    continue
                name = rnd.choice(held)
                o = obj(name)
                reading = s.clock.read()
                rem = s.contract.functions.remaining(o, s.clock.epoch, reading).call()
                until = reading + max(0, min(WINDOW_MS, rem - 1))
                fn = s.contract.functions.use(o, s.clock.epoch, reading, until,
                                              s.clock.attest(C.clock_digest, s.k, s.clock.epoch, reading, o))
            elif kind == "consume":
                name, fn = "parts", s.contract.functions.consume(parts, 1)
            else:
                name, fn = "log", s.contract.functions.record(keccak(text=f"log{t}"))
            try:
                fn.call({"from": s.op_s.acct.address})
            except Exception as e:  # noqa: BLE001  rejected by the site contract
                ctx["log"].add("op", site=s.k, op=kind, obj=name, ok=False, why=str(e)[:60])
                continue
            a = s.contract.functions.base(obj(name)).call()[1] if until is not None else 0
            r = s.op_s.send(fn)
            ctx["log"].add("op", site=s.k, op=kind, obj=name, ok=r.status == 1, latency=round(time.time() - t, 3),
                           gas=r.gasUsed, block=r.blockNumber, until=until)
            if r.status == 1 and until is not None:
                with s.glock:
                    s.pending.append({"block": r.blockNumber, "name": name, "a": a, "until": until,
                                      "epoch": s.clock.epoch, "t": round(t - ctx["t0"], 3)})
            if r.status == 1 and kind == "release":
                s.locks.pop(name, None)
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
    """A Byzantine quorum (validators 0-2 of site 1) seals out-of-rights checkpoints; fresh registries keep the
    slashing counts independent. Then no-framing checks on every honest sealed operation."""
    out = {}
    admin = ctx["gadmin"]
    s1, s2 = ctx["sites"][1], ctx["sites"][2]
    parts = ctx["parts"]
    zero = b"\x00" * 32

    def fresh():
        reg, _ = admin.deploy("RightsRegistry", RHO_PPM, G_SLACK, LAG_MS)
        admin.send(reg.functions.setCap(parts, 100))
        for s in (s1, s2):
            admin.send(reg.functions.registerSite(s.k, 1, Account.from_key(s.clock.key).address,
                                                  [v["address"] for v in s.vals], s.clock.epoch, s.clock.read()))
            admin.send(reg.functions.setShare(parts, s.k, 40))
        o, lk = obj("P-attack"), obj("L-attack")
        admin.send(reg.functions.createLease(o, True, A_MS))
        admin.send(reg.functions.permit(o, s1.k))
        admin.send(reg.functions.createLease(lk, True, A_MS))
        admin.send(reg.functions.setOpenHold(lk))
        admin.send(reg.functions.permit(lk, s1.k))
        return reg, o, lk

    def sealed(reg, ops, signers, height=1, prev=zero, total=0):
        h, proofs = C.make_header(s1.clock, s1.k, height, prev, ops, C.state_leaf(parts, total), 0, zero)
        sigs = [C.sign(s1.vkeys[i], C.checkpoint_digest(reg.address, C.header_hash(h))) for i in signers]
        return h, sigs, proofs

    def run(name, reg, fn):
        r = admin.send(fn, gas=6_000_000)
        n = len(reg.events.Slashed().process_receipt(r))
        out[name] = {"status": r.status, "gas": r.gasUsed, "slashed": n}

    def renew(reg, o, cq):
        admin.send(reg.functions.renew(s1.k, o, s1.clock.epoch, cq,
                                       s1.clock.attest(C.request_digest, s1.k, o, s1.clock.epoch, cq)))

    def grant(o, a, b, c, e=None):
        e = s1.clock.epoch if e is None else e
        return (C.USE, o, a, b, c, e, s1.clock.attest(C.clock_digest, s1.k, e, b, o))

    byz = [0, 1, 2]
    reg, o, lk = fresh()
    ops = [(C.CONSUME, parts, 45, 45, 1, 0, b"")]
    h, sigs, pr = sealed(reg, ops, byz, total=45)
    run("overspend", reg, reg.functions.proveOverspend(h, sigs, ops[0], 0, pr[0]))

    reg, o, lk = fresh()
    ops = [(C.CONSUME, parts, 30, 30, 1, 0, b""), (C.CONSUME, parts, 5, 5, 1, 0, b"")]
    h, sigs, pr = sealed(reg, ops, byz, total=5)
    run("understate", reg, reg.functions.proveUnderstate(h, sigs, ops[0], 0, pr[0], ops[1], 1, pr[1]))

    reg, o, lk = fresh()
    hp, _, _ = sealed(reg, [(C.CONSUME, parts, 35, 35, 1, 0, b"")], [], total=35)
    ops = [(C.CONSUME, parts, 5, 5, 1, 0, b"")]
    h, sigs, pr = sealed(reg, ops, byz, height=2, prev=C.header_hash(hp), total=5)
    run("understate_parent", reg, reg.functions.proveUnderstateParent(h, sigs, ops[0], 0, pr[0], hp, 35, 0, []))

    reg, o, lk = fresh()
    ops = [(C.CONSUME, parts, 30, 30, 1, 0, b"")]
    h, sigs, pr = sealed(reg, ops, byz, total=10)
    run("state_mismatch", reg, reg.functions.proveStateMismatch(h, sigs, ops[0], 0, pr[0], 10, 0, []))

    reg, o, lk = fresh()
    cq = s1.clock.read()
    renew(reg, o, cq)
    ops = [grant(o, cq, cq + A_MS, cq + A_MS)]
    h, sigs, pr = sealed(reg, ops, byz)
    run("overuse", reg, reg.functions.proveOveruse(h, sigs, ops[0], 0, pr[0]))

    reg, o, lk = fresh()
    renew(reg, o, cq)
    ops = [grant(o, cq, cq + 10, cq + A_MS)]          # starts inside, ends past the allowance
    h, sigs, pr = sealed(reg, ops, byz)
    run("hold_past_allowance", reg, reg.functions.proveOveruse(h, sigs, ops[0], 0, pr[0]))

    reg, o, lk = fresh()
    renew(reg, o, cq)
    e2 = s1.clock.epoch + 1
    ops = [grant(o, cq, cq + 10, cq + 10, e2)]
    h, sigs, pr = sealed(reg, ops, byz)
    run("use_after_reset", reg, reg.functions.proveOveruse(h, sigs, ops[0], 0, pr[0]))

    def acked(reg, ob, ra):
        admin.send(reg.functions.stop(ob, s2.k))
        acks = [C.sign(s1.vkeys[i], C.ack_digest(reg.address, s1.k, ob, s1.clock.epoch, ra)) for i in [0, 1, 2]]
        admin.send(reg.functions.reassignAcked(ob, s1.clock.epoch, ra,
                                               s1.clock.attest(C.clock_digest, s1.k, s1.clock.epoch, ra, ob), acks))

    reg, o, lk = fresh()
    renew(reg, o, cq)
    acked(reg, o, cq + 1000)
    ops = [grant(o, cq, cq + 1001, cq + 1001)]
    h, sigs, pr = sealed(reg, ops, [1, 2, 3])
    run("use_after_ack", reg, reg.functions.proveUseAfterAck(h, sigs, ops[0], 0, pr[0]))

    reg, o, lk = fresh()
    renew(reg, lk, cq)
    acked(reg, lk, cq + 1000)
    rel = (C.RELEASE, lk, cq, cq + 1500, 0, s1.clock.epoch,
           s1.clock.attest(C.clock_digest, s1.k, s1.clock.epoch, cq + 1500, C.release_tag(lk)))
    h, sigs, pr = sealed(reg, [rel], [1, 2, 3])
    run("release_after_ack", reg, reg.functions.proveUseAfterAck(h, sigs, rel, 0, pr[0]))

    reg, o, lk = fresh()
    h1, sg1, _ = sealed(reg, [(C.LOG, keccak(text="a"), 0, 0, 0, 0, b"")], [0, 1, 2])
    h2, sg2, _ = sealed(reg, [(C.LOG, keccak(text="b"), 0, 0, 0, 0, b"")], [1, 2, 3])
    run("fork", reg, reg.functions.proveFork(h1, sg1, h2, sg2))

    # Forged close: a quorum inflates its coverage; G must refuse the anchor (no slashing involved).
    reg, o, lk = fresh()
    h, sigs, _ = sealed(reg, [(C.LOG, keccak(text="c"), 0, 0, 0, 0, b"")], byz)
    hf = h[:9] + (h[9] + 10_000_000,) + h[10:]
    sigs_f = [C.sign(s1.vkeys[i], C.checkpoint_digest(reg.address, C.header_hash(hf))) for i in byz]
    try:
        reg.functions.anchor(hf, sigs_f).call({"from": admin.acct.address})
        out["forged_close"] = {"rejected": False}
    except Exception as e:  # noqa: BLE001
        out["forged_close"] = {"rejected": True, "reason": revert_reason(e)}

    # No framing: every applicable proof against every honest sealed operation (and every consecutive honest
    # checkpoint pair) must revert with NotAViolation, the contract's verdict that the operation is in rights.
    reg = ctx["reg"]
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

    for s in (s1, s2):
        prev = None
        for h, sigs, ops in s.sealed:
            if len(sigs) < 3:
                prev = (h, sigs, ops)
                continue
            _, proofs = C.merkle([C.op_leaf(op) for op in ops])
            committed = [op[3] for op in ops if op[0] == C.CONSUME and op[1] == parts]   # the state root's total
            for i, op in enumerate(ops):
                if op[0] == C.CONSUME:
                    attempt(reg.functions.proveOverspend(h, sigs, op, i, proofs[i]))
                    attempt(reg.functions.proveStateMismatch(h, sigs, op, i, proofs[i], committed[-1], 0, []))
                    if prev is not None:
                        ptotal = None
                        for pop in prev[2]:
                            if pop[0] == C.CONSUME and pop[1] == parts:
                                ptotal = pop[3]
                        if ptotal is not None:
                            attempt(reg.functions.proveUnderstateParent(h, sigs, op, i, proofs[i], prev[0], ptotal, 0, []))
                if op[0] == C.USE:
                    attempt(reg.functions.proveOveruse(h, sigs, op, i, proofs[i]))
                if op[0] in (C.USE, C.RELEASE):
                    attempt(reg.functions.proveUseAfterAck(h, sigs, op, i, proofs[i]))
            prev = (h, sigs, ops)
    out["no_framing"] = {"proof_attempts_on_honest_ops": tried, "verdicts": verdicts}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cut", type=int, default=150)
    ap.add_argument("--tag", default="v4")
    ap.add_argument("--flap", action="store_true", help="site 1's uplink flaps and is lossy instead of cut")
    args = ap.parse_args()
    nodes = json.loads((NET / "nodes.json").read_text())
    for k in (1, 2):
        uplink(k, True)
    t0 = time.time()
    ctx = {"t0": t0, "drift": {1: -RHO_PPM / 1e6, 2: 0.05}, "gas": {}, "sites": {}}
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
            th.join(timeout=30)
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
                         "drift": ctx["drift"], "flap": args.flap},
              "gas": ctx["gas"], "events": ctx["log"].rows}
    result["attacks"] = attacks(ctx)
    out = ROOT / "experiments" / "results" / f"e2e_{args.tag}.json"
    out.write_text(json.dumps(result, indent=1, default=lambda x: x.hex() if isinstance(x, bytes) else str(x)))
    print("wrote", out)


if __name__ == "__main__":
    main()
