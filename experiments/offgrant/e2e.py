"""End-to-end run of OffGrant (contracts v6) on local PureChain networks (testbed/purechain/net_offgrant).

Global chain G (4 Clique signers, the authorities) and two site chains (4 signers each, the site validators).
Each site's relayer reaches G only through its uplink proxy container; cutting the proxy (netem loss 100%)
cuts the site's uplink while the site chain keeps running. Site clocks are TPM stand-ins: drift (site 1 at the
-15% bound, site 2 at +5%), power epochs, strictly increasing attested readings.

Roles, as in the paper:
  gateway    holds the trusted clock and is the only component that attests. It attests a grant only under a
             renewal certificate it verified, in the clock's current epoch, inside the allowance (a bounded hold
             must end inside it); a consumption only within the share it verified; a release only by the crew that
             applied the lock; an acknowledgement only when no hold of the object can be in effect, including
             holds from an earlier power epoch (it waits out their remaining time, scaled by the drift bound).
             It executes a grant only once the grant is in a sealed checkpoint and a fresh reading is still before
             the hold's end and the allowance; an actuator loop logs every observed effect end.
  validators each recompute the operations and the state from their own node; sign a checkpoint only if it
             matches; never sign a different checkpoint at a height they signed (a retry re-proposes the same
             content); and halt for good if a block under a sealed checkpoint leaves their chain (reorg).
  relayer    anchors the newest sealed checkpoint (one transaction after an outage), renews in one batch, applies
             certificates; every transaction to G is signed once and rebroadcast until mined, so a lossy, flapping
             link delays it but cannot lose it. Every anchor attempt is logged, and the run cross-checks the log
             against the Anchored events on G.

Scenario (seconds after the warm-up):
  10  G lowers site 2's share of parts (40 -> 30); site 2 applies it and G frees the capacity once a sealed
      checkpoint shows the new version (confirmShare)
  20  cut site 1's uplink for CUT s (or, with --flap, make it alternate between cut and lossy/slow)
  35  G stops P11 (bounded holds, site 1 cut off) and L11 (open hold, site 1) in favour of site 2:
      P11 moves by the slow path at releaseAt; L11 is refused by the slow path (a lock may be on)
  45  G revokes credential C11 of site 1 (cut off)
  20+CUT  heal site 1: one anchor catches up; stops are applied; L11 moves by acknowledgement once released
  +30 G stops P21 (site 2, connected): fast path once every running hold of P21 has ended
  +60 power loss at site 2 (clock epoch changes); +62 G stops P22 (site 2): the acknowledgement waits out the
      holds of P22 granted in the earlier epoch
Then fraud proofs by a faulty site quorum (fresh registries), rejected forgeries, and no-framing checks: every
applicable proof against every honest sealed operation, checkpoint pair and acknowledgement.
Writes experiments/results/e2e_<tag>.json.
"""
import argparse
import json
import math
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
RHO = RHO_PPM / 1e6
G_SLACK = 2            # s, bound on G timestamp error (W adds 2 x this)
D_S = 60               # offline tolerance (s), time-compressed for a real-time run
A_MS = int(D_S * 1000 * (1 + RHO))
P_RENEW = 4.0          # pause between relayer rounds while connected (s); one batch renewal per round
CKPT_EVERY = 6.0       # checkpoint period (s)
CONFIRM = 3            # site blocks a checkpoint waits for before validators sign it (Clique depth k)
CONFIRM_G = 2          # G blocks a renewal waits for before the authorities certify it
LAG_MS = 60_000        # anchor lag: renewals need anchored coverage up to (request reading - lag)
WARMUP = 25            # s of normal operation before the scenario events
WINDOW_MS = 25_000     # hold window requested per grant (clock ms)
LOCK_S = 20            # an open hold (lock) stays on for this long once executed
G_TIMEOUT = 8          # s, RPC timeout through the uplink proxy (slow, lossy links); reads are retried
TX_DEADLINE = 90       # s a transaction to G is rebroadcast before the relayer gives up on it
OBJECTS = ["P11", "P12", "C11", "L11", "P21", "P22", "C21"]
ERRS = {
    "NotAViolation": "NotAViolation()", "BadProof": "BadProof()", "BadClockSig": "BadClockSig()",
    "NoQuorum": "NoQuorum()", "HoldMayBeOpen": "HoldMayBeOpen()", "StaleAck": "StaleAck()", "NotHeld": "NotHeld()",
    "StaleReading": "StaleReading()", "StillHeld": "StillHeld()", "NotStopped": "NotStopped()",
    "NoRenewal": "NoRenewal()", "BadHold": "BadHold()", "StaleShare": "StaleShare()",
    "SiteRevokedErr": "SiteRevokedErr()", "LeaseStopped": "LeaseStopped()", "StaleRequest": "StaleRequest()",
    "TooEarly": "TooEarly(uint64)", "AnchorDebt": "AnchorDebt(uint64,uint64)",
    "AllowanceExpired": "AllowanceExpired(uint64,uint64)", "OverShare": "OverShare(uint64,uint64)",
}
SEL = {name: keccak(text=sig)[:4].hex() for name, sig in ERRS.items()}


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


def transient(e):
    m = str(e)
    return any(k in m for k in ("timed out", "Max retries", "Connection", "RemoteDisconnected", "not mined",
                                "Timeout", "timeout", "reset by peer"))


def rd(f, tries=3, pause=0.5):
    """A read over the uplink, retried on transient errors (lossy links drop requests)."""
    for i in range(tries):
        try:
            return f()
        except Exception as e:  # noqa: BLE001
            if not transient(e) or i == tries - 1:
                raise
            time.sleep(pause)


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


def flapper(ctx, until, stop, seed):
    """Flapping, lossy uplink for site 1: cut for 3-15 s, then slow and lossy for 10-30 s, alternately."""
    rnd = random.Random(seed)
    on = False
    while time.time() < until and not stop.is_set():
        on = not on
        uplink(1, on, degraded=True)
        ctx["log"].add("flap", site=1, up=on)
        stop.wait(min(rnd.uniform(10, 30) if on else rnd.uniform(3, 15), max(0.0, until - time.time())))


class Refused(Exception):
    pass


class Gateway:
    """The site's gateway: holds the trusted clock, checks rights before attesting, executes sealed grants."""

    def __init__(self, s, ctx):
        self.s, self.ctx = s, ctx
        self.auth = set(ctx["auth"])
        self.renewal = {}   # name -> (epoch, cq) newest renewal whose certificate it verified
        self.stopped = {}   # name -> (epoch, cq) newest stop certificate it verified
        self.share = {}     # resource -> (amount, version) newest share certificate it verified
        self.total = {}     # resource -> running total it has attested
        self.crew = {}      # (name, hold id) -> (crew, grant epoch) of attested open holds
        self.lock = threading.Lock()

    def _cert(self, digest, sigs):
        if not C.certified_by(digest, sigs, self.auth, 3):
            raise Refused("certificate")

    # ---- certificates relayed from G (verified, not trusted)
    def on_renewal(self, names, epoch, cq, issued, sigs):
        self._cert(C.renewal_digest(self.ctx["dom"], self.s.k, C.objects_hash([obj(n) for n in names]), epoch, cq,
                                    issued), sigs)
        with self.lock:
            for n in names:
                if (epoch, cq) > self.renewal.get(n, (0, 0)) and (epoch, cq) > self.stopped.get(n, (0, 0)):
                    self.renewal[n] = (epoch, cq)

    def on_stop(self, name, epoch, cq, sigs):
        self._cert(C.stop_digest(self.ctx["dom"], self.s.k, obj(name), epoch, cq), sigs)
        with self.lock:
            self.stopped[name] = max(self.stopped.get(name, (0, 0)), (epoch, cq))
            if self.renewal.get(name, (0, 0)) <= self.stopped[name]:
                self.renewal.pop(name, None)

    def on_share(self, resource, amount, version, sigs):
        self._cert(C.share_digest(self.ctx["dom"], self.s.k, resource, amount, version), sigs)
        with self.lock:
            if version > self.share.get(resource, (0, 0))[1]:
                self.share[resource] = (amount, version)

    # ---- attestations
    def _attest(self, op):
        return C.attest_op(self.s.clock, self.ctx["dom"], self.s.k, op)

    def use(self, name, crew=0):
        """Attests a grant of `name` at a fresh reading: a bounded hold of up to WINDOW_MS, or an open hold by
        `crew`. Returns the attested operation; raises Refused when the rights do not cover it."""
        s = self.s
        with self.lock:
            if name in s.acked:
                raise Refused("acknowledged")
            b = self.renewal.get(name)
            epoch, reading = s.clock.epoch, s.clock.read()
            if b is None:
                raise Refused("no renewal")
            if b[0] != epoch:
                raise Refused("renewal of an earlier epoch")
            if reading - b[1] >= A_MS:
                raise Refused("allowance expired")
            if is_open(name):
                if crew == 0:
                    raise Refused("lock without crew")
                until = C.OPEN
            else:
                until = min(reading + WINDOW_MS, b[1] + A_MS - 1)
                if until <= reading:
                    raise Refused("no time left")
            op = self._attest(C.make_op(C.USE, obj(name), epoch, reading, base=b[1], until=until, amount=crew))
            if is_open(name):
                self.crew[(name, reading)] = (crew, epoch)
            return op

    def consume(self, resource, amount):
        with self.lock:
            sh = self.share.get(resource)
            if sh is None:
                raise Refused("no share")
            t = self.total.get(resource, 0) + amount
            if t > sh[0]:
                raise Refused("share exhausted")
            self.total[resource] = t
            epoch, reading = self.s.clock.epoch, self.s.clock.read()
            return self._attest(C.make_op(C.CONSUME, resource, epoch, reading, amount=amount, version=sh[1]))

    def release(self, name, hold_id, crew):
        with self.lock:
            rec = self.crew.get((name, hold_id))
            if rec is None or rec[0] != crew:
                raise Refused("wrong crew")
            epoch, reading = self.s.clock.epoch, self.s.clock.read()
            return self._attest(C.make_op(C.RELEASE, obj(name), epoch, reading, base=hold_id, until=rec[1],
                                          amount=crew))

    def quiet(self, name):
        """Why a hold of the object may still be in effect (None if none can be)."""
        s = self.s
        now_ep, now = s.clock.epoch, s.clock.read()
        with s.glock:
            if any(h["epoch"] == now_ep and h["until"] > now for h in s.bounded.get(name, [])):
                return "bounded hold running"
            if any(e == now_ep and d > now for e, d in s.carry.get(name, [])):
                return "hold from an earlier epoch may still run"
            if s.locks.get(name):
                return "lock on"
            if any(g["name"] == name for g in s.pending):
                return "grant awaiting execution"
        return None

    def ack(self, name, base, opens, releases):
        with self.lock:
            if opens != releases:
                raise Refused("lock on")
            why = self.quiet(name)
            if why:
                raise Refused(why)
            epoch, reading = self.s.clock.epoch, self.s.clock.read()
            self.s.acked.add(name)   # nothing of the object is attested or executed from now on
            return self._attest(C.make_op(C.ACK, obj(name), epoch, reading, base=base, amount=opens, total=releases))

    def power_loss(self):
        """Power loss: actuators de-energise (bounded holds end), the clock enters a new epoch. Holds of the old
        epoch that a person may still be acting on (permits) are carried as deadlines in the new epoch: their
        remaining time, scaled by (1 + rho)/(1 - rho), so an acknowledgement waits them out."""
        s = self.s
        with self.lock:
            old, last = s.clock.epoch, s.clock.read()
            s.clock.reset()
            start = s.clock.read()
            with s.glock:
                for name, holds in s.bounded.items():
                    for h in holds:
                        if h["epoch"] == old and h["until"] > last and not h["ended"]:
                            wait = math.ceil((h["until"] - last) * (1 + RHO) / (1 - RHO))
                            s.carry.setdefault(name, []).append((s.clock.epoch, start + wait))
                            h["ended"] = True
                            self.ctx["log"].add("effect_end", site=s.k, obj=name, epoch=old, until=h["until"],
                                                why="power_loss", carry_ms=wait)
        return s.clock.epoch


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
        self.gw = None
        self.hist = [C.ZERO]       # hist[i] = hash of the sealed checkpoint at height i
        self.state = C.SiteState()  # state after the last sealed checkpoint
        self.sealed = []           # dict(h, sigs, ops, state, height, tip_block) of every sealed checkpoint
        self.sealed_sigs = {}      # attestation of a sealed operation -> height of its checkpoint
        self.signed = [dict() for _ in self.vals]   # per validator: height -> header hash it signed
        self.proposal = None       # checkpoint proposed and not yet sealed (re-proposed unchanged on retry)
        self.halted = False
        self.ckpt_block = 0
        self.final_block = 0       # blocks below this are in a sealed checkpoint
        self.pending = []          # grants awaiting execution: dict(op, name, block, t)
        self.bounded = {}          # name -> list of dict(epoch, until, ended) of executed bounded holds
        self.carry = {}            # name -> list of (epoch, deadline) carried over a power loss
        self.locks = {}            # name -> {holdId: (exec time, crew)} of executed open holds not yet released
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
    ctx["reg_block"] = r.blockNumber
    ctx["gas"]["deploy_registry"] = r.gasUsed
    g_chain = gadmin.w3.eth.chain_id
    ctx["dom"] = C.domain(reg.address, g_chain)
    assert ctx["dom"] == bytes(reg.functions.dom().call())
    ctx["gkeys"] = [n["key"] for n in nodes["g"]]
    auth = [Account.from_key(k).address for k in ctx["gkeys"]]
    ctx["auth"] = auth
    parts = obj("spare-parts")
    ctx["parts"] = parts
    gadmin.send(reg.functions.setCap(parts, 100))
    for s in ctx["sites"].values():
        s.gw = Gateway(s, ctx)
        gadmin.send(reg.functions.registerSite(s.k, 1, Account.from_key(s.clock.key).address,
                                               [v["address"] for v in s.vals], s.clock.epoch, s.clock.read()))
        gadmin.send(reg.functions.setShare(parts, s.k, 40))     # version 1
        s.contract, r = s.rel_s.deploy("SiteRights", s.k, reg.address, g_chain,
                                       Account.from_key(s.clock.key).address, auth, 3)
        ctx["gas"]["deploy_site"] = r.gasUsed
        cert = certify(ctx, C.share_digest(ctx["dom"], s.k, parts, 40, 1))
        s.rel_s.send(s.contract.functions.applyShare(parts, 40, 1, cert))
        s.gw.on_share(parts, 40, 1, cert)
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
def g_send(ctx, s, fn, what, **kw):
    """Sends a transaction to G over the uplink, rebroadcasting until mined; logs the attempt and the outcome."""
    t = time.time()
    sent = {}

    def on_sent(h):
        sent["h"] = h.hex()
        ctx["log"].add(what + "_sent", site=s.k, tx=sent["h"], **kw)

    try:
        r = s.rel_g.send_robust(fn, deadline=TX_DEADLINE, on_sent=on_sent)
    except Exception as e:  # noqa: BLE001
        ctx["log"].add(what + "_fail", site=s.k, tx=sent.get("h"), err=str(e)[:100], **kw)
        raise
    return r, round(time.time() - t, 3)


def anchor_newest(ctx, s, reg_g):
    ah = rd(lambda: reg_g.functions.sites(s.k).call())[6]
    with s.glock:
        cands = [c for c in s.sealed if c["height"] > ah]
        if not cands:
            return
        c = cands[-1]
        path = C.hist_path(s.hist[:c["height"]], ah) if ah > 0 else []
    r, dt = g_send(ctx, s, reg_g.functions.anchor(c["h"], c["sigs"], path), "anchor", height=c["height"])
    ctx["log"].add("anchor", site=s.k, height=c["height"], covers=len(cands), status=r.status, gas=r.gasUsed,
                   close_epoch=c["h"][8], close_reading=c["h"][9], latency=dt, block=r.blockNumber)


def apply_shares(ctx, s, reg_g):
    parts = ctx["parts"]
    gv = rd(lambda: reg_g.functions.shareVersion(parts, s.k).call())
    sv = s.contract.functions.shareVersion(parts).call()
    if gv > sv:
        amount = rd(lambda: reg_g.functions.certified(parts, s.k, gv).call())
        cert = certify(ctx, C.share_digest(ctx["dom"], s.k, parts, amount, gv))
        try:
            s.contract.functions.applyShare(parts, amount, gv, cert).call({"from": s.rel_s.acct.address})
            r = s.rel_s.send(s.contract.functions.applyShare(parts, amount, gv, cert))
            s.gw.on_share(parts, amount, gv, cert)
            ctx["log"].add("share_applied", site=s.k, version=gv, amount=amount, gas=r.gasUsed)
        except Exception as e:  # noqa: BLE001
            ctx["log"].add("share_refused", site=s.k, version=gv, why=revert_reason(e))
    pv = rd(lambda: reg_g.functions.pendingVersion(parts, s.k).call())
    if pv and pv not in s.share_confirmed:
        amount = rd(lambda: reg_g.functions.certified(parts, s.k, pv).call())
        with s.glock:
            cands = [c for c in s.sealed if C.lookup(c["state"], parts)[1] >= pv
                     and C.lookup(c["state"], parts)[0] <= amount]
        if cands:
            c = cands[-1]
            r, _ = g_send(ctx, s, reg_g.functions.confirmShare(parts, s.k, c["h"], c["sigs"], c["state"]),
                          "confirm_share")
            s.share_confirmed.add(pv)
            ctx["log"].add("share_confirmed", site=s.k, version=pv, amount=amount, height=c["height"],
                           status=r.status, gas=r.gasUsed)


def relay_once(ctx, s):
    reg_g = ctx["reg_at"](s.g)
    try:
        rd(lambda: s.g.eth.block_number, tries=2)
    except Exception:  # noqa: BLE001
        return False
    anchor_newest(ctx, s, reg_g)   # anchor first: G renews only sites whose checkpoints are anchored
    renew = []
    for name in OBJECTS:
        o = obj(name)
        lease = rd(lambda: reg_g.functions.leases(o).call())   # exists, exclusive, openHold, stopped, A, lastIssue, holder, next
        exclusive, stopped, holder = lease[1], lease[3], lease[6]
        mine = holder == s.k if exclusive else rd(lambda: reg_g.functions.permitted(o, s.k).call())
        if stopped and mine:
            handle_stop(ctx, s, name, o, exclusive, reg_g)
        elif not stopped and rd(lambda: reg_g.functions.mayRenew(o, s.k).call()):
            renew.append(name)
    apply_shares(ctx, s, reg_g)
    if renew:
        objs = [obj(n) for n in renew]
        t_send = time.time()
        epoch, cq = s.clock.epoch, s.clock.read()   # the request is attested when it is SENT
        sig = C.sign(s.clock.key, C.clock_digest(ctx["dom"], s.k, epoch, cq, C.request_tag(C.objects_hash(objs))))
        try:   # a renewal G would refuse (e.g. AnchorDebt) is not sent; it is logged instead
            rd(lambda: reg_g.functions.renew(s.k, objs, epoch, cq, sig).call({"from": s.rel_g.acct.address}))
        except Exception as e:  # noqa: BLE001
            if transient(e):
                raise
            ctx["log"].add("renew_refused", site=s.k, objs=renew, why=revert_reason(e))
            return True
        r, _ = g_send(ctx, s, reg_g.functions.renew(s.k, objs, epoch, cq, sig), "renew", objs=renew, cq=cq)
        if r.status == 1:
            t_end = time.time() + TX_DEADLINE
            while rd(lambda: s.g.eth.block_number) < r.blockNumber + CONFIRM_G and time.time() < t_end:
                time.sleep(0.3)   # certify only once final on G
            ev = reg_g.events.Renewed().process_receipt(r)[0]["args"]
            cert = certify(ctx, C.renewal_digest(ctx["dom"], s.k, C.objects_hash(objs), epoch, cq, ev["issued"]))
            r2 = s.rel_s.send(s.contract.functions.applyRenewal(objs, epoch, cq, ev["issued"], cert))
            s.gw.on_renewal(renew, epoch, cq, ev["issued"], cert)
            ctx["log"].add("renewal", site=s.k, objs=renew, epoch=epoch, cq=cq, issued=ev["issued"],
                           t_send=round(t_send - ctx["t0"], 3), latency=round(time.time() - t_send, 3),
                           gas_g=r.gasUsed, gas_site=r2.gasUsed, g_block=r.blockNumber)
    anchor_newest(ctx, s, reg_g)
    return True


def handle_stop(ctx, s, name, o, exclusive, reg_g):
    epoch, cq = rd(lambda: reg_g.functions.lastRenewal(o, s.k).call())
    key = (name, epoch, cq)
    st = s.stops.get(key)
    if st is None:
        cert = certify(ctx, C.stop_digest(ctx["dom"], s.k, o, epoch, cq))
        r = s.rel_s.send(s.contract.functions.applyStop(o, epoch, cq, cert))
        s.gw.on_stop(name, epoch, cq, cert)
        st = s.stops[key] = {"block": r.blockNumber, "done": False, "seen": time.time()}
        ctx["log"].add("stop_applied", site=s.k, obj=name, gas=r.gasUsed)
    if st["done"] or not exclusive:
        return
    if s.final_block <= st["block"]:
        return   # the stop is not yet in a sealed checkpoint
    if "ack" not in st:
        base = s.contract.functions.stoppedUpTo(o).call()[1]
        opens = s.contract.functions.opens(o).call()
        rels = s.contract.functions.releases(o).call()
        try:
            op = s.gw.ack(name, base, opens, rels)
        except Refused as e:
            if st.get("waiting") != str(e):
                ctx["log"].add("ack_wait", site=s.k, obj=name, why=str(e))
                st["waiting"] = str(e)
            return
        a_epoch, reading = op[2], op[3]
        try:
            s.contract.functions.acknowledge(o, a_epoch, reading, op[9]).call({"from": s.rel_s.acct.address})
        except Exception as e:  # noqa: BLE001
            ctx["log"].add("ack_refused", site=s.k, obj=name, why=revert_reason(e))
            return
        r = s.rel_s.send(s.contract.functions.acknowledge(o, a_epoch, reading, op[9]))
        st["ack"] = (a_epoch, reading, opens, op)
        ctx["log"].add("ack_op", site=s.k, obj=name, status=r.status, gas=r.gasUsed, reading=reading, opens=opens)
        return
    a_epoch, reading, opens, op = st["ack"]
    if op[9] not in s.sealed_sigs:
        return   # validators acknowledge only an ACK operation in a sealed checkpoint
    acks = [C.sign(vk, C.ack_digest(ctx["dom"], s.k, o, a_epoch, reading)) for vk in s.vkeys[:3]]
    r, _ = g_send(ctx, s, reg_g.functions.reassignAcked(o, a_epoch, reading, opens, op[9], acks), "reassign_acked",
                  obj=name)
    st["done"] = r.status == 1
    ctx["log"].add("reassign_acked", site=s.k, obj=name, status=r.status, gas=r.gasUsed,
                   latency_from_stop_seen=round(time.time() - st["seen"], 3), ack_reading=reading, ack_epoch=a_epoch,
                   g_block=r.blockNumber)
    if r.status == 1:
        ctx["acks"].append((name, s.k, a_epoch, reading))


def relayer(ctx, s, stop):
    up_prev = None
    while not stop.is_set():
        try:
            up = relay_once(ctx, s)
        except Exception as e:  # noqa: BLE001  (timeouts while the uplink is cut or lossy)
            up = False
            if not transient(e):
                ctx["log"].add("relayer_error", site=s.k, err=str(e)[:160])
        if up != up_prev:
            ctx["log"].add("uplink_seen", site=s.k, up=up)
            up_prev = up
        stop.wait(P_RENEW)


# ------------------------------------------------------------------------------------------- checkpoints
def seal_round(ctx, s):
    dom = ctx["dom"]
    if s.halted:
        return
    if s.sealed:   # reorg check: the tip under the last sealed checkpoint must still be in every replica
        last = s.sealed[-1]
        for vi, vw in enumerate(s.vw3):
            b = vw.eth.get_block(last["tip_block"])
            if bytes(b["hash"]) != last["h"][7]:
                s.halted = True
                ctx["log"].add("halt_reorg", site=s.k, validator=vi, height=last["height"])
                return
    if s.proposal is None:
        head = s.w3.eth.block_number - CONFIRM
        lo, hi = s.ckpt_block, head
        if hi <= lo:
            return
        sc = s.vw3[0].eth.contract(address=s.contract.address, abi=s.contract.abi)
        logs = sc.events.OpRecorded().get_logs(from_block=lo, to_block=hi - 1)
        ops = [op_tuple(l["args"]["op"]) for l in sorted(logs, key=lambda l: l["args"]["seq"])]
        st = s.state.copy()
        for op in ops:
            st.apply(op)
        tip = bytes(s.w3.eth.get_block(hi - 1)["hash"])
        h, _ = C.make_header(s.clock, dom, s.k, s.hist, ops, st.tuple(), tip)
        s.proposal = {"h": h, "ops": ops, "st": st, "state": st.tuple(), "lo": lo, "hi": hi,
                      "height": len(s.hist), "tries": 0}
    p = s.proposal
    p["tries"] += 1
    hh = C.header_hash(p["h"])
    sigs = []
    for vi, (vw, vk) in enumerate(zip(s.vw3, s.vkeys)):
        # each validator recomputes the operations, the state and the tip from its own node
        sc = vw.eth.contract(address=s.contract.address, abi=s.contract.abi)
        try:
            logs = sc.events.OpRecorded().get_logs(from_block=p["lo"], to_block=p["hi"] - 1)
            tip_v = bytes(vw.eth.get_block(p["hi"] - 1)["hash"])
        except Exception:  # noqa: BLE001  replica behind: no signature this round
            continue
        v_ops = [op_tuple(l["args"]["op"]) for l in sorted(logs, key=lambda l: l["args"]["seq"])]
        v_st = s.state.copy()
        for op in v_ops:
            v_st.apply(op)
        if v_ops != p["ops"] or v_st.tuple() != p["state"] or tip_v != p["h"][7]:
            continue
        prev = s.signed[vi].get(p["height"])
        if prev is not None and prev != hh:
            ctx["log"].add("refuse_second_checkpoint", site=s.k, validator=vi, height=p["height"])
            continue
        s.signed[vi][p["height"]] = hh
        sigs.append(C.sign(vk, C.checkpoint_digest(dom, hh)))
    if len(sigs) < 3:
        ctx["log"].add("ckpt_retry", site=s.k, agree=len(sigs), height=p["height"], tries=p["tries"])
        return
    h = p["h"]
    with s.glock:
        s.ckpt_block = p["hi"]
        s.state = p["st"]
        s.hist.append(hh)
        height = len(s.hist) - 1
        s.sealed.append({"h": h, "sigs": sigs, "ops": p["ops"], "state": p["state"], "height": height,
                         "tip_block": p["hi"] - 1})
        for op in p["ops"]:
            if op[9]:
                s.sealed_sigs[op[9]] = height
        s.final_block = p["hi"]
        s.proposal = None
    ctx["log"].add("checkpoint", site=s.k, height=height, ops=len(p["ops"]), agree=len(sigs), lo=p["lo"], hi=p["hi"],
                   close_epoch=h[8], close_reading=h[9], state_len=h[6], tries=p["tries"])


def checkpointer(ctx, s, stop):
    while not stop.wait(CKPT_EVERY):
        try:
            seal_round(ctx, s)
            execute(ctx, s)
        except Exception as e:  # noqa: BLE001
            ctx["log"].add("ckpt_error", site=s.k, err=str(e)[:160])


def execute(ctx, s):
    """The gateway executes grants that are in a sealed checkpoint, with a fresh clock reading; a grant whose window
    or allowance has passed, or that belongs to another epoch or an acknowledged object, lapses."""
    now_ep, now = s.clock.epoch, s.clock.read()
    keep = []
    with s.glock:
        pending, s.pending = s.pending, []
    for g in pending:
        op = g["op"]
        if op[9] not in s.sealed_sigs:
            if op[2] != now_ep:   # attested before a power loss: it can never execute, so it lapses now
                ctx["log"].add("lapse", site=s.k, obj=g["name"], grant_t=g["t"], epoch=op[2], now_epoch=now_ep,
                               sealed=False)
                continue
            keep.append(g)
            continue
        cq, until, epoch = op[4], op[5], op[2]
        end = cq + A_MS if until == C.OPEN else min(until, cq + A_MS)
        ok = now_ep == epoch and now < end and g["name"] not in s.acked
        row = dict(site=s.k, obj=g["name"], grant_t=g["t"], reading=now, until=until, a=cq, epoch=epoch,
                   now_epoch=now_ep, height=s.sealed_sigs[op[9]], hold=op[3] if until == C.OPEN else None)
        if ok and until != C.OPEN:
            with s.glock:
                s.bounded.setdefault(g["name"], []).append({"epoch": epoch, "until": until, "ended": False})
        if ok and until == C.OPEN:
            with s.glock:
                s.locks.setdefault(g["name"], {})[op[3]] = (time.time(), op[6])
        ctx["log"].add("exec" if ok else "lapse", **row)
    with s.glock:
        s.pending = keep + s.pending


def actuator(ctx, s, stop):
    """Observes the end of every executed bounded hold on the site clock (the actuator drops out)."""
    while not stop.wait(0.1):
        ep, now = s.clock.epoch, s.clock.read()
        with s.glock:
            for name, holds in s.bounded.items():
                for h in holds:
                    if not h["ended"] and h["epoch"] == ep and h["until"] <= now:
                        h["ended"] = True
                        ctx["log"].add("effect_end", site=s.k, obj=name, epoch=ep, until=h["until"], reading=now,
                                       why="hold_end")


# ------------------------------------------------------------------------------------------- workload
def operator(ctx, s, stop):
    """Requests operations; every attestation comes from the gateway, which refuses what the rights do not cover."""
    rnd = random.Random(s.k)
    parts = ctx["parts"]
    wrong_crew_tried = False
    while not stop.wait(1.0):
        kind = rnd.choices(["use", "cred", "lock", "consume", "log"], [0.4, 0.2, 0.1, 0.2, 0.1])[0]
        t = time.time()
        grant, hid = None, None
        try:
            if kind == "lock":
                name = f"L{s.k}1" if f"L{s.k}1" in OBJECTS else "L11"
                o = obj(name)
                with s.glock:
                    mine = dict(s.locks.get(name, {}))
                    waiting = any(g["name"] == name for g in s.pending)
                done = [(h, c) for h, (et, c) in mine.items() if time.time() - et >= LOCK_S]
                if done:   # the crew removes its lock: the release names the hold it ends
                    hid, crew = done[0]
                    if not wrong_crew_tried:   # another crew tries to remove it first: refused
                        wrong_crew_tried = True
                        try:
                            s.gw.release(name, hid, crew + 100)
                            ctx["log"].add("op", site=s.k, op="release", obj=name, ok=True, why="WRONG CREW ACCEPTED")
                        except Refused as e:
                            ctx["log"].add("op", site=s.k, op="release_other_crew", obj=name, ok=False, why=str(e))
                    op = s.gw.release(name, hid, crew)
                    fn = s.contract.functions.release(o, hid, crew, op[2], op[3], op[9])
                    kind = "release"
                elif mine or waiting:
                    continue
                elif name not in s.gw.renewal and name not in s.gw.stopped:
                    ctx["log"].add("op", site=s.k, op=kind, obj=None, ok=False, why="none held")
                    continue
                else:
                    crew = rnd.randint(1, 9)
                    grant = s.gw.use(name, crew)
                    fn = s.contract.functions.use(o, grant[4], grant[2], grant[3], C.OPEN, crew, grant[9])
            elif kind in ("use", "cred"):
                names = [n for n in OBJECTS if (n.startswith("C") if kind == "cred" else n.startswith("P"))]
                with s.gw.lock:
                    held = [n for n in names if n in s.gw.renewal and n not in s.acked]
                if not held:
                    ctx["log"].add("op", site=s.k, op=kind, obj=None, ok=False, why="none held")
                    continue
                name = rnd.choice(held)
                grant = s.gw.use(name)
                fn = s.contract.functions.use(obj(name), grant[4], grant[2], grant[3], grant[5], 0, grant[9])
            elif kind == "consume":
                name = "parts"
                op = s.gw.consume(parts, 1)
                fn = s.contract.functions.consume(parts, 1, op[8], op[2], op[3], op[9])
            else:
                name, fn = "log", s.contract.functions.record(keccak(text=f"log{t}"))
        except Refused as e:
            ctx["log"].add("op", site=s.k, op=kind, obj=name, ok=False, why="gateway: " + str(e))
            continue
        try:
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
                    s.locks.get(name, {}).pop(hid, None)
                ctx["log"].add("effect_end", site=s.k, obj=name, epoch=op[2], until=C.OPEN, reading=op[3],
                               why="released", hold=hid)
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
            ctx["log"].add("reassigned_slow", obj=name, release_at=at, g_time=now, status=r.status, gas=r.gasUsed,
                           g_block=r.blockNumber)
            return
        time.sleep(1)


def scenario(ctx, cut_s, flap=False, seed=7):
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
        threading.Thread(target=flapper, args=(ctx, t0 + WARMUP + 20 + cut_s, fstop, seed), daemon=True).start()
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
    at(20 + cut_s + 52)
    s2 = ctx["sites"][2]   # a crew takes a P22 permit, so a hold is running when the power fails
    try:
        g = s2.gw.use("P22")
        r = s2.op_s.send(s2.contract.functions.use(obj("P22"), g[4], g[2], g[3], g[5], 0, g[9]))
        if r.status == 1:   # a grant the site ledger rejected is never sealed, so it awaits nothing
            with s2.glock:
                s2.pending.append({"op": g, "name": "P22", "block": r.blockNumber,
                                   "t": round(time.time() - t0, 3)})
        log.add("op", site=2, op="use", obj="P22", ok=r.status == 1, gas=r.gasUsed, until=g[5], scripted=True)
    except Exception as e:  # noqa: BLE001
        log.add("op", site=2, op="use", obj="P22", ok=False, why="scripted: " + str(e)[:60])
    at(20 + cut_s + 60)
    ep = ctx["sites"][2].gw.power_loss()
    log.add("clock_reset", site=2, epoch=ep)
    at(20 + cut_s + 62)
    r = admin.send(reg.functions.stop(obj("P22"), 1))
    log.add("stop", obj="P22", next=1, g_time=admin.w3.eth.get_block(r.blockNumber).timestamp, gas=r.gasUsed,
            after_reset=True)
    at(20 + cut_s + 130)


# ------------------------------------------------------------------------------------------- attacks
def attacks(ctx):
    """A faulty quorum of site 1 seals out-of-rights checkpoints; fresh registries keep the slashing counts
    independent. Then rejected forgeries, and no-framing checks on every honest sealed operation, checkpoint pair
    and acknowledgement."""
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
        return C.make_header(s1.clock, dom, s1.k, hist, ops, state, b"\x00" * 32)

    def seal(dom, h, who):
        return [C.sign(s1.vkeys[i], C.checkpoint_digest(dom, C.header_hash(h))) for i in who]

    def opp(ops, proofs, i):
        return (ops[i], i, proofs[i])

    def st(reading, total, version, epoch=None):
        return (E if epoch is None else epoch, reading, [parts], [total], [version], [], [], [])

    def empty(reading, epoch=None):
        return (E if epoch is None else epoch, reading, [], [], [], [], [], [])

    def locks(reading, ob, n_open, n_rel, epoch=None):
        return (E if epoch is None else epoch, reading, [], [], [], [ob], [n_open], [n_rel])

    def run(name, reg, fn):
        r = admin.send(fn, gas=8_000_000)
        out[name] = {"status": r.status, "gas": r.gasUsed, "slashed": len(reg.events.Slashed().process_receipt(r))}

    def rejected(name, fn):
        try:
            fn.call({"from": admin.acct.address})
            out[name] = {"rejected": False}
        except Exception as e:  # noqa: BLE001
            out[name] = {"rejected": True, "reason": revert_reason(e)}

    def renew(reg, dom, objs, cq):
        sig = C.sign(s1.clock.key, C.clock_digest(dom, s1.k, E, cq, C.request_tag(C.objects_hash(objs))))
        admin.send(reg.functions.renew(s1.k, objs, E, cq, sig))

    def acked(reg, dom, ob, cq, ra):
        admin.send(reg.functions.stop(ob, s2.k))
        ack = att(dom, C.make_op(C.ACK, ob, E, ra, base=cq))
        acks = [C.sign(s1.vkeys[i], C.ack_digest(dom, s1.k, ob, E, ra)) for i in (0, 1, 2)]
        admin.send(reg.functions.reassignAcked(ob, E, ra, 0, ack[9], acks))

    def lock_op(dom, ob, reading, cq, crew, n):
        return att(dom, C.make_op(C.USE, ob, E, reading, base=cq, until=C.OPEN, amount=crew, total=n))

    byz = [0, 1, 2]
    H1 = [C.ZERO]
    base_r = s1.clock.read()   # readings for the forged history start here (the registries are fresh)
    R = lambda d: base_r + d   # noqa: E731

    # ---- resources
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
    ops = [C.make_op(C.LOG, keccak(text="x"))]
    over = st(R(1), 55, 1)                                                          # above the certified 40
    h, pr = ckpt(dom, H1, ops, over)
    run("state_above_share", reg, reg.functions.proveStateMismatch(h, seal(dom, h, byz), opp(ops, pr, 0), over))

    reg, dom, o, lk = fresh()
    h, pr = ckpt(dom, H1, ops, empty(0))
    hb = list(h)
    hb[6] = 1_000_000                                                               # a million-entry state
    hb[10] = C.sign(s1.clock.key, C.clock_digest(dom, s1.k, hb[8], hb[9], C.content_tag(tuple(hb))))
    hb = tuple(hb)
    run("oversized_state", reg, reg.functions.proveStateMismatch(hb, seal(dom, hb, byz), opp(ops, pr, 0), empty(0)))

    # ---- grants and holds
    reg, dom, o, lk = fresh()
    cq = R(1)
    renew(reg, dom, [o], cq)
    ops = [att(dom, C.make_op(C.USE, o, E, cq + A_MS, base=cq, until=cq + A_MS + 5))]
    h, pr = ckpt(dom, H1, ops, empty(cq + A_MS))
    run("overuse", reg, reg.functions.proveOveruse(h, seal(dom, h, byz), opp(ops, pr, 0)))

    reg, dom, o, lk = fresh()
    renew(reg, dom, [o], cq)
    ops = [att(dom, C.make_op(C.USE, o, E, cq + 10, base=cq, until=cq + A_MS))]   # ends past the allowance
    h, pr = ckpt(dom, H1, ops, empty(cq + 10))
    run("hold_past_allowance", reg, reg.functions.proveOveruse(h, seal(dom, h, byz), opp(ops, pr, 0)))

    reg, dom, o, lk = fresh()
    renew(reg, dom, [o], cq)
    ops = [att(dom, C.make_op(C.USE, o, E + 1, 10, base=cq, until=20))]          # new epoch, old renewal
    h, pr = ckpt(dom, H1, ops, empty(10, E + 1))
    run("use_after_reset", reg, reg.functions.proveOveruse(h, seal(dom, h, byz), opp(ops, pr, 0)))

    reg, dom, o, lk = fresh()
    renew(reg, dom, [o], cq)
    g = att(dom, C.make_op(C.USE, o, E, cq + 10, base=cq, until=cq + 20))
    ops = [g, g]                                                                    # replayed attestation
    h, pr = ckpt(dom, H1, ops, empty(cq + 10))
    run("replayed_attestation", reg, reg.functions.proveInconsistent(h, seal(dom, h, byz), opp(ops, pr, 0),
                                                                     opp(ops, pr, 1)))

    reg, dom, o, lk = fresh()
    rel = C.make_op(C.RELEASE, lk, E, cq + 30, base=cq + 10, until=E, amount=1, total=1,
                    sig=C.sign(s1.clock.key, b"\x01" * 32))
    ops = [rel]                                                                     # release never attested
    h, pr = ckpt(dom, H1, ops, locks(cq + 30, lk, 1, 1))
    run("forged_release", reg, reg.functions.proveBadOp(h, seal(dom, h, byz), opp(ops, pr, 0)))

    # ---- lockouts at acknowledgement (v6)
    reg, dom, o, lk = fresh()
    ops = [lock_op(dom, lk, cq + 10, cq, 1, 1), att(dom, C.make_op(C.ACK, lk, E, cq + 20, base=cq, amount=1, total=0))]
    h, pr = ckpt(dom, H1, ops, locks(cq + 20, lk, 1, 0))                           # ACK admits a lock is on
    run("ack_with_lock_on", reg, reg.functions.proveBadOp(h, seal(dom, h, byz), opp(ops, pr, 1)))

    reg, dom, o, lk = fresh()
    ops = [lock_op(dom, lk, cq + 10, cq, 1, 1), att(dom, C.make_op(C.ACK, lk, E, cq + 20, base=cq))]
    h, pr = ckpt(dom, H1, ops, locks(cq + 20, lk, 1, 0))                           # ACK hides the lock
    run("ack_hides_lock", reg, reg.functions.proveInconsistent(h, seal(dom, h, byz), opp(ops, pr, 0), opp(ops, pr, 1)))

    reg, dom, o, lk = fresh()
    s_1 = locks(cq + 10, lk, 1, 0)
    c1, _ = ckpt(dom, H1, [lock_op(dom, lk, cq + 10, cq, 1, 1)], s_1)
    hist2 = H1 + [C.header_hash(c1)]
    ops = [att(dom, C.make_op(C.ACK, lk, E, cq + 20, base=cq))]
    h, pr = ckpt(dom, hist2, ops, locks(cq + 20, lk, 1, 0))                        # hides an earlier checkpoint's lock
    run("ack_hides_earlier_lock", reg, reg.functions.proveOpRegress(h, seal(dom, h, byz), opp(ops, pr, 0),
                                                                     (c1, s_1, C.hist_path(hist2, 1))))

    reg, dom, o, lk = fresh()
    s_1 = locks(cq + 10, lk, 2, 1)
    c1, _ = ckpt(dom, H1, [lock_op(dom, lk, cq + 10, cq, 1, 2)], s_1)
    hist2 = H1 + [C.header_hash(c1)]
    s_2 = locks(cq + 10, lk, 1, 1)                                                  # a lock forgotten
    c2, _ = ckpt(dom, hist2, [C.make_op(C.LOG, keccak(text="noop"))], s_2)
    run("lock_counter_regress", reg, reg.functions.proveRegress(c2, seal(dom, c2, byz), s_2,
                                                                (c1, s_1, C.hist_path(hist2, 1))))

    # ---- after an acknowledgement
    reg, dom, o, lk = fresh()
    renew(reg, dom, [o], cq)
    acked(reg, dom, o, cq, cq + 1000)
    ops = [att(dom, C.make_op(C.USE, o, E, cq + 1001, base=cq, until=cq + 1500))]
    h, pr = ckpt(dom, H1, ops, empty(cq + 1001))
    run("use_after_ack", reg, reg.functions.proveUseAfterAck(h, seal(dom, h, [1, 2, 3]), opp(ops, pr, 0), E, cq + 1000))

    reg, dom, o, lk = fresh()
    renew(reg, dom, [lk], cq)
    acked(reg, dom, lk, cq, cq + 1000)
    ops = [att(dom, C.make_op(C.RELEASE, lk, E, cq + 1500, base=cq + 10, until=E, amount=1, total=1))]
    h, pr = ckpt(dom, H1, ops, locks(cq + 1500, lk, 1, 1))
    run("release_after_ack", reg, reg.functions.proveUseAfterAck(h, seal(dom, h, [1, 2, 3]), opp(ops, pr, 0), E, cq + 1000))

    reg, dom, o, lk = fresh()
    renew(reg, dom, [lk], cq)
    acked(reg, dom, lk, cq, cq + 1000)
    ops = [att(dom, C.make_op(C.RELEASE, lk, E + 1, 500, base=cq + 10, until=E, amount=1, total=1))]
    h, pr = ckpt(dom, H1, ops, locks(500, lk, 1, 1, E + 1))                        # released after a reboot
    run("release_after_ack_new_epoch", reg, reg.functions.proveUseAfterAck(h, seal(dom, h, [1, 2, 3]), opp(ops, pr, 0),
                                                                           E, cq + 1000))

    # ---- forks
    reg, dom, o, lk = fresh()
    h1, _ = ckpt(dom, H1, [C.make_op(C.LOG, keccak(text="a"))], empty(0))
    h2, _ = ckpt(dom, H1, [C.make_op(C.LOG, keccak(text="b"))], empty(0))
    run("fork", reg, reg.functions.proveFork(h1, seal(dom, h1, [0, 1, 2]), h2, seal(dom, h2, [1, 2, 3]), C.ZERO, []))

    reg, dom, o, lk = fresh()
    a1, _ = ckpt(dom, H1, [C.make_op(C.LOG, keccak(text="a"))], empty(0))
    b1, _ = ckpt(dom, H1, [C.make_op(C.LOG, keccak(text="b"))], empty(0))
    histb = [C.ZERO] * 500
    histb[1] = C.header_hash(b1)
    b500, _ = ckpt(dom, histb, [C.make_op(C.LOG, keccak(text="c"))], empty(0))
    run("fork_across_heights", reg, reg.functions.proveFork(a1, seal(dom, a1, [0, 1, 2]), b500,
                                                            seal(dom, b500, [1, 2, 3]), C.header_hash(b1),
                                                            C.hist_path(histb, 1)))

    # ---- rejected outright (no slashing needed)
    reg, dom, o, lk = fresh()
    c, _ = ckpt(dom, H1, [C.make_op(C.LOG, keccak(text="c"))], empty(0))
    cf = c[:9] + (c[9] + 10_000_000,) + c[10:]
    rejected("forged_close", reg.functions.anchor(cf, seal(dom, cf, byz), []))
    renew(reg, dom, [lk], cq)
    admin.send(reg.functions.stop(lk, s2.k))
    lock = lock_op(dom, lk, cq + 5, cq, 1, 1)
    acks = [C.sign(s1.vkeys[i], C.ack_digest(dom, s1.k, lk, E, cq + 5)) for i in (0, 1, 2)]
    rejected("grant_attestation_as_ack", reg.functions.reassignAcked(lk, E, cq + 5, 1, lock[9], acks))
    rejected("force_reassign_before_W", reg.functions.forceReassign(lk))

    # ---- retirement keeps old history judgeable (v6 replaces key rotation)
    reg, dom, o, lk = fresh()
    ops = [att(dom, C.make_op(C.CONSUME, parts, E, R(1), amount=30, total=30, version=1))]
    h, pr = ckpt(dom, H1, ops, st(R(1), 30, 1))
    admin.send(reg.functions.retireSite(s1.k))
    rejected("honest_op_after_retire_not_slashable", reg.functions.proveBadOp(h, seal(dom, h, byz), opp(ops, pr, 0)))
    sig = C.sign(s1.clock.key, C.clock_digest(dom, s1.k, E, cq, C.request_tag(C.objects_hash([o]))))
    rejected("renew_after_retire", reg.functions.renew(s1.k, [o], E, cq, sig))

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


def anchors_onchain(ctx):
    """Every Anchored event of the run's registry, to cross-check against the relayer's log."""
    reg = ctx["reg"]
    logs = reg.events.Anchored().get_logs(from_block=ctx["reg_block"])
    return [{"site": l["args"]["site"], "height": l["args"]["height"], "block": l["blockNumber"],
             "tx": l["transactionHash"].hex()} for l in logs]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cut", type=int, default=150)
    ap.add_argument("--tag", default="v6")
    ap.add_argument("--seed", type=int, default=7, help="seed of the flapping pattern")
    ap.add_argument("--flap", action="store_true", help="site 1's uplink flaps and is lossy instead of cut")
    args = ap.parse_args()
    nodes = json.loads((NET / "nodes.json").read_text())
    for k in (1, 2):
        uplink(k, True)
    t0 = time.time()
    ctx = {"t0": t0, "drift": {1: -RHO, 2: 0.05}, "gas": {}, "sites": {}, "acks": []}
    ctx["log"] = Log(t0)
    for k in (1, 2):
        ctx["sites"][k] = Site(k, nodes, ctx)
    setup(ctx, nodes)
    ctx["reg_at"] = lambda w3: w3.eth.contract(address=ctx["reg"].address, abi=ctx["reg"].abi)
    ctx["t0"] = ctx["log"].t0 = time.time()   # the scenario clock starts after setup
    stop = threading.Event()
    threads = []
    for s in ctx["sites"].values():
        for f in (relayer, checkpointer, operator, actuator):
            th = threading.Thread(target=f, args=(ctx, s, stop), daemon=True)
            th.start()
            threads.append(th)
    try:
        scenario(ctx, args.cut, args.flap, args.seed)
    finally:
        stop.set()
        for th in threads:
            th.join(timeout=120)
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
                         "drift": ctx["drift"], "flap": args.flap, "seed": args.seed, "g_timeout_s": G_TIMEOUT,
                         "tx_deadline_s": TX_DEADLINE, "confirm_site": CONFIRM, "confirm_g": CONFIRM_G},
              "gas": ctx["gas"], "events": ctx["log"].rows}
    result["anchors_onchain"] = anchors_onchain(ctx)
    result["attacks"] = attacks(ctx)
    out = ROOT / "experiments" / "results" / f"e2e_{args.tag}.json"
    out.write_text(json.dumps(result, indent=1, default=lambda x: x.hex() if isinstance(x, bytes) else str(x)))
    print("wrote", out)


if __name__ == "__main__":
    main()
