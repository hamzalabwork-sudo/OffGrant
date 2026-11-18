"""Reconnection storm on the global ledger (contracts v6): N sites come back at the same instant after an outage.

Each site was registered, anchored one checkpoint, then sealed OUT checkpoints while cut off (its trusted clock
advanced by OUTAGE_S). At t = 0 every site's relayer, from its own key, anchors its newest checkpoint (one
transaction covering the whole outage, with a history path to its last anchored checkpoint) and then renews a
batch of its objects. Measures, for N in --sites: time from the storm's start until each site holds a renewal again,
the G blocks the storm spans, gas and transactions per block, and the block gas limit.

Uses the local PureChain G of testbed/purechain/net_offgrant (zero gas price); site validators, clocks and relayers
use throwaway keys. Writes experiments/results/storm_<tag>.json.
"""
import argparse
import json
import secrets
import statistics as st
import threading
import time

from eth_account import Account
from eth_utils import keccak

import chain as C

NET = C.ROOT / "testbed" / "purechain" / "net_offgrant"
RHO_PPM, G_SLACK, LAG_MS = 150_000, 2, 60_000
A_MS = 69_000
OUTAGE_S = 3600          # simulated outage (site clock advances by this much)
OUT = 600                # checkpoints sealed while cut off (one every 6 s)
OBJS_PER_SITE = 3


class StormSite:
    def __init__(self, k):
        self.k = k
        self.vkeys = ["0x" + secrets.token_hex(32) for _ in range(4)]
        self.clock = C.Clock("0x" + secrets.token_hex(32), k, 0.0, time.time())
        self.rel_key = "0x" + secrets.token_hex(32)
        self.objs = [keccak(text=f"storm-{k}-{i}") for i in range(OBJS_PER_SITE)]
        self.hist = [C.ZERO]


def seal(dom, h, keys):
    return [C.sign(k, C.checkpoint_digest(dom, C.header_hash(h))) for k in keys[:3]]


def empty(clock):
    return (clock.epoch, 0, [], [], [], [], [], [])


def run(n, w3, admin, nodes_g):
    reg, _ = admin.deploy("RightsRegistry", RHO_PPM, G_SLACK, LAG_MS)
    dom = bytes(reg.functions.dom().call())
    sites = [StormSite(100 + i) for i in range(n)]
    last = None
    for s in sites:   # setup, pipelined (wait only for the last transaction)
        last = admin.send(reg.functions.registerSite(s.k, 1, Account.from_key(s.clock.key).address,
                                                     [Account.from_key(v).address for v in s.vkeys],
                                                     s.clock.epoch, s.clock.read()), wait=False)
        for o in s.objs:
            admin.send(reg.functions.createLease(o, True, False, A_MS), wait=False)
            last = admin.send(reg.functions.permit(o, s.k), wait=False)
    w3.eth.wait_for_transaction_receipt(last, timeout=300)
    # Before the outage: each site anchors height 1 (relayers send in parallel from their own keys).
    pre = []
    for s in sites:
        h, _ = C.make_header(s.clock, dom, s.k, s.hist, [C.make_op(C.LOG, keccak(text="pre"))], empty(s.clock), C.ZERO)
        s.rel = C.Sender(w3, s.rel_key)
        pre.append(s.rel.send(reg.functions.anchor(h, seal(dom, h, s.vkeys), []), wait=False))
        s.hist.append(C.header_hash(h))
    for tx in pre:
        assert w3.eth.wait_for_transaction_receipt(tx, timeout=300).status == 1
    # The outage: the clocks advance and every site seals OUT checkpoints offline.
    for s in sites:
        s.clock.offset += OUTAGE_S * 1000
        s.hist += [keccak(text=f"offline-{s.k}-{i}") for i in range(OUT - 1)]
        h, _ = C.make_header(s.clock, dom, s.k, s.hist, [C.make_op(C.LOG, keccak(text="newest"))], empty(s.clock),
                             C.ZERO)
        s.newest = (h, seal(dom, h, s.vkeys), C.hist_path(s.hist, 1))
    res = {}
    start_block = w3.eth.block_number
    barrier = threading.Barrier(n + 1)

    def relayer(s):
        barrier.wait()
        t0 = time.time()
        try:
            h, sg, path = s.newest
            ra = s.rel.send_robust(reg.functions.anchor(h, sg, path), deadline=300)
            t_a = time.time() - t0
            cq = s.clock.read()
            sig = C.sign(s.clock.key, C.clock_digest(dom, s.k, s.clock.epoch, cq, C.request_tag(C.objects_hash(s.objs))))
            rr = s.rel.send_robust(reg.functions.renew(s.k, s.objs, s.clock.epoch, cq, sig), deadline=300)
            res[s.k] = {"anchor_s": round(t_a, 3), "renewed_s": round(time.time() - t0, 3),
                        "ok": ra.status == 1 and rr.status == 1, "anchor_gas": ra.gasUsed, "renew_gas": rr.gasUsed,
                        "blocks": [ra.blockNumber, rr.blockNumber]}
        except Exception as e:  # noqa: BLE001
            res[s.k] = {"ok": False, "err": str(e)[:100]}

    for s in sites:   # sync nonces before the storm, so the storm itself sends only the two transactions
        s.rel._sync()
    ths = [threading.Thread(target=relayer, args=(s,)) for s in sites]
    for t in ths:
        t.start()
    barrier.wait()
    t_start = time.time()
    for t in ths:
        t.join()
    wall = time.time() - t_start
    ok = [r for r in res.values() if r.get("ok")]
    blocks = sorted({b for r in ok for b in r["blocks"]})
    per_block = []
    for b in range(blocks[0], blocks[-1] + 1) if blocks else []:
        blk = w3.eth.get_block(b)
        per_block.append({"block": b, "txs": len(blk["transactions"]), "gas": blk["gasUsed"]})
    ren = [r["renewed_s"] for r in ok]
    return {
        "sites": n, "ok": len(ok), "wall_s": round(wall, 2),
        "renewed_s": {"median": round(st.median(ren), 2), "p90": round(sorted(ren)[int(0.9 * (len(ren) - 1))], 2),
                      "max": round(max(ren), 2)} if ren else None,
        "anchor_gas_median": int(st.median(r["anchor_gas"] for r in ok)) if ok else None,
        "renew_gas_median": int(st.median(r["renew_gas"] for r in ok)) if ok else None,
        "blocks_spanned": len(per_block), "start_block": start_block,
        "max_gas_per_block": max((b["gas"] for b in per_block), default=0),
        "max_txs_per_block": max((b["txs"] for b in per_block), default=0),
        "block_gas_limit": w3.eth.get_block("latest")["gasLimit"],
        "failures": [r for r in res.values() if not r.get("ok")][:5],
        "per_block": per_block,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sites", default="10,25,50,100")
    ap.add_argument("--tag", default="v6")
    args = ap.parse_args()
    nodes = json.loads((NET / "nodes.json").read_text())
    w3 = C.connect(8700, timeout=30)
    admin = C.Sender(w3, nodes["g"][0]["key"])
    out = {"params": {"outage_s": OUTAGE_S, "offline_checkpoints": OUT, "objects_per_site": OBJS_PER_SITE,
                      "hist_depth": C.HIST_DEPTH}, "runs": []}
    for n in [int(x) for x in args.sites.split(",")]:
        r = run(n, w3, admin, nodes["g"])
        out["runs"].append(r)
        print(json.dumps({k: v for k, v in r.items() if k != "per_block"}))
    path = C.ROOT / "experiments" / "results" / f"storm_{args.tag}.json"
    path.write_text(json.dumps(out, indent=1))
    print("wrote", path)


if __name__ == "__main__":
    main()
