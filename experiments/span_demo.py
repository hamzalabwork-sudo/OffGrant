"""Problem demonstration on a real client: one PureChain (Clique, 12 signers) stretched over three sites.

Site C (4 signers) loses its links to sites A and B for CUT seconds (netem drops all packets to the other sites'
addresses; traffic inside each site is untouched). Site C keeps submitting operations (zero-gas transactions)
during the cut. We record, once per second, the head (number, hash) seen at one node of each site; at the end we
check which of C's operations ended up in the canonical chain, and when.

Usage: python span_demo.py [--cut 120] [--after 60] [--out experiments/results/span_demo.json]
"""
import argparse
import json
import subprocess
import time
from pathlib import Path

from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

ROOT = Path(__file__).resolve().parents[1]
NET = ROOT / "testbed" / "purechain" / "net_span"


def sh(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def cut(nodes, site, on):
    """Drop (on=True) or restore traffic between `site` and every other site, in both directions."""
    for n in nodes:
        others = [m["ip"] for m in nodes if (m["site"] == site) != (n["site"] == site)]
        if not others:
            continue
        name = n["name"]
        subprocess.run(["docker", "exec", name, "tc", "qdisc", "del", "dev", "eth0", "root"],
                       capture_output=True)
        if on:
            sh("docker", "exec", name, "tc", "qdisc", "add", "dev", "eth0", "root", "handle", "1:", "prio")
            sh("docker", "exec", name, "tc", "qdisc", "add", "dev", "eth0", "parent", "1:3", "handle", "30:",
               "netem", "loss", "100%")
            for ip in others:
                sh("docker", "exec", name, "tc", "filter", "add", "dev", "eth0", "protocol", "ip", "parent", "1:0",
                   "prio", "3", "u32", "match", "ip", "dst", f"{ip}/32", "flowid", "1:3")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cut", type=int, default=120)
    ap.add_argument("--before", type=int, default=20)
    ap.add_argument("--after", type=int, default=60)
    ap.add_argument("--rate", type=float, default=1.0, help="site C operations per second")
    ap.add_argument("--out", default=str(ROOT / "experiments" / "results" / "span_demo.json"))
    args = ap.parse_args()

    nodes = json.loads((NET / "nodes.json").read_text())["span"]
    probe = {s: next(n for n in nodes if n["site"] == s) for s in "abc"}
    w3 = {s: Web3(Web3.HTTPProvider(f"http://127.0.0.1:{probe[s]['rpc']}", request_kwargs={"timeout": 5}))
          for s in "abc"}
    for x in w3.values():
        x.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)  # Clique extraData > 32 bytes
    # Site C's operator account: a site C signer (zero gas; value-less self-transfers carrying an op id).
    opk = probe["c"]["key"]
    op_addr = probe["c"]["address"]
    acct = w3["c"].eth.account.from_key(opk)
    nonce = w3["c"].eth.get_transaction_count(op_addr, "pending")
    chain_id = w3["c"].eth.chain_id

    trace, ops = [], []
    t0 = time.time()
    phase_end = {"before": args.before, "cut": args.before + args.cut, "after": args.before + args.cut + args.after}
    cut_on = False
    next_op = t0
    while True:
        t = time.time() - t0
        if t >= phase_end["after"]:
            break
        if not cut_on and phase_end["before"] <= t < phase_end["cut"]:
            cut(nodes, "c", True)
            cut_on = True
            trace.append({"t": t, "event": "cut"})
        if cut_on and t >= phase_end["cut"]:
            cut(nodes, "c", False)
            cut_on = False
            trace.append({"t": t, "event": "heal"})
        row = {"t": round(t, 2)}
        for s in "abc":
            try:
                b = w3[s].eth.get_block("latest")
                row[s] = [b.number, b.hash.hex()[:10]]
            except Exception as e:  # noqa: BLE001
                row[s] = None
                row[s + "_err"] = str(e)[:80]
        trace.append(row)
        if time.time() >= next_op:
            tx = {"to": op_addr, "value": 0, "gas": 30000, "gasPrice": 0, "nonce": nonce, "chainId": chain_id,
                  "data": Web3.to_bytes(text=f"op{len(ops)}")}
            raw = acct.sign_transaction(tx).raw_transaction
            try:
                h = w3["c"].eth.send_raw_transaction(raw)
                ops.append({"i": len(ops), "t_submit": round(t, 2), "hash": h.hex(), "nonce": nonce,
                            "phase": "cut" if cut_on else ("before" if t < phase_end["before"] else "after")})
                nonce += 1
            except Exception as e:  # noqa: BLE001
                ops.append({"i": len(ops), "t_submit": round(t, 2), "error": str(e)[:80]})
            next_op += 1.0 / args.rate
        time.sleep(max(0.0, 1.0 - (time.time() - t0 - t)))

    if cut_on:
        cut(nodes, "c", False)
    time.sleep(10)
    # Final canonical inclusion (as seen by site A after healing) and when each op's block was sealed.
    for op in ops:
        if "hash" not in op:
            continue
        try:
            r = w3["a"].eth.get_transaction_receipt(op["hash"])
            blk = w3["a"].eth.get_block(r.blockNumber)
            op["block"] = r.blockNumber
            op["t_final_block"] = blk.timestamp - t0
        except Exception:  # noqa: BLE001
            op["block"] = None
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    meta = {k: v for k, v in vars(args).items() if k != "out"}
    Path(args.out).write_text(json.dumps({"args": meta, "t0": t0, "trace": trace, "ops": ops}, indent=1))
    print("wrote", args.out)


if __name__ == "__main__":
    main()
