"""RightsRegistry on the public PureChain testnet: gas and confirmation latency of the global-ledger side.

Funded testnet keys come from a git-ignored .env file (ADMIN_KEY deploys and administers, GATEWAY_KEY relays), by
default testbed/purechain/.env or the path in OFFGRANT_KEYS_ENV; they are read here and never printed. Site
validators, the site clocks and the checkpoints use local throwaway keys, as on a real site. About 45
transactions in total.

Steps: deploy and register two sites; 24 clock-attested renewals, with an anchor of the newest checkpoint after
every 8 (G renews only sites whose anchored coverage is recent); no-framing checks (eth_call) of every applicable
proof against the honest anchored operations; a fast-path reassignment; and two fraud proofs by faulty quorums.

Writes experiments/results/pubtest_<tag>.json (addresses, gas, latencies; no keys).
"""
import json
import os
import secrets
import statistics as st
import sys
import time
from pathlib import Path

from eth_account import Account
from eth_utils import keccak
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

import chain as C

try:  # use the OS certificate store (some networks intercept TLS with a local CA)
    import truststore

    truststore.inject_into_ssl()
except ImportError:
    pass

ENV = Path(os.environ.get("OFFGRANT_KEYS_ENV", Path(__file__).resolve().parents[2] / "testbed" / "purechain" / ".env"))
RHO_PPM, A_MS, G_SLACK, LAG_MS = 150_000, 69_000, 2, 60_000
ZERO = b"\x00" * 32


def env():
    vals = {}
    for line in ENV.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            vals[k.strip()] = v.strip()
    return vals


def timed(sender, fn, gas=3_000_000):
    t = time.time()
    r = sender.send(fn, gas=gas, timeout=120)
    return r, time.time() - t


SEL = {name: keccak(text=name + "()")[:4].hex() for name in ("NotAViolation", "BadProof", "BadClockSig", "NoQuorum")}


def revert_reason(e):
    s = str(e) + " " + str(getattr(e, "data", ""))
    for name, sel in SEL.items():
        if sel in s:
            return name
    return "other:" + s[:60]


def main(tag="v4"):
    e = env()
    w3 = Web3(Web3.HTTPProvider(e["RPC"], request_kwargs={"timeout": 30}))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    out = {"chain_id": w3.eth.chain_id, "start_block": w3.eth.block_number, "gas": {}, "latency_s": {}}
    admin = C.Sender(w3, e["ADMIN_KEY"])
    relayer = C.Sender(w3, e["GATEWAY_KEY"])

    vkeys = ["0x" + secrets.token_hex(32) for _ in range(4)]
    vkeys2 = ["0x" + secrets.token_hex(32) for _ in range(4)]
    clock = C.Clock("0x" + secrets.token_hex(32), 1, 0.0, time.time())
    clock2 = C.Clock("0x" + secrets.token_hex(32), 2, 0.0, time.time())
    t = time.time()
    reg, r = admin.deploy("RightsRegistry", RHO_PPM, G_SLACK, LAG_MS)
    out["registry"] = reg.address
    out["gas"]["deploy"] = r.gasUsed
    out["latency_s"]["deploy"] = round(time.time() - t, 2)
    parts, obj = keccak(text="spare-parts"), keccak(text="loto:pump-7")
    setup = [
        ("setCap", reg.functions.setCap(parts, 100)),
        ("registerSite", reg.functions.registerSite(1, 1, Account.from_key(clock.key).address,
                                                    [Account.from_key(k).address for k in vkeys], clock.epoch,
                                                    clock.read())),
        ("registerSite2", reg.functions.registerSite(2, 1, Account.from_key(clock2.key).address,
                                                     [Account.from_key(k).address for k in vkeys2], clock2.epoch,
                                                     clock2.read())),
        ("setShare", reg.functions.setShare(parts, 1, 40)),
        ("createLease", reg.functions.createLease(obj, True, A_MS)),
        ("permit", reg.functions.permit(obj, 1)),
    ]
    for name, fn in setup:
        r, dt = timed(admin, fn)
        assert r.status == 1, name
        out["gas"][name] = r.gasUsed
        out["latency_s"][name] = round(dt, 2)

    # Site 1's ledger, kept locally: consumptions within the share and grants under the latest renewal.
    total, renewals, anchors = 0, [], []
    pending = []
    sealed = []   # (header, seals, ops) of every anchored checkpoint
    base = (0, ZERO)
    prev = ZERO

    def site_ops(cq):
        nonlocal total
        total += 1   # 24 in all, within the share of 40
        ops = [(C.CONSUME, parts, 1, total, 1, 0, b""), (C.LOG, keccak(text=f"record-{total}"), 0, 0, 0, 0, b"")]
        b = clock.read()
        ops.append((C.USE, obj, cq, b, b + 1000, clock.epoch, clock.attest(C.clock_digest, 1, clock.epoch, b, obj)))
        return ops

    def anchor_newest():
        nonlocal base, prev, pending
        h, _ = C.make_header(clock, 1, base[0] + 1, prev, pending, C.state_leaf(parts, total), base[0], base[1])
        seals = [C.sign(k, C.checkpoint_digest(reg.address, C.header_hash(h))) for k in vkeys[:3]]
        r, dt = timed(relayer, reg.functions.anchor(h, seals))
        assert r.status == 1, "anchor"
        anchors.append({"ops": len(pending), "gas": r.gasUsed, "latency_s": round(dt, 2)})
        sealed.append((h, seals, pending))
        base = (h[1], C.header_hash(h))
        prev = base[1]
        pending = []

    # Renewals: the relayer submits clock-attested requests; latency = submission to receipt.
    ren_lat, ren_gas = [], []
    for i in range(24):
        cq = clock.read()
        r, dt = timed(relayer, reg.functions.renew(1, obj, clock.epoch, cq,
                                                   clock.attest(C.request_digest, 1, obj, clock.epoch, cq)))
        assert r.status == 1, "renew"
        ren_lat.append(dt)
        ren_gas.append(r.gasUsed)
        renewals.append(cq)
        pending += site_ops(cq)
        if (i + 1) % 8 == 0:
            anchor_newest()
    out["renew"] = {"n": len(ren_lat), "gas": int(st.median(ren_gas)), "latency_median_s": round(st.median(ren_lat), 2),
                    "latency_max_s": round(max(ren_lat), 2)}
    out["anchor"] = {"n": len(anchors), "ops_each": anchors[0]["ops"], "gas_median": int(st.median(a["gas"] for a in anchors)),
                     "latency_median_s": round(st.median(a["latency_s"] for a in anchors), 2)}

    # No framing on the public chain: every applicable proof against every honest anchored operation reverts
    # (eth_call; the contract's verdict is recorded).
    verdicts, tried = {}, 0
    for h, seals, ops in sealed:
        _, proofs = C.merkle([C.op_leaf(op) for op in ops])
        committed = [op[3] for op in ops if op[0] == C.CONSUME][-1]
        for i, op in enumerate(ops):
            fns = []
            if op[0] == C.CONSUME:
                fns = [reg.functions.proveOverspend(h, seals, op, i, proofs[i]),
                       reg.functions.proveStateMismatch(h, seals, op, i, proofs[i], committed, 0, [])]
            elif op[0] == C.USE:
                fns = [reg.functions.proveOveruse(h, seals, op, i, proofs[i]),
                       reg.functions.proveUseAfterAck(h, seals, op, i, proofs[i])]
            for fn in fns:
                tried += 1
                try:
                    fn.call({"from": relayer.acct.address})
                    verdicts["accepted"] = verdicts.get("accepted", 0) + 1
                except Exception as ex:  # noqa: BLE001
                    k = revert_reason(ex)
                    verdicts[k] = verdicts.get(k, 0) + 1
    out["no_framing"] = {"attempts": tried, "verdicts": verdicts}

    # Fast path: stop, then reassignment acknowledged by three site validators with a fresh clock reading.
    r, dt = timed(admin, reg.functions.stop(obj, 2))
    out["gas"]["stop"], out["latency_s"]["stop"] = r.gasUsed, round(dt, 2)
    ra = clock.read()
    acks = [C.sign(k, C.ack_digest(reg.address, 1, obj, clock.epoch, ra)) for k in vkeys[:3]]
    r, dt = timed(relayer, reg.functions.reassignAcked(obj, clock.epoch, ra,
                                                     clock.attest(C.clock_digest, 1, clock.epoch, ra, obj), acks))
    assert r.status == 1, "reassignAcked"
    out["gas"]["reassignAcked"], out["latency_s"]["reassignAcked"] = r.gasUsed, round(dt, 2)

    # Fraud proofs by faulty quorums.
    proofs_out = {}
    # Overspend at site 2, which holds no share: any sealed consumption exceeds it (validators 0-2).
    bad = [(C.CONSUME, parts, 45, 45, 1, 0, b"")]
    hb, pr = C.make_header(clock2, 2, 1, ZERO, bad, C.state_leaf(parts, 45), 0, ZERO)
    seals2 = [C.sign(vkeys2[i], C.checkpoint_digest(reg.address, C.header_hash(hb))) for i in (0, 1, 2)]
    r, dt = timed(relayer, reg.functions.proveOverspend(hb, seals2, bad[0], 0, pr[0]), 6_000_000)
    proofs_out["overspend"] = {"status": r.status, "gas": r.gasUsed, "latency_s": round(dt, 2),
                               "slashed": len(reg.events.Slashed().process_receipt(r))}
    # A grant past the acknowledged reading, sealed by validators 1-3: the two that also acknowledged are slashed.
    rd = ra + 5
    late = [(C.USE, obj, renewals[-1], rd, rd, clock.epoch, clock.attest(C.clock_digest, 1, clock.epoch, rd, obj))]
    hl, pr = C.make_header(clock, 1, base[0] + 1, prev, late, C.state_leaf(parts, total), base[0], base[1])
    seals_l = [C.sign(vkeys[i], C.checkpoint_digest(reg.address, C.header_hash(hl))) for i in (1, 2, 3)]
    r, dt = timed(relayer, reg.functions.proveUseAfterAck(hl, seals_l, late[0], 0, pr[0]), 6_000_000)
    proofs_out["use_after_ack"] = {"status": r.status, "gas": r.gasUsed, "latency_s": round(dt, 2),
                                   "slashed": len(reg.events.Slashed().process_receipt(r))}
    out["proofs"] = proofs_out
    out["end_block"] = w3.eth.block_number
    path = C.ROOT / "experiments" / "results" / f"pubtest_{tag}.json"
    path.write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main(*sys.argv[1:])
