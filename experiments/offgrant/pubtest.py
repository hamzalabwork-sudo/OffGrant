"""RightsRegistry (contracts v5) on the public PureChain testnet: gas and confirmation latency of the global-ledger
side.

Funded testnet keys come from a git-ignored .env file (RPC, ADMIN_KEY deploys and administers, GATEWAY_KEY
relays), by default testbed/purechain/.env or the path in OFFGRANT_KEYS_ENV; they are read here and never
printed. Site validators, the site clocks and the checkpoints use local throwaway keys, as on a real site.
About 45 transactions in total.

Steps: deploy and register two sites; 24 clock-attested batch renewals, with an anchor of the newest checkpoint
after every 8 (G renews only sites whose anchored coverage is recent); no-framing checks (eth_call) of every
applicable proof against the honest anchored operations and checkpoint pairs; a fast-path reassignment; and two
fraud proofs by faulty quorums.

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
SEL = {name: keccak(text=name + "()")[:4].hex() for name in ("NotAViolation", "BadProof", "BadClockSig", "NoQuorum")}


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


def revert_reason(e):
    s = str(e) + " " + str(getattr(e, "data", ""))
    for name, sel in SEL.items():
        if sel in s:
            return name
    return "other:" + s[:60]


def main(tag="v5"):
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
    dom = bytes(reg.functions.dom().call())
    assert dom == C.domain(reg.address, out["chain_id"])
    parts, obj = keccak(text="spare-parts"), keccak(text="loto:pump-7")
    E = clock.epoch
    setup = [
        ("setCap", reg.functions.setCap(parts, 100)),
        ("registerSite", reg.functions.registerSite(1, 1, Account.from_key(clock.key).address,
                                                    [Account.from_key(k).address for k in vkeys], E, clock.read())),
        ("registerSite2", reg.functions.registerSite(2, 1, Account.from_key(clock2.key).address,
                                                     [Account.from_key(k).address for k in vkeys2], clock2.epoch,
                                                     clock2.read())),
        ("setShare", reg.functions.setShare(parts, 1, 40)),
        ("createLease", reg.functions.createLease(obj, True, False, A_MS)),
        ("permit", reg.functions.permit(obj, 1)),
    ]
    for name, fn in setup:
        r, dt = timed(admin, fn)
        assert r.status == 1, name
        out["gas"][name] = r.gasUsed
        out["latency_s"][name] = round(dt, 2)

    # Site 1's ledger, kept locally: consumptions within the share, records, and grants under the latest renewal.
    state = C.SiteState()
    hist = [C.ZERO]
    sealed = []        # dict(h, seals, ops, state, height) of every anchored checkpoint
    pending_ops, renewals, anchors = [], [], []
    total = 0

    def seal(h, keys, who):
        return [C.sign(keys[i], C.checkpoint_digest(dom, C.header_hash(h))) for i in who]

    def site_ops(cq):
        nonlocal total
        total += 1   # 24 in all, within the share of 40
        ops = [C.attest_op(clock, dom, 1, C.make_op(C.CONSUME, parts, E, clock.read(), amount=1, total=total, version=1)),
               C.make_op(C.LOG, keccak(text=f"record-{total}"))]
        b = clock.read()
        ops.append(C.attest_op(clock, dom, 1, C.make_op(C.USE, obj, E, b, base=cq, until=b + 1000)))
        return ops

    def anchor_newest():
        nonlocal pending_ops
        for op in pending_ops:
            state.apply(op)
        s_t = state.tuple()
        h, _ = C.make_header(clock, dom, 1, hist, pending_ops, s_t, C.ZERO)
        seals = seal(h, vkeys, (0, 1, 2))
        ah = sealed[-1]["height"] if sealed else 0
        path = C.hist_path(hist, ah) if ah else []
        r, dt = timed(relayer, reg.functions.anchor(h, seals, path))
        assert r.status == 1, "anchor"
        anchors.append({"ops": len(pending_ops), "gas": r.gasUsed, "latency_s": round(dt, 2)})
        sealed.append({"h": h, "seals": seals, "ops": pending_ops, "state": s_t, "height": len(hist)})
        hist.append(C.header_hash(h))
        pending_ops = []

    # Batch renewals: the relayer submits clock-attested requests; latency = submission to receipt.
    ren_lat, ren_gas = [], []
    objs = [obj]
    for i in range(24):
        cq = clock.read()
        sig = C.sign(clock.key, C.clock_digest(dom, 1, E, cq, C.request_tag(C.objects_hash(objs))))
        r, dt = timed(relayer, reg.functions.renew(1, objs, E, cq, sig))
        assert r.status == 1, "renew"
        ren_lat.append(dt)
        ren_gas.append(r.gasUsed)
        renewals.append(cq)
        pending_ops += site_ops(cq)
        if (i + 1) % 8 == 0:
            anchor_newest()
    out["renew"] = {"n": len(ren_lat), "gas": int(st.median(ren_gas)), "latency_median_s": round(st.median(ren_lat), 2),
                    "latency_max_s": round(max(ren_lat), 2)}
    out["anchor"] = {"n": len(anchors), "ops_each": anchors[0]["ops"], "gas_median": int(st.median(a["gas"] for a in anchors)),
                     "latency_median_s": round(st.median(a["latency_s"] for a in anchors), 2)}

    # No framing on the public chain: every applicable proof against every honest anchored operation and
    # checkpoint pair reverts (eth_call; the contract's verdict is recorded).
    verdicts, tried = {}, 0

    def attempt(fn):
        nonlocal tried
        tried += 1
        try:
            fn.call({"from": relayer.acct.address})
            verdicts["accepted"] = verdicts.get("accepted", 0) + 1
        except Exception as ex:  # noqa: BLE001
            k = revert_reason(ex)
            verdicts[k] = verdicts.get(k, 0) + 1

    for j, c in enumerate(sealed):
        h, seals, ops, s_t = c["h"], c["seals"], c["ops"], c["state"]
        _, proofs = C.merkle([C.op_leaf(op) for op in ops])
        anc = sealed[j - 1] if j else None
        path = C.hist_path(hist[:c["height"]], anc["height"]) if anc else None
        for i, op in enumerate(ops):
            p = (op, i, proofs[i])
            attempt(reg.functions.proveBadOp(h, seals, p))
            attempt(reg.functions.proveStateMismatch(h, seals, p, s_t))
            if op[0] == C.CONSUME:
                attempt(reg.functions.proveOverspend(h, seals, p))
            if op[0] == C.USE:
                attempt(reg.functions.proveOveruse(h, seals, p))
            if anc:
                attempt(reg.functions.proveOpRegress(h, seals, p, (anc["h"], anc["state"], path)))
            if i + 1 < len(ops):
                attempt(reg.functions.proveInconsistent(h, seals, p, (ops[i + 1], i + 1, proofs[i + 1])))
        if anc:
            attempt(reg.functions.proveRegress(h, seals, s_t, (anc["h"], anc["state"], path)))
            attempt(reg.functions.proveFork(anc["h"], anc["seals"], h, seals, C.header_hash(anc["h"]), path))
    out["no_framing"] = {"attempts": tried, "verdicts": verdicts}

    # Fast path: stop, then the ACK operation (attested by the clock) acknowledged by three site validators.
    r, dt = timed(admin, reg.functions.stop(obj, 2))
    out["gas"]["stop"], out["latency_s"]["stop"] = r.gasUsed, round(dt, 2)
    ra = clock.read()
    ack = C.attest_op(clock, dom, 1, C.make_op(C.ACK, obj, E, ra, base=renewals[-1]))
    acks = [C.sign(k, C.ack_digest(dom, 1, obj, E, ra)) for k in vkeys[:3]]
    r, dt = timed(relayer, reg.functions.reassignAcked(obj, E, ra, ack[9], acks))
    assert r.status == 1, "reassignAcked"
    out["gas"]["reassignAcked"], out["latency_s"]["reassignAcked"] = r.gasUsed, round(dt, 2)

    # Fraud proofs by faulty quorums.
    proofs_out = {}
    # Overspend at site 2, which holds no share: any sealed consumption exceeds it (validators 0-2).
    bad = [C.attest_op(clock2, dom, 2, C.make_op(C.CONSUME, parts, clock2.epoch, clock2.read(), amount=45, total=45, version=1))]
    hb, pr = C.make_header(clock2, dom, 2, [C.ZERO], bad, (clock2.epoch, bad[0][3], [parts], [45], [1]), C.ZERO)
    r, dt = timed(relayer, reg.functions.proveOverspend(hb, seal(hb, vkeys2, (0, 1, 2)), (bad[0], 0, pr[0])), 6_000_000)
    proofs_out["overspend"] = {"status": r.status, "gas": r.gasUsed, "latency_s": round(dt, 2),
                               "slashed": len(reg.events.Slashed().process_receipt(r))}
    # A grant past the acknowledged reading under the old renewal, sealed by validators 1-3: the two that also
    # acknowledged are slashed.
    rd = clock.read()
    late = [C.attest_op(clock, dom, 1, C.make_op(C.USE, obj, E, rd, base=renewals[-1], until=rd + 10))]
    hl, pr = C.make_header(clock, dom, 1, hist, late, (E, rd, [parts], [total], [1]), C.ZERO)
    r, dt = timed(relayer, reg.functions.proveUseAfterAck(hl, seal(hl, vkeys, (1, 2, 3)), (late[0], 0, pr[0]), E, ra),
                  6_000_000)
    proofs_out["use_after_ack"] = {"status": r.status, "gas": r.gasUsed, "latency_s": round(dt, 2),
                                   "slashed": len(reg.events.Slashed().process_receipt(r))}
    out["proofs"] = proofs_out
    out["end_block"] = w3.eth.block_number
    path = C.ROOT / "experiments" / "results" / f"pubtest_{tag}.json"
    path.write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main(*sys.argv[1:])
