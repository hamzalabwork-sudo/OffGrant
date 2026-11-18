"""RightsRegistry on the public PureChain testnet: gas and confirmation latency of the global-ledger side.

Funded testnet keys come from a git-ignored .env file (ADMIN_KEY deploys and administers, GATEWAY_KEY relays), by
default testbed/purechain/.env or the path in OFFGRANT_KEYS_ENV; they are read here and never printed. Site validators, the site clock and the checkpoints are local
throwaway keys, as on a real site. About 60 transactions in total.

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

try:  # use the Windows certificate store (TLS on this network is intercepted by a local CA)
    import truststore

    truststore.inject_into_ssl()
except ImportError:
    pass

ENV = Path(os.environ.get("OFFGRANT_KEYS_ENV", Path(__file__).resolve().parents[2] / "testbed" / "purechain" / ".env"))
RHO_PPM, A_MS = 150_000, 69_000


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


def main(tag="v1"):
    e = env()
    w3 = Web3(Web3.HTTPProvider(e["RPC"], request_kwargs={"timeout": 30}))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    out = {"chain_id": w3.eth.chain_id, "start_block": w3.eth.block_number, "gas": {}, "latency_s": {}}
    admin = C.Sender(w3, e["ADMIN_KEY"])
    relayer = C.Sender(w3, e["GATEWAY_KEY"])

    vkeys = ["0x" + secrets.token_hex(32) for _ in range(4)]
    vkeys2 = ["0x" + secrets.token_hex(32) for _ in range(4)]
    clock = C.Clock("0x" + secrets.token_hex(32), 1, 0.0, time.time())
    t = time.time()
    reg, r = admin.deploy("RightsRegistry", RHO_PPM, 2, 60_000)
    out["registry"] = reg.address
    out["gas"]["deploy"] = r.gasUsed
    out["latency_s"]["deploy"] = round(time.time() - t, 2)
    parts, obj = keccak(text="spare-parts"), keccak(text="loto:pump-7")
    start = clock.read()
    for name, fn in [("registerSite", reg.functions.registerSite(1, 1, Account.from_key(clock.key).address,
                                                                 [Account.from_key(k).address for k in vkeys], start)),
                     ("registerSite2", reg.functions.registerSite(2, 1, Account.from_key(vkeys[0]).address,
                                                                  [Account.from_key(k).address for k in vkeys2], start)),
                     ("setCap", reg.functions.setCap(parts, 100)),
                     ("setShare", reg.functions.setShare(parts, 1, 40)),
                     ("createLease", reg.functions.createLease(obj, True, A_MS)),
                     ("permit", reg.functions.permit(obj, 1))]:
        r, dt = timed(admin, fn)
        assert r.status == 1, name
        out["gas"][name] = r.gasUsed
        out["latency_s"][name] = round(dt, 2)

    # Renewals: the relayer submits clock-attested requests; latency = submission to receipt.
    ren_lat, ren_gas = [], []
    for _ in range(20):
        cq = clock.read()
        r, dt = timed(relayer, reg.functions.renew(1, obj, clock.epoch, cq,
                                                   clock.attest(C.request_digest, 1, obj, clock.epoch, cq)))
        assert r.status == 1
        ren_lat.append(dt)
        ren_gas.append(r.gasUsed)
    out["renew"] = {"n": 20, "gas": int(st.median(ren_gas)), "latency_median_s": round(st.median(ren_lat), 2),
                    "latency_max_s": round(max(ren_lat), 2)}

    # Checkpoint anchoring with real site-validator seals (16 operations).
    ops = [(C.CONSUME, parts, 1, i + 1, 0, b"") for i in range(8)]
    for i in range(8):
        rd = clock.read()
        ops.append((C.USE, obj, cq, rd, clock.epoch, clock.attest(C.clock_digest, 1, clock.epoch, rd, obj)))
    root, proofs = C.merkle([C.op_leaf(op) for op in ops])
    h = (1, 1, b"\x00" * 32, root, len(ops), clock.read())
    seals = [C.sign(k, C.checkpoint_digest(reg.address, C.header_hash(h))) for k in vkeys[:3]]
    r, dt = timed(relayer, reg.functions.anchor(h, seals))
    out["gas"]["anchor_16ops"] = r.gasUsed
    out["latency_s"]["anchor"] = round(dt, 2)
    # No framing on the public chain: proofs against honest operations revert (eth_call).
    reverted = 0
    for i, op in enumerate(ops):
        fn = reg.functions.proveOverspend if op[0] == C.CONSUME else reg.functions.proveOveruse
        try:
            fn(h, seals, op, i, proofs[i]).call({"from": relayer.acct.address})
        except Exception:  # noqa: BLE001
            reverted += 1
    out["no_framing"] = {"attempts": len(ops), "reverted": reverted}

    # Fast path: stop, then reassignment acknowledged by three site validators.
    r, dt = timed(admin, reg.functions.stop(obj, 2))
    out["gas"]["stop"], out["latency_s"]["stop"] = r.gasUsed, round(dt, 2)
    ra = clock.read()
    acks = [C.sign(k, C.ack_digest(reg.address, 1, obj, clock.epoch, ra)) for k in vkeys[:3]]
    r, dt = timed(relayer, reg.functions.reassignAcked(obj, clock.epoch, ra,
                                                     clock.attest(C.clock_digest, 1, clock.epoch, ra, obj), acks))
    assert r.status == 1
    out["gas"]["reassignAcked"], out["latency_s"]["reassignAcked"] = r.gasUsed, round(dt, 2)

    # Fraud proofs by a Byzantine quorum (validators 0-2; 1-3 for the second checkpoint of the fork).
    def seal(hh, who):
        return [C.sign(vkeys[i], C.checkpoint_digest(reg.address, C.header_hash(hh))) for i in who]

    proofs_out = {}
    bad = [(C.CONSUME, parts, 45, 45, 0, b"")]
    rt, pr = C.merkle([C.op_leaf(op) for op in bad])
    hb = (2, 1, b"\x00" * 32, rt, 1, 0)   # site 2 has no share: any consumption is an overspend
    seals2 = [C.sign(vkeys2[i], C.checkpoint_digest(reg.address, C.header_hash(hb))) for i in (0, 1, 2)]
    r, dt = timed(relayer, reg.functions.proveOverspend(hb, seals2, bad[0], 0, pr[0]), 6_000_000)
    proofs_out["overspend"] = {"gas": r.gasUsed, "latency_s": round(dt, 2),
                               "slashed": len(reg.events.Slashed().process_receipt(r))}
    rd = ra + 5
    late = [(C.USE, obj, cq, rd, clock.epoch, clock.attest(C.clock_digest, 1, clock.epoch, rd, obj))]
    rt, pr = C.merkle([C.op_leaf(op) for op in late])
    hl = (1, 3, b"\x02" * 32, rt, 1, 0)
    r, dt = timed(relayer, reg.functions.proveUseAfterAck(hl, seal(hl, [1, 2, 3]), late[0], 0, pr[0]), 6_000_000)
    proofs_out["use_after_ack"] = {"gas": r.gasUsed, "latency_s": round(dt, 2),
                                   "slashed": len(reg.events.Slashed().process_receipt(r))}
    out["proofs"] = proofs_out
    out["end_block"] = w3.eth.block_number
    path = C.ROOT / "experiments" / "results" / f"pubtest_{tag}.json"
    path.write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main(*sys.argv[1:])
