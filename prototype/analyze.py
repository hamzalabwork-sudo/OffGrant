"""Summaries of offsim results: per clock regime, outage length L and offline tolerance D, mean over seeds
(and the maximum over seeds for worst-case windows)."""
import json
import sys
from collections import defaultdict

import numpy as np

H = 3600.0
PROTOS = ["ours", "global", "discard", "crdt", "timestamp", "nodrift"]


def load(path):
    groups = defaultdict(list)
    for line in open(path):
        r = json.loads(line)
        c = r["cfg"]
        groups[(c["rho"], c["clock"], c["L"], c["D"])].append(r)
    return groups


def summary(rs, p):
    g = lambda k: float(np.mean([r[p][k] for r in rs]))
    mx = lambda k: float(max(max(r[p][k] or [0.0]) for r in rs))
    return dict(
        X_out=g("X_avail_out"), V_out=g("V_avail_out"), B_out=g("B_avail_out"), C_out=g("C_avail_out"),
        X_conf=g("X_conflicts"), V_stale=g("V_stale_acc"), B_over=g("B_over"), rolled=g("rolled_back"),
        auth_after_max_h=mx("X_authority_after") / H, V_win_max_h=mx("V_window") / H,
        overlap_max_s=float(max(r[p]["X_overlap_max"] for r in rs)),
        W_h=rs[0]["ours"]["W_bound"] / H, offline=float(np.mean([r[p]["offline_frac"] for r in rs])),
    )


def main(path):
    groups = load(path)
    for key in sorted(groups):
        rho, clock, L, D = key
        rs = groups[key]
        s0 = summary(rs, "ours")
        print(f"== rho={rho:g} {clock} L={L / H:g}h D={D / H:g}h n={len(rs)} offline={s0['offline']:.3f} "
              f"W={s0['W_h']:.3f}h")
        for p in PROTOS:
            s = summary(rs, p)
            print(f"  {p:9s} Xout={s['X_out']:.2f} Vout={s['V_out']:.2f} Bout={s['B_out']:.2f} "
                  f"Xconf={s['X_conf']:.1f} Vstale={s['V_stale']:.1f} Bover={s['B_over']:.1f} "
                  f"rolled={s['rolled']:.0f} authMax={s['auth_after_max_h']:.2f}h "
                  f"VwinMax={s['V_win_max_h']:.2f}h overlapMax={s['overlap_max_s']:.0f}s")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "experiments/results/offsim_v2.jsonl")
