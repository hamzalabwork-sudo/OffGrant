"""Summaries of offsim results per clock regime, outage length L and offline tolerance D: mean over seeds with a
95% confidence half-width (normal approximation) and the maximum over seeds; worst-case windows are maxima."""
import json
import sys
from collections import defaultdict

import numpy as np

H = 3600.0
PROTOS = ["ours", "global", "discard", "crdt", "timestamp", "nodrift", "noepoch"]


def load(path):
    groups = defaultdict(list)
    for line in open(path):
        r = json.loads(line)
        c = r["cfg"]
        groups[(c["rho"], c["clock"], c["L"], c["D"])].append(r)
    return groups


def ci(xs):
    a = np.asarray(xs, dtype=float)
    half = 1.96 * a.std(ddof=1) / np.sqrt(len(a)) if len(a) > 1 else 0.0
    return float(a.mean()), float(half), float(a.max())


def summary(rs, p):
    c = lambda k: ci([r[p][k] for r in rs])
    mx = lambda k: float(max(max(r[p][k] or [0.0]) for r in rs))
    return dict(
        X_out=c("X_avail_out"), V_out=c("V_avail_out"), B_out=c("B_avail_out"),
        X_conf=c("X_conflicts"), V_stale=c("V_stale_acc"), B_over=c("B_over"), rolled=c("rolled_back"),
        auth_after_max_h=mx("X_authority_after") / H, V_win_max_h=mx("V_window") / H,
        overlap_max_s=float(max(r[p]["X_overlap_max"] for r in rs)),
        W_h=rs[0]["ours"]["W_bound"] / H, offline=float(np.mean([r[p]["offline_frac"] for r in rs])),
    )


def fmt(t, d=1):
    m, h, x = t
    return f"{m:.{d}f}±{h:.{d}f}(max {x:.{d}f})"


def main(path):
    groups = load(path)
    for key in sorted(groups):
        rho, clock, L, D = key
        rs = groups[key]
        s0 = summary(rs, "ours")
        print(f"== rho={rho:g} {clock} L={L / H:g}h D={D / H:g}h n={len(rs)} offline={s0['offline']:.3f} "
              f"W={s0['W_h']:.4f}h")
        for p in PROTOS:
            s = summary(rs, p)
            print(f"  {p:9s} Xout={fmt(s['X_out'], 2)} Bout={fmt(s['B_out'], 2)} Xconf={fmt(s['X_conf'])} "
                  f"Vstale={fmt(s['V_stale'])} Bover={fmt(s['B_over'])} rolled={fmt(s['rolled'], 0)} "
                  f"authMax={s['auth_after_max_h']:.3f}h VwinMax={s['V_win_max_h']:.3f}h "
                  f"overlapMax={s['overlap_max_s']:.0f}s")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "experiments/results/offsim_v3.jsonl")
