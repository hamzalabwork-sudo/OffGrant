"""Summaries of offsim v4 results per clock regime, outage length L and offline tolerance D: mean over the
independent runs with a 95% Student-t confidence half-width, and the maximum over runs; worst-case windows are
maxima. Also prints, over all 720 runs, how many runs each protocol had a conflict / over-consumption in and
how many runs exceeded the bound W."""
import json
import sys
from collections import defaultdict

import numpy as np
from scipy import stats

H = 3600.0
PROTOS = ["ours", "global", "discard", "crdt", "timestamp", "waitrel", "nodrift", "noepoch", "nofresh"]


def load(path):
    groups = defaultdict(list)
    for line in open(path):
        r = json.loads(line)
        c = r["cfg"]
        groups[(c["rho"], c["clock"], c["L"], c["D"])].append(r)
    return groups


def ci(xs):
    a = np.asarray(xs, dtype=float)
    n = len(a)
    half = float(stats.t.ppf(0.975, n - 1) * a.std(ddof=1) / np.sqrt(n)) if n > 1 else 0.0
    return float(a.mean()), half, float(a.max())


def summary(rs, p):
    c = lambda k: ci([r[p][k] for r in rs])
    mx = lambda k: float(max(max(r[p][k] or [0.0]) for r in rs))
    return dict(
        X_out=c("X_avail_out"), V_out=c("V_avail_out"), B_out=c("B_avail_out"),
        X_conf=c("X_conflicts"), V_stale=c("V_stale_acc"), B_over=c("B_over"), rolled=c("rolled_back"),
        rdel=c("X_reassign_delay_mean"), rdel_max_h=float(max(r[p]["X_reassign_delay_max"] for r in rs)) / H,
        idle=c("X_idle_mean"),
        auth_after_max_h=mx("X_authority_after") / H, V_win_max_h=mx("V_window") / H,
        overlap_max_s=float(max(r[p]["X_overlap_max"] for r in rs)),
        W_h=rs[0]["ours"]["W_bound"] / H, offline=ci([r[p]["offline_frac"] for r in rs]),
    )


def fmt(t, d=1, scale=1.0):
    m, h, x = (v / scale for v in t)
    return f"{m:.{d}f}±{h:.{d}f}(max {x:.{d}f})"


def main(path):
    groups = load(path)
    allr = [r for rs in groups.values() for r in rs]
    print(f"runs={len(allr)} independent traces={len({(r['cfg']['seed'], r['cfg']['trace']) for r in allr})}")
    for p in PROTOS:
        conf = sum(1 for r in allr if r[p]["X_conflicts"] > 0)
        over = sum(1 for r in allr if r[p]["B_over"] > 0)
        exceed = sum(1 for r in allr if max(r[p]["X_authority_after"] or [0]) > r["ours"]["W_bound"])
        ovl = max(r[p]["X_overlap_max"] for r in allr)
        conf_max = max(r[p]["X_conflicts"] for r in allr)
        print(f"  {p:9s} runs with X conflict={conf} (max {conf_max}/run, overlap max {ovl:.0f}s) "
              f"runs with over-consumption={over} runs with authority > W={exceed}")
    for key in sorted(groups):
        rho, clock, L, D = key
        rs = groups[key]
        s0 = summary(rs, "ours")
        off = s0["offline"]
        print(f"== rho={rho:g} {clock} L={L / H:g}h D={D / H:g}h n={len(rs)} offline={off[0]:.3f}±{off[1]:.3f} "
              f"W={s0['W_h']:.4f}h")
        for p in PROTOS:
            s = summary(rs, p)
            print(f"  {p:9s} Xout={fmt(s['X_out'], 2)} Vout={fmt(s['V_out'], 2)} Bout={fmt(s['B_out'], 2)} "
                  f"Xconf={fmt(s['X_conf'])} Vstale={fmt(s['V_stale'])} Bover={fmt(s['B_over'])} "
                  f"rolled={fmt(s['rolled'], 0)} rdel={fmt(s['rdel'], 2, H)}h rdelMax={s['rdel_max_h']:.2f}h "
                  f"idle={fmt(s['idle'], 2, H)}h authMax={s['auth_after_max_h']:.3f}h "
                  f"VwinMax={s['V_win_max_h']:.3f}h overlapMax={s['overlap_max_s']:.0f}s")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")   # the summary uses "±"; keep it UTF-8 whatever the console
    main(sys.argv[1] if len(sys.argv) > 1 else "experiments/results/offsim_v4.jsonl")
