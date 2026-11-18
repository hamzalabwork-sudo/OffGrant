"""Summaries of offsim v5 results.

Header: the measured workload (rates the documentation states), offline fraction and longest continuous offline
period per L, and, over all runs and per clock regime, how many runs each protocol had a violation in:
  authority overlap  a hold in effect while G gives the object to another site (X_conflicts)
  double use         executed holds of two sites on one object overlap (X_double)
  rights > move      the old holder could still grant after the new holder became entitled (X_rights_beyond)
  cred > bound       a revoked credential took effect after G's bound for it (V_late; lease protocols)
Then offline credential availability per grid point, and per grid point each protocol's mean with a 95% Student-t
confidence half-width over the independent runs, and the maximum; worst-case windows are maxima."""
import json
import sys
from collections import defaultdict

import numpy as np
from scipy import stats

H = 3600.0
PROTOS = ["ours", "global", "discard", "crdt", "timestamp", "waitrel",
          "nodrift", "noepoch", "nofresh", "nohold", "receipt", "eps1"]
ABL = ["nodrift", "noepoch", "nofresh", "nohold", "receipt", "eps1"]
CLOCKS = [(0.0001, "uniform"), (0.15, "uniform"), (0.15, "slow")]
CLOCK_NAME = {(0.0001, "uniform"): "100 ppm uniform", (0.15, "uniform"): "rho=0.15 uniform",
              (0.15, "slow"): "rho=0.15 all slow"}


def load(path):
    groups = defaultdict(list)
    for line in open(path, encoding="utf-8"):
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
        X_conf=c("X_conflicts"), X_dbl=c("X_double"), V_stale=c("V_stale_acc"), B_over=c("B_over"),
        rolled_x=c("rolled_back_excl"), rolled_c=c("rolled_back_log"),
        rdel=c("X_reassign_delay_mean"), rdel_max_h=float(max(r[p]["X_reassign_delay_max"] for r in rs)) / H,
        fast=c("X_fast_frac"), idle=c("X_idle_mean"),
        auth_after_max_h=mx("X_authority_after") / H, V_win_max_h=mx("V_window") / H,
        overlap_max_s=float(max(r[p]["X_overlap_max"] for r in rs)),
        W_h=rs[0]["ours"]["W_bound"] / H, offline=ci([r[p]["offline_frac"] for r in rs]),
    )


def fmt(t, d=1, scale=1.0):
    m, h, x = (v / scale for v in t)
    return f"{m:.{d}f}±{h:.{d}f}(max {x:.{d}f})"


def violations(rs, p):
    """Runs with: authority overlap, double use, rights > move, credential > bound, over-consumption."""
    return (sum(r[p]["X_conflicts"] > 0 for r in rs), sum(r[p]["X_double"] > 0 for r in rs),
            sum(r[p]["X_rights_beyond"] > 0 for r in rs), sum(r[p]["V_late"] > 0 for r in rs),
            sum(r[p]["B_over"] > 0 for r in rs))


def main(path):
    groups = load(path)
    allr = [r for rs in groups.values() for r in rs]
    c0 = allr[0]["cfg"]
    tr = lambda k: [r["trace"][k] for r in allr]
    rng = lambda xs, d=2: f"{np.mean(xs):.{d}f} (runs {min(xs):.{d}f}-{max(xs):.{d}f})"
    print(f"runs={len(allr)} independent traces={len({(r['cfg']['seed'], r['cfg']['trace']) for r in allr})}")
    print("Measured workload (mean over runs, range over runs):")
    print(f"  permit requests per object per day at its holder (while powered): {rng(tr('permit_req_per_obj_day'))}")
    print(f"  G moves per day of the decision window (first {c0['decide_frac'] * c0['days']:g} d): "
          f"{rng(tr('decisions_per_day'))}; per run {rng(tr('decisions'), 1)}; at least "
          f"{c0['min_gap_days']:g} d between moves of one object")
    print(f"  credential revocations per day of the decision window: {rng(tr('revocations_per_day'))}; "
          f"per run {rng(tr('revocations'), 1)}")
    print(f"  finality delay F: mean {np.mean(tr('F_mean')):.1f} s, share over 60 s "
          f"{np.mean(tr('F_frac_over_60s')):.4f}")
    print(f"  renewal responses: share delayed over 1 s {np.mean(tr('resp_frac_over_1s')):.4f}, over 60 s "
          f"{np.mean(tr('resp_frac_over_60s')):.4f}, longest issue-to-arrival {max(tr('resp_max_delay_h')):.1f} h")
    print("Offline per L (fraction of time a site's link is down; longest continuous offline period of any site "
          "in a run, outages and power losses merged):")
    for L in sorted({r["cfg"]["L"] for r in allr}):
        rs = [r for r in allr if r["cfg"]["L"] == L]
        off = ci([r["trace"]["offline_frac"] for r in rs])
        lo = [r["trace"]["longest_offline_h"] for r in rs]
        print(f"  L={L / H:g}h n={len(rs)} offline={off[0]:.3f}±{off[1]:.3f} longest offline: mean {np.mean(lo):.1f} h, "
              f"median {np.median(lo):.1f} h, max {max(lo):.1f} h; runs with longest > L: "
              f"{sum(x > L / H for x in lo)}")
    print("Over all runs (authority overlap = hold in effect while another site holds the object; double use = "
          "executed holds of two sites overlap; rights > move = the old holder could still grant after the new "
          "holder became entitled; cred > bound = revoked credential took effect after G's bound):")
    for p in PROTOS:
        conf, dbl, rights, late, over = violations(allr, p)
        exceed = sum(1 for r in allr if max(r[p]["X_authority_after"] or [0]) > r["ours"]["W_bound"])
        print(f"  {p:9s} authority overlap: {conf} runs (max {max(r[p]['X_conflicts'] for r in allr)}/run, "
              f"longest {max(r[p]['X_overlap_max'] for r in allr):.0f}s); double use: {dbl} runs "
              f"(max {max(r[p]['X_double'] for r in allr)}/run, longest "
              f"{max(r[p]['X_double_max'] for r in allr):.0f}s); rights > move: {rights}; cred > bound: {late}; "
              f"over-consumption: {over}; authority > W: {exceed}")
    print("Runs with a violation per clock regime (authority overlap / double use / rights > move / cred > bound "
          "/ over-consumption):")
    for p in ["discard", "waitrel"] + ABL:
        cells = []
        for ck in CLOCKS:
            rs = [r for r in allr if (r["cfg"]["rho"], r["cfg"]["clock"]) == ck]
            cells.append(f"{CLOCK_NAME[ck]} {'/'.join(map(str, violations(rs, p)))} of {len(rs)}")
        print(f"  {p:9s} " + "; ".join(cells))
    print("Merging baselines per L (fair handover): runs with authority overlap, mean per run:")
    for L in sorted({r["cfg"]["L"] for r in allr}):
        rs = [r for r in allr if r["cfg"]["L"] == L]
        print(f"  L={L / H:g}h: {sum(r['crdt']['X_conflicts'] > 0 for r in rs)} of {len(rs)} runs, "
              f"{np.mean([r['crdt']['X_conflicts'] for r in rs]):.1f} per run, double use "
              f"{np.mean([r['crdt']['X_double'] for r in rs]):.1f} per run")
    print("No-drift ablation at 100 ppm, per L and D: runs with authority overlap / double use / rights > move / "
          "cred > bound / over-consumption, longest overlap (s), overlaps per run:")
    for key in sorted(k for k in groups if k[0] == 0.0001):
        rs = groups[key]
        v = violations(rs, "nodrift")
        print(f"  L={key[2] / H:g}h D={key[3] / H:g}h n={len(rs)}: {'/'.join(map(str, v))}, longest "
              f"{max(r['nodrift']['X_overlap_max'] for r in rs):.0f}s, "
              f"{fmt(ci([r['nodrift']['X_conflicts'] for r in rs]))}")
    print("Credential availability offline (V_avail_out: share of check-ins accepted while cut off; mean over runs; "
          "revoked operators' check-ins count as requests for every protocol):")
    cols = ["ours", "global", "crdt", "waitrel"] + ABL
    print("  " + " " * 35 + " ".join(f"{c:>8s}" for c in cols))
    for key in sorted(groups):
        rho, clock, L, D = key
        rs = groups[key]
        print(f"  rho={rho:<6g} {clock:7s} L={L / H:<4g}h D={D / H:<3g}h " +
              " ".join(f"{np.mean([r[c]['V_avail_out'] for r in rs]):8.2f}" for c in cols))
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
                  f"Xconf={fmt(s['X_conf'])} Xdouble={fmt(s['X_dbl'])} Vstale={fmt(s['V_stale'])} "
                  f"Bover={fmt(s['B_over'])} rolledExcl={fmt(s['rolled_x'], 0)} rolledLog={fmt(s['rolled_c'], 0)} "
                  f"rdel={fmt(s['rdel'], 2, H)}h rdelMax={s['rdel_max_h']:.2f}h fast={fmt(s['fast'], 2)} "
                  f"idle={fmt(s['idle'], 2, H)}h authMax={s['auth_after_max_h']:.3f}h "
                  f"VwinMax={s['V_win_max_h']:.3f}h overlapMax={s['overlap_max_s']:.0f}s")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")   # the summary uses "±"; keep it UTF-8 whatever the console
    main(sys.argv[1] if len(sys.argv) > 1 else "experiments/results/offsim_v5.jsonl")
