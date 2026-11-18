"""Summaries of offsim v6 results.

What the numbers are evidence of. The simulator enforces each protocol's rules as stated; for OffGrant these are
the rules of Proposition 1(b), with every clock inside its drift bound and every G timestamp inside eps_G. OffGrant's
zero conflicts (and the global chain's) therefore hold by construction: offsim.run() asserts them, so a completed
grid can only contain zeros for them. They are a consistency check of the implementation against the proposition,
not independent evidence of safety. What the simulation measures is availability (cut off and connected), hand-over
delays, idle time, refused locks and the cost of the hold-end rule, and the violations that the baselines and the
ablations (each drops one rule) actually produce.

Statistics. Per-run metrics are skewed and often zero, so every headline cell is the mean over the independent runs
of a grid point with a 95% percentile bootstrap confidence interval (10,000 resamples of the runs, fixed seed), and
the median. Maxima are sample maxima and their scope is printed with them: "max over the n runs of this grid point"
(per-point blocks) or "max over all N runs" (the over-all-runs section). Counts of runs with a violation are
reported with the 95% one-sided upper bound when they are zero (exact binomial, 1 - 0.05^(1/N)).

Sections, in order:
  1. measured workload; offline fraction and longest continuous offline period per L;
  2. over all runs, per protocol: runs with each kind of violation, for bounded-class permits (X), open-class locks
     (O), credentials (V) and consumption (B), and per clock regime;
       authority overlap  a hold or lock in effect while G gives the object to another site (X_conflicts, O_conflicts)
       double use         executed holds / locks of two sites on one object overlap (X_double, O_double)
       rights > move      the old holder could still grant after the new holder became entitled (X_rights_beyond)
       cred > bound       a revoked credential took effect after G's bound for it (V_late; lease protocols)
  3. merging baselines per L; the no-drift ablation at 100 ppm;
  4. offline credential availability per grid point;
  5. the hold-end rule's cost while connected (R06 M4b) and open-class results per grid point;
  6. per grid point, every protocol: mean [95% bootstrap CI] md median, mx max over the runs of the point."""
import json
import sys
from collections import defaultdict
from functools import lru_cache

import numpy as np

H = 3600.0
PROTOS = ["ours", "global", "discard", "crdt", "timestamp", "waitrel",
          "nodrift", "noepoch", "nofresh", "nohold", "receipt", "eps1"]
ABL = ["nodrift", "noepoch", "nofresh", "nohold", "receipt", "eps1"]
CLOCKS = [(0.0001, "uniform"), (0.15, "uniform"), (0.15, "slow")]
CLOCK_NAME = {(0.0001, "uniform"): "100 ppm uniform", (0.15, "uniform"): "rho=0.15 uniform",
              (0.15, "slow"): "rho=0.15 all slow"}
B_RESAMPLES = 10_000
B_SEED = 20261119


def load(path):
    groups = defaultdict(list)
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        c = r["cfg"]
        groups[(c["rho"], c["clock"], c["L"], c["D"])].append(r)
    return groups


@lru_cache(maxsize=None)
def _boot_idx(n):
    """Resampling indices for n runs: the same fixed seed for every call, so results do not depend on order."""
    return np.random.default_rng(B_SEED).integers(0, n, (B_RESAMPLES, n))


def ci(xs):
    """(mean, 95% percentile-bootstrap low, high, median, max) over the runs."""
    a = np.asarray(xs, dtype=float)
    if len(a) == 0:
        return (0.0,) * 5
    m, md, mx = float(a.mean()), float(np.median(a)), float(a.max())
    if len(a) == 1 or np.all(a == a[0]):
        return m, m, m, md, mx
    bm = a[_boot_idx(len(a))].mean(axis=1)
    lo, hi = np.percentile(bm, [2.5, 97.5])
    return m, float(lo), float(hi), md, mx


def fmt(t, d=1, scale=1.0, mx=True):
    m, lo, hi, md, x = (v / scale for v in t)
    s = f"{m:.{d}f} [{lo:.{d}f},{hi:.{d}f}] md {md:.{d}f}"
    return s + f" mx {x:.{d}f}" if mx else s


def nz(rs, p, k):
    return sum(r[p][k] > 0 for r in rs)


def upper0(n):
    """95% one-sided upper bound on a probability after 0 events in n trials."""
    return 1 - 0.05 ** (1 / n) if n else 1.0


def violations(rs, p):
    """Runs with: authority overlap, double use, rights > move, credential > bound, over-consumption, open-class
    authority overlap, open-class double use."""
    return (nz(rs, p, "X_conflicts"), nz(rs, p, "X_double"), nz(rs, p, "X_rights_beyond"), nz(rs, p, "V_late"),
            nz(rs, p, "B_over"), nz(rs, p, "O_conflicts"), nz(rs, p, "O_double"))


def rmax(rs, p, k):
    return max(r[p][k] for r in rs)


def lmax(rs, p, k):
    return float(max(max(r[p][k] or [0.0]) for r in rs))


def main(path):
    groups = load(path)
    allr = [r for rs in groups.values() for r in rs]
    N = len(allr)
    c0 = allr[0]["cfg"]
    tr = lambda k: [r["trace"][k] for r in allr]
    rng = lambda xs, d=2: f"{np.mean(xs):.{d}f} (runs {min(xs):.{d}f}-{max(xs):.{d}f})"
    npt = sorted({len(rs) for rs in groups.values()})
    print(f"runs={N} independent traces={len({(r['cfg']['seed'], r['cfg']['trace']) for r in allr})} "
          f"grid points={len(groups)} runs per point={'/'.join(map(str, npt))}")
    print("NOTE: the simulator enforces each protocol's rules, so OffGrant's and the global chain's zero conflicts "
          "hold by construction (asserted in offsim.run()); they check the implementation against Proposition "
          "1(b). The measurements are availability, delays, idle time, refusals and the failures of baselines and "
          "ablations.")
    print(f"Statistics: mean [95% percentile bootstrap CI, {B_RESAMPLES} resamples of the runs, seed {B_SEED}] "
          "md median; 'mx' and 'max' are sample maxima with the scope printed beside them.")
    print("Measured workload (mean over all runs, range over runs):")
    print(f"  permit requests per bounded object per day at its holder (while powered): "
          f"{rng(tr('permit_req_per_obj_day'))}")
    print(f"  G moves of bounded objects per day of the decision window (first {c0['decide_frac'] * c0['days']:g} d): "
          f"{rng(tr('decisions_per_day'))}; per run {rng(tr('decisions'), 1)}; at least "
          f"{c0['min_gap_days']:g} d between moves of one object")
    print(f"  open class: {c0['open_per_site']} isolation points per site; lock requests per object per day at its "
          f"holder {rng(tr('lock_req_per_obj_day'))}; lock duration lognormal median {c0['lock_med'] / H:g} h, "
          f"sigma {c0['lock_sigma']:g}, capped at {c0['lock_cap'] / H:g} h: mean {np.mean(tr('lock_mean_h')):.2f} h, "
          f"share capped {np.mean(tr('lock_frac_capped')):.4f}; G moves per day {rng(tr('open_decisions_per_day'))}, "
          f"per run {rng(tr('open_decisions'), 1)}")
    print(f"  credential revocations per day of the decision window: {rng(tr('revocations_per_day'))}; "
          f"per run {rng(tr('revocations'), 1)}")
    print(f"  finality delay F: mean {np.mean(tr('F_mean')):.1f} s, share over 60 s "
          f"{np.mean(tr('F_frac_over_60s')):.4f}")
    print(f"  renewal responses: share delayed over 1 s {np.mean(tr('resp_frac_over_1s')):.4f}, over 60 s "
          f"{np.mean(tr('resp_frac_over_60s')):.4f}, longest issue-to-arrival {max(tr('resp_max_delay_h')):.1f} h "
          f"(max over all {N} runs)")
    print("Offline per L (fraction of time a site's link is down; longest continuous offline period of any site "
          "in a run, outages and power losses merged):")
    for L in sorted({r["cfg"]["L"] for r in allr}):
        rs = [r for r in allr if r["cfg"]["L"] == L]
        off = ci([r["trace"]["offline_frac"] for r in rs])
        lo = [r["trace"]["longest_offline_h"] for r in rs]
        print(f"  L={L / H:g}h n={len(rs)} offline={fmt(off, 3, mx=False)} longest offline: mean {np.mean(lo):.1f} h, "
              f"median {np.median(lo):.1f} h, max {max(lo):.1f} h (max over the {len(rs)} runs at this L); "
              f"runs with longest > L: {sum(x > L / H for x in lo)}")

    print(f"Over all {N} runs: runs with a violation (and the largest count per run and longest overlap, max over "
          f"all {N} runs). X = bounded-class permits, O = open-class locks:")
    for p in PROTOS:
        conf, dbl, rights, late, over, oconf, odbl = violations(allr, p)
        exceed = sum(1 for r in allr if max(r[p]["X_authority_after"] or [0]) > r["ours"]["W_bound"])
        print(f"  {p:9s} X authority overlap: {conf} runs (max {rmax(allr, p, 'X_conflicts')}/run, longest "
              f"{rmax(allr, p, 'X_overlap_max'):.0f}s); X double use: {dbl} runs (max {rmax(allr, p, 'X_double')}/run, "
              f"longest {rmax(allr, p, 'X_double_max'):.0f}s); rights > move: {rights} (largest excess "
              f"{rmax(allr, p, 'X_rights_excess_max'):.2f}s); cred > bound: {late}; over-consumption: {over}; "
              f"authority > W: {exceed}; O authority overlap: {oconf} runs (max {rmax(allr, p, 'O_conflicts')}/run, "
              f"longest {rmax(allr, p, 'O_overlap_max') / H:.1f}h); O double use: {odbl} runs")
    ours_slow = sum(round((1 - r["ours"]["X_fast_frac"]) * r["trace"]["decisions"]) for r in allr)
    ours_odec = sum(r["ours"]["O_decisions"] for r in allr)
    ours_olock = sum(r["ours"]["O_locked_at_decision"] for r in allr)
    print(f"  Zero counts, 95% one-sided upper bounds (within the model only; see NOTE): 0 of {N} runs -> share of "
          f"runs <= {100 * upper0(N):.2f}%; OffGrant bounded moves by the slow path: {ours_slow} (0 overlaps -> "
          f"<= {100 * upper0(ours_slow):.3f}% per slow-path move); open-class moves: {ours_odec}, of which "
          f"{ours_olock} with a lock of the old holder on at the decision (0 overlaps -> <= "
          f"{100 * upper0(ours_olock):.3f}% per such move)")
    print("  Counterfactual 'move open-class objects by expiry' (OffGrant's rules otherwise; O_expiry_moves = moves "
          "for which G's wait W would have ended while a lock of the old holder was still on):")
    for p in ["ours"] + ABL:
        em = sum(r[p]["O_expiry_moves"] for r in allr)
        el = sum(r[p]["O_expiry_locks"] for r in allr)
        print(f"    {p:9s} {em} moves in {nz(allr, p, 'O_expiry_moves')} of {N} runs ({el} locks on)")
    print("Runs with a violation per clock regime (X authority overlap / X double use / rights > move / cred > bound "
          "/ over-consumption / O authority overlap / O double use):")
    for p in ["discard", "waitrel"] + ABL:
        cells = []
        for ck in CLOCKS:
            rs = [r for r in allr if (r["cfg"]["rho"], r["cfg"]["clock"]) == ck]
            if rs:
                cells.append(f"{CLOCK_NAME[ck]} {'/'.join(map(str, violations(rs, p)))} of {len(rs)}")
        print(f"  {p:9s} " + "; ".join(cells))
    print("Merging baselines per L (fair hand-over for bounded objects; open-class objects move at once): runs with "
          "authority overlap, mean per run:")
    for L in sorted({r["cfg"]["L"] for r in allr}):
        rs = [r for r in allr if r["cfg"]["L"] == L]
        print(f"  L={L / H:g}h: X {nz(rs, 'crdt', 'X_conflicts')} of {len(rs)} runs, "
              f"{np.mean([r['crdt']['X_conflicts'] for r in rs]):.1f} per run, double use "
              f"{np.mean([r['crdt']['X_double'] for r in rs]):.1f} per run; O {nz(rs, 'crdt', 'O_conflicts')} of "
              f"{len(rs)} runs, {np.mean([r['crdt']['O_conflicts'] for r in rs]):.2f} per run")
    print("No-drift ablation at 100 ppm, per L and D: runs with the violations above, longest overlap (s, max over "
          "the runs of the point), overlaps per run:")
    for key in sorted(k for k in groups if k[0] == 0.0001):
        rs = groups[key]
        v = violations(rs, "nodrift")
        print(f"  L={key[2] / H:g}h D={key[3] / H:g}h n={len(rs)}: {'/'.join(map(str, v))}, longest "
              f"{rmax(rs, 'nodrift', 'X_overlap_max'):.0f}s, {fmt(ci([r['nodrift']['X_conflicts'] for r in rs]))}")

    print("Credential availability offline (V_avail_out: share of check-ins accepted while cut off; mean over the "
          "runs of the point; revoked operators' check-ins count as requests for every protocol):")
    cols = ["ours", "global", "crdt", "waitrel"] + ABL
    print("  " + " " * 35 + " ".join(f"{c:>8s}" for c in cols))
    for key in sorted(groups):
        rho, clock, L, D = key
        rs = groups[key]
        print(f"  rho={rho:<6g} {clock:7s} L={L / H:<4g}h D={D / H:<3g}h " +
              " ".join(f"{np.mean([r[c]['V_avail_out'] for r in rs]):8.2f}" for c in cols))

    print("Hold-end rule while CONNECTED (R06 M4b), bounded permits: X_avail_conn = accepted / requested while "
          "connected (mean [95% CI]); refused = requests refused because the hold would end after the allowance, "
          "and truncated = max-fit holds shortened to fit, as shares of connected requests (pooled over the runs "
          "of the point); 'nohold' and 'waitrel' show the availability without the rule:")
    for key in sorted(groups):
        rho, clock, L, D = key
        rs = groups[key]
        rq = sum(r["ours"]["X_req"] - r["ours"]["X_req_out"] for r in rs)
        ref = sum(r["ours"]["X_holdend_refused_conn"] for r in rs)
        trc = sum(r["ours"]["X_truncated_conn"] for r in rs)
        print(f"  rho={rho:<6g} {clock:7s} L={L / H:<4g}h D={D / H:<3g}h ours {fmt(ci([r['ours']['X_avail_conn'] for r in rs]), 3, mx=False)}"
              f"  refused {ref / max(1, rq):.3f} truncated {trc / max(1, rq):.3f}"
              f"  | nohold {np.mean([r['nohold']['X_avail_conn'] for r in rs]):.3f}"
              f" waitrel {np.mean([r['waitrel']['X_avail_conn'] for r in rs]):.3f}"
              f" global {np.mean([r['global']['X_avail_conn'] for r in rs]):.3f}")

    print("Open class (locks) per grid point: Oout = lock requests accepted while cut off / requested while cut off "
          "(mean); refused/run = locks refused because the allowance lapsed; hand-over = decision to the moment "
          "the new holder may act (h): OffGrant mean [95% CI] md median of the per-run means, others mean; 'max' = "
          "max over the runs of the point; conflicts = mean overlaps per run:")
    for key in sorted(groups):
        rho, clock, L, D = key
        rs = groups[key]
        m = lambda p, k: np.mean([r[p][k] for r in rs])
        hm = ci([r["ours"]["O_handover_mean"] for r in rs])
        print(f"  rho={rho:<6g} {clock:7s} L={L / H:<4g}h D={D / H:<3g}h Oout ours {m('ours', 'O_avail_out'):.2f} "
              f"waitrel {m('waitrel', 'O_avail_out'):.2f} crdt {m('crdt', 'O_avail_out'):.2f}; refused/run ours "
              f"{m('ours', 'O_refused_allow'):.1f}; hand-over ours {fmt(hm, 2, H, mx=False)} max "
              f"{rmax(rs, 'ours', 'O_handover_max') / H:.1f}; waitrel {m('waitrel', 'O_handover_mean') / H:.2f} max "
              f"{rmax(rs, 'waitrel', 'O_handover_max') / H:.1f}; global {m('global', 'O_handover_mean') / H:.2f} max "
              f"{rmax(rs, 'global', 'O_handover_max') / H:.1f}; conflicts crdt {m('crdt', 'O_conflicts'):.2f} "
              f"({nz(rs, 'crdt', 'O_conflicts')}/{len(rs)} runs), ours 0 by construction")

    for key in sorted(groups):
        rho, clock, L, D = key
        rs = groups[key]
        n = len(rs)
        off = ci([r["ours"]["offline_frac"] for r in rs])
        print(f"== rho={rho:g} {clock} L={L / H:g}h D={D / H:g}h n={n} offline={fmt(off, 3, mx=False)} "
              f"W={rs[0]['ours']['W_bound'] / H:.4f}h  [cells: mean [95% bootstrap CI] md median mx max over the "
              f"{n} runs of this grid point; 'Max' fields: max over the {n} runs of this grid point; nz = runs "
              f"with a non-zero count]")
        for p in PROTOS:
            c = lambda k, rs=rs, p=p: ci([r[p][k] for r in rs])
            print(f"  {p:9s} X: out={fmt(c('X_avail_out'), 2)} outFixed={fmt(c('X_avail_out_fixed'), 2)} "
                  f"conn={fmt(c('X_avail_conn'), 3)} conf={fmt(c('X_conflicts'))} nz={nz(rs, p, 'X_conflicts')} "
                  f"double={fmt(c('X_double'))} nz={nz(rs, p, 'X_double')} "
                  f"holdendRefusedConn={fmt(c('X_holdend_refused_conn'))} truncConn={fmt(c('X_truncated_conn'))} "
                  f"delay={fmt(c('X_reassign_delay_mean'), 2, H)}h delayMax={rmax(rs, p, 'X_reassign_delay_max') / H:.2f}h "
                  f"fast={fmt(c('X_fast_frac'), 2, mx=False)} idle={fmt(c('X_idle_mean'), 2, H)}h "
                  f"authAfterMax={lmax(rs, p, 'X_authority_after') / H:.3f}h overlapMax={rmax(rs, p, 'X_overlap_max'):.0f}s")
            print(f"  {'':9s} V: out={fmt(c('V_avail_out'), 2)} staleAcc={fmt(c('V_stale_acc'))} "
                  f"staleObservedMax={rmax(rs, p, 'V_stale_max') / H:.1f}h windowMax={lmax(rs, p, 'V_window') / H:.1f}h "
                  f"B: out={fmt(c('B_avail_out'), 2)} over={fmt(c('B_over'))} nz={nz(rs, p, 'B_over')} "
                  f"rolledExcl={fmt(c('rolled_back_excl'), 0)} rolledLog={fmt(c('rolled_back_log'), 0)}")
            print(f"  {'':9s} O: out={fmt(c('O_avail_out'), 2)} conn={fmt(c('O_avail_conn'), 3)} "
                  f"accOut={fmt(c('O_acc_out'))} refusedAllow={fmt(c('O_refused_allow'))} "
                  f"conf={fmt(c('O_conflicts'))} nz={nz(rs, p, 'O_conflicts')} double={fmt(c('O_double'))} "
                  f"handover={fmt(c('O_handover_mean'), 2, H)}h handoverMax={rmax(rs, p, 'O_handover_max') / H:.1f}h "
                  f"lockedAtDecision={fmt(c('O_locked_at_decision'))} expiryMoves={fmt(c('O_expiry_moves'))} "
                  f"overlapMax={rmax(rs, p, 'O_overlap_max') / H:.2f}h")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")   # keep the summary UTF-8 whatever the console
    main(sys.argv[1] if len(sys.argv) > 1 else "experiments/results/offsim_v6.jsonl")
