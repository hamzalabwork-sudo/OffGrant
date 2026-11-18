"""Figures for the OffGrant paper (written to paper/figures/)."""
import json
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "paper" / "figures"
H = 3600.0
plt.rcParams.update({"font.family": "serif", "font.size": 7, "axes.linewidth": 0.6, "legend.fontsize": 6,
                     "xtick.major.width": 0.5, "ytick.major.width": 0.5, "pdf.fonttype": 42})
C_OURS, C_NODRIFT, C_BOUND, C_ALT = "#1f4e79", "#c0504d", "#555555", "#7f9fbf"
BOUND_LABEL = "bound $(1+\\rho)/(1-\\rho)$"


def load():
    g = defaultdict(list)
    for line in open(ROOT / "experiments" / "results" / "offsim_v4.jsonl"):
        r = json.loads(line)
        c = r["cfg"]
        g[(c["rho"], c["clock"], c["L"], c["D"])].append(r)
    return g


def tradeoff():
    g = load()
    Ds = sorted({k[3] for k in g})
    x = np.array(Ds) / H
    fig, (a, b) = plt.subplots(1, 2, figsize=(3.45, 1.95))
    # (a) permit availability while cut off (OffGrant), two outage lengths and two clock regimes
    for L, ls in [(24 * H, "-"), (72 * H, "--")]:
        for rho, ck, col, mk in [(1e-4, "uniform", C_ALT, "s"), (0.15, "uniform", C_OURS, "o")]:
            y = [np.mean([r["ours"]["X_avail_out"] for r in g[(rho, ck, L, D)]]) for D in Ds]
            a.plot(x, y, ls, color=col, marker=mk, ms=2.6, lw=0.9,
                   label=f"{'TPM' if rho > 0.01 else '100 ppm'}, {L / H:.0f} h")
    a.set_xscale("log")
    a.set_xticks(x)
    a.set_xticklabels([f"{v:g}" for v in x])
    a.set_ylim(0, 1.05)
    a.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    a.set_xlabel("(a) offline tolerance $D$ (h)")
    a.set_ylabel("offline permit avail.")
    a.legend(loc="lower left", bbox_to_anchor=(-0.02, 1.0), ncol=2, frameon=False, fontsize=5.3,
             handlelength=1.5, columnspacing=0.7, borderaxespad=0.1, labelspacing=0.25)
    a.grid(alpha=0.25, lw=0.4)
    # (b) authority after a reassignment decision, relative to D, TPM clocks all slow (worst case)
    rho = 0.15
    b.axhline((1 + rho) / (1 - rho), color=C_BOUND, lw=0.8, label="bound")
    b.axhline(1.0, color=C_NODRIFT, lw=0.8, ls=":", label="no-drift wait")
    for proto, col, mk in [("ours", C_OURS, "o"), ("nodrift", C_NODRIFT, "x"), ("noepoch", "#8064a2", "^")]:
        y = [max(max(r[proto]["X_authority_after"] or [0]) for L in (24 * H, 72 * H)
                 for r in g[(rho, "slow", L, D)]) / D for D in Ds]
        lab = {"ours": "OffGrant", "nodrift": "no drift", "noepoch": "no epochs"}[proto]
        b.plot(x, y, mk, color=col, ms=3.4, mew=0.9, label=lab)
    b.fill_between([x[0] * 0.8, x[-1] * 1.25], 1.0, 1 / (1 - rho), color=C_NODRIFT, alpha=0.08, lw=0)
    b.text(x[-1] * 1.15, 1.02, "double authority", fontsize=5.5, color=C_NODRIFT, ha="right", va="bottom")
    b.set_xscale("log")
    b.set_xlim(x[0] * 0.8, x[-1] * 1.25)
    b.set_ylim(0.9, 1.45)
    b.set_xticks(x)
    b.set_xticklabels([f"{v:g}" for v in x])
    b.set_xlabel("(b) tolerance $D$ (h)")
    b.set_ylabel("authority after / $D$")
    b.legend(loc="lower left", bbox_to_anchor=(-0.04, 1.0), ncol=2, frameon=False, fontsize=5.3,
             handlelength=1.3, columnspacing=0.5, borderaxespad=0.1, labelspacing=0.25)
    b.grid(alpha=0.25, lw=0.4)
    fig.tight_layout(pad=0.4, w_pad=1.0)
    OUT.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT / "tradeoff.pdf")
    fig.savefig(OUT / "tradeoff.png", dpi=220)
    print("wrote", OUT / "tradeoff.pdf")


def timeline(tag="v4"):
    """End-to-end PureChain run: holds in effect per object and site, with the cut, stops and moves."""
    d = json.loads((ROOT / "experiments" / "results" / f"e2e_{tag}.json").read_text())
    ev = d["events"]
    first = lambda k, **kw: next(e for e in ev if e["kind"] == k and all(e.get(a) == b for a, b in kw.items()))
    cut, heal = first("uplink_cut", site=1)["t"], first("uplink_heal", site=1)["t"]
    t_end = max(e["t"] for e in ev if e["kind"] in ("exec", "op")) + 3
    rel = {e["obj"]: e["t"] for e in ev if e["kind"] == "op" and e.get("op") == "release" and e.get("ok")}
    lanes = ["P11", "L11", "C11", "P21"]
    y = {o: len(lanes) - 1 - k for k, o in enumerate(lanes)}
    col = {1: C_OURS, 2: "#e08a2c"}
    fig, ax = plt.subplots(figsize=(3.45, 1.55))
    ax.axvspan(cut, heal, color=C_NODRIFT, alpha=0.08, lw=0)
    ax.text((cut + heal) / 2, len(lanes) - 0.35, "site 1 uplink cut", ha="center", va="center", fontsize=5.5,
            color=C_NODRIFT)
    for e in ev:
        if e["kind"] == "exec" and e["obj"] in y:
            end = e.get("hold_end_t") or rel.get(e["obj"]) if e["site"] == 1 else e.get("hold_end_t")
            end = end if end and end > e["t"] else t_end
            ax.add_patch(plt.Rectangle((e["t"], y[e["obj"]] - 0.17), end - e["t"], 0.34, color=col[e["site"]],
                                       alpha=0.55, lw=0))
        if e["kind"] == "lapse" and e["obj"] in y:
            ax.plot(e["t"], y[e["obj"]], "x", color="k", ms=2.6, mew=0.7)
    moves = [(first("reassigned_slow", obj="P11")["t"], "P11"), (first("reassign_acked", obj="L11")["t"], "L11"),
             (first("reassign_acked", obj="P21")["t"], "P21")]
    for t, o in moves:
        ax.plot([t, t], [y[o] - 0.33, y[o] + 0.33], color=C_NODRIFT, lw=1.3)
    ax.plot(first("reassign_refused", obj="L11")["t"], y["L11"] + 0.33, "v", color=C_BOUND, ms=2.6, mew=0)
    for e in ev:
        if e["kind"] in ("stop", "revoke") and e["obj"] in y:
            ax.plot(e["t"], y[e["obj"]] + 0.33, "v", color="k", ms=2.6, mew=0)
    tr = first("clock_reset", site=2)["t"]
    ax.text(tr, y["P21"] - 0.5, "S2 power loss", fontsize=5, ha="center", va="center", color=C_BOUND)
    h = [plt.Rectangle((0, 0), 1, 1, color=col[1], alpha=0.55, lw=0),
         plt.Rectangle((0, 0), 1, 1, color=col[2], alpha=0.55, lw=0),
         plt.Line2D([], [], color="k", marker="v", ls="", ms=2.6), plt.Line2D([], [], color=C_NODRIFT, lw=1.3),
         plt.Line2D([], [], color="k", marker="x", ls="", ms=2.6, mew=0.7)]
    ax.legend(h, ["site 1 hold", "site 2 hold", "stop", "moved", "lapsed"], loc="lower left",
              bbox_to_anchor=(-0.01, 1.0), ncol=5, frameon=False, fontsize=5.3, handlelength=1.2,
              columnspacing=0.8, borderaxespad=0.1)
    ax.set_yticks([y[o] for o in lanes])
    ax.set_yticklabels(lanes, fontsize=6)
    ax.set_ylim(-0.75, len(lanes) - 0.15)
    ax.set_xlim(0, t_end)
    ax.set_xlabel("time (s)")
    ax.grid(axis="x", alpha=0.25, lw=0.4)
    fig.tight_layout(pad=0.3)
    fig.savefig(OUT / "timeline.pdf")
    fig.savefig(OUT / "timeline.png", dpi=220)
    print("wrote", OUT / "timeline.pdf")


if __name__ == "__main__":
    tradeoff()
    timeline()
