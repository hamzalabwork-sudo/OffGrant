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
    for line in open(ROOT / "experiments" / "results" / "offsim_v3.jsonl"):
        r = json.loads(line)
        c = r["cfg"]
        g[(c["rho"], c["clock"], c["L"], c["D"])].append(r)
    return g


def tradeoff():
    g = load()
    Ds = sorted({k[3] for k in g})
    x = np.array(Ds) / H
    fig, (a, b) = plt.subplots(1, 2, figsize=(3.45, 1.65))
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
    a.set_xlabel("(a) offline tolerance $D$ (h)")
    a.set_ylabel("offline permit avail.")
    a.legend(loc="upper left", frameon=False, handlelength=1.6, borderaxespad=0.2)
    a.grid(alpha=0.25, lw=0.4)
    # (b) authority after a reassignment decision, relative to D, TPM clocks all slow (worst case)
    rho = 0.15
    b.axhline((1 + rho) / (1 - rho), color=C_BOUND, lw=0.8)
    b.text(x[0], (1 + rho) / (1 - rho) + 0.015, BOUND_LABEL, fontsize=6, va="bottom")
    b.axhline(1.0, color=C_NODRIFT, lw=0.8, ls=":")
    b.text(x[0], 1.0 - 0.015, "no-drift wait", fontsize=6, va="top", color=C_NODRIFT)
    for proto, col, mk in [("ours", C_OURS, "o"), ("nodrift", C_NODRIFT, "x"), ("noepoch", "#8064a2", "^")]:
        y = [max(max(r[proto]["X_authority_after"] or [0]) for L in (24 * H, 72 * H)
                 for r in g[(rho, "slow", L, D)]) / D for D in Ds]
        lab = {"ours": "OffGrant", "nodrift": "no-drift lease", "noepoch": "no epochs"}[proto]
        b.plot(x, y, mk, color=col, ms=3.4, mew=0.9, label=lab)
    b.fill_between([x[0] * 0.8, x[-1] * 1.25], 1.0, 1 / (1 - rho), color=C_NODRIFT, alpha=0.08, lw=0)
    b.text(x[0] * 0.95, 1.12, "double authority", fontsize=6, color=C_NODRIFT)
    b.set_xscale("log")
    b.set_xlim(x[0] * 0.8, x[-1] * 1.25)
    b.set_ylim(0.9, 1.45)
    b.set_xticks(x)
    b.set_xticklabels([f"{v:g}" for v in x])
    b.set_xlabel("(b) offline tolerance $D$ (h)")
    b.set_ylabel("authority after / $D$")
    b.legend(loc="lower right", frameon=True, framealpha=1.0, edgecolor="#bbbbbb", fancybox=False,
             handlelength=1.0, borderaxespad=0.3)
    b.grid(alpha=0.25, lw=0.4)
    fig.tight_layout(pad=0.4, w_pad=1.0)
    OUT.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT / "tradeoff.pdf")
    print("wrote", OUT / "tradeoff.pdf")


def timeline(tag="v3"):
    """End-to-end PureChain run: operations per site over time, with the cut and the protocol events."""
    d = json.loads((ROOT / "experiments" / "results" / f"e2e_{tag}.json").read_text())
    ev, p = d["events"], d["params"]
    first = lambda k, **kw: next(e for e in ev if e["kind"] == k and all(e.get(a) == b for a, b in kw.items()))
    cut, heal = first("uplink_cut", site=1)["t"], first("uplink_heal", site=1)["t"]
    expiries = []
    for o in ("P11", "P12", "C11"):
        sends = [r["t_send"] for r in ev if r["kind"] == "renewal" and r["site"] == 1 and r["obj"] == o and r["t_send"] < cut]
        expiries.append(max(sends) + p["A_ms"] / 1000 / (1 + p["drift"]["1"]))
    fig, ax = plt.subplots(figsize=(3.45, 1.55))
    ax.axvspan(cut, heal, color=C_NODRIFT, alpha=0.08, lw=0)
    ax.text(cut + 2, 3.62, "site 1 uplink cut", ha="left", fontsize=6, color=C_NODRIFT)
    lanes = [(1, ("use", "cred"), "S1 permits, cred."), (1, ("consume", "log"), "S1 parts, logs"),
             (2, ("use", "cred"), "S2 permits, cred."), (2, ("consume", "log"), "S2 parts, logs")]
    for y, (site, kinds, _) in zip([3, 2, 1, 0], lanes):
        ops = [e for e in ev if e["kind"] == "op" and e["site"] == site and e["op"] in kinds]
        ok = [e["t"] for e in ops if e.get("ok")]
        bad = [e["t"] for e in ops if not e.get("ok")]
        ax.plot(ok, [y] * len(ok), "o", color=C_OURS, ms=2.0, mew=0)
        ax.plot(bad, [y] * len(bad), "x", color=C_NODRIFT, ms=2.6, mew=0.7)
    for t in expiries:  # per-object end of site 1's allowance (slow clock, -15%)
        ax.plot([t, t], [2.6, 3.4], color=C_NODRIFT, lw=1.0)
    ax.text(max(expiries) + 1.5, 2.5, "S1 leases expire (one tick per object)", fontsize=5, color=C_NODRIFT,
            ha="left", va="center")
    marks = [(first("reassigned_slow", obj="P11")["t"], "P11 moved\n(slow path)"),
             (first("stop", obj="P21")["t"], "P21 stop"),
             (first("reassign_acked", obj="P21")["t"], "P21 moved\n(fast path)"),
             (first("clock_reset", site=2)["t"], "S2 clock\nreset")]
    for i, (t, lab) in enumerate(marks):
        ax.axvline(t, color=C_BOUND, lw=0.5, ls="--")
        right = i == len(marks) - 1   # last label on the right of its line, clear of the previous one
        ax.text(t + (1.0 if right else -1.0), -1.7, lab.replace("\n", " "), fontsize=5, va="bottom",
                ha="left" if right else "right", rotation=90, color=C_BOUND)
    ax.set_yticks([3, 2, 1, 0])
    ax.set_yticklabels([l[2] for l in lanes], fontsize=6)
    ax.set_ylim(-1.75, 3.95)
    ax.set_xlim(0, max(e["t"] for e in ev if e["kind"] == "op") + 3)
    ax.set_xlabel("time (s);  $\\bullet$ accepted, $\\times$ rejected by SiteRights")
    ax.grid(axis="x", alpha=0.25, lw=0.4)
    fig.tight_layout(pad=0.3)
    fig.savefig(OUT / "timeline.pdf")
    print("wrote", OUT / "timeline.pdf")


if __name__ == "__main__":
    tradeoff()
    timeline()
