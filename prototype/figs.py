"""Figures for the OffGrant paper (written to paper_iotj/figures/)."""
import json
from collections import defaultdict
from pathlib import Path

import matplotlib
import matplotlib.ticker

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "paper_iotj" / "figures"
H = 3600.0
plt.rcParams.update({"font.family": "serif", "font.size": 7, "axes.linewidth": 0.6, "legend.fontsize": 6,
                     "xtick.major.width": 0.5, "ytick.major.width": 0.5, "pdf.fonttype": 42})
C_OURS, C_NODRIFT, C_BOUND, C_ALT = "#1f4e79", "#c0504d", "#555555", "#7f9fbf"
BOUND_LABEL = "bound $(1+\\rho)/(1-\\rho)$"


def load(path=None):
    g = defaultdict(list)
    for line in open(path or ROOT / "experiments" / "results" / "offsim_v6.jsonl", encoding="utf-8"):
        r = json.loads(line)
        c = r["cfg"]
        g[(c["rho"], c["clock"], c["L"], c["D"])].append(r)
    return g


def tradeoff(path=None):
    g = load(path)
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
    # (b) authority after a reassignment decision, relative to D, TPM clocks all slow (worst case). Log y-axis so
    # that no point is clipped (the no-epochs ablation reaches about 4 x D at D = 1 h); markers are offset in x so
    # that coinciding values stay visible. receipt / eps1 / nohold / nofresh are not drawn: their rights end at
    # most seconds (receipt: the response delay) after OffGrant's and would coincide with its markers.
    rho = 0.15
    bound = (1 + rho) / (1 - rho)
    b.axhline(bound, color=C_BOUND, lw=0.8, label="bound")
    b.axhline(1.0, color=C_NODRIFT, lw=0.8, ls=":", label="no-drift wait")
    ymax, ymin = bound, 1.0
    for proto, col, mk, dx in [("ours", C_OURS, "o", 1.0), ("nodrift", C_NODRIFT, "x", 0.88),
                               ("noepoch", "#8064a2", "^", 1.13)]:
        y = [max(max(r[proto]["X_authority_after"] or [0]) for L in (24 * H, 72 * H)
                 for r in g[(rho, "slow", L, D)]) / D for D in Ds]
        lab = {"ours": "OffGrant", "nodrift": "no drift", "noepoch": "no epochs"}[proto]
        b.plot(x * dx, y, mk, color=col, ms=3.4, mew=0.9, label=lab, mfc="none" if mk == "o" else col)
        ymax, ymin = max(ymax, max(y)), min([ymin] + [v for v in y if v > 0])
        if proto == "noepoch":
            k = int(np.argmax(y))
            if y[k] > bound * 1.05:
                b.annotate(f"{y[k]:.2f}", (x[k] * dx, y[k]), xytext=(4, -1), textcoords="offset points",
                           fontsize=5.3, color="#8064a2", va="center")
    b.fill_between([x[0] * 0.8, x[-1] * 1.25], 1.0, 1 / (1 - rho), color=C_NODRIFT, alpha=0.08, lw=0)
    b.text(x[-1] * 1.15, 1.02, "double authority", fontsize=5.5, color=C_NODRIFT, ha="right", va="bottom")
    b.set_xscale("log")
    b.set_yscale("log")
    b.set_xlim(x[0] * 0.8, x[-1] * 1.25)
    b.set_ylim(min(0.9, ymin * 0.95), max(1.6, ymax * 1.25))
    yt = [1.0, bound] + [v for v in (2.0, 3.0, 4.0, 6.0) if v < ymax * 1.25]
    b.set_yticks(yt)
    b.set_yticklabels([f"{v:.2f}" if v == bound else f"{v:g}" for v in yt])
    b.yaxis.set_minor_formatter(matplotlib.ticker.NullFormatter())
    b.set_xticks(x)
    b.set_xticklabels([f"{v:g}" for v in x])
    b.set_xlabel("(b) tolerance $D$ (h)")
    b.set_ylabel("authority after / $D$ (log)")
    b.legend(loc="lower left", bbox_to_anchor=(-0.04, 1.0), ncol=2, frameon=False, fontsize=5.3,
             handlelength=1.3, columnspacing=0.5, borderaxespad=0.1, labelspacing=0.25)
    b.grid(alpha=0.25, lw=0.4)
    fig.tight_layout(pad=0.4, w_pad=1.0)
    OUT.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT / "tradeoff.pdf")
    fig.savefig(OUT / "tradeoff.png", dpi=220)
    print("wrote", OUT / "tradeoff.pdf")


def timeline(tag="v6_r1"):
    """End-to-end PureChain run: holds in effect per object and site (ending at the OBSERVED effect end), with the
    cut, stops and moves."""
    d = json.loads((ROOT / "experiments" / "results" / f"e2e_{tag}.json").read_text())
    ev = d["events"]
    first = lambda k, **kw: next(e for e in ev if e["kind"] == k and all(e.get(a) == b for a, b in kw.items()))
    cut, heal = first("uplink_cut", site=1)["t"], first("uplink_heal", site=1)["t"]
    t_end = max(e["t"] for e in ev if e["kind"] in ("exec", "op")) + 3
    ends = [e for e in ev if e["kind"] == "effect_end"]

    def observed_end(e):
        if e["until"] == 2**64 - 1:
            xs = [x["t"] for x in ends if x["site"] == e["site"] and x["obj"] == e["obj"] and x.get("hold") == e.get("hold")
                  and x["t"] >= e["t"]]
        else:
            xs = [x["t"] for x in ends if x["site"] == e["site"] and x["obj"] == e["obj"] and x["until"] == e["until"]
                  and x["epoch"] == e["epoch"]]
        return min(xs, default=None)

    lanes = ["P11", "L11", "C11", "P21", "P22"]
    y = {o: len(lanes) - 1 - k for k, o in enumerate(lanes)}
    col = {1: C_OURS, 2: "#e08a2c"}
    fig, ax = plt.subplots(figsize=(3.45, 1.8))
    ax.axvspan(cut, heal, color=C_NODRIFT, alpha=0.08, lw=0)
    ax.text((cut + heal) / 2, len(lanes) - 0.35, "site 1 uplink cut", ha="center", va="center", fontsize=5.5,
            color=C_NODRIFT)
    for e in ev:
        if e["kind"] == "exec" and e["obj"] in y:
            end = observed_end(e)
            end = end if end and end > e["t"] else t_end
            ax.add_patch(plt.Rectangle((e["t"], y[e["obj"]] - 0.17), end - e["t"], 0.34, color=col[e["site"]],
                                       alpha=0.55, lw=0))
        if e["kind"] == "lapse" and e["obj"] in y:
            ax.plot(e["t"], y[e["obj"]], "x", color="k", ms=2.6, mew=0.7)
    moves = [(first("reassigned_slow", obj="P11")["t"], "P11"), (first("reassign_acked", obj="L11")["t"], "L11"),
             (first("reassign_acked", obj="P21")["t"], "P21"), (first("reassign_acked", obj="P22")["t"], "P22")]
    for t, o in moves:
        ax.plot([t, t], [y[o] - 0.33, y[o] + 0.33], color=C_NODRIFT, lw=1.3)
    ax.plot(first("reassign_refused", obj="L11")["t"], y["L11"] + 0.33, "v", color=C_BOUND, ms=2.6, mew=0)
    for e in ev:
        if e["kind"] in ("stop", "revoke") and e["obj"] in y:
            ax.plot(e["t"], y[e["obj"]] + 0.33, "v", color="k", ms=2.6, mew=0)
    tr = first("clock_reset", site=2)["t"]
    ax.axvline(tr, color=C_BOUND, lw=0.6, ls=":")
    ax.text(tr, y["P22"] - 0.5, "S2 power loss", fontsize=5, ha="center", va="center", color=C_BOUND)
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


def storm(tag="v6", pub="v6"):
    """(a) Reconnection storm on G: time until each site holds a renewal again, against the number of sites that
    reconnect at once. (b) Renewal gas against the number of objects in one batch (public testnet)."""
    d = json.loads((ROOT / "experiments" / "results" / f"storm_{tag}.json").read_text())
    p = json.loads((ROOT / "experiments" / "results" / f"pubtest_{pub}.json").read_text())
    fig, (a, b) = plt.subplots(1, 2, figsize=(3.45, 1.45))
    ns = [r["sites"] for r in d["runs"]]
    for key, lab, style in (("median", "median", "-o"), ("p90", "90th pct.", "--s"), ("max", "max", ":^")):
        a.plot(ns, [r["renewed_s"][key] for r in d["runs"]], style, color=C_OURS, ms=2.5, lw=0.9, label=lab)
    a.set_xlabel("sites reconnecting at once")
    a.set_ylabel("renewed after (s)")
    a.set_yticks([0, 5, 10])
    a.set_xscale("log")
    a.set_xticks(ns)
    a.get_xaxis().set_major_formatter(matplotlib.ticker.ScalarFormatter())
    a.set_ylim(bottom=0)
    a.legend(frameon=False, loc="upper left", handlelength=1.6)
    a.grid(alpha=0.25, lw=0.4)
    a.set_title("(a)", fontsize=7, pad=2)
    sw = p["renew_batch_sweep"]
    xs = sorted(int(k) for k in sw)
    b.plot(xs, [sw[str(x)]["gas"] / 1000 for x in xs], "-o", color=C_OURS, ms=2.5, lw=0.9)
    b.set_xlabel("objects per batch renewal")
    b.set_ylabel("gas (k)")
    b.set_xticks(xs)
    b.set_ylim(bottom=0)
    b.grid(alpha=0.25, lw=0.4)
    b.set_title("(b)", fontsize=7, pad=2)
    fig.tight_layout(pad=0.3, w_pad=0.8)
    fig.savefig(OUT / "storm.pdf")
    fig.savefig(OUT / "storm.png", dpi=220)
    print("wrote", OUT / "storm.pdf")


if __name__ == "__main__":
    tradeoff()
    timeline()
    storm()
