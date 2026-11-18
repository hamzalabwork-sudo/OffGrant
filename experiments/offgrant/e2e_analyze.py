"""Summary of an end-to-end run (experiments/results/e2e_<tag>.json)."""
import json
import statistics as st
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main(tag="v1"):
    d = json.loads((ROOT / "experiments" / "results" / f"e2e_{tag}.json").read_text())
    ev = d["events"]
    p = d["params"]
    first = lambda k, **kw: next(e for e in ev if e["kind"] == k and all(e.get(a) == b for a, b in kw.items()))
    cut = first("uplink_cut", site=1)["t"]
    heal = first("uplink_heal", site=1)["t"]
    ops = [e for e in ev if e["kind"] == "op"]
    rt = lambda o: o["t"] - o.get("latency", 0.0)   # submission time, when the clock was read
    ren = [e for e in ev if e["kind"] == "renewal"]
    out = {"params": p}

    # Slow path: P11 held by cut-off site 1, moved to site 2.
    stop11 = first("stop", obj="P11")
    rea11 = first("reassigned_slow", obj="P11")
    last_send_1 = max(r["t_send"] for r in ren if r["site"] == 1 and r["obj"] == "P11" and r["t_send"] < cut + 5)
    use11_s1 = [rt(o) for o in ops if o["site"] == 1 and o["obj"] == "P11" and o.get("ok")]
    use11_s2 = [rt(o) for o in ops if o["site"] == 2 and o["obj"] == "P11" and o.get("ok")]
    t_rea = rea11["t"]
    out["slow_path"] = {
        "W_s": p["W_s"],
        "stop_to_reassign_s": round(t_rea - stop11["t"], 1),
        "g_release_minus_stop_g": rea11["g_time"] - stop11["g_time"],
        "site1_last_use_after_lastsend_s": round(max(use11_s1) - last_send_1, 1) if use11_s1 else None,
        "site1_allowance_real_s": round(p["A_ms"] / 1000 / (1 + p["drift"]["1"]), 1),
        "site1_last_use_before_reassign_s": round(t_rea - max(use11_s1), 1) if use11_s1 else None,
        "site2_first_use_after_reassign_s": round(min(t for t in use11_s2 if t > t_rea) - t_rea, 1)
        if any(t > t_rea for t in use11_s2) else None,
    }
    # Revocation of C11 while site 1 is cut off.
    rev = first("revoke", obj="C11")
    c11 = [rt(o) for o in ops if o["site"] == 1 and o["obj"] == "C11" and o.get("ok")]
    stale = [t for t in c11 if t >= rev["t"]]
    out["revocation"] = {"accepted_after_revoke": len(stale),
                         "max_window_s": round(max(stale) - rev["t"], 1) if stale else 0.0,
                         "bound_s": p["W_s"],
                         "stop_applied_after_heal_s": round(first("stop_applied", obj="C11")["t"] - heal, 1)}
    # Fast path: P21 held by connected site 2, moved to site 1.
    stop21 = first("stop", obj="P21")
    ack = first("reassign_acked", obj="P21")
    use21_s2 = [rt(o) for o in ops if o["site"] == 2 and o["obj"] == "P21" and o.get("ok")]
    use21_s1 = [rt(o) for o in ops if o["site"] == 1 and o["obj"] == "P21" and o.get("ok")]
    out["fast_path"] = {"stop_to_reassign_s": round(ack["t"] - stop21["t"], 1), "gas_reassignAcked": ack["gas"],
                        "site2_uses_after_ack": sum(1 for t in use21_s2 if t > ack["t"]),
                        "site1_first_use_after_ack_s": round(min(t for t in use21_s1 if t > ack["t"]) - ack["t"], 1)
                        if any(t > ack["t"] for t in use21_s1) else None}
    # Clock reset at site 2.
    rst = first("clock_reset", site=2)["t"]
    s2_use = [o for o in ops if o["site"] == 2 and o["op"] in ("use", "cred") and o["t"] > rst]
    ok_after = [o["t"] for o in s2_use if o.get("ok")]
    rej_after = [o["t"] for o in s2_use if not o.get("ok")]
    out["clock_reset"] = {"rejected_after_reset": len([t for t in rej_after if not ok_after or t < min(ok_after)]),
                          "first_accept_after_reset_s": round(min(ok_after) - rst, 1) if ok_after else None}
    # Availability of site 1 during the cut, per class.
    av = {}
    for cls in ("use", "cred", "consume", "log"):
        xs = [o for o in ops if o["site"] == 1 and o["op"] == cls and cut <= o["t"] < heal]
        av[cls] = f"{sum(1 for o in xs if o.get('ok'))}/{len(xs)}"
    out["site1_during_cut"] = av
    lat = [o["latency"] for o in ops if o.get("ok") and "latency" in o]
    out["op_latency_s"] = {"median": round(st.median(lat), 2), "max": round(max(lat), 2)}
    # Finality: an exclusive use takes effect once the checkpoint covering its block is sealed.
    cks = [e for e in ev if e["kind"] == "checkpoint"]
    fin = []
    for o in ops:
        if o.get("ok") and o["op"] in ("use", "cred") and "block" in o:
            c = next((c for c in cks if c["site"] == o["site"] and c.get("lo", 0) <= o["block"] < c.get("hi", -1)), None)
            if c:
                fin.append(c["t"] - rt(o))
    if fin:
        out["finality_latency_s"] = {"n": len(fin), "median": round(st.median(fin), 1), "max": round(max(fin), 1)}
    rl = [r["latency"] for r in ren]
    out["renewal_latency_s"] = {"median": round(st.median(rl), 2), "max": round(max(rl), 2)}
    gas = {}
    for o in ops:
        if o.get("ok") and "gas" in o:
            gas.setdefault(o["op"], []).append(o["gas"])
    out["gas_median"] = {k: int(st.median(v)) for k, v in gas.items()}
    out["gas_median"]["renew_G"] = int(st.median(r["gas_g"] for r in ren))
    out["gas_median"]["applyRenewal"] = int(st.median(r["gas_site"] for r in ren))
    anc = [e for e in ev if e["kind"] == "anchor"]
    out["anchor"] = {"n": len(anc), "ok": sum(1 for a in anc if a["status"] == 1),
                     "gas_median": int(st.median(a["gas"] for a in anc)),
                     "ops_median": int(st.median(a["ops"] for a in anc))}
    out["stop_gas"] = {e["obj"]: e["gas"] for e in ev if e["kind"] in ("stop", "revoke")}
    out["applyStop_gas"] = [e["gas"] for e in ev if e["kind"] == "stop_applied"]
    out["attacks"] = d["attacks"]
    print(json.dumps(out, indent=1))
    (ROOT / "experiments" / "results" / f"e2e_{tag}_summary.json").write_text(json.dumps(out, indent=1))


if __name__ == "__main__":
    main(*sys.argv[1:])
