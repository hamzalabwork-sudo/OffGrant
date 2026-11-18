"""Summary of an end-to-end run of OffGrant (contracts v5) (experiments/results/e2e_<tag>.json).

Effect times are those of the site gateway: a grant takes effect when the gateway executes it (once final, with a
fresh clock reading) and, for a bounded hold, lasts until the hold's end on the site clock (converted to real time
with the site's drift). Safety is checked on these effect intervals against the time each object moved."""
import json
import statistics as st
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main(tag="v5"):
    d = json.loads((ROOT / "experiments" / "results" / f"e2e_{tag}.json").read_text())
    ev, p = d["events"], d["params"]
    first = lambda k, **kw: next((e for e in ev if e["kind"] == k and all(e.get(a) == b for a, b in kw.items())), None)
    cut, heal = first("uplink_cut", site=1)["t"], first("uplink_heal", site=1)["t"]
    ops = [e for e in ev if e["kind"] == "op"]
    ex = [e for e in ev if e["kind"] == "exec"]
    lapse = [e for e in ev if e["kind"] == "lapse"]
    ren = [e for e in ev if e["kind"] == "renewal"]
    out = {"params": p}

    # Every move of an exclusive object: the old holder's last effect must end before the move.
    moves = [(e["obj"], e["t"], "slow") for e in ev if e["kind"] == "reassigned_slow"] + \
            [(e["obj"], e["t"], "acked") for e in ev if e["kind"] == "reassign_acked" and e["status"] == 1]
    releases = [o for o in ops if o["op"] == "release" and o.get("ok")]

    def effect_end(e):
        if e.get("until") == 2**64 - 1:   # open hold: lasts until its release
            return min((r["t"] for r in releases if r["site"] == e["site"] and r["obj"] == e["obj"] and r["t"] > e["t"]),
                       default=float("inf"))
        return e.get("hold_end_t", e["t"])

    safety = {}
    for o, t_move, how in moves:
        old = next(e["site"] for e in ev if e["kind"] == "reassign_acked" and e["obj"] == o) if how == "acked" \
            else int(o[1])
        started = [e for e in ex if e["obj"] == o and e["site"] == old and e["t"] < t_move]
        late_start = [e for e in ex if e["obj"] == o and e["site"] == old and e["t"] >= t_move]
        ends = [effect_end(e) for e in started]
        last_end = max(ends, default=None)
        safety[o] = {"path": how, "moved_at": t_move, "old_holder": old, "old_effects": len(started),
                     "last_effect_end": last_end,
                     "margin_s": round(t_move - last_end, 2) if last_end is not None else None,
                     "effects_ending_after_move": sum(1 for x in ends if x > t_move),
                     "effects_starting_after_move": len(late_start)}
    out["effect_safety"] = safety

    # Grants that lapsed: the gateway refused them at execution (window or allowance passed, or new epoch).
    out["lapses"] = {"n": len(lapse), "by_obj": {}}
    for e in lapse:
        out["lapses"]["by_obj"][e["obj"]] = out["lapses"]["by_obj"].get(e["obj"], 0) + 1
    out["exec_n"] = len(ex)
    fin = [e["t"] - e["grant_t"] for e in ex]
    out["grant_to_effect_s"] = {"median": round(st.median(fin), 1), "max": round(max(fin), 1)} if fin else None

    # Slow path for P11.
    stop11, rea11 = first("stop", obj="P11"), first("reassigned_slow", obj="P11")
    last_send_1 = max(r["t_send"] for r in ren if r["site"] == 1 and "P11" in r["objs"] and r["t_send"] < cut + 5)
    allow_real = p["A_ms"] / 1000 / (1 + p["drift"]["1"])
    s1_p11 = [e for e in ex if e["site"] == 1 and e["obj"] == "P11"]
    lap_p11 = [e for e in lapse if e["site"] == 1 and e["obj"] == "P11" and e["t"] > cut]
    out["slow_path_P11"] = {
        "W_s": p["W_s"], "stop_to_reassign_s": round(rea11["t"] - stop11["t"], 1) if rea11 else None,
        "allowance_end_after_last_send_s": round(allow_real, 1),
        "allowance_end_t": round(last_send_1 + allow_real, 1), "reassigned_t": rea11["t"] if rea11 else None,
        "last_effect_end_t": max((max(e["t"], e.get("hold_end_t", e["t"])) for e in s1_p11), default=None),
        "lapsed_after_cut": len(lap_p11),
    }
    # Open hold L11: refused by the slow path, moved by the fast path once the lock was released.
    out["open_hold_L11"] = {
        "slow_path": first("reassign_refused", obj="L11"),
        "acked": first("reassign_acked", obj="L11"),
        "ack_after_heal_s": round(first("reassign_acked", obj="L11")["t"] - heal, 1)
        if first("reassign_acked", obj="L11") else None,
        "release_ops": [o["t"] for o in ops if o["op"] == "release" and o.get("ok")],
    }
    # Revocation of C11 while site 1 is cut off: credential effects after the revocation.
    rev = first("revoke", obj="C11")
    c11 = [e["t"] for e in ex if e["site"] == 1 and e["obj"] == "C11"]
    stale = [t for t in c11 if t >= rev["t"]]
    out["revocation_C11"] = {"effects_after_revoke": len(stale),
                             "max_window_s": round(max(stale) - rev["t"], 1) if stale else 0.0, "bound_W_s": p["W_s"]}
    # Fast path for P21.
    stop21, ack21 = first("stop", obj="P21"), first("reassign_acked", obj="P21")
    applied21 = first("stop_applied", obj="P21")
    out["fast_path_P21"] = {"stop_to_reassign_s": round(ack21["t"] - stop21["t"], 1) if ack21 else None,
                            "stop_to_site_s": round(applied21["t"] - stop21["t"], 1) if applied21 else None,
                            "stop_seen_to_reassign_s": ack21.get("latency_from_stop_seen") if ack21 else None,
                            "gas_reassignAcked": ack21["gas"] if ack21 else None}
    acks = [e for e in ev if e["kind"] == "ack_op"]
    out["ack_ops"] = {"n": len(acks), "gas_median": int(st.median(a["gas"] for a in acks)) if acks else None,
                      "refused": sum(1 for e in ev if e["kind"] == "ack_refused")}
    # Share lowering at site 2: applied on the site ledger, capacity freed on G from a sealed checkpoint.
    low, app, conf = first("share_lowered"), first("share_applied", site=2), first("share_confirmed", site=2)
    out["share_lowering"] = {"lowered_t": low["t"] if low else None, "applied_t": app["t"] if app else None,
                             "confirmed_t": conf["t"] if conf else None,
                             "confirm_gas": conf["gas"] if conf else None,
                             "refused": [e for e in ev if e["kind"] == "share_refused"][:3]}
    # Renewal cadence per object (batch renewals), and renewals that got through during the cut or flapping.
    cad = []
    for k in (1, 2):
        per = {}
        for r in ren:
            if r["site"] == k:
                for o in r["objs"]:
                    per.setdefault(o, []).append(r["t"])
        for ts in per.values():
            cad += [b - a for a, b in zip(ts, ts[1:]) if b - a < 60]
    out["renewal_interval_per_object_s"] = {"median": round(st.median(cad), 1), "p90": round(sorted(cad)[int(0.9 * len(cad))], 1)} if cad else None
    out["site1_renewals_during_cut"] = sum(1 for r in ren if r["site"] == 1 and cut <= r["t"] < heal)
    out["site1_anchors_during_cut"] = sum(1 for a in ev if a["kind"] == "anchor" and a["site"] == 1 and cut <= a["t"] < heal and a["status"] == 1)
    # Clock reset at site 2.
    rst = first("clock_reset", site=2)["t"]
    out["clock_reset"] = {
        "lapsed_old_epoch": sum(1 for e in lapse if e["site"] == 2 and e["now_epoch"] != e["epoch"]),
        "first_effect_after_reset_s": round(min((e["t"] for e in ex if e["site"] == 2 and e["t"] > rst), default=rst) - rst, 1),
        "renew_refused_after_reset": sum(1 for e in ev if e["kind"] == "renew_refused" and e["site"] == 2 and e["t"] > rst)}
    # Catch-up after the outage: one anchor covers every checkpoint sealed while cut off.
    anc = [e for e in ev if e["kind"] == "anchor"]
    a_heal = next((a for a in anc if a["site"] == 1 and a["t"] >= heal and a["status"] == 1), None)
    out["catch_up"] = {"anchor_after_heal_s": round(a_heal["t"] - heal, 1) if a_heal else None,
                       "checkpoints_covered": a_heal["covers"] if a_heal else None,
                       "gas": a_heal["gas"] if a_heal else None}
    out["anchors"] = {"n": len(anc), "ok": sum(1 for a in anc if a["status"] == 1),
                      "failed": [a for a in anc if a["status"] != 1],
                      "gas_median": int(st.median(a["gas"] for a in anc if a["status"] == 1))}
    out["checkpoints"] = {"n": sum(1 for e in ev if e["kind"] == "checkpoint"),
                          "all_agree": all(e["agree"] == 4 for e in ev if e["kind"] == "checkpoint")}
    av = {}
    for cls in ("use", "cred", "lock", "consume", "log"):
        xs = [o for o in ops if o["site"] == 1 and o["op"] == cls and cut <= o["t"] < heal]
        av[cls] = f"{sum(1 for o in xs if o.get('ok'))}/{len(xs)}"
    out["site1_during_cut_recorded"] = av
    eff_cut = [e for e in ex if e["site"] == 1 and cut <= e["grant_t"] < heal]
    lap_cut = [e for e in lapse if e["site"] == 1 and cut <= e["grant_t"] < heal]
    out["site1_during_cut_effects"] = {"executed": len(eff_cut), "lapsed": len(lap_cut)}
    lat = [o["latency"] for o in ops if o.get("ok") and "latency" in o]
    out["op_latency_s"] = {"median": round(st.median(lat), 2), "max": round(max(lat), 2)}
    rl = [r["latency"] for r in ren]
    out["renewal_latency_s"] = {"median": round(st.median(rl), 2), "max": round(max(rl), 2), "n": len(rl)}
    gas = {}
    for o in ops:
        if o.get("ok") and "gas" in o:
            gas.setdefault(o["op"], []).append(o["gas"])
    out["gas_median"] = {k: int(st.median(v)) for k, v in gas.items()}
    out["gas_median"]["renew_G"] = int(st.median(r["gas_g"] for r in ren))
    out["gas_median"]["applyRenewal"] = int(st.median(r["gas_site"] for r in ren))
    out["stop_gas"] = {e["obj"]: e["gas"] for e in ev if e["kind"] in ("stop", "revoke")}
    out["errors"] = [e for e in ev if e["kind"] in ("relayer_error", "ckpt_error", "op_error")][:10]
    out["attacks"] = d["attacks"]
    print(json.dumps(out, indent=1))
    (ROOT / "experiments" / "results" / f"e2e_{tag}_summary.json").write_text(json.dumps(out, indent=1))


if __name__ == "__main__":
    main(*sys.argv[1:])
