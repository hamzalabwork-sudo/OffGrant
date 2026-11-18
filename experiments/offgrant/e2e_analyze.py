"""Summary of end-to-end runs of OffGrant (contracts v6) (experiments/results/e2e_<tag>.json).

Effect times are OBSERVED at the site gateway: a grant takes effect when the gateway executes it (once sealed, with
a fresh clock reading); a bounded hold ends when the actuator loop sees the clock pass the hold's end (or at a power
loss); an open hold ends when its crew's release is recorded. Safety is checked on these intervals against the time
each object moved on G.

  python e2e_analyze.py v6_r1                       one run -> e2e_v6_r1_summary.json
  python e2e_analyze.py --agg v6 v6_r1 v6_r2 v6_r3  several runs -> e2e_v6_agg.json (min / median / max)
"""
import json
import statistics as st
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RES = ROOT / "experiments" / "results"
OPEN = 2**64 - 1


def summarize(tag):
    d = json.loads((RES / f"e2e_{tag}.json").read_text())
    ev, p = d["events"], d["params"]
    first = lambda k, **kw: next((e for e in ev if e["kind"] == k and all(e.get(a) == b for a, b in kw.items())), None)
    cut, heal = first("uplink_cut", site=1)["t"], first("uplink_heal", site=1)["t"]
    ops = [e for e in ev if e["kind"] == "op"]
    ex = [e for e in ev if e["kind"] == "exec"]
    lapse = [e for e in ev if e["kind"] == "lapse"]
    ren = [e for e in ev if e["kind"] == "renewal"]
    ends = [e for e in ev if e["kind"] == "effect_end"]
    out = {"tag": tag, "params": p}

    def observed_end(e):
        if e["until"] == OPEN:
            xs = [x["t"] for x in ends if x["site"] == e["site"] and x["obj"] == e["obj"] and x["until"] == OPEN
                  and x.get("hold", e.get("hold")) == e.get("hold") and x["t"] >= e["t"]]
        else:
            xs = [x["t"] for x in ends if x["site"] == e["site"] and x["obj"] == e["obj"] and x["until"] == e["until"]
                  and x["epoch"] == e["epoch"]]
        return min(xs, default=float("inf"))

    # Every move of an exclusive object: each effect of the old holder must have ended (observed) before the move.
    moves = [(e["obj"], e["t"], "slow") for e in ev if e["kind"] == "reassigned_slow"] + \
            [(e["obj"], e["t"], "acked") for e in ev if e["kind"] == "reassign_acked" and e["status"] == 1]
    safety = {}
    for o, t_move, how in moves:
        old = next(e["site"] for e in ev if e["kind"] == "reassign_acked" and e["obj"] == o) if how == "acked" \
            else int(o[1])
        started = [e for e in ex if e["obj"] == o and e["site"] == old and e["t"] < t_move]
        late_start = [e for e in ex if e["obj"] == o and e["site"] == old and e["t"] >= t_move]
        e_ends = [observed_end(e) for e in started]
        last_end = max(e_ends, default=None)
        safety[o] = {"path": how, "moved_at": t_move, "old_holder": old, "old_effects": len(started),
                     "last_effect_end_observed": last_end,
                     "margin_s": round(t_move - last_end, 2) if last_end is not None else None,
                     "effects_ending_after_move": sum(1 for x in e_ends if x > t_move),
                     "effects_starting_after_move": len(late_start)}
    out["effect_safety"] = safety
    out["safe"] = all(v["effects_ending_after_move"] == 0 and v["effects_starting_after_move"] == 0
                      for v in safety.values())

    out["lapses"] = {"n": len(lapse), "by_obj": {}}
    for e in lapse:
        out["lapses"]["by_obj"][e["obj"]] = out["lapses"]["by_obj"].get(e["obj"], 0) + 1
    out["exec_n"] = len(ex)
    fin = [e["t"] - e["grant_t"] for e in ex]
    out["grant_to_effect_s"] = {"median": round(st.median(fin), 1), "max": round(max(fin), 1)} if fin else None

    # Slow path for P11, and what counting the allowance from the certificate's RECEIPT would have given.
    stop11, rea11 = first("stop", obj="P11"), first("reassigned_slow", obj="P11")
    allow_real = p["A_ms"] / 1000 / (1 + p["drift"]["1"])
    r11 = [r for r in ren if r["site"] == 1 and "P11" in r["objs"] and r["t"] < (stop11["t"] if stop11 else 1e9)]
    last11 = max(r11, key=lambda r: r["t_send"]) if r11 else None
    s1_p11 = [e for e in ex if e["site"] == 1 and e["obj"] == "P11"]
    out["slow_path_P11"] = {
        "W_s": p["W_s"], "stop_to_reassign_s": round(rea11["t"] - stop11["t"], 1) if rea11 and stop11 else None,
        "allowance_real_s": round(allow_real, 1),
        "allowance_end_from_send_t": round(last11["t_send"] + allow_real, 1) if last11 else None,
        "allowance_end_from_receipt_t": round(last11["t"] + allow_real, 1) if last11 else None,
        "last_renewal_latency_s": last11["latency"] if last11 else None,
        "reassigned_t": rea11["t"] if rea11 else None,
        "last_effect_end_observed_t": max((observed_end(e) for e in s1_p11), default=None),
        "lapsed_after_cut": sum(1 for e in lapse if e["site"] == 1 and e["obj"] == "P11" and e["t"] > cut),
    }
    if rea11 and last11:
        out["slow_path_P11"]["receipt_count_would_overlap_move"] = last11["t"] + allow_real > rea11["t"]

    # Open hold L11: refused by the slow path, moved by the fast path once released.
    ack_l = first("reassign_acked", obj="L11")
    out["open_hold_L11"] = {
        "slow_path": (first("reassign_refused", obj="L11") or {}).get("why"),
        "acked_t": ack_l["t"] if ack_l else None,
        "ack_after_heal_s": round(ack_l["t"] - heal, 1) if ack_l else None,
        "ack_waits": [(e["t"], e["why"]) for e in ev if e["kind"] == "ack_wait" and e["obj"] == "L11"],
        "releases": [o["t"] for o in ops if o["op"] == "release" and o.get("ok")],
    }
    # Locks: attempts, refused ones (gateway or site contract) and why; another crew's release attempt.
    lk = [o for o in ops if o["op"] == "lock" and o.get("obj")]
    why = {}
    for o in lk:
        if not o.get("ok"):
            why[o["why"]] = why.get(o["why"], 0) + 1
    out["locks"] = {"attempts": len(lk), "recorded": sum(1 for o in lk if o.get("ok")), "refused": why,
                    "other_crew_release": [o["why"] for o in ops if o["op"] == "release_other_crew"],
                    "wrong_crew_accepted": sum(1 for o in ops if o.get("why") == "WRONG CREW ACCEPTED")}
    # Gateway refusals of all kinds (no attestation was issued).
    gw = {}
    for o in ops:
        if not o.get("ok") and str(o.get("why", "")).startswith("gateway:"):
            gw[o["why"]] = gw.get(o["why"], 0) + 1
    out["gateway_refusals"] = gw

    rev = first("revoke", obj="C11")
    stale = [e["t"] for e in ex if e["site"] == 1 and e["obj"] == "C11" and e["t"] >= rev["t"]]
    out["revocation_C11"] = {"effects_after_revoke": len(stale),
                             "max_window_s": round(max(stale) - rev["t"], 1) if stale else 0.0, "bound_W_s": p["W_s"]}

    def fast(name):
        stop, ack, applied = first("stop", obj=name), first("reassign_acked", obj=name), first("stop_applied", obj=name)
        return {"stop_to_reassign_s": round(ack["t"] - stop["t"], 1) if ack and stop else None,
                "stop_to_site_s": round(applied["t"] - stop["t"], 1) if applied and stop else None,
                "stop_seen_to_reassign_s": ack.get("latency_from_stop_seen") if ack else None,
                "gas_reassignAcked": ack["gas"] if ack else None,
                "ack_waits": sorted({e["why"] for e in ev if e["kind"] == "ack_wait" and e["obj"] == name})}
    out["fast_path_P21"] = fast("P21")
    out["fast_path_P22_after_reset"] = fast("P22")
    carry = [e for e in ends if e.get("why") == "power_loss"]
    out["fast_path_P22_after_reset"]["holds_carried"] = len([e for e in carry if e["obj"] == "P22"])
    out["fast_path_P22_after_reset"]["carry_ms_max"] = max((e["carry_ms"] for e in carry if e["obj"] == "P22"),
                                                           default=None)
    acks = [e for e in ev if e["kind"] == "ack_op"]
    out["ack_ops"] = {"n": len(acks), "gas_median": int(st.median(a["gas"] for a in acks)) if acks else None,
                      "refused_by_contract": sum(1 for e in ev if e["kind"] == "ack_refused")}

    low, app, conf = first("share_lowered"), first("share_applied", site=2), first("share_confirmed", site=2)
    out["share_lowering"] = {"lowered_t": low["t"] if low else None, "applied_t": app["t"] if app else None,
                             "confirmed_t": conf["t"] if conf else None, "confirm_gas": conf["gas"] if conf else None}

    cad = []
    for k in (1, 2):
        per = {}
        for r in ren:
            if r["site"] == k:
                for o in r["objs"]:
                    per.setdefault(o, []).append(r["t"])
        for ts in per.values():
            cad += [b - a for a, b in zip(ts, ts[1:]) if b - a < 60]
    out["renewal_interval_per_object_s"] = {"median": round(st.median(cad), 1),
                                            "p90": round(sorted(cad)[int(0.9 * len(cad))], 1)} if cad else None
    out["site1_during_outage"] = {
        "renewals": sum(1 for r in ren if r["site"] == 1 and cut <= r["t"] < heal),
        "renew_sent": sum(1 for e in ev if e["kind"] == "renew_sent" and e["site"] == 1 and cut <= e["t"] < heal),
        "renew_fail": sum(1 for e in ev if e["kind"] == "renew_fail" and e["site"] == 1 and cut <= e["t"] < heal),
        "anchors_ok": sum(1 for a in ev if a["kind"] == "anchor" and a["site"] == 1 and cut <= a["t"] < heal
                          and a["status"] == 1)}
    sent = [r for r in ren if r["site"] == 1 and cut <= r["t_send"] < heal]
    out["site1_during_outage"]["renewal_latency_s"] = {"median": round(st.median(r["latency"] for r in sent), 2),
                                                       "max": round(max(r["latency"] for r in sent), 2)} if sent else None

    rst = first("clock_reset", site=2)["t"]
    out["clock_reset"] = {
        "lapsed_old_epoch": sum(1 for e in lapse if e["site"] == 2 and e["now_epoch"] != e["epoch"]),
        "first_effect_after_reset_s": round(min((e["t"] for e in ex if e["site"] == 2 and e["t"] > rst), default=rst) - rst, 1),
        "renew_refused_after_reset": sum(1 for e in ev if e["kind"] == "renew_refused" and e["site"] == 2 and e["t"] > rst)}

    anc = [e for e in ev if e["kind"] == "anchor"]
    a_heal = next((a for a in anc if a["site"] == 1 and a["t"] >= heal and a["status"] == 1), None)
    out["catch_up"] = {"anchor_after_heal_s": round(a_heal["t"] - heal, 1) if a_heal else None,
                       "checkpoints_covered": a_heal["covers"] if a_heal else None,
                       "gas": a_heal["gas"] if a_heal else None}
    onchain = d.get("anchors_onchain", [])
    logged = {(a["site"], a["height"]) for a in anc if a["status"] == 1}
    chain = {(a["site"], a["height"]) for a in onchain}
    out["anchors"] = {"logged_ok": len(logged), "onchain": len(chain), "unlogged": sorted(chain - logged),
                      "logged_not_onchain": sorted(logged - chain),
                      "sent": sum(1 for e in ev if e["kind"] == "anchor_sent"),
                      "fail": sum(1 for e in ev if e["kind"] == "anchor_fail"),
                      "gas_median": int(st.median(a["gas"] for a in anc if a["status"] == 1)) if anc else None}
    cks = [e for e in ev if e["kind"] == "checkpoint"]
    out["checkpoints"] = {"n": len(cks), "all_agree": all(e["agree"] == 4 for e in cks),
                          "retries": sum(1 for e in ev if e["kind"] == "ckpt_retry"),
                          "second_checkpoint_refused": sum(1 for e in ev if e["kind"] == "refuse_second_checkpoint"),
                          "halted": [e for e in ev if e["kind"] == "halt_reorg"],
                          "state_len_max": max((e.get("state_len", 0) for e in cks), default=0)}
    av = {}
    for cls in ("use", "cred", "lock", "consume", "log"):
        xs = [o for o in ops if o["site"] == 1 and o["op"] == cls and cut <= o["t"] < heal]
        av[cls] = f"{sum(1 for o in xs if o.get('ok'))}/{len(xs)}"
    out["site1_during_outage_recorded"] = av
    out["site1_during_outage_effects"] = {
        "executed": sum(1 for e in ex if e["site"] == 1 and cut <= e["grant_t"] < heal),
        "lapsed": sum(1 for e in lapse if e["site"] == 1 and cut <= e["grant_t"] < heal)}
    lat = [o["latency"] for o in ops if o.get("ok") and "latency" in o]
    out["op_latency_s"] = {"median": round(st.median(lat), 2), "max": round(max(lat), 2)} if lat else None
    rl = [r["latency"] for r in ren]
    out["renewal_latency_s"] = {"median": round(st.median(rl), 2), "max": round(max(rl), 2), "n": len(rl)} if rl else None
    gas = {}
    for o in ops:
        if o.get("ok") and "gas" in o:
            gas.setdefault(o["op"], []).append(o["gas"])
    out["gas_median"] = {k: int(st.median(v)) for k, v in gas.items()}
    by_n = {}
    for r in ren:
        by_n.setdefault(len(r["objs"]), []).append(r["gas_g"])
    out["gas_median"]["renew_G_by_batch_size"] = {n: int(st.median(v)) for n, v in sorted(by_n.items())}
    if ren:
        out["gas_median"]["applyRenewal"] = int(st.median(r["gas_site"] for r in ren))
    out["stop_gas"] = {e["obj"]: e["gas"] for e in ev if e["kind"] in ("stop", "revoke")}
    out["errors"] = [e for e in ev if e["kind"] in ("relayer_error", "ckpt_error", "op_error")][:10]
    att = d["attacks"]
    out["attacks"] = att
    slashing = {k: v for k, v in att.items() if isinstance(v, dict) and "slashed" in v}
    out["attacks_ok"] = all(v["status"] == 1 and v["slashed"] >= 2 for v in slashing.values())
    out["rejections_ok"] = all(v["rejected"] for v in att.values() if isinstance(v, dict) and "rejected" in v)
    nf = att["no_framing"]
    out["no_framing_ok"] = set(nf["verdicts"]) <= {"NotAViolation"}
    (RES / f"e2e_{tag}_summary.json").write_text(json.dumps(out, indent=1))
    return out


def aggregate(name, tags):
    runs = [summarize(t) for t in tags]

    def col(f):
        xs = []
        for r in runs:
            try:
                v = f(r)
            except (KeyError, TypeError):
                v = None
            if v is not None:
                xs.append(v)
        return {"min": min(xs), "median": round(st.median(xs), 2), "max": max(xs), "n": len(xs)} if xs else None

    agg = {
        "runs": tags,
        "all_safe": all(r["safe"] for r in runs),
        "all_attacks_slashed": all(r["attacks_ok"] for r in runs),
        "all_forgeries_rejected": all(r["rejections_ok"] for r in runs),
        "all_no_framing": all(r["no_framing_ok"] for r in runs),
        "no_framing_attempts": sum(r["attacks"]["no_framing"]["proof_attempts_on_honest_data"] for r in runs),
        "unlogged_anchors": sum(len(r["anchors"]["unlogged"]) for r in runs),
        "margin_P11_s": col(lambda r: r["effect_safety"]["P11"]["margin_s"]),
        "margin_L11_s": col(lambda r: r["effect_safety"]["L11"]["margin_s"]),
        "margin_P21_s": col(lambda r: r["effect_safety"]["P21"]["margin_s"]),
        "margin_P22_s": col(lambda r: r["effect_safety"]["P22"]["margin_s"]),
        "P22_stop_to_reassign_s": col(lambda r: r["fast_path_P22_after_reset"]["stop_to_reassign_s"]),
        "P21_stop_to_reassign_s": col(lambda r: r["fast_path_P21"]["stop_to_reassign_s"]),
        "L11_ack_after_heal_s": col(lambda r: r["open_hold_L11"]["ack_after_heal_s"]),
        "catch_up_s": col(lambda r: r["catch_up"]["anchor_after_heal_s"]),
        "catch_up_checkpoints": col(lambda r: r["catch_up"]["checkpoints_covered"]),
        "renewal_latency_median_s": col(lambda r: r["renewal_latency_s"]["median"]),
        "renewal_latency_max_s": col(lambda r: r["renewal_latency_s"]["max"]),
        "site1_outage_renewals": col(lambda r: r["site1_during_outage"]["renewals"]),
        "site1_outage_renewal_latency_max_s": col(lambda r: r["site1_during_outage"]["renewal_latency_s"]["max"]),
        "lock_attempts": col(lambda r: r["locks"]["attempts"]),
        "locks_refused": col(lambda r: sum(r["locks"]["refused"].values())),
        "lapses": col(lambda r: r["lapses"]["n"]),
        "executed": col(lambda r: r["exec_n"]),
        "receipt_count_would_overlap": [r["slow_path_P11"].get("receipt_count_would_overlap_move") for r in runs],
        "gas_anchor_median": col(lambda r: r["anchors"]["gas_median"]),
        "gas_reassignAcked": col(lambda r: r["fast_path_P21"]["gas_reassignAcked"]),
    }
    (RES / f"e2e_{name}_agg.json").write_text(json.dumps(agg, indent=1))
    print(json.dumps(agg, indent=1))


if __name__ == "__main__":
    if sys.argv[1] == "--agg":
        aggregate(sys.argv[2], sys.argv[3:])
    else:
        print(json.dumps(summarize(sys.argv[1] if len(sys.argv) > 1 else "v6"), indent=1))
