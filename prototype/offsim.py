"""Discrete-event simulation of industrial sites whose uplinks fail, comparing rights-scoped offline
operation (ours) with five baselines on identical traces (paired: same outages, requests, clocks).

Sites hold exclusive objects (lockout/tagout permits), credentials (operators) and resource shares
(spare parts). The global ledger G reassigns objects and revokes credentials at random times; sites
learn of it only while connected. Operation classes:
  X  exercise an exclusive object (permit)       conflict = exercise after G gave the object away
  V  accept an operator credential               staleness = acceptance after revocation
  B  consume one unit of a capped resource       over-consumption = units beyond the global cap
  C  append a commutative record (log)           never conflicts
Protocols:
  ours      site ledger + send-time leases with A = D(1+rho), G waits A/(1-rho) (+slack); shares + online reserve
  global    one ledger spanning all sites: a cut-off site can finalize nothing (halts, no conflicts)
  discard   site chain accepts everything offline; on reconnection the whole offline set is discarded if
            any operation in it conflicts (DTNB / Zi-Cong rule)
  crdt      accept everything offline and merge (Vegvisir-style): no exclusivity, no rollback
  timestamp accept offline, on reconnection drop conflicting operations by timestamp (SWORD-style)
  nodrift   leases with A = D and G waiting D + 1 s: absolute clock-error bound, no drift (Chen et al.-style)
"""
from __future__ import annotations

import argparse
import bisect
import json
import math
import os
from dataclasses import dataclass, asdict
from multiprocessing import Pool

import numpy as np

DAY = 86400.0
HOUR = 3600.0
PROTOCOLS = ["ours", "global", "discard", "crdt", "timestamp", "nodrift"]


@dataclass
class Cfg:
    seed: int = 0
    days: float = 30.0
    sites: int = 3
    objects_per_site: int = 10
    operators_per_site: int = 50
    rho: float = 100e-6           # drift bound assumed by the protocol (TPM 2.0 spec allows 0.15)
    clock: str = "uniform"        # actual drift: "uniform" in [-rho, rho], or "slow" (every site at -rho)
    D: float = 6 * HOUR           # offline tolerance
    L: float = 24 * HOUR          # longest outage of the scenario
    long_rate_per_week: float = 1.0
    P: float = 60.0               # renewal period while connected
    rtt: float = 0.5
    slack: float = 2.0            # G timestamp slack
    permit_rate_day: float = 10.0          # per object at its believed holder
    reassign_rate_day: float = 3.0         # global
    auth_rate_day: float = 4.0             # per operator
    revoke_rate_day: float = 1.0           # global
    insider_days: float = 3.0              # a revoked operator keeps trying for this long
    consume_rate_day: float = 50.0         # per site
    cap_factor: float = 0.95               # cap / expected total demand
    share_frac: float = 0.8                # shares issued in advance; rest is an online reserve
    log_rate_day: float = 1440.0           # per site (one per minute)


# ------------------------------------------------------------------------------------------ traces
def outages(rng, cfg: Cfg):
    """Merged outage intervals of one site: Starlink-like micro outages, minute clusters, long outages."""
    T = cfg.days * DAY
    iv = []
    n = rng.poisson(0.8 * T / HOUR)
    for s in rng.uniform(0, T, n):
        iv.append((s, s + min(31.0, rng.lognormal(math.log(0.9), 0.8))))
    n = rng.poisson(2.0 * T / DAY)
    for s in rng.uniform(0, T, n):
        iv.append((s, s + rng.uniform(50, 75)))
    n = rng.poisson(cfg.long_rate_per_week * T / (7 * DAY))
    for s in rng.uniform(0, T, n):
        iv.append((s, s + rng.uniform(cfg.L / 2, cfg.L)))
    iv.sort()
    merged = []
    for a, b in iv:
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    return merged


class Link:
    def __init__(self, iv):
        self.iv = iv
        self.starts = [a for a, _ in iv]

    def down_at(self, t):
        """Outage interval containing t, or None."""
        k = bisect.bisect_right(self.starts, t) - 1
        if k >= 0 and self.iv[k][0] <= t < self.iv[k][1]:
            return self.iv[k]
        return None

    def up(self, t):
        return self.down_at(t) is None

    def next_up(self, t):
        d = self.down_at(t)
        return t if d is None else d[1]

    def last_up(self, t):
        """Latest moment <= t at which the link was up."""
        d = self.down_at(t)
        return t if d is None else d[0]


# ------------------------------------------------------------------------------------------ model
class World:
    def __init__(self, cfg: Cfg):
        self.cfg = cfg
        rng = np.random.default_rng(cfg.seed)
        self.rng = rng
        T = cfg.days * DAY
        S = cfg.sites
        self.T = T
        self.links = [Link(outages(rng, cfg)) for _ in range(S)]
        self.drift = rng.uniform(-cfg.rho, cfg.rho, S)          # actual clock rate is 1 + drift
        if cfg.clock == "slow":
            self.drift = np.full(S, -cfg.rho)
        self.phase = rng.uniform(0, cfg.P, S)
        n_obj = S * cfg.objects_per_site
        self.home = [o // cfg.objects_per_site for o in range(n_obj)]
        # Reassignments: (t_decide, object, to_site), at most one pending per object.
        n = rng.poisson(cfg.reassign_rate_day * cfg.days)
        self.reassign = sorted(
            (float(t), int(rng.integers(n_obj)), int(rng.integers(S))) for t in rng.uniform(0, T * 0.9, n)
        )
        # Revocations: (t_revoke, operator).
        n_op = S * cfg.operators_per_site
        n = rng.poisson(cfg.revoke_rate_day * cfg.days)
        ops = rng.choice(n_op, size=min(n, n_op), replace=False)
        self.revocations = {int(o): float(t) for o, t in zip(ops, rng.uniform(0, T * 0.9, len(ops)))}
        self.op_site = [o // cfg.operators_per_site for o in range(n_op)]
        # Request streams (thinned later by belief).
        self.permit_req = [np.sort(rng.uniform(0, T, rng.poisson(cfg.permit_rate_day * cfg.days * 2)))
                           for _ in range(n_obj)]
        self.permit_site = [rng.integers(0, S, len(r)) for r in self.permit_req]   # who asks (filtered by belief)
        self.auth_req = [np.sort(rng.uniform(0, T, rng.poisson(cfg.auth_rate_day * cfg.days)))
                         for _ in range(n_op)]
        # A revoked operator (insider) keeps trying at four times the normal rate for insider_days.
        for op, t_rev in self.revocations.items():
            n = rng.poisson(cfg.auth_rate_day * cfg.insider_days * 4)
            extra = rng.uniform(t_rev, min(T, t_rev + cfg.insider_days * DAY), n)
            self.auth_req[op] = np.sort(np.concatenate([self.auth_req[op], extra]))
        self.consume_req = [np.sort(rng.uniform(0, T, rng.poisson(cfg.consume_rate_day * cfg.days)))
                            for _ in range(S)]
        self.log_req = [np.sort(rng.uniform(0, T, rng.poisson(cfg.log_rate_day * cfg.days))) for _ in range(S)]

    # Renewal helpers for the lease protocols ---------------------------------------------------
    def last_answered_send(self, s, t, not_after=math.inf):
        """Real time of the latest renewal request of site s that G answered and s received by time t,
        with G issuing it no later than `not_after`. Requests leave every P (phase) while the link is up."""
        cfg = self.cfg
        lk = self.links[s]
        horizon = min(lk.last_up(t), not_after + cfg.rtt / 2, t) - cfg.rtt
        k = math.floor((horizon - self.phase[s]) / cfg.P)
        for _ in range(100000):
            ts = self.phase[s] + k * cfg.P
            if ts < 0:
                return None
            if lk.up(ts) and lk.up(ts + cfg.rtt):
                return ts
            k -= 1
        return None

    def first_send_after(self, s, t0):
        """First answered request of site s sent at or after t0 (G issues it at once)."""
        cfg = self.cfg
        lk = self.links[s]
        k = math.ceil((t0 - self.phase[s]) / cfg.P)
        while True:
            ts = self.phase[s] + k * cfg.P
            if ts > self.T:
                return None
            if lk.up(ts) and lk.up(ts + cfg.rtt):
                return ts
            k += 1


def lease_params(cfg: Cfg, proto: str):
    """(allowance in site-clock seconds, G wait after the last renewal)."""
    if proto == "nodrift":
        return cfg.D, cfg.D + 1.0
    A = cfg.D * (1 + cfg.rho)
    return A, A / (1 - cfg.rho) + cfg.slack


# ------------------------------------------------------------------------------------------ X: permits
def simulate_permits(w: World, proto: str):
    """Returns per-request outcomes and per-reassignment authority overlap."""
    cfg = w.cfg
    lease = proto in ("ours", "nodrift")
    A, W = lease_params(cfg, proto) if lease else (0.0, 0.0)
    n_obj = len(w.home)
    # Holder timeline per object at G: list of (t_from, site); for leases the switch happens at release.
    timeline = {o: [(0.0, w.home[o])] for o in range(n_obj)}
    pending_until = {o: -1.0 for o in range(n_obj)}
    overlap = []           # seconds during which the old holder could still exercise after the new one may
    authority_after = []   # seconds after G's decision during which the old holder could still exercise
    reassign_delay = []    # G decision -> new holder may exercise
    decided = {o: [] for o in range(n_obj)}  # (t_decide, from, to) actually executed
    stop_applied = {}      # (object, old holder, t_decide) -> when the old holder applied the stop
    for t_d, o, to in w.reassign:
        cur = timeline[o][-1][1]
        if to == cur or t_d < pending_until[o]:
            continue
        if lease:
            ts = w.last_answered_send(cur, t_d, not_after=t_d)
            last_issue = (ts + cfg.rtt / 2) if ts is not None else 0.0
            release = max(t_d, last_issue + W)
            # Fast path: the old holder applies the certified stop at its next contact and its quorum
            # acknowledges; the object moves then if that is earlier than the release time.
            applied = w.links[cur].next_up(t_d) + cfg.rtt / 2
            switch = min(release, applied + cfg.rtt / 2)
            # Real end of the old holder's authority under its actual drift.
            expiry = (ts + A / (1 + w.drift[cur])) if ts is not None else 0.0
            end = min(expiry, applied)
            overlap.append(max(0.0, end - switch))
            authority_after.append(max(0.0, end - t_d))
            stop_applied[(o, cur, t_d)] = applied
        else:
            switch = t_d
            # The old holder keeps acting on its belief until it reconnects (global: never, it halts).
            authority_after.append(0.0 if proto == "global" else w.links[cur].next_up(t_d) - t_d)
        timeline[o].append((switch, to))
        decided[o].append((t_d, cur, to, switch))
        pending_until[o] = switch
        reassign_delay.append(switch - t_d)

    def g_holder(o, t):
        tl = timeline[o]
        k = bisect.bisect_right([a for a, _ in tl], t) - 1
        return tl[k][1]

    def believed_holder(s, o, t):
        """What site s believes at time t: G's holder as of s's last connected moment (exact for G's
        immediate switch; leases additionally need a valid renewal, checked separately)."""
        return g_holder(o, w.links[s].last_up(t)) == s

    # Lease protocols: windows [start, end) during which G issues renewals of o to s
    # (from becoming holder until G decides to move o away).
    windows = {}
    for o in range(n_obj):
        start = {w.home[o]: 0.0}
        for td, fr, to_, sw in decided[o]:
            windows.setdefault((o, fr), []).append((start.pop(fr), td, stop_applied.get((o, fr, td), math.inf)))
            start[to_] = sw
        for s, a in start.items():
            windows.setdefault((o, s), []).append((a, math.inf, math.inf))

    def lease_valid(o, s, t):
        wins = [x for x in windows.get((o, s), []) if x[0] <= t]
        if not wins:
            return False
        a, b, applied = wins[-1]
        if t >= applied:
            return False
        ts = w.last_answered_send(s, t, not_after=b)
        return ts is not None and ts + cfg.rtt / 2 >= a and t < ts + A / (1 + w.drift[s])

    res = dict(req=0, req_out=0, acc=0, acc_out=0, conflicts=0, conflict_sets=[], acc_sets=[])
    for o in range(n_obj):
        for t, s in zip(w.permit_req[o], w.permit_site[o]):
            s = int(s)
            if not believed_holder(s, o, t):
                continue
            offline = not w.links[s].up(t)
            res["req"] += 1
            res["req_out"] += offline
            if proto == "global":
                ok = not offline and g_holder(o, t) == s
            elif lease:
                ok = lease_valid(o, s, t)
            else:
                ok = True
            if not ok:
                continue
            res["acc"] += 1
            res["acc_out"] += offline
            if offline:
                res["acc_sets"].append((s, w.links[s].down_at(t)[0]))
            if g_holder(o, t) != s:
                res["conflicts"] += 1
                if offline:
                    res["conflict_sets"].append((s, w.links[s].down_at(t)[0]))
    res["authority_after"] = authority_after
    return res, overlap, reassign_delay


# ------------------------------------------------------------------------------------------ V: credentials
def simulate_auth(w: World, proto: str):
    cfg = w.cfg
    lease = proto in ("ours", "nodrift")
    A, W = lease_params(cfg, proto) if lease else (0.0, 0.0)
    res = dict(req=0, req_out=0, acc=0, acc_out=0, stale_acc=0, stale_max=0.0, conflict_sets=[],
               acc_sets=[], window=[])
    for op, t_rev in w.revocations.items():
        s = w.op_site[op]
        if proto == "global":
            res["window"].append(0.0)
        elif lease:
            ts = w.last_answered_send(s, t_rev, not_after=t_rev)
            applied = w.links[s].next_up(t_rev) + cfg.rtt / 2
            end = 0.0 if ts is None else min(ts + A / (1 + w.drift[s]), applied)
            res["window"].append(max(0.0, end - t_rev))
        else:
            res["window"].append(w.links[s].next_up(t_rev) - t_rev)
    for op, reqs in enumerate(w.auth_req):
        s = w.op_site[op]
        t_rev = w.revocations.get(op, math.inf)
        for t in reqs:
            lk = w.links[s]
            offline = not lk.up(t)
            res["req"] += 1
            res["req_out"] += offline
            if proto == "global":
                ok = not offline and t < t_rev
            elif lease:
                ts = w.last_answered_send(s, t, not_after=t_rev)
                applied = w.links[s].next_up(t_rev) + cfg.rtt / 2 if t_rev < math.inf else math.inf
                ok = ts is not None and t < ts + A / (1 + w.drift[s]) and t < applied
            else:
                # The site learns of the revocation at its first connected moment after it.
                ok = t < t_rev or t < lk.next_up(t_rev)
            if not ok:
                continue
            res["acc"] += 1
            res["acc_out"] += offline
            if offline:
                res["acc_sets"].append((s, lk.down_at(t)[0]))
            if t >= t_rev:
                res["stale_acc"] += 1
                res["stale_max"] = max(res["stale_max"], t - t_rev)
                if offline:
                    res["conflict_sets"].append((s, lk.down_at(t)[0]))
    return res


# ------------------------------------------------------------------------------------------ B: resource
def simulate_consume(w: World, proto: str):
    cfg = w.cfg
    S = cfg.sites
    cap = cfg.cap_factor * cfg.consume_rate_day * cfg.days * S
    events = sorted((float(t), s) for s in range(S) for t in w.consume_req[s])
    res = dict(req=0, req_out=0, acc=0, acc_out=0, over=0.0, conflict_sets=[], acc_sets=[])
    used = 0.0                     # globally consumed (truth)
    shares = proto in ("ours", "nodrift")
    if shares:
        share = [cfg.share_frac * cap / S] * S
        reserve = cap - sum(share)
        local = [0.0] * S
    known = [0.0] * S              # baselines: global consumption known to site s at last contact
    off_used = [0.0] * S
    for t, s in events:
        lk = w.links[s]
        offline = not lk.up(t)
        res["req"] += 1
        res["req_out"] += offline
        if proto == "global":
            ok = not offline and used + 1 <= cap
        elif shares:
            if local[s] + 1 > share[s] and not offline and reserve >= 10:
                share[s] += 10
                reserve -= 10
            ok = local[s] + 1 <= share[s]
            if ok:
                local[s] += 1
        else:
            if not offline:
                known[s] = used
                off_used[s] = 0.0
            ok = known[s] + off_used[s] + 1 <= cap
            if ok and offline:
                off_used[s] += 1
        if not ok:
            continue
        used += 1
        res["acc"] += 1
        res["acc_out"] += offline
        if offline:
            res["acc_sets"].append((s, lk.down_at(t)[0]))
        if used > cap:
            res["over"] += 1
            if offline:
                res["conflict_sets"].append((s, lk.down_at(t)[0]))
    return res


# ------------------------------------------------------------------------------------------ driver
def run(cfg: Cfg):
    w = World(cfg)
    out = {"cfg": asdict(cfg)}
    for proto in PROTOCOLS:
        px, overlap, rdelay = simulate_permits(w, proto)
        pv = simulate_auth(w, proto)
        pb = simulate_consume(w, proto)
        # C: logs. Available offline for every protocol except the global ledger.
        c_req = sum(len(r) for r in w.log_req)
        c_out = sum(sum(1 for t in r if not w.links[s].up(t)) for s, r in enumerate(w.log_req))
        # Offline sets with a conflict: discard rolls back every operation accepted in that outage;
        # timestamp rolls back only the conflicting operations.
        bad_sets = set(px["conflict_sets"]) | set(pv["conflict_sets"]) | set(pb["conflict_sets"])
        rolled = 0
        if proto == "discard":
            accepted = {}
            for k in px["acc_sets"] + pv["acc_sets"] + pb["acc_sets"]:
                accepted[k] = accepted.get(k, 0) + 1
            for s, start in bad_sets:
                end = w.links[s].down_at(start)[1]
                logs = int(((w.log_req[s] >= start) & (w.log_req[s] < end)).sum())
                rolled += accepted.get((s, start), 0) + logs
        elif proto == "timestamp":
            rolled = px["conflicts"] + pv["stale_acc"] + int(pb["over"])
        out[proto] = dict(
            X_avail_out=px["acc_out"] / max(1, px["req_out"]),
            X_avail=px["acc"] / max(1, px["req"]),
            X_conflicts=px["conflicts"],
            X_overlap_max=max(overlap) if overlap else 0.0,
            X_reassign_delay_max=max(rdelay) if rdelay else 0.0,
            X_authority_after=px["authority_after"],
            V_window=pv["window"],
            W_bound=lease_params(cfg, "ours")[1],
            V_avail_out=pv["acc_out"] / max(1, pv["req_out"]),
            V_stale_acc=pv["stale_acc"],
            V_stale_max=pv["stale_max"],
            B_avail_out=pb["acc_out"] / max(1, pb["req_out"]),
            B_over=pb["over"],
            C_avail_out=0.0 if proto == "global" else 1.0,
            C_out=c_out,
            rolled_back=rolled,
            offline_frac=float(np.mean([sum(b - a for a, b in lk.iv) / w.T for lk in w.links])),
        )
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="experiments/results/offsim.jsonl")
    ap.add_argument("--seeds", type=int, default=10)
    ap.add_argument("--workers", type=int, default=os.cpu_count())
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    Ds = [1 * HOUR, 6 * HOUR, 24 * HOUR, 72 * HOUR]
    Ls = [2.5 * HOUR, 24 * HOUR, 72 * HOUR]
    clocks = [(100e-6, "uniform"), (0.15, "uniform"), (0.15, "slow")]
    cfgs = [Cfg(seed=s, D=D, L=L, rho=rho, clock=ck)
            for rho, ck in clocks for L in Ls for D in Ds for s in range(args.seeds)]
    if args.quick:
        cfgs = [Cfg(seed=0, days=5)]
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with Pool(args.workers) as pool, open(args.out, "w") as f:
        for r in pool.imap_unordered(run, cfgs):
            f.write(json.dumps(r) + "\n")
            f.flush()


if __name__ == "__main__":
    main()
