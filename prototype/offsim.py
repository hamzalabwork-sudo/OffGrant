"""Discrete-event simulation (v4) of industrial sites whose uplinks fail, comparing rights-scoped offline
operation (OffGrant) with baselines and ablations on identical traces (paired within a run: same outages, power
losses, requests, clocks). Every run draws its own trace (seed and grid point), so runs are independent.

Sites hold exclusive objects (permits held for a duration), credentials (operators) and resource shares (spare
parts). G reassigns objects and revokes credentials at random times (the same decisions for every protocol);
sites learn of them only while connected. Operation classes:
  X  hold an exclusive object for h        conflict = a hold in effect while G gives the object to another site
  V  accept an operator credential         stale = acceptance after revocation
  B  consume one unit of a capped resource over-consumption = units beyond the global cap
  C  append a commutative record (log)     never conflicts
Protocols:
  ours      site ledger + send-time leases (A = D(1+rho)), G waits A/(1-rho) + 2 eps_G; a grant takes effect
            when its checkpoint is final (delay F) and only if a fresh clock reading is still inside the hold
            window and the allowance; holds must end inside the allowance; shares + online reserve
  global    one ledger spanning all sites: a cut-off site can finalize nothing (halts, no conflicts)
  discard   accept everything offline; on reconnection discard the whole offline set if any operation in it
            conflicts (DTNB / Zi-Cong rule)
  crdt      accept everything offline and merge (Vegvisir-style): no exclusivity, no rollback
  timestamp accept offline, on reconnection drop conflicting operations by timestamp (SWORD-style)
  waitrel   wait for release: sites keep rights while cut off with no expiry; G moves an object only after
            the old holder acknowledges (its holds ended) and revokes only when the site reconnects
Ablations of OffGrant:
  nodrift   A = D and G waits D + 1 s (absolute clock-error bound, no drift; Chen et al.-style)
  noepoch   no clock epochs (the TPM clock stops during a power loss; the allowance resumes afterwards)
  nofresh   no fresh check at execution: the hold runs for h from its (delayed) execution
Sites also lose power (about weekly, 5 min to 4 h): they are then down and their trusted clock stops.
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
PROTOCOLS = ["ours", "global", "discard", "crdt", "timestamp", "waitrel", "nodrift", "noepoch", "nofresh"]
LEASES = ("ours", "nodrift", "noepoch", "nofresh")
SHARES = LEASES + ("waitrel",)


@dataclass
class Cfg:
    seed: int = 0
    trace: int = 0                # grid point: with seed, selects an independent trace
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
    slack: float = 2.0            # eps_G: G timestamp error (the wait adds 2 eps_G)
    F: float = 15.0               # site finality delay: grant -> final checkpoint -> gateway execution
    hold_min: float = 600.0       # permit hold duration, uniform in [hold_min, hold_max] (s)
    hold_max: float = 7200.0
    permit_rate_day: float = 10.0          # per object at its intended holder
    reassign_rate_day: float = 3.0         # global
    min_gap_days: float = 7.0              # decisions on one object at least this far apart
    auth_rate_day: float = 4.0             # per operator
    revoke_rate_day: float = 1.0           # global
    insider_days: float = 3.0              # a revoked operator keeps trying for this long
    consume_rate_day: float = 50.0         # per site
    cap_factor: float = 0.95               # cap / expected total demand
    share_frac: float = 0.8                # shares issued in advance; rest is an online reserve
    log_rate_day: float = 1440.0           # per site (one per minute)
    power_rate_per_week: float = 1.0       # site power losses
    power_min: float = 300.0
    power_max: float = 4 * 3600.0


# ------------------------------------------------------------------------------------------ traces
def _merge(iv):
    merged = []
    for a, b in sorted(iv):
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    return merged


def outages(rng, cfg: Cfg):
    """Outage intervals of one site: Starlink-like micro outages (about 0.8 per hour, lognormal, median 0.9 s,
    at most 31 s), minute-long outages (about 2 per day, 50-75 s) and long outages (about weekly, uniform in
    [L/2, L])."""
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
    return _merge(iv)


class Link:
    def __init__(self, iv):
        self.iv = iv
        self.starts = [a for a, _ in iv]

    def down_at(self, t):
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
        d = self.down_at(t)
        return t if d is None else d[0]


class Timeline:
    """Piecewise-constant holder of one object: [(t_from, site), ...]."""

    def __init__(self, first):
        self.t = [0.0]
        self.s = [first]

    def add(self, t, s):
        self.t.append(t)
        self.s.append(s)

    def at(self, t):
        return self.s[bisect.bisect_right(self.t, t) - 1]

    def foreign(self, s, a, b):
        """Seconds within [a, b) during which the holder is not s."""
        if b <= a:
            return 0.0
        tot = 0.0
        k = bisect.bisect_right(self.t, a) - 1
        while k < len(self.t) and self.t[k] < b:
            lo = max(a, self.t[k])
            hi = min(b, self.t[k + 1]) if k + 1 < len(self.t) else b
            if self.s[k] != s and hi > lo:
                tot += hi - lo
            k += 1
        return tot


# ------------------------------------------------------------------------------------------ model
class World:
    def __init__(self, cfg: Cfg):
        self.cfg = cfg
        rng = np.random.default_rng([cfg.seed, cfg.trace])
        T = cfg.days * DAY
        S = cfg.sites
        self.T = T
        raw = [outages(rng, cfg) for _ in range(S)]
        self.power = []
        for _ in range(S):
            n = rng.poisson(cfg.power_rate_per_week * T / (7 * DAY))
            self.power.append(Link(_merge([a, a + rng.uniform(cfg.power_min, cfg.power_max)]
                                          for a in rng.uniform(0, T, n))))
        # A site without power cannot communicate either: its link is down during power losses.
        self.links = [Link(_merge([list(x) for x in raw[s]] + [list(x) for x in self.power[s].iv]))
                      for s in range(S)]
        self.drift = rng.uniform(-cfg.rho, cfg.rho, S)          # actual clock rate is 1 + drift
        if cfg.clock == "slow":
            self.drift = np.full(S, -cfg.rho)
        self.phase = rng.uniform(0, cfg.P, S)
        n_obj = S * cfg.objects_per_site
        self.home = [o // cfg.objects_per_site for o in range(n_obj)]
        # Decisions (the same for every protocol): per object, (t_decide, from, to), at least min_gap apart.
        n = rng.poisson(cfg.reassign_rate_day * cfg.days)
        raw_dec = sorted((float(t), int(rng.integers(n_obj)), int(rng.integers(S)))
                         for t in rng.uniform(0, T * 0.9, n))
        self.decisions = {o: [] for o in range(n_obj)}
        cur = list(self.home)
        last = [-math.inf] * n_obj
        for t, o, to in raw_dec:
            if to == cur[o] or t - last[o] < cfg.min_gap_days * DAY:
                continue
            self.decisions[o].append((t, cur[o], to))
            cur[o], last[o] = to, t
        self.intended = {}
        for o in range(n_obj):
            tl = Timeline(self.home[o])
            for t, _, to in self.decisions[o]:
                tl.add(t, to)
            self.intended[o] = tl
        n_op = S * cfg.operators_per_site
        n = rng.poisson(cfg.revoke_rate_day * cfg.days)
        ops = rng.choice(n_op, size=min(n, n_op), replace=False)
        self.revocations = {int(o): float(t) for o, t in zip(ops, rng.uniform(0, T * 0.9, len(ops)))}
        self.op_site = [o // cfg.operators_per_site for o in range(n_op)]
        # Permit requests: (time, asking site, hold duration in site-clock seconds).
        self.permit_req = []
        for _ in range(n_obj):
            k = rng.poisson(cfg.permit_rate_day * cfg.days * 2)
            self.permit_req.append((np.sort(rng.uniform(0, T, k)), rng.integers(0, S, k),
                                    rng.uniform(cfg.hold_min, cfg.hold_max, k)))
        self.auth_req = [np.sort(rng.uniform(0, T, rng.poisson(cfg.auth_rate_day * cfg.days)))
                         for _ in range(n_op)]
        for op, t_rev in self.revocations.items():   # a revoked insider keeps trying at four times the rate
            n = rng.poisson(cfg.auth_rate_day * cfg.insider_days * 4)
            extra = rng.uniform(t_rev, min(T, t_rev + cfg.insider_days * DAY), n)
            self.auth_req[op] = np.sort(np.concatenate([self.auth_req[op], extra]))
        self.consume_req = [np.sort(rng.uniform(0, T, rng.poisson(cfg.consume_rate_day * cfg.days)))
                            for _ in range(S)]
        self.log_req = [np.sort(rng.uniform(0, T, rng.poisson(cfg.log_rate_day * cfg.days))) for _ in range(S)]

    def powered(self, s, t):
        return self.power[s].up(t)

    def auth_end(self, s, start, A, epoch=True):
        """Real time at which A site-clock seconds counted from `start` end at site s. The clock runs at
        1 + drift and stops during power losses: with epochs a power loss ends the interval at once; without,
        it resumes after power returns."""
        rate = 1 + self.drift[s]
        end = start + A / rate
        pw = self.power[s]
        if pw.down_at(start) is not None:
            return start
        k = bisect.bisect_right(pw.starts, start)
        while k < len(pw.iv) and pw.iv[k][0] < end:
            a, b = pw.iv[k]
            if epoch:
                return a
            end += b - a
            k += 1
        return end

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


def lease_params(cfg: Cfg, proto: str):
    """(allowance in site-clock seconds, G wait after the last renewal)."""
    if proto == "nodrift":
        return cfg.D, cfg.D + 1.0
    A = cfg.D * (1 + cfg.rho)
    return A, A / (1 - cfg.rho) + 2 * cfg.slack


# ------------------------------------------------------------------------------------------ X: permits
def simulate_permits(w: World, proto: str):
    cfg = w.cfg
    lease = proto in LEASES
    epoch = proto != "noepoch"
    A, W = lease_params(cfg, proto) if lease else (0.0, 0.0)
    n_obj = len(w.home)
    out = dict(req=0, req_out=0, acc=0, acc_out=0, conflicts=0, overlap=0.0, acc_sets=[], conflict_sets=[],
               authority_after=[], reassign_delay=[], idle=[])
    for o in range(n_obj):
        decs = w.decisions[o]
        # Per decision: when the stop reaches the old holder, and (leases) the last renewal before it.
        applied, release, ts_last = [], [], []
        for t_d, fr, to in decs:
            ap = w.links[fr].next_up(t_d) + cfg.rtt / 2
            applied.append(ap)
            if lease:
                ts = w.last_answered_send(fr, t_d, not_after=t_d)
                ts_last.append(ts)
                last_issue = (ts + cfg.rtt / 2) if ts is not None else -math.inf
                release.append(max(t_d, last_issue + W))
            else:
                ts_last.append(None)
                release.append(math.inf)
        # Requests of this object in time order; the switch of waitrel depends on holds still running.
        times, asker, hold = w.permit_req[o]
        max_hold_before = [0.0] * len(decs)      # waitrel: latest end of the old holder's holds before `applied`
        switch = [None] * len(decs)

        def switch_of(i, t):
            """Time from which the new holder of decision i may act (final once t >= applied[i])."""
            if switch[i] is not None:
                return switch[i]
            t_d = decs[i][0]
            if proto in ("global", "discard", "crdt", "timestamp"):
                sw = t_d
            elif proto == "waitrel":
                if t < applied[i]:
                    return math.inf
                sw = max(applied[i] + cfg.rtt / 2, max_hold_before[i])
            else:   # leases: release time, or the acknowledged fast path once every hold ended
                fast = max(applied[i] + cfg.rtt / 2, max_hold_before[i])
                sw = min(release[i], fast) if t >= applied[i] else release[i]
                if t < applied[i]:
                    return sw
            switch[i] = sw
            return sw

        grants = []   # (s, e0, e1, offline, t)
        for t, s, h in zip(times, asker, hold):
            s = int(s)
            if not w.powered(s, t):
                continue
            # The site asks only for objects it believes it holds (the intended holder as of its last contact).
            if w.intended[o].at(w.links[s].last_up(t)) != s:
                continue
            offline = not w.links[s].up(t)
            out["req"] += 1
            out["req_out"] += offline
            # Which decision made s holder, and is s still entitled at t?
            idx_in = max((i for i, d in enumerate(decs) if d[2] == s and d[0] <= t), default=-1)
            idx_out = next((i for i, d in enumerate(decs) if d[1] == s and d[0] > (decs[idx_in][0] if idx_in >= 0 else -1)), None)
            if idx_in < 0 and w.home[o] != s:
                continue
            start_ok = 0.0 if idx_in < 0 else switch_of(idx_in, t)
            if t < start_ok:
                continue
            e0 = e1 = None
            if proto == "global":
                if offline:
                    continue
                e0, e1 = t + cfg.F, t + cfg.F + h
            elif proto in ("discard", "crdt", "timestamp"):
                e0, e1 = t, t + h
            elif proto == "waitrel":
                if idx_out is not None and t >= applied[idx_out]:
                    continue
                e0 = t + cfg.F
                e1 = w.auth_end(s, e0, h, True)
            else:
                b = decs[idx_out][0] if idx_out is not None else math.inf
                ap = applied[idx_out] if idx_out is not None else math.inf
                if t >= ap:
                    continue
                ts = w.last_answered_send(s, t, not_after=b)
                if ts is None or ts + cfg.rtt / 2 < start_ok:
                    continue
                end_auth = w.auth_end(s, ts, A, epoch)
                hold_end = w.auth_end(s, t, h, epoch)          # hold window measured on the site clock
                if t >= end_auth or hold_end > end_auth:       # SiteRights: grant and hold end inside allowance
                    continue
                e0 = t + cfg.F
                if proto == "nofresh":
                    e1 = w.auth_end(s, e0, h, epoch)           # runs for h from the delayed execution
                    if not w.powered(s, e0):
                        continue
                else:
                    if e0 >= hold_end or not w.powered(s, e0) or e0 >= ap:   # fresh check at execution
                        continue
                    e1 = hold_end
            out["acc"] += 1
            out["acc_out"] += offline
            if offline:
                out["acc_sets"].append((s, w.links[s].down_at(t)[0]))
            grants.append((s, e0, e1, offline, t))
            # waitrel and the fast path: the old holder's acknowledgement waits for its running holds.
            for i, d in enumerate(decs):
                if d[1] == s and t < applied[i] and d[0] > (decs[idx_in][0] if idx_in >= 0 else -1):
                    max_hold_before[i] = max(max_hold_before[i], e1)
                    break
        # Holder timeline in force, and conflicts: any part of a hold while another site holds the object.
        tl = Timeline(w.home[o])
        for i, (t_d, fr, to) in enumerate(decs):
            sw = switch_of(i, math.inf)
            tl.add(sw, to)
            out["reassign_delay"].append(sw - t_d)
            if lease:
                ts = ts_last[i]
                old_end = 0.0 if ts is None else min(w.auth_end(fr, ts, A, epoch), applied[i])
            elif proto == "waitrel":
                old_end = sw
            elif proto == "global":
                old_end = t_d
            else:
                old_end = w.links[fr].next_up(t_d)
            out["authority_after"].append(max(0.0, old_end - t_d))
            out["idle"].append(max(0.0, sw - max(t_d, old_end)))
        if proto != "global":
            for s, e0, e1, offline, t in grants:
                f = tl.foreign(s, e0, e1)
                if f > 0:
                    out["conflicts"] += 1
                    out["overlap"] = max(out["overlap"], f)
                    if offline:
                        out["conflict_sets"].append((s, w.links[s].down_at(t)[0]))
    return out


# ------------------------------------------------------------------------------------------ V: credentials
def simulate_auth(w: World, proto: str):
    cfg = w.cfg
    lease = proto in LEASES
    epoch = proto != "noepoch"
    A, W = lease_params(cfg, proto) if lease else (0.0, 0.0)
    res = dict(req=0, req_out=0, acc=0, acc_out=0, stale_acc=0, stale_max=0.0, conflict_sets=[],
               acc_sets=[], window=[])
    for op, t_rev in w.revocations.items():
        s = w.op_site[op]
        applied = w.links[s].next_up(t_rev) + cfg.rtt / 2
        if proto == "global":
            res["window"].append(0.0)
        elif lease:
            ts = w.last_answered_send(s, t_rev, not_after=t_rev)
            end = 0.0 if ts is None else min(w.auth_end(s, ts, A, epoch), applied)
            res["window"].append(max(0.0, end - t_rev))
        else:
            res["window"].append(applied - t_rev)
    for op, reqs in enumerate(w.auth_req):
        s = w.op_site[op]
        t_rev = w.revocations.get(op, math.inf)
        lk = w.links[s]
        applied = lk.next_up(t_rev) + cfg.rtt / 2 if t_rev < math.inf else math.inf
        for t in reqs:
            if not w.powered(s, t):
                continue
            offline = not lk.up(t)
            res["req"] += 1
            res["req_out"] += offline
            te = t   # time the acceptance takes effect
            if proto == "global":
                ok = not offline and t < t_rev
            elif lease:
                ts = w.last_answered_send(s, t, not_after=t_rev)
                end = w.auth_end(s, ts, A, epoch) if ts is not None else -math.inf
                te = t + cfg.F
                if proto == "nofresh":
                    ok = t < end and t < applied
                else:
                    ok = te < end and te < applied and w.powered(s, te)
            else:   # merge baselines and waitrel: the site learns of the revocation at its next contact
                ok = t < applied
            if not ok:
                continue
            res["acc"] += 1
            res["acc_out"] += offline
            if offline:
                res["acc_sets"].append((s, lk.down_at(t)[0]))
            if te >= t_rev:
                res["stale_acc"] += 1
                res["stale_max"] = max(res["stale_max"], te - t_rev)
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
    used = 0.0
    shares = proto in SHARES
    if shares:
        share = [cfg.share_frac * cap / S] * S
        reserve = cap - sum(share)
        local = [0.0] * S
    known = [0.0] * S
    off_used = [0.0] * S
    for t, s in events:
        if not w.powered(s, t):
            continue
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
        px = simulate_permits(w, proto)
        pv = simulate_auth(w, proto)
        pb = simulate_consume(w, proto)
        c_out = sum(sum(1 for t in r if w.powered(s, t) and not w.links[s].up(t)) for s, r in enumerate(w.log_req))
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
        rd = px["reassign_delay"]
        out[proto] = dict(
            X_avail_out=px["acc_out"] / max(1, px["req_out"]),
            X_avail=px["acc"] / max(1, px["req"]),
            X_req_out=px["req_out"],
            X_conflicts=px["conflicts"],
            X_overlap_max=px["overlap"],
            X_reassign_delay_mean=float(np.mean(rd)) if rd else 0.0,
            X_reassign_delay_max=max(rd) if rd else 0.0,
            X_idle_mean=float(np.mean(px["idle"])) if px["idle"] else 0.0,
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
    ap.add_argument("--out", default="experiments/results/offsim_v4.jsonl")
    ap.add_argument("--seeds", type=int, default=20)
    ap.add_argument("--workers", type=int, default=os.cpu_count())
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    Ds = [1 * HOUR, 6 * HOUR, 24 * HOUR, 72 * HOUR]
    Ls = [2.5 * HOUR, 24 * HOUR, 72 * HOUR]
    clocks = [(100e-6, "uniform"), (0.15, "uniform"), (0.15, "slow")]
    grid = [(rho, ck, L, D) for rho, ck in clocks for L in Ls for D in Ds]
    cfgs = [Cfg(seed=s, trace=g, D=D, L=L, rho=rho, clock=ck)
            for g, (rho, ck, L, D) in enumerate(grid) for s in range(args.seeds)]
    if args.quick:
        cfgs = [Cfg(seed=0, trace=999, days=5, rho=0.15, D=6 * HOUR, L=24 * HOUR)]
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with Pool(args.workers) as pool, open(args.out, "w") as f:
        for r in pool.imap_unordered(run, cfgs):
            f.write(json.dumps(r) + "\n")
            f.flush()


if __name__ == "__main__":
    main()
