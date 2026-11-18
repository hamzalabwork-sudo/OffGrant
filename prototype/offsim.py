"""Discrete-event simulation (v5) of industrial sites whose uplinks fail, comparing rights-scoped offline
operation (OffGrant) with baselines and ablations on identical traces (paired within a run: same outages, power
losses, requests, clocks, message delays, finality delays and G timestamp errors). Every run draws its own trace
(seed and grid point), so runs are independent.

Sites hold exclusive objects (permits held for a duration), credentials (operators) and resource shares (spare
parts). G reassigns objects and revokes credentials at random times (the same decisions for every protocol);
sites learn of them through delayed messages. Operation classes:
  X  hold an exclusive object for h        authority overlap = a hold in effect while G gives the object to
                                           another site; double use = executed holds of two sites overlap
  V  accept an operator credential         stale = acceptance after revocation
  B  consume one unit of a capped resource over-consumption = units beyond the global cap
  C  append a commutative record (log)     never conflicts
Protocols:
  ours      site ledger + send-time leases (A = D(1+rho)), G waits W = ceil(A/(1-rho)) + 2 eps_G; a grant takes
            effect when its checkpoint is final (sampled delay F) and only if a fresh clock reading is still
            inside the hold end and the allowance; holds must end inside the allowance; shares + online reserve
  global    one ledger spanning all sites: a cut-off site can finalize nothing (halts, no conflicts)
  discard   accept everything offline; on reconnection discard the whole offline set if any operation in it
            conflicts (DTNB / Zi-Cong rule)
  crdt      accept everything offline and merge (Vegvisir-style): no exclusivity, no rollback
  timestamp accept offline, on reconnection drop conflicting operations by timestamp (SWORD-style)
  waitrel   wait for release: sites keep rights while cut off with no expiry; G moves an object only after
            the old holder acknowledges (its holds ended) and revokes only when the site reconnects
Ablations of OffGrant (each drops exactly one rule):
  nodrift   A = D and W = ceil(D) + 2 eps_G (a lease that ignores clock drift)
  noepoch   no clock epochs (the TPM clock stops during a power loss; the allowance resumes afterwards)
  nofresh   no fresh check at execution: the hold runs for its full length from its (delayed) execution
  nohold    no hold-end rule: a hold may start inside the allowance and runs its full requested length
  receipt   the allowance is counted from the RECEIPT of the renewal response instead of the request's send
  eps1      G waits ceil(A/(1-rho)) + eps_G (one eps_G only)
Sites also lose power (about weekly, 5 min to 4 h): they are then down and their trusted clock stops.

v5 changes (after review round 3; see docs/SIMULATOR.md, "Changes in v5"):
  * Fair handover (R06 M1): when the old holder is connected at a decision, EVERY protocol (merging baselines
    and the global chain included) lets holds already running finish before the new holder may act; when it is
    cut off, merging baselines cannot know of its offline holds and the new holder acts at once. Conflicts are
    computed for the global chain too and asserted to be zero.
  * Two conflict metrics (R09 M4.3): authority overlaps (as before) and double use (executed holds overlap).
  * Rollbacks split into exclusive/credential/consumption operations and commutative log records (R09 M4.2).
  * New ablations nohold, receipt, eps1 (R06 M2); G timestamp error; heavy-tailed message delays with
    store-and-forward delivery; sampled finality delay F; a share of "max-fit" permit requests (the e2e
    workload) so that holds can end at the allowance edge, where the hold-end, send-time, 2 eps_G and fresh
    rules bite.
  * Calibrated rates (R06 M3): 10 permit requests per object per day at the holder, 3 moves and 1 revocation
    per day of G's decision window; measured rates and the longest continuous offline period are written per run.
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
MERGES = ("discard", "crdt", "timestamp")
LEASES = ("ours", "nodrift", "noepoch", "nofresh", "nohold", "receipt", "eps1")
PROTOCOLS = ["ours", "global"] + list(MERGES) + ["waitrel"] + list(LEASES[1:])
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
    L: float = 24 * HOUR          # longest single outage drawn (merged outages can be longer)
    long_rate_per_week: float = 1.0
    P: float = 60.0               # renewal period while connected
    rtt: float = 0.5              # request leg = rtt/2; acknowledgement leg = rtt/2
    eps_G: float = 2.0            # G timestamp error bound: each G timestamp errs uniformly in [-eps_G, eps_G]
    # Message delay of G -> site messages (renewal responses, stops, notices): a mixture, see msg_delays().
    d_fast_lo: float = 0.3
    d_fast_hi: float = 1.0
    d_slow_p: float = 0.04        # log-uniform in [1 s, 60 s]
    d_vslow_p: float = 0.01       # log-uniform in [60 s, 1800 s]
    # Finality delay F (grant -> final checkpoint -> gateway execution), sampled per operation, see finality().
    F_med: float = 15.0
    F_sigma: float = 0.3
    F_stall_p: float = 0.01       # a consensus stall (round changes) adds uniform [F_stall_min, F_stall_max]
    F_stall_min: float = 60.0
    F_stall_max: float = 900.0
    hold_min: float = 600.0       # permit hold duration, uniform in [hold_min, hold_max] (s)
    hold_max: float = 7200.0
    maxfit_frac: float = 0.2      # share of permit requests that accept a shortened hold ("as long as allowed")
    fit_min: float = 60.0         # shortest useful shortened hold (site-clock s)
    permit_rate_day: float = 10.0          # per object at the site that believes it holds it
    decide_frac: float = 0.9               # G decides during [0, decide_frac * T] (effects fall inside the run)
    reassign_rate_day: float = 3.0         # global, per day of the decision window
    min_gap_days: float = 7.0              # moves of one object at least this far apart
    auth_rate_day: float = 4.0             # per operator
    revoke_rate_day: float = 1.0           # global, per day of the decision window
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
    [L/2, L]). Overlapping outages merge, so a continuous offline period can exceed L."""
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


def msg_delays(rng, cfg: Cfg, n):
    """Delivery delay of G -> site messages (an assumed stress model, not fitted to a measured trace):
    with probability 1 - p_slow - p_vslow uniform in [0.3 s, 1 s]; with p_slow (4%) log-uniform in [1 s, 60 s];
    with p_vslow (1%) log-uniform in [60 s, 30 min]. A message whose nominal arrival falls in an outage of the
    site is delivered when the outage ends (store-and-forward, e.g. a persistent message-queue session)."""
    u = rng.random(n)
    d = rng.uniform(cfg.d_fast_lo, cfg.d_fast_hi, n)
    slow = np.exp(rng.uniform(0.0, math.log(60.0), n))
    vslow = np.exp(rng.uniform(math.log(60.0), math.log(1800.0), n))
    d = np.where(u < cfg.d_slow_p, slow, d)
    d = np.where((u >= cfg.d_slow_p) & (u < cfg.d_slow_p + cfg.d_vslow_p), vslow, d)
    return d


def finality(rng, cfg: Cfg, n):
    """Finality delay F per operation (assumed model): F_med * lognormal(0, F_sigma) (about 8-27 s for 95% of
    operations), plus, with probability F_stall_p (1%), a consensus stall of 1-15 min (uniform)."""
    f = cfg.F_med * rng.lognormal(0.0, cfg.F_sigma, n)
    stall = rng.random(n) < cfg.F_stall_p
    return f + np.where(stall, rng.uniform(cfg.F_stall_min, cfg.F_stall_max, n), 0.0)


class Link:
    """Merged down intervals of a site (outages and power losses)."""

    def __init__(self, iv):
        self.iv = iv
        self.starts = [a for a, _ in iv]
        self.a = np.array([a for a, _ in iv] or [np.inf])
        self.b = np.array([b for _, b in iv] or [np.inf])

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

    def down_mask(self, t):
        k = np.searchsorted(self.a, t, side="right") - 1
        kk = np.maximum(k, 0)
        return (k >= 0) & (t >= self.a[kk]) & (t < self.b[kk]), kk

    def next_up_vec(self, t):
        down, kk = self.down_mask(t)
        return np.where(down, self.b[kk], t)

    def downtime(self, a, b):
        """Seconds of [a, b) inside down intervals."""
        tot = 0.0
        k = max(0, bisect.bisect_right(self.starts, a) - 1)
        while k < len(self.iv) and self.iv[k][0] < b:
            lo, hi = max(a, self.iv[k][0]), min(b, self.iv[k][1])
            if hi > lo:
                tot += hi - lo
            k += 1
        return tot


class Timeline:
    """Piecewise-constant holder of one object: [(t_from, site), ...]."""

    def __init__(self, first):
        self.t = [0.0]
        self.s = [first]

    def add(self, t, s):
        self.t.append(max(t, self.t[-1]))   # moves of one object are >= 7 days apart; keep it monotone anyway
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


class Responses:
    """Renewal responses received by one site, sorted by arrival, for queries 'best renewal usable at t'."""

    def __init__(self, ts, ti, arr):
        o = np.argsort(arr, kind="stable")
        self.arr = arr[o].tolist()
        self.ts = ts[o].tolist()
        self.ti = ti[o].tolist()
        self.pmax_ts = np.maximum.accumulate(ts[o]).tolist() if len(o) else []


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
        # Renewals. A request leaves every P while the site's link is up and reaches G after rtt/2 if the link is
        # still up (otherwise it is lost and G issues nothing). G issues the response at ti = ts + rtt/2 and
        # stamps it with an error uniform in [-eps_G, eps_G]. The response arrives after a heavy-tailed delay
        # (msg_delays), or when the outage it falls into ends. With epochs, a response whose request was sent
        # before a power loss that happened before it arrived is useless (its send is in an older epoch).
        self.g_ti, self.g_err, self.resp_arr_issue, self.resp_delays = [], [], [], []
        self.resp_all, self.resp_valid = [], []
        for s in range(S):
            lk = self.links[s]
            ks = self.phase[s] + cfg.P * np.arange(int((T - self.phase[s]) // cfg.P) + 1)
            sent = ~lk.down_mask(ks)[0] & ~lk.down_mask(ks + cfg.rtt / 2)[0]
            ts = ks[sent]
            ti = ts + cfg.rtt / 2
            err = rng.uniform(-cfg.eps_G, cfg.eps_G, len(ts))
            arr = lk.next_up_vec(ti + msg_delays(rng, cfg, len(ts)))
            pa = self.power[s].a
            same_epoch = np.searchsorted(pa, arr, side="right") == np.searchsorted(pa, ts, side="right")
            self.resp_delays.append(arr - ti)
            self.g_ti.append(ti.tolist())
            self.g_err.append(err.tolist())
            self.resp_arr_issue.append(arr.tolist())
            self.resp_all.append(Responses(ts, ti, arr))
            self.resp_valid.append(Responses(ts[same_epoch], ti[same_epoch], arr[same_epoch]))
        n_obj = S * cfg.objects_per_site
        self.home = [o // cfg.objects_per_site for o in range(n_obj)]
        # Decisions (the same for every protocol): about reassign_rate_day per day of the decision window. Each
        # picks an object uniformly among those not moved in the last min_gap_days, and a new holder uniformly
        # among the other sites. Per decision: G's timestamp error on the move, the delay of the stop to the old
        # holder and of the notice to the new holder.
        Td = T * cfg.decide_frac
        times = np.sort(rng.uniform(0, Td, rng.poisson(cfg.reassign_rate_day * cfg.days * cfg.decide_frac)))
        self.decisions = {o: [] for o in range(n_obj)}
        cur = list(self.home)
        last = [-math.inf] * n_obj
        u_obj, u_to = rng.random(len(times)), rng.integers(1, S, len(times))
        for t, uo, k in zip(times, u_obj, u_to):
            elig = [o for o in range(n_obj) if t - last[o] >= cfg.min_gap_days * DAY]
            if not elig:
                continue
            o = elig[int(uo * len(elig))]
            to = (cur[o] + int(k)) % S
            self.decisions[o].append((float(t), cur[o], to))
            cur[o], last[o] = to, float(t)
        self.n_decisions = sum(len(v) for v in self.decisions.values())
        self.dec_err, self.dec_applied, self.dec_learned = {}, {}, {}
        for o in range(n_obj):
            k = len(self.decisions[o])
            err = rng.uniform(-cfg.eps_G, cfg.eps_G, k)
            d_stop, d_note = msg_delays(rng, cfg, k), msg_delays(rng, cfg, k)
            self.dec_err[o] = err.tolist()
            # The old holder learns of the move from the stop or from any renewal response issued after it.
            self.dec_applied[o] = [self.learn(fr, t, d) for (t, fr, _), d in zip(self.decisions[o], d_stop)]
            self.dec_learned[o] = [self.learn(to, t, d) for (t, _, to), d in zip(self.decisions[o], d_note)]
        n_op = S * cfg.operators_per_site
        n = rng.poisson(cfg.revoke_rate_day * cfg.days * cfg.decide_frac)
        ops = rng.choice(n_op, size=min(n, n_op), replace=False)
        self.revocations = {int(o): float(t) for o, t in zip(ops, rng.uniform(0, Td, len(ops)))}
        self.op_site = [o // cfg.operators_per_site for o in range(n_op)]
        d_rev = msg_delays(rng, cfg, len(self.revocations))
        self.rev_applied = {op: self.learn(self.op_site[op], t, d)
                            for (op, t), d in zip(self.revocations.items(), d_rev)}
        # Permit requests: per object and site a Poisson process at permit_rate_day; a site asks only while it
        # believes it holds the object (filtered in simulate_permits), so the holder sees about permit_rate_day.
        # Each: (time, site, hold length in site-clock seconds, max-fit?, finality delay).
        self.permit_req = []
        for _ in range(n_obj):
            ts_, ss_ = [], []
            for s in range(S):
                k = rng.poisson(cfg.permit_rate_day * cfg.days)
                ts_.append(rng.uniform(0, T, k))
                ss_.append(np.full(k, s))
            t_all = np.concatenate(ts_)
            o_ = np.argsort(t_all, kind="stable")
            k = len(t_all)
            self.permit_req.append(list(zip(t_all[o_].tolist(), np.concatenate(ss_)[o_].tolist(),
                                            rng.uniform(cfg.hold_min, cfg.hold_max, k).tolist(),
                                            (rng.random(k) < cfg.maxfit_frac).tolist(),
                                            finality(rng, cfg, k).tolist())))
        self.auth_req = [np.sort(rng.uniform(0, T, rng.poisson(cfg.auth_rate_day * cfg.days)))
                         for _ in range(n_op)]
        for op, t_rev in self.revocations.items():   # a revoked insider keeps trying at four times the rate
            n = rng.poisson(cfg.auth_rate_day * cfg.insider_days * 4)
            extra = rng.uniform(t_rev, min(T, t_rev + cfg.insider_days * DAY), n)
            self.auth_req[op] = np.sort(np.concatenate([self.auth_req[op], extra]))
        self.auth_F = [finality(rng, cfg, len(r)).tolist() for r in self.auth_req]
        self.auth_req = [r.tolist() for r in self.auth_req]
        self.consume_req = [np.sort(rng.uniform(0, T, rng.poisson(cfg.consume_rate_day * cfg.days)))
                            for _ in range(S)]
        self.log_req = [np.sort(rng.uniform(0, T, rng.poisson(cfg.log_rate_day * cfg.days))) for _ in range(S)]

    def powered(self, s, t):
        return self.power[s].up(t)

    def learn(self, s, t, d_msg):
        """Real time at which site s learns of a decision G took at t: the decision's own message (delay d_msg,
        store-and-forward) or the first renewal response G issued after t, whichever arrives first."""
        best = self.links[s].next_up(t + d_msg)
        ti, arr = self.g_ti[s], self.resp_arr_issue[s]
        k = bisect.bisect_right(ti, t)
        while k < len(ti) and ti[k] < best:
            best = min(best, arr[k])
            k += 1
        return best

    def g_last_issue(self, s, lo, hi):
        """(issue time, G timestamp error) of the last renewal G issued to s in [lo, hi] (G knows only what it
        issued, not what was delivered), or None."""
        ti = self.g_ti[s]
        k = bisect.bisect_right(ti, hi) - 1
        if k < 0 or ti[k] < lo:
            return None
        return ti[k], self.g_err[s][k]

    def best_start(self, s, t, lo, hi, receipt, valid):
        """Start of the allowance of site s at time t: the send time of the latest-sent renewal it has received
        by t (or, receipt=True, the latest receipt), among responses G issued in [lo, hi]. valid=True drops
        responses whose request was sent in an older power epoch than their arrival."""
        R = self.resp_valid[s] if valid else self.resp_all[s]
        j = bisect.bisect_right(R.arr, t) - 1
        if j < 0:
            return None
        if not receipt and hi >= t:          # every response received by t was issued before t <= hi
            ts = R.pmax_ts[j]
            return ts if ts + self.cfg.rtt / 2 >= lo else None
        best = None
        while j >= 0 and R.arr[j] >= lo:     # arrival >= issue, so arrivals before lo were issued before lo
            if lo <= R.ti[j] <= hi:
                if receipt:
                    return R.arr[j]          # latest receipt
                if best is None or R.ts[j] > best:
                    best = R.ts[j]
            if best is not None and R.arr[j] <= best:
                break                        # earlier arrivals were sent before this one arrived
            j -= 1
        return best

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

    def clock_elapsed(self, s, a, b):
        """Site-clock seconds elapsed in [a, b] (the clock stops while the site has no power)."""
        return (b - a - self.power[s].downtime(a, b)) * (1 + self.drift[s])


def lease_params(cfg: Cfg, proto: str):
    """(allowance A in site-clock seconds, G wait W after the last renewal in G-clock seconds)."""
    if proto == "nodrift":
        return cfg.D, math.ceil(cfg.D) + 2 * cfg.eps_G
    A = cfg.D * (1 + cfg.rho)
    eps_terms = 1 if proto == "eps1" else 2
    return A, math.ceil(A / (1 - cfg.rho)) + eps_terms * cfg.eps_G


# ------------------------------------------------------------------------------------------ X: permits
def simulate_permits(w: World, proto: str):
    cfg = w.cfg
    lease = proto in LEASES
    merge = proto in MERGES
    epoch = proto != "noepoch"
    receipt = proto == "receipt"
    A, W = lease_params(cfg, proto) if lease else (0.0, 0.0)
    n_obj = len(w.home)
    out = dict(req=0, req_out=0, acc=0, acc_out=0, req_out_fixed=0, acc_out_fixed=0, lapsed=0, conflicts=0,
               overlap=0.0, double=0, double_max=0.0, acc_sets=[], conflict_sets=[], authority_after=[],
               reassign_delay=[], idle=[], fast=0, rights_beyond=0, rights_excess=0.0)
    for o in range(n_obj):
        decs = w.decisions[o]
        nd = len(decs)
        applied, learned, g_err = w.dec_applied[o], w.dec_learned[o], w.dec_err[o]
        # Holds of the old holder per decision: granted before the stop reached it (all of them), and granted
        # while connected before the decision (those G and the other sites know of at the decision).
        before_applied = [0.0] * nd
        known = [0.0] * nd
        switch, release = [None] * nd, [None] * nd

        def release_of(i, t):
            """Lease protocols, slow path: G moves the object W after its last renewal to the old holder
            (G clock; both G timestamps err by up to eps_G), and not before the decision."""
            if release[i] is None:
                t_d, fr, _ = decs[i]
                lo = 0.0 if i == 0 else switch_of(i - 1, t)
                last = w.g_last_issue(fr, lo, t_d)
                if last is None:
                    release[i] = t_d          # the old holder never had a lease on this object
                else:
                    ti, e_i = last
                    release[i] = max(t_d, ti + e_i + W - g_err[i])
            return release[i]

        def switch_of(i, t):
            """Time from which the new holder of decision i may act, as known at time t (final once cached)."""
            if switch[i] is not None:
                return switch[i]
            t_d, fr, _ = decs[i]
            if proto == "global" or (merge and not w.links[fr].up(t_d)):
                # Global chain: it orders the decision and knows every hold, so the new holder may act once the
                # old holder's holds end. Merging baselines with the old holder cut off: they know only the
                # holds granted while it was connected; offline holds are invisible (inherent to merging).
                if t < t_d:
                    return math.inf
                sw = max(t_d, known[i])
            else:
                # Connected handover, the same for every site-local protocol (merging baselines when the old
                # holder is connected at the decision, wait-for-release, leases' fast path): the stop reaches
                # the old holder (applied), it grants nothing more, and its acknowledgement reaches G once its
                # running holds have ended and its link is up.
                if t < applied[i]:
                    return release_of(i, t) if lease else math.inf
                fast = w.links[fr].next_up(max(applied[i], before_applied[i])) + cfg.rtt / 2
                sw = min(release_of(i, t), fast) if lease else fast
            if i > 0:
                # A move cannot complete before the previous move of the object did (G hands an object on only
                # once it has it; matters only when a merged outage outlasts the 7-day gap between moves).
                prev = switch_of(i - 1, t)
                if switch[i - 1] is None:
                    return max(sw, prev)
                sw = max(sw, prev)
            switch[i] = sw
            return sw

        def believes(s, t):
            """Site s believes it holds o at t: its latest learned move to it is newer than its latest learned
            move away from it (the home site holds it from the start)."""
            t_in = -1.0 if w.home[o] == s else -math.inf
            t_out = -math.inf
            for i, (t_d, fr, to) in enumerate(decs):
                if t_d > t:
                    break
                if to == s and learned[i] <= t:
                    t_in = t_d
                if fr == s and applied[i] <= t:
                    t_out = t_d
            return t_in > t_out

        grants = []   # (s, e0, e1, offline, t)
        for t, s, h, maxfit, F in w.permit_req[o]:
            s = int(s)
            if not w.powered(s, t) or not believes(s, t):
                continue
            offline = not w.links[s].up(t)
            out["req"] += 1
            out["req_out"] += offline
            out["req_out_fixed"] += offline and not maxfit
            # The decision that made s holder (latest move to s by t; -1: home) and the next move away from s.
            idx_in = -1
            for i, d in enumerate(decs):
                if d[0] <= t and d[2] == s:
                    idx_in = i
            if idx_in < 0 and w.home[o] != s:
                continue
            idx_out = idx_in + 1 if idx_in + 1 < nd else None
            assert idx_out is None or decs[idx_out][1] == s
            start_ok = 0.0 if idx_in < 0 else switch_of(idx_in, t)
            if t < start_ok:
                continue
            t_out = decs[idx_out][0] if idx_out is not None else math.inf
            ap = applied[idx_out] if idx_out is not None else math.inf
            e0 = e1 = None
            if proto == "global":
                if offline or t >= t_out:      # a cut-off site finalizes nothing; the chain orders the move first
                    continue
                e0, e1 = t + F, t + F + h
            elif merge:
                e0, e1 = t, t + h
            elif proto == "waitrel":
                if t >= ap:
                    continue
                e0 = t + F
                e1 = w.auth_end(s, e0, h, True)
            else:
                if t >= ap:
                    continue
                # Allowance: A site-clock seconds from the send (receipt: the receipt) of the latest renewal
                # response that covers the object (issued after s became holder, before the move away).
                st = w.best_start(s, t, start_ok, t_out, receipt, epoch)
                if st is None:
                    continue
                allow_end = w.auth_end(s, st, A, epoch)
                if t >= allow_end:
                    continue
                rem = A - w.clock_elapsed(s, st, t)          # what the site's own clock says is left
                if proto == "nohold" or h < rem:
                    hh = h                                   # nohold: runs its full length, may outlast A
                elif maxfit and rem - 1.0 >= cfg.fit_min:
                    hh = rem - 1.0                           # max-fit: shortened to end 1 s before the edge
                else:
                    continue                                 # hold-end rule: the hold must end inside A
                hold_end = w.auth_end(s, t, hh, epoch)       # hold window measured on the site clock
                e0 = t + F
                if not w.powered(s, e0):                     # the gateway cannot execute while down
                    out["lapsed"] += 1
                    continue
                if proto == "nofresh":
                    e1 = w.auth_end(s, e0, hh, epoch)        # runs for hh from the delayed execution
                else:
                    # Fresh check at execution: a fresh clock reading (same epoch) is still inside the hold
                    # end and the allowance, otherwise the grant lapses.
                    if e0 >= hold_end or e0 >= allow_end:
                        out["lapsed"] += 1
                        continue
                    e1 = hold_end
            out["acc"] += 1
            out["acc_out"] += offline
            out["acc_out_fixed"] += offline and not maxfit
            if offline:
                out["acc_sets"].append((s, w.links[s].down_at(t)[0]))
            grants.append((s, e0, e1, offline, t))
            if idx_out is not None:
                if t < ap:
                    before_applied[idx_out] = max(before_applied[idx_out], e1)
                if t < t_out and not offline:
                    known[idx_out] = max(known[idx_out], e1)
        # Holder timeline in force, and authority overlaps: any part of a hold while another site holds it.
        tl = Timeline(w.home[o])
        prev_sw = 0.0
        for i, (t_d, fr, to) in enumerate(decs):
            sw = switch_of(i, math.inf)
            tl.add(sw, to)
            out["reassign_delay"].append(sw - t_d)
            if lease:
                out["fast"] += sw < release_of(i, math.inf)
                st = w.best_start(fr, applied[i], prev_sw, t_d, receipt, epoch)
                old_end = t_d if st is None else min(max(t_d, w.auth_end(fr, st, A, epoch)), applied[i])
            elif proto == "waitrel":
                out["fast"] += 1
                old_end = sw
            elif proto == "global":
                old_end = t_d
            else:
                out["fast"] += w.links[fr].up(t_d)
                old_end = applied[i]
            out["authority_after"].append(max(0.0, old_end - t_d))
            out["idle"].append(max(0.0, sw - max(t_d, old_end)))
            if old_end > sw:          # the old holder could still grant after the new holder became entitled
                out["rights_beyond"] += 1
                out["rights_excess"] = max(out["rights_excess"], old_end - sw)
            prev_sw = sw
        for s, e0, e1, offline, t in grants:
            f = tl.foreign(s, e0, e1)
            if f > 0:
                out["conflicts"] += 1
                out["overlap"] = max(out["overlap"], f)
                if offline:
                    out["conflict_sets"].append((s, w.links[s].down_at(t)[0]))
        # Double use: executed holds of two different sites overlap in time.
        act = []
        for s, e0, e1, _, _ in sorted(grants, key=lambda g: g[1]):
            act = [x for x in act if x[1] > e0]
            for s2, b2 in act:
                if s2 != s:
                    out["double"] += 1
                    out["double_max"] = max(out["double_max"], min(b2, e1) - e0)
            act.append((s, e1))
    return out


# ------------------------------------------------------------------------------------------ V: credentials
def simulate_auth(w: World, proto: str):
    cfg = w.cfg
    lease = proto in LEASES
    epoch = proto != "noepoch"
    receipt = proto == "receipt"
    A, W = lease_params(cfg, proto) if lease else (0.0, 0.0)
    res = dict(req=0, req_out=0, acc=0, acc_out=0, stale_acc=0, stale_max=0.0, late=0, conflict_sets=[],
               acc_sets=[], window=[])
    bound = {}
    for op, t_rev in w.revocations.items():
        s = w.op_site[op]
        applied = w.rev_applied[op]
        if proto == "global":
            res["window"].append(0.0)
        elif lease:
            st = w.best_start(s, applied, 0.0, t_rev, receipt, epoch)
            end = t_rev if st is None else min(max(t_rev, w.auth_end(s, st, A, epoch)), applied)
            res["window"].append(max(0.0, end - t_rev))
            # G's promise: the credential is dead W after G's last renewal to the site before the revocation.
            last = w.g_last_issue(s, 0.0, t_rev)
            bound[op] = t_rev if last is None else max(t_rev, last[0] + W)
        else:
            res["window"].append(applied - t_rev)
    for op, reqs in enumerate(w.auth_req):
        s = w.op_site[op]
        t_rev = w.revocations.get(op, math.inf)
        lk = w.links[s]
        applied = w.rev_applied.get(op, math.inf)
        for t, F in zip(reqs, w.auth_F[op]):
            if not w.powered(s, t):
                continue
            offline = not lk.up(t)
            res["req"] += 1
            res["req_out"] += offline
            te = t   # time the acceptance takes effect
            if proto == "global":
                ok = not offline and t < t_rev
            elif lease:
                ok = False
                if t < applied:
                    st = w.best_start(s, t, 0.0, t_rev, receipt, epoch)
                    if st is not None:
                        end = w.auth_end(s, st, A, epoch)
                        te = t + F
                        # Grant inside the allowance; fresh check at execution (not for nofresh).
                        ok = t < end and w.powered(s, te) and (proto == "nofresh" or te < end)
            else:   # merge baselines and waitrel: the site learns of the revocation when the message arrives
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
                if op in bound and te > bound[op]:
                    res["late"] += 1     # took effect after G's bound for this revocation
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
def trace_stats(w: World):
    """Protocol-independent statistics of the trace (measured rates, outages, delays)."""
    cfg = w.cfg
    n_obj = len(w.home)
    n_req = 0
    for o in range(n_obj):
        decs, applied, learned = w.decisions[o], w.dec_applied[o], w.dec_learned[o]
        for t, s, *_ in w.permit_req[o]:
            if not w.powered(s, t):
                continue
            t_in = -1.0 if w.home[o] == s else -math.inf
            t_out = -math.inf
            for i, (t_d, fr, to) in enumerate(decs):
                if t_d > t:
                    break
                if to == s and learned[i] <= t:
                    t_in = t_d
                if fr == s and applied[i] <= t:
                    t_out = t_d
            n_req += t_in > t_out
    longest = float(max((b - a for lk in w.links for a, b in lk.iv), default=0.0))
    Fs = np.concatenate([np.array([r[4] for r in w.permit_req[o]]) for o in range(n_obj)])
    win = cfg.days * cfg.decide_frac
    rd = np.concatenate(w.resp_delays)       # renewal response issue -> arrival (incl. store-and-forward)
    return dict(
        permit_req_per_obj_day=n_req / (n_obj * cfg.days),
        decisions=w.n_decisions, decisions_per_day=w.n_decisions / win,
        revocations=len(w.revocations), revocations_per_day=len(w.revocations) / win,
        longest_offline_h=longest / HOUR,
        offline_frac=float(np.mean([sum(b - a for a, b in lk.iv) / w.T for lk in w.links])),
        F_mean=float(Fs.mean()), F_frac_over_60s=float((Fs > 60).mean()),
        resp_frac_over_1s=float(np.mean(rd > 1.0)), resp_frac_over_60s=float(np.mean(rd > 60.0)),
        resp_max_delay_h=float(rd.max()) / HOUR,
    )


def run(cfg: Cfg):
    w = World(cfg)
    out = {"cfg": asdict(cfg), "trace": trace_stats(w)}
    c_out = 0
    for s, r in enumerate(w.log_req):
        down = w.links[s].down_mask(r)[0]
        unpowered = w.power[s].down_mask(r)[0]
        c_out += int((down & ~unpowered).sum())
    cache = {}
    for proto in PROTOCOLS:
        key = "merge" if proto in MERGES else proto     # the three merges differ only in rollback accounting
        if key not in cache:
            cache[key] = (simulate_permits(w, proto), simulate_auth(w, proto), simulate_consume(w, proto))
        px, pv, pb = cache[key]
        if proto in ("ours", "global"):
            # Cheap invariants: OffGrant and the global chain never give two sites the same object at once.
            assert px["conflicts"] == 0 and px["double"] == 0, (proto, px["conflicts"], px["double"])
        if proto == "ours":
            assert pb["over"] == 0 and pv["late"] == 0 and px["rights_beyond"] == 0
        bad_sets = set(px["conflict_sets"]) | set(pv["conflict_sets"]) | set(pb["conflict_sets"])
        rolled_excl = rolled_log = 0
        if proto == "discard":
            accepted = {}
            for k in px["acc_sets"] + pv["acc_sets"] + pb["acc_sets"]:
                accepted[k] = accepted.get(k, 0) + 1
            for s, start in bad_sets:
                end = w.links[s].down_at(start)[1]
                rolled_log += int(((w.log_req[s] >= start) & (w.log_req[s] < end)).sum())
                rolled_excl += accepted.get((s, start), 0)
        elif proto == "timestamp":
            rolled_excl = px["conflicts"] + pv["stale_acc"] + int(pb["over"])
        rd = px["reassign_delay"]
        out[proto] = dict(
            X_avail_out=px["acc_out"] / max(1, px["req_out"]),
            X_avail_out_fixed=px["acc_out_fixed"] / max(1, px["req_out_fixed"]),
            X_avail=px["acc"] / max(1, px["req"]),
            X_req=px["req"],
            X_req_out=px["req_out"],
            X_lapsed=px["lapsed"],
            X_conflicts=px["conflicts"],              # authority overlaps
            X_overlap_max=px["overlap"],
            X_double=px["double"],                    # double use (executed holds of two sites overlap)
            X_double_max=px["double_max"],
            X_reassign_delay_mean=float(np.mean(rd)) if rd else 0.0,
            X_reassign_delay_max=max(rd) if rd else 0.0,
            X_fast_frac=px["fast"] / max(1, len(rd)),
            X_idle_mean=float(np.mean(px["idle"])) if px["idle"] else 0.0,
            X_authority_after=px["authority_after"],
            X_rights_beyond=px["rights_beyond"],
            X_rights_excess_max=px["rights_excess"],
            V_window=pv["window"],
            W_bound=lease_params(cfg, "ours")[1],
            V_avail_out=pv["acc_out"] / max(1, pv["req_out"]),
            V_stale_acc=pv["stale_acc"],
            V_stale_max=pv["stale_max"],
            V_late=pv["late"],
            B_avail_out=pb["acc_out"] / max(1, pb["req_out"]),
            B_over=pb["over"],
            C_avail_out=0.0 if proto == "global" else 1.0,
            C_out=c_out,
            rolled_back=rolled_excl + rolled_log,
            rolled_back_excl=rolled_excl,
            rolled_back_log=rolled_log,
            offline_frac=out["trace"]["offline_frac"],
        )
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="experiments/results/offsim_v5.jsonl")
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
