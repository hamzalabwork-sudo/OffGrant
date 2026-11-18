---------------------------- MODULE LeaseV3 ----------------------------
(***************************************************************************)
(* Proposition 1 with the mechanisms that make it hold on a TPM clock.    *)
(*                                                                         *)
(* One exclusive object. Site S1 holds it through renewals from G; G may  *)
(* decide at any time to move it to S2, which then uses it at once. S1's  *)
(* uplink may be cut and restored, messages may be delayed or lost, and   *)
(* S1 may lose power: its clock stops while it is off and the TPM starts  *)
(* a new epoch when it comes back. Real time advances in steps of K; the  *)
(* site clock advances K-R .. K+R per step while powered (rho = R/K).     *)
(* G's block timestamps are off from real time by at most EG.             *)
(*                                                                         *)
(* S1 records (epoch, clock) when it SENDS a request (Mode = "send") or   *)
(* counts from the renewal's receipt (Mode = "receipt"). It grants a hold *)
(* with end u <= base + A - 1 (an instant, or the longest hold allowed).  *)
(* The grant takes effect when the gateway executes it, an arbitrary time *)
(* later (finality delay). With Fresh, the gateway executes only if, at   *)
(* execution, the clock is in the same epoch and before u. With Epochs,  *)
(* an allowance holds only in the epoch of its base.                      *)
(*                                                                         *)
(* Safe:      S1's hold is never in effect after the object moved to S2.  *)
(* Tolerance: S1 may grant for real time D after sending the request      *)
(*            answered by its latest renewal (same epoch, powered).       *)
(* Expected: Safe holds iff Mode = "send", Epochs, Fresh, HoldInside and  *)
(*           Wait >= A*K/(K-R) + 2*EG.                                    *)
(***************************************************************************)
EXTENDS Integers

CONSTANTS K, R, A, Wait, D, EG, Tmax, MaxPowerLoss,
          Mode, Epochs, Fresh, HoldInside

VARIABLES t, c, ep, on, losses, pend, inflight, base, bep, baseT,
          gStopped, lastIssueG, reassigned, cut, hold

vars == <<t, c, ep, on, losses, pend, inflight, base, bep, baseT,
          gStopped, lastIssueG, reassigned, cut, hold>>

NoReq == [cq |-> -1, ce |-> -1, tq |-> -1]
NoHold == [u |-> -1, he |-> -1, ex |-> FALSE, now |-> FALSE]

Init ==
  /\ t = 0 /\ c = 0 /\ ep = 0 /\ on = TRUE /\ losses = 0
  /\ pend = NoReq
  /\ inflight = {}
  /\ base = -1 /\ bep = -1 /\ baseT = -1
  /\ gStopped = FALSE
  /\ lastIssueG = -1000
  /\ reassigned = FALSE
  /\ cut = FALSE
  /\ hold = NoHold

Send ==
  /\ on /\ pend = NoReq
  /\ pend' = [cq |-> c, ce |-> ep, tq |-> t]
  /\ UNCHANGED <<t, c, ep, on, losses, inflight, base, bep, baseT, gStopped, lastIssueG, reassigned, cut, hold>>

\* G renews unless it has decided to reassign, stamping the renewal with its own (inexact) time.
\* Only the newest renewal in flight is kept: an older one grants strictly less.
Issue ==
  /\ pend /= NoReq /\ ~cut /\ ~gStopped
  /\ inflight' = {pend}
  /\ \E e \in {-EG, 0, EG} : lastIssueG' = t + e
  /\ pend' = NoReq
  /\ UNCHANGED <<t, c, ep, on, losses, base, bep, baseT, gStopped, reassigned, cut, hold>>

LoseRequest ==
  /\ pend /= NoReq /\ pend' = NoReq
  /\ UNCHANGED <<t, c, ep, on, losses, inflight, base, bep, baseT, gStopped, lastIssueG, reassigned, cut, hold>>

Deliver ==
  /\ on /\ ~cut
  /\ \E r \in inflight :
       /\ inflight' = inflight \ {r}
       /\ IF Mode = "send"
            THEN IF r.ce > bep \/ (r.ce = bep /\ r.cq > base)
                   THEN base' = r.cq /\ bep' = r.ce /\ baseT' = r.tq
                   ELSE UNCHANGED <<base, bep, baseT>>
            ELSE base' = c /\ bep' = ep /\ baseT' = t
  /\ UNCHANGED <<t, c, ep, on, losses, pend, gStopped, lastIssueG, reassigned, cut, hold>>

Allowed == base >= 0 /\ (Epochs => bep = ep) /\ c - base < A

\* S1 grants a hold (only one at a time is modelled): the shortest hold (ending one clock unit after the
\* grant) or the longest allowed. With HoldInside a hold must end inside the allowance (u <= base + A - 1);
\* without it, a hold may also run past the allowance (by one real-time step).
HoldEnds ==
  IF HoldInside THEN {x \in {c + 1, base + A - 1} : x <= base + A - 1}
                ELSE {c + 1, base + A - 1, base + A + K}

Grant ==
  /\ on /\ Allowed /\ hold = NoHold
  /\ \E u \in HoldEnds : u > c /\ hold' = [u |-> u, he |-> ep, ex |-> FALSE, now |-> FALSE]
  /\ UNCHANGED <<t, c, ep, on, losses, pend, inflight, base, bep, baseT, gStopped, lastIssueG, reassigned, cut>>

\* The gateway executes the grant once it is final (any later time).
Execute ==
  /\ on /\ hold /= NoHold /\ ~hold.ex
  /\ Fresh => (hold.he = ep /\ c < hold.u)
  /\ hold' = [hold EXCEPT !.ex = TRUE, !.now = TRUE]
  /\ UNCHANGED <<t, c, ep, on, losses, pend, inflight, base, bep, baseT, gStopped, lastIssueG, reassigned, cut>>

Lapse ==   \* a grant that was never executed, or a hold that ended, is dropped
  /\ hold /= NoHold
  /\ ~(hold.ex /\ on /\ hold.he = ep /\ c < hold.u)
  /\ ~hold.now
  /\ hold' = NoHold
  /\ UNCHANGED <<t, c, ep, on, losses, pend, inflight, base, bep, baseT, gStopped, lastIssueG, reassigned, cut>>

Decide ==
  /\ ~gStopped /\ gStopped' = TRUE
  /\ UNCHANGED <<t, c, ep, on, losses, pend, inflight, base, bep, baseT, lastIssueG, reassigned, cut, hold>>

Reassign ==
  /\ gStopped /\ ~reassigned
  /\ \E e \in {-EG, 0, EG} : (t + e) - lastIssueG >= Wait
  /\ reassigned' = TRUE
  /\ UNCHANGED <<t, c, ep, on, losses, pend, inflight, base, bep, baseT, gStopped, lastIssueG, cut, hold>>

ToggleCut ==
  /\ cut' = ~cut
  /\ UNCHANGED <<t, c, ep, on, losses, pend, inflight, base, bep, baseT, gStopped, lastIssueG, reassigned, hold>>

PowerOff ==
  /\ on /\ losses < MaxPowerLoss
  /\ on' = FALSE /\ losses' = losses + 1
  /\ UNCHANGED <<t, c, ep, pend, inflight, base, bep, baseT, gStopped, lastIssueG, reassigned, cut, hold>>

PowerOn ==   \* the TPM clock resumes from its last saved value; resetCount starts a new epoch
  /\ ~on /\ on' = TRUE /\ ep' = ep + 1
  /\ UNCHANGED <<t, c, losses, pend, inflight, base, bep, baseT, gStopped, lastIssueG, reassigned, cut, hold>>

Tick ==
  /\ t + K <= Tmax
  /\ t' = t + K
  /\ IF on THEN \E d \in (K - R)..(K + R) : c' = c + d ELSE c' = c
  /\ hold' = IF hold = NoHold THEN hold ELSE [hold EXCEPT !.now = FALSE]
  /\ UNCHANGED <<ep, on, losses, pend, inflight, base, bep, baseT, gStopped, lastIssueG, reassigned, cut>>

Next == Send \/ Issue \/ LoseRequest \/ Deliver \/ Grant \/ Execute \/ Lapse
        \/ Decide \/ Reassign \/ ToggleCut \/ PowerOff \/ PowerOn \/ Tick

Spec == Init /\ [][Next]_vars

InEffect == hold /= NoHold /\ hold.ex /\ (hold.now \/ (on /\ hold.he = ep /\ c < hold.u))

TypeOK == t \in 0..Tmax /\ reassigned \in BOOLEAN

Safe == ~(InEffect /\ reassigned)

Tolerance == (base >= 0 /\ bep = ep /\ on /\ t - baseT < D) => c - base < A
=============================================================================
