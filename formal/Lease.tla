---------------------------- MODULE Lease ----------------------------
(***************************************************************************)
(* Theorem 1: offline exclusive authority under clock drift.              *)
(*                                                                         *)
(* One exclusive object. Site S1 holds it through renewals from the       *)
(* global ledger G; G may at any time decide to move it to S2. The uplink *)
(* of S1 may be cut and restored arbitrarily, and messages may be delayed *)
(* or lost. Real time advances in steps of K; the site clock advances by  *)
(* K-R .. K+R per step (drift rho = R/K).                                 *)
(*                                                                         *)
(* Rule (send-time counting): S1 records its clock reading cq when it     *)
(* SENDS a renewal request; a renewal answering it lets S1 exercise while *)
(* its clock has advanced less than A since cq. G records the real time   *)
(* of its last renewal and reassigns only Wait after it.                  *)
(*                                                                         *)
(* Claims checked:                                                         *)
(*   Safe:      never both S1 and S2 exercise    (iff Wait >= A*K/(K-R))  *)
(*   Tolerance: S1 exercises for real time D after sending the request    *)
(*              answered by its latest renewal  (iff A >= D*(K+R)/K)      *)
(* With A = D(1+rho) the optimal wait is D(1+rho)/(1-rho) (Theorem 1).    *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS K, R, A, Wait, D, Tmax

VARIABLES t, c, pend, inflight, base, baseT, gStopped, lastIssue, reassigned, cut

vars == <<t, c, pend, inflight, base, baseT, gStopped, lastIssue, reassigned, cut>>

None == [cq |-> -1, tq |-> -1]

Init ==
  /\ t = 0
  /\ c = 0
  /\ pend = None
  /\ inflight = {}
  /\ base = -1          \* site clock reading at the send of the latest renewal's request
  /\ baseT = -1         \* real time of that send (for the Tolerance check only)
  /\ gStopped = FALSE
  /\ lastIssue = -1
  /\ reassigned = FALSE
  /\ cut = FALSE

\* S1 sends a renewal request, recording its own clock.
Send ==
  /\ pend = None
  /\ pend' = [cq |-> c, tq |-> t]
  /\ UNCHANGED <<t, c, inflight, base, baseT, gStopped, lastIssue, reassigned, cut>>

\* The request reaches G, which renews unless it has decided to reassign.
\* Only the newest renewal in flight is kept: an older one carries a smaller
\* cq and grants S1 strictly less, so dropping it removes no unsafe behaviour
\* (equivalent to losing it, which the model allows anyway).
Issue ==
  /\ pend /= None /\ ~cut /\ ~gStopped
  /\ inflight' = {pend}
  /\ lastIssue' = t
  /\ pend' = None
  /\ UNCHANGED <<t, c, base, baseT, gStopped, reassigned, cut>>

LoseRequest ==
  /\ pend /= None
  /\ pend' = None
  /\ UNCHANGED <<t, c, inflight, base, baseT, gStopped, lastIssue, reassigned, cut>>

\* A renewal reaches S1 (possibly much later, after a reconnection).
Deliver ==
  /\ ~cut
  /\ \E r \in inflight :
       /\ inflight' = inflight \ {r}
       /\ IF r.cq > base THEN base' = r.cq /\ baseT' = r.tq
                         ELSE UNCHANGED <<base, baseT>>
  /\ UNCHANGED <<t, c, pend, gStopped, lastIssue, reassigned, cut>>

Decide ==
  /\ ~gStopped
  /\ gStopped' = TRUE
  /\ UNCHANGED <<t, c, pend, inflight, base, baseT, lastIssue, reassigned, cut>>

Reassign ==
  /\ gStopped /\ ~reassigned
  /\ lastIssue = -1 \/ t - lastIssue >= Wait
  /\ reassigned' = TRUE
  /\ UNCHANGED <<t, c, pend, inflight, base, baseT, gStopped, lastIssue, cut>>

ToggleCut ==
  /\ cut' = ~cut
  /\ UNCHANGED <<t, c, pend, inflight, base, baseT, gStopped, lastIssue, reassigned>>

Tick ==
  /\ t + K <= Tmax
  /\ t' = t + K
  /\ \E d \in (K - R)..(K + R) : c' = c + d
  /\ UNCHANGED <<pend, inflight, base, baseT, gStopped, lastIssue, reassigned, cut>>

Next == Send \/ Issue \/ LoseRequest \/ Deliver \/ Decide \/ Reassign \/ ToggleCut \/ Tick

Spec == Init /\ [][Next]_vars

Exercising1 == base >= 0 /\ c - base < A

TypeOK == t \in 0..Tmax /\ reassigned \in BOOLEAN

Safe == ~(Exercising1 /\ reassigned)

Tolerance == (base >= 0 /\ t - baseT < D) => Exercising1
=============================================================================
