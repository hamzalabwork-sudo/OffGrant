---------------------------- MODULE RightsV3 ----------------------------
(***************************************************************************)
(* Theorem 1 (i)-(ii): safety and accountability of a site ledger over    *)
(* several checkpoint heights, without an oracle for "in/out of rights".  *)
(*                                                                         *)
(* Validators V (n = 3f+1), of which Byz are faulty, seal checkpoints     *)
(* while the site is cut off. A checkpoint at height h names a parent at  *)
(* h-1 and consumes Amt[id] units of a resource whose share is Cap; its   *)
(* running total is computed along its parent chain. A correct validator *)
(* seals at most one checkpoint per height, only one that extends the     *)
(* last checkpoint it sealed, and only if the running total is within     *)
(* Cap. Faulty validators seal anything. A checkpoint is final with a     *)
(* quorum of 2f+1 seals. On reconnection G blames                         *)
(*   - every sealer of a final checkpoint whose running total exceeds Cap *)
(*     (overspend / understatement proof), and                            *)
(*   - every validator that sealed two different final checkpoints at     *)
(*     one height (fork proof).                                           *)
(* Checked:                                                                *)
(*   Safety:      |Byz| <= f => no final over-share checkpoint, no fork   *)
(*   NoFraming:   blamed \subseteq Byz                                     *)
(*   Accountable: violation => |blamed| >= f+1                            *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS V, Byz, F, H, Cap

ASSUME Byz \subseteq V /\ Cardinality(V) = 3 * F + 1

Amt == [i \in 1..2 |-> i]                               \* checkpoint id 1 consumes 1 unit, id 2 consumes 2
Ckpts == {[h |-> 1, id |-> i, par |-> 0] : i \in 1..2}
         \cup [h : 2..H, id : 1..2, par : 1..2]         \* par: id of the parent at h-1

Parent(b) == CHOOSE p \in Ckpts : p.h = b.h - 1 /\ p.id = b.par

RECURSIVE Total(_)
Total(b) == IF b.h = 1 THEN Amt[b.id] ELSE Amt[b.id] + Total(Parent(b))

RECURSIVE Ancestors(_)
Ancestors(b) == IF b.h = 1 THEN {b} ELSE {b} \cup Ancestors(Parent(b))

VARIABLES seals, anchored

vars == <<seals, anchored>>

Quorum == 2 * F + 1

Init == /\ seals = [b \in Ckpts |-> {}]
        /\ anchored = FALSE

SealedBy(v) == {b \in Ckpts : v \in seals[b]}

LastSealed(v) == {b \in SealedBy(v) : \A b2 \in SealedBy(v) : b2.h <= b.h}

Seal(v, b) ==
  /\ ~anchored
  /\ v \notin seals[b]
  /\ v \notin Byz =>
       /\ Total(b) <= Cap
       /\ \A b2 \in SealedBy(v) : b2.h /= b.h                    \* once per height
       /\ \A l \in LastSealed(v) : l.h < b.h /\ l \in Ancestors(b)  \* extends its last sealed checkpoint
  /\ seals' = [seals EXCEPT ![b] = @ \cup {v}]
  /\ UNCHANGED anchored

Anchor == /\ ~anchored /\ anchored' = TRUE /\ UNCHANGED seals

Next == (\E v \in V, b \in Ckpts : Seal(v, b)) \/ Anchor

Spec == Init /\ [][Next]_vars

Final(b) == Cardinality(seals[b]) >= Quorum

Over == {b \in Ckpts : Final(b) /\ Total(b) > Cap}
Forks == {<<b1, b2>> \in Ckpts \X Ckpts : b1.h = b2.h /\ b1 /= b2 /\ Final(b1) /\ Final(b2)}

Violation == Over /= {} \/ Forks /= {}

Blamed ==
  IF ~anchored THEN {}
  ELSE (UNION {seals[b] : b \in Over}) \cup (UNION {seals[p[1]] \cap seals[p[2]] : p \in Forks})

Safety == Cardinality(Byz) <= F => ~Violation
NoFraming == Blamed \subseteq Byz
Accountable == (anchored /\ Violation) => Cardinality(Blamed) >= F + 1
=============================================================================
