---------------------------- MODULE Rights ----------------------------
(***************************************************************************)
(* Theorem 2: rights-scoped safety and accountability of a site ledger.   *)
(*                                                                         *)
(* A site ledger has validators V (n = 3f+1), of which Byz are faulty.    *)
(* It runs while cut off from G. Each height carries one operation; an    *)
(* operation is either within the site's rights ("in") or outside them    *)
(* ("out": over the share, past the lease allowance, a revoked            *)
(* credential). Correct validators seal at most one block per height and  *)
(* only "in" blocks; faulty ones seal anything. A block is final with a   *)
(* quorum of 2f+1 seals. On reconnection the site's final blocks are      *)
(* anchored on G, which blames:                                           *)
(*   - every sealer of a final "out" block (the seal is a signed          *)
(*     out-of-rights statement),                                          *)
(*   - every validator that sealed two different final blocks at one      *)
(*     height (equivocation).                                             *)
(* Checked:                                                                *)
(*   Safety:     |Byz| <= f  => no final "out" block, no fork             *)
(*   NoFraming:  blamed \subseteq Byz                                      *)
(*   Accountable: violation => |blamed| >= f+1                            *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS V, Byz, F, H

ASSUME Byz \subseteq V /\ Cardinality(V) = 3 * F + 1

Ops == {"in", "out"}
Blocks == [h : 1..H, id : 1..2, op : Ops]       \* two candidate blocks per height

VARIABLES seals, anchored

vars == <<seals, anchored>>

Quorum == 2 * F + 1

Init == /\ seals = [b \in Blocks |-> {}]
        /\ anchored = FALSE

\* A validator seals a block, subject to its own rule if it is correct.
Seal(v, b) ==
  /\ ~anchored
  /\ v \notin seals[b]
  /\ v \notin Byz =>
       /\ b.op = "in"
       /\ \A b2 \in Blocks : (b2.h = b.h /\ b2 /= b) => v \notin seals[b2]
  /\ seals' = [seals EXCEPT ![b] = @ \cup {v}]
  /\ UNCHANGED anchored

\* Reconnection: the site's sealed blocks are anchored on G.
Anchor == /\ ~anchored /\ anchored' = TRUE /\ UNCHANGED seals

Next == (\E v \in V, b \in Blocks : Seal(v, b)) \/ Anchor

Spec == Init /\ [][Next]_vars

Final(b) == Cardinality(seals[b]) >= Quorum

OutFinal == {b \in Blocks : Final(b) /\ b.op = "out"}
Forks == {<<b1, b2>> \in Blocks \X Blocks :
            b1.h = b2.h /\ b1 /= b2 /\ Final(b1) /\ Final(b2)}

Violation == OutFinal /= {} \/ Forks /= {}

Blamed ==
  IF ~anchored THEN {}
  ELSE (UNION {seals[b] : b \in OutFinal})
       \cup (UNION {seals[p[1]] \cap seals[p[2]] : p \in Forks})

Safety == Cardinality(Byz) <= F => ~Violation
NoFraming == Blamed \subseteq Byz
Accountable == (anchored /\ Violation) => Cardinality(Blamed) >= F + 1
=============================================================================
