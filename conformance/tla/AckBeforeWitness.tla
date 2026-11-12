-------------------------- MODULE AckBeforeWitness --------------------------
\* SEC23, §13, §17.1, CR-48 m.5, OP-159 m.3 (x)
EXTENDS Naturals, FiniteSets

CONSTANTS MaxLen

VARIABLES len, witnessed, replicated, acked, restored

vars == <<len, witnessed, replicated, acked, restored>>

TypeOK ==
    /\ len \in 0..MaxLen
    /\ witnessed \in 0..MaxLen
    /\ replicated \in 0..MaxLen
    /\ acked \subseteq 1..MaxLen
    /\ restored \in 0..MaxLen

Init ==
    /\ len = 0
    /\ witnessed = 0
    /\ replicated = 0
    /\ acked = {}
    /\ restored = 0

Append ==
    /\ len < MaxLen
    /\ len' = len + 1
    /\ UNCHANGED <<witnessed, replicated, acked, restored>>

\* §17.1
Replicate ==
    /\ replicated < len
    /\ replicated' = replicated + 1
    /\ UNCHANGED <<len, witnessed, acked, restored>>

\* §13
Cosign(s) ==
    /\ s \in (witnessed + 1)..len
    /\ witnessed' = s
    /\ UNCHANGED <<len, replicated, acked, restored>>

\* SEC23
Ack(i) ==
    /\ i \in 1..len
    /\ i \notin acked
    /\ i <= witnessed
    /\ i <= replicated
    /\ acked' = acked \cup {i}
    /\ UNCHANGED <<len, witnessed, replicated, restored>>

\* §17.1
LoseProvider ==
    /\ len > replicated
    /\ len' = replicated
    /\ restored' = replicated
    /\ UNCHANGED <<witnessed, replicated, acked>>

Next ==
    \/ Append
    \/ Replicate
    \/ \E s \in 1..MaxLen : Cosign(s)
    \/ \E i \in 1..MaxLen : Ack(i)
    \/ LoseProvider

Spec == Init /\ [][Next]_vars

\* SEC23
AckedIsWitnessedAndReplicated ==
    \A i \in acked : i <= witnessed /\ i <= replicated

\* SEC23
AckSurvivesProviderLoss == \A i \in acked : i <= len

ReplicaIsAPrefix == replicated <= len
=============================================================================
