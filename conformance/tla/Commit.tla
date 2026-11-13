------------------------------- MODULE Commit -------------------------------
\* CR-48 m.5, §5.1, §6.5 S1–S7, T6, OP-159 m.3 (x)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Leaders, Requests, Capacity, MaxEpoch, Fenced

VARIABLES log, dbEpoch, lepoch, acked, denied

vars == <<log, dbEpoch, lepoch, acked, denied>>

Logged(r) == \E i \in 1..Len(log) : log[i].req = r

\* T6
Writer(l) ==
    IF Fenced THEN lepoch[l] > 0 /\ lepoch[l] = dbEpoch ELSE lepoch[l] > 0

TypeOK ==
    /\ dbEpoch \in 0..MaxEpoch
    /\ lepoch \in [Leaders -> 0..MaxEpoch]
    /\ acked \subseteq Requests
    /\ denied \subseteq Requests
    /\ \A i \in 1..Len(log) : log[i].req \in Requests /\ log[i].epoch \in 1..MaxEpoch

Init ==
    /\ log = << >>
    /\ dbEpoch = 0
    /\ lepoch = [l \in Leaders |-> 0]
    /\ acked = {}
    /\ denied = {}

\* T6
Elect(l) ==
    /\ dbEpoch < MaxEpoch
    /\ dbEpoch' = dbEpoch + 1
    /\ lepoch' = [lepoch EXCEPT ![l] = dbEpoch + 1]
    /\ UNCHANGED <<log, acked, denied>>

\* §6.5 S1
AppendRecord(l, r) ==
    /\ Writer(l)
    /\ ~Logged(r)
    /\ r \notin denied
    /\ Len(log) < Capacity
    /\ log' = Append(log, [req |-> r, epoch |-> lepoch[l]])
    /\ UNCHANGED <<dbEpoch, lepoch, acked, denied>>

\* §6.5 S2
Deny(l, r) ==
    /\ Writer(l)
    /\ ~Logged(r)
    /\ r \notin denied
    /\ Len(log) >= Capacity
    /\ denied' = denied \cup {r}
    /\ UNCHANGED <<log, dbEpoch, lepoch, acked>>

\* §6.5 S3
Ack(r) ==
    /\ Logged(r)
    /\ r \notin acked
    /\ acked' = acked \cup {r}
    /\ UNCHANGED <<log, dbEpoch, lepoch, denied>>

\* §6.5 S4
Retry(l, r) ==
    /\ Writer(l)
    /\ Logged(r)
    /\ UNCHANGED vars

Next ==
    \/ \E l \in Leaders : Elect(l)
    \/ \E l \in Leaders, r \in Requests : AppendRecord(l, r) \/ Deny(l, r) \/ Retry(l, r)
    \/ \E r \in Requests : Ack(r)

Spec == Init /\ [][Next]_vars

WithinCapacity == Len(log) <= Capacity

AckedIsLogged == \A r \in acked : Logged(r)

RetryIsIdempotent == \A i, j \in 1..Len(log) : i # j => log[i].req # log[j].req

AtMostOneWriter == Cardinality({l \in Leaders : Writer(l)}) <= 1

EpochMonotone == \A i, j \in 1..Len(log) : i < j => log[i].epoch <= log[j].epoch
=============================================================================
