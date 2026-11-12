------------------------------ MODULE PqReanchor ------------------------------
\* CR-45, §15.18, T17, §13.6, CR-48 m.5, OP-159 m.3 (x)
EXTENDS Naturals, Sequences

CONSTANTS MaxLen, MaxId

VARIABLES log, wlog, at, pqEntry, state, nextId

vars == <<log, wlog, at, pqEntry, state, nextId>>

Prefix(s, n) == SubSeq(s, 1, n)

TypeOK ==
    /\ state \in {"none", "pending", "anchored"}
    /\ at \in 0..MaxLen
    /\ Len(wlog) <= Len(log)

Init ==
    /\ log = << >>
    /\ wlog = << >>
    /\ at = 0
    /\ pqEntry = 0
    /\ state = "none"
    /\ nextId = 1

Append ==
    /\ Len(log) < MaxLen
    /\ nextId <= MaxId
    /\ log' = Append(log, nextId)
    /\ nextId' = nextId + 1
    /\ UNCHANGED <<wlog, at, pqEntry, state>>

\* §13
Cosign(s) ==
    /\ s \in (Len(wlog) + 1)..Len(log)
    /\ wlog' = Prefix(log, s)
    /\ UNCHANGED <<log, at, pqEntry, state, nextId>>

\* CR-45 RA-1
Reanchor ==
    /\ state # "pending"
    /\ Len(wlog) > at
    /\ at' = Len(wlog)
    /\ state' = "pending"
    /\ UNCHANGED <<log, wlog, pqEntry, nextId>>

\* CR-45 RA-3
PqCosign ==
    /\ state = "pending"
    /\ at <= Len(wlog)
    /\ Prefix(wlog, at) = Prefix(log, at)
    /\ pqEntry' = log[at]
    /\ state' = "anchored"
    /\ UNCHANGED <<log, wlog, at, nextId>>

\* T17, §13.6
Recover(n) ==
    /\ n \in 0..Len(wlog)
    /\ n < MaxLen
    /\ nextId <= MaxId
    /\ log' = Append(Prefix(log, n), nextId)
    /\ wlog' = Prefix(wlog, n)
    /\ nextId' = nextId + 1
    /\ IF at > n
          THEN /\ at' = 0
               /\ pqEntry' = 0
               /\ state' = IF state = "none" THEN "none" ELSE "pending"
          ELSE UNCHANGED <<at, pqEntry, state>>

RecoveryReanchor ==
    /\ state = "pending"
    /\ at = 0
    /\ Len(wlog) > 0
    /\ at' = Len(wlog)
    /\ UNCHANGED <<log, wlog, pqEntry, state, nextId>>

Next ==
    \/ Append
    \/ \E s \in 1..MaxLen : Cosign(s)
    \/ Reanchor
    \/ PqCosign
    \/ \E n \in 0..MaxLen : Recover(n)
    \/ RecoveryReanchor

Spec ==
    Init /\ [][Next]_vars /\ WF_vars(PqCosign) /\ WF_vars(RecoveryReanchor)
        /\ WF_vars(Append) /\ WF_vars(\E s \in 1..MaxLen : Cosign(s))

\* CR-45, §15.18
AnchorFollowsBranch ==
    state = "anchored" => (at \in 1..Len(log) /\ log[at] = pqEntry /\ at <= Len(wlog))

\* T17
NoAnchorOnAbandonedBranch == state = "pending" => at <= Len(wlog)

\* CR-45 RA-3
PendingIsAnchored == (state = "pending" /\ at > 0) ~> (state = "anchored" \/ at = 0)
=============================================================================
