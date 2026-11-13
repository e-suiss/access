-------------------------- MODULE HandoverRecovery --------------------------
\* EI-20, §13, §17.1, §6.5 S12, SEC20, SEC21, SEC22, CR-48 m.5, OP-159 m.3 (x)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Providers, None, MaxLen, MaxKey, MaxId, MirrorFirst

Live == MaxLen + 1

VARIABLES
    local,
    owner,
    key,
    fenceAt,
    wkey,
    wlog,
    cosigned,
    replica,
    frozen,
    lost,
    nextId,
    nextKey,
    recovered

vars == <<local, owner, key, fenceAt, wkey, wlog, cosigned, replica, frozen, lost,
          nextId, nextKey, recovered>>

Prefix(s, n) == SubSeq(s, 1, n)

IsPrefix(a, b) == Len(a) <= Len(b) /\ Prefix(b, Len(a)) = a

Min(a, b) == IF a <= b THEN a ELSE b

\* §13.6
Common(a, b) ==
    LET m == Min(Len(a), Len(b))
    IN CHOOSE k \in 0..m :
        /\ Prefix(a, k) = Prefix(b, k)
        /\ (k = m \/ Prefix(a, k + 1) # Prefix(b, k + 1))

LiveKey(p) == key[p] # 0 /\ fenceAt[key[p]] = Live

TypeOK ==
    /\ None \notin Providers
    /\ owner \in Providers \cup {None}
    /\ key \in [Providers -> 0..MaxKey]
    /\ fenceAt \in [1..MaxKey -> 0..Live]
    /\ wkey \in 0..MaxKey
    /\ frozen \in BOOLEAN
    /\ lost \subseteq 1..MaxLen
    /\ recovered \in 0..MaxLen

Init ==
    \E p \in Providers :
        /\ local = [q \in Providers |-> << >>]
        /\ owner = p
        /\ key = [q \in Providers |-> IF q = p THEN 1 ELSE 0]
        /\ fenceAt = [k \in 1..MaxKey |-> Live]
        /\ wkey = 1
        /\ wlog = << >>
        /\ cosigned = {}
        /\ replica = << >>
        /\ frozen = FALSE
        /\ lost = {}
        /\ nextId = 1
        /\ nextKey = 2
        /\ recovered = 0

AppendTo(p) ==
    /\ Len(local[p]) < MaxLen
    /\ nextId <= MaxId
    /\ local' = [local EXCEPT ![p] = Append(@, nextId)]
    /\ nextId' = nextId + 1

AppendRecord(p) ==
    /\ p = owner
    /\ ~frozen
    /\ AppendTo(p)
    /\ UNCHANGED <<owner, key, fenceAt, wkey, wlog, cosigned, replica, frozen, lost, nextKey,
                   recovered>>

\* EI-20: a deposed provider keeps writing to its own copy
ZombieAppend(p) ==
    /\ p # owner
    /\ key[p] # 0
    /\ AppendTo(p)
    /\ UNCHANGED <<owner, key, fenceAt, wkey, wlog, cosigned, replica, frozen, lost, nextKey,
                   recovered>>

\* §17.1
Replicate ==
    /\ owner # None
    /\ IsPrefix(replica, local[owner])
    /\ Len(replica) < Len(local[owner])
    /\ replica' = Prefix(local[owner], Len(replica) + 1)
    /\ UNCHANGED <<local, owner, key, fenceAt, wkey, wlog, cosigned, frozen, lost, nextId,
                   nextKey, recovered>>

\* §13, SEC23
Cosign(p, s) ==
    /\ key[p] # 0
    /\ key[p] = wkey
    /\ s \in (Len(wlog) + 1)..Len(local[p])
    /\ s <= fenceAt[key[p]]
    /\ IsPrefix(wlog, local[p])
    /\ MirrorFirst => (s <= Len(replica) /\ Prefix(replica, s) = Prefix(local[p], s))
    /\ wlog' = Prefix(local[p], s)
    /\ cosigned' = cosigned \cup {<<s, key[p], local[p][s]>>}
    /\ UNCHANGED <<local, owner, key, fenceAt, wkey, replica, frozen, lost, nextId, nextKey,
                   recovered>>

\* §9.13.7
Freeze(p) ==
    /\ p = owner
    /\ ~frozen
    /\ frozen' = TRUE
    /\ UNCHANGED <<local, owner, key, fenceAt, wkey, wlog, cosigned, replica, lost, nextId,
                   nextKey, recovered>>

\* §9.13.7, PI-15: the handover batch C_k → pos k..h, the seal at h, the new provider from h + 1
Handover(p, q) ==
    /\ frozen
    /\ p = owner
    /\ q # p
    /\ key[q] = 0
    /\ nextKey <= MaxKey
    /\ Len(local[p]) < MaxLen
    /\ nextId <= MaxId
    /\ LET h == Len(local[p]) + 1
           batch == Append(local[p], nextId)
       IN /\ local' = [local EXCEPT ![p] = batch, ![q] = batch]
          /\ fenceAt' = [fenceAt EXCEPT ![key[p]] = h]
    /\ key' = [key EXCEPT ![q] = nextKey]
    /\ wkey' = nextKey
    /\ owner' = q
    /\ frozen' = FALSE
    /\ nextId' = nextId + 1
    /\ nextKey' = nextKey + 1
    /\ UNCHANGED <<wlog, cosigned, replica, lost, recovered>>

Crash(p) ==
    /\ p = owner
    /\ owner' = None
    /\ frozen' = FALSE
    /\ UNCHANGED <<local, key, fenceAt, wkey, wlog, cosigned, replica, lost, nextId, nextKey,
                   recovered>>

\* SEC21
Fence(p) ==
    /\ owner = None
    /\ LiveKey(p)
    /\ fenceAt' = [fenceAt EXCEPT ![key[p]] = Len(wlog)]
    /\ UNCHANGED <<local, owner, key, wkey, wlog, cosigned, replica, frozen, lost, nextId,
                   nextKey, recovered>>

\* §13.6, SEC20, SEC22
Recover(q) ==
    /\ owner = None
    /\ \A p \in Providers : ~LiveKey(p)
    /\ nextKey <= MaxKey
    /\ nextId <= MaxId
    /\ LET armI == Len(replica) >= Len(wlog) /\ Prefix(replica, Len(wlog)) = wlog
           n == IF armI THEN Len(wlog) ELSE Common(replica, wlog)
       IN /\ n < MaxLen
          /\ local' = [local EXCEPT ![q] = Append(Prefix(replica, n), nextId)]
          /\ replica' = Prefix(replica, n)
          /\ wlog' = Prefix(wlog, n)
          /\ lost' = lost \cup ((n + 1)..Len(wlog))
          /\ recovered' = n + 1
    /\ key' = [key EXCEPT ![q] = nextKey]
    /\ wkey' = nextKey
    /\ owner' = q
    /\ nextId' = nextId + 1
    /\ nextKey' = nextKey + 1
    /\ UNCHANGED <<fenceAt, cosigned, frozen>>

Next ==
    \/ \E p \in Providers :
        \/ AppendRecord(p)
        \/ ZombieAppend(p)
        \/ Freeze(p)
        \/ Crash(p)
        \/ Fence(p)
        \/ Recover(p)
        \/ \E q \in Providers : Handover(p, q)
        \/ \E s \in 1..MaxLen : Cosign(p, s)
    \/ Replicate

CosignOwner == \E p \in Providers : p = owner /\ \E s \in 1..MaxLen : Cosign(p, s)

Spec == Init /\ [][Next]_vars /\ WF_vars(Replicate) /\ WF_vars(CosignOwner)

\* EI-20
SingleLineage == Cardinality({p \in Providers : LiveKey(p)}) <= 1

\* SEC21
NoCosignAfterFence == \A c \in cosigned : c[1] <= fenceAt[c[2]]

\* §6.5 S12
ForksAreDeclared ==
    \A c, d \in cosigned : (c[1] = d[1] /\ c[3] # d[3]) => c[1] \in lost

\* §13.6
HonestFailoverNoFork == MirrorFirst => lost = {}

\* §17.1
MirrorBeforeWitness == MirrorFirst => Len(replica) >= Len(wlog)

\* §9.13.7, §13.6, OP-159 m.25 (a): a witnessed cutover is never rolled back
CutoverIsSealed ==
    \A p \in Providers :
        (key[p] # 0 /\ ~LiveKey(p) /\ fenceAt[key[p]] > 0 /\ p # owner /\ owner # None
            /\ Len(wlog) >= fenceAt[key[p]])
            => fenceAt[key[p]] <= Len(local[owner])

\* §13.6, T17
NewLineageCosigned ==
    \A n \in 1..MaxLen, q \in Providers :
        [](recovered = n /\ owner = q => <>(Len(wlog) >= n \/ owner # q \/ recovered # n))
=============================================================================
