/-!
Holding episodes (INV-31, TI-RT9, SI-10, CR-48 m.3). A holding through a dynamic selector lives
in episodes. The history is a list of events, newest first; an event's position is the number of
events before it.

- `qualifies b`: the holder's qualification, recomputed from the claims it rests on;
- `stale`: a proof aged past its freshness, the qualification unchanged;
- `close`: an affirmative close (terminal lapse, revoke);
- `cutoff`: an ingest-time cutoff on the acceptance closes the episodes that rest on later claims;
- `uncutoff`: the cutoff is lifted, a widening.

`eager` replays every event; `lazySince` reads only the qualification levels and finds the last
false→true transition. They agree.
-/

namespace Access.Holding

inductive Ev where
  | qualifies (b : Bool)
  | stale
  | close
  | cutoff
  | uncutoff
  deriving DecidableEq, Repr

structure St where
  since : Option Nat
  qualified : Bool
  deriving DecidableEq, Repr

def step (s : St) (n : Nat) : Ev → St
  | .qualifies true => if s.qualified then s else ⟨some n, true⟩
  | .qualifies false => ⟨none, false⟩
  | .stale => s
  | .close => ⟨none, false⟩
  | .cutoff => ⟨none, false⟩
  | .uncutoff => s

def eager : List Ev → St
  | [] => ⟨none, false⟩
  | e :: h => step (eager h) h.length e

/-- The qualification level after a history: set by the newest event that sets it. -/
def level : List Ev → Bool
  | [] => false
  | .qualifies b :: _ => b
  | .close :: _ => false
  | .cutoff :: _ => false
  | .stale :: h => level h
  | .uncutoff :: h => level h

/-- TI-RT9: the position of the newest false→true transition of the level. -/
def lastRise : List Ev → Option Nat
  | [] => none
  | e :: h => if level (e :: h) && !level h then some h.length else lastRise h

def lazySince (h : List Ev) : Option Nat := if level h then lastRise h else none

/-- TI-RT9: the lazy computation equals the eager one. -/
theorem lazy_eq_eager : ∀ h : List Ev, eager h = ⟨lazySince h, level h⟩
  | [] => rfl
  | e :: h => by
    have ih := lazy_eq_eager h
    simp only [eager, ih]
    cases e with
    | qualifies b =>
      cases b with
      | true =>
        cases hl : level h with
        | true => simp [step, lazySince, lastRise, level, hl]
        | false => simp [step, lazySince, lastRise, level, hl]
      | false => simp [step, lazySince, level]
    | stale => cases hl : level h <;> simp [step, lazySince, lastRise, level, hl]
    | close => simp [step, lazySince, level]
    | cutoff => simp [step, lazySince, level]
    | uncutoff => cases hl : level h <;> simp [step, lazySince, lastRise, level, hl]

/-- INV-31: staleness does not close an episode. -/
theorem staleness_keeps_episode (h : List Ev) : eager (.stale :: h) = eager h := rfl

theorem since_lt : ∀ {h : List Ev} {s : Nat}, (eager h).since = some s → s < h.length
  | [], _, hs => by simp [eager] at hs
  | e :: h, s, hs => by
    simp only [eager] at hs
    cases e with
    | qualifies b =>
      cases b with
      | true =>
        simp only [step] at hs
        split at hs
        · have := since_lt hs; simp; omega
        · simp at hs; simp; omega
      | false => simp [step] at hs
    | stale => have := since_lt hs; simp; omega
    | close => simp [step] at hs
    | cutoff => simp [step] at hs
    | uncutoff => have := since_lt hs; simp; omega

def Closes : Ev → Prop
  | .close => True
  | .cutoff => True
  | .qualifies false => True
  | _ => False

/-- Every episode current after a closing event started after it. -/
theorem since_after_close {c : Ev} (hc : Closes c) (h : List Ev) :
    ∀ (h' : List Ev) {s : Nat}, (eager (h' ++ c :: h)).since = some s → h.length < s
  | [], s, hs => by
    cases c with
    | qualifies b => cases b <;> simp_all [Closes, eager, step]
    | stale => simp [Closes] at hc
    | close => simp [eager, step] at hs
    | cutoff => simp [eager, step] at hs
    | uncutoff => simp [Closes] at hc
  | e :: h', s, hs => by
    simp only [List.cons_append, eager] at hs
    have hlen : h.length < (h' ++ c :: h).length := by simp; omega
    cases e with
    | qualifies b =>
      cases b with
      | true =>
        simp only [step] at hs
        split at hs
        · exact since_after_close hc h h' hs
        · simp at hs; omega
      | false => simp [step] at hs
    | stale => exact since_after_close hc h h' hs
    | close => simp [step] at hs
    | cutoff => simp [step] at hs
    | uncutoff => exact since_after_close hc h h' hs

/-- INV-31: an affirmative close is terminal. The closed episode is never current again, whatever
follows; a later re-qualification is a new episode. -/
theorem close_is_terminal {h : List Ev} {s : Nat} (hs : (eager h).since = some s) (h' : List Ev) :
    (eager (h' ++ .close :: h)).since ≠ some s := by
  intro e
  have := since_after_close (c := .close) trivial h h' e
  have := since_lt hs
  omega

/-- SI-10: lifting a cutoff is a widening; the episodes the cutoff closed do not come back. -/
theorem cutoff_lift_never_revives {h : List Ev} {s : Nat} (hs : (eager h).since = some s)
    (h' : List Ev) : (eager (h' ++ .uncutoff :: .cutoff :: h)).since ≠ some s := by
  intro e
  have := since_after_close (c := .cutoff) trivial h (h' ++ [.uncutoff]) (by simpa using e)
  have := since_lt hs
  omega

end Access.Holding
