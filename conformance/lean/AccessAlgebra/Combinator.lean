import AccessAlgebra.Order

/-!
The Decision Combinator of protocol/l0/evaluation.md §3–§8, over prepared facts (L0-EVAL-4): each
hop says whether it is understood, covers the intent, is live and has budget; the mandate says
whether it covers the intent and holds; each restriction result is `no_objection`, `deny` or
`require`. A requirement term is matched by a proof through the prepared `fits` relation
(L0-EVAL-22), and the earliest proof by (`position`, `id`) is chosen (L0-EVAL-27).

The theorems are the Access counterparts of Cedar's (CR-48 m.2).
-/

namespace Access.Combinator

open LinOrd

abbrev Term := String

structure Proof where
  position : Nat
  id : String
  deriving DecidableEq, Repr

instance : LinOrd Proof :=
  ofInj (fun p => (p.position, p.id)) (fun a b h => by cases a; cases b; simp_all)

inductive Blocker where
  | noCover (hop : Nat)
  | ended (hop : Nat)
  | budget (hop : Nat)
  | capacity
  | outsideLimits
  | mandateEnded
  | restricted (policy : String)
  deriving DecidableEq, Repr

instance : LinOrd Blocker :=
  ofInj (β := Sum Nat (Sum Nat (Sum Nat (Sum Nat String))))
    (fun | .noCover k => .inl k | .ended k => .inr (.inl k) | .budget k => .inr (.inr (.inl k))
         | .capacity => .inr (.inr (.inr (.inl 0))) | .outsideLimits => .inr (.inr (.inr (.inl 1)))
         | .mandateEnded => .inr (.inr (.inr (.inl 2))) | .restricted p => .inr (.inr (.inr (.inr p))))
    (fun a b h => by cases a <;> cases b <;> simp_all)

structure Hop where
  understood : Bool
  covers : Bool
  live : Bool
  budgetOk : Bool
  terms : List Term

structure Basis where
  hops : List Hop
  capacityOk : Bool

structure Mandate where
  covers : Bool
  ok : Bool
  terms : List Term

inductive PolicyResult where
  | noObjection
  | deny (policy : String)
  | require (terms : List Term)
  deriving DecidableEq

inductive Mode where
  | commit
  | cont
  | check
  deriving DecidableEq

structure Input where
  mode : Mode
  bases : List Basis
  mandate : Option Mandate
  restrictions : List PolicyResult
  proofs : List Proof
  fits : Term → Proof → Bool
  singleUse : Term → Bool

inductive Outcome where
  | allow
  | deny
  | requireAction
  deriving DecidableEq, Repr

structure Decision where
  outcome : Outcome
  blockers : List Blocker
  unmet : List Term
  reliedOn : List Proof
  deriving DecidableEq, Repr

inductive Rejection where
  | input
  | fuel
  deriving DecidableEq, Repr

/-! ### One basis (L0-EVAL-12 … L0-EVAL-19, L0-EVAL-33) -/

/-- L0-EVAL-12, L0-EVAL-12a, L0-EVAL-13 … L0-EVAL-15. -/
def hopBlockers (k : Nat) (h : Hop) : List Blocker :=
  if h.understood then
    (if h.covers then [] else [.noCover k]) ++ (if h.live then [] else [.ended k])
      ++ (if h.budgetOk then [] else [.budget k])
  else [.noCover k]

def hopTerms (h : Hop) : List Term := if h.understood then h.terms else []

def hopsBlockers : Nat → List Hop → List Blocker
  | _, [] => []
  | k, h :: hs => hopBlockers k h ++ hopsBlockers (k + 1) hs

/-- L0-EVAL-16, L0-EVAL-16b. -/
def mandateBlockers : Option Mandate → List Blocker
  | none => []
  | some m => (if m.covers then [] else [.outsideLimits]) ++ (if m.ok then [] else [.mandateEnded])

def mandateTerms : Option Mandate → List Term
  | none => []
  | some m => m.terms

/-- L0-EVAL-18. -/
def resultBlocker : PolicyResult → Option Blocker
  | .deny p => some (.restricted p)
  | _ => none

def resultTerms : PolicyResult → List Term
  | .require ts => ts
  | _ => []

def basisBlockers (inp : Input) (b : Basis) : List Blocker :=
  hopsBlockers 0 b.hops ++ (if b.capacityOk then [] else [.capacity]) ++ mandateBlockers inp.mandate
    ++ inp.restrictions.filterMap resultBlocker

/-- L0-EVAL-20, L0-EVAL-21: identical terms count once and are resolved in canonical order. -/
def basisTerms (inp : Input) (b : Basis) : List Term :=
  nrm (b.hops.flatMap hopTerms ++ mandateTerms inp.mandate ++ inp.restrictions.flatMap resultTerms)

def pick (p q : Proof) : Proof := if lt p q then p else q

/-- L0-EVAL-27: the proof with the earliest (`position`, `id`). -/
def best : List Proof → Option Proof
  | [] => none
  | p :: ps => match best ps with
    | none => some p
    | some q => some (pick p q)

/-- L0-EVAL-20 … L0-EVAL-29: unmet terms and the proofs relied on. -/
def resolve (fits : Term → Proof → Bool) (single : Term → Bool) :
    List Term → List Proof → List Term × List Proof
  | [], _ => ([], [])
  | t :: ts, pool =>
    match best (pool.filter (fits t)) with
    | none => let r := resolve fits single ts pool; (t :: r.1, r.2)
    | some p =>
      let r := resolve fits single ts (if single t then pool.erase p else pool)
      (r.1, p :: r.2)

/-- L0-EVAL-33: deny overrides everything. -/
def basisDecision (inp : Input) (b : Basis) : Decision :=
  let bl := basisBlockers inp b
  let r := resolve inp.fits inp.singleUse (basisTerms inp b) inp.proofs
  if !bl.isEmpty then ⟨.deny, nrm bl, nrm r.1, []⟩
  else if !r.1.isEmpty then ⟨.requireAction, [], nrm r.1, []⟩
  else ⟨.allow, [], [], nrm r.2⟩

/-! ### The whole input (L0-EVAL-34 … L0-EVAL-36, L0-EVAL-45, L0-EVAL-60) -/

/-- L0-EVAL-35, L0-EVAL-35a, L0-EVAL-36. -/
def decideCheck (inp : Input) : Decision :=
  match (inp.bases.map (basisDecision inp)).find? (·.outcome == .allow) with
  | some d => d
  | none => match (inp.bases.map (basisDecision inp)).find? (·.outcome == .requireAction) with
    | some d => d
    | none =>
      ⟨.deny, nrm (if inp.bases.isEmpty then [.noCover 0]
        else (inp.bases.map (basisDecision inp)).flatMap (·.blockers)), [], []⟩

/-- L0-EVAL-3, L0-EVAL-34. -/
def decide (inp : Input) : Except Rejection Decision :=
  if (inp.proofs.map (·.id)).Nodup then
    if inp.mode = .check then .ok (decideCheck inp)
    else match inp.bases with
      | [b] => .ok (basisDecision inp b)
      | _ => .error .input
  else .error .input

/-- L0-EVAL-45, taken over every candidate: an upper bound of the cost the rule charges. -/
def basisCost (inp : Input) (b : Basis) : Nat :=
  b.hops.length + inp.restrictions.length + (basisTerms inp b).length * inp.proofs.length

def cost (inp : Input) : Nat := (inp.bases.map (basisCost inp)).sum

/-- L0-EVAL-46: running out of fuel is a rejection, never a decision. -/
def evaluate (fuel : Nat) (inp : Input) : Except Rejection Decision :=
  match decide inp with
  | .error e => .error e
  | .ok d => if cost inp ≤ fuel then .ok d else .error .fuel

/-- L0-EVAL-62: only an `allow` decision permits an effect. -/
def Allows (fuel : Nat) (inp : Input) : Prop :=
  ∃ d, evaluate fuel inp = .ok d ∧ d.outcome = .allow

/-! ### Lemmas -/

theorem sorted_ext {α : Type} [DecidableEq α] [LinOrd α] :
    ∀ {a b : List α}, Sorted id a → Sorted id b → (∀ x, x ∈ a ↔ x ∈ b) → a = b
  | [], [], _, _, _ => rfl
  | [], y :: _, _, _, h => absurd ((h y).mpr List.mem_cons_self) (by simp)
  | x :: _, [], _, _, h => absurd ((h x).mp List.mem_cons_self) (by simp)
  | x :: as, y :: bs, ha, hb, h => by
    have ha' := List.pairwise_cons.mp ha
    have hb' := List.pairwise_cons.mp hb
    have hxy : x = y := by
      rcases List.mem_cons.mp ((h x).mp List.mem_cons_self) with e | hx
      · exact e
      · rcases List.mem_cons.mp ((h y).mpr List.mem_cons_self) with e | hy
        · exact e.symm
        · have h1 := hb'.1 x hx
          have h2 := ha'.1 y hy
          simp only [id] at h1 h2
          rw [asymm h1] at h2
          exact absurd h2 (by decide)
    subst hxy
    have tail : ∀ z, z ∈ as ↔ z ∈ bs := by
      intro z
      constructor
      · intro hz
        have hne := ne_of_lt (ha'.1 z hz)
        rcases List.mem_cons.mp ((h z).mp (List.mem_cons_of_mem _ hz)) with e | e
        · exact absurd e.symm hne
        · exact e
      · intro hz
        have hne := ne_of_lt (hb'.1 z hz)
        rcases List.mem_cons.mp ((h z).mpr (List.mem_cons_of_mem _ hz)) with e | e
        · exact absurd e.symm hne
        · exact e
    rw [sorted_ext ha'.2 hb'.2 tail]

theorem nrm_ext {α : Type} [DecidableEq α] [LinOrd α] {a b : List α}
    (h : ∀ x, x ∈ a ↔ x ∈ b) : nrm a = nrm b :=
  sorted_ext (sorted_nrmBy id a) (sorted_nrmBy id b) (fun x => by rw [mem_nrm, mem_nrm]; exact h x)

theorem isEmpty_ext {α : Type} {a b : List α} (h : ∀ x, x ∈ a ↔ x ∈ b) : a.isEmpty = b.isEmpty := by
  cases a with
  | nil => cases b with
    | nil => rfl
    | cons y _ => exact absurd ((h y).mpr List.mem_cons_self) (by simp)
  | cons x _ => cases b with
    | nil => exact absurd ((h x).mp List.mem_cons_self) (by simp)
    | cons _ _ => rfl

theorem best_none : ∀ {ps : List Proof}, best ps = none → ps = []
  | [], _ => rfl
  | x :: xs, h => by
    simp only [best] at h
    split at h <;> simp at h

theorem best_spec : ∀ {ps : List Proof} {p : Proof}, best ps = some p →
    p ∈ ps ∧ ∀ q ∈ ps, q = p ∨ lt p q = true
  | [], _, h => by simp [best] at h
  | x :: xs, p, h => by
    cases hb : best xs with
    | none =>
      have := best_none hb
      subst this
      simp only [best, Option.some.injEq] at h
      subst h
      simp
    | some q =>
      have ih := best_spec hb
      simp only [best, hb, Option.some.injEq, pick] at h
      by_cases hlt : lt x q = true
      · simp only [hlt, ↓reduceIte] at h
        subst h
        refine ⟨List.mem_cons_self, fun r hr => ?_⟩
        rcases List.mem_cons.mp hr with e | e
        · exact Or.inl e
        · rcases ih.2 r e with e' | e'
          · exact Or.inr (e' ▸ hlt)
          · exact Or.inr (LinOrd.trans _ _ _ hlt e')
      · simp only [hlt, Bool.false_eq_true, ↓reduceIte] at h
        subst h
        refine ⟨List.mem_cons_of_mem _ ih.1, fun r hr => ?_⟩
        rcases List.mem_cons.mp hr with e | e
        · subst e
          by_cases hrp : r = q
          · exact Or.inl hrp
          · rcases LinOrd.total _ _ hrp with h' | h'
            · exact absurd h' hlt
            · exact Or.inr h'
        · exact ih.2 r e

theorem best_ext {ps qs : List Proof} (h : ∀ x, x ∈ ps ↔ x ∈ qs) : best ps = best qs := by
  cases hp : best ps with
  | none =>
    have := best_none hp
    subst this
    cases hq : best qs with
    | none => rfl
    | some q => exact absurd ((h q).mpr (best_spec hq).1) (by simp)
  | some p =>
    cases hq : best qs with
    | none =>
      have := best_none hq
      subst this
      exact absurd ((h p).mp (best_spec hp).1) (by simp)
    | some q =>
      have sp := best_spec hp
      have sq := best_spec hq
      rcases sp.2 q ((h q).mpr sq.1) with e | e
      · rw [e]
      · rcases sq.2 p ((h p).mp sp.1) with e' | e'
        · rw [e']
        · rw [asymm e] at e'
          exact absurd e' (by decide)

theorem resolve_perm (fits : Term → Proof → Bool) (single : Term → Bool) :
    ∀ (ts : List Term) {pool pool' : List Proof}, pool.Perm pool' →
      resolve fits single ts pool = resolve fits single ts pool'
  | [], _, _, _ => rfl
  | t :: ts, pool, pool', hp => by
    have hb : best (pool.filter (fits t)) = best (pool'.filter (fits t)) :=
      best_ext (fun x => (hp.filter _).mem_iff)
    simp only [resolve, hb]
    split
    · rw [resolve_perm fits single ts hp]
    · rename_i p _
      have hp' : (if single t then pool.erase p else pool).Perm
          (if single t then pool'.erase p else pool') := by
        split
        · exact hp.erase p
        · exact hp
      rw [resolve_perm fits single ts hp']

theorem filter_erase {keep : Proof → Bool} {p : Proof} (hp : keep p = true) :
    ∀ (l : List Proof), (l.filter keep).erase p = (l.erase p).filter keep
  | [] => rfl
  | x :: xs => by
    by_cases hx : x = p
    · subst hx
      simp [hp]
    · have hb : (x == p) = false := by simpa using hx
      cases hk : keep x
      · simp [hk, hb, filter_erase hp xs]
      · simp [hk, hb, filter_erase hp xs]

theorem resolve_slice (fits : Term → Proof → Bool) (single : Term → Bool) (keep : Proof → Bool) :
    ∀ (ts : List Term) {pool : List Proof}, (∀ p ∈ pool, ∀ t, fits t p = true → keep p = true) →
      resolve fits single ts (pool.filter keep) = resolve fits single ts pool
  | [], _, _ => rfl
  | t :: ts, pool, hk => by
    have hf : (pool.filter keep).filter (fits t) = pool.filter (fits t) := by
      rw [List.filter_filter]
      apply List.filter_congr
      intro x hx
      cases hm : fits t x
      · simp
      · simp [hk x hx t hm]
    simp only [resolve, hf]
    split
    · rw [resolve_slice fits single keep ts hk]
    · rename_i p hbest
      have hpm : fits t p = true := by
        have := (best_spec hbest).1
        simp at this
        exact this.2
      have hpk : keep p = true := hk p (by have := (best_spec hbest).1; simp at this; exact this.1) t hpm
      have he : (if single t then (pool.filter keep).erase p else pool.filter keep)
          = (if single t then pool.erase p else pool).filter keep := by
        split
        · exact filter_erase hpk pool
        · rfl
      rw [he, resolve_slice fits single keep ts]
      intro q hq t' hm
      split at hq
      · exact hk q (List.mem_of_mem_erase hq) t' hm
      · exact hk q hq t' hm

theorem resolve_met (fits : Term → Proof → Bool) (single : Term → Bool) {P : List Proof} :
    ∀ (ts : List Term) {pool : List Proof}, (∀ p ∈ pool, p ∈ P) → (resolve fits single ts pool).1 = [] →
      ∀ t ∈ ts, ∃ q ∈ P, fits t q = true
  | [], _, _, _, t, ht => by simp at ht
  | t :: ts, pool, hsub, h, t', ht' => by
    simp only [resolve] at h
    split at h
    · simp at h
    · rename_i p hbest
      have hsub' : ∀ q ∈ (if single t then pool.erase p else pool), q ∈ P := by
        intro q hq
        split at hq
        · exact hsub q (List.mem_of_mem_erase hq)
        · exact hsub q hq
      rcases List.mem_cons.mp ht' with e | e
      · subst e
        have := (best_spec hbest).1
        simp at this
        exact ⟨p, hsub p this.1, this.2⟩
      · exact resolve_met fits single ts hsub' h t' e

theorem hopsBlockers_nil : ∀ {k : Nat} {hs : List Hop}, hopsBlockers k hs = [] →
    ∀ h ∈ hs, h.understood = true ∧ h.covers = true ∧ h.live = true ∧ h.budgetOk = true
  | _, [], _, _, hh => by simp at hh
  | k, x :: xs, he, h, hh => by
    simp only [hopsBlockers, List.append_eq_nil_iff] at he
    rcases List.mem_cons.mp hh with e | e
    · subst e
      have := he.1
      unfold hopBlockers at this
      split at this
      · simp only [List.append_eq_nil_iff] at this
        refine ⟨by assumption, ?_, ?_, ?_⟩
        · cases hc : h.covers <;> simp_all
        · cases hc : h.live <;> simp_all
        · cases hc : h.budgetOk <;> simp_all
      · simp at this
    · exact hopsBlockers_nil he.2 h e

theorem mem_restriction_blocker {rs : List PolicyResult} {p : String} (h : PolicyResult.deny p ∈ rs) :
    Blocker.restricted p ∈ rs.filterMap resultBlocker :=
  List.mem_filterMap.mpr ⟨_, h, rfl⟩

theorem basis_denies {inp : Input} {b : Basis} {p : String} (h : PolicyResult.deny p ∈ inp.restrictions) :
    (basisDecision inp b).outcome = .deny := by
  have hm : Blocker.restricted p ∈ basisBlockers inp b := by
    simp only [basisBlockers, List.mem_append]
    exact Or.inr (mem_restriction_blocker h)
  have hne : (basisBlockers inp b).isEmpty = false := by
    cases hb : basisBlockers inp b with
    | nil => rw [hb] at hm; simp at hm
    | cons _ _ => rfl
  simp [basisDecision, hne]

theorem basis_allows {inp : Input} {b : Basis} (h : (basisDecision inp b).outcome = .allow) :
    basisBlockers inp b = [] ∧ (resolve inp.fits inp.singleUse (basisTerms inp b) inp.proofs).1 = [] := by
  unfold basisDecision at h
  simp only at h
  split at h
  · simp at h
  · split at h
    · simp at h
    · rename_i h1 h2
      simp only [Bool.not_eq_true', List.isEmpty_eq_false_iff, ne_eq, Decidable.not_not] at h1 h2
      exact ⟨by simpa using h1, by simpa using h2⟩

theorem decideCheck_mem {inp : Input} (ha : (decideCheck inp).outcome = .allow) :
    ∃ b ∈ inp.bases, basisDecision inp b = decideCheck inp := by
  have key : decideCheck inp ∈ inp.bases.map (basisDecision inp) := by
    unfold decideCheck at ha ⊢
    cases hf : (inp.bases.map (basisDecision inp)).find? (·.outcome == .allow) with
    | some d =>
      exact List.mem_of_find?_eq_some hf
    | none =>
      cases hr : (inp.bases.map (basisDecision inp)).find? (·.outcome == .requireAction) with
      | some d =>
        simp only [hf, hr] at ha
        have := List.find?_some hr
        rw [ha] at this
        cases this
      | none =>
        simp only [hf, hr] at ha
        cases ha
  obtain ⟨b, hb, e⟩ := List.mem_map.mp key
  exact ⟨b, hb, e⟩

theorem decide_ok {inp : Input} {d : Decision} (h : decide inp = .ok d) :
    (inp.proofs.map (·.id)).Nodup ∧
      ((inp.mode = .check ∧ d = decideCheck inp) ∨ (∃ b, inp.bases = [b] ∧ d = basisDecision inp b)) := by
  unfold decide at h
  by_cases hn : (inp.proofs.map (·.id)).Nodup
  · refine ⟨hn, ?_⟩
    simp only [hn, ↓reduceIte] at h
    by_cases hm : inp.mode = .check
    · simp only [hm, ↓reduceIte, Except.ok.injEq] at h
      exact Or.inl ⟨hm, h.symm⟩
    · simp only [hm, ↓reduceIte] at h
      split at h
      · rename_i b hb
        cases h
        exact Or.inr ⟨b, hb, rfl⟩
      · cases h
  · simp only [hn, ↓reduceIte] at h
    cases h

theorem decide_allows {inp : Input} {d : Decision} (h : decide inp = .ok d) (ha : d.outcome = .allow) :
    ∃ b ∈ inp.bases, basisDecision inp b = d := by
  rcases (decide_ok h).2 with ⟨_, e⟩ | ⟨b, hb, e⟩
  · subst e
    exact decideCheck_mem ha
  · exact ⟨b, by simp [hb], e.symm⟩

theorem evaluate_ok {fuel : Nat} {inp : Input} {d : Decision} (h : evaluate fuel inp = .ok d) :
    decide inp = .ok d ∧ cost inp ≤ fuel := by
  unfold evaluate at h
  split at h
  · cases h
  · rename_i d' hd
    split at h
    · cases h
      exact ⟨hd, by assumption⟩
    · cases h

theorem decide_congr {inp inp' : Input} (hm : inp.mode = inp'.mode) (hb : inp.bases = inp'.bases)
    (hn : (inp.proofs.map (·.id)).Nodup ↔ (inp'.proofs.map (·.id)).Nodup)
    (hc : decideCheck inp = decideCheck inp') (hd : ∀ b, basisDecision inp b = basisDecision inp' b) :
    decide inp = decide inp' := by
  unfold decide
  simp only [hm, hb, hc, hd, hn]

/-! ### Theorems (CR-48 m.2) -/

/-- `forbid_trumps_permit`: a restriction that denies overrides every covering basis (MD-4,
L0-EVAL-33). -/
theorem forbid_trumps_permit {fuel : Nat} {inp : Input} {d : Decision} {p : String}
    (hr : PolicyResult.deny p ∈ inp.restrictions) (he : evaluate fuel inp = .ok d) :
    d.outcome = .deny := by
  rcases (decide_ok (evaluate_ok he).1).2 with ⟨_, e⟩ | ⟨b, _, e⟩
  · subst e
    have hall : ∀ x ∈ inp.bases.map (basisDecision inp), x.outcome = .deny := by
      intro x hx
      obtain ⟨b, _, e⟩ := List.mem_map.mp hx
      rw [← e]
      exact basis_denies hr
    unfold decideCheck
    cases hf : (inp.bases.map (basisDecision inp)).find? (·.outcome == .allow) with
    | some x =>
      have h1 := hall x (List.mem_of_find?_eq_some hf)
      have h2 := List.find?_some hf
      rw [h1] at h2
      cases h2
    | none =>
      cases hq : (inp.bases.map (basisDecision inp)).find? (·.outcome == .requireAction) with
      | some x =>
        have h1 := hall x (List.mem_of_find?_eq_some hq)
        have h2 := List.find?_some hq
        rw [h1] at h2
        cases h2
      | none => rfl
  · subst e
    exact basis_denies hr

/-- `default_deny`: a rejection (malformed input, an ambiguous basis count, fuel), no candidate
basis, or a hop on every basis that is not understood or does not cover gives no ALLOW (SI-6,
TI-9, MD-8). -/
theorem default_deny {fuel : Nat} {inp : Input}
    (h : (∃ e, evaluate fuel inp = .error e) ∨ inp.bases = []
      ∨ (∀ b ∈ inp.bases, ∃ x ∈ b.hops, x.understood = false ∨ x.covers = false)) :
    ¬ Allows fuel inp := by
  rintro ⟨d, he, ha⟩
  have hd : decide inp = .ok d := (evaluate_ok he).1
  obtain ⟨b, hb, e⟩ := decide_allows hd ha
  have hbl := (basis_allows (e ▸ ha : (basisDecision inp b).outcome = .allow)).1
  rcases h with ⟨err, herr⟩ | hn | hh
  · rw [he] at herr; cases herr
  · rw [hn] at hb; simp at hb
  · obtain ⟨x, hx, hux⟩ := hh b hb
    simp only [basisBlockers, List.append_eq_nil_iff] at hbl
    have := hopsBlockers_nil hbl.1.1.1 x hx
    rcases hux with u | u <;> simp_all

/-- `allowed_only_if_explicitly_permitted`: ALLOW needs a basis whose every hop covers and holds,
whose capacity is declared, a mandate that covers and holds, no denying restriction, and a
matching proof for every requirement term (L0-EVAL-33). -/
theorem allowed_only_if_explicitly_permitted {fuel : Nat} {inp : Input} (h : Allows fuel inp) :
    ∃ b ∈ inp.bases,
      (∀ x ∈ b.hops, x.understood = true ∧ x.covers = true ∧ x.live = true ∧ x.budgetOk = true)
      ∧ b.capacityOk = true
      ∧ (∀ m, inp.mandate = some m → m.covers = true ∧ m.ok = true)
      ∧ (∀ p, PolicyResult.deny p ∉ inp.restrictions)
      ∧ (∀ t ∈ basisTerms inp b, ∃ q ∈ inp.proofs, inp.fits t q = true) := by
  obtain ⟨d, he, ha⟩ := h
  have hd : decide inp = .ok d := (evaluate_ok he).1
  obtain ⟨b, hb, e⟩ := decide_allows hd ha
  have hab := basis_allows (e ▸ ha : (basisDecision inp b).outcome = .allow)
  have hbl := hab.1
  simp only [basisBlockers, List.append_eq_nil_iff] at hbl
  refine ⟨b, hb, hopsBlockers_nil hbl.1.1.1, ?_, ?_, ?_, ?_⟩
  · cases hc : b.capacityOk <;> simp_all
  · intro m hm
    have := hbl.1.2
    rw [hm] at this
    simp only [mandateBlockers, List.append_eq_nil_iff] at this
    constructor
    · cases hc : m.covers <;> simp_all
    · cases hc : m.ok <;> simp_all
  · intro p hp
    have := mem_restriction_blocker hp
    rw [hbl.2] at this
    simp at this
  · exact resolve_met inp.fits inp.singleUse _ (fun p hp => hp) hab.2

theorem basisDecision_congr {inp inp' : Input} (b : Basis)
    (hb : ∀ x, x ∈ basisBlockers inp b ↔ x ∈ basisBlockers inp' b)
    (hr : resolve inp.fits inp.singleUse (basisTerms inp b) inp.proofs
      = resolve inp'.fits inp'.singleUse (basisTerms inp' b) inp'.proofs) :
    basisDecision inp b = basisDecision inp' b := by
  unfold basisDecision
  simp only [isEmpty_ext hb, nrm_ext hb, hr]

theorem decideCheck_congr {inp inp' : Input} (hb : inp.bases = inp'.bases)
    (hd : ∀ b, basisDecision inp b = basisDecision inp' b) : decideCheck inp = decideCheck inp' := by
  have hf : basisDecision inp = basisDecision inp' := funext hd
  unfold decideCheck
  rw [hf, hb]

/-- `order_and_dup_independent`: the decision does not depend on the order of the presented
proofs, nor on the order or repetition of the restriction results (INV-27). Which proof is relied
on follows the earliest-position rule (T14, L0-EVAL-27), a property of the proofs, not of their
order. -/
theorem order_and_dup_independent (inp : Input) {rs : List PolicyResult} {ps : List Proof}
    (hr : ∀ r, r ∈ inp.restrictions ↔ r ∈ rs) (hp : inp.proofs.Perm ps) :
    decide inp = decide { inp with restrictions := rs, proofs := ps } := by
  let inp' : Input := { inp with restrictions := rs, proofs := ps }
  have hbl : ∀ b, ∀ x, x ∈ basisBlockers inp b ↔ x ∈ basisBlockers inp' b := by
    intro b x
    simp only [basisBlockers, List.mem_append, List.mem_filterMap, inp']
    constructor
    · rintro (h | ⟨r, hm, e⟩)
      · exact Or.inl h
      · exact Or.inr ⟨r, (hr r).mp hm, e⟩
    · rintro (h | ⟨r, hm, e⟩)
      · exact Or.inl h
      · exact Or.inr ⟨r, (hr r).mpr hm, e⟩
  have hts : ∀ b, basisTerms inp b = basisTerms inp' b := by
    intro b
    apply nrm_ext
    intro x
    simp only [List.mem_append, List.mem_flatMap, inp']
    constructor
    · rintro (h | ⟨r, hm, e⟩)
      · exact Or.inl h
      · exact Or.inr ⟨r, (hr r).mp hm, e⟩
    · rintro (h | ⟨r, hm, e⟩)
      · exact Or.inl h
      · exact Or.inr ⟨r, (hr r).mpr hm, e⟩
  have hd : ∀ b, basisDecision inp b = basisDecision inp' b := by
    intro b
    apply basisDecision_congr b (hbl b)
    rw [← hts b]
    exact resolve_perm inp.fits inp.singleUse _ hp
  have hc := decideCheck_congr (inp := inp) (inp' := inp') rfl hd
  exact decide_congr rfl rfl (hp.map _).nodup_iff hc hd

def objects : PolicyResult → Bool
  | .noObjection => false
  | _ => true

/-- An index or cache that drops `no_objection` results and proofs that match no term. -/
def slice (keep : Proof → Bool) (inp : Input) : Input :=
  { inp with
    restrictions := inp.restrictions.filter objects
    proofs := inp.proofs.filter keep }

theorem filterMap_slice (rs : List PolicyResult) :
    (rs.filter objects).filterMap resultBlocker = rs.filterMap resultBlocker := by
  induction rs with
  | nil => rfl
  | cons r rs ih =>
    cases r with
    | noObjection => simp only [List.filter, objects, List.filterMap_cons, resultBlocker, ih]
    | deny p => simp only [List.filter, objects, List.filterMap_cons, resultBlocker, ih]
    | require ts => simp only [List.filter, objects, List.filterMap_cons, resultBlocker, ih]

theorem flatMap_slice (rs : List PolicyResult) :
    (rs.filter objects).flatMap resultTerms = rs.flatMap resultTerms := by
  induction rs with
  | nil => rfl
  | cons r rs ih =>
    cases r with
    | noObjection => simp only [List.filter, objects, List.flatMap_cons, resultTerms, ih, List.nil_append]
    | deny p => simp only [List.filter, objects, List.flatMap_cons, resultTerms, ih, List.nil_append]
    | require ts => simp only [List.filter, objects, List.flatMap_cons, resultTerms, ih]

theorem sum_le {α : Type} {f g : α → Nat} :
    ∀ (l : List α), (∀ x ∈ l, f x ≤ g x) → (l.map f).sum ≤ (l.map g).sum
  | [], _ => by simp
  | x :: xs, h => by
    simp only [List.map_cons, List.sum_cons]
    have := sum_le xs (fun y hy => h y (List.mem_cons_of_mem _ hy))
    have := h x List.mem_cons_self
    omega

/-- Sound slicing (Cedar's `PolicySlice`): evaluating only the restriction results that object and
the proofs that match some term gives the same decision, within the same fuel (cache
transparency, CR-49 m.3). -/
theorem sound_slicing {fuel : Nat} {inp : Input} {d : Decision} (keep : Proof → Bool)
    (hk : ∀ p ∈ inp.proofs, ∀ t, inp.fits t p = true → keep p = true)
    (he : evaluate fuel inp = .ok d) : evaluate fuel (slice keep inp) = .ok d := by
  let s := slice keep inp
  have hbl : ∀ b, basisBlockers s b = basisBlockers inp b := by
    intro b
    simp only [basisBlockers, s, slice, filterMap_slice]
  have hts : ∀ b, basisTerms s b = basisTerms inp b := by
    intro b
    simp only [basisTerms, s, slice, flatMap_slice]
  have hd : ∀ b, basisDecision s b = basisDecision inp b := by
    intro b
    apply basisDecision_congr b (fun x => by rw [hbl b])
    rw [hts b]
    exact resolve_slice inp.fits inp.singleUse keep _ hk
  have hc := decideCheck_congr (inp := s) (inp' := inp) rfl hd
  have hcost : cost s ≤ cost inp := by
    unfold cost
    apply sum_le
    intro b _
    unfold basisCost
    rw [hts b]
    have h1 : s.restrictions.length ≤ inp.restrictions.length := List.length_filter_le _ _
    have h2 : s.proofs.length ≤ inp.proofs.length := List.length_filter_le _ _
    have h3 := Nat.mul_le_mul_left (basisTerms inp b).length h2
    omega
  obtain ⟨hdec, hfuel⟩ := evaluate_ok he
  have hnod := (decide_ok hdec).1
  have hnod' : (s.proofs.map (·.id)).Nodup := hnod.sublist (List.filter_sublist.map _)
  have heq : decide s = decide inp := decide_congr rfl rfl ⟨fun _ => hnod, fun _ => hnod'⟩ hc hd
  unfold evaluate
  rw [heq, hdec]
  have hf : cost (slice keep inp) ≤ fuel := Nat.le_trans hcost hfuel
  simp only [hf, ↓reduceIte]

end Access.Combinator
