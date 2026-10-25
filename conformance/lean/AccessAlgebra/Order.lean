/-!
Strict total orders and the sorted, duplicate-free lists that serve as canonical sets and maps.
-/

namespace Access

class LinOrd (α : Type) [DecidableEq α] where
  lt : α → α → Bool
  irrefl : ∀ a, lt a a = false
  trans : ∀ a b c, lt a b = true → lt b c = true → lt a c = true
  total : ∀ a b, a ≠ b → lt a b = true ∨ lt b a = true

namespace LinOrd

variable {α β : Type} [DecidableEq α] [DecidableEq β]

theorem asymm [LinOrd α] {a b : α} (h : lt a b = true) : lt b a = false := by
  cases h' : lt b a
  · rfl
  · have := LinOrd.trans a b a h h'
    rw [LinOrd.irrefl] at this
    exact absurd this (by decide)

theorem ne_of_lt [LinOrd α] {a b : α} (h : lt a b = true) : a ≠ b := by
  intro e
  subst e
  rw [LinOrd.irrefl] at h
  exact absurd h (by decide)

@[reducible] def ofInj [LinOrd β] (f : α → β) (hf : ∀ a b, f a = f b → a = b) : LinOrd α where
  lt a b := lt (f a) (f b)
  irrefl a := LinOrd.irrefl (f a)
  trans a b c := LinOrd.trans (f a) (f b) (f c)
  total a b h := LinOrd.total (f a) (f b) (fun e => h (hf a b e))

instance : LinOrd Nat where
  lt a b := decide (a < b)
  irrefl a := by simp
  trans a b c := by simp only [decide_eq_true_eq]; omega
  total a b h := by simp only [decide_eq_true_eq]; omega

instance : LinOrd Int where
  lt a b := decide (a < b)
  irrefl a := by simp
  trans a b c := by simp only [decide_eq_true_eq]; omega
  total a b h := by simp only [decide_eq_true_eq]; omega

instance : LinOrd Bool where
  lt a b := !a && b
  irrefl a := by cases a <;> rfl
  trans a b c := by cases a <;> cases b <;> cases c <;> simp
  total a b := by cases a <;> cases b <;> simp

instance [LinOrd α] [LinOrd β] : LinOrd (α × β) where
  lt x y := lt x.1 y.1 || (decide (x.1 = y.1) && lt x.2 y.2)
  irrefl x := by simp [LinOrd.irrefl]
  trans x y z := by
    intro h1 h2
    simp only [Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq] at h1 h2 ⊢
    rcases h1 with h1 | ⟨e1, h1⟩ <;> rcases h2 with h2 | ⟨e2, h2⟩
    · exact Or.inl (LinOrd.trans _ _ _ h1 h2)
    · exact Or.inl (e2 ▸ h1)
    · exact Or.inl (e1 ▸ h2)
    · exact Or.inr ⟨e1.trans e2, LinOrd.trans _ _ _ h1 h2⟩
  total x y h := by
    simp only [Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq]
    by_cases e : x.1 = y.1
    · have : x.2 ≠ y.2 := fun e2 => h (Prod.ext e e2)
      rcases LinOrd.total _ _ this with h' | h'
      · exact Or.inl (Or.inr ⟨e, h'⟩)
      · exact Or.inr (Or.inr ⟨e.symm, h'⟩)
    · rcases LinOrd.total _ _ e with h' | h'
      · exact Or.inl (Or.inl h')
      · exact Or.inr (Or.inl h')

instance [LinOrd α] [LinOrd β] : LinOrd (Sum α β) where
  lt
    | .inl a, .inl b => lt a b
    | .inl _, .inr _ => true
    | .inr _, .inl _ => false
    | .inr a, .inr b => lt a b
  irrefl x := by cases x <;> simp [LinOrd.irrefl]
  trans x y z := by
    cases x <;> cases y <;> cases z <;> simp <;> exact LinOrd.trans _ _ _
  total x y h := by
    cases x <;> cases y <;> simp at h ⊢ <;> exact LinOrd.total _ _ h

instance [LinOrd α] : LinOrd (Option α) where
  lt
    | none, none => false
    | none, some _ => true
    | some _, none => false
    | some a, some b => lt a b
  irrefl x := by cases x <;> simp [LinOrd.irrefl]
  trans x y z := by
    cases x <;> cases y <;> cases z <;> simp <;> exact LinOrd.trans _ _ _
  total x y h := by
    cases x <;> cases y <;> simp at h ⊢ <;> exact LinOrd.total _ _ h

def listLt [LinOrd α] : List α → List α → Bool
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | a :: as, b :: bs => lt a b || (decide (a = b) && listLt as bs)

theorem listLt_irrefl [LinOrd α] : ∀ l : List α, listLt l l = false
  | [] => rfl
  | a :: as => by simp [listLt, LinOrd.irrefl, listLt_irrefl as]

theorem listLt_trans [LinOrd α] :
    ∀ x y z : List α, listLt x y = true → listLt y z = true → listLt x z = true
  | [], [], _, h, _ => by simp [listLt] at h
  | [], _ :: _, [], _, h => by simp [listLt] at h
  | [], _ :: _, _ :: _, _, _ => rfl
  | _ :: _, [], _, h, _ => by simp [listLt] at h
  | _ :: _, _ :: _, [], _, h => by simp [listLt] at h
  | a :: as, b :: bs, c :: cs, h1, h2 => by
    simp only [listLt, Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq] at h1 h2 ⊢
    rcases h1 with h1 | ⟨e1, h1⟩ <;> rcases h2 with h2 | ⟨e2, h2⟩
    · exact Or.inl (LinOrd.trans _ _ _ h1 h2)
    · exact Or.inl (e2 ▸ h1)
    · exact Or.inl (e1 ▸ h2)
    · exact Or.inr ⟨e1.trans e2, listLt_trans as bs cs h1 h2⟩

theorem listLt_total [LinOrd α] :
    ∀ x y : List α, x ≠ y → listLt x y = true ∨ listLt y x = true
  | [], [], h => absurd rfl h
  | [], _ :: _, _ => Or.inl rfl
  | _ :: _, [], _ => Or.inr rfl
  | a :: as, b :: bs, h => by
    simp only [listLt, Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq]
    by_cases e : a = b
    · subst e
      have : as ≠ bs := fun e2 => h (e2 ▸ rfl)
      rcases listLt_total as bs this with h' | h'
      · exact Or.inl (Or.inr ⟨rfl, h'⟩)
      · exact Or.inr (Or.inr ⟨rfl, h'⟩)
    · rcases LinOrd.total _ _ e with h' | h'
      · exact Or.inl (Or.inl h')
      · exact Or.inr (Or.inl h')

instance [LinOrd α] : LinOrd (List α) where
  lt := listLt
  irrefl := listLt_irrefl
  trans := listLt_trans
  total := listLt_total

instance : LinOrd Char :=
  ofInj Char.toNat (fun _ _ h => Char.toNat_inj.mp h)

instance : LinOrd String :=
  ofInj String.toList (fun _ _ h => String.toList_inj.mp h)

end LinOrd

open LinOrd

section Sorted

variable {α κ β : Type} [DecidableEq κ] [LinOrd κ]

/-- Insert `y`; an element with the same key is replaced, so the inserted element wins. -/
def ins (key : α → κ) (y : α) : List α → List α
  | [] => [y]
  | z :: zs =>
    if lt (key y) (key z) then y :: z :: zs
    else if key y = key z then y :: zs
    else z :: ins key y zs

/-- Sorted by key, one element per key; the first occurrence of a key wins. -/
def nrmBy (key : α → κ) (l : List α) : List α := l.foldr (ins key) []

/-- Canonical set: sorted, without repeats. -/
abbrev nrm [DecidableEq α] [LinOrd α] (l : List α) : List α := nrmBy id l

def Sorted (key : α → κ) (l : List α) : Prop := l.Pairwise (fun a b => lt (key a) (key b) = true)

theorem mem_ins {key : α → κ} {x y : α} :
    ∀ {l : List α}, x ∈ ins key y l → x = y ∨ x ∈ l
  | [], h => by simp [ins] at h; exact Or.inl h
  | z :: zs, h => by
    unfold ins at h
    split at h
    · simpa using h
    · split at h
      · simp at h
        rcases h with h | h
        · exact Or.inl h
        · exact Or.inr (List.mem_cons_of_mem _ h)
      · simp at h
        rcases h with h | h
        · exact Or.inr (h ▸ List.mem_cons_self)
        · rcases mem_ins h with h | h
          · exact Or.inl h
          · exact Or.inr (List.mem_cons_of_mem _ h)

theorem self_mem_ins {key : α → κ} {y : α} : ∀ {l : List α}, y ∈ ins key y l
  | [] => by simp [ins]
  | z :: zs => by
    unfold ins
    split
    · simp
    · split
      · simp
      · exact List.mem_cons_of_mem _ self_mem_ins

theorem mem_ins_of {key : α → κ} {x y : α} :
    ∀ {l : List α}, x ∈ l → key x ≠ key y → x ∈ ins key y l
  | [], h, _ => by simp at h
  | z :: zs, h, hk => by
    unfold ins
    split
    · exact List.mem_cons_of_mem _ h
    · split
      · rename_i e
        rcases List.mem_cons.mp h with h | h
        · subst h; exact absurd e.symm hk
        · exact List.mem_cons_of_mem _ h
      · rcases List.mem_cons.mp h with h | h
        · subst h; exact List.mem_cons_self
        · exact List.mem_cons_of_mem _ (mem_ins_of h hk)

theorem sorted_ins {key : α → κ} {y : α} :
    ∀ {l : List α}, Sorted key l → Sorted key (ins key y l)
  | [], _ => by simp [ins, Sorted]
  | z :: zs, h => by
    have hz := List.pairwise_cons.mp h
    unfold ins
    split
    · rename_i hlt
      refine List.Pairwise.cons ?_ h
      intro w hw
      rcases List.mem_cons.mp hw with hw | hw
      · exact hw ▸ hlt
      · exact LinOrd.trans _ _ _ hlt (hz.1 w hw)
    · split
      · rename_i e
        refine List.Pairwise.cons ?_ hz.2
        intro w hw
        rw [e]; exact hz.1 w hw
      · rename_i hlt e
        refine List.Pairwise.cons ?_ (sorted_ins hz.2)
        intro w hw
        rcases mem_ins hw with hw | hw
        · subst hw
          rcases LinOrd.total _ _ e with h' | h'
          · simp_all
          · exact h'
        · exact hz.1 w hw

theorem ins_of_lt {key : α → κ} {y : α} :
    ∀ {l : List α}, (∀ z ∈ l, lt (key y) (key z) = true) → ins key y l = y :: l
  | [], _ => rfl
  | z :: zs, h => by
    unfold ins
    simp [h z List.mem_cons_self]

theorem sorted_nrmBy (key : α → κ) : ∀ l : List α, Sorted key (nrmBy key l)
  | [] => List.Pairwise.nil
  | _ :: l => sorted_ins (sorted_nrmBy key l)

theorem nrmBy_of_sorted {key : α → κ} : ∀ {l : List α}, Sorted key l → nrmBy key l = l
  | [], _ => rfl
  | y :: l, h => by
    have h' := List.pairwise_cons.mp h
    show ins key y (nrmBy key l) = y :: l
    rw [nrmBy_of_sorted h'.2]
    exact ins_of_lt h'.1

theorem nrmBy_idem (key : α → κ) (l : List α) : nrmBy key (nrmBy key l) = nrmBy key l :=
  nrmBy_of_sorted (sorted_nrmBy key l)

theorem mem_of_mem_nrmBy {key : α → κ} {x : α} : ∀ {l : List α}, x ∈ nrmBy key l → x ∈ l
  | [], h => by simp [nrmBy] at h
  | y :: l, h => by
    rcases mem_ins h with h | h
    · exact h ▸ List.mem_cons_self
    · exact List.mem_cons_of_mem _ (mem_of_mem_nrmBy h)

theorem mem_nrm [DecidableEq α] [LinOrd α] {x : α} : ∀ {l : List α}, x ∈ nrm l ↔ x ∈ l
  | [] => by simp [nrmBy]
  | y :: l => by
    constructor
    · exact mem_of_mem_nrmBy
    · intro h
      show x ∈ ins id y (nrmBy id l)
      by_cases e : x = y
      · subst e; exact self_mem_ins
      · rcases List.mem_cons.mp h with h | h
        · exact absurd h e
        · exact mem_ins_of (mem_nrm.mpr h) e

theorem nrm_eq_nil [DecidableEq α] [LinOrd α] {l : List α} : nrm l = [] ↔ l = [] := by
  constructor
  · intro h
    cases l with
    | nil => rfl
    | cons y t =>
      have : y ∈ nrm (y :: t) := mem_nrm.mpr List.mem_cons_self
      rw [h] at this; simp at this
  · intro h; subst h; rfl

end Sorted

section Maps

variable {κ β γ : Type} [DecidableEq κ]

/-- Value of the first entry with key `k`. -/
def look (k : κ) : List (κ × β) → Option β
  | [] => none
  | (k', v) :: t => if k' = k then some v else look k t

theorem look_mem {k : κ} {v : β} : ∀ {l : List (κ × β)}, look k l = some v → (k, v) ∈ l
  | [], h => by simp [look] at h
  | (k', v') :: t, h => by
    unfold look at h
    split at h
    · rename_i e; subst e; simp at h; subst h; exact List.mem_cons_self
    · exact List.mem_cons_of_mem _ (look_mem h)

theorem look_isSome_of_mem {k : κ} {v : β} :
    ∀ {l : List (κ × β)}, (k, v) ∈ l → ∃ w, look k l = some w
  | [], h => by simp at h
  | (k', v') :: t, h => by
    unfold look
    split
    · exact ⟨v', rfl⟩
    · rename_i e
      rcases List.mem_cons.mp h with h | h
      · simp at h; exact absurd h.1.symm e
      · exact look_isSome_of_mem h

theorem look_append {k : κ} :
    ∀ (l m : List (κ × β)), look k (l ++ m) = (look k l).or (look k m)
  | [], m => by simp [look]
  | (k', v) :: t, m => by
    simp only [List.cons_append, look]
    split
    · rfl
    · exact look_append t m

theorem look_filter {k : κ} (p : κ → Bool) :
    ∀ l : List (κ × β), look k (l.filter (fun e => p e.1)) = if p k then look k l else none
  | [] => by simp [look]
  | (k', v) :: t => by
    simp only [List.filter_cons]
    have ih := look_filter (k := k) p t
    by_cases hp : p k' = true
    · simp only [hp, ite_true, look]
      by_cases e : k' = k
      · subst e; simp [hp]
      · simp only [e, ite_false]; exact ih
    · simp only [hp, Bool.false_eq_true, ite_false]
      rw [ih]
      by_cases e : k' = k
      · subst e; simp [hp]
      · simp [look, e]

theorem look_ins [LinOrd κ] {k k' : κ} {v : β} :
    ∀ l : List (κ × β), look k (ins Prod.fst (k', v) l) = if k' = k then some v else look k l
  | [] => by simp [ins, look]
  | (k'', w) :: t => by
    simp only [ins]
    by_cases h1 : lt k' k'' = true
    · simp [h1, look]
    · by_cases h2 : k' = k''
      · subst h2; by_cases e : k' = k <;> simp [h1, look, e, LinOrd.irrefl]
      · simp only [h1, h2, ite_false, Bool.false_eq_true, look]
        rw [look_ins t]
        by_cases e2 : k'' = k
        · subst e2; simp [h2]
        · simp [e2]

theorem look_nrmBy [LinOrd κ] {k : κ} :
    ∀ l : List (κ × β), look k (nrmBy Prod.fst l) = look k l
  | [] => rfl
  | (k', v) :: t => by
    show look k (ins Prod.fst (k', v) (nrmBy Prod.fst t)) = _
    rw [look_ins, look_nrmBy t]
    rfl

theorem look_of_mem_nodup {k : κ} {v : β} :
    ∀ {l : List (κ × β)}, (l.map Prod.fst).Nodup → (k, v) ∈ l → look k l = some v
  | [], _, h => by simp at h
  | (k', v') :: t, hn, h => by
    simp only [List.map_cons, List.nodup_cons] at hn
    unfold look
    rcases List.mem_cons.mp h with h | h
    · simp at h; rcases h with ⟨rfl, rfl⟩; simp
    · have : k' ≠ k := by
        intro e; subst e
        exact hn.1 (List.mem_map.mpr ⟨_, h, rfl⟩)
      simp only [this, ite_false]
      exact look_of_mem_nodup hn.2 h

theorem nodup_of_sorted [LinOrd κ] {l : List (κ × β)} (h : Sorted Prod.fst l) :
    (l.map Prod.fst).Nodup := by
  unfold Sorted at h
  rw [List.Nodup, List.pairwise_map]
  exact h.imp (fun hlt => LinOrd.ne_of_lt hlt)

theorem mem_iff_look [LinOrd κ] {k : κ} {v : β} {l : List (κ × β)} (h : Sorted Prod.fst l) :
    (k, v) ∈ l ↔ look k l = some v :=
  ⟨look_of_mem_nodup (nodup_of_sorted h), look_mem⟩

/-- Map every value; `none` from `g` makes the whole result `none`. -/
def mapVals (g : κ → β → Option γ) : List (κ × β) → Option (List (κ × γ))
  | [] => some []
  | (k, v) :: t =>
    match g k v, mapVals g t with
    | some w, some ws => some ((k, w) :: ws)
    | _, _ => none

theorem look_mapVals {g : κ → β → Option γ} {k : κ} :
    ∀ {l : List (κ × β)} {m : List (κ × γ)}, mapVals g l = some m → look k m = (look k l).bind (g k)
  | [], m, h => by simp [mapVals] at h; subst h; rfl
  | (k', v) :: t, m, h => by
    unfold mapVals at h
    split at h
    · rename_i w ws hw hws
      simp at h; subst h
      simp only [look]
      by_cases e : k' = k
      · subst e; simp [hw]
      · simp only [e, ite_false]; exact look_mapVals hws
    · simp at h

omit [DecidableEq κ] in
theorem mapVals_none {g : κ → β → Option γ} :
    ∀ {l : List (κ × β)}, mapVals g l = none → ∃ k v, (k, v) ∈ l ∧ g k v = none
  | [], h => by simp [mapVals] at h
  | (k, v) :: t, h => by
    unfold mapVals at h
    split at h
    · simp at h
    · rename_i hne
      cases hg : g k v with
      | none => exact ⟨k, v, List.mem_cons_self, hg⟩
      | some w =>
        cases ht : mapVals g t with
        | none =>
          obtain ⟨k', v', hm, hg'⟩ := mapVals_none ht
          exact ⟨k', v', List.mem_cons_of_mem _ hm, hg'⟩
        | some ws => exact (hne w ws hg ht).elim

omit [DecidableEq κ] in
theorem mem_mapVals {g : κ → β → Option γ} {k : κ} {w : γ} :
    ∀ {l : List (κ × β)} {m : List (κ × γ)}, mapVals g l = some m →
      ((k, w) ∈ m ↔ ∃ v, (k, v) ∈ l ∧ g k v = some w)
  | [], m, h => by simp [mapVals] at h; subst h; simp
  | (k', v) :: t, m, h => by
    unfold mapVals at h
    split at h
    · rename_i w' ws hw hws
      simp at h; subst h
      rw [List.mem_cons, mem_mapVals hws]
      constructor
      · rintro (h | ⟨v', hv, hg⟩)
        · simp at h; rcases h with ⟨rfl, rfl⟩; exact ⟨v, List.mem_cons_self, hw⟩
        · exact ⟨v', List.mem_cons_of_mem _ hv, hg⟩
      · rintro ⟨v', hv, hg⟩
        rcases List.mem_cons.mp hv with hv | hv
        · simp at hv; rcases hv with ⟨rfl, rfl⟩
          rw [hw] at hg; simp at hg; subst hg; exact Or.inl rfl
        · exact Or.inr ⟨v', hv, hg⟩
    · simp at h

omit [DecidableEq κ] in
theorem mapVals_keys {g : κ → β → Option γ} :
    ∀ {l : List (κ × β)} {m : List (κ × γ)}, mapVals g l = some m → m.map Prod.fst = l.map Prod.fst
  | [], m, h => by simp [mapVals] at h; subst h; rfl
  | (k', v) :: t, m, h => by
    unfold mapVals at h
    split at h
    · rename_i w' ws hw hws
      simp at h; subst h
      simp [mapVals_keys hws]
    · simp at h

omit [DecidableEq κ] in
theorem mapVals_fix {g : κ → β → Option β} :
    ∀ {l : List (κ × β)}, (∀ k v, (k, v) ∈ l → g k v = some v) → mapVals g l = some l
  | [], _ => rfl
  | (k, v) :: t, h => by
    unfold mapVals
    rw [h k v List.mem_cons_self, mapVals_fix (fun k' v' hm => h k' v' (List.mem_cons_of_mem _ hm))]

end Maps

end Access
