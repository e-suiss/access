import AccessAlgebra.Meet

/-!
L0-ALG-5, L0-ALG-51: the authority intersection is the greatest lower bound.
-/

namespace Access

variable {cat : Catalog}

/-! ### Actions -/

theorem covered_exact (ex : List ActionRef) : covered cat ⟨ex, []⟩ = ex := by simp [covered]

theorem actsMeet_le {a b m : ActionSet} (h : actsMeet cat a b = some m) :
    actsLe cat m a = true ∧ actsLe cat m b = true := by
  simp only [actsMeet] at h
  split at h
  · simp at h
  · simp only [Option.some.injEq] at h
    subst h
    simp only [actsLe_iff, covered_exact, mem_nrm, List.mem_filter,
      List.contains_iff_mem]
    exact ⟨fun x hx => hx.1, fun x hx => by simpa using hx.2⟩

theorem actsMeet_greatest {a b z : ActionSet} (hz : covered cat z ≠ [])
    (h1 : actsLe cat z a = true) (h2 : actsLe cat z b = true) :
    ∃ m, actsMeet cat a b = some m ∧ actsLe cat z m = true := by
  rw [actsLe_iff] at h1 h2
  obtain ⟨e, he⟩ := List.exists_mem_of_ne_nil _ hz
  simp only [actsMeet]
  split
  · rename_i hempty
    rw [List.isEmpty_iff, nrm_eq_nil, List.filter_eq_nil_iff] at hempty
    exact absurd (by simpa using h2 e he) (hempty e (h1 e he))
  · refine ⟨_, rfl, ?_⟩
    rw [actsLe_iff, covered_exact]
    intro x hx
    rw [mem_nrm, List.mem_filter]
    exact ⟨h1 x hx, by simpa using h2 x hx⟩

/-! ### Optional dimensions -/

theorem optMeet_le {α : Type} {m : α → α → Option α} {le : α → α → Bool}
    (hm : ∀ x y r, m x y = some r → le r x = true ∧ le r y = true) (hr : ∀ x, le x x = true)
    {a b r : Option α} (h : optMeet m a b = some r) :
    optLe le r a = true ∧ optLe le r b = true := by
  cases a <;> cases b <;> simp only [optMeet, Option.some.injEq] at h
  · subst h; simp [optLe]
  · subst h; simp [optLe, hr]
  · subst h; simp [optLe, hr]
  · cases hxy : m _ _ with
    | none => rw [hxy] at h; simp at h
    | some r' =>
      rw [hxy] at h; simp at h; subst h
      exact hm _ _ _ hxy

theorem optMeet_greatest {α : Type} {m : α → α → Option α} {le : α → α → Bool} {P : α → Prop}
    (hm : ∀ x y z, P z → le z x = true → le z y = true → ∃ r, m x y = some r ∧ le z r = true)
    {a b z : Option α} (hz : ∀ v, z = some v → P v) (h1 : optLe le z a = true)
    (h2 : optLe le z b = true) : ∃ r, optMeet m a b = some r ∧ optLe le z r = true := by
  cases a <;> cases b <;> simp only [optMeet]
  · exact ⟨none, rfl, by cases z <;> simp [optLe]⟩
  · exact ⟨_, rfl, h2⟩
  · exact ⟨_, rfl, h1⟩
  · cases z with
    | none => simp [optLe] at h1
    | some w =>
      simp only [optLe] at h1 h2
      obtain ⟨r, hr, hle⟩ := hm _ _ w (hz w rfl) h1 h2
      exact ⟨some r, by rw [hr]; rfl, hle⟩

/-! ### Parameters -/

theorem mapVals_some_all {κ β γ : Type} {g : κ → β → Option γ} :
    ∀ {l : List (κ × β)} {m : List (κ × γ)}, mapVals g l = some m →
      ∀ k v, (k, v) ∈ l → ∃ w, g k v = some w
  | [], _, _, _, _, hm => by simp at hm
  | (k', v') :: t, m, h, k, v, hm => by
    unfold mapVals at h
    split at h
    · rename_i w ws hw hws
      rcases List.mem_cons.mp hm with hm | hm
      · simp at hm; rcases hm with ⟨rfl, rfl⟩; exact ⟨w, hw⟩
      · exact mapVals_some_all hws k v hm
    · simp at h

theorem meetParams_le (hc : cat.Lawful) {a b m : List (String × Bound)} (sa : Sorted Prod.fst a)
    (sb : Sorted Prod.fst b) (h : meetParams cat a b = some m) :
    paramsLe cat m a = true ∧ paramsLe cat m b = true := by
  unfold meetParams at h
  split at h
  · simp at h
  · rename_i left hl
    simp only [Option.some.injEq] at h
    subst h
    have hall := mapVals_some_all hl
    constructor
    · rw [paramsLe_iff]
      intro k ab hm
      have hla : look k a = some ab := (mem_iff_look sa).mp hm
      rw [look_nrmBy, look_append, look_mapVals hl, hla]
      obtain ⟨w, hw⟩ := hall k ab hm
      simp only [Option.bind_some] at hw ⊢
      rw [hw]
      refine ⟨w, rfl, ?_⟩
      revert hw
      cases look k b with
      | none => simp only [Option.some.injEq]; intro e; subst e; exact boundLe_refl hc _
      | some bb => intro e; exact (boundMeet_le e).1
    · rw [paramsLe_iff]
      intro k bb hm
      have hlb : look k b = some bb := (mem_iff_look sb).mp hm
      rw [look_nrmBy, look_append, look_mapVals hl]
      cases hla : look k a with
      | none =>
        simp only [Option.bind_none, Option.none_or]
        rw [look_filter (fun k => (look k a).isNone), hla]
        simp only [Option.isNone_none, ite_true, hlb]
        exact ⟨bb, rfl, boundLe_refl hc _⟩
      | some ab =>
        obtain ⟨w, hw⟩ := hall k ab (look_mem hla)
        simp only [Option.bind_some] at hw ⊢
        rw [hw]
        refine ⟨w, rfl, ?_⟩
        rw [hlb] at hw
        exact (boundMeet_le hw).2

theorem meetParams_greatest (hc : cat.Lawful) {a b z : List (String × Bound)}
    (hz : ∀ k v, (k, v) ∈ z → BoundWF v)
    (h1 : paramsLe cat z a = true) (h2 : paramsLe cat z b = true) :
    ∃ m, meetParams cat a b = some m ∧ paramsLe cat z m = true := by
  rw [paramsLe_iff] at h1 h2
  have both : ∀ k ab bb, (k, ab) ∈ a → (k, bb) ∈ b →
      ∃ r, boundMeet cat ab bb = some r ∧ ∃ zb, look k z = some zb ∧ boundLe cat zb r = true := by
    intro k ab bb ha hb
    obtain ⟨zb, hzb, hle1⟩ := h1 k ab ha
    obtain ⟨zb', hzb', hle2⟩ := h2 k bb hb
    rw [hzb] at hzb'
    simp only [Option.some.injEq] at hzb'
    subst hzb'
    obtain ⟨r, hr, hle⟩ := boundMeet_greatest hc (hz k zb (look_mem hzb)) hle1 hle2
    exact ⟨r, hr, zb, hzb, hle⟩
  unfold meetParams
  split
  · rename_i hl
    obtain ⟨k, va, hm, hg⟩ := mapVals_none hl
    revert hg
    cases hb : look k b with
    | none => simp
    | some vb =>
      intro hg
      obtain ⟨r, hr, _⟩ := both k va vb hm (look_mem hb)
      simp only at hg
      rw [hr] at hg
      simp at hg
  · rename_i left hl
    refine ⟨_, rfl, ?_⟩
    rw [paramsLe_iff]
    intro k mb hm
    rw [mem_iff_look (sorted_nrmBy _ _), look_nrmBy, look_append, look_mapVals hl] at hm
    cases hla : look k a with
    | none =>
      rw [hla] at hm
      simp only [Option.bind_none, Option.none_or] at hm
      rw [look_filter (fun k => (look k a).isNone), hla] at hm
      simp only [Option.isNone_none, ite_true] at hm
      exact h2 k mb (look_mem hm)
    | some ab =>
      rw [hla] at hm
      simp only [Option.bind_some] at hm
      revert hm
      cases hlb : look k b with
      | none =>
        simp only [Option.some_or, Option.some.injEq]
        intro e; subst e
        exact h1 k _ (look_mem hla)
      | some bb =>
        intro hm
        obtain ⟨r, hr, zb, hzb, hle⟩ := both k ab bb (look_mem hla) (look_mem hlb)
        simp only at hm
        rw [hr] at hm
        simp only [Option.some_or, Option.some.injEq] at hm
        subst hm
        exact ⟨zb, hzb, hle⟩

/-! ### Authority sets -/

/-- Normal-form side conditions on the arguments of `∩` (L0-ALG-52). -/
def ParamsSorted (a : Authority) : Prop := Sorted Prod.fst a.params

/-- A lower bound that is not `⊥`: it covers some action and its bounds are well formed. -/
def MeetWF (cat : Catalog) (z : Authority) : Prop :=
  covered cat z.actions ≠ [] ∧ ResWF z.resource ∧ (∀ k v, (k, v) ∈ z.params → BoundWF v)
    ∧ ∀ s, z.purpose = some s → s ≠ []

/-- L0-ALG-5: `a ∩ b ⊑ a` and `a ∩ b ⊑ b`. -/
theorem authMeet_le (hc : cat.Lawful) {a b m : Authority} (sa : ParamsSorted a)
    (sb : ParamsSorted b) (h : authMeet cat a b = some m) :
    authLe cat m a = true ∧ authLe cat m b = true := by
  unfold authMeet at h
  split at h
  · rename_i acts res ps rc pu ha hr hp hrc hpu
    simp only [Option.some.injEq] at h
    subst h
    have la := actsMeet_le ha
    have lr := resMeet_le hr
    have lp := meetParams_le hc sa sb hp
    have lrc := optMeet_le (le := subjLe) (fun _ _ _ h => subjMeet_le h) subjLe_refl hrc
    have lpu := optMeet_le (le := pLe cat) (fun _ _ _ h => pMeet_le _ _ h) (pLe_refl hc) hpu
    exact ⟨authLe_iff.mpr ⟨la.1, lr.1, lp.1, lrc.1, lpu.1⟩,
      authLe_iff.mpr ⟨la.2, lr.2, lp.2, lrc.2, lpu.2⟩⟩
  · simp at h

/-- Every lower bound of `a` and `b` that is not `⊥` is below `a ∩ b`. -/
theorem authMeet_greatest_wf (hc : cat.Lawful) {a b z : Authority} (hz : MeetWF cat z) (h1 : authLe cat z a = true)
    (h2 : authLe cat z b = true) : ∃ m, authMeet cat a b = some m ∧ authLe cat z m = true := by
  rw [authLe_iff] at h1 h2
  obtain ⟨ma, hma, la⟩ := actsMeet_greatest hz.1 h1.1 h2.1
  obtain ⟨mr, hmr, lr⟩ := resMeet_greatest hz.2.1 h1.2.1 h2.2.1
  obtain ⟨mp, hmp, lp⟩ := meetParams_greatest hc hz.2.2.1 h1.2.2.1 h2.2.2.1
  obtain ⟨mrc, hmrc, lrc⟩ := optMeet_greatest (m := subjMeet) (le := subjLe) (P := fun _ => True)
    (fun _ _ _ _ h1 h2 => subjMeet_greatest h1 h2) (fun _ _ => trivial) h1.2.2.2.1 h2.2.2.2.1
  obtain ⟨mpu, hmpu, lpu⟩ := optMeet_greatest (m := pMeet cat) (le := pLe cat)
    (P := fun s => s ≠ []) (fun _ _ _ hz h1 h2 => pMeet_greatest hc hz h1 h2) hz.2.2.2
    h1.2.2.2.2 h2.2.2.2.2
  refine ⟨⟨ma, mr, mp, mrc, mpu⟩, ?_, authLe_iff.mpr ⟨la, lr, lp, lrc, lpu⟩⟩
  unfold authMeet
  rw [hma, hmr, hmp, hmrc, hmpu]

/-- Well-formed intents name at least one resource (CDDL `[+ resource-ref]`). -/
def IntentWF (i : Intent) : Prop := i.resources ≠ []

/-- OP-124 m.3: a value that covers no well-formed intent is equivalent to `⊥`. -/
def CoversNothing (cat : Catalog) (z : Authority) : Prop := ∀ i, IntentWF i → coversA cat z i = false

theorem resWF_of_exact_le {r : ResourceRef} {s : ResSel} (h : resLe (.exact r) s = true) :
    ResWF s := by
  cases s with
  | exact _ => trivial
  | struct t =>
    have := (resLe_es.mp h).2.2.2
    simp [ResWF, this]

theorem boundWF_of_within {b : Bound} {v : PValue} (h : withinB cat b v = true) : BoundWF b := by
  cases b <;> cases v <;> simp only [withinB, reduceCtorEq] at h <;> simp only [BoundWF]
  · rename_i s x
    intro e; subst e; simp at h
  · rename_i r x u
    obtain ⟨mn, mx, un⟩ := r
    simp only [Bool.and_eq_true, beq_iff_eq] at h
    simp only [rangeEmpty]
    revert h
    cases mn <;> cases mx <;> simp <;> omega
  · rename_i w x
    simp only [winLe, Bool.and_eq_true, decide_eq_true_eq] at h
    omega
  · exact resWF_of_exact_le h
  · rename_i s x
    intro e; subst e; simp at h

theorem meetWF_of_covers {z : Authority} {i : Intent} (hi : IntentWF i)
    (h : coversA cat z i = true) : MeetWF cat z := by
  obtain ⟨ha, hr, hp, _, hpu⟩ := coversA_iff.mp h
  refine ⟨fun e => by rw [e] at ha; simp at ha, ?_, ?_, ?_⟩
  · obtain ⟨r, hrm⟩ := List.exists_mem_of_ne_nil _ hi
    exact resWF_of_exact_le (hr r hrm)
  · intro k v hm
    cases hpb : isPubBound v
    · obtain ⟨x, _, hx⟩ := hp k v hm hpb
      exact boundWF_of_within hx
    · cases v <;> simp_all [isPubBound, BoundWF]
  · intro s hs e
    subst e
    obtain ⟨_, _, y, hy, _⟩ := hpu [] hs
    simp at hy

/-- L0-ALG-5, OP-124 m.3: up to coverage, `a ∩ b` is the greatest lower bound. Every lower bound
of `a` and `b` either covers nothing (it is equivalent to `⊥`) or is below `a ∩ b`. -/
theorem authMeet_greatest (hc : cat.Lawful) {a b z : Authority} (h1 : authLe cat z a = true)
    (h2 : authLe cat z b = true) :
    CoversNothing cat z ∨ ∃ m, authMeet cat a b = some m ∧ authLe cat z m = true := by
  by_cases hn : CoversNothing cat z
  · exact Or.inl hn
  · right
    have : ∃ i, IntentWF i ∧ coversA cat z i = true := by
      apply Classical.byContradiction
      intro hne
      apply hn
      intro i hi
      cases hz : coversA cat z i
      · rfl
      · exact absurd ⟨i, hi, hz⟩ hne
    obtain ⟨i, hi, hz⟩ := this
    exact authMeet_greatest_wf hc (meetWF_of_covers hi hz) h1 h2

end Access
