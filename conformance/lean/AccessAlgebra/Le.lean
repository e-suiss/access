import AccessAlgebra.Algebra

/-!
L0-ALG-5: `⊑` is reflexive, transitive and sound with respect to coverage.
-/

namespace Access

variable {cat : Catalog}

/-! ### Subjects -/

theorem subjLe_refl (s : SubjSel) : subjLe s s = true := by
  cases s <;> simp [subjLe]

theorem subjLe_trans {a b c : SubjSel} (h1 : subjLe a b = true) (h2 : subjLe b c = true) :
    subjLe a c = true := by
  cases a <;> cases b <;> cases c <;> simp_all [subjLe]

/-! ### Resources -/

theorem resLe_ss {c p : Structural} :
    resLe (.struct c) (.struct p) = true ↔
      c.ns = p.ns ∧ p.path <+: c.path ∧ (p.type = none ∨ p.type = c.type)
        ∧ ∀ e ∈ p.attrs, e ∈ c.attrs := by
  simp [resLe, List.isPrefixOf_iff_prefix, Option.isNone_iff_eq_none, and_assoc]

theorem resLe_es {c : ResourceRef} {p : Structural} :
    resLe (.exact c) (.struct p) = true ↔
      c.ns = p.ns ∧ p.path <+: c.path ∧ p.type = none ∧ p.attrs = [] := by
  simp [resLe, List.isPrefixOf_iff_prefix, Option.isNone_iff_eq_none, and_assoc]

theorem resLe_ee {c p : ResourceRef} : resLe (.exact c) (.exact p) = true ↔ c = p := by
  simp [resLe]

theorem resLe_se {c : Structural} {p : ResourceRef} : resLe (.struct c) (.exact p) = false := rfl

theorem resLe_refl (s : ResSel) : resLe s s = true := by
  cases s with
  | exact r => exact resLe_ee.mpr rfl
  | struct s => exact resLe_ss.mpr ⟨rfl, List.prefix_refl _, Or.inr rfl, fun _ h => h⟩

theorem resLe_trans :
    ∀ {a b c : ResSel}, resLe a b = true → resLe b c = true → resLe a c = true
  | .exact _, .exact _, .exact _, h1, h2 => by rw [resLe_ee] at *; exact h1.trans h2
  | .exact _, .exact _, .struct _, h1, h2 => by rw [resLe_ee] at h1; subst h1; exact h2
  | _, .struct _, .exact _, _, h2 => by simp [resLe_se] at h2
  | .struct _, .exact _, _, h1, _ => by simp [resLe_se] at h1
  | .exact _, .struct y, .struct z, h1, h2 => by
    rw [resLe_es] at *
    obtain ⟨n1, p1, t1, a1⟩ := h1
    rw [resLe_ss] at h2
    obtain ⟨n2, p2, t2, a2⟩ := h2
    refine ⟨n1.trans n2, p2.trans p1, ?_, ?_⟩
    · rcases t2 with t2 | t2
      · exact t2
      · exact t2.trans t1
    · apply List.eq_nil_iff_forall_not_mem.mpr
      intro e he
      have := a2 e he
      rw [a1] at this
      simp at this
  | .struct _, .struct _, .struct _, h1, h2 => by
    rw [resLe_ss] at *
    obtain ⟨n1, p1, t1, a1⟩ := h1
    obtain ⟨n2, p2, t2, a2⟩ := h2
    refine ⟨n1.trans n2, p2.trans p1, ?_, fun e he => a1 e (a2 e he)⟩
    rcases t2 with t2 | t2
    · exact Or.inl t2
    · rcases t1 with t1 | t1
      · exact Or.inl (t2.trans t1)
      · exact Or.inr (t2.trans t1)

/-! ### Ranges and windows -/

theorem loLe_refl (a : Option Int) : loLe a a = true := by cases a <;> simp [loLe]
theorem hiLe_refl (a : Option Int) : hiLe a a = true := by cases a <;> simp [hiLe]

theorem loLe_trans {a b c : Option Int} (h1 : loLe a b = true) (h2 : loLe b c = true) :
    loLe a c = true := by
  cases a <;> cases b <;> cases c <;> simp_all [loLe] <;> omega

theorem hiLe_trans {a b c : Option Int} (h1 : hiLe a b = true) (h2 : hiLe b c = true) :
    hiLe a c = true := by
  cases a <;> cases b <;> cases c <;> simp_all [hiLe] <;> omega

theorem rangeLe_refl (r : Range) : rangeLe r r = true := by
  simp [rangeLe, loLe_refl, hiLe_refl]

theorem rangeLe_trans {a b c : Range} (h1 : rangeLe a b = true) (h2 : rangeLe b c = true) :
    rangeLe a c = true := by
  simp only [rangeLe, Bool.and_eq_true, beq_iff_eq] at *
  exact ⟨⟨h1.1.1.trans h2.1.1, loLe_trans h2.1.2 h1.1.2⟩, hiLe_trans h1.2 h2.2⟩

theorem winLe_refl (w : Window) : winLe w w = true := by simp [winLe]

theorem winLe_trans {a b c : Window} (h1 : winLe a b = true) (h2 : winLe b c = true) :
    winLe a c = true := by
  simp only [winLe, Bool.and_eq_true, decide_eq_true_eq] at *
  omega

/-! ### Purposes -/

theorem pLe_refl (hc : cat.Lawful) (s : List Purpose) : pLe cat s s = true := by
  simp only [pLe, List.all_eq_true, List.any_eq_true]
  exact fun x hx => ⟨x, hx, hc.refl x⟩

theorem pLe_trans (hc : cat.Lawful) {a b c : List Purpose} (h1 : pLe cat a b = true)
    (h2 : pLe cat b c = true) : pLe cat a c = true := by
  simp only [pLe, List.all_eq_true, List.any_eq_true] at *
  intro x hx
  obtain ⟨y, hy, hxy⟩ := h1 x hx
  obtain ⟨z, hz, hyz⟩ := h2 y hy
  exact ⟨z, hz, hc.trans _ _ _ hxy hyz⟩

/-! ### Bounds -/

theorem boundLe_refl (hc : cat.Lawful) (b : Bound) : boundLe cat b b = true := by
  cases b <;> simp [boundLe, rangeLe_refl, winLe_refl, resLe_refl, subjLe_refl, pLe_refl hc]

theorem boundLe_trans (hc : cat.Lawful) {a b c : Bound} (h1 : boundLe cat a b = true)
    (h2 : boundLe cat b c = true) : boundLe cat a c = true := by
  cases a <;> cases b <;> cases c <;> simp only [boundLe, reduceCtorEq] at h1 h2 ⊢
  · simp only [List.all_eq_true, List.contains_iff_mem] at *
    exact fun x hx => h2 x (h1 x hx)
  · simp_all
  · simp_all
  · exact rangeLe_trans h1 h2
  · simp only [decide_eq_true_eq] at *; omega
  · exact winLe_trans h1 h2
  · exact resLe_trans h1 h2
  · exact subjLe_trans h1 h2
  · exact pLe_trans hc h1 h2

theorem withinB_mono (hc : cat.Lawful) {c p : Bound} {v : PValue} (h : boundLe cat c p = true)
    (hv : withinB cat c v = true) : withinB cat p v = true := by
  cases c <;> cases p <;> simp only [boundLe, reduceCtorEq] at h <;> cases v <;>
    simp only [withinB, reduceCtorEq] at hv ⊢
  · simp only [List.all_eq_true, List.contains_iff_mem] at *
    exact h _ hv
  · simp_all
  · simp_all
  · rename_i c p _ _
    simp only [rangeLe, Bool.and_eq_true, beq_iff_eq] at h hv ⊢
    obtain ⟨⟨hu, hlo⟩, hhi⟩ := h
    obtain ⟨⟨hu', hmin⟩, hmax⟩ := hv
    refine ⟨⟨hu ▸ hu', ?_⟩, ?_⟩
    · revert hlo hmin; cases p.min <;> cases c.min <;> simp [loLe] <;> omega
    · revert hhi hmax; cases p.max <;> cases c.max <;> simp [hiLe] <;> omega
  · simp only [decide_eq_true_eq] at *; omega
  · simp only [Bool.and_eq_true, decide_eq_true_eq] at hv ⊢
    exact ⟨hv.1, winLe_trans hv.2 h⟩
  · exact resLe_trans hv h
  · exact subjLe_trans hv h
  · simp only [pLe, List.all_eq_true, List.any_eq_true] at *
    obtain ⟨y, hy, hqy⟩ := hv
    obtain ⟨z, hz, hyz⟩ := h y hy
    exact ⟨z, hz, hc.trans _ _ _ hqy hyz⟩

/-! ### Actions -/

theorem actsLe_iff {c p : ActionSet} :
    actsLe cat c p = true ↔ ∀ a ∈ covered cat c, a ∈ covered cat p := by
  simp [actsLe]

theorem actsLe_refl (c : ActionSet) : actsLe cat c c = true :=
  actsLe_iff.mpr fun _ ha => ha

theorem actsLe_trans {a b c : ActionSet} (h1 : actsLe cat a b = true)
    (h2 : actsLe cat b c = true) : actsLe cat a c = true := by
  rw [actsLe_iff] at *
  exact fun x hx => h2 x (h1 x hx)

/-! ### Optional dimensions -/

theorem optLe_refl {α : Type} {le : α → α → Bool} (hr : ∀ a, le a a = true) (o : Option α) :
    optLe le o o = true := by
  cases o <;> simp [optLe, hr]

theorem optLe_trans {α : Type} {le : α → α → Bool}
    (ht : ∀ a b c, le a b = true → le b c = true → le a c = true) {a b c : Option α}
    (h1 : optLe le a b = true) (h2 : optLe le b c = true) : optLe le a c = true := by
  cases a <;> cases b <;> cases c <;> simp_all [optLe]
  exact ht _ _ _ h1 h2

/-! ### Parameters -/

theorem paramsLe_iff {c p : List (String × Bound)} :
    paramsLe cat c p = true ↔ ∀ k pb, (k, pb) ∈ p → ∃ cb, look k c = some cb ∧ boundLe cat cb pb = true := by
  simp only [paramsLe, List.all_eq_true]
  constructor
  · intro h k pb hm
    have := h (k, pb) hm
    simp only at this
    split at this
    · rename_i cb hcb; exact ⟨cb, hcb, this⟩
    · simp at this
  · intro h e he
    obtain ⟨cb, hcb, hle⟩ := h e.1 e.2 he
    simp only [hcb, hle]

theorem paramsLe_refl (hc : cat.Lawful) {c : List (String × Bound)} (hn : (c.map Prod.fst).Nodup) :
    paramsLe cat c c = true :=
  paramsLe_iff.mpr fun _ pb hm => ⟨pb, look_of_mem_nodup hn hm, boundLe_refl hc pb⟩

theorem paramsLe_trans (hc : cat.Lawful) {a b c : List (String × Bound)}
    (h1 : paramsLe cat a b = true) (h2 : paramsLe cat b c = true) : paramsLe cat a c = true := by
  rw [paramsLe_iff] at *
  intro k cb hm
  obtain ⟨bb, hbb, hle2⟩ := h2 k cb hm
  obtain ⟨ab, hab, hle1⟩ := h1 k bb (look_mem hbb)
  exact ⟨ab, hab, boundLe_trans hc hle1 hle2⟩

/-! ### Authority sets -/

/-- OP-124 m.2: well-formed authority sets have unique parameter keys. -/
def AuthWF (a : Authority) : Prop := (a.params.map Prod.fst).Nodup

theorem authLe_iff {c p : Authority} :
    authLe cat c p = true ↔
      actsLe cat c.actions p.actions = true ∧ resLe c.resource p.resource = true
        ∧ paramsLe cat c.params p.params = true ∧ optLe subjLe c.recipient p.recipient = true
        ∧ optLe (pLe cat) c.purpose p.purpose = true := by
  simp [authLe, and_assoc]

/-- L0-ALG-5: `⊑` is reflexive. -/
theorem authLe_refl (hc : cat.Lawful) {a : Authority} (hw : AuthWF a) : authLe cat a a = true :=
  authLe_iff.mpr ⟨actsLe_refl _, resLe_refl _, paramsLe_refl hc hw,
    optLe_refl subjLe_refl _, optLe_refl (pLe_refl hc) _⟩

/-- L0-ALG-5: `⊑` is transitive. -/
theorem authLe_trans (hc : cat.Lawful) {a b c : Authority} (h1 : authLe cat a b = true)
    (h2 : authLe cat b c = true) : authLe cat a c = true := by
  rw [authLe_iff] at *
  exact ⟨actsLe_trans h1.1 h2.1, resLe_trans h1.2.1 h2.2.1, paramsLe_trans hc h1.2.2.1 h2.2.2.1,
    optLe_trans (le := subjLe) (fun _ _ _ h1 h2 => subjLe_trans h1 h2) h1.2.2.2.1 h2.2.2.2.1,
    optLe_trans (le := pLe cat) (fun _ _ _ h1 h2 => pLe_trans hc h1 h2) h1.2.2.2.2 h2.2.2.2.2⟩

theorem coversA_iff {a : Authority} {i : Intent} :
    coversA cat a i = true ↔
      i.action ∈ covered cat a.actions
        ∧ (∀ r ∈ i.resources, resLe (.exact r) a.resource = true)
        ∧ (∀ k b, (k, b) ∈ a.params → isPubBound b = false →
            ∃ v, look k i.params = some v ∧ withinB cat b v = true)
        ∧ (∀ s, a.recipient = some s → isPubSel s = false →
            ∃ p, i.recipient = some p ∧ subjLe (.party p) s = true)
        ∧ (∀ s, a.purpose = some s → ∃ q, i.purpose = some q ∧ ∃ y ∈ s, cat.below q y = true) := by
  simp only [coversA, Bool.and_eq_true, List.contains_iff_mem, List.all_eq_true, and_assoc]
  refine and_congr Iff.rfl (and_congr Iff.rfl (and_congr ?_ (and_congr ?_ ?_)))
  · constructor
    · intro h k b hm hp
      have := h (k, b) hm
      simp only [hp, Bool.false_or] at this
      split at this
      · rename_i v hv; exact ⟨v, hv, this⟩
      · simp at this
    · intro h e he
      cases hp : isPubBound e.2
      · obtain ⟨v, hv, hw⟩ := h e.1 e.2 he hp
        simp only [hv, hw, Bool.or_true]
      · simp
  · cases a.recipient with
    | none => simp
    | some s =>
      cases hp : isPubSel s <;> cases i.recipient <;> simp [hp]
  · cases a.purpose with
    | none => simp
    | some s =>
      cases i.purpose <;> simp

theorem isPubSel_of_le {c p : SubjSel} (hp : isPubSel p = false) (h : subjLe c p = true) :
    isPubSel c = false := by
  cases c <;> cases p <;> simp_all [isPubSel, subjLe]

theorem isPubBound_of_le {c p : Bound} (hp : isPubBound p = false) (h : boundLe cat c p = true) :
    isPubBound c = false := by
  cases c <;> cases p <;> simp only [boundLe, reduceCtorEq] at h <;> try rfl
  rename_i c p
  simp only [isPubBound] at hp ⊢
  have := isPubSel_of_le (c := c) (p := p) (by cases p <;> simp_all [isPubSel]) h
  cases c <;> simp_all [isPubSel]

/-- L0-ALG-5: `⊑` is sound: whatever the child covers, the parent covers. -/
theorem authLe_sound (hc : cat.Lawful) {c p : Authority} {i : Intent} (h : authLe cat c p = true)
    (hv : coversA cat c i = true) : coversA cat p i = true := by
  rw [authLe_iff] at h
  obtain ⟨ha, hr, hp, hrc, hpu⟩ := h
  rw [coversA_iff] at *
  obtain ⟨va, vr, vp, vrc, vpu⟩ := hv
  refine ⟨(actsLe_iff.mp ha) _ va, fun r hr' => resLe_trans (vr r hr') hr, ?_, ?_, ?_⟩
  · intro k pb hm hpub
    obtain ⟨cb, hcb, hle⟩ := (paramsLe_iff.mp hp) k pb hm
    obtain ⟨v, hv, hw⟩ := vp k cb (look_mem hcb) (isPubBound_of_le hpub hle)
    exact ⟨v, hv, withinB_mono hc hle hw⟩
  · intro s hs hpub
    cases hcr : c.recipient with
    | none => rw [hcr, hs] at hrc; simp [optLe] at hrc
    | some t =>
      rw [hcr, hs] at hrc
      obtain ⟨q, hq, hqt⟩ := vrc t hcr (isPubSel_of_le hpub hrc)
      exact ⟨q, hq, subjLe_trans hqt hrc⟩
  · intro s hs
    cases hcp : c.purpose with
    | none => rw [hcp, hs] at hpu; simp [optLe] at hpu
    | some t =>
      rw [hcp, hs] at hpu
      simp only [optLe, pLe, List.all_eq_true, List.any_eq_true] at hpu
      obtain ⟨q, hq, y, hy, hqy⟩ := vpu t hcp
      obtain ⟨z, hz, hyz⟩ := hpu y hy
      exact ⟨q, hq, z, hz, hc.trans _ _ _ hqy hyz⟩

end Access
