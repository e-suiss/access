import AccessAlgebra.Le

/-!
L0-ALG-5: `a ∩ b` is the greatest lower bound of `a` and `b` under `⊑`.
-/

namespace Access

variable {cat : Catalog}

/-- Well-formed decoded values (L0-ALG-11, L0-ALG-12, CDDL `[+ …]`, canonical maps). -/
def ResWF : ResSel → Prop
  | .struct s => ∀ e ∈ s.attrs, ∀ f ∈ s.attrs, e.1 = f.1 → e.2 = f.2
  | .exact _ => True

def BoundWF : Bound → Prop
  | .enum s => s ≠ []
  | .range r => rangeEmpty r = false
  | .interval w => w.start ≤ w.stop
  | .resource s => ResWF s
  | .purpose s => s ≠ []
  | _ => True

/-! ### Lists -/

theorem filter_length_le {α : Type} (p q : α → Bool) :
    ∀ l : List α, (∀ x ∈ l, p x = true → q x = true) → (l.filter p).length ≤ (l.filter q).length
  | [], _ => by simp
  | x :: t, h => by
    have ih := filter_length_le p q t (fun y hy => h y (List.mem_cons_of_mem _ hy))
    cases hp : p x <;> cases hq : q x <;> simp [hp, hq] <;> try omega
    have := h x List.mem_cons_self hp
    simp_all

theorem filter_length_lt {α : Type} (p q : α → Bool) :
    ∀ l : List α, (∀ x ∈ l, p x = true → q x = true) → (∃ x ∈ l, q x = true ∧ p x = false) →
      (l.filter p).length < (l.filter q).length
  | [], _, ⟨_, hx, _⟩ => by simp at hx
  | x :: t, h, ⟨y, hy, hqy, hpy⟩ => by
    have hle := filter_length_le p q t (fun z hz => h z (List.mem_cons_of_mem _ hz))
    rcases List.mem_cons.mp hy with hy | hy
    · subst hy
      simp [hqy, hpy]
      omega
    · have ih := filter_length_lt p q t (fun z hz => h z (List.mem_cons_of_mem _ hz)) ⟨y, hy, hqy, hpy⟩
      cases hp : p x <;> cases hq : q x <;> simp [hp, hq] <;> try omega
      have := h x List.mem_cons_self hp
      simp_all

/-! ### Purposes -/

theorem mem_maximal {s : List Purpose} {x : Purpose} :
    x ∈ maximal cat s ↔ x ∈ s ∧ ∀ y ∈ s, y ≠ x → cat.below x y = false := by
  simp [maximal]

theorem exists_max (hc : cat.Lawful) (s : List Purpose) (e : Purpose) (he : e ∈ s) :
    ∃ m ∈ maximal cat s, cat.below e m = true := by
  by_cases hmax : e ∈ maximal cat s
  · exact ⟨e, hmax, hc.refl e⟩
  · have : ∃ y ∈ s, y ≠ e ∧ cat.below e y = true := by
      apply Classical.byContradiction
      intro hn
      apply hmax
      rw [mem_maximal]
      refine ⟨he, fun y hy hne => ?_⟩
      cases hb : cat.below e y
      · rfl
      · exact absurd ⟨y, hy, hne, hb⟩ hn
    obtain ⟨y, hy, hne, hey⟩ := this
    have hlt : (s.filter (fun z => z != y && cat.below y z)).length
        < (s.filter (fun z => z != e && cat.below e z)).length := by
      apply filter_length_lt
      · intro z _ hz
        simp only [Bool.and_eq_true, bne_iff_ne, ne_eq] at hz ⊢
        refine ⟨?_, hc.trans _ _ _ hey hz.2⟩
        intro hze
        subst hze
        exact hne (hc.antisymm _ _ hz.2 hey)
      · refine ⟨y, hy, ?_, ?_⟩
        · simp [hne, hey]
        · simp
    obtain ⟨m, hm, hym⟩ := exists_max hc s y hy
    exact ⟨m, hm, hc.trans _ _ _ hey hym⟩
termination_by (s.filter (fun z => z != e && cat.below e z)).length

theorem mem_pNorm {s : List Purpose} {x : Purpose} : x ∈ pNorm cat s ↔ x ∈ maximal cat s :=
  mem_nrm

theorem pMeet_le (a b : List Purpose) {r : List Purpose} (h : pMeet cat a b = some r) :
    pLe cat r a = true ∧ pLe cat r b = true := by
  simp only [pMeet] at h
  split at h
  · simp at h
  · simp only [Option.some.injEq] at h
    subst h
    simp only [pLe, List.all_eq_true, List.any_eq_true]
    have hm : ∀ x ∈ pNorm cat ((a ++ b ++ cat.purposes).filter
        (fun z => a.any (fun y => cat.below z y) && b.any (fun y => cat.below z y))),
        (∃ y ∈ a, cat.below x y = true) ∧ ∃ y ∈ b, cat.below x y = true := by
      intro x hx
      rw [mem_pNorm, mem_maximal] at hx
      have := hx.1
      simp only [List.mem_filter, Bool.and_eq_true, List.any_eq_true] at this
      exact this.2
    exact ⟨fun x hx => (hm x hx).1, fun x hx => (hm x hx).2⟩

theorem pMeet_greatest (hc : cat.Lawful) {a b z : List Purpose} (hz : z ≠ [])
    (h1 : pLe cat z a = true) (h2 : pLe cat z b = true) :
    ∃ r, pMeet cat a b = some r ∧ pLe cat z r = true := by
  simp only [pLe, List.all_eq_true, List.any_eq_true] at h1 h2
  have hcommon : ∀ e ∈ z, e ∈ (a ++ b ++ cat.purposes).filter
      (fun w => a.any (fun y => cat.below w y) && b.any (fun y => cat.below w y)) := by
    intro e he
    obtain ⟨y, hy, hey⟩ := h1 e he
    obtain ⟨y', hy', hey'⟩ := h2 e he
    simp only [List.mem_filter, List.mem_append, Bool.and_eq_true, List.any_eq_true]
    refine ⟨?_, ⟨y, hy, hey⟩, ⟨y', hy', hey'⟩⟩
    by_cases hne : e = y
    · subst hne; exact Or.inl (Or.inl hy)
    · exact Or.inr (hc.closed _ _ hey hne)
  have hall : ∀ e ∈ z, ∃ m ∈ pNorm cat ((a ++ b ++ cat.purposes).filter
      (fun w => a.any (fun y => cat.below w y) && b.any (fun y => cat.below w y))),
        cat.below e m = true := by
    intro e he
    obtain ⟨m, hm, hem⟩ := exists_max hc _ e (hcommon e he)
    exact ⟨m, mem_pNorm.mpr hm, hem⟩
  obtain ⟨e0, he0⟩ := List.exists_mem_of_ne_nil z hz
  simp only [pMeet]
  split
  · rename_i hempty
    obtain ⟨m, hm, _⟩ := hall e0 he0
    rw [List.isEmpty_iff] at hempty
    rw [hempty] at hm
    simp at hm
  · refine ⟨_, rfl, ?_⟩
    simp only [pLe, List.all_eq_true, List.any_eq_true]
    exact hall

/-! ### Subjects -/

theorem subjMeet_le {a b r : SubjSel} (h : subjMeet a b = some r) :
    subjLe r a = true ∧ subjLe r b = true := by
  unfold subjMeet at h
  split at h
  · simp at h; subst h; exact ⟨subjLe_refl _, by assumption⟩
  · split at h
    · simp at h; subst h; exact ⟨by assumption, subjLe_refl _⟩
    · split at h
      · simp at h; subst h
        simp only [subjLe, List.all_eq_true, List.contains_iff_mem, mem_nrm, List.mem_append]
        exact ⟨fun x h => Or.inl h, fun x h => Or.inr h⟩
      · simp at h

theorem subjMeet_greatest {a b z : SubjSel} (h1 : subjLe z a = true) (h2 : subjLe z b = true) :
    ∃ r, subjMeet a b = some r ∧ subjLe z r = true := by
  unfold subjMeet
  split
  · exact ⟨a, rfl, h1⟩
  · split
    · exact ⟨b, rfl, h2⟩
    · rename_i n1 n2
      cases a <;> cases b <;> cases z <;> simp_all [subjLe, mem_nrm]
      all_goals
        intro x hx
        rcases hx with hx | hx
        · exact h1 x hx
        · exact h2 x hx

/-! ### Resources -/

theorem typeMeet_spec {x y : Option String} {t : Option String} (h : typeMeet x y = some t) :
    (x = none ∨ x = t) ∧ (y = none ∨ y = t) := by
  cases x with
  | none => simp [typeMeet] at h; subst h; exact ⟨Or.inl rfl, Or.inr rfl⟩
  | some a =>
    cases y with
    | none => simp [typeMeet] at h; subst h; exact ⟨Or.inr rfl, Or.inl rfl⟩
    | some b => simp [typeMeet] at h; obtain ⟨rfl, rfl⟩ := h; exact ⟨Or.inr rfl, Or.inr rfl⟩

theorem structMeet_le {x y r : Structural} (h : structMeet x y = some r) :
    resLe (.struct r) (.struct x) = true ∧ resLe (.struct r) (.struct y) = true := by
  unfold structMeet at h
  split at h
  · simp at h
  · split at h
    · simp at h
    · rename_i hns _
      split at h
      · rename_i pre ty hpre hty
        simp at h; subst h
        have ht := typeMeet_spec hty
        rw [resLe_ss, resLe_ss]
        have hp : x.path <+: pre ∧ y.path <+: pre := by
          split at hpre
          · rename_i hxy
            simp at hpre; subst hpre
            exact ⟨List.isPrefixOf_iff_prefix.mp hxy, List.prefix_refl _⟩
          · split at hpre
            · rename_i hyx
              simp at hpre; subst hpre
              exact ⟨List.prefix_refl _, List.isPrefixOf_iff_prefix.mp hyx⟩
            · simp at hpre
        refine ⟨⟨rfl, hp.1, ht.1, fun e he => List.mem_append_left _ he⟩,
          ⟨Decidable.of_not_not hns, hp.2, ht.2, fun e he => List.mem_append_right _ he⟩⟩
      · simp at h

theorem resMeet_le {a b r : ResSel} (h : resMeet a b = some r) :
    resLe r a = true ∧ resLe r b = true := by
  cases a <;> cases b <;> simp only [resMeet] at h
  · split at h
    · simp at h; subst h; exact ⟨resLe_refl _, by assumption⟩
    · simp at h
  · split at h
    · simp at h; subst h; exact ⟨resLe_refl _, by assumption⟩
    · simp at h
  · split at h
    · simp at h; subst h; exact ⟨by assumption, resLe_refl _⟩
    · simp at h
  · cases hm : structMeet _ _ with
    | none => rw [hm] at h; simp at h
    | some s => rw [hm] at h; simp at h; subst h; exact structMeet_le hm

theorem resMeet_greatest {a b z : ResSel} (hz : ResWF z) (h1 : resLe z a = true)
    (h2 : resLe z b = true) : ∃ r, resMeet a b = some r ∧ resLe z r = true := by
  cases a with
  | exact x =>
    cases z with
    | struct _ => simp [resLe_se] at h1
    | exact w =>
      rw [resLe_ee] at h1; subst h1
      exact ⟨_, by simp [resMeet, h2], resLe_refl _⟩
  | struct x =>
    cases b with
    | exact y =>
      cases z with
      | struct _ => simp [resLe_se] at h2
      | exact w =>
        rw [resLe_ee] at h2; subst h2
        exact ⟨_, by simp [resMeet, h1], resLe_refl _⟩
    | struct y =>
      simp only [resMeet]
      have key : ∀ (zns : String) (zpath : List String) (zty : Option String)
          (zat : List (String × EqVal)),
          zns = x.ns → zns = y.ns → x.path <+: zpath → y.path <+: zpath →
          (x.type = none ∨ x.type = zty) → (y.type = none ∨ y.type = zty) →
          (∀ e ∈ x.attrs, e ∈ zat) → (∀ e ∈ y.attrs, e ∈ zat) →
          (∀ e ∈ zat, ∀ f ∈ zat, e.1 = f.1 → e.2 = f.2) →
          ∃ s, structMeet x y = some s ∧ s.ns = zns ∧ s.path <+: zpath
            ∧ (s.type = none ∨ s.type = zty) ∧ ∀ e ∈ s.attrs, e ∈ zat := by
        intro zns zpath zty zat n1 n2 p1 p2 t1 t2 a1 a2 wf
        unfold structMeet
        rw [ite_eq_right (by rw [← n1, ← n2]; simp)]
        have hconf : attrsConflict x.attrs y.attrs = false := by
          simp only [attrsConflict, List.any_eq_false, Bool.and_eq_true, beq_iff_eq, bne_iff_ne,
            ne_eq, List.any_eq_true, not_exists, not_and]
          intro e he f hf hk hv
          exact hv (wf e (a1 e he) f (a2 f hf) hk)
        rw [ite_eq_right (by simp [hconf])]
        have hpre : ∃ pre, (if x.path.isPrefixOf y.path = true then some y.path
            else if y.path.isPrefixOf x.path = true then some x.path else none) = some pre
              ∧ pre <+: zpath := by
          rcases List.prefix_or_prefix_of_prefix p1 p2 with h | h
          · exact ⟨y.path, by simp [List.isPrefixOf_iff_prefix.mpr h], p2⟩
          · by_cases h' : x.path.isPrefixOf y.path = true
            · exact ⟨y.path, by simp [h'], p2⟩
            · exact ⟨x.path, by simp [h', List.isPrefixOf_iff_prefix.mpr h], p1⟩
        obtain ⟨pre, hpre, hpz⟩ := hpre
        have hty : ∃ t, typeMeet x.type y.type = some t ∧ (t = none ∨ t = zty) := by
          rcases t1 with t1 | t1 <;> rcases t2 with t2 | t2
          · exact ⟨none, by simp [t1, t2, typeMeet], Or.inl rfl⟩
          · exact ⟨y.type, by simp [t1, typeMeet], Or.inr t2⟩
          · refine ⟨x.type, ?_, Or.inr t1⟩
            rw [t2]; cases x.type <;> simp [typeMeet]
          · have e : y.type = x.type := t2.trans t1.symm
            refine ⟨x.type, ?_, Or.inr t1⟩
            rw [e]; cases x.type <;> simp [typeMeet]
        obtain ⟨t, ht, htz⟩ := hty
        rw [hpre, ht]
        refine ⟨_, rfl, n1.symm, hpz, htz, ?_⟩
        intro e he
        rcases List.mem_append.mp he with he | he
        · exact a1 e he
        · exact a2 e he
      cases z with
      | exact w =>
        rw [resLe_es] at h1 h2
        obtain ⟨s, hs, hns, hp, ht, ha⟩ := key w.ns w.path none [] h1.1 h2.1 h1.2.1 h2.2.1
          (Or.inl h1.2.2.1) (Or.inl h2.2.2.1) (by simp [h1.2.2.2]) (by simp [h2.2.2.2]) (by simp)
        refine ⟨_, by rw [hs]; rfl, ?_⟩
        rw [resLe_es]
        refine ⟨hns.symm, hp, by simpa using ht, ?_⟩
        apply List.eq_nil_iff_forall_not_mem.mpr
        intro e he
        simpa using ha e he
      | struct w =>
        rw [resLe_ss] at h1 h2
        obtain ⟨s, hs, hns, hp, ht, ha⟩ := key w.ns w.path w.type w.attrs h1.1 h2.1 h1.2.1 h2.2.1
          h1.2.2.1 h2.2.2.1 h1.2.2.2 h2.2.2.2 hz
        refine ⟨_, by rw [hs]; rfl, ?_⟩
        rw [resLe_ss]
        exact ⟨hns.symm, hp, ht, ha⟩

/-! ### Ranges and windows -/

theorem rangeMeet_le {a b r : Range} (h : rangeMeet a b = some r) :
    rangeLe r a = true ∧ rangeLe r b = true := by
  simp only [rangeMeet] at h
  split at h
  · simp at h
  · rename_i hu
    split at h
    · simp at h
    · simp at h; subst h
      have hu' : a.unit = b.unit := Decidable.of_not_not hu
      simp only [rangeLe, Bool.and_eq_true, beq_iff_eq, hu', true_and]
      refine ⟨⟨?_, ?_⟩, ⟨?_, ?_⟩⟩ <;>
        cases a.min <;> cases b.min <;> cases a.max <;> cases b.max <;>
        simp [loLe, hiLe, maxO, minO] <;> omega

theorem rangeMeet_greatest {a b z : Range} (hz : rangeEmpty z = false) (h1 : rangeLe z a = true)
    (h2 : rangeLe z b = true) : ∃ r, rangeMeet a b = some r ∧ rangeLe z r = true := by
  simp only [rangeLe, Bool.and_eq_true, beq_iff_eq] at h1 h2
  obtain ⟨⟨u1, l1⟩, m1⟩ := h1
  obtain ⟨⟨u2, l2⟩, m2⟩ := h2
  unfold rangeMeet
  rw [ite_eq_right (by rw [← u1, ← u2]; simp)]
  have hne : rangeEmpty ⟨maxO a.min b.min, minO a.max b.max, a.unit⟩ = false := by
    revert hz l1 l2 m1 m2
    simp only [rangeEmpty]
    cases a.min <;> cases b.min <;> cases a.max <;> cases b.max <;> cases z.min <;> cases z.max <;>
      simp [loLe, hiLe, maxO, minO] <;> omega
  rw [ite_eq_right (by simp [hne])]
  refine ⟨_, rfl, ?_⟩
  simp only [rangeLe, Bool.and_eq_true, beq_iff_eq]
  refine ⟨⟨u1, ?_⟩, ?_⟩
  · revert l1 l2
    cases a.min <;> cases b.min <;> cases z.min <;> simp [loLe, maxO] <;> omega
  · revert m1 m2
    cases a.max <;> cases b.max <;> cases z.max <;> simp [hiLe, minO] <;> omega

theorem winMeet_le {a b r : Window} (h : winMeet a b = some r) :
    winLe r a = true ∧ winLe r b = true := by
  simp only [winMeet] at h
  split at h
  · simp at h; subst h; simp [winLe]; omega
  · simp at h

theorem winMeet_greatest {a b z : Window} (hz : z.start ≤ z.stop) (h1 : winLe z a = true)
    (h2 : winLe z b = true) : ∃ r, winMeet a b = some r ∧ winLe z r = true := by
  simp only [winLe, Bool.and_eq_true, decide_eq_true_eq] at h1 h2
  unfold winMeet
  rw [ite_eq_left (by simp only; omega)]
  refine ⟨_, rfl, ?_⟩
  simp [winLe]; omega

/-! ### Bounds -/

/-- L0-ALG-5: `a ∩ b ⊑ a` and `a ∩ b ⊑ b`. -/
theorem boundMeet_le {a b r : Bound} (h : boundMeet cat a b = some r) :
    boundLe cat r a = true ∧ boundLe cat r b = true := by
  cases a <;> cases b <;> simp only [boundMeet, reduceCtorEq] at h
  · split at h
    · simp at h
    · simp at h; subst h
      simp only [boundLe, List.all_eq_true, List.contains_iff_mem, mem_nrm, List.mem_filter]
      exact ⟨fun x hx => hx.1, fun x hx => by simpa using hx.2⟩
  · split at h
    · simp at h; subst h; simp_all [boundLe]
    · simp at h
  · split at h
    · simp at h; subst h; simp_all [boundLe]
    · simp at h
  · cases hm : rangeMeet _ _ with
    | none => rw [hm] at h; simp at h
    | some s => rw [hm] at h; simp at h; subst h; exact rangeMeet_le hm
  · simp at h; subst h; simp [boundLe]; omega
  · cases hm : winMeet _ _ with
    | none => rw [hm] at h; simp at h
    | some s => rw [hm] at h; simp at h; subst h; exact winMeet_le hm
  · cases hm : resMeet _ _ with
    | none => rw [hm] at h; simp at h
    | some s => rw [hm] at h; simp at h; subst h; exact resMeet_le hm
  · cases hm : subjMeet _ _ with
    | none => rw [hm] at h; simp at h
    | some s => rw [hm] at h; simp at h; subst h; exact subjMeet_le hm
  · cases hm : pMeet cat _ _ with
    | none => rw [hm] at h; simp at h
    | some s => rw [hm] at h; simp at h; subst h; exact pMeet_le _ _ hm

/-- L0-ALG-5: every well-formed lower bound of `a` and `b` is below `a ∩ b`. -/
theorem boundMeet_greatest (hc : cat.Lawful) {a b z : Bound} (hz : BoundWF z)
    (h1 : boundLe cat z a = true) (h2 : boundLe cat z b = true) :
    ∃ r, boundMeet cat a b = some r ∧ boundLe cat z r = true := by
  cases z <;> cases a <;> simp only [boundLe, reduceCtorEq] at h1 <;> cases b <;>
    simp only [boundLe, reduceCtorEq] at h2 <;> simp only [boundMeet, BoundWF] at hz ⊢
  · rename_i zs as bs
    simp only [List.all_eq_true, List.contains_iff_mem] at h1 h2
    obtain ⟨e, he⟩ := List.exists_mem_of_ne_nil zs hz
    rw [ite_eq_right]
    · refine ⟨_, rfl, ?_⟩
      simp only [boundLe, List.all_eq_true, List.contains_iff_mem, mem_nrm, List.mem_filter]
      exact fun x hx => ⟨h1 x hx, by simpa using h2 x hx⟩
    · intro hempty
      rw [List.isEmpty_iff, nrm_eq_nil, List.filter_eq_nil_iff] at hempty
      exact hempty e (h1 e he) (by simpa using h2 e he)
  · simp only [beq_iff_eq] at h1 h2; subst h1; subst h2; simp [boundLe]
  · simp only [beq_iff_eq] at h1 h2; subst h1; subst h2; simp [boundLe]
  · obtain ⟨r, hr, hle⟩ := rangeMeet_greatest hz h1 h2
    exact ⟨.range r, by rw [hr]; rfl, hle⟩
  · simp only [decide_eq_true_eq] at h1 h2
    refine ⟨_, rfl, ?_⟩; simp [boundLe]; omega
  · obtain ⟨r, hr, hle⟩ := winMeet_greatest hz h1 h2
    exact ⟨.interval r, by rw [hr]; rfl, hle⟩
  · obtain ⟨r, hr, hle⟩ := resMeet_greatest hz h1 h2
    exact ⟨.resource r, by rw [hr]; rfl, hle⟩
  · obtain ⟨r, hr, hle⟩ := subjMeet_greatest h1 h2
    exact ⟨.subject r, by rw [hr]; rfl, hle⟩
  · obtain ⟨r, hr, hle⟩ := pMeet_greatest hc hz h1 h2
    exact ⟨.purpose r, by rw [hr]; rfl, hle⟩

end Access
