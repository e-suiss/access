import AccessAlgebra.AuthMeet

/-!
L0-ALG-5, L0-ALG-52: `normalize` is idempotent and allows exactly what its input allows.
-/

namespace Access

variable {cat : Catalog}

/-! ### Purposes and subjects -/

theorem maximal_nrm_maximal (s : List Purpose) :
    maximal cat (nrm (maximal cat s)) = nrm (maximal cat s) := by
  apply List.filter_eq_self.mpr
  intro x hx
  have hxm := mem_maximal.mp (mem_nrm.mp hx)
  simp only [Bool.not_eq_eq_eq_not, Bool.not_true, List.any_eq_false, Bool.and_eq_true,
    bne_iff_ne, ne_eq, not_and, Bool.not_eq_true]
  intro y hy hne
  exact hxm.2 y (mem_maximal.mp (mem_nrm.mp hy)).1 hne

theorem pNorm_idem (s : List Purpose) : pNorm cat (pNorm cat s) = pNorm cat s := by
  unfold pNorm
  rw [maximal_nrm_maximal]
  exact nrmBy_idem id _

theorem any_pNorm (hc : cat.Lawful) (s : List Purpose) (q : Purpose) :
    (∃ y ∈ pNorm cat s, cat.below q y = true) ↔ ∃ y ∈ s, cat.below q y = true := by
  constructor
  · rintro ⟨y, hy, hq⟩
    exact ⟨y, (mem_maximal.mp (mem_pNorm.mp hy)).1, hq⟩
  · rintro ⟨y, hy, hq⟩
    obtain ⟨m, hm, hym⟩ := exists_max hc s y hy
    exact ⟨m, mem_pNorm.mpr hm, hc.trans _ _ _ hq hym⟩

theorem subjNorm_idem (s : SubjSel) : subjNorm (subjNorm s) = subjNorm s := by
  cases s <;> simp [subjNorm, nrmBy_idem]

theorem subjLe_party_norm (p : String) (s : SubjSel) :
    subjLe (.party p) (subjNorm s) = subjLe (.party p) s := by
  cases s <;> simp [subjNorm, subjLe]

theorem isPubSel_subjNorm (s : SubjSel) : isPubSel (subjNorm s) = isPubSel s := by
  cases s <;> rfl

theorem dropPub_idem (o : Option SubjSel) :
    dropPub ((dropPub (o.map subjNorm)).map subjNorm) = dropPub (o.map subjNorm) := by
  cases o with
  | none => rfl
  | some s => cases s <;> simp [dropPub, subjNorm, nrmBy_idem]

/-! ### Bounds -/

def withinN (cat : Catalog) : Option Bound → PValue → Bool
  | none, _ => false
  | some b, v => withinB cat b v

/-- L0-ALG-5: normalizing a bound twice is normalizing it once. -/
theorem boundNorm_idem {b n : Bound} (h : boundNorm cat b = some n) : boundNorm cat n = some n := by
  cases b <;> simp only [boundNorm, Option.some.injEq] at h
  · subst h; simp [boundNorm, nrmBy_idem]
  · subst h; rfl
  · subst h; rfl
  · split at h
    · simp at h
    · rename_i he
      simp only [Option.some.injEq] at h
      subst h
      simp [boundNorm, he]
  · subst h; rfl
  · subst h; rfl
  · subst h; rfl
  · subst h; simp [boundNorm, subjNorm_idem]
  · subst h; simp [boundNorm, pNorm_idem]

/-- L0-ALG-5: a normalized bound allows exactly what the bound allows. -/
theorem boundNorm_within (hc : cat.Lawful) (b : Bound) (v : PValue) :
    withinN cat (boundNorm cat b) v = withinB cat b v := by
  cases b <;> simp only [boundNorm, withinN]
  · cases v <;> simp [withinB, mem_nrm]
  · rename_i r
    obtain ⟨mn, mx, un⟩ := r
    by_cases he : rangeEmpty ⟨mn, mx, un⟩ = true
    · simp only [he, ite_true]
      cases v <;> simp only [withinB]
      rename_i x u
      simp only [rangeEmpty] at he
      revert he
      cases mn <;> cases mx <;> simp <;> omega
    · simp [he]
  · cases v <;> simp [withinB, subjLe_party_norm]
  · cases v <;> simp only [withinB]
    rename_i s q
    rw [Bool.eq_iff_iff, List.any_eq_true, List.any_eq_true]
    exact any_pNorm hc s q

theorem isPubBound_norm {b n : Bound} (h : boundNorm cat b = some n) :
    isPubBound n = isPubBound b := by
  cases b <;> simp only [boundNorm, Option.some.injEq] at h
  all_goals first
    | (subst h; rfl)
    | (subst h; rename_i s; cases s <;> rfl)
    | (split at h <;> simp at h; subst h; rfl)

theorem isPubBound_of_norm_none {b : Bound} (h : boundNorm cat b = none) : isPubBound b = false := by
  cases b <;> simp_all [boundNorm, isPubBound]

/-! ### Authority sets -/

theorem mem_covered_nrm {s : ActionSet} {x : ActionRef} :
    x ∈ covered cat ⟨nrm s.exact, nrm s.prefixes⟩ ↔ x ∈ covered cat s := by
  simp [covered, mem_nrm, List.mem_flatMap]

theorem isEmpty_nrm {α : Type} [DecidableEq α] [LinOrd α] (l : List α) :
    (nrm l).isEmpty = l.isEmpty := by
  rw [Bool.eq_iff_iff, List.isEmpty_iff, List.isEmpty_iff, nrm_eq_nil]

theorem actsEmpty_nrm (s : ActionSet) :
    actsEmpty ⟨nrm s.exact, nrm s.prefixes⟩ = actsEmpty s := by
  simp only [actsEmpty, isEmpty_nrm]

theorem covered_of_actsEmpty {s : ActionSet} (h : actsEmpty s = true) : covered cat s = [] := by
  simp only [actsEmpty, Bool.and_eq_true, List.isEmpty_iff] at h
  simp [covered, h.1, h.2]

theorem mem_nrmBy_of_nodup {β : Type} {l : List (String × β)} (hn : (l.map Prod.fst).Nodup)
    {k : String} {v : β} : (k, v) ∈ nrmBy Prod.fst l ↔ (k, v) ∈ l := by
  constructor
  · exact mem_of_mem_nrmBy
  · intro h
    have := look_of_mem_nodup hn h
    rw [← look_nrmBy] at this
    exact look_mem this


/-- L0-ALG-5: normalizing an authority set twice is normalizing it once. -/
theorem authNorm_idem {a n : Authority} (h : authNorm cat a = some n) :
    authNorm cat n = some n := by
  unfold authNorm at h
  split at h
  · simp at h
  · rename_i hne
    split at h
    · simp at h
    · rename_i ps hps
      simp only [Option.some.injEq] at h
      subst h
      unfold authNorm
      have hne' : actsEmpty ⟨nrm a.actions.exact, nrm a.actions.prefixes⟩ = false := by
        rw [actsEmpty_nrm]; simpa using hne
      rw [ite_eq_right (by simp only at hne' ⊢; simp [hne'])]
      have hfix : mapVals (fun _ b => boundNorm cat b)
          (nrmBy Prod.fst (ps.filter (fun e => !isPubBound e.2)))
          = some (nrmBy Prod.fst (ps.filter (fun e => !isPubBound e.2))) := by
        apply mapVals_fix
        intro k v hm
        obtain ⟨v0, _, hv0⟩ := (mem_mapVals hps).mp (List.mem_filter.mp (mem_of_mem_nrmBy hm)).1
        exact boundNorm_idem hv0
      have hflt : (nrmBy Prod.fst (ps.filter (fun e => !isPubBound e.2))).filter
          (fun e => !isPubBound e.2) = nrmBy Prod.fst (ps.filter (fun e => !isPubBound e.2)) := by
        apply List.filter_eq_self.mpr
        intro e he
        exact (List.mem_filter.mp (mem_of_mem_nrmBy he)).2
      simp only
      rw [hfix]
      simp only [hflt, nrmBy_idem, Option.map_map, dropPub_idem]
      congr 1
      congr 1
      cases a.purpose <;> simp [pNorm_idem]

/-- L0-ALG-5: a normalized authority set covers exactly the intents its input covers. -/
theorem authNorm_covers (hc : cat.Lawful) {a : Authority} (hn : (a.params.map Prod.fst).Nodup)
    (i : Intent) : coversO cat (authNorm cat a) i = coversA cat a i := by
  unfold authNorm
  split
  · rename_i he
    simp only [coversO]
    symm
    rw [Bool.eq_false_iff]
    intro hc'
    have := (coversA_iff.mp hc').1
    rw [covered_of_actsEmpty he] at this
    simp at this
  · split
    · rename_i hnone
      obtain ⟨k, v, hm, hv⟩ := mapVals_none hnone
      simp only [coversO]
      symm
      rw [Bool.eq_false_iff]
      intro hc'
      obtain ⟨x, _, hw⟩ := (coversA_iff.mp hc').2.2.1 k v hm (isPubBound_of_norm_none hv)
      have := boundNorm_within hc v x
      rw [hv] at this
      simp only [withinN] at this
      rw [← this] at hw
      simp at hw
    · rename_i ps hps
      simp only [coversO]
      rw [Bool.eq_iff_iff]
      have hnps : ((ps.filter (fun e => !isPubBound e.2)).map Prod.fst).Nodup := by
        apply ((List.filter_sublist (l := ps)).map Prod.fst).nodup
        rw [mapVals_keys hps]; exact hn
      rw [coversA_iff, coversA_iff]
      simp only [mem_covered_nrm]
      refine and_congr Iff.rfl (and_congr Iff.rfl (and_congr ?_ (and_congr ?_ ?_)))
      · simp only [mem_nrmBy_of_nodup hnps, List.mem_filter, Bool.not_eq_eq_eq_not, Bool.not_true]
        constructor
        · intro h k v0 hm hp
          obtain ⟨w, hw⟩ := mapVals_some_all hps k v0 hm
          have hpw : isPubBound w = false := by rw [isPubBound_norm hw]; exact hp
          obtain ⟨x, hx, hwx⟩ := h k w ⟨(mem_mapVals hps).mpr ⟨v0, hm, hw⟩, hpw⟩ hpw
          refine ⟨x, hx, ?_⟩
          have := boundNorm_within hc v0 x
          rw [hw] at this
          simp only [withinN] at this
          rw [← this]; exact hwx
        · intro h k w hm hp
          obtain ⟨v0, hm0, hw⟩ := (mem_mapVals hps).mp hm.1
          obtain ⟨x, hx, hvx⟩ := h k v0 hm0 (by rw [← isPubBound_norm hw]; exact hp)
          refine ⟨x, hx, ?_⟩
          have := boundNorm_within hc v0 x
          rw [hw] at this
          simp only [withinN] at this
          rw [this]; exact hvx
      · cases a.recipient with
        | none => simp [dropPub]
        | some s => cases s <;> simp [dropPub, subjNorm, isPubSel, subjLe]
      · cases a.purpose with
        | none => simp
        | some s =>
          simp only [Option.map_some, Option.some.injEq, forall_eq']
          constructor
          · rintro ⟨q, hq, hy⟩; exact ⟨q, hq, (any_pNorm hc s q).mp hy⟩
          · rintro ⟨q, hq, hy⟩; exact ⟨q, hq, (any_pNorm hc s q).mpr hy⟩

end Access
