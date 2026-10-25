import AccessAlgebra.Norm

/-!
L0-ALG-51: the intersection of two normalized authority sets is normalized.
-/

namespace Access

variable {cat : Catalog}

/-- The parts of an authority set that `normalize` fixes. -/
structure NormalParts (cat : Catalog) (a : Authority) : Prop where
  nonempty : actsEmpty a.actions = false
  exact : nrm a.actions.exact = a.actions.exact
  prefixes : nrm a.actions.prefixes = a.actions.prefixes
  bounds : ∀ k v, (k, v) ∈ a.params → boundNorm cat v = some v
  nopub : ∀ k v, (k, v) ∈ a.params → isPubBound v = false
  sorted : Sorted Prod.fst a.params
  recipient : a.recipient.map subjNorm = a.recipient
  recipientNotPub : a.recipient ≠ some .pub
  purpose : a.purpose.map (pNorm cat) = a.purpose

theorem normalParts_of {a : Authority} (h : authNorm cat a = some a) : NormalParts cat a := by
  have h' := h
  unfold authNorm at h'
  split at h'
  · simp at h'
  · rename_i hne
    split at h'
    · simp at h'
    · rename_i ps hps
      have e := Option.some.inj h'
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
      · rw [← e, actsEmpty_nrm]; simpa using hne
      · rw [← e]; exact nrmBy_idem id _
      · rw [← e]; exact nrmBy_idem id _
      · rw [← e]
        intro k v hm
        obtain ⟨v0, _, hv0⟩ := (mem_mapVals hps).mp (List.mem_filter.mp (mem_of_mem_nrmBy hm)).1
        exact boundNorm_idem hv0
      · rw [← e]
        intro k v hm
        simpa using (List.mem_filter.mp (mem_of_mem_nrmBy hm)).2
      · rw [← e]; exact sorted_nrmBy _ _
      · rw [← e]
        cases a.recipient with
        | none => rfl
        | some s => cases s <;> simp [dropPub, subjNorm, nrmBy_idem]
      · rw [← e]
        cases a.recipient with
        | none => simp [dropPub]
        | some s => cases s <;> simp [dropPub, subjNorm]
      · rw [← e]; simp only [Option.map_map]; cases a.purpose <;> simp [pNorm_idem]

theorem authNorm_of_parts {a : Authority} (h : NormalParts cat a) : authNorm cat a = some a := by
  unfold authNorm
  rw [ite_eq_right (by simp [h.nonempty])]
  rw [mapVals_fix h.bounds]
  dsimp only
  rw [List.filter_eq_self.mpr (fun e he => by simp [h.nopub e.1 e.2 he])]
  have hrp : dropPub (a.recipient.map subjNorm) = a.recipient := by
    rw [h.recipient]
    cases hr : a.recipient with
    | none => rfl
    | some s => cases s <;> simp_all [dropPub, h.recipientNotPub]
  obtain ⟨⟨ex, pre⟩, res, ps, rc, pu⟩ := a
  have hs := nrmBy_of_sorted h.sorted
  have he := h.exact
  have hp := h.prefixes
  have hu := h.purpose
  simp only at hs he hp hrp hu ⊢
  rw [hs, he, hp, hrp, hu]

theorem boundMeet_norm {a b r : Bound} (ha : boundNorm cat a = some a)
    (hb : boundNorm cat b = some b) (h : boundMeet cat a b = some r) : boundNorm cat r = some r := by
  cases a <;> cases b <;> simp only [boundMeet, reduceCtorEq] at h
  · split at h
    · simp at h
    · simp only [Option.some.injEq] at h; subst h; simp [boundNorm, nrmBy_idem]
  · split at h
    · simp only [Option.some.injEq] at h; subst h; rfl
    · simp at h
  · split at h
    · simp only [Option.some.injEq] at h; subst h; rfl
    · simp at h
  · cases hm : rangeMeet _ _ with
    | none => rw [hm] at h; simp at h
    | some s =>
      rw [hm] at h; simp only [Option.map_some, Option.some.injEq] at h; subst h
      simp only [rangeMeet] at hm
      split at hm
      · simp at hm
      · split at hm
        · simp at hm
        · rename_i hne
          simp only [Option.some.injEq] at hm
          subst hm
          simp [boundNorm, hne]
  · simp only [Option.some.injEq] at h; subst h; rfl
  · cases hm : winMeet _ _ with
    | none => rw [hm] at h; simp at h
    | some s => rw [hm] at h; simp only [Option.map_some, Option.some.injEq] at h; subst h; rfl
  · cases hm : resMeet _ _ with
    | none => rw [hm] at h; simp at h
    | some s => rw [hm] at h; simp only [Option.map_some, Option.some.injEq] at h; subst h; rfl
  · rename_i x y
    simp only [boundNorm, Option.some.injEq, Bound.subject.injEq] at ha hb
    cases hm : subjMeet x y with
    | none => rw [hm] at h; simp at h
    | some s =>
      rw [hm] at h; simp only [Option.map_some, Option.some.injEq] at h; subst h
      simp only [boundNorm, Option.some.injEq, Bound.subject.injEq]
      unfold subjMeet at hm
      split at hm
      · simp only [Option.some.injEq] at hm; subst hm; exact ha
      · split at hm
        · simp only [Option.some.injEq] at hm; subst hm; exact hb
        · split at hm
          · simp only [Option.some.injEq] at hm; subst hm; simp [subjNorm, nrmBy_idem]
          · simp at hm
  · cases hm : pMeet cat _ _ with
    | none => rw [hm] at h; simp at h
    | some s =>
      rw [hm] at h; simp only [Option.map_some, Option.some.injEq] at h; subst h
      simp only [pMeet] at hm
      split at hm
      · simp at hm
      · simp only [Option.some.injEq] at hm; subst hm
        simp [boundNorm, pNorm_idem]

theorem subjMeet_norm {x y r : SubjSel} (hx : subjNorm x = x) (hy : subjNorm y = y)
    (h : subjMeet x y = some r) : subjNorm r = r := by
  have := boundMeet_norm (cat := ⟨[], [], [], fun _ _ => true⟩) (a := .subject x) (b := .subject y) (r := .subject r)
    (by simp [boundNorm, hx]) (by simp [boundNorm, hy]) (by simp [boundMeet, h])
  simpa [boundNorm] using this

theorem optMeet_norm {α : Type} {m : α → α → Option α} {N : α → α}
    (hm : ∀ x y r, N x = x → N y = y → m x y = some r → N r = r) {a b r : Option α}
    (ha : a.map N = a) (hb : b.map N = b) (h : optMeet m a b = some r) : r.map N = r := by
  cases a <;> cases b <;> simp only [optMeet, Option.some.injEq] at h
  · subst h; rfl
  · subst h; exact hb
  · subst h; exact ha
  · rename_i x y
    simp only [Option.map_some, Option.some.injEq] at ha hb
    cases hxy : m x y with
    | none => rw [hxy] at h; simp at h
    | some r' =>
      rw [hxy] at h; simp only [Option.map_some, Option.some.injEq] at h; subst h
      simp [hm x y r' ha hb hxy]

theorem subjMeet_nopub {x y r : SubjSel} (hx : isPubSel x = false) (hy : isPubSel y = false)
    (h : subjMeet x y = some r) : isPubSel r = false := by
  unfold subjMeet at h
  split at h
  · simp only [Option.some.injEq] at h; subst h; exact hx
  · split at h
    · simp only [Option.some.injEq] at h; subst h; exact hy
    · split at h
      · simp only [Option.some.injEq] at h; subst h; rfl
      · simp at h

theorem boundMeet_nopub {a b r : Bound} (ha : isPubBound a = false) (hb : isPubBound b = false)
    (h : boundMeet cat a b = some r) : isPubBound r = false := by
  cases a <;> cases b <;> simp only [boundMeet, reduceCtorEq] at h
  case subject.subject x y =>
    have hx : isPubSel x = false := by cases x <;> simp_all [isPubBound, isPubSel]
    have hy : isPubSel y = false := by cases y <;> simp_all [isPubBound, isPubSel]
    obtain ⟨s, hm, rfl⟩ := Option.map_eq_some_iff.mp h
    have := subjMeet_nopub hx hy hm
    cases s <;> simp_all [isPubBound, isPubSel]
  all_goals
    revert h
    first
    | (split <;> intro h <;> simp only [Option.some.injEq, reduceCtorEq] at h <;> subst h <;> rfl)
    | (intro h; simp only [Option.some.injEq] at h; subst h; rfl)
    | (intro h; obtain ⟨_, _, rfl⟩ := Option.map_eq_some_iff.mp h; rfl)

/-- L0-ALG-51: the intersection of two normalized authority sets is itself normalized. -/
theorem authMeet_normal {a b m : Authority} (na : authNorm cat a = some a)
    (nb : authNorm cat b = some b) (h : authMeet cat a b = some m) : authNorm cat m = some m := by
  have pa := normalParts_of na
  have pb := normalParts_of nb
  unfold authMeet at h
  split at h
  · rename_i acts res ps rc pu ha hr hp hrc hpu
    simp only [Option.some.injEq] at h
    subst h
    apply authNorm_of_parts
    simp only [actsMeet] at ha
    split at ha
    · simp at ha
    · rename_i hne
      simp only [Option.some.injEq] at ha
      subst ha
      unfold meetParams at hp
      split at hp
      · simp at hp
      · rename_i left hl
        simp only [Option.some.injEq] at hp
        subst hp
        refine ⟨?_, nrmBy_idem id _, rfl, ?_, ?_, sorted_nrmBy _ _, ?_, ?_, ?_⟩
        · simpa [actsEmpty, List.isEmpty_iff] using hne
        · intro k v hm
          rcases List.mem_append.mp (mem_of_mem_nrmBy hm) with hm | hm
          · obtain ⟨v0, hv0, hg⟩ := (mem_mapVals hl).mp hm
            revert hg
            cases hb : look k b.params with
            | none => simp only [Option.some.injEq]; intro e; subst e; exact pa.bounds k _ hv0
            | some vb =>
              intro hg
              exact boundMeet_norm (pa.bounds k v0 hv0) (pb.bounds k vb (look_mem hb)) hg
          · exact pb.bounds k v (List.mem_filter.mp hm).1
        · intro k v hm
          rcases List.mem_append.mp (mem_of_mem_nrmBy hm) with hm | hm
          · obtain ⟨v0, hv0, hg⟩ := (mem_mapVals hl).mp hm
            revert hg
            cases hb : look k b.params with
            | none => simp only [Option.some.injEq]; intro e; subst e; exact pa.nopub k _ hv0
            | some vb =>
              intro hg
              exact boundMeet_nopub (pa.nopub k v0 hv0) (pb.nopub k vb (look_mem hb)) hg
          · exact pb.nopub k v (List.mem_filter.mp hm).1
        · exact optMeet_norm (fun _ _ _ hx hy h => subjMeet_norm hx hy h)
            pa.recipient pb.recipient hrc
        · have nopub : ∀ o : Option SubjSel, o ≠ some .pub → ∀ s, o = some s → isPubSel s = false := by
            intro o ho s hs; subst hs; cases s <;> simp_all [isPubSel]
          intro hr
          simp only at hr
          have := optMeet_norm (N := fun s => if isPubSel s then .party "" else s)
            (m := subjMeet) (a := a.recipient) (b := b.recipient) (r := rc) ?_ ?_ ?_ hrc
          · rw [hr] at this; simp [isPubSel] at this
          · intro x y r hx hy h
            have hx' : isPubSel x = false := by revert hx; cases x <;> simp [isPubSel]
            have hy' : isPubSel y = false := by revert hy; cases y <;> simp [isPubSel]
            simp [subjMeet_nopub hx' hy' h]
          · cases hra : a.recipient with
            | none => rfl
            | some s => simp [nopub _ pa.recipientNotPub s hra]
          · cases hrb : b.recipient with
            | none => rfl
            | some s => simp [nopub _ pb.recipientNotPub s hrb]
        · refine optMeet_norm (N := pNorm cat) (fun _ _ r _ _ h => ?_) pa.purpose pb.purpose hpu
          simp only [pMeet] at h
          split at h
          · simp at h
          · simp only [Option.some.injEq] at h; subst h; exact pNorm_idem _
  · simp at h

end Access
