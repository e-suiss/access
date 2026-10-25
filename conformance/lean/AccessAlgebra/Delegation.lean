import AccessAlgebra.Norm

/-!
L0-ALG-70 … L0-ALG-77: a delegated Grant never covers more than the Grant it comes from.
-/

namespace Access

variable {cat : Catalog}

theorem childWithinParent_iff {c p : CanonAuth} {holder : SubjSel} :
    childWithinParent cat c p holder = true ↔
      isPublic p.delegation.holderClass = false
      ∧ (c.delegation.depth = 0
          ∨ (isPublic (some holder) = false ∧ isPublic c.delegation.holderClass = false))
      ∧ authLe cat c.authority p.authority = true
      ∧ winLe c.constraints.validity p.constraints.validity = true
      ∧ (∀ w ∈ p.constraints.conditions, w ∈ c.constraints.conditions)
      ∧ 0 < p.delegation.depth ∧ c.delegation.depth < p.delegation.depth
      ∧ (∀ cls, p.delegation.holderClass = some cls →
          subjLe holder cls = true ∧ optLe subjLe c.delegation.holderClass (some cls) = true)
      ∧ (∀ r ∈ p.requirements, r ∈ c.requirements) := by
  simp only [childWithinParent, Bool.and_eq_true, Bool.not_eq_true', Bool.or_eq_true, beq_iff_eq,
    List.all_eq_true, List.contains_iff_mem, decide_eq_true_eq, and_assoc]
  refine and_congr Iff.rfl (and_congr Iff.rfl (and_congr Iff.rfl (and_congr Iff.rfl
    (and_congr Iff.rfl (and_congr Iff.rfl (and_congr Iff.rfl (and_congr ?_ Iff.rfl)))))))
  cases p.delegation.holderClass <;> simp

/-- L0-ALG-70: delegation never widens. Every use the child covers, the parent covers. -/
theorem delegation_never_widens (hc : cat.Lawful) {c p : CanonAuth} {holder : SubjSel} {u : Use}
    (h : childWithinParent cat c p holder = true) (hu : coversCA cat c u = true) :
    coversCA cat p u = true := by
  obtain ⟨_, _, ha, hv, hw, _, _, _, hr⟩ := childWithinParent_iff.mp h
  simp only [coversCA, Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true] at hu ⊢
  obtain ⟨⟨⟨⟨hcov, hs⟩, he⟩, hcond⟩, hreq⟩ := hu
  simp only [winLe, Bool.and_eq_true, decide_eq_true_eq] at hv
  exact ⟨⟨⟨⟨authLe_sound hc ha hcov, by omega⟩, by omega⟩, fun w hm => hcond w (hw w hm)⟩,
    fun r hm => hreq r (hr r hm)⟩

/-- L0-ALG-73: delegation strictly lowers the remaining depth. -/
theorem delegation_depth_decreases {c p : CanonAuth} {holder : SubjSel}
    (h : childWithinParent cat c p holder = true) :
    0 < p.delegation.depth ∧ c.delegation.depth < p.delegation.depth := by
  obtain ⟨_, _, _, _, _, h1, h2, _⟩ := childWithinParent_iff.mp h
  exact ⟨h1, h2⟩

/-- L0-ALG-75: a Grant held by `public` cannot be delegated further. -/
theorem public_holder_is_leaf {c p : CanonAuth}
    (h : childWithinParent cat c p .pub = true) : c.delegation.depth = 0 := by
  obtain ⟨_, h2, _⟩ := childWithinParent_iff.mp h
  rcases h2 with h2 | ⟨h2, _⟩
  · exact h2
  · simp [isPublic] at h2

/-- A delegation chain: each Grant is within the one before it. -/
def Chain (cat : Catalog) : List (CanonAuth × SubjSel) → CanonAuth → Prop
  | [], _ => True
  | (c, holder) :: rest, p => childWithinParent cat c p holder = true ∧ Chain cat rest c

/-- L0-ALG-70 along a lineage: the last Grant of a chain covers nothing the root does not. -/
theorem chain_never_widens (hc : cat.Lawful) {u : Use} :
    ∀ (l : List (CanonAuth × SubjSel)) (root : CanonAuth), Chain cat l root →
      ∀ g ∈ l, coversCA cat g.1 u = true → coversCA cat root u = true
  | [], _, _, _, hg, _ => by simp at hg
  | (c, holder) :: rest, root, ⟨h, hrest⟩, g, hg, hu => by
    rcases List.mem_cons.mp hg with hg | hg
    · subst hg; exact delegation_never_widens hc h hu
    · exact delegation_never_widens hc h (chain_never_widens hc rest c hrest g hg hu)

end Access
