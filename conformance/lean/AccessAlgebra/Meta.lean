/-!
Holding terms on meta-actions (L0-META-13, OP-157 m.22 (f), OP-159 m.3 (k)). A meta-Exercise on a
holding basis reads the declared holding's lineage at the evaluation's trusted time: every link
has not ended, lies within its validity window, has its requirement terms met and its
while-conditions holding, and a Mandate pin, if any, names that holding and episode. The other
bases (root power over an Anchor, `public`) and the implicit powers (lineage power, power over
one's own Instances) are decided as before.
-/

namespace Access.Meta

structure Link where
  ended : Bool
  validFrom : Nat
  validUntil : Nat
  termsMet : Bool
  conditionsHold : Bool
  deriving DecidableEq, Repr

structure Pin where
  grant : String
  since : Nat
  deriving DecidableEq, Repr

inductive Basis where
  | anchor (a : String)
  | holding (grant : String) (since : Nat) (lineage : List Link)
  | pub (g : String)
  deriving DecidableEq, Repr

structure Input where
  now : Nat
  basis : Basis
  basisFits : Bool
  authorized : Bool
  pin : Option Pin

inductive Reason where
  | metaBasis
  | holdingTerms
  | notAuthorized
  deriving DecidableEq, Repr

def linkHolds (now : Nat) (k : Link) : Bool :=
  !k.ended && decide (k.validFrom ≤ now) && decide (now ≤ k.validUntil) && k.termsMet
    && k.conditionsHold

def holdingTerms (now : Nat) (pin : Option Pin) (g : String) (s : Nat) (l : List Link) : Bool :=
  l.all (linkHolds now) && pin.all (fun p => p.grant == g && p.since == s)

def decide (m : Input) : Except Reason Unit :=
  if !m.basisFits then .error .metaBasis
  else match m.basis with
    | .holding g s l =>
      if !holdingTerms m.now m.pin g s l then .error .holdingTerms
      else if m.authorized then .ok () else .error .notAuthorized
    | _ => if m.authorized then .ok () else .error .notAuthorized

/-- L0-META-13, OP-157 m.22 (f): an allowed meta-Exercise on a holding basis rests on a lineage
whose every link holds at the trusted time, and on the pinned episode when a pin exists. -/
theorem meta_holding_sound {m : Input} {g : String} {s : Nat} {l : List Link}
    (hb : m.basis = .holding g s l) (h : decide m = .ok ()) :
    (∀ k ∈ l, k.ended = false ∧ k.validFrom ≤ m.now ∧ m.now ≤ k.validUntil ∧ k.termsMet = true
        ∧ k.conditionsHold = true)
    ∧ ∀ p, m.pin = some p → p.grant = g ∧ p.since = s := by
  unfold decide at h
  rw [hb] at h
  cases hf : m.basisFits <;> simp only [hf, Bool.not_false, Bool.not_true] at h
  · cases h
  · cases ht : holdingTerms m.now m.pin g s l <;> simp only [ht, Bool.not_false, Bool.not_true] at h
    · cases h
    · simp only [holdingTerms, Bool.and_eq_true, List.all_eq_true] at ht
      refine ⟨fun k hk => ?_, fun p hp => ?_⟩
      · have := ht.1 k hk
        simp only [linkHolds, Bool.and_eq_true, Bool.not_eq_true', decide_eq_true_eq] at this
        exact ⟨this.1.1.1.1, this.1.1.1.2, this.1.1.2, this.1.2, this.2⟩
      · have := ht.2
        rw [hp] at this
        simpa using this

/-- OP-157 m.22 (f): the holding terms do not change how the other bases are decided. -/
theorem meta_other_bases_unchanged {m : Input} (hb : ∀ g s l, m.basis ≠ .holding g s l) :
    decide m = .ok () ↔ m.basisFits = true ∧ m.authorized = true := by
  unfold decide
  cases hbs : m.basis with
  | holding g s l => exact absurd hbs (hb g s l)
  | anchor a => cases m.basisFits <;> cases m.authorized <;> simp
  | pub g => cases m.basisFits <;> cases m.authorized <;> simp

end Access.Meta
