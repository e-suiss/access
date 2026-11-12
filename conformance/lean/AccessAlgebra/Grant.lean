import AccessAlgebra.Delegation
import AccessAlgebra.AuthMeet

/-!
Grant-algebra properties of INV-3, INV-5 and INV-8: the operations are decidable, a projection
never covers more than its source, and a lineage's validity cascades monotonically.
-/

namespace Access

variable {cat : Catalog}

/-! ### INV-8: ⊑, ∩ and normalize decide their relations -/

def Subsumes (cat : Catalog) (c p : Authority) : Prop := authLe cat c p = true

def MeetIs (cat : Catalog) (a b : Authority) (m : Option Authority) : Prop := authMeet cat a b = m

def NormalizesTo (cat : Catalog) (a : Authority) (n : Option Authority) : Prop := authNorm cat a = n

instance decSubsumes (cat : Catalog) (c p : Authority) : Decidable (Subsumes cat c p) :=
  inferInstanceAs (Decidable (authLe cat c p = true))

instance decMeetIs (cat : Catalog) (a b : Authority) (m : Option Authority) :
    Decidable (MeetIs cat a b m) :=
  inferInstanceAs (Decidable (authMeet cat a b = m))

instance decNormalizesTo (cat : Catalog) (a : Authority) (n : Option Authority) :
    Decidable (NormalizesTo cat a n) :=
  inferInstanceAs (Decidable (authNorm cat a = n))

/-! ### INV-3: every projection lies within its source -/

/-- A projection narrows its source to a scope (a token, a Mandate, a derived view). -/
def project (cat : Catalog) (source scope : Authority) : Option Authority := authMeet cat source scope

theorem projection_within_source (hc : cat.Lawful) {source scope p : Authority}
    (ss : ParamsSorted source) (sc : ParamsSorted scope) (h : project cat source scope = some p) :
    authLe cat p source = true ∧ ∀ i, coversA cat p i = true → coversA cat source i = true := by
  have hle := (authMeet_le hc ss sc h).1
  exact ⟨hle, fun _ hi => authLe_sound hc hle hi⟩

/-! ### INV-5: terminal invalidity and a monotone cascade -/

/-- When a Grant was issued and, if it has, when it ended (revoke, expire, renounce, affirmative
lapse, Instance termination). Ending is terminal: the time never moves. -/
structure Life where
  issued : Nat
  ended : Option Nat
  deriving DecidableEq, Repr

def Life.liveAt (g : Life) (t : Nat) : Bool := decide (g.issued ≤ t) && g.ended.all (fun e => decide (t < e))

structure Link where
  grant : CanonAuth
  life : Life

/-- A lineage is valid at `t` only when every link from the root to the Grant is. -/
def live (l : List Link) (t : Nat) : Bool := l.all (fun k => k.life.liveAt t)

/-- What a lineage permits: it is valid at the use's time and every link covers the use. -/
def permits (cat : Catalog) (l : List Link) (u : Use) : Bool :=
  live l u.time && l.all (fun k => coversCA cat k.grant u)

theorem live_of_between {l : List Link} {t₀ t₁ t₂ : Nat} (h01 : t₀ ≤ t₁) (h12 : t₁ ≤ t₂)
    (h0 : live l t₀ = true) (h2 : live l t₂ = true) : live l t₁ = true := by
  simp only [live, List.all_eq_true] at *
  intro k hk
  have a := h0 k hk
  have b := h2 k hk
  simp only [Life.liveAt, Bool.and_eq_true, decide_eq_true_eq] at a b ⊢
  refine ⟨by omega, ?_⟩
  cases he : k.life.ended with
  | none => rfl
  | some e =>
    rw [he] at b
    simp only [Option.all_some, decide_eq_true_eq] at b
    simp only [Option.all_some, decide_eq_true_eq]
    omega

theorem narrowed_permits (hc : cat.Lawful) {pre post : List Link} {k k' : Link}
    (ha : authLe cat k'.grant.authority k.grant.authority = true)
    (hcons : k'.grant.constraints = k.grant.constraints)
    (hreq : k'.grant.requirements = k.grant.requirements) (hl : k'.life = k.life) {u : Use}
    (h : permits cat (pre ++ k' :: post) u = true) : permits cat (pre ++ k :: post) u = true := by
  simp only [permits, live, Bool.and_eq_true, List.all_eq_true, List.mem_append, List.mem_cons] at h ⊢
  obtain ⟨hlive, hcov⟩ := h
  refine ⟨fun x hx => ?_, fun x hx => ?_⟩
  · rcases hx with hx | rfl | hx
    · exact hlive x (Or.inl hx)
    · rw [← hl]; exact hlive k' (Or.inr (Or.inl rfl))
    · exact hlive x (Or.inr (Or.inr hx))
  · rcases hx with hx | rfl | hx
    · exact hcov x (Or.inl hx)
    · have hk' := hcov k' (Or.inr (Or.inl rfl))
      simp only [coversCA, Bool.and_eq_true] at hk' ⊢
      obtain ⟨⟨⟨⟨hcv, h1⟩, h2⟩, h3⟩, h4⟩ := hk'
      rw [hcons] at h1 h2 h3
      rw [hreq] at h4
      exact ⟨⟨⟨⟨authLe_sound hc ha hcv, h1⟩, h2⟩, h3⟩, h4⟩
    · exact hcov x (Or.inr (Or.inr hx))

/-- INV-3, INV-5: an ended link ends the whole lineage from its end on; a lineage that was valid,
stopped being valid and is valid again cannot exist (no revival); narrowing any link narrows what
the lineage permits. -/
theorem cascade_monotone (hc : cat.Lawful) (l : List Link) :
    (∀ k ∈ l, ∀ e, k.life.ended = some e → ∀ t, e ≤ t → live l t = false)
    ∧ (∀ t₀ t₁ t₂, t₀ ≤ t₁ → t₁ ≤ t₂ → live l t₀ = true → live l t₁ = false → live l t₂ = false)
    ∧ (∀ pre post k k', l = pre ++ k :: post →
        authLe cat k'.grant.authority k.grant.authority = true →
        k'.grant.constraints = k.grant.constraints → k'.grant.requirements = k.grant.requirements →
        k'.life = k.life → ∀ u, permits cat (pre ++ k' :: post) u = true → permits cat l u = true) := by
  refine ⟨?_, ?_, ?_⟩
  · intro k hk e he t ht
    cases h : live l t with
    | false => rfl
    | true =>
      simp only [live, List.all_eq_true] at h
      have := h k hk
      simp only [Life.liveAt, he, Option.all_some, Bool.and_eq_true, decide_eq_true_eq] at this
      omega
  · intro t₀ t₁ t₂ h01 h12 h0 h1
    cases h2 : live l t₂ with
    | false => rfl
    | true => rw [live_of_between h01 h12 h0 h2] at h1; cases h1
  · intro pre post k k' hl ha hcons hreq hlife u h
    subst hl
    exact narrowed_permits hc ha hcons hreq hlife h

end Access
