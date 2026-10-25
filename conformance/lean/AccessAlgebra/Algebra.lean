import AccessAlgebra.Model

/-!
The operations of protocol/l0/algebra.md: `⊑` (`le`), `∩` (`meet`, `none` is `⊥`) and `normalize`,
together with coverage of an intent (L0-ALG-13, L0-EVAL-10).
-/

namespace Access

variable (cat : Catalog)

/-! ### Actions (L0-ALG-30 … L0-ALG-34) -/

def under (ns pre : String) : Bool := ns == pre || ns.startsWith (pre ++ ".")

def resolve (pre : Prefix) : List ActionRef :=
  match look pre.catalog cat.catalogs with
  | none => []
  | some acts => acts.filter (fun a => under a.ns pre.ns && !cat.reserved.contains a)

def covered (s : ActionSet) : List ActionRef := s.exact ++ s.prefixes.flatMap (resolve cat)

def actsEmpty (s : ActionSet) : Bool := s.exact.isEmpty && s.prefixes.isEmpty

def actsLe (c p : ActionSet) : Bool :=
  (covered cat c).all (fun a => (covered cat p).contains a)

def actsMeet (a b : ActionSet) : Option ActionSet :=
  let ex := nrm ((covered cat a).filter (fun x => (covered cat b).contains x))
  if ex.isEmpty then none else some ⟨ex, []⟩

/-! ### Resources (L0-ALG-40 … L0-ALG-42) -/

def resLe : ResSel → ResSel → Bool
  | .exact c, .exact p => c == p
  | .exact c, .struct p =>
    c.ns == p.ns && p.path.isPrefixOf c.path && p.type.isNone && p.attrs.isEmpty
  | .struct _, .exact _ => false
  | .struct c, .struct p =>
    c.ns == p.ns && p.path.isPrefixOf c.path && (p.type.isNone || p.type == c.type)
      && p.attrs.all (fun e => c.attrs.contains e)

def typeMeet : Option String → Option String → Option (Option String)
  | some a, some b => if a = b then some (some a) else none
  | some a, none => some (some a)
  | none, t => some t

def attrsConflict (x y : List (String × EqVal)) : Bool :=
  x.any (fun e => y.any (fun f => e.1 == f.1 && e.2 != f.2))

def structMeet (x y : Structural) : Option Structural :=
  if x.ns ≠ y.ns then none
  else if attrsConflict x.attrs y.attrs then none
  else
    match (if x.path.isPrefixOf y.path then some y.path
           else if y.path.isPrefixOf x.path then some x.path else none),
          typeMeet x.type y.type with
    | some pre, some ty => some ⟨x.ns, pre, ty, x.attrs ++ y.attrs⟩
    | _, _ => none

def resMeet : ResSel → ResSel → Option ResSel
  | .exact a, b => if resLe (.exact a) b then some (.exact a) else none
  | .struct a, .exact b => if resLe (.exact b) (.struct a) then some (.exact b) else none
  | .struct a, .struct b => (structMeet a b).map .struct

/-! ### Subjects (L0-ALG-45, L0-ALG-46) -/

def subjLe : SubjSel → SubjSel → Bool
  | _, .pub => true
  | .party a, .party b => a == b
  | .pred c, .pred p => p.all (fun x => c.contains x)
  | .foreign d k, .foreign d' k' => d == d' && k == k'
  | _, _ => false

def subjMeet (a b : SubjSel) : Option SubjSel :=
  if subjLe a b then some a
  else if subjLe b a then some b
  else match a, b with
    | .pred x, .pred y => some (.pred (nrm (x ++ y)))
    | _, _ => none

def isPubSel : SubjSel → Bool
  | .pub => true
  | _ => false

def dropPub : Option SubjSel → Option SubjSel
  | some .pub => none
  | o => o

def subjNorm : SubjSel → SubjSel
  | .pred cs => .pred (nrm cs)
  | s => s

/-! ### Purposes (L0-ALG-47, L0-ALG-48) -/

def pLe (c p : List Purpose) : Bool := c.all (fun x => p.any (fun y => cat.below x y))

def maximal (s : List Purpose) : List Purpose :=
  s.filter (fun x => !s.any (fun y => y != x && cat.below x y))

def pNorm (s : List Purpose) : List Purpose := nrm (maximal cat s)

def pMeet (a b : List Purpose) : Option (List Purpose) :=
  let common := (a ++ b ++ cat.purposes).filter
    (fun z => a.any (fun y => cat.below z y) && b.any (fun y => cat.below z y))
  let r := pNorm cat common
  if r.isEmpty then none else some r

/-! ### Ranges and windows (L0-ALG-11, L0-ALG-12) -/

def loLe : Option Int → Option Int → Bool
  | none, _ => true
  | some _, none => false
  | some p, some c => decide (p ≤ c)

def hiLe : Option Int → Option Int → Bool
  | _, none => true
  | none, some _ => false
  | some c, some p => decide (c ≤ p)

def maxO : Option Int → Option Int → Option Int
  | some a, some b => some (max a b)
  | some a, none => some a
  | none, b => b

def minO : Option Int → Option Int → Option Int
  | some a, some b => some (min a b)
  | some a, none => some a
  | none, b => b

def rangeLe (c p : Range) : Bool := c.unit == p.unit && loLe p.min c.min && hiLe c.max p.max

def rangeEmpty (r : Range) : Bool :=
  match r.min, r.max with
  | some lo, some hi => decide (hi < lo)
  | _, _ => false

def rangeMeet (a b : Range) : Option Range :=
  if a.unit ≠ b.unit then none
  else
    let r : Range := ⟨maxO a.min b.min, minO a.max b.max, a.unit⟩
    if rangeEmpty r then none else some r

def winLe (c p : Window) : Bool := decide (p.start ≤ c.start) && decide (c.stop ≤ p.stop)

def winMeet (a b : Window) : Option Window :=
  let w : Window := ⟨max a.start b.start, min a.stop b.stop⟩
  if w.start ≤ w.stop then some w else none

/-! ### Bounds (L0-ALG-10) -/

def boundLe : Bound → Bound → Bool
  | .enum c, .enum p => c.all (fun x => p.contains x)
  | .eq c, .eq p => c == p
  | .flag c, .flag p => c == p
  | .range c, .range p => rangeLe c p
  | .countMax c, .countMax p => decide (c ≤ p)
  | .interval c, .interval p => winLe c p
  | .resource c, .resource p => resLe c p
  | .subject c, .subject p => subjLe c p
  | .purpose c, .purpose p => pLe cat c p
  | _, _ => false

def boundMeet : Bound → Bound → Option Bound
  | .enum x, .enum y =>
    let s := nrm (x.filter (fun e => y.contains e))
    if s.isEmpty then none else some (.enum s)
  | .eq x, .eq y => if x = y then some (.eq x) else none
  | .flag x, .flag y => if x = y then some (.flag x) else none
  | .range x, .range y => (rangeMeet x y).map .range
  | .countMax x, .countMax y => some (.countMax (min x y))
  | .interval x, .interval y => (winMeet x y).map .interval
  | .resource x, .resource y => (resMeet x y).map .resource
  | .subject x, .subject y => (subjMeet x y).map .subject
  | .purpose x, .purpose y => (pMeet cat x y).map .purpose
  | _, _ => none

def isPubBound : Bound → Bool
  | .subject .pub => true
  | _ => false

def boundNorm : Bound → Option Bound
  | .enum s => some (.enum (nrm s))
  | .range r => if rangeEmpty r then none else some (.range r)
  | .subject s => some (.subject (subjNorm s))
  | .purpose s => some (.purpose (pNorm cat s))
  | b => some b

/-- L0-ALG-13. -/
def withinB : Bound → PValue → Bool
  | .enum s, .enum v => s.contains v
  | .eq b, .eq v => b == v
  | .flag b, .flag v => b == v
  | .range r, .amount v u => r.unit == u && r.min.all (· ≤ v) && r.max.all (v ≤ ·)
  | .countMax n, .count v => decide (v ≤ n)
  | .interval w, .interval v => decide (v.start ≤ v.stop) && winLe v w
  | .resource s, .resource r => resLe (.exact r) s
  | .subject s, .subject p => subjLe (.party p) s
  | .purpose s, .purpose q => s.any (fun y => cat.below q y)
  | _, _ => false

/-! ### Authority sets (L0-ALG-50 … L0-ALG-52) -/

def optLe {α : Type} (le : α → α → Bool) : Option α → Option α → Bool
  | _, none => true
  | none, some _ => false
  | some c, some p => le c p

def optMeet {α : Type} (m : α → α → Option α) : Option α → Option α → Option (Option α)
  | none, none => some none
  | some x, none => some (some x)
  | none, some y => some (some y)
  | some x, some y => (m x y).map some

def paramsLe (c p : List (String × Bound)) : Bool :=
  p.all (fun e => match look e.1 c with
    | some cb => boundLe cat cb e.2
    | none => false)

def authLe (c p : Authority) : Bool :=
  actsLe cat c.actions p.actions && resLe c.resource p.resource && paramsLe cat c.params p.params
    && optLe subjLe c.recipient p.recipient && optLe (pLe cat) c.purpose p.purpose

def meetParams (a b : List (String × Bound)) : Option (List (String × Bound)) :=
  match mapVals (fun k va => match look k b with
      | some vb => boundMeet cat va vb
      | none => some va) a with
  | none => none
  | some left => some (nrmBy Prod.fst (left ++ b.filter (fun e => (look e.1 a).isNone)))

def authMeet (a b : Authority) : Option Authority :=
  match actsMeet cat a.actions b.actions, resMeet a.resource b.resource,
      meetParams cat a.params b.params, optMeet subjMeet a.recipient b.recipient,
      optMeet (pMeet cat) a.purpose b.purpose with
  | some acts, some res, some ps, some rc, some pu => some ⟨acts, res, ps, rc, pu⟩
  | _, _, _, _, _ => none

def authNorm (a : Authority) : Option Authority :=
  if actsEmpty a.actions then none
  else match mapVals (fun _ b => boundNorm cat b) a.params with
    | none => none
    | some ps => some
      { actions := ⟨nrm a.actions.exact, nrm a.actions.prefixes⟩
        resource := a.resource
        params := nrmBy Prod.fst (ps.filter (fun e => !isPubBound e.2))
        recipient := dropPub (a.recipient.map subjNorm)
        purpose := a.purpose.map (pNorm cat) }

/-- L0-EVAL-10. -/
def coversA (a : Authority) (i : Intent) : Bool :=
  (covered cat a.actions).contains i.action
    && i.resources.all (fun r => resLe (.exact r) a.resource)
    && a.params.all (fun e => isPubBound e.2 || match look e.1 i.params with
      | some v => withinB cat e.2 v
      | none => false)
    && (match a.recipient with
      | none => true
      | some s => isPubSel s || match i.recipient with
        | some p => subjLe (.party p) s
        | none => false)
    && (match a.purpose with
      | none => true
      | some s => match i.purpose with
        | some q => s.any (fun y => cat.below q y)
        | none => false)

def coversO : Option Authority → Intent → Bool
  | none, _ => false
  | some a, i => coversA cat a i

/-! ### Delegation (L0-ALG-70 … L0-ALG-77) -/

def coversCA (c : CanonAuth) (u : Use) : Bool :=
  coversA cat c.authority u.intent
    && decide (c.constraints.validity.start ≤ u.time) && decide (u.time ≤ c.constraints.validity.stop)
    && c.constraints.conditions.all u.holds
    && c.requirements.all u.met

def isPublic : Option SubjSel → Bool
  | some .pub => true
  | _ => false

def childWithinParent (c p : CanonAuth) (holder : SubjSel) : Bool :=
  -- L0-ALG-75
  !isPublic p.delegation.holderClass
    && (c.delegation.depth == 0
        || (!isPublic (some holder) && !isPublic c.delegation.holderClass))
    -- L0-ALG-71
    && authLe cat c.authority p.authority
    -- L0-ALG-72
    && winLe c.constraints.validity p.constraints.validity
    && p.constraints.conditions.all (fun w => c.constraints.conditions.contains w)
    -- L0-ALG-73
    && decide (0 < p.delegation.depth) && decide (c.delegation.depth < p.delegation.depth)
    -- L0-ALG-74
    && (match p.delegation.holderClass with
      | none => true
      | some cls => subjLe holder cls && optLe subjLe c.delegation.holderClass (some cls))
    -- L0-ALG-76
    && p.requirements.all (fun r => c.requirements.contains r)

end Access
