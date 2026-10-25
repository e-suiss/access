import AccessAlgebra.Order

/-!
Values of the authority algebra. Identifiers, digests and opaque encodings are strings; times are
milliseconds; amounts are integers.
-/

namespace Access

inductive EqVal where
  | text (s : String)
  | bytes (s : String)
  | int (n : Int)
  | bool (b : Bool)
  deriving DecidableEq, Repr

structure ActionRef where
  ns : String
  name : String
  major : Nat
  schema : String
  deriving DecidableEq, Repr

structure Prefix where
  ns : String
  catalog : String
  deriving DecidableEq, Repr

structure ActionSet where
  exact : List ActionRef
  prefixes : List Prefix
  deriving DecidableEq, Repr

structure ResourceRef where
  ns : String
  path : List String
  incarnation : Nat
  deriving DecidableEq, Repr

structure Structural where
  ns : String
  path : List String
  type : Option String
  attrs : List (String × EqVal)
  deriving DecidableEq, Repr

inductive ResSel where
  | exact (r : ResourceRef)
  | struct (s : Structural)
  deriving DecidableEq, Repr

structure Conjunct where
  cls : String
  value : Option EqVal
  deriving DecidableEq, Repr

inductive SubjSel where
  | pub
  | party (p : String)
  | pred (cs : List Conjunct)
  | foreign (domain cls : String)
  deriving DecidableEq, Repr

inductive Purpose where
  | code (s : String)
  | work (d : String)
  | aim (d : String)
  deriving DecidableEq, Repr

structure Range where
  min : Option Int
  max : Option Int
  unit : String
  deriving DecidableEq, Repr

structure Window where
  start : Nat
  stop : Nat
  deriving DecidableEq, Repr

/-- L0-ALG-10: the nine closed bound types. -/
inductive Bound where
  | enum (s : List String)
  | eq (v : EqVal)
  | flag (b : Bool)
  | range (r : Range)
  | countMax (n : Nat)
  | interval (w : Window)
  | resource (s : ResSel)
  | subject (s : SubjSel)
  | purpose (s : List Purpose)
  deriving DecidableEq, Repr

inductive PValue where
  | enum (s : String)
  | eq (v : EqVal)
  | flag (b : Bool)
  | amount (v : Int) (unit : String)
  | count (n : Nat)
  | interval (w : Window)
  | resource (r : ResourceRef)
  | subject (p : String)
  | purpose (p : Purpose)
  deriving DecidableEq, Repr

structure Authority where
  actions : ActionSet
  resource : ResSel
  params : List (String × Bound)
  recipient : Option SubjSel
  purpose : Option (List Purpose)
  deriving DecidableEq, Repr

inductive WhileCond where
  | instanceAlive (i : String)
  | claimHeld (cls : String) (subject : SubjSel) (acceptance : String)
  deriving DecidableEq, Repr

structure Constraints where
  validity : Window
  conditions : List WhileCond
  deriving DecidableEq, Repr

structure Delegation where
  depth : Nat
  holderClass : Option SubjSel
  deriving DecidableEq, Repr

/-- L0-ALG-61: requirement terms compare by canonical encoding only. -/
structure CanonAuth where
  authority : Authority
  constraints : Constraints
  delegation : Delegation
  requirements : List String
  deriving DecidableEq, Repr

structure Intent where
  action : ActionRef
  resources : List ResourceRef
  params : List (String × PValue)
  recipient : Option String
  purpose : Option Purpose
  deriving DecidableEq, Repr

/-- A concrete use: an intent at a time, with the while-conditions and requirement terms it meets. -/
structure Use where
  intent : Intent
  time : Nat
  holds : WhileCond → Bool
  met : String → Bool

/-- Catalog input: pinned action catalogs, reserved actions and the declared purpose order. -/
structure Catalog where
  catalogs : List (String × List ActionRef)
  reserved : List ActionRef
  purposes : List Purpose
  below : Purpose → Purpose → Bool

/-- L0-ALG-47: "below" is a partial order and only declared purposes sit strictly below another. -/
structure Catalog.Lawful (cat : Catalog) : Prop where
  refl : ∀ a, cat.below a a = true
  trans : ∀ a b c, cat.below a b = true → cat.below b c = true → cat.below a c = true
  antisymm : ∀ a b, cat.below a b = true → cat.below b a = true → a = b
  closed : ∀ a b, cat.below a b = true → a ≠ b → a ∈ cat.purposes

section Orders
open LinOrd

instance : LinOrd EqVal :=
  ofInj (β := Sum String (Sum String (Sum Int Bool)))
    (fun | .text s => .inl s | .bytes s => .inr (.inl s) | .int n => .inr (.inr (.inl n))
         | .bool b => .inr (.inr (.inr b)))
    (fun a b h => by cases a <;> cases b <;> simp_all)

instance : LinOrd ActionRef :=
  ofInj (fun a => (a.ns, a.name, a.major, a.schema))
    (fun a b h => by cases a; cases b; simp_all)

instance : LinOrd Prefix :=
  ofInj (fun a => (a.ns, a.catalog)) (fun a b h => by cases a; cases b; simp_all)

instance : LinOrd Conjunct :=
  ofInj (fun a => (a.cls, a.value)) (fun a b h => by cases a; cases b; simp_all)

instance : LinOrd Purpose :=
  ofInj (β := Sum String (Sum String String))
    (fun | .code s => .inl s | .work d => .inr (.inl d) | .aim d => .inr (.inr d))
    (fun a b h => by cases a <;> cases b <;> simp_all)

end Orders

end Access
