import Decode

/-!
Rust ↔ Lean differential runner (OP-159 m.3 (v), CR-49 m.1). Reads the CBOR sequences that
`just f0-random` writes (a header with the catalog, then one case per item), evaluates the model on
each case and compares its answer with the Kernel's.
-/

open Access

-- OP-159 m.3 (v)
def reach (edges : List (Purpose × List Purpose)) : Nat → Purpose → Purpose → Bool
  | 0, _, _ => false
  | n + 1, a, b => match look b edges with
    | none => false
    | some cs => cs.any (fun c => c == a || reach edges n a c)

def catalogOf (c : Cbor) : D Catalog := do
  let m ← asMap c
  let catalogs ← (← asArr (← req m "catalogs")).mapM fun e => do
    match ← asArr e with
    | [k, acts] => return (k.render, ← (← asArr acts).mapM actionRef)
    | _ => throw "expected a catalog entry"
  let reserved ← (← asArr (← req m "reserved")).mapM actionRef
  let edges ← (← asArr (← req m "purposes")).mapM fun e => do
    match ← asArr e with
    | [p, below] => return (← purposeRef p, ← (← asArr below).mapM purposeRef)
    | _ => throw "expected a purpose entry"
  let n := edges.length + 1
  return ⟨catalogs, reserved, edges.map (·.1) ++ edges.flatMap (·.2),
    fun a b => a == b || reach edges n a b⟩

def canonSubj : SubjSel → SubjSel
  | .pred cs => .pred (nrm cs)
  | s => s

def canonRes : ResSel → ResSel
  | .struct s => .struct { s with attrs := nrmBy Prod.fst s.attrs }
  | r => r

def canonBound : Bound → Bound
  | .enum s => .enum (nrm s)
  | .resource r => .resource (canonRes r)
  | .subject s => .subject (canonSubj s)
  | .purpose p => .purpose (nrm p)
  | b => b

/-- One representation per value: the model and the Kernel order sets differently. -/
def canonA (a : Authority) : Authority :=
  { actions := ⟨nrm a.actions.exact, nrm a.actions.prefixes⟩
    resource := canonRes a.resource
    params := nrmBy Prod.fst (a.params.map fun e => (e.1, canonBound e.2))
    recipient := a.recipient.map canonSubj
    purpose := a.purpose.map nrm }

def sameO (x y : Option Authority) : Bool := x.map canonA == y.map canonA

def asBool : Cbor → D Bool
  | .bool b => pure b
  | _ => throw "expected bool"

def runCase (cat : Catalog) (c : Cbor) : D Bool := do
  let m ← asMap c
  let result := field m "result"
  match ← asText (← req m "op") with
  | "le" =>
    let want ← asBool (← req m "result")
    return authLe cat (← authority (← req m "a")) (← authority (← req m "b")) == want
  | "meet" =>
    let want ← result.mapM authority
    return sameO (authMeet cat (← authority (← req m "a")) (← authority (← req m "b"))) want
  | "normalize" =>
    let want ← result.mapM authority
    return sameO (authNorm cat (← authority (← req m "a"))) want
  | "within" =>
    let want ← asBool (← req m "result")
    return childWithinParent cat (← canonAuth (← req m "child")) (← canonAuth (← req m "parent"))
      (← subjSel (← req m "holder")) == want
  | op => throw s!"unknown operation {op}"

def items (b : ByteArray) : Except String (Array Cbor) := do
  let mut out := #[]
  let mut i := 0
  while i < b.size do
    let (v, j) ← (item b).run i
    if j ≤ i then throw "no progress"
    out := out.push v
    i := j
  return out

structure Tally where
  cases : Nat := 0
  mismatches : Nat := 0

def runFile (path : String) (t : Tally) : IO Tally := do
  let all ← IO.ofExcept (items (← IO.FS.readBinFile path))
  let some header := all[0]? | throw (IO.userError s!"{path}: empty")
  let cat ← IO.ofExcept (do catalogOf (← req (← asMap header) "catalog"))
  let mut t := t
  for c in all.extract 1 all.size do
    let ident := (do (← asMap c) |> fun m => req m "id").toOption.map Cbor.render |>.getD "?"
    t := { t with cases := t.cases + 1 }
    match runCase cat c with
    | .ok true => pure ()
    | .ok false =>
      t := { t with mismatches := t.mismatches + 1 }
      if t.mismatches ≤ 20 then IO.eprintln s!"{path}: case {ident}: model disagrees with the Kernel: {c.render}"
    | .error e =>
      t := { t with mismatches := t.mismatches + 1 }
      if t.mismatches ≤ 20 then IO.eprintln s!"{path}: case {ident}: {e}"
  return t

def main (args : List String) : IO UInt32 := do
  let (summary, files) := match args with
    | "--summary" :: s :: rest => (some s, rest)
    | rest => (none, rest)
  let mut t : Tally := {}
  for path in files do
    t ← runFile path t
  IO.println s!"lean-drt: {t.cases} cases, {t.mismatches} mismatches"
  if let some s := summary then
    IO.FS.writeFile s
      s!"\{\"lean_cases\": {t.cases}, \"lean_mismatches\": {t.mismatches}, \"model\": \"access-algebra\"}\n"
  return if t.mismatches == 0 && t.cases > 0 then 0 else 1
