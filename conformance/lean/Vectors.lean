import AccessAlgebra
import Lean.Data.Json

/-!
Differential runner: evaluates the model on the `algebra.child_within_parent` cases of the Kernel
vector files given on the command line.
-/

open Access Lean

inductive Cbor where
  | uint (n : Nat)
  | nint (n : Nat)
  | bytes (b : ByteArray)
  | text (s : String)
  | arr (xs : Array Cbor)
  | map (kvs : Array (Cbor × Cbor))
  | bool (b : Bool)
  deriving Inhabited

partial def Cbor.render : Cbor → String
  | .uint n => s!"u{n}"
  | .nint n => s!"n{n}"
  | .bytes b => "h" ++ String.join (b.toList.map fun x => String.ofList (Nat.toDigits 16 x.toNat))
  | .text s => s!"t{s.quote}"
  | .arr xs => "[" ++ ",".intercalate (xs.toList.map render) ++ "]"
  | .map kvs => "{" ++ ",".intercalate (kvs.toList.map fun (k, v) => render k ++ ":" ++ render v) ++ "}"
  | .bool b => s!"b{b}"

def hexVal (c : Char) : Option Nat :=
  if '0' ≤ c ∧ c ≤ '9' then some (c.toNat - '0'.toNat)
  else if 'a' ≤ c ∧ c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
  else none

def unhex (s : String) : Except String ByteArray := do
  let cs := s.toList.toArray
  if cs.size % 2 ≠ 0 then throw "odd hex length"
  let mut out := ByteArray.empty
  for i in [0:cs.size / 2] do
    match hexVal cs[2 * i]!, hexVal cs[2 * i + 1]! with
    | some h, some l => out := out.push (UInt8.ofNat (h * 16 + l))
    | _, _ => throw "bad hex digit"
  return out

abbrev Parser := StateT Nat (Except String)

def byte (b : ByteArray) : Parser Nat := do
  let i ← get
  if h : i < b.size then
    set (i + 1)
    return b[i].toNat
  else throw "truncated"

def argument (b : ByteArray) (info : Nat) : Parser Nat := do
  if info < 24 then return info
  let n ← match info with
    | 24 => pure 1
    | 25 => pure 2
    | 26 => pure 4
    | 27 => pure 8
    | _ => throw "unsupported length"
  let mut v := 0
  for _ in [0:n] do
    v := v * 256 + (← byte b)
  return v

partial def item (b : ByteArray) : Parser Cbor := do
  let ib ← byte b
  let major := ib / 32
  let info := ib % 32
  match major with
  | 0 => return .uint (← argument b info)
  | 1 => return .nint (← argument b info)
  | 2 =>
    let n ← argument b info
    let i ← get
    if i + n > b.size then throw "truncated"
    set (i + n)
    return .bytes (b.extract i (i + n))
  | 3 =>
    let n ← argument b info
    let i ← get
    if i + n > b.size then throw "truncated"
    set (i + n)
    match String.fromUTF8? (b.extract i (i + n)) with
    | some s => return .text s
    | none => throw "bad utf-8"
  | 4 =>
    let n ← argument b info
    let mut xs := #[]
    for _ in [0:n] do
      xs := xs.push (← item b)
    return .arr xs
  | 5 =>
    let n ← argument b info
    let mut kvs := #[]
    for _ in [0:n] do
      let k ← item b
      let v ← item b
      kvs := kvs.push (k, v)
    return .map kvs
  | 7 =>
    match info with
    | 20 => return .bool false
    | 21 => return .bool true
    | _ => throw "unsupported simple value"
  | _ => throw "unsupported major type"

def decode (b : ByteArray) : Except String Cbor := do
  let (v, i) ← (item b).run 0
  if i ≠ b.size then throw "trailing bytes"
  return v

abbrev D := Except String

def field (kvs : Array (Cbor × Cbor)) (k : String) : Option Cbor :=
  (kvs.find? fun (key, _) => match key with | .text s => s == k | _ => false).map (·.2)

def asMap : Cbor → D (Array (Cbor × Cbor))
  | .map kvs => pure kvs
  | _ => throw "expected map"

def req (kvs : Array (Cbor × Cbor)) (k : String) : D Cbor :=
  match field kvs k with
  | some v => pure v
  | none => throw s!"missing {k}"

def asText : Cbor → D String
  | .text s => pure s
  | _ => throw "expected text"

def asNat : Cbor → D Nat
  | .uint n => pure n
  | _ => throw "expected uint"

def asInt : Cbor → D Int
  | .uint n => pure n
  | .nint n => pure (-1 - (n : Int))
  | _ => throw "expected int"

def asArr : Cbor → D (List Cbor)
  | .arr xs => pure xs.toList
  | _ => throw "expected array"

def opt {α : Type} (kvs : Array (Cbor × Cbor)) (k : String) (f : Cbor → D α) : D (Option α) :=
  match field kvs k with
  | some v => some <$> f v
  | none => pure none

def single (c : Cbor) : D (String × Cbor) := do
  let kvs ← asMap c
  if h : kvs.size = 1 then
    return (← asText kvs[0].1, kvs[0].2)
  else throw "expected a one-key map"

def eqVal : Cbor → D EqVal
  | .text s => pure (.text s)
  | c@(.bytes _) => pure (.bytes c.render)
  | .bool b => pure (.bool b)
  | c => .int <$> asInt c

def window (c : Cbor) : D Window := do
  match ← asArr c with
  | [a, b] => return ⟨← asNat a, ← asNat b⟩
  | _ => throw "expected a time window"

def actionRef (c : Cbor) : D ActionRef := do
  let m ← asMap c
  return ⟨← asText (← req m "namespace"), ← asText (← req m "name"), ← asNat (← req m "major"),
    (← req m "schema").render⟩

def resourceRef (c : Cbor) : D ResourceRef := do
  let m ← asMap c
  return ⟨← asText (← req m "namespace"), ← (← asArr (← req m "path")).mapM asText,
    ← asNat (← req m "incarnation")⟩

def resSel (c : Cbor) : D ResSel := do
  let m ← asMap c
  match field m "exact" with
  | some r => return .exact (← resourceRef r)
  | none =>
    let attrs ← match field m "where" with
      | some w => (← asMap w).toList.mapM fun (k, v) => return (← asText k, ← eqVal v)
      | none => pure []
    return .struct ⟨← asText (← req m "namespace"),
      ← (← opt m "prefix" asArr).getD [] |>.mapM asText, ← opt m "type" asText, attrs⟩

def conjunct (c : Cbor) : D Conjunct := do
  let m ← asMap c
  return ⟨← asText (← req m "claim_class"), ← opt m "value" eqVal⟩

def subjSel : Cbor → D SubjSel
  | .text "public" => pure .pub
  | c => do
    let (k, v) ← single c
    match k with
    | "party" => return .party v.render
    | "pred" => return .pred (← (← asArr v).mapM conjunct)
    | "foreign" =>
      let m ← asMap v
      return .foreign (← req m "domain").render (← asText (← req m "authority_class"))
    | _ => throw s!"unknown subject selector {k}"

def purposeRef (c : Cbor) : D Purpose := do
  let (k, v) ← single c
  match k with
  | "code" => return .code (← asText v)
  | "work" => return .work v.render
  | "aim" => return .aim v.render
  | _ => throw s!"unknown purpose {k}"

def bound (c : Cbor) : D Bound := do
  let (k, v) ← single c
  match k with
  | "enum" => return .enum (← (← asArr v).mapM asText)
  | "eq" => return .eq (← eqVal v)
  | "flag" => match v with
    | .bool b => return .flag b
    | _ => throw "expected bool"
  | "range" =>
    let m ← asMap v
    return .range ⟨← opt m "min" asInt, ← opt m "max" asInt, ← asText (← req m "unit")⟩
  | "count_max" => return .countMax (← asNat v)
  | "interval" => return .interval (← window v)
  | "resource" => return .resource (← resSel v)
  | "subject" => return .subject (← subjSel v)
  | "purpose" => return .purpose (← (← asArr v).mapM purposeRef)
  | _ => throw s!"unknown bound {k}"

def actionSet (c : Cbor) : D ActionSet := do
  let m ← asMap c
  let exact ← (← opt m "exact" asArr).getD [] |>.mapM actionRef
  let prefixes ← (← opt m "prefix" asArr).getD [] |>.mapM fun p => do
    let pm ← asMap p
    return (⟨← asText (← req pm "namespace"), (← req pm "catalog").render⟩ : Prefix)
  return ⟨exact, prefixes⟩

def authority (c : Cbor) : D Authority := do
  let m ← asMap c
  let params ← match field m "params" with
    | some p => (← asMap p).toList.mapM fun (k, v) => return (← asText k, ← bound v)
    | none => pure []
  return ⟨← actionSet (← req m "actions"), ← resSel (← req m "resource"), params,
    ← opt m "recipient" subjSel, ← opt m "purpose" fun v => do (← asArr v).mapM purposeRef⟩

def whileCond (c : Cbor) : D WhileCond := do
  let (k, v) ← single c
  match k with
  | "instance_alive" => return .instanceAlive v.render
  | "claim_held" =>
    let m ← asMap v
    return .claimHeld (← asText (← req m "class")) (← subjSel (← req m "subject"))
      (← req m "acceptance").render
  | _ => throw s!"unknown while-condition {k}"

def canonAuth (c : Cbor) : D CanonAuth := do
  let m ← asMap c
  let cs ← asMap (← req m "constraints")
  let dl ← asMap (← req m "delegation")
  return {
    authority := ← authority (← req m "authority")
    constraints := ⟨← window (← req cs "validity"),
      ← (← opt cs "while" asArr).getD [] |>.mapM whileCond⟩
    delegation := ⟨(← opt dl "depth" asNat).getD 0, ← opt dl "downstream_holder_class" subjSel⟩
    requirements := (← asArr (← req m "requirements")).map Cbor.render }

def emptyCatalog : Catalog := ⟨[], [], [], fun a b => a == b⟩

def fromHex {α : Type} (f : Cbor → D α) (j : Json) (k : String) : D α := do
  let s ← j.getObjValAs? String k
  f (← decode (← unhex s))

def runCase (j : Json) : D Bool := do
  let child ← fromHex canonAuth j "child"
  let parent ← fromHex canonAuth j "parent"
  let holder ← fromHex subjSel j "holder"
  let want ← j.getObjValAs? Bool "within"
  return childWithinParent emptyCatalog child parent holder == want

def main (args : List String) : IO UInt32 := do
  let mut pass := 0
  let mut fail := 0
  for path in args do
    let j ← IO.ofExcept (Json.parse (← IO.FS.readFile path))
    let cases := (j.getObjValAs? (Array Json) "cases").toOption.getD #[]
    for c in cases do
      if (c.getObjValAs? String "operation").toOption != some "algebra.child_within_parent" then
        continue
      let id := (c.getObjValAs? String "id").toOption.getD "?"
      match runCase c with
      | .ok true => pass := pass + 1
      | .ok false =>
        fail := fail + 1
        IO.eprintln s!"{path}: {id}: model disagrees with the vector"
      | .error e =>
        fail := fail + 1
        IO.eprintln s!"{path}: {id}: {e}"
  IO.println s!"child_within_parent: {pass} agree, {fail} disagree"
  return if fail == 0 && pass > 0 then 0 else 1
