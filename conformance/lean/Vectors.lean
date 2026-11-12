import Decode
import Lean.Data.Json

/-!
Differential runner: evaluates the model on the `algebra.child_within_parent` cases of the Kernel
vector files given on the command line.
-/

open Access Lean

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
