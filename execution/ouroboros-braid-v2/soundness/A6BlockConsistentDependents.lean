-- SPDX-License-Identifier: Apache-2.0
import Lutar
open Lean Elab Command

/-- Memoized: does constant `n` (transitively) reference `target`? Only constants
    from modules under the `Lutar` root are expanded, since Lean core / Mathlib
    modules cannot reference a Lutar declaration. -/
partial def dependsOn (env : Environment) (target : Name) (n : Name) :
    StateM (Std.HashMap Name Bool) Bool := do
  if n == target then return true
  if let some b := (← get)[n]? then return b
  modify (·.insert n false)
  let inLutar : Bool := match env.getModuleIdxFor? n with
    | some idx => (env.allImportedModuleNames[idx.toNat]!).getRoot == `Lutar
    | none => true
  if !inLutar then return false
  let some ci := env.find? n | return false
  let mut r := false
  for m in ci.getUsedConstantsAsSet.toList do
    if ← dependsOn env target m then
      r := true
      break
  modify (·.insert n r)
  return r

run_cmd do
  let env ← getEnv
  let target := `Lutar.Wave4.BlockConsistency.A6'_block_consistent
  unless env.contains target do throwError "axiom not found"
  let mut st : Std.HashMap Name Bool := {}
  let mut hits : Array (Name × Name) := #[]
  let mut scanned := 0
  for (n, _) in env.constants.toList do
    let some idx := env.getModuleIdxFor? n | continue
    let mod := env.allImportedModuleNames[idx.toNat]!
    unless mod.getRoot == `Lutar do continue
    if n == target then continue
    scanned := scanned + 1
    let (b, st') := (dependsOn env target n).run st
    st := st'
    if b then hits := hits.push (n, mod)
  logInfo m!"scanned {scanned} Lutar-module constants; dependents of {target}: {hits.size}"
  for (n, mod) in hits do
    logInfo m!"DEPENDENT {n}  (module {mod})"
