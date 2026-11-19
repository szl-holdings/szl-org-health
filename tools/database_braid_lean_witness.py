#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the Lean kernel over a pinned corpus and record what it actually accepted.

For one clean git checkout of the Lean repository this tool, with no network:

1. runs the repository's default ``lake build``;
2. runs its own reviewed guard scripts (locked-set axiom guard, axiom check);
3. asks Lake to build every library module the default build does NOT reach,
   so a file nobody imports is still judged by the kernel, one way or the other;
4. loads every accepted module into one Lean program and reads, from the
   kernel's own records, the axioms each theorem depends on.

Every tracked ``.lean`` file gets exactly one status. A file the kernel
rejected is REJECTED, a file nobody checks is NOT_CHECKED_BY_POLICY, and
neither is ever counted as proved. ``sorry`` is detected as the kernel axiom
``sorryAx`` reached through any chain of lemmas, which a text search cannot do.

Limits, stated plainly. This is one elaboration by one toolchain on one
machine: it is not an independent second kernel, not a signature, and not a
review of what the theorems MEAN. A theorem with a clean axiom footprint can
still state something weaker than its name suggests. The corpus source is
never modified, nothing is promoted, and dependency libraries are used from
the local cache only: if that cache is absent the result is UNAVAILABLE
rather than a from-source build.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from fnmatch import fnmatchcase
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

try:
    from tools.database_braid_common import (
        REPOSITORY, SHA40, SHA64, checkout_root, closed, digest, git_blob_sha1,
        lean_code_only, natural, read_json, require, sha256_hex, write_exclusive,
    )
    from tools.database_braid_source_census import list_tree
    from tools.database_catalog_admission import InputError
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools.database_braid_common import (
        REPOSITORY, SHA40, SHA64, checkout_root, closed, digest, git_blob_sha1,
        lean_code_only, natural, read_json, require, sha256_hex, write_exclusive,
    )
    from tools.database_braid_source_census import list_tree
    from tools.database_catalog_admission import InputError

SCHEMA = "szl.database-braid-lean-witness/v1"
MODULE = re.compile(r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z")
DECL = re.compile(r"[^\x00-\x1f\x7f]{1,300}\Z")
TOOLCHAIN = re.compile(r"leanprover/lean4:v[0-9]+\.[0-9]+\.[0-9]+(?:-rc[0-9]+)?\Z")
GLOB = re.compile(r"[A-Za-z0-9_.*?/+@-]{1,200}\Z")
IMPORT = re.compile(r"^[ \t]*(?:public[ \t]+|private[ \t]+|meta[ \t]+)*import[ \t]+"
                    r"(?:all[ \t]+)?([A-Za-z_][A-Za-z0-9_'.]*)", re.M)
ACCEPTED_DEFAULT = "ACCEPTED_DEFAULT_BUILD"
ACCEPTED_REQUEST = "ACCEPTED_ON_REQUEST"
ACCEPTED_STANDALONE = "ACCEPTED_STANDALONE"
REJECTED = "REJECTED"
NOT_CHECKED = "NOT_CHECKED_BY_POLICY"
STATUSES = (ACCEPTED_DEFAULT, ACCEPTED_REQUEST, ACCEPTED_STANDALONE, REJECTED, NOT_CHECKED)
CLASS_SORRY = "sorry_tainted"
CLASS_NATIVE = "native_decide"
CLASS_AXIOM = "declared_axiom_dependent"
CLASS_CLEAN = "trust_base_only"
CLASSES = (CLASS_CLEAN, CLASS_SORRY, CLASS_AXIOM, CLASS_NATIVE)
SORRY_AXIOM = "sorryAx"
NATIVE_AXIOMS = ("Lean.ofReduceBool", "Lean.trustCompiler", "Lean.ofReduceNat")
NATIVE_MARK = "._native.native_decide."
MAX_FILES = 5000
MAX_WITNESS_BYTES = 8388608
MAX_LOG_BYTES = 67108864
_FALSE_FLAGS = ("independent_kernel_replay", "network_used", "sources_modified",
                "proofs_promoted", "meaning_of_statements_reviewed", "production_authorized")
_FIELDS = ("schema", "observed_at", "repository", "commit", "worktree_matches_commit",
           "toolchain", "manifest_sha256", "mathlib_revision", "steps", "default_build",
           "locked_guard", "axiom_check", "executables", "files", "file_totals", "modules",
           "theorem_totals", "declared_axioms", "sorry_sources", "carrier_theorems",
           "census", "state", "policy_section_sha256", "kernel_executed_by_this_run",
           *_FALSE_FLAGS)

# One JSON line per constant of every listed module, read from the kernel environment.
CENSUS_TEMPLATE = r'''import Lean
__IMPORTS__
open Lean Elab Command

namespace BraidCensus

def modules : Array Name := #[__MODULES__]

def kindOf : ConstantInfo → String
  | .axiomInfo _  => "axiom"
  | .defnInfo _   => "def"
  | .thmInfo _    => "theorem"
  | .opaqueInfo _ => "opaque"
  | .quotInfo _   => "quot"
  | .inductInfo _ => "inductive"
  | .ctorInfo _   => "constructor"
  | .recInfo _    => "recursor"

def directConsts (ci : ConstantInfo) : Array Name :=
  let t := ci.type.getUsedConstants
  match ci.value? (allowOpaque := true) with
  | some v => t ++ v.getUsedConstants
  | none   => t

abbrev M := StateT (NameMap (Array Name)) CommandElabM

/-- Declarations that mention `sorryAx` directly and are reachable from `c`. -/
partial def sorrySources (c : Name) : M (Array Name) := do
  if let some r := (← get).find? c then return r
  let axs ← collectAxioms c
  modify (·.insert c #[])
  if !axs.contains ``sorryAx then return #[]
  let env ← getEnv
  let some ci := env.find? c | return #[]
  let used := directConsts ci
  let mut acc : NameSet := {}
  if used.contains ``sorryAx then acc := acc.insert c
  for d in used do
    if d != ``sorryAx then
      for s in (← sorrySources d) do acc := acc.insert s
  let r := acc.toArray.qsort Name.lt
  modify (·.insert c r)
  return r

end BraidCensus

open BraidCensus in
elab "#braid_axiom_census" : command => do
  let env ← getEnv
  let names := env.header.moduleNames
  let mut memo : NameMap (Array Name) := {}
  let mut nMods := 0
  let mut nConsts := 0
  for i in [0:names.size] do
    let m := names[i]!
    if modules.contains m then
      nMods := nMods + 1
      let md := env.header.moduleData[i]!
      for n in md.constNames do
        let some ci := env.find? n | continue
        let axs ← collectAxioms n
        let (src, memo') ← (sorrySources n).run memo
        memo := memo'
        nConsts := nConsts + 1
        IO.println (Json.mkObj
          [ ("module", toString m), ("decl", toString n), ("kind", kindOf ci)
          , ("internal", n.isInternalDetail)
          , ("direct_sorry", (directConsts ci).contains ``sorryAx)
          , ("axioms", toJson (axs.map toString))
          , ("sorry_sources", toJson (src.map toString)) ]).compress
  IO.println (Json.mkObj [("census_end", true), ("modules", nMods), ("constants", nConsts)]).compress

#braid_axiom_census
'''


def validate_policy(section) -> dict:
    """Validate the ``lean`` section of the braid v2 policy."""
    closed(section, ("repository", "toolchain_pin", "trust_base", "source_dirs",
                     "default_roots", "executables", "library_roots", "standalone",
                     "not_checked", "locked_guard", "axiom_check", "carrier_theorems",
                     "min_dependency_oleans", "step_timeout_seconds"),
           "WITNESS_POLICY_FIELDS_INVALID")
    require(type(section["repository"]) is str and REPOSITORY.fullmatch(section["repository"])
            and type(section["toolchain_pin"]) is str and
            TOOLCHAIN.fullmatch(section["toolchain_pin"]), "WITNESS_POLICY_INVALID")
    base = section["trust_base"]
    require(type(base) is list and base == sorted(set(base)) and 0 < len(base) <= 8 and
            all(type(a) is str and MODULE.fullmatch(a) for a in base) and
            SORRY_AXIOM not in base, "WITNESS_TRUST_BASE_INVALID")
    dirs = section["source_dirs"]
    require(type(dirs) is list and 0 < len(dirs) <= 8 and dirs[0] == "." and
            all(type(d) is str and re.fullmatch(r"\.|[A-Za-z0-9_][A-Za-z0-9_/-]{0,80}", d)
                for d in dirs) and len(set(dirs)) == len(dirs), "WITNESS_POLICY_INVALID")
    for field in ("default_roots", "library_roots"):
        names = section[field]
        require(type(names) is list and len(names) <= 64 and names == sorted(set(names)) and
                all(type(n) is str and MODULE.fullmatch(n) for n in names),
                "WITNESS_POLICY_INVALID")
    require(len(section["default_roots"]) > 0 and len(section["library_roots"]) > 0,
            "WITNESS_POLICY_INVALID")
    executables = section["executables"]
    require(type(executables) is list and len(executables) <= 8, "WITNESS_POLICY_INVALID")
    for item in executables:
        closed(item, ("name", "root", "arguments"), "WITNESS_POLICY_INVALID")
        require(type(item["name"]) is str and re.fullmatch(r"[a-z][a-z0-9_]{1,30}", item["name"])
                and type(item["root"]) is str and MODULE.fullmatch(item["root"]) and
                item["root"] not in section["default_roots"] and
                type(item["arguments"]) is list and len(item["arguments"]) <= 4 and
                all(type(a) is str and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", a)
                    for a in item["arguments"]), "WITNESS_POLICY_INVALID")
    require(len({e["name"] for e in executables}) == len(executables) and
            len({e["root"] for e in executables}) == len(executables),
            "WITNESS_POLICY_INVALID")
    require(type(section["standalone"]) is list and len(section["standalone"]) <= 16 and
            all(type(g) is str and GLOB.fullmatch(g) for g in section["standalone"]),
            "WITNESS_POLICY_INVALID")
    rules = section["not_checked"]
    require(type(rules) is list and len(rules) <= 16, "WITNESS_POLICY_INVALID")
    for rule in rules:
        closed(rule, ("glob", "reason"), "WITNESS_POLICY_INVALID")
        require(type(rule["glob"]) is str and GLOB.fullmatch(rule["glob"]) and
                type(rule["reason"]) is str and re.fullmatch(r"[A-Z][A-Z_]{2,60}", rule["reason"]),
                "WITNESS_POLICY_INVALID")
    guard = closed(section["locked_guard"], ("path", "expected_allowed"),
                   "WITNESS_POLICY_INVALID")
    check = closed(section["axiom_check"], ("path",), "WITNESS_POLICY_INVALID")
    require(all(type(p) is str and p.endswith(".lean") and GLOB.fullmatch(p) and "*" not in p
                and "?" not in p and not p.startswith(("-", "/", ".")) and ".." not in p
                for p in (guard["path"], check["path"])), "WITNESS_POLICY_INVALID")
    natural(guard["expected_allowed"], "WITNESS_POLICY_INVALID", maximum=10000)
    carriers = section["carrier_theorems"]
    require(type(carriers) is list and len(carriers) <= 64, "WITNESS_POLICY_INVALID")
    seen = []
    for item in carriers:
        closed(item, ("decl", "role"), "WITNESS_POLICY_INVALID")
        require(type(item["decl"]) is str and MODULE.fullmatch(item["decl"]) and
                type(item["role"]) is str and re.fullmatch(r"[A-Z][A-Z0-9_]{2,60}", item["role"]),
                "WITNESS_POLICY_INVALID")
        seen.append(item["decl"])
    require(seen == sorted(set(seen)), "WITNESS_POLICY_INVALID")
    natural(section["min_dependency_oleans"], "WITNESS_POLICY_INVALID", maximum=10 ** 6)
    natural(section["step_timeout_seconds"], "WITNESS_POLICY_INVALID", maximum=21600)
    require(section["step_timeout_seconds"] >= 60, "WITNESS_POLICY_INVALID")
    return section


def module_name(path: str, source_dirs) -> str | None:
    """Module name of a tracked ``.lean`` path under the first matching source directory."""
    if not path.endswith(".lean"):
        return None
    stem = path[:-5]
    for directory in sorted((d for d in source_dirs if d != "."), key=len, reverse=True):
        if stem.startswith(directory + "/"):
            stem = stem[len(directory) + 1:]
            break
    name = stem.replace("/", ".")
    return name if MODULE.fullmatch(name) else None


def lean_imports(text: str) -> list:
    """Modules named by ``import`` lines, ignoring anything inside comments."""
    return IMPORT.findall(lean_code_only(text))


def import_closure(imports_of: dict, roots) -> set:
    """Workspace modules reachable from ``roots`` through ``imports_of``."""
    seen, stack = set(), [r for r in roots]
    while stack:
        name = stack.pop()
        if name in seen or name not in imports_of:
            continue
        seen.add(name)
        stack.extend(imports_of[name])
    return seen


def classify(axioms, trust_base) -> str:
    """Exactly one class per theorem; the most serious dependency wins."""
    names = set(axioms)
    if SORRY_AXIOM in names:
        return CLASS_SORRY
    if any(a in NATIVE_AXIOMS or NATIVE_MARK in a for a in names):
        return CLASS_NATIVE
    return CLASS_CLEAN if names <= set(trust_base) else CLASS_AXIOM


def census_program(modules) -> str:
    """Lean source that prints the axiom census for exactly ``modules``."""
    names = sorted(modules)
    require(len(names) > 0 and all(MODULE.fullmatch(n) for n in names), "WITNESS_MODULE_INVALID")
    return (CENSUS_TEMPLATE
            .replace("__IMPORTS__", "\n".join("import " + n for n in names))
            .replace("__MODULES__", ", ".join("`" + n for n in names)))


def parse_census(text: str, modules) -> list:
    """Strictly parse census output; requires the terminal marker and exact module set."""
    rows, end = [], None
    for line in text.splitlines():
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except ValueError:
            raise InputError("WITNESS_CENSUS_LINE_INVALID") from None
        if item.get("census_end") is True:
            end = item
            continue
        require(type(item) is dict and set(item) == {"module", "decl", "kind", "internal",
                                                     "direct_sorry", "axioms", "sorry_sources"}
                and type(item["module"]) is str and item["module"] in modules and
                type(item["decl"]) is str and DECL.fullmatch(item["decl"]) and
                item["kind"] in ("axiom", "def", "theorem", "opaque", "quot", "inductive",
                                 "constructor", "recursor") and
                type(item["internal"]) is bool and type(item["direct_sorry"]) is bool and
                all(type(item[f]) is list and all(type(a) is str and DECL.fullmatch(a)
                                                  for a in item[f])
                    for f in ("axioms", "sorry_sources")), "WITNESS_CENSUS_LINE_INVALID")
        rows.append(item)
    require(type(end) is dict and end.get("constants") == len(rows) and
            end.get("modules") == len(set(modules)), "WITNESS_CENSUS_INCOMPLETE")
    return rows


def census_digest(rows) -> str:
    """Order-independent identity of a census (rows sorted before hashing)."""
    return digest(sorted([r["module"], r["decl"], r["kind"], r["internal"], r["direct_sorry"],
                          sorted(r["axioms"]), sorted(r["sorry_sources"])] for r in rows))


def rollup(rows, trust_base, module_paths: dict) -> tuple:
    """Per-module theorem classes, declared-axiom load and sorry-source reach."""
    per, load, taints, sole = {}, {}, {}, {}
    axioms_declared, direct = [], {}
    for row in rows:
        entry = per.setdefault(row["module"], {c: 0 for c in CLASSES} | {
            "user_theorems": 0, "direct_sorry_declarations": 0, "declared_axioms": 0})
        if row["kind"] == "axiom":
            entry["declared_axioms"] += 1
            axioms_declared.append(row)
        if row["direct_sorry"]:
            entry["direct_sorry_declarations"] += 1
            direct[row["decl"]] = row["module"]
        if row["kind"] == "theorem" and not row["internal"]:
            kind = classify(row["axioms"], trust_base)
            entry["user_theorems"] += 1
            entry[kind] += 1
            for axiom in set(row["axioms"]) - set(trust_base) - {SORRY_AXIOM}:
                load[axiom] = load.get(axiom, 0) + 1
            if kind == CLASS_SORRY:
                for source in row["sorry_sources"]:
                    taints[source] = taints.get(source, 0) + 1
                if len(row["sorry_sources"]) == 1:
                    only = row["sorry_sources"][0]
                    sole[only] = sole.get(only, 0) + 1
    modules = [{"module": name, "path": module_paths.get(name), **per[name]}
               for name in sorted(per)]
    totals = {key: sum(m[key] for m in modules)
              for key in ("user_theorems", *CLASSES, "direct_sorry_declarations",
                          "declared_axioms")}
    declared = sorted(({"decl": r["decl"], "module": r["module"],
                        "native_decide_auxiliary": NATIVE_MARK in r["decl"],
                        "user_theorem_load": load.get(r["decl"], 0)}
                       for r in axioms_declared), key=lambda a: a["decl"])
    sources = sorted(({"decl": name, "module": direct[name], "taints": taints.get(name, 0),
                       "sole_blocker_for": sole.get(name, 0)} for name in direct),
                     key=lambda s: s["decl"])
    return modules, totals, declared, sources


def parse_log(text: str) -> tuple:
    """``(error_lines_by_path, sorry_declarations_by_path)`` from Lake/Lean output."""
    errors, sorries = {}, {}
    for line in text.splitlines():
        hit = re.match(r"error: (?:\./)?([^:\n]+\.lean)(?::\d+:\d+)?: ", line)
        if hit:
            errors[hit.group(1)] = errors.get(hit.group(1), 0) + 1
            continue
        hit = re.match(r"warning: (?:\./)?([^:\n]+\.lean):\d+:\d+: "
                       r"declaration uses [`']sorry[`']", line)
        if hit:
            sorries[hit.group(1)] = sorries.get(hit.group(1), 0) + 1
    return errors, sorries


def _runner(toolchain_bin: Path, home: str):
    """Subprocess runner with a minimal environment: no proxy, no tokens, fixed PATH."""
    env = {"PATH": f"{toolchain_bin}:/usr/bin:/bin", "HOME": home, "LANG": "C.UTF-8",
           "LC_ALL": "C.UTF-8", "NO_PROXY": "*", "GIT_TERMINAL_PROMPT": "0"}
    for name in ("ELAN_HOME",):
        if os.environ.get(name):
            env[name] = os.environ[name]

    def run(argv, cwd: Path, timeout: int) -> tuple:
        started = time.monotonic()
        try:
            proc = subprocess.run(argv, cwd=str(cwd), env=env, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, timeout=timeout, check=False)
            code, out = proc.returncode, proc.stdout[:MAX_LOG_BYTES]
        except subprocess.TimeoutExpired as exc:
            code, out = 124, (exc.stdout or b"")[:MAX_LOG_BYTES]
        except OSError:
            code, out = 127, b""
        return code, out, int(time.monotonic() - started)

    return run


def _git_clean(checkout: Path) -> bool:
    try:
        proc = subprocess.run(["git", "-C", str(checkout), "status", "--porcelain",
                               "--untracked-files=no"], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=120, check=False,
                              env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                                   "HOME": os.environ.get("HOME", "/"), "LC_ALL": "C",
                                   "GIT_OPTIONAL_LOCKS": "0"})
    except (OSError, subprocess.TimeoutExpired):
        raise InputError("WITNESS_GIT_UNAVAILABLE") from None
    require(proc.returncode == 0, "WITNESS_GIT_REFUSED")
    return proc.stdout.strip() == b""


def _oleans(root: Path) -> set:
    found = set()
    if root.is_dir():
        for path in root.rglob("*.olean"):
            if path.name.endswith((".server.olean", ".private.olean")):
                continue
            found.add(".".join(path.relative_to(root).with_suffix("").parts))
    return found


def observe(section, checkout: Path, *, toolchain_bin: Path, run=None, at=None,
            log_dir: Path | None = None) -> dict:
    """Execute the kernel over ``checkout`` and return the witness."""
    validate_policy(section)
    at = at or datetime.now(timezone.utc)
    commit, _shallow, tree = list_tree(checkout)
    require(_git_clean(checkout), "WITNESS_WORKTREE_DIFFERS_FROM_COMMIT")
    lean_files = sorted(path for mode, kind, _sha, _size, path in tree
                        if kind == "blob" and path.endswith(".lean"))
    require(0 < len(lean_files) <= MAX_FILES, "WITNESS_FILE_BUDGET_EXCEEDED")
    for mode, kind, sha, _size, path in tree:
        if kind == "blob" and path.endswith(".lean"):
            require(git_blob_sha1((checkout / path).read_bytes()) == sha,
                    "WITNESS_WORKTREE_DIFFERS_FROM_COMMIT")
    run = run or _runner(toolchain_bin, os.environ.get("HOME", "/"))
    timeout = section["step_timeout_seconds"]
    steps, logs = [], {}

    def step(name, argv, *, cwd=checkout):
        code, out, seconds = run(argv, cwd, timeout)
        steps.append({"name": name, "exit_code": code, "output_sha256": sha256_hex(out),
                      "seconds": seconds})
        logs[name] = out.decode("utf-8", "replace")
        if log_dir is not None:
            (log_dir / (name + ".log")).write_bytes(out)
        return code, logs[name]

    pin_file = checkout / "lean-toolchain"
    pin = pin_file.read_text(encoding="utf-8").strip() if pin_file.is_file() else None
    code_lean, lean_line = step("lean_version", ["lean", "--version"])
    code_lake, lake_line = step("lake_version", ["lake", "--version"])
    toolchain = {"pin_required": section["toolchain_pin"], "pin_in_checkout": pin,
                 "lean_version": lean_line.strip()[:200] if code_lean == 0 else None,
                 "lake_version": lake_line.strip()[:200] if code_lake == 0 else None}
    if code_lean != 0 or code_lake != 0 or pin != section["toolchain_pin"]:
        return _finish(section, commit, at, steps=steps, toolchain=toolchain, manifest=None,
                       mathlib=None, default_build=None, locked=None, axiom_check=None,
                       executables=[], files=[], rows=None, census_state="UNAVAILABLE",
                       census_reason="TOOLCHAIN_UNAVAILABLE_OR_PIN_MISMATCH", module_paths={},
                       state="UNAVAILABLE")
    manifest_file = checkout / "lake-manifest.json"
    manifest_sha, mathlib = None, None
    if manifest_file.is_file():
        raw = manifest_file.read_bytes()
        manifest_sha = sha256_hex(raw)
        try:
            for package in json.loads(raw).get("packages", []):
                if package.get("name") == "mathlib" and SHA40.fullmatch(str(package.get("rev"))):
                    mathlib = package["rev"]
        except (ValueError, AttributeError):
            mathlib = None
    cached = sum(1 for _ in (checkout / ".lake/packages").rglob("*.olean")) if (
        checkout / ".lake/packages").is_dir() else 0
    if cached < section["min_dependency_oleans"]:
        # Never fall back to compiling the dependency libraries from source.
        return _finish(section, commit, at, steps=steps, toolchain=toolchain,
                       manifest=manifest_sha, mathlib=mathlib, default_build=None, locked=None,
                       axiom_check=None, executables=[], files=[], rows=None,
                       census_state="UNAVAILABLE", census_reason="DEPENDENCY_CACHE_ABSENT",
                       module_paths={}, state="UNAVAILABLE")

    dirs = section["source_dirs"]
    path_of, imports_of = {}, {}
    for path in lean_files:
        name = module_name(path, dirs)
        if name is not None and name not in path_of:
            path_of[name] = path
            imports_of[name] = lean_imports((checkout / path).read_text("utf-8", "replace"))
    default_set = import_closure(imports_of, section["default_roots"])

    build_code, build_log = step("default_build", ["lake", "build"])
    library = checkout / ".lake/build/lib/lean"
    after_default = _oleans(library)
    default_ok = build_code == 0 and default_set <= after_default
    default_build = {"exit_code": build_code, "state": "PASSED" if default_ok else "FAILED",
                     "modules_in_import_closure": len(default_set),
                     "closure_modules_with_olean": len(default_set & after_default)}

    guard_code, guard_log = step("locked_guard", ["lake", "env", "lean",
                                                  "./" + section["locked_guard"]["path"]])
    allowed = guard_log.count('"allowed":true')
    refused = guard_log.count('"allowed":false')
    expected = section["locked_guard"]["expected_allowed"]
    locked = {"exit_code": guard_code, "allowed": allowed, "refused": refused,
              "expected": expected,
              "state": "PASSED" if guard_code == 0 and refused == 0 and allowed == expected
              else "FAILED"}
    check_code, check_log = step("axiom_check", ["lake", "env", "lean",
                                                 "./" + section["axiom_check"]["path"]])
    mentions = check_log.count(SORRY_AXIOM)
    axiom_check = {"exit_code": check_code, "sorry_axiom_mentions": mentions,
                   "state": "PASSED" if check_code == 0 and mentions == 0 else "FAILED"}
    # Executables are not default targets: building and running them is its own request.
    executables = []
    for exe in section["executables"]:
        exe_code, _out = step("exe_" + exe["name"],
                              ["lake", "exe", exe["name"], *exe["arguments"]])
        executables.append({"name": exe["name"], "root": exe["root"], "exit_code": exe_code,
                            "state": "PASSED" if exe_code == 0 else "FAILED"})
    exe_set = import_closure(imports_of, [e["root"] for e in section["executables"]]) - default_set
    after_exe = _oleans(library)

    def skipped(path):
        for rule in section["not_checked"]:
            if fnmatchcase(path, rule["glob"]):
                return rule["reason"]
        return None

    standalone = [p for p in lean_files if skipped(p) is None and
                  any(fnmatchcase(p, g) for g in section["standalone"])]
    requested = sorted(name for name, path in path_of.items()
                       if name not in default_set and name not in exe_set and
                       skipped(path) is None and
                       path not in standalone and
                       any(name == r or name.startswith(r + ".") for r in section["library_roots"]))
    request_log = ""
    if requested:
        _code, request_log = step("on_request_build",
                                  ["lake", "build", *("+" + name for name in requested)])
    after_request = _oleans(library)
    errors, sorries = parse_log(build_log + "\n" + request_log)

    files = []
    for path in lean_files:
        name = module_name(path, dirs)
        reason = skipped(path)
        row = {"path": path, "module": name if path_of.get(name) == path else None,
               "status": None, "reason": None,
               "elaborator_sorry_declarations": sorries.get(path, 0),
               "error_lines": errors.get(path, 0)}
        if reason is not None:
            row.update(status=NOT_CHECKED, reason=reason)
        elif path in standalone:
            code, out = step("standalone_" + sha256_hex(path.encode())[:12],
                             ["lake", "env", "lean", "./" + path])
            alone_errors, alone_sorries = parse_log(out)
            row.update(status=ACCEPTED_STANDALONE if code == 0 else REJECTED,
                       reason=None if code == 0 else "ELABORATION_FAILED",
                       elaborator_sorry_declarations=alone_sorries.get(path, 0),
                       error_lines=alone_errors.get(path, 0))
        elif row["module"] is None:
            row.update(status=NOT_CHECKED, reason="NOT_A_WORKSPACE_MODULE")
        elif name in default_set:
            ok = name in after_default and build_code == 0
            row.update(status=ACCEPTED_DEFAULT if ok else REJECTED,
                       reason=None if ok else "DEFAULT_BUILD_FAILED")
        elif name in exe_set:
            ok = name in after_exe
            row.update(status=ACCEPTED_REQUEST if ok else REJECTED,
                       reason=None if ok else "EXECUTABLE_BUILD_FAILED")
        elif name in requested:
            ok = name in after_request
            row.update(status=ACCEPTED_REQUEST if ok else REJECTED,
                       reason=None if ok else "ELABORATION_FAILED")
        else:
            row.update(status=NOT_CHECKED, reason="OUTSIDE_LIBRARY_ROOTS")
        files.append(row)

    accepted = sorted(r["module"] for r in files
                      if r["status"] in (ACCEPTED_DEFAULT, ACCEPTED_REQUEST) and
                      r["module"] not in {e["root"] for e in section["executables"]})
    rows, census_state, census_reason = None, "UNAVAILABLE", "NO_ACCEPTED_MODULES"
    if accepted:
        with tempfile.TemporaryDirectory(prefix="braid-lean-") as scratch:
            program = Path(scratch) / "BraidAxiomCensus.lean"
            program.write_text(census_program(accepted), encoding="utf-8")
            code, out = step("axiom_census", ["lake", "env", "lean", str(program)])
        if code == 0:
            rows = parse_census(out, set(accepted))
            census_state, census_reason = "EXECUTED", None
        else:
            census_reason = "CENSUS_PROGRAM_FAILED"
    healthy = (default_ok and locked["state"] == "PASSED" and axiom_check["state"] == "PASSED"
               and all(e["state"] == "PASSED" for e in executables)
               and census_state == "EXECUTED")
    return _finish(section, commit, at, steps=steps, toolchain=toolchain, manifest=manifest_sha,
                   mathlib=mathlib, default_build=default_build, locked=locked,
                   axiom_check=axiom_check, executables=executables, files=files, rows=rows,
                   census_state=census_state,
                   census_reason=census_reason, module_paths=path_of,
                   state="KERNEL_EXECUTED" if healthy else "HOLD")


def _finish(section, commit, at, *, steps, toolchain, manifest, mathlib, default_build, locked,
            axiom_check, executables, files, rows, census_state, census_reason, module_paths,
            state) -> dict:
    if rows is None:
        modules, totals, declared, sources, carriers = [], None, [], [], []
        census = {"state": census_state, "reason": census_reason, "constants": None,
                  "modules": None, "rows_sha256": None}
    else:
        modules, totals, declared, sources = rollup(rows, section["trust_base"], module_paths)
        by_decl = {r["decl"]: r for r in rows}
        carriers = []
        for item in section["carrier_theorems"]:
            row = by_decl.get(item["decl"])
            found = row is not None and row["kind"] == "theorem"
            carriers.append({"decl": item["decl"], "role": item["role"], "found": found,
                             "axioms": sorted(row["axioms"]) if found else None,
                             "class": classify(row["axioms"], section["trust_base"])
                             if found else None})
        census = {"state": census_state, "reason": None, "constants": len(rows),
                  "modules": len({r["module"] for r in rows}), "rows_sha256": census_digest(rows)}
    witness = {
        "schema": SCHEMA, "observed_at": at.isoformat(), "repository": section["repository"],
        "commit": commit, "worktree_matches_commit": True, "toolchain": toolchain,
        "manifest_sha256": manifest, "mathlib_revision": mathlib, "steps": steps,
        "default_build": default_build, "locked_guard": locked, "axiom_check": axiom_check,
        "executables": executables, "files": files,
        "file_totals": {s: sum(f["status"] == s for f in files) for s in STATUSES},
        "modules": modules, "theorem_totals": totals, "declared_axioms": declared,
        "sorry_sources": sources, "carrier_theorems": carriers, "census": census,
        "state": state, "policy_section_sha256": digest(section),
        "kernel_executed_by_this_run": state != "UNAVAILABLE",
    }
    witness.update({flag: False for flag in _FALSE_FLAGS})
    validate_witness(witness, section)
    return witness


def validate_witness(value, section) -> bool:
    """Closed-schema and internal-consistency check of a witness."""
    validate_policy(section)
    closed(value, _FIELDS, "WITNESS_FIELDS_INVALID")
    require(value["schema"] == SCHEMA and value["repository"] == section["repository"] and
            type(value["commit"]) is str and SHA40.fullmatch(value["commit"]) and
            value["worktree_matches_commit"] is True and
            value["policy_section_sha256"] == digest(section), "WITNESS_BINDING_INVALID")
    require(all(value[flag] is False for flag in _FALSE_FLAGS), "WITNESS_FALSE_AUTHORITY_CLAIM")
    require(value["state"] in ("KERNEL_EXECUTED", "HOLD", "UNAVAILABLE") and
            value["kernel_executed_by_this_run"] is (value["state"] != "UNAVAILABLE"),
            "WITNESS_STATE_INVALID")
    require(type(value["steps"]) is list and len(value["steps"]) <= 64, "WITNESS_FIELDS_INVALID")
    for item in value["steps"]:
        closed(item, ("name", "exit_code", "output_sha256", "seconds"), "WITNESS_FIELDS_INVALID")
        require(type(item["name"]) is str and re.fullmatch(r"[a-z][a-z0-9_]{2,40}", item["name"])
                and type(item["exit_code"]) is int and type(item["output_sha256"]) is str and
                SHA64.fullmatch(item["output_sha256"]), "WITNESS_FIELDS_INVALID")
        natural(item["seconds"], "WITNESS_FIELDS_INVALID", maximum=10 ** 6)
    files = value["files"]
    require(type(files) is list and len(files) <= MAX_FILES, "WITNESS_FIELDS_INVALID")
    paths = []
    for row in files:
        closed(row, ("path", "module", "status", "reason", "elaborator_sorry_declarations",
                     "error_lines"), "WITNESS_FILE_FIELDS_INVALID")
        require(type(row["path"]) is str and row["path"].endswith(".lean") and
                row["status"] in STATUSES and
                (row["module"] is None or (type(row["module"]) is str and
                                           MODULE.fullmatch(row["module"]))) and
                (row["reason"] is None or (type(row["reason"]) is str and
                                           re.fullmatch(r"[A-Z][A-Z_]{2,60}", row["reason"]))),
                "WITNESS_FILE_FIELDS_INVALID")
        natural(row["elaborator_sorry_declarations"], "WITNESS_FILE_FIELDS_INVALID")
        natural(row["error_lines"], "WITNESS_FILE_FIELDS_INVALID")
        # A status that is not an acceptance must carry its reason; an acceptance must not.
        require((row["reason"] is None) == row["status"].startswith("ACCEPTED"),
                "WITNESS_FILE_REASON_INVALID")
        paths.append(row["path"])
    require(paths == sorted(set(paths)), "WITNESS_FILE_ORDER_OR_DUPLICATE")
    totals = closed(value["file_totals"], STATUSES, "WITNESS_FIELDS_INVALID")
    require(all(totals[s] == sum(f["status"] == s for f in files) for s in STATUSES),
            "WITNESS_FILE_TOTALS_DRIFT")
    census = closed(value["census"], ("state", "reason", "constants", "modules", "rows_sha256"),
                    "WITNESS_FIELDS_INVALID")
    require(census["state"] in ("EXECUTED", "UNAVAILABLE"), "WITNESS_FIELDS_INVALID")
    modules = value["modules"]
    require(type(modules) is list, "WITNESS_FIELDS_INVALID")
    if census["state"] == "UNAVAILABLE":
        require(value["theorem_totals"] is None and modules == [] and
                value["declared_axioms"] == [] and value["sorry_sources"] == [] and
                value["carrier_theorems"] == [] and census["rows_sha256"] is None and
                census["constants"] is None and value["state"] != "KERNEL_EXECUTED",
                "WITNESS_UNAVAILABLE_NOT_UNKNOWN")
        return True
    require(type(census["rows_sha256"]) is str and SHA64.fullmatch(census["rows_sha256"]),
            "WITNESS_FIELDS_INVALID")
    natural(census["constants"], "WITNESS_FIELDS_INVALID")
    keys = ("user_theorems", *CLASSES, "direct_sorry_declarations", "declared_axioms")
    accepted = {f["module"] for f in files
                if f["status"] in (ACCEPTED_DEFAULT, ACCEPTED_REQUEST) and f["module"]}
    require(type(value["executables"]) is list and
            [e.get("name") if type(e) is dict else None for e in value["executables"]] in
            ([], [e["name"] for e in section["executables"]]), "WITNESS_EXECUTABLES_INVALID")
    names = []
    for row in modules:
        closed(row, ("module", "path", *keys), "WITNESS_MODULE_FIELDS_INVALID")
        require(type(row["module"]) is str and row["module"] in accepted,
                "WITNESS_MODULE_NOT_ACCEPTED")
        for key in keys:
            natural(row[key], "WITNESS_MODULE_FIELDS_INVALID")
        # Every observed theorem falls in exactly one class.
        require(row["user_theorems"] == sum(row[c] for c in CLASSES),
                "WITNESS_THEOREM_PARTITION_BROKEN")
        names.append(row["module"])
    require(names == sorted(set(names)), "WITNESS_MODULE_ORDER_OR_DUPLICATE")
    sums = closed(value["theorem_totals"], keys, "WITNESS_FIELDS_INVALID")
    require(all(sums[k] == sum(m[k] for m in modules) for k in keys),
            "WITNESS_THEOREM_TOTALS_DRIFT")
    declared = value["declared_axioms"]
    require(type(declared) is list and len(declared) == sums["declared_axioms"] and
            all(type(a) is dict and set(a) == {"decl", "module", "native_decide_auxiliary",
                                               "user_theorem_load"} for a in declared) and
            [a["decl"] for a in declared] == sorted({a["decl"] for a in declared}),
            "WITNESS_AXIOM_LIST_INVALID")
    sources = value["sorry_sources"]
    require(type(sources) is list and len(sources) == sums["direct_sorry_declarations"] and
            all(type(s) is dict and set(s) == {"decl", "module", "taints", "sole_blocker_for"}
                for s in sources) and
            [s["decl"] for s in sources] == sorted({s["decl"] for s in sources}),
            "WITNESS_SORRY_SOURCES_INVALID")
    carriers = value["carrier_theorems"]
    require(type(carriers) is list and
            [c.get("decl") if type(c) is dict else None for c in carriers] ==
            [c["decl"] for c in section["carrier_theorems"]], "WITNESS_CARRIERS_INVALID")
    for item in carriers:
        closed(item, ("decl", "role", "found", "axioms", "class"), "WITNESS_CARRIERS_INVALID")
        require(type(item["found"]) is bool and
                (item["class"] in CLASSES and type(item["axioms"]) is list
                 and item["class"] == classify(item["axioms"], section["trust_base"])
                 if item["found"] else item["class"] is None and item["axioms"] is None),
                "WITNESS_CARRIERS_INVALID")
    if value["state"] == "KERNEL_EXECUTED":
        require(type(value["default_build"]) is dict and
                value["default_build"].get("state") == "PASSED" and
                type(value["locked_guard"]) is dict and
                value["locked_guard"].get("state") == "PASSED" and
                value["locked_guard"].get("allowed") == section["locked_guard"]["expected_allowed"]
                and value["locked_guard"].get("refused") == 0 and
                type(value["axiom_check"]) is dict and
                value["axiom_check"].get("state") == "PASSED" and
                len(value["executables"]) == len(section["executables"]) and
                all(e.get("state") == "PASSED" for e in value["executables"]) and
                type(value["toolchain"]) is dict and
                value["toolchain"].get("pin_in_checkout") == section["toolchain_pin"],
                "WITNESS_STATE_DRIFT")
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(description="Lean kernel witness for one clean checkout")
    ap.add_argument("--policy", type=Path, required=True)
    ap.add_argument("--lean-checkout", type=Path, required=True)
    ap.add_argument("--toolchain-bin", type=Path, required=True,
                    help="directory holding the lake and lean executables")
    ap.add_argument("--log-dir", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        policy, _ = read_json(args.policy, max_bytes=1048576)
        require(type(policy) is dict and "lean" in policy, "WITNESS_POLICY_FIELDS_INVALID")
        require(args.toolchain_bin.is_absolute() and (args.toolchain_bin / "lake").exists() and
                (args.toolchain_bin / "lean").exists(), "WITNESS_TOOLCHAIN_UNAVAILABLE")
        if args.log_dir is not None:
            require(args.log_dir.is_dir() and
                    not args.log_dir.resolve().is_relative_to(checkout_root()),
                    "WITNESS_LOG_DIRECTORY_DENIED")
        witness = observe(policy["lean"], args.lean_checkout, toolchain_bin=args.toolchain_bin,
                          log_dir=args.log_dir)
        write_exclusive(args.output, witness, max_bytes=MAX_WITNESS_BYTES,
                        checkout=checkout_root())
        print(json.dumps({"state": witness["state"], "file_totals": witness["file_totals"],
                          "theorem_totals": witness["theorem_totals"],
                          "locked_guard": (witness["locked_guard"] or {}).get("state"),
                          "proofs_promoted": False, "production_authorized": False}))
        return 0 if witness["state"] == "KERNEL_EXECUTED" else 2
    except InputError as exc:
        code = exc.code
    except Exception:
        code = "WITNESS_UNAVAILABLE"
    print(json.dumps({"state": "UNAVAILABLE", "code": code, "proofs_promoted": False,
                      "production_authorized": False}))
    return 3


if __name__ == "__main__":
    sys.exit(main())
