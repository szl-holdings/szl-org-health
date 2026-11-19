#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the Lean kernel over a fresh export of one commit and record what it accepted.

For the HEAD commit of one Lean checkout this tool:

1. writes the commit's committed regular files, read from the object store,
   into a new empty temporary directory, so no untracked, ignored or earlier
   build file of the checkout can stand in for a committed source. The
   project's ``.lake/build`` does not exist when the first build starts;
2. links that export's ``.lake/packages`` to an existing dependency cache
   (never copied) and records each manifest revision next to the revision
   actually checked out in the cache. A mismatch is UNAVAILABLE, not a build;
3. in the export, runs the repository's default ``lake build``, its own
   reviewed guard scripts (locked-set axiom guard, axiom check), builds and
   runs the executables the policy names, and asks Lake to build every
   library module the default build does NOT reach, so a file nobody imports
   is still judged by the kernel, one way or the other;
4. loads every accepted module into one Lean program and reads, from the
   kernel's own records, the axioms each theorem depends on.

Every tracked regular ``.lean`` file gets exactly one status. A module is
accepted only when its ``.olean`` was written during the step that judged it
and the de-duplicated diagnostics of the whole run hold no error for its file;
otherwise it is REJECTED. A file nobody checks is NOT_CHECKED_BY_POLICY, and
neither is ever counted as proved. ``sorry`` is detected as the kernel axiom
``sorryAx`` reached through any chain of lemmas, which a text search cannot do.
Lake's job lines are read per step: a project module that Lake took from a
trace or cache instead of building, with no earlier step of this run having
built it, is an anomaly in a fresh export and holds the witness, and so does an
accepted module that no job line reports as built.

Limits, stated plainly. The kernel elaborates the project's own modules in the
export. Dependency ``.olean`` files (Mathlib and the rest) come from the cache:
they are trusted, NOT re-checked by the kernel, and how the cache was filled is
not observed here. Executables are built and run only because the policy asks
for them. Building runs the commit's own lakefile. Each Lake and Lean child is
started in an empty network namespace only when the host allows one; every step
records what it got, and nothing more about the network is claimed. This is
one elaboration by one toolchain on one machine: not an independent second
kernel, not a signature, and not a review of what the theorems MEAN. A theorem
with a clean axiom footprint can still state something weaker than its name
suggests. No tracked file of the checkout is written and nothing is promoted.
When the dependency cache holds fewer ``.olean`` files than the policy minimum,
or differs from the manifest, the result is UNAVAILABLE rather than a
from-source build of the dependencies; a cache that passes those checks but
lacks some build product is completed by Lake in place, which is not observed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from fnmatch import fnmatchcase
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tempfile

try:
    from tools.database_braid_common import (
        NETNS_EMPTY, NETNS_NOT_REQUESTED, NETNS_STATES, NETNS_UNAVAILABLE, REPOSITORY, SHA40,
        SHA64, bounded_run, checkout_root, closed, digest, git_blob_sha1, lean_code_only, natural,
        read_json, require, sha256_hex, strict_json, write_exclusive, write_new_bytes,
    )
    from tools.database_braid_source_census import export_tree, list_tree
    from tools.database_catalog_admission import InputError
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools.database_braid_common import (
        NETNS_EMPTY, NETNS_NOT_REQUESTED, NETNS_STATES, NETNS_UNAVAILABLE, REPOSITORY, SHA40,
        SHA64, bounded_run, checkout_root, closed, digest, git_blob_sha1, lean_code_only, natural,
        read_json, require, sha256_hex, strict_json, write_exclusive, write_new_bytes,
    )
    from tools.database_braid_source_census import export_tree, list_tree
    from tools.database_catalog_admission import InputError

SCHEMA = "szl.database-braid-lean-witness/v2"
BUILD_TREE = "FRESH_EXPORT_OF_COMMIT"
MODULE = re.compile(r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z")
DECL = re.compile(r"[^\x00-\x1f\x7f]{1,300}\Z")
TOOLCHAIN = re.compile(r"leanprover/lean4:v[0-9]+\.[0-9]+\.[0-9]+(?:-rc[0-9]+)?\Z")
GLOB = re.compile(r"[A-Za-z0-9_.*?/+@-]{1,200}\Z")
_NAME = r"[A-Za-z_][A-Za-z0-9_'.]*"
HEADER = re.compile(r"\A\s*(?:module\s+)?(?:prelude\s+)?(?:(?:(?:public|private|meta)\s+)*"
                    r"import\s+(?:all\s+)?" + _NAME + r"(?![A-Za-z0-9_'.])\s*)*")
IMPORT = re.compile(r"(?<![A-Za-z0-9_'.])import\s+(?:all\s+)?(" + _NAME + r")")
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
SORRY_WARNING = re.compile(r"declaration uses [`']sorry[`']")
STATE_EXECUTED = "KERNEL_EXECUTED"
STATE_HOLD = "HOLD"
STATE_UNAVAILABLE = "UNAVAILABLE"
STATES = (STATE_EXECUTED, STATE_HOLD, STATE_UNAVAILABLE)
UNAVAILABLE_REASONS = ("DEPENDENCY_CACHE_ABSENT", "DEPENDENCY_CACHE_MISMATCH",
                       "TOOLCHAIN_UNAVAILABLE_OR_PIN_MISMATCH")
CENSUS_REASONS = ("CENSUS_PROGRAM_FAILED", "NO_ACCEPTED_MODULES")
HOLD_REASONS = ("ACCEPTED_MODULE_WITHOUT_BUILD_LINE", "AXIOM_CENSUS_UNAVAILABLE",
                "AXIOM_CHECK_FAILED", "DEFAULT_BUILD_FAILED", "EXECUTABLE_FAILED",
                "LOCKED_GUARD_FAILED", "PROJECT_MODULE_REPLAYED_NOT_BUILT",
                "STEP_OUTPUT_TRUNCATED", "STEP_TIMED_OUT")
DEPENDENCY_STATES = ("ABSENT", "MANIFEST_INVALID", "MATCHES_MANIFEST", "MISMATCH", "NO_MANIFEST")
PACKAGE_STATES = ("DIRECTORY_ABSENT", "MATCHES_MANIFEST", "NOT_A_GIT_CHECKOUT",
                  "NOT_PINNED_BY_MANIFEST", "REVISION_DIFFERS")
DEPENDENCY_ORIGIN = "NOT_OBSERVED_BY_THIS_TOOL"
REGULAR_MODES = ("100644", "100755")
MAX_FILES = 5000
MAX_STANDALONE_FILES = 32
MAX_STEPS = 64
MAX_PACKAGES = 256
MAX_WITNESS_BYTES = 8388608
MAX_LOG_BYTES = 67108864
MAX_EXPORT_BLOB_BYTES = 8388608
MAX_EXPORT_BYTES = 1073741824
MAX_MANIFEST_BYTES = 1048576
GIT_TIMEOUT_SECONDS = 120
# One Lake job line per finished job: icon, [n/m], optional marker, verb, caption, time.
JOB_LINE = re.compile(r"([\u2714\u26a0\u2139\u2716\u2298]) \[[0-9]+/[0-9]+\]"
                      r"(?: \(Optional\))? ([A-Z][a-z]+) (\S+)(?: \([0-9.]+m?s\))?\Z")
_FAILED_ICONS = ("\u2716", "\u2298")
_REUSE_VERBS = ("Fetched", "Ran", "Replayed", "Reused", "Unpacked")
_DIAG_LAKE = re.compile(r"(error|warning|info)(?:\([^)\n]*\))?: ([^:\n]+\.lean)"
                        r"(?::([0-9]+):([0-9]+))?: ?(.*)\Z")
_DIAG_LEAN = re.compile(r"([^:\n]+\.lean):([0-9]+):([0-9]+): (error|warning|info)"
                        r"(?:\([^)\n]*\))?:(?: (.*))?\Z")
_FALSE_FLAGS = ("independent_kernel_replay", "sources_modified", "proofs_promoted",
                "meaning_of_statements_reviewed", "production_authorized")
_STEP_FIELDS = ("name", "exit_code", "output_sha256", "seconds", "timed_out", "truncated",
                "network_namespace", "project_modules_built", "project_modules_replayed",
                "project_modules_failed")
_CENSUS_FIELDS = ("state", "reason", "constants", "modules", "modules_loaded", "rows_sha256")
_CACHE_FIELDS = ("state", "manifest_sha256", "packages", "dependency_oleans", "origin",
                 "dependency_oleans_rechecked_by_kernel")
_FIELDS = ("schema", "observed_at", "repository", "commit", "worktree_matches_commit",
           "build_tree", "build_tree_files", "build_tree_skipped_entries", "toolchain",
           "manifest_sha256", "mathlib_revision", "dependency_cache", "network_namespace",
           "steps", "default_build", "locked_guard", "axiom_check", "executables",
           "on_request_build", "files", "file_totals", "modules", "theorem_totals",
           "declared_axioms", "sorry_sources", "carrier_theorems", "census",
           "project_modules_built_by_this_run", "project_modules_replayed", "hold_reasons",
           "state", "policy_section_sha256", "kernel_executed_by_this_run", *_FALSE_FLAGS)
_GIT_HARDENING = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                  "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
                  "GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "core.fsmonitor",
                  "GIT_CONFIG_VALUE_0": "false", "GIT_CONFIG_KEY_1": "core.untrackedCache",
                  "GIT_CONFIG_VALUE_1": "false"}

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
    # A trailing or doubled slash would silently stop module_name from matching the directory.
    require(type(dirs) is list and 0 < len(dirs) <= 8 and dirs[0] == "." and
            all(type(d) is str and re.fullmatch(r"\.|[A-Za-z0-9_][A-Za-z0-9_/-]{0,80}", d) and
                not d.endswith("/") and "//" not in d for d in dirs) and
            len(set(dirs)) == len(dirs), "WITNESS_POLICY_INVALID")
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
    """Every module named by the ``import`` commands of the file header.

    Comments and literals are removed first; the header ends at the first token
    that is not part of an import, so ``import A import B`` gives ``[A, B]``.
    """
    header = HEADER.match(lean_code_only(text)).group(0)
    return [hit.group(1) for hit in IMPORT.finditer(header)]


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


def parse_jobs(text: str, project) -> dict:
    """Project modules that Lake's job lines report as built, reused without building, or failed.

    Lake prints a line for every job that built something or logged output, so
    a module it rebuilt is always listed; a silent replay is not. Captions that
    are not modules of ``project`` (dependencies, ``:c.o`` facets, executables)
    are ignored.
    """
    built, reused, failed = set(), set(), set()
    for line in text.splitlines():
        hit = JOB_LINE.match(line)
        if hit is None or hit.group(3) not in project:
            continue
        icon, verb, name = hit.groups()
        if icon in _FAILED_ICONS:
            failed.add(name)
        elif verb == "Built":
            built.add(name)
        elif verb in _REUSE_VERBS:
            reused.add(name)
    return {"built": built, "reused": reused, "failed": failed}


def _normal_path(path: str, prefixes) -> str:
    for prefix in prefixes:
        if path.startswith(prefix):
            path = path[len(prefix):]
            break
    while path.startswith("./"):
        path = path[2:]
    return path


def _diagnostics(text: str, prefixes) -> dict:
    found = {}
    for line in text.splitlines():
        hit = _DIAG_LAKE.match(line)
        if hit:
            severity, path, row, column, message = hit.groups()
        else:
            hit = _DIAG_LEAN.match(line)
            if hit is None:
                continue
            path, row, column, severity, message = hit.groups()
        key = (_normal_path(path, prefixes), row, column, severity, (message or "").strip())
        found[key] = found.get(key, 0) + 1
    return found


def parse_logs(texts, prefixes=()) -> tuple:
    """``(error_lines_by_path, sorry_declarations_by_path)`` over every log of one run.

    Reads both ``error: PATH:l:c: msg`` (Lake) and ``PATH:l:c: error: msg``
    (``lean`` run directly). A diagnostic is keyed by its normalised path,
    line, column, severity and first message line, and counts as many times as
    it occurs in the one log where it occurs most: Lake replaying a cached log
    in a later step adds nothing, while two different messages that share a
    position inside one elaboration both count.
    """
    prefixes = tuple(sorted(set(prefixes), key=len, reverse=True))
    best = {}
    for text in texts:
        for key, count in _diagnostics(text, prefixes).items():
            best[key] = max(best.get(key, 0), count)
    errors, sorries = {}, {}
    for (path, _row, _column, severity, message), count in best.items():
        if severity == "error":
            errors[path] = errors.get(path, 0) + count
        elif severity == "warning" and SORRY_WARNING.search(message):
            sorries[path] = sorries.get(path, 0) + count
    return errors, sorries


def parse_log(text: str, prefixes=()) -> tuple:
    """``parse_logs`` over a single log."""
    return parse_logs([text], prefixes)


def _elan_home() -> str | None:
    configured = os.environ.get("ELAN_HOME")
    if configured:
        return configured
    # The child gets a private HOME, so an elan install found through the real HOME is named.
    default = Path(os.environ.get("HOME", "/")) / ".elan"
    return str(default) if default.is_dir() else None


def _runner(toolchain_bin: Path, home: str):
    """Runner for lake and lean steps: minimal environment, private HOME, no network if possible.

    Each call returns ``bounded_run``'s result. No address-space limit is set:
    Lean reserves a large address space by design.
    """
    env = {"PATH": f"{toolchain_bin}:/usr/bin:/bin", "HOME": home, "LANG": "C.UTF-8",
           "LC_ALL": "C.UTF-8", "NO_PROXY": "*", "LAKE_ARTIFACT_CACHE": "false",
           **_GIT_HARDENING}
    elan = _elan_home()
    if elan:
        env["ELAN_HOME"] = elan

    def run(argv, cwd: Path, timeout: int) -> dict:
        return bounded_run(argv, cwd=cwd, env=env, timeout=timeout, max_output=MAX_LOG_BYTES,
                           isolate_network=True)

    return run


def _git_head(directory: Path, home: str) -> tuple:
    """``(commit, None)`` checked out at the top of ``directory``, else ``(None, state)``."""
    if not directory.is_dir():
        return None, "DIRECTORY_ABSENT"
    env = {"PATH": "/usr/bin:/bin", "HOME": home, "LC_ALL": "C", **_GIT_HARDENING}
    result = bounded_run(["git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
                          "-C", str(directory), "rev-parse", "--show-toplevel", "HEAD^{commit}"],
                         cwd=directory, env=env, timeout=GIT_TIMEOUT_SECONDS, max_output=65536,
                         merge_stderr=False)
    lines = result["output"].decode("utf-8", "replace").splitlines()
    if (result["exit_code"] != 0 or len(lines) != 2 or not SHA40.fullmatch(lines[1]) or
            Path(lines[0]).resolve() != directory.resolve()):
        return None, "NOT_A_GIT_CHECKOUT"
    return lines[1], None


def _manifest_packages(raw: bytes):
    """``[{"name", "rev"}]`` from ``lake-manifest.json``; ``rev`` only for a pinned git package."""
    try:
        value = strict_json(raw, max_bytes=MAX_MANIFEST_BYTES)
    except InputError:
        return None
    if type(value) is not dict or value.get("packagesDir", ".lake/packages") != ".lake/packages":
        return None
    entries = value.get("packages", [])
    if type(entries) is not list or len(entries) > MAX_PACKAGES:
        return None
    out = []
    for entry in entries:
        if type(entry) is not dict:
            return None
        name, rev = entry.get("name"), entry.get("rev")
        if (type(name) is not str or not re.fullmatch(r"[A-Za-z0-9_.+-]{1,100}", name) or
                name in (".", "..")):
            return None
        pinned = entry.get("type") == "git" and type(rev) is str and SHA40.fullmatch(rev)
        out.append({"name": name, "rev": rev if pinned else None})
    if len({e["name"] for e in out}) != len(out):
        return None
    return out


def _dependency_cache(export: Path, packages: Path, home: str, minimum: int) -> tuple:
    """``(cache, manifest_sha256, mathlib_revision, unavailable_reason_or_None)``."""
    manifest_file = export / "lake-manifest.json"
    manifest_sha, entries = None, []
    if manifest_file.is_file():
        raw = manifest_file.read_bytes()
        manifest_sha = sha256_hex(raw)
        entries = _manifest_packages(raw)
    mathlib = next((e["rev"] for e in entries or () if e["name"] == "mathlib"), None)
    oleans = sum(1 for _ in packages.rglob("*.olean")) if packages.is_dir() else 0
    cache = {"state": "ABSENT", "manifest_sha256": manifest_sha, "packages": None,
             "dependency_oleans": oleans, "origin": DEPENDENCY_ORIGIN,
             "dependency_oleans_rechecked_by_kernel": False}
    # Never fall back to compiling the dependency libraries from source.
    if oleans < minimum:
        return cache, manifest_sha, mathlib, "DEPENDENCY_CACHE_ABSENT"
    if manifest_sha is None:
        cache.update(state="NO_MANIFEST", packages=[])
        return cache, None, None, None
    if entries is None:
        cache.update(state="MANIFEST_INVALID", packages=[])
        return cache, manifest_sha, None, "DEPENDENCY_CACHE_MISMATCH"
    rows = []
    for entry in sorted(entries, key=lambda e: e["name"]):
        head, problem = _git_head(packages / entry["name"], home)
        if entry["rev"] is None:
            state = "NOT_PINNED_BY_MANIFEST"
        elif head is None:
            state = problem
        else:
            state = "MATCHES_MANIFEST" if head == entry["rev"] else "REVISION_DIFFERS"
        rows.append({"name": entry["name"], "manifest_rev": entry["rev"],
                     "checked_out_rev": head, "state": state})
    matches = all(r["state"] == "MATCHES_MANIFEST" for r in rows)
    cache.update(state="MATCHES_MANIFEST" if matches else "MISMATCH", packages=rows)
    return cache, manifest_sha, mathlib, None if matches else "DEPENDENCY_CACHE_MISMATCH"


def _safe_parts(path: str) -> tuple:
    parts = PurePosixPath(path).parts
    require(len(parts) > 0 and not PurePosixPath(path).is_absolute() and
            all(p not in ("", ".", "..", ".git") for p in parts), "WITNESS_TREE_PATH_INVALID")
    return parts


def _worktree_matches(checkout: Path, tree) -> bool:
    """Every tracked file in the working tree has its committed bytes. No ``git status``."""
    root = checkout.resolve()
    for mode, kind, sha, size, path in tree:
        parts = _safe_parts(path)
        if kind != "blob":
            continue
        target = root.joinpath(*parts)
        if mode == "120000":
            try:
                link = os.readlink(target)
            except OSError:
                return False
            if git_blob_sha1(os.fsencode(link)) != sha:
                return False
            continue
        try:
            fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError:
            return False
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size != size:
                return False
            if git_blob_sha1(stream.read(size + 1)) != sha:
                return False
    return True


def _log_dir_allowed(log_dir, denied) -> None:
    require(isinstance(log_dir, Path) and not log_dir.is_symlink() and log_dir.is_dir(),
            "WITNESS_LOG_DIRECTORY_DENIED")
    resolved = log_dir.resolve()
    for directory in denied:
        require(not resolved.is_relative_to(Path(directory).resolve()),
                "WITNESS_LOG_DIRECTORY_DENIED")
    require(not any(log_dir.iterdir()), "WITNESS_LOG_DIRECTORY_NOT_EMPTY")


def _write_log(log_dir: Path, name: str, raw: bytes) -> None:
    try:
        write_new_bytes(log_dir / (name + ".log"), raw)
    except OSError:
        raise InputError("WITNESS_LOG_WRITE_REFUSED") from None


def _clock(marks: Path, index: int) -> int:
    """A file-system timestamp taken just before a step starts; what it writes is not older."""
    path = marks / ("step-%03d" % index)
    write_new_bytes(path, b"")
    return os.lstat(path).st_mtime_ns


def _olean_state(library: Path, name: str, since: int) -> str:
    parts = name.split(".")
    try:
        info = os.lstat(library.joinpath(*parts[:-1], parts[-1] + ".olean"))
    except OSError:
        return "ABSENT"
    if not stat.S_ISREG(info.st_mode):
        return "ABSENT"
    return "FRESH" if info.st_mtime_ns >= since else "STALE"


def _prefixes(*roots) -> tuple:
    out = set()
    for root in roots:
        for form in (str(root), str(Path(root).resolve())):
            out.add(form.rstrip("/") + "/")
    return tuple(out)


def _remove_work(work: Path) -> None:
    link = work / "export" / ".lake" / "packages"
    try:
        if link.is_symlink():
            link.unlink()
    except OSError:
        # Deliberately not raised: the is_symlink() re-check below refuses to
        # rmtree while the cache link still exists, so the shared dependency
        # cache can never be deleted through it.
        pass
    if link.is_symlink():
        return
    shutil.rmtree(work, ignore_errors=True)


def _not_checked_reason(section, path):
    for rule in section["not_checked"]:
        if fnmatchcase(path, rule["glob"]):
            return rule["reason"]
    return None


def observe(section, checkout: Path, *, toolchain_bin: Path, run=None, at=None,
            log_dir: Path | None = None, packages_dir: Path | None = None) -> dict:
    """Build the HEAD commit of ``checkout`` in a fresh export and return the witness.

    ``packages_dir`` is the dependency cache linked as the export's
    ``.lake/packages`` (default ``<checkout>/.lake/packages``); it is never
    copied, and only the link is removed afterwards. ``run(argv, cwd, timeout)``
    must return a ``bounded_run``-shaped dict; offline tests pass a fake Lake.
    """
    validate_policy(section)
    at = at or datetime.now(timezone.utc)
    checkout = Path(checkout)
    packages = Path(packages_dir) if packages_dir is not None else checkout / ".lake" / "packages"
    if log_dir is not None:
        _log_dir_allowed(log_dir, (checkout, checkout_root(), packages))
    commit, _shallow, tree = list_tree(checkout)
    lean_files = sorted(path for mode, kind, _sha, _size, path in tree
                        if kind == "blob" and mode in REGULAR_MODES and path.endswith(".lean"))
    require(0 < len(lean_files) <= MAX_FILES, "WITNESS_FILE_BUDGET_EXCEEDED")
    # A committed .lake directory would put build products into the fresh export.
    require(not any(path == ".lake" or path.startswith(".lake/") for *_entry, path in tree),
            "WITNESS_COMMIT_TRACKS_LAKE_DIRECTORY")
    require(_worktree_matches(checkout, tree), "WITNESS_WORKTREE_DIFFERS_FROM_COMMIT")
    work = Path(tempfile.mkdtemp(prefix="braid-lean-"))
    try:
        place = work.resolve()
        require(not any(place.is_relative_to(Path(p).resolve())
                        for p in (checkout, checkout_root(), packages)),
                "WITNESS_EXPORT_LOCATION_DENIED")
        if log_dir is not None:
            require(not log_dir.resolve().is_relative_to(place), "WITNESS_LOG_DIRECTORY_DENIED")
        export = work / "export"
        for directory in (export, work / "home", work / "marks", work / "census"):
            directory.mkdir()
        shape = export_tree(checkout, commit, export, max_blob_bytes=MAX_EXPORT_BLOB_BYTES,
                            max_total_bytes=MAX_EXPORT_BYTES)
        require(not (export / ".lake").exists(), "WITNESS_COMMIT_TRACKS_LAKE_DIRECTORY")
        (export / ".lake").mkdir()
        if packages.is_dir():
            (export / ".lake" / "packages").symlink_to(packages.resolve(), target_is_directory=True)
        return _build(section, commit, at, work=work, checkout=checkout, packages=packages,
                      lean_files=lean_files, shape=shape,
                      run=run or _runner(toolchain_bin, str(work / "home")), log_dir=log_dir)
    finally:
        _remove_work(work)


def _build(section, commit, at, *, work, checkout, packages, lean_files, shape, run,
           log_dir) -> dict:
    export = work / "export"
    library = export / ".lake" / "build" / "lib" / "lean"
    timeout = section["step_timeout_seconds"]
    dirs = section["source_dirs"]
    path_of, imports_of = {}, {}
    for path in lean_files:
        name = module_name(path, dirs)
        if name is not None and name not in path_of:
            path_of[name] = path
            imports_of[name] = lean_imports((export / path).read_text("utf-8", "replace"))
    project = set(path_of)
    default_set = import_closure(imports_of, section["default_roots"])
    exe_set = import_closure(imports_of, [e["root"] for e in section["executables"]]) - default_set
    standalone = [p for p in lean_files if _not_checked_reason(section, p) is None and
                  any(fnmatchcase(p, g) for g in section["standalone"])]
    require(len(standalone) <= MAX_STANDALONE_FILES, "WITNESS_STANDALONE_BUDGET_EXCEEDED")
    requested = sorted(name for name, path in path_of.items()
                       if name not in default_set and name not in exe_set and
                       _not_checked_reason(section, path) is None and path not in standalone and
                       any(name == r or name.startswith(r + ".") for r in section["library_roots"]))
    steps, logs, built, replayed = [], [], set(), set()

    def step(name, argv):
        since = _clock(work / "marks", len(steps))
        result = run(argv, export, timeout)
        if type(result) is tuple:
            code, out, seconds = result
            result = {"exit_code": code, "output": out, "timed_out": False, "truncated": False,
                      "seconds": seconds, "network_namespace": NETNS_NOT_REQUESTED}
        raw = result["output"]
        text = raw.decode("utf-8", "replace")
        jobs = parse_jobs(text, project)
        first = jobs["built"] - built
        # Reuse of a module that no step of this run built came from outside this run.
        foreign = jobs["reused"] - built - jobs["built"] - replayed
        built.update(jobs["built"])
        replayed.update(foreign)
        steps.append({"name": name, "exit_code": result["exit_code"],
                      "output_sha256": sha256_hex(raw), "seconds": result["seconds"],
                      "timed_out": result["timed_out"], "truncated": result["truncated"],
                      "network_namespace": result["network_namespace"],
                      "project_modules_built": len(first), "project_modules_replayed": len(foreign),
                      "project_modules_failed": len(jobs["failed"])})
        logs.append(text)
        if log_dir is not None:
            _write_log(log_dir, name, raw)
        return result["exit_code"], text, since

    pin_file = export / "lean-toolchain"
    pin = pin_file.read_text("utf-8", "replace").strip()[:200] if pin_file.is_file() else None
    code_lean, lean_line, _ = step("lean_version", ["lean", "--version"])
    code_lake, lake_line, _ = step("lake_version", ["lake", "--version"])
    toolchain = {"pin_required": section["toolchain_pin"], "pin_in_checkout": pin,
                 "lean_version": lean_line.strip()[:200] if code_lean == 0 else None,
                 "lake_version": lake_line.strip()[:200] if code_lake == 0 else None}
    base = {"section": section, "commit": commit, "at": at, "shape": shape, "steps": steps,
            "toolchain": toolchain, "built": built, "replayed": replayed}
    if code_lean != 0 or code_lake != 0 or pin != section["toolchain_pin"]:
        return _witness(**base, manifest=None, mathlib=None, cache=None,
                        unavailable="TOOLCHAIN_UNAVAILABLE_OR_PIN_MISMATCH")
    cache, manifest, mathlib, reason = _dependency_cache(
        export, packages, str(work / "home"), section["min_dependency_oleans"])
    base.update(manifest=manifest, mathlib=mathlib, cache=cache)
    if reason is not None:
        return _witness(**base, unavailable=reason)

    judged = {}
    build_code, _text, since = step("default_build", ["lake", "build"])
    for name in default_set:
        judged[name] = (_olean_state(library, name, since), "DEFAULT_BUILD_FAILED")
    fresh = sum(judged[name][0] == "FRESH" for name in default_set)
    default_ok = build_code == 0 and fresh == len(default_set)
    default_build = {"exit_code": build_code, "state": "PASSED" if default_ok else "FAILED",
                     "modules_in_import_closure": len(default_set),
                     "closure_modules_with_olean": fresh}

    guard_code, guard_log, _ = step("locked_guard", ["lake", "env", "lean",
                                                     "./" + section["locked_guard"]["path"]])
    allowed = guard_log.count('"allowed":true')
    refused = guard_log.count('"allowed":false')
    expected = section["locked_guard"]["expected_allowed"]
    locked = {"exit_code": guard_code, "allowed": allowed, "refused": refused,
              "expected": expected,
              "state": "PASSED" if guard_code == 0 and refused == 0 and allowed == expected
              else "FAILED"}
    check_code, check_log, _ = step("axiom_check", ["lake", "env", "lean",
                                                    "./" + section["axiom_check"]["path"]])
    mentions = check_log.count(SORRY_AXIOM)
    axiom_check = {"exit_code": check_code, "sorry_axiom_mentions": mentions,
                   "state": "PASSED" if check_code == 0 and mentions == 0 else "FAILED"}
    # Executables are not default targets: building and running them is its own request.
    executables, claimed = [], set(default_set)
    for exe in section["executables"]:
        exe_code, _text, since = step("exe_" + exe["name"],
                                      ["lake", "exe", exe["name"], *exe["arguments"]])
        executables.append({"name": exe["name"], "root": exe["root"], "exit_code": exe_code,
                            "state": "PASSED" if exe_code == 0 else "FAILED"})
        for name in import_closure(imports_of, [exe["root"]]) - claimed:
            judged[name] = (_olean_state(library, name, since), "EXECUTABLE_BUILD_FAILED")
            claimed.add(name)
    request_code = None
    if requested:
        request_code, _text, since = step("on_request_build",
                                          ["lake", "build", *("+" + name for name in requested)])
        for name in requested:
            judged[name] = (_olean_state(library, name, since), "ON_REQUEST_BUILD_FAILED")
    alone = {}
    for path in standalone:
        alone[path] = step("standalone_" + sha256_hex(path.encode())[:12],
                           ["lake", "env", "lean", "./" + path])[0]
    errors, sorries = parse_logs(logs, _prefixes(export, checkout))

    files = []
    for path in lean_files:
        name = module_name(path, dirs)
        module = name if path_of.get(name) == path else None
        reason = _not_checked_reason(section, path)
        row = {"path": path, "module": module, "status": None, "reason": None,
               "elaborator_sorry_declarations": sorries.get(path, 0),
               "error_lines": errors.get(path, 0)}
        if reason is not None:
            row.update(status=NOT_CHECKED, reason=reason)
        elif path in alone:
            ok = alone[path] == 0 and row["error_lines"] == 0
            row.update(status=ACCEPTED_STANDALONE if ok else REJECTED,
                       reason=None if ok else "ELABORATION_FAILED")
        elif module is None:
            row.update(status=NOT_CHECKED, reason="NOT_A_WORKSPACE_MODULE")
        elif module in judged:
            olean, failure = judged[module]
            if row["error_lines"]:
                row.update(status=REJECTED, reason="ELABORATION_FAILED")
            elif olean == "STALE":
                row.update(status=REJECTED, reason="OLEAN_NOT_WRITTEN_BY_THIS_STEP")
            elif olean == "ABSENT":
                row.update(status=REJECTED, reason=failure)
            else:
                row.update(status=ACCEPTED_DEFAULT if module in default_set else ACCEPTED_REQUEST)
        else:
            row.update(status=NOT_CHECKED, reason="OUTSIDE_LIBRARY_ROOTS")
        files.append(row)
    on_request = None
    if requested:
        wanted = set(requested)
        asked = [r for r in files if r["module"] in wanted]
        on_request = {"exit_code": request_code, "modules_requested": len(requested),
                      "modules_accepted": sum(r["status"] == ACCEPTED_REQUEST for r in asked),
                      "modules_rejected": sum(r["status"] == REJECTED for r in asked)}

    roots = {e["root"] for e in section["executables"]}
    kernel_accepted = {r["module"] for r in files if r["status"] in (ACCEPTED_DEFAULT,
                                                                     ACCEPTED_REQUEST)}
    accepted = sorted(kernel_accepted - roots)
    rows, census_state, census_reason = None, "UNAVAILABLE", "NO_ACCEPTED_MODULES"
    if accepted:
        program = work / "census" / "BraidAxiomCensus.lean"
        write_new_bytes(program, census_program(accepted).encode("utf-8"))
        code, out, _ = step("axiom_census", ["lake", "env", "lean", str(program)])
        if code == 0:
            rows = parse_census(out, set(accepted))
            census_state, census_reason = "EXECUTED", None
        else:
            census_reason = "CENSUS_PROGRAM_FAILED"
    reasons = set()
    if not default_ok:
        reasons.add("DEFAULT_BUILD_FAILED")
    if locked["state"] != "PASSED":
        reasons.add("LOCKED_GUARD_FAILED")
    if axiom_check["state"] != "PASSED":
        reasons.add("AXIOM_CHECK_FAILED")
    if any(e["state"] != "PASSED" for e in executables):
        reasons.add("EXECUTABLE_FAILED")
    if census_state != "EXECUTED":
        reasons.add("AXIOM_CENSUS_UNAVAILABLE")
    if replayed:
        reasons.add("PROJECT_MODULE_REPLAYED_NOT_BUILT")
    if kernel_accepted - built:
        reasons.add("ACCEPTED_MODULE_WITHOUT_BUILD_LINE")
    if any(s["timed_out"] for s in steps):
        reasons.add("STEP_TIMED_OUT")
    if any(s["truncated"] for s in steps):
        reasons.add("STEP_OUTPUT_TRUNCATED")
    return _witness(**base, default_build=default_build, locked=locked, axiom_check=axiom_check,
                    executables=executables, on_request=on_request, files=files, rows=rows,
                    census_state=census_state, census_reason=census_reason,
                    module_paths=path_of, loaded=len(accepted), reasons=sorted(reasons))


def _witness(*, section, commit, at, shape, steps, toolchain, built, replayed, manifest, mathlib,
             cache, unavailable=None, default_build=None, locked=None, axiom_check=None,
             executables=(), on_request=None, files=(), rows=None, census_state="UNAVAILABLE",
             census_reason=None, module_paths=None, loaded=None, reasons=()) -> dict:
    files = list(files)
    if unavailable is not None:
        census_reason = unavailable
    if rows is None:
        modules, totals, declared, sources, carriers = [], None, [], [], []
        census = {"state": "UNAVAILABLE", "reason": census_reason, "constants": None,
                  "modules": None, "modules_loaded": None, "rows_sha256": None}
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
                  "modules": len({r["module"] for r in rows}), "modules_loaded": loaded,
                  "rows_sha256": census_digest(rows)}
    state = (STATE_UNAVAILABLE if unavailable is not None
             else STATE_HOLD if reasons else STATE_EXECUTED)
    witness = {
        "schema": SCHEMA, "observed_at": at.isoformat(), "repository": section["repository"],
        "commit": commit, "worktree_matches_commit": True, "build_tree": BUILD_TREE,
        "build_tree_files": shape["files"], "build_tree_skipped_entries": shape["skipped_entries"],
        "toolchain": toolchain, "manifest_sha256": manifest, "mathlib_revision": mathlib,
        "dependency_cache": cache,
        "network_namespace": NETNS_EMPTY if steps and all(
            s["network_namespace"] == NETNS_EMPTY for s in steps) else NETNS_UNAVAILABLE,
        "steps": steps, "default_build": default_build, "locked_guard": locked,
        "axiom_check": axiom_check, "executables": list(executables),
        "on_request_build": on_request, "files": files,
        "file_totals": {s: sum(f["status"] == s for f in files) for s in STATUSES},
        "modules": modules, "theorem_totals": totals, "declared_axioms": declared,
        "sorry_sources": sources, "carrier_theorems": carriers, "census": census,
        "project_modules_built_by_this_run": len(built),
        "project_modules_replayed": len(replayed), "hold_reasons": list(reasons),
        "state": state, "policy_section_sha256": digest(section),
        "kernel_executed_by_this_run": state != STATE_UNAVAILABLE,
    }
    witness.update({flag: False for flag in _FALSE_FLAGS})
    validate_witness(witness, section)
    return witness


def _validate_steps(value) -> dict:
    steps = value["steps"]
    require(type(steps) is list and 0 < len(steps) <= MAX_STEPS, "WITNESS_FIELDS_INVALID")
    by_name = {}
    for item in steps:
        closed(item, _STEP_FIELDS, "WITNESS_FIELDS_INVALID")
        require(type(item["name"]) is str and re.fullmatch(r"[a-z][a-z0-9_]{2,40}", item["name"])
                and item["name"] not in by_name and type(item["exit_code"]) is int and
                type(item["output_sha256"]) is str and SHA64.fullmatch(item["output_sha256"]) and
                type(item["timed_out"]) is bool and type(item["truncated"]) is bool and
                item["network_namespace"] in NETNS_STATES, "WITNESS_FIELDS_INVALID")
        for field in ("seconds", "project_modules_built", "project_modules_replayed",
                      "project_modules_failed"):
            natural(item[field], "WITNESS_FIELDS_INVALID", maximum=10 ** 6)
        by_name[item["name"]] = item
    require([s["name"] for s in steps[:2]] == ["lean_version", "lake_version"],
            "WITNESS_FIELDS_INVALID")
    isolated = all(s["network_namespace"] == NETNS_EMPTY for s in steps)
    require(value["network_namespace"] == (NETNS_EMPTY if isolated else NETNS_UNAVAILABLE),
            "WITNESS_NETWORK_NAMESPACE_DRIFT")
    for field, per_step in (("project_modules_built_by_this_run", "project_modules_built"),
                            ("project_modules_replayed", "project_modules_replayed")):
        natural(value[field], "WITNESS_FIELDS_INVALID")
        require(value[field] == sum(s[per_step] for s in steps),
                "WITNESS_PROJECT_MODULE_TOTALS_DRIFT")
    return by_name


def _validate_cache(value, section) -> None:
    cache, manifest = value["dependency_cache"], value["manifest_sha256"]
    require(manifest is None or (type(manifest) is str and SHA64.fullmatch(manifest)),
            "WITNESS_FIELDS_INVALID")
    require(value["mathlib_revision"] is None or (type(value["mathlib_revision"]) is str and
                                                  SHA40.fullmatch(value["mathlib_revision"])),
            "WITNESS_FIELDS_INVALID")
    if cache is None:
        require(manifest is None and value["mathlib_revision"] is None,
                "WITNESS_DEPENDENCY_CACHE_INVALID")
        return
    closed(cache, _CACHE_FIELDS, "WITNESS_DEPENDENCY_CACHE_INVALID")
    natural(cache["dependency_oleans"], "WITNESS_DEPENDENCY_CACHE_INVALID")
    require(cache["state"] in DEPENDENCY_STATES and cache["origin"] == DEPENDENCY_ORIGIN and
            cache["dependency_oleans_rechecked_by_kernel"] is False and
            cache["manifest_sha256"] == manifest and
            (cache["state"] == "ABSENT") ==
            (cache["dependency_oleans"] < section["min_dependency_oleans"]),
            "WITNESS_DEPENDENCY_CACHE_INVALID")
    if cache["state"] == "ABSENT":
        require(cache["packages"] is None, "WITNESS_DEPENDENCY_CACHE_INVALID")
        return
    packages = cache["packages"]
    require(type(packages) is list and len(packages) <= MAX_PACKAGES,
            "WITNESS_DEPENDENCY_CACHE_INVALID")
    names = []
    for row in packages:
        closed(row, ("name", "manifest_rev", "checked_out_rev", "state"),
               "WITNESS_DEPENDENCY_CACHE_INVALID")
        revs = (row["manifest_rev"], row["checked_out_rev"])
        require(type(row["name"]) is str and row["state"] in PACKAGE_STATES and
                all(r is None or (type(r) is str and SHA40.fullmatch(r)) for r in revs),
                "WITNESS_DEPENDENCY_CACHE_INVALID")
        if revs[0] is None:
            derived = {"NOT_PINNED_BY_MANIFEST"}
        elif revs[1] is None:
            derived = {"DIRECTORY_ABSENT", "NOT_A_GIT_CHECKOUT"}
        else:
            derived = {"MATCHES_MANIFEST" if revs[0] == revs[1] else "REVISION_DIFFERS"}
        require(row["state"] in derived, "WITNESS_DEPENDENCY_CACHE_INVALID")
        names.append(row["name"])
    require(names == sorted(set(names)), "WITNESS_DEPENDENCY_CACHE_INVALID")
    matching = all(r["state"] == "MATCHES_MANIFEST" for r in packages)
    if manifest is None:
        derived = "NO_MANIFEST"
    elif cache["state"] == "MANIFEST_INVALID":
        derived = "MANIFEST_INVALID" if packages == [] else None
    else:
        derived = "MATCHES_MANIFEST" if matching else "MISMATCH"
    mathlib = next((r["manifest_rev"] for r in packages if r["name"] == "mathlib"), None)
    require(cache["state"] == derived and (packages != [] or derived != "MISMATCH") and
            (derived != "NO_MANIFEST" or packages == []) and
            value["mathlib_revision"] == mathlib, "WITNESS_DEPENDENCY_CACHE_INVALID")


def _validate_gates(value, section, steps) -> dict:
    """Each gate's state and exit code, re-derived from its own numbers and its step."""
    def gate(summary, step_name, fields, passed):
        closed(summary, fields, "WITNESS_GATE_DRIFT")
        entry = steps.get(step_name)
        require(type(summary["exit_code"]) is int and entry is not None and
                summary["exit_code"] == entry["exit_code"] and
                summary["state"] == ("PASSED" if passed else "FAILED"), "WITNESS_GATE_DRIFT")
        return summary["state"] == "PASSED"

    build = value["default_build"]
    require(type(build) is dict, "WITNESS_GATE_DRIFT")
    for field in ("modules_in_import_closure", "closure_modules_with_olean"):
        natural(build.get(field), "WITNESS_GATE_DRIFT")
    require(build["closure_modules_with_olean"] <= build["modules_in_import_closure"],
            "WITNESS_GATE_DRIFT")
    states = {"DEFAULT_BUILD_FAILED": not gate(
        build, "default_build",
        ("exit_code", "state", "modules_in_import_closure", "closure_modules_with_olean"),
        build.get("exit_code") == 0 and
        build["closure_modules_with_olean"] == build["modules_in_import_closure"])}
    guard = value["locked_guard"]
    require(type(guard) is dict and guard.get("expected") == section["locked_guard"][
        "expected_allowed"], "WITNESS_GATE_DRIFT")
    natural(guard.get("allowed"), "WITNESS_GATE_DRIFT")
    natural(guard.get("refused"), "WITNESS_GATE_DRIFT")
    states["LOCKED_GUARD_FAILED"] = not gate(
        guard, "locked_guard", ("exit_code", "allowed", "refused", "expected", "state"),
        guard.get("exit_code") == 0 and guard["refused"] == 0 and
        guard["allowed"] == guard["expected"])
    check = value["axiom_check"]
    require(type(check) is dict, "WITNESS_GATE_DRIFT")
    natural(check.get("sorry_axiom_mentions"), "WITNESS_GATE_DRIFT")
    states["AXIOM_CHECK_FAILED"] = not gate(
        check, "axiom_check", ("exit_code", "sorry_axiom_mentions", "state"),
        check.get("exit_code") == 0 and check["sorry_axiom_mentions"] == 0)
    executables = value["executables"]
    require(type(executables) is list and
            [(e.get("name"), e.get("root")) if type(e) is dict else None for e in executables]
            == [(e["name"], e["root"]) for e in section["executables"]],
            "WITNESS_EXECUTABLES_INVALID")
    states["EXECUTABLE_FAILED"] = not all([
        gate(e, "exe_" + e["name"], ("name", "root", "exit_code", "state"),
             e.get("exit_code") == 0) for e in executables])
    return states


def validate_witness(value, section) -> bool:
    """Closed-schema check of a witness that re-derives every state from its own numbers."""
    validate_policy(section)
    closed(value, _FIELDS, "WITNESS_FIELDS_INVALID")
    require(value["schema"] == SCHEMA and value["repository"] == section["repository"] and
            type(value["commit"]) is str and SHA40.fullmatch(value["commit"]) and
            value["worktree_matches_commit"] is True and value["build_tree"] == BUILD_TREE and
            value["policy_section_sha256"] == digest(section), "WITNESS_BINDING_INVALID")
    require(all(value[flag] is False for flag in _FALSE_FLAGS), "WITNESS_FALSE_AUTHORITY_CLAIM")
    state = value["state"]
    require(state in STATES and value["kernel_executed_by_this_run"] is
            (state != STATE_UNAVAILABLE), "WITNESS_STATE_INVALID")
    require(type(value["observed_at"]) is str and len(value["observed_at"]) <= 48,
            "WITNESS_FIELDS_INVALID")
    try:
        stamp = datetime.fromisoformat(value["observed_at"])
    except ValueError:
        raise InputError("WITNESS_FIELDS_INVALID") from None
    require(stamp.tzinfo is not None, "WITNESS_FIELDS_INVALID")
    natural(value["build_tree_files"], "WITNESS_FIELDS_INVALID")
    natural(value["build_tree_skipped_entries"], "WITNESS_FIELDS_INVALID")
    toolchain = closed(value["toolchain"], ("pin_required", "pin_in_checkout", "lean_version",
                                            "lake_version"), "WITNESS_FIELDS_INVALID")
    require(toolchain["pin_required"] == section["toolchain_pin"] and
            all(toolchain[k] is None or (type(toolchain[k]) is str and len(toolchain[k]) <= 200)
                for k in ("pin_in_checkout", "lean_version", "lake_version")),
            "WITNESS_FIELDS_INVALID")
    steps = _validate_steps(value)
    require((toolchain["lean_version"] is None) == (steps["lean_version"]["exit_code"] != 0) and
            (toolchain["lake_version"] is None) == (steps["lake_version"]["exit_code"] != 0),
            "WITNESS_FIELDS_INVALID")
    toolchain_ok = (toolchain["pin_in_checkout"] == section["toolchain_pin"] and
                    toolchain["lean_version"] is not None and toolchain["lake_version"] is not None)
    _validate_cache(value, section)
    files = value["files"]
    require(type(files) is list and len(files) <= min(MAX_FILES, value["build_tree_files"]),
            "WITNESS_FIELDS_INVALID")
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
        # The kernel did not accept a file for which the run logged an error.
        require(not row["status"].startswith("ACCEPTED") or row["error_lines"] == 0,
                "WITNESS_ACCEPTED_WITH_ERRORS")
        require(row["status"] not in (ACCEPTED_DEFAULT, ACCEPTED_REQUEST) or
                row["module"] is not None, "WITNESS_FILE_FIELDS_INVALID")
        paths.append(row["path"])
    require(paths == sorted(set(paths)), "WITNESS_FILE_ORDER_OR_DUPLICATE")
    totals = closed(value["file_totals"], STATUSES, "WITNESS_FIELDS_INVALID")
    require(all(totals[s] == sum(f["status"] == s for f in files) for s in STATUSES),
            "WITNESS_FILE_TOTALS_DRIFT")
    census = closed(value["census"], _CENSUS_FIELDS, "WITNESS_FIELDS_INVALID")
    require(census["state"] in ("EXECUTED", "UNAVAILABLE"), "WITNESS_FIELDS_INVALID")
    modules = value["modules"]
    require(type(modules) is list, "WITNESS_FIELDS_INVALID")
    reasons = value["hold_reasons"]
    require(type(reasons) is list and all(type(r) is str and r in HOLD_REASONS for r in reasons)
            and reasons == sorted(set(reasons)), "WITNESS_HOLD_REASONS_INVALID")
    cache_state = (value["dependency_cache"] or {}).get("state")
    if state == STATE_UNAVAILABLE:
        derived = ("TOOLCHAIN_UNAVAILABLE_OR_PIN_MISMATCH" if not toolchain_ok
                   else "DEPENDENCY_CACHE_ABSENT" if cache_state == "ABSENT"
                   else "DEPENDENCY_CACHE_MISMATCH" if cache_state in ("MISMATCH",
                                                                         "MANIFEST_INVALID")
                   else None)
        require(census["reason"] == derived and derived is not None and
                (value["dependency_cache"] is None) == (not toolchain_ok) and
                list(steps) == ["lean_version", "lake_version"] and
                value["theorem_totals"] is None and modules == [] and files == [] and
                value["declared_axioms"] == [] and value["sorry_sources"] == [] and
                value["carrier_theorems"] == [] and census["state"] == "UNAVAILABLE" and
                all(census[k] is None for k in ("constants", "modules", "modules_loaded",
                                                "rows_sha256")) and
                value["default_build"] is None and value["locked_guard"] is None and
                value["axiom_check"] is None and value["executables"] == [] and
                value["on_request_build"] is None and reasons == [],
                "WITNESS_UNAVAILABLE_NOT_UNKNOWN")
        return True
    require(toolchain_ok and cache_state in ("MATCHES_MANIFEST", "NO_MANIFEST"),
            "WITNESS_STATE_DRIFT")
    failing = _validate_gates(value, section, steps)
    request = value["on_request_build"]
    if request is None:
        require("on_request_build" not in steps, "WITNESS_GATE_DRIFT")
    else:
        closed(request, ("exit_code", "modules_requested", "modules_accepted",
                         "modules_rejected"), "WITNESS_GATE_DRIFT")
        for field in ("modules_requested", "modules_accepted", "modules_rejected"):
            natural(request[field], "WITNESS_GATE_DRIFT")
        require("on_request_build" in steps and
                request["exit_code"] == steps["on_request_build"]["exit_code"] and
                request["modules_requested"] > 0 and request["modules_requested"] ==
                request["modules_accepted"] + request["modules_rejected"] and
                request["modules_accepted"] <= totals[ACCEPTED_REQUEST], "WITNESS_GATE_DRIFT")
    roots = {e["root"] for e in section["executables"]}
    kernel_accepted = [f["module"] for f in files
                       if f["status"] in (ACCEPTED_DEFAULT, ACCEPTED_REQUEST)]
    accepted = {m for m in kernel_accepted if m not in roots}
    path_of = {f["module"]: f["path"] for f in files if f["module"] in set(kernel_accepted)}
    census_step = steps.get("axiom_census")
    if census["state"] == "UNAVAILABLE":
        require(census["reason"] in CENSUS_REASONS and
                (census["reason"] == "NO_ACCEPTED_MODULES") == (not accepted) and
                (census_step is None) == (census["reason"] == "NO_ACCEPTED_MODULES") and
                (census_step is None or census_step["exit_code"] != 0) and
                value["theorem_totals"] is None and modules == [] and
                value["declared_axioms"] == [] and value["sorry_sources"] == [] and
                value["carrier_theorems"] == [] and
                all(census[k] is None for k in ("constants", "modules", "modules_loaded",
                                                "rows_sha256")),
                "WITNESS_UNAVAILABLE_NOT_UNKNOWN")
    else:
        _validate_census_rollup(value, section, accepted, path_of, census_step)
    derived = dict(failing)
    derived.update({
        "AXIOM_CENSUS_UNAVAILABLE": census["state"] != "EXECUTED",
        "PROJECT_MODULE_REPLAYED_NOT_BUILT": value["project_modules_replayed"] > 0,
        "STEP_TIMED_OUT": any(s["timed_out"] for s in steps.values()),
        "STEP_OUTPUT_TRUNCATED": any(s["truncated"] for s in steps.values()),
    })
    require(all((code in reasons) == holds for code, holds in derived.items()),
            "WITNESS_HOLD_REASONS_DRIFT")
    # Modules accepted outnumbering modules Lake built means some were never built here.
    require(len(kernel_accepted) <= value["project_modules_built_by_this_run"] or
            "ACCEPTED_MODULE_WITHOUT_BUILD_LINE" in reasons, "WITNESS_HOLD_REASONS_DRIFT")
    require((state == STATE_HOLD) == bool(reasons), "WITNESS_STATE_DRIFT")
    if state == STATE_EXECUTED:
        require(value["build_tree"] == BUILD_TREE and value["project_modules_replayed"] == 0 and
                len(kernel_accepted) <= value["project_modules_built_by_this_run"],
                "WITNESS_STATE_DRIFT")
    return True


def _validate_census_rollup(value, section, accepted, path_of, census_step) -> None:
    census, modules = value["census"], value["modules"]
    require(census["reason"] is None and type(census["rows_sha256"]) is str and
            SHA64.fullmatch(census["rows_sha256"]) and census_step is not None and
            census_step["exit_code"] == 0, "WITNESS_FIELDS_INVALID")
    natural(census["constants"], "WITNESS_FIELDS_INVALID")
    natural(census["modules"], "WITNESS_FIELDS_INVALID")
    natural(census["modules_loaded"], "WITNESS_FIELDS_INVALID")
    # The census program imports exactly the accepted non-executable modules; a module with no
    # constants yields no module row, so the row count can only be smaller.
    require(census["modules_loaded"] == len(accepted) and census["modules"] == len(modules) and
            census["modules"] <= census["modules_loaded"], "WITNESS_CENSUS_MODULES_DRIFT")
    keys = ("user_theorems", *CLASSES, "direct_sorry_declarations", "declared_axioms")
    names = []
    for row in modules:
        closed(row, ("module", "path", *keys), "WITNESS_MODULE_FIELDS_INVALID")
        require(type(row["module"]) is str and row["module"] in accepted and
                row["path"] == path_of.get(row["module"]), "WITNESS_MODULE_NOT_ACCEPTED")
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
                                               "user_theorem_load"} and type(a["decl"]) is str
                for a in declared) and
            [a["decl"] for a in declared] == sorted({a["decl"] for a in declared}),
            "WITNESS_AXIOM_LIST_INVALID")
    sources = value["sorry_sources"]
    require(type(sources) is list and len(sources) == sums["direct_sorry_declarations"] and
            all(type(s) is dict and set(s) == {"decl", "module", "taints", "sole_blocker_for"}
                and type(s["decl"]) is str for s in sources) and
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


def main(argv=None):
    ap = argparse.ArgumentParser(description="Lean kernel witness for one commit, built in a "
                                             "fresh export of that commit")
    ap.add_argument("--policy", type=Path, required=True)
    ap.add_argument("--lean-checkout", type=Path, required=True)
    ap.add_argument("--toolchain-bin", "--lean-toolchain-bin", dest="toolchain_bin", type=Path,
                    required=True, help="directory holding the lake and lean executables")
    ap.add_argument("--packages-dir", type=Path,
                    help="dependency cache linked (never copied) as the export's .lake/packages;"
                         " default <lean-checkout>/.lake/packages")
    ap.add_argument("--log-dir", type=Path, help="existing empty directory for the step logs")
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        policy, _ = read_json(args.policy, max_bytes=1048576)
        require(type(policy) is dict and "lean" in policy, "WITNESS_POLICY_FIELDS_INVALID")
        require(args.toolchain_bin.is_absolute() and (args.toolchain_bin / "lake").exists() and
                (args.toolchain_bin / "lean").exists(), "WITNESS_TOOLCHAIN_UNAVAILABLE")
        packages = (args.packages_dir if args.packages_dir is not None
                    else args.lean_checkout / ".lake" / "packages")
        if args.log_dir is not None:
            _log_dir_allowed(args.log_dir, (args.lean_checkout, checkout_root(), packages))
        output = args.output
        require(not output.is_symlink() and not output.exists() and output.parent.is_dir() and
                not any(output.resolve().is_relative_to(Path(p).resolve())
                        for p in (args.lean_checkout, checkout_root(), packages)),
                "OUTPUT_PATH_DENIED")
        witness = observe(policy["lean"], args.lean_checkout, toolchain_bin=args.toolchain_bin,
                          log_dir=args.log_dir, packages_dir=args.packages_dir)
        write_exclusive(output, witness, max_bytes=MAX_WITNESS_BYTES, checkout=checkout_root())
        print(json.dumps({"state": witness["state"], "hold_reasons": witness["hold_reasons"],
                          "file_totals": witness["file_totals"],
                          "theorem_totals": witness["theorem_totals"],
                          "locked_guard": (witness["locked_guard"] or {}).get("state"),
                          "build_tree": witness["build_tree"],
                          "network_namespace": witness["network_namespace"],
                          "project_modules_built_by_this_run":
                              witness["project_modules_built_by_this_run"],
                          "project_modules_replayed": witness["project_modules_replayed"],
                          "proofs_promoted": False, "production_authorized": False}))
        return 0 if witness["state"] == STATE_EXECUTED else 2
    except InputError as exc:
        code = exc.code
    except Exception:
        code = "WITNESS_UNAVAILABLE"
    print(json.dumps({"state": "UNAVAILABLE", "code": code, "proofs_promoted": False,
                      "production_authorized": False}))
    return 3


if __name__ == "__main__":
    sys.exit(main())
