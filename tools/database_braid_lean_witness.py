#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the Lean kernel over a fresh export of one commit and record what it accepted.

For the HEAD commit of one Lean checkout this tool:

1. writes the commit's committed regular files, read from the object store,
   into a new empty temporary directory, so no untracked, ignored or earlier
   build file of the checkout's own tree can stand in for a committed source.
   The project's ``.lake/build`` does not exist when the first build starts;
2. links that export's ``.lake/packages`` to an existing dependency cache
   (never copied) and records each manifest revision next to the commit
   checked out in each package directory. Only commits are compared: the
   package work trees and the build products inside them are not. A mismatch
   is UNAVAILABLE, not a build;
3. in the export, runs the repository's default ``lake build``, reads the
   search path Lake would give Lean, runs the repository's own reviewed guard
   scripts (locked-set axiom guard, axiom check), builds and runs the
   executables the policy names, and asks Lake to build every library module
   the default build does NOT reach, so a file nobody imports is still judged
   by the kernel, one way or the other;
4. loads every accepted module into one Lean program and reads, from the
   kernel's own records, the axioms each theorem depends on.

Every tracked regular ``.lean`` file gets exactly one status and names the
step that judged it. Which build step judges a module follows the import
headers as Lake itself reads them (a port of Lean 4.35's fast header reader).
A module is accepted only when its ``.olean`` exists after that step and was
written during this run, no Lake job line of the run reports its build as
failed, and the de-duplicated diagnostics of the whole run hold no error for
its file; otherwise it is REJECTED. A file nobody checks is
NOT_CHECKED_BY_POLICY, and neither is ever counted as proved. ``sorry`` is
detected as the kernel axiom ``sorryAx`` reached through any chain of lemmas,
which a text search cannot do. Lake's job lines are read per step: a project
module that Lake took from a trace or cache instead of building, with no
earlier step of this run having built it, is an anomaly in a fresh export and
holds the witness, and so does an accepted module that no job line reports as
built by the step that judged it or an earlier one.

Lake builds a module from the exact files it names, but the guard scripts, the
stand-alone files and the census are elaborated by Lean on its own, and Lean
looks each import up on its search path. The witness asks ``lake env``, with
no command, for that path: Lake then prints its environment itself and starts
no program. Each of those steps runs the ``lean`` that comes first on the
runner's PATH (the toolchain directory: the binary that ``lean --version``
reported) with exactly that ``LEAN_PATH`` added to the runner's minimal
environment. None runs through ``lake env``, which would put every package's
build directory first on PATH and on the shared-library path, so a program
or a library planted there is not what runs. Lake puts every dependency's
library directory on the search path BEFORE the project's own, and Lean takes
a module from the first entry that holds its root namespace, so a project
namespace planted in the dependency cache (which by default lives in the
checkout's ignored ``.lake``) is what those steps would load. The project's
namespaces are the first name component of every tracked ``.lean`` file's
module and of every root the policy names. The witness reads the search path
once, before the first such step, looks for those namespaces in every entry
other than the export's own library then and again after the last stand-alone
file, and holds when it finds one; a stand-alone file is accepted only when it
found none. The census program prints the file each loaded module was read
from: a module of a project namespace, or one whose ``.olean`` the export's
library holds, read from anywhere else makes the census unavailable.

Limits, stated plainly. The kernel elaborates the project's own modules in the
export. Everything in the dependency cache is trusted, as code and not only as
data, and how the cache was filled is not observed here. Its ``.olean`` files
(Mathlib and the rest) are NOT re-checked by the kernel. Lean runs the
``initialize`` code of every ``.olean`` it imports, in the build of each
project module and in every step above. ``lake exe`` runs an executable linked
with the cache's compiled code, with every package's build directory on its
PATH and shared-library path. Whoever can write into the cache, even into the
ignored build directory of a package whose commit matches the manifest, can
therefore make any step print anything, and no check here can tell: the checks
above catch a stale or misplaced build product, not a deliberate writer.
Comparing the cache's build products with a digest pinned from a trusted build
would catch such a writer; that is ROADMAP, not done here. The toolchain's own
library is trusted with the toolchain, which counts as the pinned one only when
the checkout's ``lean-toolchain`` names the policy's pin and both
``lean --version`` and ``lake --version`` report that Lean version; otherwise
the result is UNAVAILABLE. Executables are built and run only because the
policy asks for them. Building runs the commit's own lakefile. Each Lake and Lean
child is started in an empty network namespace only when the host allows one;
every step records what it got, and nothing more about the network is claimed.
The search path is looked at between steps, not while one runs. This is one
elaboration by one toolchain on one machine: not an independent second kernel,
not a signature, and not a review of what the theorems MEAN. A theorem with a
clean axiom footprint can still state something weaker than its name suggests.
No tracked file of the checkout is written and nothing is promoted. When the
dependency cache holds fewer ``.olean`` files than the policy minimum, or
differs from the manifest, the result is UNAVAILABLE rather than a from-source
build of the dependencies; a cache that passes those checks but lacks some
build product is completed by Lake in place, which is not observed. The checks
of a witness file re-derive every state and count from the rows it carries;
rows rewritten consistently with each other cannot be told from observed ones
without the step logs, whose digests the witness records. With no package rows
(a cache too small to look at), the mathlib revision is the manifest's pin as
read, which nothing in the witness can re-derive.
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
        SHA64, bounded_run, checkout_root, closed, digest, git_blob_sha1, natural, read_json,
        require, sha256_hex, strict_json, write_exclusive, write_new_bytes,
    )
    from tools.database_braid_source_census import export_tree, list_tree
    from tools.database_catalog_admission import InputError
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools.database_braid_common import (
        NETNS_EMPTY, NETNS_NOT_REQUESTED, NETNS_STATES, NETNS_UNAVAILABLE, REPOSITORY, SHA40,
        SHA64, bounded_run, checkout_root, closed, digest, git_blob_sha1, natural, read_json,
        require, sha256_hex, strict_json, write_exclusive, write_new_bytes,
    )
    from tools.database_braid_source_census import export_tree, list_tree
    from tools.database_catalog_admission import InputError

# v3 adds the search-path record, each row's build evidence and the census's olean count, and its
# Lean steps run the toolchain's lean directly on the search path the witness checked. A v2 witness
# has another shape and is refused, never re-read.
SCHEMA = "szl.database-braid-lean-witness/v3"
BUILD_TREE = "FRESH_EXPORT_OF_COMMIT"
MODULE = re.compile(r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z")
DECL = re.compile(r"[^\x00-\x1f\x7f]{1,300}\Z")
TOOLCHAIN = re.compile(r"leanprover/lean4:v[0-9]+\.[0-9]+\.[0-9]+(?:-rc[0-9]+)?\Z")
# What `lean --version` and `lake --version` print, e.g. "Lean (version 4.35.0, x86_64-...)" and
# "Lake version 5.0.0-src+eb6cafb (Lean version 4.35.0)".
LEAN_REPORTS = re.compile(r"\bLean \(version ([0-9A-Za-z.+-]{1,40})[,)]")
LAKE_REPORTS = re.compile(r"\bLake version \S{1,60} \(Lean version ([0-9A-Za-z.+-]{1,40})\)")
GLOB = re.compile(r"[A-Za-z0-9_.*?/+@-]{1,200}\Z")
REASON = re.compile(r"[A-Z][A-Z_]{2,60}\Z")
LOCAL_PATH = re.compile(r"[^\x00-\x1f\x7f]{1,4096}\Z")
PACKAGE_NAME = re.compile(r"[A-Za-z0-9_.+-]{1,100}\Z")
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
CENSUS_REASONS = ("CENSUS_OLEAN_OUTSIDE_EXPORT", "CENSUS_PROGRAM_FAILED", "NO_ACCEPTED_MODULES")
HOLD_REASONS = ("ACCEPTED_MODULE_WITHOUT_BUILD_LINE", "AXIOM_CENSUS_UNAVAILABLE",
                "AXIOM_CHECK_FAILED", "DEFAULT_BUILD_FAILED", "EXECUTABLE_FAILED",
                "LEAN_SEARCH_PATH_SHADOWS_PROJECT", "LEAN_SEARCH_PATH_UNVERIFIED",
                "LOCKED_GUARD_FAILED", "PROJECT_MODULE_REPLAYED_NOT_BUILT",
                "STEP_OUTPUT_TRUNCATED", "STEP_TIMED_OUT")
OLEAN_STATES = ("ABSENT", "FRESH", "STALE")
SEARCH_PATH_STATES = ("EXPORT_ONLY", "SHADOWED", "UNVERIFIED")
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
_CENSUS_FIELDS = ("state", "reason", "constants", "modules", "modules_loaded", "rows_sha256",
                  "project_oleans_from_export")
_CACHE_FIELDS = ("state", "manifest_sha256", "packages", "dependency_oleans", "origin",
                 "dependency_oleans_rechecked_by_kernel")
_FILE_FIELDS = ("path", "module", "status", "reason", "elaborator_sorry_declarations",
                "error_lines", "judging_step", "olean", "built_in_step", "build_job_failed")
_SEARCH_FIELDS = ("exit_code", "state", "entries", "export_library_entries",
                  "project_namespaces", "shadowed_namespaces")
_FIELDS = ("schema", "observed_at", "repository", "commit", "worktree_matches_commit",
           "build_tree", "build_tree_files", "build_tree_skipped_entries", "toolchain",
           "manifest_sha256", "mathlib_revision", "dependency_cache", "network_namespace",
           "steps", "default_build", "lean_search_path", "locked_guard", "axiom_check",
           "executables", "on_request_build", "files", "file_totals", "modules",
           "theorem_totals", "declared_axioms", "sorry_sources", "carrier_theorems", "census",
           "project_modules_built_by_this_run", "project_modules_replayed", "hold_reasons",
           "state", "policy_section_sha256", "kernel_executed_by_this_run", *_FALSE_FLAGS)
# Replace refs are ignored too, so a planted refs/replace entry cannot change what a commit is.
_GIT_HARDENING = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                  "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
                  "GIT_NO_REPLACE_OBJECTS": "1",
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
  -- `import` found each module with `findOLean` on this same search path.
  for m in names do
    let path : Json := match ← (findOLean m).toBaseIO with
      | .ok p => toJson p.toString
      | .error _ => Json.null
    IO.println (Json.mkObj [("census_olean", toString m), ("path", path)]).compress
  IO.println (Json.mkObj [("census_end", true), ("modules", nMods), ("constants", nConsts),
    ("loaded", names.size)]).compress

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


def _module_stem(path: str, source_dirs) -> str:
    """A ``.lean`` path without its suffix and its longest matching source directory."""
    stem = path[:-5]
    for directory in sorted((d for d in source_dirs if d != "."), key=len, reverse=True):
        if stem.startswith(directory + "/"):
            return stem[len(directory) + 1:]
    return stem


def module_name(path: str, source_dirs) -> str | None:
    """Module name of a tracked ``.lean`` path under the first matching source directory."""
    if not path.endswith(".lean"):
        return None
    name = _module_stem(path, source_dirs).replace("/", ".")
    return name if MODULE.fullmatch(name) else None


def _root_namespace(path: str, source_dirs) -> str | None:
    """First name component of the module at a ``.lean`` path, whatever its characters."""
    return re.split(r"[/.]", _module_stem(path, source_dirs), maxsplit=1)[0] or None


def project_roots(paths, section) -> list:
    """Root namespaces of every tracked ``.lean`` path and of every root the policy names."""
    named = (*section["default_roots"], *section["library_roots"],
             *(e["root"] for e in section["executables"]))
    roots = {_root_namespace(p, section["source_dirs"]) for p in paths if p.endswith(".lean")}
    roots |= {name.split(".")[0] for name in named}
    roots.discard(None)
    return sorted(roots)


def _letter_like(c: str) -> bool:
    """Lean 4.35's ``isLetterLike`` (Init/Meta/Defs.lean)."""
    v = ord(c)
    return ((0x3b1 <= v <= 0x3c9 and v != 0x3bb) or
            (0x391 <= v <= 0x3a9 and v not in (0x3a0, 0x3a3)) or 0x3ca <= v <= 0x3fb or
            0x1f00 <= v <= 0x1ffe or 0x2100 <= v <= 0x214f or 0x1d49c <= v <= 0x1d59f or
            (0xc0 <= v <= 0xff and v not in (0xd7, 0xf7)) or 0x100 <= v <= 0x17f)


def _id_first(c: str) -> bool:
    """Lean's ``isIdFirst``: ASCII letters, ``_`` and the letter-like blocks."""
    return "A" <= c <= "Z" or "a" <= c <= "z" or c == "_" or _letter_like(c)


def _id_rest(c: str) -> bool:
    """Lean's ``isIdRest``: ``isIdFirst``, ASCII digits, ``' ! ?`` and the subscripts."""
    v = ord(c)
    return (_id_first(c) or "0" <= c <= "9" or c in ("'", "!", "?") or 0x2080 <= v <= 0x2089
            or 0x2090 <= v <= 0x209c or 0x1d62 <= v <= 0x1d6a or v == 0x2c7c)


def _header_comment_end(text: str, i: int) -> int | None:
    """Just past the ``-/`` closing a block comment whose body starts at ``i``; nesting counts."""
    depth, size = 1, len(text)
    while i < size:
        c = text[i]
        i += 1
        if c in ("-", "/") and i >= size:
            return None
        if c == "-" and text[i] == "/":
            if depth == 1:
                return i + 1
            depth, i = depth - 1, i + 1
        elif c == "/" and text[i] == "-":
            depth, i = depth + 1, i + 1
    return None


def _header_space(text: str, i: int) -> int:
    """Past the spaces and comments at ``i``, as Lake's header reader skips them; -1 on its errors.

    A tab or an unclosed comment is an error; ``/--`` and ``/-!`` are doc comments, which are
    tokens and end the run of space. The character after ``/-`` is skipped unread, as there.
    """
    size = len(text)
    while i < size:
        if text[i] == "\t":
            return -1
        if text[i] in (" ", "\r", "\n"):
            i += 1
        elif text.startswith("--", i):
            end = text.find("\n", i + 2)
            i = size if end < 0 else end
        elif text.startswith("/-", i) and text[i + 2:i + 3] not in ("-", "!"):
            end = _header_comment_end(text, i + 3)
            if end is None:
                return -1
            i = end
        else:
            break
    return i


def _name_parts(text: str, i: int = 0) -> tuple:
    """``(components, end)`` of the Lean name at ``i``, «escapes» removed; ``(None, i)`` if none.

    A ``.`` continues the name only when an identifier or ``«`` follows it.
    """
    size, parts = len(text), []
    while True:
        if i >= size:
            return None, i
        if text[i] == "«":
            end = text.find("»", i + 1)
            if end < 0:
                return None, i
            parts.append(text[i + 1:end])
            i = end + 1
        elif _id_first(text[i]):
            j = i + 1
            while j < size and _id_rest(text[j]):
                j += 1
            parts.append(text[i:j])
            i = j
        else:
            return None, i
        if not (i + 1 < size and text[i] == "." and
                (_id_first(text[i + 1]) or text[i + 1] == "«")):
            return parts, i
        i += 1


def lean_imports(text: str) -> list:
    """The modules a file's header imports, read the way Lake reads them.

    A port of Lean 4.35's ``ParseImportsFast`` (Lean/Elab/ParseImportsFast.lean),
    which Lake uses to find each module's imports: comments are skipped, a doc
    comment or any other token ends the header, keywords match as prefixes, and
    names follow Lean's identifier rules, so ``import Lutar.Λ`` and
    ``import «Lutar».X`` are read whole (as ``Lutar.Λ`` and ``Lutar.X``). Where
    that reader fails (a tab, an unclosed comment, a missing name, or
    ``public``, ``meta`` or ``all`` in a file that is not a ``module``), Lake
    knows no import of the file, and the result is ``[]``. The implicit ``Init``
    import of a file without ``prelude`` is not listed.
    """
    i = _header_space(text, 0)
    is_module = i >= 0 and text.startswith("module", i)
    if is_module:
        i = _header_space(text, i + 6)
    if i >= 0 and text.startswith("prelude", i):
        i = _header_space(text, i + 7)
    if i < 0:
        return []
    names = []
    while True:
        j, modifier = i, False
        for word in ("public", "meta"):
            if j >= 0 and text.startswith(word, j):
                j, modifier = _header_space(text, j + len(word)), True
        # Up to here a failure only ends the header; after ``import`` it fails the whole read.
        if j < 0 or not text.startswith("import", j):
            return names
        j = _header_space(text, j + 6)
        if j < 0:
            return names
        if text.startswith("all", j):
            j, modifier = _header_space(text, j + 3), True
            if j < 0:
                return []
        parts, j = _name_parts(text, j)
        if parts is None or (modifier and not is_module):
            return []
        names.append(".".join(parts))
        i = _header_space(text, j)
        if i < 0:
            return []


def source_imports(raw: bytes) -> list:
    """``lean_imports`` of a source file's bytes. Lake reads a source with Lean's
    ``IO.FS.readFile``, which refuses bytes that are not UTF-8: then no import is known."""
    try:
        return lean_imports(raw.decode("utf-8"))
    except UnicodeDecodeError:
        return []


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


def parse_census_output(text: str, modules) -> tuple:
    """``(rows, oleans)``: strictly parsed census output.

    ``oleans`` holds one ``{"census_olean", "path"}`` record per module the
    census program loaded. The terminal marker must be the last record and
    must agree with the rows, the listed module set and the loaded count.
    """
    rows, oleans, end = [], [], None
    for line in text.splitlines():
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except ValueError:
            raise InputError("WITNESS_CENSUS_LINE_INVALID") from None
        require(type(item) is dict and end is None, "WITNESS_CENSUS_LINE_INVALID")
        if item.get("census_end") is True:
            end = item
        elif "census_olean" in item:
            require(set(item) == {"census_olean", "path"} and
                    type(item["census_olean"]) is str and DECL.fullmatch(item["census_olean"]) and
                    (item["path"] is None or (type(item["path"]) is str and
                                              LOCAL_PATH.fullmatch(item["path"]))),
                    "WITNESS_CENSUS_LINE_INVALID")
            oleans.append(item)
        else:
            require(set(item) == {"module", "decl", "kind", "internal", "direct_sorry", "axioms",
                                  "sorry_sources"} and
                    type(item["module"]) is str and item["module"] in modules and
                    type(item["decl"]) is str and DECL.fullmatch(item["decl"]) and
                    item["kind"] in ("axiom", "def", "theorem", "opaque", "quot", "inductive",
                                     "constructor", "recursor") and
                    type(item["internal"]) is bool and type(item["direct_sorry"]) is bool and
                    all(type(item[f]) is list and all(type(a) is str and DECL.fullmatch(a)
                                                      for a in item[f])
                        for f in ("axioms", "sorry_sources")), "WITNESS_CENSUS_LINE_INVALID")
            rows.append(item)
    require(type(end) is dict and set(end) == {"census_end", "modules", "constants", "loaded"}
            and end["constants"] == len(rows) and end["modules"] == len(set(modules)) and
            end["loaded"] == len(oleans) and
            len({o["census_olean"] for o in oleans}) == len(oleans), "WITNESS_CENSUS_INCOMPLETE")
    return rows, oleans


def parse_census(text: str, modules) -> list:
    """The rows of strictly parsed census output (see ``parse_census_output``)."""
    return parse_census_output(text, modules)[0]


def oleans_in_export(oleans, roots, library: Path, listed, cwd: Path):
    """How many loaded modules were read from the export's ``library``, or ``None``.

    Every loaded module of a project root namespace, and every loaded module
    whose ``.olean`` the library holds, must have been read from the library: a
    relative path is read from ``cwd``, where Lean ran. ``None`` when one was
    read from anywhere else, could not be found, is not a regular file there,
    has a name that is not a module name, or when a module of ``listed`` was
    not loaded. Other modules (dependencies, the toolchain's) are not judged.
    """
    base = os.path.realpath(library)
    seen = set()
    for item in oleans:
        name, found = item["census_olean"], item["path"]
        parts, end = _name_parts(name)
        if (parts is None or end != len(name) or
                any(p in ("", ".", "..") or "/" in p or "\x00" in p for p in parts)):
            return None
        expected = os.path.join(base, *parts[:-1], parts[-1] + ".olean")
        if parts[0] not in roots and not os.path.lexists(expected):
            continue
        if found is None:
            return None
        found = os.path.join(cwd, found)
        if (os.path.basename(found) != os.path.basename(expected) or
                os.path.realpath(os.path.dirname(found)) != os.path.dirname(expected)):
            return None
        try:
            info = os.lstat(expected)
        except OSError:
            return None
        if not stat.S_ISREG(info.st_mode):
            return None
        seen.add(item["census_olean"])
    return len(seen) if set(listed) <= seen else None


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

    The toolchain directory comes first on PATH, and nothing names a shared-library
    path. Each call returns ``bounded_run``'s result. No address-space limit is
    set: Lean reserves a large address space by design.
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
        if type(name) is not str or not PACKAGE_NAME.match(name) or name in (".", ".."):
            return None
        pinned = entry.get("type") == "git" and type(rev) is str and SHA40.fullmatch(rev)
        out.append({"name": name, "rev": rev if pinned else None})
    if len({e["name"] for e in out}) != len(out):
        return None
    return out


def toolchain_matches(toolchain, pin: str) -> bool:
    """The checkout's ``lean-toolchain`` names ``pin``; lean and lake both report its version."""
    want = pin.split(":v", 1)[1]
    lean = LEAN_REPORTS.search(toolchain["lean_version"] or "")
    lake = LAKE_REPORTS.search(toolchain["lake_version"] or "")
    return (toolchain["pin_in_checkout"] == pin and lean is not None and lake is not None and
            lean.group(1) == want and lake.group(1) == want)


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


def _standalone(section, path) -> bool:
    """A file the policy elaborates on its own with Lean, on the search path Lake would give it."""
    return (_not_checked_reason(section, path) is None and
            any(fnmatchcase(path, glob) for glob in section["standalone"]))


def _standalone_step(path: str) -> str:
    return "standalone_" + sha256_hex(path.encode())[:12]


def _in_library(name: str, library_roots) -> bool:
    return any(name == root or name.startswith(root + ".") for root in library_roots)


def _absent_reason(step_name: str) -> str:
    if step_name == "default_build":
        return "DEFAULT_BUILD_FAILED"
    if step_name == "on_request_build":
        return "ON_REQUEST_BUILD_FAILED"
    return "EXECUTABLE_BUILD_FAILED"


def _module_verdict(row) -> tuple:
    """``(status, reason)`` of a module judged by a Lake build step, from its own row."""
    if row["error_lines"]:
        return REJECTED, "ELABORATION_FAILED"
    if row["build_job_failed"]:
        return REJECTED, "BUILD_JOB_FAILED"
    if row["olean"] == "STALE":
        return REJECTED, "OLEAN_NOT_WRITTEN_BY_THIS_RUN"
    if row["olean"] != "FRESH":
        return REJECTED, _absent_reason(row["judging_step"])
    return (ACCEPTED_DEFAULT if row["judging_step"] == "default_build" else ACCEPTED_REQUEST), None


def _standalone_verdict(row, exit_code, search_state) -> tuple:
    """Lean looked a stand-alone file's imports up on its search path: accepted only when no
    entry but the export's library could have supplied a project module."""
    if exit_code != 0 or row["error_lines"]:
        return REJECTED, "ELABORATION_FAILED"
    if search_state != "EXPORT_ONLY":
        return REJECTED, "LEAN_SEARCH_PATH_NOT_EXPORT_ONLY"
    return ACCEPTED_STANDALONE, None


def _without_build_line(row, order) -> bool:
    """An accepted module that no job line reports built by its judging step or earlier."""
    return (row["status"] in (ACCEPTED_DEFAULT, ACCEPTED_REQUEST) and
            (row["built_in_step"] is None or
             order[row["built_in_step"]] > order[row["judging_step"]]))


def lean_path_value(exit_code: int, text: str) -> str | None:
    """The ``LEAN_PATH`` that ``lake env`` printed, or ``None``.

    Without a command, ``lake env`` prints Lake's own environment, one
    ``NAME=value`` line each, and starts no program. ``None`` unless it exited
    0 and printed exactly one ``LEAN_PATH=`` line, holding no NUL (which no
    environment value can hold).
    """
    if exit_code != 0:
        return None
    found = [line[len("LEAN_PATH="):] for line in text.split("\n")
             if line.startswith("LEAN_PATH=")]
    return found[0] if len(found) == 1 and "\x00" not in found[0] else None


def _lean_join(entry: str, name: str, cwd) -> str:
    """Lean's ``FilePath.join`` of a search-path entry and a relative name, read from ``cwd``:
    an empty entry joins to ``/name``, the filesystem root, and a relative one is read from
    the directory Lean runs in."""
    joined = entry + "/" + name
    return joined if joined.startswith("/") else os.path.join(cwd, joined)


def _lean_argv(lean_path, target: str) -> list:
    """A step Lean elaborates on its own: the ``lean`` first on the runner's PATH (the toolchain's)
    with only ``LEAN_PATH`` added to the runner's environment, never through ``lake env``. With no
    search path read, ``LEAN_PATH`` stays unset: an empty one would name the filesystem root."""
    if lean_path is None:
        return ["lean", target]
    return ["env", "LEAN_PATH=" + lean_path, "lean", target]


def search_path_check(exit_code: int, text: str, export: Path, library: Path, roots,
                      earlier=()) -> dict:
    """Which project root namespaces Lean could find outside the export's library.

    ``text`` is the output of ``lake env`` (see ``lean_path_value``); its
    ``LEAN_PATH`` is exactly the one the Lean steps get. Lean's ``findOLean``
    takes a module from the first entry holding a directory or an ``.olean``
    named after the module's root namespace, so any entry other than the
    export's library that holds a project root can stand in for the project's
    own modules. Each entry is joined to a name as Lean joins it (see
    ``_lean_join``); Lean runs in the export. ``earlier`` are the namespaces
    an earlier look at the same entries found.
    """
    value = lean_path_value(exit_code, text)
    entries = value.split(os.pathsep) if value is not None else []
    own, shadowed, base = 0, set(earlier), os.path.realpath(library)
    for entry in entries:
        if os.path.realpath(_lean_join(entry, ".", export)) == base:
            own += 1
            continue
        for root in roots:
            if (os.path.isdir(_lean_join(entry, root, export)) or
                    os.path.exists(_lean_join(entry, root + ".olean", export))):
                shadowed.add(root)
    state = ("SHADOWED" if shadowed else
             "UNVERIFIED" if exit_code != 0 or own == 0 else "EXPORT_ONLY")
    return {"exit_code": exit_code, "state": state, "entries": len(entries),
            "export_library_entries": own, "project_namespaces": len(set(roots)),
            "shadowed_namespaces": sorted(shadowed)}


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
            imports_of[name] = source_imports((export / path).read_bytes())
    project = set(path_of)
    roots = project_roots(lean_files, section)
    standalone = [p for p in lean_files if _standalone(section, p)]
    require(len(standalone) <= MAX_STANDALONE_FILES, "WITNESS_STANDALONE_BUDGET_EXCEEDED")
    # A file that a not-checked rule or the stand-alone list claims is never judged as a module.
    judgeable = {name for name, path in path_of.items()
                 if _not_checked_reason(section, path) is None and path not in standalone}
    default_set = import_closure(imports_of, section["default_roots"]) & judgeable
    exe_sets, claimed = [], set(default_set)
    for exe in section["executables"]:
        own = (import_closure(imports_of, [exe["root"]]) & judgeable) - claimed
        exe_sets.append(own)
        claimed |= own
    requested = sorted(name for name in judgeable - claimed
                       if _in_library(name, section["library_roots"]))
    steps, logs, built_in, failed, replayed = [], [], {}, set(), set()

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
        first = jobs["built"] - set(built_in)
        # Reuse of a module that no step of this run built came from outside this run.
        foreign = jobs["reused"] - set(built_in) - jobs["built"] - replayed
        built_in.update(dict.fromkeys(first, name))
        failed.update(jobs["failed"])
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
            "toolchain": toolchain, "built": built_in, "replayed": replayed}
    if not toolchain_matches(toolchain, section["toolchain_pin"]):
        return _witness(**base, manifest=None, mathlib=None, cache=None,
                        unavailable="TOOLCHAIN_UNAVAILABLE_OR_PIN_MISMATCH")
    cache, manifest, mathlib, reason = _dependency_cache(
        export, packages, str(work / "home"), section["min_dependency_oleans"])
    base.update(manifest=manifest, mathlib=mathlib, cache=cache)
    if reason is not None:
        return _witness(**base, unavailable=reason)

    # Every .olean of the export is written after this mark: its .lake/build did not exist.
    build_code, _text, run_start = step("default_build", ["lake", "build"])
    judged, olean = {}, {}

    def judge(names, step_name):
        for name in names:
            judged[name] = step_name
            olean[name] = _olean_state(library, name, run_start)

    judge(default_set, "default_build")
    fresh = sum(olean[name] == "FRESH" for name in default_set)
    default_ok = build_code == 0 and fresh == len(default_set)
    default_build = {"exit_code": build_code, "state": "PASSED" if default_ok else "FAILED",
                     "modules_in_import_closure": len(default_set),
                     "closure_modules_with_olean": fresh}
    path_code, path_text, _ = step("lean_search_path", ["lake", "env"])
    search = search_path_check(path_code, path_text, export, library, roots)
    lean_path = lean_path_value(path_code, path_text)

    guard_code, guard_log, _ = step("locked_guard",
                                    _lean_argv(lean_path, "./" + section["locked_guard"]["path"]))
    allowed = guard_log.count('"allowed":true')
    refused = guard_log.count('"allowed":false')
    expected = section["locked_guard"]["expected_allowed"]
    locked = {"exit_code": guard_code, "allowed": allowed, "refused": refused,
              "expected": expected,
              "state": "PASSED" if guard_code == 0 and refused == 0 and allowed == expected
              else "FAILED"}
    check_code, check_log, _ = step("axiom_check",
                                    _lean_argv(lean_path, "./" + section["axiom_check"]["path"]))
    mentions = check_log.count(SORRY_AXIOM)
    axiom_check = {"exit_code": check_code, "sorry_axiom_mentions": mentions,
                   "state": "PASSED" if check_code == 0 and mentions == 0 else "FAILED"}
    # Executables are not default targets: building and running them is its own request.
    executables = []
    for exe, own in zip(section["executables"], exe_sets):
        exe_code, _text, _since = step("exe_" + exe["name"],
                                       ["lake", "exe", exe["name"], *exe["arguments"]])
        executables.append({"name": exe["name"], "root": exe["root"], "exit_code": exe_code,
                            "state": "PASSED" if exe_code == 0 else "FAILED"})
        judge(own, "exe_" + exe["name"])
    request_code = None
    if requested:
        request_code, _text, _since = step("on_request_build",
                                           ["lake", "build", *("+" + name for name in requested)])
        judge(requested, "on_request_build")
    alone = {}
    for path in standalone:
        name = _standalone_step(path)
        alone[path] = (name, step(name, _lean_argv(lean_path, "./" + path))[0])
    # The same entries once more: a later build step may have written into the dependency cache.
    search = search_path_check(path_code, path_text, export, library, roots,
                               earlier=search["shadowed_namespaces"])
    errors, sorries = parse_logs(logs, _prefixes(export, checkout))

    files = []
    for path in lean_files:
        name = module_name(path, dirs)
        module = name if name is not None and path_of.get(name) == path else None
        row = {"path": path, "module": module, "status": NOT_CHECKED, "reason": None,
               "elaborator_sorry_declarations": sorries.get(path, 0),
               "error_lines": errors.get(path, 0), "judging_step": None, "olean": None,
               "built_in_step": built_in.get(module), "build_job_failed": module in failed}
        rule = _not_checked_reason(section, path)
        if rule is not None:
            row["reason"] = rule
        elif path in alone:
            row["judging_step"], code = alone[path]
            row["status"], row["reason"] = _standalone_verdict(row, code, search["state"])
        elif module is None:
            row["reason"] = "NOT_A_WORKSPACE_MODULE"
        elif module in judged:
            row.update(judging_step=judged[module], olean=olean[module])
            row["status"], row["reason"] = _module_verdict(row)
        else:
            row["reason"] = "OUTSIDE_LIBRARY_ROOTS"
        files.append(row)
    on_request = None
    if requested:
        asked = [r for r in files if r["judging_step"] == "on_request_build"]
        on_request = {"exit_code": request_code, "modules_requested": len(requested),
                      "modules_accepted": sum(r["status"] == ACCEPTED_REQUEST for r in asked),
                      "modules_rejected": sum(r["status"] == REJECTED for r in asked)}

    exe_roots = {e["root"] for e in section["executables"]}
    kernel_accepted = {r["module"] for r in files if r["status"] in (ACCEPTED_DEFAULT,
                                                                     ACCEPTED_REQUEST)}
    accepted = sorted(kernel_accepted - exe_roots)
    rows, census_state, from_export = None, "UNAVAILABLE", None
    census_reason = "NO_ACCEPTED_MODULES"
    if accepted:
        program = work / "census" / "BraidAxiomCensus.lean"
        write_new_bytes(program, census_program(accepted).encode("utf-8"))
        code, out, _ = step("axiom_census", _lean_argv(lean_path, str(program)))
        census_reason = "CENSUS_PROGRAM_FAILED"
        if code == 0:
            parsed, oleans = parse_census_output(out, set(accepted))
            from_export = oleans_in_export(oleans, set(roots), library, accepted, export)
            if from_export is None:
                census_reason = "CENSUS_OLEAN_OUTSIDE_EXPORT"
            else:
                rows, census_state, census_reason = parsed, "EXECUTED", None
    order = {s["name"]: i for i, s in enumerate(steps)}
    reasons = set()
    if not default_ok:
        reasons.add("DEFAULT_BUILD_FAILED")
    if search["state"] == "SHADOWED":
        reasons.add("LEAN_SEARCH_PATH_SHADOWS_PROJECT")
    if search["state"] == "UNVERIFIED":
        reasons.add("LEAN_SEARCH_PATH_UNVERIFIED")
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
    if any(_without_build_line(r, order) for r in files):
        reasons.add("ACCEPTED_MODULE_WITHOUT_BUILD_LINE")
    if any(s["timed_out"] for s in steps):
        reasons.add("STEP_TIMED_OUT")
    if any(s["truncated"] for s in steps):
        reasons.add("STEP_OUTPUT_TRUNCATED")
    return _witness(**base, default_build=default_build, search=search, locked=locked,
                    axiom_check=axiom_check, executables=executables, on_request=on_request,
                    files=files, rows=rows, census_state=census_state,
                    census_reason=census_reason, from_export=from_export, module_paths=path_of,
                    loaded=len(accepted), reasons=sorted(reasons))


def _witness(*, section, commit, at, shape, steps, toolchain, built, replayed, manifest, mathlib,
             cache, unavailable=None, default_build=None, search=None, locked=None,
             axiom_check=None, executables=(), on_request=None, files=(), rows=None,
             census_state="UNAVAILABLE", census_reason=None, from_export=None,
             module_paths=None, loaded=None, reasons=()) -> dict:
    files = list(files)
    if unavailable is not None:
        census_reason = unavailable
    if rows is None:
        modules, totals, declared, sources, carriers = [], None, [], [], []
        census = {"state": "UNAVAILABLE", "reason": census_reason, "constants": None,
                  "modules": None, "modules_loaded": None, "rows_sha256": None,
                  "project_oleans_from_export": None}
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
                  "rows_sha256": census_digest(rows), "project_oleans_from_export": from_export}
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
        "steps": steps, "default_build": default_build, "lean_search_path": search,
        "locked_guard": locked, "axiom_check": axiom_check, "executables": list(executables),
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
        # A child exits 0..255 or by a signal (negative); 127 when it could not be started.
        require(type(item["name"]) is str and re.fullmatch(r"[a-z][a-z0-9_]{2,40}", item["name"])
                and item["name"] not in by_name and type(item["exit_code"]) is int and
                -255 <= item["exit_code"] <= 255 and
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
        require(type(row["name"]) is str and PACKAGE_NAME.match(row["name"]) is not None and
                row["name"] not in (".", "..") and row["state"] in PACKAGE_STATES and
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


def _clean_path(path: str) -> bool:
    return (LOCAL_PATH.fullmatch(path) is not None and not path.startswith("/") and
            all(part not in ("", ".", "..", ".git") for part in path.split("/")))


def _validate_file_rows(value, steps) -> list:
    """Each file row's fields, the row order and the pairing of status and reason."""
    files = value["files"]
    require(type(files) is list and len(files) <= min(MAX_FILES, value["build_tree_files"]),
            "WITNESS_FIELDS_INVALID")
    paths = []
    for row in files:
        closed(row, _FILE_FIELDS, "WITNESS_FILE_FIELDS_INVALID")
        require(type(row["path"]) is str and row["path"].endswith(".lean") and
                _clean_path(row["path"]) and row["status"] in STATUSES and
                (row["module"] is None or (type(row["module"]) is str and
                                           MODULE.fullmatch(row["module"]))) and
                (row["reason"] is None or (type(row["reason"]) is str and
                                           REASON.fullmatch(row["reason"]))) and
                all(row[k] is None or (type(row[k]) is str and row[k] in steps)
                    for k in ("judging_step", "built_in_step")) and
                (row["olean"] is None or row["olean"] in OLEAN_STATES) and
                type(row["build_job_failed"]) is bool and
                (row["module"] is not None or (row["built_in_step"] is None and
                                               not row["build_job_failed"])),
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
    return files


def _validate_verdicts(files, section, steps, search_state) -> None:
    """Each file row's module, judging step and verdict, re-derived from its own evidence."""
    builds = {"default_build", "on_request_build",
              *("exe_" + e["name"] for e in section["executables"])}
    owners = set()
    for row in files:
        # The first path, in order, that names a module owns it, as the producer assigns them.
        name = module_name(row["path"], section["source_dirs"])
        require(row["module"] == (None if name is None or name in owners else name),
                "WITNESS_FILE_MODULE_DRIFT")
        owners.add(name)
        rule, judge = _not_checked_reason(section, row["path"]), row["judging_step"]
        if _standalone(section, row["path"]):
            require(judge == _standalone_step(row["path"]) and row["olean"] is None,
                    "WITNESS_FILE_VERDICT_DRIFT")
            verdict = _standalone_verdict(row, steps[judge]["exit_code"], search_state)
        elif rule is None and row["module"] is not None and judge is not None:
            require(judge in builds and row["olean"] is not None and
                    (judge != "on_request_build" or
                     _in_library(row["module"], section["library_roots"])),
                    "WITNESS_FILE_VERDICT_DRIFT")
            verdict = _module_verdict(row)
        else:
            if rule is None:
                rule = ("NOT_A_WORKSPACE_MODULE" if row["module"] is None
                        else "OUTSIDE_LIBRARY_ROOTS")
            # A judgeable library module is always requested, so it is never left unjudged.
            require(judge is None and row["olean"] is None and
                    (rule != "OUTSIDE_LIBRARY_ROOTS" or
                     not _in_library(row["module"], section["library_roots"])),
                    "WITNESS_FILE_VERDICT_DRIFT")
            verdict = (NOT_CHECKED, rule)
        require((row["status"], row["reason"]) == verdict, "WITNESS_FILE_VERDICT_DRIFT")


def _validate_runs(value, section, steps, files) -> None:
    """The step sequence and the per-step job counts, re-derived from the policy and the rows."""
    accepted = {f["module"] for f in files if f["status"] in (ACCEPTED_DEFAULT, ACCEPTED_REQUEST)}
    expected = ["lean_version", "lake_version", "default_build", "lean_search_path",
                "locked_guard", "axiom_check",
                *("exe_" + e["name"] for e in section["executables"])]
    if any(f["judging_step"] == "on_request_build" for f in files):
        expected.append("on_request_build")
    expected += [f["judging_step"] for f in files if _standalone(section, f["path"])]
    if accepted - {e["root"] for e in section["executables"]}:
        expected.append("axiom_census")
    require(list(steps) == expected, "WITNESS_STEP_SEQUENCE_DRIFT")
    require(all(s["project_modules_built"] == sum(f["built_in_step"] == name for f in files)
                for name, s in steps.items()), "WITNESS_PROJECT_MODULE_TOTALS_DRIFT")
    failing = sum(f["build_job_failed"] for f in files)
    per_step = [s["project_modules_failed"] for s in steps.values()]
    require(max(per_step) <= failing <= sum(per_step), "WITNESS_PROJECT_MODULE_TOTALS_DRIFT")


def _validate_search_path(value, section, steps, files) -> str:
    """The search-path record, re-derived from its own numbers, its step and the tracked paths."""
    search = closed(value["lean_search_path"], _SEARCH_FIELDS, "WITNESS_SEARCH_PATH_INVALID")
    roots = project_roots([f["path"] for f in files], section)
    for field in ("entries", "export_library_entries", "project_namespaces"):
        natural(search[field], "WITNESS_SEARCH_PATH_INVALID")
    shadowed, step = search["shadowed_namespaces"], steps.get("lean_search_path")
    require(type(search["exit_code"]) is int and step is not None and
            search["exit_code"] == step["exit_code"] and
            search["export_library_entries"] <= search["entries"] and
            search["project_namespaces"] == len(roots) and type(shadowed) is list and
            all(type(r) is str and r in roots for r in shadowed) and
            shadowed == sorted(set(shadowed)) and
            (search["exit_code"] == 0 or (search["entries"] == 0 and shadowed == [])),
            "WITNESS_SEARCH_PATH_INVALID")
    derived = ("SHADOWED" if shadowed else "UNVERIFIED"
               if search["exit_code"] != 0 or search["export_library_entries"] == 0
               else "EXPORT_ONLY")
    require(search["state"] == derived, "WITNESS_SEARCH_PATH_INVALID")
    return derived


def _validate_gates(value, section, steps, files) -> dict:
    """Each gate's state, exit code and counts, re-derived from its own numbers, step and rows."""
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
    closure = [f for f in files if f["judging_step"] == "default_build"]
    require(build["modules_in_import_closure"] == len(closure) and
            build["closure_modules_with_olean"] == sum(f["olean"] == "FRESH" for f in closure),
            "WITNESS_GATE_DRIFT")
    states = {"DEFAULT_BUILD_FAILED": not gate(
        build, "default_build",
        ("exit_code", "state", "modules_in_import_closure", "closure_modules_with_olean"),
        build.get("exit_code") == 0 and
        build["closure_modules_with_olean"] == build["modules_in_import_closure"])}
    guard = value["locked_guard"]
    require(type(guard) is dict, "WITNESS_GATE_DRIFT")
    natural(guard.get("expected"), "WITNESS_GATE_DRIFT")
    require(guard["expected"] == section["locked_guard"]["expected_allowed"], "WITNESS_GATE_DRIFT")
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
    request = value["on_request_build"]
    asked = [f for f in files if f["judging_step"] == "on_request_build"]
    if not asked:
        require(request is None and "on_request_build" not in steps, "WITNESS_GATE_DRIFT")
    else:
        closed(request, ("exit_code", "modules_requested", "modules_accepted",
                         "modules_rejected"), "WITNESS_GATE_DRIFT")
        for field in ("modules_requested", "modules_accepted", "modules_rejected"):
            natural(request[field], "WITNESS_GATE_DRIFT")
        require(type(request["exit_code"]) is int and "on_request_build" in steps and
                request["exit_code"] == steps["on_request_build"]["exit_code"] and
                request["modules_requested"] == len(asked) and
                request["modules_accepted"] == sum(f["status"] == ACCEPTED_REQUEST
                                                   for f in asked) and
                request["modules_rejected"] == sum(f["status"] == REJECTED for f in asked),
                "WITNESS_GATE_DRIFT")
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
    toolchain_ok = toolchain_matches(toolchain, section["toolchain_pin"])
    _validate_cache(value, section)
    totals = closed(value["file_totals"], STATUSES, "WITNESS_FIELDS_INVALID")
    for status in STATUSES:
        natural(totals[status], "WITNESS_FIELDS_INVALID")
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
                value["theorem_totals"] is None and modules == [] and value["files"] == [] and
                all(totals[s] == 0 for s in STATUSES) and
                value["declared_axioms"] == [] and value["sorry_sources"] == [] and
                value["carrier_theorems"] == [] and census["state"] == "UNAVAILABLE" and
                all(census[k] is None for k in ("constants", "modules", "modules_loaded",
                                                "rows_sha256", "project_oleans_from_export")) and
                value["default_build"] is None and value["lean_search_path"] is None and
                value["locked_guard"] is None and value["axiom_check"] is None and
                value["executables"] == [] and value["on_request_build"] is None and
                reasons == [], "WITNESS_UNAVAILABLE_NOT_UNKNOWN")
        return True
    require(toolchain_ok and cache_state in ("MATCHES_MANIFEST", "NO_MANIFEST"),
            "WITNESS_STATE_DRIFT")
    files = _validate_file_rows(value, steps)
    search_state = _validate_search_path(value, section, steps, files)
    _validate_verdicts(files, section, steps, search_state)
    require(all(totals[s] == sum(f["status"] == s for f in files) for s in STATUSES),
            "WITNESS_FILE_TOTALS_DRIFT")
    _validate_runs(value, section, steps, files)
    failing = _validate_gates(value, section, steps, files)
    roots = {e["root"] for e in section["executables"]}
    kernel_accepted = [f["module"] for f in files
                       if f["status"] in (ACCEPTED_DEFAULT, ACCEPTED_REQUEST)]
    accepted = {m for m in kernel_accepted if m not in roots}
    path_of = {f["module"]: f["path"] for f in files if f["module"] in set(kernel_accepted)}
    census_step = steps.get("axiom_census")
    if census["state"] == "UNAVAILABLE":
        reason = census["reason"]
        require(reason in CENSUS_REASONS and
                (reason == "NO_ACCEPTED_MODULES") == (not accepted) and
                (census_step is None) == (reason == "NO_ACCEPTED_MODULES") and
                (reason != "CENSUS_PROGRAM_FAILED" or census_step["exit_code"] != 0) and
                (reason != "CENSUS_OLEAN_OUTSIDE_EXPORT" or census_step["exit_code"] == 0) and
                value["theorem_totals"] is None and modules == [] and
                value["declared_axioms"] == [] and value["sorry_sources"] == [] and
                value["carrier_theorems"] == [] and
                all(census[k] is None for k in ("constants", "modules", "modules_loaded",
                                                "rows_sha256", "project_oleans_from_export")),
                "WITNESS_UNAVAILABLE_NOT_UNKNOWN")
    else:
        _validate_census_rollup(value, section, accepted, path_of, census_step)
    order = {name: i for i, name in enumerate(steps)}
    derived = dict(failing)
    derived.update({
        "ACCEPTED_MODULE_WITHOUT_BUILD_LINE": any(_without_build_line(f, order) for f in files),
        "AXIOM_CENSUS_UNAVAILABLE": census["state"] != "EXECUTED",
        "LEAN_SEARCH_PATH_SHADOWS_PROJECT": search_state == "SHADOWED",
        "LEAN_SEARCH_PATH_UNVERIFIED": search_state == "UNVERIFIED",
        "PROJECT_MODULE_REPLAYED_NOT_BUILT": value["project_modules_replayed"] > 0,
        "STEP_TIMED_OUT": any(s["timed_out"] for s in steps.values()),
        "STEP_OUTPUT_TRUNCATED": any(s["truncated"] for s in steps.values()),
    })
    require(all((code in reasons) == holds for code, holds in derived.items()),
            "WITNESS_HOLD_REASONS_DRIFT")
    require((state == STATE_HOLD) == bool(reasons), "WITNESS_STATE_DRIFT")
    if state == STATE_EXECUTED:
        require(value["build_tree"] == BUILD_TREE and value["project_modules_replayed"] == 0 and
                search_state == "EXPORT_ONLY", "WITNESS_STATE_DRIFT")
    return True


def _validate_census_rollup(value, section, accepted, path_of, census_step) -> None:
    census, modules = value["census"], value["modules"]
    require(census["reason"] is None and type(census["rows_sha256"]) is str and
            SHA64.fullmatch(census["rows_sha256"]) and census_step is not None and
            census_step["exit_code"] == 0, "WITNESS_FIELDS_INVALID")
    for field in ("constants", "modules", "modules_loaded", "project_oleans_from_export"):
        natural(census[field], "WITNESS_FIELDS_INVALID")
    # The census program imports exactly the accepted non-executable modules; a module with no
    # constants yields no module row, so the row count can only be smaller. Each of them, and
    # every other loaded module of a project namespace, was read from the export's library.
    require(census["modules_loaded"] == len(accepted) and census["modules"] == len(modules) and
            census["modules"] <= census["modules_loaded"] and
            census["project_oleans_from_export"] >= census["modules_loaded"],
            "WITNESS_CENSUS_MODULES_DRIFT")
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
    for key in keys:
        # JSON true equals 1 under ==: a count must be a count first.
        natural(sums[key], "WITNESS_FIELDS_INVALID")
    require(all(sums[k] == sum(m[k] for m in modules) for k in keys),
            "WITNESS_THEOREM_TOTALS_DRIFT")
    # Each user theorem and each declared axiom is a constant of its own.
    require(census["constants"] >= sums["user_theorems"] + sums["declared_axioms"],
            "WITNESS_CENSUS_MODULES_DRIFT")
    _validate_axioms_and_sources(value, sums, {m["module"]: m for m in modules})
    sources = {s["decl"] for s in value["sorry_sources"]}
    carriers = value["carrier_theorems"]
    require(type(carriers) is list and
            [c.get("decl") if type(c) is dict else None for c in carriers] ==
            [c["decl"] for c in section["carrier_theorems"]], "WITNESS_CARRIERS_INVALID")
    for item, wanted in zip(carriers, section["carrier_theorems"]):
        closed(item, ("decl", "role", "found", "axioms", "class"), "WITNESS_CARRIERS_INVALID")
        axioms = item["axioms"]
        require(item["role"] == wanted["role"] and type(item["found"]) is bool and
                (item["class"] is None and axioms is None if not item["found"] else
                 type(axioms) is list and all(type(a) is str and DECL.fullmatch(a)
                                              for a in axioms) and axioms == sorted(axioms) and
                 item["class"] == classify(axioms, section["trust_base"]) and
                 # A declaration whose own term holds sorryAx depends on sorryAx.
                 (item["decl"] not in sources or SORRY_AXIOM in axioms)),
                "WITNESS_CARRIERS_INVALID")


def _validate_axioms_and_sources(value, sums, by_module) -> None:
    """Declared axioms and sorry sources: shapes, owning modules and per-module counts."""
    declared = value["declared_axioms"]
    require(type(declared) is list and len(declared) == sums["declared_axioms"],
            "WITNESS_AXIOM_LIST_INVALID")
    # A theorem that rests on a declared axiom is never in the trust-base-only class.
    reach = sums["user_theorems"] - sums[CLASS_CLEAN]
    for item in declared:
        closed(item, ("decl", "module", "native_decide_auxiliary", "user_theorem_load"),
               "WITNESS_AXIOM_LIST_INVALID")
        require(type(item["decl"]) is str and DECL.fullmatch(item["decl"]) and
                type(item["module"]) is str and item["module"] in by_module and
                item["native_decide_auxiliary"] is (NATIVE_MARK in item["decl"]),
                "WITNESS_AXIOM_LIST_INVALID")
        natural(item["user_theorem_load"], "WITNESS_AXIOM_LIST_INVALID")
        require(item["user_theorem_load"] <= reach, "WITNESS_AXIOM_LIST_INVALID")
    require([a["decl"] for a in declared] == sorted({a["decl"] for a in declared}) and
            all(m["declared_axioms"] == sum(a["module"] == name for a in declared)
                for name, m in by_module.items()), "WITNESS_AXIOM_LIST_INVALID")
    sources = value["sorry_sources"]
    require(type(sources) is list and len(sources) == sums["direct_sorry_declarations"],
            "WITNESS_SORRY_SOURCES_INVALID")
    for item in sources:
        closed(item, ("decl", "module", "taints", "sole_blocker_for"),
               "WITNESS_SORRY_SOURCES_INVALID")
        require(type(item["decl"]) is str and DECL.fullmatch(item["decl"]) and
                type(item["module"]) is str and item["module"] in by_module,
                "WITNESS_SORRY_SOURCES_INVALID")
        natural(item["taints"], "WITNESS_SORRY_SOURCES_INVALID")
        natural(item["sole_blocker_for"], "WITNESS_SORRY_SOURCES_INVALID")
        # A theorem counts towards a source's taints only when it is sorry-tainted, and towards
        # its sole_blocker_for only when that source is the theorem's only one.
        require(item["sole_blocker_for"] <= item["taints"] <= sums[CLASS_SORRY],
                "WITNESS_SORRY_SOURCES_INVALID")
    require([s["decl"] for s in sources] == sorted({s["decl"] for s in sources}) and
            sum(s["sole_blocker_for"] for s in sources) <= sums[CLASS_SORRY] and
            all(m["direct_sorry_declarations"] == sum(s["module"] == name for s in sources)
                for name, m in by_module.items()), "WITNESS_SORRY_SOURCES_INVALID")


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
                          "lean_search_path": (witness["lean_search_path"] or {}).get("state"),
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
