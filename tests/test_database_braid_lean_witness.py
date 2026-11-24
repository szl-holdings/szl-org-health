# SPDX-License-Identifier: Apache-2.0
"""Synthetic, offline regression suite for the braid v2 Lean kernel witness (schema v3).

Covers policy refusals, module naming, import headers read the way Lake reads them (expected values
recorded from Lean 4.35.0's own Lean.parseImports'), import closure, theorem classification
precedence, the census program and its strict parser, order-independent census digests, Lake
job-line and diagnostic parsing (both message formats, path normalisation, replay de-duplication),
and observe() driven by an injected fake Lake: the build always runs in a fresh export of the commit
with .lake/packages linked to the dependency cache, never in the checkout; planted build products in
the checkout change nothing; an .olean older than the run, a failed job or a file with an error line
is never accepted; a replayed or silently produced project module holds the witness; a project
namespace that the Lean search path could take from the dependency cache holds the witness, keeps
stand-alone files from being accepted and makes the census unavailable; the search path is read from a
bare `lake env` and every Lean step runs the toolchain's lean on exactly that path, so a program planted
on Lake's own PATH never runs; dependency revisions are compared with the manifest; network isolation
is recorded per step; logs are create-exclusive and never written inside a source tree. A
one-change-at-a-time validate_witness tamper matrix, including golden forgeries of every gate, of the
cross-field invariants and of each check that alone refuses a forgery, and a sweep that puts a value of
another type in every field and requires a typed refusal, closes the suite with the CLI. Every
repository, package, toolchain and policy is made up inside temporary directories; nothing touches a
network, a real Lean toolchain or this checkout's git state.
"""
from contextlib import redirect_stdout
from copy import deepcopy
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from unittest import TestCase, main as unittest_main, mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.database_catalog_admission import InputError  # noqa: E402
from tools.database_braid_common import (  # noqa: E402
    NETNS_EMPTY, NETNS_NOT_REQUESTED, NETNS_STATES, NETNS_UNAVAILABLE, digest, sha256_hex,
)
from tools import database_braid_lean_witness as witness_module  # noqa: E402
from tools.database_braid_lean_witness import (  # noqa: E402
    ACCEPTED_DEFAULT, ACCEPTED_REQUEST, ACCEPTED_STANDALONE, BUILD_TREE, CENSUS_REASONS, CLASS_AXIOM,
    CLASS_CLEAN, CLASS_NATIVE, CLASS_SORRY, CLASSES, HOLD_REASONS, NOT_CHECKED, OLEAN_STATES, REJECTED,
    SCHEMA, SEARCH_PATH_STATES, STATUSES, _FALSE_FLAGS, census_digest, census_program, classify,
    import_closure, lean_imports, main, module_name, observe, oleans_in_export, parse_census,
    parse_census_output, parse_jobs, parse_log, parse_logs, search_path_check, validate_policy,
    validate_witness,
)

NOW = datetime(2026, 11, 19, 7, 15, tzinfo=timezone.utc)
PIN = "leanprover/lean4:v4.35.0"
TRUST = ["Classical.choice", "Quot.sound", "propext"]
NATIVE_AUX = "Lib.B.nat._native.native_decide.ax_1_1"
PACKAGES = ("batteries", "mathlib")
OK, WARN, INFO, FAIL = "✔", "⚠", "ℹ", "✖"

FILES = {
    ".gitignore": b"/.lake\n",
    "lean-toolchain": (PIN + "\n").encode(),
    "Root.lean": b"-- import Lib.Orphan\n/- import Lib.Deep /- nested -/ import Lib.Broken -/\n"
                 b"import Lib.A\nimport Lib.B\nimport Mathlib.Tactic\n\ntheorem Root.main : True := trivial\n",
    "Lib/A.lean": b"theorem Lib.A.clean : True := trivial\n",
    "Lib/B.lean": b"import Lib.A\n",
    "Lib/Orphan.lean": b"theorem Lib.Orphan.carrier : True := trivial\n",
    "Lib/Broken.lean": b"theorem Lib.Broken.bad : False := nope\n",
    "Lib/Exe.lean": b"import Lib.A\n",
    "Extra/Lib/Deep.lean": b"import Lib.A\n",
    "Main.lean": b"import Lib.Exe\ndef main : IO Unit := pure ()\n",
    "Other/Outside.lean": b"theorem Other.Outside.t : True := trivial\n",
    "TH8/Solo.lean": b"theorem solo : True := sorry\n",
    "TH8/Bad.lean": b"example : False := nope\n",
    "TH8/Skip.lean": b"example : True := trivial\n",
    "proposals/Scratch.lean": b"theorem scratch : True := sorry\n",
    "tools/lean/LockedGuard.lean": b"#eval 0\n",
    "tools/lean/AxiomCheck.lean": b"#print axioms Root.main\n",
    "lakefile.lean": b"import Lake\n",
    "Bad-Name.lean": b"example : True := trivial\n",
    "README.md": b"synthetic fixture\n",
}

EXPECTED = {
    "Bad-Name.lean": (NOT_CHECKED, "NOT_A_WORKSPACE_MODULE", None),
    "Extra/Lib/Deep.lean": (ACCEPTED_REQUEST, None, "Lib.Deep"),
    "Lib/A.lean": (ACCEPTED_DEFAULT, None, "Lib.A"),
    "Lib/B.lean": (ACCEPTED_DEFAULT, None, "Lib.B"),
    "Lib/Broken.lean": (REJECTED, "ELABORATION_FAILED", "Lib.Broken"),
    "Lib/Exe.lean": (ACCEPTED_REQUEST, None, "Lib.Exe"),
    "Lib/Orphan.lean": (ACCEPTED_REQUEST, None, "Lib.Orphan"),
    "Main.lean": (ACCEPTED_REQUEST, None, "Main"),
    "Other/Outside.lean": (NOT_CHECKED, "OUTSIDE_LIBRARY_ROOTS", "Other.Outside"),
    "Root.lean": (ACCEPTED_DEFAULT, None, "Root"),
    "TH8/Bad.lean": (REJECTED, "ELABORATION_FAILED", "TH8.Bad"),
    "TH8/Skip.lean": (NOT_CHECKED, "KNOWN_SLOW_BY_POLICY", "TH8.Skip"),
    "TH8/Solo.lean": (ACCEPTED_STANDALONE, None, "TH8.Solo"),
    "lakefile.lean": (NOT_CHECKED, "BUILD_CONFIGURATION", "lakefile"),
    "proposals/Scratch.lean": (NOT_CHECKED, "SCRATCH_MIRROR_BY_REPOSITORY_POLICY", "proposals.Scratch"),
    "tools/lean/AxiomCheck.lean": (NOT_CHECKED, "GUARD_SCRIPT_RUN_SEPARATELY", "tools.lean.AxiomCheck"),
    "tools/lean/LockedGuard.lean": (NOT_CHECKED, "GUARD_SCRIPT_RUN_SEPARATELY", "tools.lean.LockedGuard"),
}
DEFAULT_CLOSURE = ("Lib.A", "Lib.B", "Root")
EXE_CLOSURE = ("Lib.Exe", "Main")
CENSUSED = ["Lib.A", "Lib.B", "Lib.Deep", "Lib.Exe", "Lib.Orphan", "Root"]
SOURCE = {"Lib.Deep": "Extra/Lib/Deep.lean"}
SORRY_LINE = "warning: ./Lib/A.lean:3:8: declaration uses 'sorry'"
# Header texts and the imports Lean 4.35.0's own Lean.parseImports' (the reader Lake builds its import
# graph with) returned for each, recorded by running it over this list. [] also stands for its errors.
LAKE_HEADERS = (
    ("import\tA\nimport B\n", []),                   # a tab right after `import` ends the header
    ("import A\n\timport B\n", []),                  # a tab after a name fails the whole read
    ("/-! Module doc -/\nimport A\n", []),           # a doc comment is a token, so the header is over
    ("/--/ import A\n", []),
    ("import A /- x -/ /-! y -/ import B\n", ["A"]),
    ("public import A\n", []),                       # public, meta and all need `module`
    ("meta import A\n", []),
    ("import allium\n", []),                         # `all` matches as a prefix ...
    ("module\nimport allium\n", ["ium"]),            # ... so this one imports `ium`
    ("importA\n", ["A"]),
    ("moduleimport A\n", ["A"]),
    ("preludeimport A\n", ["A"]),
    ("import A\u00a0import B\n", ["A"]),             # only space, CR and LF are spaces
    ("import A\x0cimport B\n", ["A"]),
    ("import A /- unclosed\nimport B\n", []),
    ("import A import\n", []),
    ("import A.1\nimport B\n", ["A"]),
    ("import A..B\n", ["A"]),
    ("import «a»b\nimport C\n", ["a"]),
    ("import A«B»\n", ["A"]),
    ("import A.«B»C\n", ["A.B"]),
    ("import «unclosed\nimport B\n", []),
    ("import 1A\nimport B\n", []),
    ("module\nmeta public import A\n", []),
    ("import A\nimport B.\n", ["A", "B"]),
    ("\ufeffimport A\n", []),
    ("import A--note\nimport B\n", ["A", "B"]),
    ("import A/-note-/import B\n", ["A", "B"]),
    ("/-/ import A -/ import B\n", ["B"]),
)


def policy(**overrides):
    section = {
        "repository": "szl-holdings/synthetic-lean", "toolchain_pin": PIN, "trust_base": list(TRUST),
        "source_dirs": [".", "Extra"], "default_roots": ["Root"],
        "executables": [{"name": "check", "root": "Main", "arguments": ["--quiet"]}],
        "library_roots": ["Lib"], "standalone": ["TH8/*"],
        "not_checked": [
            {"glob": "TH8/Skip.lean", "reason": "KNOWN_SLOW_BY_POLICY"},
            {"glob": "proposals/*", "reason": "SCRATCH_MIRROR_BY_REPOSITORY_POLICY"},
            {"glob": "lakefile.lean", "reason": "BUILD_CONFIGURATION"},
            {"glob": "tools/lean/*", "reason": "GUARD_SCRIPT_RUN_SEPARATELY"},
        ],
        "locked_guard": {"path": "tools/lean/LockedGuard.lean", "expected_allowed": 3},
        "axiom_check": {"path": "tools/lean/AxiomCheck.lean"},
        "carrier_theorems": [
            {"decl": "Lib.A.helper", "role": "NOT_A_THEOREM"},
            {"decl": "Lib.A.sorried", "role": "SORRY_CARRIER"},
            {"decl": "Lib.Orphan.carrier", "role": "CLEAN_CARRIER"},
            {"decl": "Missing.thm", "role": "ABSENT_CARRIER"},
        ],
        "min_dependency_oleans": 2, "step_timeout_seconds": 600,
    }
    section.update(overrides)
    return section


def row(module, decl, kind="theorem", axioms=(), internal=False, direct=False, sources=()):
    return {"module": module, "decl": decl, "kind": kind, "internal": internal, "direct_sorry": direct,
            "axioms": list(axioms), "sorry_sources": list(sources)}


CENSUS_ROWS = {
    "Lib.A": [
        row("Lib.A", "Lib.A.clean", axioms=["propext"]),
        row("Lib.A", "Lib.A.sorried", axioms=["propext", "sorryAx"], direct=True, sources=["Lib.A.sorried"]),
        row("Lib.A", "Lib.A.helper", kind="def"),
    ],
    "Lib.B": [
        row("Lib.B", "Lib.B.myAxiom", kind="axiom", axioms=["Lib.B.myAxiom"]),
        row("Lib.B", "Lib.B.usesAxiom", axioms=["Lib.B.myAxiom", "propext"]),
        row("Lib.B", "Lib.B.chain", axioms=["sorryAx"], sources=["Lib.A.sorried"]),
        row("Lib.B", NATIVE_AUX, kind="axiom", axioms=[NATIVE_AUX]),
        row("Lib.B", "Lib.B.nat", axioms=[NATIVE_AUX, "propext"]),
        row("Lib.B", "Lib.B._proof_1", axioms=["sorryAx"], internal=True, sources=["Lib.A.sorried"]),
        row("Lib.B", "Lib.B.inst", kind="inductive", internal=True),
    ],
    "Root": [
        row("Root", "Root.main"),
        row("Root", "Root.gap", kind="def", axioms=["sorryAx"], direct=True, sources=["Root.gap"]),
        row("Root", "Root.both", axioms=["Lib.B.myAxiom", "sorryAx"], sources=["Lib.A.sorried", "Root.gap"]),
    ],
    "Lib.Orphan": [row("Lib.Orphan", "Lib.Orphan.carrier", axioms=["propext", "Quot.sound",
                                                                   "Classical.choice"])],
    # A module that declares nothing: loaded by the census, but it yields no module row.
    "Lib.Exe": [],
}


def census_rows_for(modules):
    out = []
    for name in modules:
        out.extend(CENSUS_ROWS.get(name, [row(name, name + ".ok", axioms=["propext"])]))
    return out


def olean_record(name, path):
    return {"census_olean": name, "path": path}


def census_text(rows, modules, *, noise=True, oleans=None):
    if oleans is None:
        oleans = [olean_record(m, "/fixture/" + m.replace(".", "/") + ".olean") for m in sorted(set(modules))]
    lines = ["building census...", "info: elaborated"] if noise else []
    lines += [json.dumps(r) for r in rows] + [json.dumps(o) for o in oleans]
    lines.append(json.dumps({"census_end": True, "modules": len(set(modules)), "constants": len(rows),
                             "loaded": len(oleans)}))
    return "\n".join(lines) + "\n"


def job(icon, verb, name, *, timed=True):
    return "%s [4/9] %s %s%s" % (icon, verb, name, " (12ms)" if timed else "")


def source(name):
    return SOURCE.get(name, name.replace(".", "/") + ".lean")


def lean_step(argv):
    """``(search path entries or None, target)`` of a step Lean elaborates on its own, else None: the
    toolchain's lean with only LEAN_PATH added, or with none when no search path could be read."""
    if len(argv) == 4 and argv[0] == "env" and argv[1].startswith("LEAN_PATH=") and argv[2] == "lean":
        return argv[1][len("LEAN_PATH="):].split(":"), argv[3]
    if len(argv) == 2 and argv[0] == "lean" and argv[1] != "--version":
        return None, argv[1]
    return None


def lean_join(entry, name, cwd):
    """Lean's FilePath.join of a search-path entry and a relative name: "" + "/" + name is the root."""
    joined = entry + "/" + name
    return Path(joined) if joined.startswith("/") else Path(cwd) / joined


class FakeLake:
    """Stands in for lean/lake inside the export: writes .olean files for what it builds, prints
    Lake-format job lines and diagnostics, prints Lake's environment (its search path among it) for a
    bare `lake env` and, from the census, the file each loaded module would be read from (found on the
    search path the step was given, the way Lean finds it). It knows no `lake env <program>`: Lake would
    start that program from its own PATH, every package's build directory first."""

    def __init__(self, *, allowed=3, refused=0, guard_exit=0, fail_default=False, fail_request=("Lib.Broken",),
                 fail_exe=False, fail_standalone=("TH8/Bad.lean",),
                 axiom_log="every listed declaration uses the trust base only\n", axiom_exit=0, census_exit=0,
                 tools_missing=False, replay_first=(), silent=(), stale=(), error_with_olean=(),
                 namespace=NETNS_EMPTY, timeout_on=None, truncate_on=None, search_exit=0, search_entries=None,
                 census_paths=None, versions=None):
        self.allowed, self.refused, self.guard_exit = allowed, refused, guard_exit
        self.fail_default, self.fail_request, self.fail_exe = fail_default, set(fail_request), fail_exe
        self.fail_standalone, self.axiom_log, self.axiom_exit = set(fail_standalone), axiom_log, axiom_exit
        self.census_exit, self.tools_missing = census_exit, tools_missing
        self.replay_first, self.silent, self.stale = set(replay_first), set(silent), set(stale)
        self.error_with_olean, self.namespace = set(error_with_olean), namespace
        self.timeout_on, self.truncate_on = timeout_on, truncate_on
        self.search_exit, self.search_entries = search_exit, search_entries
        self.census_paths = dict(census_paths or {})
        # What the real Lean 4.35.0 toolchain prints for `lean --version` and `lake --version`.
        self.versions = versions or {"lean": "Lean (version 4.35.0, x86_64-unknown-linux-gnu, Release)\n",
                                     "lake": "Lake version 5.0.0-src+eb6cafb (Lean version 4.35.0)\n"}
        self.calls, self.programs, self.census_modules, self.links, self.seen = [], [], None, [], []
        self.lean_paths = []

    def entries(self, cwd):
        """Like Lake's: every dependency's library first, then the project's own."""
        if self.search_entries is not None:
            return self.search_entries(cwd)
        packages = cwd / ".lake" / "packages"
        return [str(packages / p / ".lake/build/lib/lean") for p in PACKAGES] + [str(cwd / ".lake/build/lib/lean")]

    def lake_env(self, cwd):
        """What a bare `lake env` prints: Lake's environment, one NAME=value line each."""
        packages = [cwd / ".lake/packages" / p / ".lake/build" for p in PACKAGES] + [cwd / ".lake/build"]
        return "\n".join(["ELAN_TOOLCHAIN=" + PIN, "LEAN_PATH=" + ":".join(self.entries(cwd)),
                          "PATH=" + ":".join(str(p / "bin") for p in packages) + ":/usr/bin:/bin",
                          "LD_LIBRARY_PATH=" + ":".join(str(p / "lib") for p in packages)]) + "\n"

    @staticmethod
    def find_olean(cwd, name, entries):
        """Lean's findOLean on ``entries``: the first entry holding the root namespace decides."""
        parts = name.split(".")
        for entry in entries:
            if lean_join(entry, parts[0], cwd).is_dir() or lean_join(entry, parts[0] + ".olean", cwd).exists():
                return str(lean_join(entry, "/".join(parts) + ".olean", cwd))
        return None

    @staticmethod
    def _olean(cwd, name, *, old=False):
        target = Path(cwd) / ".lake/build/lib/lean" / (name.replace(".", "/") + ".olean")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"olean")
        if old:
            os.utime(target, ns=(10 ** 9, 10 ** 9))

    def _build(self, cwd, names, failing=()):
        lines, failed = [], False
        for name in names:
            if name in failing:
                lines += [job(FAIL, "Building", name),
                          "error: ./%s:1:34: unknown identifier 'nope'" % source(name)]
                failed = True
            elif name in self.stale:
                self._olean(cwd, name, old=True)
                failed = True
            elif name in self.error_with_olean:
                self._olean(cwd, name)
                lines += [job(FAIL, "Building", name), "error: ./%s:2:0: (kernel) declaration has metavariables"
                          % source(name)]
                failed = True
            elif name in self.silent:
                self._olean(cwd, name)
            elif name in self.replay_first:
                self._olean(cwd, name)
                lines.append(job(WARN, "Replayed", name, timed=False))
            else:
                self._olean(cwd, name)
                lines.append(job(WARN if name == "Lib.A" else OK, "Built", name))
                if name == "Lib.A":
                    lines.append(SORRY_LINE)
        return lines, failed

    def __call__(self, argv, cwd, timeout):
        argv, cwd = list(argv), Path(cwd)
        self.calls.append((argv, cwd, timeout))
        self.links.append(os.path.islink(cwd / ".lake" / "packages"))
        self.seen.append(sorted(p.name for p in cwd.iterdir()))
        kind, code, text = self.respond(argv, cwd)
        namespace = self.namespace(kind) if callable(self.namespace) else self.namespace
        return {"exit_code": -9 if kind == self.timeout_on else code, "output": text.encode(),
                "timed_out": kind == self.timeout_on, "truncated": kind == self.truncate_on,
                "seconds": 1, "network_namespace": namespace}

    def respond(self, argv, cwd):
        if argv in (["lean", "--version"], ["lake", "--version"]):
            if self.tools_missing:
                return "version", 127, ""
            return "version", 0, self.versions[argv[0]]
        if argv == ["lake", "build"]:
            lines = [job(WARN, "Replayed", "Mathlib.Tactic", timed=False),
                     "warning: ././.lake/packages/mathlib/Mathlib/Tactic.lean:1:0: dependency note"]
            if self.fail_default:
                built, _ = self._build(cwd, ["Lib.A"])
                lines += built + [job(FAIL, "Building", "Lib.B"), "error: ./Lib/B.lean:1:0: unknown package",
                                  "error: build failed"]
                return "default", 1, "\n".join(lines) + "\n"
            built, _ = self._build(cwd, DEFAULT_CLOSURE)
            return "default", 0, "\n".join(lines + built + ["Build completed successfully (9 jobs)."]) + "\n"
        if argv[:2] == ["lake", "build"]:
            assert all(a.startswith("+") for a in argv[2:])
            lines, failed = self._build(cwd, [a[1:] for a in argv[2:]], self.fail_request)
            return "request", (1 if failed else 0), "\n".join(lines + ["done"]) + "\n"
        if argv == ["lake", "env"]:
            if self.search_exit:
                return "search_path", self.search_exit, "error: no workspace\n"
            return "search_path", 0, self.lake_env(cwd)
        if argv[:3] == ["lake", "exe", "check"]:
            if self.fail_exe:
                return "exe", 1, "\n".join([job(FAIL, "Building", "Main"),
                                            "error: ./Main.lean:2:0: type mismatch"]) + "\n"
            lines = [job(WARN, "Replayed", "Lib.A", timed=False), SORRY_LINE]
            built, _ = self._build(cwd, EXE_CLOSURE)
            lines += built + [job(OK, "Built", "Main:c.o"), job(OK, "Built", "check:exe"), "check ok"]
            return "exe", 0, "\n".join(lines) + "\n"
        lean = lean_step(argv)
        if lean is not None:
            self.lean_paths.append(lean[0])
            return self.elaborate(cwd, *lean)
        raise AssertionError("unexpected argv %r" % (argv,))

    def elaborate(self, cwd, entries, target):
        """Lean run on ``target`` with the search path ``entries`` (None when LEAN_PATH is unset)."""
        if target == "./tools/lean/LockedGuard.lean":
            lines = ['{"name":"F%d","allowed":true}' % i for i in range(self.allowed)]
            lines += ['{"name":"X%d","allowed":false}' % i for i in range(self.refused)]
            return "guard", self.guard_exit, "\n".join(lines) + "\n"
        if target == "./tools/lean/AxiomCheck.lean":
            return "axiom_check", self.axiom_exit, self.axiom_log
        if target.startswith("./"):
            if target[2:] in self.fail_standalone:
                return "standalone", 1, "%s:1:19: error: unknown identifier 'nope'\n" % target[2:]
            return "standalone", 0, "%s:1:8: warning: declaration uses `sorry`\n" % target[2:]
        program = Path(target).read_text(encoding="utf-8")
        self.programs.append(program)
        listed = re.search(r"def modules : Array Name := #\[(.*)\]", program).group(1)
        modules = [m.strip().lstrip("`") for m in listed.split(",")]
        self.census_modules = modules
        if self.census_exit:
            return "census", self.census_exit, "error: census failed\n"
        if entries is None:
            # Without LEAN_PATH, Lean knows only the toolchain's own library.
            return "census", 1, f"{target}:2:0: error: unknown module prefix '{modules[0].split('.')[0]}'\n"
        loaded = ["Init", "Mathlib.Tactic", *modules]
        oleans = [olean_record(m, self.census_paths.get(m, self.find_olean(cwd, m, entries))) for m in loaded]
        return "census", 0, census_text(census_rows_for(modules), modules, oleans=oleans)

    def names(self):
        return [c[0] for c in self.calls]


class WideDefault(FakeLake):
    """A default target wider than the default roots' import closure: the default build also builds
    Lib.Orphan, and the later on-request build finds it up to date and prints nothing for it."""

    def respond(self, argv, cwd):
        if argv == ["lake", "build"]:
            kind, code, text = super().respond(argv, cwd)
            lines, _ = self._build(cwd, ["Lib.Orphan"])
            return kind, code, text + "\n".join(lines) + "\n"
        if argv[:2] == ["lake", "build"]:
            names = [a[1:] for a in argv[2:] if a != "+Lib.Orphan"]
            lines, failed = self._build(cwd, names, self.fail_request)
            return "request", (1 if failed else 0), "\n".join(lines + ["done"]) + "\n"
        return super().respond(argv, cwd)


class CrashAfterWrite(FakeLake):
    """Lake reports Lib.Orphan's job as failed with no positioned error, after a fresh .olean."""

    def __init__(self, *, fail_first=False, **kw):
        super().__init__(**kw)
        self.fail_first = fail_first

    def respond(self, argv, cwd):
        if argv == ["lake", "build"] and self.fail_first:
            kind, _code, text = super().respond(argv, cwd)
            return kind, 1, text + job(FAIL, "Building", "Lib.Orphan") + "\nerror: Lean exited with code 139\n"
        if argv[:2] == ["lake", "build"] and len(argv) > 2 and not self.fail_first:
            names = [a[1:] for a in argv[2:] if a != "+Lib.Orphan"]
            lines, _failed = self._build(cwd, names, self.fail_request)
            self._olean(cwd, "Lib.Orphan")
            lines += [job(FAIL, "Building", "Lib.Orphan"), "error: Lean exited with code 139"]
            return "request", 1, "\n".join(lines + ["error: build failed"]) + "\n"
        return super().respond(argv, cwd)


class LateBuildLine(FakeLake):
    """The default build writes Lib.B's .olean without a job line; only the executable build reports
    building it, after the step that judged it."""

    def respond(self, argv, cwd):
        kind, code, text = super().respond(argv, cwd)
        if argv[:3] == ["lake", "exe", "check"]:
            text += job(OK, "Built", "Lib.B") + "\n"
        return kind, code, text


class AlsoBuildsScratch(FakeLake):
    """The on-request build also builds a module the policy does not check (proposals.Scratch)."""

    def respond(self, argv, cwd):
        kind, code, text = super().respond(argv, cwd)
        if argv[:2] == ["lake", "build"] and len(argv) > 2:
            self._olean(cwd, "proposals.Scratch")
            text += job(OK, "Built", "proposals.Scratch") + "\n"
        return kind, code, text


class PlantsDuringRequest(FakeLake):
    """The on-request build writes an object file named after a project namespace into a dependency's
    build directory: after the first look at the search path, before the stand-alone files run."""

    def respond(self, argv, cwd):
        if argv[:2] == ["lake", "build"] and len(argv) > 2:
            planted = cwd / ".lake/packages/batteries/.lake/build/lib/lean/TH8.olean"
            planted.parent.mkdir(parents=True, exist_ok=True)
            planted.write_bytes(b"planted while the run was going on")
        return super().respond(argv, cwd)


def scrubbed(text):
    """What a planted lean prints: the honest output with every sorryAx removed."""
    out = []
    for line in text.splitlines():
        if line.startswith("{") and '"axioms"' in line:
            item = json.loads(line)
            item.update(axioms=[a for a in item["axioms"] if a != "sorryAx"], direct_sorry=False, sorry_sources=[])
            line = json.dumps(item)
        out.append(line.replace("sorryAx", "propext"))
    return "\n".join(out) + "\n"


class LakeEnvPlanted(FakeLake):
    """`lake env <program>` starts the program from Lake's own PATH, every package's build directory
    first (Lake 4.35's Workspace.augmentedPath): here a dependency's ignored build directory holds a
    `lean` that hides sorryAx (the review's repro) and a `printenv` that prints only the export's
    library. A bare `lake env` prints Lake's real environment; the toolchain's lean is honest."""

    def __init__(self, *, plant_lean=True, plant_printenv=True, **kw):
        super().__init__(**kw)
        self.plant_lean, self.plant_printenv, self.planted_runs = plant_lean, plant_printenv, []

    def respond(self, argv, cwd):
        if argv[:2] == ["lake", "env"] and len(argv) > 2:
            self.planted_runs.append(argv)
            if argv[2:] == ["printenv", "LEAN_PATH"]:
                entries = [str(cwd / ".lake/build/lib/lean")] if self.plant_printenv else self.entries(cwd)
                return "search_path", 0, ":".join(entries) + "\n"
            assert argv[2] == "lean" and len(argv) == 4
            kind, code, text = self.elaborate(cwd, self.entries(cwd), argv[3])
            return kind, (0 if self.plant_lean else code), (scrubbed(text) if self.plant_lean else text)
        return super().respond(argv, cwd)


class BuildsUnderMathlib(FakeLake):
    """The default build also writes Mathlib/Tactic.olean into the export's library: a module outside
    the project's namespaces that the export built all the same."""

    def respond(self, argv, cwd):
        if argv == ["lake", "build"]:
            self._olean(cwd, "Mathlib.Tactic")
        return super().respond(argv, cwd)


def git(repo, *args, home):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "Synthetic Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
           "GIT_COMMITTER_NAME": "Synthetic Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
           "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"}
    proc = subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", *args],
                          cwd=str(repo), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    return proc.stdout


def head(directory, home):
    return git(directory, "rev-parse", "HEAD", home=home).decode().strip()


def manifest_bytes(revs, *, kinds=None):
    kinds = kinds or {}
    return json.dumps({"version": "1.1.0", "packagesDir": ".lake/packages", "name": "synthetic",
                       "packages": [{"name": name, "type": kinds.get(name, "git"), "rev": rev}
                                    for name, rev in sorted(revs.items())]}).encode()


def make_checkout(base, *, files=None, cache=2, name="lean", revs=None, manifest="auto", packages_dir=None):
    base = Path(base)
    repo = base / name
    repo.mkdir(parents=True)
    git(repo, "init", "-q", home=base)
    packages = Path(packages_dir) if packages_dir is not None else repo / ".lake" / "packages"
    heads = {}
    for package in PACKAGES:
        directory = packages / package
        directory.mkdir(parents=True)
        git(directory, "init", "-q", home=base)
        (directory / "lakefile.toml").write_text('name = "%s"\n' % package)
        git(directory, "add", "-A", home=base)
        git(directory, "commit", "-q", "-m", package, home=base)
        heads[package] = head(directory, base)
    for i in range(cache):
        target = packages / "mathlib" / ".lake/build/lib/lean" / ("Dep%d.olean" % i)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"dep")
    chosen = dict(FILES if files is None else files)
    chosen.setdefault(".gitignore", b"/.lake\n")
    if manifest == "auto":
        chosen["lake-manifest.json"] = manifest_bytes(dict(heads, **(revs or {})))
    elif manifest is not None:
        chosen["lake-manifest.json"] = manifest
    for path, raw in chosen.items():
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    git(repo, "add", "-A", home=base)
    git(repo, "commit", "-q", "-m", "synthetic fixture", home=base)
    return repo


class _Checkout(TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.base = Path(self._temp.name)

    def fresh(self, **make):
        base = Path(tempfile.mkdtemp(dir=self.base))
        return make_checkout(base, **make), base

    def run_witness(self, *, section=None, make=None, packages_dir=None, **fake):
        repo, base = self.fresh(**(make or {}))
        lake = FakeLake(**fake)
        value = observe(section or policy(), repo, toolchain_bin=base / "bin", run=lake, at=NOW,
                        packages_dir=packages_dir)
        return value, lake, repo


def by_path(value):
    return {f["path"]: f for f in value["files"]}


def step_named(value, name):
    return next(s for s in value["steps"] if s["name"] == name)


def idle_step(value, name):
    step = deepcopy(step_named(value, name))
    step.update(project_modules_built=0, project_modules_replayed=0, project_modules_failed=0)
    return step


def lake_modules(value):
    return [m["module"] for m in value["modules"]]


class PolicyTests(TestCase):
    def refuses(self, section, code="WITNESS_POLICY_INVALID"):
        with self.assertRaisesRegex(InputError, code):
            validate_policy(section)

    def test_valid_policy_and_shipped_v2_section(self):
        self.assertEqual(validate_policy(policy()), policy())
        shipped = json.loads((ROOT / "governance/database_contracts/ouroboros_braid_v2.json").read_text())
        validate_policy(shipped["lean"])

    def test_field_set_is_closed(self):
        self.refuses(policy(extra=1), "WITNESS_POLICY_FIELDS_INVALID")
        missing = policy()
        del missing["carrier_theorems"]
        self.refuses(missing, "WITNESS_POLICY_FIELDS_INVALID")
        self.refuses([policy()], "WITNESS_POLICY_FIELDS_INVALID")

    def test_identity_refusals(self):
        self.refuses(policy(repository="other-org/synthetic-lean"))
        self.refuses(policy(toolchain_pin="leanprover/lean4:v4.35"))
        self.refuses(policy(toolchain_pin="leanprover/lean4:nightly"))

    def test_trust_base_refusals(self):
        for base in ([], ["propext", "Quot.sound"], ["propext", "propext"], ["propext", "sorryAx"],
                     ["bad name"], [1], "propext", ["a%d" % i for i in range(9)]):
            self.refuses(policy(trust_base=base), "WITNESS_TRUST_BASE_INVALID")

    def test_source_dir_refusals(self):
        for dirs in ([], ["Extra", "."], [".", "Extra", "Extra"], [".", "../up"], [".", "/abs"], [".", 1],
                     [".", "Extra/"], [".", "Extra//Sub"], [".", "Extra/Sub/"]):
            self.refuses(policy(source_dirs=dirs))
        validate_policy(policy(source_dirs=[".", "Extra/Sub"]))

    def test_root_list_refusals(self):
        for field in ("default_roots", "library_roots"):
            for names in ([], ["B", "A"], ["A", "A"], ["bad-name"], [True], "Root"):
                self.refuses(policy(**{field: names}))

    def test_executable_refusals(self):
        good = {"name": "check", "root": "Main", "arguments": []}
        for exe in ({**good, "root": "Root"}, {**good, "name": "X"}, {**good, "name": "c"},
                    {**good, "arguments": ["a b"]}, {**good, "arguments": ["a"] * 5}, {**good, "extra": 1},
                    {"name": "check", "root": "Main"}, {**good, "root": "bad-root"}):
            self.refuses(policy(executables=[exe]))
        self.refuses(policy(executables=[good, {**good, "root": "Other"}]))
        self.refuses(policy(executables=[good, {**good, "name": "other"}]))
        self.refuses(policy(executables=[dict(good, name="e%d" % i, root="R%d" % i) for i in range(9)]))
        validate_policy(policy(executables=[]))

    def test_glob_and_rule_refusals(self):
        self.refuses(policy(standalone=["TH8/ *"]))
        self.refuses(policy(standalone=["a"] * 17))
        self.refuses(policy(not_checked=[{"glob": "x/*", "reason": "lowercase"}]))
        self.refuses(policy(not_checked=[{"glob": "x/*", "reason": "OK_REASON", "extra": 1}]))
        self.refuses(policy(not_checked=[{"glob": "x y", "reason": "OK_REASON"}]))

    def test_guard_path_refusals(self):
        for path in ("/abs/Guard.lean", "./Guard.lean", "-x.lean", "tools/*.lean", "tools/?.lean",
                     "tools/../Guard.lean", "tools/Guard.py", 7):
            self.refuses(policy(locked_guard={"path": path, "expected_allowed": 3}))
            self.refuses(policy(axiom_check={"path": path}))
        self.refuses(policy(locked_guard={"path": "tools/lean/LockedGuard.lean"}))
        self.refuses(policy(axiom_check={"path": "tools/lean/AxiomCheck.lean", "extra": 1}))

    def test_count_refusals_bool_float_negative(self):
        for value in (True, 3.0, -1, "3", 10001):
            self.refuses(policy(locked_guard={"path": "tools/lean/LockedGuard.lean", "expected_allowed": value}))
        for value in (True, 2.0, -1, 10 ** 6 + 1):
            self.refuses(policy(min_dependency_oleans=value))
        for value in (59, 21601, 600.0, False, "600"):
            self.refuses(policy(step_timeout_seconds=value))

    def test_carrier_refusals(self):
        carriers = policy()["carrier_theorems"]
        self.refuses(policy(carrier_theorems=list(reversed(carriers))))
        self.refuses(policy(carrier_theorems=carriers + [carriers[0]]))
        self.refuses(policy(carrier_theorems=[{"decl": "A.b", "role": "lower"}]))
        self.refuses(policy(carrier_theorems=[{"decl": "A b", "role": "ROLE"}]))
        self.refuses(policy(carrier_theorems=[{"decl": "A.b"}]))


class HelperTests(TestCase):
    def test_module_name(self):
        self.assertEqual(module_name("Lib/A.lean", ["."]), "Lib.A")
        self.assertEqual(module_name("Extra/Lib/Deep.lean", [".", "Extra"]), "Lib.Deep")
        self.assertEqual(module_name("Extra/Sub/X.lean", [".", "Extra", "Extra/Sub"]), "X")
        self.assertEqual(module_name("Extra/Lib/Deep.lean", ["."]), "Extra.Lib.Deep")
        self.assertEqual(module_name("Root.lean", ["."]), "Root")
        self.assertIsNone(module_name("Lib/A.py", ["."]))
        self.assertIsNone(module_name("Bad-Name.lean", ["."]))
        self.assertIsNone(module_name("1Lib/A.lean", ["."]))

    def test_lean_imports_ignore_comments(self):
        # Every expected list below is what Lean 4.35.0's own Lean.parseImports' (Lake's reader) returns.
        text = ("-- import Hidden.Line\n/- import Hidden.Block /- import Hidden.Nested -/ still -/\n"
                "module\nimport A.B\npublic import C\nimport all D\n  meta import E'\n"
                "theorem t : True := trivial -- import Hidden.Trailing\n")
        self.assertEqual(lean_imports(text), ["A.B", "C", "D", "E'"])
        self.assertEqual(lean_imports("theorem import_like : True := trivial\n"), [])
        # `private` is no header keyword: the header ends there.
        self.assertEqual(lean_imports("import A.B\nprivate import C\n"), ["A.B"])
        # Without `module`, `public` makes Lake's reader fail: it then knows no import of the file at all.
        self.assertEqual(lean_imports(text.replace("module\n", "")), [])

    def test_lean_imports_reads_every_import_of_the_header_only(self):
        self.assertEqual(lean_imports("module\nimport A import B\nimport C.D import all E\n"), ["A", "B", "C.D", "E"])
        self.assertEqual(lean_imports("import A import B\nimport C.D\n"), ["A", "B", "C.D"])
        self.assertEqual(lean_imports("import A import B\nimport C.D import all E\n"), [])
        self.assertEqual(lean_imports("module\n\npublic import A\nmeta import B\n"), ["A", "B"])
        self.assertEqual(lean_imports("prelude\nimport Init.Core\n"), ["Init.Core"])
        self.assertEqual(lean_imports("import A\ntheorem t : True := trivial\nimport B\n"), ["A"])
        self.assertEqual(lean_imports('import A\ndef s := "/-"\nimport Hidden\n'), ["A"])
        self.assertEqual(lean_imports("/- header note -/ import A -- trailing\nimport B\n"), ["A", "B"])
        self.assertEqual(lean_imports("import\n  A.B\n"), ["A.B"])
        self.assertEqual(lean_imports(""), [])

    def test_import_closure(self):
        imports_of = {"R": ["A", "Mathlib"], "A": ["B"], "B": ["A", "R"], "X": ["A"], "S": []}
        self.assertEqual(import_closure(imports_of, ["R"]), {"R", "A", "B"})
        self.assertEqual(import_closure(imports_of, ["X"]), {"X", "A", "B", "R"})
        self.assertEqual(import_closure(imports_of, ["Missing"]), set())
        self.assertEqual(import_closure(imports_of, []), set())
        self.assertEqual(import_closure(imports_of, ["S", "R"]), {"S", "R", "A", "B"})

    def test_classify_precedence(self):
        self.assertEqual(classify(["sorryAx", "Lean.ofReduceBool", "My.ax", "propext"], TRUST), CLASS_SORRY)
        self.assertEqual(classify(["Lean.ofReduceBool", "My.ax"], TRUST), CLASS_NATIVE)
        self.assertEqual(classify(["Lean.trustCompiler"], TRUST), CLASS_NATIVE)
        self.assertEqual(classify(["Lean.ofReduceNat"], TRUST), CLASS_NATIVE)
        self.assertEqual(classify([NATIVE_AUX, "My.ax"], TRUST), CLASS_NATIVE)
        self.assertEqual(classify(["My.ax", "propext"], TRUST), CLASS_AXIOM)
        self.assertEqual(classify(["propext", "Quot.sound", "Classical.choice"], TRUST), CLASS_CLEAN)
        self.assertEqual(classify([], TRUST), CLASS_CLEAN)
        self.assertEqual(classify(["Classical.choice"], ["propext"]), CLASS_AXIOM)

    def test_census_program_deterministic_and_strict(self):
        one = census_program(["Lib.B", "Root", "Lib.A"])
        self.assertEqual(one, census_program({"Root", "Lib.A", "Lib.B"}))
        self.assertIn("import Lib.A\nimport Lib.B\nimport Root\n", one)
        self.assertIn("#[`Lib.A, `Lib.B, `Root]", one)
        self.assertTrue(one.startswith("import Lean\n"))
        self.assertNotIn("__IMPORTS__", one)
        self.assertNotIn("__MODULES__", one)
        self.assertNotEqual(one, census_program(["Lib.A"]))
        for bad in ([], ["bad-name"], ["Lib.A", "1x"], ["A\nimport Evil"], ["A B"]):
            with self.assertRaisesRegex(InputError, "WITNESS_MODULE_INVALID"):
                census_program(bad)

    def test_parse_census_accepts_valid_output(self):
        modules = {"Lib.A", "Root"}
        rows = census_rows_for(sorted(modules))
        self.assertEqual(parse_census(census_text(rows, modules), modules), rows)

    def test_parse_census_refusals(self):
        modules = {"Lib.A", "Root"}
        rows = census_rows_for(sorted(modules))
        good = census_text(rows, modules, noise=False)
        no_end = "\n".join(json.dumps(r) for r in rows) + "\n"
        with self.assertRaisesRegex(InputError, "WITNESS_CENSUS_INCOMPLETE"):
            parse_census(no_end, modules)
        with self.assertRaisesRegex(InputError, "WITNESS_CENSUS_INCOMPLETE"):
            parse_census(good.replace('"constants": %d' % len(rows), '"constants": %d' % (len(rows) + 1)),
                         modules)
        with self.assertRaisesRegex(InputError, "WITNESS_CENSUS_INCOMPLETE"):
            parse_census(good, modules | {"Lib.B"})
        with self.assertRaisesRegex(InputError, "WITNESS_CENSUS_LINE_INVALID"):
            parse_census(good, {"Lib.A"})
        with self.assertRaisesRegex(InputError, "WITNESS_CENSUS_LINE_INVALID"):
            parse_census('{"module": broken\n' + good, modules)
        mutations = [
            lambda r: r.update(module="Unknown"), lambda r: r.update(kind="lemma"),
            lambda r: r.update(internal=0), lambda r: r.update(direct_sorry="false"),
            lambda r: r.update(axioms=[1]), lambda r: r.update(axioms="propext"),
            lambda r: r.update(sorry_sources=["bad\x01"]), lambda r: r.update(decl=""),
            lambda r: r.update(decl=7), lambda r: r.update(extra=True), lambda r: r.pop("kind"),
            lambda r: r.update(decl="x" * 301),
        ]
        for mutate in mutations:
            bad = deepcopy(rows)
            mutate(bad[0])
            with self.assertRaisesRegex(InputError, "WITNESS_CENSUS_LINE_INVALID"):
                parse_census(census_text(bad, modules), modules)

    def test_census_digest_order_independent(self):
        rows = census_rows_for(["Lib.A", "Lib.B", "Root"])
        shuffled = deepcopy(list(reversed(rows)))
        for r in shuffled:
            r["axioms"].reverse()
            r["sorry_sources"].reverse()
        self.assertEqual(census_digest(rows), census_digest(shuffled))
        self.assertRegex(census_digest(rows), r"\A[0-9a-f]{64}\Z")
        changed = deepcopy(rows)
        changed[0]["internal"] = True
        self.assertNotEqual(census_digest(rows), census_digest(changed))
        self.assertNotEqual(census_digest(rows), census_digest(rows[1:]))

    def test_parse_log_both_formats(self):
        text = ("error: ./Lib/A.lean:1:2: unknown identifier\n"
                "error: Lib/A.lean:4:0: another\n"
                "error: Lib/B.lean: bad import 'Mathlib.Gone'\n"
                "warning: ./Lib/C.lean:3:8: declaration uses 'sorry'\n"
                "warning: Lib/C.lean:9:8: declaration uses `sorry`\n"
                "warning: Lib/D.lean:9:8: unused variable\n"
                "info: ./Lib/E.lean:1:1: error: not a header\n"
                "TH8/X.lean:61:45: error: Function expected at\n"
                "  zero_le\n"
                "TH8/X.lean:35:0: warning: \n"
                "'Mathlib.Data.NNReal.Basic' has been deprecated\n"
                "./TH8/X.lean:80:8: warning: declaration uses `sorry`\n"
                "TH8/X.lean:1:0: info: depends on axioms: [propext]\n"
                "error: no such file or directory (error code: 2)\n"
                "error: build failed\n")
        errors, sorries = parse_log(text)
        self.assertEqual(errors, {"Lib/A.lean": 2, "Lib/B.lean": 1, "TH8/X.lean": 1})
        self.assertEqual(sorries, {"Lib/C.lean": 2, "TH8/X.lean": 1})
        self.assertEqual(parse_log(""), ({}, {}))

    def test_parse_logs_mixes_path_only_and_positioned_messages_of_one_file(self):
        # Real Lake output: an import note without a position next to positioned diagnostics.
        text = ("warning: Lutar/Axioms.lean: imports `Mathlib.Data.NNReal.Basic` from package `mathlib`\n"
                "warning: Lutar/Axioms.lean:74:0: 'Mathlib.Data.NNReal.Basic' has been deprecated\n"
                "error: Lutar/Axioms.lean: bad import 'Mathlib.Gone'\n"
                "error: Lutar/Axioms.lean:3:1: unknown identifier\n"
                "warning: Lutar/Axioms.lean:9:8: declaration uses `sorry`\n")
        self.assertEqual(parse_logs([text, text]), ({"Lutar/Axioms.lean": 2}, {"Lutar/Axioms.lean": 1}))

    def test_parse_logs_normalises_paths(self):
        prefixes = ("/tmp/braid-lean-x/export/", "/work/lutar-lean/")
        text = ("error: /tmp/braid-lean-x/export/Lib/A.lean:1:2: boom\n"
                "/work/lutar-lean/Lib/A.lean:1:2: error: boom\n"
                "error: ././Lib/A.lean:1:2: boom\n"
                "warning: /elsewhere/Lib/A.lean:3:3: declaration uses 'sorry'\n")
        errors, sorries = parse_logs([text], prefixes)
        self.assertEqual(errors, {"Lib/A.lean": 3})
        self.assertEqual(sorries, {"/elsewhere/Lib/A.lean": 1})
        self.assertEqual(parse_logs([text.splitlines()[0]], prefixes)[0], {"Lib/A.lean": 1})

    def test_parse_logs_counts_a_replayed_log_once(self):
        built = ("⚠ [4/9] Built Lutar.Uniqueness (2.0s)\n"
                 "warning: Lutar/Uniqueness.lean:40:8: declaration uses `sorry`\n")
        replayed = ("⚠ [9/12] Replayed Lutar.Uniqueness\n"
                    "warning: Lutar/Uniqueness.lean:40:8: declaration uses `sorry`\n")
        standalone = "./Lutar/Uniqueness.lean:40:8: warning: declaration uses `sorry`\n"
        self.assertEqual(parse_logs([built, replayed, standalone])[1], {"Lutar/Uniqueness.lean": 1})
        # Two different errors that share a position and a first line inside one elaboration both count.
        twice = ("error: Lutar/R.lean:23:21: failed to synthesize instance of type class\n  LT Real\n"
                 "error: Lutar/R.lean:23:21: failed to synthesize instance of type class\n  OfNat Real 0\n")
        self.assertEqual(parse_logs([twice, twice, twice.split("\n  LT")[0]])[0], {"Lutar/R.lean": 2})

    def test_parse_jobs_real_formats(self):
        project = {"Lutar.Axioms", "Lutar.Egyptian", "Lutar.X", "Main", "Lutar.Y", "Lutar.Z", "Lutar.W"}
        text = "\n".join([
            "⚠ [3142/3154] Built Lutar.Axioms (1.9s)",
            "warning: Lutar/Axioms.lean:74:0: 'Mathlib.Data.NNReal.Basic' has been deprecated",
            "✔ [13088/18422] Built Main (6.0s)",
            "✔ [12340/18422] Built Lutar.Axioms:c.o (1.4s)",
            "✔ [18422/18422] Built check:exe (4.7s)",
            "⚠ [2075/2290] Replayed Lutar.Egyptian",
            "ℹ [2076/2290] Replayed Mathlib.Tactic",
            "✖ [2280/2293] Building Lutar.X (1.9s)",
            "✖ [3665/3675] Running Lutar.Y",
            "✖ [3664/3675] Running Mathlib.Analysis.Matrix",
            "✔ [5/9] (Optional) Built Lutar.Z (12ms)",
            "⊘ [6/9] Canceled Lutar.W",
            "  ✔ [7/9] Built Lutar.Egyptian (1ms)",
            "Build completed successfully (9242 jobs).",
        ])
        self.assertEqual(parse_jobs(text, project), {"built": {"Lutar.Axioms", "Main", "Lutar.Z"},
                                                      "reused": {"Lutar.Egyptian"},
                                                      "failed": {"Lutar.X", "Lutar.Y", "Lutar.W"}})
        self.assertEqual(parse_jobs(text, set()), {"built": set(), "reused": set(), "failed": set()})

    def test_lean_imports_follow_lean_identifier_rules(self):
        # A name Lean accepts is read whole, so the imports after it are not lost (Lake's own results).
        self.assertEqual(lean_imports("import Lutar.Λ\nimport B\n"), ["Lutar.Λ", "B"])
        self.assertEqual(lean_imports("import «Lutar».X\nimport B\n"), ["Lutar.X", "B"])
        self.assertEqual(lean_imports("import «a.b».c import B\n"), ["a.b.c", "B"])
        self.assertEqual(lean_imports("import Lutar.x₁ import Müller.αβ import 𝔸.ℕ'\nimport B\n"),
                         ["Lutar.x₁", "Müller.αβ", "𝔸.ℕ'", "B"])
        self.assertEqual(lean_imports("import A\r\nimport B?!\r\n"), ["A", "B?!"])
        # λ, Π, Σ and × are no identifier letters: the name ends before them, and so does the header.
        self.assertEqual(lean_imports("import A\nimport Bλ\nimport C\n"), ["A", "B"])
        self.assertEqual(lean_imports("import A×B\nimport C\n"), ["A"])
        self.assertEqual(lean_imports("import Σ\nimport B\n"), [])
        # A dot continues a name only before an identifier: `A.` is the module A, then the header ends.
        self.assertEqual(lean_imports("import A.\nimport B\n"), ["A"])
        self.assertEqual(import_closure({"Root": lean_imports("import Lib.Λ\nimport Lib.Orphan\n"),
                                         "Lib.Orphan": []}, ["Root"]), {"Root", "Lib.Orphan"})

    def test_lean_imports_match_lakes_own_header_reader(self):
        """Headers where the earlier readers and Lake differ, each with the list Lean 4.35.0's own
        Lean.parseImports' (Lean/Elab/ParseImportsFast.lean, which Lake uses) returned for it."""
        for text, lake in LAKE_HEADERS:
            with self.subTest(text=text):
                self.assertEqual(lean_imports(text), lake)

    def test_source_that_is_not_utf8_has_no_import_lake_could_read(self):
        self.assertEqual(witness_module.source_imports("import Lutar.Λ\nimport B\n".encode()), ["Lutar.Λ", "B"])
        self.assertEqual(witness_module.source_imports(b"import Lib.Orphan\n-- caf\xe9\n"), [])
        self.assertEqual(witness_module.source_imports(b"\xef\xbb\xbfimport A\n"), [])

    def test_parse_census_output_reads_where_each_module_came_from(self):
        modules = {"Lib.A", "Root"}
        rows = census_rows_for(sorted(modules))
        oleans = [olean_record("Init", None), olean_record("Lib.A", "/x/Lib/A.olean"),
                  olean_record("Root", "/x/Root.olean")]
        self.assertEqual(parse_census_output(census_text(rows, modules, oleans=oleans), modules),
                         (rows, oleans))
        good = census_text(rows, modules, oleans=oleans, noise=False)
        for bad in (lambda o: o.update(extra=1), lambda o: o.pop("path"), lambda o: o.update(path=7),
                    lambda o: o.update(path="/x/\x01.olean"), lambda o: o.update(path=""),
                    lambda o: o.update(census_olean=""), lambda o: o.update(census_olean=5),
                    lambda o: o.update(root="Lib")):
            changed = deepcopy(oleans)
            bad(changed[1])
            with self.assertRaisesRegex(InputError, "WITNESS_CENSUS_LINE_INVALID"):
                parse_census_output(census_text(rows, modules, oleans=changed), modules)
        with self.assertRaisesRegex(InputError, "WITNESS_CENSUS_INCOMPLETE"):
            parse_census_output(good.replace('"loaded": 3', '"loaded": 4'), modules)
        with self.assertRaisesRegex(InputError, "WITNESS_CENSUS_INCOMPLETE"):
            parse_census_output(census_text(rows, modules, oleans=oleans + oleans[:1]), modules)
        with self.assertRaisesRegex(InputError, "WITNESS_CENSUS_INCOMPLETE"):
            parse_census_output(good.replace(', "loaded": 3', ""), modules)
        with self.assertRaisesRegex(InputError, "WITNESS_CENSUS_LINE_INVALID"):
            parse_census_output(good + json.dumps(rows[0]) + "\n", modules)

    def test_oleans_in_export_requires_the_export_library(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            library = base / "export" / ".lake/build/lib/lean"
            (library / "Lib").mkdir(parents=True)
            for name in ("Lib/A.olean", "Root.olean"):
                (library / name).write_bytes(b"olean")
            elsewhere = base / "cache" / "Lib"
            elsewhere.mkdir(parents=True)
            (elsewhere / "A.olean").write_bytes(b"planted")
            os.symlink(elsewhere / "A.olean", library / "Lib" / "Link.olean")
            os.symlink(library, base / "via-link")
            honest = [olean_record("Init", None), olean_record("Mathlib.Tactic", "/m/Mathlib/Tactic.olean"),
                      olean_record("Lib.A", str(library / "Lib/A.olean")),
                      olean_record("Root", str(base / "via-link" / "Root.olean"))]
            roots, cwd = {"Lib", "Root"}, base / "export"
            self.assertEqual(oleans_in_export(honest, roots, library, ["Lib.A", "Root"], cwd), 2)
            # A relative path is where Lean ran: the export.
            relative = deepcopy(honest)
            relative[2]["path"] = ".lake/build/lib/lean/Lib/A.olean"
            self.assertEqual(oleans_in_export(relative, roots, library, ["Lib.A", "Root"], cwd), 2)
            for change in (lambda o: o[2].update(path=str(elsewhere / "A.olean")),
                           lambda o: o[2].update(path=None), lambda o: o[2].update(path="Lib/A.olean"),
                           lambda o: o[2].update(census_olean="Lib.Gone", path=str(library / "Lib/Gone.olean")),
                           lambda o: o[3].update(path=str(library / "Lib/A.olean")),
                           lambda o: o.append(olean_record("Lib.Link", str(library / "Lib/Link.olean"))),
                           lambda o: o.pop(3),
                           lambda o: o[1].update(census_olean="Mathlib..Tactic"),
                           lambda o: o[1].update(census_olean="«..».Tactic"),
                           lambda o: o[1].update(census_olean="Mathlib.Tactic x")):
                changed = deepcopy(honest)
                change(changed)
                self.assertIsNone(oleans_in_export(changed, roots, library, ["Lib.A", "Root"], cwd), changed)
            # A module outside the project's namespaces is judged too once the export's library holds it:
            # what the export built must be what Lean read.
            (library / "Mathlib").mkdir()
            (library / "Mathlib/Tactic.olean").write_bytes(b"olean")
            self.assertIsNone(oleans_in_export(honest, roots, library, ["Lib.A", "Root"], cwd))
            honest[1]["path"] = str(library / "Mathlib/Tactic.olean")
            self.assertEqual(oleans_in_export(honest, roots, library, ["Lib.A", "Root"], cwd), 3)
            # Names are read with Lean's escapes, so «weird name» is the file `weird name.olean`.
            (library / "weird name.olean").write_bytes(b"olean")
            odd = honest + [olean_record("«weird name»", str(library / "weird name.olean"))]
            self.assertEqual(oleans_in_export(odd, roots | {"weird name"}, library, ["Lib.A", "Root"], cwd), 4)
            odd[-1]["path"] = str(elsewhere / "weird name.olean")
            self.assertIsNone(oleans_in_export(odd, roots, library, ["Lib.A", "Root"], cwd))

    def test_search_path_check(self):
        with tempfile.TemporaryDirectory() as temp:
            export = Path(temp) / "export"
            library = export / ".lake/build/lib/lean"
            library.mkdir(parents=True)
            (export / "Lib").mkdir()
            dep = Path(temp) / "dep"
            dep.mkdir()
            roots = ["Lib", "Root"]

            def lake_env(entries):
                # A bare `lake env`: Lake's whole environment, the search path one line of it.
                return (f"info: noise\nPATH={dep}/.lake/build/bin:/usr/bin\nLEAN_PATH={':'.join(entries)}\n"
                        "LEAN_SRC_PATH=.\n")

            def check(entries, code=0):
                return search_path_check(code, lake_env(entries), export, library, roots)
            clean = check([str(dep), str(library)])
            self.assertEqual(clean, {"exit_code": 0, "state": "EXPORT_ONLY", "entries": 2, "export_library_entries": 1,
                                     "project_namespaces": 2, "shadowed_namespaces": []})
            self.assertEqual(check([str(dep), ".lake/build/lib/lean"])["state"], "EXPORT_ONLY")
            (dep / "Root.olean").write_bytes(b"planted")
            self.assertEqual(check([str(dep), str(library)])["shadowed_namespaces"], ["Root"])
            (dep / "Root.olean").unlink()
            (dep / "Lib").mkdir()
            shadowed = check([str(library), str(dep)])
            self.assertEqual((shadowed["state"], shadowed["shadowed_namespaces"]), ("SHADOWED", ["Lib"]))
            # A relative entry is read from the export, where Lean runs, and its source tree holds Lib/.
            self.assertEqual(check([".", str(library)])["shadowed_namespaces"], ["Lib"])
            self.assertEqual(check(["."])["state"], "SHADOWED")
            # An empty entry is the filesystem root: Lean 4.35's FilePath.join makes "" and a name "/name".
            self.assertTrue(os.path.isdir("/tmp") and not os.path.exists("/Lib") and not os.path.exists("/Root"))
            self.assertEqual(check(["", str(library)])["state"], "EXPORT_ONLY", "the export's Lib/ is not /Lib")
            rooted = search_path_check(0, lake_env(["", str(library)]), export, library, ["tmp"])
            self.assertEqual((rooted["state"], rooted["shadowed_namespaces"]), ("SHADOWED", ["tmp"]))
            self.assertEqual(search_path_check(0, lake_env([""]), export, library, roots)["state"], "UNVERIFIED")
            # Lean's findOLean wants a directory or an .olean named after the root: a source file is neither.
            (dep / "Lib").rmdir()
            (dep / "Root.lean").write_bytes(b"theorem t : True := trivial\n")
            self.assertEqual(check([str(dep), str(library)])["state"], "EXPORT_ONLY")
            self.assertEqual(check([str(Path(temp) / "nowhere")])["state"], "UNVERIFIED")
            self.assertEqual(search_path_check(1, "error\n", export, library, roots)["state"], "UNVERIFIED")
            self.assertEqual(search_path_check(1, lake_env([str(library)]), export, library, roots)["entries"], 0)
            self.assertEqual(search_path_check(0, "", export, library, roots)["entries"], 0)
            self.assertEqual(search_path_check(0, lake_env([str(library), "\x00"]), export, library, roots)["state"],
                             "UNVERIFIED")
            # printenv's bare path is not Lake's environment, and two search paths are no search path.
            self.assertEqual(search_path_check(0, str(library) + "\n", export, library, roots)["state"], "UNVERIFIED")
            twice = lake_env([str(library)]) + f"LEAN_PATH={library}\n"
            self.assertEqual(search_path_check(0, twice, export, library, roots)["entries"], 0)
            # What an earlier look at the same entries found stays found.
            again = search_path_check(0, lake_env([str(dep), str(library)]), export, library, roots,
                                      earlier=["Root"])
            self.assertEqual((again["state"], again["shadowed_namespaces"]), ("SHADOWED", ["Root"]))
            self.assertTrue(all(check(e)["state"] in SEARCH_PATH_STATES for e in ([], ["."], [str(library)])))

    def test_lean_path_value_is_the_one_line_lake_printed(self):
        value = witness_module.lean_path_value
        text = "info: noise\nPATH=/dep/.lake/build/bin:/usr/bin\nLEAN_PATH=/a:/b\nLEAN_SRC_PATH=/s\n"
        self.assertEqual(value(0, text), "/a:/b")
        self.assertEqual(value(0, "XLEAN_PATH=/x\nLEAN_PATH=\n"), "", "an empty value is one empty entry")
        for code, bad in ((1, text), (0, "/a:/b\n"), (0, text + "LEAN_PATH=/c\n"), (0, "LEAN_PATH=/a\x00\n"),
                          (0, ""), (0, " LEAN_PATH=/a\n")):
            with self.subTest(text=bad, code=code):
                self.assertIsNone(value(code, bad))
        # Lean is given exactly what was checked: LEAN_PATH added to the runner's environment, never
        # `lake env lean`, and none at all when nothing could be read (an empty one would be the root).
        self.assertEqual(witness_module._lean_argv("/a:/b", "./T.lean"), ["env", "LEAN_PATH=/a:/b", "lean", "./T.lean"])
        self.assertEqual(witness_module._lean_argv(None, "./T.lean"), ["lean", "./T.lean"])

    def test_runner_gives_lean_no_shared_library_path_and_the_toolchain_first(self):
        seen = []

        def record(argv, **kw):
            seen.append((argv, kw["env"], kw["isolate_network"]))
            return {"exit_code": 0, "output": b"", "timed_out": False, "truncated": False, "seconds": 0,
                    "network_namespace": NETNS_NOT_REQUESTED}
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(witness_module, "bounded_run", record), \
                mock.patch.dict(os.environ, {"LD_LIBRARY_PATH": "/planted", "LEAN_PATH": "/planted"}):
            witness_module._runner(Path(temp) / "bin", temp)(["env", "LEAN_PATH=/a", "lean", "./T.lean"],
                                                              Path(temp), 60)
        (argv, env, isolated), = seen
        self.assertEqual(argv, ["env", "LEAN_PATH=/a", "lean", "./T.lean"])
        self.assertTrue(env["PATH"].startswith(str(Path(temp) / "bin") + ":"))
        self.assertFalse({"LD_LIBRARY_PATH", "LD_PRELOAD", "LEAN_PATH", "LEAN_SYSROOT"} & set(env))
        self.assertTrue(isolated)

    def test_project_roots_name_every_tracked_file_and_policy_root(self):
        paths = ["Lib/A.lean", "Extra/Lib/Deep.lean", "Λ.lean", "Bad-Name.lean", "foo.bar.lean", "tools/x/Y.lean",
                 "..lean", "README.md"]
        self.assertEqual(witness_module.project_roots(paths, policy()),
                         ["Bad-Name", "Lib", "Main", "Root", "foo", "tools", "Λ"])
        self.assertEqual(witness_module.project_roots([], policy(default_roots=["Top.Sub"], executables=[])),
                         ["Lib", "Top"])

    def test_git_runs_ignore_replace_refs(self):
        self.assertEqual(witness_module._GIT_HARDENING["GIT_NO_REPLACE_OBJECTS"], "1")
        seen = []

        def record(argv, **kw):
            seen.append((argv, kw["env"]))
            return {"exit_code": 1, "output": b"", "timed_out": False, "truncated": False, "seconds": 0,
                    "network_namespace": NETNS_NOT_REQUESTED}
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(witness_module, "bounded_run", record):
            self.assertEqual(witness_module._git_head(Path(temp), temp), (None, "NOT_A_GIT_CHECKOUT"))
            witness_module._runner(Path(temp), temp)(["lake", "--version"], Path(temp), 60)
        self.assertEqual([argv[0] for argv, _env in seen], ["git", "lake"])
        self.assertTrue(all(env["GIT_NO_REPLACE_OBJECTS"] == "1" and env["GIT_CONFIG_NOSYSTEM"] == "1"
                            for _argv, env in seen))


class ObserveTests(_Checkout):
    def test_every_tracked_file_gets_exactly_one_correct_status(self):
        value, lake, repo = self.run_witness()
        tracked = sorted(p for p in FILES if p.endswith(".lean"))
        self.assertEqual([f["path"] for f in value["files"]], tracked)
        self.assertEqual(set(EXPECTED), set(tracked))
        for path, (status, reason, module) in EXPECTED.items():
            entry = by_path(value)[path]
            self.assertEqual((entry["status"], entry["reason"], entry["module"]), (status, reason, module), path)
        self.assertEqual(sum(value["file_totals"].values()), len(tracked))
        self.assertEqual(set(value["file_totals"]), set(STATUSES))
        self.assertEqual(value["file_totals"], {ACCEPTED_DEFAULT: 3, ACCEPTED_REQUEST: 4, ACCEPTED_STANDALONE: 1,
                                                REJECTED: 2, NOT_CHECKED: 7})
        self.assertEqual(value["state"], "KERNEL_EXECUTED")
        self.assertTrue(validate_witness(value, policy()))

    def test_build_runs_in_a_fresh_export_never_the_checkout(self):
        repo, base = self.fresh()
        (repo / "Lib/Untracked.lean").write_bytes(b"theorem u : True := trivial\n")
        (repo / "Lib/Untracked.olean").write_bytes(b"ignored build product\n")
        lake, visible = FakeLake(), []

        def run(argv, cwd, timeout):
            visible.append(any((Path(cwd) / "Lib" / n).exists() for n in ("Untracked.lean", "Untracked.olean")))
            return lake(argv, cwd, timeout)
        value = observe(policy(), repo, toolchain_bin=base / "bin", run=run, at=NOW)
        exports = {cwd for _argv, cwd, _t in lake.calls}
        self.assertEqual(len(exports), 1)
        export = exports.pop()
        self.assertFalse(export.resolve().is_relative_to(repo.resolve()))
        self.assertFalse(export.exists(), "the export directory is removed afterwards")
        self.assertTrue(all(lake.links), ".lake/packages is a link in every step")
        self.assertFalse(any(visible), "untracked and ignored files of the checkout never reach the export")
        self.assertEqual(lake.seen[0], sorted({p.split("/")[0] for p in FILES} | {".lake", "lake-manifest.json"}))
        packages = repo / ".lake" / "packages"
        self.assertTrue((packages / "mathlib" / ".lake/build/lib/lean/Dep0.olean").is_file())
        self.assertTrue((packages / "batteries" / "lakefile.toml").is_file())
        self.assertFalse((repo / ".lake" / "build").exists(), "nothing is built in the checkout")
        self.assertEqual(value["build_tree"], BUILD_TREE)
        self.assertEqual(value["build_tree_files"], len(FILES) + 1)
        self.assertEqual(value["build_tree_skipped_entries"], 0)
        self.assertIs(value["worktree_matches_commit"], True)

    def test_planted_build_products_in_the_checkout_change_nothing(self):
        repo, base = self.fresh()
        for name in ("Lib/Broken", "Lib/Orphan"):
            planted = repo / ".lake/build/lib/lean" / (name + ".olean")
            planted.parent.mkdir(parents=True, exist_ok=True)
            planted.write_bytes(b"crafted object file")
            planted.with_suffix(".trace").write_text("{}")
        value = observe(policy(), repo, toolchain_bin=base, run=FakeLake(), at=NOW)
        self.assertEqual(by_path(value)["Lib/Broken.lean"]["status"], REJECTED)
        self.assertEqual(by_path(value)["Lib/Orphan.lean"]["status"], ACCEPTED_REQUEST)
        self.assertEqual((repo / ".lake/build/lib/lean/Lib/Broken.olean").read_bytes(), b"crafted object file")

    def test_tracked_lean_symlink_is_skipped_not_refused(self):
        repo, base = self.fresh()
        os.symlink("A.lean", repo / "Lib/Link.lean")
        git(repo, "add", "Lib/Link.lean", home=base)
        git(repo, "commit", "-q", "-m", "link", home=base)
        lake = FakeLake()
        value = observe(policy(), repo, toolchain_bin=base, run=lake, at=NOW)
        self.assertNotIn("Lib/Link.lean", by_path(value))
        self.assertEqual(value["build_tree_skipped_entries"], 1)
        self.assertEqual(value["state"], "KERNEL_EXECUTED")
        (repo / "Lib/Link.lean").unlink()
        os.symlink("B.lean", repo / "Lib/Link.lean")
        with self.assertRaisesRegex(InputError, "WITNESS_WORKTREE_DIFFERS_FROM_COMMIT"):
            observe(policy(), repo, toolchain_bin=base, run=FakeLake(), at=NOW)

    def test_commit_that_tracks_lake_directory_is_refused(self):
        repo, base = self.fresh()
        planted = repo / ".lake/build/lib/lean/Lib/Broken.olean"
        planted.parent.mkdir(parents=True, exist_ok=True)
        planted.write_bytes(b"committed object file")
        git(repo, "add", "-f", ".lake/build/lib/lean/Lib/Broken.olean", home=base)
        git(repo, "commit", "-q", "-m", "commit a build product", home=base)
        lake = FakeLake()
        with self.assertRaisesRegex(InputError, "WITNESS_COMMIT_TRACKS_LAKE_DIRECTORY"):
            observe(policy(), repo, toolchain_bin=base, run=lake, at=NOW)
        self.assertEqual(lake.calls, [])

    def test_export_location_inside_a_checkout_is_refused_and_removed(self):
        repo, base = self.fresh()
        inside = repo / "scratch"
        inside.mkdir()
        lake = FakeLake()
        with mock.patch.object(tempfile, "tempdir", str(inside)):
            with self.assertRaisesRegex(InputError, "WITNESS_EXPORT_LOCATION_DENIED"):
                observe(policy(), repo, toolchain_bin=base, run=lake, at=NOW)
        self.assertEqual(list(inside.iterdir()), [])
        self.assertEqual(lake.calls, [])

    def test_default_versus_on_request_follows_import_closure(self):
        value, lake, _repo = self.run_witness()
        self.assertEqual(value["default_build"], {"exit_code": 0, "state": "PASSED",
                                                  "modules_in_import_closure": 3, "closure_modules_with_olean": 3})
        builds = [a for a in lake.names() if a[:2] == ["lake", "build"] and len(a) > 2]
        self.assertEqual(len(builds), 1)
        self.assertEqual(set(builds[0][2:]), {"+Lib.Broken", "+Lib.Deep", "+Lib.Orphan"})
        self.assertIn(["lake", "exe", "check", "--quiet"], lake.names())
        alone = [lean_step(a)[1] for a in lake.names() if lean_step(a) and lean_step(a)[1].startswith("./TH8/")]
        self.assertEqual(alone, ["./TH8/Bad.lean", "./TH8/Solo.lean"])
        self.assertTrue(all(c[2] == 600 for c in lake.calls))
        self.assertEqual(value["on_request_build"], {"exit_code": 1, "modules_requested": 3,
                                                     "modules_accepted": 2, "modules_rejected": 1})
        self.assertEqual(by_path(value)["Lib/Broken.lean"]["error_lines"], 1)
        self.assertEqual(by_path(value)["TH8/Bad.lean"]["error_lines"], 1)

    def test_sorry_warnings_counted_once_across_replays_and_formats(self):
        value, _lake, _repo = self.run_witness()
        # Lib.A's warning is printed by the default build and replayed by the executable build.
        self.assertEqual(by_path(value)["Lib/A.lean"]["elaborator_sorry_declarations"], 1)
        # A standalone run prints PATH:l:c: warning: ..., which counts too.
        self.assertEqual(by_path(value)["TH8/Solo.lean"]["elaborator_sorry_declarations"], 1)
        self.assertEqual(sum(f["elaborator_sorry_declarations"] for f in value["files"]), 2)

    def test_job_lines_counted_per_step(self):
        value, _lake, _repo = self.run_witness()
        counts = {s["name"]: (s["project_modules_built"], s["project_modules_replayed"],
                              s["project_modules_failed"]) for s in value["steps"]}
        self.assertEqual(counts["default_build"], (3, 0, 0))
        self.assertEqual(counts["exe_check"], (2, 0, 0), "replaying Lib.A, built earlier, is not an anomaly")
        self.assertEqual(counts["on_request_build"], (2, 0, 1))
        self.assertEqual(value["project_modules_built_by_this_run"], 7)
        self.assertEqual(value["project_modules_replayed"], 0)

    def test_rejected_module_is_never_counted_as_accepted(self):
        value, lake, _repo = self.run_witness()
        self.assertEqual(by_path(value)["Lib/Broken.lean"]["status"], REJECTED)
        self.assertEqual(by_path(value)["Lib/Broken.lean"]["reason"], "ELABORATION_FAILED")
        self.assertEqual(lake.census_modules, CENSUSED)
        self.assertNotIn("Lib.Broken", lake.programs[0])
        self.assertNotIn("import Main", lake.programs[0])
        self.assertNotIn("Lib.Broken", [m["module"] for m in value["modules"]])
        self.assertNotIn("TH8.Bad", [m["module"] for m in value["modules"]])

    def test_stale_olean_from_before_the_run_is_rejected(self):
        value, _lake, _repo = self.run_witness(stale=("Lib.Orphan",))
        entry = by_path(value)["Lib/Orphan.lean"]
        self.assertEqual((entry["status"], entry["reason"]), (REJECTED, "OLEAN_NOT_WRITTEN_BY_THIS_RUN"))
        self.assertEqual((entry["judging_step"], entry["olean"], entry["built_in_step"]),
                         ("on_request_build", "STALE", None))
        self.assertEqual(value["on_request_build"]["exit_code"], 1)
        self.assertEqual(value["on_request_build"]["modules_rejected"], 2)
        self.assertNotIn("Lib.Orphan", [m["module"] for m in value["modules"]])
        self.assertTrue(validate_witness(value, policy()))

    def test_error_line_rejects_even_with_a_fresh_olean(self):
        value, _lake, _repo = self.run_witness(error_with_olean=("Lib.Deep",))
        entry = by_path(value)["Extra/Lib/Deep.lean"]
        self.assertEqual((entry["status"], entry["reason"], entry["error_lines"]), (REJECTED, "ELABORATION_FAILED", 1))
        self.assertNotIn("Lib.Deep", [m["module"] for m in value["modules"]])

    def test_replayed_project_module_holds_the_witness(self):
        value, _lake, _repo = self.run_witness(fail_request=(), fail_standalone=(), replay_first=("Lib.B",))
        self.assertEqual(value["state"], "HOLD")
        self.assertEqual(value["hold_reasons"], ["ACCEPTED_MODULE_WITHOUT_BUILD_LINE",
                                                 "PROJECT_MODULE_REPLAYED_NOT_BUILT"])
        self.assertEqual(value["project_modules_replayed"], 1)
        self.assertEqual(step_named(value, "default_build")["project_modules_replayed"], 1)
        self.assertTrue(validate_witness(value, policy()))

    def test_module_produced_without_a_build_line_holds_the_witness(self):
        value, _lake, _repo = self.run_witness(fail_request=(), fail_standalone=(), silent=("Lib.B",))
        self.assertEqual((value["state"], value["hold_reasons"]), ("HOLD", ["ACCEPTED_MODULE_WITHOUT_BUILD_LINE"]))
        self.assertEqual(value["project_modules_replayed"], 0)
        self.assertEqual(by_path(value)["Lib/B.lean"]["status"], ACCEPTED_DEFAULT)
        self.assertTrue(validate_witness(value, policy()))

    def test_timed_out_or_truncated_step_holds_the_witness(self):
        for fake, reason in (({"timeout_on": "standalone"}, "STEP_TIMED_OUT"),
                             ({"truncate_on": "request"}, "STEP_OUTPUT_TRUNCATED")):
            with self.subTest(reason=reason):
                value, _lake, _repo = self.run_witness(fail_request=(), fail_standalone=(), **fake)
                self.assertEqual((value["state"], value["hold_reasons"]), ("HOLD", [reason]))
                self.assertTrue(validate_witness(value, policy()))

    def test_theorem_classes_rollups_and_carriers(self):
        value, _lake, _repo = self.run_witness()
        modules = {m["module"]: m for m in value["modules"]}
        self.assertEqual(sorted(modules), ["Lib.A", "Lib.B", "Lib.Deep", "Lib.Orphan", "Root"])
        self.assertEqual(modules["Lib.Deep"]["path"], "Extra/Lib/Deep.lean")
        expected = {
            "Lib.A": (2, 1, 1, 0, 0, 1, 0), "Lib.B": (3, 0, 1, 1, 1, 0, 2), "Root": (2, 1, 1, 0, 0, 1, 0),
            "Lib.Deep": (1, 1, 0, 0, 0, 0, 0), "Lib.Orphan": (1, 1, 0, 0, 0, 0, 0),
        }
        keys = ("user_theorems", CLASS_CLEAN, CLASS_SORRY, CLASS_AXIOM, CLASS_NATIVE,
                "direct_sorry_declarations", "declared_axioms")
        for name, numbers in expected.items():
            self.assertEqual(tuple(modules[name][k] for k in keys), numbers, name)
            self.assertEqual(modules[name]["user_theorems"], sum(modules[name][c] for c in CLASSES))
        self.assertEqual(value["theorem_totals"], dict(zip(keys, (9, 4, 3, 1, 1, 2, 2))))
        self.assertEqual(value["declared_axioms"], [
            {"decl": "Lib.B.myAxiom", "module": "Lib.B", "native_decide_auxiliary": False,
             "user_theorem_load": 2},
            {"decl": NATIVE_AUX, "module": "Lib.B", "native_decide_auxiliary": True, "user_theorem_load": 1},
        ])
        self.assertEqual(value["sorry_sources"], [
            {"decl": "Lib.A.sorried", "module": "Lib.A", "taints": 3, "sole_blocker_for": 2},
            {"decl": "Root.gap", "module": "Root", "taints": 1, "sole_blocker_for": 0},
        ])
        self.assertEqual(value["carrier_theorems"], [
            {"decl": "Lib.A.helper", "role": "NOT_A_THEOREM", "found": False, "axioms": None, "class": None},
            {"decl": "Lib.A.sorried", "role": "SORRY_CARRIER", "found": True, "axioms": ["propext", "sorryAx"],
             "class": CLASS_SORRY},
            {"decl": "Lib.Orphan.carrier", "role": "CLEAN_CARRIER", "found": True, "axioms": sorted(TRUST),
             "class": CLASS_CLEAN},
            {"decl": "Missing.thm", "role": "ABSENT_CARRIER", "found": False, "axioms": None, "class": None},
        ])
        rows = census_rows_for(CENSUSED)
        # Six listed modules of the Lib and Root namespaces, each read from the export's library.
        self.assertEqual(value["census"], {"state": "EXECUTED", "reason": None, "constants": len(rows),
                                           "modules": 5, "modules_loaded": 6, "rows_sha256": census_digest(rows),
                                           "project_oleans_from_export": 6})

    def test_kernel_executed_when_every_gate_passed(self):
        value, lake, repo = self.run_witness(fail_request=(), fail_standalone=())
        self.assertEqual(value["state"], "KERNEL_EXECUTED")
        self.assertEqual(value["hold_reasons"], [])
        self.assertIs(value["kernel_executed_by_this_run"], True)
        self.assertEqual(value["schema"], SCHEMA)
        self.assertEqual(value["observed_at"], NOW.isoformat())
        self.assertEqual(value["commit"], head(repo, repo.parent))
        packages = repo / ".lake" / "packages"
        revs = {name: head(packages / name, repo.parent) for name in PACKAGES}
        self.assertEqual(value["mathlib_revision"], revs["mathlib"])
        self.assertEqual(value["manifest_sha256"], sha256_hex((repo / "lake-manifest.json").read_bytes()))
        self.assertEqual(value["dependency_cache"], {
            "state": "MATCHES_MANIFEST", "manifest_sha256": value["manifest_sha256"],
            "packages": [{"name": n, "manifest_rev": revs[n], "checked_out_rev": revs[n],
                          "state": "MATCHES_MANIFEST"} for n in PACKAGES],
            "dependency_oleans": 2, "origin": "NOT_OBSERVED_BY_THIS_TOOL",
            "dependency_oleans_rechecked_by_kernel": False})
        self.assertEqual(value["policy_section_sha256"], digest(policy()))
        self.assertEqual(value["toolchain"]["pin_in_checkout"], PIN)
        self.assertEqual(value["locked_guard"], {"exit_code": 0, "allowed": 3, "refused": 0, "expected": 3,
                                                 "state": "PASSED"})
        self.assertEqual(value["axiom_check"]["state"], "PASSED")
        self.assertEqual(value["executables"], [{"name": "check", "root": "Main", "exit_code": 0,
                                                 "state": "PASSED"}])
        self.assertEqual(value["file_totals"][REJECTED], 0)
        for flag in _FALSE_FLAGS:
            self.assertIs(value[flag], False, flag)
        self.assertNotIn("network_used", value)
        self.assertFalse(any("sign" in key for key in value))
        self.assertEqual(len(value["steps"]), len(lake.calls))
        for step in value["steps"]:
            self.assertRegex(step["output_sha256"], r"\A[0-9a-f]{64}\Z")
            self.assertEqual(step["network_namespace"], NETNS_EMPTY)
        self.assertEqual(value["network_namespace"], NETNS_EMPTY)
        digest(value)
        self.assertTrue(validate_witness(value, policy()))

    def test_network_namespace_is_what_every_step_observed(self):
        cases = ((NETNS_UNAVAILABLE, NETNS_UNAVAILABLE), (NETNS_NOT_REQUESTED, NETNS_UNAVAILABLE),
                 (lambda kind: NETNS_UNAVAILABLE if kind == "census" else NETNS_EMPTY, NETNS_UNAVAILABLE))
        for namespace, expected in cases:
            with self.subTest(namespace=namespace):
                value, _lake, _repo = self.run_witness(fail_request=(), fail_standalone=(), namespace=namespace)
                self.assertEqual(value["network_namespace"], expected)
                self.assertEqual(value["state"], "KERNEL_EXECUTED", "isolation is recorded, not a gate")
                self.assertTrue(all(s["network_namespace"] in NETNS_STATES for s in value["steps"]))
                self.assertTrue(validate_witness(value, policy()))

    def test_tuple_runner_is_recorded_as_not_isolated(self):
        repo, base = self.fresh()
        lake = FakeLake(fail_request=(), fail_standalone=())

        def legacy(argv, cwd, timeout):
            result = lake(argv, cwd, timeout)
            return result["exit_code"], result["output"], result["seconds"]
        value = observe(policy(), repo, toolchain_bin=base, run=legacy, at=NOW)
        self.assertEqual(value["state"], "KERNEL_EXECUTED")
        self.assertEqual({s["network_namespace"] for s in value["steps"]}, {NETNS_NOT_REQUESTED})
        self.assertEqual(value["network_namespace"], NETNS_UNAVAILABLE)

    def test_log_dir_receives_one_create_exclusive_log_per_step(self):
        repo, base = self.fresh()
        logs = self.base / "logs"
        logs.mkdir()
        value = observe(policy(), repo, toolchain_bin=base / "bin", run=FakeLake(), at=NOW, log_dir=logs)
        self.assertEqual(sorted(p.stem for p in logs.iterdir()), sorted(s["name"] for s in value["steps"]))
        for step in value["steps"]:
            self.assertEqual(sha256_hex((logs / (step["name"] + ".log")).read_bytes()), step["output_sha256"])
        with self.assertRaisesRegex(InputError, "WITNESS_LOG_DIRECTORY_NOT_EMPTY"):
            observe(policy(), repo, toolchain_bin=base, run=FakeLake(), at=NOW, log_dir=logs)

    def test_log_dir_refusals_in_observe(self):
        repo, base = self.fresh()
        victim = self.base / "victim.txt"
        victim.write_text("keep me")
        planted = self.base / "planted"
        planted.mkdir()
        os.symlink(victim, planted / "default_build.log")
        linked = self.base / "linked"
        os.symlink(self.base / "logs-target", linked)
        (self.base / "logs-target").mkdir()
        inside_lean = repo / "logs"
        inside_lean.mkdir()
        inside_packages = repo / ".lake" / "packages" / "logs"
        inside_packages.mkdir()
        for directory, code in ((inside_lean, "WITNESS_LOG_DIRECTORY_DENIED"),
                                (inside_packages, "WITNESS_LOG_DIRECTORY_DENIED"),
                                (ROOT / "tests", "WITNESS_LOG_DIRECTORY_DENIED"),
                                (self.base / "missing", "WITNESS_LOG_DIRECTORY_DENIED"),
                                (linked, "WITNESS_LOG_DIRECTORY_DENIED"),
                                (planted, "WITNESS_LOG_DIRECTORY_NOT_EMPTY")):
            with self.subTest(directory=directory):
                lake = FakeLake()
                with self.assertRaisesRegex(InputError, code):
                    observe(policy(), repo, toolchain_bin=base, run=lake, at=NOW, log_dir=directory)
                self.assertEqual(lake.calls, [])
        self.assertEqual(victim.read_text(), "keep me")

    def test_log_written_through_a_planted_link_is_refused(self):
        repo, base = self.fresh()
        logs = self.base / "logs"
        logs.mkdir()
        victim = self.base / "victim.txt"
        victim.write_text("keep me")
        lake = FakeLake()

        def plant(argv, cwd, timeout):
            if argv == ["lake", "--version"]:
                os.symlink(victim, logs / "default_build.log")
            return lake(argv, cwd, timeout)
        with self.assertRaisesRegex(InputError, "WITNESS_LOG_WRITE_REFUSED"):
            observe(policy(), repo, toolchain_bin=base, run=plant, at=NOW, log_dir=logs)
        self.assertEqual(victim.read_text(), "keep me")

    def assert_hold(self, value, reasons):
        self.assertEqual(value["state"], "HOLD")
        self.assertEqual(value["hold_reasons"], reasons)
        self.assertIs(value["kernel_executed_by_this_run"], True)
        self.assertTrue(validate_witness(value, policy()))

    def test_hold_when_locked_guard_short_or_refused(self):
        for fake in ({"allowed": 2}, {"allowed": 4}, {"refused": 1}, {"guard_exit": 1}):
            with self.subTest(fake=fake):
                value, _lake, _repo = self.run_witness(fail_request=(), **fake)
                self.assertEqual(value["locked_guard"]["state"], "FAILED")
                self.assert_hold(value, ["LOCKED_GUARD_FAILED"])
                self.assertIsNotNone(value["theorem_totals"])

    def test_hold_when_executable_fails(self):
        value, _lake, _repo = self.run_witness(fail_request=(), fail_exe=True)
        self.assert_hold(value, ["EXECUTABLE_FAILED"])
        self.assertEqual(value["executables"][0]["state"], "FAILED")
        self.assertEqual((by_path(value)["Main.lean"]["status"], by_path(value)["Main.lean"]["reason"]),
                         (REJECTED, "ELABORATION_FAILED"))
        self.assertEqual((by_path(value)["Lib/Exe.lean"]["status"], by_path(value)["Lib/Exe.lean"]["reason"]),
                         (REJECTED, "EXECUTABLE_BUILD_FAILED"))
        self.assertNotIn("Lib.Exe", lake_modules(value))

    def test_hold_when_default_build_fails(self):
        value, _lake, _repo = self.run_witness(fail_request=(), fail_default=True)
        self.assert_hold(value, ["DEFAULT_BUILD_FAILED"])
        self.assertEqual(value["default_build"], {"exit_code": 1, "state": "FAILED", "modules_in_import_closure": 3,
                                                  "closure_modules_with_olean": 1})
        self.assertEqual(by_path(value)["Lib/A.lean"]["status"], ACCEPTED_DEFAULT)
        self.assertEqual((by_path(value)["Lib/B.lean"]["status"], by_path(value)["Lib/B.lean"]["reason"],
                          by_path(value)["Lib/B.lean"]["error_lines"]), (REJECTED, "ELABORATION_FAILED", 1))
        self.assertEqual((by_path(value)["Root.lean"]["status"], by_path(value)["Root.lean"]["reason"]),
                         (REJECTED, "DEFAULT_BUILD_FAILED"))

    def test_hold_when_axiom_check_mentions_sorry(self):
        value, _lake, _repo = self.run_witness(fail_request=(), axiom_log="Root.main depends on [sorryAx]\n")
        self.assertEqual(value["axiom_check"]["sorry_axiom_mentions"], 1)
        self.assert_hold(value, ["AXIOM_CHECK_FAILED"])

    def test_census_failure_is_unavailable_not_zero(self):
        value, _lake, _repo = self.run_witness(fail_request=(), census_exit=1)
        self.assert_hold(value, ["AXIOM_CENSUS_UNAVAILABLE"])
        self.assertEqual(value["census"], {"state": "UNAVAILABLE", "reason": "CENSUS_PROGRAM_FAILED",
                                           "constants": None, "modules": None, "modules_loaded": None,
                                           "rows_sha256": None, "project_oleans_from_export": None})
        self.assertIsNone(value["theorem_totals"])
        self.assertEqual((value["modules"], value["declared_axioms"], value["sorry_sources"],
                          value["carrier_theorems"]), ([], [], [], []))

    def assert_unavailable(self, value, reason):
        self.assertEqual(value["state"], "UNAVAILABLE")
        self.assertIs(value["kernel_executed_by_this_run"], False)
        self.assertIsNone(value["theorem_totals"])
        self.assertEqual(value["census"], {"state": "UNAVAILABLE", "reason": reason, "constants": None,
                                           "modules": None, "modules_loaded": None, "rows_sha256": None,
                                           "project_oleans_from_export": None})
        self.assertIsNone(value["lean_search_path"])
        self.assertEqual((value["files"], value["modules"], value["declared_axioms"], value["sorry_sources"],
                          value["carrier_theorems"], value["executables"], value["hold_reasons"]),
                         ([], [], [], [], [], [], []))
        for field in ("default_build", "locked_guard", "axiom_check", "on_request_build"):
            self.assertIsNone(value[field], field)
        self.assertEqual(value["file_totals"], {s: 0 for s in STATUSES})
        self.assertEqual((value["project_modules_built_by_this_run"], value["project_modules_replayed"]), (0, 0))
        for flag in _FALSE_FLAGS:
            self.assertIs(value[flag], False)
        self.assertTrue(validate_witness(value, policy()))

    def test_unavailable_when_dependency_cache_absent_or_short(self):
        for cache in (0, 1):
            with self.subTest(cache=cache):
                value, lake, repo = self.run_witness(make={"cache": cache})
                self.assert_unavailable(value, "DEPENDENCY_CACHE_ABSENT")
                self.assertEqual(lake.names(), [["lean", "--version"], ["lake", "--version"]])
                self.assertEqual(value["dependency_cache"]["state"], "ABSENT")
                self.assertEqual(value["dependency_cache"]["dependency_oleans"], cache)
                self.assertIsNone(value["dependency_cache"]["packages"])
                self.assertEqual(value["mathlib_revision"], head(repo / ".lake/packages/mathlib", repo.parent))

    def test_unavailable_when_packages_dir_missing(self):
        value, lake, _repo = self.run_witness(packages_dir=self.base / "nowhere")
        self.assert_unavailable(value, "DEPENDENCY_CACHE_ABSENT")
        self.assertFalse(any(lake.links))

    def test_explicit_packages_dir_outside_the_checkout(self):
        base = Path(tempfile.mkdtemp(dir=self.base))
        cache = base / "cache"
        repo = make_checkout(base, packages_dir=cache)
        lake = FakeLake(fail_request=(), fail_standalone=())
        value = observe(policy(), repo, toolchain_bin=base, run=lake, at=NOW, packages_dir=cache)
        self.assertEqual(value["state"], "KERNEL_EXECUTED")
        self.assertTrue(all(lake.links))
        self.assertTrue((cache / "mathlib" / ".lake/build/lib/lean/Dep1.olean").is_file())
        default = observe(policy(), repo, toolchain_bin=base, run=FakeLake(), at=NOW)
        self.assert_unavailable(default, "DEPENDENCY_CACHE_ABSENT")
        inside = cache / "logs"
        inside.mkdir()
        with self.assertRaisesRegex(InputError, "WITNESS_LOG_DIRECTORY_DENIED"):
            observe(policy(), repo, toolchain_bin=base, run=FakeLake(), at=NOW, packages_dir=cache, log_dir=inside)

    def test_unavailable_when_a_package_differs_from_the_manifest(self):
        value, lake, _repo = self.run_witness(make={"revs": {"mathlib": "0" * 40}})
        self.assert_unavailable(value, "DEPENDENCY_CACHE_MISMATCH")
        self.assertEqual(lake.names(), [["lean", "--version"], ["lake", "--version"]])
        cache = value["dependency_cache"]
        self.assertEqual(cache["state"], "MISMATCH")
        self.assertEqual([(p["name"], p["state"]) for p in cache["packages"]],
                         [("batteries", "MATCHES_MANIFEST"), ("mathlib", "REVISION_DIFFERS")])
        self.assertEqual(value["mathlib_revision"], "0" * 40)

    def test_unavailable_when_a_package_is_absent_or_not_a_checkout(self):
        for damage, state in ((lambda p: shutil.rmtree(p), "DIRECTORY_ABSENT"),
                              (lambda p: shutil.rmtree(p / ".git"), "NOT_A_GIT_CHECKOUT")):
            with self.subTest(state=state):
                repo, base = self.fresh()
                damage(repo / ".lake/packages/batteries")
                value = observe(policy(), repo, toolchain_bin=base, run=FakeLake(), at=NOW)
                self.assert_unavailable(value, "DEPENDENCY_CACHE_MISMATCH")
                first = value["dependency_cache"]["packages"][0]
                self.assertEqual((first["name"], first["checked_out_rev"], first["state"]), ("batteries", None, state))
                self.assertRegex(first["manifest_rev"], r"\A[0-9a-f]{40}\Z")

    def test_unpinned_or_invalid_manifest_is_a_mismatch(self):
        unpinned = json.dumps({"packages": [{"name": "mathlib", "type": "git", "rev": "main"}]}).encode()
        value, _lake, _repo = self.run_witness(make={"manifest": unpinned})
        self.assert_unavailable(value, "DEPENDENCY_CACHE_MISMATCH")
        self.assertEqual(value["dependency_cache"]["packages"],
                         [{"name": "mathlib", "manifest_rev": None,
                           "checked_out_rev": value["dependency_cache"]["packages"][0]["checked_out_rev"],
                           "state": "NOT_PINNED_BY_MANIFEST"}])
        self.assertIsNone(value["mathlib_revision"])
        for raw in (b"{not json", b'{"packagesDir": "deps", "packages": []}', b'{"packages": [{"name": "../x"}]}',
                    b'{"packages": [{"name": "a", "rev": 1.5}]}'):
            with self.subTest(raw=raw):
                value, _lake, _repo = self.run_witness(make={"manifest": raw})
                self.assert_unavailable(value, "DEPENDENCY_CACHE_MISMATCH")
                self.assertEqual((value["dependency_cache"]["state"], value["dependency_cache"]["packages"]),
                                 ("MANIFEST_INVALID", []))

    def test_no_manifest_runs_and_records_none(self):
        value, _lake, _repo = self.run_witness(make={"manifest": None}, fail_request=(), fail_standalone=())
        self.assertEqual(value["state"], "KERNEL_EXECUTED")
        self.assertIsNone(value["manifest_sha256"])
        self.assertIsNone(value["mathlib_revision"])
        self.assertEqual((value["dependency_cache"]["state"], value["dependency_cache"]["packages"]),
                         ("NO_MANIFEST", []))

    def test_unavailable_when_pin_differs_or_absent(self):
        for pin in (b"leanprover/lean4:v4.34.0\n", None, b"\xff\xfe" + b"x" * 300):
            with self.subTest(pin=pin):
                files = dict(FILES)
                if pin is None:
                    del files["lean-toolchain"]
                else:
                    files["lean-toolchain"] = pin
                value, lake, _repo = self.run_witness(make={"files": files})
                self.assert_unavailable(value, "TOOLCHAIN_UNAVAILABLE_OR_PIN_MISMATCH")
                self.assertEqual(value["toolchain"]["pin_in_checkout"],
                                 None if pin is None else pin.decode("utf-8", "replace").strip()[:200])
                self.assertIsNone(value["manifest_sha256"])
                self.assertIsNone(value["dependency_cache"])
                self.assertEqual(len(lake.calls), 2)

    def test_unavailable_when_the_toolchain_reports_another_lean_version(self):
        good = FakeLake().versions
        for versions in ({"lean": "Lean (version 4.34.0, x86_64-unknown-linux-gnu, Release)\n", "lake": good["lake"]},
                         {"lean": good["lean"], "lake": "Lake version 5.0.0-src+0000000 (Lean version 4.34.0)\n"},
                         {"lean": good["lean"], "lake": "Lake version 5.0.0\n"},
                         {"lean": "Lean (version 4.35.0-rc1)\n", "lake": good["lake"]}):
            with self.subTest(versions=versions):
                value, lake, _repo = self.run_witness(versions=versions)
                self.assert_unavailable(value, "TOOLCHAIN_UNAVAILABLE_OR_PIN_MISMATCH")
                self.assertEqual(len(lake.calls), 2)
                self.assertEqual((value["toolchain"]["lean_version"], value["toolchain"]["lake_version"]),
                                 (versions["lean"].strip(), versions["lake"].strip()))
        self.assertTrue(witness_module.toolchain_matches(
            {"pin_in_checkout": PIN + "-rc1", "lean_version": "Lean (version 4.35.0-rc1)",
             "lake_version": "Lake version 5.0.0 (Lean version 4.35.0-rc1)"}, PIN + "-rc1"))

    def test_unavailable_when_tools_missing(self):
        value, _lake, _repo = self.run_witness(tools_missing=True)
        self.assert_unavailable(value, "TOOLCHAIN_UNAVAILABLE_OR_PIN_MISMATCH")
        self.assertIsNone(value["toolchain"]["lean_version"])
        self.assertIsNone(value["toolchain"]["lake_version"])
        self.assertEqual([s["exit_code"] for s in value["steps"]], [127, 127])

    def test_dirty_tracked_file_is_refused(self):
        repo, base = self.fresh()
        (repo / "Lib/A.lean").write_bytes(b"theorem Lib.A.clean : False := sorry\n")
        lake = FakeLake()
        with self.assertRaisesRegex(InputError, "WITNESS_WORKTREE_DIFFERS_FROM_COMMIT"):
            observe(policy(), repo, toolchain_bin=base, run=lake, at=NOW)
        self.assertEqual(lake.calls, [])

    def test_staged_or_deleted_change_is_refused(self):
        for change in ("staged", "deleted"):
            with self.subTest(change=change):
                repo, base = self.fresh()
                if change == "staged":
                    (repo / "README.md").write_bytes(b"changed\n")
                    git(repo, "add", "README.md", home=base)
                else:
                    (repo / "README.md").unlink()
                with self.assertRaisesRegex(InputError, "WITNESS_WORKTREE_DIFFERS_FROM_COMMIT"):
                    observe(policy(), repo, toolchain_bin=base, run=FakeLake(), at=NOW)

    def test_repository_config_cannot_run_commands(self):
        repo, base = self.fresh()
        marker = self.base / "fsmonitor-ran"
        hook = self.base / "hook.sh"
        hook.write_text("#!/bin/sh\ntouch %s\n" % marker)
        hook.chmod(0o755)
        git(repo, "config", "core.fsmonitor", str(hook), home=base)
        value = observe(policy(), repo, toolchain_bin=base, run=FakeLake(), at=NOW)
        self.assertEqual(value["state"], "KERNEL_EXECUTED")
        self.assertFalse(marker.exists())

    def test_invalid_policy_refused_before_anything_runs(self):
        lake = FakeLake()
        with self.assertRaisesRegex(InputError, "WITNESS_POLICY_INVALID"):
            observe(policy(step_timeout_seconds=1), self.base, toolchain_bin=self.base, run=lake, at=NOW)
        self.assertEqual(lake.calls, [])

    def test_repository_without_lean_files_is_refused(self):
        repo, base = self.fresh(files={"README.md": b"x\n", "lean-toolchain": PIN.encode()})
        with self.assertRaisesRegex(InputError, "WITNESS_FILE_BUDGET_EXCEEDED"):
            observe(policy(), repo, toolchain_bin=base, run=FakeLake(), at=NOW)

    def test_standalone_budget_is_checked_before_building(self):
        files = dict(FILES, **{"TH8/S%02d.lean" % i: b"example : True := trivial\n" for i in range(33)})
        repo, base = self.fresh(files=files)
        lake = FakeLake()
        with self.assertRaisesRegex(InputError, "WITNESS_STANDALONE_BUDGET_EXCEEDED"):
            observe(policy(), repo, toolchain_bin=base, run=lake, at=NOW)
        self.assertEqual(lake.calls, [])

    def test_every_row_names_its_judging_step_and_build_evidence(self):
        value, lake, _repo = self.run_witness()
        rows = by_path(value)
        self.assertEqual({p: rows[p]["judging_step"] for p in ("Root.lean", "Lib/Exe.lean", "Main.lean",
                                                               "Lib/Orphan.lean", "TH8/Solo.lean", "TH8/Skip.lean")},
                         {"Root.lean": "default_build", "Lib/Exe.lean": "exe_check", "Main.lean": "exe_check",
                          "Lib/Orphan.lean": "on_request_build",
                          "TH8/Solo.lean": "standalone_" + sha256_hex(b"TH8/Solo.lean")[:12], "TH8/Skip.lean": None})
        self.assertEqual((rows["Lib/A.lean"]["olean"], rows["Lib/A.lean"]["built_in_step"]), ("FRESH", "default_build"))
        self.assertEqual((rows["Lib/Broken.lean"]["olean"], rows["Lib/Broken.lean"]["built_in_step"],
                          rows["Lib/Broken.lean"]["build_job_failed"]), ("ABSENT", None, True))
        self.assertEqual({rows[p]["olean"] for p in ("TH8/Solo.lean", "Bad-Name.lean", "TH8/Skip.lean")}, {None})
        self.assertEqual(lake.names()[3], ["lake", "env"])
        # Root, Lib, Main, Other, TH8, proposals, tools, lakefile and Bad-Name: one per tracked file's root.
        self.assertEqual(value["lean_search_path"], {
            "exit_code": 0, "state": "EXPORT_ONLY", "entries": 3, "export_library_entries": 1,
            "project_namespaces": 9, "shadowed_namespaces": []})
        self.assertTrue(all(o in OLEAN_STATES for o in (r["olean"] for r in value["files"]) if o is not None))

    def test_project_namespace_planted_in_the_dependency_cache_holds(self):
        """A complete project tree in a dependency's ignored build directory, the package checkout's
        commit unchanged: lake env lean would load it, so the witness must not report it as the commit's."""
        repo, base = self.fresh()
        planted = repo / ".lake/packages/mathlib/.lake/build/lib/lean"
        for name in ("Lib/A.olean", "Lib/B.olean", "Lib/Orphan.olean"):
            (planted / name).parent.mkdir(parents=True, exist_ok=True)
            (planted / name).write_bytes(b"built from a clean Lib.A.sorried")
        lake = FakeLake(fail_request=(), fail_standalone=())
        value = observe(policy(), repo, toolchain_bin=base, run=lake, at=NOW)
        self.assertEqual(value["dependency_cache"]["state"], "MATCHES_MANIFEST", "commits alone do not see it")
        self.assertEqual((value["state"], value["hold_reasons"]),
                         ("HOLD", ["AXIOM_CENSUS_UNAVAILABLE", "LEAN_SEARCH_PATH_SHADOWS_PROJECT"]))
        self.assertEqual((value["lean_search_path"]["state"], value["lean_search_path"]["shadowed_namespaces"]),
                         ("SHADOWED", ["Lib"]))
        self.assertEqual((value["census"]["state"], value["census"]["reason"]),
                         ("UNAVAILABLE", "CENSUS_OLEAN_OUTSIDE_EXPORT"))
        self.assertIsNone(value["theorem_totals"])
        self.assertEqual(step_named(value, "axiom_census")["exit_code"], 0)
        self.assertTrue(validate_witness(value, policy()))
        forged = deepcopy(value)
        forged.update(hold_reasons=["AXIOM_CENSUS_UNAVAILABLE"])
        with self.assertRaisesRegex(InputError, "WITNESS_HOLD_REASONS_DRIFT"):
            validate_witness(forged, policy())
        forged["lean_search_path"].update(state="EXPORT_ONLY")
        with self.assertRaisesRegex(InputError, "WITNESS_SEARCH_PATH_INVALID"):
            validate_witness(forged, policy())

    def test_programs_planted_on_lakes_own_path_never_run(self):
        """The review's repro (lake-env-path-runs-dependency-lean): a `lean` in a dependency's ignored
        build directory, which `lake env` puts first on PATH, hides sorryAx from the axiom check and
        the census. The Lean steps run the toolchain's lean instead, with the search path the witness
        read from Lake itself, so the planted program never runs and the sorry stays visible."""
        repo, base = self.fresh()
        lake = LakeEnvPlanted(fail_request=(), fail_standalone=(),
                              axiom_log="'Root.main' depends on axioms: [sorryAx]\n")
        value = observe(policy(), repo, toolchain_bin=base, run=lake, at=NOW)
        self.assertEqual((value["state"], value["hold_reasons"]), ("HOLD", ["AXIOM_CHECK_FAILED"]))
        self.assertEqual(lake.planted_runs, [])
        self.assertEqual(value["dependency_cache"]["state"], "MATCHES_MANIFEST", "commits alone do not see it")
        self.assertEqual((value["axiom_check"]["state"], value["axiom_check"]["sorry_axiom_mentions"]), ("FAILED", 1))
        self.assertEqual(value["theorem_totals"][CLASS_SORRY], 3)
        carrier = next(c for c in value["carrier_theorems"] if c["decl"] == "Lib.A.sorried")
        self.assertEqual((carrier["class"], carrier["axioms"]), (CLASS_SORRY, ["propext", "sorryAx"]))
        # Each Lean step got exactly the search path that Lake printed and the witness checked.
        printed = witness_module.lean_path_value(0, lake.lake_env(lake.calls[0][1]))
        self.assertEqual(lake.lean_paths, [printed.split(":")] * 5)
        self.assertTrue(validate_witness(value, policy()))

    def test_search_path_is_read_from_lake_itself_not_a_program_on_its_path(self):
        """`lake env printenv LEAN_PATH` would run a planted printenv that hides a planted namespace."""
        repo, base = self.fresh()
        (repo / ".lake/packages/mathlib/.lake/build/lib/lean/TH8").mkdir()
        lake = LakeEnvPlanted(plant_lean=False, fail_request=(), fail_standalone=())
        value = observe(policy(), repo, toolchain_bin=base, run=lake, at=NOW)
        self.assertEqual((value["lean_search_path"]["state"], value["lean_search_path"]["shadowed_namespaces"]),
                         ("SHADOWED", ["TH8"]))
        self.assertEqual(lake.planted_runs, [])
        self.assertEqual((value["state"], value["hold_reasons"]), ("HOLD", ["LEAN_SEARCH_PATH_SHADOWS_PROJECT"]))
        self.assertEqual(by_path(value)["TH8/Solo.lean"]["reason"], "LEAN_SEARCH_PATH_NOT_EXPORT_ONLY")
        self.assertTrue(validate_witness(value, policy()))

    def test_census_that_read_a_project_olean_elsewhere_is_unavailable(self):
        value, _lake, _repo = self.run_witness(fail_request=(), fail_standalone=(),
                                               census_paths={"Lib.Deep": "/elsewhere/Lib/Deep.olean"})
        self.assertEqual(value["lean_search_path"]["state"], "EXPORT_ONLY")
        self.assertEqual((value["state"], value["hold_reasons"]), ("HOLD", ["AXIOM_CENSUS_UNAVAILABLE"]))
        self.assertEqual(value["census"]["reason"], "CENSUS_OLEAN_OUTSIDE_EXPORT")
        self.assertEqual((value["modules"], value["sorry_sources"], value["carrier_theorems"]), ([], [], []))
        self.assertTrue(validate_witness(value, policy()))
        self.assertIn(value["census"]["reason"], CENSUS_REASONS)
        # A module that is not of a project namespace is not the export's to vouch for ...
        value, _lake, _repo = self.run_witness(fail_request=(), fail_standalone=(),
                                               census_paths={"Mathlib.Tactic": "/elsewhere/Mathlib/Tactic.olean"})
        self.assertEqual(value["state"], "KERNEL_EXECUTED")
        # ... unless the export built it: then Lean must have read the export's own file.
        for paths, state in (({}, "EXECUTED"), ({"Mathlib.Tactic": "/elsewhere/Mathlib/Tactic.olean"}, "UNAVAILABLE")):
            with self.subTest(paths=paths):
                repo, base = self.fresh()
                value = observe(policy(), repo, toolchain_bin=base, at=NOW,
                                run=BuildsUnderMathlib(fail_request=(), fail_standalone=(), census_paths=paths))
                self.assertEqual(value["census"]["state"], state)
                # Seven listed modules and Mathlib.Tactic, each read from the export's library.
                self.assertEqual(value["census"]["project_oleans_from_export"], 8 if not paths else None)
                self.assertTrue(validate_witness(value, policy()))

    def test_search_path_unreadable_or_missing_the_export_holds(self):
        value, lake, _repo = self.run_witness(fail_request=(), fail_standalone=(), search_exit=1)
        # Lean then gets no LEAN_PATH at all, so the census cannot load the project's modules.
        self.assertEqual(value["hold_reasons"], ["AXIOM_CENSUS_UNAVAILABLE", "LEAN_SEARCH_PATH_UNVERIFIED"])
        self.assertEqual(value["census"]["reason"], "CENSUS_PROGRAM_FAILED")
        # The guard, the axiom check, TH8/Bad, TH8/Solo and the census.
        self.assertEqual(lake.lean_paths, [None] * 5)
        self.assertEqual(value["lean_search_path"], {"exit_code": 1, "state": "UNVERIFIED", "entries": 0,
                                                     "export_library_entries": 0, "project_namespaces": 9,
                                                     "shadowed_namespaces": []})
        self.assertTrue(validate_witness(value, policy()))
        value, _lake, _repo = self.run_witness(
            fail_request=(), fail_standalone=(),
            search_entries=lambda cwd: [str(cwd / ".lake/packages/mathlib/.lake/build/lib/lean")])
        self.assertEqual(value["hold_reasons"], ["AXIOM_CENSUS_UNAVAILABLE", "LEAN_SEARCH_PATH_UNVERIFIED"])
        self.assertTrue(validate_witness(value, policy()))

    def test_relative_search_path_entry_reaches_the_export_sources(self):
        value, _lake, _repo = self.run_witness(
            fail_request=(), fail_standalone=(),
            search_entries=lambda cwd: [".", str(cwd / ".lake/build/lib/lean")])
        # "." is the export: its source directories are namespaces Lean would look for modules in, while
        # Root.lean, Main.lean, lakefile.lean and Bad-Name.lean are sources, not .olean files.
        self.assertEqual(value["lean_search_path"]["shadowed_namespaces"],
                         ["Lib", "Other", "TH8", "proposals", "tools"])
        self.assertEqual(value["hold_reasons"], ["AXIOM_CENSUS_UNAVAILABLE", "LEAN_SEARCH_PATH_SHADOWS_PROJECT"])
        self.assertEqual((by_path(value)["TH8/Solo.lean"]["status"], by_path(value)["TH8/Solo.lean"]["reason"]),
                         (REJECTED, "LEAN_SEARCH_PATH_NOT_EXPORT_ONLY"))
        self.assertTrue(validate_witness(value, policy()))

    def test_module_built_by_an_earlier_step_of_the_run_is_accepted(self):
        repo, base = self.fresh()
        value = observe(policy(), repo, toolchain_bin=base, run=WideDefault(fail_request=(), fail_standalone=()),
                        at=NOW)
        row = by_path(value)["Lib/Orphan.lean"]
        self.assertEqual((row["status"], row["judging_step"], row["olean"], row["built_in_step"]),
                         (ACCEPTED_REQUEST, "on_request_build", "FRESH", "default_build"))
        self.assertEqual((value["state"], value["hold_reasons"]), ("KERNEL_EXECUTED", []))
        self.assertIn("Lib.Orphan", lake_modules(value))

    def test_failed_job_line_rejects_even_with_a_fresh_olean(self):
        for fail_first in (False, True):
            with self.subTest(fail_first=fail_first):
                repo, base = self.fresh()
                value = observe(policy(), repo, toolchain_bin=base,
                                run=CrashAfterWrite(fail_first=fail_first, fail_request=(), fail_standalone=()),
                                at=NOW)
                row = by_path(value)["Lib/Orphan.lean"]
                self.assertEqual((row["status"], row["reason"], row["error_lines"], row["olean"],
                                  row["build_job_failed"]), (REJECTED, "BUILD_JOB_FAILED", 0, "FRESH", True))
                self.assertNotIn("Lib.Orphan", lake_modules(value))
                self.assertEqual(value["on_request_build"]["modules_rejected"], 1)
                self.assertTrue(validate_witness(value, policy()))

    def test_build_line_after_the_judging_step_does_not_count(self):
        repo, base = self.fresh()
        value = observe(policy(), repo, toolchain_bin=base,
                        run=LateBuildLine(fail_request=(), fail_standalone=(), silent=("Lib.B",)), at=NOW)
        row = by_path(value)["Lib/B.lean"]
        self.assertEqual((row["status"], row["judging_step"], row["built_in_step"]),
                         (ACCEPTED_DEFAULT, "default_build", "exe_check"))
        self.assertEqual((value["state"], value["hold_reasons"]), ("HOLD", ["ACCEPTED_MODULE_WITHOUT_BUILD_LINE"]))
        self.assertTrue(validate_witness(value, policy()))

    def test_build_line_hold_is_re_derived_when_the_counts_match(self):
        """The review's case: a module the policy does not check is built too, so as many modules were
        built as were accepted, yet one accepted module has no build line."""
        repo, base = self.fresh()
        value = observe(policy(), repo, toolchain_bin=base, at=NOW,
                        run=AlsoBuildsScratch(fail_request=(), fail_standalone=(), silent=("Lib.B",)))
        accepted = value["file_totals"][ACCEPTED_DEFAULT] + value["file_totals"][ACCEPTED_REQUEST]
        self.assertEqual((value["project_modules_built_by_this_run"], accepted), (8, 8))
        self.assertEqual((by_path(value)["proposals/Scratch.lean"]["built_in_step"],
                          by_path(value)["Lib/B.lean"]["built_in_step"]), ("on_request_build", None))
        self.assertEqual((value["state"], value["hold_reasons"]), ("HOLD", ["ACCEPTED_MODULE_WITHOUT_BUILD_LINE"]))
        self.assertTrue(validate_witness(value, policy()))
        forged = deepcopy(value)
        forged.update(hold_reasons=[], state="KERNEL_EXECUTED")
        with self.assertRaisesRegex(InputError, "WITNESS_HOLD_REASONS_DRIFT"):
            validate_witness(forged, policy())

    def test_standalone_file_needs_an_export_only_search_path(self):
        repo, base = self.fresh()
        (repo / ".lake/packages/mathlib/.lake/build/lib/lean/TH8").mkdir()
        value = observe(policy(), repo, toolchain_bin=base, run=FakeLake(fail_request=(), fail_standalone=()), at=NOW)
        self.assertEqual((value["state"], value["hold_reasons"]), ("HOLD", ["LEAN_SEARCH_PATH_SHADOWS_PROJECT"]))
        self.assertEqual(value["lean_search_path"]["shadowed_namespaces"], ["TH8"])
        row = by_path(value)["TH8/Solo.lean"]
        self.assertEqual((row["status"], row["reason"], row["error_lines"]),
                         (REJECTED, "LEAN_SEARCH_PATH_NOT_EXPORT_ONLY", 0))
        self.assertEqual(step_named(value, row["judging_step"])["exit_code"], 0, "Lean itself was content")
        self.assertEqual(value["census"]["state"], "EXECUTED", "no census module is of the TH8 namespace")
        self.assertTrue(validate_witness(value, policy()))

        def accept(v):
            by_path(v)["TH8/Solo.lean"].update(status=ACCEPTED_STANDALONE, reason=None)
            v["file_totals"][REJECTED] -= 1
            v["file_totals"][ACCEPTED_STANDALONE] += 1
        forged = deepcopy(value)
        accept(forged)
        with self.assertRaisesRegex(InputError, "WITNESS_FILE_VERDICT_DRIFT"):
            validate_witness(forged, policy())
        value, _lake, _repo = self.run_witness(fail_request=(), fail_standalone=(), search_exit=1)
        self.assertEqual((by_path(value)["TH8/Solo.lean"]["status"], by_path(value)["TH8/Solo.lean"]["reason"]),
                         (REJECTED, "LEAN_SEARCH_PATH_NOT_EXPORT_ONLY"))

    def test_namespace_written_into_the_cache_during_the_run_is_found(self):
        repo, base = self.fresh()
        lake = PlantsDuringRequest(fail_request=(), fail_standalone=())
        value = observe(policy(), repo, toolchain_bin=base, run=lake, at=NOW)
        names = lake.names()
        self.assertLess(names.index(["lake", "env"]),
                        next(i for i, a in enumerate(names) if a[:2] == ["lake", "build"] and len(a) > 2),
                        "the first look came before the planting step")
        self.assertEqual((value["lean_search_path"]["state"], value["lean_search_path"]["shadowed_namespaces"]),
                         ("SHADOWED", ["TH8"]))
        self.assertEqual((value["state"], value["hold_reasons"]), ("HOLD", ["LEAN_SEARCH_PATH_SHADOWS_PROJECT"]))
        self.assertEqual(by_path(value)["TH8/Solo.lean"]["reason"], "LEAN_SEARCH_PATH_NOT_EXPORT_ONLY")
        self.assertTrue(validate_witness(value, policy()))

    def test_non_ascii_project_namespace_planted_in_the_cache_holds(self):
        """Λ.lean has no ASCII module name, yet Lean resolves `import Λ` on the search path like any other."""
        repo, base = self.fresh(files=dict(FILES, **{"Λ.lean": b"theorem lam : True := trivial\n"}))
        planted = repo / ".lake/packages/mathlib/.lake/build/lib/lean/Λ.olean"
        planted.write_bytes(b"planted")
        value = observe(policy(), repo, toolchain_bin=base, run=FakeLake(fail_request=(), fail_standalone=()), at=NOW)
        self.assertEqual((by_path(value)["Λ.lean"]["status"], by_path(value)["Λ.lean"]["reason"]),
                         (NOT_CHECKED, "NOT_A_WORKSPACE_MODULE"))
        self.assertEqual((value["lean_search_path"]["project_namespaces"],
                          value["lean_search_path"]["shadowed_namespaces"]), (10, ["Λ"]))
        self.assertEqual((value["state"], value["hold_reasons"]), ("HOLD", ["LEAN_SEARCH_PATH_SHADOWS_PROJECT"]))
        self.assertTrue(validate_witness(value, policy()))
        planted.unlink()
        value = observe(policy(), repo, toolchain_bin=base, run=FakeLake(fail_request=(), fail_standalone=()), at=NOW)
        self.assertEqual(value["state"], "KERNEL_EXECUTED")


class _Witnesses(TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory()
        try:
            base = Path(temp.name)
            repo = make_checkout(base, name="good")
            cls.good = observe(policy(), repo, toolchain_bin=base, run=FakeLake(fail_request=()), at=NOW)
            repo = make_checkout(base, name="cacheless", cache=0)
            cls.unavailable = observe(policy(), repo, toolchain_bin=base, run=FakeLake(), at=NOW)
            repo = make_checkout(base, name="guard")
            cls.hold = observe(policy(), repo, toolchain_bin=base, run=FakeLake(allowed=2), at=NOW)
            repo = make_checkout(base, name="rejecting")
            cls.rejecting = observe(policy(), repo, toolchain_bin=base, run=FakeLake(), at=NOW)
            repo = make_checkout(base, name="census-failed")
            cls.census_failed = observe(policy(), repo, toolchain_bin=base, run=FakeLake(census_exit=1), at=NOW)
            repo = make_checkout(base, name="default-failed")
            cls.default_failed = observe(policy(), repo, toolchain_bin=base, run=FakeLake(fail_default=True), at=NOW)
        finally:
            temp.cleanup()

    def refuses(self, value, code):
        with self.assertRaisesRegex(InputError, code):
            validate_witness(value, policy())

    def mutated(self, change, base=None):
        value = deepcopy(self.good if base is None else base)
        change(value)
        return value


def set_exit(value, gate, code, *, step=None):
    """Forge one gate's exit code in its summary and (by default) in its matching step."""
    names = {"default_build": "default_build", "locked_guard": "locked_guard", "axiom_check": "axiom_check"}
    if gate == "exe":
        value["executables"][0]["exit_code"] = code
        name = "exe_" + value["executables"][0]["name"]
    else:
        value[gate]["exit_code"] = code
        name = names[gate]
    if step is not False:
        step_named(value, name)["exit_code"] = code if step is None else step


class ValidateWitnessTests(_Witnesses):
    def test_baselines_validate(self):
        self.assertEqual(self.good["state"], "KERNEL_EXECUTED")
        self.assertTrue(validate_witness(self.good, policy()))
        self.assertEqual(self.unavailable["state"], "UNAVAILABLE")
        self.assertTrue(validate_witness(self.unavailable, policy()))
        self.assertEqual((self.hold["state"], self.hold["hold_reasons"]), ("HOLD", ["LOCKED_GUARD_FAILED"]))
        self.assertTrue(validate_witness(self.hold, policy()))
        self.assertEqual(set(HOLD_REASONS), {
            "ACCEPTED_MODULE_WITHOUT_BUILD_LINE", "AXIOM_CENSUS_UNAVAILABLE", "AXIOM_CHECK_FAILED",
            "DEFAULT_BUILD_FAILED", "EXECUTABLE_FAILED", "LEAN_SEARCH_PATH_SHADOWS_PROJECT",
            "LEAN_SEARCH_PATH_UNVERIFIED", "LOCKED_GUARD_FAILED", "PROJECT_MODULE_REPLAYED_NOT_BUILT",
            "STEP_OUTPUT_TRUNCATED", "STEP_TIMED_OUT"})
        self.assertEqual(list(HOLD_REASONS), sorted(HOLD_REASONS))
        self.assertTrue(all(re.fullmatch(r"[A-Z_]{3,80}", r) for r in HOLD_REASONS))

    def test_closed_top_level_fields(self):
        self.refuses(self.mutated(lambda v: v.update(signature="x")), "WITNESS_FIELDS_INVALID")
        self.refuses(self.mutated(lambda v: v.update(network_used=False)), "WITNESS_FIELDS_INVALID")
        self.refuses(self.mutated(lambda v: v.pop("census")), "WITNESS_FIELDS_INVALID")
        self.refuses([self.good], "WITNESS_FIELDS_INVALID")

    def test_binding(self):
        # v2 had no search-path record or per-row build evidence: its shape is not this one.
        self.assertEqual(SCHEMA, "szl.database-braid-lean-witness/v3")
        for change in (lambda v: v.update(schema="szl.database-braid-lean-witness/v1"),
                       lambda v: v.update(schema="szl.database-braid-lean-witness/v2"),
                       lambda v: v.update(repository="szl-holdings/other"),
                       lambda v: v.update(commit="A" * 40), lambda v: v.update(commit="a" * 39),
                       lambda v: v.update(worktree_matches_commit=1),
                       lambda v: v.update(worktree_matches_commit=False),
                       lambda v: v.update(build_tree="CHECKOUT_WORKING_TREE"),
                       lambda v: v.update(build_tree=None),
                       lambda v: v.update(policy_section_sha256="0" * 64)):
            self.refuses(self.mutated(change), "WITNESS_BINDING_INVALID")
        with self.assertRaisesRegex(InputError, "WITNESS_BINDING_INVALID"):
            validate_witness(self.good, policy(step_timeout_seconds=601))

    def test_false_flags_must_be_false(self):
        for flag in _FALSE_FLAGS:
            for bad in (True, 0, None, "false"):
                self.refuses(self.mutated(lambda v: v.update({flag: bad})), "WITNESS_FALSE_AUTHORITY_CLAIM")

    def test_state_field(self):
        for change in (lambda v: v.update(state="SIGNED"), lambda v: v.update(state="AUTHORIZED"),
                       lambda v: v.update(kernel_executed_by_this_run=False),
                       lambda v: v.update(kernel_executed_by_this_run=1)):
            self.refuses(self.mutated(change), "WITNESS_STATE_INVALID")
        self.refuses(self.mutated(lambda v: v.update(kernel_executed_by_this_run=True), self.unavailable),
                     "WITNESS_STATE_INVALID")

    def test_scalar_fields(self):
        for change in (lambda v: v.update(observed_at="yesterday"), lambda v: v.update(observed_at=7),
                       lambda v: v.update(observed_at="2026-11-19T07:15:00"),
                       lambda v: v.update(build_tree_files=-1), lambda v: v.update(build_tree_files=True),
                       lambda v: v.update(build_tree_files=3),
                       lambda v: v.update(build_tree_skipped_entries=1.0),
                       lambda v: v["toolchain"].update(pin_required="leanprover/lean4:v4.34.0"),
                       lambda v: v["toolchain"].update(lean_version=None),
                       lambda v: v.update(toolchain=None)):
            self.refuses(self.mutated(change), "WITNESS_FIELDS_INVALID")

    def test_steps(self):
        for change in (lambda v: v["steps"][0].update(exit_code=True),
                       lambda v: v["steps"][0].update(exit_code=0.0),
                       lambda v: v["steps"][0].update(seconds=1.5),
                       lambda v: v["steps"][0].update(seconds=-1),
                       lambda v: v["steps"][0].update(output_sha256="A" * 64),
                       lambda v: v["steps"][0].update(name="Bad-Name"),
                       lambda v: v["steps"][3].update(name="default_build"),
                       lambda v: v["steps"][0].update(timed_out=0),
                       lambda v: v["steps"][0].update(truncated=None),
                       lambda v: v["steps"][0].update(network_namespace="ISOLATED"),
                       lambda v: v["steps"][0].update(project_modules_failed=-1),
                       lambda v: v["steps"][0].update(extra=1),
                       lambda v: v["steps"][0].pop("seconds"),
                       lambda v: v["steps"].reverse(),
                       lambda v: v.update(steps=v["steps"] * 10),
                       lambda v: v.update(steps=[]),
                       lambda v: v.update(steps={})):
            self.refuses(self.mutated(change), "WITNESS_FIELDS_INVALID")

    def test_step_exit_codes_are_ones_a_process_can_return(self):
        # A failed census step is read only as "not 0", so nothing else bounds its exit code.
        self.assertEqual(step_named(self.census_failed, "axiom_census")["exit_code"], 1)

        def census_exit(code):
            return self.mutated(lambda v: step_named(v, "axiom_census").update(exit_code=code), self.census_failed)
        for code in (256, -256, 2 ** 70):
            self.refuses(census_exit(code), "WITNESS_FIELDS_INVALID")
        for code in (-9, 127, 255):
            self.assertTrue(validate_witness(census_exit(code), policy()))

    def test_network_namespace_must_be_what_the_steps_observed(self):
        self.refuses(self.mutated(lambda v: v["steps"][4].update(network_namespace=NETNS_UNAVAILABLE)),
                     "WITNESS_NETWORK_NAMESPACE_DRIFT")
        self.refuses(self.mutated(lambda v: v.update(network_namespace=NETNS_UNAVAILABLE)),
                     "WITNESS_NETWORK_NAMESPACE_DRIFT")
        self.refuses(self.mutated(lambda v: v.update(network_namespace=NETNS_NOT_REQUESTED)),
                     "WITNESS_NETWORK_NAMESPACE_DRIFT")

        def unisolated(v):
            for s in v["steps"]:
                s["network_namespace"] = NETNS_UNAVAILABLE
        self.assertTrue(validate_witness(self.mutated(lambda v: (unisolated(v), v.update(
            network_namespace=NETNS_UNAVAILABLE))), policy()))

    def test_project_module_totals_are_re_derived_from_steps(self):
        self.refuses(self.mutated(lambda v: v.update(project_modules_built_by_this_run=9)),
                     "WITNESS_PROJECT_MODULE_TOTALS_DRIFT")
        self.refuses(self.mutated(lambda v: step_named(v, "default_build").update(project_modules_built=2)),
                     "WITNESS_PROJECT_MODULE_TOTALS_DRIFT")
        self.refuses(self.mutated(lambda v: v.update(project_modules_replayed=True)), "WITNESS_FIELDS_INVALID")

    def test_golden_forgery_every_gate_exit_one_with_kernel_executed(self):
        def all_gates_fail(v):
            for gate in ("default_build", "locked_guard", "axiom_check", "exe"):
                set_exit(v, gate, 1)
        self.refuses(self.mutated(all_gates_fail), "WITNESS_GATE_DRIFT")
        for gate in ("default_build", "locked_guard", "axiom_check", "exe"):
            with self.subTest(gate=gate):
                self.refuses(self.mutated(lambda v: set_exit(v, gate, 1)), "WITNESS_GATE_DRIFT")
                self.refuses(self.mutated(lambda v: set_exit(v, gate, 1, step=False)), "WITNESS_GATE_DRIFT")
                self.refuses(self.mutated(lambda v: set_exit(v, gate, 0, step=1)), "WITNESS_GATE_DRIFT")

    def test_golden_forgery_rejected_files_relabelled_accepted(self):
        def relabel(v):
            for row in v["files"]:
                if row["status"] == REJECTED and row["module"]:
                    row.update(status=ACCEPTED_REQUEST, reason=None)
                    v["file_totals"][REJECTED] -= 1
                    v["file_totals"][ACCEPTED_REQUEST] += 1
        rejected = [f for f in self.rejecting["files"] if f["status"] == REJECTED]
        self.assertEqual(self.rejecting["state"], "KERNEL_EXECUTED")
        self.assertTrue(len(rejected) == 2 and all(f["error_lines"] > 0 for f in rejected))
        self.refuses(self.mutated(relabel, self.rejecting), "WITNESS_ACCEPTED_WITH_ERRORS")

        def standalone(v):
            row = by_path(v)["TH8/Bad.lean"]
            row.update(status=ACCEPTED_STANDALONE, reason=None)
            v["file_totals"][REJECTED] -= 1
            v["file_totals"][ACCEPTED_STANDALONE] += 1
        self.refuses(self.mutated(standalone), "WITNESS_ACCEPTED_WITH_ERRORS")

    def test_golden_forgery_closure_oleans_zero_with_passed(self):
        self.refuses(self.mutated(lambda v: v["default_build"].update(closure_modules_with_olean=0)),
                     "WITNESS_GATE_DRIFT")
        self.refuses(self.mutated(lambda v: v["default_build"].update(closure_modules_with_olean=4)),
                     "WITNESS_GATE_DRIFT")

    def test_golden_forgery_sorry_axiom_mentions_with_passed(self):
        self.refuses(self.mutated(lambda v: v["axiom_check"].update(sorry_axiom_mentions=7)), "WITNESS_GATE_DRIFT")
        self.refuses(self.mutated(lambda v: v["locked_guard"].update(refused=1)), "WITNESS_GATE_DRIFT")
        self.refuses(self.mutated(lambda v: v["locked_guard"].update(allowed=2)), "WITNESS_GATE_DRIFT")
        self.refuses(self.mutated(lambda v: v["locked_guard"].update(expected=2, allowed=2)), "WITNESS_GATE_DRIFT")

    def test_golden_forgery_replayed_modules_with_kernel_executed(self):
        def replayed(v):
            v["project_modules_replayed"] = 1
            step_named(v, "default_build")["project_modules_replayed"] = 1
        self.refuses(self.mutated(replayed), "WITNESS_HOLD_REASONS_DRIFT")
        self.refuses(self.mutated(lambda v: (replayed(v), v.update(
            hold_reasons=["PROJECT_MODULE_REPLAYED_NOT_BUILT"]))), "WITNESS_STATE_DRIFT")
        self.assertTrue(validate_witness(self.mutated(lambda v: (replayed(v), v.update(
            hold_reasons=["PROJECT_MODULE_REPLAYED_NOT_BUILT"], state="HOLD"))), policy()))

    def test_accepted_modules_must_have_been_built(self):
        self.assertEqual((self.good["project_modules_built_by_this_run"], self.good["file_totals"][ACCEPTED_DEFAULT]
                          + self.good["file_totals"][ACCEPTED_REQUEST]), (8, 8))

        def fewer_built(v):
            v["project_modules_built_by_this_run"] -= 1
            step_named(v, "on_request_build")["project_modules_built"] -= 1
        # The per-step counts are re-derived from the rows' built_in_step.
        self.refuses(self.mutated(fewer_built), "WITNESS_PROJECT_MODULE_TOTALS_DRIFT")
        self.refuses(self.mutated(lambda v: (fewer_built(v), v.update(
            hold_reasons=["ACCEPTED_MODULE_WITHOUT_BUILD_LINE"]))), "WITNESS_PROJECT_MODULE_TOTALS_DRIFT")

        def unbuilt(v):
            fewer_built(v)
            by_path(v)["Lib/Orphan.lean"]["built_in_step"] = None
        self.refuses(self.mutated(unbuilt), "WITNESS_HOLD_REASONS_DRIFT")
        self.refuses(self.mutated(lambda v: (unbuilt(v), v.update(
            hold_reasons=["ACCEPTED_MODULE_WITHOUT_BUILD_LINE"]))), "WITNESS_STATE_DRIFT")
        self.assertTrue(validate_witness(self.mutated(lambda v: (unbuilt(v), v.update(
            hold_reasons=["ACCEPTED_MODULE_WITHOUT_BUILD_LINE"], state="HOLD"))), policy()))

    def test_hold_reasons_are_re_derived(self):
        for change in (lambda v: v.update(hold_reasons=["NOT_A_REASON"]),
                       lambda v: v.update(hold_reasons="LOCKED_GUARD_FAILED"),
                       lambda v: v.update(hold_reasons=[1, "LOCKED_GUARD_FAILED"]),
                       lambda v: v.update(hold_reasons=[{}]),
                       lambda v: v.update(hold_reasons=["LOCKED_GUARD_FAILED", "LOCKED_GUARD_FAILED"])):
            self.refuses(self.mutated(change, self.hold), "WITNESS_HOLD_REASONS_INVALID")
        self.refuses(self.mutated(lambda v: v.update(hold_reasons=[]), self.hold), "WITNESS_HOLD_REASONS_DRIFT")
        self.refuses(self.mutated(lambda v: v.update(hold_reasons=[], state="KERNEL_EXECUTED"), self.hold),
                     "WITNESS_HOLD_REASONS_DRIFT")
        self.refuses(self.mutated(lambda v: v.update(hold_reasons=["STEP_TIMED_OUT"], state="HOLD")),
                     "WITNESS_HOLD_REASONS_DRIFT")
        self.refuses(self.mutated(lambda v: v.update(state="HOLD")), "WITNESS_STATE_DRIFT")
        self.refuses(self.mutated(lambda v: v.update(state="KERNEL_EXECUTED"), self.hold), "WITNESS_STATE_DRIFT")
        self.refuses(self.mutated(lambda v: step_named(v, "axiom_census").update(timed_out=True)),
                     "WITNESS_HOLD_REASONS_DRIFT")

    def test_on_request_summary(self):
        for change in (lambda v: v["on_request_build"].update(exit_code=0),
                       lambda v: v["on_request_build"].update(modules_accepted=3),
                       lambda v: v["on_request_build"].update(modules_requested=0, modules_accepted=0,
                                                              modules_rejected=0),
                       lambda v: v["on_request_build"].pop("exit_code"),
                       lambda v: v.update(on_request_build=None)):
            self.refuses(self.mutated(change, self.rejecting), "WITNESS_GATE_DRIFT")
        self.assertEqual(self.rejecting["on_request_build"], {"exit_code": 1, "modules_requested": 3,
                                                              "modules_accepted": 2, "modules_rejected": 1})

    def test_dependency_cache_is_re_derived(self):
        def package(v, name):
            return next(p for p in v["dependency_cache"]["packages"] if p["name"] == name)
        for change in (lambda v: v["dependency_cache"].update(dependency_oleans_rechecked_by_kernel=True),
                       lambda v: v["dependency_cache"].update(origin="PUBLISHED_CACHE"),
                       lambda v: v["dependency_cache"].update(manifest_sha256="0" * 64),
                       lambda v: v["dependency_cache"].update(dependency_oleans=1),
                       lambda v: v["dependency_cache"].update(state="MISMATCH"),
                       lambda v: v["dependency_cache"].update(packages=None),
                       lambda v: v["dependency_cache"]["packages"].reverse(),
                       lambda v: package(v, "mathlib").update(checked_out_rev="0" * 40),
                       lambda v: package(v, "mathlib").update(state="REVISION_DIFFERS"),
                       lambda v: package(v, "mathlib").update(checked_out_rev=None),
                       lambda v: package(v, "mathlib").update(extra=1),
                       lambda v: v.update(mathlib_revision="0" * 40),
                       lambda v: v["dependency_cache"].pop("origin")):
            self.refuses(self.mutated(change), "WITNESS_DEPENDENCY_CACHE_INVALID")
        self.refuses(self.mutated(lambda v: v.update(dependency_cache=None)), "WITNESS_DEPENDENCY_CACHE_INVALID")

        def mismatch_but_built(v):
            package(v, "mathlib").update(checked_out_rev="0" * 40, state="REVISION_DIFFERS")
            v["dependency_cache"]["state"] = "MISMATCH"
        self.refuses(self.mutated(mismatch_but_built), "WITNESS_STATE_DRIFT")

    def test_file_rows(self):
        def first(v, **kw):
            v["files"][0].update(kw)
        for change in (lambda v: first(v, status="PROVED"), lambda v: first(v, error_lines=True),
                       lambda v: first(v, error_lines=-1), lambda v: first(v, elaborator_sorry_declarations=1.0),
                       lambda v: first(v, module="bad-name"), lambda v: first(v, path="Lib/A.py"),
                       lambda v: first(v, reason="lower"), lambda v: first(v, extra=1),
                       lambda v: v["files"][0].pop("reason")):
            self.refuses(self.mutated(change), "WITNESS_FILE_FIELDS_INVALID")
        self.refuses(self.mutated(lambda v: by_path(v)["Lib/A.lean"].update(module=None)),
                     "WITNESS_FILE_FIELDS_INVALID")
        self.refuses(self.mutated(lambda v: by_path(v)["Lib/A.lean"].update(error_lines=1)),
                     "WITNESS_ACCEPTED_WITH_ERRORS")

    def test_file_reason_matches_status(self):
        def accepted_with_reason(v):
            row = next(f for f in v["files"] if f["status"] == ACCEPTED_DEFAULT)
            row["reason"] = "ANY_REASON"

        def rejected_without_reason(v):
            row = next(f for f in v["files"] if f["status"] == NOT_CHECKED)
            row["reason"] = None
        self.refuses(self.mutated(accepted_with_reason), "WITNESS_FILE_REASON_INVALID")
        self.refuses(self.mutated(rejected_without_reason), "WITNESS_FILE_REASON_INVALID")

    def test_file_order_and_totals(self):
        self.refuses(self.mutated(lambda v: v["files"].reverse()), "WITNESS_FILE_ORDER_OR_DUPLICATE")
        self.refuses(self.mutated(lambda v: v["files"].insert(0, deepcopy(v["files"][0]))),
                     "WITNESS_FILE_ORDER_OR_DUPLICATE")

        def flip_status(v):
            row = next(f for f in v["files"] if f["status"] == NOT_CHECKED)
            row.update(status=REJECTED)
        self.refuses(self.mutated(flip_status), "WITNESS_FILE_VERDICT_DRIFT")

        def flip_status_and_totals(v):
            flip_status(v)
            v["file_totals"][NOT_CHECKED] -= 1
            v["file_totals"][REJECTED] += 1
        self.refuses(self.mutated(flip_status_and_totals), "WITNESS_FILE_VERDICT_DRIFT")
        self.refuses(self.mutated(lambda v: v["file_totals"].update({REJECTED: True})), "WITNESS_FIELDS_INVALID")
        self.refuses(self.mutated(lambda v: v["file_totals"].update({REJECTED: v["file_totals"][REJECTED] + 1})),
                     "WITNESS_FILE_TOTALS_DRIFT")
        self.refuses(self.mutated(lambda v: v["file_totals"].pop(REJECTED)), "WITNESS_FIELDS_INVALID")

    def test_census_block(self):
        for change in (lambda v: v["census"].update(state="PARTIAL"),
                       lambda v: v["census"].update(rows_sha256="0" * 63),
                       lambda v: v["census"].update(rows_sha256=None),
                       lambda v: v["census"].update(constants=True),
                       lambda v: v["census"].update(constants=-1),
                       lambda v: v["census"].update(reason="CENSUS_PROGRAM_FAILED"),
                       lambda v: v["census"].pop("modules"),
                       lambda v: v.update(modules={})):
            self.refuses(self.mutated(change), "WITNESS_FIELDS_INVALID")

    def test_census_module_counts_are_re_derived(self):
        self.assertEqual((self.good["census"]["modules"], self.good["census"]["modules_loaded"]), (6, 7))
        for change in (lambda v: v["census"].update(modules_loaded=6),
                       lambda v: v["census"].update(modules_loaded=8),
                       lambda v: v["census"].update(modules=7),
                       lambda v: v["census"].update(modules=5)):
            self.refuses(self.mutated(change), "WITNESS_CENSUS_MODULES_DRIFT")

    def test_module_rows(self):
        def module(v, name):
            return next(m for m in v["modules"] if m["module"] == name)
        self.refuses(self.mutated(lambda v: module(v, "Lib.A").update(module="Other.Outside")),
                     "WITNESS_MODULE_NOT_ACCEPTED")
        self.refuses(self.mutated(lambda v: module(v, "Lib.A").update(path="Lib/B.lean")),
                     "WITNESS_MODULE_NOT_ACCEPTED")
        self.refuses(self.mutated(lambda v: module(v, "Lib.A").update(user_theorems=True)),
                     "WITNESS_MODULE_FIELDS_INVALID")
        self.refuses(self.mutated(lambda v: module(v, "Lib.A").update({CLASS_CLEAN: 1.0})),
                     "WITNESS_MODULE_FIELDS_INVALID")
        self.refuses(self.mutated(lambda v: module(v, "Lib.A").pop("declared_axioms")),
                     "WITNESS_MODULE_FIELDS_INVALID")
        self.refuses(self.mutated(lambda v: module(v, "Lib.A").update({CLASS_CLEAN: 2})),
                     "WITNESS_THEOREM_PARTITION_BROKEN")
        self.refuses(self.mutated(lambda v: module(v, "Lib.A").update({CLASS_SORRY: 0, CLASS_CLEAN: 2})),
                     "WITNESS_THEOREM_TOTALS_DRIFT")
        self.refuses(self.mutated(lambda v: v["modules"].reverse()), "WITNESS_MODULE_ORDER_OR_DUPLICATE")

        self.refuses(self.mutated(lambda v: v["modules"].append(deepcopy(v["modules"][-1]))),
                     "WITNESS_CENSUS_MODULES_DRIFT")

        def duplicate(v):
            v["modules"].append(deepcopy(v["modules"][-1]))
            v["census"]["modules"] += 1
        self.refuses(self.mutated(duplicate), "WITNESS_MODULE_ORDER_OR_DUPLICATE")

    def test_theorem_totals(self):
        self.refuses(self.mutated(lambda v: v["theorem_totals"].update(
            user_theorems=v["theorem_totals"]["user_theorems"] + 1)),
                     "WITNESS_THEOREM_TOTALS_DRIFT")
        self.refuses(self.mutated(lambda v: v["theorem_totals"].pop(CLASS_NATIVE)), "WITNESS_FIELDS_INVALID")
        self.refuses(self.mutated(lambda v: v.update(theorem_totals=None)), "WITNESS_FIELDS_INVALID")

    def test_declared_axioms_and_sorry_sources(self):
        for change in (lambda v: v["declared_axioms"].pop(), lambda v: v["declared_axioms"].reverse(),
                       lambda v: v["declared_axioms"][0].update(extra=1),
                       lambda v: v["declared_axioms"][0].pop("user_theorem_load"),
                       lambda v: v["declared_axioms"][0].update(decl=None)):
            self.refuses(self.mutated(change), "WITNESS_AXIOM_LIST_INVALID")
        for change in (lambda v: v["sorry_sources"].pop(), lambda v: v["sorry_sources"].reverse(),
                       lambda v: v["sorry_sources"][0].pop("taints"),
                       lambda v: v["sorry_sources"][0].update(decl=7)):
            self.refuses(self.mutated(change), "WITNESS_SORRY_SOURCES_INVALID")

    def test_carriers(self):
        def carrier(v, decl):
            return next(c for c in v["carrier_theorems"] if c["decl"] == decl)
        for change in (lambda v: v["carrier_theorems"].reverse(), lambda v: v["carrier_theorems"].pop(),
                       lambda v: carrier(v, "Lib.Orphan.carrier").update({"class": CLASS_SORRY}),
                       lambda v: carrier(v, "Lib.Orphan.carrier").update(axioms=["sorryAx"]),
                       lambda v: carrier(v, "Lib.Orphan.carrier").update(found=1),
                       lambda v: carrier(v, "Missing.thm").update({"class": CLASS_CLEAN}),
                       lambda v: carrier(v, "Missing.thm").update(axioms=[]),
                       lambda v: carrier(v, "Missing.thm").update(found=True),
                       lambda v: carrier(v, "Missing.thm").pop("role")):
            self.refuses(self.mutated(change), "WITNESS_CARRIERS_INVALID")

    def test_executables_list(self):
        self.refuses(self.mutated(lambda v: v["executables"][0].update(name="other")),
                     "WITNESS_EXECUTABLES_INVALID")
        self.refuses(self.mutated(lambda v: v["executables"][0].update(root="Other")),
                     "WITNESS_EXECUTABLES_INVALID")
        self.refuses(self.mutated(lambda v: v["executables"].append(deepcopy(v["executables"][0]))),
                     "WITNESS_EXECUTABLES_INVALID")
        self.refuses(self.mutated(lambda v: v.update(executables=None)), "WITNESS_EXECUTABLES_INVALID")
        self.refuses(self.mutated(lambda v: v.update(executables=[])), "WITNESS_EXECUTABLES_INVALID")

    def test_kernel_executed_requires_every_gate(self):
        for change in (lambda v: v["default_build"].update(state="FAILED"),
                       lambda v: v.update(default_build=None),
                       lambda v: v["locked_guard"].update(state="FAILED"),
                       lambda v: v["axiom_check"].update(state="FAILED"),
                       lambda v: v.update(axiom_check=None),
                       lambda v: v["executables"][0].update(state="FAILED"),
                       lambda v: v["default_build"].pop("closure_modules_with_olean")):
            self.refuses(self.mutated(change), "WITNESS_GATE_DRIFT")
        self.refuses(self.mutated(lambda v: v["toolchain"].update(pin_in_checkout="leanprover/lean4:v4.34.0")),
                     "WITNESS_STATE_DRIFT")
        # The verifier's G7: a toolchain that reports another Lean version is not the pinned one.
        self.refuses(self.mutated(lambda v: v["toolchain"].update(lean_version="Lean (version 9.9.9)")),
                     "WITNESS_STATE_DRIFT")
        self.refuses(self.mutated(lambda v: v["toolchain"].update(lake_version="Lake version 5.0.0")),
                     "WITNESS_STATE_DRIFT")

    def test_unavailable_must_stay_unknown_not_zero(self):
        zeros = {k: 0 for k in self.good["theorem_totals"]}
        for change in (lambda v: v.update(theorem_totals=zeros), lambda v: v["census"].update(constants=0),
                       lambda v: v["census"].update(rows_sha256="0" * 64),
                       lambda v: v["census"].update(modules_loaded=0),
                       lambda v: v["census"].update(reason="TOOLCHAIN_UNAVAILABLE_OR_PIN_MISMATCH"),
                       lambda v: v.update(declared_axioms=[{"decl": "x"}]),
                       lambda v: v.update(sorry_sources=[{}]),
                       lambda v: v.update(carrier_theorems=[{}]),
                       lambda v: v.update(modules=[{"module": "Lib.A"}]),
                       lambda v: v.update(hold_reasons=["DEFAULT_BUILD_FAILED"]),
                       lambda v: v.update(on_request_build={"exit_code": 0}),
                       lambda v: v.update(files=deepcopy(self.good["files"]),
                                          file_totals=deepcopy(self.good["file_totals"])),
                       lambda v: v.update(steps=v["steps"] + [idle_step(self.good, "default_build")])):
            self.refuses(self.mutated(change, self.unavailable), "WITNESS_UNAVAILABLE_NOT_UNKNOWN")
        self.refuses(self.mutated(lambda v: v.update(state="KERNEL_EXECUTED", kernel_executed_by_this_run=True),
                                  self.unavailable), "WITNESS_STATE_DRIFT")

        def census_lost(v):
            v["census"].update(state="UNAVAILABLE", reason="CENSUS_PROGRAM_FAILED", constants=None,
                               modules=None, modules_loaded=None, rows_sha256=None)
            v.update(hold_reasons=["AXIOM_CENSUS_UNAVAILABLE"], state="HOLD")
        self.refuses(self.mutated(census_lost), "WITNESS_UNAVAILABLE_NOT_UNKNOWN")

    def test_standalone_rows_are_tied_to_their_steps(self):
        bad = by_path(self.rejecting)["TH8/Bad.lean"]
        self.assertEqual((bad["status"], step_named(self.rejecting, bad["judging_step"])["exit_code"]), (REJECTED, 1))

        def relabel(v):
            # The review's forgery: error lines zeroed and totals moved, while the file's own step exited 1.
            by_path(v)["TH8/Bad.lean"].update(status=ACCEPTED_STANDALONE, reason=None, error_lines=0)
            v["file_totals"][REJECTED] -= 1
            v["file_totals"][ACCEPTED_STANDALONE] += 1
        self.refuses(self.mutated(relabel, self.rejecting), "WITNESS_FILE_VERDICT_DRIFT")
        name = by_path(self.good)["TH8/Solo.lean"]["judging_step"]
        self.refuses(self.mutated(lambda v: v["steps"].remove(step_named(v, name))), "WITNESS_FILE_FIELDS_INVALID")
        self.refuses(self.mutated(lambda v: v["steps"].insert(-1, dict(idle_step(v, name),
                                                                       name="standalone_000000000000"))),
                     "WITNESS_STEP_SEQUENCE_DRIFT")
        self.refuses(self.mutated(lambda v: by_path(v)["TH8/Solo.lean"].update(judging_step="axiom_check")),
                     "WITNESS_FILE_VERDICT_DRIFT")

    def test_search_path_record_is_re_derived(self):
        search = self.good["lean_search_path"]
        self.assertEqual((search["state"], search["project_namespaces"]), ("EXPORT_ONLY", 9))
        for change in (lambda s: s.update(project_namespaces=8), lambda s: s.update(shadowed_namespaces=["Mathlib"]),
                       lambda s: s.update(shadowed_namespaces=["TH8", "Lib"]),
                       lambda s: s.update(export_library_entries=4), lambda s: s.update(exit_code=1),
                       lambda s: s.update(state="UNVERIFIED"), lambda s: s.update(entries=True),
                       lambda s: s.pop("entries")):
            self.refuses(self.mutated(lambda v, change=change: change(v["lean_search_path"])),
                         "WITNESS_SEARCH_PATH_INVALID")
        self.refuses(self.mutated(lambda v: v.update(lean_search_path=None)), "WITNESS_SEARCH_PATH_INVALID")

        def shadowed_but_accepted(v):
            v["lean_search_path"].update(state="SHADOWED", shadowed_namespaces=["Lib"])
            v.update(hold_reasons=["LEAN_SEARCH_PATH_SHADOWS_PROJECT"], state="HOLD")
        self.refuses(self.mutated(shadowed_but_accepted), "WITNESS_FILE_VERDICT_DRIFT")

    def test_golden_forgeries_of_cross_field_invariants(self):
        """The review's forgeries: each keeps every total it touches consistent and must still be refused."""
        def module(v, name):
            return next(m for m in v["modules"] if m["module"] == name)

        def cleaned(v):
            for m in v["modules"] + [v["theorem_totals"]]:
                m[CLASS_CLEAN] += m[CLASS_SORRY]
                m[CLASS_SORRY] = 0
            for c in v["carrier_theorems"]:
                if c["class"] == CLASS_SORRY:
                    c["axioms"] = [a for a in c["axioms"] if a != "sorryAx"]
                    c["class"] = classify(c["axioms"], TRUST)

        def cleaned_and_untainted(v):
            cleaned(v)
            for s in v["sorry_sources"]:
                s.update(taints=0, sole_blocker_for=0)

        def moved_direct_sorry(v):
            module(v, "Lib.A")["direct_sorry_declarations"] -= 1
            module(v, "Lib.Deep")["direct_sorry_declarations"] += 1
        for change, code in (
                (cleaned, "WITNESS_SORRY_SOURCES_INVALID"), (cleaned_and_untainted, "WITNESS_CARRIERS_INVALID"),
                (lambda v: v["default_build"].update(modules_in_import_closure=0, closure_modules_with_olean=0),
                 "WITNESS_GATE_DRIFT"),
                (moved_direct_sorry, "WITNESS_SORRY_SOURCES_INVALID"),
                (lambda v: v["declared_axioms"][1].update(native_decide_auxiliary=False), "WITNESS_AXIOM_LIST_INVALID"),
                (lambda v: v["declared_axioms"][0].update(module="Not.A.Module"), "WITNESS_AXIOM_LIST_INVALID"),
                (lambda v: v["declared_axioms"][0].update(user_theorem_load="many"), "WITNESS_AXIOM_LIST_INVALID"),
                (lambda v: v["sorry_sources"][0].update(module="Not.A.Module"), "WITNESS_SORRY_SOURCES_INVALID"),
                (lambda v: v["sorry_sources"][0].update(taints=True), "WITNESS_SORRY_SOURCES_INVALID"),
                (lambda v: v["sorry_sources"][0].update(sole_blocker_for=v["sorry_sources"][0]["taints"] + 50),
                 "WITNESS_SORRY_SOURCES_INVALID"),
                (lambda v: v["carrier_theorems"][1].update(role=123), "WITNESS_CARRIERS_INVALID"),
                (lambda v: v["carrier_theorems"][1].update(role="ANY_ROLE_I_LIKE"), "WITNESS_CARRIERS_INVALID"),
                (lambda v: v["carrier_theorems"][1].update(axioms=[7, 8]), "WITNESS_CARRIERS_INVALID"),
                (lambda v: v["census"].update(constants=0), "WITNESS_CENSUS_MODULES_DRIFT")):
            with self.subTest(change=change):
                self.refuses(self.mutated(change), code)
        self.refuses(self.mutated(lambda v: v["on_request_build"].update(modules_rejected=200, modules_requested=202),
                                  self.rejecting), "WITNESS_GATE_DRIFT")

    def test_golden_forgeries_each_refused_by_one_check(self):
        """The review's surviving mutants: each forgery keeps every other field it touches consistent, so
        exactly one check of the validator refuses it, and deleting that check would let it through."""
        def module_less_built(v):
            by_path(v)["Bad-Name.lean"]["built_in_step"] = "default_build"
            step_named(v, "default_build")["project_modules_built"] += 1
            v["project_modules_built_by_this_run"] += 1

        def outside_requested(v):
            by_path(v)["Other/Outside.lean"].update(status=ACCEPTED_REQUEST, reason=None, olean="FRESH",
                                                    judging_step="on_request_build", built_in_step="on_request_build")
            v["file_totals"][NOT_CHECKED] -= 1
            v["file_totals"][ACCEPTED_REQUEST] += 1
            step_named(v, "on_request_build")["project_modules_built"] += 1
            v["project_modules_built_by_this_run"] += 1
            for field in ("modules_requested", "modules_accepted"):
                v["on_request_build"][field] += 1
            for field in ("modules_loaded", "project_oleans_from_export"):
                v["census"][field] += 1

        def duplicated_modules(v):
            v["modules"] += deepcopy(v["modules"][-1:]) * 2
            v["census"]["modules"] += 2
        cases = (
            ("M13 every loaded project module was read from the export's library",
             lambda v: v["census"].update(project_oleans_from_export=6), None, "WITNESS_CENSUS_MODULES_DRIFT"),
            ("M42 no more module rows than modules loaded", duplicated_modules, None, "WITNESS_CENSUS_MODULES_DRIFT"),
            ("M15 a failed job line no row carries",
             lambda v: by_path(v)["Lib/Broken.lean"].update(build_job_failed=False), "rejecting",
             "WITNESS_PROJECT_MODULE_TOTALS_DRIFT"),
            ("M15 a failed row no job line reported",
             lambda v: by_path(v)["Other/Outside.lean"].update(build_job_failed=True), "rejecting",
             "WITNESS_PROJECT_MODULE_TOTALS_DRIFT"),
            ("M27 more sole blockers than sorry-tainted theorems",
             lambda v: [s.update(sole_blocker_for=s["taints"]) for s in v["sorry_sources"]], None,
             "WITNESS_SORRY_SOURCES_INVALID"),
            ("M32 a file that names no module was built", module_less_built, None, "WITNESS_FILE_FIELDS_INVALID"),
            ("M34 the fresh count of a default build that failed anyway",
             lambda v: v["default_build"].update(closure_modules_with_olean=2), "default_failed", "WITNESS_GATE_DRIFT"),
            ("M35 a module outside the library roots judged on request", outside_requested, None,
             "WITNESS_FILE_VERDICT_DRIFT"),
            ("M36 an olean outside the export, from a census program that failed",
             lambda v: v["census"].update(reason="CENSUS_OLEAN_OUTSIDE_EXPORT"), "census_failed",
             "WITNESS_UNAVAILABLE_NOT_UNKNOWN"),
            ("M41 an axiom loading more theorems than leave the trust base",
             lambda v: v["declared_axioms"][0].update(user_theorem_load=6), None, "WITNESS_AXIOM_LIST_INVALID"),
            ("M43 a stand-alone file with an .olean", lambda v: by_path(v)["TH8/Solo.lean"].update(olean="FRESH"), None,
             "WITNESS_FILE_VERDICT_DRIFT"),
            ("M45 a search-path record that exited 0 when its step did not",
             lambda v: step_named(v, "lean_search_path").update(exit_code=1), None, "WITNESS_SEARCH_PATH_INVALID"))
        self.assertEqual((self.good["census"]["project_oleans_from_export"], self.good["census"]["modules_loaded"],
                          self.good["theorem_totals"]["user_theorems"] - self.good["theorem_totals"][CLASS_CLEAN]),
                         (7, 7, 5))
        for label, change, base, code in cases:
            with self.subTest(label):
                self.refuses(self.mutated(change, getattr(self, base) if base else None), code)

    def test_counts_are_counts_not_booleans(self):
        """JSON true equals 1 under ==, so a total or an expected count must be checked as a count first."""
        for key in ("native_decide", "declared_axiom_dependent"):
            self.assertEqual(self.good["theorem_totals"][key], 1)
            self.refuses(self.mutated(lambda v, key=key: v["theorem_totals"].update({key: True})),
                         "WITNESS_FIELDS_INVALID")
        self.refuses(self.mutated(lambda v: v["theorem_totals"].update(user_theorems=10.0)), "WITNESS_FIELDS_INVALID")
        section = policy(locked_guard={"path": "tools/lean/LockedGuard.lean", "expected_allowed": 1})
        with tempfile.TemporaryDirectory() as temp:
            repo = make_checkout(Path(temp), name="one")
            value = observe(section, repo, toolchain_bin=Path(temp), run=FakeLake(allowed=1, fail_request=()), at=NOW)
        self.assertEqual((value["state"], value["locked_guard"]["expected"]), ("KERNEL_EXECUTED", 1))
        value["locked_guard"]["expected"] = True
        with self.assertRaisesRegex(InputError, "WITNESS_GATE_DRIFT"):
            validate_witness(value, section)

    def test_dependency_package_names_follow_the_manifest_rule(self):
        self.assertEqual([p["name"] for p in self.good["dependency_cache"]["packages"]], list(PACKAGES))
        for name in ("", ".", "..", "bad name", "a/b", "x" * 101, "mathlib\n"):
            with self.subTest(name=name):
                self.refuses(self.mutated(lambda v, name=name: v["dependency_cache"]["packages"][0].update(name=name)),
                             "WITNESS_DEPENDENCY_CACHE_INVALID")

    def test_every_field_of_the_wrong_type_is_a_typed_refusal(self):
        """A value of another JSON type in any field is refused with an InputError code: never accepted,
        never a TypeError or a KeyError. (A value of the same type is the consistent-rewrite case.)"""
        def paths(value, prefix=()):
            yield prefix
            if type(value) is dict:
                for key, item in value.items():
                    yield from paths(item, prefix + (key,))
            elif type(value) is list:
                for index, item in enumerate(value):
                    yield from paths(item, prefix + (index,))
        checked = 0
        for base in (self.good, self.unavailable, self.hold, self.rejecting, self.census_failed, self.default_failed):
            value = deepcopy(base)
            for path in list(paths(value))[1:]:
                holder = value
                for key in path[:-1]:
                    holder = holder[key]
                original = holder[path[-1]]
                # A step renamed to a well-formed name it does not have, too.
                renamed = ("renamed_step",) if path[-1] == "name" and path[0] == "steps" else ()
                for bad in (None, -1, "x", [7], {}, True, False, 1.5, *renamed):
                    holder[path[-1]] = bad
                    try:
                        validate_witness(value, policy())
                    except InputError:
                        checked += type(bad) is not type(original)
                        continue
                    except Exception as exc:  # noqa: BLE001 - any other exception is the defect
                        self.fail(f"{bad!r} at {path!r} raised {exc!r}")
                    finally:
                        holder[path[-1]] = original
                    # With no package rows (a cache too small to look at), the manifest's mathlib pin
                    # is reported as read: nothing in the witness can re-derive it.
                    unrows = path == ("mathlib_revision",) and base["dependency_cache"]["state"] == "ABSENT"
                    if type(bad) is not type(original) and not unrows:
                        self.fail(f"{bad!r} at {path!r} (was {original!r}) was accepted")
        self.assertGreater(checked, 5000)


class CliTests(TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.policy_path = self.base / "policy.json"
        self.policy_path.write_text(json.dumps({"lean": policy()}))
        self.bin = self.base / "bin"
        self.bin.mkdir()
        for tool in ("lean", "lake"):
            script = self.bin / tool
            script.write_text("#!/bin/sh\nexit 1\n")
            script.chmod(0o755)
        self.repo = make_checkout(self.base)

    def call(self, *extra, output=None, policy_path=None, toolchain=None, flag="--toolchain-bin"):
        args = ["--policy", str(policy_path or self.policy_path), "--lean-checkout", str(self.repo),
                flag, str(toolchain or self.bin), "--output", str(output or self.base / "w.json"), *extra]
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main(args)
        lines = buffer.getvalue().strip().splitlines()
        self.assertEqual(len(lines), 1, "one JSON line on stdout")
        return code, json.loads(lines[0])

    def test_kernel_executed_through_cli_and_never_overwrites(self):
        logs = self.base / "logs"
        logs.mkdir()
        output = self.base / "out" / "witness.json"
        output.parent.mkdir()
        with mock.patch.object(witness_module, "_runner",
                               lambda _bin, _home: FakeLake(fail_request=(), fail_standalone=())):
            code, summary = self.call("--log-dir", str(logs), output=output)
            self.assertEqual(code, 0)
            self.assertEqual(summary["state"], "KERNEL_EXECUTED")
            self.assertEqual(summary["hold_reasons"], [])
            self.assertEqual(summary["build_tree"], BUILD_TREE)
            self.assertEqual(summary["network_namespace"], NETNS_EMPTY)
            self.assertEqual((summary["project_modules_built_by_this_run"], summary["project_modules_replayed"]),
                             (8, 0))
            self.assertIs(summary["proofs_promoted"], False)
            self.assertIs(summary["production_authorized"], False)
            written = json.loads(output.read_text())
            self.assertTrue(validate_witness(written, policy()))
            self.assertTrue((logs / "default_build.log").is_file())
            before = output.read_bytes()
            code, summary = self.call(output=output)
            self.assertEqual(code, 3)
            self.assertEqual(summary["code"], "OUTPUT_PATH_DENIED")
            self.assertEqual(output.read_bytes(), before)

    def test_lean_toolchain_bin_alias_and_packages_dir(self):
        cache = self.base / "elsewhere" / "packages"
        shutil.copytree(self.repo / ".lake" / "packages", cache, symlinks=True)
        shutil.rmtree(self.repo / ".lake")
        with mock.patch.object(witness_module, "_runner",
                               lambda _bin, _home: FakeLake(fail_request=(), fail_standalone=())):
            code, summary = self.call(flag="--lean-toolchain-bin", output=self.base / "a.json")
            self.assertEqual((code, summary["state"]), (2, "UNAVAILABLE"))
            self.assertEqual(json.loads((self.base / "a.json").read_text())["census"]["reason"],
                             "DEPENDENCY_CACHE_ABSENT")
            code, summary = self.call("--packages-dir", str(cache), flag="--lean-toolchain-bin",
                                      output=self.base / "b.json")
        self.assertEqual((code, summary["state"]), (0, "KERNEL_EXECUTED"))
        self.assertTrue((cache / "mathlib" / ".lake/build/lib/lean/Dep0.olean").is_file())

    def test_hold_exit_code(self):
        with mock.patch.object(witness_module, "_runner", lambda _bin, _home: FakeLake(allowed=1)):
            code, summary = self.call()
        self.assertEqual(code, 2)
        self.assertEqual(summary["state"], "HOLD")
        self.assertEqual(summary["hold_reasons"], ["LOCKED_GUARD_FAILED"])
        self.assertEqual(summary["locked_guard"], "FAILED")

    def test_real_runner_with_failing_tools_is_unavailable(self):
        output = self.base / "w.json"
        code, summary = self.call(output=output)
        self.assertEqual(code, 2)
        self.assertEqual(summary["state"], "UNAVAILABLE")
        self.assertIsNone(summary["theorem_totals"])
        written = json.loads(output.read_text())
        self.assertEqual(written["census"]["reason"], "TOOLCHAIN_UNAVAILABLE_OR_PIN_MISMATCH")
        self.assertIs(written["kernel_executed_by_this_run"], False)
        self.assertEqual([s["exit_code"] for s in written["steps"]], [1, 1])
        self.assertIn(written["network_namespace"], (NETNS_EMPTY, NETNS_UNAVAILABLE))
        self.assertEqual({s["network_namespace"] for s in written["steps"]}, {written["network_namespace"]})
        self.assertTrue(validate_witness(written, policy()))
        self.assertEqual(self.call(output=output)[0], 3)

    def test_output_inside_a_source_tree_refused(self):
        inside = ROOT / "tests" / "braid_lean_witness_should_never_exist.json"
        self.addCleanup(lambda: inside.unlink() if inside.exists() else None)
        for target in (inside, self.repo / "w.json", self.repo / ".lake" / "packages" / "w.json"):
            with self.subTest(target=target):
                code, summary = self.call(output=target)
                self.assertEqual((code, summary["code"]), (3, "OUTPUT_PATH_DENIED"))
                self.assertFalse(target.exists())

    def test_cli_refusals(self):
        code, summary = self.call(toolchain=Path("relative/bin"))
        self.assertEqual((code, summary["code"]), (3, "WITNESS_TOOLCHAIN_UNAVAILABLE"))
        code, summary = self.call(toolchain=self.base / "nowhere")
        self.assertEqual((code, summary["code"]), (3, "WITNESS_TOOLCHAIN_UNAVAILABLE"))
        code, summary = self.call("--log-dir", str(ROOT / "tests"))
        self.assertEqual((code, summary["code"]), (3, "WITNESS_LOG_DIRECTORY_DENIED"))
        code, summary = self.call("--log-dir", str(self.base / "missing"))
        self.assertEqual((code, summary["code"]), (3, "WITNESS_LOG_DIRECTORY_DENIED"))
        inside = self.repo / "logs"
        inside.mkdir()
        code, summary = self.call("--log-dir", str(inside))
        self.assertEqual((code, summary["code"]), (3, "WITNESS_LOG_DIRECTORY_DENIED"))
        busy = self.base / "busy"
        busy.mkdir()
        (busy / "old.log").write_text("x")
        code, summary = self.call("--log-dir", str(busy))
        self.assertEqual((code, summary["code"]), (3, "WITNESS_LOG_DIRECTORY_NOT_EMPTY"))
        other = self.base / "other.json"
        other.write_text(json.dumps({"not_lean": {}}))
        code, summary = self.call(policy_path=other)
        self.assertEqual((code, summary["code"]), (3, "WITNESS_POLICY_FIELDS_INVALID"))
        floaty = self.base / "float.json"
        floaty.write_text(json.dumps({"lean": policy(step_timeout_seconds=600.0)}))
        code, summary = self.call(policy_path=floaty)
        self.assertEqual((code, summary["code"]), (3, "FLOAT_VALUE_REFUSED"))
        self.assertFalse((self.base / "w.json").exists())
        self.assertEqual(summary["state"], "UNAVAILABLE")
        self.assertIs(summary["production_authorized"], False)


if __name__ == "__main__":
    unittest_main()
