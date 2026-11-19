# SPDX-License-Identifier: Apache-2.0
"""Synthetic, offline regression suite for the braid v2 Lean kernel witness (schema v2).

Covers policy refusals, module naming, header-only import parsing, import closure, theorem
classification precedence, the census program and its strict parser, order-independent census
digests, Lake job-line and diagnostic parsing (both message formats, path normalisation, replay
de-duplication), and observe() driven by an injected fake Lake: the build always runs in a fresh
export of the commit with .lake/packages linked to the dependency cache, never in the checkout;
planted build products in the checkout change nothing; an .olean older than its step or a file with
an error line is never accepted; a replayed or silently produced project module holds the witness;
dependency revisions are compared with the manifest; network isolation is recorded per step; logs
are create-exclusive and never written inside a source tree. A one-change-at-a-time validate_witness
tamper matrix, including golden forgeries of every gate, closes the suite with the CLI. Every
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
    ACCEPTED_DEFAULT, ACCEPTED_REQUEST, ACCEPTED_STANDALONE, BUILD_TREE, CLASS_AXIOM, CLASS_CLEAN,
    CLASS_NATIVE, CLASS_SORRY, CLASSES, HOLD_REASONS, NOT_CHECKED, REJECTED, SCHEMA, STATUSES,
    _FALSE_FLAGS, census_digest, census_program, classify, import_closure, lean_imports, main,
    module_name, observe, parse_census, parse_jobs, parse_log, parse_logs, validate_policy,
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


def census_text(rows, modules, *, noise=True):
    lines = ["building census...", "info: elaborated"] if noise else []
    lines += [json.dumps(r) for r in rows]
    lines.append(json.dumps({"census_end": True, "modules": len(set(modules)), "constants": len(rows)}))
    return "\n".join(lines) + "\n"


def job(icon, verb, name, *, timed=True):
    return "%s [4/9] %s %s%s" % (icon, verb, name, " (12ms)" if timed else "")


def source(name):
    return SOURCE.get(name, name.replace(".", "/") + ".lean")


class FakeLake:
    """Stands in for lean/lake inside the export: writes .olean files for what it builds and prints
    Lake-format job lines and diagnostics."""

    def __init__(self, *, allowed=3, refused=0, guard_exit=0, fail_default=False, fail_request=("Lib.Broken",),
                 fail_exe=False, fail_standalone=("TH8/Bad.lean",),
                 axiom_log="every listed declaration uses the trust base only\n", axiom_exit=0, census_exit=0,
                 tools_missing=False, replay_first=(), silent=(), stale=(), error_with_olean=(),
                 namespace=NETNS_EMPTY, timeout_on=None, truncate_on=None):
        self.allowed, self.refused, self.guard_exit = allowed, refused, guard_exit
        self.fail_default, self.fail_request, self.fail_exe = fail_default, set(fail_request), fail_exe
        self.fail_standalone, self.axiom_log, self.axiom_exit = set(fail_standalone), axiom_log, axiom_exit
        self.census_exit, self.tools_missing = census_exit, tools_missing
        self.replay_first, self.silent, self.stale = set(replay_first), set(silent), set(stale)
        self.error_with_olean, self.namespace = set(error_with_olean), namespace
        self.timeout_on, self.truncate_on = timeout_on, truncate_on
        self.calls, self.programs, self.census_modules, self.links, self.seen = [], [], None, [], []

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
            return "version", 0, ("Lean (version 4.35.0)\n" if argv[0] == "lean" else "Lake version 5.0.0\n")
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
        if argv[:3] == ["lake", "exe", "check"]:
            if self.fail_exe:
                return "exe", 1, "\n".join([job(FAIL, "Building", "Main"),
                                            "error: ./Main.lean:2:0: type mismatch"]) + "\n"
            lines = [job(WARN, "Replayed", "Lib.A", timed=False), SORRY_LINE]
            built, _ = self._build(cwd, EXE_CLOSURE)
            lines += built + [job(OK, "Built", "Main:c.o"), job(OK, "Built", "check:exe"), "check ok"]
            return "exe", 0, "\n".join(lines) + "\n"
        if argv[:3] == ["lake", "env", "lean"] and len(argv) == 4:
            target = argv[3]
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
            return "census", 0, census_text(census_rows_for(modules), modules)
        raise AssertionError("unexpected argv %r" % (argv,))

    def names(self):
        return [c[0] for c in self.calls]


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
        text = ("-- import Hidden.Line\n/- import Hidden.Block /- import Hidden.Nested -/ still -/\n"
                "import A.B\npublic import C\nimport all D\n  private meta import E'\n"
                "theorem t : True := trivial -- import Hidden.Trailing\n")
        self.assertEqual(lean_imports(text), ["A.B", "C", "D", "E'"])
        self.assertEqual(lean_imports("theorem import_like : True := trivial\n"), [])

    def test_lean_imports_reads_every_import_of_the_header_only(self):
        self.assertEqual(lean_imports("import A import B\nimport C.D import all E\n"), ["A", "B", "C.D", "E"])
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
        self.assertIn(["lake", "env", "lean", "./TH8/Solo.lean"], lake.names())
        self.assertNotIn(["lake", "env", "lean", "./TH8/Skip.lean"], lake.names())
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

    def test_stale_olean_from_before_the_step_is_rejected(self):
        value, _lake, _repo = self.run_witness(stale=("Lib.Orphan",))
        entry = by_path(value)["Lib/Orphan.lean"]
        self.assertEqual((entry["status"], entry["reason"]), (REJECTED, "OLEAN_NOT_WRITTEN_BY_THIS_STEP"))
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
        self.assertEqual(value["census"], {"state": "EXECUTED", "reason": None, "constants": len(rows),
                                           "modules": 5, "modules_loaded": 6, "rows_sha256": census_digest(rows)})

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
                                           "rows_sha256": None})
        self.assertIsNone(value["theorem_totals"])
        self.assertEqual((value["modules"], value["declared_axioms"], value["sorry_sources"],
                          value["carrier_theorems"]), ([], [], [], []))

    def assert_unavailable(self, value, reason):
        self.assertEqual(value["state"], "UNAVAILABLE")
        self.assertIs(value["kernel_executed_by_this_run"], False)
        self.assertIsNone(value["theorem_totals"])
        self.assertEqual(value["census"], {"state": "UNAVAILABLE", "reason": reason, "constants": None,
                                           "modules": None, "modules_loaded": None, "rows_sha256": None})
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
            "DEFAULT_BUILD_FAILED", "EXECUTABLE_FAILED", "LOCKED_GUARD_FAILED",
            "PROJECT_MODULE_REPLAYED_NOT_BUILT", "STEP_OUTPUT_TRUNCATED", "STEP_TIMED_OUT"})
        self.assertTrue(all(re.fullmatch(r"[A-Z_]{3,80}", r) for r in HOLD_REASONS))

    def test_closed_top_level_fields(self):
        self.refuses(self.mutated(lambda v: v.update(signature="x")), "WITNESS_FIELDS_INVALID")
        self.refuses(self.mutated(lambda v: v.update(network_used=False)), "WITNESS_FIELDS_INVALID")
        self.refuses(self.mutated(lambda v: v.pop("census")), "WITNESS_FIELDS_INVALID")
        self.refuses([self.good], "WITNESS_FIELDS_INVALID")

    def test_binding(self):
        for change in (lambda v: v.update(schema="szl.database-braid-lean-witness/v1"),
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
        self.refuses(self.mutated(fewer_built), "WITNESS_HOLD_REASONS_DRIFT")
        self.refuses(self.mutated(lambda v: (fewer_built(v), v.update(
            hold_reasons=["ACCEPTED_MODULE_WITHOUT_BUILD_LINE"]))), "WITNESS_STATE_DRIFT")

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
        self.refuses(self.mutated(flip_status), "WITNESS_FILE_TOTALS_DRIFT")
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
