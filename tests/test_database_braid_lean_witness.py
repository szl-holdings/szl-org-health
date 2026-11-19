# SPDX-License-Identifier: Apache-2.0
"""Synthetic, offline regression suite for the braid v2 Lean kernel witness: policy refusals, module naming,
comment-blind import parsing, import closure, theorem classification precedence, the census program and its
strict parser, order-independent census digests, Lake log parsing, observe() driven by an injected fake Lake
runner over throwaway git repositories (exactly one status per tracked file, default versus on-request builds,
rejections never counted as accepted, theorem partitions, axiom load and sorry-source rollups, carrier
theorems, KERNEL_EXECUTED / HOLD / UNAVAILABLE states), a one-change-at-a-time validate_witness tamper matrix
and the create-exclusive CLI. Every repository, toolchain and policy is made up here inside temporary
directories; nothing touches a network, a real Lean toolchain or this checkout's git state.
"""
from contextlib import redirect_stdout
from copy import deepcopy
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from unittest import TestCase, main as unittest_main, mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.database_catalog_admission import InputError  # noqa: E402
from tools.database_braid_common import digest, sha256_hex  # noqa: E402
from tools import database_braid_lean_witness as witness_module  # noqa: E402
from tools.database_braid_lean_witness import (  # noqa: E402
    ACCEPTED_DEFAULT, ACCEPTED_REQUEST, ACCEPTED_STANDALONE, CLASS_AXIOM, CLASS_CLEAN, CLASS_NATIVE,
    CLASS_SORRY, CLASSES, NOT_CHECKED, REJECTED, SCHEMA, STATUSES, _FALSE_FLAGS, census_digest,
    census_program, classify, import_closure, lean_imports, main, module_name, observe, parse_census,
    parse_log, validate_policy, validate_witness,
)

NOW = datetime(2026, 11, 19, 7, 15, tzinfo=timezone.utc)
PIN = "leanprover/lean4:v4.35.0"
MATHLIB_REV = "0123456789abcdef0123456789abcdef01234567"
TRUST = ["Classical.choice", "Quot.sound", "propext"]
NATIVE_AUX = "Lib.B.nat._native.native_decide.ax_1_1"

FILES = {
    "lean-toolchain": (PIN + "\n").encode(),
    "lake-manifest.json": json.dumps({"version": 7, "packages": [
        {"name": "batteries", "rev": "f" * 40}, {"name": "mathlib", "rev": MATHLIB_REV}]}).encode(),
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
    "TH8/Solo.lean": b"example : True := trivial\n",
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


class FakeLake:
    """Stands in for lean/lake: writes .olean files for what it builds and prints fixed logs."""

    def __init__(self, *, allowed=3, refused=0, guard_exit=0, fail_default=False, fail_request=("Lib.Broken",),
                 fail_exe=False, fail_standalone=("TH8/Bad.lean",),
                 axiom_log="every listed declaration uses the trust base only\n",
                 axiom_exit=0, census_exit=0, tools_missing=False):
        self.allowed, self.refused, self.guard_exit = allowed, refused, guard_exit
        self.fail_default, self.fail_request, self.fail_exe = fail_default, set(fail_request), fail_exe
        self.fail_standalone, self.axiom_log, self.axiom_exit = set(fail_standalone), axiom_log, axiom_exit
        self.census_exit, self.tools_missing = census_exit, tools_missing
        self.calls, self.programs, self.census_modules = [], [], None

    @staticmethod
    def _olean(cwd, name):
        target = Path(cwd) / ".lake/build/lib/lean" / (name.replace(".", "/") + ".olean")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"olean")

    def __call__(self, argv, cwd, timeout):
        argv = list(argv)
        self.calls.append((argv, Path(cwd), timeout))
        if argv in (["lean", "--version"], ["lake", "--version"]):
            if self.tools_missing:
                return 127, b"", 0
            return 0, ("Lean (version 4.35.0)\n" if argv[0] == "lean" else "Lake version 5.0.0\n").encode(), 0
        if argv == ["lake", "build"]:
            if self.fail_default:
                self._olean(cwd, "Lib.A")
                return 1, b"error: ./Lib/B.lean:1:0: unknown package\n", 3
            for name in DEFAULT_CLOSURE:
                self._olean(cwd, name)
            return 0, b"warning: ./Lib/A.lean:3:8: declaration uses 'sorry'\nBuild completed\n", 5
        if argv[:2] == ["lake", "build"]:
            requested = [a[1:] for a in argv[2:]]
            assert all(a.startswith("+") for a in argv[2:])
            out = []
            for name in requested:
                if name in self.fail_request:
                    out.append("error: ./%s.lean:1:34: unknown identifier 'nope'" % name.replace(".", "/"))
                else:
                    self._olean(cwd, name)
            return (1 if out else 0), ("\n".join(out) + "\n").encode(), 2
        if argv[:3] == ["lake", "exe", "check"]:
            if self.fail_exe:
                return 1, b"error: ./Main.lean:2:0: type mismatch\n", 1
            for name in EXE_CLOSURE:
                self._olean(cwd, name)
            return 0, b"check ok\n", 1
        if argv[:3] == ["lake", "env", "lean"] and len(argv) == 4:
            target = argv[3]
            if target == "./tools/lean/LockedGuard.lean":
                lines = ['{"name":"F%d","allowed":true}' % i for i in range(self.allowed)]
                lines += ['{"name":"X%d","allowed":false}' % i for i in range(self.refused)]
                return self.guard_exit, ("\n".join(lines) + "\n").encode(), 1
            if target == "./tools/lean/AxiomCheck.lean":
                return self.axiom_exit, self.axiom_log.encode(), 1
            if target.startswith("./"):
                if target[2:] in self.fail_standalone:
                    return 1, ("error: %s:1:19: unknown identifier 'nope'\n" % target).encode(), 1
                return 0, b"", 1
            program = Path(target).read_text(encoding="utf-8")
            self.programs.append(program)
            listed = re.search(r"def modules : Array Name := #\[(.*)\]", program).group(1)
            modules = [m.strip().lstrip("`") for m in listed.split(",")]
            self.census_modules = modules
            if self.census_exit:
                return self.census_exit, b"error: census failed\n", 1
            return 0, census_text(census_rows_for(modules), modules).encode(), 4
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


def make_checkout(base, *, files=None, cache=2, name="lean"):
    repo = Path(base) / name
    repo.mkdir(parents=True)
    git(repo, "init", "-q", home=base)
    for path, raw in (FILES if files is None else files).items():
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    git(repo, "add", "-A", home=base)
    git(repo, "commit", "-q", "-m", "synthetic fixture", home=base)
    for i in range(cache):
        target = repo / ".lake/packages/x" / ("sub%d" % (i % 2)) / ("a%d.olean" % i)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"dep")
    return repo


class _Checkout(TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.base = Path(self._temp.name)

    def run_witness(self, *, section=None, files=None, cache=2, **fake):
        base = Path(tempfile.mkdtemp(dir=self.base))
        repo = make_checkout(base, files=files, cache=cache)
        lake = FakeLake(**fake)
        value = observe(section or policy(), repo, toolchain_bin=base / "bin", run=lake, at=NOW)
        return value, lake, repo


def by_path(value):
    return {f["path"]: f for f in value["files"]}


class PolicyTests(TestCase):
    def refuses(self, section, code="WITNESS_POLICY_INVALID"):
        with self.assertRaisesRegex(InputError, code):
            validate_policy(section)

    def test_valid_policy_and_shipped_v2_section(self):
        self.assertEqual(validate_policy(policy()), policy())
        shipped = json.loads((ROOT / "governance/database_contracts/ouroboros_braid_v2.json").read_text())
        validate_policy(shipped["lean"])

    def test_field_set_is_closed(self):
        extra = policy(extra=1)
        self.refuses(extra, "WITNESS_POLICY_FIELDS_INVALID")
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
        for dirs in ([], ["Extra", "."], [".", "Extra", "Extra"], [".", "../up"], [".", "/abs"], [".", 1]):
            self.refuses(policy(source_dirs=dirs))

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

    def test_parse_log(self):
        text = ("error: ./Lib/A.lean:1:2: unknown identifier\n"
                "error: Lib/A.lean:4:0: another\n"
                "error: Lib/B.lean: whole-file error\n"
                "warning: ./Lib/C.lean:3:8: declaration uses 'sorry'\n"
                "warning: Lib/C.lean:9:8: declaration uses `sorry`\n"
                "warning: Lib/D.lean:9:8: unused variable\n"
                "info: ./Lib/E.lean:1:1: error: not a header\n"
                "build failed\n")
        errors, sorries = parse_log(text)
        self.assertEqual(errors, {"Lib/A.lean": 2, "Lib/B.lean": 1})
        self.assertEqual(sorries, {"Lib/C.lean": 2})
        self.assertEqual(parse_log(""), ({}, {}))


class ObserveTests(_Checkout):
    def test_every_tracked_file_gets_exactly_one_correct_status(self):
        value, lake, repo = self.run_witness()
        (repo / "Lib/Untracked.lean").write_bytes(b"theorem u : True := trivial\n")
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
        self.assertTrue(validate_witness(value, policy()))

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
        self.assertEqual(by_path(value)["Lib/A.lean"]["elaborator_sorry_declarations"], 1)
        self.assertEqual(by_path(value)["Lib/Broken.lean"]["error_lines"], 1)
        self.assertEqual(by_path(value)["TH8/Bad.lean"]["error_lines"], 1)

    def test_rejected_module_is_never_counted_as_accepted(self):
        value, lake, _repo = self.run_witness()
        self.assertEqual(by_path(value)["Lib/Broken.lean"]["status"], REJECTED)
        self.assertEqual(by_path(value)["Lib/Broken.lean"]["reason"], "ELABORATION_FAILED")
        self.assertEqual(lake.census_modules, ["Lib.A", "Lib.B", "Lib.Deep", "Lib.Exe", "Lib.Orphan", "Root"])
        self.assertNotIn("Lib.Broken", lake.programs[0])
        self.assertNotIn("import Main", lake.programs[0])
        self.assertNotIn("Lib.Broken", [m["module"] for m in value["modules"]])
        self.assertNotIn("TH8.Bad", [m["module"] for m in value["modules"]])

    def test_theorem_classes_rollups_and_carriers(self):
        value, _lake, _repo = self.run_witness()
        modules = {m["module"]: m for m in value["modules"]}
        self.assertEqual(sorted(modules), ["Lib.A", "Lib.B", "Lib.Deep", "Lib.Exe", "Lib.Orphan", "Root"])
        self.assertEqual(modules["Lib.Deep"]["path"], "Extra/Lib/Deep.lean")
        expected = {
            "Lib.A": (2, 1, 1, 0, 0, 1, 0), "Lib.B": (3, 0, 1, 1, 1, 0, 2), "Root": (2, 1, 1, 0, 0, 1, 0),
            "Lib.Deep": (1, 1, 0, 0, 0, 0, 0), "Lib.Exe": (1, 1, 0, 0, 0, 0, 0),
            "Lib.Orphan": (1, 1, 0, 0, 0, 0, 0),
        }
        keys = ("user_theorems", CLASS_CLEAN, CLASS_SORRY, CLASS_AXIOM, CLASS_NATIVE,
                "direct_sorry_declarations", "declared_axioms")
        for name, numbers in expected.items():
            self.assertEqual(tuple(modules[name][k] for k in keys), numbers, name)
            self.assertEqual(modules[name]["user_theorems"], sum(modules[name][c] for c in CLASSES))
        self.assertEqual(value["theorem_totals"], dict(zip(keys, (10, 5, 3, 1, 1, 2, 2))))
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
        rows = census_rows_for(["Lib.A", "Lib.B", "Lib.Deep", "Lib.Exe", "Lib.Orphan", "Root"])
        self.assertEqual(value["census"], {"state": "EXECUTED", "reason": None, "constants": len(rows),
                                           "modules": 6, "rows_sha256": census_digest(rows)})

    def test_kernel_executed_when_every_gate_passed(self):
        value, lake, repo = self.run_witness(fail_request=(), fail_standalone=())
        self.assertEqual(value["state"], "KERNEL_EXECUTED")
        self.assertIs(value["kernel_executed_by_this_run"], True)
        self.assertEqual(value["schema"], SCHEMA)
        self.assertEqual(value["observed_at"], NOW.isoformat())
        commit = git(repo, "rev-parse", "HEAD", home=repo.parent).decode().strip()
        self.assertEqual(value["commit"], commit)
        self.assertEqual(value["mathlib_revision"], MATHLIB_REV)
        self.assertEqual(value["manifest_sha256"], sha256_hex(FILES["lake-manifest.json"]))
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
        self.assertFalse(any("sign" in key for key in value))
        self.assertEqual(len(value["steps"]), len(lake.calls))
        for step in value["steps"]:
            self.assertRegex(step["output_sha256"], r"\A[0-9a-f]{64}\Z")
        digest(value)
        self.assertTrue(validate_witness(value, policy()))

    def test_log_dir_receives_one_log_per_step(self):
        repo = make_checkout(self.base)
        logs = self.base / "logs"
        logs.mkdir()
        value = observe(policy(), repo, toolchain_bin=self.base / "bin", run=FakeLake(), at=NOW, log_dir=logs)
        self.assertEqual(sorted(p.stem for p in logs.iterdir()), sorted(s["name"] for s in value["steps"]))
        for step in value["steps"]:
            self.assertEqual(sha256_hex((logs / (step["name"] + ".log")).read_bytes()), step["output_sha256"])

    def assert_hold(self, value):
        self.assertEqual(value["state"], "HOLD")
        self.assertIs(value["kernel_executed_by_this_run"], True)
        self.assertTrue(validate_witness(value, policy()))

    def test_hold_when_locked_guard_short_or_refused(self):
        for fake in ({"allowed": 2}, {"allowed": 4}, {"refused": 1}, {"guard_exit": 1}):
            with self.subTest(fake=fake):
                value, _lake, _repo = self.run_witness(fail_request=(), **fake)
                self.assertEqual(value["locked_guard"]["state"], "FAILED")
                self.assert_hold(value)
                self.assertIsNotNone(value["theorem_totals"])

    def test_hold_when_executable_fails(self):
        value, _lake, _repo = self.run_witness(fail_request=(), fail_exe=True)
        self.assert_hold(value)
        self.assertEqual(value["executables"][0]["state"], "FAILED")
        for path in ("Main.lean", "Lib/Exe.lean"):
            self.assertEqual(by_path(value)[path]["status"], REJECTED)
            self.assertEqual(by_path(value)[path]["reason"], "EXECUTABLE_BUILD_FAILED")
        self.assertNotIn("Lib.Exe", [m["module"] for m in value["modules"]])

    def test_hold_when_default_build_fails(self):
        value, _lake, _repo = self.run_witness(fail_request=(), fail_default=True)
        self.assert_hold(value)
        self.assertEqual(value["default_build"]["state"], "FAILED")
        for path in ("Root.lean", "Lib/A.lean", "Lib/B.lean"):
            self.assertEqual(by_path(value)[path]["status"], REJECTED)
            self.assertEqual(by_path(value)[path]["reason"], "DEFAULT_BUILD_FAILED")
        self.assertEqual(by_path(value)["Lib/B.lean"]["error_lines"], 1)

    def test_hold_when_axiom_check_mentions_sorry(self):
        value, _lake, _repo = self.run_witness(fail_request=(), axiom_log="Root.main depends on [sorryAx]\n")
        self.assertEqual(value["axiom_check"]["sorry_axiom_mentions"], 1)
        self.assert_hold(value)

    def test_census_failure_is_unavailable_not_zero(self):
        value, _lake, _repo = self.run_witness(fail_request=(), census_exit=1)
        self.assert_hold(value)
        self.assertEqual(value["census"], {"state": "UNAVAILABLE", "reason": "CENSUS_PROGRAM_FAILED",
                                           "constants": None, "modules": None, "rows_sha256": None})
        self.assertIsNone(value["theorem_totals"])
        self.assertEqual((value["modules"], value["declared_axioms"], value["sorry_sources"],
                          value["carrier_theorems"]), ([], [], [], []))

    def assert_unavailable(self, value, reason):
        self.assertEqual(value["state"], "UNAVAILABLE")
        self.assertIs(value["kernel_executed_by_this_run"], False)
        self.assertIsNone(value["theorem_totals"])
        self.assertEqual(value["census"], {"state": "UNAVAILABLE", "reason": reason, "constants": None,
                                           "modules": None, "rows_sha256": None})
        self.assertEqual((value["files"], value["modules"], value["declared_axioms"], value["sorry_sources"],
                          value["carrier_theorems"], value["executables"]), ([], [], [], [], [], []))
        self.assertIsNone(value["default_build"])
        self.assertIsNone(value["locked_guard"])
        self.assertIsNone(value["axiom_check"])
        self.assertEqual(value["file_totals"], {s: 0 for s in STATUSES})
        for flag in _FALSE_FLAGS:
            self.assertIs(value[flag], False)
        self.assertTrue(validate_witness(value, policy()))

    def test_unavailable_when_dependency_cache_absent_or_short(self):
        for cache in (0, 1):
            with self.subTest(cache=cache):
                base = Path(tempfile.mkdtemp(dir=self.base))
                repo = make_checkout(base, cache=cache)
                lake = FakeLake()
                value = observe(policy(), repo, toolchain_bin=base / "bin", run=lake, at=NOW)
                self.assert_unavailable(value, "DEPENDENCY_CACHE_ABSENT")
                self.assertEqual(lake.names(), [["lean", "--version"], ["lake", "--version"]])
                self.assertEqual(value["mathlib_revision"], MATHLIB_REV)
                self.assertFalse((repo / ".lake/build").exists())

    def test_unavailable_when_pin_differs_or_absent(self):
        for pin in (b"leanprover/lean4:v4.34.0\n", None):
            with self.subTest(pin=pin):
                files = dict(FILES)
                if pin is None:
                    del files["lean-toolchain"]
                else:
                    files["lean-toolchain"] = pin
                base = Path(tempfile.mkdtemp(dir=self.base))
                repo = make_checkout(base, files=files)
                lake = FakeLake()
                value = observe(policy(), repo, toolchain_bin=base / "bin", run=lake, at=NOW)
                self.assert_unavailable(value, "TOOLCHAIN_UNAVAILABLE_OR_PIN_MISMATCH")
                self.assertEqual(value["toolchain"]["pin_in_checkout"], None if pin is None else pin.decode().strip())
                self.assertIsNone(value["manifest_sha256"])
                self.assertEqual(len(lake.calls), 2)

    def test_unavailable_when_tools_missing(self):
        value, lake, _repo = self.run_witness(tools_missing=True)
        self.assert_unavailable(value, "TOOLCHAIN_UNAVAILABLE_OR_PIN_MISMATCH")
        self.assertIsNone(value["toolchain"]["lean_version"])
        self.assertIsNone(value["toolchain"]["lake_version"])
        self.assertEqual([s["exit_code"] for s in value["steps"]], [127, 127])

    def test_manifest_without_mathlib_rev_is_none(self):
        files = dict(FILES, **{"lake-manifest.json": b'{"packages": [{"name": "mathlib", "rev": "main"}]}'})
        value, _lake, _repo = self.run_witness(files=files)
        self.assertIsNone(value["mathlib_revision"])
        files = dict(FILES)
        del files["lake-manifest.json"]
        base = Path(tempfile.mkdtemp(dir=self.base))
        value = observe(policy(), make_checkout(base, files=files), toolchain_bin=base, run=FakeLake(), at=NOW)
        self.assertIsNone(value["manifest_sha256"])
        self.assertIsNone(value["mathlib_revision"])

    def test_dirty_tracked_file_is_refused(self):
        repo = make_checkout(self.base)
        (repo / "Lib/A.lean").write_bytes(b"theorem Lib.A.clean : False := sorry\n")
        lake = FakeLake()
        with self.assertRaisesRegex(InputError, "WITNESS_WORKTREE_DIFFERS_FROM_COMMIT"):
            observe(policy(), repo, toolchain_bin=self.base, run=lake, at=NOW)
        self.assertEqual(lake.calls, [])

    def test_staged_change_is_refused(self):
        repo = make_checkout(self.base)
        (repo / "README.md").write_bytes(b"changed\n")
        git(repo, "add", "README.md", home=self.base)
        with self.assertRaisesRegex(InputError, "WITNESS_WORKTREE_DIFFERS_FROM_COMMIT"):
            observe(policy(), repo, toolchain_bin=self.base, run=FakeLake(), at=NOW)

    def test_invalid_policy_refused_before_anything_runs(self):
        lake = FakeLake()
        with self.assertRaisesRegex(InputError, "WITNESS_POLICY_INVALID"):
            observe(policy(step_timeout_seconds=1), self.base, toolchain_bin=self.base, run=lake, at=NOW)
        self.assertEqual(lake.calls, [])

    def test_repository_without_lean_files_is_refused(self):
        repo = make_checkout(self.base, files={"README.md": b"x\n", "lean-toolchain": PIN.encode()})
        with self.assertRaisesRegex(InputError, "WITNESS_FILE_BUDGET_EXCEEDED"):
            observe(policy(), repo, toolchain_bin=self.base, run=FakeLake(), at=NOW)


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
        finally:
            temp.cleanup()

    def refuses(self, value, code):
        with self.assertRaisesRegex(InputError, code):
            validate_witness(value, policy())

    def mutated(self, change, base=None):
        value = deepcopy(self.good if base is None else base)
        change(value)
        return value


class ValidateWitnessTests(_Witnesses):
    def test_baselines_validate(self):
        self.assertEqual(self.good["state"], "KERNEL_EXECUTED")
        self.assertTrue(validate_witness(self.good, policy()))
        self.assertEqual(self.unavailable["state"], "UNAVAILABLE")
        self.assertTrue(validate_witness(self.unavailable, policy()))

    def test_closed_top_level_fields(self):
        self.refuses(self.mutated(lambda v: v.update(signature="x")), "WITNESS_FIELDS_INVALID")
        self.refuses(self.mutated(lambda v: v.pop("census")), "WITNESS_FIELDS_INVALID")
        self.refuses([self.good], "WITNESS_FIELDS_INVALID")

    def test_binding(self):
        for change in (lambda v: v.update(schema=SCHEMA + "x"),
                       lambda v: v.update(repository="szl-holdings/other"),
                       lambda v: v.update(commit="A" * 40), lambda v: v.update(commit="a" * 39),
                       lambda v: v.update(worktree_matches_commit=1),
                       lambda v: v.update(worktree_matches_commit=False),
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

    def test_steps(self):
        for change in (lambda v: v["steps"][0].update(exit_code=True),
                       lambda v: v["steps"][0].update(exit_code=0.0),
                       lambda v: v["steps"][0].update(seconds=1.5),
                       lambda v: v["steps"][0].update(seconds=-1),
                       lambda v: v["steps"][0].update(output_sha256="A" * 64),
                       lambda v: v["steps"][0].update(name="Bad-Name"),
                       lambda v: v["steps"][0].update(extra=1),
                       lambda v: v["steps"][0].pop("seconds"),
                       lambda v: v.update(steps=v["steps"] * 10),
                       lambda v: v.update(steps={})):
            self.refuses(self.mutated(change), "WITNESS_FIELDS_INVALID")

    def test_file_rows(self):
        def first(v, **kw):
            v["files"][0].update(kw)
        for change in (lambda v: first(v, status="PROVED"), lambda v: first(v, error_lines=True),
                       lambda v: first(v, error_lines=-1), lambda v: first(v, elaborator_sorry_declarations=1.0),
                       lambda v: first(v, module="bad-name"), lambda v: first(v, path="Lib/A.py"),
                       lambda v: first(v, reason="lower"), lambda v: first(v, extra=1),
                       lambda v: v["files"][0].pop("reason")):
            self.refuses(self.mutated(change), "WITNESS_FILE_FIELDS_INVALID")

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
                       lambda v: v["census"].pop("modules"),
                       lambda v: v.update(modules={})):
            self.refuses(self.mutated(change), "WITNESS_FIELDS_INVALID")

    def test_module_rows(self):
        def module(v, name):
            return next(m for m in v["modules"] if m["module"] == name)
        self.refuses(self.mutated(lambda v: module(v, "Lib.A").update(module="Other.Outside")),
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
                     "WITNESS_MODULE_ORDER_OR_DUPLICATE")

    def test_theorem_totals(self):
        self.refuses(self.mutated(lambda v: v["theorem_totals"].update(
            user_theorems=v["theorem_totals"]["user_theorems"] + 1)),
                     "WITNESS_THEOREM_TOTALS_DRIFT")
        self.refuses(self.mutated(lambda v: v["theorem_totals"].pop(CLASS_NATIVE)), "WITNESS_FIELDS_INVALID")
        self.refuses(self.mutated(lambda v: v.update(theorem_totals=None)), "WITNESS_FIELDS_INVALID")

    def test_declared_axioms_and_sorry_sources(self):
        for change in (lambda v: v["declared_axioms"].pop(), lambda v: v["declared_axioms"].reverse(),
                       lambda v: v["declared_axioms"][0].update(extra=1),
                       lambda v: v["declared_axioms"][0].pop("user_theorem_load")):
            self.refuses(self.mutated(change), "WITNESS_AXIOM_LIST_INVALID")
        for change in (lambda v: v["sorry_sources"].pop(), lambda v: v["sorry_sources"].reverse(),
                       lambda v: v["sorry_sources"][0].pop("taints")):
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
        self.refuses(self.mutated(lambda v: v["executables"].append(deepcopy(v["executables"][0]))),
                     "WITNESS_EXECUTABLES_INVALID")
        self.refuses(self.mutated(lambda v: v.update(executables=None)), "WITNESS_EXECUTABLES_INVALID")

    def test_kernel_executed_requires_every_gate(self):
        for change in (lambda v: v["default_build"].update(state="FAILED"),
                       lambda v: v.update(default_build=None),
                       lambda v: v["locked_guard"].update(state="FAILED"),
                       lambda v: v["locked_guard"].update(allowed=2),
                       lambda v: v["locked_guard"].update(refused=1),
                       lambda v: v["axiom_check"].update(state="FAILED"),
                       lambda v: v.update(axiom_check=None),
                       lambda v: v["executables"][0].update(state="FAILED"),
                       lambda v: v.update(executables=[]),
                       lambda v: v["toolchain"].update(pin_in_checkout="leanprover/lean4:v4.34.0"),
                       lambda v: v.update(toolchain=None)):
            self.refuses(self.mutated(change), "WITNESS_STATE_DRIFT")
        self.assertTrue(validate_witness(self.mutated(lambda v: (v.update(state="HOLD"),
                                                                 v["locked_guard"].update(state="FAILED"))),
                                         policy()))

    def test_unavailable_must_stay_unknown_not_zero(self):
        zeros = {k: 0 for k in self.good["theorem_totals"]}
        for change in (lambda v: v.update(theorem_totals=zeros), lambda v: v["census"].update(constants=0),
                       lambda v: v["census"].update(rows_sha256="0" * 64),
                       lambda v: v.update(declared_axioms=[{"decl": "x"}]),
                       lambda v: v.update(sorry_sources=[{}]),
                       lambda v: v.update(carrier_theorems=[{}]),
                       lambda v: v.update(modules=[{"module": "Lib.A"}]),
                       lambda v: v.update(state="KERNEL_EXECUTED", kernel_executed_by_this_run=True)):
            self.refuses(self.mutated(change, self.unavailable), "WITNESS_UNAVAILABLE_NOT_UNKNOWN")

        def census_lost(v):
            v["census"].update(state="UNAVAILABLE", reason="CENSUS_PROGRAM_FAILED", constants=None,
                               modules=None, rows_sha256=None)
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

    def call(self, *extra, output=None, policy_path=None, toolchain=None):
        args = ["--policy", str(policy_path or self.policy_path), "--lean-checkout", str(self.repo),
                "--toolchain-bin", str(toolchain or self.bin), "--output", str(output or self.base / "w.json"),
                *extra]
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main(args)
        return code, json.loads(buffer.getvalue().strip().splitlines()[-1])

    def test_kernel_executed_through_cli_and_never_overwrites(self):
        logs = self.base / "logs"
        logs.mkdir()
        output = self.base / "out" / "witness.json"
        output.parent.mkdir()
        with mock.patch.object(witness_module, "_runner", lambda _bin, _home: FakeLake(fail_request=())):
            code, summary = self.call("--log-dir", str(logs), output=output)
            self.assertEqual(code, 0)
            self.assertEqual(summary["state"], "KERNEL_EXECUTED")
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

    def test_hold_exit_code(self):
        with mock.patch.object(witness_module, "_runner", lambda _bin, _home: FakeLake(allowed=1)):
            code, summary = self.call()
        self.assertEqual(code, 2)
        self.assertEqual(summary["state"], "HOLD")
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
        self.assertEqual(self.call(output=output)[0], 3)

    def test_output_inside_repository_refused(self):
        inside = ROOT / "tests" / "braid_lean_witness_should_never_exist.json"
        self.addCleanup(lambda: inside.unlink() if inside.exists() else None)
        code, summary = self.call(output=inside)
        self.assertEqual(code, 3)
        self.assertEqual(summary["code"], "OUTPUT_PATH_DENIED")
        self.assertFalse(inside.exists())

    def test_cli_refusals(self):
        code, summary = self.call(toolchain=Path("relative/bin"))
        self.assertEqual((code, summary["code"]), (3, "WITNESS_TOOLCHAIN_UNAVAILABLE"))
        code, summary = self.call(toolchain=self.base / "nowhere")
        self.assertEqual((code, summary["code"]), (3, "WITNESS_TOOLCHAIN_UNAVAILABLE"))
        code, summary = self.call("--log-dir", str(ROOT / "tests"))
        self.assertEqual((code, summary["code"]), (3, "WITNESS_LOG_DIRECTORY_DENIED"))
        code, summary = self.call("--log-dir", str(self.base / "missing"))
        self.assertEqual((code, summary["code"]), (3, "WITNESS_LOG_DIRECTORY_DENIED"))
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
