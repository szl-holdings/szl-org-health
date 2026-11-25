# SPDX-License-Identifier: Apache-2.0
"""Synthetic, offline regression suite for the braid v2 source census: census-policy and family-map refusals,
cord-key percent-encoding, text-level Lean sorry counting, list_tree/read_blobs over throwaway git repositories,
observe() accounting and honest UNAVAILABLE rows, committed-bytes-only reading, a one-change-at-a-time
validate_census tamper matrix and the create-exclusive CLI. Every repository, file and policy is made up here
inside temporary directories; nothing touches a network, a Lean toolchain or this checkout's git state.
"""
from contextlib import redirect_stdout
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import TestCase, main as unittest_main, mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.database_catalog_admission import InputError  # noqa: E402
from tools.database_braid_common import canonical, digest, git_blob_sha1, strict_json  # noqa: E402
from tools import database_braid_source_census as census_tool  # noqa: E402
from tools.database_braid_source_census import (  # noqa: E402
    FAMILY_MAP_SCHEMA, IDENTITIES, LFS_MAGIC, SCHEMA, UNCLASSIFIED, _FALSE_FLAGS, checkout_identity,
    cord_key, export_tree, lean_text_sorry_tokens, list_tree, main, observe, read_blobs,
    validate_census, validate_census_policy, validate_family_map, verify_census_checkouts,
)

NOW = datetime(2026, 11, 19, 6, 30, tzinfo=timezone.utc)
ALPHA, BETA, GAMMA = "szl-holdings/alpha", "szl-holdings/beta", "szl-holdings/gamma"
CAP = 256
EMPTY_BLOB = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
LEAN_TEXT = (b"theorem t : True := sorry\n-- sorry in a line comment\n/- sorry /- nested sorry -/ -/\n"
             b"example : True := by sorry\ndef sorryAx' := 1\n")
SPACED = "docs/my file é.md"
LFS_POINTER = LFS_MAGIC + b"\noid sha256:" + b"4" * 64 + b"\nsize 12345\n"
ALPHA_FILES = {
    "README.md": b"# alpha\n",
    "src/a.lean": LEAN_TEXT,
    "src/b.py": b"#!/usr/bin/env python3\nprint('never executed')\n",
    SPACED: b"same bytes\n",
    "docs/dup.txt": b"same bytes\n",
    "docs/empty.txt": b"",
    "docs/cap.bin": b"c" * CAP,
    "docs/big.bin": b"b" * (CAP + 1),
    "docs/lfs.bin": LFS_POINTER,
    "build/out.lean": b"theorem built : True := sorry\n",
}
SUBMODULE_SHA = "1" * 40


def git(repo, *args, home):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "Synthetic Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
           "GIT_COMMITTER_NAME": "Synthetic Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
           "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"}
    proc = subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", *args],
                          cwd=str(repo), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    return proc.stdout


def make_repo(base, name, files, *, symlinks=(), executables=(), submodules=(), commit=True):
    repo = Path(base) / name
    repo.mkdir(parents=True)
    git(repo, "init", "-q", home=base)
    for path, raw in files.items():
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        if path in executables:
            target.chmod(0o755)
    for path, points_to in symlinks:
        (repo / path).parent.mkdir(parents=True, exist_ok=True)
        os.symlink(points_to, repo / path)
    git(repo, "add", "-A", home=base)
    for path, sha in submodules:
        git(repo, "update-index", "--add", "--cacheinfo", f"160000,{sha},{path}", home=base)
    if commit:
        git(repo, "commit", "-q", "-m", "synthetic fixture", home=base)
    return repo


def make_alpha(base):
    return make_repo(base, "alpha", ALPHA_FILES, symlinks=[("docs/link.md", "../README.md")],
                     executables=("src/b.py",), submodules=[("vendor/sub", SUBMODULE_SHA)])


def alpha_policy(**overrides):
    repo = {"repository": ALPHA, "include": ["src/*", "docs/*", "build/*"], "exclude": ["build/*"],
            "families": [{"glob": "src/*.lean", "family": "LEAN_CORE"},
                         {"glob": "src/*", "family": "PY_TOOLS"}]}
    repo.update(overrides)
    return repo


def beta_policy():
    return {"repository": BETA, "include": ["*"], "exclude": [], "families": [{"glob": "*", "family": "BETA_ALL"}]}


def gamma_policy():
    return {"repository": GAMMA, "include": ["*"], "exclude": [], "families": []}


def section(*repos, max_cords=100, max_blob_bytes=CAP):
    return {"max_cords": max_cords, "max_blob_bytes": max_blob_bytes, "repositories": list(repos)}


def family_map(families=None, status="MACHINE_PROPOSED_UNRATIFIED"):
    return {"schema": FAMILY_MAP_SCHEMA, "review_status": status,
            "families": {ALPHA: {"src/a.lean": "EXPLICIT_PICK"}} if families is None else families}


def row_of(report, name):
    return next(r for r in report["repositories"] if r["repository"] == name)


def cord_of(report, path):
    return next(c for c in report["cords"] if c["path"] == path)


_FIXTURE = {}


def setUpModule():
    temp = tempfile.TemporaryDirectory()
    _FIXTURE["temp"] = temp
    base = Path(temp.name)
    _FIXTURE.update(base=base, alpha=make_alpha(base),
                    beta=make_repo(base, "beta", {"one.txt": b"one\n", "two/three.md": b"three\n"}))


def tearDownModule():
    _FIXTURE.pop("temp").cleanup()


class _Repos(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base, cls.alpha, cls.beta = _FIXTURE["base"], _FIXTURE["alpha"], _FIXTURE["beta"]


class CensusPolicyTests(TestCase):
    def setUp(self):
        self.section = section(alpha_policy(), beta_policy(), gamma_policy())

    def refuses(self, value, code):
        with self.assertRaisesRegex(InputError, code):
            validate_census_policy(value)

    def test_valid_policy_returns_repositories(self):
        self.assertEqual([r["repository"] for r in validate_census_policy(self.section)], [ALPHA, BETA, GAMMA])

    def test_shipped_braid_v2_census_policy_and_family_map_validate(self):
        policy = json.loads((ROOT / "governance/database_contracts/ouroboros_braid_v2.json").read_text())
        self.assertTrue(validate_census_policy(policy["census"]))
        raw_map = json.loads((ROOT / "governance/database_contracts/braid_family_map_v1.json").read_text())
        self.assertIsInstance(validate_family_map(raw_map), dict)

    def test_section_field_set_is_closed(self):
        extra = deepcopy(self.section)
        extra["signed"] = False
        self.refuses(extra, "CENSUS_POLICY_FIELDS_INVALID")
        for field in ("max_cords", "max_blob_bytes", "repositories"):
            missing = deepcopy(self.section)
            del missing[field]
            self.refuses(missing, "CENSUS_POLICY_FIELDS_INVALID")
        self.refuses([self.section], "CENSUS_POLICY_FIELDS_INVALID")

    def test_budgets_are_positive_bounded_ints(self):
        for field, bad in (("max_cords", 0), ("max_cords", -1), ("max_cords", True), ("max_cords", 5.0),
                           ("max_cords", "5"), ("max_cords", 50001), ("max_blob_bytes", 0),
                           ("max_blob_bytes", False), ("max_blob_bytes", 67108865), ("max_blob_bytes", 1.5)):
            value = deepcopy(self.section)
            value[field] = bad
            with self.subTest(field=field, bad=bad):
                self.refuses(value, "CENSUS_POLICY_INVALID")
        edge = deepcopy(self.section)
        edge.update(max_cords=50000, max_blob_bytes=67108864)
        validate_census_policy(edge)

    def test_repository_list_shape(self):
        for bad in ([], None, tuple(self.section["repositories"]),
                    [dict(gamma_policy(), repository=f"szl-holdings/r{i:02d}") for i in range(33)]):
            value = deepcopy(self.section)
            value["repositories"] = bad
            with self.subTest(bad=type(bad).__name__):
                self.refuses(value, "CENSUS_POLICY_INVALID")

    def test_repository_entry_refusals(self):
        extra = deepcopy(self.section)
        extra["repositories"][0]["authorized"] = False
        self.refuses(extra, "CENSUS_REPOSITORY_FIELDS_INVALID")
        missing = deepcopy(self.section)
        del missing["repositories"][0]["families"]
        self.refuses(missing, "CENSUS_REPOSITORY_FIELDS_INVALID")
        for bad in ("other-org/alpha", "szl-holdings/", "szl-holdings/a b", 7, None, "szl-holdings/x/y"):
            value = deepcopy(self.section)
            value["repositories"][0]["repository"] = bad
            with self.subTest(bad=bad):
                self.refuses(value, "CENSUS_REPOSITORY_INVALID")

    def test_glob_refusals(self):
        for field, bad in (("include", []), ("include", ["has space/*"]), ("include", [7]),
                           ("include", "src/*"), ("include", ["x" * 201]), ("exclude", ["a;b"]),
                           ("exclude", None), ("exclude", ["ok/*", ""]), ("include", ["*"] * 201)):
            value = deepcopy(self.section)
            value["repositories"][0][field] = bad
            with self.subTest(field=field, bad=str(bad)[:20]):
                self.refuses(value, "CENSUS_GLOB_INVALID")

    def test_family_rule_refusals(self):
        bads = ("not a list", [{"glob": "*"}], [{"glob": "*", "family": "OK_FAMILY", "extra": 1}],
                [{"glob": "*", "family": "lowercase"}], [{"glob": "*", "family": "A"}],
                [{"glob": "*", "family": "A" * 49}], [{"glob": "bad glob", "family": "OK_FAMILY"}],
                [{"glob": "*", "family": 3}], [{"glob": "*", "family": "OK_FAMILY"}] * 201)
        for bad in bads:
            value = deepcopy(self.section)
            value["repositories"][0]["families"] = bad
            with self.subTest(bad=str(bad)[:40]):
                self.refuses(value, "CENSUS_FAMILY_RULES_INVALID")

    def test_repositories_sorted_and_unique(self):
        reordered = deepcopy(self.section)
        reordered["repositories"].reverse()
        self.refuses(reordered, "CENSUS_REPOSITORY_ORDER_OR_DUPLICATE")
        duplicated = section(alpha_policy(), alpha_policy())
        self.refuses(duplicated, "CENSUS_REPOSITORY_ORDER_OR_DUPLICATE")


class FamilyMapTests(TestCase):
    def refuses(self, value):
        with self.assertRaisesRegex(InputError, "CENSUS_FAMILY_MAP_INVALID"):
            validate_family_map(value)

    def test_valid_maps(self):
        self.assertEqual(validate_family_map(family_map()), {ALPHA: {"src/a.lean": "EXPLICIT_PICK"}})
        self.assertEqual(validate_family_map(family_map({}, "OWNER_RATIFIED")), {})

    def test_refusals_one_change_at_a_time(self):
        good = family_map()
        mutations = {
            "schema": lambda v: v.update(schema="szl.database-braid-family-map/v2"),
            "status": lambda v: v.update(review_status="RATIFIED"),
            "families_list": lambda v: v.update(families=[]),
            "extra": lambda v: v.update(signed=False),
            "missing": lambda v: v.pop("review_status"),
            "repo_key": lambda v: v["families"].update({"other/alpha": {}}),
            "paths_list": lambda v: v["families"].update({BETA: ["x"]}),
            "empty_path": lambda v: v["families"][ALPHA].update({"": "OK_FAMILY"}),
            "long_path": lambda v: v["families"][ALPHA].update({"p" * 401: "OK_FAMILY"}),
            "lower_family": lambda v: v["families"][ALPHA].update({"x": "lower"}),
            "int_family": lambda v: v["families"][ALPHA].update({"x": 1}),
        }
        for name, mutate in mutations.items():
            value = deepcopy(good)
            mutate(value)
            with self.subTest(name):
                self.refuses(value)
        self.refuses(None)
        edge = deepcopy(good)
        edge["families"][ALPHA]["p" * 400] = "OK_FAMILY"
        validate_family_map(edge)


class CordKeyAndSorryTests(TestCase):
    def test_cord_key_percent_encodes_unusual_characters(self):
        self.assertEqual(cord_key(ALPHA, "src/a.lean"), "alpha:src/a.lean")
        self.assertEqual(cord_key(ALPHA, SPACED), "alpha:docs/my%20file%20%C3%A9.md")
        self.assertEqual(cord_key(ALPHA, "a/b_c.d+e@f-g"), "alpha:a/b_c.d+e@f-g")
        self.assertEqual(cord_key(ALPHA, "x:y#z?w%"), "alpha:x%3Ay%23z%3Fw%25")
        self.assertEqual(cord_key(ALPHA, "line\nbreak"), "alpha:line%0Abreak")

    def test_cord_key_is_injective_on_lookalike_paths(self):
        paths = ["a b", "a%20b", "a%2520b", "a+b", "aé", "a%C3%A9"]
        keys = [cord_key(ALPHA, p) for p in paths]
        self.assertEqual(len(set(keys)), len(paths))
        self.assertNotEqual(cord_key(ALPHA, "x"), cord_key(BETA, "x"))

    def test_sorry_tokens_outside_comments_only(self):
        cases = {
            b"": 0, b"sorry": 1, b"(sorry)": 1, b"by sorry\nexact sorry\n": 2,
            b"-- sorry\n": 0, b"/- sorry -/": 0, b"/- a /- sorry -/ sorry -/ x": 0,
            b"/- a /- b -/ still comment sorry -/ sorry": 1, b"sorryAx": 0, b"x_sorry": 0,
            b"Foo.sorry": 0, b"sorry'": 0, b"sorry!": 0, b"\xff sorry \xfe": 1, LEAN_TEXT: 2,
            # Lean reads a block comment as whitespace, so it never hides a token next to it.
            b"theorem t : True := by/- c -/sorry": 1, b"exact/- why -/sorry": 1,
            b"by/- a /- b -/ c -/sorry/- d -/": 1,
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(lean_text_sorry_tokens(raw), expected)

    def test_a_path_with_no_utf8_form_is_a_typed_refusal(self):
        with self.assertRaisesRegex(InputError, "CENSUS_PATH_NOT_UTF"):
            cord_key(ALPHA, "Lutar/X\ud800.lean")


class ListTreeAndBlobTests(_Repos):
    def test_list_tree_reports_committed_tree(self):
        commit, shallow, rows = list_tree(self.alpha)
        self.assertEqual(commit, git(self.alpha, "rev-parse", "HEAD", home=self.base).decode().strip())
        self.assertIs(shallow, False)
        by_path = {r[4]: r for r in rows}
        tracked = git(self.alpha, "ls-files", "-z", home=self.base).decode("utf-8").split("\0")
        self.assertEqual(sorted(by_path), sorted(p for p in tracked if p))
        self.assertIn(SPACED, by_path)
        self.assertEqual(by_path["src/b.py"][:2], ("100755", "blob"))
        self.assertEqual(by_path["src/a.lean"][:2], ("100644", "blob"))
        self.assertEqual(by_path["docs/link.md"][:2], ("120000", "blob"))
        self.assertEqual(by_path["vendor/sub"][:3], ("160000", "commit", SUBMODULE_SHA))
        self.assertEqual(by_path["docs/empty.txt"][2:4], (EMPTY_BLOB, 0))
        self.assertIsNone(by_path["vendor/sub"][3])
        for path, raw in ALPHA_FILES.items():
            self.assertEqual(by_path[path][2], git_blob_sha1(raw), path)
            self.assertEqual(by_path[path][3], len(raw), path)

    def test_list_tree_refuses_unusable_checkouts(self):
        with self.assertRaisesRegex(InputError, "CENSUS_CHECKOUT_UNAVAILABLE"):
            list_tree(self.base / "does-not-exist")
        link = self.base / "alpha-link"
        if not link.exists():
            os.symlink(self.alpha, link)
        with self.assertRaisesRegex(InputError, "CENSUS_CHECKOUT_UNAVAILABLE"):
            list_tree(link)
        with tempfile.TemporaryDirectory() as temp:
            plain = Path(temp) / "plain"
            plain.mkdir()
            with self.assertRaises(InputError) as caught:
                list_tree(plain)
            self.assertIn(caught.exception.code, ("CENSUS_GIT_REFUSED", "CENSUS_CHECKOUT_UNAVAILABLE"))
            unborn = make_repo(temp, "unborn", {"x.txt": b"x\n"}, commit=False)
            with self.assertRaisesRegex(InputError, "CENSUS_GIT_REFUSED"):
                list_tree(unborn)

    def test_list_tree_reports_shallow_clone(self):
        with tempfile.TemporaryDirectory() as temp:
            git(temp, "clone", "-q", "--depth", "1", self.beta.resolve().as_uri(), "shallow", home=temp)
            commit, shallow, rows = list_tree(Path(temp) / "shallow")
            self.assertIs(shallow, True)
            self.assertEqual(commit, list_tree(self.beta)[0])
            self.assertEqual(len(rows), 2)

    def test_read_blobs_returns_committed_bytes_and_caps(self):
        shas = sorted({git_blob_sha1(raw) for raw in ALPHA_FILES.values()})
        blobs = read_blobs(self.alpha, shas, max_bytes=CAP)
        self.assertEqual(set(blobs), set(shas))
        self.assertEqual(blobs[EMPTY_BLOB], b"")
        self.assertEqual(blobs[git_blob_sha1(b"c" * CAP)], b"c" * CAP)
        self.assertIsNone(blobs[git_blob_sha1(b"b" * (CAP + 1))])
        self.assertEqual(blobs[git_blob_sha1(LFS_POINTER)], LFS_POINTER)
        for raw in ALPHA_FILES.values():
            if len(raw) <= CAP:
                self.assertEqual(blobs[git_blob_sha1(raw)], raw)
        self.assertEqual(read_blobs(self.alpha, [], max_bytes=CAP), {})

    def test_read_blobs_refuses_absent_object(self):
        with self.assertRaisesRegex(InputError, "CENSUS_BLOB_PARSE_FAILED"):
            read_blobs(self.alpha, ["2" * 40], max_bytes=CAP)


class ObserveTests(_Repos):
    def observe_all(self, **kwargs):
        return observe(section(alpha_policy(), beta_policy(), gamma_policy()),
                       {ALPHA: self.alpha, BETA: self.beta}, at=NOW, **kwargs)

    def test_missing_checkout_is_unavailable_with_unknown_counts(self):
        report = self.observe_all()
        self.assertEqual(report["schema"], SCHEMA)
        self.assertEqual(report["state"], "PARTIAL")
        self.assertEqual((report["repositories_required"], report["repositories_observed"]), (3, 2))
        gamma = row_of(report, GAMMA)
        self.assertEqual(gamma["state"], "UNAVAILABLE")
        for field, value in gamma.items():
            if field not in ("repository", "state"):
                with self.subTest(field=field):
                    self.assertIsNone(value)
                    self.assertIsNot(value, 0)
        self.assertFalse([c for c in report["cords"] if c["repository"] == GAMMA])
        self.assertEqual(report["observed_at"], NOW.isoformat())
        canonical(report)

    def test_nothing_observed_is_partial_never_complete_or_empty(self):
        report = observe(section(beta_policy(), gamma_policy()), {}, at=NOW)
        self.assertEqual(report["state"], "PARTIAL")
        self.assertEqual(report["repositories_observed"], 0)
        self.assertTrue(all(r["state"] == "UNAVAILABLE" and r["tracked_files"] is None
                            for r in report["repositories"]))

    def test_accounting_identity_and_counts(self):
        report = self.observe_all()
        alpha = row_of(report, ALPHA)
        self.assertEqual(alpha["state"], "OBSERVED")
        self.assertEqual(alpha["tracked_files"], 12)
        self.assertEqual(alpha["symlink_or_submodule_entries"], 2)
        self.assertEqual(alpha["out_of_scope_files"], 2)
        self.assertEqual(alpha["in_scope_files"], 8)
        self.assertEqual((alpha["cords"], alpha["unavailable_cords"]), (6, 2))
        for row in report["repositories"]:
            if row["state"] != "OBSERVED":
                continue
            with self.subTest(row["repository"]):
                self.assertEqual(row["tracked_files"], row["in_scope_files"] + row["out_of_scope_files"]
                                 + row["symlink_or_submodule_entries"])
                self.assertEqual(row["in_scope_files"], row["cords"] + row["unavailable_cords"])
                self.assertEqual(row["cords"], sum(c["repository"] == row["repository"] for c in report["cords"]))
        self.assertEqual(sum(r["unavailable_cords"] or 0 for r in report["repositories"]),
                         len(report["unavailable_cords"]))
        self.assertEqual(row_of(report, BETA)["tracked_files"], 2)

    def test_cords_carry_committed_digests(self):
        report = self.observe_all()
        alpha_paths = sorted(c["path"] for c in report["cords"] if c["repository"] == ALPHA)
        self.assertEqual(alpha_paths, sorted(["src/a.lean", "src/b.py", SPACED, "docs/dup.txt",
                                              "docs/empty.txt", "docs/cap.bin"]))
        for path in alpha_paths:
            cord, raw = cord_of(report, path), ALPHA_FILES[path]
            with self.subTest(path=path):
                self.assertEqual(cord["key"], cord_key(ALPHA, path))
                self.assertEqual(cord["blob_sha1"], git_blob_sha1(raw))
                self.assertEqual(cord["sha256"], hashlib.sha256(raw).hexdigest())
                self.assertEqual(cord["bytes"], len(raw))
                self.assertEqual(cord["is_lean"], path.endswith(".lean"))
        self.assertEqual(cord_of(report, SPACED)["key"], "alpha:docs/my%20file%20%C3%A9.md")
        self.assertEqual(cord_of(report, "docs/empty.txt")["bytes"], 0)
        self.assertEqual(cord_of(report, "src/a.lean")["lean_text_sorry_tokens"], 2)
        self.assertEqual(cord_of(report, "src/b.py")["lean_text_sorry_tokens"], 0)
        self.assertEqual(report["unavailable_cords"], [
            {"key": "alpha:docs/big.bin", "repository": ALPHA, "path": "docs/big.bin",
             "reason": "BLOB_OVER_SIZE_CAP"},
            {"key": "alpha:docs/lfs.bin", "repository": ALPHA, "path": "docs/lfs.bin",
             "reason": "LFS_POINTER_CONTENT_ABSENT"},
        ])
        keys = [c["key"] for c in report["cords"]]
        self.assertEqual(keys, sorted(set(keys)))
        excluded = {c["path"] for c in report["cords"]} & {"build/out.lean", "README.md", "docs/link.md",
                                                           "vendor/sub"}
        self.assertEqual(excluded, set())

    def test_honest_labels_never_signed_or_authorized(self):
        report = self.observe_all()
        self.assertIs(report["git_object_bytes_checked_by_this_collector"], True)
        for flag in _FALSE_FLAGS:
            self.assertIs(report[flag], False, flag)
        self.assertIsNone(report["policy_sha256"])
        self.assertIsNone(report["family_map_sha256"])
        text = json.dumps(report).lower()
        for word in ("signature", "signed", "authorized", "verified\": true"):
            self.assertNotIn(word, text)

    def test_family_rules_map_precedence_and_unclassified_default(self):
        plain = self.observe_all()
        self.assertEqual(cord_of(plain, "src/a.lean")["family"], "LEAN_CORE")
        self.assertEqual(cord_of(plain, "src/b.py")["family"], "PY_TOOLS")
        self.assertEqual(cord_of(plain, SPACED)["family"], UNCLASSIFIED)
        self.assertEqual(cord_of(plain, "one.txt")["family"], "BETA_ALL")
        explicit = validate_family_map(family_map({
            ALPHA: {"src/a.lean": "EXPLICIT_PICK", "docs/empty.txt": "EXPLICIT_EMPTY",
                    "build/out.lean": "NEVER_IN_SCOPE"},
            BETA: {"src/b.py": "WRONG_REPOSITORY"},
        }))
        mapped = self.observe_all(family_map=explicit, family_map_sha256="f" * 64)
        self.assertEqual(cord_of(mapped, "src/a.lean")["family"], "EXPLICIT_PICK")
        self.assertEqual(cord_of(mapped, "docs/empty.txt")["family"], "EXPLICIT_EMPTY")
        self.assertEqual(cord_of(mapped, "src/b.py")["family"], "PY_TOOLS")
        self.assertNotIn("build/out.lean", {c["path"] for c in mapped["cords"]})
        self.assertEqual(mapped["family_map_sha256"], "f" * 64)
        self.assertEqual([c["key"] for c in mapped["cords"]], [c["key"] for c in plain["cords"]])

    def test_include_and_exclude_globs(self):
        only_md = observe(section(alpha_policy(include=["docs/*.md"], exclude=[])), {ALPHA: self.alpha}, at=NOW)
        self.assertEqual([c["path"] for c in only_md["cords"]], [SPACED])
        row = row_of(only_md, ALPHA)
        self.assertEqual((row["in_scope_files"], row["out_of_scope_files"]), (1, 9))
        self.assertEqual(only_md["state"], "COMPLETE")
        case = observe(section(alpha_policy(include=["DOCS/*"], exclude=[])), {ALPHA: self.alpha}, at=NOW)
        self.assertEqual((case["cords"], row_of(case, ALPHA)["out_of_scope_files"]), ([], 10))
        excluded = observe(section(alpha_policy(include=["docs/*"], exclude=["docs/*.bin", "docs/dup.txt"])),
                           {ALPHA: self.alpha}, at=NOW)
        self.assertEqual(sorted(c["path"] for c in excluded["cords"]), sorted([SPACED, "docs/empty.txt"]))
        self.assertEqual(excluded["unavailable_cords"], [])
        self.assertEqual(excluded["state"], "COMPLETE")

    def test_checkout_mapping_and_budget_refusals(self):
        with self.assertRaisesRegex(InputError, "CENSUS_CHECKOUT_NOT_IN_POLICY"):
            observe(section(beta_policy()), {ALPHA: self.alpha, BETA: self.beta}, at=NOW)
        with self.assertRaisesRegex(InputError, "CENSUS_CHECKOUT_NOT_IN_POLICY"):
            observe(section(beta_policy()), [(BETA, self.beta)], at=NOW)
        with self.assertRaisesRegex(InputError, "CENSUS_CORD_BUDGET_EXCEEDED"):
            observe(section(alpha_policy(), max_cords=5), {ALPHA: self.alpha}, at=NOW)
        with self.assertRaisesRegex(InputError, "CENSUS_CHECKOUT_UNAVAILABLE"):
            observe(section(beta_policy()), {BETA: self.base / "missing"}, at=NOW)
        with self.assertRaisesRegex(InputError, "CENSUS_POLICY_INVALID"):
            observe(section(beta_policy(), max_cords=0), {BETA: self.beta}, at=NOW)

    def test_census_reads_committed_bytes_not_working_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            files = {"kept.txt": b"committed kept\n", "gone.txt": b"committed gone\n",
                     "staged.txt": b"committed staged\n"}
            repo = make_repo(temp, "wt", files)
            policy = section({"repository": BETA, "include": ["*"], "exclude": [], "families": []})
            before = observe(policy, {BETA: repo}, at=NOW)
            (repo / "kept.txt").write_bytes(b"edited in the working tree only\n")
            (repo / "gone.txt").unlink()
            (repo / "staged.txt").write_bytes(b"staged but not committed\n")
            git(repo, "add", "staged.txt", home=temp)
            (repo / "untracked.txt").write_bytes(b"never committed\n")
            after = observe(policy, {BETA: repo}, at=NOW)
            self.assertEqual(after, before)
            self.assertEqual(sorted(c["path"] for c in after["cords"]), sorted(files))
            for path, raw in files.items():
                self.assertEqual(cord_of(after, path)["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(row_of(after, BETA)["tracked_files"], 3)
            self.assertEqual(git(repo, "status", "--porcelain", home=temp).count(b"\n"), 4)


class ValidateCensusTamperTests(_Repos):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.section = section(alpha_policy(), beta_policy(), gamma_policy())
        cls.report = observe(cls.section, {ALPHA: cls.alpha, BETA: cls.beta}, at=NOW,
                             policy_sha256="a" * 64)
        cls.complete_section = section(beta_policy())
        cls.complete = observe(cls.complete_section, {BETA: cls.beta}, at=NOW)

    def refuses(self, mutate, code, *, base=None, policy=None):
        value = deepcopy(self.report if base is None else base)
        mutate(value)
        with self.assertRaisesRegex(InputError, code):
            validate_census(value, self.section if policy is None else policy)

    def alpha_row(self, value):
        return row_of(value, ALPHA)

    def test_untampered_reports_validate(self):
        self.assertEqual(validate_census(deepcopy(self.report), self.section), self.report["cords"])
        self.assertEqual(self.complete["state"], "COMPLETE")
        validate_census(deepcopy(self.complete), self.complete_section)

    def test_report_survives_canonical_json_round_trip(self):
        again = json.loads(canonical(self.report))
        validate_census(again, self.section)

    def test_dropped_or_duplicated_cords(self):
        self.refuses(lambda v: v["cords"].pop(0), "CENSUS_CORD_COUNT_MISMATCH")
        self.refuses(lambda v: v["unavailable_cords"].pop(), "CENSUS_CORD_COUNT_MISMATCH")
        self.refuses(lambda v: v["cords"].insert(0, deepcopy(v["cords"][0])), "CENSUS_CORD_ORDER_OR_DUPLICATE")
        self.refuses(lambda v: v["unavailable_cords"].append(deepcopy(v["unavailable_cords"][-1])),
                     "CENSUS_CORD_ORDER_OR_DUPLICATE")

    def test_reordered_lists(self):
        self.refuses(lambda v: v["cords"].reverse(), "CENSUS_CORD_ORDER_OR_DUPLICATE")
        self.refuses(lambda v: v["unavailable_cords"].reverse(), "CENSUS_CORD_ORDER_OR_DUPLICATE")
        self.refuses(lambda v: v["repositories"].reverse(), "CENSUS_REPOSITORY_COVERAGE_INVALID")
        self.refuses(lambda v: v["repositories"].pop(), "CENSUS_REPOSITORY_COVERAGE_INVALID")
        self.refuses(lambda v: v.update(repositories=v["repositories"][:1] * 3), "CENSUS_REPOSITORY_COVERAGE_INVALID")

    def test_changed_blob_id_and_digests(self):
        for bad in ("A" * 40, "a" * 39, "a" * 41, "a" * 64, None, 0):
            with self.subTest(blob=bad):
                self.refuses(lambda v: v["cords"][0].update(blob_sha1=bad), "CENSUS_CORD_FIELDS_INVALID")
        for bad in ("A" * 64, "a" * 63, "a" * 40, None):
            with self.subTest(sha256=bad):
                self.refuses(lambda v: v["cords"][0].update(sha256=bad), "CENSUS_CORD_FIELDS_INVALID")
        self.refuses(lambda v: v["cords"][0].update(key=v["cords"][0]["key"] + "x"), "CENSUS_CORD_FIELDS_INVALID")
        self.refuses(lambda v: v["cords"][0].update(path=v["cords"][0]["path"] + "x"), "CENSUS_CORD_FIELDS_INVALID")
        self.refuses(lambda v: v.update(policy_sha256="nope"), "CENSUS_FIELDS_INVALID")
        self.refuses(lambda v: v.update(family_map_sha256="F" * 64), "CENSUS_FIELDS_INVALID")

    def test_wrong_counts(self):
        self.refuses(lambda v: self.alpha_row(v).update(tracked_files=13), "CENSUS_FILE_ACCOUNTING_BROKEN")
        self.refuses(lambda v: self.alpha_row(v).update(out_of_scope_files=1), "CENSUS_FILE_ACCOUNTING_BROKEN")
        self.refuses(lambda v: self.alpha_row(v).update(unavailable_cords=3), "CENSUS_FILE_ACCOUNTING_BROKEN")

        def inflate_cords(value):
            row = self.alpha_row(value)
            row.update(cords=row["cords"] + 1, in_scope_files=row["in_scope_files"] + 1,
                       tracked_files=row["tracked_files"] + 1)
        self.refuses(inflate_cords, "CENSUS_CORD_COUNT_MISMATCH")

        def shift_unavailable(value):
            row = self.alpha_row(value)
            row.update(unavailable_cords=row["unavailable_cords"] + 1, in_scope_files=row["in_scope_files"] + 1,
                       tracked_files=row["tracked_files"] + 1)
        self.refuses(shift_unavailable, "CENSUS_CORD_COUNT_MISMATCH")
        self.refuses(lambda v: self.alpha_row(v).update(cords=-1), "CENSUS_REPOSITORY_FIELDS_INVALID")
        self.refuses(lambda v: v.update(repositories_required=2), "CENSUS_STATE_INVALID")
        self.refuses(lambda v: v.update(repositories_observed=3), "CENSUS_STATE_INVALID")
        self.refuses(lambda v: v["cords"][0].update(bytes=CAP + 1), "CENSUS_CORD_FIELDS_INVALID")
        tight = section(alpha_policy(), beta_policy(), gamma_policy(), max_cords=3)
        with self.assertRaisesRegex(InputError, "CENSUS_CORDS_INVALID"):
            validate_census(deepcopy(self.report), tight)

    def test_bools_and_floats_where_ints_are_required(self):
        for field in ("tracked_files", "in_scope_files", "out_of_scope_files", "symlink_or_submodule_entries",
                      "cords", "unavailable_cords"):
            for bad in (True, float(self.report["repositories"][0][field]), str(self.report["repositories"][0][field])):
                with self.subTest(field=field, bad=bad):
                    self.refuses(lambda v: self.alpha_row(v).update({field: bad}), "CENSUS_REPOSITORY_FIELDS_INVALID")
        for field, bad in (("bytes", 11.0), ("bytes", True), ("lean_text_sorry_tokens", 2.0),
                           ("lean_text_sorry_tokens", True), ("is_lean", 1)):
            with self.subTest(field=field, bad=bad):
                lean = next(i for i, c in enumerate(self.report["cords"]) if c["is_lean"])
                self.refuses(lambda v: v["cords"][lean].update({field: bad}), "CENSUS_CORD_FIELDS_INVALID")
        # A one-repository census counts 1 of 1, where True == 1 would otherwise pass.
        self.assertEqual((self.complete["repositories_required"], self.complete["repositories_observed"]),
                         (1, 1))
        for change in ({"repositories_required": True}, {"repositories_observed": True},
                       {"repositories_required": True, "repositories_observed": True},
                       {"repositories_required": 1.0}, {"repositories_observed": "1"}):
            with self.subTest(change=change):
                self.refuses(lambda v: v.update(change), "CENSUS_STATE_INVALID", base=self.complete,
                             policy=self.complete_section)

    def test_a_cord_path_with_no_utf8_form_is_a_typed_refusal(self):
        def surrogate(value):
            cord = cord_of(value, "src/b.py")
            cord["path"] = "src/b\ud800.py"
            value["cords"].sort(key=lambda c: c["key"])
        forged = deepcopy(self.report)
        surrogate(forged)
        # Read back through the strict loader, as a census file with a \ud800 escape would be.
        with self.assertRaisesRegex(InputError, "CENSUS_PATH_NOT_UTF"):
            validate_census(strict_json(canonical(forged), max_bytes=1 << 24), self.section)

        def surrogate_unavailable(value):
            value["unavailable_cords"][0]["path"] += "\ud800"
        self.refuses(surrogate_unavailable, "CENSUS_PATH_NOT_UTF")

    def test_false_flags_must_stay_false(self):
        for flag in _FALSE_FLAGS:
            for bad in (True, 0, None, "false"):
                with self.subTest(flag=flag, bad=bad):
                    self.refuses(lambda v: v.update({flag: bad}), "CENSUS_FALSE_AUTHORITY_CLAIM")
        for bad in (False, 1, None):
            self.refuses(lambda v: v.update(git_object_bytes_checked_by_this_collector=bad),
                         "CENSUS_FALSE_AUTHORITY_CLAIM")
        self.refuses(lambda v: v.update(schema="szl.database-braid-source-census/v2"), "CENSUS_FALSE_AUTHORITY_CLAIM")

    def test_missing_or_extra_fields(self):
        self.refuses(lambda v: v.update(signed=False), "CENSUS_FIELDS_INVALID")
        self.refuses(lambda v: v.pop("network_used"), "CENSUS_FIELDS_INVALID")
        self.refuses(lambda v: v.pop("unavailable_cords"), "CENSUS_FIELDS_INVALID")
        self.refuses(lambda v: self.alpha_row(v).update(authorized=False), "CENSUS_REPOSITORY_FIELDS_INVALID")
        self.refuses(lambda v: self.alpha_row(v).pop("shallow"), "CENSUS_REPOSITORY_FIELDS_INVALID")
        self.refuses(lambda v: v["cords"][0].update(signature=None), "CENSUS_CORD_FIELDS_INVALID")
        self.refuses(lambda v: v["cords"][0].pop("family"), "CENSUS_CORD_FIELDS_INVALID")
        self.refuses(lambda v: v["unavailable_cords"][0].update(bytes=0), "CENSUS_CORD_FIELDS_INVALID")
        self.refuses(lambda v: v.update(cords=tuple(v["cords"])), "CENSUS_CORDS_INVALID")
        self.refuses(lambda v: v.update(unavailable_cords={}), "CENSUS_CORDS_INVALID")
        with self.assertRaisesRegex(InputError, "CENSUS_FIELDS_INVALID"):
            validate_census([self.report], self.section)

    def test_unavailable_row_must_stay_unknown(self):
        gamma = lambda v: row_of(v, GAMMA)  # noqa: E731
        for field in ("commit", "tree_id", "listing_sha256", "checkout_identity", "shallow",
                      "tracked_files", "in_scope_files", "out_of_scope_files",
                      "symlink_or_submodule_entries", "cords", "unavailable_cords"):
            bad = {"commit": "c" * 40, "tree_id": "d" * 40, "listing_sha256": "e" * 64,
                   "checkout_identity": "NO_ORIGIN", "shallow": False}.get(field, 0)
            with self.subTest(field=field):
                self.refuses(lambda v: gamma(v).update({field: bad}), "CENSUS_UNAVAILABLE_NOT_UNKNOWN")
        for state in ("EMPTY", "observed", None):
            self.refuses(lambda v: gamma(v).update(state=state), "CENSUS_UNAVAILABLE_NOT_UNKNOWN")

        def fake_observed_empty(value):
            gamma(value).update(state="OBSERVED", commit="c" * 40, tree_id="d" * 40,
                                listing_sha256="e" * 64, checkout_identity="NO_ORIGIN", shallow=False,
                                tracked_files=0, in_scope_files=0, out_of_scope_files=0,
                                symlink_or_submodule_entries=0, cords=0, unavailable_cords=0)
        self.refuses(fake_observed_empty, "CENSUS_STATE_INVALID")
        self.refuses(lambda v: v["cords"].append(dict(v["cords"][-1], repository=GAMMA,
                                                      key=cord_key(GAMMA, v["cords"][-1]["path"]))),
                     "CENSUS_CORD_FIELDS_INVALID")

    def test_observed_row_needs_commit_and_shallow(self):
        for field, bad in (("commit", None), ("commit", "C" * 40), ("commit", "c" * 39), ("shallow", None),
                           ("shallow", 0), ("tree_id", None), ("tree_id", "D" * 40), ("tree_id", "d" * 64),
                           ("listing_sha256", None), ("listing_sha256", "e" * 40),
                           ("checkout_identity", "VERIFIED"), ("checkout_identity", None)):
            with self.subTest(field=field, bad=bad):
                self.refuses(lambda v: self.alpha_row(v).update({field: bad}), "CENSUS_REPOSITORY_FIELDS_INVALID")

    def test_cord_semantics(self):
        lean = next(i for i, c in enumerate(self.report["cords"]) if c["is_lean"])
        plain = next(i for i, c in enumerate(self.report["cords"]) if not c["is_lean"])
        self.refuses(lambda v: v["cords"][lean].update(is_lean=False), "CENSUS_CORD_FIELDS_INVALID")
        self.refuses(lambda v: v["cords"][plain].update(is_lean=True), "CENSUS_CORD_FIELDS_INVALID")
        self.refuses(lambda v: v["cords"][plain].update(lean_text_sorry_tokens=1), "CENSUS_CORD_FIELDS_INVALID")
        self.refuses(lambda v: v["cords"][plain].update(family="lower"), "CENSUS_CORD_FIELDS_INVALID")
        self.refuses(lambda v: v["cords"][plain].update(repository="szl-holdings/delta"),
                     "CENSUS_CORD_FIELDS_INVALID")
        self.refuses(lambda v: v["unavailable_cords"][0].update(reason="MISSING"), "CENSUS_CORD_FIELDS_INVALID")
        self.refuses(lambda v: v["unavailable_cords"][0].update(key=None), "CENSUS_CORD_FIELDS_INVALID")

        def collide(value):
            first = value["cords"][0]
            value["unavailable_cords"][0].update(key=first["key"], repository=first["repository"],
                                                 path=first["path"])
            value["unavailable_cords"].sort(key=lambda c: c["key"])
        self.refuses(collide, "CENSUS_CORD_ORDER_OR_DUPLICATE")

    def test_state_and_timestamp(self):
        self.refuses(lambda v: v.update(state="COMPLETE"), "CENSUS_STATE_INVALID")
        self.refuses(lambda v: v.update(state="OK"), "CENSUS_STATE_INVALID")
        self.refuses(lambda v: v.update(state="PARTIAL"), "CENSUS_STATE_INVALID", base=self.complete,
                     policy=self.complete_section)
        for bad in ("2026-11-19T06:30:00", "yesterday", "", None, 1, "2026-11-19T06:30:00+00:00" + " " * 30):
            with self.subTest(observed_at=bad):
                self.refuses(lambda v: v.update(observed_at=bad), "CENSUS_TIMESTAMP_INVALID")
        zulu = deepcopy(self.report)
        zulu["observed_at"] = "2026-11-19T06:30:00Z"
        validate_census(zulu, self.section)

    def test_report_is_checked_against_the_given_policy(self):
        other = section(alpha_policy(), beta_policy())
        with self.assertRaisesRegex(InputError, "CENSUS_REPOSITORY_COVERAGE_INVALID"):
            validate_census(deepcopy(self.report), other)
        with self.assertRaisesRegex(InputError, "CENSUS_POLICY_INVALID"):
            validate_census(deepcopy(self.report), section(max_cords=1))


class CliTests(_Repos):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.out = Path(temp.name)

    def write_policy(self, census, name="policy.json"):
        path = self.out / name
        path.write_text(json.dumps({"schema": "synthetic", "census": census}))
        return path

    def run_main(self, argv):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main([str(a) for a in argv])
        return code, json.loads(buffer.getvalue().strip().splitlines()[-1])

    def clone_with_origin(self, url):
        repo = make_repo(self.out, "clone-" + url.rsplit("/", 1)[-1], {"one.txt": b"one\n"})
        git(repo, "remote", "add", "origin", url, home=self.out)
        return repo

    def test_complete_run_exit_zero_and_never_overwrites(self):
        census = section(beta_policy())
        policy = self.write_policy(census)
        output = self.out / "census.json"
        repo = self.clone_with_origin("https://github.com/szl-holdings/beta.git")
        argv = ["--policy", policy, "--checkout", f"{BETA}={repo}", "--output", output]
        code, summary = self.run_main(argv)
        self.assertEqual(code, 0)
        self.assertEqual((summary["state"], summary["checkout_identity_unverified"],
                          summary["provider_writes"]), ("COMPLETE", [], False))
        written = output.read_bytes()
        report = json.loads(written)
        validate_census(report, census)
        self.assertEqual(report["policy_sha256"], hashlib.sha256(policy.read_bytes()).hexdigest())
        self.assertIsNone(report["family_map_sha256"])
        code, summary = self.run_main(argv)
        self.assertEqual(code, 3)
        self.assertEqual((summary["state"], summary["code"]), ("UNAVAILABLE", "OUTPUT_PATH_DENIED"))
        self.assertEqual(output.read_bytes(), written)

    def test_a_complete_census_of_unverified_checkouts_is_exit_two(self):
        # A full file inventory of a checkout that is not shown to be the named repository is
        # not a clean result: the CLI says which rows are unverified and does not exit 0.
        policy = self.write_policy(section(beta_policy()))
        cases = ((self.beta, "NO_ORIGIN"),
                 (self.clone_with_origin("https://github.com/szl-holdings/hatun-mcp.git"),
                  "ORIGIN_DIFFERS"))
        for index, (repo, identity) in enumerate(cases):
            output = self.out / f"unverified-{index}.json"
            with self.subTest(identity=identity):
                code, summary = self.run_main(["--policy", policy, "--checkout", f"{BETA}={repo}",
                                               "--output", output])
                self.assertEqual((code, summary["state"], summary["checkout_identity_unverified"]),
                                 (2, "COMPLETE", [BETA]))
                report = json.loads(output.read_bytes())
                self.assertEqual(row_of(report, BETA)["checkout_identity"], identity)

    def test_partial_run_exit_two_with_family_map(self):
        census = section(alpha_policy(), gamma_policy())
        policy = self.write_policy(census)
        map_path = self.out / "map.json"
        map_path.write_text(json.dumps(family_map()))
        output = self.out / "partial.json"
        code, summary = self.run_main(["--policy", policy, "--family-map", map_path,
                                       "--checkout", f"{ALPHA}={self.alpha}", "--output", output])
        self.assertEqual(code, 2)
        self.assertEqual((summary["state"], summary["repositories_observed"], summary["repositories_required"]),
                         ("PARTIAL", 1, 2))
        report = json.loads(output.read_bytes())
        validate_census(report, census)
        self.assertEqual(report["family_map_sha256"], hashlib.sha256(map_path.read_bytes()).hexdigest())
        self.assertEqual(cord_of(report, "src/a.lean")["family"], "EXPLICIT_PICK")
        self.assertIsNone(row_of(report, GAMMA)["tracked_files"])

    def test_output_inside_repository_is_refused(self):
        policy = self.write_policy(section(beta_policy()))
        for target in (ROOT / "census_output_must_not_exist.json", ROOT / "tests" / "census_must_not_exist.json"):
            with self.subTest(target=target.name):
                self.assertFalse(target.exists())
                code, summary = self.run_main(["--policy", policy, "--checkout", f"{BETA}={self.beta}",
                                               "--output", target])
                self.assertEqual((code, summary["code"]), (3, "OUTPUT_PATH_DENIED"))
                self.assertFalse(target.exists())

    def test_refusals_exit_three_with_typed_code(self):
        policy = self.write_policy(section(beta_policy()))
        no_census = self.out / "no_census.json"
        no_census.write_text(json.dumps({"schema": "synthetic"}))
        floaty = self.out / "float.json"
        floaty.write_text('{"census": {"max_cords": 1.5, "max_blob_bytes": 10, "repositories": []}}')
        linked = self.out / "linked.json"
        os.symlink(policy, linked)
        bad_map = self.out / "bad_map.json"
        bad_map.write_text(json.dumps(family_map(status="RATIFIED")))
        ok = f"{BETA}={self.beta}"
        cases = [
            (["--policy", policy, "--checkout", str(self.beta)], "CENSUS_CHECKOUT_ARGUMENT_INVALID"),
            (["--policy", policy, "--checkout", f"{BETA}="], "CENSUS_CHECKOUT_ARGUMENT_INVALID"),
            (["--policy", policy, "--checkout", f"other/beta={self.beta}"], "CENSUS_CHECKOUT_ARGUMENT_INVALID"),
            (["--policy", policy, "--checkout", ok, "--checkout", ok], "CENSUS_CHECKOUT_ARGUMENT_INVALID"),
            (["--policy", policy, "--checkout", f"{ALPHA}={self.alpha}"], "CENSUS_CHECKOUT_NOT_IN_POLICY"),
            (["--policy", no_census, "--checkout", ok], "CENSUS_POLICY_FIELDS_INVALID"),
            (["--policy", floaty, "--checkout", ok], "FLOAT_VALUE_REFUSED"),
            (["--policy", linked, "--checkout", ok], "SOURCE_FILE_UNAVAILABLE"),
            (["--policy", self.out / "absent.json", "--checkout", ok], "SOURCE_FILE_UNAVAILABLE"),
            (["--policy", policy, "--family-map", bad_map, "--checkout", ok], "CENSUS_FAMILY_MAP_INVALID"),
            (["--policy", policy, "--checkout", f"{BETA}={self.out / 'nope'}"], "CENSUS_CHECKOUT_UNAVAILABLE"),
        ]
        for index, (argv, expected) in enumerate(cases):
            output = self.out / f"refused-{index}.json"
            with self.subTest(expected=expected, index=index):
                code, summary = self.run_main([*argv, "--output", output])
                self.assertEqual(code, 3)
                self.assertEqual(summary, {"state": "UNAVAILABLE", "code": expected, "provider_writes": False})
                self.assertFalse(output.exists())
        code, summary = self.run_main(["--policy", policy, "--checkout", ok,
                                       "--output", self.out / "missing-dir" / "x.json"])
        self.assertEqual((code, summary["code"]), (3, "OUTPUT_PATH_DENIED"))


def batch_spy(seen):
    """Wrap the census git runner and record every blob id handed to ``cat-file --batch``."""
    real = census_tool._git

    def spy(directory, *args, stdin=None, ok_codes=(0,)):
        if args[:2] == ("cat-file", "--batch"):
            seen.append(stdin.decode("ascii").split())
        return real(directory, *args, stdin=stdin, ok_codes=ok_codes)
    return spy


class TreeIdentityTests(_Repos):
    def test_rows_bind_the_root_tree_and_a_listing_digest_anyone_can_recompute(self):
        report = observe(section(alpha_policy(), beta_policy()), {ALPHA: self.alpha, BETA: self.beta},
                         at=NOW)
        for name, repo in ((ALPHA, self.alpha), (BETA, self.beta)):
            row = row_of(report, name)
            with self.subTest(name):
                tree = git(repo, "rev-parse", "HEAD^{tree}", home=self.base).decode().strip()
                self.assertEqual(row["tree_id"], tree)
                listing = []
                for record in git(repo, "ls-tree", "-r", "-z", "--full-tree", "HEAD",
                                  home=self.base).split(b"\0"):
                    if record:
                        meta, _, path = record.partition(b"\t")
                        mode, _kind, sha = meta.decode("ascii").split()
                        listing.append([path.decode("utf-8"), mode, sha])
                self.assertEqual(row["listing_sha256"], digest(sorted(listing)))
                self.assertEqual(row["tracked_files"], len(listing))
                self.assertIn(row["checkout_identity"], IDENTITIES)


class CheckoutIdentityTests(TestCase):
    def test_origin_url_is_compared_with_the_policy_name_only(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(temp, "alpha", {"x.txt": b"x\n"})
            self.assertEqual(checkout_identity(repo, ALPHA), "NO_ORIGIN")
            git(repo, "remote", "add", "origin", "https://github.com/szl-holdings/alpha.git", home=temp)
            cases = (("https://github.com/szl-holdings/alpha.git", "ORIGIN_MATCHES"),
                     ("git@github.com:szl-holdings/alpha.git", "ORIGIN_MATCHES"),
                     ("https://github.com/szl-holdings/alpha/", "ORIGIN_MATCHES"),
                     ("https://github.com/SZL-Holdings/Alpha", "ORIGIN_MATCHES"),
                     ("http://proxy@127.0.0.1:9/git/szl-holdings/alpha", "ORIGIN_MATCHES"),
                     ("https://github.com/szl-holdings/hatun-mcp.git", "ORIGIN_DIFFERS"),
                     ("https://github.com/other-org/alpha.git", "ORIGIN_DIFFERS"),
                     ("https://github.com/szl-holdings/alpha-fork.git", "ORIGIN_DIFFERS"))
            for url, expected in cases:
                git(repo, "remote", "set-url", "origin", url, home=temp)
                with self.subTest(url=url):
                    self.assertEqual(checkout_identity(repo, ALPHA), expected)
            report = observe(section({"repository": ALPHA, "include": ["*"], "exclude": [],
                                      "families": []}), {ALPHA: repo}, at=NOW)
            self.assertEqual(row_of(report, ALPHA)["checkout_identity"], "ORIGIN_DIFFERS")


class CheckoutBindingTests(_Repos):
    def test_a_subdirectory_of_another_repository_is_refused(self):
        for nested in (self.alpha / "src", self.alpha / "docs"):
            with self.subTest(nested=nested.name):
                with self.assertRaisesRegex(InputError, "CENSUS_CHECKOUT_NOT_TOP_LEVEL"):
                    list_tree(nested)
        with self.assertRaisesRegex(InputError, "CENSUS_CHECKOUT_NOT_TOP_LEVEL"):
            observe(section(beta_policy()), {BETA: self.alpha / "src"}, at=NOW)
        with tempfile.TemporaryDirectory(dir=self.alpha) as untracked:
            with self.assertRaisesRegex(InputError, "CENSUS_CHECKOUT_NOT_TOP_LEVEL"):
                list_tree(Path(untracked))


class BlobReadingTests(_Repos):
    def test_an_over_cap_blob_is_never_read(self):
        seen = []
        with mock.patch.object(census_tool, "_git", batch_spy(seen)):
            report = observe(section(alpha_policy()), {ALPHA: self.alpha}, at=NOW)
        read = {sha for batch in seen for sha in batch}
        self.assertNotIn(git_blob_sha1(ALPHA_FILES["docs/big.bin"]), read)
        self.assertIn(git_blob_sha1(ALPHA_FILES["docs/cap.bin"]), read)
        self.assertIn({"key": "alpha:docs/big.bin", "repository": ALPHA, "path": "docs/big.bin",
                       "reason": "BLOB_OVER_SIZE_CAP"}, report["unavailable_cords"])

    def test_blobs_are_read_in_bounded_batches_with_identical_bytes(self):
        shas = sorted({git_blob_sha1(raw) for raw in ALPHA_FILES.values()})
        whole = read_blobs(self.alpha, shas, max_bytes=CAP)
        seen = []
        with mock.patch.object(census_tool, "MAX_BATCH_BYTES", 40), \
                mock.patch.object(census_tool, "_git", batch_spy(seen)):
            batched = read_blobs(self.alpha, shas, max_bytes=CAP)
        self.assertEqual(batched, whole)
        self.assertGreater(len(seen), 2)
        sizes = {git_blob_sha1(raw): len(raw) for raw in ALPHA_FILES.values()}
        for batch in seen:
            self.assertTrue(len(batch) == 1 or sum(sizes[s] for s in batch) <= 40, batch)

    def test_each_batch_is_released_before_the_next_is_read(self):
        shas = sorted({git_blob_sha1(raw) for raw in ALPHA_FILES.values()})
        whole = read_blobs(self.alpha, shas, max_bytes=CAP)
        events = []
        real = census_tool._git

        class Output(bytes):
            def __del__(self):
                events.append("released")

        def spy(directory, *args, stdin=None, ok_codes=(0,)):
            raw = real(directory, *args, stdin=stdin, ok_codes=ok_codes)
            if args[:2] != ("cat-file", "--batch"):
                return raw
            events.append("read")
            return Output(raw)
        with mock.patch.object(census_tool, "MAX_BATCH_BYTES", 40), \
                mock.patch.object(census_tool, "_git", spy):
            batched = read_blobs(self.alpha, shas, max_bytes=CAP)
        self.assertEqual(batched, whole)
        self.assertTrue(all(type(body) is bytes for body in batched.values() if body is not None))
        # Never two batches of git output alive at once.
        reads = events.count("read")
        self.assertGreater(reads, 2)
        self.assertEqual(events, ["read", "released"] * reads)

    def test_blob_ids_are_checked_before_git_sees_them(self):
        for bad in ("HEAD:README.md", "2" * 39, "2" * 64, "Z" * 40, "2" * 40 + "\nHEAD", 7):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(InputError, "CENSUS_BLOB_ID_INVALID"):
                    read_blobs(self.alpha, [bad], max_bytes=CAP)

    def test_a_census_read_in_tiny_batches_is_identical(self):
        policy = section(alpha_policy(), beta_policy())
        whole = observe(policy, {ALPHA: self.alpha, BETA: self.beta}, at=NOW)
        with mock.patch.object(census_tool, "MAX_BATCH_BYTES", 16):
            batched = observe(policy, {ALPHA: self.alpha, BETA: self.beta}, at=NOW)
        self.assertEqual(batched, whole)

    def test_the_cord_budget_is_enforced_before_any_blob_is_read(self):
        seen = []
        with mock.patch.object(census_tool, "_git", batch_spy(seen)):
            with self.assertRaisesRegex(InputError, "CENSUS_CORD_BUDGET_EXCEEDED"):
                observe(section(alpha_policy(), max_cords=5), {ALPHA: self.alpha}, at=NOW)
        self.assertEqual(seen, [])


class CensusForgeryTests(_Repos):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.section = section(alpha_policy(), beta_policy(), gamma_policy())
        cls.checkouts = {ALPHA: cls.alpha, BETA: cls.beta}
        cls.report = observe(cls.section, cls.checkouts, at=NOW)

    def forged(self, mutate):
        value = deepcopy(self.report)
        mutate(value)
        return value

    def refused_offline(self, value, code):
        with self.assertRaisesRegex(InputError, code):
            validate_census(value, self.section)

    def refused_on_rederivation(self, value, code):
        validate_census(deepcopy(value), self.section)
        with self.assertRaisesRegex(InputError, code):
            verify_census_checkouts(value, self.section, self.checkouts)

    @staticmethod
    def drop_file(value, path, *, as_out_of_scope=False):
        index = next(i for i, c in enumerate(value["cords"]) if c["path"] == path)
        cord = value["cords"].pop(index)
        row = row_of(value, cord["repository"])
        row["cords"] -= 1
        row["in_scope_files"] -= 1
        if as_out_of_scope:
            row["out_of_scope_files"] += 1
        else:
            row["tracked_files"] -= 1

    def test_the_untampered_census_rederives_equal(self):
        self.assertEqual(verify_census_checkouts(deepcopy(self.report), self.section, self.checkouts),
                         [ALPHA, BETA])
        self.assertEqual(verify_census_checkouts(deepcopy(self.report), self.section, {BETA: self.beta}),
                         [BETA])
        with self.assertRaisesRegex(InputError, "CENSUS_CHECKOUT_NOT_IN_POLICY"):
            verify_census_checkouts(deepcopy(self.report), self.section,
                                    {"szl-holdings/delta": self.beta})

    def test_a_dropped_file_with_adjusted_counts_is_refused(self):
        # The report's own arithmetic still adds up, so only re-derivation can see the drop.
        for out_of_scope in (False, True):
            with self.subTest(out_of_scope=out_of_scope):
                self.refused_on_rederivation(
                    self.forged(lambda v: self.drop_file(v, "src/b.py", as_out_of_scope=out_of_scope)),
                    "CENSUS_REDERIVED_COUNTS_MISMATCH")

        def relisted(value):
            self.drop_file(value, "src/b.py")
            row_of(value, ALPHA)["listing_sha256"] = digest([["src/a.lean", "100644", "0" * 40]])
        self.refused_on_rederivation(self.forged(relisted), "CENSUS_LISTING_MISMATCH")

        def retreed(value):
            self.drop_file(value, "src/b.py")
            row_of(value, ALPHA)["tree_id"] = "0" * 40
        self.refused_on_rederivation(self.forged(retreed), "CENSUS_LISTING_MISMATCH")
        self.refused_offline(self.forged(lambda v: v["cords"].pop(0)), "CENSUS_CORD_COUNT_MISMATCH")

    def test_edited_cord_contents_are_refused_on_rederivation(self):
        def lean(value):
            return next(c for c in value["cords"] if c["path"] == "src/a.lean")
        self.refused_on_rederivation(self.forged(lambda v: lean(v).update(sha256="f" * 64)),
                                     "CENSUS_REDERIVED_CORDS_MISMATCH")
        self.refused_on_rederivation(self.forged(lambda v: lean(v).update(lean_text_sorry_tokens=0)),
                                     "CENSUS_REDERIVED_CORDS_MISMATCH")
        self.refused_on_rederivation(self.forged(lambda v: lean(v).update(blob_sha1="1" * 40)),
                                     "CENSUS_REDERIVED_CORDS_MISMATCH")

    def test_an_invented_unavailable_entry_is_refused(self):
        def add(entry):
            def mutate(value):
                value["unavailable_cords"].append(entry)
                value["unavailable_cords"].sort(key=lambda c: str(c["key"]))
            return mutate
        invented = (
            {"key": "alpha:docs/invented.bin", "repository": ALPHA, "path": "docs/other.bin",
             "reason": "BLOB_OVER_SIZE_CAP"},
            {"key": "delta:x.txt", "repository": "szl-holdings/delta", "path": "x.txt",
             "reason": "BLOB_OVER_SIZE_CAP"},
            {"key": cord_key(GAMMA, "x.txt"), "repository": GAMMA, "path": "x.txt",
             "reason": "BLOB_OVER_SIZE_CAP"},
            {"key": "alpha:README.md", "repository": ALPHA, "path": "README.md",
             "reason": "BLOB_OVER_SIZE_CAP"},
            {"key": "alpha:build/out.lean", "repository": ALPHA, "path": "build/out.lean",
             "reason": "LFS_POINTER_CONTENT_ABSENT"},
            {"key": "alpha:docs/x.bin", "repository": ALPHA, "path": "docs/x.bin", "reason": "MISSING"},
            {"key": "alpha:docs/x.bin", "repository": [ALPHA], "path": "docs/x.bin",
             "reason": "BLOB_OVER_SIZE_CAP"},
        )
        for entry in invented:
            with self.subTest(entry=entry["key"]):
                self.refused_offline(self.forged(add(entry)), "CENSUS_CORD_FIELDS_INVALID")

        def well_formed(value):
            add({"key": "alpha:docs/x.bin", "repository": ALPHA, "path": "docs/x.bin",
                 "reason": "BLOB_OVER_SIZE_CAP"})(value)
            row = row_of(value, ALPHA)
            row.update(unavailable_cords=row["unavailable_cords"] + 1,
                       in_scope_files=row["in_scope_files"] + 1, tracked_files=row["tracked_files"] + 1)
        self.refused_on_rederivation(self.forged(well_formed), "CENSUS_REDERIVED_COUNTS_MISMATCH")

    def test_unavailable_counts_are_checked_per_repository(self):
        def move_to_beta(value):
            entry = next(u for u in value["unavailable_cords"] if u["path"] == "docs/big.bin")
            entry.update(key=cord_key(BETA, "big.bin"), repository=BETA, path="big.bin")
            value["unavailable_cords"].sort(key=lambda c: c["key"])
        # The global total is unchanged; only the per-repository count can see the move.
        self.refused_offline(self.forged(move_to_beta), "CENSUS_CORD_COUNT_MISMATCH")

    def test_cords_outside_the_policy_globs_are_refused(self):
        def relocate(path):
            def mutate(value):
                cord = next(c for c in value["cords"] if c["path"] == "src/b.py")
                cord.update(path=path, key=cord_key(ALPHA, path))
                value["cords"].sort(key=lambda c: c["key"])
            return mutate
        for path in ("build/out.lean", "README.md", "vendor/sub"):
            with self.subTest(path=path):
                self.refused_offline(self.forged(relocate(path)), "CENSUS_CORD_FIELDS_INVALID")

        def beta_path(path, *, unavailable=False):
            def mutate(value):
                if unavailable:
                    value["unavailable_cords"].append({"key": cord_key(BETA, path), "repository": BETA,
                                                       "path": path, "reason": "BLOB_OVER_SIZE_CAP"})
                    value["unavailable_cords"].sort(key=lambda c: c["key"])
                    return
                cord = next(c for c in value["cords"] if c["repository"] == BETA)
                cord.update(path=path, key=cord_key(BETA, path))
                value["cords"].sort(key=lambda c: c["key"])
            return mutate
        # Beta includes "*", which fnmatch lets match any text; git never lists these paths.
        for path in ("../../etc/passwd", "/abs/x.txt", "a//b", "./x", "x/.", ".git/config", ""):
            for unavailable in (False, True):
                with self.subTest(path=path, unavailable=unavailable):
                    self.refused_offline(self.forged(beta_path(path, unavailable=unavailable)),
                                         "CENSUS_CORD_FIELDS_INVALID")
        self.refused_offline(self.forged(lambda v: v["cords"][0].update(repository=[ALPHA])),
                             "CENSUS_CORD_FIELDS_INVALID")

    def test_families_are_re_derived_whenever_they_can_be(self):
        relabel = self.forged(lambda v: cord_of(v, "src/a.lean").update(family="BETA_ALL"))
        self.refused_offline(relabel, "CENSUS_CORD_FAMILY_NOT_DERIVED")
        explicit = validate_family_map(family_map())
        mapped = observe(self.section, self.checkouts, at=NOW, family_map=explicit,
                         family_map_sha256="f" * 64)
        validate_census(deepcopy(mapped), self.section)
        validate_census(deepcopy(mapped), self.section, family_map=explicit)
        self.assertEqual(verify_census_checkouts(deepcopy(mapped), self.section, self.checkouts,
                                                 family_map=explicit), [ALPHA, BETA])
        forged = deepcopy(mapped)
        cord_of(forged, "src/a.lean")["family"] = "LEAN_CORE"
        # Without the map the label cannot be re-derived, and is not claimed to be.
        validate_census(deepcopy(forged), self.section)
        with self.assertRaisesRegex(InputError, "CENSUS_CORD_FAMILY_NOT_DERIVED"):
            validate_census(deepcopy(forged), self.section, family_map=explicit)

    def test_a_row_hidden_as_unavailable_is_refused_when_its_checkout_is_supplied(self):
        def hide_alpha(value):
            row = row_of(value, ALPHA)
            for field in list(row):
                if field not in ("repository", "state"):
                    row[field] = None
            row["state"] = "UNAVAILABLE"
            value["cords"] = [c for c in value["cords"] if c["repository"] != ALPHA]
            value["unavailable_cords"] = []
            value["repositories_observed"] -= 1
        hidden = self.forged(hide_alpha)
        validate_census(deepcopy(hidden), self.section)
        self.assertEqual(verify_census_checkouts(deepcopy(hidden), self.section, {BETA: self.beta}),
                         [BETA])
        with self.assertRaisesRegex(InputError, "CENSUS_REDERIVATION_ROW_NOT_OBSERVED"):
            verify_census_checkouts(hidden, self.section, self.checkouts)

    def test_rederivation_reads_the_recorded_commit_not_head(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(temp, "moving", {"one.txt": b"first\n", "two.txt": b"two\n"})
            policy = section(beta_policy())
            first = observe(policy, {BETA: repo}, at=NOW)
            (repo / "one.txt").write_bytes(b"second\n")
            git(repo, "commit", "-q", "-am", "move on", home=temp)
            self.assertNotEqual(list_tree(repo)[0], row_of(first, BETA)["commit"])
            self.assertEqual(verify_census_checkouts(deepcopy(first), policy, {BETA: repo}), [BETA])
            unknown = deepcopy(first)
            row_of(unknown, BETA)["commit"] = "3" * 40
            with self.assertRaisesRegex(InputError, "CENSUS_GIT_REFUSED"):
                verify_census_checkouts(unknown, policy, {BETA: repo})


class ExportTreeTests(_Repos):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.dest = Path(temp.name) / "export"
        self.dest.mkdir()

    def exported(self):
        return {p.relative_to(self.dest).as_posix(): p.read_bytes()
                for p in self.dest.rglob("*") if p.is_file() and not p.is_symlink()}

    def test_exports_committed_regular_files_only(self):
        commit = list_tree(self.alpha)[0]
        shape = export_tree(self.alpha, commit, self.dest, max_blob_bytes=1 << 20)
        self.assertEqual(self.exported(), ALPHA_FILES)
        self.assertEqual(shape, {"files": len(ALPHA_FILES), "bytes": sum(map(len, ALPHA_FILES.values())),
                                 "skipped_entries": 2})
        self.assertFalse(os.path.lexists(self.dest / "docs/link.md"))
        self.assertFalse(os.path.lexists(self.dest / "vendor/sub"))
        self.assertTrue(os.access(self.dest / "src/b.py", os.X_OK))
        self.assertFalse(os.access(self.dest / "src/a.lean", os.X_OK))

    def test_export_in_tiny_batches_writes_the_same_bytes(self):
        commit = list_tree(self.alpha)[0]
        with mock.patch.object(census_tool, "MAX_BATCH_BYTES", 16):
            export_tree(self.alpha, commit, self.dest, max_blob_bytes=1 << 20)
        self.assertEqual(self.exported(), ALPHA_FILES)

    def test_export_paths_must_stay_inside_the_destination(self):
        root = self.dest.resolve()
        self.assertEqual(census_tool._export_path(root, "src/a.lean"), root / "src" / "a.lean")
        for bad in ("../escape.txt", "/etc/passwd", ".git/config", "a/../../b", "a/./b", "a//b", ""):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(InputError, "EXPORT_PATH_INVALID"):
                    census_tool._export_path(root, bad)

    def test_export_takes_committed_bytes_not_the_working_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(temp, "wt", {"kept.txt": b"committed\n"})
            (repo / "kept.txt").write_bytes(b"edited in the working tree\n")
            (repo / "untracked.py").write_bytes(b"print('never exported')\n")
            export_tree(repo, list_tree(repo)[0], self.dest)
            self.assertEqual(self.exported(), {"kept.txt": b"committed\n"})

    def test_export_refusals(self):
        commit = list_tree(self.alpha)[0]
        with self.assertRaisesRegex(InputError, "EXPORT_BLOB_UNAVAILABLE"):
            export_tree(self.alpha, commit, self.dest, max_blob_bytes=CAP)
        for child in sorted(self.dest.rglob("*"), reverse=True):
            child.unlink() if child.is_file() else child.rmdir()
        with self.assertRaisesRegex(InputError, "EXPORT_TOO_LARGE"):
            export_tree(self.alpha, commit, self.dest, max_total_bytes=10)
        (self.dest / "stale.txt").write_bytes(b"x")
        with self.assertRaisesRegex(InputError, "EXPORT_DESTINATION_INVALID"):
            export_tree(self.alpha, commit, self.dest)
        link = self.dest.parent / "link"
        os.symlink(self.dest, link)
        for target in (link, self.dest.parent / "absent", "not-a-path"):
            with self.subTest(target=str(target)):
                with self.assertRaisesRegex(InputError, "EXPORT_DESTINATION_INVALID"):
                    export_tree(self.alpha, commit, target)


class CliVerifyTests(_Repos):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.out = Path(temp.name)
        self.policy = self.out / "policy.json"
        self.policy.write_text(json.dumps({"census": section(alpha_policy(), beta_policy())}))
        self.checkouts = ["--checkout", f"{ALPHA}={self.alpha}", "--checkout", f"{BETA}={self.beta}"]

    def run_main(self, argv):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main([str(a) for a in argv])
        lines = buffer.getvalue().strip().splitlines()
        self.assertEqual(len(lines), 1)
        return code, json.loads(lines[0])

    def test_verify_rederives_an_honest_census_and_refuses_a_forged_one(self):
        census = self.out / "census.json"
        code, _ = self.run_main(["--policy", self.policy, *self.checkouts, "--output", census])
        self.assertEqual(code, 2)
        code, summary = self.run_main(["--policy", self.policy, *self.checkouts, "--verify", census])
        self.assertEqual((code, summary["state"], summary["repositories_rederived"]),
                         (0, "REDERIVED_EQUAL", 2))
        # Re-derivation says the report is faithful; the census's own state stays what it was.
        self.assertEqual(summary["census_state"], "PARTIAL")
        self.assertEqual(summary["census_sha256"], hashlib.sha256(census.read_bytes()).hexdigest())
        forged = json.loads(census.read_bytes())
        CensusForgeryTests.drop_file(forged, "src/b.py")
        forged_path = self.out / "forged.json"
        forged_path.write_text(json.dumps(forged))
        code, summary = self.run_main(["--policy", self.policy, *self.checkouts, "--verify", forged_path])
        self.assertEqual((code, summary["state"], summary["code"]),
                         (3, "UNAVAILABLE", "CENSUS_REDERIVED_COUNTS_MISMATCH"))
        other = self.out / "other-policy.json"
        other.write_text(json.dumps({"census": section(alpha_policy(), beta_policy())}, indent=1))
        code, summary = self.run_main(["--policy", other, *self.checkouts, "--verify", census])
        self.assertEqual((code, summary["code"]), (3, "CENSUS_INPUTS_DIFFER"))

    def test_verify_without_a_checkout_for_every_observed_row_is_never_equal(self):
        census = self.out / "census.json"
        self.run_main(["--policy", self.policy, *self.checkouts, "--output", census])
        forged = json.loads(census.read_bytes())
        CensusForgeryTests.drop_file(forged, "src/b.py")
        forged_path = self.out / "forged.json"
        forged_path.write_text(json.dumps(forged))
        # The forged census is refused once its row is re-derived, and never vouched for before.
        for checkouts, rederived, skipped in (([], 0, [ALPHA, BETA]),
                                              (["--checkout", f"{BETA}={self.beta}"], 1, [ALPHA])):
            for target in (census, forged_path):
                with self.subTest(target=target.name, rederived=rederived):
                    code, summary = self.run_main(["--policy", self.policy, *checkouts,
                                                   "--verify", target])
                    self.assertEqual((code, summary["state"], summary["repositories_rederived"],
                                      summary["repositories_not_rederived"]),
                                     (2, "REDERIVATION_INCOMPLETE", rederived, skipped))
        code, summary = self.run_main(["--policy", self.policy, *self.checkouts, "--verify", census])
        self.assertEqual((code, summary["state"], summary["repositories_not_rederived"]),
                         (0, "REDERIVED_EQUAL", []))

    def test_a_census_with_no_observed_row_is_never_rederived_equal(self):
        nothing = self.out / "nothing.json"
        code, _ = self.run_main(["--policy", self.policy, "--output", nothing])
        self.assertEqual(code, 2)
        code, summary = self.run_main(["--policy", self.policy, "--verify", nothing])
        self.assertEqual((code, summary["state"], summary["repositories_rederived"],
                          summary["repositories_not_rederived"]), (2, "REDERIVATION_INCOMPLETE", 0, []))
        # With checkouts, a row recorded as unavailable that could have been observed is refused.
        code, summary = self.run_main(["--policy", self.policy, *self.checkouts, "--verify", nothing])
        self.assertEqual((code, summary["code"]), (3, "CENSUS_REDERIVATION_ROW_NOT_OBSERVED"))


class ContractFormatTests(TestCase):
    def test_family_map_is_serialised_like_every_contract_and_pinned_to_lf(self):
        path = ROOT / "governance/database_contracts/braid_family_map_v1.json"
        raw = path.read_bytes()
        self.assertEqual(raw, (json.dumps(json.loads(raw), indent=2, ensure_ascii=True) + "\n").encode())
        rules = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
        self.assertIn("/governance/database_contracts/*.json text eol=lf", rules)


class ReplaceRefTests(TestCase):
    """A planted refs/replace entry must not change what a listing or an export contains."""

    def test_listing_and_export_ignore_replace_refs(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base, "replaced", {"src/a.py": b"TRUE = 1\n"})
            (base / "planted.py").write_bytes(b"TRUE = 0\n")
            planted = git(repo, "hash-object", "-w", str(base / "planted.py"),
                          home=base).strip().decode()
            original = git(repo, "rev-parse", "HEAD:src/a.py", home=base).strip().decode()
            git(repo, "replace", original, planted, home=base)
            commit = git(repo, "rev-parse", "HEAD", home=base).strip().decode()
            rows = census_tool._ls_tree(repo, commit)
            self.assertEqual([r[2] for r in rows if r[4] == "src/a.py"], [original])
            out = base / "export"
            out.mkdir()
            census_tool.export_tree(repo, commit, out, max_blob_bytes=CAP, max_total_bytes=1 << 20)
            self.assertEqual((out / "src/a.py").read_bytes(), b"TRUE = 1\n")


if __name__ == "__main__":
    unittest_main()
