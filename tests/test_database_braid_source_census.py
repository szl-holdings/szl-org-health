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
from unittest import TestCase, main as unittest_main

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.database_catalog_admission import InputError  # noqa: E402
from tools.database_braid_common import canonical, git_blob_sha1  # noqa: E402
from tools.database_braid_source_census import (  # noqa: E402
    FAMILY_MAP_SCHEMA, LFS_MAGIC, SCHEMA, UNCLASSIFIED, _FALSE_FLAGS, cord_key, lean_text_sorry_tokens,
    list_tree, main, observe, read_blobs, validate_census, validate_census_policy, validate_family_map,
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
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(lean_text_sorry_tokens(raw), expected)


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
        self.assertEqual(by_path["docs/empty.txt"][2:4], (EMPTY_BLOB, "0"))
        for path, raw in ALPHA_FILES.items():
            self.assertEqual(by_path[path][2], git_blob_sha1(raw), path)
            self.assertEqual(by_path[path][3], str(len(raw)), path)

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
            {"key": "alpha:docs/big.bin", "reason": "BLOB_OVER_SIZE_CAP"},
            {"key": "alpha:docs/lfs.bin", "reason": "LFS_POINTER_CONTENT_ABSENT"},
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
        for field in ("commit", "shallow", "tracked_files", "in_scope_files", "out_of_scope_files",
                      "symlink_or_submodule_entries", "cords", "unavailable_cords"):
            bad = {"commit": "c" * 40, "shallow": False}.get(field, 0)
            with self.subTest(field=field):
                self.refuses(lambda v: gamma(v).update({field: bad}), "CENSUS_UNAVAILABLE_NOT_UNKNOWN")
        for state in ("EMPTY", "observed", None):
            self.refuses(lambda v: gamma(v).update(state=state), "CENSUS_UNAVAILABLE_NOT_UNKNOWN")

        def fake_observed_empty(value):
            gamma(value).update(state="OBSERVED", commit="c" * 40, shallow=False, tracked_files=0,
                                in_scope_files=0, out_of_scope_files=0, symlink_or_submodule_entries=0,
                                cords=0, unavailable_cords=0)
        self.refuses(fake_observed_empty, "CENSUS_STATE_INVALID")
        self.refuses(lambda v: v["cords"].append(dict(v["cords"][-1], repository=GAMMA,
                                                      key=cord_key(GAMMA, v["cords"][-1]["path"]))),
                     "CENSUS_CORD_FIELDS_INVALID")

    def test_observed_row_needs_commit_and_shallow(self):
        for field, bad in (("commit", None), ("commit", "C" * 40), ("commit", "c" * 39), ("shallow", None),
                           ("shallow", 0)):
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
            value["unavailable_cords"][0]["key"] = value["cords"][0]["key"]
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

    def test_complete_run_exit_zero_and_never_overwrites(self):
        census = section(beta_policy())
        policy = self.write_policy(census)
        output = self.out / "census.json"
        argv = ["--policy", policy, "--checkout", f"{BETA}={self.beta}", "--output", output]
        code, summary = self.run_main(argv)
        self.assertEqual(code, 0)
        self.assertEqual((summary["state"], summary["provider_writes"]), ("COMPLETE", False))
        written = output.read_bytes()
        report = json.loads(written)
        validate_census(report, census)
        self.assertEqual(report["policy_sha256"], hashlib.sha256(policy.read_bytes()).hexdigest())
        self.assertIsNone(report["family_map_sha256"])
        code, summary = self.run_main(argv)
        self.assertEqual(code, 3)
        self.assertEqual((summary["state"], summary["code"]), ("UNAVAILABLE", "OUTPUT_PATH_DENIED"))
        self.assertEqual(output.read_bytes(), written)

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


if __name__ == "__main__":
    unittest_main()
