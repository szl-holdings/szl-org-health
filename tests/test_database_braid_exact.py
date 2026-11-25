# SPDX-License-Identifier: Apache-2.0
"""Synthetic, offline tests for the braid v2 shared helpers and the exact geometric-mean decision.

Every input is built in the test. Git, where used, runs only inside a temporary repository the
test creates and removes; nothing here opens a network connection, calls a model or signs.
"""
from copy import deepcopy
from fractions import Fraction
import hashlib
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import time
from unittest import TestCase, main as unittest_main, skipUnless

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.database_catalog_admission import InputError  # noqa: E402
from tools.database_ouroboros_braid import canonical as v1_canonical  # noqa: E402
from tools.database_braid_common import (  # noqa: E402
    GENESIS, MAX_JSON_DEPTH, canonical, checkout_root, closed, digest, git_blob_sha1,
    lean_code_only, natural, parse_rational, rational_text, read_json, sha256_hex,
    strict_json, write_exclusive,
)
from tools.database_braid_exact import (  # noqa: E402
    AGGREGATE, MAX_AXIS_BITS, MAX_OPERAND_BITS, PATH_BELOW, PATH_NONE, PATH_ZERO_PINNED, RUNG_AM,
    RUNG_HM, RUNG_POWER, RUNG_ZERO, SCHEMA, decide, iroot, ratio, verify_decision,
)

F = Fraction
TAU = F(4, 5)
AXES = ("a1", "a2", "a3", "a4")
DEMO_VECTORS = (
    ("nominal", ("0.95", "0.92", "0.88", "0.90"), True, False),
    ("provenance_drop", ("0.95", "0.04", "0.88", "0.90"), False, False),
    ("liar", ("0.97", "0.97", "0.97", "0.02"), False, False),
    ("hidden_weak", ("0.95", "0.95", "0.95", "0.40"), False, True),
    ("false_friend", ("0.95", "0.92", "0.90", "0.55"), True, False),
)


def vector(values):
    return {name: F(text) for name, text in zip(AXES, values)}


def equal_weights(axes):
    return {name: 1 for name in axes}


def nested(levels, leaf=1):
    value = leaf
    for _ in range(levels):
        value = [value]
    return value


def brute_meets(axes, weights, tau):
    product = F(1)
    for name, value in axes.items():
        product *= value ** weights[name]
    return product >= tau ** sum(weights.values())


def brute_ppm_floor(axes, weights):
    total = sum(weights.values())
    product = F(1)
    for name, value in axes.items():
        product *= value ** weights[name]
    low, high = 0, 10 ** 6
    while low < high:
        mid = (low + high + 1) // 2
        if F(mid, 10 ** 6) ** total <= product:
            low = mid
        else:
            high = mid - 1
    return low


def generated_cases(count=300):
    rng = random.Random(20261119)
    cases = []
    for _ in range(count):
        size = rng.randint(1, 5)
        axes, weights = {}, {}
        for index in range(size):
            den = rng.randint(1, 40)
            roll = rng.random()
            if roll < 0.04:
                num = 0
            elif roll < 0.15:
                num = rng.randint(0, den)
            else:
                num = rng.randint(max(1, den // 2), den)
            axes[f"x{index}"] = F(num, den)
            weights[f"x{index}"] = rng.randint(1, 5)
        tau_den = rng.randint(1, 20)
        tau = F(rng.randint(1, tau_den), tau_den)
        cases.append((axes, weights, tau))
    return cases


def git_env(home):
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home),
        "GIT_AUTHOR_NAME": "Synthetic Test", "GIT_AUTHOR_EMAIL": "synthetic@example.invalid",
        "GIT_COMMITTER_NAME": "Synthetic Test", "GIT_COMMITTER_EMAIL": "synthetic@example.invalid",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C",
    }


def git(directory, env, *args, stdin=None):
    return subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", "-c", "core.autocrlf=false",
         "-C", str(directory), *args],
        input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=True, timeout=60,
    ).stdout


class CanonicalTests(TestCase):
    SAMPLES = (
        {"b": 1, "a": [True, False, None, "x"], "c": {"z": -7, "y": 10 ** 40}},
        ["unicode é ☃ \U0001f600", "", 0, -1],
        {"nested": {"deep": [[{"k": "v"}]]}, "empty": {}, "list": []},
        "plain", 12345, True, None, [],
    )

    def test_byte_identical_to_v1_on_float_free_values(self):
        for value in self.SAMPLES:
            self.assertEqual(canonical(value), v1_canonical(value))
            self.assertEqual(digest(value), hashlib.sha256(v1_canonical(value)).hexdigest())

    def test_sorted_compact_ascii(self):
        self.assertEqual(canonical({"b": 1, "a": "é"}), b'{"a":"\\u00e9","b":1}')
        self.assertEqual(canonical((1, 2)), canonical([1, 2]))

    def test_floats_refused_anywhere(self):
        for value in (1.0, [0.5], {"a": {"b": [1, 2.5]}}, float("nan"), float("inf"), (0.0,)):
            with self.assertRaisesRegex(InputError, "FLOAT_VALUE_REFUSED"):
                canonical(value)

    def test_non_text_keys_and_foreign_types_refused(self):
        with self.assertRaisesRegex(InputError, "JSON_KEY_NOT_TEXT"):
            canonical({1: "a"})
        with self.assertRaisesRegex(InputError, "JSON_KEY_NOT_TEXT"):
            canonical({"ok": {None: 1}})
        for value in (F(1, 2), b"raw", {1, 2}, object(), [Path("x")]):
            with self.assertRaisesRegex(InputError, "JSON_VALUE_TYPE_REFUSED"):
                canonical(value)

    def test_depth_cap(self):
        canonical(nested(MAX_JSON_DEPTH))
        with self.assertRaisesRegex(InputError, "JSON_DEPTH_EXCEEDED"):
            canonical(nested(MAX_JSON_DEPTH + 1))
        deep = {}
        cursor = deep
        for _ in range(MAX_JSON_DEPTH + 1):
            cursor["k"] = {}
            cursor = cursor["k"]
        with self.assertRaisesRegex(InputError, "JSON_DEPTH_EXCEEDED"):
            canonical(deep)

    def test_digest_helpers(self):
        self.assertEqual(sha256_hex(b""), hashlib.sha256(b"").hexdigest())
        self.assertEqual(GENESIS, "0" * 64)


class StrictJsonTests(TestCase):
    def test_valid_round_trip(self):
        value = {"a": [1, True, None, "x"], "b": {"c": -3}}
        self.assertEqual(strict_json(canonical(value), max_bytes=1000), value)

    def test_duplicate_keys_refused_at_any_depth(self):
        for raw in (b'{"a":1,"a":2}', b'{"x":{"a":1,"a":1}}', b'[{"k":1,"k":1}]'):
            with self.assertRaisesRegex(InputError, "DUPLICATE_JSON_KEY"):
                strict_json(raw, max_bytes=100)

    def test_nonfinite_refused(self):
        for raw in (b"NaN", b'{"a":Infinity}', b"[-Infinity]"):
            with self.assertRaisesRegex(InputError, "NONFINITE_JSON_VALUE"):
                strict_json(raw, max_bytes=100)

    def test_floats_refused(self):
        for raw in (b"1.0", b'{"a":0.5}', b"[1e3]", b"-0.0", b"2E-1"):
            with self.assertRaisesRegex(InputError, "FLOAT_VALUE_REFUSED"):
                strict_json(raw, max_bytes=100)

    def test_size_and_type_bounds(self):
        with self.assertRaisesRegex(InputError, "INPUT_SIZE_INVALID"):
            strict_json(b"", max_bytes=10)
        with self.assertRaisesRegex(InputError, "INPUT_SIZE_INVALID"):
            strict_json(b"[1,2,3]", max_bytes=6)
        self.assertEqual(strict_json(b"[1,2,3]", max_bytes=7), [1, 2, 3])
        for raw in ("[1]", bytearray(b"[1]"), None):
            with self.assertRaisesRegex(InputError, "INPUT_SIZE_INVALID"):
                strict_json(raw, max_bytes=10)

    def test_malformed_refused(self):
        for raw in (b"{", b"[1]x", b"\xff\xfe", b"\xef\xbb\xbf[1]", b"'a'", b"[1,]"):
            with self.assertRaisesRegex(InputError, "INVALID_JSON"):
                strict_json(raw, max_bytes=100)

    def test_depth(self):
        depth = MAX_JSON_DEPTH
        self.assertEqual(strict_json(b"[" * depth + b"1" + b"]" * depth, max_bytes=1000), nested(depth))
        with self.assertRaisesRegex(InputError, "JSON_DEPTH_EXCEEDED"):
            strict_json(b"[" * (depth + 1) + b"1" + b"]" * (depth + 1), max_bytes=1000)
        with self.assertRaises(InputError):
            strict_json(b"[" * 100000 + b"]" * 100000, max_bytes=10 ** 6)


class ReadJsonTests(TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_reads_value_and_sha_of_exact_bytes(self):
        raw = b'{"b": 2, "a": 1}\n'
        path = self.dir / "in.json"
        path.write_bytes(raw)
        value, sha = read_json(path, max_bytes=100)
        self.assertEqual(value, {"a": 1, "b": 2})
        self.assertEqual(sha, hashlib.sha256(raw).hexdigest())

    def test_symlink_directory_missing_and_str_refused(self):
        target = self.dir / "real.json"
        target.write_bytes(b"[1]")
        link = self.dir / "link.json"
        link.symlink_to(target)
        for path in (link, self.dir, self.dir / "missing.json"):
            with self.assertRaisesRegex(InputError, "SOURCE_FILE_UNAVAILABLE"):
                read_json(path, max_bytes=100)
        with self.assertRaisesRegex(InputError, "SOURCE_FILE_UNAVAILABLE"):
            read_json(str(target), max_bytes=100)

    def test_size_bounds(self):
        empty = self.dir / "empty.json"
        empty.write_bytes(b"")
        with self.assertRaisesRegex(InputError, "INPUT_SIZE_INVALID"):
            read_json(empty, max_bytes=100)
        big = self.dir / "big.json"
        big.write_bytes(b"[" + b"1," * 50 + b"1]")
        with self.assertRaisesRegex(InputError, "INPUT_SIZE_INVALID"):
            read_json(big, max_bytes=50)

    def test_strictness_carries_through(self):
        path = self.dir / "dup.json"
        path.write_bytes(b'{"a":1,"a":2}')
        with self.assertRaisesRegex(InputError, "DUPLICATE_JSON_KEY"):
            read_json(path, max_bytes=100)
        path = self.dir / "float.json"
        path.write_bytes(b'{"a":0.1}')
        with self.assertRaisesRegex(InputError, "FLOAT_VALUE_REFUSED"):
            read_json(path, max_bytes=100)


class WriteExclusiveTests(TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_writes_canonical_plus_newline_and_never_overwrites(self):
        path = self.dir / "out.json"
        sha = write_exclusive(path, {"b": 1, "a": 2}, max_bytes=100)
        raw = path.read_bytes()
        self.assertEqual(raw, b'{"a":2,"b":1}\n')
        self.assertEqual(sha, hashlib.sha256(raw).hexdigest())
        with self.assertRaisesRegex(InputError, "OUTPUT_PATH_DENIED"):
            write_exclusive(path, {"other": 1}, max_bytes=100)
        self.assertEqual(path.read_bytes(), raw)

    def test_symlink_missing_parent_and_str_refused(self):
        dangling = self.dir / "dangling.json"
        dangling.symlink_to(self.dir / "nowhere.json")
        with self.assertRaisesRegex(InputError, "OUTPUT_PATH_DENIED"):
            write_exclusive(dangling, [1], max_bytes=100)
        self.assertFalse((self.dir / "nowhere.json").exists())
        with self.assertRaisesRegex(InputError, "OUTPUT_PATH_DENIED"):
            write_exclusive(self.dir / "no" / "parent.json", [1], max_bytes=100)
        with self.assertRaisesRegex(InputError, "OUTPUT_PATH_DENIED"):
            write_exclusive(str(self.dir / "str.json"), [1], max_bytes=100)
        self.assertFalse((self.dir / "str.json").exists())

    def test_refuses_inside_given_checkout_including_via_symlinked_parent(self):
        checkout = self.dir / "checkout"
        (checkout / "sub").mkdir(parents=True)
        for path in (checkout / "a.json", checkout / "sub" / "b.json"):
            with self.assertRaisesRegex(InputError, "OUTPUT_PATH_DENIED"):
                write_exclusive(path, [1], max_bytes=100, checkout=checkout)
            self.assertFalse(path.exists())
        link = self.dir / "alias"
        link.symlink_to(checkout, target_is_directory=True)
        with self.assertRaisesRegex(InputError, "OUTPUT_PATH_DENIED"):
            write_exclusive(link / "c.json", [1], max_bytes=100, checkout=checkout)
        self.assertFalse((checkout / "c.json").exists())
        outside = self.dir / "outside.json"
        write_exclusive(outside, [1], max_bytes=100, checkout=checkout)
        self.assertTrue(outside.is_file())

    def test_refuses_inside_this_repository(self):
        self.assertEqual(checkout_root(), ROOT)
        path = ROOT / "braid-exact-test-must-not-exist.json"
        self.assertFalse(path.exists())
        try:
            with self.assertRaisesRegex(InputError, "OUTPUT_PATH_DENIED"):
                write_exclusive(path, [1], max_bytes=100, checkout=checkout_root())
            self.assertFalse(path.exists())
        finally:
            if path.exists() and not path.is_symlink():
                path.unlink()

    def test_size_cap_and_floats_leave_no_file(self):
        path = self.dir / "big.json"
        with self.assertRaisesRegex(InputError, "OUTPUT_TOO_LARGE"):
            write_exclusive(path, "x" * 20, max_bytes=22)
        self.assertFalse(path.exists())
        write_exclusive(path, "x" * 20, max_bytes=23)
        self.assertEqual(path.stat().st_size, 23)
        floaty = self.dir / "float.json"
        with self.assertRaisesRegex(InputError, "FLOAT_VALUE_REFUSED"):
            write_exclusive(floaty, {"a": 0.5}, max_bytes=100)
        self.assertFalse(floaty.exists())


class RationalTests(TestCase):
    def test_round_trips(self):
        for value in (F(0), F(1), F(4, 5), F(13, 16), F(3), F(10 ** 300 - 1, 10 ** 300)):
            text = rational_text(value)
            self.assertEqual(parse_rational(text), value)
            self.assertEqual(rational_text(parse_rational(text)), text)
        self.assertEqual(rational_text(F(6, 8)), "3/4")
        self.assertEqual(rational_text(F(0, 7)), "0/1")

    def test_rational_text_refusals(self):
        class Sub(Fraction):
            pass

        for value in (F(-1, 2), 0.5, 1, True, "1/2", Sub(1, 2), None):
            with self.assertRaisesRegex(InputError, "RATIONAL_INVALID"):
                rational_text(value)

    def test_parse_refusals(self):
        bad = ("0.5", "1", "1/0", "-1/2", "+1/2", " 1/2", "1/2 ", "1/2\n", "01/2", "1/02", "1 /2",
               "", "/2", "1/", "1//2", "١/2", "1/2/3", "0x1/2", "1" * 402 + "/1", "1/" + "1" * 402)
        for text in bad:
            with self.assertRaisesRegex(InputError, "RATIONAL_INVALID"):
                parse_rational(text)
        for value in (0.5, 1, None, b"1/2", F(1, 2), True):
            with self.assertRaisesRegex(InputError, "RATIONAL_INVALID"):
                parse_rational(value)
        with self.assertRaisesRegex(InputError, "RATIONAL_INVALID"):
            parse_rational("1" * 405 + "/" + "1" * 405)

    def test_non_reduced_refused(self):
        for text in ("2/4", "0/5", "4/2", "10/10", "6/9"):
            with self.assertRaisesRegex(InputError, "RATIONAL_NOT_REDUCED"):
                parse_rational(text)
        self.assertEqual(parse_rational("0/1"), 0)
        self.assertEqual(parse_rational("3/1"), 3)


class NaturalAndClosedTests(TestCase):
    def test_natural(self):
        for value in (0, 1, 10 ** 15):
            self.assertEqual(natural(value), value)
        for value in (-1, 10 ** 15 + 1, True, False, 1.0, "1", None, F(1)):
            with self.assertRaisesRegex(InputError, "NATURAL_INVALID"):
                natural(value)
        with self.assertRaisesRegex(InputError, "COUNT_BAD"):
            natural(-1, "COUNT_BAD")
        with self.assertRaisesRegex(InputError, "NATURAL_INVALID"):
            natural(6, maximum=5)
        self.assertEqual(natural(5, maximum=5), 5)

    def test_closed(self):
        value = {"a": 1, "b": 2}
        self.assertIs(closed(value, ("b", "a"), "SHAPE_BAD"), value)
        for bad in ({"a": 1}, {"a": 1, "b": 2, "c": 3}, [("a", 1), ("b", 2)], None, {"a": 1, "c": 2}):
            with self.assertRaisesRegex(InputError, "SHAPE_BAD"):
                closed(bad, ("a", "b"), "SHAPE_BAD")


class LeanCodeOnlyTests(TestCase):
    def test_line_comments_keep_newlines(self):
        self.assertEqual(lean_code_only("a -- sorry\nb"), "a \nb")
        self.assertEqual(lean_code_only("x -- tail without newline"), "x ")

    def test_nested_block_comments(self):
        # Each outermost block comment becomes one space, as Lean reads it.
        text = "a /- b /- c -/ still comment sorry -/ e"
        self.assertEqual(lean_code_only(text), "a   e")
        self.assertEqual(lean_code_only("/- outer /- inner -/ -- not a line comment\n-/z"), " z")
        self.assertEqual(lean_code_only("/-- doc sorry -/ theorem t"), "  theorem t")

    def test_a_block_comment_never_joins_the_tokens_around_it(self):
        self.assertEqual(lean_code_only("by/- c -/sorry"), "by sorry")
        self.assertEqual(lean_code_only("exact/- why /- nested -/ -/sorry"), "exact sorry")
        self.assertEqual(lean_code_only("a/--/b"), "a b")

    def test_unterminated_block_swallows_rest(self):
        self.assertEqual(lean_code_only("keep /- open sorry"), "keep ")

    def test_stray_close_and_plain_text_kept(self):
        self.assertEqual(lean_code_only("a -/ b"), "a -/ b")
        source = "theorem t : 1 = 1 := rfl\n"
        self.assertEqual(lean_code_only(source), source)
        self.assertEqual(lean_code_only(""), "")


@skipUnless(shutil.which("git"), "git is not installed")
class GitBlobTests(TestCase):
    def test_matches_git_hash_object_and_committed_tree(self):
        samples = {
            "empty.bin": b"",
            "text.txt": b"hello braid\n",
            "crlf.txt": b"line one\r\nline two\r\n",
            "binary.bin": bytes(range(256)) * 3,
            "unicode.lean": "theorem λ : True := trivial\n".encode("utf-8"),
        }
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            repo = Path(tmp) / "repo"
            home.mkdir()
            repo.mkdir()
            env = git_env(home)
            git(repo, env, "init", "-q")
            for name, raw in samples.items():
                (repo / name).write_bytes(raw)
            git(repo, env, "add", "--", *samples)
            git(repo, env, "commit", "-q", "-m", "synthetic")
            listing = git(repo, env, "ls-tree", "-r", "HEAD").decode("ascii").splitlines()
            tree = {}
            for line in listing:
                meta, path = line.split("\t", 1)
                tree[path] = meta.split()[2]
            self.assertEqual(set(tree), set(samples))
            for name, raw in samples.items():
                ours = git_blob_sha1(raw)
                self.assertRegex(ours, r"\A[0-9a-f]{40}\Z")
                self.assertEqual(ours, tree[name])
                stdin_id = git(repo, env, "hash-object", "--no-filters", "--stdin", stdin=raw)
                self.assertEqual(ours, stdin_id.decode("ascii").strip())
        self.assertEqual(git_blob_sha1(b""), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")


class DemoVectorTests(TestCase):
    def test_published_vectors_exact(self):
        for name, values, meets, dang in DEMO_VECTORS:
            axes = vector(values)
            record = decide(axes, equal_weights(axes), TAU)
            self.assertEqual((record["geometric_mean_meets_tau"], record["dang"]), (meets, dang), name)
            self.assertIs(record["authority_granted"], False)
            self.assertEqual(record["schema"], SCHEMA)
            self.assertEqual(record["aggregate"], AGGREGATE)
            self.assertEqual(record["refusal_path"], PATH_NONE if meets else PATH_BELOW)
            self.assertTrue(verify_decision(record))
            self.assertEqual(meets, brute_meets(axes, equal_weights(axes), TAU))

    def test_hidden_weak_arithmetic(self):
        axes = vector(("0.95", "0.95", "0.95", "0.40"))
        record = decide(axes, equal_weights(axes), TAU)
        self.assertEqual(parse_rational(record["arithmetic_mean"]), F(13, 16))
        self.assertEqual(record["arithmetic_mean"], "13/16")
        self.assertEqual(record["geometric_mean_ppm_floor"], 765257)
        self.assertEqual(record["rung"], RUNG_POWER)
        self.assertEqual(record["min_axis"], {"id": "a4", "value": "2/5"})
        self.assertEqual(record["weight_sum"], 4)
        self.assertEqual(record["tau"], "4/5")
        self.assertEqual(record["power_comparison"]["relation"], "LEFT_BELOW_RIGHT")
        self.assertLess(int(record["power_comparison"]["left"]), int(record["power_comparison"]["right"]))

    def test_exact_ties_meet_tau(self):
        for size in (1, 2, 4, 7):
            axes = {f"t{i}": TAU for i in range(size)}
            record = decide(axes, equal_weights(axes), TAU)
            self.assertTrue(record["geometric_mean_meets_tau"])
            self.assertEqual(record["rung"], RUNG_HM)
            self.assertFalse(record["dang"])
            self.assertEqual(record["geometric_mean_ppm_floor"], 800000)
            self.assertEqual(record["harmonic_mean"], "4/5")
        axes = {"p": F(16, 25), "q": F(1)}
        record = decide(axes, equal_weights(axes), TAU)
        self.assertTrue(record["geometric_mean_meets_tau"])
        self.assertEqual(record["rung"], RUNG_POWER)
        self.assertEqual(record["power_comparison"]["left"], record["power_comparison"]["right"])
        self.assertEqual(record["power_comparison"]["relation"], "LEFT_AT_LEAST_RIGHT")
        self.assertEqual(record["geometric_mean_ppm_floor"], 800000)
        self.assertEqual(record["refusal_path"], PATH_NONE)
        self.assertFalse(record["dang"])

    def test_one_below_tie_fails(self):
        axes = {"p": F(16, 25) - F(1, 10 ** 9), "q": F(1)}
        record = decide(axes, equal_weights(axes), TAU)
        self.assertFalse(record["geometric_mean_meets_tau"])
        self.assertTrue(record["dang"])
        self.assertEqual(record["refusal_path"], PATH_BELOW)
        self.assertEqual(record["geometric_mean_ppm_floor"], 799999)


class ZeroPinnedTests(TestCase):
    def test_zero_axis_pins_without_power_comparison(self):
        axes = {"a": F(0), "b": F(1), "c": F(1), "d": F(1), "e": F(1)}
        record = decide(axes, equal_weights(axes), TAU)
        self.assertEqual(record["refusal_path"], PATH_ZERO_PINNED)
        self.assertEqual(record["rung"], RUNG_ZERO)
        self.assertIsNone(record["power_comparison"])
        self.assertIsNone(record["harmonic_mean"])
        self.assertIs(record["geometric_mean_meets_tau"], False)
        self.assertEqual(record["geometric_mean_ppm_floor"], 0)
        self.assertEqual(record["arithmetic_mean"], "4/5")
        self.assertIs(record["dang"], True)
        self.assertEqual(record["min_axis"], {"id": "a", "value": "0/1"})
        self.assertIs(record["authority_granted"], False)
        self.assertTrue(verify_decision(record))

    def test_zero_axis_dang_only_when_arithmetic_clears(self):
        axes = {"a": F(0), "b": F(1), "c": F(1), "d": F(1)}
        record = decide(axes, equal_weights(axes), TAU)
        self.assertEqual(record["refusal_path"], PATH_ZERO_PINNED)
        self.assertIs(record["dang"], False)
        heavy = decide(axes, {"a": 1, "b": 5, "c": 5, "d": 5}, TAU)
        self.assertIs(heavy["dang"], True)
        all_zero = decide({"a": F(0)}, {"a": 1}, F(1, 10 ** 6))
        self.assertIs(all_zero["dang"], False)
        self.assertEqual(all_zero["geometric_mean_ppm_floor"], 0)

    def test_tiny_positive_axis_is_not_pinned(self):
        axes = {"a": F(1, 10 ** 12), "b": F(1)}
        record = decide(axes, equal_weights(axes), F(1, 10 ** 7))
        self.assertEqual(record["refusal_path"], PATH_NONE)
        self.assertIsNotNone(record["power_comparison"])
        self.assertEqual(record["geometric_mean_ppm_floor"], 1)


class DecideInputTests(TestCase):
    def setUp(self):
        self.axes = vector(DEMO_VECTORS[0][1])
        self.weights = equal_weights(self.axes)

    def test_axes_refusals(self):
        for axes in ({}, [], None, {f"n{i}": F(1) for i in range(65)}, {"": F(1)}, {"x" * 65: F(1)},
                     {1: F(1)}):
            weights = {k: 1 for k in axes} if type(axes) is dict else {}
            with self.assertRaisesRegex(InputError, "EXACT_AXES_INVALID"):
                decide(axes, weights, TAU)
        decide({f"n{i}": F(1) for i in range(64)}, {f"n{i}": 1 for i in range(64)}, TAU)

    def test_axis_value_refusals(self):
        for value in (F(-1, 2), F(3, 2), 0.5, 1, True, "1/2", None):
            axes = dict(self.axes, a1=value)
            with self.assertRaisesRegex(InputError, "EXACT_AXIS_OUT_OF_RANGE"):
                decide(axes, self.weights, TAU)

    def test_weight_refusals(self):
        for weights in (dict(self.weights, a1=0), dict(self.weights, a1=65), dict(self.weights, a1=True),
                        dict(self.weights, a1=1.0), dict(self.weights, a1="1"), dict(self.weights, extra=1),
                        {k: 1 for k in AXES[:3]}, [1, 1, 1, 1], None):
            with self.assertRaisesRegex(InputError, "EXACT_WEIGHTS_INVALID"):
                decide(self.axes, weights, TAU)
        decide(self.axes, dict(self.weights, a1=64), TAU)

    def test_tau_refusals(self):
        for tau in (F(0), F(-1, 2), F(5, 4), 0.8, 1, "4/5", None):
            with self.assertRaisesRegex(InputError, "EXACT_TAU_INVALID"):
                decide(self.axes, self.weights, tau)
        self.assertTrue(decide({"a": F(1)}, {"a": 1}, F(1))["geometric_mean_meets_tau"])

    def test_inputs_not_mutated_and_output_canonical(self):
        axes, weights = deepcopy(self.axes), deepcopy(self.weights)
        record = decide(axes, weights, TAU)
        self.assertEqual((axes, weights), (self.axes, self.weights))
        self.assertEqual(strict_json(canonical(record), max_bytes=10 ** 6), record)
        self.assertEqual(list(record["axes"]), sorted(record["axes"]))

    def test_ratio(self):
        self.assertEqual(ratio(3, 4), F(3, 4))
        self.assertEqual(ratio(0, 1), 0)
        self.assertEqual(ratio(5, 5), 1)
        for num, den in ((0, 0), (1, 0), (2, 1), (-1, 2), (1, -2), (True, 2), (1, True), (1.0, 2), ("1", 2)):
            with self.assertRaisesRegex(InputError, "EXACT_RATIO_INVALID"):
                ratio(num, den)


class IrootTests(TestCase):
    def test_edges(self):
        self.assertEqual(iroot(0, 1), 0)
        self.assertEqual(iroot(0, 7), 0)
        self.assertEqual(iroot(1, 9), 1)
        self.assertEqual(iroot(2, 2), 1)
        self.assertEqual(iroot(3, 2), 1)
        self.assertEqual(iroot(4, 2), 2)
        self.assertEqual(iroot(12345, 1), 12345)
        self.assertEqual(iroot(2, 64), 1)
        self.assertEqual(iroot(2 ** 64, 64), 2)
        self.assertEqual(iroot(2 ** 64 - 1, 64), 1)

    def test_exact_around_perfect_powers(self):
        for base in (2, 3, 10, 999, 10 ** 20 + 7):
            for degree in (2, 3, 5, 17):
                power = base ** degree
                self.assertEqual(iroot(power, degree), base)
                self.assertEqual(iroot(power - 1, degree), base - 1)
                self.assertEqual(iroot(power + 1, degree), base)

    def test_matches_floor_definition_on_random_values(self):
        rng = random.Random(20261119)
        for _ in range(200):
            value = rng.randrange(0, 1 << rng.randint(1, 300))
            degree = rng.randint(1, 12)
            root = iroot(value, degree)
            self.assertLessEqual(root ** degree, value)
            self.assertGreater((root + 1) ** degree, value)

    def test_refusals(self):
        for value, degree in ((-1, 2), (4, 0), (4, -1), (True, 2), (4, True), (4.0, 2), (4, 2.0), ("4", 2)):
            with self.assertRaisesRegex(InputError, "EXACT_ROOT_INVALID"):
                iroot(value, degree)


class GeneratedPropertyTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = generated_cases()

    def test_generator_covers_every_path(self):
        paths, rungs, weights = set(), set(), set()
        for axes, weight_map, tau in self.cases:
            record = decide(axes, weight_map, tau)
            paths.add(record["refusal_path"])
            rungs.add(record["rung"])
            weights.update(weight_map.values())
        self.assertEqual(paths, {PATH_NONE, PATH_BELOW, PATH_ZERO_PINNED})
        self.assertEqual(rungs, {RUNG_ZERO, RUNG_HM, RUNG_AM, RUNG_POWER})
        self.assertEqual(weights, {1, 2, 3, 4, 5})

    def test_decide_matches_brute_force(self):
        for axes, weights, tau in self.cases:
            record = decide(axes, weights, tau)
            total = sum(weights.values())
            arithmetic = sum(axes[n] * weights[n] for n in axes) / total
            self.assertEqual(record["weight_sum"], total)
            self.assertEqual(parse_rational(record["arithmetic_mean"]), arithmetic)
            low = min(axes.values())
            self.assertEqual(parse_rational(record["min_axis"]["value"]), low)
            if low == 0:
                self.assertIs(record["geometric_mean_meets_tau"], False)
                self.assertEqual(record["refusal_path"], PATH_ZERO_PINNED)
                self.assertIsNone(record["power_comparison"])
                self.assertIs(record["dang"], arithmetic >= tau)
                continue
            meets = brute_meets(axes, weights, tau)
            self.assertIs(record["geometric_mean_meets_tau"], meets)
            self.assertIs(record["dang"], arithmetic >= tau and not meets)
            self.assertEqual(record["refusal_path"], PATH_NONE if meets else PATH_BELOW)
            self.assertEqual(record["geometric_mean_ppm_floor"], brute_ppm_floor(axes, weights))
            harmonic = total / sum(F(weights[n]) / axes[n] for n in axes)
            self.assertEqual(parse_rational(record["harmonic_mean"]), harmonic)

    def test_mean_order_and_rung_agree_with_verdict(self):
        for axes, weights, tau in self.cases:
            record = decide(axes, weights, tau)
            if record["rung"] == RUNG_ZERO:
                self.assertEqual(min(axes.values()), 0)
                continue
            harmonic = parse_rational(record["harmonic_mean"])
            arithmetic = parse_rational(record["arithmetic_mean"])
            self.assertLessEqual(harmonic, arithmetic)
            meets = record["geometric_mean_meets_tau"]
            if record["rung"] == RUNG_HM:
                self.assertGreaterEqual(harmonic, tau)
                self.assertTrue(meets)
            elif record["rung"] == RUNG_AM:
                self.assertLess(arithmetic, tau)
                self.assertFalse(meets)
            else:
                self.assertEqual(record["rung"], RUNG_POWER)
                self.assertTrue(harmonic < tau <= arithmetic)
            relation = "LEFT_AT_LEAST_RIGHT" if meets else "LEFT_BELOW_RIGHT"
            self.assertEqual(record["power_comparison"]["relation"], relation)
            left, right = int(record["power_comparison"]["left"]), int(record["power_comparison"]["right"])
            self.assertIs(left >= right, meets)

    def test_every_generated_record_verifies_after_json_round_trip(self):
        for axes, weights, tau in self.cases:
            record = decide(axes, weights, tau)
            self.assertIs(record["authority_granted"], False)
            self.assertTrue(verify_decision(strict_json(canonical(record), max_bytes=10 ** 6)))


class VerifyDecisionTests(TestCase):
    def setUp(self):
        self.record = decide(vector(DEMO_VECTORS[3][1]), equal_weights(AXES), TAU)
        self.zero = decide({"a": F(0), "b": F(1)}, {"a": 1, "b": 1}, F(1, 2))
        self.assertTrue(verify_decision(self.record))
        self.assertTrue(verify_decision(self.zero))

    def tampered(self, mutate, base=None):
        record = deepcopy(self.record if base is None else base)
        mutate(record)
        return record

    def assert_refused(self, record, code):
        with self.assertRaisesRegex(InputError, code):
            verify_decision(record)

    def test_every_drift_tamper_refused(self):
        def setter(*keys, value):
            def mutate(record):
                target = record
                for key in keys[:-1]:
                    target = target[key]
                target[keys[-1]] = value
            return mutate

        tampers = (
            setter("tau", value="3/4"),
            setter("axes", "a1", value="9/10"),
            setter("weights", "a1", value=2),
            setter("weight_sum", value=5),
            setter("min_axis", "id", value="a1"),
            setter("min_axis", "value", value="1/2"),
            setter("arithmetic_mean", value="4/5"),
            setter("harmonic_mean", value="3/4"),
            setter("harmonic_mean", value=None),
            setter("geometric_mean_meets_tau", value=True),
            setter("geometric_mean_ppm_floor", value=765258),
            setter("geometric_mean_ppm_floor", value=765256),
            setter("rung", value=RUNG_AM),
            setter("power_comparison", "left", value="1"),
            setter("power_comparison", "right", value="1"),
            setter("power_comparison", "relation", value="LEFT_AT_LEAST_RIGHT"),
            setter("power_comparison", "meaning", value="other"),
            setter("power_comparison", value=None),
            setter("dang", value=False),
            setter("refusal_path", value=PATH_NONE),
            setter("refusal_path", value=PATH_ZERO_PINNED),
            lambda record: record["power_comparison"].pop("meaning"),
            lambda record: record["power_comparison"].update(extra=1),
            lambda record: record["min_axis"].update(extra=1),
        )
        for mutate in tampers:
            self.assert_refused(self.tampered(mutate), "EXACT_DECISION_DRIFT")

    def test_zero_pinned_tampers_refused(self):
        self.assertIs(self.zero["dang"], True)
        for key, value in (("dang", False), ("geometric_mean_meets_tau", True),
                           ("geometric_mean_ppm_floor", 1), ("rung", RUNG_POWER),
                           ("refusal_path", PATH_BELOW), ("harmonic_mean", "0/1"),
                           ("power_comparison", {"left": "0", "right": "1"})):
            record = deepcopy(self.zero)
            record[key] = value
            self.assert_refused(record, "EXACT_DECISION_DRIFT")

    def test_shape_and_schema_tampers_refused(self):
        for key in list(self.record):
            record = deepcopy(self.record)
            record.pop(key)
            self.assert_refused(record, "EXACT_DECISION_FIELDS_INVALID")
        self.assert_refused(self.tampered(lambda r: r.update(signed=False)), "EXACT_DECISION_FIELDS_INVALID")
        self.assert_refused([self.record], "EXACT_DECISION_FIELDS_INVALID")
        self.assert_refused(None, "EXACT_DECISION_FIELDS_INVALID")
        for key, value in (("schema", SCHEMA + "x"), ("aggregate", "WEIGHTED_SUM"),
                           ("authority_granted", True), ("authority_granted", 0),
                           ("authority_granted", None), ("authority_granted", "false")):
            record = deepcopy(self.record)
            record[key] = value
            self.assert_refused(record, "EXACT_DECISION_SCHEMA_INVALID")
        for key in ("axes", "weights"):
            for value in (list(self.record[key].items()), None):
                record = deepcopy(self.record)
                record[key] = value
                self.assert_refused(record, "EXACT_DECISION_FIELDS_INVALID")
        self.assert_refused(self.tampered(lambda r: r["axes"].update({1: "1/2"})),
                            "EXACT_DECISION_FIELDS_INVALID")

    def test_value_type_tampers_refused(self):
        self.assert_refused(self.tampered(lambda r: r.update(tau="8/10")), "RATIONAL_NOT_REDUCED")
        self.assert_refused(self.tampered(lambda r: r.update(tau=0.8)), "RATIONAL_INVALID")
        self.assert_refused(self.tampered(lambda r: r.update(tau="0.8")), "RATIONAL_INVALID")
        self.assert_refused(self.tampered(lambda r: r["axes"].update(a1="19/20 ")), "RATIONAL_INVALID")
        self.assert_refused(self.tampered(lambda r: r["axes"].update(a1="38/40")), "RATIONAL_NOT_REDUCED")
        self.assert_refused(self.tampered(lambda r: r["axes"].update(a1="3/2")), "EXACT_AXIS_OUT_OF_RANGE")
        self.assert_refused(self.tampered(lambda r: r.update(tau="0/1")), "EXACT_TAU_INVALID")
        self.assert_refused(self.tampered(lambda r: r["weights"].update(a1=True)), "EXACT_WEIGHTS_INVALID")
        self.assert_refused(self.tampered(lambda r: r["weights"].update(a1=1.0)), "EXACT_WEIGHTS_INVALID")
        self.assert_refused(self.tampered(lambda r: r["weights"].update(a1=0)), "EXACT_WEIGHTS_INVALID")
        self.assert_refused(self.tampered(lambda r: r["weights"].pop("a4")), "EXACT_WEIGHTS_INVALID")
        self.assert_refused(self.tampered(lambda r: r["axes"].update(a5="1/1")), "EXACT_WEIGHTS_INVALID")
        self.assert_refused(self.tampered(lambda r: r.update(axes={}, weights={})), "EXACT_AXES_INVALID")

    def test_key_order_is_not_identity(self):
        record = deepcopy(self.record)
        record["axes"] = dict(reversed(list(record["axes"].items())))
        record["weights"] = dict(reversed(list(record["weights"].items())))
        self.assertTrue(verify_decision(record))
        self.assertEqual(canonical(record), canonical(self.record))

    def test_nothing_reports_signed_or_authorized(self):
        for record in (self.record, self.zero):
            self.assertIs(record["authority_granted"], False)
            lowered = canonical(record).decode("ascii").lower()
            for word in ("signed", "signature", "authorized", "verified", "allow"):
                self.assertNotIn(word, lowered)


def operand_bits(axes, weights, tau):
    """Bit lengths of both sides of the power comparison, computed directly."""
    total = sum(weights.values())
    left, right = tau.denominator ** total, tau.numerator ** total
    for name, value in axes.items():
        left *= value.numerator ** weights[name]
        right *= value.denominator ** weights[name]
    return max(left.bit_length(), right.bit_length())


class SizeBoundTests(TestCase):
    def refused(self, code, *args):
        with self.assertRaises(InputError) as caught:
            decide(*args)
        self.assertEqual(caught.exception.code, code)

    def test_axis_and_tau_bit_caps_are_exact(self):
        edge = F(1, 2 ** (MAX_AXIS_BITS - 1))
        self.assertEqual(edge.denominator.bit_length(), MAX_AXIS_BITS)
        self.assertTrue(verify_decision(decide({"a": edge}, {"a": 1}, F(1, 2))))
        self.assertTrue(verify_decision(decide({"a": F(1, 2)}, {"a": 1}, edge)))
        over = F(1, 2 ** MAX_AXIS_BITS)
        self.refused("EXACT_AXIS_OUT_OF_RANGE", {"a": over}, {"a": 1}, F(1, 2))
        self.refused("EXACT_TAU_INVALID", {"a": F(1, 2)}, {"a": 1}, over)

    def test_every_record_decide_accepts_reads_back_through_verify_decision(self):
        # The widest numbers the cap admits have exactly the most digits parse_rational reads.
        widest = 2 ** MAX_AXIS_BITS - 1
        self.assertEqual(len(str(widest)), 401)
        self.assertEqual(len(str(2 ** (MAX_AXIS_BITS + 1) - 1)), 402)
        near_one = F(widest - 1, widest)
        for axes, tau in (({"a": F(1, widest)}, F(1, 2)),
                          ({"a": near_one, "b": F(1, widest)}, near_one),
                          ({"a": near_one}, near_one), ({"a": F(1, 2)}, F(1, widest))):
            with self.subTest(axes=sorted(axes)):
                record = decide(axes, {name: 1 for name in axes}, tau)
                self.assertTrue(verify_decision(record))
        # The case the old 1400-bit cap let through: written by decide, unreadable by verify.
        self.refused("EXACT_AXIS_OUT_OF_RANGE", {"a": F(1, 2 ** 1333)}, {"a": 1}, F(1, 2))
        self.refused("EXACT_TAU_INVALID", {"a": F(1, 2)}, {"a": 1}, F(2 ** 1398 + 1, 2 ** 1399))

    def test_operand_cap_is_exact_at_the_boundary_and_never_a_value_error(self):
        # right = (2^619)^21 = 2^12999 has exactly MAX_OPERAND_BITS bits; 2^13000 has one more.
        record = decide({"a": F(1, 2 ** 619)}, {"a": 21}, F(1))
        self.assertEqual(int(record["power_comparison"]["right"]).bit_length(), MAX_OPERAND_BITS)
        self.assertGreater(len(record["power_comparison"]["right"]), 3900)
        self.assertTrue(verify_decision(record))
        self.refused("EXACT_OPERAND_TOO_LARGE", {"a": F(1, 2 ** 325)}, {"a": 40}, F(1))
        previous = sys.get_int_max_str_digits()
        sys.set_int_max_str_digits(640)
        try:
            # A lowered digit limit refuses with the typed code instead of raising ValueError.
            self.refused("EXACT_OPERAND_TOO_LARGE", {"a": F(1, 2 ** 619)}, {"a": 21}, F(1))
        finally:
            sys.set_int_max_str_digits(previous)

    def test_early_bound_never_refuses_what_the_exact_check_accepts(self):
        rng = random.Random(20261119)
        refused = accepted = 0
        for _ in range(400):
            size = rng.randint(1, 6)
            axes = {}
            for index in range(size):
                den = rng.randrange(1, 1 << rng.randint(1, 700))
                axes[f"x{index}"] = F(rng.randint(1, den), den)
            weights = {name: rng.randint(1, 64) for name in axes}
            tau_den = rng.randrange(1, 1 << rng.randint(1, 60))
            tau = F(rng.randint(1, tau_den), tau_den)
            bits = operand_bits(axes, weights, tau)
            try:
                decide(axes, weights, tau)
                accepted += 1
                self.assertLessEqual(bits, MAX_OPERAND_BITS)
            except InputError as exc:
                if exc.code != "EXACT_OPERAND_TOO_LARGE":
                    raise
                refused += 1
                self.assertGreater(bits, MAX_OPERAND_BITS)
        self.assertGreater(refused, 20)
        self.assertGreater(accepted, 20)

    def test_the_largest_inputs_are_refused_before_any_product_is_formed(self):
        value = F(2 ** (MAX_AXIS_BITS - 1) - 1, 2 ** (MAX_AXIS_BITS - 1))
        axes = {f"n{i:02d}": value for i in range(64)}
        started = time.monotonic()
        self.refused("EXACT_OPERAND_TOO_LARGE", axes, {name: 64 for name in axes}, value)
        self.assertLess(time.monotonic() - started, 5)


class VerifyDecisionTypeTests(TestCase):
    def test_bool_and_int_aliases_are_refused(self):
        single = decide({"a": F(9, 10)}, {"a": 1}, F(4, 5))
        self.assertEqual((single["weight_sum"], single["geometric_mean_meets_tau"], single["dang"]),
                         (1, True, False))
        zero = decide({"a": F(0), "b": F(1)}, {"a": 1, "b": 1}, F(1, 2))
        self.assertEqual((zero["geometric_mean_ppm_floor"], zero["dang"]), (0, True))
        below = decide({"a": F(1, 10)}, {"a": 1}, F(4, 5))
        cases = ((single, "geometric_mean_meets_tau", 1), (single, "dang", 0),
                 (single, "weight_sum", True), (zero, "geometric_mean_ppm_floor", False),
                 (zero, "geometric_mean_meets_tau", 0), (zero, "dang", 1),
                 (below, "geometric_mean_meets_tau", 0), (below, "dang", 0))
        for base, field, alias in cases:
            with self.subTest(field=field, alias=alias):
                record = deepcopy(base)
                record[field] = alias
                # Python's == calls these equal; the verifier must not.
                self.assertEqual(record, base)
                with self.assertRaisesRegex(InputError, "EXACT_DECISION_DRIFT"):
                    verify_decision(record)
        record = deepcopy(single)
        record["weights"]["a"] = True
        with self.assertRaisesRegex(InputError, "EXACT_WEIGHTS_INVALID"):
            verify_decision(record)


if __name__ == "__main__":
    unittest_main()
