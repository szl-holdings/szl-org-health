# SPDX-License-Identifier: Apache-2.0
"""Synthetic, offline regression suite for the braid v2 three-tier khipu sum-tree: build, verify, knot,
cord_index, prove, verify_proof and diff, with a one-change-at-a-time tamper matrix, inclusion-with-sum
proofs, a fixed-seed conservation property and domain-separation checks. Every cord, digest and count is
made up here; nothing touches a network, git, a Lean toolchain or any file outside this checkout.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import random
import sys
from unittest import TestCase, main as unittest_main

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.database_catalog_admission import InputError  # noqa: E402
from tools.database_braid_common import canonical  # noqa: E402
from tools import database_braid_khipu_tree as khipu  # noqa: E402
from tools.database_braid_khipu_tree import (  # noqa: E402
    MAX_KNOTS, PROOF_SCHEMA, SCHEMA, TIERS, build, cord_hash, cord_index, diff, knot,
    pendant_hash, primary_hash, prove, verify, verify_proof,
)

NAMES = ["total", "red", "blue", "weight"]
PARTITIONS = [{"name": "colours", "whole": "total", "parts": ["red", "blue"]}]


def sha(char):
    return char * 64


def cords_fixture():
    return [
        {"key": "a/2", "pendant": "alpha", "digest": sha("2"), "knots": [4, 4, 0, 1]},
        {"key": "b/1", "pendant": "beta", "digest": sha("3"), "knots": [2, 0, 2, 7]},
        {"key": "a/1", "pendant": "alpha", "digest": sha("1"), "knots": [3, 1, 2, 5]},
        {"key": "c/1", "pendant": "gamma", "digest": sha("4"), "knots": [0, 0, 0, 0]},
    ]


def tree_fixture(**overrides):
    args = {"knot_names": list(NAMES), "partitions": deepcopy(PARTITIONS),
            "cords": cords_fixture(), "unavailable": ["z/9"]}
    args.update(overrides)
    unavailable = args.pop("unavailable")
    return build(args["knot_names"], args["partitions"], args["cords"], unavailable=unavailable)


def reseal(tree):
    """Recompute every hash, sum and count bottom-up so only structural checks can refuse."""
    width = len(tree["knots"])
    total = [0] * width
    for pendant in tree["pendants"]:
        subtotal = [0] * width
        for cord in pendant["cords"]:
            cord["hash"] = cord_hash(cord["key"], cord["digest"], cord["knots"])
            subtotal = [a + b for a, b in zip(subtotal, cord["knots"])]
        pendant["sum"] = subtotal
        pendant["hash"] = pendant_hash(pendant["label"],
                                       [[c["hash"], c["knots"]] for c in pendant["cords"]])
        total = [a + b for a, b in zip(total, subtotal)]
    tree["primary"]["sum"] = total
    tree["primary"]["pendant_count"] = len(tree["pendants"])
    tree["primary"]["cord_count"] = sum(len(p["cords"]) for p in tree["pendants"])
    tree["primary"]["hash"] = primary_hash(tree["knots"],
                                           [[p["hash"], p["sum"]] for p in tree["pendants"]])
    return tree


def all_keys(value):
    found = set()
    if isinstance(value, dict):
        for key, item in value.items():
            found.add(key)
            found |= all_keys(item)
    elif isinstance(value, list):
        for item in value:
            found |= all_keys(item)
    return found


def random_tree(rng, *, partitioned=False, unavailable=0):
    width = rng.randint(1, 5)
    names = [f"knot_{i}" for i in range(width)]
    partitions = []
    if partitioned:
        names = ["whole_n"] + names + ["extra_n"]
        partitions = [{"name": "split", "whole": "whole_n", "parts": names[1:-1]}]
        if width < 2:
            names.insert(2, "knot_pad")
            partitions[0]["parts"] = ["knot_0", "knot_pad"]
    labels = [f"p{i}" for i in range(rng.randint(1, 6))]
    cords = []
    for i in range(rng.randint(1, 30)):
        vector = [rng.randint(0, 1000) for _ in names]
        if partitioned:
            index = {n: j for j, n in enumerate(names)}
            vector[0] = sum(vector[index[p]] for p in partitions[0]["parts"])
        cords.append({"key": f"k{i:04d}", "pendant": rng.choice(labels),
                      "digest": "%064x" % rng.getrandbits(256), "knots": vector})
    missing = [f"m{i:04d}" for i in range(unavailable)]
    return build(names, partitions, cords, unavailable=missing), cords, names, partitions


class KhipuTreeCase(TestCase):
    def refused(self, code, fn, *args, **kwargs):
        with self.assertRaises(InputError) as caught:
            fn(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def tampered(self, code, mutate, tree=None):
        tree = deepcopy(tree if tree is not None else self.tree)
        mutate(tree)
        self.refused(code, verify, tree)


class BuildTests(KhipuTreeCase):
    def setUp(self):
        self.tree = tree_fixture()

    def test_valid_tree_shape_sums_and_honest_flags(self):
        tree = self.tree
        self.assertTrue(verify(tree))
        self.assertEqual(tree["schema"], SCHEMA)
        self.assertEqual(tree["tiers"], TIERS)
        self.assertIs(tree["missing_is_zero"], False)
        self.assertEqual(tree["unavailable_cords"], ["z/9"])
        self.assertEqual([p["label"] for p in tree["pendants"]], ["alpha", "beta", "gamma"])
        self.assertEqual([c["key"] for c in tree["pendants"][0]["cords"]], ["a/1", "a/2"])
        self.assertEqual(tree["pendants"][0]["sum"], [7, 5, 2, 6])
        self.assertEqual(tree["primary"]["sum"], [9, 5, 4, 13])
        self.assertEqual(tree["primary"]["pendant_count"], 3)
        self.assertEqual(tree["primary"]["cord_count"], 4)
        for pendant in tree["pendants"]:
            self.assertEqual(pendant["sum"][0], pendant["sum"][1] + pendant["sum"][2])

    def test_tree_reports_nothing_signed_or_authorized(self):
        keys = {k.lower() for k in all_keys(self.tree)}
        for word in ("signed", "signature", "signer", "authorized", "authority", "allow"):
            self.assertFalse(any(word in k for k in keys), word)

    def test_input_order_does_not_change_tree_and_inputs_are_not_mutated(self):
        cords = cords_fixture()
        snapshot = deepcopy(cords)
        forward = build(list(NAMES), deepcopy(PARTITIONS), cords, unavailable=["z/9"])
        self.assertEqual(cords, snapshot)
        backward = build(list(NAMES), deepcopy(PARTITIONS), list(reversed(cords)),
                         unavailable=["z/9", "z/9"])
        self.assertEqual(forward, backward)
        self.assertEqual(forward, self.tree)

    def test_knot_and_cord_index(self):
        self.assertEqual(knot(self.tree, "total"), 9)
        self.assertEqual(knot(self.tree, "weight"), 13)
        self.refused("KHIPU_KNOT_UNKNOWN", knot, self.tree, "green")
        self.refused("KHIPU_KNOT_UNKNOWN", knot, self.tree, "z/9")
        self.assertEqual(cord_index(self.tree),
                         {"a/1": (0, 0), "a/2": (0, 1), "b/1": (1, 0), "c/1": (2, 0)})

    def test_missing_cords_listed_never_zero(self):
        without = tree_fixture(unavailable=[])
        self.assertEqual(without["unavailable_cords"], [])
        self.assertEqual(self.tree["primary"]["sum"], without["primary"]["sum"])
        self.assertEqual(self.tree["primary"]["cord_count"], 4)
        self.assertNotIn("z/9", cord_index(self.tree))
        self.assertEqual(self.tree["pendants"], without["pendants"])
        self.refused("KHIPU_CORD_NOT_FOUND", prove, self.tree, "z/9")
        zero_cord = cords_fixture() + [{"key": "z/9", "pendant": "zeta", "digest": sha("9"),
                                        "knots": [0, 0, 0, 0]}]
        as_zero = tree_fixture(cords=zero_cord, unavailable=[])
        self.assertNotEqual(as_zero["primary"]["hash"], self.tree["primary"]["hash"])
        self.assertEqual(as_zero["primary"]["cord_count"], 5)

    def test_refuses_bad_knot_names(self):
        for names in ([], ["total", "total"], ["Total"], ["a"], ["9lives"], "total", [1],
                      [f"knot_{i}" for i in range(MAX_KNOTS + 1)], ("total",)):
            with self.subTest(names=names):
                self.refused("KHIPU_KNOT_NAMES_INVALID", build, names, [], cords_fixture())

    def test_refuses_bad_partitions(self):
        good = PARTITIONS[0]
        bad = [
            "colours",
            [dict(good, extra=1)],
            [{k: v for k, v in good.items() if k != "parts"}],
            [dict(good, parts=["red"])],
            [dict(good, parts=["red", "red"])],
            [dict(good, parts=["red", "green"])],
            [dict(good, whole="green")],
            [dict(good, parts=["total", "red"])],
            [dict(good, name="Colours")],
            [good, dict(good)],
            [dict(good, parts=("red", "blue"))],
            [dict(good, name=f"part_{i}") for i in range(17)],
        ]
        for partitions in bad:
            with self.subTest(partitions=partitions):
                self.refused("KHIPU_PARTITIONS_INVALID", build, list(NAMES), partitions,
                             cords_fixture())

    def test_refuses_bad_cord_list_and_fields(self):
        self.refused("KHIPU_CORDS_INVALID", build, list(NAMES), [], [])
        self.refused("KHIPU_CORDS_INVALID", build, list(NAMES), [], tuple(cords_fixture()))
        mutations = [
            lambda c: c.update(extra=1),
            lambda c: c.pop("digest"),
            lambda c: c.update(digest="A" * 64),
            lambda c: c.update(digest="a" * 63),
            lambda c: c.update(key="bad key"),
            lambda c: c.update(key=7),
            lambda c: c.update(pendant=""),
            lambda c: c.update(pendant="x" * 201),
        ]
        for mutate in mutations:
            cords = cords_fixture()
            mutate(cords[0])
            with self.subTest(cord=cords[0]):
                self.refused("KHIPU_CORD_FIELDS_INVALID", build, list(NAMES), PARTITIONS, cords)

    def test_refuses_bad_knot_vectors(self):
        for vector in ([4, 4, 0], [4, 4, 0, 1, 0], [4, 4, 0, -1], [4, 4, 0, 1.0], [4, 4, 0, True],
                       [4, 4, 0, "1"], [4, 4, 0, None], [4, 4, 0, 10 ** 15 + 1], (4, 4, 0, 1)):
            cords = cords_fixture()
            cords[0]["knots"] = vector
            with self.subTest(vector=vector):
                self.refused("KHIPU_KNOT_VECTOR_INVALID", build, list(NAMES), PARTITIONS, cords)

    def test_refuses_duplicate_key_even_across_pendants(self):
        cords = cords_fixture()
        cords[1]["key"] = "a/2"
        self.refused("KHIPU_CORD_DUPLICATE", build, list(NAMES), PARTITIONS, cords)

    def test_refuses_partition_broken_at_cord(self):
        cords = cords_fixture()
        cords[1]["knots"] = [3, 0, 2, 7]
        self.refused("KHIPU_PARTITION_BROKEN_AT_CORD", build, list(NAMES), PARTITIONS, cords)

    def test_refuses_unavailable_that_is_present_or_malformed(self):
        for missing in (["a/1"], ["z/9", "b/1"], ["bad key"], [""], [5]):
            with self.subTest(missing=missing):
                self.refused("KHIPU_UNAVAILABLE_INVALID", build, list(NAMES), PARTITIONS,
                             cords_fixture(), unavailable=missing)


class VerifyTamperTests(KhipuTreeCase):
    def setUp(self):
        self.tree = tree_fixture()

    def test_reseal_helper_is_faithful(self):
        self.assertEqual(reseal(deepcopy(self.tree)), self.tree)

    def test_top_level_fields_and_schema(self):
        self.tampered("KHIPU_TREE_FIELDS_INVALID", lambda t: t.update(signed=False))
        self.tampered("KHIPU_TREE_FIELDS_INVALID", lambda t: t.pop("unavailable_cords"))
        self.tampered("KHIPU_TREE_FIELDS_INVALID", lambda t: t.pop("missing_is_zero"))
        self.refused("KHIPU_TREE_FIELDS_INVALID", verify, [self.tree])
        self.tampered("KHIPU_TREE_SCHEMA_INVALID", lambda t: t.update(schema=PROOF_SCHEMA))
        self.tampered("KHIPU_TREE_SCHEMA_INVALID", lambda t: t.update(tiers=TIERS[::-1]))
        self.tampered("KHIPU_TREE_SCHEMA_INVALID", lambda t: t.update(tiers=tuple(TIERS)))
        for flag in (True, 0, None, "false"):
            with self.subTest(missing_is_zero=flag):
                self.tampered("KHIPU_TREE_SCHEMA_INVALID", lambda t: t.update(missing_is_zero=flag))

    def test_knot_names_and_partitions(self):
        self.tampered("KHIPU_KNOT_NAMES_INVALID", lambda t: t["knots"].append("total"))
        self.tampered("KHIPU_KNOT_NAMES_INVALID", lambda t: t.update(knots=[]))
        self.tampered("KHIPU_PARTITIONS_INVALID", lambda t: t["partitions"][0].update(extra=1))
        self.tampered("KHIPU_PARTITIONS_INVALID", lambda t: t["partitions"][0].update(whole="pink"))
        self.tampered("KHIPU_PARTITIONS_INVALID", lambda t: t.update(partitions={}))

    def test_primary_and_pendant_container_fields(self):
        self.tampered("KHIPU_TREE_FIELDS_INVALID", lambda t: t["primary"].update(extra=1))
        self.tampered("KHIPU_TREE_FIELDS_INVALID", lambda t: t["primary"].pop("cord_count"))
        self.tampered("KHIPU_TREE_FIELDS_INVALID", lambda t: t.update(pendants=[]))
        self.tampered("KHIPU_TREE_FIELDS_INVALID", lambda t: t.update(pendants={}))
        self.tampered("KHIPU_PENDANT_FIELDS_INVALID", lambda t: t["pendants"][0].update(extra=1))
        self.tampered("KHIPU_PENDANT_FIELDS_INVALID", lambda t: t["pendants"][0].pop("sum"))
        self.tampered("KHIPU_PENDANT_FIELDS_INVALID", lambda t: t["pendants"][2].update(cords=[]))
        self.tampered("KHIPU_PENDANT_FIELDS_INVALID", lambda t: t["pendants"][0].update(label="a b"))

    def test_cord_fields(self):
        self.tampered("KHIPU_CORD_FIELDS_INVALID", lambda t: t["pendants"][0]["cords"][0].update(x=1))
        self.tampered("KHIPU_CORD_FIELDS_INVALID", lambda t: t["pendants"][0]["cords"][0].pop("hash"))
        self.tampered("KHIPU_CORD_FIELDS_INVALID",
                      lambda t: t["pendants"][0]["cords"][0].update(pendant="alpha"))
        self.tampered("KHIPU_CORD_FIELDS_INVALID",
                      lambda t: t["pendants"][0]["cords"][0].update(digest="F" * 64))

    def test_one_knot_changed(self):
        self.tampered("KHIPU_CORD_HASH_MISMATCH",
                      lambda t: t["pendants"][1]["cords"][0]["knots"].__setitem__(3, 8))

    def test_knot_vector_types_in_tree(self):
        for value in (True, 1.0, -1, "1"):
            with self.subTest(value=value):
                self.tampered("KHIPU_KNOT_VECTOR_INVALID",
                              lambda t: t["pendants"][0]["cords"][0]["knots"].__setitem__(3, value))
                self.tampered("KHIPU_KNOT_VECTOR_INVALID",
                              lambda t: t["pendants"][0]["sum"].__setitem__(3, value))
                self.tampered("KHIPU_KNOT_VECTOR_INVALID",
                              lambda t: t["primary"]["sum"].__setitem__(3, value))
        self.tampered("KHIPU_KNOT_VECTOR_INVALID", lambda t: t["pendants"][0]["sum"].pop())

    def test_one_digest_or_hash_changed(self):
        self.tampered("KHIPU_CORD_HASH_MISMATCH",
                      lambda t: t["pendants"][0]["cords"][1].update(digest=sha("e")))
        self.tampered("KHIPU_CORD_HASH_MISMATCH",
                      lambda t: t["pendants"][0]["cords"][1].update(hash=sha("e")))
        self.tampered("KHIPU_PENDANT_HASH_MISMATCH", lambda t: t["pendants"][1].update(hash=sha("e")))
        self.tampered("KHIPU_PRIMARY_HASH_MISMATCH", lambda t: t["primary"].update(hash=sha("e")))
        self.tampered("KHIPU_PRIMARY_HASH_MISMATCH", lambda t: t["primary"].update(hash=None))

    def test_pendant_label_renamed_breaks_pendant_hash(self):
        self.tampered("KHIPU_PENDANT_HASH_MISMATCH", lambda t: t["pendants"][1].update(label="betb"))

    def test_one_pendant_sum_changed(self):
        self.tampered("KHIPU_PENDANT_SUM_NOT_CONSERVED",
                      lambda t: t["pendants"][1]["sum"].__setitem__(3, 8))

    def test_primary_sum_changed(self):
        self.tampered("KHIPU_PRIMARY_SUM_NOT_CONSERVED",
                      lambda t: t["primary"]["sum"].__setitem__(3, 14))

    def test_counts(self):
        self.tampered("KHIPU_COUNT_MISMATCH", lambda t: t["primary"].update(pendant_count=4))
        self.tampered("KHIPU_COUNT_MISMATCH", lambda t: t["primary"].update(cord_count=5))
        self.tampered("KHIPU_COUNT_MISMATCH", lambda t: t["primary"].update(cord_count=3.0 + 1))
        one = build(["count_n"], [], [{"key": "k", "pendant": "p", "digest": sha("a"), "knots": [1]}])
        self.assertTrue(verify(one))
        self.tampered("KHIPU_COUNT_MISMATCH", lambda t: t["primary"].update(pendant_count=True), one)
        self.tampered("KHIPU_COUNT_MISMATCH", lambda t: t["primary"].update(cord_count=True), one)

    def test_tamper_by_addition_is_caught_at_every_tier(self):
        def bump(t):
            t["pendants"][1]["cords"][0]["knots"][3] += 1

        def with_cord_hash(t):
            bump(t)
            c = t["pendants"][1]["cords"][0]
            c["hash"] = cord_hash(c["key"], c["digest"], c["knots"])

        def with_pendant_sum(t):
            with_cord_hash(t)
            t["pendants"][1]["sum"][3] += 1

        def with_pendant_hash(t):
            with_pendant_sum(t)
            p = t["pendants"][1]
            p["hash"] = pendant_hash(p["label"], [[c["hash"], c["knots"]] for c in p["cords"]])

        def with_primary_sum(t):
            with_pendant_hash(t)
            t["primary"]["sum"][3] += 1

        self.tampered("KHIPU_CORD_HASH_MISMATCH", bump)
        self.tampered("KHIPU_PENDANT_SUM_NOT_CONSERVED", with_cord_hash)
        self.tampered("KHIPU_PENDANT_HASH_MISMATCH", with_pendant_sum)
        self.tampered("KHIPU_PRIMARY_SUM_NOT_CONSERVED", with_pendant_hash)
        self.tampered("KHIPU_PRIMARY_HASH_MISMATCH", with_primary_sum)
        forged = deepcopy(self.tree)
        with_primary_sum(forged)
        forged["primary"]["hash"] = primary_hash(forged["knots"],
                                                 [[p["hash"], p["sum"]] for p in forged["pendants"]])
        self.assertTrue(verify(forged))
        self.assertNotEqual(forged["primary"]["hash"], self.tree["primary"]["hash"])
        self.assertNotEqual(forged["primary"]["sum"], self.tree["primary"]["sum"])

    def test_cord_order_swapped(self):
        def swap(t):
            t["pendants"][0]["cords"].reverse()
        self.tampered("KHIPU_CORD_ORDER_INVALID", swap)
        self.tampered("KHIPU_CORD_ORDER_INVALID", lambda t: reseal(swap(t) or t))

    def test_pendant_order_swapped(self):
        def swap(t):
            t["pendants"].reverse()
        self.tampered("KHIPU_PENDANT_ORDER_INVALID", swap)
        self.tampered("KHIPU_PENDANT_ORDER_INVALID", lambda t: reseal(swap(t) or t))

    def test_duplicate_pendant_label(self):
        def duplicate(t):
            t["pendants"][1]["label"] = "alpha"
            reseal(t)
        self.tampered("KHIPU_PENDANT_ORDER_INVALID", duplicate)

    def test_duplicate_key(self):
        def within(t):
            t["pendants"][0]["cords"][1]["key"] = "a/1"
            reseal(t)

        def across(t):
            t["pendants"][1]["cords"][0]["key"] = "a/1"
            reseal(t)
        self.tampered("KHIPU_CORD_DUPLICATE", within)
        self.tampered("KHIPU_CORD_DUPLICATE", across)

    def test_partition_that_no_longer_adds_up(self):
        def at_cord(t):
            t["pendants"][1]["cords"][0]["knots"][0] = 3
            reseal(t)

        def at_every_cord(t):
            for p in t["pendants"]:
                for c in p["cords"]:
                    c["knots"][0] += 1
            reseal(t)

        def redeclared(t):
            t["partitions"] = [{"name": "colours", "whole": "weight", "parts": ["red", "blue"]}]
        self.tampered("KHIPU_PARTITION_BROKEN_AT_CORD", at_cord)
        self.tampered("KHIPU_PARTITION_BROKEN_AT_CORD", at_every_cord)
        self.tampered("KHIPU_PARTITION_BROKEN_AT_CORD", redeclared)

    def test_unavailable_cord_also_present_or_malformed(self):
        self.tampered("KHIPU_UNAVAILABLE_INVALID", lambda t: t.update(unavailable_cords=["b/1"]))
        self.tampered("KHIPU_UNAVAILABLE_INVALID", lambda t: t.update(unavailable_cords=["z/9", "z/9"]))
        self.tampered("KHIPU_UNAVAILABLE_INVALID", lambda t: t.update(unavailable_cords=["z/9", "y/1"]))
        self.tampered("KHIPU_UNAVAILABLE_INVALID", lambda t: t.update(unavailable_cords=["bad key"]))
        self.tampered("KHIPU_UNAVAILABLE_INVALID", lambda t: t.update(unavailable_cords="z/9"))
        self.tampered("KHIPU_UNAVAILABLE_INVALID", lambda t: t.update(unavailable_cords=("z/9",)))

    def test_json_round_trip_still_verifies(self):
        self.assertTrue(verify(json.loads(canonical(self.tree))))


class ProofTests(KhipuTreeCase):
    def setUp(self):
        self.tree = tree_fixture()
        self.hash = self.tree["primary"]["hash"]
        self.sum = self.tree["primary"]["sum"]

    def check(self, proof, **kwargs):
        expected = {"primary_hash_expected": self.hash, "primary_sum_expected": self.sum}
        expected.update(kwargs)
        return verify_proof(proof, **expected)

    def proof_refused(self, code, mutate, key="a/2", **kwargs):
        proof = prove(self.tree, key)
        mutate(proof)
        with self.assertRaises(InputError) as caught:
            self.check(proof, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_every_cord_proof_verifies(self):
        for key in cord_index(self.tree):
            with self.subTest(key=key):
                proof = prove(self.tree, key)
                self.assertEqual(proof["schema"], PROOF_SCHEMA)
                self.assertEqual(proof["cord"]["key"], key)
                self.assertTrue(self.check(proof))
                self.assertTrue(self.check(json.loads(canonical(proof))))

    def test_proof_reveals_no_other_cord_and_claims_nothing(self):
        proof = prove(self.tree, "a/2")
        text = canonical(proof).decode("ascii")
        for cord in cords_fixture():
            if cord["key"] != "a/2":
                self.assertNotIn(cord["key"], text)
                self.assertNotIn(cord["digest"], text)
        keys = {k.lower() for k in all_keys(proof)}
        for word in ("signed", "signature", "authorized", "authority"):
            self.assertFalse(any(word in k for k in keys), word)

    def test_prove_refusals(self):
        self.refused("KHIPU_CORD_NOT_FOUND", prove, self.tree, "nope")
        broken = deepcopy(self.tree)
        broken["primary"]["sum"][0] += 1
        self.refused("KHIPU_PRIMARY_SUM_NOT_CONSERVED", prove, broken, "a/1")

    def test_altered_cord(self):
        self.proof_refused("KHIPU_PROOF_CORD_MISMATCH", lambda p: p["cord"]["knots"].__setitem__(3, 2))
        self.proof_refused("KHIPU_PROOF_CORD_MISMATCH", lambda p: p["cord"].update(digest=sha("e")))
        self.proof_refused("KHIPU_PROOF_CORD_MISMATCH", lambda p: p["cord"].update(key="a/3"))

    def test_altered_sibling_knots_or_hash(self):
        self.proof_refused("KHIPU_PROOF_PENDANT_MISMATCH",
                           lambda p: p["pendant"]["cords"][0][1].__setitem__(3, 6))
        self.proof_refused("KHIPU_PROOF_PENDANT_MISMATCH",
                           lambda p: p["pendant"]["cords"][0].__setitem__(0, sha("e")))
        self.proof_refused("KHIPU_PROOF_PRIMARY_MISMATCH",
                           lambda p: p["primary"]["pendants"][1][1].__setitem__(3, 6))
        self.proof_refused("KHIPU_PROOF_PRIMARY_MISMATCH",
                           lambda p: p["primary"]["pendants"][2].__setitem__(0, sha("e")))
        self.proof_refused("KHIPU_PROOF_PENDANT_MISMATCH",
                           lambda p: p["primary"]["pendants"][0][1].__setitem__(3, 7))

    def test_altered_label_or_position(self):
        self.proof_refused("KHIPU_PROOF_PENDANT_MISMATCH", lambda p: p["pendant"].update(label="beta"))
        self.proof_refused("KHIPU_PROOF_CORD_MISMATCH", lambda p: p["pendant"].update(position=0))
        self.proof_refused("KHIPU_PROOF_PENDANT_MISMATCH", lambda p: p["primary"].update(position=1))

    def test_reordered_rows(self):
        self.proof_refused("KHIPU_PROOF_CORD_MISMATCH", lambda p: p["pendant"]["cords"].reverse())

        def both(p):
            p["pendant"]["cords"].reverse()
            p["pendant"]["position"] = 0
        self.proof_refused("KHIPU_PROOF_PENDANT_MISMATCH", both)

        def pendants(p):
            p["primary"]["pendants"].reverse()
            p["primary"]["position"] = 2
        self.proof_refused("KHIPU_PROOF_PRIMARY_MISMATCH", pendants)

    def test_against_another_tree_or_total(self):
        other = tree_fixture(unavailable=[], cords=cords_fixture()[:3])
        self.proof_refused("KHIPU_PROOF_PRIMARY_MISMATCH", lambda p: None,
                           primary_hash_expected=other["primary"]["hash"])
        self.proof_refused("KHIPU_PROOF_PRIMARY_MISMATCH", lambda p: None,
                           primary_sum_expected=[9, 5, 4, 14])
        self.proof_refused("KHIPU_PROOF_PRIMARY_MISMATCH", lambda p: None,
                           primary_sum_expected=tuple(self.sum))
        self.proof_refused("KHIPU_PROOF_PRIMARY_MISMATCH", lambda p: p["knots"].__setitem__(3, "mass"))
        proof = prove(other, "a/1")
        self.assertTrue(verify_proof(proof, primary_hash_expected=other["primary"]["hash"],
                                     primary_sum_expected=other["primary"]["sum"]))
        with self.assertRaises(InputError) as caught:
            self.check(proof)
        self.assertEqual(caught.exception.code, "KHIPU_PROOF_PRIMARY_MISMATCH")

    def test_malformed_proof_fields(self):
        code = "KHIPU_PROOF_FIELDS_INVALID"
        mutations = [
            lambda p: p.update(extra=1),
            lambda p: p.pop("knots"),
            lambda p: p.update(schema=SCHEMA),
            lambda p: p["cord"].update(extra=1),
            lambda p: p["cord"].update(digest="A" * 64),
            lambda p: p["cord"].update(key="bad key"),
            lambda p: p["cord"]["knots"].__setitem__(0, True),
            lambda p: p["cord"]["knots"].__setitem__(0, 4.0),
            lambda p: p["cord"]["knots"].pop(),
            lambda p: p["pendant"].update(extra=1),
            lambda p: p["pendant"].update(position=True),
            lambda p: p["pendant"].update(position=1.0),
            lambda p: p["pendant"].update(position=2),
            lambda p: p["pendant"].update(position=-1),
            lambda p: p["pendant"].update(label=""),
            lambda p: p["pendant"].update(cords=[]),
            lambda p: p["pendant"]["cords"][0].append(1),
            lambda p: p["pendant"]["cords"].__setitem__(0, tuple(p["pendant"]["cords"][0])),
            lambda p: p["pendant"]["cords"][0].__setitem__(0, "E" * 64),
            lambda p: p["pendant"]["cords"][0][1].__setitem__(0, -1),
            lambda p: p["primary"].update(extra=1),
            lambda p: p["primary"].update(position=False),
            lambda p: p["primary"].update(position=3),
            lambda p: p["primary"].update(pendants=[]),
            lambda p: p["primary"]["pendants"][1][1].pop(),
        ]
        for i, mutate in enumerate(mutations):
            with self.subTest(mutation=i):
                self.proof_refused(code, mutate)
        self.proof_refused("KHIPU_KNOT_NAMES_INVALID", lambda p: p["knots"].append("total"))


class ConservationPropertyTests(KhipuTreeCase):
    SEED = 20261119

    def test_primary_sum_equals_column_sums_and_proofs_verify(self):
        rng = random.Random(self.SEED)
        for trial in range(25):
            tree, cords, names, _ = random_tree(rng, partitioned=trial % 2 == 1,
                                                unavailable=trial % 3)
            with self.subTest(trial=trial):
                self.assertTrue(verify(tree))
                columns = [sum(c["knots"][i] for c in cords) for i in range(len(names))]
                self.assertEqual(tree["primary"]["sum"], columns)
                for i, name in enumerate(names):
                    self.assertEqual(knot(tree, name), columns[i])
                self.assertEqual(tree["primary"]["cord_count"], len(cords))
                self.assertEqual(len(tree["unavailable_cords"]), trial % 3)
                for pendant in tree["pendants"]:
                    expected = [sum(c["knots"][i] for c in cords if c["pendant"] == pendant["label"])
                                for i in range(len(names))]
                    self.assertEqual(pendant["sum"], expected)
                for key in cord_index(tree):
                    self.assertTrue(verify_proof(prove(tree, key),
                                                 primary_hash_expected=tree["primary"]["hash"],
                                                 primary_sum_expected=tree["primary"]["sum"]))

    def test_bumping_any_single_knot_changes_sum_and_hash(self):
        rng = random.Random(self.SEED + 1)
        for trial in range(15):
            tree, cords, names, partitions = random_tree(rng)
            for _ in range(4):
                target = rng.randrange(len(cords))
                column = rng.randrange(len(names))
                delta = rng.randint(1, 50)
                bumped = deepcopy(cords)
                bumped[target]["knots"][column] += delta
                after = build(names, partitions, bumped)
                with self.subTest(trial=trial, target=target, column=column):
                    self.assertNotEqual(after["primary"]["hash"], tree["primary"]["hash"])
                    self.assertNotEqual(after["primary"]["sum"], tree["primary"]["sum"])
                    expected = list(tree["primary"]["sum"])
                    expected[column] += delta
                    self.assertEqual(after["primary"]["sum"], expected)
                    label = bumped[target]["pendant"]
                    for old, new in zip(tree["pendants"], after["pendants"]):
                        self.assertEqual(old["hash"] != new["hash"], old["label"] == label)
                    change = diff(tree, after)
                    self.assertEqual(change["knots_changed"], [bumped[target]["key"]])
                    self.assertEqual(change["sum_delta"][names[column]], delta)
                    self.assertTrue(change["primary_hash_changed"])

    def test_bumping_a_part_without_its_whole_is_refused(self):
        rng = random.Random(self.SEED + 2)
        for trial in range(10):
            tree, cords, names, partitions = random_tree(rng, partitioned=True)
            bumped = deepcopy(cords)
            target = rng.randrange(len(cords))
            bumped[target]["knots"][names.index(partitions[0]["parts"][0])] += 1
            with self.subTest(trial=trial):
                self.refused("KHIPU_PARTITION_BROKEN_AT_CORD", build, names, partitions, bumped)
                bumped[target]["knots"][0] += 1
                after = build(names, partitions, bumped)
                self.assertNotEqual(after["primary"]["hash"], tree["primary"]["hash"])
                self.assertEqual(after["primary"]["sum"][0], tree["primary"]["sum"][0] + 1)


class DiffTests(KhipuTreeCase):
    def setUp(self):
        self.tree = tree_fixture()

    def test_identical_trees(self):
        change = diff(self.tree, deepcopy(self.tree))
        self.assertEqual(change["added"], [])
        self.assertEqual(change["removed"], [])
        self.assertEqual(change["content_changed"], [])
        self.assertEqual(change["knots_changed"], [])
        self.assertEqual(change["sum_delta"], {name: 0 for name in NAMES})
        self.assertIs(change["primary_hash_changed"], False)

    def test_added_removed_changed_and_signed_delta(self):
        cords = cords_fixture()
        cords = [c for c in cords if c["key"] != "b/1"]
        cords.append({"key": "d/1", "pendant": "delta", "digest": sha("5"), "knots": [1, 1, 0, 0]})
        by_key = {c["key"]: c for c in cords}
        by_key["a/1"]["digest"] = sha("6")
        by_key["a/2"]["knots"] = [1, 0, 1, 1]
        new = tree_fixture(cords=cords, unavailable=["b/1"])
        change = diff(self.tree, new)
        self.assertEqual(change["added"], ["d/1"])
        self.assertEqual(change["removed"], ["b/1"])
        self.assertEqual(change["content_changed"], ["a/1"])
        self.assertEqual(change["knots_changed"], ["a/2"])
        self.assertEqual(change["sum_delta"], {"total": -4, "red": -3, "blue": -1, "weight": -7})
        self.assertIs(change["primary_hash_changed"], True)
        self.assertEqual(diff(new, self.tree)["sum_delta"],
                         {"total": 4, "red": 3, "blue": 1, "weight": 7})

    def test_refusals(self):
        other = build(["count_n"], [], [{"key": "k", "pendant": "p", "digest": sha("a"), "knots": [1]}])
        self.refused("KHIPU_DIFF_KNOTS_DIFFER", diff, self.tree, other)
        reordered = tree_fixture(knot_names=["total", "blue", "red", "weight"])
        self.refused("KHIPU_DIFF_KNOTS_DIFFER", diff, self.tree, reordered)
        broken = deepcopy(self.tree)
        broken["pendants"][0]["sum"][0] += 1
        self.refused("KHIPU_PENDANT_SUM_NOT_CONSERVED", diff, self.tree, broken)
        self.refused("KHIPU_PENDANT_SUM_NOT_CONSERVED", diff, broken, self.tree)


class DomainSeparationTests(TestCase):
    def test_tags_distinct_and_prefix_free(self):
        tags = [khipu._CORD, khipu._PENDANT, khipu._PRIMARY]
        self.assertEqual(len(set(tags)), 3)
        for a in tags:
            self.assertTrue(a.endswith(b"\x00"))
            for b in tags:
                if a != b:
                    self.assertFalse(b.startswith(a))

    def test_same_payload_never_collides_across_tiers(self):
        payloads = [
            {"key": "a/1", "digest": sha("1"), "knots": [3, 1, 2, 5]},
            {"label": "alpha", "cords": [[sha("1"), [1]]]},
            {"knots": ["total"], "pendants": [[sha("1"), [1]]]},
            [], {}, "x", 0,
        ]
        for payload in payloads:
            with self.subTest(payload=payload):
                hashes = {khipu._h(tag, payload)
                          for tag in (khipu._CORD, khipu._PENDANT, khipu._PRIMARY)}
                hashes.add(hashlib.sha256(canonical(payload)).hexdigest())
                self.assertEqual(len(hashes), 4)

    def test_public_hashes_are_tagged(self):
        key, dig, vector = "a/1", sha("1"), [3, 1, 2, 5]
        plain = hashlib.sha256(canonical({"key": key, "digest": dig, "knots": vector})).hexdigest()
        self.assertNotEqual(cord_hash(key, dig, vector), plain)
        self.assertEqual(cord_hash(key, dig, vector), khipu._h(khipu._CORD,
                                                               {"key": key, "digest": dig, "knots": vector}))
        children = [[cord_hash(key, dig, vector), vector]]
        self.assertEqual(pendant_hash("alpha", children),
                         khipu._h(khipu._PENDANT, {"label": "alpha", "cords": children}))
        self.assertNotEqual(pendant_hash("alpha", children),
                            khipu._h(khipu._PRIMARY, {"label": "alpha", "cords": children}))
        self.assertEqual(primary_hash(["total"], children),
                         khipu._h(khipu._PRIMARY, {"knots": ["total"], "pendants": children}))
        self.assertNotEqual(primary_hash(["total"], children),
                            khipu._h(khipu._CORD, {"knots": ["total"], "pendants": children}))

    def test_float_payload_refused(self):
        with self.assertRaises(InputError) as caught:
            cord_hash("a/1", sha("1"), [1.5])
        self.assertEqual(caught.exception.code, "FLOAT_VALUE_REFUSED")


if __name__ == "__main__":
    unittest_main()
