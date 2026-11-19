#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Three-tier khipu sum-tree for the SZL Ouroboros braid v2.

A primary cord carries pendant cords, each pendant carries leaf cords, and
every cord carries a vector of non-negative integer knots. The value on a
pendant is the sum of its cords and the value on the primary cord is the sum
of its pendants (sum-of-sums), checked at every node together with declared
partition identities ("the coloured parts add up to the whole"). Each node
hash binds its children's hashes AND their sums, so one leaf can be shown to
be included in a stated total without revealing the other leaves' contents.

Prior art, not ours: hash trees (Merkle 1987) and hash trees that carry sums
(the Merkle-sum tree used for proof of liabilities, Maxwell 2013; Dagher et
al. 2015) are standard. The three-tier summation structure follows published
descriptions of Inka khipu accounting (Locke 1923; Ascher and Ascher 1981;
Urton 2003). The estate's own Lean carrier for the summation law is
``Lutar/Khipu/SummationInvariant.lean``. This is a modern accounting check
inspired by that record, NOT a decipherment and NOT an ancient cipher.

A missing cord is listed as unavailable and is never counted as zero. The
tree is unsigned: it identifies bytes and totals, it does not say who made
them, and it grants no authority.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sys

try:
    from tools.database_braid_common import SHA64, canonical, closed, natural, require
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools.database_braid_common import SHA64, canonical, closed, natural, require

SCHEMA = "szl.database-braid-khipu-tree/v1"
PROOF_SCHEMA = "szl.database-braid-khipu-proof/v1"
TIERS = ["PRIMARY", "PENDANT", "CORD"]
KNOT = re.compile(r"[a-z][a-z0-9_]{1,47}\Z")
LABEL = re.compile(r"[A-Za-z0-9_.:|/+@%-]{1,200}\Z")
KEY = re.compile(r"[A-Za-z0-9_.:|/+@%-]{1,400}\Z")
MAX_KNOTS = 32
MAX_CORDS = 50000
MAX_TREE_BYTES = 33554432
_CORD = b"szl.khipu.cord.v1\x00"
_PENDANT = b"szl.khipu.pendant.v1\x00"
_PRIMARY = b"szl.khipu.primary.v1\x00"


def _h(tag: bytes, value) -> str:
    return hashlib.sha256(tag + canonical(value)).hexdigest()


def cord_hash(key, content_digest, knots) -> str:
    return _h(_CORD, {"key": key, "digest": content_digest, "knots": knots})


def pendant_hash(label, children) -> str:
    """``children`` is the ordered list of ``[cord_hash, knots]`` pairs."""
    return _h(_PENDANT, {"label": label, "cords": children})


def primary_hash(knot_names, children) -> str:
    """``children`` is the ordered list of ``[pendant_hash, sum]`` pairs."""
    return _h(_PRIMARY, {"knots": knot_names, "pendants": children})


def _knot_names(names):
    require(type(names) is list and 0 < len(names) <= MAX_KNOTS and
            all(type(n) is str and KNOT.fullmatch(n) for n in names) and
            len(set(names)) == len(names), "KHIPU_KNOT_NAMES_INVALID")
    return names


def _partitions(partitions, names):
    require(type(partitions) is list and len(partitions) <= 16, "KHIPU_PARTITIONS_INVALID")
    seen = set()
    for item in partitions:
        closed(item, ("name", "whole", "parts"), "KHIPU_PARTITIONS_INVALID")
        require(type(item["name"]) is str and KNOT.fullmatch(item["name"]) and
                item["name"] not in seen and item["whole"] in names and
                type(item["parts"]) is list and len(item["parts"]) >= 2 and
                all(p in names for p in item["parts"]) and
                len(set(item["parts"])) == len(item["parts"]) and
                item["whole"] not in item["parts"], "KHIPU_PARTITIONS_INVALID")
        seen.add(item["name"])
    return partitions


def _vector(knots, width, code):
    require(type(knots) is list and len(knots) == width, code)
    for value in knots:
        natural(value, code)
    return knots


def _add(left, right):
    return [a + b for a, b in zip(left, right)]


def _partition_holds(vector, names, partitions):
    index = {name: i for i, name in enumerate(names)}
    return all(vector[index[p["whole"]]] == sum(vector[index[x]] for x in p["parts"])
               for p in partitions)


def build(knot_names, partitions, cords, *, unavailable=()) -> dict:
    """Build the tree from leaf cords ``{key, pendant, digest, knots}``."""
    names = _knot_names(knot_names)
    parts = _partitions(partitions, names)
    require(type(cords) is list and 0 < len(cords) <= MAX_CORDS, "KHIPU_CORDS_INVALID")
    grouped, keys = {}, set()
    for cord in cords:
        closed(cord, ("key", "pendant", "digest", "knots"), "KHIPU_CORD_FIELDS_INVALID")
        require(type(cord["key"]) is str and KEY.fullmatch(cord["key"]) and
                type(cord["pendant"]) is str and LABEL.fullmatch(cord["pendant"]) and
                type(cord["digest"]) is str and SHA64.fullmatch(cord["digest"]),
                "KHIPU_CORD_FIELDS_INVALID")
        require(cord["key"] not in keys, "KHIPU_CORD_DUPLICATE")
        keys.add(cord["key"])
        knots = list(_vector(cord["knots"], len(names), "KHIPU_KNOT_VECTOR_INVALID"))
        require(_partition_holds(knots, names, parts), "KHIPU_PARTITION_BROKEN_AT_CORD")
        grouped.setdefault(cord["pendant"], []).append(
            {"key": cord["key"], "digest": cord["digest"], "knots": knots,
             "hash": cord_hash(cord["key"], cord["digest"], knots)})
    missing = sorted(set(unavailable))
    require(all(type(k) is str and KEY.fullmatch(k) for k in missing) and
            not keys.intersection(missing), "KHIPU_UNAVAILABLE_INVALID")
    pendants, total = [], [0] * len(names)
    for label in sorted(grouped):
        leaves = sorted(grouped[label], key=lambda c: c["key"])
        subtotal = [0] * len(names)
        for leaf in leaves:
            subtotal = _add(subtotal, leaf["knots"])
        pendants.append({
            "label": label, "sum": subtotal, "cords": leaves,
            "hash": pendant_hash(label, [[c["hash"], c["knots"]] for c in leaves]),
        })
        total = _add(total, subtotal)
    tree = {
        "schema": SCHEMA, "tiers": list(TIERS), "knots": list(names),
        "partitions": [dict(p) for p in parts], "missing_is_zero": False,
        "unavailable_cords": missing,
        "primary": {
            "hash": primary_hash(names, [[p["hash"], p["sum"]] for p in pendants]),
            "sum": total, "pendant_count": len(pendants), "cord_count": len(keys),
        },
        "pendants": pendants,
    }
    verify(tree)
    return tree


def verify(tree) -> bool:
    """Recompute every hash, every sum and every partition identity."""
    closed(tree, ("schema", "tiers", "knots", "partitions", "missing_is_zero",
                  "unavailable_cords", "primary", "pendants"), "KHIPU_TREE_FIELDS_INVALID")
    require(tree["schema"] == SCHEMA and tree["tiers"] == TIERS and
            tree["missing_is_zero"] is False, "KHIPU_TREE_SCHEMA_INVALID")
    names = _knot_names(tree["knots"])
    parts = _partitions(tree["partitions"], names)
    width = len(names)
    primary = closed(tree["primary"], ("hash", "sum", "pendant_count", "cord_count"),
                     "KHIPU_TREE_FIELDS_INVALID")
    pendants = tree["pendants"]
    require(type(pendants) is list and 0 < len(pendants) <= MAX_CORDS,
            "KHIPU_TREE_FIELDS_INVALID")
    labels, keys, total, children = [], set(), [0] * width, []
    for pendant in pendants:
        closed(pendant, ("label", "sum", "cords", "hash"), "KHIPU_PENDANT_FIELDS_INVALID")
        require(type(pendant["label"]) is str and LABEL.fullmatch(pendant["label"]) and
                type(pendant["cords"]) is list and len(pendant["cords"]) > 0,
                "KHIPU_PENDANT_FIELDS_INVALID")
        labels.append(pendant["label"])
        subtotal, leaf_keys, leaf_children = [0] * width, [], []
        for cord in pendant["cords"]:
            closed(cord, ("key", "digest", "knots", "hash"), "KHIPU_CORD_FIELDS_INVALID")
            require(type(cord["key"]) is str and KEY.fullmatch(cord["key"]) and
                    type(cord["digest"]) is str and SHA64.fullmatch(cord["digest"]),
                    "KHIPU_CORD_FIELDS_INVALID")
            knots = _vector(cord["knots"], width, "KHIPU_KNOT_VECTOR_INVALID")
            require(cord["key"] not in keys, "KHIPU_CORD_DUPLICATE")
            keys.add(cord["key"])
            leaf_keys.append(cord["key"])
            require(cord["hash"] == cord_hash(cord["key"], cord["digest"], knots),
                    "KHIPU_CORD_HASH_MISMATCH")
            require(_partition_holds(knots, names, parts), "KHIPU_PARTITION_BROKEN_AT_CORD")
            subtotal = _add(subtotal, knots)
            leaf_children.append([cord["hash"], knots])
        require(leaf_keys == sorted(leaf_keys), "KHIPU_CORD_ORDER_INVALID")
        _vector(pendant["sum"], width, "KHIPU_KNOT_VECTOR_INVALID")
        require(pendant["sum"] == subtotal, "KHIPU_PENDANT_SUM_NOT_CONSERVED")
        require(_partition_holds(subtotal, names, parts), "KHIPU_PARTITION_BROKEN_AT_PENDANT")
        require(pendant["hash"] == pendant_hash(pendant["label"], leaf_children),
                "KHIPU_PENDANT_HASH_MISMATCH")
        total = _add(total, subtotal)
        children.append([pendant["hash"], subtotal])
    require(labels == sorted(set(labels)), "KHIPU_PENDANT_ORDER_INVALID")
    _vector(primary["sum"], width, "KHIPU_KNOT_VECTOR_INVALID")
    require(primary["sum"] == total, "KHIPU_PRIMARY_SUM_NOT_CONSERVED")
    require(_partition_holds(total, names, parts), "KHIPU_PARTITION_BROKEN_AT_PRIMARY")
    require(type(primary["pendant_count"]) is int and primary["pendant_count"] == len(pendants)
            and type(primary["cord_count"]) is int and primary["cord_count"] == len(keys)
            and len(keys) <= MAX_CORDS, "KHIPU_COUNT_MISMATCH")
    require(type(primary["hash"]) is str and
            primary["hash"] == primary_hash(names, children), "KHIPU_PRIMARY_HASH_MISMATCH")
    missing = tree["unavailable_cords"]
    require(type(missing) is list and missing == sorted(set(missing)) and
            all(type(k) is str and KEY.fullmatch(k) for k in missing) and
            not keys.intersection(missing), "KHIPU_UNAVAILABLE_INVALID")
    return True


def knot(tree, name) -> int:
    """The primary-cord total for one named knot of a verified tree."""
    require(name in tree["knots"], "KHIPU_KNOT_UNKNOWN")
    return tree["primary"]["sum"][tree["knots"].index(name)]


def cord_index(tree) -> dict:
    """Map every cord key to ``(pendant position, cord position)``."""
    return {cord["key"]: (i, j) for i, pendant in enumerate(tree["pendants"])
            for j, cord in enumerate(pendant["cords"])}


def prove(tree, key) -> dict:
    """Inclusion-with-sum proof for one cord of a verified tree."""
    verify(tree)
    place = cord_index(tree).get(key)
    require(place is not None, "KHIPU_CORD_NOT_FOUND")
    pendant = tree["pendants"][place[0]]
    cord = pendant["cords"][place[1]]
    return {
        "schema": PROOF_SCHEMA, "knots": list(tree["knots"]),
        "cord": {"key": cord["key"], "digest": cord["digest"], "knots": list(cord["knots"])},
        "pendant": {"label": pendant["label"], "position": place[1],
                    "cords": [[c["hash"], list(c["knots"])] for c in pendant["cords"]]},
        "primary": {"position": place[0],
                    "pendants": [[p["hash"], list(p["sum"])] for p in tree["pendants"]]},
    }


def verify_proof(proof, *, primary_hash_expected, primary_sum_expected) -> bool:
    """Check a proof against a trusted primary hash and total. Reveals no other cord."""
    closed(proof, ("schema", "knots", "cord", "pendant", "primary"), "KHIPU_PROOF_FIELDS_INVALID")
    require(proof["schema"] == PROOF_SCHEMA, "KHIPU_PROOF_FIELDS_INVALID")
    names = _knot_names(proof["knots"])
    width = len(names)
    cord = closed(proof["cord"], ("key", "digest", "knots"), "KHIPU_PROOF_FIELDS_INVALID")
    require(type(cord["key"]) is str and KEY.fullmatch(cord["key"]) and
            type(cord["digest"]) is str and SHA64.fullmatch(cord["digest"]),
            "KHIPU_PROOF_FIELDS_INVALID")
    knots = _vector(cord["knots"], width, "KHIPU_PROOF_FIELDS_INVALID")
    pendant = closed(proof["pendant"], ("label", "position", "cords"),
                     "KHIPU_PROOF_FIELDS_INVALID")
    primary = closed(proof["primary"], ("position", "pendants"), "KHIPU_PROOF_FIELDS_INVALID")

    def pairs(rows, code):
        require(type(rows) is list and 0 < len(rows) <= MAX_CORDS, code)
        for row in rows:
            require(type(row) is list and len(row) == 2 and type(row[0]) is str and
                    SHA64.fullmatch(row[0]), code)
            _vector(row[1], width, code)
        return rows

    leaves = pairs(pendant["cords"], "KHIPU_PROOF_FIELDS_INVALID")
    groups = pairs(primary["pendants"], "KHIPU_PROOF_FIELDS_INVALID")
    require(type(pendant["label"]) is str and LABEL.fullmatch(pendant["label"]) and
            type(pendant["position"]) is int and 0 <= pendant["position"] < len(leaves) and
            type(primary["position"]) is int and 0 <= primary["position"] < len(groups),
            "KHIPU_PROOF_FIELDS_INVALID")
    require(leaves[pendant["position"]] ==
            [cord_hash(cord["key"], cord["digest"], knots), knots], "KHIPU_PROOF_CORD_MISMATCH")
    subtotal = [0] * width
    for row in leaves:
        subtotal = _add(subtotal, row[1])
    require(groups[primary["position"]] ==
            [pendant_hash(pendant["label"], leaves), subtotal], "KHIPU_PROOF_PENDANT_MISMATCH")
    total = [0] * width
    for row in groups:
        total = _add(total, row[1])
    require(total == primary_sum_expected and
            primary_hash(names, groups) == primary_hash_expected, "KHIPU_PROOF_PRIMARY_MISMATCH")
    return True


def diff(old, new) -> dict:
    """What changed between two verified trees with the same knot names."""
    verify(old)
    verify(new)
    require(old["knots"] == new["knots"], "KHIPU_DIFF_KNOTS_DIFFER")

    def leaves(tree):
        return {c["key"]: c for p in tree["pendants"] for c in p["cords"]}

    before, after = leaves(old), leaves(new)
    return {
        "added": sorted(set(after) - set(before)),
        "removed": sorted(set(before) - set(after)),
        "content_changed": sorted(k for k in set(before) & set(after)
                                  if before[k]["digest"] != after[k]["digest"]),
        "knots_changed": sorted(k for k in set(before) & set(after)
                                if before[k]["knots"] != after[k]["knots"]),
        "sum_delta": {name: new["primary"]["sum"][i] - old["primary"]["sum"][i]
                      for i, name in enumerate(new["knots"])},
        "primary_hash_changed": old["primary"]["hash"] != new["primary"]["hash"],
    }
