#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Known-answer checks transcribed from the estate's ancient-mathematics sources.

Each answer is one concrete numeric claim copied from a first-party source
file (a unit-fraction decomposition, a reciprocal pair, a sexagesimal value,
an epoch cycle, a checksum) together with the exact line it was copied from.
The claim is re-derived here with exact integer and rational arithmetic in a
tiny closed expression language (no ``eval``, no floats), independently of
Lean. An answer counts only while it is still BOUND to the source bytes it
was transcribed from: when the file changes the answer is re-anchored by its
exact source line or reported STALE, never silently kept.

What this is: an arithmetic cross-check of numbers written in modern source
files that cite historical mathematics. What it is not: a reading of any
manuscript, tablet or khipu, a claim about what an ancient source says, or a
proof of the surrounding theorem. A FAIL means the number written in the
source file does not hold as written; it is reported, never corrected here.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import json
import math
from pathlib import Path
import re
import sys

try:
    from tools.database_braid_common import (
        REPOSITORY, SHA40, SHA64, checkout_root, closed, natural, read_json,
        require, write_exclusive,
    )
    from tools.database_braid_source_census import (
        cord_key, list_tree, read_blobs,
    )
    from tools.database_catalog_admission import InputError
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools.database_braid_common import (
        REPOSITORY, SHA40, SHA64, checkout_root, closed, natural, read_json,
        require, write_exclusive,
    )
    from tools.database_braid_source_census import (
        cord_key, list_tree, read_blobs,
    )
    from tools.database_catalog_admission import InputError

SET_SCHEMA = "szl.database-braid-codex-kat-set/v1"
SCHEMA = "szl.database-braid-codex-kat/v1"
ANSWER_ID = re.compile(r"[a-z][a-z0-9-]{2,63}\Z")
FAMILY = re.compile(r"[A-Z][A-Z0-9_]{1,47}\Z")
NUMBER = re.compile(r"-?(?:0|[1-9][0-9]{0,400})(?:/[1-9][0-9]{0,400})?\Z")
MAX_ANSWERS = 2000
MAX_SET_BYTES = 4194304
MAX_REPORT_BYTES = 4194304
MAX_NODES = 4000
MAX_DEPTH = 40
MAX_DIGITS = 6000
MAX_EXPONENT = 4096
MAX_BLOB_BYTES = 8388608
BOUND = "BOUND_TO_TRANSCRIBED_BYTES"
REBOUND = "REBOUND_BY_EXACT_SOURCE_LINE"
STALE = "STALE_SOURCE_CHANGED"
ABSENT = "SOURCE_NOT_IN_CENSUS"
_FALSE_FLAGS = ("manuscript_or_artifact_read", "historical_claim_asserted",
                "surrounding_theorem_proved_by_this_check", "source_corrected",
                "production_authorized")


class _Budget:
    def __init__(self):
        self.nodes = 0


def _number(value) -> Fraction:
    if type(value) is int:
        result = Fraction(value)
    else:
        require(type(value) is str and NUMBER.fullmatch(value) is not None, "KAT_NUMBER_INVALID")
        result = Fraction(value)
    require(len(str(result.numerator)) + len(str(result.denominator)) <= MAX_DIGITS,
            "KAT_NUMBER_TOO_LARGE")
    return result


def _integer(value: Fraction, code="KAT_INTEGER_REQUIRED") -> int:
    require(value.denominator == 1, code)
    return value.numerator


def evaluate(node, budget=None, depth=0):
    """Evaluate one closed expression. Numbers are exact; booleans come only from relations."""
    budget = budget or _Budget()
    budget.nodes += 1
    require(budget.nodes <= MAX_NODES and depth <= MAX_DEPTH, "KAT_EXPRESSION_TOO_LARGE")
    if type(node) in (int, str):
        return _number(node)
    require(type(node) is dict and len(node) == 1, "KAT_EXPRESSION_INVALID")
    (op, args), = node.items()

    def each(items, minimum=1):
        require(type(items) is list and minimum <= len(items) <= 400, "KAT_EXPRESSION_INVALID")
        return [evaluate(item, budget, depth + 1) for item in items]

    def numbers(items, minimum=1):
        values = each(items, minimum)
        require(all(type(v) is Fraction for v in values), "KAT_NUMBER_EXPECTED")
        return values

    def truths(items, minimum=1):
        values = each(items, minimum)
        require(all(type(v) is bool for v in values), "KAT_RELATION_EXPECTED")
        return values

    if op == "add":
        out = sum(numbers(args), Fraction(0))
    elif op == "mul":
        out = Fraction(1)
        for value in numbers(args):
            out *= value
    elif op == "sub":
        require(type(args) is list and len(args) == 2, "KAT_EXPRESSION_INVALID")
        left, right = numbers(args, 2)
        out = left - right
    elif op == "div":
        require(type(args) is list and len(args) == 2, "KAT_EXPRESSION_INVALID")
        left, right = numbers(args, 2)
        require(right != 0, "KAT_DIVISION_BY_ZERO")
        out = left / right
    elif op == "neg":
        out = -numbers([args])[0]
    elif op == "abs":
        out = abs(numbers([args])[0])
    elif op == "pow":
        require(type(args) is list and len(args) == 2, "KAT_EXPRESSION_INVALID")
        base, exponent = numbers(args, 2)
        power = _integer(exponent)
        require(abs(power) <= MAX_EXPONENT and not (base == 0 and power < 0),
                "KAT_EXPONENT_INVALID")
        require((len(str(base.numerator)) + len(str(base.denominator))) * max(1, abs(power))
                <= MAX_DIGITS, "KAT_NUMBER_TOO_LARGE")
        out = base ** power
    elif op in ("floordiv", "mod"):
        require(type(args) is list and len(args) == 2, "KAT_EXPRESSION_INVALID")
        left, right = (_integer(v) for v in numbers(args, 2))
        require(right != 0, "KAT_DIVISION_BY_ZERO")
        out = Fraction(left // right if op == "floordiv" else left % right)
    elif op in ("gcd", "lcm"):
        whole = [_integer(v) for v in numbers(args)]
        require(all(v >= 0 for v in whole), "KAT_NATURAL_REQUIRED")
        out = Fraction(math.gcd(*whole) if op == "gcd" else math.lcm(*whole))
    elif op in ("min", "max"):
        out = (min if op == "min" else max)(numbers(args))
    elif op == "unit_sum":
        # Sum of unit fractions 1/d over the listed positive integer denominators.
        whole = [_integer(v) for v in numbers(args)]
        require(all(v > 0 for v in whole), "KAT_NATURAL_REQUIRED")
        out = sum((Fraction(1, v) for v in whole), Fraction(0))
    elif op == "sexagesimal":
        closed(args, ("digits", "integer_places"), "KAT_EXPRESSION_INVALID")
        digits = args["digits"]
        require(type(digits) is list and 0 < len(digits) <= 40 and
                all(type(d) is int and 0 <= d < 60 for d in digits) and
                type(args["integer_places"]) is int and
                0 <= args["integer_places"] <= len(digits), "KAT_SEXAGESIMAL_INVALID")
        out = sum((Fraction(d) * Fraction(60) ** (args["integer_places"] - 1 - i)
                   for i, d in enumerate(digits)), Fraction(0))
    elif op == "count":
        require(type(args) is list and len(args) <= 400, "KAT_EXPRESSION_INVALID")
        out = Fraction(len(args))
    elif op in ("eq", "ne", "lt", "le", "gt", "ge"):
        require(type(args) is list and len(args) == 2, "KAT_EXPRESSION_INVALID")
        left, right = numbers(args, 2)
        return {"eq": left == right, "ne": left != right, "lt": left < right,
                "le": left <= right, "gt": left > right, "ge": left >= right}[op]
    elif op == "and":
        return all(truths(args))
    elif op == "or":
        return any(truths(args))
    elif op == "not":
        return not truths([args])[0]
    else:
        raise InputError("KAT_OPERATOR_UNKNOWN")
    require(len(str(out.numerator)) + len(str(out.denominator)) <= MAX_DIGITS,
            "KAT_NUMBER_TOO_LARGE")
    return out


def validate_set(value) -> list:
    """Closed-schema check of a known-answer set. Returns its answers."""
    closed(value, ("schema", "review_status", "answers"), "KAT_SET_FIELDS_INVALID")
    require(value["schema"] == SET_SCHEMA and
            value["review_status"] in ("MACHINE_TRANSCRIBED_UNRATIFIED", "OWNER_RATIFIED"),
            "KAT_SET_FIELDS_INVALID")
    answers = value["answers"]
    require(type(answers) is list and 0 < len(answers) <= MAX_ANSWERS, "KAT_SET_FIELDS_INVALID")
    ids = []
    for item in answers:
        closed(item, ("id", "family", "source", "anchor", "statement", "claim"),
               "KAT_ANSWER_FIELDS_INVALID")
        source = closed(item["source"], ("repository", "path", "line", "blob_sha1"),
                        "KAT_ANSWER_FIELDS_INVALID")
        require(type(item["id"]) is str and ANSWER_ID.fullmatch(item["id"]) and
                type(item["family"]) is str and FAMILY.fullmatch(item["family"]) and
                type(source["repository"]) is str and REPOSITORY.fullmatch(source["repository"])
                and type(source["path"]) is str and 0 < len(source["path"]) <= 400 and
                type(source["line"]) is int and 1 <= source["line"] <= 10 ** 6 and
                type(source["blob_sha1"]) is str and SHA40.fullmatch(source["blob_sha1"]) and
                type(item["anchor"]) is str and 0 < len(item["anchor"].strip()) and
                len(item["anchor"]) <= 600 and "\n" not in item["anchor"] and
                type(item["statement"]) is str and 0 < len(item["statement"]) <= 400 and
                type(item["claim"]) is dict, "KAT_ANSWER_FIELDS_INVALID")
        ids.append(item["id"])
    require(ids == sorted(set(ids)), "KAT_ANSWER_ORDER_OR_DUPLICATE")
    return answers


def _line(body: bytes, number: int) -> str | None:
    lines = body.decode("utf-8", "replace").split("\n")
    return lines[number - 1].strip() if 1 <= number <= len(lines) else None


def binding(answer, cords_by_key: dict, read_current) -> str:
    """How an answer relates to the source bytes present in this census."""
    source = answer["source"]
    cord = cords_by_key.get(cord_key(source["repository"], source["path"]))
    if cord is None:
        return ABSENT
    if cord["blob_sha1"] == source["blob_sha1"]:
        return BOUND
    body = read_current(source["repository"], cord["blob_sha1"]) if read_current else None
    if body is None:
        return STALE
    anchor = answer["anchor"].strip()
    hits = [line.strip() for line in body.decode("utf-8", "replace").split("\n")
            if line.strip() == anchor]
    return REBOUND if len(hits) == 1 else STALE


def check(answer_set, census, *, read_current=None, set_sha256=None,
          census_sha256=None) -> dict:
    """Evaluate every answer and report binding and verdict separately."""
    answers = validate_set(answer_set)
    require(type(census) is dict and type(census.get("cords")) is list, "KAT_CENSUS_INVALID")
    cords = {c["key"]: c for c in census["cords"]}
    results = []
    for answer in answers:
        state = binding(answer, cords, read_current)
        verdict, detail = "NOT_EVALUATED", None
        if state in (BOUND, REBOUND):
            try:
                outcome = evaluate(answer["claim"])
                require(type(outcome) is bool, "KAT_CLAIM_NOT_A_RELATION")
                verdict = "PASS" if outcome else "FAIL"
            except InputError as exc:
                verdict, detail = "INVALID_CLAIM", exc.code
        results.append({"id": answer["id"], "family": answer["family"],
                        "repository": answer["source"]["repository"],
                        "path": answer["source"]["path"], "line": answer["source"]["line"],
                        "binding": state, "verdict": verdict, "detail": detail})
    counted = [r for r in results if r["binding"] in (BOUND, REBOUND)]
    families = {}
    for row in counted:
        entry = families.setdefault(row["family"], {"evaluated": 0, "passed": 0})
        entry["evaluated"] += 1
        entry["passed"] += row["verdict"] == "PASS"
    report = {
        "schema": SCHEMA, "answer_set_sha256": set_sha256, "census_sha256": census_sha256,
        "review_status": answer_set["review_status"], "answers": len(results),
        "evaluated": len(counted),
        "passed": sum(r["verdict"] == "PASS" for r in counted),
        "failed": sum(r["verdict"] == "FAIL" for r in counted),
        "invalid_claims": sum(r["verdict"] == "INVALID_CLAIM" for r in counted),
        "stale": sum(r["binding"] == STALE for r in results),
        "source_not_in_census": sum(r["binding"] == ABSENT for r in results),
        "rebound_by_line": sum(r["binding"] == REBOUND for r in results),
        "families": {name: families[name] for name in sorted(families)},
        "results": results,
        "arithmetic": "EXACT_INTEGER_AND_RATIONAL_NO_FLOATS",
    }
    report.update({flag: False for flag in _FALSE_FLAGS})
    validate_report(report)
    return report


def validate_report(value) -> bool:
    closed(value, ("schema", "answer_set_sha256", "census_sha256", "review_status", "answers",
                   "evaluated", "passed", "failed", "invalid_claims", "stale",
                   "source_not_in_census", "rebound_by_line", "families", "results",
                   "arithmetic", *_FALSE_FLAGS), "KAT_REPORT_FIELDS_INVALID")
    require(value["schema"] == SCHEMA and all(value[f] is False for f in _FALSE_FLAGS) and
            value["arithmetic"] == "EXACT_INTEGER_AND_RATIONAL_NO_FLOATS",
            "KAT_FALSE_AUTHORITY_CLAIM")
    for field in ("answer_set_sha256", "census_sha256"):
        require(value[field] is None or (type(value[field]) is str and
                                         SHA64.fullmatch(value[field])),
                "KAT_REPORT_FIELDS_INVALID")
    rows = value["results"]
    require(type(rows) is list and len(rows) == value["answers"] <= MAX_ANSWERS,
            "KAT_REPORT_FIELDS_INVALID")
    for row in rows:
        closed(row, ("id", "family", "repository", "path", "line", "binding", "verdict",
                     "detail"), "KAT_REPORT_FIELDS_INVALID")
        require(row["binding"] in (BOUND, REBOUND, STALE, ABSENT) and
                row["verdict"] in ("PASS", "FAIL", "INVALID_CLAIM", "NOT_EVALUATED") and
                # An answer that is not bound to present source bytes is never scored.
                (row["verdict"] == "NOT_EVALUATED") == (row["binding"] in (STALE, ABSENT)),
                "KAT_REPORT_ROW_INVALID")
    counted = [r for r in rows if r["binding"] in (BOUND, REBOUND)]
    for field, expected in (
            ("evaluated", len(counted)),
            ("passed", sum(r["verdict"] == "PASS" for r in counted)),
            ("failed", sum(r["verdict"] == "FAIL" for r in counted)),
            ("invalid_claims", sum(r["verdict"] == "INVALID_CLAIM" for r in counted)),
            ("stale", sum(r["binding"] == STALE for r in rows)),
            ("source_not_in_census", sum(r["binding"] == ABSENT for r in rows)),
            ("rebound_by_line", sum(r["binding"] == REBOUND for r in rows))):
        natural(value[field], "KAT_REPORT_FIELDS_INVALID")
        require(value[field] == expected, "KAT_REPORT_TOTALS_DRIFT")
    require(value["evaluated"] == value["passed"] + value["failed"] + value["invalid_claims"],
            "KAT_REPORT_TOTALS_DRIFT")
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(description="Exact known-answer checks bound to source bytes")
    ap.add_argument("--answers", type=Path, required=True)
    ap.add_argument("--census", type=Path, required=True)
    ap.add_argument("--checkout", action="append", default=[], metavar="REPOSITORY=DIRECTORY")
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        answer_set, set_sha = read_json(args.answers, max_bytes=MAX_SET_BYTES)
        census, census_sha = read_json(args.census, max_bytes=16777216)
        checkouts = {}
        for item in args.checkout:
            name, sep, directory = item.partition("=")
            require(sep == "=" and REPOSITORY.fullmatch(name) and directory and
                    name not in checkouts, "KAT_CHECKOUT_ARGUMENT_INVALID")
            checkouts[name] = Path(directory)

        def read_current(repository, blob_sha1):
            directory = checkouts.get(repository)
            if directory is None:
                return None
            list_tree(directory)
            return read_blobs(directory, [blob_sha1], max_bytes=MAX_BLOB_BYTES).get(blob_sha1)

        report = check(answer_set, census, read_current=read_current, set_sha256=set_sha,
                       census_sha256=census_sha)
        write_exclusive(args.output, report, max_bytes=MAX_REPORT_BYTES, checkout=checkout_root())
        print(json.dumps({"answers": report["answers"], "evaluated": report["evaluated"],
                          "passed": report["passed"], "failed": report["failed"],
                          "stale": report["stale"], "production_authorized": False}))
        clean = (report["failed"] == 0 and report["invalid_claims"] == 0 and report["stale"] == 0
                 and report["source_not_in_census"] == 0 and report["evaluated"] > 0)
        return 0 if clean else 2
    except InputError as exc:
        code = exc.code
    except Exception:
        code = "KAT_UNAVAILABLE"
    print(json.dumps({"state": "UNAVAILABLE", "code": code, "production_authorized": False}))
    return 3


if __name__ == "__main__":
    sys.exit(main())
