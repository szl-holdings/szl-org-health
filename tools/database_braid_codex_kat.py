#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Known-answer checks transcribed from estate Lean source files.

Each answer is one concrete numeric claim copied from a first-party source
file (a unit-fraction decomposition, a reciprocal pair, a sexagesimal value,
a calendar cycle, a checksum) together with the exact line it was copied from.
Its family names the subject of the claim, not a tradition the file cites.
The claim is re-derived here with exact integer and rational arithmetic in a
tiny closed expression language (no ``eval``, no floats), independently of
Lean. An answer is scored only while it is BOUND to the source bytes it was
transcribed from with its anchor text at the stated line: when the file
changes the answer is re-anchored by its exact source line or reported STALE,
an anchor found elsewhere is ANCHOR_NOT_AT_STATED_LINE, and bytes that could
not be read are SOURCE_BYTES_NOT_READ. None of these is ever silently kept or
dropped: every answer stays in the report's ``answers`` total, and in its
family's ``answers`` total, so a caller can divide by answers rather than by
the evaluated ones, overall and per family.

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
import operator
from pathlib import Path
import re
import sys

try:
    from tools.database_braid_common import (
        REPOSITORY, SHA40, SHA64, checkout_root, closed, git_blob_sha1, natural, read_json,
        require, write_exclusive,
    )
    from tools.database_braid_source_census import (
        cord_key, list_tree, read_blobs,
    )
    from tools.database_catalog_admission import InputError
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools.database_braid_common import (
        REPOSITORY, SHA40, SHA64, checkout_root, closed, git_blob_sha1, natural, read_json,
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
DETAIL = re.compile(r"[A-Z_]{3,80}\Z")
REVIEW_STATUSES = ("MACHINE_TRANSCRIBED_UNRATIFIED", "OWNER_RATIFIED")
MAX_ANSWERS = 2000
MAX_SET_BYTES = 4194304
MAX_REPORT_BYTES = 4194304
MAX_NODES = 4000
MAX_DEPTH = 40
MAX_BITS = 13000
MAX_EXPONENT = 4096
MAX_BLOB_BYTES = 8388608
BOUND = "BOUND_TO_TRANSCRIBED_BYTES"
REBOUND = "REBOUND_BY_EXACT_SOURCE_LINE"
STALE = "STALE_SOURCE_CHANGED"
ABSENT = "SOURCE_NOT_IN_CENSUS"
MISPLACED = "ANCHOR_NOT_AT_STATED_LINE"
UNREAD = "SOURCE_BYTES_NOT_READ"
BINDINGS = (BOUND, REBOUND, STALE, ABSENT, MISPLACED, UNREAD)
SUMMARY_COUNTS = ("answers", "evaluated", "passed", "failed", "invalid_claims", "stale",
                  "source_not_in_census", "anchor_not_at_line", "source_bytes_not_read",
                  "rebound_by_line")
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
    require(_fits(result), "KAT_NUMBER_TOO_LARGE")
    return result


def _fits(value: Fraction) -> bool:
    # Measured in bits so no integer is ever turned into text above Python's limit.
    return max(value.numerator.bit_length(), value.denominator.bit_length()) <= MAX_BITS


def _fold(values, step, start):
    # Every partial result is size-checked, so a long list cannot build a huge intermediate.
    out = start
    for value in values:
        out = step(out, value)
        require(_fits(out), "KAT_NUMBER_TOO_LARGE")
    return out


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
        out = _fold(numbers(args), operator.add, Fraction(0))
    elif op == "mul":
        out = _fold(numbers(args), operator.mul, Fraction(1))
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
        bits = max(base.numerator.bit_length(), base.denominator.bit_length())
        # A power has at least |p| * (bits - 1) + 1 bits, so this refuses only a result that
        # could not fit, before computing it; the exact size check follows.
        require(abs(power) * max(0, bits - 1) < MAX_BITS, "KAT_NUMBER_TOO_LARGE")
        out = base ** power
    elif op in ("floordiv", "mod"):
        require(type(args) is list and len(args) == 2, "KAT_EXPRESSION_INVALID")
        left, right = (_integer(v) for v in numbers(args, 2))
        require(right != 0, "KAT_DIVISION_BY_ZERO")
        out = Fraction(left // right if op == "floordiv" else left % right)
    elif op in ("gcd", "lcm"):
        whole = [_integer(v) for v in numbers(args)]
        require(all(v >= 0 for v in whole), "KAT_NATURAL_REQUIRED")
        out = (Fraction(math.gcd(*whole)) if op == "gcd" else
               _fold((Fraction(v) for v in whole),
                     lambda a, b: Fraction(math.lcm(a.numerator, b.numerator)), Fraction(1)))
    elif op in ("min", "max"):
        out = (min if op == "min" else max)(numbers(args))
    elif op == "unit_sum":
        # Sum of unit fractions 1/d over the listed positive integer denominators.
        whole = [_integer(v) for v in numbers(args)]
        require(all(v > 0 for v in whole), "KAT_NATURAL_REQUIRED")
        out = _fold((Fraction(1, v) for v in whole), operator.add, Fraction(0))
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
        # Every counted element must itself be a valid number or relation.
        out = Fraction(len(each(args, 0)))
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
    require(_fits(out), "KAT_NUMBER_TOO_LARGE")
    return out


def _utf8(text: str) -> bool:
    # A lone surrogate, which only a JSON escape can produce, has no UTF-8 form.
    try:
        text.encode("utf-8")
    except UnicodeError:
        return False
    return True


def validate_set(value) -> list:
    """Closed-schema check of a known-answer set. Returns its answers."""
    closed(value, ("schema", "review_status", "answers"), "KAT_SET_FIELDS_INVALID")
    require(value["schema"] == SET_SCHEMA and value["review_status"] in REVIEW_STATUSES,
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
                _utf8(source["path"]) and
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
    """How an answer relates to the source bytes present in this census.

    The anchor is always checked against bytes actually read: BOUND needs the
    transcribed blob AND the anchor text at the stated line.
    """
    source = answer["source"]
    cord = cords_by_key.get(cord_key(source["repository"], source["path"]))
    if cord is None:
        return ABSENT
    try:
        body = read_current(source["repository"], cord["blob_sha1"]) if read_current else None
    except InputError:
        # A blob this checkout cannot supply is missing evidence, never a pass.
        body = None
    if type(body) is not bytes or git_blob_sha1(body) != cord["blob_sha1"]:
        return UNREAD
    anchor = answer["anchor"].strip()
    if cord["blob_sha1"] == source["blob_sha1"]:
        return BOUND if _line(body, source["line"]) == anchor else MISPLACED
    hits = [line.strip() for line in body.decode("utf-8", "replace").split("\n")
            if line.strip() == anchor]
    return REBOUND if len(hits) == 1 else STALE


def _cords_by_key(census) -> dict:
    require(type(census) is dict and type(census.get("cords")) is list, "KAT_CENSUS_INVALID")
    cords = {}
    for cord in census["cords"]:
        require(type(cord) is dict and type(cord.get("key")) is str and
                cord["key"] not in cords and type(cord.get("blob_sha1")) is str and
                SHA40.fullmatch(cord["blob_sha1"]) is not None, "KAT_CENSUS_INVALID")
        cords[cord["key"]] = cord
    return cords


def check(answer_set, census, *, read_current=None, set_sha256=None,
          census_sha256=None) -> dict:
    """Evaluate every answer and report binding and verdict separately."""
    answers = validate_set(answer_set)
    cords = _cords_by_key(census)
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
            except (ValueError, ArithmeticError, RecursionError):
                verdict, detail = "INVALID_CLAIM", "KAT_ARITHMETIC_ERROR"
        results.append({"id": answer["id"], "family": answer["family"],
                        "repository": answer["source"]["repository"],
                        "path": answer["source"]["path"], "line": answer["source"]["line"],
                        "binding": state, "verdict": verdict, "detail": detail})
    report = {
        "schema": SCHEMA, "answer_set_sha256": set_sha256, "census_sha256": census_sha256,
        "review_status": answer_set["review_status"], **_tally(results),
        "families": _families(results),
        "results": results,
        "arithmetic": "EXACT_INTEGER_AND_RATIONAL_NO_FLOATS",
    }
    report.update({flag: False for flag in _FALSE_FLAGS})
    validate_report(report)
    return report


def _tally(rows) -> dict:
    """Every ``SUMMARY_COUNTS`` total of ``rows``; only bound or rebound rows are scored."""
    scored = [r for r in rows if r["binding"] in (BOUND, REBOUND)]
    return {"answers": len(rows), "evaluated": len(scored),
            "passed": sum(r["verdict"] == "PASS" for r in scored),
            "failed": sum(r["verdict"] == "FAIL" for r in scored),
            "invalid_claims": sum(r["verdict"] == "INVALID_CLAIM" for r in scored),
            "stale": sum(r["binding"] == STALE for r in rows),
            "source_not_in_census": sum(r["binding"] == ABSENT for r in rows),
            "anchor_not_at_line": sum(r["binding"] == MISPLACED for r in rows),
            "source_bytes_not_read": sum(r["binding"] == UNREAD for r in rows),
            "rebound_by_line": sum(r["binding"] == REBOUND for r in rows)}


def _families(rows) -> dict:
    """The same totals per family, for every family that has an answer, scored or not."""
    return {name: _tally([r for r in rows if r["family"] == name])
            for name in sorted({r["family"] for r in rows})}


def validate_report(value) -> bool:
    """Closed-schema check of a report; every total is re-derived from its rows."""
    closed(value, ("schema", "answer_set_sha256", "census_sha256", "review_status", "answers",
                   "evaluated", "passed", "failed", "invalid_claims", "stale",
                   "source_not_in_census", "anchor_not_at_line", "source_bytes_not_read",
                   "rebound_by_line", "families", "results", "arithmetic", *_FALSE_FLAGS),
           "KAT_REPORT_FIELDS_INVALID")
    require(value["schema"] == SCHEMA and all(value[f] is False for f in _FALSE_FLAGS) and
            value["arithmetic"] == "EXACT_INTEGER_AND_RATIONAL_NO_FLOATS",
            "KAT_FALSE_AUTHORITY_CLAIM")
    require(value["review_status"] in REVIEW_STATUSES, "KAT_REPORT_FIELDS_INVALID")
    for field in ("answer_set_sha256", "census_sha256"):
        require(value[field] is None or (type(value[field]) is str and
                                         SHA64.fullmatch(value[field])),
                "KAT_REPORT_FIELDS_INVALID")
    for field in SUMMARY_COUNTS:
        # natural() first: Python's == would let True stand for 1 and False for 0.
        natural(value[field], "KAT_REPORT_FIELDS_INVALID")
    rows = value["results"]
    # check() never reports an empty set, so neither may a report.
    require(type(rows) is list and 0 < len(rows) == value["answers"] <= MAX_ANSWERS,
            "KAT_REPORT_FIELDS_INVALID")
    ids = []
    for row in rows:
        closed(row, ("id", "family", "repository", "path", "line", "binding", "verdict",
                     "detail"), "KAT_REPORT_FIELDS_INVALID")
        require(row["binding"] in BINDINGS and
                row["verdict"] in ("PASS", "FAIL", "INVALID_CLAIM", "NOT_EVALUATED") and
                # An answer that is not bound to present source bytes is never scored.
                (row["verdict"] == "NOT_EVALUATED") == (row["binding"] not in (BOUND, REBOUND))
                and type(row["family"]) is str and FAMILY.fullmatch(row["family"]) and
                type(row["id"]) is str and ANSWER_ID.fullmatch(row["id"]) and
                type(row["repository"]) is str and REPOSITORY.fullmatch(row["repository"]) and
                type(row["path"]) is str and 0 < len(row["path"]) <= 400 and _utf8(row["path"])
                and type(row["line"]) is int and 1 <= row["line"] <= 10 ** 6 and
                # Only a refused claim carries a reason, and it is a refusal code.
                ((row["detail"] is None) == (row["verdict"] != "INVALID_CLAIM")) and
                (row["detail"] is None or (type(row["detail"]) is str and
                                           DETAIL.fullmatch(row["detail"]) is not None)),
                "KAT_REPORT_ROW_INVALID")
        ids.append(row["id"])
    require(ids == sorted(set(ids)), "KAT_REPORT_ROW_INVALID")
    totals = _tally(rows)
    require(all(value[field] == totals[field] for field in SUMMARY_COUNTS) and
            value["evaluated"] == value["passed"] + value["failed"] + value["invalid_claims"] and
            value["answers"] == value["evaluated"] + value["stale"] +
            value["source_not_in_census"] + value["anchor_not_at_line"] +
            value["source_bytes_not_read"], "KAT_REPORT_TOTALS_DRIFT")
    families = value["families"]
    require(type(families) is dict, "KAT_REPORT_FIELDS_INVALID")
    for entry in families.values():
        closed(entry, SUMMARY_COUNTS, "KAT_REPORT_FIELDS_INVALID")
        for field in SUMMARY_COUNTS:
            natural(entry[field], "KAT_REPORT_FIELDS_INVALID")
    require(families == _families(rows), "KAT_REPORT_TOTALS_DRIFT")
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
        for directory in checkouts.values():
            # Each checkout must be the top level of a git work tree with a commit.
            list_tree(directory)

        def read_current(repository, blob_sha1):
            directory = checkouts.get(repository)
            if directory is None:
                return None
            return read_blobs(directory, [blob_sha1], max_bytes=MAX_BLOB_BYTES).get(blob_sha1)

        report = check(answer_set, census, read_current=read_current, set_sha256=set_sha,
                       census_sha256=census_sha)
        write_exclusive(args.output, report, max_bytes=MAX_REPORT_BYTES, checkout=checkout_root())
        print(json.dumps({**{name: report[name] for name in SUMMARY_COUNTS},
                          "production_authorized": False}))
        # Clean means every answer was evaluated and passed; answers is the denominator.
        clean = report["answers"] == report["evaluated"] == report["passed"] > 0
        return 0 if clean else 2
    except InputError as exc:
        code = exc.code
    except Exception:
        code = "KAT_UNAVAILABLE"
    print(json.dumps({"state": "UNAVAILABLE", "code": code, "production_authorized": False}))
    return 3


if __name__ == "__main__":
    sys.exit(main())
