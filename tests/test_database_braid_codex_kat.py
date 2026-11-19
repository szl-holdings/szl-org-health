#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline tests for the braid v2 known-answer checker.

Covers every operator of the closed expression language, the bit-size guards at their exact
boundary, every binding state (an anchor at the wrong line is never a pass), per-answer error
isolation, the report's re-derived totals and families, the shipped answer set and family
labels, and the CLI over a throwaway git repository. Nothing here reads a manuscript or
touches a network; every repository is made up inside a temporary directory.
"""
from contextlib import redirect_stdout
from copy import deepcopy
from datetime import datetime, timezone
from fractions import Fraction
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
from tools import database_braid_codex_kat as kat  # noqa: E402
from tools.database_braid_codex_kat import (  # noqa: E402
    ABSENT, BINDINGS, BOUND, MAX_BITS, MISPLACED, REBOUND, SCHEMA, SET_SCHEMA, STALE,
    SUMMARY_COUNTS, UNREAD, binding, check, evaluate, main, validate_report, validate_set,
)
from tools.database_braid_common import git_blob_sha1  # noqa: E402
from tools.database_braid_source_census import cord_key, observe  # noqa: E402

F = Fraction
REPO = "szl-holdings/alpha"
CONTRACT = ROOT / "governance/database_contracts/braid_codex_known_answers_v1.json"
FAMILY_MAP = ROOT / "governance/database_contracts/braid_family_map_v1.json"
SOURCE = (b"-- header\n"
          b"theorem four : 2 + 2 = 4 := by decide\n"
          b"theorem seven : 3 + 4 = 7 := by decide\n"
          b"theorem wrong : 2 + 2 = 5 := by decide\n")
CHANGED = b"-- edited header\n-- moved down\n" + SOURCE[len(b"-- header\n"):]
ANCHORS = {"four": (2, "theorem four : 2 + 2 = 4 := by decide"),
           "seven": (3, "theorem seven : 3 + 4 = 7 := by decide"),
           "wrong": (4, "theorem wrong : 2 + 2 = 5 := by decide")}
CLAIMS = {"four": {"eq": [{"add": [2, 2]}, 4]}, "seven": {"eq": [{"add": [3, 4]}, 7]},
          "wrong": {"eq": [{"add": [2, 2]}, 5]}}


def answer(name, *, path="src/a.lean", blob=None, line=None, anchor=None, claim=None,
           family="ARITHMETIC_CHECK", repository=REPO):
    stated_line, stated_anchor = ANCHORS[name]
    return {"id": f"t-{name}", "family": family,
            "source": {"repository": repository, "path": path,
                       "line": stated_line if line is None else line,
                       "blob_sha1": git_blob_sha1(SOURCE) if blob is None else blob},
            "anchor": stated_anchor if anchor is None else anchor,
            "statement": f"Theorem {name} states a sum.",
            "claim": deepcopy(CLAIMS[name]) if claim is None else claim}


def answer_set(*answers):
    return {"schema": SET_SCHEMA, "review_status": "MACHINE_TRANSCRIBED_UNRATIFIED",
            "answers": sorted(answers, key=lambda a: a["id"])}


def census_of(files, repository=REPO):
    return {"cords": [{"key": cord_key(repository, path), "blob_sha1": git_blob_sha1(raw)}
                      for path, raw in sorted(files.items())]}


def reader(*bodies):
    blobs = {git_blob_sha1(raw): raw for raw in bodies}
    return lambda repository, blob_sha1: blobs.get(blob_sha1)


def row(report, name):
    return next(r for r in report["results"] if r["id"] == f"t-{name}")


class EvaluatorTests(TestCase):
    def refused(self, node, code):
        with self.assertRaises(InputError) as caught:
            evaluate(node)
        self.assertEqual(caught.exception.code, code, node)

    def test_numbers_are_exact_and_strictly_written(self):
        for node, value in ((7, F(7)), (-7, F(-7)), ("3/4", F(3, 4)), ("-3/4", F(-3, 4)),
                            ("0", F(0)), ("6/4", F(3, 2))):
            self.assertEqual(evaluate(node), value, node)
        for node in ("1.5", "007", "1/0", "+1", "1/-2", " 1", "1/02", "", "1e3"):
            self.refused(node, "KAT_NUMBER_INVALID")
        for node in (True, False, 1.5, None, [1], {}, {"add": [1], "mul": [1]}):
            self.refused(node, "KAT_EXPRESSION_INVALID")

    def test_every_arithmetic_operator(self):
        cases = (
            ({"add": [1, "1/2", "1/3"]}, F(11, 6)), ({"mul": [2, "3/4", -1]}, F(-3, 2)),
            ({"sub": [1, "1/3"]}, F(2, 3)), ({"div": [1, 3]}, F(1, 3)), ({"neg": "2/5"}, F(-2, 5)),
            ({"abs": "-2/5"}, F(2, 5)), ({"pow": ["2/3", 3]}, F(8, 27)), ({"pow": [2, -2]}, F(1, 4)),
            ({"pow": [0, 0]}, F(1)), ({"floordiv": [-7, 2]}, F(-4)), ({"mod": [-7, 2]}, F(1)),
            ({"gcd": [12, 18, 30]}, F(6)), ({"lcm": [4, 6, 10]}, F(60)), ({"gcd": [0, 5]}, F(5)),
            ({"min": [3, "1/2", 2]}, F(1, 2)), ({"max": [3, "7/2"]}, F(7, 2)),
            ({"unit_sum": [2, 3, 6]}, F(1)),
            ({"sexagesimal": {"digits": [1, 24, 51, 10], "integer_places": 1}}, F(30547, 21600)),
            ({"sexagesimal": {"digits": [30], "integer_places": 0}}, F(1, 2)),
            ({"count": []}, F(0)), ({"count": [1, {"eq": [1, 1]}, "1/2"]}, F(3)),
        )
        for node, value in cases:
            with self.subTest(node=node):
                self.assertEqual(evaluate(node), value)
                self.assertIs(type(evaluate(node)), Fraction)

    def test_every_relation_and_connective(self):
        cases = (
            ({"eq": ["2/4", "1/2"]}, True), ({"ne": [1, 1]}, False), ({"lt": [1, 2]}, True),
            ({"le": [2, 2]}, True), ({"gt": ["1/3", "1/2"]}, False), ({"ge": [3, 2]}, True),
            ({"and": [{"eq": [1, 1]}, {"lt": [1, 2]}]}, True),
            ({"and": [{"eq": [1, 1]}, {"lt": [2, 1]}]}, False),
            ({"or": [{"eq": [1, 2]}, {"lt": [1, 2]}]}, True), ({"not": {"eq": [1, 2]}}, True),
        )
        for node, value in cases:
            with self.subTest(node=node):
                self.assertIs(evaluate(node), value)

    def test_operator_refusals(self):
        cases = (
            ({"bogus": [1]}, "KAT_OPERATOR_UNKNOWN"), ({"div": [1, 0]}, "KAT_DIVISION_BY_ZERO"),
            ({"mod": [1, 0]}, "KAT_DIVISION_BY_ZERO"), ({"floordiv": ["1/2", 1]}, "KAT_INTEGER_REQUIRED"),
            ({"pow": [2, "1/2"]}, "KAT_INTEGER_REQUIRED"), ({"pow": [0, -1]}, "KAT_EXPONENT_INVALID"),
            ({"pow": [2, 4097]}, "KAT_EXPONENT_INVALID"), ({"gcd": [-2, 4]}, "KAT_NATURAL_REQUIRED"),
            ({"unit_sum": [2, 0]}, "KAT_NATURAL_REQUIRED"), ({"lcm": ["1/2"]}, "KAT_INTEGER_REQUIRED"),
            ({"sub": [1]}, "KAT_EXPRESSION_INVALID"), ({"div": [1, 2, 3]}, "KAT_EXPRESSION_INVALID"),
            ({"eq": [1]}, "KAT_EXPRESSION_INVALID"), ({"add": []}, "KAT_EXPRESSION_INVALID"),
            ({"add": 1}, "KAT_EXPRESSION_INVALID"), ({"add": [1] * 401}, "KAT_EXPRESSION_INVALID"),
            ({"add": [{"eq": [1, 1]}]}, "KAT_NUMBER_EXPECTED"), ({"lt": [{"eq": [1, 1]}, 1]},
                                                                 "KAT_NUMBER_EXPECTED"),
            ({"and": [1]}, "KAT_RELATION_EXPECTED"), ({"not": 1}, "KAT_RELATION_EXPECTED"),
            ({"sexagesimal": {"digits": [60], "integer_places": 1}}, "KAT_SEXAGESIMAL_INVALID"),
            ({"sexagesimal": {"digits": [1], "integer_places": 2}}, "KAT_SEXAGESIMAL_INVALID"),
            ({"sexagesimal": {"digits": [True], "integer_places": 1}}, "KAT_SEXAGESIMAL_INVALID"),
            ({"sexagesimal": {"digits": [1]}}, "KAT_EXPRESSION_INVALID"),
        )
        for node, code in cases:
            with self.subTest(node=str(node)[:60]):
                self.refused(node, code)

    def test_count_evaluates_every_element(self):
        self.refused({"eq": [{"count": [{"bogus": 1}, {"x": []}, None]}, 3]}, "KAT_OPERATOR_UNKNOWN")
        self.refused({"count": [None]}, "KAT_EXPRESSION_INVALID")
        self.refused({"count": [{"div": [1, 0]}]}, "KAT_DIVISION_BY_ZERO")
        self.refused({"count": [2 ** MAX_BITS]}, "KAT_NUMBER_TOO_LARGE")
        self.refused({"count": "x"}, "KAT_EXPRESSION_INVALID")

    def test_bit_size_guards_at_the_exact_boundary(self):
        def bits(value):
            return max(value.numerator.bit_length(), value.denominator.bit_length())
        fits = (2 ** MAX_BITS - 1, {"mul": [2 ** (MAX_BITS - 2), 2]}, {"pow": [16, 3249]},
                {"add": [2 ** (MAX_BITS - 2), 2 ** (MAX_BITS - 2)]}, {"lcm": [2 ** (MAX_BITS - 2), 3]},
                {"div": [1, 2 ** MAX_BITS - 1]}, {"pow": [7, 4096]}, {"pow": [10, 3913]})
        for node in fits:
            with self.subTest(fits=str(node)[:40]):
                self.assertLessEqual(bits(evaluate(node)), MAX_BITS)
        too_large = (2 ** MAX_BITS, -(2 ** MAX_BITS), {"mul": [2 ** (MAX_BITS - 1), 2]},
                     {"pow": [16, 3250]}, {"pow": [10, 4096]}, {"pow": ["1/16", 3250]},
                     {"add": [2 ** (MAX_BITS - 1), 2 ** (MAX_BITS - 1)]},
                     {"lcm": [2 ** (MAX_BITS - 1), 3]}, {"unit_sum": [2 ** (MAX_BITS - 1), 3]},
                     {"mul": [2 ** 7000, 2 ** 7000, {"pow": ["1/2", 1]}]})
        for node in too_large:
            with self.subTest(too_large=str(node)[:40]):
                self.refused(node, "KAT_NUMBER_TOO_LARGE")

    def test_numbers_beyond_the_int_text_limit_are_typed_refusals(self):
        previous = sys.get_int_max_str_digits()
        sys.set_int_max_str_digits(4300)
        try:
            self.refused(10 ** 5000, "KAT_NUMBER_TOO_LARGE")
            self.refused({"pow": [10, 4000]}, "KAT_NUMBER_TOO_LARGE")
            self.assertEqual(len(str(evaluate({"pow": [10, 3913]}).numerator)), 3914)
        finally:
            sys.set_int_max_str_digits(previous)

    def test_expression_budget(self):
        deep = 1
        for _ in range(kat.MAX_DEPTH + 1):
            deep = {"neg": deep}
        self.refused(deep, "KAT_EXPRESSION_TOO_LARGE")
        wide = {"add": [{"add": [1] * 400}] * 11}
        self.refused(wide, "KAT_EXPRESSION_TOO_LARGE")


class BindingTests(TestCase):
    def setUp(self):
        self.census = census_of({"src/a.lean": SOURCE})
        self.cords = {c["key"]: c for c in self.census["cords"]}

    def state(self, item, *bodies, census=None):
        cords = self.cords if census is None else {c["key"]: c for c in census["cords"]}
        return binding(item, cords, reader(*bodies) if bodies else None)

    def test_bound_needs_the_transcribed_blob_and_the_anchor_at_the_stated_line(self):
        self.assertEqual(self.state(answer("four"), SOURCE), BOUND)
        self.assertEqual(self.state(answer("four", anchor="  " + ANCHORS["four"][1] + "  "),
                                    SOURCE), BOUND)

    def test_anchor_at_another_line_is_misplaced_never_bound(self):
        self.assertEqual(self.state(answer("four", line=3), SOURCE), MISPLACED)
        self.assertEqual(self.state(answer("four", line=999999), SOURCE), MISPLACED)
        self.assertEqual(self.state(answer("four", anchor="theorem nowhere := rfl"), SOURCE),
                         MISPLACED)

    def test_changed_file_rebinds_only_by_a_unique_exact_line(self):
        changed = census_of({"src/a.lean": CHANGED})
        self.assertEqual(self.state(answer("four"), CHANGED, census=changed), REBOUND)
        doubled = CHANGED + ANCHORS["four"][1].encode() + b"\n"
        twice = census_of({"src/a.lean": doubled})
        self.assertEqual(self.state(answer("four"), doubled, census=twice), STALE)
        removed = SOURCE.replace(ANCHORS["four"][1].encode(), b"theorem four := rfl")
        gone = census_of({"src/a.lean": removed})
        self.assertEqual(self.state(answer("four"), removed, census=gone), STALE)

    def test_source_absent_from_the_census(self):
        self.assertEqual(self.state(answer("four", path="src/other.lean"), SOURCE), ABSENT)
        self.assertEqual(self.state(answer("four", repository="szl-holdings/beta"), SOURCE), ABSENT)

    def test_bytes_not_read_are_unread(self):
        self.assertEqual(self.state(answer("four")), UNREAD)
        self.assertEqual(self.state(answer("four"), CHANGED), UNREAD)

        def raising(repository, blob_sha1):
            raise InputError("CENSUS_BLOB_PARSE_FAILED")
        self.assertEqual(binding(answer("four"), self.cords, raising), UNREAD)
        self.assertEqual(binding(answer("four"), self.cords, lambda r, b: SOURCE.decode()), UNREAD)
        self.assertEqual(binding(answer("four"), self.cords, lambda r, b: CHANGED), UNREAD)

    def test_binding_states_are_closed(self):
        self.assertEqual(set(BINDINGS), {BOUND, REBOUND, STALE, ABSENT, MISPLACED, UNREAD})


class CheckTests(TestCase):
    def setUp(self):
        self.census = census_of({"src/a.lean": SOURCE})
        self.read = reader(SOURCE)

    def run_check(self, *answers, read=None):
        return check(answer_set(*answers), self.census, read_current=read or self.read,
                     set_sha256="a" * 64, census_sha256="b" * 64)

    def test_verdicts_and_every_count_are_exposed(self):
        report = self.run_check(answer("four"), answer("seven"), answer("wrong"))
        self.assertEqual(report["schema"], SCHEMA)
        self.assertEqual([r["verdict"] for r in report["results"]], ["PASS", "PASS", "FAIL"])
        for name in SUMMARY_COUNTS:
            self.assertIs(type(report[name]), int, name)
        self.assertEqual((report["answers"], report["evaluated"], report["passed"],
                          report["failed"]), (3, 3, 2, 1))
        self.assertEqual(report["families"], {"ARITHMETIC_CHECK": {"evaluated": 3, "passed": 2}})
        for flag in kat._FALSE_FLAGS:
            self.assertIs(report[flag], False)
        self.assertTrue(validate_report(report))

    def test_misplaced_anchor_is_never_a_pass_and_stays_in_the_total(self):
        report = self.run_check(answer("four", line=3), answer("seven"))
        self.assertEqual((row(report, "four")["binding"], row(report, "four")["verdict"]),
                         (MISPLACED, "NOT_EVALUATED"))
        self.assertEqual((report["answers"], report["evaluated"], report["passed"],
                          report["anchor_not_at_line"]), (2, 1, 1, 1))
        self.assertEqual(report["answers"], report["evaluated"] + report["stale"] +
                         report["source_not_in_census"] + report["anchor_not_at_line"] +
                         report["source_bytes_not_read"])

    def test_every_unscored_state_is_counted(self):
        stale = census_of({"src/a.lean": CHANGED, "src/b.lean": SOURCE})
        report = check(answer_set(answer("four"), answer("seven", anchor="theorem gone := rfl"),
                                  answer("wrong", path="src/c.lean")),
                       stale, read_current=reader(CHANGED))
        self.assertEqual([r["binding"] for r in report["results"]], [REBOUND, STALE, ABSENT])
        self.assertEqual((report["rebound_by_line"], report["stale"], report["source_not_in_census"],
                          report["evaluated"], report["answers"]), (1, 1, 1, 1, 3))
        unread = check(answer_set(answer("four")), self.census, read_current=None)
        self.assertEqual((unread["source_bytes_not_read"], unread["evaluated"]), (1, 0))

    def test_an_arithmetic_error_in_one_answer_refuses_only_that_answer(self):
        real = kat.evaluate
        for error in (ValueError("Exceeds the limit (4300 digits)"), ZeroDivisionError(),
                      OverflowError(), RecursionError()):
            def flaky(node, budget=None, depth=0, error=error):
                if node == CLAIMS["seven"]:
                    raise error
                return real(node, budget, depth)
            with self.subTest(error=type(error).__name__), mock.patch.object(kat, "evaluate", flaky):
                report = self.run_check(answer("four"), answer("seven"), answer("wrong"))
                self.assertEqual((row(report, "seven")["verdict"], row(report, "seven")["detail"]),
                                 ("INVALID_CLAIM", "KAT_ARITHMETIC_ERROR"))
                self.assertEqual((row(report, "four")["verdict"], row(report, "wrong")["verdict"]),
                                 ("PASS", "FAIL"))
                self.assertEqual((report["invalid_claims"], report["evaluated"]), (1, 3))
                self.assertTrue(validate_report(report))

    def test_typed_refusals_inside_a_claim_stay_with_that_claim(self):
        report = self.run_check(answer("four", claim={"eq": [{"div": [1, 0]}, 1]}),
                                answer("seven", claim={"add": [1, 2]}), answer("wrong"))
        self.assertEqual(row(report, "four")["detail"], "KAT_DIVISION_BY_ZERO")
        self.assertEqual(row(report, "seven")["detail"], "KAT_CLAIM_NOT_A_RELATION")
        self.assertEqual(row(report, "wrong")["verdict"], "FAIL")
        big = self.run_check(answer("four", claim={"eq": [2 ** (MAX_BITS + 5), 1]}))
        self.assertEqual(row(big, "four")["detail"], "KAT_NUMBER_TOO_LARGE")

    def test_census_shape_is_checked(self):
        for census in (None, {}, {"cords": {}}, {"cords": [None]}, {"cords": [{"key": "x"}]},
                       {"cords": [{"key": 1, "blob_sha1": "a" * 40}]},
                       {"cords": [{"key": "x", "blob_sha1": "A" * 40}]},
                       {"cords": [{"key": "x", "blob_sha1": "a" * 40}] * 2}):
            with self.subTest(census=str(census)[:50]):
                with self.assertRaises(InputError) as caught:
                    check(answer_set(answer("four")), census, read_current=self.read)
                self.assertEqual(caught.exception.code, "KAT_CENSUS_INVALID")


class ValidateReportTests(TestCase):
    @classmethod
    def setUpClass(cls):
        census = census_of({"src/a.lean": SOURCE})
        cls.report = check(answer_set(answer("four"), answer("seven", line=2), answer("wrong")),
                           census, read_current=reader(SOURCE), set_sha256="a" * 64)

    def refused(self, mutate, code):
        value = deepcopy(self.report)
        mutate(value)
        with self.assertRaises(InputError) as caught:
            validate_report(value)
        self.assertEqual(caught.exception.code, code)

    def test_untampered_report_validates(self):
        self.assertTrue(validate_report(deepcopy(self.report)))
        self.assertEqual(self.report["anchor_not_at_line"], 1)

    def test_totals_drift_is_refused(self):
        for field in ("evaluated", "passed", "failed", "invalid_claims", "stale",
                      "source_not_in_census", "anchor_not_at_line", "source_bytes_not_read",
                      "rebound_by_line"):
            with self.subTest(field=field):
                self.refused(lambda v: v.update({field: v[field] + 1}), "KAT_REPORT_TOTALS_DRIFT")
        self.refused(lambda v: v.update(passed=v["passed"] + 1, failed=v["failed"] - 1),
                     "KAT_REPORT_TOTALS_DRIFT")
        self.refused(lambda v: v.update(evaluated=-1), "KAT_REPORT_FIELDS_INVALID")
        self.refused(lambda v: v.update(passed=True), "KAT_REPORT_FIELDS_INVALID")

    def test_families_are_re_derived(self):
        self.refused(lambda v: v["families"]["ARITHMETIC_CHECK"].update(passed=2),
                     "KAT_REPORT_TOTALS_DRIFT")
        self.refused(lambda v: v["families"].update(EXTRA_FAMILY={"evaluated": 0, "passed": 0}),
                     "KAT_REPORT_TOTALS_DRIFT")
        self.refused(lambda v: v["families"].pop("ARITHMETIC_CHECK"), "KAT_REPORT_TOTALS_DRIFT")

        def relabel(value):
            value["results"][0]["family"] = "OTHER_FAMILY"
        self.refused(relabel, "KAT_REPORT_TOTALS_DRIFT")

    def test_family_names_follow_the_pattern(self):
        for bad in ("lowercase", "A", "A" * 49, "1ABC", "AB-CD", "", None):
            with self.subTest(bad=bad):
                self.refused(lambda v: v["results"][0].update(family=bad), "KAT_REPORT_ROW_INVALID")
        good = deepcopy(self.report)
        for item in good["results"]:
            item["family"] = "A1"
        good["families"] = {"A1": {"evaluated": 2, "passed": 1}}
        self.assertTrue(validate_report(good))

    def test_row_tampering_is_refused(self):
        misplaced = next(i for i, r in enumerate(self.report["results"]) if r["binding"] == MISPLACED)
        self.refused(lambda v: v["results"][misplaced].update(verdict="PASS"), "KAT_REPORT_ROW_INVALID")
        self.refused(lambda v: v["results"][misplaced].update(binding=BOUND), "KAT_REPORT_ROW_INVALID")
        self.refused(lambda v: v["results"][0].update(binding="BOUND"), "KAT_REPORT_ROW_INVALID")
        self.refused(lambda v: v["results"][0].update(detail="KAT_NUMBER_TOO_LARGE"),
                     "KAT_REPORT_ROW_INVALID")
        self.refused(lambda v: v["results"][0].update(line=0), "KAT_REPORT_ROW_INVALID")
        self.refused(lambda v: v["results"][0].update(line=True), "KAT_REPORT_ROW_INVALID")
        self.refused(lambda v: v["results"][0].update(repository="other/alpha"), "KAT_REPORT_ROW_INVALID")
        self.refused(lambda v: v["results"][0].update(id="T-UPPER"), "KAT_REPORT_ROW_INVALID")
        self.refused(lambda v: v["results"].reverse(), "KAT_REPORT_ROW_INVALID")

        def duplicate(value):
            value["results"][1] = deepcopy(value["results"][0])
        self.refused(duplicate, "KAT_REPORT_ROW_INVALID")
        self.refused(lambda v: v["results"][0].update(signed=False), "KAT_REPORT_FIELDS_INVALID")
        self.refused(lambda v: v["results"].pop(), "KAT_REPORT_FIELDS_INVALID")

    def test_invalid_claim_rows_carry_a_refusal_code(self):
        value = deepcopy(self.report)
        first = value["results"][0]
        first.update(verdict="INVALID_CLAIM", detail=None)
        value.update(passed=value["passed"] - 1, invalid_claims=1)
        value["families"]["ARITHMETIC_CHECK"]["passed"] -= 1
        with self.assertRaises(InputError):
            validate_report(value)
        first["detail"] = "KAT_ARITHMETIC_ERROR"
        self.assertTrue(validate_report(value))
        first["detail"] = "not a code"
        with self.assertRaises(InputError):
            validate_report(value)

    def test_authority_and_schema_flags(self):
        for flag in kat._FALSE_FLAGS:
            self.refused(lambda v: v.update({flag: True}), "KAT_FALSE_AUTHORITY_CLAIM")
        self.refused(lambda v: v.update(arithmetic="FLOAT"), "KAT_FALSE_AUTHORITY_CLAIM")
        self.refused(lambda v: v.update(schema=SCHEMA + "x"), "KAT_FALSE_AUTHORITY_CLAIM")
        self.refused(lambda v: v.update(review_status="RATIFIED"), "KAT_REPORT_FIELDS_INVALID")
        self.refused(lambda v: v.update(census_sha256="B" * 64), "KAT_REPORT_FIELDS_INVALID")
        self.refused(lambda v: v.update(extra=1), "KAT_REPORT_FIELDS_INVALID")


class AnswerSetTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = CONTRACT.read_bytes()
        cls.shipped = json.loads(cls.raw)

    def refused(self, mutate, code):
        value = deepcopy(answer_set(answer("four"), answer("seven")))
        mutate(value)
        with self.assertRaises(InputError) as caught:
            validate_set(value)
        self.assertEqual(caught.exception.code, code)

    def test_set_refusals(self):
        self.refused(lambda v: v.update(schema="x"), "KAT_SET_FIELDS_INVALID")
        self.refused(lambda v: v.update(answers=[]), "KAT_SET_FIELDS_INVALID")
        self.refused(lambda v: v["answers"].reverse(), "KAT_ANSWER_ORDER_OR_DUPLICATE")
        self.refused(lambda v: v["answers"].append(deepcopy(v["answers"][-1])),
                     "KAT_ANSWER_ORDER_OR_DUPLICATE")
        for field, bad in (("family", "lower"), ("anchor", "two\nlines"), ("anchor", "   "),
                           ("statement", "x" * 401), ("id", "Upper-case"), ("claim", [1])):
            with self.subTest(field=field):
                self.refused(lambda v: v["answers"][0].update({field: bad}), "KAT_ANSWER_FIELDS_INVALID")
        for field, bad in (("line", 0), ("line", True), ("blob_sha1", "A" * 40),
                           ("repository", "other/alpha")):
            with self.subTest(field=field):
                self.refused(lambda v: v["answers"][0]["source"].update({field: bad}),
                             "KAT_ANSWER_FIELDS_INVALID")
        self.refused(lambda v: v["answers"][0].update(signed=False), "KAT_ANSWER_FIELDS_INVALID")

    def test_shipped_set_validates_and_is_serialised_like_every_contract(self):
        answers = validate_set(self.shipped)
        self.assertEqual(len(answers), 46)
        self.assertEqual(self.raw, (json.dumps(self.shipped, indent=2, ensure_ascii=True) + "\n")
                         .encode("ascii"))
        rule = "/governance/database_contracts/*.json text eol=lf"
        self.assertIn(rule, (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines())

    def test_shipped_labels_name_the_subject_not_a_tradition(self):
        by_id = {a["id"]: a for a in self.shipped["answers"]}
        for item in self.shipped["answers"]:
            # No answer reads a codex, so none is named as if it did.
            self.assertFalse(item["id"].startswith("codex-"), item["id"])
        for name in ("52-weeks", "mod7", "quarter-weeks", "quarters"):
            self.assertEqual(by_id[f"lean-enoch-{name}"]["family"], "CALENDAR_ASTRONOMY")
        for name in ("lambda-nine-axis-weight-sum", "lambda-nine-axis-denominators-regular"):
            self.assertEqual(by_id[name]["family"], "LAMBDA_CORE")
        heron = by_id["bab-ybc-heron-iterate-header"]["statement"]
        self.assertIn("which line 5 itself attributes to 'the tablet'", heron)
        self.assertIn("'Calendar Round' is the source file's own name",
                      by_id["maya-calendar-round-lcm"]["statement"])
        for item in self.shipped["answers"]:
            text = item["statement"]
            if "tablet" in text or "Calendar Round" in text:
                self.assertTrue("attributes to" in text or "own name" in text, item["id"])

    def test_shipped_family_map_labels(self):
        families = json.loads(FAMILY_MAP.read_text(encoding="utf-8"))["families"]
        lean = families["szl-holdings/lutar-lean"]
        expected = {
            "Lutar/Innovations/round4/ELSBonferroniBound.lean": "PROBABILITY_STATISTICS",
            "Lutar/Innovations/round4/EnochEpochAlignment.lean": "CALENDAR_ASTRONOMY",
            "Lutar/KhipuConsensus.lean": "CONSENSUS_BFT",
            "Lutar/Khipu/MerkleFunctor.lean": "CRYPTO_PROVENANCE",
            "Lutar/Propagation/RelayChain.lean": "CRYPTO_PROVENANCE",
            "Lutar/Transduction/ReceiptInvariant.lean": "CRYPTO_PROVENANCE",
        }
        for path, family in expected.items():
            self.assertEqual(lean[path], family, path)

    def test_every_shipped_claim_evaluates_and_the_one_wrong_value_stays_wrong(self):
        outcomes = {a["id"]: evaluate(a["claim"]) for a in self.shipped["answers"]}
        self.assertTrue(all(type(v) is bool for v in outcomes.values()))
        # 1;24,51,10 = 30547/21600 is not the second Heron iterate 17/12: reported, never fixed.
        self.assertEqual([k for k, v in outcomes.items() if not v], ["bab-ybc-heron-iterate-header"])


def git(repo, *args):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(repo.parent),
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "Synthetic Fixture",
           "GIT_AUTHOR_EMAIL": "fixture@example.invalid", "GIT_COMMITTER_NAME": "Synthetic Fixture",
           "GIT_COMMITTER_EMAIL": "fixture@example.invalid", "GIT_TERMINAL_PROMPT": "0",
           "LC_ALL": "C"}
    subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", *args],
                   cwd=str(repo), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                   check=True, timeout=60)


class CliTests(TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.repo = self.base / "alpha"
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "src" / "a.lean").write_bytes(SOURCE)
        git(self.repo, "init", "-q")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "synthetic fixture")
        section = {"max_cords": 10, "max_blob_bytes": 4096,
                   "repositories": [{"repository": REPO, "include": ["src/*"], "exclude": [],
                                     "families": []}]}
        census = observe(section, {REPO: self.repo}, at=datetime(2026, 11, 19, tzinfo=timezone.utc))
        self.census = self.base / "census.json"
        self.census.write_text(json.dumps(census))

    def run_main(self, answers, *extra, output="out.json"):
        path = self.base / "answers.json"
        path.write_text(json.dumps(answer_set(*answers)))
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main(["--answers", str(path), "--census", str(self.census),
                         "--output", str(self.base / output), *extra])
        lines = buffer.getvalue().strip().splitlines()
        self.assertEqual(len(lines), 1)
        return code, json.loads(lines[0])

    def test_clean_run_is_exit_zero_and_prints_every_count(self):
        code, summary = self.run_main([answer("four"), answer("seven")],
                                      "--checkout", f"{REPO}={self.repo}")
        self.assertEqual(code, 0)
        self.assertEqual(set(summary), set(SUMMARY_COUNTS) | {"production_authorized"})
        self.assertEqual((summary["answers"], summary["evaluated"], summary["passed"]), (2, 2, 2))
        self.assertIs(summary["production_authorized"], False)
        written = json.loads((self.base / "out.json").read_bytes())
        self.assertTrue(validate_report(written))
        code, summary = self.run_main([answer("four")], "--checkout", f"{REPO}={self.repo}")
        self.assertEqual((code, summary["code"]), (3, "OUTPUT_PATH_DENIED"))

    def test_any_unevaluated_or_failed_answer_is_exit_two(self):
        code, summary = self.run_main([answer("four"), answer("seven", line=1)],
                                      "--checkout", f"{REPO}={self.repo}")
        self.assertEqual((code, summary["anchor_not_at_line"], summary["passed"]), (2, 1, 1))
        code, summary = self.run_main([answer("wrong")], "--checkout", f"{REPO}={self.repo}",
                                      output="failed.json")
        self.assertEqual((code, summary["failed"]), (2, 1))
        code, summary = self.run_main([answer("four")], output="unread.json")
        self.assertEqual((code, summary["source_bytes_not_read"], summary["evaluated"]), (2, 1, 0))

    def test_a_checkout_that_is_not_a_top_level_work_tree_is_refused(self):
        code, summary = self.run_main([answer("four")], "--checkout", f"{REPO}={self.repo / 'src'}")
        self.assertEqual((code, summary["state"], summary["code"]),
                         (3, "UNAVAILABLE", "CENSUS_CHECKOUT_NOT_TOP_LEVEL"))
        self.assertFalse((self.base / "out.json").exists())
        code, summary = self.run_main([answer("four")], "--checkout", f"{REPO}={self.base / 'nope'}")
        self.assertEqual((code, summary["code"]), (3, "CENSUS_CHECKOUT_UNAVAILABLE"))


if __name__ == "__main__":
    unittest_main()
