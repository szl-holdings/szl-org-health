#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline contracts for the Ouroboros braid v2 orchestrator.

A small synthetic estate (temporary git repositories) is censused with the real
census code, known answers are checked with the real evaluator and database
plans come from the real planner, so every turn here runs the real verifiers.
Witness-level logic (kernel state, veto ladder, ratchet across turns) is tested
on the pure derivation functions with hand-built, internally consistent
sections. No network, no Lean, no Hatun, no database.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from fractions import Fraction
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import TestCase, main as unittest_main

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import database_braid_codex_kat as kat  # noqa: E402
from tools import database_braid_source_census as census_tool  # noqa: E402
from tools import database_ouroboros_braid_v2 as braid  # noqa: E402
from tools.database_braid_common import canonical, git_blob_sha1, sha256_hex  # noqa: E402
from tools.database_braid_khipu_tree import build  # noqa: E402
from tools.database_catalog_admission import InputError  # noqa: E402

POLICY_PATH = ROOT / "governance/database_contracts/ouroboros_braid_v2.json"
POLICY = json.loads(POLICY_PATH.read_text())
ACTION_POLICY = json.loads(
    (ROOT / "governance/database_contracts/database_agentic_actions_v1.json").read_text())
SOURCE_POLICY = json.loads(
    (ROOT / "governance/database_contracts/memory_covenant_v2.json").read_text())
AT = datetime(2026, 11, 19, 12, 0, 0, tzinfo=timezone.utc)
LEAN_REPO, HATUN_REPO, LAKE_REPO = ("szl-holdings/lutar-lean", "szl-holdings/hatun-mcp",
                                    "szl-holdings/szl-lake")
FILES = {
    HATUN_REPO: {"hatun_mcp/__init__.py": "VERSION = 1\n", "hatun_mcp/gate.py": "DENY = True\n"},
    LEAN_REPO: {"Lutar/Alpha.lean": "theorem alpha : True := trivial\n",
                "Lutar/Beta.lean": "theorem beta : 1 = 1 := by\n  sorry\n",
                "README.md": "corpus\n"},
    LAKE_REPO: {"szl_lake_receipt.py": "SCHEMA = 1\n"},
}


def _git(directory, *args):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(directory),
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
           "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
           "GIT_AUTHOR_DATE": "2026-11-19T12:00:00Z", "GIT_COMMITTER_DATE": "2026-11-19T12:00:00Z"}
    return subprocess.run(["git", *args], cwd=directory, env=env, check=True,
                          capture_output=True, text=True).stdout.strip()


def make_estate(base: Path) -> dict:
    checkouts = {}
    for repository, files in FILES.items():
        directory = base / repository.split("/", 1)[1]
        for rel, text in files.items():
            path = directory / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        _git(directory, "init", "-q", "-b", "main")
        _git(directory, "add", "-A")
        _git(directory, "commit", "-q", "-m", "fixture")
        _git(directory, "remote", "add", "origin", "https://github.com/" + repository + ".git")
        checkouts[repository] = directory
    return checkouts


def test_policy() -> dict:
    policy = deepcopy(POLICY)
    policy["census"]["repositories"] = [
        {"repository": HATUN_REPO, "include": ["hatun_mcp/*"], "exclude": [],
         "families": [{"glob": "*", "family": "VETO_GATE"}]},
        {"repository": LEAN_REPO, "include": ["*.lean", "*.md"], "exclude": [],
         "families": [{"glob": "*", "family": "LEAN_CORPUS"}]},
        {"repository": LAKE_REPO, "include": ["*.py"], "exclude": [],
         "families": [{"glob": "*", "family": "LAKE_RECEIPT"}]},
    ]
    return policy


def answer_set(checkouts, *, beta_blob=None, beta_line=2, beta_anchor="sorry"):
    alpha = (checkouts[LEAN_REPO] / "Lutar/Alpha.lean").read_bytes()
    beta = (checkouts[LEAN_REPO] / "Lutar/Beta.lean").read_bytes()
    return {"schema": kat.SET_SCHEMA, "review_status": "MACHINE_TRANSCRIBED_UNRATIFIED",
            "answers": [
                {"id": "lean-alpha-product", "family": "ARITHMETIC",
                 "source": {"repository": LEAN_REPO, "path": "Lutar/Alpha.lean", "line": 1,
                            "blob_sha1": git_blob_sha1(alpha)},
                 "anchor": "theorem alpha : True := trivial",
                 "statement": "fixture: 2*3 = 6", "claim": {"eq": [{"mul": [2, 3]}, 6]}},
                {"id": "lean-beta-wrong-sum", "family": "ARITHMETIC",
                 "source": {"repository": LEAN_REPO, "path": "Lutar/Beta.lean",
                            "line": beta_line, "blob_sha1": beta_blob or git_blob_sha1(beta)},
                 "anchor": beta_anchor,
                 "statement": "fixture: 1+1 = 3 must FAIL", "claim": {"eq": [{"add": [1, 1]}, 3]}},
            ]}


def database_plans():
    from tests import test_database_agentic_planner as planner
    catalog, frontier = planner.catalog(), planner.frontier()
    catalog.update(state="CATALOG_MATCH_ONLY", gap_count=0, gaps=[], observed_tables=8)
    frontier.update(state="STRUCTURAL_FRONTIER_MATCH_ONLY", gap_count=0, gaps=[],
                    coverage_numerator=4, observed_stage_count=4)
    return planner.plan(catalog, frontier, planner.role(1)), planner.plan()


class Estate:
    """One synthetic estate censused once; turns are cheap to braid from it."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.checkouts = make_estate(Path(self.tmp.name))
        self.policy = test_policy()
        self.policy_sha = sha256_hex(json.dumps(self.policy, sort_keys=True).encode())
        self.census = census_tool.observe(self.policy["census"], self.checkouts, at=AT,
                                          policy_sha256=self.policy_sha)
        self.census_sha = sha256_hex(canonical(self.census))

    def read_current(self, repository, blob):
        directory = self.checkouts.get(repository)
        if directory is None:
            return None
        return census_tool.read_blobs(directory, [blob], max_bytes=kat.MAX_BLOB_BYTES).get(blob)

    def answers(self, **kwargs):
        return kat.check(answer_set(self.checkouts, **kwargs), self.census,
                         read_current=self.read_current, set_sha256="c" * 64,
                         census_sha256=self.census_sha)

    def digests(self, **extra):
        return {"policy": self.policy_sha, "census": self.census_sha, **extra}

    def turn(self, **kwargs):
        kwargs.setdefault("input_digests", self.digests())
        return braid.turn(self.policy, self.census, **kwargs)


ESTATE = None


def setUpModule():
    global ESTATE
    ESTATE = Estate()


def tearDownModule():
    ESTATE.tmp.cleanup()


def refused(test, code, fn, *args, **kwargs):
    with test.assertRaises(InputError) as caught:
        fn(*args, **kwargs)
    test.assertEqual(caught.exception.code, code)


class PolicyTests(TestCase):
    def test_committed_policy_validates_and_pins_the_new_fields(self):
        braid.validate_policy(deepcopy(POLICY))
        self.assertEqual(POLICY["khipu"]["knots"], braid.KNOTS)
        self.assertIn("lean_theorem_counts_unknown", POLICY["khipu"]["knots"])
        self.assertEqual(POLICY["decision"]["evidence_window_seconds"], 86400)
        self.assertEqual(tuple(POLICY["ratchet"]["floor"]), braid.FLOOR_FIELDS)
        roles = {c["role"] for c in POLICY["lean"]["carrier_theorems"]}
        self.assertIn("KHIPU_ROOT_BUMP_CHANGES_TOTAL_RELATED_MODEL", roles)
        self.assertNotIn("KHIPU_SUM_OF_SUMS_TAMPER_EVIDENCE", roles)

    def test_committed_policy_bytes_are_the_contract_formatting(self):
        raw = POLICY_PATH.read_bytes()
        self.assertEqual(raw, (json.dumps(json.loads(raw), indent=2, ensure_ascii=True) +
                               "\n").encode())

    def test_window_outside_bounds_refused(self):
        for window in (59, 31 * 86400 + 1, True, "86400"):
            policy = deepcopy(POLICY)
            policy["decision"]["evidence_window_seconds"] = window
            refused(self, "BRAID_DECISION_POLICY_INVALID", braid.validate_policy, policy)

    def test_floor_without_a_debt_field_refused(self):
        policy = deepcopy(POLICY)
        del policy["ratchet"]["floor"]["theorems_native_decide_max"]
        refused(self, "BRAID_RATCHET_POLICY_INVALID", braid.validate_policy, policy)

    def test_knot_list_must_match_exactly(self):
        policy = deepcopy(POLICY)
        policy["khipu"]["knots"].remove("lean_theorem_counts_unknown")
        refused(self, "BRAID_KHIPU_POLICY_INVALID", braid.validate_policy, policy)

    def test_witnessed_repository_must_be_in_the_census(self):
        policy = deepcopy(POLICY)
        policy["census"]["repositories"] = [r for r in policy["census"]["repositories"]
                                            if r["repository"] != HATUN_REPO]
        refused(self, "BRAID_POLICY_REPOSITORY_NOT_IN_CENSUS", braid.validate_policy, policy)

    def test_authority_claim_refused(self):
        policy = deepcopy(POLICY)
        policy["fixed_claims"]["production_authority"] = "GRANTED"
        refused(self, "BRAID_AUTHORITY_CLAIM_REFUSED", braid.validate_policy, policy)


class CensusOnlyTurnTests(TestCase):
    def setUp(self):
        self.report, self.tree = ESTATE.turn()

    def test_absent_evidence_refuses_with_named_reasons_and_no_score(self):
        decision = self.report["decision"]
        self.assertEqual(self.report["state"], braid.STATE_HOLD)
        self.assertEqual(decision["refusal_path"], "PRE_AGGREGATION")
        self.assertEqual(decision["sub_reasons"], [
            "LEAN_WITNESS_NOT_SUPPLIED", "HATUN_WITNESS_NOT_SUPPLIED",
            "KNOWN_ANSWERS_NOT_SUPPLIED", "DATABASE_PLAN_NOT_SUPPLIED"])
        self.assertIsNone(decision["exact"])
        self.assertEqual(decision["axes_computed"], {"source_cords_present": "1/1"})
        self.assertEqual(decision["axis_labels"], {"source_cords_present": "REPORTED"})
        self.assertEqual(self.report["termination"], "CLOSED_WITH_HOLD")
        for name in ("lean", "hatun", "known_answers", "database"):
            self.assertEqual(self.report[name]["label"], "UNAVAILABLE", name)

    def test_unjudged_lean_files_are_unknown_not_zero(self):
        total = self.report["khipu"]["primary_sum"]
        self.assertEqual(total["lean_files"], 2)
        self.assertEqual(total["lean_not_judged"], 2)
        self.assertEqual(total["lean_theorem_counts_unknown"], 2)
        self.assertEqual(total["user_theorems"], 0)
        self.assertEqual(self.report["lean"]["theorem_counts_scope"],
                         "KERNEL_ACCEPTED_MODULES_ONLY")

    def test_report_verifies_and_replays_byte_identically(self):
        self.assertTrue(braid.verify_turn(self.report, policy_for_shape=ESTATE.policy,
                                          tree=self.tree))
        self.assertTrue(braid.replay_turn(self.report, ESTATE.policy, ESTATE.census,
                                          input_digests=ESTATE.digests()))

    def test_replay_from_other_evidence_diverges(self):
        census = deepcopy(ESTATE.census)
        census["observed_at"] = (AT + timedelta(seconds=1)).isoformat()
        refused(self, "BRAID_TURN_REPLAY_DIVERGED", braid.replay_turn, self.report,
                ESTATE.policy, census, input_digests=ESTATE.digests())

    def test_census_rows_record_and_require_a_matching_checkout(self):
        identities = {r["repository"]: r["checkout_identity"]
                      for r in self.report["census"]["repositories"]}
        self.assertEqual(set(identities.values()), {"ORIGIN_MATCHES"})
        census = deepcopy(ESTATE.census)
        census["repositories"][0]["checkout_identity"] = "ORIGIN_DIFFERS"
        report, _ = braid.turn(ESTATE.policy, census, input_digests=ESTATE.digests())
        self.assertIn("CENSUS_CHECKOUT_IDENTITY_UNVERIFIED", report["decision"]["sub_reasons"])

    def test_a_relabelled_family_is_refused_not_braided(self):
        census = deepcopy(ESTATE.census)
        census["cords"][0]["family"] = "SOMETHING_ELSE"
        with self.assertRaises(InputError):
            braid.turn(ESTATE.policy, census, input_digests=ESTATE.digests())

    def test_a_census_taken_with_a_family_map_needs_that_map(self):
        census = deepcopy(ESTATE.census)
        census["family_map_sha256"] = "9" * 64
        refused(self, "BRAID_FAMILY_MAP_REQUIRED", braid.turn, ESTATE.policy, census,
                input_digests=ESTATE.digests())
        refused(self, "BRAID_FAMILY_MAP_REQUIRED", ESTATE.turn, family_map={},
                family_map_sha256="9" * 64)

    def test_genesis_is_never_a_fixed_point(self):
        self.assertIs(self.report["ouroboros_fixed_point"], False)
        self.assertEqual(self.report["ratchet"]["against_previous_turn"]["state"],
                         "GENESIS_NO_PREVIOUS_TURN")

    def test_measured_label_only_for_evidence_produced_in_this_invocation(self):
        report, _ = ESTATE.turn(produced=["census"])
        self.assertEqual(report["census"]["label"], "MEASURED")
        self.assertEqual(report["decision"]["axis_labels"], {"source_cords_present": "MEASURED"})
        self.assertNotEqual(report["state_digest"], self.report["state_digest"])

    def test_produced_claim_without_the_evidence_refused(self):
        refused(self, "BRAID_PRODUCED_EVIDENCE_INVALID", ESTATE.turn, produced=["lean_witness"])
        refused(self, "BRAID_PRODUCED_EVIDENCE_INVALID", ESTATE.turn,
                produced=["census", "census"])
        refused(self, "BRAID_PRODUCED_EVIDENCE_INVALID", ESTATE.turn, produced=["database"])


class ForgeryTests(TestCase):
    """Every edit of a verdict, a derived field or an observed section must be refused."""

    def setUp(self):
        plan, _ = database_plans()
        self.report, self.tree = ESTATE.turn(
            kat_report=ESTATE.answers(), db_plan=plan, action_policy=deepcopy(ACTION_POLICY),
            source_policy=deepcopy(SOURCE_POLICY),
            input_digests=ESTATE.digests(database_plan="d" * 64))

    def forged(self, mutate, code):
        report = deepcopy(self.report)
        mutate(report)
        refused(self, code, braid.verify_turn, report, policy_for_shape=ESTATE.policy,
                tree=self.tree)

    def test_the_untouched_report_verifies(self):
        self.assertTrue(braid.verify_turn(self.report, policy_for_shape=ESTATE.policy,
                                          tree=self.tree))
        self.assertEqual(self.report["decision"]["sub_reasons"],
                         ["LEAN_WITNESS_NOT_SUPPLIED", "HATUN_WITNESS_NOT_SUPPLIED"])

    def test_forged_met_with_all_axes_one_refused(self):
        def met(report):
            report["decision"].update(refusal_path="NONE", sub_reasons=[], axes_missing=[],
                                      axes_computed={a: "1/1" for a in braid.AXES})
            report["state"] = braid.STATE_MET
            report["termination"] = "CLOSED_EVIDENCE_COMPLETE_NO_AUTHORITY"
        self.forged(met, "BRAID_TURN_DERIVATION_DRIFT")

    def test_dropped_reason_refused(self):
        self.forged(lambda r: r["decision"]["sub_reasons"].pop(), "BRAID_TURN_DERIVATION_DRIFT")

    def test_edited_axis_refused(self):
        self.forged(lambda r: r["decision"]["axes_computed"].update(codex_known_answers="2/2"),
                    "BRAID_TURN_DERIVATION_DRIFT")

    def test_summary_edit_keeping_digest_refused(self):
        self.forged(lambda r: r["known_answers"].update(passed=2, failed=0),
                    "BRAID_TURN_DERIVATION_DRIFT")

    def test_summary_arithmetic_drift_refused(self):
        self.forged(lambda r: r["known_answers"].update(answers=1), "BRAID_TURN_SUMMARY_DRIFT")

    def test_label_upgrade_refused(self):
        self.forged(lambda r: r["known_answers"].update(label="MEASURED"),
                    "BRAID_TURN_SUMMARY_DRIFT")

    def test_database_hold_relabelled_refused(self):
        self.forged(lambda r: r["database"].update(plan_state="HOLD"),
                    "BRAID_TURN_DERIVATION_DRIFT")

    def test_trace_step_flip_refused(self):
        self.forged(lambda r: r["loop_trace"][3].update(state="OBSERVED"),
                    "BRAID_TURN_DERIVATION_DRIFT")

    def test_trace_rehashed_after_flip_still_refused(self):
        def flip(report):
            step = report["loop_trace"][3]
            step["state"] = "OBSERVED"
            body = {k: v for k, v in step.items() if k != "sha256"}
            step["sha256"] = sha256_hex(canonical(body))
        self.forged(flip, "BRAID_TURN_DERIVATION_DRIFT")

    def test_state_digest_and_turn_id_edit_refused(self):
        self.forged(lambda r: r.update(state_digest="e" * 64), "BRAID_TURN_DERIVATION_DRIFT")
        self.forged(lambda r: r.update(turn_id="braid-turn:" + "0" * 32),
                    "BRAID_TURN_DERIVATION_DRIFT")

    def test_bool_for_int_and_int_for_bool_refused(self):
        self.forged(lambda r: r.update(ouroboros_fixed_point=0), "BRAID_TURN_FIELDS_INVALID")
        self.forged(lambda r: r["decision"].update(evidence_window_seconds=True),
                    "BRAID_DECISION_FIELDS_INVALID")

    def test_window_widened_against_policy_refused(self):
        self.forged(lambda r: r["decision"].update(evidence_window_seconds=31 * 86400),
                    "BRAID_DECISION_POLICY_DRIFT")

    def test_khipu_unavailable_count_bound_to_the_tree(self):
        self.forged(lambda r: (r["khipu"].update(unavailable_cords=1),
                               r["census"].update(unavailable_cords=1)),
                    "BRAID_TURN_DERIVATION_DRIFT")
        report = deepcopy(self.report)
        tree = deepcopy(self.tree)
        tree["unavailable_cords"] = ["lutar-lean:Ghost.lean"]
        with self.assertRaises(InputError):
            braid.verify_turn(report, policy_for_shape=ESTATE.policy, tree=tree)

    def test_produced_list_edit_refused(self):
        self.forged(lambda r: r.update(evidence_produced_in_invocation=["known_answers"]),
                    "BRAID_TURN_SUMMARY_DRIFT")

    def test_authority_flag_refused(self):
        self.forged(lambda r: r.update(production_authorized=True), "BRAID_FALSE_AUTHORITY_CLAIM")
        self.forged(lambda r: r.update(energy_joules=0), "BRAID_FALSE_AUTHORITY_CLAIM")

    def test_ratchet_violation_dropped_refused(self):
        def plant(report):
            report["ratchet"]["violations"] = ["CORD_VANISHED_WITHOUT_RETIREMENT"]
        self.forged(plant, "BRAID_TURN_DERIVATION_DRIFT")

    def test_malformed_section_refused_with_a_code(self):
        self.forged(lambda r: r.update(lean=[]), "BRAID_TURN_BOUNDARY_DRIFT")
        self.forged(lambda r: r["khipu"].pop("primary_sum"), "BRAID_TURN_SECTIONS_INVALID")


class KnownAnswerTests(TestCase):
    def test_bound_answers_are_scored_over_evaluated(self):
        answers = ESTATE.answers()
        self.assertEqual((answers["answers"], answers["evaluated"], answers["passed"],
                          answers["failed"]), (2, 2, 1, 1))
        report, _ = ESTATE.turn(kat_report=answers, produced=["census", "known_answers"])
        summary = report["known_answers"]
        self.assertEqual((summary["binding"], summary["label"]),
                         (braid.KAT_BOUND, "MEASURED"))
        self.assertEqual(report["decision"]["axes_computed"]["codex_known_answers"], "1/2")
        self.assertNotIn("KNOWN_ANSWERS_NOT_ALL_BOUND", report["decision"]["sub_reasons"])

    def test_answers_for_another_census_refuse_the_aggregate(self):
        answers = ESTATE.answers()
        answers["census_sha256"] = "f" * 64
        report, _ = ESTATE.turn(kat_report=answers)
        self.assertIn("KNOWN_ANSWERS_NOT_BOUND_TO_CENSUS", report["decision"]["sub_reasons"])
        self.assertEqual(report["known_answers"]["label"], "UNAVAILABLE")

    def test_answers_with_no_census_digest_refuse_the_aggregate(self):
        answers = kat.check(answer_set(ESTATE.checkouts), ESTATE.census,
                            read_current=ESTATE.read_current, set_sha256="c" * 64,
                            census_sha256=None)
        report, _ = ESTATE.turn(kat_report=answers)
        self.assertIn("KNOWN_ANSWERS_NOT_BOUND_TO_CENSUS", report["decision"]["sub_reasons"])

    def test_moved_anchor_rebinds_by_exact_line(self):
        answers = kat.check(answer_set(ESTATE.checkouts, beta_blob="0" * 40), ESTATE.census,
                            read_current=ESTATE.read_current, set_sha256="c" * 64,
                            census_sha256=ESTATE.census_sha)
        self.assertEqual((answers["rebound_by_line"], answers["evaluated"]), (1, 2))
        report, _ = ESTATE.turn(kat_report=answers)
        self.assertNotIn("KNOWN_ANSWERS_NOT_ALL_BOUND", report["decision"]["sub_reasons"])

    def test_stale_answer_refuses_instead_of_shrinking_the_denominator(self):
        answers = kat.check(answer_set(ESTATE.checkouts, beta_blob="0" * 40,
                                       beta_anchor="sorry -- this line was edited away"),
                            ESTATE.census, read_current=ESTATE.read_current,
                            set_sha256="c" * 64, census_sha256=ESTATE.census_sha)
        self.assertEqual((answers["stale"], answers["evaluated"]), (1, 1))
        report, _ = ESTATE.turn(kat_report=answers)
        self.assertIn("KNOWN_ANSWERS_NOT_ALL_BOUND", report["decision"]["sub_reasons"])
        self.assertEqual(report["decision"]["axes_computed"]["codex_known_answers"], "1/1")
        self.assertEqual(report["state"], braid.STATE_HOLD)

    def test_anchor_at_the_wrong_line_is_never_scored(self):
        answers = kat.check(answer_set(ESTATE.checkouts, beta_line=1), ESTATE.census,
                            read_current=ESTATE.read_current, set_sha256="c" * 64,
                            census_sha256=ESTATE.census_sha)
        self.assertEqual(answers["anchor_not_at_line"], 1)
        report, _ = ESTATE.turn(kat_report=answers)
        self.assertIn("KNOWN_ANSWERS_NOT_ALL_BOUND", report["decision"]["sub_reasons"])


class DatabaseLaneTests(TestCase):
    def test_held_plan_refuses_the_aggregate_even_with_coverage(self):
        _, held = database_plans()
        report, _ = ESTATE.turn(db_plan=held, action_policy=deepcopy(ACTION_POLICY),
                                source_policy=deepcopy(SOURCE_POLICY))
        self.assertIn("DATABASE_LANE_HOLD", report["decision"]["sub_reasons"])
        self.assertEqual(report["database"]["label"], "REPORTED")
        self.assertEqual(report["decision"]["axis_labels"]["database_catalog_coverage"],
                         "REPORTED")

    def test_structural_plan_is_reported_not_measured(self):
        structural, _ = database_plans()
        self.assertEqual(structural["state"], braid.DATABASE_PASS)
        report, _ = ESTATE.turn(db_plan=structural, action_policy=deepcopy(ACTION_POLICY),
                                source_policy=deepcopy(SOURCE_POLICY))
        self.assertNotIn("DATABASE_LANE_HOLD", report["decision"]["sub_reasons"])
        self.assertNotIn("DATABASE_PLAN_NOT_SUPPLIED", report["decision"]["sub_reasons"])
        self.assertEqual(report["decision"]["axes_computed"]["database_catalog_coverage"], "1/1")
        self.assertIs(report["database_queried"], False)


class ChainTests(TestCase):
    def setUp(self):
        self.first, self.first_tree = ESTATE.turn(kat_report=ESTATE.answers())
        self.first_sha = sha256_hex(canonical(self.first))

    def chained(self, **kwargs):
        digests = ESTATE.digests(previous_turn=self.first_sha,
                                 previous_khipu_tree=sha256_hex(canonical(self.first_tree)))
        kwargs.setdefault("kat_report", ESTATE.answers())
        return ESTATE.turn(previous_turn=self.first, previous_tree=self.first_tree,
                           previous_turn_sha256=self.first_sha, input_digests=digests, **kwargs)

    def test_unchanged_evidence_reaches_a_fixed_point(self):
        second, tree = self.chained()
        self.assertEqual(second["ordinal"], 2)
        self.assertEqual(second["previous_turn_id"], self.first["turn_id"])
        self.assertIs(second["ouroboros_fixed_point"], True)
        self.assertEqual(second["state_digest"], self.first["state_digest"])
        self.assertNotEqual(second["turn_id"], self.first["turn_id"])
        self.assertTrue(braid.verify_turn(second, policy_for_shape=ESTATE.policy, tree=tree,
                                          previous=self.first))

    def test_changed_evidence_is_not_a_fixed_point(self):
        second, _ = self.chained(kat_report=None)
        self.assertIs(second["ouroboros_fixed_point"], False)

    def test_tampered_previous_turn_is_recorded_and_a_new_chain_starts(self):
        tampered = deepcopy(self.first)
        tampered["known_answers"]["passed"] = 2
        report, tree = ESTATE.turn(previous_turn=tampered, previous_tree=self.first_tree,
                                   previous_turn_sha256=self.first_sha,
                                   input_digests=ESTATE.digests(previous_turn=self.first_sha))
        self.assertEqual(report["previous_turn_rejected"],
                         {"sha256": self.first_sha, "code": "BRAID_TURN_SUMMARY_DRIFT"})
        self.assertEqual((report["ordinal"], report["previous_turn_id"],
                          report["previous_turn_sha256"]), (1, None, None))
        self.assertIn("PREVIOUS_TURN_REJECTED", report["decision"]["sub_reasons"])
        self.assertIs(report["ouroboros_fixed_point"], False)
        self.assertEqual(report["loop_trace"][0]["state"], "HOLD")
        self.assertIn("TAIL_REJECTED_NEW_CHAIN", report["loop_trace"][0]["detail"])
        self.assertTrue(braid.verify_turn(report, policy_for_shape=ESTATE.policy, tree=tree))

    def test_a_previous_turn_of_another_shape_is_rejected_not_fatal(self):
        older = deepcopy(self.first)
        del older["previous_turn_rejected"]
        report, _ = ESTATE.turn(previous_turn=older, previous_tree=self.first_tree,
                                previous_turn_sha256=self.first_sha,
                                input_digests=ESTATE.digests(previous_turn=self.first_sha))
        self.assertEqual(report["previous_turn_rejected"]["code"], "BRAID_TURN_FIELDS_INVALID")
        self.assertEqual(report["ordinal"], 1)

    def test_a_rejection_record_cannot_ride_on_a_chained_turn(self):
        second, tree = self.chained()
        forged = deepcopy(second)
        forged["previous_turn_rejected"] = {"sha256": "1" * 64, "code": "ANYTHING_AT_ALL"}
        with self.assertRaises(InputError):
            braid.verify_turn(forged, policy_for_shape=ESTATE.policy, tree=tree)
        report, _ = ESTATE.turn()
        for bad in ({"sha256": "1" * 64}, {"sha256": "x", "code": "OK_CODE"},
                    {"sha256": "1" * 64, "code": "bad code 9"}):
            forged = deepcopy(report)
            forged["previous_turn_rejected"] = bad
            with self.assertRaises(InputError):
                braid.verify_turn(forged)

    def test_the_rejection_guard_cannot_be_dropped(self):
        tampered = deepcopy(self.first)
        tampered["ordinal"] = 7
        report, tree = ESTATE.turn(previous_turn=tampered, previous_tree=self.first_tree,
                                   previous_turn_sha256=self.first_sha,
                                   input_digests=ESTATE.digests(previous_turn=self.first_sha))
        forged = deepcopy(report)
        forged["decision"]["sub_reasons"].remove("PREVIOUS_TURN_REJECTED")
        with self.assertRaises(InputError):
            braid.verify_turn(forged, policy_for_shape=ESTATE.policy, tree=tree)

    def test_fixed_point_claim_checked_against_the_previous_turn(self):
        second, tree = self.chained(kat_report=None)
        forged = deepcopy(second)
        forged["ouroboros_fixed_point"] = True
        with self.assertRaises(InputError):
            braid.verify_turn(forged, policy_for_shape=ESTATE.policy, tree=tree,
                              previous=self.first)

    def test_previous_pair_must_be_complete(self):
        refused(self, "BRAID_PREVIOUS_PAIR_INCOMPLETE", ESTATE.turn, previous_turn=self.first)
        refused(self, "BRAID_PREVIOUS_DIGEST_REQUIRED", ESTATE.turn, previous_turn=self.first,
                previous_tree=self.first_tree)


class WitnessIntegrationTests(TestCase):
    """Real Hatun witnesses and Lake wraps, assembled by their own tools from synthetic child
    output, braided by the real orchestrator with the real validators."""

    def setUp(self):
        from tests import test_database_braid_hatun_gate as hatun_tests
        from tests import test_database_braid_lake_receipt as lake_tests
        from tools import database_braid_hatun_gate as hatun
        from tools import database_braid_lake_receipt as lake
        self.hatun, self.lake = hatun, lake
        self.hatun_tests, self.lake_tests = hatun_tests, lake_tests
        rows = {r["repository"]: r for r in ESTATE.census["repositories"]}
        self.hatun_commit = rows[HATUN_REPO]["commit"]
        self.lake_commit = rows[LAKE_REPO]["commit"]

    def hatun_witness(self, *, commit=None, at=AT, raw=None):
        section = ESTATE.policy["hatun"]
        return self.hatun.assemble(section, commit or self.hatun_commit, "d" * 64,
                                   raw or self.hatun_tests.child_raw(section),
                                   observed=self.hatun_tests.observed(), at=at)

    def wrap_for(self, report, report_sha, *, commit=None, version=None, subject=None):
        section = deepcopy(ESTATE.policy["lake"])
        if version is not None:
            section["receipt_library"]["version"] = version
        subject = subject or report["turn_id"]
        value = self.lake_tests.body(subject=subject, input_digest=report["inputs_digest"],
                                     stored=report_sha)
        raw = self.lake_tests.child_ok(value, version=section["receipt_library"]["version"])
        request = self.lake_tests.request(subject=subject, input_digest=report["inputs_digest"],
                                          stored=report_sha, section=section)
        return self.lake.assemble(section, commit or self.lake_commit, "b" * 40, request, raw,
                                  observed=self.lake_tests.observed(), at=AT)

    def test_bound_conforming_hatun_witness_clears_every_hatun_guard(self):
        witness = self.hatun_witness()
        self.assertEqual(witness["state"], "VETO_LADDER_CONFORMS")
        report, _ = ESTATE.turn(hatun_witness=witness)
        reasons = report["decision"]["sub_reasons"]
        self.assertFalse([r for r in reasons if r.startswith("HATUN_")], reasons)
        self.assertEqual((report["hatun"]["binding"], report["hatun"]["label"]),
                         (braid.BOUND, "REPORTED"))
        self.assertEqual(report["decision"]["axes_computed"]["hatun_veto_ladder"], "1/1")
        measured, _ = ESTATE.turn(hatun_witness=witness, produced=["census", "hatun_witness"])
        self.assertEqual(measured["hatun"]["label"], "MEASURED")

    def test_hatun_witness_of_another_commit_is_not_bound(self):
        report, _ = ESTATE.turn(hatun_witness=self.hatun_witness(commit="e" * 40))
        self.assertIn("HATUN_WITNESS_NOT_BOUND_TO_CENSUS", report["decision"]["sub_reasons"])
        self.assertEqual(report["hatun"]["label"], "UNAVAILABLE")
        self.assertEqual(report["loop_trace"][3]["state"], "HOLD")

    def test_stale_hatun_witness_refuses(self):
        report, _ = ESTATE.turn(hatun_witness=self.hatun_witness(at=AT - timedelta(days=2)))
        self.assertIn("HATUN_WITNESS_OUTSIDE_EVIDENCE_WINDOW", report["decision"]["sub_reasons"])

    def test_veto_that_did_not_hold_refuses_instead_of_scoring(self):
        section = ESTATE.policy["hatun"]
        raw = self.hatun_tests.child_raw(section)
        injected = next(p for p in raw["mcp"]["probes"]
                        if p["id"] == "mcp_injected_instruction_text")
        injected.update(status="success", decline_reason=None, owasp_class=None)
        witness = self.hatun_witness(raw=raw)
        self.assertNotEqual(witness["state"], "VETO_LADDER_CONFORMS")
        report, _ = ESTATE.turn(hatun_witness=witness)
        self.assertIn("HATUN_LADDER_DID_NOT_CONFORM", report["decision"]["sub_reasons"])
        self.assertIsNone(report["decision"]["exact"])

    def chain(self, wrap_of_first):
        first, first_tree = ESTATE.turn()
        first_sha = sha256_hex(canonical(first))
        wrap = wrap_of_first(first, first_sha)
        digests = ESTATE.digests(previous_turn=first_sha, previous_lake_wrap="5" * 64,
                                 previous_khipu_tree=sha256_hex(canonical(first_tree)))
        second, tree = ESTATE.turn(previous_turn=first, previous_tree=first_tree,
                                   previous_turn_sha256=first_sha, previous_lake_wrap=wrap,
                                   input_digests=digests)
        self.assertTrue(braid.verify_turn(second, policy_for_shape=ESTATE.policy, tree=tree,
                                          previous=first))
        return second

    def test_previous_lake_receipt_that_binds_is_verified(self):
        second = self.chain(lambda turn, sha: self.wrap_for(turn, sha))
        self.assertEqual(second["previous_turn_lake_receipt"],
                         "VERIFIED_UNSIGNED_BINDS_PREVIOUS_TURN")
        self.assertIs(second["ouroboros_fixed_point"], True)
        self.assertEqual(second["loop_trace"][0]["state"], "OBSERVED")

    def test_previous_lake_receipt_for_another_subject_is_a_mismatch(self):
        second = self.chain(lambda turn, sha: self.wrap_for(
            turn, sha, subject="braid-turn:" + "9" * 32))
        self.assertEqual(second["previous_turn_lake_receipt"], "MISMATCH")
        self.assertIn("PREVIOUS_LAKE_RECEIPT_DOES_NOT_BIND_PREVIOUS_TURN",
                      second["decision"]["sub_reasons"])
        self.assertEqual(second["loop_trace"][0]["state"], "HOLD")

    def test_previous_lake_receipt_from_another_adapter_commit_is_a_mismatch(self):
        second = self.chain(lambda turn, sha: self.wrap_for(turn, sha, commit="f" * 40))
        self.assertEqual(second["previous_turn_lake_receipt"], "MISMATCH")

    def test_forged_receipt_digest_is_invalid_not_a_crash(self):
        def forged(turn, sha):
            wrap = self.wrap_for(turn, sha)
            wrap["envelope"]["digest"] = "1" * 64
            return wrap
        second = self.chain(forged)
        self.assertEqual(second["previous_turn_lake_receipt"], "RECEIPT_INVALID")
        self.assertIn("PREVIOUS_LAKE_RECEIPT_INVALID", second["decision"]["sub_reasons"])

    def test_receipt_made_under_an_older_pin_still_binds_and_says_so(self):
        second = self.chain(lambda turn, sha: self.wrap_for(turn, sha, version="0.3.0"))
        self.assertEqual(second["previous_turn_lake_receipt"],
                         "VERIFIED_UNSIGNED_BINDS_PREVIOUS_TURN_UNDER_OTHER_PINS")
        self.assertNotIn("PREVIOUS_LAKE_RECEIPT_INVALID", second["decision"]["sub_reasons"])


class FullStackTests(TestCase):
    """Every witness real: a kernel witness from the Lean tool (with its test suite's stand-in
    for Lake), a Hatun witness and Lake wrap from their tools, known answers from the evaluator
    and a plan from the planner. Only the census scope and the ratchet floor are fixture-sized."""

    LEAN = "szl-holdings/synthetic-lean"

    @classmethod
    def setUpClass(cls):
        from tests import test_database_braid_hatun_gate as hatun_tests
        from tests import test_database_braid_lean_witness as lean_tests
        from tools import database_braid_hatun_gate as hatun
        from tools import database_braid_lean_witness as lean
        cls.lean, cls.lean_tests = lean, lean_tests
        cls.tmp = tempfile.TemporaryDirectory()
        base = Path(cls.tmp.name)
        cls.lean_repo = lean_tests.make_checkout(base / "lean-home", name="synthetic-lean")
        _git(cls.lean_repo, "remote", "add", "origin", "https://github.com/" + cls.LEAN)
        estate = make_estate(base / "others")
        cls.checkouts = {HATUN_REPO: estate[HATUN_REPO], LAKE_REPO: estate[LAKE_REPO],
                         cls.LEAN: cls.lean_repo}
        policy = test_policy()
        policy["census"]["repositories"][1] = {
            "repository": cls.LEAN, "include": ["*.lean"], "exclude": [],
            "families": [{"glob": "*", "family": "LEAN_CORPUS"}]}
        policy["lean"] = lean_tests.policy()
        policy["khipu"]["lean_carrier"] = "Lib.Orphan.carrier"
        cls.policy = policy
        cls.census = census_tool.observe(policy["census"], cls.checkouts, at=AT,
                                         policy_sha256="a" * 64)
        cls.census_sha = sha256_hex(canonical(cls.census))
        cls.witness = {
            name: lean.observe(policy["lean"], cls.lean_repo, toolchain_bin=base / "bin",
                               run=lean_tests.FakeLake(**fake), at=AT)
            for name, fake in (("good", {"fail_request": ()}), ("hold", {"allowed": 2}))}
        rows = {r["repository"]: r for r in cls.census["repositories"]}
        section = policy["hatun"]
        cls.hatun = hatun.assemble(section, rows[HATUN_REPO]["commit"], "d" * 64,
                                   hatun_tests.child_raw(section), observed=hatun_tests.observed(),
                                   at=AT)
        body = (cls.lean_repo / "Lib/A.lean").read_bytes()
        cls.answer_set = {
            "schema": kat.SET_SCHEMA, "review_status": "MACHINE_TRANSCRIBED_UNRATIFIED",
            "answers": [{"id": "lean-fixture-product", "family": "ARITHMETIC",
                         "source": {"repository": cls.LEAN, "path": "Lib/A.lean", "line": 1,
                                    "blob_sha1": git_blob_sha1(body)},
                         "anchor": "theorem Lib.A.clean : True := trivial",
                         "statement": "fixture: 2*3 = 6",
                         "claim": {"eq": [{"mul": [2, 3]}, 6]}}]}
        cls.plan, _ = database_plans()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def answers(self):
        def read_current(repository, blob):
            directory = self.checkouts.get(repository)
            return None if directory is None else census_tool.read_blobs(
                directory, [blob], max_bytes=kat.MAX_BLOB_BYTES).get(blob)
        return kat.check(self.answer_set, self.census, read_current=read_current,
                         set_sha256="c" * 64, census_sha256=self.census_sha)

    def turn(self, policy=None, *, witness="good", **kwargs):
        evidence = dict(lean_witness=self.witness[witness], hatun_witness=self.hatun,
                        kat_report=self.answers(), db_plan=self.plan,
                        action_policy=deepcopy(ACTION_POLICY),
                        source_policy=deepcopy(SOURCE_POLICY),
                        input_digests={"policy": "a" * 64, "census": self.census_sha,
                                       "database_plan": "d" * 64})
        evidence.update(kwargs)
        return braid.turn(policy or self.policy, self.census, **evidence)

    def floored(self):
        """The fixture policy with its ratchet floor set to what the good witness measures."""
        report, _ = self.turn()
        policy = deepcopy(self.policy)
        floor = policy["ratchet"]["floor"]
        for field, name, _, _ in braid.FLOOR_RULES:
            floor[field] = report["ratchet"]["debt"][name]
        floor["declared_axioms_allowed"] = sorted(report["lean"]["declared_axiom_names"])
        return policy

    def test_the_lean_witness_binds_and_its_knots_follow_the_kernel(self):
        report, _ = self.turn()
        lean = report["lean"]
        self.assertEqual((lean["binding"], lean["witness_state"], lean["build_tree"]),
                         (braid.BOUND, "KERNEL_EXECUTED", "FRESH_EXPORT_OF_COMMIT"))
        totals = self.witness["good"]["file_totals"]
        knots = report["khipu"]["primary_sum"]
        self.assertEqual(knots["lean_accepted_default"], totals["ACCEPTED_DEFAULT_BUILD"])
        self.assertEqual(knots["lean_rejected"], totals["REJECTED"])
        self.assertEqual(knots["user_theorems"],
                         self.witness["good"]["theorem_totals"]["user_theorems"])
        self.assertEqual(lean["files_kernel_accepted"],
                         sum(totals[k] for k in ("ACCEPTED_DEFAULT_BUILD", "ACCEPTED_ON_REQUEST",
                                                 "ACCEPTED_STANDALONE")))

    def test_with_every_witness_bound_the_threshold_is_met_without_authority(self):
        policy = self.floored()
        report, tree = self.turn(policy)
        decision = report["decision"]
        self.assertEqual(decision["sub_reasons"], [])
        self.assertIsNotNone(decision["exact"])
        self.assertEqual(set(decision["axes_computed"]), set(braid.AXES))
        # Fixture axes: 9/10 kernel-accepted files and 1/2 trust-base theorems, the rest 1/1.
        self.assertEqual(decision["axes_computed"]["lean_files_kernel_accepted"], "9/10")
        self.assertEqual(decision["axes_computed"]["theorems_trust_base_only"], "1/2")
        self.assertEqual(decision["exact"]["geometric_mean_ppm_floor"], 905006)
        self.assertEqual(decision["refusal_path"], "NONE")
        self.assertEqual(report["state"], braid.STATE_MET)
        self.assertEqual(report["termination"], "CLOSED_EVIDENCE_COMPLETE_NO_AUTHORITY")
        self.assertTrue(all(step["state"] == "OBSERVED" for step in report["loop_trace"]))
        self.assertIs(decision["exact"]["authority_granted"], False)
        self.assertIs(report["production_authorized"], False)
        self.assertTrue(braid.verify_turn(report, policy_for_shape=policy, tree=tree))
        self.assertTrue(braid.replay_turn(report, policy, self.census,
                                          lean_witness=self.witness["good"],
                                          hatun_witness=self.hatun, kat_report=self.answers(),
                                          db_plan=self.plan,
                                          action_policy=deepcopy(ACTION_POLICY),
                                          source_policy=deepcopy(SOURCE_POLICY),
                                          input_digests={"policy": "a" * 64,
                                                         "census": self.census_sha,
                                                         "database_plan": "d" * 64}))

    def test_kernel_witness_in_hold_refuses_the_aggregate(self):
        self.assertEqual(self.witness["hold"]["state"], "HOLD")
        report, _ = self.turn(self.floored(), witness="hold")
        self.assertIn("LEAN_WITNESS_NOT_KERNEL_EXECUTED", report["decision"]["sub_reasons"])
        self.assertIsNone(report["decision"]["exact"])
        # A HOLD witness's numbers are not scored, not even as information.
        for name in ("lean_files_kernel_accepted", "theorems_trust_base_only",
                     "locked_set_guard"):
            self.assertNotIn(name, report["decision"]["axes_computed"])

    def test_floor_breach_refuses_the_aggregate(self):
        policy = self.floored()
        policy["ratchet"]["floor"]["lean_files_kernel_accepted_min"] += 1
        report, _ = self.turn(policy)
        self.assertEqual(report["decision"]["sub_reasons"], ["RATCHET_VIOLATION"])
        self.assertEqual(report["ratchet"]["violations"], ["KERNEL_ACCEPTED_FILES_BELOW_FLOOR"])

    def test_a_carrier_that_is_not_kernel_clean_refuses(self):
        policy = self.floored()
        policy["khipu"]["lean_carrier"] = "Lib.A.sorried"
        report, _ = self.turn(policy)
        self.assertIn("KHIPU_LEAN_CARRIER_NOT_KERNEL_CLEAN", report["decision"]["sub_reasons"])

    def test_witness_validator_is_not_bypassed(self):
        forged = deepcopy(self.witness["good"])
        forged["project_modules_replayed"] = 1
        with self.assertRaises(InputError):
            self.turn(lean_witness=forged)


# ---------------------------------------------------------------- pure derivation level


def lean_summary(**over):
    summary = {
        "binding": braid.BOUND, "label": "MEASURED", "witness_state": "KERNEL_EXECUTED",
        "commit": "a" * 40, "toolchain_pin": "leanprover/lean4:v4.35.0",
        "build_tree": "FRESH_EXPORT_OF_COMMIT", "network_namespace": "EMPTY_NETWORK_NAMESPACE",
        "project_modules_built_by_this_run": 2, "project_modules_replayed": 0,
        "hold_reasons": [], "dependency_cache_state": "MATCHES_MANIFEST",
        "mathlib_revision": "5" * 40, "dependency_oleans_rechecked_by_kernel": False,
        "files_kernel_accepted": 2, "files_rejected": 1, "files_not_checked_by_policy": 0,
        "files_theorem_counts_unknown": 1, "theorem_counts_scope": "KERNEL_ACCEPTED_MODULES_ONLY",
        "file_totals": {}, "theorem_totals": {},
        "locked_guard_allowed": 24, "locked_guard_refused": 0, "locked_guard_expected": 24,
        "census_rows_sha256": "b" * 64, "declared_axiom_names": [], "sorry_source_names": [],
        "khipu_carrier": {"decl": POLICY["khipu"]["lean_carrier"], "found": True,
                          "class": "trust_base_only"},
        "independent_kernel_replay": False,
    }
    summary.update(over)
    return summary


def tree_for(**knots):
    """A one-pendant khipu tree whose three Lean cords carry the given totals."""
    base = dict.fromkeys(braid.KNOTS, 0)
    base.update(cords=3, bytes=30, lean_files=3, lean_accepted_default=2, lean_rejected=1,
                lean_theorem_counts_unknown=1, user_theorems=10, theorems_trust_base_only=8,
                theorems_sorry_tainted=1, theorems_declared_axiom_dependent=1)
    base.update(knots)
    first = dict(base)
    rest = dict.fromkeys(braid.KNOTS, 0)
    cords = [{"key": "lutar-lean:A.lean", "pendant": "lutar-lean|LEAN_CORPUS", "digest": "1" * 64,
              "knots": [first[k] for k in braid.KNOTS]},
             {"key": "lutar-lean:B.lean", "pendant": "lutar-lean|LEAN_CORPUS", "digest": "2" * 64,
              "knots": [rest[k] for k in braid.KNOTS]}]
    return build(braid.KNOTS, braid.PARTITIONS, cords, unavailable=[])


def floor_policy(**floor):
    policy = deepcopy(POLICY)
    policy["ratchet"]["floor"].update({
        "lean_files_kernel_accepted_min": 2, "lean_rejected_max": 1,
        "theorems_sorry_tainted_max": 1, "direct_sorry_declarations_max": 0,
        "theorems_declared_axiom_dependent_max": 1, "theorems_native_decide_max": 0,
        "theorems_trust_base_only_min": 8, "declared_axioms_allowed": [],
        "locked_guard_allowed_min": 24})
    policy["ratchet"]["floor"].update(floor)
    return policy


def previous_turn(turn_id, debt, baseline=(None, None)):
    return {"turn_id": turn_id, "ratchet": {
        "debt": debt, "against_previous_turn": {"baseline_turn_id": baseline[0],
                                                "baseline_debt": baseline[1]}}}


class RatchetTests(TestCase):
    def test_floor_holds_at_the_measured_values(self):
        policy, tree = floor_policy(), tree_for()
        ratchet = braid._ratchet(policy, tree, lean_summary(), None, None)
        self.assertEqual((ratchet["floor_state"], ratchet["violations"], ratchet["can_tighten"]),
                         ("CHECKED", [], []))

    def test_axiom_and_native_debt_have_floors(self):
        tree = tree_for(theorems_trust_base_only=6, theorems_declared_axiom_dependent=2,
                        theorems_native_decide=1)
        ratchet = braid._ratchet(floor_policy(), tree, lean_summary(), None, None)
        self.assertEqual(ratchet["violations"], [
            "AXIOM_DEPENDENT_THEOREMS_ABOVE_FLOOR", "NATIVE_DECIDE_THEOREMS_ABOVE_FLOOR",
            "TRUST_BASE_THEOREMS_BELOW_FLOOR"])

    def test_missing_locked_guard_is_a_violation_not_a_pass(self):
        ratchet = braid._ratchet(floor_policy(), tree_for(),
                                 lean_summary(locked_guard_allowed=None), None, None)
        self.assertIn("LOCKED_GUARD_NOT_MEASURED", ratchet["violations"])

    def test_better_than_floor_is_reported_as_can_tighten(self):
        tree = tree_for(lean_accepted_default=3, lean_rejected=0)
        ratchet = braid._ratchet(floor_policy(), tree,
                                 lean_summary(files_kernel_accepted=3, files_rejected=0),
                                 None, None)
        self.assertEqual(ratchet["violations"], [])
        self.assertEqual(ratchet["can_tighten"],
                         ["lean_files_kernel_accepted_min", "lean_rejected_max"])

    def test_debt_moved_between_classes_is_caught_between_turns(self):
        before = braid._debt(lean_summary(), dict(zip(braid.KNOTS, tree_for()["primary"]["sum"])))
        tree = tree_for(theorems_trust_base_only=7, theorems_declared_axiom_dependent=2)
        policy = floor_policy(theorems_declared_axiom_dependent_max=5,
                              theorems_trust_base_only_min=0)
        ratchet = braid._ratchet(policy, tree, lean_summary(), previous_turn("braid-turn:" +
                                 "1" * 32, before), tree_for())
        self.assertEqual(ratchet["against_previous_turn"]["state"], "COMPARED_WITH_PREVIOUS_TURN")
        self.assertIn("PROOF_DEBT_INCREASED_SINCE_LAST_BOUND_TURN", ratchet["violations"])
        self.assertIn("KERNEL_CREDIT_DECREASED_SINCE_LAST_BOUND_TURN", ratchet["violations"])

    def test_debt_cannot_be_laundered_through_a_turn_without_witness(self):
        bound_debt = braid._debt(lean_summary(),
                                 dict(zip(braid.KNOTS, tree_for()["primary"]["sum"])))
        unbound = previous_turn("braid-turn:" + "2" * 32, None,
                                ("braid-turn:" + "1" * 32, bound_debt))
        worse = tree_for(theorems_sorry_tainted=2, theorems_trust_base_only=7)
        policy = floor_policy(theorems_sorry_tainted_max=9, theorems_trust_base_only_min=0)
        ratchet = braid._ratchet(policy, worse, lean_summary(), unbound, tree_for())
        record = ratchet["against_previous_turn"]
        self.assertEqual(record["state"], "COMPARED_WITH_EARLIER_BOUND_TURN")
        self.assertEqual(record["baseline_turn_id"], "braid-turn:" + "1" * 32)
        self.assertEqual(record["debt_delta"]["theorems_sorry_tainted"], 1)
        self.assertIn("PROOF_DEBT_INCREASED_SINCE_LAST_BOUND_TURN", ratchet["violations"])

    def test_unbound_turn_carries_the_baseline_forward(self):
        bound_debt = {"lean_rejected": 1}
        carried = previous_turn("braid-turn:" + "2" * 32, None,
                                ("braid-turn:" + "1" * 32, bound_debt))
        self.assertEqual(braid._baseline(carried), ("braid-turn:" + "1" * 32, bound_debt))
        own = previous_turn("braid-turn:" + "3" * 32, {"lean_rejected": 0})
        self.assertEqual(braid._baseline(own), ("braid-turn:" + "3" * 32, {"lean_rejected": 0}))


def section_report(base, **sections):
    """``base`` with replaced observed sections, a matching ratchet and derived verdicts."""
    report = deepcopy(base)
    report.update(deepcopy(sections))
    debt = braid._debt(report["lean"], report["khipu"]["primary_sum"])
    floor = deepcopy(POLICY["ratchet"]["floor"])
    if debt is not None:
        # A floor equal to what was measured: no violation, nothing to tighten.
        for field, name, _, _ in braid.FLOOR_RULES:
            floor[field] = debt[name] if debt[name] is not None else 0
        floor["declared_axioms_allowed"] = sorted(report["lean"]["declared_axiom_names"])
    state, violations, tighten, outside = braid._floor(floor, report["lean"], debt)
    report["ratchet"] = dict(report["ratchet"], floor_state=state, violations=violations,
                             can_tighten=tighten, declared_axioms_outside_allowed_set=outside,
                             debt=debt)
    policy = ESTATE.policy
    report.update(braid._derive(report, tau=policy["decision"]["tau"],
                                weights={a["id"]: a["weight"] for a in policy["decision"]["axes"]},
                                window=policy["decision"]["evidence_window_seconds"]))
    return report


class GuardTests(TestCase):
    """The pre-aggregation guards, on internally consistent hand-built sections."""

    def setUp(self):
        structural, _ = database_plans()
        self.base, _ = ESTATE.turn(
            kat_report=ESTATE.answers(), db_plan=structural,
            action_policy=deepcopy(ACTION_POLICY), source_policy=deepcopy(SOURCE_POLICY),
            input_digests=ESTATE.digests(database_plan="d" * 64))
        total = dict(self.base["khipu"]["primary_sum"])
        total.update(lean_accepted_default=1, lean_rejected=1, lean_not_judged=0,
                     lean_theorem_counts_unknown=1, user_theorems=4, theorems_trust_base_only=4)
        self.khipu = dict(self.base["khipu"], primary_sum=total)
        self.lean = lean_summary(files_kernel_accepted=1, files_rejected=1)
        self.hatun = {"binding": braid.BOUND, "label": "REPORTED",
                      "state": "VETO_LADDER_CONFORMS", "commit": "b" * 40,
                      "source_modules_digest": "c" * 64, "source_tree": "FRESH_EXPORT_OF_COMMIT",
                      "network_namespace": "EMPTY_NETWORK_NAMESPACE", "kernel_state": "EXECUTED",
                      "mcp_state": "EXECUTED", "probes_matched": 8, "probes_expected": 8,
                      "caller_context": "SET_THROUGH_HATUN_TEST_HOOKS",
                      "api_key_authentication_path_exercised": False,
                      "effect_authority": "NOT_ATTACHED"}
        stamp = self.base["evidence_times"]["census"]
        self.times = {"census": stamp, "lean_witness": stamp, "hatun_witness": stamp}
        self.answers = dict(self.base["known_answers"], passed=2, failed=0)

    def report(self, **over):
        sections = {"khipu": self.khipu, "lean": dict(self.lean, label="REPORTED"),
                    "hatun": self.hatun, "known_answers": self.answers,
                    "evidence_times": self.times}
        sections.update(over)
        return section_report(self.base, **sections)

    def test_everything_bound_and_conforming_reaches_met_without_authority(self):
        report = self.report()
        self.assertEqual(report["decision"]["sub_reasons"], [])
        self.assertEqual(report["state"], braid.STATE_MET)
        self.assertEqual(report["termination"], "CLOSED_EVIDENCE_COMPLETE_NO_AUTHORITY")
        self.assertTrue(all(s["state"] == "OBSERVED" for s in report["loop_trace"]))
        exact = report["decision"]["exact"]
        self.assertIs(exact["authority_granted"], False)
        self.assertEqual(exact["axes"]["lean_files_kernel_accepted"], "1/2")
        self.assertIs(report["production_authorized"], False)
        self.assertTrue(braid.verify_turn(report))

    def test_kernel_witness_in_hold_refuses(self):
        report = self.report(lean=dict(self.lean, label="REPORTED", witness_state="HOLD"))
        self.assertEqual(report["decision"]["sub_reasons"], ["LEAN_WITNESS_NOT_KERNEL_EXECUTED"])
        self.assertEqual(report["loop_trace"][3]["state"], "HOLD")

    def test_failed_veto_is_a_refusal_not_partial_credit(self):
        hatun = dict(self.hatun, state="HOLD", probes_matched=7)
        report = self.report(hatun=hatun)
        self.assertEqual(report["decision"]["sub_reasons"], ["HATUN_LADDER_DID_NOT_CONFORM"])
        self.assertIsNone(report["decision"]["exact"])

    def test_hatun_witness_of_another_commit_refuses(self):
        report = self.report(hatun=dict(self.hatun, binding="COMMIT_MISMATCH",
                                        label="UNAVAILABLE"))
        self.assertEqual(report["decision"]["sub_reasons"], ["HATUN_WITNESS_NOT_BOUND_TO_CENSUS"])

    def test_unexecuted_ladder_tier_refuses(self):
        report = self.report(hatun=dict(self.hatun, mcp_state="UNAVAILABLE"))
        self.assertIn("HATUN_LADDER_NOT_FULLY_EXECUTED", report["decision"]["sub_reasons"])

    def test_evidence_outside_the_window_refuses(self):
        old = (datetime.fromisoformat(self.times["census"]) - timedelta(days=2)).isoformat()
        report = self.report(evidence_times=dict(self.times, lean_witness=old,
                                                 hatun_witness=old))
        self.assertEqual(report["decision"]["sub_reasons"], [
            "LEAN_WITNESS_OUTSIDE_EVIDENCE_WINDOW", "HATUN_WITNESS_OUTSIDE_EVIDENCE_WINDOW"])

    def test_naive_timestamp_refused(self):
        with self.assertRaises(InputError):
            self.report(evidence_times=dict(self.times, lean_witness="2026-11-19T12:00:00"))

    def test_carrier_not_kernel_clean_refuses(self):
        carrier = dict(self.lean["khipu_carrier"], **{"class": "sorry_tainted"})
        report = self.report(lean=dict(self.lean, label="REPORTED", khipu_carrier=carrier))
        self.assertEqual(report["decision"]["sub_reasons"],
                         ["KHIPU_LEAN_CARRIER_NOT_KERNEL_CLEAN"])

    def test_refused_locked_guard_pins_its_axis_to_zero(self):
        report = self.report(lean=dict(self.lean, label="REPORTED", locked_guard_refused=1))
        exact = report["decision"]["exact"]
        self.assertEqual(exact["axes"]["locked_set_guard"], "0/1")
        self.assertEqual(exact["refusal_path"], "ZERO_PINNED")
        self.assertEqual(report["state"], braid.STATE_HOLD)

    def test_forged_met_over_a_failed_veto_does_not_verify(self):
        report = self.report(hatun=dict(self.hatun, state="HOLD", probes_matched=7))
        met = self.report()
        for name in braid._DERIVED:
            report[name] = deepcopy(met[name])
        with self.assertRaises(InputError):
            braid.verify_turn(report)

    def test_axes_never_score_a_missing_witness(self):
        lean = dict(self.lean, binding="NOT_SUPPLIED", label="UNAVAILABLE")
        computed = braid._axes(dict(self.report(), lean=lean))
        for name in ("lean_files_kernel_accepted", "theorems_trust_base_only",
                     "locked_set_guard"):
            self.assertNotIn(name, computed)
        self.assertEqual(computed["source_cords_present"], Fraction(1))


if __name__ == "__main__":
    unittest_main()
