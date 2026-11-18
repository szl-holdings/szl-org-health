# SPDX-License-Identifier: Apache-2.0
"""No-effect Ouroboros, Hatun and Khipu proof-boundary regression fixtures."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from unittest import TestCase, main as unittest_main

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.database_catalog_admission import InputError  # noqa: E402
from tools.database_agentic_planner import propose  # noqa: E402
from tools.database_ouroboros_braid import (  # noqa: E402
    GENESIS, PHASES, PROOF_STATUS, braid, main, verify_report,
)

BRAID_POLICY = json.loads(
    (ROOT / "governance/database_contracts/ouroboros_braid_v1.json").read_text()
)
SOURCE_POLICY = json.loads(
    (ROOT / "governance/database_contracts/memory_covenant_v2.json").read_text()
)
ACTION_POLICY = json.loads(
    (ROOT / "governance/database_contracts/database_agentic_actions_v1.json").read_text()
)
NOW = datetime(2026, 11, 18, 5, 2, tzinfo=timezone.utc)
SHA = "a" * 64


def source_readback(*, at=NOW):
    entries = []
    for ref in BRAID_POLICY["source_refs"]:
        entries.append({
            **ref, "status": "MATCHED", "byte_length": 123,
            "content_sha256": SHA,
        })
    return {
        "schema": "szl.database-ouroboros-source-readback/v1",
        "observed_at": at.isoformat(), "state": "COMPLETE_BLOB_MATCH",
        "required_count": len(entries), "matched_count": len(entries),
        "entries": entries,
        "github_commit_and_blob_pins_reported": True,
        "git_bytes_checked_by_this_collector": True,
        "runtime_sources_independently_verified": False,
        "lean_kernel_executed": False,
        "hatun_authority_present": False,
        "lake_canonical_receipt_emitted": False,
        "provider_writes": False, "secrets_recorded": False,
    }


def plan_fixture():
    catalog = {
        "schema": "szl.database-catalog-admission/v1",
        "catalog_observed_at": NOW.isoformat(),
        "catalog_sha256": SHA, "contract_id": ACTION_POLICY["catalog_contract_id"],
        "database_queried_by_this_verifier": False, "external_writes_performed": False,
        "gap_count": 1,
        "gaps": [{"code": "TABLE_NOT_OBSERVED", "object": "public.memory_context_bindings"}],
        "independent_witness": False, "migration_authorized": False,
        "observed_functions": 1, "observed_tables": 7, "policy_sha256": SHA,
        "production_authorized": False, "reported_source_blob_matches": True,
        "required_functions": 1, "required_tables": 8,
        "source_identity_independently_verified": False, "state": "HOLD",
    }
    frontier = {
        "schema": "szl.database-causal-frontier-admission/v1",
        "contract_id": ACTION_POLICY["frontier_contract_id"],
        "coverage_denominator": 4, "coverage_numerator": 0,
        "database_queried": False, "effects_authorized": False,
        "external_consistency_proven": False,
        "gap_count": 4,
        "gaps": [{"code": "REQUIRED_STAGE_UNAVAILABLE", "stage": s}
                 for s in sorted(("source_ledger", "transactional_outbox",
                                  "retrieval_index", "api_projection"))],
        "intersection": None, "observed_stage_count": 0,
        "policy_sha256": SHA, "production_authorized": False,
        "replication_proven": False, "requested_version": 0,
        "required_stage_count": 4, "schema_migrated_by_this_verifier": False,
        "snapshot_sha256": SHA, "source_identity_independently_verified": False,
        "stage_digests_independently_verified": False,
        "state": "HOLD", "true_time_available": False,
        "upper_version_spread": None,
    }
    return propose(ACTION_POLICY, catalog, frontier, at=NOW,
                   catalog_sha=SHA, frontier_sha=SHA)


def run(*, sources=None, policy=None, plan=None, at=NOW):
    return braid(policy or deepcopy(BRAID_POLICY),
                 sources or source_readback(),
                 plan or plan_fixture(), ACTION_POLICY, SOURCE_POLICY,
                 now=at, policy_sha=SHA, readback_sha=SHA, plan_sha=SHA)


class OuroborosBraidTests(TestCase):
    def test_all_pinned_source_families_join_one_finite_trace(self):
        report = run()
        self.assertEqual(report["schema"], "szl.database-ouroboros-braid/v1")
        self.assertEqual(report["state"], "HOLD")
        self.assertEqual(report["termination"], "CLOSED_WITH_HOLD")
        self.assertEqual(report["executed_steps"], report["max_steps"])
        self.assertEqual(report["executed_steps"], 5)
        self.assertEqual(tuple(x["phase"] for x in report["loop_trace"]), PHASES)
        self.assertEqual(report["loop_trace"][0]["prev_sha256"], GENESIS)
        self.assertEqual(report["loop_trace"][-1]["state"], "HOLD")
        self.assertTrue(verify_report(report, BRAID_POLICY, plan_fixture()))

    def test_khipu_unit_cords_conserve_observed_count_only(self):
        report = run()
        self.assertEqual(report["source_ref_count"], 14)
        self.assertEqual(report["source_matched_count"], 14)
        self.assertEqual(report["khipu_root_observed_unit_sum"], 14)
        self.assertFalse(report["khipu_missing_is_zero"])
        self.assertEqual(report["khipu_missing_cords"], 0)
        self.assertEqual(sum(x["unit_weight"] for x in report["cords"]), 14)

    def test_missing_khipu_anchor_never_encoded_as_zero(self):
        obs = source_readback()
        row = next(x for x in obs["entries"] if x["id"] == "khipu_math")
        row.update(status="UNAVAILABLE", byte_length=None,
                   content_sha256=None)
        obs["matched_count"] -= 1
        obs["state"] = "HOLD"
        report = run(sources=obs)
        self.assertIn("khipu_math", report["missing_source_ids"])
        self.assertIsNone(next(x for x in report["cords"]
                               if x["source_id"] == "khipu_math")["unit_weight"])
        self.assertEqual(report["khipu_root_observed_unit_sum"], 13)
        self.assertTrue(verify_report(report, BRAID_POLICY, plan_fixture()))

    def test_missing_lean_source_never_upgraded_by_braid(self):
        obs = source_readback()
        row = next(x for x in obs["entries"] if x["id"] == "lean_khipu")
        row.update(status="MISMATCH", byte_length=None, content_sha256=None)
        obs["matched_count"] -= 1
        obs["state"] = "HOLD"
        report = run(sources=obs)
        self.assertEqual(report["lean_checker_result"], PROOF_STATUS)
        self.assertEqual(report["state"], "HOLD")
        self.assertFalse(report["source_runtime_verified"])

    def test_no_formal_proof_or_registered_lake_signature_inference(self):
        p = run()
        for field in ("canonical_dsse_signed", "independent_witness",
                      "production_authorized", "external_effects_performed",
                      "model_inference_invoked", "git_source_code_executed",
                      "database_queried", "sql_generated", "sql_executed"):
            self.assertIs(p[field], False, field)
        self.assertEqual(p["lake_canonical_receipt"], "NOT_EMITTED")
        self.assertEqual(p["hatun_effect_authority"], "NOT_ATTACHED")
        self.assertEqual(p["archaeological_data_rights"], "NOT_GRANTED")
        self.assertEqual(p["lambda_uniqueness_status"],
                         "UNCONDITIONAL_UNIQUENESS_DISPROVEN_AS_STATED")
        self.assertIsNone(p["energy_joules"])
        self.assertIsNone(p["loop_tax_ms"])

    def test_fresh_readback_is_not_live_runtime_verification(self):
        p = run()
        self.assertEqual(p["source_readback_freshness"], "FRESH")
        self.assertFalse(p["source_runtime_verified"])

    def test_old_readback_is_hold_even_when_pins_match(self):
        age = NOW - timedelta(hours=3)
        p = run(sources=source_readback(at=age))
        self.assertEqual(p["source_readback_freshness"], "STALE_OR_FUTURE")
        self.assertEqual(p["loop_trace"][1]["state"], "HOLD")

    def test_future_readback_is_hold(self):
        p = run(sources=source_readback(at=NOW + timedelta(minutes=12)))
        self.assertEqual(p["source_readback_freshness"], "STALE_OR_FUTURE")

    def test_runtime_proof_claim_in_readback_refused(self):
        obs = source_readback()
        obs["lean_kernel_executed"] = True
        with self.assertRaisesRegex(InputError, "BRAID_FALSE_AUTHORITY_CLAIM"):
            run(sources=obs)

    def test_signed_lake_claim_from_untrusted_source_refused(self):
        obs = source_readback()
        obs["lake_canonical_receipt_emitted"] = True
        with self.assertRaisesRegex(InputError, "BRAID_FALSE_AUTHORITY_CLAIM"):
            run(sources=obs)

    def test_hatun_approval_claim_from_untrusted_source_refused(self):
        obs = source_readback()
        obs["hatun_authority_present"] = True
        with self.assertRaisesRegex(InputError, "BRAID_FALSE_AUTHORITY_CLAIM"):
            run(sources=obs)

    def test_observation_proof_id_is_not_self_attesting(self):
        obs = source_readback()
        obs["runtime_sources_independently_verified"] = True
        with self.assertRaisesRegex(InputError, "BRAID_FALSE_AUTHORITY_CLAIM"):
            run(sources=obs)

    def test_duplicate_observation_id_fails_source_pin(self):
        obs = source_readback()
        obs["entries"][1]["id"] = obs["entries"][0]["id"]
        with self.assertRaisesRegex(InputError, "BRAID_SOURCE_PIN_MISMATCH"):
            run(sources=obs)

    def test_replaced_source_sha_fails_even_if_matched_count_is_14(self):
        obs = source_readback()
        obs["entries"][2]["blob_sha1"] = "f" * 40
        with self.assertRaisesRegex(InputError, "BRAID_SOURCE_PIN_MISMATCH"):
            run(sources=obs)

    def test_wrong_content_digest_type_fails(self):
        obs = source_readback()
        obs["entries"][3]["content_sha256"] = "NOT_SHA"
        with self.assertRaisesRegex(InputError, "BRAID_OBSERVATION_DIGEST_INVALID"):
            run(sources=obs)

    def test_false_missing_count_fails(self):
        obs = source_readback()
        obs["matched_count"] = 2
        with self.assertRaisesRegex(InputError, "BRAID_SOURCE_COUNT_MISMATCH"):
            run(sources=obs)

    def test_unknown_readback_field_refused(self):
        obs = source_readback()
        obs["private_key"] = "synthetic-only"
        with self.assertRaisesRegex(InputError, "BRAID_READBACK_FIELDS_INVALID"):
            run(sources=obs)

    def test_unmatched_source_cannot_have_fake_zero_count(self):
        obs = source_readback()
        obs["entries"][0].update(status="UNAVAILABLE", byte_length=0,
                                 content_sha256=None)
        obs["state"] = "HOLD"
        obs["matched_count"] -= 1
        with self.assertRaisesRegex(InputError, "BRAID_MISSING_SOURCE_NOT_UNKNOWN"):
            run(sources=obs)

    def test_forged_prod_authority_from_db_agent_refused(self):
        plan = plan_fixture()
        plan["production_authorized"] = True
        with self.assertRaisesRegex(InputError, "PLAN_EFFECT_CLAIM_REFUSED"):
            run(plan=plan)

    def test_recomputed_plan_hash_cannot_add_effect(self):
        plan = plan_fixture()
        plan["actions"][0]["effect_contract"] = "WRITE_TO_PRODUCTION"
        subset = {k: v for k, v in plan.items()
                  if k not in ("content_sha256", "signature_state")}
        plan["content_sha256"] = hashlib.sha256(json.dumps(
            subset, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True).encode()).hexdigest()
        with self.assertRaisesRegex(InputError, "PLAN_ACTION_CONTRACT_MISMATCH"):
            run(plan=plan)

    def test_lake_receipt_cannot_be_promoted_by_policy(self):
        policy = deepcopy(BRAID_POLICY)
        policy["lake_receipt_emission"] = "CANONICALLY_SIGNED"
        with self.assertRaisesRegex(InputError, "BRAID_AUTHORITY_CLAIM_REFUSED"):
            run(policy=policy)

    def test_loop_budget_5_never_6_or_unbounded(self):
        policy = deepcopy(BRAID_POLICY)
        policy["max_steps"] = 6
        with self.assertRaisesRegex(InputError, "BRAID_POLICY_INVALID"):
            run(policy=policy)

    def test_chain_checksum_tamper_detected(self):
        p = run()
        p["loop_trace"][1]["sha256"] = "f" * 64
        with self.assertRaisesRegex(InputError, "BRAID_TRACE_HASH_MISMATCH"):
            verify_report(p, BRAID_POLICY, plan_fixture())

    def test_chain_link_tamper_detected(self):
        p = run()
        p["loop_trace"][2]["prev_sha256"] = "1" * 64
        with self.assertRaisesRegex(InputError, "BRAID_TRACE_CONTRACT_DRIFT"):
            verify_report(p, BRAID_POLICY, plan_fixture())

    def test_historical_sum_weight_tamper_detected(self):
        p = run()
        p["khipu_root_observed_unit_sum"] = 15
        with self.assertRaisesRegex(InputError, "BRAID_KHIPU_CONSERVATION_DRIFT"):
            verify_report(p, BRAID_POLICY, plan_fixture())

    def test_false_verifier_promotion_detected(self):
        p = run()
        p["lean_checker_result"] = "ALL_THEOREMS_PROVED"
        with self.assertRaisesRegex(InputError, "BRAID_FALSE_AUTHORITY_CLAIM"):
            verify_report(p, BRAID_POLICY, plan_fixture())

    def test_unknown_report_claim_field_refused(self):
        p = run()
        p["formal_proof_verified"] = True
        with self.assertRaisesRegex(InputError, "BRAID_REPORT_FIELDS_INVALID"):
            verify_report(p, BRAID_POLICY, plan_fixture())

    def test_rehashed_untrue_phase_status_still_refused(self):
        p = run()
        p["loop_trace"][3]["state"] = "OBSERVED"
        prior = p["loop_trace"][3]["prev_sha256"]
        for i in (3, 4):
            step = p["loop_trace"][i]
            step["prev_sha256"] = prior
            raw = {k: v for k, v in step.items() if k != "sha256"}
            step["sha256"] = hashlib.sha256(json.dumps(
                raw, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True).encode()).hexdigest()
            prior = step["sha256"]
        with self.assertRaisesRegex(InputError, "BRAID_TRACE_CONTRACT_DRIFT"):
            verify_report(p, BRAID_POLICY, plan_fixture())

    def test_wrong_action_set_detected(self):
        p = run()
        p["db_actions_inert"].append("RUN_SQL")
        with self.assertRaisesRegex(InputError, "BRAID_REPORT_PLAN_DRIFT"):
            verify_report(p, BRAID_POLICY, plan_fixture())

    def test_deterministic_braid_at_same_inputs(self):
        self.assertEqual(run(), run())

    def test_cli_writes_private_receipt_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td)
            inputplan = dest / "db-plan.json"
            readback = dest / "source-readback.json"
            output = dest / "braid.json"
            inputplan.write_text(json.dumps(plan_fixture()), encoding="utf-8")
            obs = source_readback(at=datetime.now(timezone.utc))
            readback.write_text(json.dumps(obs), encoding="utf-8")
            args = [
                "--braid-policy", str(ROOT / "governance/database_contracts/ouroboros_braid_v1.json"),
                "--source-readback", str(readback),
                "--db-plan", str(inputplan),
                "--db-action-policy", str(ROOT / "governance/database_contracts/database_agentic_actions_v1.json"),
                "--source-policy", str(ROOT / "governance/database_contracts/memory_covenant_v2.json"),
                "--output", str(output),
            ]
            self.assertEqual(main(args), 2)
            data = json.loads(output.read_text())
            self.assertEqual(data["executed_steps"], 5)
            self.assertFalse(data["production_authorized"])
            self.assertEqual(main(args), 3)  # never overwrite receipts


if __name__ == "__main__":
    unittest_main()
