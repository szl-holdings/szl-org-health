# SPDX-License-Identifier: Apache-2.0
"""Adversarial tests for an inert, source-owned agentic database work planner.

No provider, network, SQL, filesystem mutations except isolated test receipts.
"""
# ruff: noqa: E402  # -I test loader explicitly binds reviewed checkout below.
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
from tools.database_agentic_planner import (
    CATALOG_SCHEMA, FRONTIER_SCHEMA, InputError, POLICY_SCHEMA,
    ROLE_SCHEMA, SCHEMA, main, propose, validate_policy, verify_plan,
)

POLICY = json.loads((ROOT / "governance/database_contracts/database_agentic_actions_v1.json").read_text())
SOURCE_POLICY = json.loads((ROOT / "governance/database_contracts/memory_covenant_v2.json").read_text())
AT = datetime(2026, 11, 18, 4, 23, 0, tzinfo=timezone.utc)
SHA = "a" * 64


def catalog():
    return {
        "schema": CATALOG_SCHEMA,
        "state": "HOLD",
        "contract_id": POLICY["catalog_contract_id"],
        "catalog_observed_at": (AT - timedelta(minutes=1)).isoformat(),
        "catalog_sha256": SHA, "policy_sha256": SHA,
        "gap_count": 4,
        "gaps": [
            {"code": "TABLE_NOT_OBSERVED", "object": "public.memory_context_bindings"},
            {"code": "SECURITY_DEFINER_DRIFT", "object": "public.a11oy_memory_context_matches"},
            {"code": "PRINCIPAL_BINDING_UNOBSERVED", "object": "public.a11oy_memory_context_matches"},
            {"code": "CONTEXT_BINDING_UNOBSERVED", "object": "public.a11oy_memory_context_matches"},
        ],
        "required_tables": 8, "observed_tables": 7,
        "required_functions": 1, "observed_functions": 1,
        "database_queried_by_this_verifier": False, "external_writes_performed": False,
        "migration_authorized": False, "production_authorized": False,
        "source_identity_independently_verified": False, "independent_witness": False,
        "reported_source_blob_matches": True,
    }


def frontier():
    return {
        "schema": FRONTIER_SCHEMA, "state": "HOLD",
        "contract_id": POLICY["frontier_contract_id"],
        "coverage_denominator": 4, "coverage_numerator": 0,
        "database_queried": False, "effects_authorized": False,
        "external_consistency_proven": False,
        "gap_count": 6,
        "gaps": [
            {"code": "CATALOG_NOT_ADMITTED"},
            {"code": "REQUIRED_STAGE_UNAVAILABLE", "stage": "source_ledger"},
            {"code": "REQUIRED_STAGE_UNAVAILABLE", "stage": "transactional_outbox"},
            {"code": "REQUIRED_STAGE_UNAVAILABLE", "stage": "retrieval_index"},
            {"code": "REQUIRED_STAGE_UNAVAILABLE", "stage": "api_projection"},
            {"code": "SNAPSHOT_INCOMPLETE"},
        ],
        "intersection": None, "observed_stage_count": 0,
        "policy_sha256": SHA, "production_authorized": False,
        "replication_proven": False, "requested_version": 0,
        "required_stage_count": 4, "schema_migrated_by_this_verifier": False,
        "snapshot_sha256": SHA, "source_identity_independently_verified": False,
        "stage_digests_independently_verified": False, "true_time_available": False,
        "upper_version_spread": None,
    }


def role(count=0):
    return {
        "schema": ROLE_SCHEMA, "state": "OBSERVED",
        "scope": "A11OY_MEMORY_VALIDATION", "observed_at": AT.isoformat(),
        "least_privileged_login_count": count, "credentials_recorded": False,
    }


def plan(c=None, f=None, r=None, policy=None, now=AT):
    return propose(policy or deepcopy(POLICY), c or catalog(), f or frontier(),
                   role_posture=role() if r is None else r, at=now,
                   catalog_sha=SHA, frontier_sha=SHA, role_sha=SHA)


class AgenticDatabaseTests(TestCase):
    def test_source_policy_is_pinned_and_closed(self):
        validate_policy(deepcopy(POLICY), SOURCE_POLICY)
        self.assertEqual(POLICY["schema"], POLICY_SCHEMA)
        self.assertEqual(POLICY["source_binding"]["git_blob_sha1"],
                         "18050de00db455da9b6db67244bd5d2f6fb8ee56")

    def test_actual_known_drift_produces_inert_prioritized_plan(self):
        p = plan()
        ids = [a["action_id"] for a in p["actions"]]
        self.assertEqual(p["schema"], SCHEMA)
        self.assertEqual(p["state"], "HOLD")
        for item in ("REHEARSE_BINDING_MIGRATION", "QUALIFY_AUDIT_ROLE",
                     "INSTRUMENT_SOURCE_EPOCH", "INSTRUMENT_OUTBOX_ACK",
                     "VERIFY_RETRIEVAL_FRONTIER", "VERIFY_API_PROJECTION"):
            self.assertIn(item, ids)
        self.assertNotIn("RECOLLECT_CATALOG", ids)
        self.assertNotIn("REVIEW_RLS_POLICY", ids)
        self.assertEqual(p["catalog_coverage"], {
            "numerator": 7, "denominator": 8, "scope": "TABLE_PRESENCE_COUNT_ONLY"})
        self.assertEqual(p["frontier_coverage"], {
            "numerator": 0, "denominator": 4,
            "scope": "SOURCE_REPORTED_STAGE_COVERAGE_ONLY"})
        for key in ("production_authorized", "database_queried",
                    "sql_generated", "sql_executed", "external_effects_performed",
                    "independent_witness", "source_identity_independently_verified",
                    "frontier_observation_freshness_verified"):
            self.assertIs(p[key], False, key)
        self.assertTrue(verify_plan(p, POLICY))

    def test_every_action_has_provenance_and_no_execution(self):
        p = plan()
        self.assertGreater(p["action_count"], 3)
        for a in p["actions"]:
            self.assertTrue(a["trigger_codes"])
            self.assertEqual(a["state"], "PROPOSED_NOT_EXECUTED")
            for key in ("tool_invocation", "approval_recorded",
                        "verification_complete", "sql_generated"):
                self.assertFalse(a[key], key)
        self.assertEqual(p["signature_state"], "UNSIGNED_STRUCTURAL_HASH_ONLY")

    def test_plan_hash_is_deterministic_same_receipt(self):
        a, b = plan(), plan()
        self.assertEqual(a, b)
        self.assertEqual(a["content_sha256"], b["content_sha256"])
        self.assertEqual(len(a["content_sha256"]), 64)

    def test_tampering_action_or_plan_hash_is_rejected(self):
        p = plan()
        p["actions"][0]["scope"] = "PRODUCTION_AUTO_EXECUTE"
        with self.assertRaisesRegex(InputError, "PLAN_ACTION_CONTRACT_MISMATCH"):
            verify_plan(p, POLICY)

    def test_recomputed_hash_cannot_approve_unreviewed_effect(self):
        p = plan()
        p["actions"][0]["effect_contract"] = "AUTO_APPLY_PRODUCTION"
        payload = {k: v for k, v in p.items()
                   if k not in ("content_sha256", "signature_state")}
        p["content_sha256"] = hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False).encode()).hexdigest()
        with self.assertRaisesRegex(InputError, "PLAN_ACTION_CONTRACT_MISMATCH"):
            verify_plan(p, POLICY)

    def test_role_status_unknown_fabricated_count_is_refused(self):
        r = role(99)
        r["state"] = "UNAVAILABLE"
        with self.assertRaisesRegex(InputError, "ROLE_COUNT_INVALID"):
            plan(r=r)

    def test_unsafe_authority_claim_from_inputs_refused(self):
        for kind in ("catalog", "frontier"):
            c, f = catalog(), frontier()
            target = c if kind == "catalog" else f
            target["production_authorized"] = True
            with self.subTest(kind=kind), self.assertRaisesRegex(InputError,
                                                                   "PRIVILEGED_RECEIPT_REFUSED"):
                plan(c, f)

    def test_effect_claim_refused_before_planning(self):
        c = catalog()
        c["external_writes_performed"] = True
        with self.assertRaisesRegex(InputError, "EFFECT_CLAIM_REFUSED"):
            plan(c=c)
        f = frontier()
        f["effects_authorized"] = True
        with self.assertRaisesRegex(InputError, "EFFECT_CLAIM_REFUSED"):
            plan(f=f)

    def test_independent_rls_policy_gap_gets_specific_review(self):
        c = catalog()
        c["gaps"].append({"code": "RLS_STATE_DRIFT",
                          "object": "public.memory_records"})
        c["gap_count"] += 1
        p = plan(c=c)
        self.assertIn("REVIEW_RLS_POLICY",
                      [a["action_id"] for a in p["actions"]])

    def test_missing_role_readback_means_unavailable(self):
        p = propose(POLICY, catalog(), frontier(), at=AT)
        a = next(x for x in p["actions"] if x["action_id"] == "QUALIFY_AUDIT_ROLE")
        self.assertIn("AUDITOR_LEAST_PRIVILEGE_NOT_OBSERVED", a["trigger_codes"])

    def test_observed_non_privileged_role_removes_only_role_action(self):
        p = plan(r=role(1))
        ids = [a["action_id"] for a in p["actions"]]
        self.assertNotIn("QUALIFY_AUDIT_ROLE", ids)
        self.assertIn("REHEARSE_BINDING_MIGRATION", ids)
        self.assertFalse(p["production_authorized"])

    def test_stale_observation_adds_recollection(self):
        c = catalog()
        c["catalog_observed_at"] = (AT - timedelta(days=2)).isoformat()
        p = plan(c=c)
        self.assertIn("CATALOG_STALE", p["finding_codes"])
        self.assertIn("RECOLLECT_CATALOG", [a["action_id"] for a in p["actions"]])

    def test_future_observation_adds_recollection(self):
        c = catalog()
        c["catalog_observed_at"] = (AT + timedelta(minutes=7)).isoformat()
        self.assertIn("CATALOG_IN_FUTURE", plan(c=c)["finding_codes"])

    def test_malformed_timestamp_refused(self):
        c = catalog()
        c["catalog_observed_at"] = "2026-11-18T00:00:00"
        with self.assertRaisesRegex(InputError, "OBSERVATION_TIMESTAMP_INVALID"):
            plan(c=c)

    def test_extra_secret_field_refused(self):
        c = catalog()
        c["database_password"] = "synthetic-only"
        with self.assertRaisesRegex(InputError, "CATALOG_FIELDS_INVALID"):
            plan(c=c)

    def test_wrong_source_blob_refused(self):
        p = deepcopy(POLICY)
        p["source_binding"]["git_blob_sha1"] = "f" * 40
        with self.assertRaisesRegex(InputError, "AGENT_SOURCE_MISMATCH"):
            validate_policy(p, SOURCE_POLICY)

    def test_unknown_action_registration_refused(self):
        p = deepcopy(POLICY)
        p["allowed_actions"].append("DROP_ALL_TABLES")
        with self.assertRaisesRegex(InputError, "AGENT_ACTION_POLICY_INVALID"):
            validate_policy(p, SOURCE_POLICY)

    def test_false_coverage_denominator_refused(self):
        f = frontier()
        f["coverage_denominator"] = 0
        with self.assertRaisesRegex(InputError, "FRONTIER_COVERAGE_INVALID"):
            plan(f=f)

    def test_overcount_boolean_coverage_refused(self):
        for x in (True, 5, -1, "4"):
            f = frontier()
            f["coverage_numerator"] = x
            with self.subTest(value=x), self.assertRaisesRegex(InputError,
                                                                 "FRONTIER_COVERAGE_INVALID"):
                plan(f=f)

    def test_duplicate_gap_refused(self):
        c = catalog()
        c["gaps"].append(deepcopy(c["gaps"][0]))
        c["gap_count"] = 5
        with self.assertRaisesRegex(InputError, "DUPLICATE_FINDING"):
            plan(c=c)

    def test_gap_count_mismatch_refused(self):
        f = frontier()
        f["gap_count"] = 7
        with self.assertRaisesRegex(InputError, "FINDING_COUNT_MISMATCH"):
            plan(f=f)

    def test_unknown_gap_remains_hold_and_escalates_no_action(self):
        c = catalog()
        c["gaps"].append({"code": "UNKNOWN_NEW_SECURITY_GATE",
                          "object": "public.memory_records"})
        c["gap_count"] += 1
        p = plan(c=c)
        self.assertEqual(p["state"], "HOLD")
        self.assertEqual(p["unmapped_codes"], ["UNKNOWN_NEW_SECURITY_GATE"])
        self.assertEqual(p["actions"][0]["action_id"],
                         "ESCALATE_UNMAPPED_FINDINGS")
        self.assertIs(p["actions"][0]["tool_invocation"], False)

    def test_missing_one_frontier_stage_only_triggers_its_owner(self):
        f = frontier()
        f["gaps"] = [{"code": "REQUIRED_STAGE_UNAVAILABLE",
                       "stage": "retrieval_index"}]
        f["gap_count"] = 1
        p = plan(f=f)
        ids = [a["action_id"] for a in p["actions"]]
        self.assertIn("VERIFY_RETRIEVAL_FRONTIER", ids)
        self.assertNotIn("INSTRUMENT_SOURCE_EPOCH", ids)
        self.assertNotIn("INSTRUMENT_OUTBOX_ACK", ids)

    def test_not_all_four_stage_gaps_requires_no_fabricated_proof(self):
        f = frontier()
        f["gaps"] = [{"code": "SNAPSHOT_INCOMPLETE"}]
        f["gap_count"] = 1
        ids = [a["action_id"] for a in plan(f=f)["actions"]]
        for act in ("INSTRUMENT_SOURCE_EPOCH", "VERIFY_RETRIEVAL_FRONTIER",
                    "INSTRUMENT_OUTBOX_ACK", "VERIFY_API_PROJECTION"):
            self.assertNotIn(act, ids)

    def test_no_authority_even_when_structural_evidence_perfect(self):
        c = catalog()
        c["state"] = "CATALOG_MATCH_ONLY"
        c["gap_count"] = 0
        c["gaps"] = []
        c["observed_tables"] = c["required_tables"]
        f = frontier()
        f["state"] = "STRUCTURAL_FRONTIER_MATCH_ONLY"
        f["gap_count"] = 0
        f["gaps"] = []
        f["coverage_numerator"] = 4
        p = plan(c=c, f=f, r=role(1))
        self.assertEqual(p["state"], "STRUCTURAL_ONLY")
        self.assertFalse(p["production_authorized"])
        self.assertFalse(p["frontier_observation_freshness_verified"])
        self.assertEqual(p["action_count"], 0)

    def test_stale_role_readback_requires_review(self):
        old = role(1)
        old["observed_at"] = (AT - timedelta(days=2)).isoformat()
        self.assertIn("QUALIFY_AUDIT_ROLE", [a["action_id"] for a in plan(r=old)["actions"]])

    def test_role_posture_has_closed_fields(self):
        r = role()
        r["db_uri"] = "fake://synthetic"
        with self.assertRaisesRegex(InputError, "ROLE_POSTURE_INVALID"):
            plan(r=r)

    def test_invalid_stage_subject_refused(self):
        f = frontier()
        f["gaps"][1]["stage"] = "../../private"
        with self.assertRaisesRegex(InputError, "FINDING_SUBJECT_INVALID"):
            plan(f=f)

    def test_max_action_budget_never_silently_truncates(self):
        p = deepcopy(POLICY)
        p["max_actions"] = 1
        with self.assertRaisesRegex(InputError, "AGENT_PLAN_BUDGET_EXCEEDED"):
            plan(policy=p)

    def test_cli_writes_private_inert_receipt_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            dest = Path(folder)
            c = catalog()
            c["catalog_observed_at"] = datetime.now(timezone.utc).isoformat()
            c["policy_sha256"] = hashlib.sha256(
                (ROOT / "governance/database_contracts/memory_covenant_v2.json")
                .read_bytes()).hexdigest()
            f = frontier()
            f["policy_sha256"] = hashlib.sha256(
                (ROOT / "governance/database_contracts/memory_causal_frontier_v1.json")
                .read_bytes()).hexdigest()
            r = role(0)
            r["observed_at"] = datetime.now(timezone.utc).isoformat()
            args = [
                "--catalog", str(dest / "catalog.json"),
                "--frontier", str(dest / "frontier.json"),
                "--role-posture", str(dest / "role.json"),
                "--policy", str(ROOT / "governance/database_contracts/database_agentic_actions_v1.json"),
                "--source-policy", str(ROOT / "governance/database_contracts/memory_covenant_v2.json"),
                "--output", str(dest / "plan.json"),
            ]
            for file, payload in (
                ("catalog.json", c), ("frontier.json", f),
                ("role.json", r),
            ):
                (dest / file).write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual(main(args), 2)
            value = json.loads((dest / "plan.json").read_text())
            self.assertTrue(verify_plan(value, POLICY))
            self.assertFalse(value["external_effects_performed"])
            self.assertEqual(main(args), 3)

    def test_cli_rejects_mismatched_source_policy_digest_before_output(self):
        with tempfile.TemporaryDirectory() as folder:
            dest = Path(folder)
            c, f = catalog(), frontier()
            c["catalog_observed_at"] = datetime.now(timezone.utc).isoformat()
            f["policy_sha256"] = hashlib.sha256(
                (ROOT / "governance/database_contracts/memory_causal_frontier_v1.json")
                .read_bytes()).hexdigest()
            (dest / "catalog.json").write_text(json.dumps(c), encoding="utf-8")
            (dest / "frontier.json").write_text(json.dumps(f), encoding="utf-8")
            result = dest / "never-written.json"
            args = ["--catalog", str(dest / "catalog.json"),
                    "--frontier", str(dest / "frontier.json"),
                    "--policy", str(ROOT / "governance/database_contracts/database_agentic_actions_v1.json"),
                    "--source-policy", str(ROOT / "governance/database_contracts/memory_covenant_v2.json"),
                    "--output", str(result)]
            self.assertEqual(main(args), 3)
            self.assertFalse(result.exists())

    def test_cli_no_source_path_write(self):
        # The only legal output path is outside the protected Git checkout.
        args = [
            "--catalog", "ignored", "--frontier", "ignored",
            "--policy", "ignored", "--source-policy", "ignored",
            "--output", str(ROOT / "NO_AGENT_PRIVATE_DATA_HERE.json"),
        ]
        # Invalid inputs cannot create a result inside the checkout.
        self.assertEqual(main(args), 3)
        self.assertFalse((ROOT / "NO_AGENT_PRIVATE_DATA_HERE.json").exists())


if __name__ == "__main__":
    unittest_main()
