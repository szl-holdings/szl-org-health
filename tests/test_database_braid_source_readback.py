# SPDX-License-Identifier: Apache-2.0
"""Synthetic source Git-blob checks, no real network or third-party imports."""
import base64
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from unittest import TestCase, main as unittest_main

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.database_braid_source_readback import (  # noqa: E402
    InputError, inspect, observe, validate_policy,
)

POLICY = json.loads((ROOT / "governance/database_contracts/ouroboros_braid_v1.json").read_text())


def sha1_blob(data):
    return hashlib.sha1(
        b"blob " + str(len(data)).encode() + b"\0" + data,
        usedforsecurity=False).hexdigest()


def fake_policy():
    p = deepcopy(POLICY)
    for row in p["source_refs"]:
        data = ("synthetic-only/" + row["id"]).encode()
        row["blob_sha1"] = sha1_blob(data)
    return p


def fake_fetch(entry):
    data = ("synthetic-only/" + entry["id"]).encode()
    return {
        "type": "file",
        "encoding": "base64",
        "sha": sha1_blob(data),
        "content": base64.b64encode(data).decode(),
    }


class SourceReadbackTests(TestCase):
    def test_policy_refs_are_exact_frozen_families(self):
        refs = validate_policy(POLICY)
        self.assertEqual(len(refs), 33)
        self.assertEqual(len({x["repository"] for x in refs}), 11)
        self.assertEqual(POLICY["lambda_claim"],
                         "UNCONDITIONAL_UNIQUENESS_DISPROVEN_AS_STATED")

    def test_fake_bytes_verify_git_object_hash(self):
        p = fake_policy()
        result = observe(p, fetch=fake_fetch,
                         at=datetime(2026, 11, 18, tzinfo=timezone.utc))
        self.assertEqual(result["state"], "COMPLETE_BLOB_MATCH")
        self.assertEqual(result["matched_count"], 33)
        self.assertEqual(result["required_count"], 33)
        self.assertTrue(all(x["content_sha256"] for x in result["entries"]))
        self.assertFalse(result["runtime_sources_independently_verified"])
        self.assertFalse(result["provider_writes"])
        self.assertFalse(result["lean_kernel_executed"])

    def test_fake_provider_metadata_sha_cannot_override_bytes(self):
        p = fake_policy()
        row = p["source_refs"][0]
        def forge(entry):
            d = fake_fetch(entry)
            d["content"] = base64.b64encode(b"tampered").decode()
            return d
        result = inspect(row, fetch=forge)
        self.assertEqual(result["status"], "MISMATCH")
        self.assertIsNone(result["content_sha256"])

    def test_provider_sha_mismatch_rejected(self):
        row = fake_policy()["source_refs"][0]
        def bad(entry):
            d = fake_fetch(entry)
            d["sha"] = "f" * 40
            return d
        self.assertEqual(inspect(row, fetch=bad)["status"], "MISMATCH")

    def test_absent_source_is_unavailable_not_zero(self):
        p = fake_policy()
        def missing(entry):
            if entry["id"] == "lean_khipu":
                raise RuntimeError("unavailable")
            return fake_fetch(entry)
        result = observe(p, fetch=missing)
        self.assertEqual(result["state"], "HOLD")
        self.assertEqual(result["matched_count"], 32)
        witness = next(x for x in result["entries"] if x["id"] == "lean_khipu")
        self.assertEqual(witness["status"], "UNAVAILABLE")
        self.assertIsNone(witness["byte_length"])

    def test_non_base64_cannot_fake_source(self):
        row = fake_policy()["source_refs"][0]
        def invalid(entry):
            d = fake_fetch(entry)
            d["content"] = "this is not base64@@@"
            return d
        self.assertEqual(inspect(row, fetch=invalid)["status"], "UNAVAILABLE")

    def test_duplicate_entry_rejected_at_policy_layer(self):
        p = fake_policy()
        p["source_refs"][1]["id"] = p["source_refs"][0]["id"]
        with self.assertRaises(InputError):
            validate_policy(p)

    def test_missing_ancient_source_ref_denied(self):
        p = fake_policy()
        p["source_refs"] = [r for r in p["source_refs"]
                            if r["id"] != "ancient_lineage"]
        p["source_refs_required"] = len(p["source_refs"])
        with self.assertRaisesRegex(InputError, "BRAID_SOURCE_FAMILY_INCOMPLETE"):
            validate_policy(p)

    def test_extra_unapproved_repository_ref_denied(self):
        p = fake_policy()
        p["source_refs"][0]["repository"] = "another-org/untrusted"
        with self.assertRaisesRegex(InputError, "BRAID_SOURCE_PIN_INVALID"):
            validate_policy(p)

    def test_axioms_egyptian_greek_and_codex_families_required(self):
        categories = {
            "AXIOM_SOURCE": 4,
            "EGYPTIAN_MATH": 4,
            "GREEK_MATH": 2,
            "GREEK_LOGIC": 4,
            "CODEX_ANALOGY": 5,
        }
        refs = validate_policy(POLICY)
        self.assertEqual(
            {tier: sum(x["tier"] == tier for x in refs)
             for tier in categories}, categories)
        for tier in categories:
            p = fake_policy()
            p["source_refs"] = [row for row in p["source_refs"]
                                if row["tier"] != tier]
            p["source_refs_required"] = len(p["source_refs"])
            with self.subTest(missing=tier), self.assertRaises(InputError):
                validate_policy(p)

    def test_axiom_reference_must_keep_axiom_classification(self):
        p = fake_policy()
        base = next(x for x in p["source_refs"]
                    if x["id"] == "axiom_base")
        base["tier"] = "HISTORICAL_LINEAGE"
        with self.assertRaisesRegex(
                InputError, "BRAID_SOURCE_FAMILY_TIER_DRIFT"):
            validate_policy(p)

    def test_greek_math_distinct_from_greek_philosophical_gates(self):
        p = fake_policy()
        theorem = next(x for x in p["source_refs"]
                       if x["id"] == "greek_pythagoras_hm")
        theorem["tier"] = "GREEK_LOGIC"
        with self.assertRaisesRegex(
                InputError, "BRAID_SOURCE_FAMILY_TIER_DRIFT"):
            validate_policy(p)

    def test_codex_analogies_cannot_be_reclassified_as_proofs(self):
        p = fake_policy()
        scroll = next(x for x in p["source_refs"]
                      if x["id"] == "codex_copper_scroll")
        scroll["tier"] = "LEAN_CARRIER"
        with self.assertRaisesRegex(
                InputError, "BRAID_SOURCE_FAMILY_TIER_DRIFT"):
            validate_policy(p)

    def test_unsupported_proof_tier_denied(self):
        p = fake_policy()
        p["source_refs"][0]["tier"] = "LEAN_PROVED_IN_PRODUCTION"
        with self.assertRaisesRegex(InputError, "BRAID_SOURCE_PIN_INVALID"):
            validate_policy(p)

    def test_formula_proof_promotion_denied(self):
        p = fake_policy()
        p["lean_proof_admission"] = "KERNEL_VERIFIED_ALL"
        with self.assertRaisesRegex(InputError, "BRAID_AUTHORITY_CLAIM_REFUSED"):
            validate_policy(p)

    def test_khipu_archaeological_rights_not_automatically_granted(self):
        p = fake_policy()
        p["archaeological_data_rights"] = "GRANTED"
        with self.assertRaisesRegex(InputError, "BRAID_AUTHORITY_CLAIM_REFUSED"):
            validate_policy(p)

    def test_hatun_effects_not_enabled_via_manifest(self):
        p = fake_policy()
        p["external_effects"] = "ALLOW_DDL"
        with self.assertRaisesRegex(InputError, "BRAID_AUTHORITY_CLAIM_REFUSED"):
            validate_policy(p)

    def test_budget_limit_never_unbounded(self):
        p = fake_policy()
        p["max_steps"] = 999
        with self.assertRaisesRegex(InputError, "BRAID_POLICY_INVALID"):
            validate_policy(p)


if __name__ == "__main__":
    unittest_main()
