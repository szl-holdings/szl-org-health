# SPDX-License-Identifier: Apache-2.0
"""Adversarial read-frontier mathematics; no clocks, models, or DB clients launched."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.database_causal_frontier import (
    FrontierInputError,
    POLICY_SCHEMA,
    RESULT_SCHEMA,
    SNAPSHOT_SCHEMA,
    evaluate,
    main,
    policy_data,
    strict_json,
)

POLICY = json.loads(
    (ROOT / "governance/database_contracts/memory_causal_frontier_v1.json")
    .read_text(encoding="utf-8")
)
NOW = datetime(2026, 11, 18, 1, 0, tzinfo=timezone.utc)
DIGEST = "a" * 64


def readback(request_version=97):
    return {
        "schema": SNAPSHOT_SCHEMA,
        "state": "OBSERVED",
        "observed_at": NOW.isoformat(),
        "source_binding": deepcopy(POLICY["source_binding"]),
        "timeline": POLICY["timeline"],
        "requested_version": request_version,
        "catalog_admission": {
            "schema": "szl.database-catalog-admission/v1",
            "state": "CATALOG_MATCH_ONLY",
            "production_authorized": False,
            "source_identity_independently_verified": False,
            "catalog_sha256": DIGEST,
        },
        "stages": [
            {
                "name": name,
                "state": "OBSERVED",
                "timeline": POLICY["timeline"],
                "since_version": 90 + idx,
                "upper_version": 100 + (idx % 3),
                "observed_at": NOW.isoformat(),
                "declared_digest_sha256": DIGEST,
            }
            for idx, name in enumerate(POLICY["required_stages"])
        ],
        "credentials_recorded": False,
    }


def verdict(snapshot, policy=None):
    return evaluate(deepcopy(policy or POLICY), snapshot, at=NOW)


def gap_codes(result):
    return {row["code"] for row in result["gaps"]}


class CausalFrontierTests(unittest.TestCase):
    def test_policy_is_source_bound_and_nonempty(self):
        self.assertEqual(policy_data(deepcopy(POLICY))["schema"], POLICY_SCHEMA)
        self.assertEqual(len(POLICY["required_stages"]), 4)

    def test_complete_frontier_matches_structurally_only(self):
        d = verdict(readback())
        self.assertEqual(d["schema"], RESULT_SCHEMA)
        self.assertEqual(d["state"], "STRUCTURAL_FRONTIER_MATCH_ONLY")
        self.assertEqual(d["gap_count"], 0)
        self.assertEqual(d["intersection"], {
            "since_inclusive": 93, "upper_exclusive": 100
        })
        self.assertEqual(d["upper_version_spread"], 2)
        self.assertEqual(d["coverage_numerator"], 4)
        self.assertEqual(d["coverage_denominator"], 4)
        for key in ("true_time_available", "external_consistency_proven",
                    "production_authorized", "effects_authorized", "database_queried",
                    "source_identity_independently_verified", "replication_proven",
                    "stage_digests_independently_verified"):
            self.assertIs(d[key], False, key)

    def test_source_hash_declared_but_not_independently_verified(self):
        d = verdict(readback())
        self.assertFalse(d["source_identity_independently_verified"])
        self.assertFalse(d["external_consistency_proven"])

    def test_min_upper_is_exclusive(self):
        d = verdict(readback(100))
        self.assertIn("READ_VERSION_OUTSIDE_STAGE_FRONTIER", gap_codes(d))
        self.assertEqual(d["state"], "HOLD")

    def test_max_since_is_inclusive(self):
        d = verdict(readback(93))
        self.assertEqual(d["state"], "STRUCTURAL_FRONTIER_MATCH_ONLY")

    def test_read_before_any_since_is_unavailable(self):
        d = verdict(readback(89))
        self.assertIn("READ_VERSION_OUTSIDE_STAGE_FRONTIER", gap_codes(d))

    def test_index_lag_denies_read(self):
        c = readback()
        next(x for x in c["stages"] if x["name"] == "retrieval_index")[
            "upper_version"] = 95
        self.assertIn("READ_VERSION_OUTSIDE_STAGE_FRONTIER", gap_codes(verdict(c)))

    def test_only_one_stale_stage_blocks_all(self):
        c = readback()
        c["stages"][0]["observed_at"] = (NOW - timedelta(hours=2)).isoformat()
        self.assertIn("STAGE_STALE", gap_codes(verdict(c)))

    def test_snapshot_stale_blocks_all(self):
        c = readback()
        c["observed_at"] = (NOW - timedelta(hours=2)).isoformat()
        self.assertIn("SNAPSHOT_STALE", gap_codes(verdict(c)))

    def test_stage_from_future_is_untrusted(self):
        c = readback()
        c["stages"][0]["observed_at"] = (NOW + timedelta(minutes=6)).isoformat()
        self.assertIn("STAGE_FUTURE", gap_codes(verdict(c)))

    def test_snapshot_from_future_is_untrusted(self):
        c = readback()
        c["observed_at"] = (NOW + timedelta(minutes=6)).isoformat()
        self.assertIn("SNAPSHOT_FUTURE", gap_codes(verdict(c)))

    def test_missing_stage_is_hold_with_denominator(self):
        c = readback()
        c["stages"].pop()
        d = verdict(c)
        self.assertIn("REQUIRED_STAGE_MISSING", gap_codes(d))
        self.assertEqual(d["coverage_denominator"], 4)
        self.assertEqual(d["coverage_numerator"], 3)
        self.assertIs(d["intersection"], None)

    def test_unavailable_stage_cannot_fake_bounds(self):
        c = readback()
        row = c["stages"][0]
        row.update(state="UNAVAILABLE", since_version=None, upper_version=None,
                   observed_at=None, declared_digest_sha256=None)
        d = verdict(c)
        self.assertIn("REQUIRED_STAGE_UNAVAILABLE", gap_codes(d))
        self.assertEqual(d["coverage_numerator"], 3)
        row["upper_version"] = 200
        with self.assertRaisesRegex(FrontierInputError, "UNAVAILABLE_STAGE_FABRICATED"):
            verdict(c)

    def test_denied_stage_does_not_get_treated_as_observed(self):
        c = readback()
        c["stages"][0].update(state="DENIED", since_version=None,
                              upper_version=None, observed_at=None,
                              declared_digest_sha256=None)
        self.assertIn("REQUIRED_STAGE_UNAVAILABLE", gap_codes(verdict(c)))

    def test_broken_catalog_holds_even_if_all_frontiers_overlap(self):
        c = readback()
        c["catalog_admission"]["state"] = "HOLD"
        self.assertIn("CATALOG_NOT_ADMITTED", gap_codes(verdict(c)))

    def test_catalog_digest_required_not_signature(self):
        c = readback()
        c["catalog_admission"]["catalog_sha256"] = None
        self.assertIn("CATALOG_DIGEST_UNAVAILABLE", gap_codes(verdict(c)))

    def test_catalog_attempts_to_grant_production_are_refused(self):
        c = readback()
        c["catalog_admission"]["production_authorized"] = True
        with self.assertRaisesRegex(FrontierInputError, "CATALOG_AUTHORITY_CLAIM_REFUSED"):
            verdict(c)

    def test_mixed_timelines_are_never_compared(self):
        c = readback()
        c["stages"][0]["timeline"] = "szl.unrelated_sequence"
        self.assertIn("STAGE_TIMELINE_MISMATCH", gap_codes(verdict(c)))

    def test_snapshot_timeline_mismatch_is_not_converted(self):
        c = readback()
        c["timeline"] = "szl.unrelated_sequence"
        self.assertIn("TIMELINE_MISMATCH", gap_codes(verdict(c)))

    def test_unreviewed_extra_stage_is_hold(self):
        c = readback()
        stage = deepcopy(c["stages"][0])
        stage["name"] = "hidden_cache"
        c["stages"].append(stage)
        self.assertIn("UNREVIEWED_STAGE_PRESENT", gap_codes(verdict(c)))

    def test_duplicate_stage_refused(self):
        c = readback()
        c["stages"].append(deepcopy(c["stages"][0]))
        with self.assertRaisesRegex(FrontierInputError, "DUPLICATE_STAGE"):
            verdict(c)

    def test_noninteger_bool_nan_or_negative_versions_refused(self):
        for value in (True, 1.5, -1, None, "97", 2**65):
            c = readback()
            c["requested_version"] = value
            with self.subTest(value=value), self.assertRaisesRegex(
                    FrontierInputError, "VERSION_INVALID"):
                verdict(c)

    def test_overlapping_intervals_without_common_version_hold(self):
        c = readback()
        c["stages"][0]["since_version"] = 102
        c["stages"][0]["upper_version"] = 103
        self.assertIn("FRONTIER_INTERSECTION_EMPTY", gap_codes(verdict(c)))

    def test_empty_local_interval_is_hold_not_exeption(self):
        c = readback()
        c["stages"][0]["since_version"] = 100
        c["stages"][0]["upper_version"] = 100
        self.assertIn("READ_VERSION_OUTSIDE_STAGE_FRONTIER", gap_codes(verdict(c)))

    def test_reverse_interval_is_invalid(self):
        c = readback()
        c["stages"][0]["since_version"] = 104
        c["stages"][0]["upper_version"] = 103
        with self.assertRaisesRegex(FrontierInputError, "FRONTIER_ORDER_INVALID"):
            verdict(c)

    def test_stage_skew_above_policy_bound_holds(self):
        c = readback()
        c["stages"][1]["upper_version"] = 120
        d = verdict(c)
        self.assertIn("FRONTIER_SKEW_EXCEEDED", gap_codes(d))
        self.assertGreater(d["upper_version_spread"], POLICY["max_version_skew"])

    def test_wrong_source_subject_holds_without_switching_authority(self):
        c = readback()
        c["source_binding"]["git_blob_sha1"] = "f" * 40
        self.assertIn("SOURCE_SUBJECT_MISMATCH", gap_codes(verdict(c)))

    def test_empty_required_denominator_refused(self):
        p = deepcopy(POLICY)
        p["required_stages"] = []
        with self.assertRaisesRegex(FrontierInputError, "STAGE_POLICY_INVALID"):
            verdict(readback(), p)

    def test_duplicate_required_stage_refused(self):
        p = deepcopy(POLICY)
        p["required_stages"].append(p["required_stages"][0])
        with self.assertRaisesRegex(FrontierInputError, "STAGE_POLICY_INVALID"):
            verdict(readback(), p)

    def test_policy_skew_bool_refused(self):
        p = deepcopy(POLICY)
        p["max_version_skew"] = True
        with self.assertRaisesRegex(FrontierInputError, "SKEW_POLICY_INVALID"):
            verdict(readback(), p)

    def test_unexpected_sensitive_data_fields_refused(self):
        c = readback()
        c["password"] = "synthetic"
        with self.assertRaisesRegex(FrontierInputError, "FIELDS_INVALID"):
            verdict(c)

    def test_recorded_credentials_flag_is_refused(self):
        c = readback()
        c["credentials_recorded"] = True
        with self.assertRaisesRegex(FrontierInputError, "CREDENTIAL_CONTENT_REFUSED"):
            verdict(c)

    def test_nonfinite_duplicate_and_empty_json_refused(self):
        for raw in (b'{"a":1,"a":2}', b'{"v":NaN}', b""):
            with self.subTest(raw=raw), self.assertRaises(FrontierInputError):
                strict_json(raw)

    def test_unaware_timestamp_refused(self):
        c = readback()
        c["observed_at"] = "2026-11-18T01:00:00"
        with self.assertRaisesRegex(FrontierInputError, "TIMESTAMP_INVALID"):
            verdict(c)

    def test_unobserved_snapshot_refused_before_scoring(self):
        c = readback()
        c["state"] = "INVALID"
        with self.assertRaisesRegex(FrontierInputError, "SNAPSHOT_STATE_INVALID"):
            verdict(c)

    def test_cli_exit_zero_holds_production_and_exclusive_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            parent = Path(td)
            p = parent / "policy.json"
            s = parent / "snapshot.json"
            out = parent / "receipt.json"
            p.write_text(json.dumps(POLICY), encoding="utf-8")
            example = readback()
            instant = datetime.now(timezone.utc).isoformat()
            example["observed_at"] = instant
            for stage in example["stages"]:
                stage["observed_at"] = instant
            s.write_text(json.dumps(example), encoding="utf-8")
            self.assertEqual(main(["--policy", str(p), "--readback", str(s),
                                   "--output", str(out)]), 0)
            result = json.loads(out.read_text(encoding="utf-8"))
            self.assertFalse(result["production_authorized"])
            with self.assertRaises(FileExistsError):
                main(["--policy", str(p), "--readback", str(s),
                      "--output", str(out)])

    def test_cli_unavailable_stage_returns_two(self):
        with tempfile.TemporaryDirectory() as td:
            parent = Path(td)
            p = parent / "policy.json"
            s = parent / "snapshot.json"
            p.write_text(json.dumps(POLICY), encoding="utf-8")
            example = readback()
            instant = datetime.now(timezone.utc).isoformat()
            example["observed_at"] = instant
            example["catalog_admission"]["state"] = "HOLD"
            for stage in example["stages"]:
                stage.update(state="UNAVAILABLE", since_version=None,
                             upper_version=None, observed_at=None,
                             declared_digest_sha256=None)
            s.write_text(json.dumps(example), encoding="utf-8")
            self.assertEqual(main(["--policy", str(p), "--readback", str(s)]), 2)

    def test_cli_malformed_file_returns_three(self):
        with tempfile.TemporaryDirectory() as td:
            parent = Path(td)
            p = parent / "policy.json"
            s = parent / "snapshot.json"
            p.write_text(json.dumps(POLICY), encoding="utf-8")
            s.write_text('{"a":1,"a":2}', encoding="utf-8")
            self.assertEqual(main(["--policy", str(p), "--readback", str(s)]), 3)


if __name__ == "__main__":
    unittest.main()
