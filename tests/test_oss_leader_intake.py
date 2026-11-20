"""No-network adversarial tests for a bounded, nonauthorizing OSS research join."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import json
import unittest

from tools import oss_leader_intake as mod

NOW = datetime(2026, 11, 20, 2, 45, tzinfo=timezone.utc)
SZL_SHA = "a" * 40
UPSTREAM_SHA = "b" * 40
REF_DIGEST = "c" * 64


def stamp(delta: int = -5) -> str:
    return (NOW + timedelta(seconds=delta)).isoformat().replace("+00:00", "Z")


def candidate() -> dict:
    repo = "ossf/scorecard"
    return {
        "upstream_repository": repo,
        "upstream_revision": UPSTREAM_SHA,
        "upstream_public": True,
        "github_observed_at_utc": stamp(),
        "github_license_spdx": "Apache-2.0",
        "license_file_sha256": None,
        "source_url": f"https://github.com/{repo}/commit/{UPSTREAM_SHA}",
        "official_reference": {
            "url": "https://scorecard.dev/", "retrieved_at": stamp(),
            "state": "MEASURED", "status": 200, "robots_allowed": True,
            "body_sha256": REF_DIGEST,
        },
        "publication_url": None,
        "szl_target_repository": "szl-holdings/szl-org-health",
        "intended_mode": "STUDY_DESIGN",
    }


def batch() -> dict:
    return {
        "schema": mod.SCHEMA, "pass_index": 1,
        "observed_at_utc": stamp(), "szl_source_sha": SZL_SHA,
        "candidates": [candidate()],
    }


def raw(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class OSSIntakeTests(unittest.TestCase):
    def result(self, data=None):
        return mod.evaluate(raw(data if data is not None else batch()), now=NOW)

    def test_positive_public_observation_is_only_research_reviewable(self):
        result = self.result()
        self.assertEqual(result["candidate_count_observed"], 1)
        self.assertEqual(result["research_reviewable_count"], 1)
        row = result["observations"][0]
        self.assertEqual(row["research_state"], "REPORTED_RESEARCH_EVIDENCE_REVIEWABLE")
        self.assertEqual(row["license_rights_state"], "INDEPENDENT_HUMAN_RIGHTS_REVIEW_REQUIRED")
        self.assertIn("LICENSE_FILE_DIGEST_UNOBSERVED", row["reasons"])
        for key in (
            "upstream_metadata_authenticated", "web_receipt_origin_authenticated",
            "publication_and_quality_verified", "license_rights_verified",
            "code_copy_authorized", "dependency_admission_authorized",
            "training_or_inference_authorized", "merge_authorized",
            "deployment_authorized", "monetization_authorized", "production_ready"
        ):
            self.assertIs(row[key], False, key)
        self.assertFalse(result["licensed_code_reuse_authorized"])
        self.assertFalse(result["source_automation_authorized"])
        self.assertFalse(result["ten_pass_campaign_complete"])
        self.assertEqual(len(result["unsigned_structural_sha256_not_signature"]), 64)

    def test_metadata_noassertion_does_not_prohibit_learning_or_allow_reuse(self):
        data = batch()
        data["candidates"][0]["github_license_spdx"] = "NOASSERTION"
        result = self.result(data)["observations"][0]
        self.assertEqual(result["research_state"], "REPORTED_RESEARCH_EVIDENCE_REVIEWABLE")
        self.assertIn("LICENSE_METADATA_UNRESOLVED", result["reasons"])
        self.assertFalse(result["code_copy_authorized"])

    def test_missing_license_metadata_distinct_from_rights(self):
        data = batch()
        data["candidates"][0]["github_license_spdx"] = None
        row = self.result(data)["observations"][0]
        self.assertIn("LICENSE_METADATA_MISSING", row["reasons"])
        self.assertEqual(row["license_rights_state"],
                         "INDEPENDENT_HUMAN_RIGHTS_REVIEW_REQUIRED")

    def test_declared_license_file_digest_never_becomes_legal_verification(self):
        data = batch()
        data["candidates"][0]["license_file_sha256"] = "d" * 64
        row = self.result(data)["observations"][0]
        self.assertIn("LICENSE_FILE_DIGEST_REPORTED_NOT_ATTESTED", row["reasons"])
        self.assertFalse(row["license_rights_verified"])

    def test_unobserved_pin_prevents_upstream_review(self):
        data = batch()
        data["candidates"][0]["upstream_revision"] = None
        data["candidates"][0]["source_url"] = None
        row = self.result(data)["observations"][0]
        self.assertEqual(row["research_state"], "HOLD_INCOMPLETE_RESEARCH_EVIDENCE")
        self.assertIn("UPSTREAM_COMMIT_UNOBSERVED", row["reasons"])

    def test_public_visibility_unknown_and_private_both_hold(self):
        for visibility in (False, None):
            with self.subTest(visibility=visibility):
                data = batch()
                data["candidates"][0]["upstream_public"] = visibility
                row = self.result(data)["observations"][0]
                self.assertIn("PUBLIC_VISIBILITY_UNVERIFIED", row["reasons"])

    def test_upstream_metadata_stale_or_future_hold(self):
        for delta in (-8 * 86400, 301):
            with self.subTest(delta=delta):
                data = batch()
                data["candidates"][0]["github_observed_at_utc"] = stamp(delta)
                self.assertIn("GITHUB_METADATA_STALE_OR_FUTURE",
                              self.result(data)["observations"][0]["reasons"])

    def test_document_stale_or_future_hold(self):
        for delta in (-8 * 86400, 301):
            with self.subTest(delta=delta):
                data = batch()
                data["candidates"][0]["official_reference"]["retrieved_at"] = stamp(delta)
                self.assertIn("DOCUMENT_OBSERVATION_STALE_OR_FUTURE",
                              self.result(data)["observations"][0]["reasons"])

    def test_blocked_reference_never_green_from_http_error(self):
        data = batch()
        data["candidates"][0]["official_reference"].update(
            state="BLOCKED", status=403, robots_allowed=False, body_sha256=None
        )
        row = self.result(data)["observations"][0]
        self.assertEqual(row["research_state"], "HOLD_INCOMPLETE_RESEARCH_EVIDENCE")
        self.assertIn("OFFICIAL_DOCUMENT_NOT_MEASURED", row["reasons"])

    def test_host_mismatch_and_lookalike_refused(self):
        for url in (
            "https://evil.scorecard.dev/",
            "https://scorecard.dev.evil.invalid/",
            "https://localhost/README",
            "http://scorecard.dev/",
            "https://scorecard.dev:444/",
            "https://scorecard.dev/?token=dummy",
        ):
            with self.subTest(url=url):
                data = batch()
                data["candidates"][0]["official_reference"]["url"] = url
                with self.assertRaisesRegex(mod.IntakeError, "OFFICIAL_REFERENCE_HOST_INVALID"):
                    self.result(data)

    def test_lookalike_same_host_document_does_not_launder_research(self):
        data = batch()
        data["candidates"][0]["official_reference"]["url"] = (
            "https://scorecard.dev/unrelated-but-fresh"
        )
        with self.assertRaisesRegex(mod.IntakeError, "OFFICIAL_REFERENCE_NOT_CURATED"):
            self.result(data)

    def test_document_reference_paths_are_exact_not_broad_host_permission(self):
        data = batch()
        data["candidates"][0]["official_reference"]["url"] = (
            "https://scorecard.dev/index.html"
        )
        with self.assertRaisesRegex(mod.IntakeError, "OFFICIAL_REFERENCE_NOT_CURATED"):
            self.result(data)


    def test_moving_branch_citation_is_rejected(self):
        data = batch()
        data["candidates"][0]["source_url"] = "https://github.com/ossf/scorecard/tree/main"
        with self.assertRaisesRegex(mod.IntakeError, "MOVING_OR_MISMATCHED_SOURCE_URL"):
            self.result(data)

    def test_other_upstream_commit_url_rejected(self):
        data = batch()
        data["candidates"][0]["source_url"] = (
            "https://github.com/other-org/scorecard/commit/" + UPSTREAM_SHA
        )
        with self.assertRaisesRegex(mod.IntakeError, "MOVING_OR_MISMATCHED_SOURCE_URL"):
            self.result(data)

    def test_unpinned_source_url_claim_refused(self):
        data = batch()
        data["candidates"][0]["upstream_revision"] = None
        with self.assertRaisesRegex(mod.IntakeError, "UNPINNED_SOURCE_URL_CLAIM"):
            self.result(data)

    def test_unmeasured_reference_cannot_carry_measured_hash(self):
        data = batch()
        data["candidates"][0]["official_reference"]["state"] = "UNAVAILABLE"
        with self.assertRaisesRegex(mod.IntakeError, "UNMEASURED_REFERENCE_CANNOT_CLAIM_DIGEST"):
            self.result(data)

    def test_false_measured_http_404_or_missing_robots_refused(self):
        for values in (
            {"status": 404}, {"robots_allowed": False},
            {"body_sha256": None}, {"status": None}
        ):
            with self.subTest(values=values):
                data = batch()
                data["candidates"][0]["official_reference"].update(values)
                with self.assertRaisesRegex(mod.IntakeError, "MEASURED_REFERENCE_INCOHERENT"):
                    self.result(data)

    def test_unknown_project_must_be_source_reviewed_into_code(self):
        data = batch()
        data["candidates"][0]["upstream_repository"] = "evil/repo"
        with self.assertRaisesRegex(mod.IntakeError, "PROJECT_NOT_SOURCE_ALLOWLISTED"):
            self.result(data)

    def test_src_duplicate_not_double_counted_in_same_cohort(self):
        data = batch()
        data["candidates"] = [candidate(), candidate()]
        with self.assertRaisesRegex(mod.IntakeError, "DUPLICATE_UPSTREAM_IN_PASS"):
            self.result(data)

    def test_large_cohort_or_zero_cohort_is_invalid(self):
        for count in (0, 11):
            with self.subTest(count=count):
                data = batch()
                data["candidates"] = [candidate()] * count
                with self.assertRaisesRegex(mod.IntakeError, "CANDIDATE_COUNT_INVALID"):
                    self.result(data)

    def test_only_ten_pass_indices_allowed(self):
        for index in (0, 11, True, 1.0, "1"):
            data = batch()
            data["pass_index"] = index
            with self.subTest(index=index), self.assertRaises(mod.IntakeError):
                self.result(data)

    def test_unauthorized_target_repo_refused(self):
        data = batch()
        data["candidates"][0]["szl_target_repository"] = "outside/szl-org-health"
        with self.assertRaisesRegex(mod.IntakeError, "SZL_TARGET_NOT_OWNED"):
            self.result(data)

    def test_publication_nonprimary_host_refused(self):
        data = batch()
        data["candidates"][0]["publication_url"] = "https://blog.evil.invalid/paper"
        with self.assertRaisesRegex(mod.IntakeError, "PUBLICATION_HOST_NOT_ADMITTED"):
            self.result(data)

    def test_publication_url_is_declared_not_peer_reviewed(self):
        data = batch()
        data["candidates"][0]["publication_url"] = "https://arxiv.org/abs/2309.06180"
        row = self.result(data)["observations"][0]
        self.assertIn("PUBLICATION_LINK_DECLARED_NOT_CHECKED", row["reasons"])
        self.assertFalse(row["publication_and_quality_verified"])

    def test_isaac_terms_separate_from_apache_label(self):
        data = batch()
        row = data["candidates"][0]
        row["upstream_repository"] = "isaac-sim/IsaacSim"
        row["source_url"] = "https://github.com/isaac-sim/IsaacSim/commit/" + UPSTREAM_SHA
        row["official_reference"]["url"] = "https://docs.isaacsim.omniverse.nvidia.com/latest/"
        row["github_license_spdx"] = "Apache-2.0"
        observed = self.result(data)["observations"][0]
        self.assertIn("NVIDIA_OMNIVERSE_ADDITIONAL_TERMS_REVIEW", observed["reasons"])
        self.assertFalse(observed["code_copy_authorized"])

    def test_same_metadata_and_row_reordering_deterministic(self):
        data = batch()
        row = copy.deepcopy(candidate())
        row["upstream_repository"] = "slsa-framework/slsa"
        row["source_url"] = "https://github.com/slsa-framework/slsa/commit/" + UPSTREAM_SHA
        row["official_reference"]["url"] = "https://slsa.dev/spec/v1.2/build-provenance"
        row["github_license_spdx"] = "NOASSERTION"
        data["candidates"].append(row)
        a = self.result(data)
        data["candidates"].reverse()
        b = self.result(data)
        self.assertEqual(a, b)
        self.assertEqual(a["candidate_count_observed"], 2)
        self.assertFalse(a["ten_pass_campaign_complete"])

    def test_unknown_research_field_rejected_not_interpreted_as_instruction(self):
        data = batch()
        data["candidates"][0]["run_shell"] = "deploy"
        with self.assertRaisesRegex(mod.IntakeError, "CANDIDATE_FIELDS"):
            self.result(data)

    def test_duplicate_json_keys_rejected(self):
        encoded = (
            b'{"schema":"a","schema":"b","pass_index":1,'
            b'"observed_at_utc":"2026-11-20T02:45:00Z",'
            b'"szl_source_sha":"' + SZL_SHA.encode() + b'","candidates":[]}'
        )
        with self.assertRaisesRegex(mod.IntakeError, "DUPLICATE_JSON_KEY"):
            mod.evaluate(encoded, now=NOW)

    def test_nan_infinity_and_floats_rejected(self):
        for payload in (
            b'{"n":NaN}', b'{"n":Infinity}', b'{"n":-Infinity}',
            b'{"schema":"bad","pass_index":1.0}'
        ):
            with self.subTest(payload=payload), self.assertRaises(mod.IntakeError):
                mod.read_input(payload)

    def test_oversized_raw_json_rejected_before_parsing(self):
        with self.assertRaisesRegex(mod.IntakeError, "INPUT_BYTE_LIMIT"):
            mod.read_input(b" " * (mod.MAX_INPUT_BYTES + 1))

    def test_stale_or_naive_global_batch_timestamp_refused(self):
        data = batch()
        data["observed_at_utc"] = stamp(-8 * 86400)
        with self.assertRaisesRegex(mod.IntakeError, "BATCH_OBSERVATION_STALE"):
            self.result(data)
        data = batch()
        data["observed_at_utc"] = "2026-11-20T02:45:00"
        with self.assertRaisesRegex(mod.IntakeError, "TIMESTAMP_FORMAT"):
            self.result(data)

    def test_independent_aware_clock_required(self):
        with self.assertRaisesRegex(mod.IntakeError, "INDEPENDENT_CLOCK_REQUIRED"):
            mod.evaluate(raw(batch()), now=datetime(2026, 11, 20, 2, 45))

    def test_footgun_input_with_incomplete_reference_cannot_claim_robots(self):
        data = batch()
        data["candidates"][0]["official_reference"]["state"] = "BLOCKED"
        data["candidates"][0]["official_reference"]["status"] = None
        data["candidates"][0]["official_reference"]["robots_allowed"] = None
        data["candidates"][0]["official_reference"]["body_sha256"] = None
        row = self.result(data)["observations"][0]
        self.assertIn("OFFICIAL_DOCUMENT_NOT_MEASURED", row["reasons"])
        self.assertFalse(row["web_receipt_origin_authenticated"])


if __name__ == "__main__":
    unittest.main()