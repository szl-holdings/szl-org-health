"""No network or provider calls; adversarial source-candidate fixtures only."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from open_source_frontier_gate import (MAX_BYTES, SCHEMA, evaluate, parse)  # noqa: E402

NOW = datetime(2026, 11, 20, 2, 25, tzinfo=timezone.utc)


def candidate() -> dict:
    return {
        "schema": SCHEMA,
        "upstream": {
            "repo_url": "https://github.com/langchain-ai/langgraph",
            "commit_sha": "a" * 40,
            "declared_spdx": "MIT",
            "license_path": "LICENSE",
            "license_sha256": "b" * 64,
            "observed_at_utc": "2026-11-20T02:25:00Z",
        },
        "proposal": {
            "szl_component": "szl-org-health",
            "approach": "study_only",
            "hypothesis": "Can a source-pinned upstream idea improve evidence traceability?",
            "negative_test": "Change the upstream SHA while holding receipt fixed; must HOLD.",
        },
    }


class GateTests(unittest.TestCase):
    def verdict(self, x: dict) -> dict:
        return evaluate(x, now=NOW)

    def assert_holds(self, x: dict, reason: str) -> None:
        result = self.verdict(x)
        self.assertEqual(result["classification"], "HOLD")
        self.assertIn(reason, result["reasons"])
        self.assertFalse(result["merge_authorized"])
        self.assertFalse(result["code_copy_authorized"])

    def test_candidate_never_authorizes(self):
        result = self.verdict(candidate())
        self.assertEqual(result["classification"], "RESEARCH_CANDIDATE_ONLY")
        for k, v in result.items():
            if k.endswith(("_verified", "_authenticated", "_authorized", "_completed", "_executed")):
                self.assertFalse(v, k)

    def test_accepts_sha256_git_object_hash(self):
        d = candidate(); d["upstream"]["commit_sha"] = "a" * 64
        self.assertEqual(self.verdict(d)["classification"], "RESEARCH_CANDIDATE_ONLY")

    def test_missing_spdx(self):
        d = candidate(); d["upstream"]["declared_spdx"] = ""
        self.assert_holds(d, "LICENSE_REVIEW_REQUIRED")

    def test_copyleft_is_not_automatically_admitted(self):
        d = candidate(); d["upstream"]["declared_spdx"] = "GPL-3.0-only"
        self.assert_holds(d, "LICENSE_REVIEW_REQUIRED")

    def test_unknown_spdx_expression_not_automatically_admitted(self):
        d = candidate(); d["upstream"]["declared_spdx"] = "MIT OR GPL-3.0-only"
        self.assert_holds(d, "LICENSE_REVIEW_REQUIRED")

    def test_rejects_source_branch_as_pin(self):
        d = candidate(); d["upstream"]["commit_sha"] = "main"
        self.assert_holds(d, "UNPINNED_SOURCE")

    def test_rejects_uppercase_sha(self):
        d = candidate(); d["upstream"]["commit_sha"] = "A" * 40
        self.assert_holds(d, "UNPINNED_SOURCE")

    def test_no_untrusted_host(self):
        d = candidate(); d["upstream"]["repo_url"] = "https://github.com.evil.test/langchain-ai/langgraph"
        self.assert_holds(d, "INVALID_UPSTREAM_URL")

    def test_no_url_credentials(self):
        d = candidate(); d["upstream"]["repo_url"] = "https://user:pass@github.com/org/repo"
        self.assert_holds(d, "INVALID_UPSTREAM_URL")

    def test_no_redirect_fragment_or_query(self):
        d = candidate(); d["upstream"]["repo_url"] += "?next=https://evil.test"
        self.assert_holds(d, "INVALID_UPSTREAM_URL")

    def test_rejects_path_traversal_license(self):
        d = candidate(); d["upstream"]["license_path"] = "../../LICENSE"
        self.assert_holds(d, "LICENSE_PATH_UNVERIFIABLE")

    def test_missing_license_digest(self):
        d = candidate(); d["upstream"]["license_sha256"] = ""
        self.assert_holds(d, "LICENSE_DIGEST_MISSING")

    def test_stale_evidence(self):
        d = candidate(); d["upstream"]["observed_at_utc"] = "2026-07-20T00:00:00Z"
        self.assert_holds(d, "STALE_OR_FUTURE_EVIDENCE")

    def test_future_evidence(self):
        d = candidate(); d["upstream"]["observed_at_utc"] = "2026-11-20T04:00:00Z"
        self.assert_holds(d, "STALE_OR_FUTURE_EVIDENCE")

    def test_nonutc_timestamp(self):
        d = candidate(); d["upstream"]["observed_at_utc"] = "2026-11-19T21:25:00-05:00"
        self.assert_holds(d, "INVALID_OBSERVATION_TIME")

    def test_unrecognized_power_claims_fail(self):
        d = candidate(); d["agent_approved"] = True
        self.assert_holds(d, "INVALID_TOP_LEVEL_SHAPE")

    def test_untrusted_owner_override_fails(self):
        d = candidate(); d["upstream"]["reviewed_by_owner"] = True
        self.assert_holds(d, "INVALID_UPSTREAM_SHAPE")

    def test_without_negative_control(self):
        d = candidate(); d["proposal"]["negative_test"] = ""
        self.assert_holds(d, "MISSING_NEGATIVE_TEST")

    def test_invalid_approach(self):
        d = candidate(); d["proposal"]["approach"] = "deploy_now"
        self.assert_holds(d, "INVALID_APPROACH")

    def test_json_duplicate_keys_rejected(self):
        with self.assertRaises(ValueError):
            parse(b'{"schema":1,"schema":2}')

    def test_json_nonfinite_rejected(self):
        with self.assertRaises(ValueError):
            parse(b'{"a":NaN}')

    def test_json_oversized_rejected(self):
        with self.assertRaises(ValueError):
            parse(b"x" * (MAX_BYTES + 1))

    def test_json_binary_type_rejected(self):
        with self.assertRaises(ValueError):
            parse("not bytes")

    def test_missing_shape_never_promotes(self):
        self.assert_holds({}, "INVALID_TOP_LEVEL_SHAPE")

    def test_bool_is_not_valid_spdx(self):
        d = candidate(); d["upstream"]["declared_spdx"] = True
        self.assert_holds(d, "LICENSE_REVIEW_REQUIRED")

    def test_malformed_repository_name(self):
        d = candidate(); d["upstream"]["repo_url"] = "https://github.com/../foo"
        self.assert_holds(d, "INVALID_UPSTREAM_URL")


if __name__ == "__main__":
    unittest.main()
