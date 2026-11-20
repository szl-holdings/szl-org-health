"""Synthetic negative/positive controls for source-only OSS license byte readback."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
import urllib.error
from datetime import UTC, datetime
from unittest.mock import patch

from tools import oss_license_byte_witness as witness

NOW = datetime(2026, 11, 20, 5, 26, tzinfo=UTC)
LICENSE_BYTES = b"MIT License\nCopyright (c) 2026 Example\n"
PIN = "a" * 40
REPO = "https://github.com/example/repo"
COMMIT_URL = "https://api.github.com/repos/example/repo/git/commits/" + PIN
BLOB_URL = "https://api.github.com/repos/example/repo/contents/LICENSE?ref=" + PIN


def candidate() -> dict:
    return {
        "schema": "szl.open_source_frontier_candidate.v1",
        "upstream": {
            "repo_url": REPO,
            "commit_sha": PIN,
            "declared_spdx": "MIT",
            "license_path": "LICENSE",
            "license_sha256": hashlib.sha256(LICENSE_BYTES).hexdigest(),
            "observed_at_utc": "2026-11-20T05:26:00Z",
        },
        "proposal": {
            "szl_component": "szl-org-health",
            "approach": "study_only",
            "hypothesis": "Source-bound license readback reduces false provenance claims.",
            "negative_test": "Tamper one byte or commit and refuse admission.",
        },
    }


def blob(data: bytes = LICENSE_BYTES) -> dict:
    return {
        "type": "file",
        "path": "LICENSE",
        "encoding": "base64",
        "size": len(data),
        "content": base64.b64encode(data).decode("ascii"),
        "sha": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest(),
    }


def fixtures(c: dict | None = None, *, obj: dict | None = None) -> tuple[dict, dict]:
    c = c or candidate()
    return {"sha": c["upstream"]["commit_sha"]}, obj if obj is not None else blob()


class WitnessTests(unittest.TestCase):
    def run_case(self, c=None, *, resolved=None, source=None, error=None):
        c = copy.deepcopy(c if c is not None else candidate())
        resolved = resolved if resolved is not None else {"sha": c["upstream"]["commit_sha"]}
        source = source if source is not None else blob()
        called = []

        def get(url):
            called.append(url)
            if error:
                raise error
            if len(called) == 1:
                return resolved
            if len(called) == 2:
                return source
            raise AssertionError("unexpected third request")

        return witness.observe(c, get=get, now=NOW), called

    def assert_hold(self, result, code):
        self.assertEqual(result["state"], "HOLD")
        self.assertEqual(result["reason"], code)
        for field in ("rights_review_completed", "dependency_rights_verified", "signer_authenticated",
                      "code_copy_authorized", "training_authorized", "merge_authorized", "deployment_authorized"):
            self.assertIs(result[field], False, field)

    def test_exact_commit_and_blob_matching_only_research(self):
        result, calls = self.run_case()
        self.assertEqual(result["state"], "EXACT_COMMIT_LICENSE_BYTES_MATCH_REVIEW_ONLY")
        self.assertEqual(result["reason"], "RIGHTS_REVIEW_AND_DEPENDENCY_SCAN_REQUIRED")
        self.assertEqual(calls, [COMMIT_URL, BLOB_URL])
        self.assertTrue(result["provider_commit_resolved"])
        self.assertTrue(result["provider_license_bytes_observed"])
        self.assertTrue(result["bytes_match_declared_digest"])
        self.assertEqual(result["license_sha256"], candidate()["upstream"]["license_sha256"])
        self.assertEqual(result["source_url"], f"{REPO}/blob/{PIN}/LICENSE")
        self.assertNotIn(LICENSE_BYTES.decode("ascii"), json.dumps(result))
        self.assertFalse(result["code_copy_authorized"])
        self.assertFalse(result["merge_authorized"])

    def test_mismatched_git_commit_denies_fetching_file(self):
        result, calls = self.run_case(resolved={"sha": "c" * 40})
        self.assert_hold(result, "COMMIT_PIN_MISMATCH")
        self.assertEqual(calls, [COMMIT_URL])

    def test_digest_mismatch_keeps_observed_hash_but_holds(self):
        c = candidate()
        c["upstream"]["license_sha256"] = "d" * 64
        result, calls = self.run_case(c)
        self.assert_hold(result, "DECLARED_DIGEST_MISMATCH")
        self.assertEqual(len(calls), 2)
        self.assertTrue(result["provider_license_bytes_observed"])
        self.assertFalse(result["bytes_match_declared_digest"])

    def test_git_blob_mismatch(self):
        obj = blob()
        obj["sha"] = "f" * 40
        result, _ = self.run_case(source=obj)
        self.assert_hold(result, "GIT_BLOB_MISMATCH")

    def test_actual_bytes_changed_and_sha_still_old(self):
        obj = blob()
        obj["content"] = base64.b64encode(LICENSE_BYTES.replace(b"MIT", b"XXX")).decode("ascii")
        result, _ = self.run_case(source=obj)
        self.assert_hold(result, "GIT_BLOB_MISMATCH")

    def test_tamper_self_consistent_provider_object_cannot_grant_rights(self):
        obj = blob(b"Something else with same length".ljust(len(LICENSE_BYTES), b"!"))
        result, _ = self.run_case(source=obj)
        self.assert_hold(result, "DECLARED_DIGEST_MISMATCH")

    def test_wrong_file_path(self):
        obj = blob()
        obj["path"] = "README.md"
        result, _ = self.run_case(source=obj)
        self.assert_hold(result, "LICENSE_OBJECT_INVALID")

    def test_no_type_file(self):
        obj = blob()
        obj["type"] = "dir"
        result, _ = self.run_case(source=obj)
        self.assert_hold(result, "LICENSE_OBJECT_INVALID")

    def test_missing_base64_encoding(self):
        obj = blob()
        obj["encoding"] = "none"
        result, _ = self.run_case(source=obj)
        self.assert_hold(result, "LICENSE_ENCODING_INVALID")

    def test_invalid_base64(self):
        obj = blob()
        obj["content"] = "@@@"
        result, _ = self.run_case(source=obj)
        self.assert_hold(result, "LICENSE_BASE64_INVALID")

    def test_size_mismatch(self):
        obj = blob()
        obj["size"] -= 1
        result, _ = self.run_case(source=obj)
        self.assert_hold(result, "LICENSE_LENGTH_MISMATCH")

    def test_bool_is_not_size(self):
        obj = blob()
        obj["size"] = True
        result, _ = self.run_case(source=obj)
        self.assert_hold(result, "LICENSE_SIZE_INVALID")

    def test_license_size_cap(self):
        obj = blob()
        obj["size"] = witness.MAX_LICENSE_BYTES + 1
        result, _ = self.run_case(source=obj)
        self.assert_hold(result, "LICENSE_SIZE_INVALID")

    def test_oversized_encoded_content(self):
        obj = blob()
        obj["content"] = "A" * (witness.MAX_RESPONSE_BYTES + 1)
        result, _ = self.run_case(source=obj)
        self.assert_hold(result, "LICENSE_ENCODED_SIZE_INVALID")

    def test_network_failure_not_silent(self):
        result, _ = self.run_case(error=urllib.error.URLError("hidden private path"))
        self.assert_hold(result, "PROVIDER_UNAVAILABLE")
        self.assertNotIn("hidden private path", str(result))

    def test_bad_commit_response_type(self):
        result, _ = self.run_case(resolved={"sha": 1})
        self.assert_hold(result, "COMMIT_PIN_MISMATCH")

    def test_declared_gpl_holds_without_network(self):
        c = candidate()
        c["upstream"]["declared_spdx"] = "GPL-3.0-only"
        result, called = self.run_case(c)
        self.assert_hold(result, "DECLARATION_HOLD")
        self.assertEqual(called, [])

    def test_unpinned_revision_holds_without_network(self):
        c = candidate()
        c["upstream"]["commit_sha"] = "main"
        result, called = self.run_case(c)
        self.assert_hold(result, "DECLARATION_HOLD")
        self.assertEqual(called, [])

    def test_fake_authority_field_holds_without_network(self):
        c = candidate()
        c["independent_review"] = True
        result, called = self.run_case(c)
        self.assert_hold(result, "DECLARATION_HOLD")
        self.assertEqual(called, [])

    def test_untrusted_host_holds_without_network(self):
        c = candidate()
        c["upstream"]["repo_url"] = "https://github.com.attacker.invalid/foo/bar"
        result, called = self.run_case(c)
        self.assert_hold(result, "DECLARATION_HOLD")
        self.assertEqual(called, [])

    def test_stale_candidate_holds_without_network(self):
        c = candidate()
        c["upstream"]["observed_at_utc"] = "2026-02-20T00:00:00Z"
        result, called = self.run_case(c)
        self.assert_hold(result, "DECLARATION_HOLD")
        self.assertEqual(called, [])

    def test_cannot_call_unsafe_origin(self):
        with self.assertRaisesRegex(witness.WitnessError, "REQUEST_ORIGIN_INVALID"):
            witness.fetch_public_json("https://example.com/repos/org/repo")

    def test_mismatched_final_url_rejected(self):
        class Response:
            status = 200

            def geturl(self):
                return "https://evil.example/api"

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

        class Opener:
            def open(self, *_args, **_kwargs):
                return Response()

        with patch.object(witness.urllib.request, "build_opener", return_value=Opener()):
            with self.assertRaisesRegex(witness.WitnessError, "PROVIDER_RESPONSE_IDENTITY_INVALID"):
                witness.fetch_public_json(COMMIT_URL)

    def test_non200_response_rejected(self):
        class Response:
            status = 302

            def geturl(self):
                return COMMIT_URL

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

        class Opener:
            def open(self, *_args, **_kwargs):
                return Response()

        with patch.object(witness.urllib.request, "build_opener", return_value=Opener()):
            with self.assertRaisesRegex(witness.WitnessError, "PROVIDER_RESPONSE_IDENTITY_INVALID"):
                witness.fetch_public_json(COMMIT_URL)

    def test_null_candidate_never_fetches(self):
        result, called = self.run_case(c={})
        self.assert_hold(result, "DECLARATION_HOLD")
        self.assertEqual(called, [])


if __name__ == "__main__":
    unittest.main()
