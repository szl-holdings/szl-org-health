# SPDX-License-Identifier: Apache-2.0
"""Synthetic-only custody recovery contracts; never inspect real user files."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from tools import evidence_custody_locator as custody


class CustodyLocatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="szl-custody-contract-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.root = self.home / "archive"
        self.root.mkdir()
        self.expected = b"unique scientific ledger line\n"
        self.name = "sample.ndjson"
        self.file = self.root / "khipu" / self.name
        self.file.parent.mkdir()
        self.file.write_bytes(self.expected)
        self.doc = {
            "schema": custody.SCHEMA,
            "artifacts": [{
                "id": "ledger-1", "basename": self.name,
                "size_bytes": len(self.expected),
                "sha256": hashlib.sha256(self.expected).hexdigest(),
            }],
        }
        self.manifest = self.home / "manifest.json"
        self.save()

    def save(self):
        self.manifest.write_text(json.dumps(self.doc), encoding="utf-8")

    def locate(self, **kwargs):
        self.save()
        doc, digest = custody.load_manifest(self.manifest)
        self.assertEqual(digest, hashlib.sha256(self.manifest.read_bytes()).hexdigest())
        return custody.inspect(doc, [self.root], **kwargs)

    def test_present_identical_bytes_are_custody_candidates_not_release(self):
        report = self.locate()
        self.assertEqual(report["status"], "CANDIDATES_FOUND_NOT_ADMITTED")
        self.assertEqual(report["matched_artifacts"], 1)
        self.assertEqual(report["artifacts"][0]["status"], "HASH_MATCH_UNATTESTED")
        self.assertFalse(report["release_authorized"])
        self.assertFalse(report["archive_durability_verified"])
        self.assertFalse(report["manifest_authenticity_verified"])
        self.assertFalse(report["artifacts"][0]["signature_verified"])

    def test_default_output_never_leaks_private_root_or_paths(self):
        report = self.locate()
        rendered = json.dumps(report)
        self.assertNotIn(str(self.home), rendered)
        self.assertNotIn("khipu", rendered)
        self.assertEqual(report["artifacts"][0]["locations"], [])

    def test_explicit_local_show_paths_only_matches(self):
        report = self.locate(show_paths=True)
        loc = report["artifacts"][0]["locations"]
        self.assertEqual(loc, [{"root_index": 0, "relative_path": os.path.join("khipu", self.name)}])

    def test_missing_artifact_is_hold_not_permanent_loss(self):
        self.file.unlink()
        report = self.locate()
        self.assertEqual(report["status"], "HOLD")
        self.assertTrue(report["scan_complete"])
        self.assertEqual(report["artifacts"][0]["status"], "NOT_FOUND_IN_SCOPED_NONPROTECTED_FILES")
        self.assertEqual(report["matched_artifacts"], 0)

    def test_same_size_wrong_digest_does_not_count(self):
        self.file.write_bytes(b"x" * len(self.expected))
        report = self.locate()
        self.assertEqual(report["status"], "HOLD")
        self.assertEqual(report["matched_artifacts"], 0)

    def test_filenames_same_different_digests_supported(self):
        self.doc["artifacts"].append({
            "id": "ledger-2", "basename": self.name, "size_bytes": len(self.expected),
            "sha256": hashlib.sha256(b"other").hexdigest(),
        })
        report = self.locate()
        self.assertEqual(report["artifact_count"], 2)
        self.assertEqual(report["matched_artifacts"], 1)
        self.assertEqual(report["status"], "HOLD")

    def test_bounded_scan_reports_incomplete(self):
        report = self.locate(max_entries=1)
        self.assertFalse(report["scan_complete"])
        self.assertEqual(report["status"], "HOLD")
        self.assertEqual(report["artifacts"][0]["status"], "UNKNOWN_INCOMPLETE_SCAN")

    def test_byte_budget_reports_incomplete(self):
        report = self.locate(max_bytes=1)
        self.assertFalse(report["scan_complete"])
        self.assertEqual(report["incomplete_reason"], "HASH_BUDGET_EXHAUSTED")
        self.assertFalse(report["release_authorized"])

    def test_skip_protected_directories(self):
        self.file.unlink()
        d = self.root / "OneDrive"
        d.mkdir()
        (d / self.name).write_bytes(self.expected)
        report = self.locate()
        self.assertEqual(report["matched_artifacts"], 0)
        self.assertGreaterEqual(report["excluded_entries"], 1)

    def test_no_mutations_during_read(self):
        before = (self.file.stat().st_mtime_ns, hashlib.sha256(self.file.read_bytes()).hexdigest())
        report = self.locate()
        self.assertEqual(report["matched_artifacts"], 1)
        after = (self.file.stat().st_mtime_ns, hashlib.sha256(self.file.read_bytes()).hexdigest())
        self.assertEqual(before, after)

    def test_root_cannot_be_system_root(self):
        with self.assertRaisesRegex(custody.Hold, "ROOT_MUST_BE_EXPLICIT_DIRECTORY"):
            custody.check_root(Path(self.home.anchor))

    def test_protected_explicit_root_refused(self):
        folder = self.home / ".ssh"
        folder.mkdir()
        with self.assertRaisesRegex(custody.Hold, "PROTECTED_ROOT"):
            custody.check_root(folder)

    def test_reparse_candidate_never_hashed(self):
        self.file.unlink()
        target = self.home / "user_file.txt"
        target.write_bytes(self.expected)
        try:
            os.symlink(target, self.file)
        except OSError:
            self.skipTest("Symlink privilege unavailable")
        report = self.locate()
        self.assertEqual(report["matched_artifacts"], 0)
        self.assertFalse(report["release_authorized"])

    def test_reparse_root_refused(self):
        linked = self.home / "linked"
        try:
            os.symlink(self.root, linked, target_is_directory=True)
        except OSError:
            self.skipTest("Symlink privilege unavailable")
        with self.assertRaisesRegex(custody.Hold, "ROOT_REPARSE_OR_NOT_DIRECTORY"):
            custody.check_root(linked)

    def test_duplicate_json_keys_rejected(self):
        self.manifest.write_bytes(b'{"schema":"a","schema":"b","artifacts":[]}')
        with self.assertRaisesRegex(custody.Hold, "DUPLICATE_JSON_KEY"):
            custody.load_manifest(self.manifest)

    def test_json_nan_constant_is_rejected(self):
        self.manifest.write_bytes(
            b'{"schema":"szl.custody.recovery-locator/v1",'
            b'"artifacts":[],"extra":NaN}'
        )
        with self.assertRaisesRegex(custody.Hold, "INVALID_JSON_CONSTANT"):
            custody.load_manifest(self.manifest)

    def test_unexpected_root_fields_rejected(self):
        self.doc["untrusted_status"] = "PRODUCTION_READY"
        self.save()
        with self.assertRaisesRegex(custody.Hold, "MANIFEST_UNEXPECTED_FIELDS"):
            custody.load_manifest(self.manifest)

    def test_duplicate_artifact_ids_case_insensitive_rejected(self):
        self.doc["artifacts"].append({
            "id": "LEDGER-1", "basename": self.name,
            "size_bytes": len(self.expected),
            "sha256": hashlib.sha256(self.expected).hexdigest(),
        })
        self.save()
        with self.assertRaisesRegex(custody.Hold, "INVALID_OR_DUPLICATE_ARTIFACT_ID"):
            custody.load_manifest(self.manifest)

    def test_unsafe_basename_rejected(self):
        self.doc["artifacts"][0]["basename"] = "../secret.json"
        self.save()
        with self.assertRaisesRegex(custody.Hold, "INVALID_BASENAME"):
            custody.load_manifest(self.manifest)

    def test_unsupported_file_type_rejected(self):
        self.doc["artifacts"][0]["basename"] = "private.pem"
        self.save()
        with self.assertRaisesRegex(custody.Hold, "INVALID_BASENAME"):
            custody.load_manifest(self.manifest)

    def test_invalid_sha_and_size_types_rejected(self):
        for value in ("wrong", "0" * 63, "A" * 64):
            self.doc["artifacts"][0]["sha256"] = value
            self.save()
            with self.assertRaisesRegex(custody.Hold, "INVALID_SHA256"):
                custody.load_manifest(self.manifest)
        self.doc["artifacts"][0]["sha256"] = hashlib.sha256(self.expected).hexdigest()
        for value in (True, 0, -1, 1024 * 1024 * 1024):
            self.doc["artifacts"][0]["size_bytes"] = value
            self.save()
            with self.assertRaisesRegex(custody.Hold, "INVALID_ARTIFACT_SIZE"):
                custody.load_manifest(self.manifest)

    def test_duplicate_scan_roots_rejected(self):
        with self.assertRaisesRegex(custody.Hold, "DUPLICATE_SCAN_ROOT"):
            custody.inspect(self.doc, [self.root, self.root])

    def test_cli_hold_and_no_output_file(self):
        self.file.unlink()
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = custody.main([
                "--manifest", str(self.manifest), "--root", str(self.root)
            ])
        self.assertEqual(exit_code, 2)
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "HOLD")
        self.assertFalse(result["deletion_authorized"])
        self.assertFalse((self.home / "output.json").exists())

    def test_unavailable_directory_never_becomes_false_absence(self):
        self.file.unlink()
        with patch.object(custody.os, "scandir", side_effect=PermissionError):
            result = self.locate()
        self.assertFalse(result["scan_complete"])
        self.assertEqual(result["artifacts"][0]["status"], "UNKNOWN_INCOMPLETE_SCAN")
        self.assertGreater(result["inaccessible_entries"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
