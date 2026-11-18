# SPDX-License-Identifier: Apache-2.0
"""Regression contracts for fail-closed, read-only Crashpad monitoring."""
from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import crashpad_steward as mod


class CrashpadMonitorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "profile"
        self.folder = self.root / "Crashpad" / "reports"
        self.folder.mkdir(parents=True)
        (self.root / "Default").mkdir()
        (self.root / "Local State").write_text("synthetic")
        (self.root / "Crashpad" / "metadata").write_bytes(b"not actual metadata")

    def make_dump(self, n=1, age_seconds=3600):
        path = self.folder / f"00000000-0000-0000-0000-{n:012x}.dmp"
        path.write_bytes(bytes([n % 256]) * 2560)
        t = time.time() - age_seconds
        os.utime(path, (t, t))
        return path

    def test_valid_profile_can_be_observed(self):
        record = mod.observe(self.root, sample_count=1)
        self.assertIn(record["status"], {"READ_ONLY_OBSERVED", "ALERT"})
        self.assertFalse(record["database_states_verified"])

    def test_database_missing_holds(self):
        (self.root / "Crashpad" / "metadata").unlink()
        record = mod.observe(self.root, sample_count=1)
        self.assertEqual(record["status"], "HOLD")
        self.assertEqual(record["reason_code"], "PROFILE_OR_DATABASE_UNAVAILABLE")

    def test_git_tree_protected(self):
        (self.root / ".git").mkdir()
        self.assertEqual(mod.observe(self.root, sample_count=1)["reason_code"],
                         "GIT_TREE_PROTECTED")

    def test_unclassified_files_remain_untouched(self):
        (self.folder / "important_receipt.json").write_text("preserve")
        (self.folder / "subdirectory").mkdir()
        report = mod.observe(self.root, sample_count=1)
        self.assertEqual(report["readings"][0]["unclassified_entries"], 2)
        self.assertTrue((self.folder / "important_receipt.json").exists())

    def test_exact_uuid_reports_counted_without_completion_claims(self):
        self.make_dump()
        record = mod.observe(self.root, sample_count=1)
        row = record["readings"][0]
        self.assertEqual(row["uuid_dmp_count"], 1)
        self.assertEqual(row["verified_completed_count"], 0)
        self.assertEqual(row["disposable_count"], 0)
        self.assertFalse(record["deletion_authorized"])

    def test_recent_report_rate_alert(self):
        for i in range(31):
            self.make_dump(i, age_seconds=30)
        record = mod.observe(self.root, sample_count=1)
        self.assertTrue(record["rapid_crash_reports"])
        self.assertEqual(record["status"], "ALERT")

    def test_dry_run_does_not_modify_file_bytes_or_mtime(self):
        file = self.make_dump()
        digest = hashlib.sha256(file.read_bytes()).digest()
        before = file.stat().st_mtime_ns
        record = mod.observe(self.root, sample_count=2, interval_seconds=0)
        self.assertEqual(record["operation"], "READ_ONLY")
        self.assertEqual(digest, hashlib.sha256(file.read_bytes()).digest())
        self.assertEqual(before, file.stat().st_mtime_ns)
        self.assertFalse(record["private_dump_contents_read"])

    def test_execute_refused_before_any_disk_mutation(self):
        file = self.make_dump()
        before = file.read_bytes()
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = mod.main(["--execute"])
        self.assertEqual(exit_code, 2)
        data = json.loads(output.getvalue())
        self.assertEqual(data["status"], "HOLD")
        self.assertEqual(data["reason_code"], "CRASHPAD_DB_STATE_UNVERIFIED")
        self.assertFalse(data["deletion_authorized"])
        self.assertEqual(file.read_bytes(), before)

    def test_module_does_not_offer_delete_functions(self):
        self.assertFalse(hasattr(mod, "cleanup_candidate"))
        self.assertFalse(hasattr(mod, "write_receipt"))
        self.assertFalse(hasattr(mod, "remove_file"))

    def test_invalid_sample_bounds_fail_closed(self):
        for value in (0, 6):
            record = mod.observe(self.root, sample_count=value)
            self.assertEqual(record["status"], "HOLD")
            self.assertEqual(record["reason_code"], "INVALID_SAMPLE_BOUNDS")

    def test_symlink_report_denied(self):
        actual = self.make_dump()
        alias = self.folder / "00000000-0000-0000-0000-000000000002.dmp"
        try:
            os.symlink(actual, alias)
        except OSError:
            self.skipTest("Symlink privilege unavailable")
        record = mod.observe(self.root, sample_count=1)
        self.assertEqual(record["readings"][0]["uuid_dmp_count"], 1)

    def test_symlink_reports_directory_denied(self):
        self.folder.rmdir()
        other = self.root / "other"
        other.mkdir()
        try:
            os.symlink(other, self.folder, target_is_directory=True)
        except OSError:
            self.skipTest("Symlink privilege unavailable")
        record = mod.observe(self.root, sample_count=1)
        self.assertEqual(record["status"], "HOLD")
        self.assertEqual(record["reason_code"], "REPARSE_OR_INVALID_DIRECTORY")


if __name__ == "__main__":
    unittest.main(verbosity=2)
