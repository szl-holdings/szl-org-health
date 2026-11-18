# SPDX-License-Identifier: Apache-2.0
"""Contract checks run entirely in disposable isolated test directories."""
from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import crashpad_steward as c


class StewardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="szl-steward-unit-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "profile"
        self.folder = self.root / "Crashpad" / "reports"
        self.folder.mkdir(parents=True)
        (self.root / "Default").mkdir()
        (self.root / "Local State").write_bytes(b"synthetic")
        self.now = time.time_ns()

    @staticmethod
    def name(n):
        return f"00000000-0000-0000-0000-{n:012x}.dmp"

    def write_dump(self, n, *, age_minutes=60, bytes=5000):
        path = self.folder / self.name(n)
        path.write_bytes(b"0" * bytes)
        when = (self.now - age_minutes * 60 * 10**9) / 10**9
        os.utime(path, (when, when))
        return path

    def test_expected_profile_passes(self):
        self.assertEqual(c.validate_profile(self.root), self.folder)

    def test_no_browser_identity_fails(self):
        (self.root / "Local State").unlink()
        with self.assertRaisesRegex(c.GuardError, "BROWSER_PROFILE_NOT_PROVEN"):
            c.validate_profile(self.root)

    def test_git_tree_fails(self):
        (self.root / ".git").mkdir()
        with self.assertRaisesRegex(c.GuardError, "GIT_TREE_PROTECTED"):
            c.validate_profile(self.root)

    def test_only_strict_guid_dump_is_candidate(self):
        self.write_dump(1)
        (self.folder / "case-sensitive.LOG").write_bytes(b"Z" * 5000)
        (self.folder / "00000000-0000-0000-0000-000000000008.dmp.backup").write_bytes(b"Z" * 5000)
        scanned = c.inventory(self.folder, now_ns=self.now)
        self.assertEqual(scanned["generated_dump_count"], 1)
        self.assertEqual(scanned["ignored_items"], 2)
        self.assertEqual(scanned["eligible"], [])  # Preserve latest 200.

    def test_inventory_identity_matches_preunlink_lstat(self):
        for i in range(210):
            self.write_dump(i)
        snapshot = c.inventory(self.folder, now_ns=self.now)
        self.assertGreater(snapshot["eligible_bytes"], 0)
        item = snapshot["eligible"][0]
        stat_now = (self.folder / item.name).lstat()
        self.assertEqual((item.inode, item.device),
                         (stat_now.st_ino, stat_now.st_dev))

    def test_recent_dumps_never_eligible(self):
        for i in range(301):
            self.write_dump(i, age_minutes=5 if i == 0 else 70)
        scanned = c.inventory(self.folder, now_ns=self.now)
        self.assertNotIn(self.name(0), [x.name for x in scanned["eligible"]])
        self.assertGreater(scanned["last_20m_count"], 0)

    def test_newest_200_preserved(self):
        for i in range(230):
            self.write_dump(i, age_minutes=80 - i / 40)
        scanned = c.inventory(self.folder, now_ns=self.now)
        self.assertEqual(len(scanned["eligible"]), 30)
        self.assertEqual(scanned["oldest_protected_count"], 200)

    def test_no_arbitrary_files_or_directories(self):
        (self.folder / "important_receipt.json").write_bytes(b"never touch")
        (self.folder / "subdir").mkdir()
        (self.folder / "subdir" / self.name(1)).write_bytes(b"Y" * 5000)
        for i in range(210):
            self.write_dump(i)
        scanned = c.inventory(self.folder, now_ns=self.now)
        self.assertEqual(scanned["ignored_items"], 2)
        self.assertEqual(len(scanned["eligible"]), 10)

    def test_reparse_file_not_candidate(self):
        dest = self.write_dump(1)
        dest.unlink()
        alt = self.root / "secret_file"
        alt.write_bytes(b"Y" * 5000)
        try:
            os.symlink(alt, dest)
        except OSError:
            self.skipTest("Windows symlink privileges unavailable")
        scanned = c.inventory(self.folder, now_ns=self.now)
        self.assertEqual(scanned["generated_dump_count"], 0)
        self.assertEqual(scanned["ignored_items"], 1)

    def test_reparse_report_directory_rejected(self):
        # Symlink/junction simulation requires appropriate privileges.
        external = self.root / "external"
        external.mkdir()
        self.folder.rmdir()
        try:
            os.symlink(external, self.folder, target_is_directory=True)
        except OSError:
            self.skipTest("Windows symlink privileges unavailable")
        with self.assertRaisesRegex(c.GuardError, "REPARSE_OR_NON_DIRECTORY"):
            c.validate_profile(self.root)

    def test_changed_size_rejected(self):
        path = self.write_dump(1)
        item = c.Candidate(path.name, path.stat().st_size,
                           path.stat().st_mtime_ns,
                           path.stat().st_ino, path.stat().st_dev)
        path.write_bytes(b"x" * 7000)
        self.assertEqual(c.cleanup_candidate(self.folder, item, now_ns=self.now), "CHANGED")
        self.assertTrue(path.is_file())

    def test_changed_mtime_rejected(self):
        path = self.write_dump(1)
        info = path.stat()
        item = c.Candidate(path.name, info.st_size, info.st_mtime_ns,
                           info.st_ino, info.st_dev)
        os.utime(path, None)
        self.assertEqual(c.cleanup_candidate(self.folder, item, now_ns=self.now), "CHANGED")
        self.assertTrue(path.is_file())

    def test_too_young_rejected_for_unlink(self):
        path = self.write_dump(1, age_minutes=1)
        info = path.stat()
        item = c.Candidate(path.name, info.st_size, info.st_mtime_ns,
                           info.st_ino, info.st_dev)
        self.assertEqual(c.cleanup_candidate(self.folder, item, now_ns=self.now), "CHANGED")
        self.assertTrue(path.exists())

    @unittest.skipUnless(os.name == "nt", "Windows exclusive-file probe required")
    def test_scoped_old_sample_can_be_removed(self):
        path = self.write_dump(1)
        info = path.stat()
        item = c.Candidate(path.name, info.st_size, info.st_mtime_ns,
                           info.st_ino, info.st_dev)
        self.assertEqual(c.cleanup_candidate(self.folder, item, now_ns=self.now), "REMOVED")
        self.assertFalse(path.exists())

    def test_dry_run_does_not_touch_sources(self):
        paths = [self.write_dump(i) for i in range(250)]
        code, result = c.run_once(execute=False, root=self.root, evidence=Path(self.tmp.name))
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "DRY_RUN_ONLY")
        self.assertEqual(len(result.get("eligible_count", [])) if isinstance(result.get("eligible_count"), list)
                         else result["eligible_count"], 50)
        self.assertTrue(all(p.is_file() for p in paths))
        self.assertFalse(list(Path(self.tmp.name).glob("crashpad-steward.lock")))

    @unittest.skipUnless(os.name == "nt", "Windows integration test")
    def test_executor_receipts_are_written_before_and_after_cleanup(self):
        for i in range(220):
            self.write_dump(i)
        receipt_root = Path(self.tmp.name) / "unsigned-receipts"
        result_code, data = c.run_once(execute=True, root=self.root,
                                       evidence=receipt_root,
                                       free_floor_bytes=10**18)
        self.assertEqual(result_code, 0)
        self.assertEqual(data["removed_count"], 20)
        self.assertEqual(data["status"], "BOUNDED_CLEANUP_COMPLETED")
        self.assertEqual(len(list(self.folder.glob("*.dmp"))), 200)
        self.assertTrue(Path(data["prepare_receipt"]).is_file())
        self.assertTrue(Path(data["receipt"]).is_file())
        self.assertIn('UNSIGNED_PREPARED_INTENT',
                      Path(data["prepare_receipt"]).read_text())

    def test_invalid_root_fails_closed(self):
        code, result = c.run_once(execute=True, root=self.root / "wrong",
                                  evidence=Path(self.tmp.name))
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["error_code"], "PATH_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main(verbosity=2)