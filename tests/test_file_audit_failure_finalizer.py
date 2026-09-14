"""Exercise real existing selector/failure schema; never use a GitHub credential."""
from __future__ import annotations

import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from census import file_audit as audit
from tools.ensure_repository_file_audit_receipt import (
    FAILED_OUTCOMES, PRIVATE_NAME, PUBLIC_NAME, ensure_failure_receipts, run,
)
from tools.run_with_validated_github_reader import run as select_and_run


class FileAuditFailureFinalizerTests(unittest.TestCase):
    def test_rejected_reader_never_starts_child_and_retains_real_failure_pair(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            log = io.StringIO()
            with patch("subprocess.run") as child:
                code = select_and_run(
                    ["--", "python", "-B", "-m", "tools.run_repository_file_audit"],
                    environ={}, subprocess_run=child, log=log,
                )
                self.assertEqual(code, 2)
                child.assert_not_called()
            with patch.object(audit, "list_repositories", side_effect=AssertionError("no collection")):
                self.assertEqual(ensure_failure_receipts(folder, "failure"), "INCOMPLETE_RECEIPTS_RETAINED")
            private = json.loads((folder / PRIVATE_NAME).read_text())
            public = json.loads((folder / PUBLIC_NAME).read_text())
            stamp = private.pop("receipt_sha256")
            self.assertEqual(stamp, audit.sha256_json(private))
            private["receipt_sha256"] = stamp
            self.assertEqual(public, audit.public_projection(private))
            self.assertEqual(private["summary"]["state"], "INCOMPLETE")
            self.assertEqual(public["summary"]["state"], "INCOMPLETE")
            self.assertEqual(private["repositories"], [])
            self.assertIsNone(private["source"]["organization_population"])
            self.assertIsNone(private["source"]["credential_present"])
            self.assertIs(private["source"]["verified_work_counts_are_population"], False)
            self.assertEqual(code, 2)

    def test_all_unsuccessful_outcomes_are_explicit(self):
        for outcome in FAILED_OUTCOMES:
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as name:
                ensure_failure_receipts(Path(name), outcome)
                value = json.loads((Path(name) / PRIVATE_NAME).read_text())
                self.assertEqual(value["source"]["collector_outcome"], outcome)
                self.assertEqual(value["summary"]["totals"]["files"], 0)

    def test_success_and_unknown_outcomes_never_write(self):
        with tempfile.TemporaryDirectory() as name:
            for outcome in ("success", "", "neutral", "failure\nsecret"):
                with self.subTest(outcome=outcome), self.assertRaises(ValueError):
                    ensure_failure_receipts(Path(name), outcome)
            self.assertEqual(list(Path(name).iterdir()), [])

    def test_existing_pair_is_preserved_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            for filename in (PRIVATE_NAME, PUBLIC_NAME):
                (folder / filename).write_bytes(b"existing evidence; not certified by finalizer")
            before = {p.name: p.read_bytes() for p in folder.iterdir()}
            self.assertEqual(ensure_failure_receipts(folder, "failure"), "EXISTING_EVIDENCE_PRESERVED")
            self.assertEqual(before, {p.name: p.read_bytes() for p in folder.iterdir()})

    def test_partial_pair_is_neither_overwritten_nor_fabricated(self):
        for filename in (PRIVATE_NAME, PUBLIC_NAME):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as name:
                folder = Path(name)
                (folder / filename).write_bytes(b"partial-original")
                with self.assertRaises(ValueError):
                    ensure_failure_receipts(folder, "failure")
                self.assertEqual({p.name: p.read_bytes() for p in folder.iterdir()}, {filename: b"partial-original"})

    def test_output_directory_and_receipt_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            with self.assertRaises(ValueError):
                ensure_failure_receipts(folder / "missing", "failure")
            (folder / "linked").symlink_to(folder, target_is_directory=True)
            with self.assertRaises(ValueError):
                ensure_failure_receipts(folder / "linked", "failure")
            (folder / PRIVATE_NAME).symlink_to(folder / "absent-target")
            with self.assertRaises(ValueError):
                ensure_failure_receipts(folder, "failure")
            self.assertFalse((folder / "absent-target").exists())

    def test_errors_are_sanitized_and_fail_closed(self):
        log = io.StringIO()
        with tempfile.TemporaryDirectory() as name:
            with patch("tools.ensure_repository_file_audit_receipt.ensure_failure_receipts",
                       side_effect=OSError("synthetic-canary-do-not-emit")):
                code = run(["--directory", name, "--collect-outcome", "failure"], log=log)
        self.assertEqual(code, 2)
        self.assertNotIn("synthetic-canary-do-not-emit", log.getvalue())
        self.assertIn("RECEIPT_RETENTION_FAILED", log.getvalue())

    def test_workflow_retains_failure_before_upload_and_enforces_original_outcome(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/scheduled-estate-census.yml").read_text()
        start = workflow.index("  file-audit:")
        workflow = workflow[start:]
        finalize = workflow.index("tools.ensure_repository_file_audit_receipt")
        self.assertLess(finalize, workflow.index("Publish sanitized file-audit summary"))
        self.assertLess(finalize, workflow.index("Retain private file evidence"))
        self.assertIn("if: always() && steps.collect.outcome != 'success'", workflow)
        self.assertIn('test "$COLLECT_OUTCOME" = success', workflow)
        self.assertIn("--minimum-repositories 123", workflow)
        self.assertNotIn("workflow_dispatch:", workflow)


if __name__ == "__main__":
    unittest.main()
