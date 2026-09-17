# SPDX-License-Identifier: Apache-2.0
"""Projection/CLI regressions use synthetic audit receipts, never live credentials."""
from __future__ import annotations

import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from census import file_audit as audit


class ClaimBoundaryTests(unittest.TestCase):
    def report(self, state="INCOMPLETE"):
        return {
            "schema": audit.SCHEMA,
            "observed_at": "2026-09-16T00:00:00Z",
            "organization": "szl-holdings",
            "source": {"organization_population": None,
                       "verified_work_counts_are_population": False},
            "inventory_reconciliation": {"authoritative_count_available": False,
                                         "authoritative_expected_count": None,
                                         "matched": None},
            "summary": {**audit.summarize([]), "state": state},
            "repositories": [],
        }

    def assert_boundary(self, value):
        text = value["claim_boundary"]
        self.assertIn("does not establish complete enumeration or byte verification", text)
        self.assertIn("INCOMPLETE result cannot establish an organization-complete audit", text)
        self.assertIn("UTF-8 source inspection remains separately labelled", text)
        self.assertIn("not recursively trusted", text)
        self.assertNotIn("was enumerated", text)
        self.assertNotIn("byte was verified", text)

    def test_precollection_failure_does_not_claim_complete_verification(self):
        value = audit.public_projection(self.report())
        self.assert_boundary(value)
        self.assertEqual(value["summary"]["state"], "INCOMPLETE")
        self.assertEqual(value["summary"]["totals"]["files"], 0)
        self.assertIsNone(value["source"]["organization_population"])
        self.assertIsNone(value["inventory_reconciliation"]["authoritative_expected_count"])
        self.assertIs(value["source"]["verified_work_counts_are_population"], False)

    def test_missing_report_fields_do_not_create_positive_claims(self):
        value = audit.public_projection({})
        self.assert_boundary(value)
        self.assertIsNone(value["summary"])
        self.assertIsNone(value["inventory_reconciliation"])

    def test_all_summary_states_preserve_their_original_evidence(self):
        for state in ("PASS", "WARN", "FAIL", "INCOMPLETE", "UNKNOWN", None):
            with self.subTest(state=state):
                report = self.report(state)
                before = copy.deepcopy(report)
                value = audit.public_projection(report)
                self.assert_boundary(value)
                for name in ("summary", "source", "inventory_reconciliation"):
                    self.assertEqual(value[name], before[name])
                self.assertEqual(report, before)

    def test_partial_population_does_not_hide_unfinished_rows(self):
        report = self.report()
        report["repositories"] = [
            {"repository": "szl-holdings/public-fixture", "visibility": "public",
             "state": "PASS", "file_count": 2, "bytes_tracked": 6},
            {"repository": "szl-holdings/unfinished-fixture", "visibility": "public",
             "state": "INCOMPLETE", "errors": ["fixture failure"]},
        ]
        report["summary"] = audit.summarize(report["repositories"])
        value = audit.public_projection(report)
        self.assert_boundary(value)
        self.assertEqual(value["public_repositories"], report["repositories"])
        self.assertEqual(value["summary"]["state_counts"], {"INCOMPLETE": 1, "PASS": 1})
        self.assertEqual(value["summary"]["totals"]["bytes_tracked_and_verified"], 6)

    def test_private_names_paths_hashes_findings_remain_undisclosed(self):
        report = self.report()
        private = {"repository": "private-fixture-name", "visibility": "private",
                   "state": "INCOMPLETE", "files": [{"path": "private-fixture-path"}],
                   "findings": [{"detail": "private-fixture-finding"}],
                   "tree_sha": "private-fixture-hash"}
        report["repositories"] = [private, {**private, "visibility": "internal"}]
        value = audit.public_projection(report)
        self.assert_boundary(value)
        self.assertEqual(value["public_repositories"], [])
        self.assertEqual(value["private_repositories"], {
            "count": 2, "state_counts": {"INCOMPLETE": 2},
            "names_paths_hashes_and_findings_disclosed": False,
        })
        self.assertNotIn("private-fixture-", json.dumps(value))

    def test_positive_inventory_reconciliation_is_retained_not_reinterpreted(self):
        report = self.report("WARN")
        report["inventory_reconciliation"] = {
            "authoritative_count_available": True, "authoritative_expected_count": 3,
            "observed_repository_count": 3, "matched": True,
        }
        value = audit.public_projection(report)
        self.assert_boundary(value)
        self.assertEqual(value["inventory_reconciliation"], report["inventory_reconciliation"])
        self.assertEqual(value["summary"]["state"], "WARN")

    def test_receipt_digest_commits_to_current_claim_boundary(self):
        value = audit.public_projection(self.report())
        digest = value.pop("receipt_sha256")
        self.assertEqual(digest, audit.sha256_json(value))
        value["claim_boundary"] = "Every tracked blob byte was verified."
        self.assertNotEqual(digest, audit.sha256_json(value))

    def test_projection_is_deterministic_and_leaves_original_receipt_untouched(self):
        report = self.report()
        report["receipt_sha256"] = audit.sha256_json(report)
        before = audit.canonical_json(report)
        first = audit.public_projection(report)
        second = audit.public_projection(json.loads(before))
        self.assertEqual(first, second)
        self.assertEqual(audit.canonical_json(report), before)
        self.assertEqual(first["schema"], audit.PUBLIC_SCHEMA)

    def test_real_cli_preserves_incomplete_exit_and_persists_bounded_claim(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            report = self.report()
            report["receipt_sha256"] = audit.sha256_json(report)
            with patch.object(audit, "run_audit", return_value=report), patch("sys.stdout", new=io.StringIO()):
                result = audit.main(["--output", str(folder / "private.json"),
                                     "--public-output", str(folder / "public.json"),
                                     "--allow-findings"])
            self.assertEqual(result, 2)
            self.assertEqual(json.loads((folder / "private.json").read_text()), report)
            self.assert_boundary(json.loads((folder / "public.json").read_text()))

    def test_complete_findings_exit_policy_is_unchanged(self):
        for state in ("PASS", "WARN", "FAIL"):
            for allow in (False, True):
                with self.subTest(state=state, allow=allow), tempfile.TemporaryDirectory() as name:
                    report = self.report(state)
                    report["receipt_sha256"] = audit.sha256_json(report)
                    argv = ["--output", str(Path(name) / "report.json")]
                    if allow:
                        argv.append("--allow-findings")
                    with patch.object(audit, "run_audit", return_value=report), patch("sys.stdout", new=io.StringIO()):
                        result = audit.main(argv)
                    self.assertEqual(result, 0 if state == "PASS" or allow else 1)


if __name__ == "__main__":
    unittest.main()
