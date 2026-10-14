# SPDX-License-Identifier: Apache-2.0
"""Private mutations cannot influence closed public file-audit bytes."""
import copy
import unittest
from unittest.mock import patch

from census import file_audit as audit


class PublicPrivacyTests(unittest.TestCase):
    def report(self):
        return {
            "observed_at": "2026-10-07T12:00:00Z", "organization": "szl-holdings",
            "repositories": [{
                "repository": "szl-holdings/public-fixture", "private": False,
                "visibility": "public", "state": "FAIL", "file_count": 1,
                "bytes_tracked": 7,
                "files": [{"path": "app.py", "size": 7, "role": "source",
                           "inspection": "hashed-and-source-inspected"}],
                "findings": [{"path": "app.py", "severity": "critical", "rule": "fixture"}],
            }],
        }

    def test_private_counts_states_findings_and_hashes_cannot_change_public_bytes(self):
        original = self.report()
        expected = audit.canonical_json(audit.public_projection(original))
        report = copy.deepcopy(original)
        for index in range(12):
            report["repositories"].append({
                "repository": f"szl-holdings/private-fixture-{index}", "private": True,
                "visibility": "private", "state": "INCOMPLETE", "file_count": 10000,
                "bytes_tracked": 999999, "findings": [{"severity": "critical"}],
                "repository_receipt_sha256": "private-hash", "errors": ["private-path"],
            })
        report["summary"] = audit.summarize(report["repositories"])
        report["source"] = {"principal": "PRIVATE", "organization_population": 140}
        report["inventory_reconciliation"] = {"observed_private_or_internal_count": 12}
        report["receipt_sha256"] = "private-aggregate-hash"
        self.assertEqual(expected, audit.canonical_json(audit.public_projection(report)))
        self.assertEqual(audit.public_projection(report)["summary"]["severity_counts"], {"critical": 1})

    def test_only_literal_false_and_coherent_visibility_are_admitted(self):
        for flag in (True, None, 0, "false", [], {}):
            report = self.report()
            report["repositories"][0]["private"] = flag
            self.assertEqual(audit.public_projection(report)["public_repositories"], [])
        report = self.report()
        del report["repositories"][0]["private"]
        self.assertEqual(audit.public_projection(report)["public_repositories"], [])
        report["repositories"][0].update(private=False, visibility="internal")
        self.assertEqual(audit.public_projection(report)["public_repositories"], [])

    def test_nested_unknown_extensions_and_raw_details_are_not_public(self):
        report = self.report()
        expected = audit.public_projection(report)
        row = report["repositories"][0]
        row["credential"] = {"principal": "PRIVATE"}
        row["files"][0]["private_extension"] = {"secret_path": "PRIVATE"}
        row["findings"][0].update(detail="PRIVATE", repository="PRIVATE", extension="PRIVATE")
        row["repository_receipt_sha256"] = "PRIVATE"
        self.assertEqual(expected, audit.public_projection(report))

    def test_nested_top_level_values_are_not_copied(self):
        report = self.report()
        report.update(observed_at={"private": "PRIVATE"}, organization={"principal": "PRIVATE"})
        value = audit.public_projection(report)
        self.assertIsNone(value["observed_at"])
        self.assertIsNone(value["organization"])
        self.assertNotIn("PRIVATE", audit.canonical_json(value).decode())

    def test_unknown_states_errors_and_boolean_counts_do_not_become_pass(self):
        for changed in ({"state": "UNKNOWN"}, {"state": "PASS", "errors": ["PRIVATE"]},
                        {"state": "PASS", "file_count": True}):
            report = self.report()
            report["repositories"][0].update(changed)
            value = audit.public_projection(report)
            self.assertEqual(value["summary"]["state"], "INCOMPLETE")
            self.assertNotIn("PRIVATE", audit.canonical_json(value).decode())

    def test_provider_private_boolean_is_retained_even_on_incomplete_audit(self):
        for flag in (False, True, None):
            row = audit.audit_repository({"full_name": "szl-holdings/fixture", "private": flag},
                max_text_bytes=1, max_archive_bytes=1, max_repository_bytes=1)
            self.assertIs(row["private"], flag)
            self.assertEqual(row["state"], "INCOMPLETE")

    def test_public_digest_and_input_are_independent(self):
        report = self.report()
        before = copy.deepcopy(report)
        value = audit.public_projection(report)
        digest = value.pop("receipt_sha256")
        self.assertEqual(digest, audit.sha256_json(value))
        row = value["public_repositories"][0]
        row_digest = row.pop("repository_receipt_sha256")
        self.assertEqual(row_digest, audit.sha256_json(row))
        self.assertEqual(report, before)


if __name__ == "__main__":
    unittest.main()
