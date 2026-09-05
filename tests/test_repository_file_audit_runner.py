# SPDX-License-Identifier: Apache-2.0
"""Contracts for the hosted authoritative repository-file audit runner."""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

RUNNER_PATH = (
    Path(__file__).resolve().parents[1]
    / "tools"
    / "run_repository_file_audit.py"
)
SPEC = importlib.util.spec_from_file_location(
    "run_repository_file_audit",
    RUNNER_PATH,
)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def _inventory(public: int, private: int) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for index in range(public):
        rows.append(
            {
                "full_name": f"szl-holdings/public-{index}",
                "visibility": "public",
                "private": False,
            }
        )
    for index in range(private):
        rows.append(
            {
                "full_name": f"szl-holdings/private-{index}",
                "visibility": "private",
                "private": True,
            }
        )
    return rows


def _reconciliation(
    *,
    public: int,
    private: int,
    authoritative: bool = True,
    matched: bool = True,
) -> dict[str, object]:
    return {
        "observed_repository_count": public + private,
        "observed_public_count": public,
        "observed_private_or_internal_count": private,
        "authoritative_count_available": authoritative,
        "authoritative_expected_count": public + private if authoritative else None,
        "matched": matched if authoritative else None,
        "error": None,
    }


class InventoryGateTests(unittest.TestCase):
    def test_authoritative_totals_are_mandatory(self) -> None:
        with self.assertRaises(runner.audit.AuditError):
            runner.validate_authoritative_inventory(
                _inventory(123, 0),
                _reconciliation(
                    public=123,
                    private=0,
                    authoritative=False,
                ),
                123,
            )

    def test_authoritative_totals_must_match_pagination(self) -> None:
        with self.assertRaises(runner.audit.AuditError):
            runner.validate_authoritative_inventory(
                _inventory(117, 6),
                _reconciliation(
                    public=117,
                    private=6,
                    matched=False,
                ),
                123,
            )

    def test_private_visibility_is_required(self) -> None:
        with self.assertRaises(runner.audit.AuditError):
            runner.validate_authoritative_inventory(
                _inventory(123, 0),
                _reconciliation(public=123, private=0),
                123,
            )

    def test_complete_authoritative_inventory_is_accepted(self) -> None:
        runner.validate_authoritative_inventory(
            _inventory(117, 6),
            _reconciliation(public=117, private=6),
            123,
        )


class ReceiptTests(unittest.TestCase):
    def test_failure_receipt_contains_no_private_identity_or_secret(self) -> None:
        report = runner.failure_report(
            org="szl-holdings",
            reason="authoritative totals unavailable",
            reconciliation=_reconciliation(
                public=117,
                private=0,
                authoritative=False,
            ),
        )
        public = runner.audit.public_projection(report)
        rendered = json.dumps(public, sort_keys=True)

        self.assertEqual(public["summary"]["state"], "INCOMPLETE")
        self.assertEqual(public["public_repositories"], [])
        self.assertNotIn("private-0", rendered)
        self.assertNotIn("TOKEN_VALUE", rendered)
        self.assertFalse(report["failure"]["secret_values_recorded"])
        self.assertFalse(report["failure"]["private_repository_names_recorded"])

    def test_missing_authority_writes_both_failure_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            private_path = Path(folder) / "private.json"
            public_path = Path(folder) / "public.json"
            with mock.patch.object(
                runner.audit,
                "list_repositories",
                return_value=(
                    _inventory(117, 0),
                    _reconciliation(
                        public=117,
                        private=0,
                        authoritative=False,
                    ),
                ),
            ):
                code = runner.run(
                    [
                        "--output",
                        str(private_path),
                        "--public-output",
                        str(public_path),
                        "--minimum-repositories",
                        "123",
                    ]
                )

            self.assertEqual(code, 2)
            private = json.loads(private_path.read_text(encoding="utf-8"))
            public = json.loads(public_path.read_text(encoding="utf-8"))
            self.assertEqual(private["summary"]["state"], "INCOMPLETE")
            self.assertEqual(public["summary"]["state"], "INCOMPLETE")
            self.assertIn("receipt_sha256", private)
            self.assertIn("receipt_sha256", public)

    def test_unexpected_exception_records_only_its_class(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            private_path = Path(folder) / "private.json"
            public_path = Path(folder) / "public.json"
            with mock.patch.object(
                runner.audit,
                "list_repositories",
                side_effect=RuntimeError("TOKEN_VALUE private-repository-name"),
            ):
                code = runner.run(
                    [
                        "--output",
                        str(private_path),
                        "--public-output",
                        str(public_path),
                    ]
                )

            self.assertEqual(code, 2)
            rendered = private_path.read_text(encoding="utf-8")
            self.assertIn("collector exception:RuntimeError", rendered)
            self.assertNotIn("TOKEN_VALUE", rendered)
            self.assertNotIn("private-repository-name", rendered)

    def test_complete_report_is_written_and_private_projection_is_redacted(self) -> None:
        inventory = _inventory(117, 6)
        reconciliation = _reconciliation(public=117, private=6)
        completed = {
            "schema": runner.audit.SCHEMA,
            "observed_at": "2026-09-05T00:00:00Z",
            "organization": "szl-holdings",
            "source": {},
            "inventory_reconciliation": reconciliation,
            "repositories": [
                {
                    "repository": "szl-holdings/public-0",
                    "visibility": "public",
                    "state": "PASS",
                    "revision": "a" * 40,
                    "tree_sha": "b" * 40,
                    "file_count": 1,
                    "entry_count": 1,
                    "tracked_bytes": 1,
                    "finding_count": 0,
                },
                {
                    "repository": "szl-holdings/private-0",
                    "visibility": "private",
                    "state": "PASS",
                    "revision": "c" * 40,
                    "tree_sha": "d" * 40,
                    "file_count": 1,
                    "entry_count": 1,
                    "tracked_bytes": 1,
                    "finding_count": 0,
                },
            ],
            "summary": {
                "state": "PASS",
                "state_counts": {"PASS": 2},
                "severity_counts": {},
                "inspection_counts": {},
                "totals": {
                    "repositories": 123,
                    "entries": 2,
                    "files": 2,
                    "directories": 0,
                    "submodules": 0,
                    "bytes_tracked_and_verified": 2,
                    "findings": 0,
                },
            },
        }
        completed["receipt_sha256"] = runner.audit.sha256_json(completed)

        with tempfile.TemporaryDirectory() as folder:
            private_path = Path(folder) / "private.json"
            public_path = Path(folder) / "public.json"
            with (
                mock.patch.object(
                    runner.audit,
                    "list_repositories",
                    return_value=(inventory, reconciliation),
                ),
                mock.patch.object(
                    runner.audit,
                    "run_audit",
                    return_value=completed,
                ) as run_audit,
            ):
                code = runner.run(
                    [
                        "--output",
                        str(private_path),
                        "--public-output",
                        str(public_path),
                        "--minimum-repositories",
                        "123",
                    ]
                )

            self.assertEqual(code, 0)
            self.assertTrue(run_audit.called)
            public_text = public_path.read_text(encoding="utf-8")
            self.assertIn("szl-holdings/public-0", public_text)
            self.assertNotIn("szl-holdings/private-0", public_text)


if __name__ == "__main__":
    unittest.main()
