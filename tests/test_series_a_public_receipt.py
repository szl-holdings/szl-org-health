"""Exact public-census receipt binding without private-run overclaims."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from build_series_a_diligence import main
from census.diligence import (
    DiligenceError,
    MAX_RECEIPT_BYTES,
    canonical_bytes,
    compile_diligence,
    strict_load_json,
    strict_parse_json_bytes,
    validate_artifact,
)
from scripts.verify_series_a_schema_contract import Draft202012Validator
from tests.test_series_a_diligence import AS_OF, ROOT, SHA


COLLECTION = "a" * 32


def pair() -> tuple[dict, bytes, dict]:
    # Begin with the real closed public projection, not an internal fixture
    # with merely forged public markers. The collection is synthetic only for
    # these offline byte-binding regressions.
    report = copy.deepcopy(strict_load_json(ROOT / "static" / "data.json"))
    report["collection"] = {
        "schema": "szl.census-collection/v1",
        "id": COLLECTION,
        "started_at": "2026-08-11T10:59:00Z",
        "completed_at": "2026-08-11T11:00:00Z",
    }
    raw = canonical_bytes(report) + b"\n"
    receipt = {
        "schema": "szl.estate-census-receipt/v1",
        # Governance FAIL_CLOSED is intentionally independent of public-byte binding.
        "status": "FAIL_CLOSED",
        "snapshot": {"sha256": "c" * 64, "schema_version": 2},
        "public_snapshot": {
            "state": "FRESH_COLLECTION_BOUND",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "collection_id": COLLECTION,
        },
    }
    return report, raw, receipt


class PublicReceiptBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = strict_load_json(ROOT / "diligence" / "policy.json")
        cls.schema = strict_load_json(
            ROOT / "schemas" / "series-a-diligence.schema.json"
        )

    def compile(self, report: dict, raw: bytes, receipt: dict | None) -> dict:
        return compile_diligence(
            report,
            compiler_source_revision=SHA,
            policy=self.policy,
            as_of=AS_OF,
            raw_public_bytes=raw,
            public_snapshot_receipt=receipt,
        )

    def assert_binding(self, artifact: dict, expected: str) -> None:
        self.assertEqual(artifact["public_snapshot_binding"]["state"], expected)
        self.assertEqual(
            artifact["requirements"]["public_snapshot_receipt"]["state"], expected
        )
        self.assertEqual(validate_artifact(artifact), [])
        self.assertEqual(Draft202012Validator(self.schema).validate(artifact), [])

    def test_fail_closed_governance_receipt_can_bind_exact_public_bytes(self) -> None:
        report, raw, receipt = pair()
        artifact = self.compile(report, raw, receipt)
        self.assert_binding(artifact, "MEASURED")
        self.assertEqual(
            artifact["public_snapshot_binding"]["raw_public_sha256"],
            hashlib.sha256(raw).hexdigest(),
        )
        self.assertNotEqual(
            report["source_snapshot_sha256"], receipt["snapshot"]["sha256"]
        )
        self.assertIn(
            "not independently verified",
            artifact["public_snapshot_binding"]["reason"],
        )

    def test_absent_receipt_is_gap_and_historical_bytes_remain_reproducible(
        self,
    ) -> None:
        report, raw, _receipt = pair()
        artifact = self.compile(report, raw, None)
        self.assert_binding(artifact, "UNAVAILABLE")
        self.assertIn(
            "public_snapshot_receipt",
            {gap["requirement"] for gap in artifact["gaps"]},
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            census = root / "public.json"
            output = root / "diligence.json"
            markdown = root / "diligence.md"
            census.write_bytes(raw)
            arguments = [
                "--input",
                str(census),
                "--source-revision",
                SHA,
                "--as-of",
                AS_OF,
                "--output",
                str(output),
                "--markdown",
                str(markdown),
            ]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(arguments), 0)
                self.assertEqual(main([*arguments, "--check", "--historical-check"]), 0)
            self.assertEqual(
                strict_load_json(output)["public_snapshot_binding"]["state"],
                "UNAVAILABLE",
            )

    def test_public_byte_mutation_and_swapped_collection_diverge(self) -> None:
        report, raw, receipt = pair()
        equivalent_but_different_bytes = json.dumps(report, indent=2).encode("utf-8")
        self.assertNotEqual(equivalent_but_different_bytes, raw)
        self.assert_binding(
            self.compile(report, equivalent_but_different_bytes, receipt),
            "DIVERGENT",
        )
        swapped = copy.deepcopy(receipt)
        swapped["public_snapshot"]["collection_id"] = "d" * 32
        self.assert_binding(self.compile(report, raw, swapped), "DIVERGENT")

    def test_bad_public_schema_exposure_version_and_collection_fail_closed(
        self,
    ) -> None:
        for name, mutate in (
            ("projection", lambda value: value.update(projection_schema="other")),
            ("exposure", lambda value: value.update(exposure="internal")),
            ("version", lambda value: value.update(schema_version=3)),
            (
                "collection schema",
                lambda value: value["collection"].update(schema="other"),
            ),
            ("collection id", lambda value: value["collection"].update(id="invalid")),
        ):
            with self.subTest(name=name):
                report, _raw, receipt = pair()
                mutate(report)
                raw = canonical_bytes(report) + b"\n"
                receipt["public_snapshot"]["sha256"] = hashlib.sha256(raw).hexdigest()
                if name == "exposure":
                    with self.assertRaisesRegex(
                        DiligenceError, "private census inventory cannot enter"
                    ):
                        self.compile(report, raw, receipt)
                else:
                    self.assert_binding(self.compile(report, raw, receipt), "DIVERGENT")

    def test_bad_receipt_schema_state_hash_and_missing_bytes_diverge(self) -> None:
        for name, mutate in (
            ("schema", lambda value: value.update(schema="other")),
            ("state", lambda value: value["public_snapshot"].update(state="WITHHELD")),
            ("hash", lambda value: value["public_snapshot"].update(sha256="0" * 64)),
            ("missing hash", lambda value: value["public_snapshot"].pop("sha256")),
            (
                "collection",
                lambda value: value["public_snapshot"].update(collection_id="z" * 32),
            ),
        ):
            with self.subTest(name=name):
                report, raw, receipt = pair()
                mutate(receipt)
                self.assert_binding(self.compile(report, raw, receipt), "DIVERGENT")
        report, _raw, receipt = pair()
        self.assert_binding(self.compile(report, b"", receipt), "DIVERGENT")

    def test_malformed_receipt_cli_fails_closed_without_outputs(self) -> None:
        report, raw, _receipt = pair()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            census = root / "public.json"
            receipt_path = root / "receipt.json"
            output = root / "diligence.json"
            markdown = root / "diligence.md"
            census.write_bytes(raw)
            arguments = [
                "--input",
                str(census),
                "--receipt",
                str(receipt_path),
                "--source-revision",
                SHA,
                "--as-of",
                AS_OF,
                "--output",
                str(output),
                "--markdown",
                str(markdown),
            ]
            for payload in (b"{", b'{"schema":1,"schema":2}'):
                with self.subTest(payload=payload):
                    receipt_path.write_bytes(payload)
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(main(arguments), 6)
                    self.assertFalse(output.exists())
                    self.assertFalse(markdown.exists())
            receipt_path.unlink()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(arguments), 6)

    def test_receipt_byte_limit_and_semantic_claim_tampering(self) -> None:
        with self.assertRaises(DiligenceError):
            strict_parse_json_bytes(
                b" " * (MAX_RECEIPT_BYTES + 1),
                source="receipt",
                max_bytes=MAX_RECEIPT_BYTES,
            )
        report, raw, _receipt = pair()
        artifact = self.compile(report, raw, None)
        artifact["public_snapshot_binding"]["state"] = "MEASURED"
        artifact["public_snapshot_binding"]["reason"] = (
            "Exact supplied public census bytes match a FRESH_COLLECTION_BOUND receipt projection; "
            "internal snapshot bytes and run identity are not independently verified."
        )
        artifact.pop("digest_sha256")
        artifact["digest_sha256"] = hashlib.sha256(
            canonical_bytes(artifact)
        ).hexdigest()
        self.assertIn(
            "public_snapshot_binding.measured_claim", validate_artifact(artifact)
        )


if __name__ == "__main__":
    unittest.main()
