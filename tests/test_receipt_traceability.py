"""Retain control outcomes without retaining private census evidence."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import tempfile
import unittest
from collections import Counter
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from census import receipt, report
from census.governance import evaluate_report
from tests.test_collection_binding import SUBJECT, collect
from tests.test_receipt import bounded_snapshot, receipt_for


class ReceiptTraceabilityTests(unittest.TestCase):
    def tearDown(self):
        report._CACHE.update(data=None, ts=0)

    def test_control_outcomes_reconcile_with_both_summaries(self):
        result = receipt_for(bounded_snapshot())
        observations = result["observations"]
        for prefix in ("governance", "governance_recomputed"):
            rows = observations[prefix + "_controls"]
            self.assertEqual([r["id"] for r in rows],
                             list(receipt.REQUIRED_GOVERNANCE_CONTROL_IDS))
            self.assertTrue(all(set(r) == {"id", "status"} for r in rows))
            counts = Counter(r["status"] for r in rows)
            self.assertEqual({s: counts[s] for s in receipt.GOVERNANCE_STATUSES},
                             observations[prefix + "_summary"])
        self.assertEqual(result["status"], "FAIL_CLOSED")

    def test_control_projection_is_deterministic(self):
        snapshot = json.loads(bounded_snapshot())
        expected = receipt_for(json.dumps(snapshot).encode())["observations"]["governance_controls"]
        snapshot["governance"]["controls"].reverse()
        actual = receipt_for(json.dumps(snapshot).encode())
        self.assertEqual(actual["observations"]["governance_controls"], expected)
        self.assertFalse(actual["observations"]["governance_recomputed_matches"])
        self.assertEqual(actual["status"], "FAIL_CLOSED")

    def test_private_metadata_does_not_enter_receipt_or_summary(self):
        snapshot = json.loads(bounded_snapshot())
        canary = "PRIVATE-TRACEABILITY-CANARY"
        for control in snapshot["governance"]["controls"]:
            control.update(summary=canary, evidence={"private_repo": canary},
                           private_extension=canary)
        result = receipt_for(json.dumps(snapshot).encode())
        self.assertIsNotNone(result["observations"]["governance_controls"])
        self.assertNotIn(canary, json.dumps(result))
        self.assertNotIn(canary, receipt.render_summary(result))
        self.assertFalse(result["observations"]["governance_recomputed_matches"])
        self.assertEqual(result["status"], "FAIL_CLOSED")

    def test_malformed_embedded_controls_are_unavailable_without_leaking(self):
        baseline = json.loads(bounded_snapshot())
        mutations = [
            lambda g: g.pop("controls"),
            lambda g: g["controls"].append(copy.deepcopy(g["controls"][0])),
            lambda g: g["controls"][0].update(id="PRIVATE-TRACEABILITY-CANARY"),
            lambda g: g["controls"][0].update(id=[]),
            lambda g: g["controls"][0].update(status={"private": "PRIVATE-TRACEABILITY-CANARY"}),
            lambda g: g["controls"].pop(),
            lambda g: g["summary"].update(PASS=999),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                snapshot = copy.deepcopy(baseline)
                mutate(snapshot["governance"])
                result = receipt_for(json.dumps(snapshot).encode())
                self.assertIsNone(result["observations"]["governance_controls"])
                self.assertIsNotNone(result["observations"]["governance_recomputed_controls"])
                self.assertNotIn("PRIVATE-TRACEABILITY-CANARY", json.dumps(result))
                self.assertEqual(result["status"], "FAIL_CLOSED")

    def test_recomputed_outcomes_are_not_copied_from_embedded_claims(self):
        snapshot = json.loads(bounded_snapshot())
        original = evaluate_report(snapshot)
        control = snapshot["governance"]["controls"][0]
        old = control["status"]
        new = "FAIL" if old != "FAIL" else "UNKNOWN"
        control["status"] = new
        snapshot["governance"]["summary"][old] -= 1
        snapshot["governance"]["summary"][new] += 1
        counts = snapshot["governance"]["summary"]
        snapshot["governance"]["overall_status"] = (
            "FAIL" if counts["FAIL"] else "UNKNOWN" if counts["UNKNOWN"] else "PASS")
        result = receipt_for(json.dumps(snapshot).encode())
        obs = result["observations"]
        embedded = {r["id"]: r["status"] for r in obs["governance_controls"]}
        recomputed = {r["id"]: r["status"] for r in obs["governance_recomputed_controls"]}
        self.assertEqual(embedded[control["id"]], new)
        self.assertEqual(recomputed, {r["id"]: r["status"] for r in original["controls"]})
        self.assertFalse(obs["governance_recomputed_matches"])
        self.assertEqual(result["status"], "FAIL_CLOSED")

    def test_recomputation_failure_cannot_emit_control_passes(self):
        raw = bounded_snapshot()
        with patch.object(receipt, "evaluate_report", side_effect=ValueError("PRIVATE")):
            result = receipt_for(raw)
        self.assertIsNone(result["observations"]["governance_recomputed_controls"])
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertEqual(result["status"], "FAIL_CLOSED")

    def test_input_digest_keeps_exact_bytes_and_explicit_verification_scope(self):
        raw = bounded_snapshot()
        result = receipt_for(raw)
        self.assertEqual(result["snapshot"]["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result["snapshot"]["sha256_verification"],
                         "REQUIRES_ORIGINAL_INPUT_BYTES")
        self.assertIn("requires original input bytes", receipt.render_summary(result))

    def test_cli_retains_outcomes_after_private_input_removal(self):
        snapshot = collect()
        raw = report.serialize_report(snapshot).encode()
        public = report.serialize_report(report.project_public_report(snapshot)).encode()
        environment = {"COLLECT_OUTCOME": "success", "EXPECTED_GITHUB_REPOSITORIES_MINIMUM": "0",
                       **{"RECEIPT_" + k.upper(): v for k, v in SUBJECT.items()}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            internal, candidate = root / "census-internal.json", root / "data.json"
            output, retained = root / "census-receipt.json", root / "census-public.json"
            internal.write_bytes(raw)
            candidate.write_bytes(public)
            with redirect_stdout(io.StringIO()):
                status = receipt.main(["--snapshot", str(internal), "--receipt", str(output),
                                       "--public-snapshot", str(candidate),
                                       "--publish-snapshot", str(retained)],
                                      environ=environment, now=datetime.now(timezone.utc))
            internal.unlink()
            saved = json.loads(output.read_bytes())
            self.assertEqual(status, 1)
            self.assertEqual(saved["status"], "FAIL_CLOSED")
            self.assertEqual(saved["public_snapshot"]["sha256"],
                             hashlib.sha256(retained.read_bytes()).hexdigest())
            self.assertEqual(len(saved["observations"]["governance_recomputed_controls"]), 15)
            self.assertFalse(internal.exists())


if __name__ == "__main__":
    unittest.main()
