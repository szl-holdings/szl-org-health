"""Deterministic receipt/CLI regression fixtures; these are not live SLO proof."""

from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from autonomic.slo_controller import (
    RECEIPT_SCHEMA,
    append_sample,
    canonical_json,
    load_policy,
    observation_digest,
    severity_for_surface,
    sha256_hex,
    summarize_window,
)


ROOT = Path(__file__).resolve().parents[1]


def receipt_fixture(*, historical_failure: bool = False) -> dict:
    """Compute a receipt from fixture history, preserving the production SLO rules."""
    policy, policy_digest = load_policy(ROOT / "autonomic/slo_policy.json")
    now = dt.datetime(2026, 9, 12, 12, 10, tzinfo=dt.timezone.utc)
    now_epoch = int(now.timestamp())
    surfaces = []
    reasons = []
    for repository in policy["allowed_hf_repositories"]:
        surface_id = repository.split("/", 1)[1]
        buckets = []
        for index in reversed(range(288)):
            buckets = append_sample(
                buckets,
                sample_epoch=now_epoch - index * 300,
                ok=not (historical_failure and surface_id == "a11oy" and index == 144),
                latency_ms=100,
                latency_objective_ms=policy["latency_objective_ms"],
                retention_minutes=policy["history_retention_minutes"],
            )
        windows = [
            summarize_window(
                buckets,
                name=window["name"],
                minutes=window["minutes"],
                now_epoch=now_epoch,
                cadence_minutes=policy["cadence_minutes"],
                availability_objective_percent=policy["availability_objective_percent"],
                minimum_coverage_percent=policy["minimum_window_coverage_percent"],
            )
            for window in policy["burn_windows"]
        ]
        severity, surface_reasons = severity_for_surface(
            current_ok=True, provider_blocker=None, windows=windows, policy=policy
        )
        reasons.extend(f"{surface_id}: {reason}" for reason in surface_reasons)
        surfaces.append(
            {
                "id": surface_id,
                "hf_repository": repository,
                "base_url": f"https://szlholdings-{surface_id}.hf.space",
                "ok": True,
                "current_ok": True,
                "provider_blocker": None,
                "maximum_latency_ms": 100,
                "paths": [],
                "severity": severity,
                "reasons": surface_reasons,
                "windows": [window.receipt() for window in windows],
                "current_failure_age_minutes": None,
            }
        )
    return {
        "schema": RECEIPT_SCHEMA,
        "cycle_id": "slo_deterministic_regression_fixture",
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "controller_repository": policy["controller_repository"],
        "controller_revision": "a" * 40,
        "manifest_repository": policy["source_manifest"]["repository"],
        "manifest_revision": "b" * 40,
        "manifest_sha256": "c" * 64,
        "policy_sha256": policy_digest,
        "availability_objective_percent": policy["availability_objective_percent"],
        "latency_objective_ms": policy["latency_objective_ms"],
        "recovery_objective_minutes": policy["recovery_objective_minutes"],
        "verdict": "INCIDENT" if reasons else "HEALTHY",
        "severity": "SEV3" if reasons else None,
        "reasons": reasons,
        "surfaces": surfaces,
        "deadman": {"state": "FRESH", "ok": True, "reason": "fixture heartbeat"},
        "healthy_cycles": 0 if reasons else 3,
        "incident": {"action": "throttled" if reasons else "none", "number": 123 if reasons else None},
        "authority": {"issue_state_only": True, "source_write": False},
        "secret_values_recorded": False,
    }


class WorkflowEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.healthy = receipt_fixture()
        cls.incident = receipt_fixture(historical_failure=True)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.report_path = self.directory / "autonomic-slo.json"
        self.sidecar_path = self.report_path.with_suffix(".json.sha256")
        self.summary_path = self.directory / "summary.md"

    def write_receipt(self, report: dict) -> dict:
        payload = {key: value for key, value in report.items() if key != "receipt_sha256"}
        payload["receipt_sha256"] = sha256_hex(canonical_json(payload))
        self.report_path.write_text(json.dumps(payload), encoding="utf-8")
        self.sidecar_path.write_text(payload["receipt_sha256"] + "\n", encoding="ascii")
        return payload

    def run_gate(self, exit_code: str | None, *, summary: bool = False) -> subprocess.CompletedProcess:
        command = [
            sys.executable,
            "-B",
            "-m",
            "autonomic.slo_evidence",
            "--report",
            str(self.report_path),
        ]
        if exit_code is not None:
            command.extend(["--exit-code", exit_code])
        if summary:
            command.extend(["--summary", str(self.summary_path)])
        return subprocess.run(
            command,
            cwd=ROOT,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
            check=False,
        )

    def assert_failure(self, result: subprocess.CompletedProcess) -> None:
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertTrue((result.stdout + result.stderr).strip())
        self.assertNotIn("Traceback", result.stdout + result.stderr)

    def test_complete_healthy_receipt_passes(self) -> None:
        self.assertEqual(len(self.healthy["surfaces"]), 7)
        self.assertTrue(all(row["current_ok"] for row in self.healthy["surfaces"]))
        self.write_receipt(self.healthy)
        result = self.run_gate("0")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("HEALTHY", result.stdout + result.stderr)

    def test_new_observation_digest_and_historical_v1_receipts_both_verify(self) -> None:
        for include_observation in (False, True):
            with self.subTest(include_observation=include_observation):
                report = dict(self.incident)
                self.assertNotIn("observation_sha256", report)
                if include_observation:
                    report["observation_sha256"] = observation_digest(report)
                self.write_receipt(report)
                result = self.run_gate("2")
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("INCIDENT", result.stdout + result.stderr)

    def test_invalid_observation_digest_fails_even_with_valid_final_receipt_hash(self) -> None:
        for observation in (None, "", "0" * 64, 123):
            with self.subTest(observation=observation):
                self.write_receipt({**self.healthy, "observation_sha256": observation})
                self.assert_failure(self.run_gate("0"))

    def test_changed_measurement_cannot_reuse_observation_digest(self) -> None:
        report = {**self.healthy, "observation_sha256": observation_digest(self.healthy)}
        report["controller_revision"] = "d" * 40
        self.write_receipt(report)
        self.assert_failure(self.run_gate("0"))

    def test_current_recovery_does_not_erase_a_real_historical_burn_incident(self) -> None:
        self.assertTrue(all(row["current_ok"] for row in self.incident["surfaces"]))
        affected = next(row for row in self.incident["surfaces"] if row["id"] == "a11oy")
        self.assertEqual(affected["severity"], "SEV3")
        fast, medium, slow = affected["windows"]
        self.assertEqual(fast["error_budget_burn"], 0)
        self.assertEqual(medium["error_budget_burn"], 0)
        self.assertEqual(slow["minutes"], 1440)
        self.assertEqual(slow["observed_samples"], 288)
        self.assertEqual(slow["coverage_percent"], 100)
        self.assertAlmostEqual(slow["error_budget_burn"], 1000 / 288, places=5)
        self.write_receipt(self.incident)
        result = self.run_gate("2")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("INCIDENT", result.stdout + result.stderr)
        self.assertIn("SEV3", result.stdout + result.stderr)
        for reason in self.incident["reasons"]:
            self.assertIn(reason, result.stdout + result.stderr)

    def test_summary_appends_incident_reasons_burn_and_coverage(self) -> None:
        self.write_receipt(self.incident)
        self.summary_path.write_text("Existing evidence\n", encoding="utf-8")
        result = self.run_gate("2", summary=True)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        summary = self.summary_path.read_text(encoding="utf-8")
        self.assertTrue(summary.startswith("Existing evidence\n"))
        for reason in self.incident["reasons"]:
            self.assertIn(reason, summary)
        self.assertIn("INCIDENT", summary)
        self.assertIn("SEV3", summary)
        self.assertIn("slow", summary.lower())
        self.assertIn("burn", summary.lower())
        self.assertIn("coverage", summary.lower())
        self.assertRegex(summary, r"3\.47")
        self.assertRegex(summary, r"(?m)^\| a11oy \| slow \|.*\| 288 / 288 \| 100(?:\.0+)?%? \|")

    def test_missing_receipt_fails_even_when_controller_claims_success(self) -> None:
        self.assert_failure(self.run_gate("0"))

    def test_malformed_receipts_fail_without_echoing_raw_input(self) -> None:
        marker = "DO_NOT_ECHO_POTENTIAL_SECRET"
        for value in (marker, "[]", "null", json.dumps({"schema": marker})):
            with self.subTest(value=value):
                self.report_path.write_text(value, encoding="utf-8")
                result = self.run_gate("0")
                self.assert_failure(result)
                self.assertNotIn(marker, result.stdout + result.stderr)

    def test_unknown_or_missing_controller_exit_cannot_become_success(self) -> None:
        self.write_receipt(self.healthy)
        for exit_code in (None, "", "1", "17", "success", "0\n2"):
            with self.subTest(exit_code=exit_code):
                self.assert_failure(self.run_gate(exit_code))

    def test_controller_exit_must_agree_with_receipt_verdict(self) -> None:
        for report, exit_code in ((self.incident, "0"), (self.healthy, "2")):
            with self.subTest(verdict=report["verdict"], exit_code=exit_code):
                self.write_receipt(report)
                self.assert_failure(self.run_gate(exit_code))

    def test_failed_receipt_cannot_be_relabelled_healthy(self) -> None:
        self.write_receipt({**self.healthy, "verdict": "FAILED", "error_kind": "URL_ERROR"})
        for exit_code in ("0", "1", "2"):
            with self.subTest(exit_code=exit_code):
                self.assert_failure(self.run_gate(exit_code))

    def test_internally_inconsistent_healthy_receipt_fails(self) -> None:
        for change in (
            {"severity": "SEV3"},
            {"reasons": ["unresolved reliability failure"]},
            {"deadman": {"state": "STALE", "ok": False}},
            {"surfaces": []},
            {"surfaces": [{**self.healthy["surfaces"][0], "current_ok": False}]},
        ):
            with self.subTest(change=change):
                self.write_receipt({**self.healthy, **change})
                self.assert_failure(self.run_gate("0"))

    def test_incident_requires_explicit_severity_and_reasons(self) -> None:
        for change in ({"severity": None}, {"reasons": []}):
            with self.subTest(change=change):
                self.write_receipt({**self.incident, **change})
                self.assert_failure(self.run_gate("2"))

    def test_tampering_with_hashed_receipt_fails(self) -> None:
        payload = self.write_receipt(self.healthy)
        payload["controller_revision"] = "d" * 40
        self.report_path.write_text(json.dumps(payload), encoding="utf-8")
        self.assert_failure(self.run_gate("0"))

    def test_missing_or_mismatched_hash_sidecar_fails(self) -> None:
        for sidecar in (None, "0" * 64, "not-a-sha256"):
            with self.subTest(sidecar=sidecar):
                self.write_receipt(self.healthy)
                if sidecar is None:
                    self.sidecar_path.unlink()
                else:
                    self.sidecar_path.write_text(sidecar + "\n", encoding="ascii")
                self.assert_failure(self.run_gate("0"))

    def test_final_workflow_step_runs_checked_gate_without_ignoring_failure(self) -> None:
        workflow = (ROOT / ".github/workflows/autonomic-slo.yml").read_text(encoding="utf-8")
        name = "      - name: Preserve the reliability verdict as workflow evidence"
        self.assertEqual(workflow.count(name), 1)
        final_step = workflow.split(name, 1)[1].split("\n      - name:", 1)[0]
        self.assertIn("if: always()", final_step)
        self.assertNotIn("continue-on-error", final_step)
        self.assertIn("python -m autonomic.slo_evidence", final_step)
        self.assertIn("--report reports/autonomic-slo.json", final_step)
        self.assertIn('--exit-code "$SLO_EXIT_CODE"', final_step)
        self.assertNotRegex(final_step, r"\|\|\s*(?:true|:)\b|exit\s+0\b")
        run_block = final_step.split("run: |", 1)[1]
        # Exercise the command that gates hosted success, not a helper disconnected from CI.
        self.assertRegex(run_block, r"set -euo pipefail\s+python -m autonomic\.slo_evidence")
        self.assertIn("tests.test_slo_workflow_evidence", workflow)


if __name__ == "__main__":
    unittest.main(verbosity=2)
