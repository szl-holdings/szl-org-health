"""Deterministic sampler tests; injected clocks and receipts are not live proof."""

from __future__ import annotations

import copy
import datetime as dt
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from autonomic.slo_controller import canonical_json, observation_digest, sha256_hex
from autonomic.slo_sampling import (
    CYCLE_TIMEOUT_SECONDS, SAMPLING_BUDGET_SECONDS, observe, run_controller, verify,
)
from tests.test_slo_workflow_evidence import receipt_fixture


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "autonomic/slo_policy.json"


class Clock:
    def __init__(self, *, oversleep=0):
        self.now = 100.0
        self.oversleep = oversleep
        self.waits = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.waits.append(seconds)
        self.now += seconds + self.oversleep


class SamplingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.healthy = receipt_fixture()
        cls.incident = receipt_fixture(historical_failure=True)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name) / "samples"
        self.clock = Clock()
        self.calls = []
        self.timeouts = []

    def controller(self, codes=(0, 0, 0), durations=(2, 2, 2)):
        def run(argv, *, timeout):
            number = len(self.calls)
            self.calls.append(self.clock.now)
            self.timeouts.append(timeout)
            path = Path(argv[argv.index("--output") + 1])
            code = codes[number]
            self.assertEqual(Path(argv[argv.index("--policy") + 1]), POLICY)
            report = copy.deepcopy(self.incident if code == 2 else self.healthy)
            report["cycle_id"] = f"slo_fixture_{number}"
            report["generated_at"] = (
                dt.datetime(2026, 9, 26, tzinfo=dt.timezone.utc)
                + dt.timedelta(seconds=self.clock.now)
            ).isoformat().replace("+00:00", "Z")
            self.write_receipt(path, report)
            self.clock.now += durations[number]
            return code
        return run

    def write_receipt(self, path, report):
        report.pop("receipt_sha256", None)
        report["observation_sha256"] = observation_digest(report)
        report["receipt_sha256"] = sha256_hex(canonical_json(report))
        path.write_text(json.dumps(report), encoding="utf-8")
        path.with_suffix(".json.sha256").write_text(report["receipt_sha256"] + "\n", encoding="ascii")

    def collect(self, codes=(0, 0, 0), durations=(2, 2, 2)):
        return observe(self.directory, POLICY, controller=self.controller(codes, durations),
                       monotonic=self.clock.monotonic, sleep=self.clock.sleep)

    def test_three_real_calls_wait_full_cadence_and_keep_all_evidence(self):
        self.assertEqual(self.collect(), 0)
        self.assertEqual(self.calls, [100, 402, 704])
        self.assertEqual(self.clock.waits, [300, 300])
        self.assertEqual(self.timeouts, [60, 60, 60])
        self.assertEqual(len(list(self.directory.iterdir())), 10)
        self.assertEqual(verify(self.directory, POLICY, exit_code="0")[0], 0)

    def test_slow_cycle_and_oversleep_never_trigger_catch_up(self):
        self.clock.oversleep = 20
        self.assertEqual(self.collect(durations=(40, 2, 2)), 0)
        self.assertEqual(self.calls, [100, 460, 782])
        self.assertEqual(self.clock.waits, [300, 300])

    def test_incident_in_any_cycle_survives_later_healthy_results(self):
        for codes in ((2, 0, 0), (0, 2, 0), (0, 0, 2)):
            with self.subTest(codes=codes):
                self.directory = self.directory.parent / ("batch-" + "".join(map(str, codes)))
                self.calls = []
                self.assertEqual(self.collect(codes), 2)
                result, summary = verify(self.directory, POLICY, exit_code="2")
                self.assertEqual(result, 2)
                self.assertEqual(summary.count("## Observation "), 3)

    def test_failed_controller_outranks_incident_and_does_not_skip_later_calls(self):
        self.assertEqual(self.collect((2, 1, 0)), 1)
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(verify(self.directory, POLICY, exit_code="1")[0], 1)

    def test_exception_is_retained_as_failure_and_later_samples_still_run(self):
        underlying = self.controller()
        def run(argv, *, timeout):
            if not self.calls:
                self.calls.append(self.clock.now)
                raise RuntimeError("fixture failure")
            return underlying(argv, timeout=timeout)
        self.assertEqual(observe(self.directory, POLICY, controller=run,
                                 monotonic=self.clock.monotonic, sleep=self.clock.sleep), 1)
        self.assertEqual(len(self.calls), 3)
        self.assertEqual((self.directory / "sample-1.exit-code").read_text(), "1\n")

    def test_production_runner_uses_subprocess_with_timeout(self):
        with mock.patch("autonomic.slo_sampling.subprocess.run") as run:
            run.return_value.returncode = 2
            self.assertEqual(run_controller(["--output", "receipt.json"], timeout=60), 2)
        run.assert_called_once_with([
            sys.executable, "-B", "-m", "autonomic.slo_controller",
            "--output", "receipt.json",
        ], timeout=60, check=False)

    def test_timeout_retains_partial_artifact_and_measures_later_samples(self):
        underlying = self.controller()
        partial = b'{"partial": true}'
        def run(argv, *, timeout):
            if not self.calls:
                self.calls.append(self.clock.now)
                self.timeouts.append(timeout)
                Path(argv[argv.index("--output") + 1]).write_bytes(partial)
                self.clock.now += timeout
                raise subprocess.TimeoutExpired(argv, timeout)
            return underlying(argv, timeout=timeout)
        self.assertEqual(observe(self.directory, POLICY, controller=run,
                                 monotonic=self.clock.monotonic, sleep=self.clock.sleep), 1)
        self.assertEqual(len(self.calls), 3)
        self.assertEqual((self.directory / "sample-1.json").read_bytes(), partial)
        self.assertFalse((self.directory / "sample-1.json.sha256").exists())
        manifest = json.loads((self.directory / "sampling.json").read_text())
        self.assertEqual(manifest["cycles"][0]["status"], "timed_out")
        self.assertEqual((self.directory / "sample-1.exit-code").read_text(), "1\n")

    def test_overrun_cannot_pass_even_when_runner_returns_healthy_receipt(self):
        self.assertEqual(self.collect(durations=(61, 2, 2)), 1)
        manifest = json.loads((self.directory / "sampling.json").read_text())
        self.assertEqual(manifest["cycles"][0]["status"], "timed_out")
        self.assertEqual(len(self.calls), 3)

    def test_exhausted_budget_stops_without_a_synthetic_receipt(self):
        self.clock.oversleep = 200
        self.assertEqual(self.collect(), 1)
        self.assertEqual(len(self.calls), 2)
        self.assertFalse((self.directory / "sample-3.json").exists())
        self.assertEqual((self.directory / "sample-3.exit-code").read_text(), "1\n")
        manifest = json.loads((self.directory / "sampling.json").read_text())
        self.assertEqual(manifest["cycles"][2]["status"], "deadline_exceeded")
        self.assertEqual(manifest["budget_seconds"], SAMPLING_BUDGET_SECONDS)
        self.assertEqual(verify(self.directory, POLICY, exit_code="1")[0], 1)

    def test_last_cycle_receives_only_remaining_budget(self):
        self.clock.oversleep = 70
        self.assertEqual(self.collect(durations=(2, 2, 50)), 1)
        self.assertEqual(self.timeouts, [60, 60, 36])
        self.assertEqual(len(self.calls), 3)
        manifest = json.loads((self.directory / "sampling.json").read_text())
        self.assertEqual(manifest["cycles"][2]["status"], "deadline_exceeded")

    def test_three_maximum_cycles_fit_the_collection_budget(self):
        self.assertEqual(self.collect(durations=(60, 60, 60)), 0)
        self.assertEqual(self.clock.now - 100, SAMPLING_BUDGET_SECONDS)
        self.assertEqual(self.timeouts, [CYCLE_TIMEOUT_SECONDS] * 3)

    def test_existing_output_cannot_be_overwritten(self):
        self.collect()
        before = {p.name: p.read_bytes() for p in self.directory.iterdir()}
        with self.assertRaises(FileExistsError):
            self.collect()
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.directory.iterdir()})

    def test_missing_middle_sidecar_fails_independent_verification(self):
        self.collect()
        (self.directory / "sample-2.json.sha256").unlink()
        self.assertEqual(verify(self.directory, POLICY, exit_code="0")[0], 1)

    def test_missing_middle_exit_code_fails_independent_verification(self):
        self.collect()
        (self.directory / "sample-2.exit-code").unlink()
        self.assertEqual(verify(self.directory, POLICY, exit_code="0")[0], 1)

    def test_incomplete_or_compressed_cadence_manifest_fails(self):
        self.collect()
        path = self.directory / "sampling.json"
        original = json.loads(path.read_text())
        for mutation in ("missing", "short", "nan", "compressed", "unbounded", "overrun", "failed"):
            with self.subTest(mutation=mutation):
                manifest = copy.deepcopy(original)
                if mutation == "missing":
                    path.unlink()
                else:
                    if mutation == "short":
                        manifest["cycles"].pop()
                    elif mutation == "nan":
                        manifest["cycles"][1]["started_seconds"] = float("nan")
                    elif mutation == "unbounded":
                        manifest["cycles"][1]["timeout_seconds"] = 61
                    elif mutation == "overrun":
                        manifest["cycles"][2]["finished_seconds"] = 781
                    elif mutation == "failed":
                        manifest["cycles"][1]["status"] = "timed_out"
                    else:
                        manifest["cycles"][1]["started_seconds"] = 1
                    path.write_text(json.dumps(manifest))
                self.assertEqual(verify(self.directory, POLICY)[0], 1)
                path.write_text(json.dumps(original))

    def test_receipt_replay_or_policy_mismatch_cannot_pass(self):
        self.collect()
        first = self.directory / "sample-1.json"
        second = self.directory / "sample-2.json"
        report = json.loads(first.read_text())
        self.write_receipt(second, report)
        self.assertEqual(verify(self.directory, POLICY)[0], 1)
        report["cycle_id"] = "slo_new_id"
        report["generated_at"] = "2026-09-26T00:10:00Z"
        report["policy_sha256"] = "0" * 64
        self.write_receipt(second, report)
        self.assertEqual(verify(self.directory, POLICY)[0], 1)

    def test_unchanged_manifest_bytes_allow_distinct_valid_manifest_revisions(self):
        self.assertEqual(self.collect((2, 2, 2)), 2)
        third = self.directory / "sample-3.json"
        report = json.loads(third.read_text())
        report["manifest_revision"] = "d" * 40
        self.write_receipt(third, report)
        before = {path.name: path.read_bytes() for path in self.directory.iterdir()}

        result, summary = verify(self.directory, POLICY, exit_code="2")

        self.assertEqual(result, 2)
        self.assertEqual(summary.count("## Observation "), 3)
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.directory.iterdir()})
        self.assertEqual(json.loads(third.read_text())["manifest_revision"], "d" * 40)

    def test_controller_or_manifest_bytes_cannot_change_between_observations(self):
        self.collect()
        second = self.directory / "sample-2.json"
        original = json.loads(second.read_text())
        for field, value in (
            ("controller_revision", "b" * 40), ("controller_revision", None),
            ("manifest_revision", None), ("manifest_revision", "d" * 39),
            ("manifest_revision", "D" * 40), ("manifest_revision", "g" * 40),
            ("manifest_sha256", "e" * 64), ("policy_sha256", "f" * 64),
            ("controller_repository", "szl-holdings/other"),
            ("manifest_repository", "szl-holdings/other"),
        ):
            with self.subTest(field=field, value=value):
                report = copy.deepcopy(original)
                report[field] = value
                self.write_receipt(second, report)
                self.assertEqual(verify(self.directory, POLICY)[0], 1)
        self.write_receipt(second, original)

    def test_live_batch_requires_observation_digest(self):
        self.collect()
        path = self.directory / "sample-2.json"
        report = json.loads(path.read_text())
        report.pop("observation_sha256")
        report.pop("receipt_sha256")
        report["receipt_sha256"] = sha256_hex(canonical_json(report))
        path.write_text(json.dumps(report))
        path.with_suffix(".json.sha256").write_text(report["receipt_sha256"] + "\n")
        self.assertEqual(verify(self.directory, POLICY)[0], 1)

    def test_invalid_policy_or_missing_directory_fails_without_crashing(self):
        self.assertEqual(verify(self.directory, POLICY)[0], 1)
        policy = self.directory.parent / "invalid-policy.json"
        policy.write_text("{}")
        self.assertEqual(verify(self.directory, policy)[0], 1)

    def test_cli_gate_rejects_false_success_and_writes_summary(self):
        self.collect((2, 0, 0))
        summary = self.directory.parent / "summary.md"
        result = subprocess.run([
            sys.executable, "-B", "-m", "autonomic.slo_sampling", "--verify-only",
            "--policy", str(POLICY), "--output-dir", str(self.directory),
            "--exit-code", "0", "--summary", str(summary),
        ], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("exit code disagrees", summary.read_text())
        self.assertIn("SLO sampling failed closed", result.stdout)

    def test_cli_gate_preserves_incident_without_failed_evidence_label(self):
        self.collect((2, 0, 0))
        summary = self.directory.parent / "incident-summary.md"
        result = subprocess.run([
            sys.executable, "-B", "-m", "autonomic.slo_sampling", "--verify-only",
            "--policy", str(POLICY), "--output-dir", str(self.directory),
            "--exit-code", "2", "--summary", str(summary),
        ], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("SLO reliability incident", result.stdout)
        self.assertNotIn("SLO sampling failed closed", result.stdout)
        self.assertIn("Batch result: `INCIDENT`", summary.read_text())

    def test_receipt_timestamps_must_independently_support_cadence(self):
        self.collect()
        second = self.directory / "sample-2.json"
        report = json.loads(second.read_text())
        report["generated_at"] = "2026-09-26T00:01:41Z"
        self.write_receipt(second, report)
        self.assertEqual(verify(self.directory, POLICY)[0], 1)

    def test_cli_gate_requires_sampler_exit_code(self):
        self.collect()
        result = subprocess.run([
            sys.executable, "-B", "-m", "autonomic.slo_sampling", "--verify-only",
            "--policy", str(POLICY), "--output-dir", str(self.directory),
        ], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("exit code disagrees", result.stdout)


if __name__ == "__main__":
    unittest.main()
