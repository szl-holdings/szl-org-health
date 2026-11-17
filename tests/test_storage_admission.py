# SPDX-License-Identifier: Apache-2.0
"""Tests for local, read-only, fail-closed storage admission."""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "tools" / "szl_storage_admission.py"
SPEC = importlib.util.spec_from_file_location("testable_szl_storage_admission", FILE)
assert SPEC is not None and SPEC.loader is not None
g = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(g)
GIB = 1024 ** 3
UTC = dt.datetime(2026, 11, 17, 14, 40, 0, tzinfo=dt.timezone.utc)


def usage(total_gib: int, free_gib: int):
    return SimpleNamespace(
        total=total_gib * GIB,
        used=(total_gib - free_gib) * GIB,
        free=free_gib * GIB,
    )


def run_case(*, free=(60, 60), reserve="8", mode="admit", **kwargs):
    calls = []
    observations = iter(free)

    def disk_reader(path):
        calls.append(("read", path))
        return usage(1000, next(observations))

    def sleeper(seconds):
        calls.append(("sleep", seconds))

    result = g.observe(
        drive="C:\\", reserve_gib=reserve if mode == "admit" else None,
        mode=mode, sample_seconds=2,
        clock=lambda: UTC,
        disk_reader=disk_reader, sleeper=sleeper, **kwargs,
    )
    return result, calls


class SZLStorageAdmissionTests(unittest.TestCase):
    def test_admits_only_declaration_leaving_floor(self):
        result, calls = run_case(free=(62, 61), reserve="8")
        self.assertEqual(result["decision"], "ADMIT_PRECHECK_ONLY")
        self.assertEqual(result["capacity_state"], "CAPACITY_OK")
        self.assertEqual(result["observed_free_bytes"], [62 * GIB, 61 * GIB])
        self.assertEqual(result["min_post_budget_free_bytes"], 53 * GIB)
        self.assertEqual(calls, [
            ("read", "C:\\"), ("sleep", 2), ("read", "C:\\"),
        ])

    def test_holds_if_budget_would_breach_headroom(self):
        result, _ = run_case(free=(53, 52), reserve="8")
        self.assertEqual(result["decision"], "HOLD")
        self.assertEqual(result["reason"], "DECLARED_BUDGET_BREACHES_HEADROOM")
        self.assertEqual(result["min_post_budget_free_bytes"], 44 * GIB)
        self.assertFalse(result["future_capacity_guaranteed"])

    def test_observe_is_not_admission(self):
        result, _ = run_case(free=(65, 60), mode="observe")
        self.assertEqual(result["decision"], "NOT_REQUESTED")
        self.assertEqual(result["reason"], "READ_ONLY_OBSERVATION")
        self.assertEqual(result["declared_budget_bytes"], 0)

    def test_declares_no_leases_or_automatic_deletions(self):
        result, _ = run_case()
        self.assertFalse(result["automatic_deletion"])
        self.assertFalse(result["lease_or_reservation_established"])
        self.assertFalse(result["concurrent_writer_exclusion_established"])
        self.assertFalse(result["signature_verified"])
        self.assertFalse(result["remote_production_readiness_established"])

    def test_critical_free_disk_wins_over_budget(self):
        r, _ = run_case(free=(19, 19), reserve="1")
        self.assertEqual(r["capacity_state"], "CRITICAL")
        self.assertEqual(r["decision"], "HOLD")
        self.assertEqual(r["reason"], "CRITICAL_FREE_SPACE")

    def test_constrained_is_not_admitted_even_if_budget_is_small(self):
        r, _ = run_case(free=(49, 49), reserve="1")
        self.assertEqual(r["capacity_state"], "CONSTRAINED")
        self.assertEqual(r["reason"], "BELOW_REQUIRED_HEADROOM")

    def test_exact_floor_boundary_and_fractional_gib(self):
        r, _ = run_case(free=(51, 51), reserve="1")
        self.assertEqual(r["decision"], "ADMIT_PRECHECK_ONLY")
        self.assertEqual(g.gib_bytes("0.001", can_be_zero=False), 1073742)
        r, _ = run_case(free=(51, 51), reserve="1.001")
        self.assertEqual(r["decision"], "HOLD")

    def test_smaller_headroom_is_treated_conservatively(self):
        r, _ = run_case(free=(52, 60), reserve="2")
        self.assertEqual(r["min_free_bytes"], 52 * GIB)
        self.assertEqual(r["decision"], "ADMIT_PRECHECK_ONLY")
        self.assertEqual(r["observed_drop_bytes"], 0)

    def test_source_and_domain_separated_digest(self):
        r, _ = run_case()
        core = {k: v for k, v in r.items() if k != "sha256"}
        self.assertEqual(
            r["sha256"], hashlib.sha256(g.DOMAIN + g._canonical(core)).hexdigest(),
        )
        self.assertEqual(r["implementation_sha256"], hashlib.sha256(FILE.read_bytes()).hexdigest())
        self.assertEqual(r["schema"], "szl.local.capacity-admission/v1")
        self.assertEqual(r["timestamp_utc"], "2026-11-17T14:40:00+00:00")

    def test_one_sample_requires_explicit_zero_second_window(self):
        observed = []

        def reader(path):
            observed.append(path)
            return usage(1000, 55)

        r = g.observe(
            drive="D:\\", mode="admit", reserve_gib="5", sample_seconds=0,
            disk_reader=reader, sleeper=lambda _: self.fail("unexpected sleep"),
            clock=lambda: UTC,
        )
        self.assertEqual(r["observations"], 1)
        self.assertEqual(observed, ["D:\\"])
        self.assertEqual(r["decision"], "ADMIT_PRECHECK_ONLY")

    def test_refuse_unsafe_or_ambiguous_budgets(self):
        bad = ["", " ", "-1", "+1", "1e3", "NaN", "Inf", "0.0000",
               "1.0001", "01", "0001", "4,2", "4096.001", "9999",
               "1\x00", None, 2, True]
        for value in bad:
            with self.subTest(raw=value), self.assertRaises(g.AdmissionInputError):
                g.gib_bytes(value, can_be_zero=False)

    def test_reject_zero_budget_when_claiming_to_admit(self):
        with self.assertRaisesRegex(g.AdmissionInputError, "BUDGET_BOUND_INVALID"):
            g.observe(drive="C:\\", mode="admit", reserve_gib="0")

    def test_reject_unpriced_admission(self):
        with self.assertRaisesRegex(g.AdmissionInputError, "DECLARED_JOB_BUDGET_REQUIRED"):
            g.observe(drive="C:\\", mode="admit")

    def test_observation_rejects_budget(self):
        with self.assertRaisesRegex(g.AdmissionInputError, "OBSERVATION_MUST_NOT_DECLARE_JOB"):
            g.observe(drive="C:\\", mode="observe", reserve_gib="5")

    def test_reject_bad_thresholds(self):
        with self.assertRaisesRegex(g.AdmissionInputError, "FLOOR_MUST_EXCEED_CRITICAL"):
            g.observe(drive="C:\\", mode="observe", floor_gib="20", critical_gib="20")

    def test_reject_bad_sample_window_types_and_bounds(self):
        for value in (True, -1, 11, 2.5, None):
            with self.subTest(value=value), self.assertRaises(g.AdmissionInputError):
                g.observe(drive="C:\\", mode="observe", sample_seconds=value)

    def test_refuse_drive_or_mode_with_wrong_shape(self):
        for path in ("", " ", "C:\x00", False, None):
            with self.subTest(path=path), self.assertRaises(g.AdmissionInputError):
                g.observe(drive=path, mode="observe")
        for mode in ("run", "force", "cleanup", "", None):
            with self.subTest(mode=mode), self.assertRaises(g.AdmissionInputError):
                g.observe(drive="C:\\", mode=mode)

    def test_disk_observation_malformed_or_inconsistent_fails_closed(self):
        bad = [
            SimpleNamespace(total=100, used=50, free=49),
            SimpleNamespace(total=0, used=0, free=0),
            SimpleNamespace(total=100, used=True, free=99),
            SimpleNamespace(total=100, used=-1, free=101),
            object(),
        ]
        for data in bad:
            with self.subTest(data=data), self.assertRaises(g.AdmissionInputError):
                g.observe(
                    drive="C:\\", mode="admit", reserve_gib="1",
                    sample_seconds=0, disk_reader=lambda _: data,
                )

    def test_disk_io_unavailable_does_not_admit(self):
        def fail(_):
            raise FileNotFoundError("missing")

        with self.assertRaisesRegex(g.AdmissionInputError, "DISK_OBSERVATION_UNAVAILABLE"):
            g.observe(
                drive="X:\\", mode="admit", reserve_gib="1",
                disk_reader=fail, sample_seconds=0,
            )

    def test_disk_geometry_changed_does_not_admit(self):
        samples = iter([usage(100, 60), usage(200, 120)])
        with self.assertRaisesRegex(g.AdmissionInputError, "DISK_GEOMETRY_CHANGED"):
            g.observe(
                drive="C:\\", mode="admit", reserve_gib="2",
                disk_reader=lambda _: next(samples), sleeper=lambda _: None,
            )

    def test_utc_timestamp_required(self):
        with self.assertRaisesRegex(g.AdmissionInputError, "UTC_TIME_REQUIRED"):
            g.observe(
                drive="C:\\", mode="observe",
                disk_reader=lambda _: usage(100, 60), sleeper=lambda _: None,
                clock=lambda: dt.datetime(2026, 11, 17),
            )

    def test_cli_denies_without_declared_budget(self):
        p = subprocess.run(
            [sys.executable, "-I", str(FILE), "--mode", "admit",
             "--drive", "."],
            cwd=ROOT, capture_output=True, text=True, timeout=15, check=False,
        )
        self.assertEqual(p.returncode, 3, p.stderr)
        q = json.loads(p.stdout)
        self.assertEqual(q["decision"], "HOLD")
        self.assertEqual(q["reason"], "DECLARED_JOB_BUDGET_REQUIRED")

    def test_cli_sensor_unknown_holds(self):
        p = subprocess.run(
            [sys.executable, "-I", str(FILE), "--mode", "admit",
             "--reserve-gib", "1", "--drive", "/not/real/hopefully",
             "--sample-seconds", "0"],
            cwd=ROOT, capture_output=True, text=True, timeout=15, check=False,
        )
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertEqual(json.loads(p.stdout)["reason"], "DISK_OBSERVATION_UNAVAILABLE")

    def test_cli_live_observation_is_readonly(self):
        p = subprocess.run(
            [sys.executable, "-I", str(FILE), "--mode", "observe",
             "--drive", str(ROOT), "--sample-seconds", "0"],
            cwd=ROOT, capture_output=True, text=True, timeout=15, check=False,
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        q = json.loads(p.stdout)
        self.assertEqual(q["decision"], "NOT_REQUESTED")
        self.assertFalse(q["automatic_deletion"])
        self.assertGreater(q["total_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
