#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline contract: bounded stdin and a source-only PowerShell sensor.

No Windows host, model, credentials, or protected files are accessed.
"""
from __future__ import annotations

from contextlib import redirect_stdout
from io import BytesIO, StringIO
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import disk_agent_hygiene_gate as gate


class TransportTests(unittest.TestCase):
    def payload(self):
        return {
            "schema": gate.SCHEMA,
            "device": "BETTERWITHAGE",
            "observations": [
                {"utc": "2026-11-20T07:03:17Z", "drive": "C:",
                 "total_bytes": 1021821579264, "free_bytes": 648120979456},
                {"utc": "2026-11-20T07:03:23Z", "drive": "C:",
                 "total_bytes": 1021821579264, "free_bytes": 648121073664},
            ],
            "historical": {"state": "UNAVAILABLE"},
            "processes": [{"name": "llama-server", "pid": 18228,
                           "working_set_bytes": 1939 * 1024 ** 2}],
            "scratch": [{"id": "gh_scan_err", "exists": True,
                         "size_bytes": 5306, "owner_state": "UNVERIFIED"}],
            "cache_growth": {"state": "UNOBSERVED"},
        }

    def invoke(self, raw: bytes):
        output = StringIO()
        with patch.object(gate.sys, "stdin", SimpleNamespace(buffer=BytesIO(raw))):
            with redirect_stdout(output):
                status = gate.main(["--stdin"])
        return status, json.loads(output.getvalue())

    def test_valid_stdin_reports_unverified_scratch_without_cleanup_authority(self):
        status, result = self.invoke(json.dumps(self.payload()).encode("utf8"))
        self.assertEqual(status, 2)
        self.assertEqual(result["status"], "ALERT")
        self.assertIn("SCRATCH_OWNER_UNVERIFIED", result["reasons"])
        self.assertEqual(result["baseline_state"], "UNAVAILABLE")
        self.assertIsNone(result["historical_drop_bytes"])
        self.assertFalse(result["cleanup_authorized"])

    def test_bad_command_line_field_refused_without_echo(self):
        payload = self.payload()
        payload["processes"][0]["command_line"] = "SECRET_AND_TOKEN"
        status, result = self.invoke(json.dumps(payload).encode("utf8"))
        self.assertEqual(status, 3)
        self.assertEqual(result["status"], "HOLD_INVALID_OR_UNAVAILABLE")
        self.assertNotIn("SECRET_AND_TOKEN", json.dumps(result))

    def test_oversized_and_empty_stdin_hold(self):
        for raw in (b"", b"x" * (gate.MAX_INPUT_BYTES + 1)):
            status, result = self.invoke(raw)
            self.assertEqual(status, 3)
            self.assertFalse(result["cleanup_authorized"])

    def test_no_scratch_does_not_claim_verified_historical_health(self):
        payload = self.payload()
        payload["scratch"] = []
        status, result = self.invoke(json.dumps(payload).encode("utf8"))
        self.assertEqual(status, 0)
        self.assertEqual(result["status"], "NO_THRESHOLD_CONFIRMED")
        self.assertFalse(result["baseline_signature_independently_verified"])
        self.assertFalse(result["training_or_release_authorized"])

    def test_powershell_collector_is_bounded_and_non_destructive(self):
        source = (Path(__file__).resolve().parents[1] / "tools" /
                  "windows_disk_agent_hygiene_observer.ps1").read_text()
        for expected in ("Get-CimInstance Win32_LogicalDisk", "Get-Process",
                         "Write-Output $json", "'UNAVAILABLE'", "'UNVERIFIED'",
                         "PROCESS_SENSOR_BUDGET_EXCEEDED"):
            self.assertIn(expected, source)
        for forbidden in ("Remove-Item", "Stop-Process", "Clear-RecycleBin",
                          "Set-Content", "Out-File", "Unregister-ScheduledTask",
                          "Win32_Process", "CommandLine", "Get-Process -IncludeUserName",
                          "Start-Process", "Get-ChildItem -Recurse"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
