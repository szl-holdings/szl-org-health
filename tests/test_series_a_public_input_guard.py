"""Private census inputs must not become public investor artifacts."""

from __future__ import annotations

import contextlib
import copy
import io
import tempfile
import unittest
from pathlib import Path

from build_series_a_diligence import main
from census.diligence import (
    DiligenceError,
    canonical_bytes,
    compile_diligence,
    require_public_projection_input,
    strict_load_json,
)
from tests.test_series_a_diligence import ROOT, SHA


class PublicInputGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.public_report = strict_load_json(ROOT / "static" / "data.json")
        cls.policy = strict_load_json(ROOT / "diligence" / "policy.json")

    def test_historical_public_projection_passes(self) -> None:
        self.assertIsNone(require_public_projection_input(self.public_report))

    def test_internal_and_spoofed_private_reports_fail_before_publication(self) -> None:
        canary = "internal-acquisition-target"

        def internal(report: dict) -> None:
            report["exposure"] = "internal"

        def extra_internal_field(report: dict) -> None:
            report["private_repository"] = canary

        def private_github(report: dict) -> None:
            repos = report["sources"]["github"]["data"]["repos"]
            repository = repos.pop(next(iter(repos)))
            repository["visibility"] = "private"
            repository["url"] = f"https://github.com/szl-holdings/{canary}"
            repos[canary] = repository

        def private_huggingface(report: dict) -> None:
            item = report["sources"]["huggingface"]["data"]["assets"]["models"][
                "items"
            ][0]
            item["id"] = f"SZLHOLDINGS/{canary}"
            item["private"] = True

        def complete_huggingface_claim(report: dict) -> None:
            report["sources"]["huggingface"]["data"]["authentication"][
                "organization_complete"
            ] = True

        for name, mutate in (
            ("internal exposure", internal),
            ("extra internal field", extra_internal_field),
            ("private GitHub visibility", private_github),
            ("private Hugging Face asset", private_huggingface),
            ("complete organization spoof", complete_huggingface_claim),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                report = copy.deepcopy(self.public_report)
                mutate(report)
                with self.assertRaisesRegex(
                    DiligenceError, "supplied census is not a closed public projection"
                ) as raised:
                    require_public_projection_input(report)
                self.assertNotIn(canary, str(raised.exception))

                root = Path(directory)
                input_path = root / "input.json"
                output_path = root / "packet.json"
                markdown_path = root / "packet.md"
                input_path.write_bytes(canonical_bytes(report) + b"\n")
                stdout, stderr = io.StringIO(), io.StringIO()
                with (
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    status = main(
                        [
                            "--input",
                            str(input_path),
                            "--source-revision",
                            SHA,
                            "--output",
                            str(output_path),
                            "--markdown",
                            str(markdown_path),
                        ]
                    )
                self.assertEqual(status, 2)
                self.assertFalse(output_path.exists())
                self.assertFalse(markdown_path.exists())
                self.assertNotIn(canary, stdout.getvalue() + stderr.getvalue())

    def test_direct_compiler_rejects_explicit_private_markers(self) -> None:
        for exposure in ("internal", "private", None):
            with self.subTest(exposure=exposure):
                report = copy.deepcopy(self.public_report)
                report["exposure"] = exposure
                with self.assertRaisesRegex(DiligenceError, "private census inventory"):
                    compile_diligence(
                        report,
                        compiler_source_revision=SHA,
                        policy=self.policy,
                        as_of="2026-08-01T18:00:00Z",
                    )

        report = copy.deepcopy(self.public_report)
        repository = next(iter(report["sources"]["github"]["data"]["repos"].values()))
        repository["visibility"] = "private"
        with self.assertRaisesRegex(DiligenceError, "private census inventory"):
            compile_diligence(
                report,
                compiler_source_revision=SHA,
                policy=self.policy,
                as_of="2026-08-01T18:00:00Z",
            )

    def test_malformed_input_diagnostics_never_echo_private_keys(self) -> None:
        canary = "internal-acquisition-target"
        payloads = (
            (b'{"internal-acquisition-target":1,"internal-acquisition-target":2}'),
            b'{"internal-acquisition-target":',
            b'{"internal-acquisition-target":{"api_key":"private-value"}}',
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "input.json"
            output_path = root / "packet.json"
            markdown_path = root / "packet.md"
            for payload in payloads:
                with self.subTest(payload=payload):
                    input_path.write_bytes(payload)
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with (
                        contextlib.redirect_stdout(stdout),
                        contextlib.redirect_stderr(stderr),
                    ):
                        status = main(
                            [
                                "--input",
                                str(input_path),
                                "--source-revision",
                                SHA,
                                "--output",
                                str(output_path),
                                "--markdown",
                                str(markdown_path),
                            ]
                        )
                    self.assertEqual(status, 2)
                    self.assertFalse(output_path.exists())
                    self.assertFalse(markdown_path.exists())
                    self.assertNotIn(canary, stdout.getvalue() + stderr.getvalue())
                    self.assertNotIn(
                        "private-value", stdout.getvalue() + stderr.getvalue()
                    )


if __name__ == "__main__":
    unittest.main()
