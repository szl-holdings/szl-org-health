import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

import app


class DnsTruthTests(unittest.TestCase):
    @patch("app.subprocess.run")
    def test_successful_empty_lookup_is_a_measured_negative(self, run):
        run.return_value = subprocess.CompletedProcess(
            args=["dig"], returncode=0, stdout="", stderr=""
        )
        self.assertEqual(app._dig_txt("example.test"), "")

    @patch("app.subprocess.run")
    def test_failed_lookup_is_unknown(self, run):
        run.return_value = subprocess.CompletedProcess(
            args=["dig"], returncode=9, stdout="", stderr="resolver failed"
        )
        self.assertIsNone(app._dig_txt("example.test"))

    @patch("app.subprocess.run", side_effect=FileNotFoundError("dig"))
    def test_missing_dig_is_unknown(self, _run):
        self.assertIsNone(app._dig_txt("example.test"))

    @patch("app._dig_txt", return_value=None)
    def test_collector_preserves_unknown_dns_state(self, _dig):
        result = app.collect_dns()
        for record in result.values():
            self.assertIsNone(record["spf"])
            self.assertIsNone(record["dmarc"])
            self.assertIsNone(record["dmarc_reject"])

    @patch("app._dig_txt")
    def test_collector_reports_only_measured_records(self, dig):
        dig.side_effect = lambda name: (
            '"v=DMARC1; p=reject"'
            if name.startswith("_dmarc.")
            else '"v=spf1 -all"'
        )
        result = app.collect_dns()
        for record in result.values():
            self.assertIs(record["spf"], True)
            self.assertIs(record["dmarc"], True)
            self.assertIs(record["dmarc_reject"], True)

    def test_frontend_renders_unknown_separately(self):
        html = Path("static/index.html").read_text(encoding="utf-8")
        self.assertIn("v.spf===null", html)
        self.assertIn("v.dmarc===null || v.dmarc_reject===null", html)
        self.assertIn("DMARC unknown", html)


if __name__ == "__main__":
    unittest.main()
