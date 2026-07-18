import unittest
from pathlib import Path
from unittest.mock import patch

import dns.exception
import dns.resolver

import app


class TxtRecord:
    def __init__(self, *chunks: bytes):
        self.strings = chunks


class DnsTruthTests(unittest.TestCase):
    @patch("app.dns.resolver.resolve", side_effect=dns.resolver.NoAnswer())
    def test_nodata_is_a_measured_negative(self, _resolve):
        self.assertEqual(app._resolve_txt("example.test"), "")

    @patch("app.dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN())
    def test_nxdomain_is_a_measured_negative(self, _resolve):
        self.assertEqual(app._resolve_txt("example.test"), "")

    @patch("app.dns.resolver.resolve", side_effect=dns.resolver.NoNameservers())
    def test_servfail_or_refused_is_unknown(self, _resolve):
        self.assertIsNone(app._resolve_txt("example.test"))

    @patch("app.dns.resolver.resolve", side_effect=dns.exception.Timeout())
    def test_timeout_is_unknown(self, _resolve):
        self.assertIsNone(app._resolve_txt("example.test"))

    @patch("app.dns.resolver.resolve")
    def test_txt_chunks_and_records_are_decoded(self, resolve):
        resolve.return_value = [
            TxtRecord(b"v=spf1 ", b"include:example.test"),
            TxtRecord(b"second-record"),
        ]
        self.assertEqual(
            app._resolve_txt("example.test"),
            "v=spf1 include:example.test\nsecond-record",
        )
        resolve.assert_called_once_with(
            "example.test", "TXT", search=False, lifetime=8.0
        )

    @patch("app._resolve_txt", return_value=None)
    def test_collector_preserves_unknown_dns_state(self, _dig):
        result = app.collect_dns()
        for record in result.values():
            self.assertIsNone(record["spf"])
            self.assertIsNone(record["dmarc"])
            self.assertIsNone(record["dmarc_reject"])

    @patch("app._resolve_txt")
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
