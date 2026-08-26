from __future__ import annotations

import unittest
from unittest.mock import call, patch

import dns.resolver

from census import sites


class DnsDomainStateTests(unittest.TestCase):
    @patch("census.sites.dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN())
    def test_domain_probe_preserves_nxdomain(self, resolve):
        self.assertEqual(sites._resolve_domain_state("missing.test"), "NXDOMAIN")
        resolve.assert_called_once_with(
            "missing.test", "SOA", search=False, lifetime=8.0
        )

    @patch("census.sites.dns.resolver.resolve", side_effect=dns.resolver.NoAnswer())
    def test_domain_probe_preserves_noerror_nodata(self, _resolve):
        self.assertEqual(
            sites._resolve_domain_state("existing.test"), "NOERROR_NODATA"
        )

    @patch.object(sites, "DOMAINS", ["missing.test"])
    @patch("census.sites.resolve_txt")
    @patch("census.sites._resolve_domain_state", return_value="NXDOMAIN")
    def test_nxdomain_fails_closed_without_record_checks(self, _state, resolve_txt):
        entry = sites.collect_dns()["missing.test"]

        self.assertEqual(entry["domain_state"], "NXDOMAIN")
        self.assertEqual(
            entry["domain_availability"],
            "REGISTRATION_OR_DELEGATION_UNAVAILABLE",
        )
        self.assertEqual(entry["spf_status"], "NOT_EVALUABLE")
        self.assertEqual(entry["dmarc_status"], "NOT_EVALUABLE")
        self.assertEqual(entry["dmarc_reject_status"], "NOT_EVALUABLE")
        self.assertEqual(entry["overall_status"], "FAIL_CLOSED")
        self.assertIs(entry["spf"], False)
        self.assertIs(entry["dmarc"], False)
        self.assertIs(entry["dmarc_reject"], False)
        resolve_txt.assert_not_called()

    @patch.object(sites, "DOMAINS", ["existing.test"])
    @patch("census.sites.resolve_txt", side_effect=["", ""])
    @patch("census.sites._resolve_domain_state", return_value="NOERROR_NODATA")
    def test_noerror_nodata_remains_missing_record_evidence(
        self, _state, resolve_txt
    ):
        entry = sites.collect_dns()["existing.test"]

        self.assertEqual(entry["domain_state"], "NOERROR_NODATA")
        self.assertEqual(entry["domain_availability"], "DNS_NAME_OBSERVED")
        self.assertEqual(entry["spf_status"], "MISSING")
        self.assertEqual(entry["dmarc_status"], "MISSING")
        self.assertEqual(entry["dmarc_reject_status"], "MISSING")
        self.assertEqual(entry["overall_status"], "FAIL")
        self.assertIs(entry["spf"], False)
        self.assertIs(entry["dmarc"], False)
        self.assertIs(entry["dmarc_reject"], False)
        self.assertEqual(
            resolve_txt.call_args_list,
            [call("existing.test"), call("_dmarc.existing.test")],
        )

    @patch.object(sites, "DOMAINS", ["unknown.test"])
    @patch("census.sites.resolve_txt")
    @patch("census.sites._resolve_domain_state", return_value="UNKNOWN")
    def test_unknown_domain_state_does_not_fabricate_record_evidence(
        self, _state, resolve_txt
    ):
        entry = sites.collect_dns()["unknown.test"]

        self.assertEqual(entry["domain_availability"], "UNKNOWN")
        self.assertEqual(entry["spf_status"], "UNKNOWN")
        self.assertEqual(entry["dmarc_status"], "UNKNOWN")
        self.assertEqual(entry["overall_status"], "UNKNOWN")
        self.assertIsNone(entry["spf"])
        self.assertIsNone(entry["dmarc"])
        self.assertIsNone(entry["dmarc_reject"])
        resolve_txt.assert_not_called()


if __name__ == "__main__":
    unittest.main()
