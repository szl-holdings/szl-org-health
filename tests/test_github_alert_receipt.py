# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import unittest
from unittest import mock

from census import github
from census.receipt import _github_alert_endpoint_projection
from census.report import project_public_report
from tests.test_receipt import bounded_snapshot, receipt_for


PATH = "/orgs/szl-holdings/code-scanning/alerts?state=open&per_page=100"
NEXT = '<https://api.github.com/orgs/szl-holdings/code-scanning/alerts?state=open&per_page=100&page=2>; rel="next"'
CANARY = "PRIVATE_ALERT_DETAILS_DO_NOT_PUBLISH"


class GitHubAlertReadEvidenceTests(unittest.TestCase):
    def observe_pages(self, responses):
        with mock.patch("census.common.request_json", side_effect=responses) as request:
            items, error = github._all_alerts(PATH, request_timeout=1, retries=0)
        return github._alert_endpoint_read_observation(items, error), request

    def test_empty_successful_collection_is_readable_and_complete(self):
        result, request = self.observe_pages([([], {}, None)])
        self.assertEqual(result, {
            "state": "READ_COMPLETE", "collection_complete": True,
            "http_failure_status": None, "reason": "NONE",
        })
        self.assertEqual(request.call_count, 1)

    def test_all_pages_are_consumed_without_projecting_details_or_counts(self):
        result, request = self.observe_pages([
            ([{"number": 31, "secret": CANARY}], {"link": NEXT}, None),
            ([], {}, None),
        ])
        self.assertEqual(request.call_count, 2)
        self.assertEqual(result["state"], "READ_COMPLETE")
        self.assertNotIn(CANARY, json.dumps(result))
        self.assertNotIn("count", result)
        self.assertNotIn("number", result)

    def test_later_page_http_failure_is_a_collection_failure(self):
        result, request = self.observe_pages([
            ([{"number": 31, "secret": CANARY}], {"link": NEXT}, None),
            (None, {}, "http403"),
        ])
        self.assertEqual(request.call_count, 2)
        self.assertEqual(result, {
            "state": "UNAVAILABLE", "collection_complete": False,
            "http_failure_status": 403, "reason": "HTTP_DENIED_OR_RESTRICTED",
        })
        self.assertNotIn(CANARY, json.dumps(result))

    def test_pagination_limit_remains_unknown(self):
        with mock.patch.object(github, "MAX_PAGES", 1):
            result, request = self.observe_pages([([], {"link": NEXT}, None)])
        self.assertEqual(request.call_count, 1)
        self.assertEqual(result["state"], "UNKNOWN")
        self.assertFalse(result["collection_complete"])
        self.assertEqual(result["reason"], "PAGINATION_INCOMPLETE")
        self.assertEqual(result["pagination_diagnostic"], "PAGE_CAP_EXCEEDED")

    def test_foreign_pagination_is_rejected_before_another_request(self):
        result, request = self.observe_pages([
            ([], {"link": NEXT.replace("api.github.com", "attacker.example")}, None),
        ])
        self.assertEqual(request.call_count, 1)
        self.assertEqual(result["reason"], "PAGINATION_INCOMPLETE")
        self.assertEqual(result["state"], "UNKNOWN")
        self.assertEqual(result["pagination_diagnostic"], "NEXT_ORIGIN_CHANGED")

    def test_changed_pagination_path_is_rejected_and_classified(self):
        changed = NEXT.replace("/code-scanning/alerts", "/secret-scanning/alerts")
        result, request = self.observe_pages([([], {"link": changed}, None)])
        self.assertEqual(request.call_count, 1)
        self.assertEqual(result["pagination_diagnostic"], "NEXT_PATH_CHANGED")
        self.assertFalse(result["collection_complete"])

    def test_pagination_cycle_is_unknown(self):
        repeated = '<https://api.github.com' + PATH + '>; rel="next"'
        result, request = self.observe_pages([([], {"link": repeated}, None)])
        self.assertEqual(request.call_count, 1)
        self.assertEqual(result["reason"], "PAGINATION_INCOMPLETE")
        self.assertEqual(result["pagination_diagnostic"], "CYCLE_DETECTED")

    def test_every_pagination_class_is_bounded_and_fail_closed(self):
        cases = {
            "pagination exceeded 20 pages": "PAGE_CAP_EXCEEDED",
            "pagination exceeded 10000 items": "ITEM_CAP_EXCEEDED",
            "pagination next origin changed": "NEXT_ORIGIN_CHANGED",
            "pagination next path changed": "NEXT_PATH_CHANGED",
            "pagination cycle detected": "CYCLE_DETECTED",
            "invalid pagination URL:" + CANARY: "INVALID_URL",
            "Link " + CANARY: "LINK_INVALID",
            "pagination " + CANARY: "OTHER",
        }
        for error, detail in cases.items():
            with self.subTest(detail=detail):
                observed = github._alert_endpoint_read_observation(None, error)
                projected = _github_alert_endpoint_projection({"code": observed})["code"]
                self.assertEqual(projected["pagination_diagnostic"], detail)
                self.assertEqual(projected["reason"], "PAGINATION_INCOMPLETE")
                self.assertEqual(projected["state"], "UNKNOWN")
                self.assertFalse(projected["collection_complete"])
                self.assertNotIn(CANARY, json.dumps(projected))

    def test_http_and_transport_reasons_are_bounded_and_redacted(self):
        expected = {
            "http401": ("UNAVAILABLE", 401, "HTTP_UNAUTHORIZED"),
            "http404": ("UNAVAILABLE", 404, "HTTP_NOT_FOUND_OR_HIDDEN"),
            "http429": ("UNKNOWN", 429, "HTTP_RATE_LIMITED"),
            "http503": ("UNKNOWN", 503, "HTTP_PROVIDER_ERROR"),
            "http422": ("UNKNOWN", 422, "HTTP_FAILURE"),
            "URLError:TimeoutError": ("UNKNOWN", None, "TRANSPORT_ERROR"),
            "invalid-json:" + CANARY: ("UNKNOWN", None, "INVALID_RESPONSE"),
            CANARY: ("UNKNOWN", None, "REQUEST_FAILED"),
            "http403 " + CANARY: ("UNKNOWN", None, "REQUEST_FAILED"),
        }
        for error, values in expected.items():
            with self.subTest(error=error):
                result = github._alert_endpoint_read_observation(None, error)
                self.assertEqual((result["state"], result["http_failure_status"], result["reason"]), values)
                self.assertFalse(result["collection_complete"])
                self.assertNotIn(CANARY, json.dumps(result))
                projected = _github_alert_endpoint_projection({"code": result})
                self.assertEqual(projected["code"], result)

    def test_missing_or_malformed_result_never_becomes_complete(self):
        for result in (None, {}, [None], "", True):
            with self.subTest(result=result):
                observation = github._alert_endpoint_read_observation(result, None)
                self.assertEqual(observation["state"], "UNKNOWN")
                self.assertEqual(observation["reason"], "INVALID_RESPONSE")

    def test_collector_attaches_existing_results_without_extra_alert_calls(self):
        calls = []

        def collect_alerts(path, **kwargs):
            calls.append(path)
            return (None, "http403") if "/secret-scanning/" in path else ([], None)

        with mock.patch.object(github, "discover_repositories", return_value=([], {"id": 273360816, "login": "szl-holdings"}, None)), \
             mock.patch.object(github, "_all_alerts", side_effect=collect_alerts), \
             mock.patch.object(github, "gh", return_value=({"total_count": 0}, None)):
            collected = github.collect_github(include_branch_protection=False)
        self.assertEqual(len(calls), 3)
        evidence = collected["alerts"]["endpoint_reads"]
        self.assertEqual(evidence["code"]["state"], "READ_COMPLETE")
        self.assertEqual(evidence["secret"]["state"], "UNAVAILABLE")
        self.assertEqual(evidence["dependabot"]["state"], "READ_COMPLETE")
        self.assertFalse(collected["alerts"]["complete"])
        self.assertIsNone(collected["alerts"]["secret_scanning_open"])


class GitHubAlertReceiptProjectionTests(unittest.TestCase):
    def test_old_snapshots_are_explicitly_not_observed(self):
        result = receipt_for(bounded_snapshot())
        observations = result["observations"]["github_alert_endpoints"]
        self.assertEqual(set(observations), {"code", "secret", "dependabot"})
        for value in observations.values():
            self.assertEqual(value, {
                "state": "UNKNOWN", "collection_complete": False,
                "http_failure_status": None, "reason": "NOT_OBSERVED",
            })

    def test_receipt_excludes_raw_errors_private_fields_counts_and_unknown_endpoints(self):
        snapshot = json.loads(bounded_snapshot())
        alerts = snapshot["sources"]["github"]["data"]["alerts"]
        valid = github._alert_endpoint_read_observation([], None)
        alerts["endpoint_reads"] = {
            "code": {**valid, "private_alerts": [CANARY], "count": 987654321},
            "secret": github._alert_endpoint_read_observation(None, "http403"),
            "dependabot": github._alert_endpoint_read_observation(None, "invalid-json:" + CANARY),
            CANARY: {"count": 987654321},
        }
        alerts["errors"] = {"secret": CANARY}
        receipt = receipt_for(json.dumps(snapshot).encode())
        projected = receipt["observations"]["github_alert_endpoints"]
        self.assertEqual(set(projected), {"code", "secret", "dependabot"})
        self.assertEqual(projected["code"], valid)
        self.assertNotIn(CANARY, json.dumps(receipt))
        self.assertNotIn("987654321", json.dumps(receipt))
        self.assertNotIn("endpoint_reads", json.dumps(project_public_report(snapshot)))

    def test_pagination_diagnostic_reaches_only_the_sanitized_receipt(self):
        snapshot = json.loads(bounded_snapshot())
        alerts = snapshot["sources"]["github"]["data"]["alerts"]
        alerts["endpoint_reads"] = {
            "code": github._alert_endpoint_read_observation(
                None, "pagination next path changed"
            ),
            "secret": github._alert_endpoint_read_observation([], None),
            "dependabot": github._alert_endpoint_read_observation([], None),
        }
        alerts["errors"] = {"code": "pagination next path changed"}
        alerts["complete"] = False
        receipt = receipt_for(json.dumps(snapshot).encode())
        self.assertEqual(receipt["status"], "FAIL_CLOSED")
        self.assertEqual(
            receipt["observations"]["github_alert_endpoints"]["code"],
            alerts["endpoint_reads"]["code"],
        )
        self.assertNotIn(
            "pagination_diagnostic", json.dumps(project_public_report(snapshot))
        )

    def test_incoherent_fields_fail_to_unknown_without_reflecting_input(self):
        valid = github._alert_endpoint_read_observation([], None)
        invalid = [
            {**valid, "collection_complete": 1},
            {**valid, "state": "UNAVAILABLE"},
            {**valid, "http_failure_status": 200},
            {**valid, "reason": CANARY},
            {**valid, "state": {CANARY: True}},
            {"state": "UNAVAILABLE", "collection_complete": False, "http_failure_status": 403, "reason": "HTTP_PROVIDER_ERROR"},
            {"state": "UNKNOWN", "collection_complete": False, "http_failure_status": True, "reason": "HTTP_FAILURE"},
            {"state": "UNKNOWN", "collection_complete": False, "http_failure_status": None, "reason": [CANARY]},
            {**valid, "pagination_diagnostic": "PAGE_CAP_EXCEEDED"},
            {**github._alert_endpoint_read_observation(None, "pagination cycle detected"),
             "pagination_diagnostic": CANARY},
        ]
        for value in invalid:
            with self.subTest(value=value):
                projected = _github_alert_endpoint_projection({"code": value})["code"]
                self.assertEqual(projected["state"], "UNKNOWN")
                self.assertFalse(projected["collection_complete"])
                self.assertEqual(projected["reason"], "INVALID_RESPONSE")
                self.assertNotIn(CANARY, json.dumps(projected))

    def test_reader_diagnostics_do_not_clear_hugging_face_authentication_failure(self):
        snapshot = json.loads(bounded_snapshot())
        snapshot["sources"]["github"]["data"]["alerts"]["endpoint_reads"] = {
            name: github._alert_endpoint_read_observation([], None)
            for name in ("code", "secret", "dependabot")
        }
        snapshot["sources"]["huggingface"]["data"]["authentication"]["credential_class"] = "LEGACY_WRITE"
        receipt = receipt_for(json.dumps(snapshot).encode())
        self.assertEqual(receipt["status"], "FAIL_CLOSED")
        self.assertEqual(receipt["observations"]["huggingface_authentication"]["credential_class"], "LEGACY_WRITE")
        self.assertTrue(any("fine-grained" in error for error in receipt["errors"]))


if __name__ == "__main__":
    unittest.main()
