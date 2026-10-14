# SPDX-License-Identifier: Apache-2.0
"""Code-alert pagination uses the organization identity already proved by discovery."""
from __future__ import annotations

import unittest
from unittest import mock

from census import github


IDENTITY = {"id": 273360816, "login": "szl-holdings"}
CANONICAL = "/organizations/273360816/code-scanning/alerts?state=open&per_page=100"
NAMED = "/orgs/szl-holdings/code-scanning/alerts?state=open&per_page=100"
NEXT = (
    "<https://api.github.com/organizations/273360816/code-scanning/alerts"
    '?state=open&per_page=100&after=opaque-test-cursor>; rel="next"'
)
ITEM = {"rule": {"security_severity_level": "high"}}


class GitHubCodeAlertPaginationTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(
            github, "github_headers", return_value={"Authorization": "Bearer test-only"}
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def observe_pages(self, path, responses):
        with mock.patch("census.common.request_json", side_effect=responses) as request:
            result = github._all_alerts(path, request_timeout=1, retries=0)
        return result, request

    def collect(self, identity, *, repositories=None, discovery_error=None):
        collected_paths = []

        def observe(path, **_kwargs):
            collected_paths.append(path)
            return ([ITEM] if "/code-scanning/" in path else []), None

        with (
            mock.patch.object(
                github, "discover_repositories",
                return_value=([] if repositories is None else repositories,
                              identity, discovery_error),
            ) as discover,
            mock.patch.object(github, "_all_alerts", side_effect=observe),
            mock.patch.object(github, "gh", return_value=({"total_count": 0}, None)),
        ):
            result = github.collect_github(request_timeout=1, retries=0)
        return result, collected_paths, discover

    def test_existing_named_path_reproduces_native_next_path_failure(self):
        (items, error), request = self.observe_pages(
            NAMED, [([ITEM], {"link": NEXT}, None)]
        )
        self.assertIsNone(items)
        self.assertEqual(error, "pagination next path changed")
        self.assertEqual(request.call_count, 1)

    def test_already_validated_identity_selects_exact_numeric_resource(self):
        self.assertEqual(github._code_alert_path(IDENTITY), CANONICAL)
        self.assertEqual(
            github._code_alert_path({"id": 321, "login": "SZL-HOLDINGS"}),
            "/organizations/321/code-scanning/alerts?state=open&per_page=100",
        )

    def test_missing_or_invalid_identity_is_not_converted_into_a_route(self):
        invalid = [
            None, [], {}, {"id": 273360816}, {"login": "szl-holdings"},
            {"id": True, "login": "szl-holdings"},
            {"id": False, "login": "szl-holdings"},
            {"id": 0, "login": "szl-holdings"},
            {"id": -1, "login": "szl-holdings"},
            {"id": 273360816.0, "login": "szl-holdings"},
            {"id": "273360816", "login": "szl-holdings"},
            {"id": 273360816, "login": None},
            {"id": 273360816, "login": "different-org"},
            {"id": 273360816, "login": "szl-holdings/other"},
        ]
        for value in invalid:
            with self.subTest(identity=value):
                self.assertIsNone(github._code_alert_path(value))

    def test_canonical_next_page_is_consumed_without_rewriting_cursor(self):
        (items, error), request = self.observe_pages(
            github._code_alert_path(IDENTITY),
            [([ITEM], {"link": NEXT}, None), ([], {}, None)],
        )
        self.assertEqual(items, [ITEM])
        self.assertIsNone(error)
        self.assertEqual(request.call_count, 2)
        self.assertEqual(request.call_args_list[0].args[0],
                         "https://api.github.com" + CANONICAL)
        self.assertEqual(
            request.call_args_list[1].args[0],
            "https://api.github.com/organizations/273360816/code-scanning/alerts"
            "?state=open&per_page=100&after=opaque-test-cursor",
        )
        self.assertTrue(all(
            call.kwargs["redirect_path"] == "/organizations/273360816/code-scanning/alerts"
            and call.kwargs["redirect_origin"] == ("https", "api.github.com", 443)
            for call in request.call_args_list
        ))

    def test_foreign_next_origin_remains_blocked_before_request(self):
        for replacement in ["attacker.example", "api.github.com.attacker.example"]:
            with self.subTest(host=replacement):
                (items, error), request = self.observe_pages(
                    CANONICAL,
                    [([ITEM], {"link": NEXT.replace("api.github.com", replacement)}, None)],
                )
                self.assertIsNone(items)
                self.assertEqual(error, "pagination next origin changed")
                self.assertEqual(request.call_count, 1)

    def test_other_organization_or_alert_endpoint_remains_blocked(self):
        links = [
            NEXT.replace("/273360816/", "/999/"),
            NEXT.replace("/code-scanning/alerts", "/secret-scanning/alerts"),
            NEXT.replace("/code-scanning/alerts", "/dependabot/alerts"),
            NEXT.replace("/organizations/273360816", "/orgs/szl-holdings"),
        ]
        for link in links:
            with self.subTest(link=link):
                (items, error), request = self.observe_pages(
                    CANONICAL, [([ITEM], {"link": link}, None)]
                )
                self.assertIsNone(items)
                self.assertEqual(error, "pagination next path changed")
                self.assertEqual(request.call_count, 1)

    def test_later_http_failure_never_returns_partial_alerts(self):
        (items, error), request = self.observe_pages(
            CANONICAL,
            [([ITEM], {"link": NEXT}, None), (None, {}, "http403")],
        )
        self.assertIsNone(items)
        self.assertEqual(error, "http403")
        self.assertEqual(request.call_count, 2)

    def test_page_cap_remains_fail_closed(self):
        with mock.patch.object(github, "MAX_ALERT_PAGES", 1):
            (items, error), request = self.observe_pages(
                CANONICAL, [([ITEM], {"link": NEXT}, None)]
            )
        self.assertIsNone(items)
        self.assertEqual(error, "pagination exceeded 1 pages")
        self.assertEqual(request.call_count, 1)

    def test_twenty_one_pages_complete_without_lifting_other_pagination_caps(self):
        responses = [
            (
                [ITEM] * 100,
                {"link": (
                    f'<https://api.github.com{CANONICAL}&page={page + 1}>; rel="next"'
                )},
                None,
            )
            for page in range(1, 21)
        ]
        responses.append(([ITEM] * 91, {}, None))
        (items, error), request = self.observe_pages(CANONICAL, responses)
        self.assertIsNone(error)
        self.assertEqual(len(items), 2091)
        self.assertEqual(request.call_count, 21)
        self.assertEqual(github.MAX_PAGES, 20)
        self.assertEqual(github.MAX_ALERT_PAGES, 100)

    def test_alert_page_cap_accepts_the_shared_ten_thousand_item_ceiling(self):
        responses = [
            (
                [ITEM] * 100,
                {"link": (
                    f'<https://api.github.com{CANONICAL}&page={page + 1}>; rel="next"'
                )},
                None,
            )
            for page in range(1, github.MAX_ALERT_PAGES)
        ]
        responses.append(([ITEM] * 100, {}, None))
        (items, error), request = self.observe_pages(CANONICAL, responses)
        self.assertIsNone(error)
        self.assertEqual(len(items), 10000)
        self.assertEqual(request.call_count, 100)

    def test_alert_specific_cap_rejects_page_101_without_a_partial_count(self):
        responses = [
            (
                [ITEM] * 100,
                {"link": (
                    f'<https://api.github.com{CANONICAL}&page={page + 1}>; rel="next"'
                )},
                None,
            )
            for page in range(1, github.MAX_ALERT_PAGES + 1)
        ]
        (items, error), request = self.observe_pages(CANONICAL, responses)
        self.assertIsNone(items)
        self.assertEqual(error, "pagination exceeded 100 pages")
        self.assertEqual(request.call_count, github.MAX_ALERT_PAGES)

    def test_pagination_cycle_remains_fail_closed(self):
        link = '<https://api.github.com' + CANONICAL + '>; rel="next"'
        (items, error), request = self.observe_pages(
            CANONICAL, [([ITEM], {"link": link}, None)]
        )
        self.assertIsNone(items)
        self.assertEqual(error, "pagination cycle detected")
        self.assertEqual(request.call_count, 1)

    def test_item_cap_remains_fail_closed(self):
        (items, error), request = self.observe_pages(
            CANONICAL, [([ITEM] * 10001, {}, None)]
        )
        self.assertIsNone(items)
        self.assertEqual(error, "pagination exceeded 10000 items")
        self.assertEqual(request.call_count, 1)

    def test_duplicate_next_link_remains_fail_closed(self):
        (items, error), request = self.observe_pages(
            CANONICAL, [([ITEM], {"link": NEXT + ", " + NEXT}, None)]
        )
        self.assertIsNone(items)
        self.assertIsNotNone(error)
        self.assertEqual(request.call_count, 1)

    def test_collector_reuses_discovery_identity_and_preserves_other_endpoints(self):
        result, paths, discover = self.collect(IDENTITY)
        self.assertEqual(discover.call_count, 1)
        self.assertEqual(set(paths), {
            CANONICAL,
            "/orgs/szl-holdings/secret-scanning/alerts?state=open&per_page=100",
            "/orgs/szl-holdings/dependabot/alerts?state=open&per_page=100",
        })
        self.assertEqual(result["alerts"]["code_scanning_open"], 1)
        self.assertEqual(result["alerts"]["code_scanning_high"], 1)
        self.assertTrue(result["alerts"]["complete"])
        self.assertTrue(result["alerts"]["endpoint_reads"]["code"]["collection_complete"])

    def test_collector_without_identity_skips_code_alert_request_and_stays_incomplete(self):
        for identity in [None, {}, {"id": True, "login": "szl-holdings"},
                         {"id": 273360816, "login": "other"}]:
            with self.subTest(identity=identity):
                result, paths, discover = self.collect(identity)
                self.assertEqual(discover.call_count, 1)
                self.assertEqual(len(paths), 2)
                self.assertFalse(any("/code-scanning/" in path for path in paths))
                self.assertIsNone(result["alerts"]["code_scanning_open"])
                self.assertIsNone(result["alerts"]["code_scanning_high"])
                self.assertFalse(result["alerts"]["complete"])
                self.assertFalse(
                    result["alerts"]["endpoint_reads"]["code"]["collection_complete"]
                )
                self.assertEqual(
                    result["alerts"]["errors"]["code"], "organization identity unavailable"
                )


if __name__ == "__main__":
    unittest.main()
