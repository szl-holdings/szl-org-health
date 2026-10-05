# SPDX-License-Identifier: Apache-2.0
"""Internal search totals require complete, coherent provider responses."""
from __future__ import annotations

import copy
import unittest
from unittest import mock

from census import github, report


def search_response(count: int) -> dict:
    return {
        "total_count": count,
        "incomplete_results": False,
        "items": [] if count == 0 else [{"id": 1}],
    }


class GitHubSearchCountTests(unittest.TestCase):
    def collect(self, prs, issues, *, pr_error=None, issue_error=None):
        def search(path, *_args, **_kwargs):
            if "is:pr+is:open&per_page=1" in path:
                return prs, pr_error
            if "is:issue+is:open&per_page=1" in path:
                return issues, issue_error
            self.fail(f"Unexpected request: {path}")

        with (
            mock.patch.object(github, "github_headers", return_value={}),
            mock.patch.object(
                github, "discover_repositories",
                return_value=([], {"id": 273360816, "login": "szl-holdings"}, None),
            ),
            mock.patch.object(github, "_all_alerts", return_value=([], None)),
            mock.patch.object(github, "gh", side_effect=search) as requests,
        ):
            result = github.collect_github(request_timeout=1, retries=0)
        self.assertEqual(requests.call_count, 2)
        self.assertTrue(result["discovery"]["complete"])
        self.assertTrue(result["alerts"]["complete"])
        self.assertEqual(result["alerts"]["code_scanning_open"], 0)
        return result

    def test_complete_zero_and_positive_counts_remain_independent(self):
        result = self.collect(search_response(0), search_response(17))
        self.assertEqual(result["open_prs"], 0)
        self.assertEqual(result["open_issues"], 17)
        result = self.collect(search_response(23), search_response(0))
        self.assertEqual(result["open_prs"], 23)
        self.assertEqual(result["open_issues"], 0)

    def test_incomplete_search_never_becomes_an_observed_total(self):
        partial = {**search_response(41), "incomplete_results": True}
        result = self.collect(partial, search_response(17))
        self.assertIsNone(result["open_prs"])
        self.assertEqual(result["open_issues"], 17)
        result = self.collect(search_response(23), partial)
        self.assertEqual(result["open_prs"], 23)
        self.assertIsNone(result["open_issues"])

    def test_missing_or_malformed_completeness_is_unknown(self):
        for flag in (None, 0, 1, "false", [], {}):
            with self.subTest(flag=flag):
                result = self.collect(
                    {**search_response(41), "incomplete_results": flag},
                    search_response(17),
                )
                self.assertIsNone(result["open_prs"])
                self.assertEqual(result["open_issues"], 17)
        missing = search_response(41)
        del missing["incomplete_results"]
        self.assertIsNone(self.collect(missing, search_response(17))["open_prs"])

    def test_malformed_count_is_unknown(self):
        for count in (True, False, -1, "41", 41.5, None):
            with self.subTest(count=count):
                result = self.collect(
                    {**search_response(41), "total_count": count}, search_response(17)
                )
                self.assertIsNone(result["open_prs"])
                self.assertEqual(result["open_issues"], 17)
        missing = search_response(41)
        del missing["total_count"]
        self.assertIsNone(self.collect(missing, search_response(17))["open_prs"])

    def test_malformed_response_and_items_are_unknown(self):
        malformed = [None, [], "unavailable", {},
                     {"total_count": 41, "incomplete_results": False}]
        malformed.extend(
            {**search_response(41), "items": items}
            for items in (None, {}, "items", [None], [1], [[], {}])
        )
        for response in malformed:
            with self.subTest(response=response):
                result = self.collect(response, search_response(17))
                self.assertIsNone(result["open_prs"])
                self.assertEqual(result["open_issues"], 17)

    def test_first_page_must_agree_with_the_total_and_one_item_request(self):
        for response in (
            {**search_response(41), "items": []},
            {**search_response(0), "items": [{"id": 1}]},
            {**search_response(41), "items": [{"id": 1}, {"id": 2}]},
        ):
            with self.subTest(response=response):
                self.assertIsNone(self.collect(response, search_response(17))["open_prs"])

    def test_request_error_does_not_admit_a_coexisting_payload(self):
        for error in ("http403", "TimeoutError", ""):
            with self.subTest(error=error):
                result = self.collect(
                    search_response(41), search_response(17), pr_error=error
                )
                self.assertIsNone(result["open_prs"])
                self.assertEqual(result["open_issues"], 17)
                result = self.collect(
                    search_response(23), search_response(41), issue_error=error
                )
                self.assertEqual(result["open_prs"], 23)
                self.assertIsNone(result["open_issues"])

    def test_public_projection_still_strips_internal_organization_totals(self):
        internal_data = self.collect(search_response(23), search_response(17))
        original = copy.deepcopy(internal_data)
        public = report.project_public_report({
            "schema_version": 2,
            "exposure": "internal",
            "generated_at": "2026-10-05T12:00:00Z",
            "sources": {"github": {"ok": True, "data": internal_data}},
        })
        public_data = public["sources"]["github"]["data"]
        self.assertIsNone(public_data["open_prs"])
        self.assertIsNone(public_data["open_issues"])
        self.assertEqual(internal_data, original)


if __name__ == "__main__":
    unittest.main()
