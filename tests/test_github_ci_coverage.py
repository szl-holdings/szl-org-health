from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from census import github, governance, report


def run(identifier, *, workflow=20, conclusion="success"):
    return {"id": identifier, "workflow_id": workflow,
            "name": "security" if workflow == 10 else "docs",
            "created_at": f"2026-10-29T12:{identifier % 60:02d}:00Z",
            "status": "completed", "conclusion": conclusion}


def page(rows, total):
    return {"workflow_runs": rows, "total_count": total}, {}, None


class WorkflowCoverageTests(unittest.TestCase):
    def census(self, responses):
        with patch.object(github, "request_json", side_effect=responses) as request:
            _, result = github._repo_census(
                {"name": "sample", "default_branch": "main", "private": False,
                 "visibility": "public"}, request_timeout=1, retries=0,
                include_branch_protection=False,
            )
        return result, request

    def control(self, row):
        return governance._github_ci({"sources": {"github": {
            "ok": True, "data": {"repos": {"sample": row}}
        }}}, {})["status"]

    def test_second_page_retains_security_failure_and_public_limit(self):
        result, request = self.census([
            page([run(i) for i in range(1, 101)], 101),
            page([run(101, workflow=10, conclusion="failure")], 101),
        ])
        self.assertEqual(request.call_count, 2)
        self.assertEqual(result["ci"], "failure")
        self.assertEqual(result["ci_coverage"], "COMPLETE")
        self.assertEqual(result["run_window_observed"], 101)
        self.assertEqual(self.control(result), "FAIL")
        public = report._public_github_repo("sample", result)
        self.assertEqual(public["ci"], "failure")
        self.assertEqual(public["run_window_observed"], 101)
        self.assertEqual(public["default_branch_push_runs_total"], 101)

    def test_complete_small_and_multiple_pages_can_pass(self):
        for responses, count in [([page([run(1)], 1)], 1), (
            [page([run(i) for i in range(1, 101)], 101), page([run(101)], 101)], 101
        )]:
            result, _ = self.census(responses)
            self.assertEqual(result["ci"], "success")
            self.assertEqual(result["ci_coverage"], "COMPLETE")
            self.assertEqual(result["run_window_observed"], count)
            self.assertEqual(self.control(result), "PASS")
            self.assertEqual(report._public_github_repo("sample", result)["ci"], "success")

    def test_skip_only_complete_window_fails_closed_through_public_projection(self):
        row, request = self.census([page([run(1, conclusion="skipped")], 1)])
        self.assertEqual(request.call_count, 1)
        self.assertEqual(row["ci_coverage"], "COMPLETE")
        self.assertEqual(row["ci"], "unknown")
        self.assertEqual(row["nonexecuted_workflows"], ["docs"])
        self.assertEqual(self.control(row), "UNKNOWN")
        public = report._public_github_repo("sample", row)
        self.assertEqual(public["ci"], "unknown")
        self.assertNotIn("nonexecuted_workflows", public)

    def test_optional_skip_with_executed_green_is_measured_but_not_release_admitted(self):
        rows = [run(1, workflow=10, conclusion="success"),
                run(2, workflow=20, conclusion="neutral")]
        row, _ = self.census([page(rows, 2)])
        self.assertEqual(row["ci_coverage"], "COMPLETE")
        self.assertEqual(row["ci"], "success")
        self.assertEqual(row["nonexecuted_workflows"], ["docs"])
        # This is a push-history status. Source SHA, required checks,
        # signatures and runtime admission are separately unverified here.
        self.assertNotIn("runtime_ready", row)

    def test_empty_complete_window_is_unknown_not_green(self):
        result, _ = self.census([page([], 0)])
        self.assertEqual(result["ci_coverage"], "COMPLETE")
        self.assertEqual(result["ci"], "unknown")
        self.assertEqual(self.control(result), "UNKNOWN")

    def test_page_cap_is_incomplete_and_preserves_observed_failure(self):
        for failure in (False, True):
            responses = [page([run(p * 100 + i) for i in range(1, 101)], 1001)
                         for p in range(10)]
            if failure:
                responses[0][0]["workflow_runs"][0] = run(1, workflow=10, conclusion="failure")
            result, request = self.census(responses)
            self.assertEqual(request.call_count, 1)
            self.assertEqual(result["ci_coverage"], "INCOMPLETE")
            self.assertEqual(result["run_window_observed"], 100)
            self.assertEqual(result["default_branch_push_runs_total"], 1001)
            self.assertEqual(result["ci"], "failure" if failure else "unknown")
            self.assertEqual(self.control(result), "FAIL" if failure else "UNKNOWN")
            self.assertEqual(report._public_github_repo("sample", result)["ci"], result["ci"])

    def test_exact_ten_page_limit_can_close(self):
        result, request = self.census([
            page([run(p * 100 + i) for i in range(1, 101)], 1000) for p in range(10)
        ])
        self.assertEqual(request.call_count, 10)
        self.assertEqual(result["ci_coverage"], "COMPLETE")
        self.assertEqual(result["run_window_observed"], 1000)
        self.assertEqual(result["ci"], "success")

    def test_error_or_count_drift_after_page_one_preserves_failure(self):
        first = [run(i) for i in range(1, 101)]
        first[0] = run(1, workflow=10, conclusion="failure")
        for second in [(None, {}, "http403"), page([run(101)], 102)]:
            result, _ = self.census([page(first, 101), second])
            self.assertEqual(result["ci_coverage"], "UNAVAILABLE")
            self.assertEqual(result["ci"], "failure")
            self.assertEqual(self.control(result), "FAIL")

    def test_malformed_or_partial_window_cannot_be_green(self):
        responses = [page([run(1)], total) for total in (None, True, -1, "1", 0, 2)]
        responses += [(None, {}, "http500"), ({"workflow_runs": None, "total_count": 1}, {}, None),
                      page([run(1), None], 2), page([run(1), run(1)], 2),
                      page([run(i) for i in range(1, 102)], 101)]
        for response in responses:
            with self.subTest(response=response):
                result, request = self.census([response])
                self.assertEqual(request.call_count, 1)
                self.assertEqual(result["ci_coverage"], "UNAVAILABLE")
                self.assertEqual(result["ci"], "unknown")
                self.assertEqual(self.control(result), "UNKNOWN")

    def test_duplicate_run_across_pages_refuses_coverage(self):
        result, _ = self.census([page([run(i) for i in range(1, 101)], 101), page([run(1)], 101)])
        self.assertEqual(result["ci_coverage"], "UNAVAILABLE")
        self.assertEqual(result["ci"], "unknown")

    def test_pagination_preserves_filters_and_locks_redirect_destination(self):
        result, request = self.census([page([run(i) for i in range(1, 101)], 101), page([run(101)], 101)])
        for index, call in enumerate(request.call_args_list, 1):
            self.assertIn("branch=main", call.args[0])
            self.assertIn("event=push", call.args[0])
            self.assertIn(f"page={index}", call.args[0])
            self.assertEqual(call.kwargs["redirect_origin"], ("https", "api.github.com", 443))
            self.assertEqual(call.kwargs["redirect_path"], "/repos/szl-holdings/sample/actions/runs")

    def test_public_complete_claim_requires_coherent_counts_and_scope(self):
        row, _ = self.census([page([run(1)], 1)])
        mutations = [{"run_window_observed": True}, {"default_branch_push_runs_total": 2},
                     {"ci_scope": "private-path-sentinel"}, {"run_window_observed": None},
                     {"ci_coverage": "UNAVAILABLE"}, {"error": "private-error-sentinel"},
                     {"run_window_observed": 0, "default_branch_push_runs_total": 0}]
        for mutation in mutations:
            altered = {**row, **mutation}
            public = report._public_github_repo("sample", altered)
            self.assertEqual(public["ci"], "unknown")
            self.assertEqual(self.control(altered), "UNKNOWN")
            self.assertNotIn("private-path-sentinel", json.dumps(public))
            self.assertEqual(report._public_github_repo("sample", public), public)

    def test_historical_green_without_coverage_is_unknown(self):
        row = {"visibility": "public", "archived": False, "ci": "success"}
        self.assertEqual(report._public_github_repo("sample", row)["ci"], "unknown")
        self.assertEqual(self.control(row), "UNKNOWN")

    def test_complete_pending_remains_pending_and_never_passes(self):
        pending = {**run(1), "status": "in_progress", "conclusion": None}
        row, _ = self.census([page([pending], 1)])
        self.assertEqual(row["ci"], "pending")
        self.assertEqual(row["ci_coverage"], "COMPLETE")
        self.assertEqual(report._public_github_repo("sample", row)["ci"], "pending")
        self.assertEqual(self.control(row), "UNKNOWN")

    def test_archived_history_is_not_measured_zero(self):
        with patch.object(github, "request_json") as request:
            _, row = github._repo_census({"name": "old", "archived": True},
                request_timeout=1, retries=0, include_branch_protection=False)
        request.assert_not_called()
        self.assertEqual(row["ci_coverage"], "NOT_APPLICABLE")
        self.assertIsNone(row["run_window_observed"])
        self.assertIsNone(row["default_branch_push_runs_total"])


class SourceErrorAdmissionTests(unittest.TestCase):
    def test_error_bearing_wrappers_retain_rows_without_restoring_availability(self):
        sentinel = "private-error-url-sentinel"
        for name, projector, data in [
            ("github", report._public_github_data, {"repos": {"sample": {
                "visibility": "public", "ci": "failure", "archived": False}}}),
            ("sites", report._public_sites_data, {"a-11-oy.com": {"http": 200}}),
            ("huggingface", report._public_hf_data, {"assets": {}}),
        ]:
            raw = {"ok": True, "error": sentinel, "data": data}
            public = report._public_source(name, raw, projector)
            self.assertFalse(public["ok"])
            self.assertEqual(public["diagnostic_state"], "SOURCE_UNAVAILABLE")
            self.assertNotIn(sentinel, json.dumps(public))
            self.assertTrue(public["data"])
            self.assertEqual(report._public_source(name, public, projector), public)
        legitimate = {"ok": False, "diagnostic_state": "PUBLIC_SUBSET", "error": None,
                      "data": {"repos": {}}}
        self.assertEqual(report._public_source("github", legitimate, report._public_github_data)["diagnostic_state"], "PUBLIC_SUBSET")

    def test_governance_does_not_trust_error_bearing_green_wrapper(self):
        row = {"archived": False, "ci": "success", "ci_coverage": "COMPLETE",
               "ci_scope": "latest-per-workflow-within-recent-default-branch-push-window",
               "run_window_observed": 1, "default_branch_push_runs_total": 1}
        source = {"ok": True, "error": "SOURCE_UNAVAILABLE", "data": {"repos": {"sample": row}}}
        self.assertEqual(governance._github_ci({"sources": {"github": source}}, {})["status"], "UNKNOWN")
        row["ci"] = "failure"
        self.assertEqual(governance._github_ci({"sources": {"github": source}}, {})["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
