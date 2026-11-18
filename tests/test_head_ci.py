"""Source-head CI witness regression: historical != currently red; CI != release."""
from __future__ import annotations

import copy
import unittest
from unittest.mock import patch

from census import github, report
from census.head_ci import SCOPE, STATES, classify_head_push_runs

OLD = "a" * 40
HEAD = "b" * 40
NEW = "c" * 40


def run(identifier=1, *, sha=HEAD, workflow_id=50,
        conclusion="success", status="completed", branch="main",
        event="push", attempt=1):
    return {
        "id": identifier, "workflow_id": workflow_id,
        "name": f"workflow-{workflow_id}", "head_sha": sha,
        "head_branch": branch, "event": event,
        "run_attempt": attempt,
        "created_at": f"2026-11-17T22:{identifier % 60:02d}:00Z",
        "status": status, "conclusion": conclusion,
    }


def classify(rows, *, coverage="COMPLETE", head=HEAD, default="main"):
    return classify_head_push_runs(
        rows, default_head_sha=head, default_branch=default, coverage=coverage,
    )


class CurrentHeadTests(unittest.TestCase):
    def test_exact_head_two_green_workflows_are_only_observed_green(self):
        r = classify([run(1), run(2, workflow_id=52)])
        self.assertEqual(r["head_ci"], "OBSERVED_HEAD_GREEN")
        self.assertEqual(r["head_push_workflows_observed"], 2)
        self.assertEqual(r["head_failed_workflows"], 0)
        self.assertEqual(r["head_ci_scope"], SCOPE)
        self.assertNotIn("runtime_ready", r)
        self.assertNotIn("required_checks_passed", r)

    def test_old_failed_attempt_superseded_by_new_success_is_not_current_red(self):
        r = classify([run(1, sha=OLD, conclusion="failure"), run(2)])
        self.assertEqual(r["head_ci"], "OBSERVED_HEAD_GREEN")
        self.assertEqual(r["head_historical_failed_workflows"], 0)

    def test_latest_workflow_failed_on_old_sha_remains_historical(self):
        r = classify([run(1, sha=OLD, conclusion="failure")])
        self.assertEqual(r["head_ci"], "HISTORICAL_FAILURE_ONLY")
        self.assertEqual(r["head_historical_failed_workflows"], 1)
        self.assertEqual(r["head_failed_workflows"], 0)

    def test_current_head_red_precedes_other_green_and_history(self):
        r = classify([run(1, sha=OLD, conclusion="failure", workflow_id=5),
                      run(2, workflow_id=50, conclusion="failure"),
                      run(3, workflow_id=80)])
        self.assertEqual(r["head_ci"], "CURRENT_HEAD_RED")
        self.assertEqual(r["head_failed_workflows"], 1)
        self.assertEqual(r["head_historical_failed_workflows"], 1)

    def test_cancelled_skipped_neutral_stale_are_not_success(self):
        for conclusion in ("cancelled", "skipped", "neutral", "stale"):
            with self.subTest(conclusion=conclusion):
                r = classify([run(1, conclusion=conclusion)])
                self.assertEqual(r["head_ci"], "CURRENT_HEAD_INCOMPLETE")

    def test_pending_precedes_historical_red_but_not_current_head_red(self):
        rows = [run(1, sha=OLD, conclusion="failure", workflow_id=20),
                run(2, status="in_progress", conclusion=None, workflow_id=21)]
        self.assertEqual(classify(rows)["head_ci"], "CURRENT_HEAD_PENDING")
        rows.append(run(3, conclusion="failure", workflow_id=22))
        self.assertEqual(classify(rows)["head_ci"], "CURRENT_HEAD_RED")

    def test_no_current_head_run_and_empty_window_are_not_green(self):
        self.assertEqual(classify([])["head_ci"], "NO_CURRENT_HEAD_RUN")
        self.assertEqual(classify([run(1, sha=OLD)])["head_ci"], "NO_CURRENT_HEAD_RUN")

    def test_partial_coverage_never_green(self):
        for coverage in ("INCOMPLETE", "UNAVAILABLE", "private-sentinel"):
            with self.subTest(coverage=coverage):
                r = classify([run()], coverage=coverage)
                self.assertEqual(r["head_ci"], "CURRENT_HEAD_INCOMPLETE")
                self.assertNotIn("private-sentinel", str(r))

    def test_latest_other_sha_makes_partial_even_when_current_workflow_green(self):
        r = classify([run(1, sha=OLD, workflow_id=20), run(2, workflow_id=30)])
        self.assertEqual(r["head_ci"], "CURRENT_HEAD_INCOMPLETE")
        self.assertEqual(r["head_missing_workflows"], 1)

    def test_newer_attempt_on_same_workflow_uses_current_latest(self):
        rows = [run(1, sha=OLD, conclusion="failure"),
                run(2, sha=HEAD, conclusion="success")]
        self.assertEqual(classify(rows)["head_ci"], "OBSERVED_HEAD_GREEN")
        self.assertEqual(classify(list(reversed(rows)))["head_ci"],
                         "OBSERVED_HEAD_GREEN")

    def test_identical_creation_timestamps_choose_latest_id(self):
        rows = [run(2, sha=OLD, conclusion="failure"), run(1)]
        rows[0]["created_at"] = rows[1]["created_at"]
        self.assertEqual(classify(rows)["head_ci"], "HISTORICAL_FAILURE_ONLY")

    def test_inconsistent_status_or_conclusion_never_confident(self):
        for status, conclusion in (
            ("completed", None), ("in_progress", "failure"),
            ("mystery", "success"), ("completed", "unknown"),
        ):
            with self.subTest(status=status, conclusion=conclusion):
                self.assertEqual(classify([run(status=status, conclusion=conclusion)])["head_ci"],
                                 "UNAVAILABLE")

    def test_untrusted_row_and_identity_variants_fail_closed(self):
        mutations = [
            {"id": True}, {"id": 0}, {"workflow_id": 0},
            {"workflow_id": True}, {"head_sha": "wrong"},
            {"head_sha": "C" * 40}, {"event": "pull_request"},
            {"head_branch": "release"}, {"created_at": "not-time"},
            {"run_attempt": True}, {"run_attempt": -1},
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertEqual(classify([{**run(), **mutation}])["head_ci"],
                                 "UNAVAILABLE")
        self.assertEqual(classify([run(), run()])["head_ci"], "UNAVAILABLE")
        self.assertEqual(classify([None])["head_ci"], "UNAVAILABLE")
        self.assertEqual(classify([run()], head=None)["head_ci"], "UNAVAILABLE")
        self.assertEqual(classify([run()], head="X" * 40)["head_ci"], "UNAVAILABLE")
        self.assertEqual(classify([run()], default="")["head_ci"], "UNAVAILABLE")

    def test_public_projection_retains_only_validated_state_not_sha(self):
        source = {
            "visibility": "public", "private": False,
            "ci": "success", "ci_coverage": "COMPLETE",
            "ci_scope": "latest-per-workflow-within-recent-default-branch-push-window",
            "run_window_observed": 1, "default_branch_push_runs_total": 1,
            **classify([run()]),
            "secret": "should-not-leak",
            "head_sha": HEAD,
        }
        projected = report._public_github_repo("sample", source)
        self.assertEqual(projected["head_ci"], "OBSERVED_HEAD_GREEN")
        self.assertNotIn("head_sha", projected)
        self.assertNotIn("secret", projected)
        bad = copy.deepcopy(source)
        bad["head_ci_scope"] = "unauthorized"
        self.assertEqual(report._public_github_repo("sample", bad)["head_ci"],
                         "UNAVAILABLE")
        bad["head_ci_scope"] = SCOPE
        bad["head_ci"] = "EXECUTION_AUTHORIZED"
        self.assertEqual(report._public_github_repo("sample", bad)["head_ci"],
                         "UNAVAILABLE")
        self.assertIn("NOT_SAMPLED", STATES)
        self.assertIn("ARCHIVED", STATES)


class BracketedCollectorTests(unittest.TestCase):
    REPO = {"name": "a11oy", "default_branch": "main",
            "private": False, "visibility": "public"}

    def test_exact_head_bracket_required_and_bounded(self):
        with patch.object(github, "_read_default_head",
                          side_effect=[HEAD, HEAD]) as get_head, \
             patch.object(github, "request_json",
                          return_value=({"workflow_runs": [run()], "total_count": 1}, {}, None)):
            _, result = github._repo_census(
                self.REPO, request_timeout=1, retries=0,
                include_branch_protection=False,
            )
        self.assertEqual(get_head.call_count, 2)
        self.assertEqual(result["head_ci"], "OBSERVED_HEAD_GREEN")

    def test_head_drift_after_run_invalidates_even_green(self):
        with patch.object(github, "_read_default_head",
                          side_effect=[HEAD, NEW]) as get_head, \
             patch.object(github, "request_json",
                          return_value=({"workflow_runs": [run()], "total_count": 1}, {}, None)):
            _, result = github._repo_census(
                self.REPO, request_timeout=1, retries=0,
                include_branch_protection=False,
            )
        self.assertEqual(get_head.call_count, 2)
        self.assertEqual(result["head_ci"], "UNAVAILABLE")

    def test_missing_head_preserves_no_api_zero_claim(self):
        with patch.object(github, "_read_default_head",
                          return_value=None) as get_head, \
             patch.object(github, "request_json",
                          return_value=({"workflow_runs": [run()], "total_count": 1}, {}, None)):
            _, result = github._repo_census(
                self.REPO, request_timeout=1, retries=0,
                include_branch_protection=False,
            )
        self.assertEqual(get_head.call_count, 1)
        self.assertEqual(result["head_ci"], "UNAVAILABLE")

    def test_archived_repository_does_not_query_ci_or_show_permission_unavailable(self):
        with patch.object(github, "_read_default_head") as get_head, \
             patch.object(github, "request_json") as api:
            _, result = github._repo_census(
                {**self.REPO, "archived": True},
                request_timeout=1, retries=0,
                include_branch_protection=False,
            )
        get_head.assert_not_called()
        api.assert_not_called()
        self.assertEqual(result["head_ci"], "ARCHIVED")
        self.assertEqual(result["ci_coverage"], "NOT_APPLICABLE")

    def test_non_sampled_repo_never_consumes_extra_head_api(self):
        with patch.object(github, "_read_default_head") as get_head, \
             patch.object(github, "request_json",
                          return_value=({"workflow_runs": [run()], "total_count": 1}, {}, None)):
            _, result = github._repo_census(
                {**self.REPO, "name": "unlisted"}, request_timeout=1,
                retries=0, include_branch_protection=False,
            )
        get_head.assert_not_called()
        self.assertEqual(result["head_ci"], "NOT_SAMPLED")


class ObservationTransportContractTests(unittest.TestCase):
    def test_exact_default_head_api_read_is_bounded_and_rejects_403(self):
        with patch.object(github, "request_json",
                          return_value=({"sha": HEAD}, {}, None)) as api:
            self.assertEqual(github._read_default_head(
                "a11oy", "main", request_timeout=1, retries=0), HEAD)
        self.assertEqual(api.call_count, 1)
        self.assertTrue(api.call_args.args[0].endswith(
            "/repos/szl-holdings/a11oy/commits/main"))
        self.assertEqual(api.call_args.kwargs["redirect_origin"],
                         ("https", "api.github.com", 443))
        with patch.object(github, "request_json",
                          return_value=(None, {}, "http403")):
            self.assertIsNone(github._read_default_head(
                "a11oy", "main", request_timeout=1, retries=0))
        for invalid in ("../../secret", "main?token=x", "", "main\\evil"):
            self.assertIsNone(github._read_default_head(
                "a11oy", invalid, request_timeout=1, retries=0))
        self.assertLessEqual(len(github.HEAD_SAMPLE_REPOS), 10)

    def test_public_graph_displays_only_separate_observation_no_release_claim(self):
        from census.proof_graph import project_proof_graph
        from tests.test_portal_projection import fresh_public_report
        from datetime import datetime, timezone
        data = fresh_public_report(datetime.now(timezone.utc).replace(microsecond=0))
        data["sources"]["github"]["data"]["repos"]["sample"] = {
            "visibility": "public", "private": False,
            "archived": False, "fork": False,
            "url": "https://github.com/szl-holdings/sample",
            "ci": "success", "ci_coverage": "COMPLETE",
            "ci_scope": "latest-per-workflow-within-recent-default-branch-push-window",
            "run_window_observed": 1, "default_branch_push_runs_total": 1,
            **classify([run()]),
        }
        graph = project_proof_graph(data)
        node = next(n for n in graph["nodes"] if n["id"] == "repo:sample")
        self.assertEqual(node["head_ci"], "OBSERVED_HEAD_GREEN")
        self.assertIs(node["runtime_verified"], False)
        self.assertEqual(graph["runtime_readiness"], "UNKNOWN")
        self.assertEqual(graph["release_authority"], "UNKNOWN")
        self.assertNotIn(HEAD, str(graph))


    def test_error_bearing_github_source_cannot_project_head_green(self):
        from datetime import datetime, timezone
        from tests.test_portal_projection import fresh_public_report
        from census.proof_graph import project_proof_graph
        data = fresh_public_report(datetime.now(timezone.utc).replace(microsecond=0))
        repos = data["sources"]["github"]["data"]["repos"]
        name = next(iter(repos))
        repos[name]["head_ci"] = "OBSERVED_HEAD_GREEN"
        repos[name]["head_ci_scope"] = SCOPE
        data["sources"]["github"]["error"] = "PRIVATE_SENTINEL_HTTP403"
        projected = report.project_public_report(data)
        self.assertEqual(projected["sources"]["github"]["diagnostic_state"],
                         "SOURCE_UNAVAILABLE")
        self.assertEqual(projected["sources"]["github"]["data"]["repos"][name]["head_ci"],
                         "UNAVAILABLE")
        graph = project_proof_graph(data)
        node = next(n for n in graph["nodes"] if n["id"] == "repo:" + name)
        self.assertEqual(node["head_ci"], "UNAVAILABLE")
        self.assertNotIn("PRIVATE_SENTINEL_HTTP403", str(graph))


if __name__ == "__main__":
    unittest.main()
