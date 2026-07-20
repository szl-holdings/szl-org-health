import unittest
from unittest import mock

from census.common import next_link
from census.github import aggregate_workflow_runs, classify_repo
from census.huggingface import (
    collect_huggingface,
    normalize_hf_repo,
    space_runtime_url,
)


class WorkflowAggregationTests(unittest.TestCase):
    def test_latest_per_workflow_preserves_red_signal(self):
        runs = [
            {
                "workflow_id": 10,
                "name": "security",
                "created_at": "2026-07-20T10:00:00Z",
                "status": "completed",
                "conclusion": "failure",
            },
            {
                "workflow_id": 20,
                "name": "docs",
                "created_at": "2026-07-20T11:00:00Z",
                "status": "completed",
                "conclusion": "success",
            },
        ]
        result = aggregate_workflow_runs(runs)
        self.assertEqual(result["ci"], "failure")
        self.assertEqual(result["failing_workflows"], ["security"])

    def test_newer_run_supersedes_older_failure_for_same_workflow(self):
        runs = [
            {
                "workflow_id": 10,
                "name": "security",
                "created_at": "2026-07-20T10:00:00Z",
                "status": "completed",
                "conclusion": "failure",
            },
            {
                "workflow_id": 10,
                "name": "security",
                "created_at": "2026-07-20T12:00:00Z",
                "status": "completed",
                "conclusion": "success",
            },
        ]
        result = aggregate_workflow_runs(runs)
        self.assertEqual(result["ci"], "success")
        self.assertEqual(result["failing_workflows"], [])


class ClassificationTests(unittest.TestCase):
    def test_archive_wins_over_name_rules(self):
        self.assertEqual(classify_repo({"name": "platform", "archived": True}), "archive")

    def test_unknown_role_is_not_guessed(self):
        self.assertEqual(classify_repo({"name": "new-unknown-repo"}), "unclassified")


class HuggingFaceNormalizationTests(unittest.TestCase):
    def test_static_space_uses_static_runtime_domain(self):
        item = {
            "id": "SZLHOLDINGS/anatomy",
            "sdk": "static",
            "subdomain": "szlholdings-anatomy",
        }
        self.assertEqual(
            space_runtime_url(item),
            "https://szlholdings-anatomy.static.hf.space/",
        )

    def test_model_weight_state_requires_observed_weight_file(self):
        item = {
            "id": "SZLHOLDINGS/example",
            "siblings": [
                {"rfilename": "README.md"},
                {"rfilename": "model.safetensors"},
            ],
        }
        result = normalize_hf_repo(item, "model")
        self.assertEqual(result["artifact_state"], "weights-present")
        self.assertEqual(result["weight_files_observed"], ["model.safetensors"])

    @mock.patch("census.huggingface.http_probe", return_value={"http": 200, "headers": {}})
    @mock.patch("census.huggingface.request_json")
    @mock.patch("census.huggingface.hf_paginate")
    def test_asset_failure_stays_unknown_not_zero(self, paginate, request_json, _probe):
        def result(path, *args, **kwargs):
            if path.startswith("/api/models"):
                return None, "http503"
            if path.startswith("/api/datasets"):
                return [], None
            if path.startswith("/api/spaces"):
                return [], None
            if path.startswith("/api/collections"):
                return [], None
            if path.startswith("/api/buckets"):
                return None, "http401"
            raise AssertionError(path)

        paginate.side_effect = result
        request_json.return_value = ({}, {}, None)
        census = collect_huggingface()
        self.assertFalse(census["assets"]["models"]["ok"])
        self.assertIsNone(census["assets"]["models"]["count"])
        self.assertEqual(census["assets"]["models"]["error"], "http503")
        self.assertFalse(census["assets"]["buckets"]["ok"])
        self.assertIsNone(census["assets"]["buckets"]["count"])
        self.assertEqual(census["assets"]["datasets"]["count"], 0)


class PaginationTests(unittest.TestCase):
    def test_next_link_parser(self):
        value = (
            '<https://example.test?page=2>; rel="next", '
            '<https://example.test?page=4>; rel="last"'
        )
        self.assertEqual(next_link(value), "https://example.test?page=2")
        self.assertIsNone(next_link(None))


if __name__ == "__main__":
    unittest.main()
