import hashlib
import json
import unittest
import urllib.parse
from unittest import mock

from census.common import next_link
from census.github import aggregate_workflow_runs, classify_repo
from census.huggingface import (
    _full_bucket,
    _full_kernel,
    _paths,
    _payload_file_path,
    classify_model_contract,
    collect_huggingface,
    normalize_hf_repo,
    normalize_space,
    space_runtime_url,
    verify_operational_payload,
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
    def test_collections_page_respects_live_api_limit(self):
        query = urllib.parse.urlparse(_paths()["collections"])
        params = urllib.parse.parse_qs(query.query)
        self.assertEqual(params["owner"], ["SZLHOLDINGS"])
        self.assertEqual(params["sort"], ["lastModified"])
        self.assertEqual(params["limit"], ["100"])

    def test_kernel_inventory_uses_first_class_hub_endpoint(self):
        query = urllib.parse.urlparse(_paths()["kernels"])
        params = urllib.parse.parse_qs(query.query)
        self.assertEqual(query.path, "/api/kernels")
        self.assertEqual(params["author"], ["SZLHOLDINGS"])
        self.assertEqual(params["limit"], ["500"])

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

    @mock.patch("census.huggingface.request_json")
    @mock.patch("census.huggingface.http_probe")
    def test_space_is_operational_only_with_health_and_source_binding(
        self, probe, request_json
    ):
        probe.side_effect = [
            {"http": 200, "headers": {}},
            {"http": 200, "headers": {}},
        ]
        request_json.return_value = (
            {"build": {"revision": "a" * 40}},
            {},
            None,
        )
        result = normalize_space(
            {
                "id": "SZLHOLDINGS/example",
                "sdk": "docker",
                "subdomain": "szlholdings-example",
                "runtime": {"stage": "RUNNING"},
                "siblings": [{"rfilename": "README.md"}],
                "cardData": {"license": "apache-2.0"},
            }
        )
        self.assertEqual(result["healthz"], 200)
        self.assertEqual(result["source_revision"], "a" * 40)
        self.assertEqual(result["source_binding_state"], "OBSERVED")
        self.assertEqual(result["operational_state"], "OPERATIONAL_SOURCE_BOUND")

    @mock.patch("census.huggingface.request_json")
    @mock.patch("census.huggingface.http_probe")
    def test_reachable_space_without_contract_stays_unverified(
        self, probe, request_json
    ):
        probe.side_effect = [
            {"http": 200, "headers": {}},
            {"http": 404, "headers": {}},
        ]
        request_json.return_value = (None, {}, "http404")
        result = normalize_space(
            {
                "id": "SZLHOLDINGS/example",
                "sdk": "docker",
                "subdomain": "szlholdings-example",
                "runtime": {"stage": "RUNNING"},
            }
        )
        self.assertEqual(result["operational_state"], "REACHABLE_UNVERIFIED")
        self.assertEqual(result["source_binding_state"], "UNAVAILABLE")

    @mock.patch("census.huggingface.request_json")
    def test_first_class_kernel_contract_requires_card_contract_and_build(self, request_json):
        request_json.side_effect = [
            (
                {
                    "id": "SZLHOLDINGS/example",
                    "sha": "b" * 40,
                    "lastModified": "2026-08-01T00:00:00Z",
                },
                {},
                None,
            ),
            (
                [
                    {"type": "file", "path": "README.md"},
                    {"type": "file", "path": "contract.json"},
                    {"type": "file", "path": "build/torch-cpu/module.py"},
                ],
                {},
                None,
            ),
        ]
        result = _full_kernel({"id": "SZLHOLDINGS/example"})
        self.assertEqual(result["metadata_state"], "OBSERVED")
        self.assertEqual(result["tree_state"], "OBSERVED")
        self.assertEqual(result["contract_state"], "COMPLETE")
        self.assertEqual(result["selfcheck_state"], "NOT_EXECUTED_BY_CENSUS")

    @mock.patch("census.huggingface.request_json")
    def test_bucket_documentation_is_observed_from_live_tree(self, request_json):
        request_json.return_value = (
            [{"type": "file", "path": "README.md"}],
            {},
            None,
        )
        result = _full_bucket(
            {
                "id": "SZLHOLDINGS/example",
                "private": True,
                "totalFiles": 1,
            }
        )
        self.assertEqual(result["tree_state"], "OBSERVED")
        self.assertTrue(result["readme_present"])
        self.assertEqual(result["documentation_state"], "COMPLETE")

    def test_model_artifact_and_weight_states_are_distinct(self):
        item = {
            "id": "SZLHOLDINGS/example",
            "siblings": [
                {"rfilename": "README.md"},
                {"rfilename": "model.safetensors"},
            ],
        }
        result = normalize_hf_repo(item, "model")
        self.assertEqual(result["artifact_state"], "artifact-present")
        self.assertEqual(result["weight_state"], "weights-present")
        self.assertEqual(result["weight_files_observed"], ["model.safetensors"])
        self.assertEqual(result["contract"], "model-artifact")

    def test_serialized_estimator_is_counted_as_model_artifact(self):
        result = normalize_hf_repo(
            {
                "id": "SZLHOLDINGS/example",
                "siblings": [
                    {"rfilename": "build.toml"},
                    {"rfilename": "build/torch-universal/example/__init__.py"},
                    {"rfilename": "model.joblib"},
                ],
            },
            "model",
        )
        self.assertEqual(result["contract"], "kernel-with-estimator")
        self.assertEqual(result["artifact_state"], "artifact-present")
        self.assertEqual(result["weight_state"], "no-weight-file-observed")
        self.assertEqual(result["estimator_files_observed"], ["model.joblib"])

    def test_kernel_without_weights_satisfies_declared_contract(self):
        result = normalize_hf_repo(
            {
                "id": "SZLHOLDINGS/example",
                "siblings": [
                    {"rfilename": "build.toml"},
                    {"rfilename": "build/torch-universal/example/__init__.py"},
                ],
            },
            "model",
        )
        self.assertEqual(result["contract"], "huggingface-kernel")
        self.assertEqual(result["artifact_state"], "not-required-by-contract")

    def test_model_contract_precedence(self):
        cases = {
            "operational-payload": [
                "a11oy-metadata.json",
                "payloads/deploy/MANIFEST.json",
            ],
            "gguf": ["model-q4_k_m.gguf"],
            "recipe-with-estimator": ["BASE_MODEL_MANIFEST.json", "model.joblib"],
            "kernel-with-torch-surrogate": [
                "build.toml",
                "build/torch-universal/example/__init__.py",
                "model.safetensors",
            ],
            "kernel-with-embedding-index": [
                "build.toml",
                "build/torch-universal/example/__init__.py",
                "vectors.npz",
            ],
            "transformers-checkpoint": ["config.json", "model.safetensors"],
            "peft-adapter": ["adapter_config.json", "adapter_model.safetensors"],
        }
        for expected, paths in cases.items():
            with self.subTest(expected=expected):
                self.assertEqual(classify_model_contract(paths), expected)

    def test_transformers_contract_recognizes_shards_and_legacy_weights(self):
        cases = [
            [
                "config.json",
                "model.safetensors.index.json",
                "model-00001-of-00002.safetensors",
            ],
            ["config.json", "pytorch_model.bin"],
            [
                "config.json",
                "pytorch_model.bin.index.json",
                "pytorch_model-00001-of-00002.bin",
            ],
        ]
        for paths in cases:
            with self.subTest(paths=paths):
                self.assertEqual(
                    classify_model_contract(paths),
                    "transformers-checkpoint",
                )

    def test_payload_paths_are_confined_to_deploy_root(self):
        self.assertEqual(
            _payload_file_path("manifests/service.yaml"),
            "payloads/deploy/manifests/service.yaml",
        )
        self.assertEqual(
            _payload_file_path("payloads/deploy/zarf.yaml"),
            "payloads/deploy/zarf.yaml",
        )
        self.assertIsNone(_payload_file_path("../secret"))

    @mock.patch("census.huggingface.request_bytes")
    def test_operational_payload_fails_closed_on_missing_file(self, request_bytes):
        present = b"present payload\n"
        manifest = {
            "manifestVersion": 1,
            "fileCount": 2,
            "files": [
                {
                    "path": "present.yaml",
                    "size": len(present),
                    "sha256": hashlib.sha256(present).hexdigest(),
                },
                {
                    "path": "missing.yaml",
                    "size": 3,
                    "sha256": hashlib.sha256(b"no\n").hexdigest(),
                },
            ],
        }
        aggregate_input = "\n".join(
            f"{entry['path']}\0{entry['size']}\0{entry['sha256']}"
            for entry in manifest["files"]
        ).encode()
        manifest["aggregateSha256"] = hashlib.sha256(aggregate_input).hexdigest()
        request_bytes.side_effect = [
            (json.dumps(manifest).encode(), {}, None),
            (present, {}, None),
        ]
        result = verify_operational_payload(
            "SZLHOLDINGS/example",
            "a" * 40,
            ["payloads/deploy/MANIFEST.json", "payloads/deploy/present.yaml"],
        )
        self.assertEqual(result["payload_manifest_state"], "incomplete")
        self.assertEqual(result["payload_manifest_declared_files"], 2)
        self.assertEqual(result["payload_manifest_verified_files"], 1)
        self.assertTrue(result["payload_manifest_aggregate_verified"])
        self.assertEqual(
            result["payload_manifest_missing_files"],
            ["payloads/deploy/missing.yaml"],
        )

    @mock.patch("census.huggingface.request_bytes")
    def test_operational_payload_verifies_bytes_and_aggregate(self, request_bytes):
        payload = b"apiVersion: v1\n"
        entry = {
            "path": "manifest.yaml",
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        aggregate_input = (
            f"{entry['path']}\0{entry['size']}\0{entry['sha256']}".encode()
        )
        manifest = {
            "manifestVersion": 1,
            "fileCount": 1,
            "aggregateSha256": hashlib.sha256(aggregate_input).hexdigest(),
            "files": [entry],
        }
        request_bytes.side_effect = [
            (json.dumps(manifest).encode(), {}, None),
            (payload, {}, None),
        ]
        result = verify_operational_payload(
            "SZLHOLDINGS/example",
            "b" * 40,
            ["payloads/deploy/MANIFEST.json", "payloads/deploy/manifest.yaml"],
        )
        self.assertEqual(result["payload_manifest_state"], "verified")
        self.assertEqual(result["payload_manifest_verified_files"], 1)
        self.assertTrue(result["payload_manifest_aggregate_verified"])

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
            if path.startswith("/api/kernels"):
                return None, "http502"
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
        self.assertFalse(census["assets"]["kernels"]["ok"])
        self.assertIsNone(census["assets"]["kernels"]["count"])


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
