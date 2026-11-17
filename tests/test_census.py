import hashlib
import json
import unittest
import urllib.parse
import urllib.error
import urllib.request
from unittest import mock

from census.common import (
    _CredentialSafeRedirectHandler,
    _response_header_map,
    next_link,
    paginate_json,
    request_bytes,
    request_json,
)
from census.github import (
    _repository_visibility,
    aggregate_workflow_runs,
    classify_repo,
)
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

    def test_only_coherent_terminal_green_conclusions_are_success(self):
        incoherent = [
            ("completed", None),
            ("completed", "future_conclusion"),
            ("queued", "success"),
            (None, "success"),
        ]
        for status, conclusion in incoherent:
            with self.subTest(status=status, conclusion=conclusion):
                result = aggregate_workflow_runs(
                    [
                        {
                            "workflow_id": 1,
                            "name": "ambiguous",
                            "created_at": "2026-08-31T00:00:00Z",
                            "status": status,
                            "conclusion": conclusion,
                        }
                    ]
                )
                self.assertEqual(result["ci"], "unknown")
                self.assertEqual(result["unknown_workflows"], ["ambiguous"])

    def test_stale_is_failure_and_failure_dominates_unknown_and_pending(self):
        runs = [
            {
                "workflow_id": 1,
                "name": "stale-run",
                "status": "completed",
                "conclusion": "stale",
            },
            {
                "workflow_id": 2,
                "name": "mystery",
                "status": "completed",
                "conclusion": None,
            },
            {
                "workflow_id": 3,
                "name": "waiting",
                "status": "queued",
                "conclusion": None,
            },
        ]
        result = aggregate_workflow_runs(runs)
        self.assertEqual(result["ci"], "failure")
        self.assertEqual(result["failing_workflows"], ["stale-run"])
        self.assertEqual(result["unknown_workflows"], ["mystery"])
        self.assertEqual(result["pending_workflows"], ["waiting"])

    def test_unknown_dominates_pending_without_failure(self):
        result = aggregate_workflow_runs(
            [
                {
                    "workflow_id": 1,
                    "name": "unknown",
                    "status": "completed",
                    "conclusion": None,
                },
                {
                    "workflow_id": 2,
                    "name": "pending",
                    "status": "in_progress",
                    "conclusion": None,
                },
            ]
        )
        self.assertEqual(result["ci"], "unknown")


    def test_all_neutral_and_skipped_runs_cannot_make_ci_green(self):
        runs = [
            {"workflow_id": 1, "name": "optional-manual", "created_at": "2026-11-17T00:00:00Z",
             "status": "completed", "conclusion": "skipped"},
            {"workflow_id": 2, "name": "neutral-coverage", "created_at": "2026-11-17T00:01:00Z",
             "status": "completed", "conclusion": "neutral"},
        ]
        result = aggregate_workflow_runs(runs)
        self.assertEqual(result["ci"], "unknown")
        self.assertEqual(result["failing_workflows"], [])
        self.assertEqual(result["nonexecuted_workflows"],
                         ["neutral-coverage", "optional-manual"])

    def test_executed_success_with_optional_skip_is_not_blocked(self):
        runs = [
            {"workflow_id": 1, "name": "required-test", "created_at": "2026-11-17T00:00:00Z",
             "status": "completed", "conclusion": "success"},
            {"workflow_id": 2, "name": "optional-manual", "created_at": "2026-11-17T00:01:00Z",
             "status": "completed", "conclusion": "skipped"},
        ]
        result = aggregate_workflow_runs(runs)
        self.assertEqual(result["ci"], "success")
        self.assertEqual(result["nonexecuted_workflows"], ["optional-manual"])

    def test_latest_skip_supersedes_old_success_without_resurrecting_it(self):
        result = aggregate_workflow_runs([
            {"workflow_id": 5, "name": "build", "created_at": "2026-11-16T00:00:00Z",
             "status": "completed", "conclusion": "success"},
            {"workflow_id": 5, "name": "build", "created_at": "2026-11-17T00:00:00Z",
             "status": "completed", "conclusion": "skipped"},
        ])
        self.assertEqual(result["ci"], "unknown")
        self.assertEqual(result["nonexecuted_workflows"], ["build"])

    def test_terminal_red_dominates_neutral_optional_workflow(self):
        result = aggregate_workflow_runs([
            {"workflow_id": 1, "name": "security", "created_at": "2026-11-17T00:00:00Z",
             "status": "completed", "conclusion": "failure"},
            {"workflow_id": 2, "name": "manual", "created_at": "2026-11-17T00:00:00Z",
             "status": "completed", "conclusion": "skipped"},
        ])
        self.assertEqual(result["ci"], "failure")
        self.assertEqual(result["failing_workflows"], ["security"])
        self.assertEqual(result["nonexecuted_workflows"], ["manual"])



class ClassificationTests(unittest.TestCase):
    def test_archive_wins_over_name_rules(self):
        self.assertEqual(classify_repo({"name": "platform", "archived": True}), "archive")

    def test_unknown_role_is_not_guessed(self):
        self.assertEqual(classify_repo({"name": "new-unknown-repo"}), "unclassified")

    def test_repository_visibility_never_defaults_missing_evidence_to_public(self):
        self.assertEqual(_repository_visibility({}), "unknown")
        self.assertEqual(_repository_visibility({"private": None}), "unknown")
        self.assertEqual(_repository_visibility({"private": False}), "public")
        self.assertEqual(_repository_visibility({"private": True}), "private")
        self.assertEqual(_repository_visibility({"visibility": "public"}), "public")
        self.assertEqual(
            _repository_visibility({"visibility": "internal", "private": True}),
            "internal",
        )

    def test_repository_visibility_fails_closed_on_contradictory_fields(self):
        self.assertEqual(
            _repository_visibility({"visibility": "public", "private": True}),
            "unknown",
        )
        self.assertEqual(
            _repository_visibility({"visibility": "private", "private": False}),
            "unknown",
        )


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
    def test_bare_build_revision_cannot_create_operational_source_binding(
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
        self.assertIsNone(result["source_revision"])
        self.assertEqual(result["source_binding_state"], "INVALID")
        self.assertEqual(result["operational_state"], "RUNTIME_HEALTHY_UNBOUND")

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
        self.assertEqual(
            next_link('<https://example.test?page=3>; rel=next'),
            "https://example.test?page=3",
        )
        self.assertIsNone(next_link(None))

    @mock.patch("census.common.request_json")
    def test_quoted_link_parameters_cannot_inject_a_next_relation(
        self, request_json
    ):
        request_json.return_value = (
            [{"id": 1}],
            {
                "link": (
                    '<https://api.github.com/items?page=2>; '
                    'title="ordinary; rel=next ; text"'
                )
            },
            None,
        )

        result, error = paginate_json(
            "https://api.github.com/items?page=1",
            headers={},
            timeout=1.0,
            retries=0,
        )

        self.assertIsNone(error)
        self.assertEqual(result, [{"id": 1}])
        request_json.assert_called_once()

    def test_real_rel_after_quoted_link_parameter_is_observed(self):
        value = (
            '<https://api.github.com/items?page=2>; '
            'title="ordinary; text"; rel="next"'
        )
        self.assertEqual(
            next_link(value),
            "https://api.github.com/items?page=2",
        )

    @mock.patch("census.common.request_json")
    def test_malformed_or_ambiguous_link_header_fails_closed(self, request_json):
        for link in (
            '<https://api.github.com/items?page=2>; rel="next"; rel="last"',
            '<https://api.github.com/items?page=2; rel="next"',
            'https://api.github.com/items?page=2; rel="next"',
            '<https://api.github.com/items?page=2>; title="a"; title="b"',
            '<https://api.github.com/items?page=2>; rel',
            '<https://api.github.com/items?page=2>; rel=""',
            '<https://api.github.com/items?page=2>; rel="next,last"',
        ):
            with self.subTest(link=link):
                request_json.return_value = ([{"id": 1}], {"link": link}, None)
                result, error = paginate_json(
                    "https://api.github.com/items?page=1",
                    headers={},
                    timeout=1.0,
                    retries=0,
                )
                self.assertIsNone(result)
                self.assertIn("Link", error)

    @mock.patch("census.common.request_json")
    def test_pagination_aggregates_same_origin_exact_path_pages(self, request_json):
        request_json.side_effect = [
            (
                [{"id": 1}],
                {
                    "link": (
                        '<https://api.github.com/items?per_page=100&page=2>; '
                        'rel="next"'
                    )
                },
                None,
            ),
            ([{"id": 2}], {}, None),
        ]

        result, error = paginate_json(
            "https://api.github.com/items?per_page=100",
            headers={"Authorization": "Bearer opaque"},
            timeout=1.0,
            retries=0,
        )

        self.assertIsNone(error)
        self.assertEqual(result, [{"id": 1}, {"id": 2}])
        self.assertEqual(request_json.call_count, 2)
        self.assertTrue(
            all(
                call.kwargs["redirect_path"] == "/items"
                for call in request_json.call_args_list
            )
        )

    @mock.patch("census.common.request_json")
    def test_pagination_rejects_cross_origin_and_path_changes(self, request_json):
        for target, expected in (
            ("https://evil.example/items?page=2", "origin changed"),
            ("https://api.github.com/other?page=2", "path changed"),
        ):
            with self.subTest(target=target):
                request_json.reset_mock()
                request_json.return_value = (
                    [{"id": 1}],
                    {"link": f'<{target}>; rel="next"'},
                    None,
                )
                result, error = paginate_json(
                    "https://api.github.com/items?page=1",
                    headers={},
                    timeout=1.0,
                    retries=0,
                )
                self.assertIsNone(result)
                self.assertIn(expected, error)

    @mock.patch("census.common.request_json")
    def test_pagination_rejects_cycles_nonobjects_and_cap_exhaustion(
        self, request_json
    ):
        request_json.return_value = (
            [{"id": 1}],
            {"link": '<https://api.github.com/items?page=1>; rel="next"'},
            None,
        )
        result, error = paginate_json(
            "https://api.github.com/items?page=1",
            headers={},
            timeout=1.0,
            retries=0,
        )
        self.assertIsNone(result)
        self.assertIn("cycle", error)

        request_json.return_value = ([{"id": 1}, "bad"], {}, None)
        result, error = paginate_json(
            "https://api.github.com/items",
            headers={},
            timeout=1.0,
            retries=0,
        )
        self.assertIsNone(result)
        self.assertIn("non-object", error)

        request_json.return_value = (
            [{"id": 1}],
            {"link": '<https://api.github.com/items?page=2>; rel="next"'},
            None,
        )
        result, error = paginate_json(
            "https://api.github.com/items?page=1",
            headers={},
            timeout=1.0,
            retries=0,
            max_pages=1,
        )
        self.assertIsNone(result)
        self.assertIn("exceeded 1 pages", error)

    def test_cross_origin_redirect_strips_credentials(self):
        handler = _CredentialSafeRedirectHandler()
        request = urllib.request.Request(
            "https://api.github.com/items",
            headers={"Authorization": "Bearer secret", "Cookie": "session=secret"},
        )

        redirected = handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://objects.githubusercontent.com/items",
        )

        self.assertFalse(redirected.has_header("Authorization"))
        self.assertFalse(redirected.has_header("Cookie"))

    def test_locked_redirect_rejects_origin_path_downgrade_userinfo_and_port(self):
        handler = _CredentialSafeRedirectHandler(
            locked_origin=("https", "api.github.com", 443),
            locked_path="/items",
        )
        request = urllib.request.Request("https://api.github.com/items")
        for target in (
            "https://evil.example/items",
            "https://api.github.com/other",
            "http://api.github.com/items",
            "https://user@api.github.com/items",
            "https://api.github.com:8443/items",
            "https://api.github.com/items bad",
        ):
            with self.subTest(target=target), self.assertRaises(urllib.error.URLError):
                handler.redirect_request(request, None, 302, "Found", {}, target)

    @mock.patch("census.common.urllib.request.build_opener")
    def test_network_errors_do_not_reflect_secret_or_url(self, build_opener):
        build_opener.return_value.open.side_effect = RuntimeError(
            "Bearer super-secret https://api.github.com/items?token=secret"
        )

        body, headers, error = request_bytes(
            "https://api.github.com/items?token=secret",
            headers={"Authorization": "Bearer super-secret"},
            retries=0,
        )

        self.assertIsNone(body)
        self.assertEqual(headers, {})
        self.assertEqual(error, "RuntimeError")

    @mock.patch("census.common.urllib.request.build_opener")
    def test_success_body_read_is_bounded(self, build_opener):
        response = mock.MagicMock()
        response.headers.items.return_value = []
        response.read.return_value = b"12345"
        build_opener.return_value.open.return_value.__enter__.return_value = response

        body, headers, error = request_bytes(
            "https://api.github.com/items",
            retries=0,
            max_bytes=4,
        )

        self.assertIsNone(body)
        self.assertEqual(headers, {})
        self.assertEqual(error, "response-body-limit-exceeded")
        response.read.assert_called_once_with(5)

    def test_repeated_link_headers_are_preserved(self):
        headers = mock.MagicMock()
        headers.items.return_value = [
            ("Link", '<https://api.github.com/items?page=2>; rel="next"'),
            ("LINK", '<https://api.github.com/items?page=3>; rel="last"'),
        ]

        result = _response_header_map(headers)

        self.assertIn('page=2>; rel="next"', result["link"])
        self.assertIn('page=3>; rel="last"', result["link"])

    @mock.patch("census.common.request_bytes")
    def test_json_parser_rejects_ambiguous_or_resource_hostile_input(
        self, request_bytes_mock
    ):
        cases = (
            b'{"key":1,"key":2}',
            b'{"number":NaN}',
            b'{"number":Infinity}',
            b"[" * 2_000 + b"0" + b"]" * 2_000,
        )
        for payload in cases:
            with self.subTest(payload=payload[:24]):
                request_bytes_mock.return_value = (payload, {}, None)
                value, headers, error = request_json(
                    "https://api.github.com/items",
                    retries=0,
                )
                self.assertIsNone(value)
                self.assertEqual(headers, {})
                self.assertTrue(error.startswith("invalid-json:"), error)


if __name__ == "__main__":
    unittest.main()
