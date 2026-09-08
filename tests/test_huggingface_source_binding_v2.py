"""Independent runtime, immutable artifact, and GitHub evidence for v2 Spaces."""

import copy
import hashlib
import json
import unittest
from unittest import mock

from census.huggingface import normalize_space


SPACE = "SZLHOLDINGS/immune"
REPOSITORY = "szl-holdings/immune"
HF_REVISION = "a" * 40
SOURCE_REVISION = "b" * 40
ARTIFACT_BYTES = b"console.log('source-bound fixture');\n"
ARTIFACTS = {"app.js": hashlib.sha256(ARTIFACT_BYTES).hexdigest()}
ARTIFACT_SET_DIGEST = hashlib.sha256(
    json.dumps(ARTIFACTS, sort_keys=True, separators=(",", ":")).encode("utf-8")
).hexdigest()
RUNTIME = "https://szlholdings-immune.hf.space"
MANIFEST_URL = (
    f"https://huggingface.co/spaces/{SPACE}/resolve/{HF_REVISION}/"
    "hf-deploy-manifest.json"
)
ARTIFACT_URL = f"https://huggingface.co/spaces/{SPACE}/resolve/{HF_REVISION}/app.js"
GITHUB_ROOT = f"https://api.github.com/repos/{REPOSITORY}"


def immune_bundle() -> dict:
    workflow = {
        "repository": REPOSITORY,
        "run_id": "1234",
        "run_attempt": "1",
        "ref": "refs/heads/main",
    }
    destination = {"repo_id": SPACE, "repo_type": "space"}
    return {
        "item": {
            "id": SPACE,
            "sha": HF_REVISION,
            "sdk": "docker",
            "subdomain": "szlholdings-immune",
            "runtime": {"stage": "RUNNING", "sha": HF_REVISION},
            "siblings": [
                {"rfilename": "README.md"},
                {"rfilename": "hf-deploy-manifest.json"},
                {"rfilename": "app.js"},
            ],
            "cardData": {"license": "apache-2.0"},
        },
        "manifest": {
            "schema": "szl.hf-deploy-manifest/v2",
            "source": {
                "repository": REPOSITORY,
                "revision": SOURCE_REVISION,
                "ref": "refs/heads/main",
            },
            "workflow": copy.deepcopy(workflow),
            "destination": copy.deepcopy(destination),
            "artifacts": copy.deepcopy(ARTIFACTS),
        },
        "source": {
            "schema": "szl.source-attestation/v2",
            "source": {
                "repository": REPOSITORY,
                "commit": SOURCE_REVISION,
                "ref": "refs/heads/main",
            },
            "workflow": copy.deepcopy(workflow),
            "destination": copy.deepcopy(destination),
            "artifact_integrity": {"status": "MATCH", "checked": 1, "failures": []},
            "manifest_schema": "szl.hf-deploy-manifest/v2",
            "deployment": {
                "hf_space": SPACE,
                "hf_revision": None,
                "workflow_run": f"https://github.com/{REPOSITORY}/actions/runs/1234",
            },
            "expected_huggingface_revision": None,
            "observed_huggingface_revision": None,
        },
        "build": {
            "schema": "szl.build-info/v2",
            "source_repository": REPOSITORY,
            "source_revision": SOURCE_REVISION,
            "artifact_count": 1,
            "runtime_hash_match": True,
        },
        "commit": {
            "sha": SOURCE_REVISION,
            "commit": {"verification": {"verified": True, "reason": "valid"}},
        },
        "run": {
            "id": 1234,
            "run_attempt": 1,
            "head_sha": SOURCE_REVISION,
            "head_branch": "main",
            "repository": {"full_name": REPOSITORY},
            "head_repository": {"full_name": REPOSITORY},
            "status": "completed",
            "conclusion": "success",
            "path": ".github/workflows/deploy-hf-space.yml",
            "name": "Deploy HF Space",
        },
    }


class HuggingFaceSourceBindingV2Tests(unittest.TestCase):
    def resolve(
        self,
        bundle=None,
        *,
        absent=(),
        authenticated=True,
        artifact_bytes=ARTIFACT_BYTES,
        artifact_error=None,
        artifact_responses=None,
        github_error=None,
    ):
        bundle = copy.deepcopy(bundle if bundle is not None else immune_bundle())
        documents = {
            f"{RUNTIME}/api/build-info": "build",
            f"{RUNTIME}/.well-known/szl-source.json": "source",
            MANIFEST_URL: "manifest",
            f"{GITHUB_ROOT}/commits/{SOURCE_REVISION}": "commit",
            f"{GITHUB_ROOT}/actions/runs/1234": "run",
            f"{GITHUB_ROOT}/actions/runs/1234/attempts/1": "run",
        }

        def request(url, **kwargs):
            self.assertIn(url, documents, f"unexpected JSON request: {url}")
            key = documents[url]
            if key in {"commit", "run"}:
                self.assertTrue(authenticated, "GitHub evidence requires credentials")
                self.assertEqual(
                    kwargs.get("headers", {}).get("Authorization"),
                    "Bearer test-only-token",
                )
                if github_error:
                    return None, {}, github_error
            return (None, {}, "http404") if key in absent else (bundle[key], {}, None)

        def request_artifact(url, **_kwargs):
            if artifact_responses is not None:
                self.assertIn(url, artifact_responses, f"unexpected artifact request: {url}")
                body, error = artifact_responses[url]
                return body, {}, error
            self.assertEqual(
                url, ARTIFACT_URL, "artifact must use its immutable HF revision"
            )
            return artifact_bytes, {}, artifact_error

        def auth(env_names):
            if authenticated and "GITHUB_TOKEN" in tuple(env_names):
                return {"Authorization": "Bearer test-only-token"}
            return {}

        with (
            mock.patch(
                "census.huggingface.http_probe",
                return_value={"http": 200, "headers": {}},
            ),
            mock.patch(
                "census.huggingface.request_json", side_effect=request
            ) as json_mock,
            mock.patch(
                "census.huggingface.request_bytes", side_effect=request_artifact
            ) as bytes_mock,
            mock.patch("census.huggingface.token_header", side_effect=auth),
        ):
            result = normalize_space(bundle["item"])
        return result, json_mock, bytes_mock

    def assert_unbound(self, result, expected_state):
        self.assertEqual(result["source_binding_state"], expected_state, result)
        self.assertNotEqual(result["operational_state"], "OPERATIONAL_SOURCE_BOUND")

    def test_matching_bundle_stays_unknown_without_verified_artifact_provenance(
        self,
    ):
        result, requests, artifacts = self.resolve()

        self.assert_unbound(result, "UNKNOWN")
        self.assertIn("artifact provenance", result["source_binding_error"])
        self.assertEqual(result["source_repository"], REPOSITORY)
        self.assertEqual(result["source_revision"], SOURCE_REVISION)
        self.assertEqual(result["source_hf_revision"], HF_REVISION)
        self.assertEqual(result["source_workflow_run_id"], 1234)
        self.assertEqual(result["source_artifact_sha256"], ARTIFACT_SET_DIGEST)
        self.assertEqual(
            set(result["source_evidence"]),
            {
                "api/build-info",
                ".well-known/szl-source.json",
                "hf-deploy-manifest.json",
            },
        )
        self.assertIn(MANIFEST_URL, [call.args[0] for call in requests.call_args_list])
        artifacts.assert_called_once()
        self.assertEqual(artifacts.call_args.args[0], ARTIFACT_URL)
        self.assertIn(
            f"{GITHUB_ROOT}/actions/runs/1234/attempts/1",
            [call.args[0] for call in requests.call_args_list],
        )

    def test_contradictory_source_aliases_are_invalid(self):
        mutations = (
            ("manifest", ("source", "commit"), "c" * 40),
            ("source", ("source", "revision"), "c" * 40),
            ("source", ("source_revision",), "c" * 40),
            ("source", ("source_revision",), ""),
            ("source", ("source_repository",), "szl-holdings/other"),
            ("build", ("source",), {"revision": "c" * 40}),
            ("source", ("source_ref",), "refs/heads/other"),
            ("source", ("deployment", "workflow_run"), f"https://github.com/{REPOSITORY}/actions/runs/4321"),
        )
        for document, path, value in mutations:
            with self.subTest(document=document, path=path):
                bundle = immune_bundle()
                target = bundle[document]
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                result, _, artifacts = self.resolve(bundle)
                self.assert_unbound(result, "INVALID")
                artifacts.assert_not_called()

    def test_v2_run_identity_requires_positive_scalar_integer(self):
        for field in ("run_id", "run_attempt"):
            for value in (True, {"id": True}, {"id": 1}, 1.0, 0, "0", "-1", "1.0"):
                with self.subTest(field=field, value=value):
                    bundle = immune_bundle()
                    bundle["manifest"]["workflow"][field] = value
                    result, _, artifacts = self.resolve(bundle)
                    self.assert_unbound(result, "INVALID")
                    artifacts.assert_not_called()

    def test_each_document_is_required_and_manifest_alone_cannot_promote(self):
        for absent in (("manifest",), ("source",), ("build",), ("source", "build")):
            with self.subTest(absent=absent):
                result, _, _ = self.resolve(absent=absent)
                self.assertIn(
                    result["source_binding_state"], {"UNKNOWN", "UNAVAILABLE"}, result
                )
                self.assertNotEqual(
                    result["operational_state"], "OPERATIONAL_SOURCE_BOUND"
                )

    def test_no_source_documents_is_unavailable_even_with_healthy_http(self):
        result, _, artifacts = self.resolve(absent=("manifest", "source", "build"))

        self.assert_unbound(result, "UNAVAILABLE")
        self.assertEqual(result["http"], 200)
        self.assertEqual(result["healthz"], 200)
        artifacts.assert_not_called()

    def test_missing_github_authentication_or_denied_api_stays_unknown(self):
        for kwargs in ({"authenticated": False}, {"github_error": "http403"}):
            with self.subTest(kwargs=kwargs):
                result, _, _ = self.resolve(**kwargs)
                self.assert_unbound(result, "UNKNOWN")

    def test_successful_unverified_build_info_preserves_http_status(self):
        for schema in (None, "szl.deployment-source/v3"):
            with self.subTest(schema=schema):
                bundle = immune_bundle()
                if schema is None:
                    del bundle["build"]["schema"]
                else:
                    bundle["build"]["schema"] = schema
                    bundle["build"]["attestation_reference"] = {
                        "repository": REPOSITORY,
                        "subject_digest": ARTIFACT_SET_DIGEST,
                    }

                result, _, _ = self.resolve(bundle)

                self.assert_unbound(result, "UNKNOWN")
                self.assertEqual(result["build_info_http"], 200)
                self.assertIsNotNone(result["build_info_error"])

    def test_independent_artifact_hash_mismatch_is_invalid(self):
        result, _, artifacts = self.resolve(artifact_bytes=b"different deployed bytes")

        self.assert_unbound(result, "INVALID")
        artifacts.assert_called_once()

    def test_artifact_mismatch_dominates_unavailable_github_authentication(self):
        for kwargs in ({"authenticated": False}, {"github_error": "http403"}):
            with self.subTest(kwargs=kwargs):
                result, _, artifacts = self.resolve(
                    artifact_bytes=b"different deployed bytes", **kwargs
                )

                self.assert_unbound(result, "INVALID")
                self.assertIn("digest", result["source_binding_error"])
                artifacts.assert_called_once()

    def test_later_artifact_mismatch_dominates_earlier_unreadable_artifact(self):
        second_bytes = b"second manifest artifact\n"
        second_url = (
            f"https://huggingface.co/spaces/{SPACE}/resolve/{HF_REVISION}/second.js"
        )
        bundle = immune_bundle()
        bundle["manifest"]["artifacts"]["second.js"] = hashlib.sha256(
            second_bytes
        ).hexdigest()
        bundle["source"]["artifact_integrity"]["checked"] = 2
        bundle["build"]["artifact_count"] = 2
        bundle["item"]["siblings"].append({"rfilename": "second.js"})
        responses = {
            ARTIFACT_URL: (None, "http403"),
            second_url: (b"different second artifact", None),
        }
        for kwargs in ({}, {"authenticated": False}, {"github_error": "http403"}):
            with self.subTest(kwargs=kwargs):
                result, _, artifacts = self.resolve(
                    bundle, artifact_responses=responses, **kwargs
                )

                self.assert_unbound(result, "INVALID")
                self.assertIn("digest", result["source_binding_error"])
                self.assertEqual(
                    [call.args[0] for call in artifacts.call_args_list],
                    [ARTIFACT_URL, second_url],
                )

    def test_unavailable_artifact_is_unknown_despite_runtime_match_claim(self):
        result, _, _ = self.resolve(artifact_bytes=None, artifact_error="http403")

        self.assert_unbound(result, "UNKNOWN")

    def test_unavailable_artifact_reads_still_consume_aggregate_byte_budget(self):
        bundle = immune_bundle()
        paths = [f"artifact-{index}.js" for index in range(5)]
        bundle["manifest"]["artifacts"] = {
            path: ARTIFACTS["app.js"] for path in paths
        }
        bundle["source"]["artifact_integrity"]["checked"] = len(paths)
        bundle["build"]["artifact_count"] = len(paths)
        bundle["item"]["siblings"].extend(
            {"rfilename": path} for path in paths
        )
        responses = {
            f"https://huggingface.co/spaces/{SPACE}/resolve/{HF_REVISION}/{path}": (
                None, "response-body-limit-exceeded"
            )
            for path in paths
        }

        result, _, artifacts = self.resolve(bundle, artifact_responses=responses)

        self.assert_unbound(result, "UNKNOWN")
        self.assertIn("budget", result["source_binding_error"].lower())
        self.assertEqual(
            [call.args[0] for call in artifacts.call_args_list],
            list(responses)[:4],
        )
        self.assertEqual(
            [call.kwargs["max_bytes"] for call in artifacts.call_args_list],
            [4 * 1024 * 1024] * 4,
        )

    def test_artifact_count_and_runtime_integrity_disagreement_are_invalid(self):
        mutations = (
            ("build", "artifact_count", 2),
            ("build", "artifact_count", True),
            ("build", "runtime_hash_match", False),
            (
                "source",
                "artifact_integrity",
                {"status": "MISMATCH", "checked": 1, "failures": []},
            ),
            (
                "source",
                "artifact_integrity",
                {"status": "MATCH", "checked": 0, "failures": []},
            ),
            (
                "source",
                "artifact_integrity",
                {"status": "MATCH", "checked": 1, "failures": ["app.js"]},
            ),
        )
        for document, key, value in mutations:
            with self.subTest(document=document, key=key, value=value):
                bundle = immune_bundle()
                bundle[document][key] = value
                result, _, _ = self.resolve(bundle)
                self.assert_unbound(result, "INVALID")

    def test_manifest_artifact_paths_and_hash_types_are_validated_before_fetch(self):
        invalid_artifacts = (
            {"../app.js": ARTIFACTS["app.js"]},
            {"nested/../../app.js": ARTIFACTS["app.js"]},
            {"/app.js": ARTIFACTS["app.js"]},
            {"nested\\app.js": ARTIFACTS["app.js"]},
            {"https://example.invalid/app.js": ARTIFACTS["app.js"]},
            {"app.js": 1},
            {"app.js": None},
            {"app.js": [ARTIFACTS["app.js"]]},
            {"app.js": "not-a-sha256"},
        )
        for artifacts in invalid_artifacts:
            with self.subTest(artifacts=artifacts):
                bundle = immune_bundle()
                bundle["manifest"]["artifacts"] = artifacts
                result, _, bytes_mock = self.resolve(bundle)
                self.assert_unbound(result, "INVALID")
                bytes_mock.assert_not_called()

    def test_destination_or_source_disagreement_is_invalid(self):
        mutations = (
            ("manifest", "destination", "repo_id", "SZLHOLDINGS/other"),
            ("source", "destination", "repo_type", "model"),
            ("source", "source", "commit", "c" * 40),
            ("manifest", "source", "repository", "szl-holdings/other"),
            ("source", "source", "ref", "refs/heads/other"),
            ("source", "workflow", "run_attempt", "2"),
        )
        for document, section, key, value in mutations:
            with self.subTest(document=document, section=section, key=key):
                bundle = immune_bundle()
                bundle[document][section][key] = value
                result, _, _ = self.resolve(bundle)
                self.assert_unbound(result, "INVALID")
        bundle = immune_bundle()
        bundle["build"]["source_revision"] = "c" * 40
        result, _, _ = self.resolve(bundle)
        self.assert_unbound(result, "INVALID")

    def test_hf_repository_and_running_revision_must_match(self):
        bundle = immune_bundle()
        bundle["item"]["runtime"]["sha"] = "c" * 40

        result, _, _ = self.resolve(bundle)

        self.assert_unbound(result, "INVALID")

    def test_authenticated_run_must_match_attempt_source_and_repository(self):
        for key, value in (
            ("run_attempt", 2),
            ("head_sha", "c" * 40),
            ("repository", {"full_name": "szl-holdings/other"}),
            ("conclusion", "failure"),
        ):
            with self.subTest(key=key):
                bundle = immune_bundle()
                bundle["run"][key] = value
                result, _, _ = self.resolve(bundle)
                self.assert_unbound(result, "INVALID")

    def test_github_source_commit_must_have_valid_signature_evidence(self):
        for verification in (
            {"verified": False, "reason": "unsigned"},
            {"verified": True, "reason": "invalid"},
            {},
        ):
            with self.subTest(verification=verification):
                bundle = immune_bundle()
                bundle["commit"]["commit"]["verification"] = verification
                result, _, _ = self.resolve(bundle)
                self.assert_unbound(result, "INVALID")

    def test_v3_reference_is_unknown_without_cryptographic_attestation_verification(
        self,
    ):
        bundle = immune_bundle()
        bundle["source"]["schema"] = "szl.deployment-source/v3"
        bundle["source"]["attestation_reference"] = {
            "repository": REPOSITORY,
            "subject_digest": ARTIFACT_SET_DIGEST,
        }

        result, requests, _ = self.resolve(bundle)

        self.assert_unbound(result, "UNKNOWN")
        self.assertFalse(
            any(
                call.args[0].startswith(GITHUB_ROOT) for call in requests.call_args_list
            ),
            "v3 reference parsing must not fabricate authenticated source evidence",
        )


if __name__ == "__main__":
    unittest.main()
