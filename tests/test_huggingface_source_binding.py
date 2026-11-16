import copy
import unittest
from unittest import mock

from census.huggingface import normalize_space


ANATOMY_HF_REVISION = "d66357340a13958adffb188ea63ab823f42820b7"
ANATOMY_SOURCE_REVISION = "4a60f66608da5e35972e7739ba317783bd6659ab"
ANATOMY_WORKFLOW_RUN = 30726848616
ANATOMY_ARTIFACT_SHA256 = (
    "73bf81e9d7ef7c60caaf3ab1e083cf6f6f10b2bd0dd11e9048d777dd4c69fc1b"
)


def anatomy_item() -> dict:
    return {
        "id": "SZLHOLDINGS/anatomy",
        "sha": ANATOMY_HF_REVISION,
        "sdk": "docker",
        "subdomain": "szlholdings-anatomy",
        "runtime": {"stage": "RUNNING", "sha": ANATOMY_HF_REVISION},
        "siblings": [
            {"rfilename": "README.md"},
            {"rfilename": "hf-deploy-manifest.json"},
        ],
        "cardData": {"license": "apache-2.0"},
    }


def anatomy_source_document() -> dict:
    return {
        "schema": "szl.deployment-source/v1",
        "state": "SOURCE_BOUND_DEPLOYMENT",
        "source": {
            "repository": "szl-holdings/anatomy",
            "commit": ANATOMY_SOURCE_REVISION,
        },
        "deployment": {
            "hf_repository": "SZLHOLDINGS/anatomy",
            "hf_revision": ANATOMY_HF_REVISION,
            "workflow_run": (
                "https://github.com/szl-holdings/anatomy/actions/runs/"
                f"{ANATOMY_WORKFLOW_RUN}"
            ),
            "artifact_set_sha256": ANATOMY_ARTIFACT_SHA256,
        },
    }


def anatomy_manifest() -> dict:
    manifest = anatomy_source_document()
    manifest["schema"] = "szl.hf-deploy-manifest/v1"
    return manifest


class HuggingFaceSourceBindingTests(unittest.TestCase):
    def resolve(
        self,
        *,
        item: dict | None = None,
        build_response: tuple | None = None,
        source_response: tuple | None = None,
        manifest_response: tuple | None = None,
        authenticated: bool = True,
        commit_response: tuple | None = None,
        run_response: tuple | None = None,
    ) -> dict:
        item = copy.deepcopy(item or anatomy_item())
        build_response = build_response or (None, {}, "http404")
        source_response = source_response or (anatomy_source_document(), {}, None)
        manifest_response = manifest_response or (anatomy_manifest(), {}, None)
        commit_response = commit_response or (
            {
                "sha": ANATOMY_SOURCE_REVISION,
                "commit": {"verification": {"verified": True, "reason": "valid"}},
            },
            {},
            None,
        )
        run_response = run_response or (
            {
                "id": ANATOMY_WORKFLOW_RUN,
                "head_sha": ANATOMY_SOURCE_REVISION,
                "status": "completed",
                "conclusion": "success",
                "repository": {"full_name": "szl-holdings/anatomy"},
            },
            {},
            None,
        )

        def request(url, **_kwargs):
            if url.endswith("/api/build-info"):
                return build_response
            if url.endswith("/.well-known/szl-source.json"):
                return source_response
            if "/resolve/" in url and url.endswith("/hf-deploy-manifest.json"):
                return manifest_response
            if url.endswith(f"/commits/{ANATOMY_SOURCE_REVISION}"):
                return commit_response
            if url.endswith(f"/actions/runs/{ANATOMY_WORKFLOW_RUN}"):
                return run_response
            if url.endswith(f"/actions/runs/{ANATOMY_WORKFLOW_RUN}/jobs"):
                return ({"jobs": [{
                    "name": "Publish Hugging Face Space", "status": "completed",
                    "conclusion": "success", "run_id": ANATOMY_WORKFLOW_RUN,
                    "head_sha": ANATOMY_SOURCE_REVISION,
                }]}, {}, None)
            raise AssertionError(f"unexpected request: {url}")

        def auth(env_names):
            if authenticated and "GITHUB_TOKEN" in tuple(env_names):
                return {"Authorization": "Bearer test-only-token"}
            return {}

        with (
            mock.patch(
                "census.huggingface.http_probe",
                side_effect=[
                    {"http": 200, "headers": {}},
                    {"http": 200, "headers": {}},
                ],
            ),
            mock.patch("census.huggingface.request_json", side_effect=request),
            mock.patch("census.huggingface.token_header", side_effect=auth),
        ):
            return normalize_space(item)

    def test_v1_metadata_agreement_remains_unknown_without_artifact_provenance(self):
        result = self.resolve()

        self.assertEqual(result["source_binding_state"], "UNKNOWN")
        self.assertEqual(result["operational_state"], "RUNTIME_HEALTHY_UNBOUND")
        self.assertIn("artifact provenance", result["source_binding_error"])
        self.assertEqual(result["source_repository"], "szl-holdings/anatomy")
        self.assertEqual(result["source_revision"], ANATOMY_SOURCE_REVISION)
        self.assertEqual(result["source_hf_revision"], ANATOMY_HF_REVISION)
        self.assertEqual(result["source_workflow_run_id"], ANATOMY_WORKFLOW_RUN)
        self.assertEqual(result["source_artifact_sha256"], ANATOMY_ARTIFACT_SHA256)
        self.assertEqual(
            set(result["source_evidence"]),
            {".well-known/szl-source.json", "hf-deploy-manifest.json"},
        )

    def test_coherent_unverified_digest_cannot_promote_operational_source_binding(self):
        from census.governance import evaluate_report

        for digest in ("1" * 64, "f" * 64):
            with self.subTest(digest=digest):
                source = anatomy_source_document()
                manifest = anatomy_manifest()
                source["deployment"]["artifact_set_sha256"] = digest
                manifest["deployment"]["artifact_set_sha256"] = digest
                # A matching claim is not independently observed artifact evidence.
                with mock.patch(
                    "census.huggingface.request_bytes",
                    return_value=(None, {}, "http403"),
                ):
                    result = self.resolve(
                        source_response=(source, {}, None),
                        manifest_response=(manifest, {}, None),
                    )
                self.assertEqual(result["source_binding_state"], "UNKNOWN")
                self.assertEqual(result["operational_state"], "RUNTIME_HEALTHY_UNBOUND")
                self.assertEqual(result["source_artifact_sha256"], digest)

                report = {"sources": {"huggingface": {"ok": True, "data": {
                    "authentication": {"inventory_scope": "AUTHENTICATED_BOUNDED"},
                    "assets": {"spaces": {"ok": True, "items": [result]}},
                }}}}
                controls = {value["id"]: value for value in evaluate_report(report)["controls"]}
                self.assertEqual(controls["HF-DYNAMIC-SPACE-SOURCE-BINDING"]["status"], "FAIL")

    def test_http_200_html_and_malformed_json_are_invalid_not_evidence(self):
        cases = {
            "html": (
                None,
                {"content-type": "text/html"},
                "invalid-json:Expecting value",
            ),
            "malformed": (
                None,
                {"content-type": "application/json"},
                "invalid-json:unterminated object",
            ),
        }
        for name, response in cases.items():
            with self.subTest(name=name):
                result = self.resolve(
                    build_response=response,
                    source_response=(None, {}, "http404"),
                    manifest_response=(None, {}, "http404"),
                    authenticated=False,
                )
                self.assertEqual(result["build_info_http"], 200)
                self.assertEqual(result["source_binding_state"], "INVALID")
                self.assertNotEqual(
                    result["operational_state"],
                    "OPERATIONAL_SOURCE_BOUND",
                )

    def test_wrong_well_known_schema_is_invalid(self):
        payload = anatomy_source_document()
        payload["schema"] = "szl.deployment-source/v0"

        result = self.resolve(
            source_response=(payload, {}, None),
            manifest_response=(None, {}, "http404"),
            authenticated=False,
        )

        self.assertEqual(result["source_binding_state"], "INVALID")

    def test_missing_required_source_fields_are_invalid(self):
        payload = anatomy_source_document()
        del payload["source"]["repository"]

        result = self.resolve(
            source_response=(payload, {}, None),
            manifest_response=(None, {}, "http404"),
            authenticated=False,
        )

        self.assertEqual(result["source_binding_state"], "INVALID")
        self.assertIn("repository", result["source_binding_error"])

    def test_claimed_repository_and_runtime_revision_mismatches_are_invalid(self):
        wrong_space = anatomy_source_document()
        wrong_space["deployment"]["hf_repository"] = "SZLHOLDINGS/not-anatomy"
        wrong_runtime_item = anatomy_item()
        wrong_runtime_item["runtime"]["sha"] = "e" * 40
        cases = (
            {
                "source_response": (wrong_space, {}, None),
                "manifest_response": (None, {}, "http404"),
            },
            {
                "item": wrong_runtime_item,
                "manifest_response": (None, {}, "http404"),
            },
        )
        for case in cases:
            with self.subTest(case=case):
                result = self.resolve(authenticated=False, **case)
                self.assertEqual(result["source_binding_state"], "INVALID")

    def test_invalid_or_conflicting_artifact_digest_is_rejected(self):
        invalid = anatomy_source_document()
        invalid["deployment"]["artifact_set_sha256"] = "sha256:not-a-digest"
        conflicting = anatomy_manifest()
        conflicting["deployment"]["artifact_set_sha256"] = "f" * 64
        cases = (
            {
                "source_response": (invalid, {}, None),
                "manifest_response": (None, {}, "http404"),
            },
            {"manifest_response": (conflicting, {}, None)},
        )
        for case in cases:
            with self.subTest(case=case):
                result = self.resolve(authenticated=False, **case)
                self.assertEqual(result["source_binding_state"], "INVALID")

    def test_valid_evidence_without_github_authentication_remains_unknown(self):
        result = self.resolve(authenticated=False)

        self.assertEqual(result["source_binding_state"], "UNKNOWN")
        self.assertEqual(result["source_revision"], ANATOMY_SOURCE_REVISION)
        self.assertEqual(result["operational_state"], "RUNTIME_HEALTHY_UNBOUND")
        self.assertIn("authentication", result["source_binding_error"].lower())

    def test_authenticated_but_unavailable_source_or_run_remains_unknown(self):
        result = self.resolve(run_response=(None, {}, "http403"))

        self.assertEqual(result["source_binding_state"], "UNKNOWN")
        self.assertIn("workflow run", result["source_binding_error"].lower())

    def test_authenticated_run_mismatch_is_invalid(self):
        result = self.resolve(
            run_response=(
                {
                    "id": ANATOMY_WORKFLOW_RUN,
                    "head_sha": "f" * 40,
                    "status": "completed",
                    "conclusion": "success",
                    "repository": {"full_name": "szl-holdings/anatomy"},
                },
                {},
                None,
            )
        )

        self.assertEqual(result["source_binding_state"], "INVALID")

    def test_one_evidence_class_cannot_establish_source_binding(self):
        absent = (None, {}, "http404")
        for changes in (
            {"manifest_response": absent},
            {"source_response": absent, "build_response": absent},
            {"item": {**anatomy_item(), "siblings": []}},
        ):
            with self.subTest(changes=changes):
                self.assertEqual(self.resolve(**changes)["source_binding_state"], "UNKNOWN")

    def test_unsigned_source_cannot_establish_source_binding(self):
        for verification in (
            {"verified": False, "reason": "unsigned"},
            {"verified": "true", "reason": "valid"},
            {"verified": True, "reason": "unknown_key"},
        ):
            with self.subTest(verification=verification):
                result = self.resolve(commit_response=({
                    "sha": ANATOMY_SOURCE_REVISION,
                    "commit": {"verification": verification},
                }, {}, None))
                self.assertEqual(result["source_binding_state"], "INVALID")

    def test_workflow_repository_is_required_even_with_a_matching_head_repository(self):
        for repository in (None, {}, {"full_name": ""}, {"full_name": "other/repo"}):
            with self.subTest(repository=repository):
                result = self.resolve(run_response=({
                    "id": ANATOMY_WORKFLOW_RUN,
                    "head_sha": ANATOMY_SOURCE_REVISION,
                    "status": "completed", "conclusion": "success",
                    "repository": repository,
                    "head_repository": {"full_name": "szl-holdings/anatomy"},
                }, {}, None))
                self.assertEqual(result["source_binding_state"], "INVALID")


if __name__ == "__main__":
    unittest.main()
