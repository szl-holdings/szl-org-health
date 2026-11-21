"""Offline standard-library adversarial controls for public Space runtime witness."""
import importlib.util
import json
import unittest
from pathlib import Path
from unittest import mock

MODULE = Path(__file__).resolve().parents[1] / "tools" / "public_space_runtime_witness.py"
spec = importlib.util.spec_from_file_location("public_space_witness", MODULE)
w = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(w)
HASH_A = "a" * 40
HASH_B = "b" * 40


def obj(data, http=200):
    return {"http": http, "error": None, "body": json.dumps(data).encode("utf-8")}


class PublicSpaceWitnessTests(unittest.TestCase):
    def test_static_host_is_not_misclassified_as_dynamic(self):
        self.assertEqual(
            w.runtime_url("SZLHOLDINGS/szl-brand-campaign", "static"),
            "https://szlholdings-szl-brand-campaign.static.hf.space",
        )
        self.assertEqual(
            w.runtime_url("SZLHOLDINGS/a11oy", "docker"),
            "https://szlholdings-a11oy.hf.space",
        )

    def test_space_url_rejects_untrusted_ids(self):
        for value in (
            "SZLHOLDINGS/a11oy/../privates", "evil/a11oy",
            "SZLHOLDINGS/a11oy?token=1", "SZLHOLDINGS/a11oy\nheader",
            "", None,
        ):
            with self.subTest(value=value):
                with self.assertRaises((ValueError, TypeError)):
                    w.runtime_url(value, "docker")

    def test_revision_accepts_only_full_lowercase_sha40(self):
        for invalid in (HASH_A.upper(), "HEAD", "main", "a" * 39,
                        "a" * 41, None, True, 7):
            with self.subTest(invalid=invalid):
                self.assertIsNone(w.revision(invalid))
        self.assertEqual(w.revision(HASH_A), HASH_A)

    def test_nonobject_json_is_not_successful_metadata(self):
        with mock.patch.object(w, "get", return_value=obj([])):
            value, witness = w.get_object("https://huggingface.co/api/spaces/SZLHOLDINGS/a11oy")
        self.assertIsNone(value)
        self.assertEqual(witness["error"], "JSON_OBJECT_REQUIRED")

    def test_invalid_index_does_not_claim_zero_or_green(self):
        with mock.patch.object(w, "get", return_value=obj({"wrong": "shape"})):
            report = w.census()
        self.assertIs(report["pagination_complete"], False)
        self.assertIsNone(report["space_count"])
        self.assertIs(report["production_qualified"], False)

    def test_at_limit_pagination_is_not_complete(self):
        with mock.patch.object(w, "get", return_value=obj([{"id": "SZLHOLDINGS/a11oy"}] * 100)):
            report = w.census()
        self.assertEqual(report["index_error"], "PAGINATION_INCOMPLETE")
        self.assertIs(report["pagination_complete"], False)
        self.assertEqual(report["spaces"], [])

    def test_unavailable_metadata_does_not_fabricate_root_probe(self):
        with (
            mock.patch.object(w, "get_object",
                              return_value=(None, {"http": 403, "error": "HTTP_ERROR"})),
            mock.patch.object(w, "get") as get,
        ):
            row = w.probe_space({"id": "SZLHOLDINGS/a11oy"})
        self.assertEqual(row["metadata_http"], 403)
        self.assertIsNone(row["root_http"])
        self.assertEqual(row["runtime_stage"], "UNKNOWN")
        get.assert_not_called()

    def test_static_space_correct_host_and_no_authority(self):
        meta = {"sha": HASH_A, "sdk": "static",
                "runtime": {"sha": HASH_A, "stage": "RUNNING"}}
        with (
            mock.patch.object(w, "get_object",
                              return_value=(meta, {"http": 200, "error": None})),
            mock.patch.object(w, "get",
                              return_value={"http": 200, "error": None, "body": b"<html/>"}) as get,
        ):
            row = w.probe_space({"id": "SZLHOLDINGS/szl-brand-campaign"})
        self.assertIn(".static.hf.space/", get.call_args.args[0])
        self.assertEqual(row["root_http"], 200)
        self.assertIsNone(row["readyz_http"])
        self.assertIs(row["release_qualified"], False)
        self.assertEqual(row["revision_match"], "MATCHED_REPOSITORY_AND_RUNTIME_METADATA")

    def test_running_root_does_not_hide_negative_readyz_and_revision_drift(self):
        meta = {"sha": HASH_A, "sdk": "docker",
                "runtime": {"stage": "RUNNING", "sha": HASH_B}}
        with (
            mock.patch.object(w, "get_object",
                              return_value=(meta, {"http": 200, "error": None})),
            mock.patch.object(w, "get", side_effect=[
                {"http": 200, "error": None, "body": b""},
                {"http": 503, "error": "HTTP_ERROR", "body": None},
            ]),
        ):
            row = w.probe_space({"id": "SZLHOLDINGS/szl-model-inference-lab"})
        self.assertEqual((row["root_http"], row["readyz_http"]), (200, 503))
        self.assertEqual(row["revision_match"], "REPOSITORY_RUNTIME_REVISION_DRIFT")
        self.assertIs(row["release_qualified"], False)

    def test_source_repo_is_not_guessed_from_unrelated_owner(self):
        meta = {"sha": HASH_A, "sdk": "docker",
                "runtime": {"stage": "RUNNING"},
                "cardData": {"source_repo": "https://github.com/not-owner/unsafe"}}
        with (
            mock.patch.object(w, "get_object",
                              return_value=(meta, {"http": 200, "error": None})),
            mock.patch.object(w, "get",
                              return_value={"http": 200, "error": None, "body": b""}),
        ):
            row = w.probe_space({"id": "SZLHOLDINGS/finance"})
        self.assertIsNone(row["source_repo_declared"])

    def test_a11oy_source_claim_never_becomes_independent_proof(self):
        row = {"id": "SZLHOLDINGS/a11oy", "sdk": "docker",
               "space_revision": "c" * 40, "metadata_error": None}
        for served, expected in (
            (HASH_B, "DECLARED_MISMATCH"),
            (HASH_A, "DECLARED_MATCH_NOT_BYTE_ATTESTED"),
            ("main", "UNAVAILABLE"), (HASH_A[:8], "UNAVAILABLE"),
        ):
            with self.subTest(served=served):
                def fake(url, **kwargs):
                    if url == w.GITHUB_MAIN:
                        return {"sha": HASH_A}, {"http": 200, "error": None}
                    if url.endswith("/api/a11oy/v1/honest"):
                        return {"git_sha": served}, {"http": 200, "error": None}
                    raise AssertionError(f"unexpected source: {url}")
                with (
                    mock.patch.object(w, "get_object", side_effect=fake),
                    mock.patch.object(w, "get",
                                      return_value={"http": 200, "error": None, "body": b""}),
                ):
                    witnessed = w.a11oy_source_witness(row)
                self.assertEqual(witnessed["source_claim_state"], expected)
                self.assertIs(witnessed["independent_runtime_verification"], False)
                self.assertEqual(witnessed["release_authority"], "NOT_PROVEN")
                self.assertEqual(witnessed["space_revision"], "c" * 40)

    def test_unavailable_index_keeps_a11oy_authority_unproven(self):
        with (
            mock.patch.object(w, "get",
                              return_value={"http": None, "error": "TimeoutError", "body": None}),
            mock.patch.object(w, "get_object") as get_json,
        ):
            report = w.census()
        self.assertIsNone(report["space_count"])
        self.assertEqual(report["a11oy"]["source_claim_state"], "UNAVAILABLE")
        self.assertIs(report["production_qualified"], False)
        get_json.assert_not_called()

    def test_non_dns_hf_id_requires_validated_hub_subdomain(self):
        for name in ("SZLHOLDINGS/Foo_Bar.v2", "SZLHOLDINGS/a.bad"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    w.runtime_url(name, "static")
                self.assertTrue(
                    w.runtime_url(name, "static", "szlholdings-foo-bar-v2").endswith(
                        "szlholdings-foo-bar-v2.static.hf.space"
                    )
                )

    def test_invalid_hub_subdomain_never_triggers_probe(self):
        meta = {"sha": HASH_A, "sdk": "docker", "subdomain": "evil.example.com",
                "runtime": {"sha": HASH_A, "stage": "RUNNING"}}
        with (
            mock.patch.object(w, "get_object",
                              return_value=(meta, {"http": 200, "error": None})),
            mock.patch.object(w, "get") as get,
        ):
            row = w.probe_space({"id": "SZLHOLDINGS/a11oy"})
        self.assertEqual(row["metadata_error"], "RUNTIME_URL_UNAVAILABLE")
        self.assertIsNone(row["root_http"])
        self.assertIs(row["release_qualified"], False)
        get.assert_not_called()

    def test_running_stage_with_http_503_remains_unreachable(self):
        meta = {"sha": HASH_A, "sdk": "docker",
                "runtime": {"sha": HASH_A, "stage": "RUNNING"}}
        with (
            mock.patch.object(w, "get_object",
                              return_value=(meta, {"http": 200, "error": None})),
            mock.patch.object(w, "get", side_effect=[
                {"http": 503, "error": "HTTP_ERROR", "body": None},
                {"http": 503, "error": "HTTP_ERROR", "body": None},
            ]),
        ):
            row = w.probe_space({"id": "SZLHOLDINGS/a11oy"})
        self.assertEqual(row["runtime_stage"], "RUNNING")
        self.assertEqual(row["root_http"], 503)
        self.assertEqual(row["reachability"], "NOT_HTTP_200_OR_UNKNOWN")
        self.assertIs(row["release_qualified"], False)


if __name__ == "__main__":
    unittest.main()
