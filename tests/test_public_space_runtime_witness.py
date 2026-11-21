"""Offline adversarial controls for the public Space runtime witness."""
import importlib.util
import json
from pathlib import Path
from unittest import mock

import pytest

MODULE = Path(__file__).resolve().parents[1] / "tools" / "public_space_runtime_witness.py"
spec = importlib.util.spec_from_file_location("public_space_witness", MODULE)
w = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(w)
HASH_A = "a" * 40
HASH_B = "b" * 40


def obj(data, http=200):
    return {"http": http, "error": None, "body": json.dumps(data).encode("utf-8")}


def test_static_host_is_not_misclassified_as_dynamic():
    assert w.runtime_url("SZLHOLDINGS/szl-brand-campaign", "static") == (
        "https://szlholdings-szl-brand-campaign.static.hf.space"
    )
    assert w.runtime_url("SZLHOLDINGS/a11oy", "docker") == "https://szlholdings-a11oy.hf.space"


@pytest.mark.parametrize("untrusted", [
    "SZLHOLDINGS/a11oy/../privates", "evil/a11oy", "SZLHOLDINGS/a11oy?token=1",
    "SZLHOLDINGS/a11oy\nheader", "", None,
])
def test_space_url_rejects_untrusted_ids(untrusted):
    with pytest.raises((ValueError, TypeError)):
        w.runtime_url(untrusted, "docker")


@pytest.mark.parametrize("invalid", [
    HASH_A.upper(), "HEAD", "main", "a" * 39, "a" * 41, None, True, 7,
])
def test_revision_accepts_only_full_lowercase_sha40(invalid):
    assert w.revision(invalid) is None
    assert w.revision(HASH_A) == HASH_A


def test_malformed_json_object_is_not_a_successful_metadata_read():
    with mock.patch.object(w, "get", return_value=obj([])):
        value, witness = w.get_object("https://huggingface.co/api/spaces/SZLHOLDINGS/a11oy")
    assert value is None and witness["error"] == "JSON_OBJECT_REQUIRED"


def test_invalid_index_never_means_zero_spaces_or_all_green():
    with mock.patch.object(w, "get", return_value=obj({"wrong": "shape"})):
        report = w.census()
    assert report["pagination_complete"] is False
    assert report["space_count"] is None
    assert report["production_qualified"] is False


def test_pagination_at_limit_is_incomplete_not_full_inventory():
    with mock.patch.object(w, "get", return_value=obj([{"id": "SZLHOLDINGS/a11oy"}] * 100)):
        report = w.census()
    assert report["index_error"] == "PAGINATION_INCOMPLETE"
    assert report["pagination_complete"] is False
    assert report["spaces"] == []


def test_unavailable_metadata_does_not_fabricate_root_probe():
    with (
        mock.patch.object(w, "get_object", return_value=(None, {"http": 403, "error": "HTTP_ERROR"})),
        mock.patch.object(w, "get") as get,
    ):
        row = w.probe_space({"id": "SZLHOLDINGS/a11oy"})
    assert row["metadata_http"] == 403
    assert row["root_http"] is None
    assert row["runtime_stage"] == "UNKNOWN"
    get.assert_not_called()


def test_static_space_uses_static_hostname_and_keeps_authority_false():
    meta = {"sha": HASH_A, "sdk": "static", "runtime": {"sha": HASH_A, "stage": "RUNNING"}}
    with (
        mock.patch.object(w, "get_object", return_value=(meta, {"http": 200, "error": None})),
        mock.patch.object(w, "get", return_value={"http": 200, "error": None, "body": b"<html/>"}) as get,
    ):
        row = w.probe_space({"id": "SZLHOLDINGS/szl-brand-campaign"})
    assert ".static.hf.space/" in get.call_args.args[0]
    assert row["root_http"] == 200 and row["readyz_http"] is None
    assert row["release_qualified"] is False
    assert row["revision_match"] == "MATCHED_REPOSITORY_AND_RUNTIME_METADATA"


def test_running_root_success_cannot_hide_negative_readyz_or_revision_drift():
    meta = {"sha": HASH_A, "sdk": "docker",
            "runtime": {"stage": "RUNNING", "sha": HASH_B}}
    with (
        mock.patch.object(w, "get_object", return_value=(meta, {"http": 200, "error": None})),
        mock.patch.object(w, "get", side_effect=[
            {"http": 200, "error": None, "body": b""},
            {"http": 503, "error": "HTTP_ERROR", "body": None},
        ]),
    ):
        row = w.probe_space({"id": "SZLHOLDINGS/szl-model-inference-lab"})
    assert row["root_http"] == 200 and row["readyz_http"] == 503
    assert row["revision_match"] == "REPOSITORY_RUNTIME_REVISION_DRIFT"
    assert row["release_qualified"] is False


def test_manifest_metadata_does_not_guess_missing_source_repo():
    meta = {"sha": HASH_A, "sdk": "docker", "runtime": {"stage": "RUNNING"},
            "cardData": {"source_repo": "https://github.com/not-owner/unsafe"}}
    with (
        mock.patch.object(w, "get_object", return_value=(meta, {"http": 200, "error": None})),
        mock.patch.object(w, "get", return_value={"http": 200, "error": None, "body": b""}),
    ):
        row = w.probe_space({"id": "SZLHOLDINGS/finance"})
    assert row["source_repo_declared"] is None


@pytest.mark.parametrize("served,expected", [
    (HASH_B, "DECLARED_MISMATCH"),
    (HASH_A, "DECLARED_MATCH_NOT_BYTE_ATTESTED"),
    ("main", "UNAVAILABLE"),
])
def test_a11oy_does_not_conflate_source_claim_and_independent_proof(served, expected):
    row = {"id": "SZLHOLDINGS/a11oy", "sdk": "docker",
           "space_revision": "c" * 40, "metadata_error": None}
    def fake(url, **kwargs):
        if url == w.GITHUB_MAIN:
            return {"sha": HASH_A}, {"http": 200, "error": None}
        if url.endswith("/api/a11oy/v1/honest"):
            return {"git_sha": served}, {"http": 200, "error": None}
        raise AssertionError(f"unexpected public source: {url}")
    with (
        mock.patch.object(w, "get_object", side_effect=fake),
        mock.patch.object(w, "get", return_value={"http": 200, "error": None, "body": b""}),
    ):
        witness = w.a11oy_source_witness(row)
    assert witness["source_claim_state"] == expected
    assert witness["independent_runtime_verification"] is False
    assert witness["release_authority"] == "NOT_PROVEN"
    assert witness["space_revision"] == "c" * 40


def test_index_unknown_keeps_a11oy_authority_unproven():
    with (
        mock.patch.object(w, "get", return_value={"http": None, "error": "TimeoutError", "body": None}),
        mock.patch.object(w, "get_object", return_value=(None, {"http": None, "error": "TimeoutError"})),
    ):
        report = w.census()
    assert report["space_count"] is None and report["a11oy"]["source_claim_state"] == "UNAVAILABLE"
    assert report["production_qualified"] is False
