"""Exercise the real collector, projection and receipt publication call path."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from census import report, receipt

SUBJECT = {"repository": "szl-holdings/szl-org-health", "workflow_sha": "a" * 40,
           "run_id": "123456789", "run_attempt": "2",
           "run_url": "https://github.com/szl-holdings/szl-org-health/actions/runs/123456789"}
ENV = {"GITHUB_REPOSITORY": SUBJECT["repository"], "GITHUB_SHA": SUBJECT["workflow_sha"],
       "GITHUB_RUN_ID": SUBJECT["run_id"], "GITHUB_RUN_ATTEMPT": SUBJECT["run_attempt"]}


def collect():
    with ExitStack() as stack:
        stack.enter_context(patch.dict(report.os.environ, ENV))
        for name in ("github", "huggingface", "sites", "dns"):
            stack.enter_context(patch.object(report, "collect_" + name, return_value={"ok": True}))
        return report.build_report(exposure="internal", use_cache=False)


def make_receipt(snapshot, outcome="success"):
    return receipt.build_receipt(report.serialize_report(snapshot).encode(),
        snapshot_path="census-internal.json", snapshot_load_error=None,
        now=datetime.now(timezone.utc), collector_outcome=outcome,
        expected_github_repositories_minimum=0, credential_presence={}, subject=SUBJECT)


class CollectionBindingTests(unittest.TestCase):
    def tearDown(self):
        report._CACHE.update(data=None, ts=0)

    def test_actual_collection_binds_source_windows_and_run_attempt(self):
        snapshot = collect()
        self.assertTrue(receipt.validate_collection(snapshot, SUBJECT))
        result = make_receipt(snapshot)
        self.assertTrue(result["observations"]["collection_binding_matches"])
        # A correctly identified collection does not prove complete/healthy sources.
        self.assertEqual(result["status"], "FAIL_CLOSED")
        self.assertEqual(set(snapshot["collection"]["source_observations"]), set(receipt.REQUIRED_SOURCES))

    def test_cache_preserves_collection_identity_and_measurement_times(self):
        first = collect()
        with patch.object(report, "collect_github", side_effect=AssertionError("must use cache")):
            cached = report.build_report(exposure="internal")
        self.assertEqual(cached, first)
        second = collect()
        self.assertNotEqual(first["collection"]["id"], second["collection"]["id"])

    def test_collection_mutations_and_retained_history_fail_binding(self):
        original = collect()
        mutations = [
            lambda s: s.pop("collection"),
            lambda s: s["collection"]["subject"].update(run_attempt="1"),
            lambda s: s["collection"]["subject"].update(workflow_sha="b" * 40),
            lambda s: s.update(generated_at="2099-01-01T00:00:00Z"),
            lambda s: s["sources"]["github"].update(ok=False),
            lambda s: s["collection"]["source_observations"]["github"].update(started_at="2000-01-01T00:00:00Z"),
            lambda s: s["collection"]["source_observations"].pop("dns"),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutations.index(mutate)):
                snapshot = copy.deepcopy(original)
                mutate(snapshot)
                self.assertFalse(receipt.validate_collection(snapshot, SUBJECT))

    def test_public_projection_hides_subject_private_digest_and_unknown_metadata(self):
        snapshot = collect()
        snapshot["collection"]["subject"]["repository"] = "private/SENTINEL"
        snapshot["collection"]["private_grants"] = "PRIVATE_SENTINEL"
        projected = report.project_public_report(snapshot)
        self.assertEqual(set(projected["collection"]), {"schema", "id", "started_at", "completed_at"})
        self.assertNotIn("SENTINEL", json.dumps(projected))
        self.assertEqual(projected, report.project_public_report(projected))

    def test_only_exact_projection_is_staged_and_old_artifact_is_withheld(self):
        snapshot = collect()
        raw = report.serialize_report(snapshot).encode()
        public = report.serialize_report(report.project_public_report(snapshot)).encode()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate, destination = root / "snapshot.json", root / "upload.json"
            candidate.write_bytes(public)
            result = receipt.stage_public_snapshot(raw, candidate, destination, make_receipt(snapshot))
            self.assertEqual(result["state"], "FRESH_COLLECTION_BOUND")
            self.assertEqual(destination.read_bytes(), public)
            self.assertEqual(result["sha256"], hashlib.sha256(public).hexdigest())
            retained = json.loads(public)
            retained["sources"]["github"]["data"] = {"stale": "fallback"}
            candidate.write_text(json.dumps(retained))
            result = receipt.stage_public_snapshot(raw, candidate, destination, make_receipt(snapshot))
            self.assertEqual(result["state"], "WITHHELD")
            self.assertFalse(destination.exists())
            candidate.write_bytes(public)
            result = receipt.stage_public_snapshot(raw, candidate, destination, make_receipt(snapshot, "failure"))
            self.assertEqual(result["state"], "WITHHELD")
            self.assertFalse(destination.exists())

    def test_duplicate_keys_nonfinite_and_overflow_json_fail_closed(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}'):
            with self.subTest(raw=raw):
                self.assertEqual(receipt._json_object(raw), ({}, "INVALID_JSON"))

    def test_failed_durable_write_or_replace_never_leaves_upload_candidate(self):
        snapshot = collect()
        raw = report.serialize_report(snapshot).encode()
        public = report.serialize_report(report.project_public_report(snapshot)).encode()
        with tempfile.TemporaryDirectory() as directory:
            candidate, destination = Path(directory) / "snapshot.json", Path(directory) / "upload.json"
            candidate.write_bytes(public)
            for operation in ("fsync", "replace"):
                with self.subTest(operation=operation), patch.object(receipt.os, operation, side_effect=OSError("disk unavailable")):
                    staged = receipt.stage_public_snapshot(raw, candidate, destination, make_receipt(snapshot))
                self.assertEqual(staged["state"], "WITHHELD")
                self.assertFalse(destination.exists())
                self.assertEqual(list(Path(directory).glob("*.tmp")), [])

    def test_stale_and_future_collection_cannot_be_uploaded_under_new_receipt(self):
        snapshot = collect()
        raw = report.serialize_report(snapshot).encode()
        public = report.serialize_report(report.project_public_report(snapshot)).encode()
        with tempfile.TemporaryDirectory() as directory:
            candidate, destination = Path(directory) / "snapshot.json", Path(directory) / "upload.json"
            candidate.write_bytes(public)
            for offset in (timedelta(hours=1), timedelta(hours=-1)):
                with self.subTest(offset=offset):
                    result = receipt.build_receipt(raw, snapshot_path="internal.json", snapshot_load_error=None,
                        now=datetime.now(timezone.utc) + offset, collector_outcome="success",
                        expected_github_repositories_minimum=0, credential_presence={}, subject=SUBJECT)
                    self.assertTrue(result["observations"]["collection_binding_matches"])
                    self.assertFalse(result["observations"]["snapshot_freshness_valid"])
                    staged = receipt.stage_public_snapshot(raw, candidate, destination, result)
                    self.assertEqual(staged["state"], "WITHHELD")
                    self.assertFalse(destination.exists())

    def test_cli_gates_actual_upload_bytes_even_when_overall_governance_fails(self):
        snapshot = collect()
        environment = {"COLLECT_OUTCOME": "success", "EXPECTED_GITHUB_REPOSITORIES_MINIMUM": "0",
                       **{"RECEIPT_" + key.upper(): value for key, value in SUBJECT.items()}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            internal, public, output, evidence = (root / name for name in ("internal.json", "public.json", "upload.json", "receipt.json"))
            internal.write_bytes(report.serialize_report(snapshot).encode("utf-8"))
            public.write_bytes(report.serialize_report(report.project_public_report(snapshot)).encode("utf-8"))
            with redirect_stdout(io.StringIO()):
                status = receipt.main(["--snapshot", str(internal), "--receipt", str(evidence),
                    "--public-snapshot", str(public), "--publish-snapshot", str(output)], environ=environment)
            self.assertEqual(status, 1)
            result = json.loads(evidence.read_text())
            self.assertEqual(result["public_snapshot"]["state"], "FRESH_COLLECTION_BOUND")
            self.assertEqual(output.read_bytes(), public.read_bytes())
            environment["COLLECT_OUTCOME"] = "failure"
            with redirect_stdout(io.StringIO()):
                receipt.main(["--snapshot", str(internal), "--receipt", str(evidence),
                    "--public-snapshot", str(public), "--publish-snapshot", str(output)], environ=environment)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
