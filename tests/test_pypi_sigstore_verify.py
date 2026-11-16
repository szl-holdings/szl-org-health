"""Standalone report boundary tests; synthetic fixtures are not live receipts."""
from __future__ import annotations

import copy
import io
import json
import sys
import tempfile
import unittest
import unittest.mock as mock
from contextlib import redirect_stdout
from pathlib import Path

from tools import pypi_sigstore_verify as cli

SOURCE = "a" * 40
OTHER = "b" * 40
PACKAGE = {"name": "example", "repo": "example", "status": "published"}
WHEEL = "example-1.2.3-py3-none-any.whl"
SDIST = "example-1.2.3.tar.gz"


def metadata():
    return {"info": {"version": "1.2.3"}, "urls": [
        {"filename": name, "url": "https://files.pythonhosted.org/packages/aa/" + name,
         "digests": {"sha256": "c" * 64}} for name in (WHEEL, SDIST)
    ]}


def synthetic_verification():
    return {"status": "VERIFIED", "source_digests": [SOURCE],
            "detail": "SYNTHETIC_TEST_ONLY", "verifier_versions": {"test": "synthetic"},
            "publisher_environment_cryptographically_verified": True,
            "publisher_environment": "pypi", "publisher_environment_evidence": cli.ENVIRONMENT_EVIDENCE,
            "files": {name: {"sha256": "c" * 64, "bytes": 12, "source_digest": SOURCE,
                            "attestations_verified": 1, "status": "VERIFIED",
                            "publisher_environment": "pypi",
                            "publisher_environment_evidence": cli.ENVIRONMENT_EVIDENCE}
                      for name in (WHEEL, SDIST)}}


class PackageBoundaryTests(unittest.TestCase):
    def run_package(self, *, meta=None, result=None, tag=SOURCE, spec=None, provenance_status=200):
        meta = metadata() if meta is None else meta
        result = synthetic_verification() if result is None else result
        def fake_fetch(url, token=None):
            self.assertIsNone(token, "GitHub credentials must not reach public PyPI metadata")
            return (200, meta) if url.endswith("/json") else (provenance_status, {"test": "synthetic"})
        results = []
        with mock.patch.object(cli, "fetch", side_effect=fake_fetch) as fetch, \
                mock.patch.object(cli, "verify_release", return_value=result) as verify, \
                mock.patch.object(cli, "release_tag_commit", return_value=tag) as tag_lookup:
            cli.verify_package("szl-holdings", spec or PACKAGE, "synthetic-gh-token", results, False)
        return results[0], fetch, verify, tag_lookup

    def test_complete_report_retains_exact_files_and_scope(self):
        row, fetch, verify, tag = self.run_package()
        self.assertEqual(row["status"], "VERIFIED")
        self.assertEqual(set(row["files"]), {WHEEL, SDIST})
        self.assertIs(row["publisher_environment_cryptographically_verified"], True)
        self.assertEqual(row["publisher_environment_evidence"], cli.ENVIRONMENT_EVIDENCE)
        self.assertEqual(row["verification_scope"], cli.VERIFICATION_SCOPE)
        self.assertEqual(sum(call.args[0].endswith("/json") for call in fetch.call_args_list), 1)
        self.assertEqual(verify.call_args.args[2], {f["filename"]: f for f in metadata()["urls"]})
        self.assertEqual(set(verify.call_args.args[3]), {WHEEL, SDIST})
        tag.assert_called_once_with("szl-holdings", "example", "v1.2.3", "synthetic-gh-token")

    def test_invalid_file_lists_rejected_before_verification(self):
        for rows in ([], None, [{}], [{"filename": WHEEL}] * 2):
            with self.subTest(rows=rows):
                meta = metadata()
                meta["urls"] = rows
                row, _, verify, tag = self.run_package(meta=meta)
                self.assertEqual(row["status"], "FAILED")
                verify.assert_not_called()
                tag.assert_not_called()

    def test_inaccessible_provenance_is_unknown(self):
        row, _, verify, tag = self.run_package(provenance_status=503)
        self.assertEqual(row["status"], "UNKNOWN")
        verify.assert_not_called()
        tag.assert_not_called()

    def test_verification_failure_and_unavailability_never_pass(self):
        for state in ("FAILED", "UNKNOWN"):
            with self.subTest(state=state):
                row, _, _, tag = self.run_package(result={"status": state, "detail": "synthetic failure"})
                self.assertEqual(row["status"], state)
                tag.assert_not_called()

    def test_partial_verified_coverage_cannot_qualify(self):
        verified = synthetic_verification()
        del verified["files"][SDIST]
        row, _, _, tag = self.run_package(result=verified)
        self.assertEqual(row["status"], "FAILED")
        tag.assert_not_called()

    def test_source_identity_must_be_single_immutable_digest(self):
        for sources in ([], [SOURCE, OTHER], ["not-a-commit"]):
            verified = synthetic_verification()
            verified["source_digests"] = sources
            row, _, _, tag = self.run_package(result=verified)
            self.assertEqual(row["status"], "FAILED")
            tag.assert_not_called()

    def test_unsigned_boolean_only_or_wrong_environment_cannot_qualify(self):
        for field, value in (("publisher_environment_cryptographically_verified", False),
                             ("publisher_environment_evidence", "PYPI_METADATA_ONLY"),
                             ("publisher_environment", "wrong")):
            with self.subTest(field=field):
                verified = synthetic_verification()
                verified[field] = value
                row, _, _, tag = self.run_package(result=verified)
                self.assertEqual(row["status"], "FAILED")
                tag.assert_not_called()
        verified = synthetic_verification()
        del verified["files"][WHEEL]["publisher_environment"]
        row, _, _, _ = self.run_package(result=verified)
        self.assertEqual(row["status"], "FAILED")

    def test_tag_mismatch_fails(self):
        row, _, _, _ = self.run_package(tag=OTHER)
        self.assertEqual(row["status"], "FAILED")

    def test_unavailable_tag_is_unknown(self):
        row, _, _, _ = self.run_package(tag=None)
        self.assertEqual(row["status"], "UNKNOWN")

    def test_recorded_exception_still_cannot_pass(self):
        package = dict(PACKAGE, tag_exception={"tag": "v1.2.3", "tag_commit": OTHER, "attested_commit": SOURCE})
        row, _, _, _ = self.run_package(tag=OTHER, spec=package)
        self.assertEqual(row["status"], "UNKNOWN")
        self.assertIn("exception", row["detail"])

    def test_sensitive_exception_text_does_not_reach_report(self):
        rows = []
        with mock.patch.object(cli, "fetch", side_effect=RuntimeError("secret-do-not-log")):
            cli.verify_package("szl-holdings", PACKAGE, "synthetic-token", rows, False)
        self.assertEqual(rows[0]["status"], "UNKNOWN")
        self.assertNotIn("secret-do-not-log", json.dumps(rows))


class TagBoundaryTests(unittest.TestCase):
    def test_annotated_tag_must_resolve_to_commit(self):
        with mock.patch.object(cli, "fetch", side_effect=[
            (200, {"object": {"type": "tag", "sha": OTHER}}),
            (200, {"sha": OTHER, "object": {"type": "commit", "sha": SOURCE}}),
        ]):
            self.assertEqual(cli.release_tag_commit("org", "repo", "v1", "synthetic"), SOURCE)

    def test_unavailable_annotated_target_is_not_a_commit(self):
        with mock.patch.object(cli, "fetch", side_effect=[
            (200, {"object": {"type": "tag", "sha": OTHER}}), (404, None),
        ]):
            self.assertIsNone(cli.release_tag_commit("org", "repo", "v1", None))

    def test_malformed_ref_and_noncommit_target_do_not_qualify(self):
        for obj in (None, {}, {"type": "blob", "sha": SOURCE}, {"type": "commit", "sha": "123"}):
            with self.subTest(obj=obj), mock.patch.object(cli, "fetch", return_value=(200, {"object": obj})):
                self.assertIsNone(cli.release_tag_commit("org", "repo", "v1", None))

    def test_cyclic_tag_chain_stops(self):
        with mock.patch.object(cli, "fetch", side_effect=[
            (200, {"object": {"type": "tag", "sha": OTHER}}),
            (200, {"sha": OTHER, "object": {"type": "tag", "sha": OTHER}}),
        ]) as fetch:
            self.assertIsNone(cli.release_tag_commit("org", "repo", "v1", None))
            self.assertEqual(fetch.call_count, 2)


class FetchBoundaryTests(unittest.TestCase):
    def response(self, url, body=b"{}", returned_url=None):
        result = mock.MagicMock()
        result.__enter__.return_value = result
        result.status = 200
        result.geturl.return_value = returned_url or url
        result.headers = {}
        result.read.return_value = body
        return result

    def test_untrusted_urls_never_open(self):
        urls = ["http://api.github.com/repos/x", "https://api.github.com.evil.example/x",
                "https://token@api.github.com/x", "https://api.github.com/x?secret=1"]
        with mock.patch.object(cli.urllib.request, "build_opener") as opener:
            for url in urls:
                with self.subTest(url=url), self.assertRaises(cli.FetchError):
                    cli.fetch(url, "synthetic", retries=1)
        opener.assert_not_called()

    def test_token_is_sent_only_to_github_and_reads_are_bounded(self):
        for host in ("api.github.com", "pypi.org"):
            url = "https://" + host + "/x"
            response = self.response(url)
            with mock.patch.object(cli.urllib.request, "build_opener") as opener:
                opener.return_value.open.return_value = response
                self.assertEqual(cli.fetch(url, "synthetic", retries=1), (200, {}))
                request = opener.return_value.open.call_args.args[0]
                self.assertEqual("Authorization" in request.headers, host == "api.github.com")
                self.assertIsInstance(opener.call_args.args[0], cli.NoRedirect)
            response.read.assert_called_once_with(cli.MAX_METADATA_BYTES + 1)

    def test_changed_response_identity_and_oversize_are_refused(self):
        url = "https://pypi.org/x"
        for response in (self.response(url, returned_url="https://evil.example"),
                         self.response(url, body=b"12345")):
            with mock.patch.object(cli, "MAX_METADATA_BYTES", 4), \
                    mock.patch.object(cli.urllib.request, "build_opener") as opener:
                opener.return_value.open.return_value = response
                with self.assertRaises(cli.FetchError):
                    cli.fetch(url, retries=1)


class SelectionBoundaryTests(unittest.TestCase):
    def run_main(self, packages, extra=()):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            (path / "manifest.json").write_text(json.dumps({
                "owner": {"github_org": "szl-holdings"}, "packages": packages,
            }), encoding="utf-8")
            args = ["verify", "--manifest", str(path / "manifest.json"),
                    "--report", str(path / "report.json"), "--summary", str(path / "summary.md"), *extra]
            with mock.patch.object(sys, "argv", args), redirect_stdout(io.StringIO()), \
                    mock.patch.object(sys, "stderr", io.StringIO()):
                status = cli.main()
            return status, json.loads((path / "report.json").read_text(encoding="utf-8")), (path / "summary.md").read_text(encoding="utf-8")

    def test_empty_manifest_fails(self):
        status, report, summary = self.run_main([])
        self.assertEqual(status, 1)
        self.assertEqual(report["verdict"], "FAIL")
        self.assertIn("No published packages", summary)
        self.assertIs(report["publisher_environment_cryptographically_verified"], False)

    def test_unknown_and_unpublished_selection_rejected(self):
        for packages, selected in (([], "missing"), ([dict(PACKAGE, status="internal")], "example")):
            with self.subTest(selected=selected), self.assertRaises(SystemExit) as raised:
                self.run_main(packages, ("--only", selected))
            self.assertEqual(raised.exception.code, 2)

    def test_success_summary_declares_signed_environment_scope_not_readiness(self):
        def fake_package(org, spec, token, results, verbose):
            results.append({"package": "example", "status": "VERIFIED", "detail": "SYNTHETIC_TEST_ONLY",
                            "publisher_environment_cryptographically_verified": True})
        with mock.patch.object(cli, "verify_package", side_effect=fake_package):
            status, report, summary = self.run_main([copy.deepcopy(PACKAGE)])
        self.assertEqual(status, 0)
        self.assertEqual(report["verification_scope"], cli.VERIFICATION_SCOPE)
        self.assertIn("signed Fulcio extension on every attestation", summary)
        self.assertIn("does not establish production readiness", summary)


if __name__ == "__main__":
    unittest.main()
