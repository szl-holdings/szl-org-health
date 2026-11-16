"""Offline negative controls; fake verification is NEVER a live evidence receipt."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
import tempfile
from pathlib import Path
import unittest
from contextlib import redirect_stdout
from unittest import mock

from tools import pypi_distribution_verification as verifier
from tools import pypi_release_path_audit as audit_module

SPEC = importlib.util.spec_from_file_location("audit_fixture", Path(__file__).with_name("test_pypi_release_path_audit.py"))
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)
PACKAGE, VERSION = fixture.PACKAGE, fixture.VERSION
EXPECTED = ("GitHub", "szl-holdings/release-example", "publish-pypi.yml", "pypi")
SOURCE = "a" * 40


def release():
    files = {
        name: {"filename": name, "url": "https://files.pythonhosted.org/packages/aa/bb/" + name,
               "digests": {"sha256": fixture.FILE_SHA256[name]}}
        for name in (fixture.WHEEL, fixture.SDIST)
    }
    proofs = {name: fixture.attestation(name) for name in files}
    return files, proofs


class VerificationTests(unittest.TestCase):
    def run_verify(self, files=None, proofs=None, **kwargs):
        default_files, default_proofs = release()
        if files is None:
            files = default_files
        if proofs is None:
            proofs = default_proofs
        with mock.patch.object(verifier.importlib.metadata, "version", return_value="synthetic-test-only"), \
                mock.patch.object(verifier, "distribution_digest", side_effect=lambda url, name: (fixture.FILE_SHA256[name], 12)), \
                mock.patch.object(verifier, "_verify_attestation", return_value=SOURCE):
            return verifier.verify_release(PACKAGE, VERSION, files, proofs, kwargs.get("publisher", EXPECTED))

    def test_complete_exact_release_binds_every_file(self):
        result = self.run_verify()
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(set(result["files"]), {fixture.WHEEL, fixture.SDIST})
        self.assertEqual(result["source_digests"], [SOURCE])
        self.assertIs(result["publisher_environment_cryptographically_verified"], False)
        self.assertIs(result["archives_installed_or_executed"], False)

    def test_empty_release_fails(self):
        self.assertEqual(self.run_verify({}, {})["status"], "FAILED")

    def test_missing_sdist_provenance_fails(self):
        files, proofs = release()
        del proofs[fixture.SDIST]
        self.assertEqual(self.run_verify(files, proofs)["status"], "FAILED")

    def test_extra_provenance_fails(self):
        files, proofs = release()
        proofs["unrelated.whl"] = {}
        self.assertEqual(self.run_verify(files, proofs)["status"], "FAILED")

    def test_wheel_alone_fails(self):
        files, proofs = release()
        del files[fixture.SDIST]
        del proofs[fixture.SDIST]
        self.assertEqual(self.run_verify(files, proofs)["status"], "FAILED")

    def test_wrong_release_version_never_passes(self):
        files, proofs = release()
        with mock.patch.object(verifier.importlib.metadata, "version", return_value="synthetic"):
            self.assertNotEqual(verifier.verify_release(PACKAGE, "9.9.9", files, proofs, EXPECTED)["status"], "VERIFIED")

    def test_mismatched_filename_metadata_fails(self):
        files, proofs = release()
        files[fixture.WHEEL]["filename"] = fixture.SDIST
        self.assertEqual(self.run_verify(files, proofs)["status"], "FAILED")

    def test_missing_digest_fails(self):
        files, proofs = release()
        files[fixture.WHEEL]["digests"] = {}
        self.assertEqual(self.run_verify(files, proofs)["status"], "FAILED")

    def test_wrong_publisher_each_field_fails(self):
        for key in ("kind", "repository", "workflow", "environment"):
            with self.subTest(key=key):
                files, proofs = release()
                proofs[fixture.WHEEL]["attestation_bundles"][0]["publisher"][key] = "wrong"
                self.assertEqual(self.run_verify(files, proofs)["status"], "FAILED")

    def test_empty_attestations_fails(self):
        files, proofs = release()
        proofs[fixture.WHEEL]["attestation_bundles"][0]["attestations"] = []
        self.assertEqual(self.run_verify(files, proofs)["status"], "FAILED")

    def test_empty_bundles_fails(self):
        files, proofs = release()
        proofs[fixture.WHEEL]["attestation_bundles"] = []
        self.assertEqual(self.run_verify(files, proofs)["status"], "FAILED")

    def test_partial_live_verification_cannot_pass(self):
        files, proofs = release()
        with mock.patch.object(verifier.importlib.metadata, "version", return_value="synthetic"), \
                mock.patch.object(verifier, "distribution_digest", side_effect=lambda url, name: (fixture.FILE_SHA256[name], 12)), \
                mock.patch.object(verifier, "_verify_attestation", side_effect=[SOURCE, verifier.UnavailableEvidence("offline")]):
            result = verifier.verify_release(PACKAGE, VERSION, files, proofs, EXPECTED)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(len(result["files"]), 1)

    def test_bad_signature_fails_not_passes(self):
        files, proofs = release()
        with mock.patch.object(verifier.importlib.metadata, "version", return_value="synthetic"), \
                mock.patch.object(verifier, "distribution_digest", return_value=(fixture.FILE_SHA256[fixture.WHEEL], 12)), \
                mock.patch.object(verifier, "_verify_attestation", side_effect=verifier.RejectedEvidence("signature")):
            result = verifier.verify_release(PACKAGE, VERSION, files, proofs, EXPECTED)
        self.assertEqual(result["status"], "FAILED")

    def test_downloaded_bytes_must_match_metadata(self):
        files, proofs = release()
        with mock.patch.object(verifier.importlib.metadata, "version", return_value="synthetic"), \
                mock.patch.object(verifier, "distribution_digest", return_value=("0" * 64, 12)), \
                mock.patch.object(verifier, "_verify_attestation") as verify:
            result = verifier.verify_release(PACKAGE, VERSION, files, proofs, EXPECTED)
        self.assertEqual(result["status"], "FAILED")
        verify.assert_not_called()

    def test_conflicting_source_commits_fail(self):
        files, proofs = release()
        with mock.patch.object(verifier.importlib.metadata, "version", return_value="synthetic"), \
                mock.patch.object(verifier, "distribution_digest", side_effect=lambda url, name: (fixture.FILE_SHA256[name], 12)), \
                mock.patch.object(verifier, "_verify_attestation", side_effect=[SOURCE, "b" * 40]):
            self.assertEqual(verifier.verify_release(PACKAGE, VERSION, files, proofs, EXPECTED)["status"], "FAILED")

    def test_missing_dependency_is_unknown(self):
        files, proofs = release()
        with mock.patch.object(verifier.importlib.metadata, "version", side_effect=ModuleNotFoundError()):
            self.assertEqual(verifier.verify_release(PACKAGE, VERSION, files, proofs, EXPECTED)["status"], "UNKNOWN")

    def test_release_byte_budget_fails_closed(self):
        with mock.patch.object(verifier, "MAX_RELEASE_BYTES", 1):
            self.assertEqual(self.run_verify()["status"], "FAILED")

    def test_malformed_expected_identity_fails(self):
        self.assertEqual(self.run_verify(publisher=("GitHub",))["status"], "FAILED")


class DownloadContractTests(unittest.TestCase):
    def test_untrusted_urls_never_opened(self):
        bad = ["http://files.pythonhosted.org/packages/a/" + fixture.WHEEL,
               "https://files.pythonhosted.org.evil.example/packages/a/" + fixture.WHEEL,
               "https://user:secret@files.pythonhosted.org/packages/a/" + fixture.WHEEL,
               "https://files.pythonhosted.org:443/packages/a/" + fixture.WHEEL,
               "https://files.pythonhosted.org/packages/../" + fixture.WHEEL,
               "https://files.pythonhosted.org/packages/a/" + fixture.WHEEL + "?token=x",
               "https://files.pythonhosted.org/packages/a/other.whl", None]
        with mock.patch.object(verifier.urllib.request, "build_opener") as open_:
            for url in bad:
                with self.subTest(url=url), self.assertRaises(verifier.RejectedEvidence):
                    verifier.distribution_digest(url, fixture.WHEEL)
        open_.assert_not_called()

    def test_redirect_is_refused(self):
        with self.assertRaises(verifier.UnavailableEvidence):
            verifier.NoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.example")

    def response(self, body=b"synthetic archive", length=None):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        self.url = "https://files.pythonhosted.org/packages/a/" + fixture.WHEEL
        response.geturl.return_value = self.url
        response.headers = {} if length is None else {"Content-Length": str(length)}
        stream = io.BytesIO(body)
        response.read1.side_effect = stream.read
        return response

    def test_exact_stream_hash_and_no_auth(self):
        response = self.response()
        with mock.patch.object(verifier.urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = response
            sha, count = verifier.distribution_digest(self.url, fixture.WHEEL)
            request = opener.return_value.open.call_args.args[0]
        self.assertEqual(sha, hashlib.sha256(b"synthetic archive").hexdigest())
        self.assertEqual(count, 17)
        self.assertNotIn("Authorization", request.headers)

    def test_oversize_response_fails(self):
        response = self.response(length=verifier.MAX_FILE_BYTES + 1)
        with mock.patch.object(verifier.urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = response
            with self.assertRaises(verifier.RejectedEvidence):
                verifier.distribution_digest(self.url, fixture.WHEEL)

    def test_truncated_response_unknown(self):
        response = self.response(length=50)
        with mock.patch.object(verifier.urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = response
            with self.assertRaises(verifier.UnavailableEvidence):
                verifier.distribution_digest(self.url, fixture.WHEEL)


class AuditCompositionTests(unittest.TestCase):
    def audit(self, crypto, *, enabled=True, responses=None):
        responses = fixture.fixture() if responses is None else responses
        results = []
        with mock.patch.object(verifier, "verify_release", return_value=crypto) as verify, redirect_stdout(io.StringIO()):
            audit_module.audit_release_repo(fixture.FakeHttp(responses), fixture.ORG,
                {"name": PACKAGE, "repo": fixture.REPO, "status": "published"},
                {"render": lambda spec: f'SZL_PACKAGES: "{spec}"\n', "gate_sha256": fixture.sha256(fixture.GATE)},
                results, {}, verify_attestations=enabled)
        return {r["check"]: r for r in results}, verify

    def crypto(self):
        return {"status": "VERIFIED", "source_digests": [SOURCE], "files": {name: {"sha256": fixture.FILE_SHA256[name], "bytes": 12,
                "attestations_verified": 1, "source_digest": SOURCE, "status": "VERIFIED"}
                for name in (fixture.WHEEL, fixture.SDIST)},
                "detail": "SYNTHETIC_TEST_ONLY"}

    def test_live_crypto_resolves_provenance_and_tag_not_environment(self):
        rows, verify = self.audit(self.crypto())
        self.assertEqual(rows["pypi:provenance"]["status"], "PASS")
        self.assertEqual(rows["github:release-tag"]["status"], "PASS")
        self.assertEqual(rows["pypi:publisher-repository-workflow"]["status"], "PASS")
        self.assertEqual(rows["pypi:publisher-identity"]["status"], "UNKNOWN")
        self.assertIn("environment", rows["pypi:publisher-identity"]["detail"])
        verify.assert_called_once()

    def test_default_metadata_mode_does_not_call_verifier(self):
        rows, verify = self.audit(self.crypto(), enabled=False)
        verify.assert_not_called()
        self.assertEqual(rows["pypi:provenance"]["status"], "UNKNOWN")
        self.assertEqual(rows["github:release-tag"]["status"], "UNKNOWN")

    def test_success_for_different_release_cannot_promote(self):
        crypto = self.crypto()
        del crypto["files"][fixture.SDIST]
        rows, _ = self.audit(crypto)
        self.assertEqual(rows["pypi:provenance"]["status"], "FAIL")
        self.assertNotEqual(rows["github:release-tag"]["status"], "PASS")

    def test_incomplete_per_file_evidence_cannot_promote(self):
        for field in ("sha256", "bytes", "attestations_verified", "source_digest", "status"):
            with self.subTest(field=field):
                crypto = self.crypto()
                del crypto["files"][fixture.WHEEL][field]
                rows, _ = self.audit(crypto)
                self.assertEqual(rows["pypi:provenance"]["status"], "FAIL")

    def test_wrong_verified_source_cannot_promote(self):
        crypto = self.crypto()
        crypto["source_digests"] = ["b" * 40]
        rows, _ = self.audit(crypto)
        self.assertEqual(rows["pypi:provenance"]["status"], "FAIL")

    def test_bad_metadata_does_not_call_verifier(self):
        responses = fixture.fixture()
        responses[fixture.SIMPLE][1]["files"].pop()
        rows, verify = self.audit(self.crypto(), responses=responses)
        verify.assert_not_called()
        self.assertEqual(rows["pypi:provenance"]["status"], "FAIL")

    def test_missing_crypto_stays_unknown(self):
        rows, _ = self.audit({"status": "UNKNOWN", "detail": "unavailable"})
        self.assertEqual(rows["pypi:provenance"]["status"], "UNKNOWN")
        self.assertEqual(rows["github:release-tag"]["status"], "UNKNOWN")

    def test_opaque_ruleset_still_blocks_even_with_verified_artifacts(self):
        responses = fixture.fixture()
        del responses[fixture.RULESET_DETAIL][1]["bypass_actors"]
        rows, _ = self.audit(self.crypto(), responses=responses)
        self.assertEqual(rows["github:tag-ruleset"]["status"], "UNKNOWN")


class EmptySelectionTests(unittest.TestCase):
    def test_empty_manifest_fails_instead_of_vacuous_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"owner": {"github_org": "szl-holdings"}, "packages": []}), encoding="utf-8")
            args = ["audit", "--manifest", str(manifest), "--report", str(root / "report.json"),
                    "--summary", str(root / "summary.md"), "--canonical-dir",
                    str(Path(__file__).resolve().parents[1] / "governance/pypi/canonical")]
            with mock.patch.object(sys, "argv", args), redirect_stdout(io.StringIO()):
                self.assertEqual(audit_module.main(), 1)
            result = json.loads((root / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(result["verdict"], "FAIL")
            self.assertIn("No eligible", (root / "summary.md").read_text(encoding="utf-8"))

    def test_unknown_selected_package_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "manifest.json"
            path.write_text(json.dumps({"owner": {"github_org": "szl-holdings"}, "packages": []}), encoding="utf-8")
            with mock.patch.object(sys, "argv", ["audit", "--manifest", str(path), "--only", "not-a-package"]), \
                    mock.patch.object(sys, "stderr", io.StringIO()), self.assertRaises(SystemExit) as err:
                audit_module.main()
            self.assertEqual(err.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
