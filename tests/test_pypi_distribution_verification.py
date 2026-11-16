"""Offline negative controls; fake verification is NEVER a live evidence receipt."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import types
import unittest
import unittest.mock as mock
from contextlib import contextmanager, redirect_stdout
from pathlib import Path

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


MISSING_ENVIRONMENT = object()


@contextmanager
def synthetic_attestation_library(*, fail_verify=False):
    """Exercise the real extraction/order logic, never create live evidence."""
    events, certificates = [], {}

    class SyntheticVerificationError(Exception):
        pass

    class SyntheticExtensionNotFound(Exception):
        pass

    class SyntheticAttestation:
        def __init__(self, raw):
            self.raw, self.verified = raw, False
            encoded = b"SYNTHETIC_TEST_CERTIFICATE_" + str(len(certificates)).encode("ascii")
            self.verification_material = types.SimpleNamespace(certificate=encoded)
            certificates[encoded] = self

        @classmethod
        def model_validate(cls, raw):
            events.append("model_validate")
            return cls(raw)

        def verify(self, publisher, distribution):
            events.append("verify")
            if fail_verify:
                raise SyntheticVerificationError("synthetic invalid signature")
            self.verified = True
            return verifier.PUBLISH_PREDICATE, {}

        @property
        def certificate_claims(self):
            if not self.verified:
                raise AssertionError("claims accessed before verification")
            events.append("source_claim")
            return {verifier.SOURCE_DIGEST_OID: self.raw.get("_synthetic_source", SOURCE)}

    def load_certificate(encoded):
        record = certificates[encoded]
        if not record.verified:
            raise AssertionError("certificate parsed before verification")
        events.append("load_same_certificate")

        def extension(oid):
            if oid != verifier.DEPLOYMENT_ENVIRONMENT_OID:
                raise AssertionError("unexpected extension")
            events.append("deployment_environment")
            value = record.raw.get("_synthetic_environment_der", b"\x0c\x04pypi")
            if value is MISSING_ENVIRONMENT:
                raise SyntheticExtensionNotFound()
            return types.SimpleNamespace(value=types.SimpleNamespace(value=value))

        return types.SimpleNamespace(extensions=types.SimpleNamespace(get_extension_for_oid=extension))

    pypi = types.ModuleType("pypi_attestations")
    pypi.Attestation = SyntheticAttestation
    pypi.Distribution = lambda **kwargs: types.SimpleNamespace(**kwargs)
    pypi.GitHubPublisher = lambda **kwargs: types.SimpleNamespace(**kwargs)
    pypi.VerificationError = SyntheticVerificationError
    cryptography = types.ModuleType("cryptography")
    cryptography.x509 = types.SimpleNamespace(
        load_der_x509_certificate=load_certificate, ObjectIdentifier=lambda value: value,
        ExtensionNotFound=SyntheticExtensionNotFound,
    )
    with mock.patch.dict(sys.modules, {"pypi_attestations": pypi, "cryptography": cryptography}):
        yield events


def synthetic_filename(filename, package, version):
    if package != PACKAGE or version != VERSION or filename not in (fixture.WHEEL, fixture.SDIST):
        raise verifier.RejectedEvidence("synthetic filename identity mismatch")


def synthetic_release_verification(files, proofs, publisher=EXPECTED):
    with mock.patch.object(verifier.importlib.metadata, "version", return_value="synthetic-test-only"), \
            mock.patch.object(verifier, "distribution_digest", side_effect=lambda url, name: (fixture.FILE_SHA256[name], 12)), \
            mock.patch.object(verifier, "_check_filename", side_effect=synthetic_filename), \
            synthetic_attestation_library():
        return verifier.verify_release(PACKAGE, VERSION, files, proofs, publisher)


class VerificationTests(unittest.TestCase):
    def setUp(self):
        # These are contract tests, not packaging/Sigstore integration tests.
        # The CI's stdlib-only runner must not inherit optional laptop packages.
        # Production has no injected-parser flag; live verification exercises
        # the real parser and cryptographic library separately.
        def synthetic_filename(filename, package, version):
            if package != PACKAGE or version != VERSION or filename not in (fixture.WHEEL, fixture.SDIST):
                raise verifier.RejectedEvidence("synthetic filename identity mismatch")
        patcher = mock.patch.object(verifier, "_check_filename", side_effect=synthetic_filename)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_verify(self, files=None, proofs=None, **kwargs):
        default_files, default_proofs = release()
        if files is None:
            files = default_files
        if proofs is None:
            proofs = default_proofs
        return synthetic_release_verification(files, proofs, kwargs.get("publisher", EXPECTED))

    def test_complete_exact_release_binds_every_file(self):
        result = self.run_verify()
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(set(result["files"]), {fixture.WHEEL, fixture.SDIST})
        self.assertEqual(result["source_digests"], [SOURCE])
        self.assertIs(result["publisher_environment_cryptographically_verified"], True)
        self.assertEqual(result["publisher_environment"], EXPECTED[3])
        self.assertEqual(result["publisher_environment_evidence"], verifier.ENVIRONMENT_EVIDENCE)
        for row in result["files"].values():
            self.assertEqual(row["publisher_environment"], EXPECTED[3])
            self.assertEqual(row["publisher_environment_evidence"], verifier.ENVIRONMENT_EVIDENCE)
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
                mock.patch.object(verifier, "_verify_attestation", side_effect=[verifier.VerifiedAttestation(SOURCE, EXPECTED[3]), verifier.UnavailableEvidence("offline")]):
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
                mock.patch.object(verifier, "_verify_attestation", side_effect=[verifier.VerifiedAttestation(SOURCE, EXPECTED[3]), verifier.VerifiedAttestation("b" * 40, EXPECTED[3])]):
            self.assertEqual(verifier.verify_release(PACKAGE, VERSION, files, proofs, EXPECTED)["status"], "FAILED")

    def test_missing_or_malformed_signed_environment_remains_unknown(self):
        for environment in (MISSING_ENVIRONMENT, None, b"\x0c\x00", b"\x0c\x04pypiTRAILER", b"\x0c\x01\xff"):
            with self.subTest(environment=repr(environment)):
                files, proofs = release()
                proofs[fixture.WHEEL]["attestation_bundles"][0]["attestations"][0]["_synthetic_environment_der"] = environment
                result = self.run_verify(files, proofs)
                self.assertEqual(result["status"], "UNKNOWN")
                self.assertIs(result["publisher_environment_cryptographically_verified"], False)
                self.assertEqual(result["publisher_environment_evidence"], "UNAVAILABLE")

    def test_wrong_signed_environment_fails_despite_matching_pypi_metadata(self):
        files, proofs = release()
        proofs[fixture.WHEEL]["attestation_bundles"][0]["attestations"][0]["_synthetic_environment_der"] = b"\x0c\x07staging"
        result = self.run_verify(files, proofs)
        self.assertEqual(result["status"], "FAILED")
        self.assertIs(result["publisher_environment_cryptographically_verified"], False)

    def test_every_attestation_must_have_the_signed_environment(self):
        files, proofs = release()
        attestations = proofs[fixture.SDIST]["attestation_bundles"][0]["attestations"]
        attestations.append({**attestations[0], "_synthetic_environment_der": MISSING_ENVIRONMENT})
        result = self.run_verify(files, proofs)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIs(result["publisher_environment_cryptographically_verified"], False)

    def test_source_only_or_boolean_only_verifier_stub_cannot_gain_environment_pass(self):
        files, proofs = release()
        for stub in (SOURCE, {"source_digest": SOURCE, "publisher_environment_cryptographically_verified": True}):
            with self.subTest(stub=stub), mock.patch.object(verifier, "_verify_attestation", return_value=stub):
                result = self.run_verify(files, proofs)
            self.assertEqual(result["status"], "FAILED")
            self.assertIs(result["publisher_environment_cryptographically_verified"], False)

    def test_missing_dependency_is_unknown(self):
        files, proofs = release()
        with mock.patch.object(verifier.importlib.metadata, "version", side_effect=ModuleNotFoundError()):
            self.assertEqual(verifier.verify_release(PACKAGE, VERSION, files, proofs, EXPECTED)["status"], "UNKNOWN")

    def test_release_byte_budget_fails_closed(self):
        with mock.patch.object(verifier, "MAX_RELEASE_BYTES", 1):
            self.assertEqual(self.run_verify()["status"], "FAILED")

    def test_malformed_expected_identity_fails(self):
        self.assertEqual(self.run_verify(publisher=("GitHub",))["status"], "FAILED")


class SignedEnvironmentClaimTests(unittest.TestCase):
    def test_claim_is_read_from_same_certificate_only_after_verification(self):
        with synthetic_attestation_library() as events:
            value = verifier._verify_attestation({}, fixture.WHEEL, fixture.FILE_SHA256[fixture.WHEEL], EXPECTED)
        self.assertEqual(value, verifier.VerifiedAttestation(SOURCE, EXPECTED[3]))
        self.assertEqual(events, ["model_validate", "verify", "source_claim", "load_same_certificate", "deployment_environment"])

    def test_failed_cryptographic_verification_never_reads_claims(self):
        with synthetic_attestation_library(fail_verify=True) as events, self.assertRaises(verifier.RejectedEvidence):
            verifier._verify_attestation({}, fixture.WHEEL, fixture.FILE_SHA256[fixture.WHEEL], EXPECTED)
        self.assertEqual(events, ["model_validate", "verify"])

    def test_strict_der_utf8_string_supports_unicode_and_long_form(self):
        self.assertEqual(verifier._decode_environment_der(b"\x0c\x04pypi"), "pypi")
        value = "production-" + "\u03bb"
        payload = value.encode("utf-8")
        self.assertEqual(verifier._decode_environment_der(b"\x0c" + bytes([len(payload)]) + payload), value)
        self.assertEqual(verifier._decode_environment_der(b"\x0c\x81\x80" + b"x" * 128), "x" * 128)

    def test_malformed_noncanonical_or_unbounded_der_is_unavailable(self):
        values = (
            None, "pypi", b"", b"\x0c", b"\x0c\x00", b"\x16\x04pypi",
            b"\x0c\x04pyp", b"\x0c\x04pypiX", b"\x0c\x80pypi",
            b"\x0c\x81\x04pypi", b"\x0c\x82\x00\x80" + b"x" * 128,
            b"\x0c\x01\xff", b"\x0c\x01\x00", b"\x0c\x01\x7f",
            b"\x0c\x82\x01\x00" + b"x" * 256,
            b"\x0c\x82\x04\x01" + b"x" * 1025,
        )
        for value in values:
            with self.subTest(value=repr(value)[:60]), self.assertRaises(verifier.UnavailableEvidence):
                verifier._decode_environment_der(value)


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
        files, proofs = release()
        return synthetic_release_verification(files, proofs)

    def test_live_crypto_requires_signed_environment_for_full_identity(self):
        rows, verify = self.audit(self.crypto())
        self.assertEqual(rows["pypi:provenance"]["status"], "PASS")
        self.assertEqual(rows["github:release-tag"]["status"], "PASS")
        self.assertEqual(rows["pypi:publisher-repository-workflow"]["status"], "PASS")
        self.assertEqual(rows["pypi:publisher-identity"]["status"], "PASS")
        self.assertIn("signed release certificate", rows["pypi:publisher-identity"]["detail"])
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
        for field in ("sha256", "bytes", "attestations_verified", "source_digest", "status",
                      "publisher_environment", "publisher_environment_evidence"):
            with self.subTest(field=field):
                crypto = self.crypto()
                del crypto["files"][fixture.WHEEL][field]
                rows, _ = self.audit(crypto)
                self.assertEqual(rows["pypi:provenance"]["status"], "FAIL")

    def test_source_only_or_boolean_only_environment_result_cannot_promote(self):
        for field in ("publisher_environment", "publisher_environment_evidence",
                      "publisher_environment_cryptographically_verified"):
            with self.subTest(field=field):
                crypto = self.crypto()
                del crypto[field]
                rows, _ = self.audit(crypto)
                self.assertEqual(rows["pypi:provenance"]["status"], "FAIL")
                self.assertEqual(rows["pypi:publisher-identity"]["status"], "FAIL")

    def test_wrong_per_file_environment_cannot_promote(self):
        crypto = self.crypto()
        crypto["files"][fixture.WHEEL]["publisher_environment"] = "staging"
        rows, _ = self.audit(crypto)
        self.assertEqual(rows["pypi:publisher-identity"]["status"], "FAIL")

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
