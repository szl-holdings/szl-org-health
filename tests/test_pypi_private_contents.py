"""Private marker retrieval must preserve source identity and fail closed."""

from __future__ import annotations

import base64
import copy
import hashlib
import io
from contextlib import redirect_stdout
from unittest import TestCase, main, mock

from tools.pypi_release_path_audit import GH_API, RAW, Http, audit_private_marker


ORG = "szl-holdings"
REPO = "private-example"
PATH = "tools/private-package/pyproject.toml"
PACKAGE = "private-example"
BODY = b'[project]\nname = "private-example"\nclassifiers = ["Private :: Do Not Upload"]\n'
RAW_URL = f"{RAW}/{ORG}/{REPO}/HEAD/{PATH}"
API_URL = f"{GH_API}/repos/{ORG}/{REPO}/contents/{PATH}?ref=HEAD"
PYPI_URL = f"https://pypi.org/pypi/{PACKAGE}/json"


def file_payload(body: bytes = BODY, path: str = PATH) -> dict:
    blob = b"blob " + str(len(body)).encode("ascii") + b"\0" + body
    return {
        "type": "file",
        "path": path,
        "encoding": "base64",
        "size": len(body),
        "sha": hashlib.sha1(blob, usedforsecurity=False).hexdigest(),
        "content": base64.encodebytes(body).decode("ascii"),
    }


class FakeHttp:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get(self, url, accept=None, raw=False):
        self.calls.append((url, raw))
        if url not in self.responses:
            raise AssertionError(f"unexpected HTTP request: {url}")
        return copy.deepcopy(self.responses[url])


def audit_marker(payload=None, *, raw_status=404, api_status=200, pypi_status=404, published_names=None):
    http = FakeHttp({
        RAW_URL: (raw_status, BODY if raw_status == 200 else None),
        API_URL: (api_status, file_payload() if payload is None else payload),
        PYPI_URL: (pypi_status, {}),
    })
    results = []
    with redirect_stdout(io.StringIO()):
        audit_private_marker(http, ORG, {
            "name": PACKAGE, "repo": REPO, "path": PATH, "status": "internal",
        }, results, published_names)
    return {row["check"]: row for row in results}, http


class PrivateContentsTests(TestCase):
    def test_private_raw_404_uses_exact_head_contents_and_records_blob(self):
        results, http = audit_marker()
        self.assertEqual(results["private-classifier"]["status"], "PASS")
        self.assertIn("ref=HEAD", results["private-classifier"]["detail"])
        self.assertIn(file_payload()["sha"], results["private-classifier"]["detail"])
        self.assertEqual(http.calls, [(RAW_URL, True), (API_URL, False), (PYPI_URL, False)])

    def test_public_raw_success_does_not_use_authenticated_fallback(self):
        results, http = audit_marker(raw_status=200)
        self.assertEqual(results["private-classifier"]["status"], "PASS")
        self.assertNotIn((API_URL, False), http.calls)

    def test_raw_failure_can_recover_only_from_valid_api_file(self):
        for raw_status in (403, 404, 503, -1):
            with self.subTest(raw_status=raw_status):
                results, _ = audit_marker(raw_status=raw_status)
                self.assertEqual(results["private-classifier"]["status"], "PASS")

    def test_missing_or_insufficient_access_remains_unknown(self):
        for status in (401, 403, 404, 429, 503, -1):
            with self.subTest(status=status):
                results, http = audit_marker(api_status=status)
                self.assertEqual(results["private-classifier"]["status"], "UNKNOWN")
                self.assertIn(f"Contents API HTTP {status}", results["private-classifier"]["detail"])
                self.assertNotIn((PYPI_URL, False), http.calls)

    def test_malformed_api_file_never_supplies_private_evidence(self):
        changes = (
            {"type": "dir"}, {"type": "symlink"}, {"type": "submodule"},
            {"path": "different/pyproject.toml"}, {"encoding": "none"},
            {"content": 123}, {"content": "not!base64"}, {"content": "é"},
            {"size": True}, {"size": -1}, {"size": len(BODY) + 1},
            {"sha": "a" * 40}, {"sha": None}, {"sha": "invalid"},
        )
        payloads = [[], {}, "file", *[{**file_payload(), **change} for change in changes]]
        payloads += [{key: value for key, value in file_payload().items() if key != missing}
                     for missing in ("type", "path", "encoding", "content", "size", "sha")]
        for payload in payloads:
            with self.subTest(payload=payload):
                results, http = audit_marker(payload)
                self.assertEqual(results["private-classifier"]["status"], "UNKNOWN")
                self.assertNotIn((PYPI_URL, False), http.calls)

    def test_content_tampering_is_rejected_even_with_same_length(self):
        payload = file_payload()
        payload["content"] = base64.b64encode(BODY.replace(b"Private", b"private")).decode("ascii")
        results, _ = audit_marker(payload)
        self.assertEqual(results["private-classifier"]["status"], "UNKNOWN")

    def test_valid_file_without_private_classifier_is_still_fail(self):
        results, _ = audit_marker(file_payload(b'[project]\nname = "private-example"\n'))
        self.assertEqual(results["private-classifier"]["status"], "FAIL")

    def test_valid_blob_with_invalid_toml_is_still_fail(self):
        results, _ = audit_marker(file_payload(b"[project\n"))
        self.assertEqual(results["private-classifier"]["status"], "FAIL")
        self.assertIn("TOML parse error", results["private-classifier"]["detail"])

    def test_private_fallback_preserves_unexpected_pypi_project_check(self):
        results, _ = audit_marker(pypi_status=200)
        self.assertEqual(results["private-classifier"]["status"], "PASS")
        self.assertEqual(results["pypi:unexpected-project"]["status"], "FAIL")
        results, _ = audit_marker(pypi_status=200, published_names={PACKAGE: "public-example"})
        self.assertEqual(results["pypi:unexpected-project"]["status"], "PASS")

    def test_api_path_query_characters_cannot_change_selected_ref(self):
        path = "tools/private?ref=untrusted/pyproject.toml"
        raw_url = f"{RAW}/{ORG}/{REPO}/HEAD/{path}"
        api_url = f"{GH_API}/repos/{ORG}/{REPO}/contents/tools/private%3Fref%3Duntrusted/pyproject.toml?ref=HEAD"
        http = FakeHttp({raw_url: (404, None), api_url: (200, file_payload(path=path))})
        results = []
        with redirect_stdout(io.StringIO()):
            audit_private_marker(http, ORG, {"repo": REPO, "path": path, "status": "internal"}, results)
        self.assertEqual(results[0]["status"], "PASS")
        self.assertEqual(http.calls, [(raw_url, True), (api_url, False)])

    def test_authenticated_api_get_uses_existing_credential_only_on_api_host(self):
        response = mock.MagicMock()
        response.status = 200
        response.read.return_value = b"{}"
        response.__enter__.return_value = response
        with mock.patch("tools.pypi_release_path_audit.urllib.request.urlopen", return_value=response) as request:
            Http("test-placeholder").get(API_URL)
            self.assertEqual(request.call_args.args[0].headers.get("Authorization"), "Bearer test-placeholder")
            Http("test-placeholder").get(RAW_URL, raw=True)
            self.assertNotIn("Authorization", request.call_args.args[0].headers)

    def test_existing_gh_authentication_can_read_contents_json(self):
        completed = mock.Mock(returncode=0, stdout='{"type":"file"}')
        with mock.patch("tools.pypi_release_path_audit.shutil.which", return_value="gh"), \
                mock.patch("tools.pypi_release_path_audit.subprocess.run", return_value=completed) as run:
            status, payload = Http(None).get(API_URL)
        self.assertEqual((status, payload), (200, {"type": "file"}))
        self.assertEqual(run.call_args.args[0], ["gh", "api", API_URL])


if __name__ == "__main__":
    main()
