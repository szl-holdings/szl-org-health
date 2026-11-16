"""Exercise real urllib redirect processing without opening a network socket."""
from __future__ import annotations

import io
import urllib.request
import urllib.response
from email.message import Message
from unittest import TestCase, main, mock

from tools import pypi_release_path_audit as audit


API_URL = "https://api.github.com/repos/szl-holdings/private/contents/pyproject.toml"
RAW_URL = "https://raw.githubusercontent.com/szl-holdings/public/HEAD/pyproject.toml"


class SyntheticHTTPS(urllib.request.HTTPSHandler):
    def __init__(self, redirect_code, destination):
        super().__init__()
        self.redirect_code, self.destination = redirect_code, destination
        self.requests = []

    def https_open(self, request):
        self.requests.append(request)
        headers = Message()
        first = len(self.requests) == 1
        if first:
            headers["Location"] = self.destination
        response = urllib.response.addinfourl(
            io.BytesIO(b'{"private": "synthetic-only"}'), headers,
            request.full_url, self.redirect_code if first else 200,
        )
        response.msg = "Redirect" if first else "OK"
        return response


class AuditHTTPBoundaryTests(TestCase):
    def test_real_redirect_processing_never_sends_token_to_destination(self):
        real_builder = urllib.request.build_opener
        for code in (301, 302, 303, 307, 308):
            for destination in ("https://credential-capture.invalid/steal", "https://api.github.com/other"):
                with self.subTest(code=code, destination=destination):
                    handler = SyntheticHTTPS(code, destination)
                    with mock.patch.object(
                        audit.urllib.request, "build_opener",
                        side_effect=lambda *handlers: real_builder(*handlers, handler),
                    ):
                        status, payload = audit.Http("synthetic-placeholder-token").get(API_URL)
                    self.assertEqual(status, code)
                    self.assertIsNone(payload)
                    self.assertEqual(len(handler.requests), 1)
                    self.assertEqual(handler.requests[0].full_url, API_URL)
                    self.assertEqual(
                        handler.requests[0].headers.get("Authorization"),
                        "Bearer synthetic-placeholder-token",
                    )

    def test_anonymous_raw_redirects_are_also_refused(self):
        real_builder = urllib.request.build_opener
        handler = SyntheticHTTPS(302, "https://untrusted.invalid/changed-content")
        with mock.patch.object(
            audit.urllib.request, "build_opener",
            side_effect=lambda *handlers: real_builder(*handlers, handler),
        ):
            self.assertEqual(audit.Http("synthetic-placeholder-token").get(RAW_URL, raw=True), (302, None))
        self.assertEqual(len(handler.requests), 1)
        self.assertNotIn("Authorization", handler.requests[0].headers)

    def response(self, *, url=API_URL, body=b"{}"):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.geturl.return_value = url
        response.read.return_value = body
        return response

    def test_changed_response_identity_is_rejected_before_reading_body(self):
        response = self.response(url="https://untrusted.invalid/redirected")
        with mock.patch.object(audit.urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = response
            self.assertEqual(audit.Http("synthetic-placeholder-token").get(API_URL), (-1, None))
        response.read.assert_not_called()

    def test_json_and_raw_reads_retain_byte_limit(self):
        for raw in (False, True):
            with self.subTest(raw=raw):
                url = RAW_URL if raw else API_URL
                response = self.response(url=url, body=b"x" * 5)
                with mock.patch.object(audit, "MAX_HTTP_RESPONSE_BYTES", 4), \
                        mock.patch.object(audit.urllib.request, "build_opener") as opener:
                    opener.return_value.open.return_value = response
                    self.assertEqual(audit.Http("synthetic-placeholder-token").get(url, raw=raw), (-1, None))
                response.read.assert_called_once_with(5)


if __name__ == "__main__":
    main()
