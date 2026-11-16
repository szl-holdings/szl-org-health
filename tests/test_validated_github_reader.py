# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import io
import traceback
import unittest
import urllib.request
import urllib.response
from email.message import Message
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse

from tools import run_with_validated_github_reader as subject


def _repositories(count: int) -> list[dict[str, object]]:
    values: list[dict[str, object]] = []
    for index in range(count):
        private = index >= max(0, count - 3)
        values.append(
            {
                "full_name": f"szl-holdings/repository-{index:03d}",
                "visibility": "private" if private else "public",
                "private": private,
            }
        )
    return values


class FixtureRequester:
    def __init__(self, modes: dict[str, str]) -> None:
        self.modes = modes
        self.calls: list[tuple[str, str]] = []

    def __call__(self, url: str, token: str):
        self.calls.append((url, token))
        mode = self.modes[token]
        if mode == "invalid":
            raise subject.ProbeError("HTTP_401")
        count = 2 if mode == "partial" else 123
        if "/orgs/szl-holdings/repos?" not in url:
            if mode == "no-authority":
                return {"public_repos": 120}
            return {"public_repos": 120, "total_private_repos": 3}

        page = int(parse_qs(urlparse(url).query)["page"][0])
        values = _repositories(count)
        start = (page - 1) * 100
        return values[start : start + 100]


class ValidatedReaderTests(unittest.TestCase):
    def _validate_counts(self, counters, observed, *, minimum=1, rows=None):
        values = [
            {"full_name": f"szl-holdings/synthetic-{i}",
             "visibility": "public" if i < 3 else "private", "private": i >= 3}
            for i in range(observed)
        ] if rows is None else rows

        def request(url, _token):
            if "/repos?" not in url:
                return counters
            page = int(parse_qs(urlparse(url).query)["page"][0])
            return values[(page - 1) * 100 : page * 100]

        return subject.validate_github_reader(
            "synthetic",
            "synthetic-count-token",
            org="szl-holdings",
            minimum_repositories=minimum,
            request_json=request,
        )

    def test_complete_owned_reader_wins_over_quota_in_both_directions(self):
        for owned, quota in ((2, 1), (1, 2)):
            with self.subTest(owned=owned, quota=quota):
                reader = self._validate_counts(
                    {"public_repos": 3, "owned_private_repos": owned,
                     "total_private_repos": quota},
                    3 + owned,
                )
                self.assertEqual(reader.repositories, 3 + owned)
                self.assertEqual(reader.authoritative_total, 3 + owned)

    def test_quota_only_match_is_rejected_in_both_directions(self):
        for owned, quota in ((2, 1), (1, 2)):
            with self.subTest(owned=owned, quota=quota):
                with self.assertRaises(subject.ProbeError) as raised:
                    self._validate_counts(
                        {"public_repos": 3, "owned_private_repos": owned,
                         "total_private_repos": quota},
                        3 + quota,
                    )
                self.assertEqual(raised.exception.code, "INVENTORY_TOTAL_MISMATCH")

    def test_owned_selection_preserves_counter_fallback_and_invalid_gates(self):
        invalid = (None, True, -1, "2", 2.0)
        for owned in invalid:
            with self.subTest(fallback_owned=owned):
                reader = self._validate_counts(
                    {"public_repos": 3, "owned_private_repos": owned,
                     "total_private_repos": 2},
                    5,
                )
                self.assertEqual(reader.authoritative_total, 5)
        for quota in invalid:
            with self.subTest(unusable_quota=quota):
                reader = self._validate_counts(
                    {"public_repos": 3, "owned_private_repos": 2,
                     "total_private_repos": quota},
                    5,
                )
                self.assertEqual(reader.authoritative_total, 5)
        for owned in invalid:
            for quota in invalid:
                with self.subTest(no_valid_private=(owned, quota)):
                    with self.assertRaises(subject.ProbeError) as raised:
                        self._validate_counts(
                            {"public_repos": 3, "owned_private_repos": owned,
                             "total_private_repos": quota},
                            5,
                        )
                    self.assertEqual(raised.exception.code, "PRIVATE_TOTAL_UNAVAILABLE")
        for public in invalid:
            with self.subTest(invalid_public=public):
                with self.assertRaises(subject.ProbeError) as raised:
                    self._validate_counts(
                        {"public_repos": public, "owned_private_repos": 2}, 5
                    )
                self.assertEqual(raised.exception.code, "PUBLIC_TOTAL_UNAVAILABLE")
        self.assertEqual(
            self._validate_counts(
                {"public_repos": 3, "owned_private_repos": 2,
                 "total_private_repos": 2}, 5
            ).authoritative_total,
            5,
        )
        self.assertEqual(
            self._validate_counts({"public_repos": 3, "owned_private_repos": 2}, 5)
            .authoritative_total,
            5,
        )
        self.assertEqual(
            self._validate_counts(
                {"public_repos": 0, "owned_private_repos": 2,
                 "total_private_repos": 1},
                2,
                rows=[{"full_name": f"szl-holdings/synthetic-private-{i}",
                       "visibility": "private", "private": True} for i in range(2)],
            ).authoritative_total,
            2,
        )

    def test_selection_skips_quota_only_candidate_for_complete_owned_reader(self):
        for owned, quota in ((2, 1), (1, 2)):
            with self.subTest(owned=owned, quota=quota):
                def request(url, token):
                    if "/repos?" not in url:
                        return {"public_repos": 3, "owned_private_repos": owned,
                                "total_private_repos": quota}
                    private_count = quota if token == "quota-only" else owned
                    return [
                        {"full_name": f"szl-holdings/synthetic-{i}",
                         "visibility": "public" if i < 3 else "private"}
                        for i in range(3 + private_count)
                    ]

                reader = subject.select_github_reader(
                    {"GITHUB_READER_APP_TOKEN": "quota-only",
                     "SZL_GITHUB_TOKEN": "owned-complete"},
                    org="szl-holdings",
                    minimum_repositories=1,
                    request_json=request,
                    log=io.StringIO(),
                )
                self.assertEqual(reader.source, "SZL_GITHUB_TOKEN")
                self.assertEqual(reader.repositories, 3 + owned)

    def test_owned_selection_preserves_identity_equality_floor_and_private_gates(self):
        counters = {"public_repos": 3, "owned_private_repos": 2,
                    "total_private_repos": 1}
        duplicate = _repositories(5)
        duplicate[1]["full_name"] = duplicate[0]["full_name"]
        foreign = _repositories(5)
        foreign[0]["full_name"] = "synthetic-foreign/repository"
        public_only = [
            {"full_name": f"szl-holdings/public-{i}", "visibility": "public",
             "private": False}
            for i in range(5)
        ]
        cases = (
            (4, 1, None, counters, "INVENTORY_TOTAL_MISMATCH"),
            (6, 1, None, counters, "INVENTORY_TOTAL_MISMATCH"),
            (5, 6, None, counters, "AUTHORITATIVE_TOTAL_BELOW_FLOOR"),
            (5, 1, duplicate, counters, "DUPLICATE_REPOSITORY_IDENTITY"),
            (5, 1, foreign, counters, "FOREIGN_OR_EMPTY_INVENTORY"),
            (5, 1, public_only, counters, "PRIVATE_REPOSITORY_NOT_OBSERVED"),
            (3, 1, None, {"public_repos": 3, "owned_private_repos": 0,
                          "total_private_repos": 2}, "PRIVATE_COVERAGE_UNPROVEN"),
        )
        for observed, minimum, rows, metadata, reason in cases:
            with self.subTest(reason=reason, observed=observed):
                with self.assertRaises(subject.ProbeError) as raised:
                    self._validate_counts(
                        metadata, observed, minimum=minimum, rows=rows
                    )
                self.assertEqual(raised.exception.code, reason)

    def test_invalid_first_candidate_does_not_mask_valid_second(self) -> None:
        requester = FixtureRequester({"stale": "invalid", "valid": "valid"})
        log = io.StringIO()
        reader = subject.select_github_reader(
            {
                "GITHUB_READER_APP_TOKEN": "stale",
                "SZL_GITHUB_TOKEN": "valid",
            },
            org="szl-holdings",
            minimum_repositories=123,
            request_json=requester,
            log=log,
        )
        self.assertEqual(reader.source, "SZL_GITHUB_TOKEN")
        self.assertEqual(reader.repositories, 123)
        self.assertNotIn("stale", log.getvalue())
        self.assertNotIn("valid", log.getvalue())
        self.assertIn("HTTP_401", log.getvalue())

    def test_subset_reader_is_rejected_even_when_http_succeeds(self) -> None:
        requester = FixtureRequester({"subset": "partial", "complete": "valid"})
        reader = subject.select_github_reader(
            {
                "GITHUB_READER_APP_TOKEN": "subset",
                "ORG_REPO_WORKFLOW_TOKEN": "complete",
            },
            org="szl-holdings",
            minimum_repositories=123,
            request_json=requester,
            log=io.StringIO(),
        )
        self.assertEqual(reader.source, "ORG_REPO_WORKFLOW_TOKEN")

    def test_authoritative_private_total_is_required(self) -> None:
        requester = FixtureRequester({"token": "no-authority"})
        with self.assertRaises(subject.ProbeError) as raised:
            subject.validate_github_reader(
                "SZL_GITHUB_TOKEN",
                "token",
                org="szl-holdings",
                minimum_repositories=123,
                request_json=requester,
            )
        self.assertEqual(raised.exception.code, "PRIVATE_TOTAL_UNAVAILABLE")

    def test_duplicate_secret_values_are_probed_once(self) -> None:
        requester = FixtureRequester({"same": "invalid"})
        with self.assertRaises(subject.SelectionError):
            subject.select_github_reader(
                {
                    "GITHUB_READER_APP_TOKEN": "same",
                    "SZL_GITHUB_TOKEN": "same",
                },
                org="szl-holdings",
                minimum_repositories=123,
                request_json=requester,
                log=io.StringIO(),
            )
        self.assertEqual(len(requester.calls), 1)

    def test_child_receives_only_selected_canonical_token(self) -> None:
        requester = FixtureRequester({"chosen-secret": "valid"})
        observed: dict[str, object] = {}

        def fake_run(command, **kwargs):
            observed["command"] = command
            observed["kwargs"] = kwargs
            return SimpleNamespace(returncode=7)

        log = io.StringIO()
        result = subject.run(
            [
                "--org",
                "szl-holdings",
                "--minimum-repositories",
                "123",
                "--",
                "python",
                "-V",
            ],
            environ={
                "SZL_GITHUB_TOKEN": "chosen-secret",
                "GH_PAT": "rejected-secret",
                "OTHER": "retained",
            },
            request_json=requester,
            subprocess_run=fake_run,
            log=log,
        )
        self.assertEqual(result, 7)
        self.assertEqual(observed["command"], ["python", "-V"])
        kwargs = observed["kwargs"]
        self.assertNotIn("shell", kwargs)
        child = kwargs["env"]
        self.assertEqual(child["GITHUB_TOKEN"], "chosen-secret")
        self.assertEqual(child["GH_TOKEN"], "chosen-secret")
        self.assertEqual(child["SZL_GITHUB_TOKEN"], "chosen-secret")
        self.assertEqual(child["OTHER"], "retained")
        self.assertNotIn("GH_PAT", child)
        self.assertNotIn("GITHUB_READER_APP_TOKEN", child)
        self.assertEqual(child["PYTHONDONTWRITEBYTECODE"], "1")
        self.assertNotIn("chosen-secret", log.getvalue())

    def test_no_complete_reader_fails_closed(self) -> None:
        requester = FixtureRequester({"bad": "invalid"})
        result = subject.run(
            ["--", "python", "-V"],
            environ={"SZL_GITHUB_TOKEN": "bad"},
            request_json=requester,
            subprocess_run=lambda *_args, **_kwargs: self.fail(
                "child command must not execute"
            ),
            log=io.StringIO(),
        )
        self.assertEqual(result, 2)


class CredentialDiagnosticTests(unittest.TestCase):
    MARKER = "SYNTHETIC_CREDENTIAL_MARKER_DO_NOT_LOG"
    URL = "https://api.github.com/orgs/szl-holdings"

    def assert_sanitized_probe_error(self, operation, expected_code):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            try:
                operation()
            except subject.ProbeError as error:
                self.assertEqual(error.code, expected_code)
                diagnostics = str(error) + repr(error) + traceback.format_exc()
            else:
                self.fail("probe did not reject unsafe request")
        for text in (output.getvalue(), errors.getvalue(), diagnostics):
            self.assertNotIn(self.MARKER, text)

    def test_invalid_header_characters_are_rejected_before_request_construction(self):
        for character in ("\r", "\n", "\r\n", "\x00", "\t", " ", "\x7f", "\u0100"):
            with self.subTest(character=repr(character)), \
                    patch.object(subject.urllib.request, "Request") as request, \
                    patch.object(subject.urllib.request.OpenerDirector, "open") as opened:
                token = self.MARKER + character + "suffix"
                self.assert_sanitized_probe_error(
                    lambda: subject._default_request_json(self.URL, token),
                    "INVALID_CREDENTIAL_FORMAT",
                )
                request.assert_not_called()
                opened.assert_not_called()

    def test_validation_rejects_malformed_candidate_before_custom_requester(self):
        requester = Mock(side_effect=AssertionError("network forbidden"))
        self.assert_sanitized_probe_error(
            lambda: subject.validate_github_reader(
                "synthetic", self.MARKER + "\r\nsuffix",
                org="szl-holdings", minimum_repositories=123,
                request_json=requester,
            ),
            "INVALID_CREDENTIAL_FORMAT",
        )
        requester.assert_not_called()

    def test_header_construction_and_serialization_errors_have_safe_diagnostics(self):
        constructor = subject.urllib.request.Request
        for stage in ("construction", "serialization"):
            for error_type in (ValueError, TypeError):
                with self.subTest(stage=stage, error_type=error_type.__name__), \
                        patch.object(subject.urllib.request, "Request", wraps=constructor) as request, \
                        patch.object(subject.urllib.request.OpenerDirector, "open") as opened, \
                        patch.object(subject.time, "sleep") as sleep:
                    failure = error_type("invalid Authorization value " + self.MARKER)
                    if stage == "construction":
                        request.side_effect = failure
                    else:
                        opened.side_effect = failure
                    self.assert_sanitized_probe_error(
                        lambda: subject._default_request_json(self.URL, self.MARKER),
                        "INVALID_REQUEST_HEADERS",
                    )
                    self.assertEqual(request.call_count, 1)
                    self.assertEqual(opened.call_count, int(stage == "serialization"))
                    sleep.assert_not_called()

    def test_header_failure_returns_fail_closed_without_child_or_secret_output(self):
        output, errors = io.StringIO(), io.StringIO()
        child = Mock(side_effect=AssertionError("child must not run"))
        with patch.object(subject.urllib.request.OpenerDirector, "open", side_effect=ValueError(self.MARKER)), \
                redirect_stdout(output), redirect_stderr(errors):
            status = subject.run(
                ["--", "python", "-V"],
                environ={"SZL_GITHUB_TOKEN": self.MARKER},
                request_json=subject._default_request_json,
                subprocess_run=child,
                log=errors,
            )
        self.assertEqual(status, 2)
        child.assert_not_called()
        self.assertIn("INVALID_REQUEST_HEADERS", errors.getvalue())
        self.assertNotIn(self.MARKER, output.getvalue() + errors.getvalue())

    def test_malformed_unicode_candidate_cannot_escape_deduplication(self):
        output, errors = io.StringIO(), io.StringIO()
        requester = Mock(side_effect=AssertionError("network forbidden"))
        child = Mock(side_effect=AssertionError("child must not run"))
        with redirect_stdout(output), redirect_stderr(errors):
            status = subject.run(
                ["--", "python", "-V"],
                environ={"SZL_GITHUB_TOKEN": self.MARKER + "\ud800suffix"},
                request_json=requester,
                subprocess_run=child,
                log=errors,
            )
        self.assertEqual(status, 2)
        requester.assert_not_called()
        child.assert_not_called()
        self.assertIn("INVALID_CREDENTIAL_FORMAT", errors.getvalue())
        self.assertNotIn(self.MARKER, output.getvalue() + errors.getvalue())

    def test_malformed_candidate_can_fall_back_without_inheriting_unused_aliases(self):
        requester = FixtureRequester({"selected-synthetic": "valid"})
        child = Mock(return_value=SimpleNamespace(returncode=0))
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            status = subject.run(
                ["--", "python", "-V"],
                environ={
                    "GITHUB_READER_APP_TOKEN": self.MARKER + "\r\nsuffix",
                    "SZL_GITHUB_TOKEN": "\n selected-synthetic \t",
                    "GH_PAT": "unused-" + self.MARKER,
                },
                request_json=requester,
                subprocess_run=child,
                log=errors,
            )
        self.assertEqual(status, 0)
        self.assertTrue(requester.calls)
        self.assertEqual({token for _, token in requester.calls}, {"selected-synthetic"})
        environment = child.call_args.kwargs["env"]
        for alias in ("GITHUB_TOKEN", "GH_TOKEN", "SZL_GITHUB_TOKEN"):
            self.assertEqual(environment[alias], "selected-synthetic")
        self.assertNotIn("GITHUB_READER_APP_TOKEN", environment)
        self.assertNotIn("GH_PAT", environment)
        self.assertNotIn(self.MARKER, repr(environment))
        self.assertNotIn(self.MARKER, output.getvalue() + errors.getvalue())


class SyntheticReaderHTTPS(urllib.request.HTTPSHandler):
    def __init__(self, code, destination):
        super().__init__()
        self.code, self.destination = code, destination
        self.requests = []

    def https_open(self, request):
        self.requests.append(request)
        headers = Message()
        first = len(self.requests) == 1
        if first:
            headers["Location"] = self.destination
        response = urllib.response.addinfourl(
            io.BytesIO(b'{"synthetic": true}'), headers,
            request.full_url, self.code if first else 200,
        )
        response.msg = "Redirect" if first else "OK"
        return response


class ReaderTransportBoundaryTests(unittest.TestCase):
    URL = "https://api.github.com/orgs/szl-holdings"
    TOKEN = "synthetic-only-reader-placeholder"

    def test_real_redirect_processing_never_forwards_authorization(self):
        builder = urllib.request.build_opener
        for code in (301, 302, 303, 307, 308):
            for destination in ("https://untrusted.invalid/steal", "https://api.github.com/other"):
                with self.subTest(code=code, destination=destination):
                    handler = SyntheticReaderHTTPS(code, destination)
                    with patch.object(
                        subject.urllib.request, "build_opener",
                        side_effect=lambda *handlers: builder(*handlers, handler),
                    ), self.assertRaises(subject.ProbeError) as error:
                        subject._default_request_json(self.URL, self.TOKEN)
                    self.assertEqual(error.exception.code, f"HTTP_{code}")
                    self.assertEqual(len(handler.requests), 1)
                    self.assertEqual(handler.requests[0].full_url, self.URL)
                    self.assertEqual(handler.requests[0].headers.get("Authorization"), "Bearer " + self.TOKEN)

    def test_noncanonical_api_destinations_never_construct_a_request(self):
        urls = (
            "http://api.github.com/orgs/x",
            "https://api.github.com.evil.invalid/orgs/x",
            "https://user@api.github.com/orgs/x",
            "https://api.github.com:443/orgs/x",
            "https://api.github.com/orgs/x#fragment",
            "https://[broken", None,
        )
        with patch.object(subject.urllib.request, "Request") as request:
            for url in urls:
                with self.subTest(url=url), self.assertRaises(subject.ProbeError) as error:
                    subject._default_request_json(url, self.TOKEN)
                self.assertEqual(error.exception.code, "REQUEST_URL_INVALID")
        request.assert_not_called()

    def response(self, *, url=None, body=b"{}"):
        response = Mock()
        response.geturl.return_value = self.URL if url is None else url
        response.read.return_value = body
        manager = Mock()
        manager.__enter__ = Mock(return_value=response)
        manager.__exit__ = Mock(return_value=False)
        return manager, response

    def test_changed_response_url_is_rejected_before_reading_private_body(self):
        manager, response = self.response(url="https://untrusted.invalid/changed")
        with patch.object(subject.urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = manager
            with self.assertRaises(subject.ProbeError) as error:
                subject._default_request_json(self.URL, self.TOKEN)
        self.assertEqual(error.exception.code, "RESPONSE_IDENTITY_CHANGED")
        response.read.assert_not_called()

    def test_direct_exact_response_keeps_bounded_json_read(self):
        manager, response = self.response(body=b'{"ok": true}')
        with patch.object(subject.urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = manager
            self.assertEqual(subject._default_request_json(self.URL, self.TOKEN), {"ok": True})
        response.read.assert_called_once_with(subject.MAX_RESPONSE_BYTES + 1)

    def test_oversized_response_remains_fail_closed(self):
        manager, response = self.response(body=b"x" * 5)
        with patch.object(subject, "MAX_RESPONSE_BYTES", 4), \
                patch.object(subject.urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = manager
            with self.assertRaises(subject.ProbeError) as error:
                subject._default_request_json(self.URL, self.TOKEN)
        self.assertEqual(error.exception.code, "RESPONSE_TOO_LARGE")
        response.read.assert_called_once_with(5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
