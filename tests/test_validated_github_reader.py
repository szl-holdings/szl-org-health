# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import io
import unittest
from types import SimpleNamespace
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
