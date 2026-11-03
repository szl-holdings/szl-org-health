#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Select a GitHub credential after bounded inventory/count validation.

A non-empty secret is not evidence that the credential is valid. This runner
probes each configured candidate without printing its value and requires exact
agreement with valid owned public/private counts when available. The legacy
quota-counter fallback applies only when owned-private data is unavailable or
invalid; it proves count agreement, not independent full owned authority or
confidential content access. One bounded child command receives only the
selected credential through canonical environment names.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, TextIO

GITHUB_API = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
DEFAULT_ORG = "szl-holdings"
DEFAULT_MINIMUM_REPOSITORIES = 123
MAX_PAGES = 20
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
CANDIDATE_ENV_NAMES = (
    "GITHUB_READER_APP_TOKEN",
    "SZL_GITHUB_TOKEN",
    "DOCS_AUTOMATION_TEAM_READ_TOKEN",
    "ORG_REPO_WORKFLOW_TOKEN",
    "SZL_ORG_PAT",
    "SZL_GITHUB_PAT",
    "GH_PAT",
    "PAT_TOKEN",
    "GITHUB_PAT",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "REPOSITORY_GITHUB_TOKEN",
)


class ProbeError(RuntimeError):
    """A credential could not prove the required bounded authority."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class SelectionError(RuntimeError):
    """No configured credential proved complete organization coverage."""


@dataclass(frozen=True)
class ValidatedReader:
    source: str
    token: str = field(repr=False)
    repositories: int
    authoritative_total: int


RequestJson = Callable[[str, str], Any]


def _default_request_json(url: str, token: str) -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
        "User-Agent": "szl-org-health-validated-reader",
    }
    last_code = "REQUEST_FAILED"
    for attempt in range(2):
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise ProbeError("RESPONSE_TOO_LARGE")
                try:
                    return json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ProbeError("INVALID_JSON") from exc
        except urllib.error.HTTPError as exc:
            last_code = f"HTTP_{exc.code}"
            if exc.code not in {429, 500, 502, 503, 504} or attempt == 1:
                raise ProbeError(last_code) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            last_code = "TRANSPORT_ERROR"
            if attempt == 1:
                raise ProbeError(last_code) from exc
        time.sleep(1.0)
    raise ProbeError(last_code)


def _nonnegative_integer(value: Any, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ProbeError(code)
    return value


def validate_github_reader(
    source: str,
    token: str,
    *,
    org: str,
    minimum_repositories: int,
    request_json: RequestJson = _default_request_json,
) -> ValidatedReader:
    """Prefer owned counts; quota-only fallback cannot prove owned authority."""

    encoded_org = urllib.parse.quote(org, safe="")
    metadata = request_json(f"{GITHUB_API}/orgs/{encoded_org}", token)
    if not isinstance(metadata, dict):
        raise ProbeError("ORG_METADATA_INVALID")

    public_count = _nonnegative_integer(
        metadata.get("public_repos"), "PUBLIC_TOTAL_UNAVAILABLE"
    )
    private_value = metadata.get("owned_private_repos")
    if (
        isinstance(private_value, bool)
        or not isinstance(private_value, int)
        or private_value < 0
    ):
        private_value = metadata.get("total_private_repos")
    private_count = _nonnegative_integer(
        private_value, "PRIVATE_TOTAL_UNAVAILABLE"
    )
    authoritative_total = public_count + private_count
    if authoritative_total < minimum_repositories:
        raise ProbeError("AUTHORITATIVE_TOTAL_BELOW_FLOOR")
    if private_count < 1:
        raise ProbeError("PRIVATE_COVERAGE_UNPROVEN")

    repositories: list[dict[str, Any]] = []
    for page in range(1, MAX_PAGES + 1):
        query = urllib.parse.urlencode(
            {
                "type": "all",
                "sort": "full_name",
                "direction": "asc",
                "per_page": 100,
                "page": page,
            }
        )
        value = request_json(
            f"{GITHUB_API}/orgs/{encoded_org}/repos?{query}",
            token,
        )
        if not isinstance(value, list) or any(
            not isinstance(row, dict) for row in value
        ):
            raise ProbeError("REPOSITORY_PAGE_INVALID")
        repositories.extend(value)
        if len(value) < 100:
            break
    else:
        raise ProbeError("REPOSITORY_PAGINATION_LIMIT")

    identities = [str(row.get("full_name") or "") for row in repositories]
    if not identities or any(
        not identity.startswith(f"{org}/") for identity in identities
    ):
        raise ProbeError("FOREIGN_OR_EMPTY_INVENTORY")
    if len(identities) != len(set(identities)):
        raise ProbeError("DUPLICATE_REPOSITORY_IDENTITY")
    if len(repositories) != authoritative_total:
        raise ProbeError("INVENTORY_TOTAL_MISMATCH")
    if len(repositories) < minimum_repositories:
        raise ProbeError("INVENTORY_BELOW_FLOOR")

    observed_private = sum(
        row.get("visibility") in {"private", "internal"}
        or row.get("private") is True
        for row in repositories
    )
    if observed_private < 1:
        raise ProbeError("PRIVATE_REPOSITORY_NOT_OBSERVED")

    return ValidatedReader(
        source=source,
        token=token,
        repositories=len(repositories),
        authoritative_total=authoritative_total,
    )


def _configured_candidates(
    environ: Mapping[str, str],
) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name in CANDIDATE_ENV_NAMES:
        token = str(environ.get(name) or "").strip()
        if not token:
            continue
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        found.append((name, token))
    return found


def select_github_reader(
    environ: Mapping[str, str],
    *,
    org: str,
    minimum_repositories: int,
    request_json: RequestJson = _default_request_json,
    log: TextIO = sys.stderr,
) -> ValidatedReader:
    candidates = _configured_candidates(environ)
    if not candidates:
        raise SelectionError("NO_CONFIGURED_CANDIDATES")

    for source, token in candidates:
        try:
            reader = validate_github_reader(
                source,
                token,
                org=org,
                minimum_repositories=minimum_repositories,
                request_json=request_json,
            )
        except ProbeError as exc:
            print(
                f"github-reader source={source} state=REJECTED reason={exc.code}",
                file=log,
            )
            continue
        print(
            "github-reader "
            f"source={source} state=VALIDATED "
            f"repositories={reader.repositories}",
            file=log,
        )
        return reader

    raise SelectionError("NO_COMPLETE_ORGANIZATION_READER")


def _child_environment(
    environ: Mapping[str, str],
    reader: ValidatedReader,
) -> dict[str, str]:
    child = {
        key: value
        for key, value in environ.items()
        if key not in CANDIDATE_ENV_NAMES
    }
    child["GITHUB_TOKEN"] = reader.token
    child["GH_TOKEN"] = reader.token
    child["SZL_GITHUB_TOKEN"] = reader.token
    child["PYTHONDONTWRITEBYTECODE"] = "1"
    child["SZL_VALIDATED_GITHUB_READER_SOURCE"] = reader.source
    child["SZL_VALIDATED_GITHUB_REPOSITORIES"] = str(reader.repositories)
    return child


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--org", default=DEFAULT_ORG)
    parser.add_argument(
        "--minimum-repositories",
        type=int,
        default=DEFAULT_MINIMUM_REPOSITORIES,
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.minimum_repositories < 1:
        parser.error("--minimum-repositories must be positive")
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        parser.error("a child command is required after --")
    return args


def run(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    request_json: RequestJson = _default_request_json,
    subprocess_run: Callable[..., Any] = subprocess.run,
    log: TextIO = sys.stderr,
) -> int:
    args = parse_args(argv)
    source_environment = dict(os.environ if environ is None else environ)
    try:
        reader = select_github_reader(
            source_environment,
            org=args.org,
            minimum_repositories=args.minimum_repositories,
            request_json=request_json,
            log=log,
        )
    except SelectionError as exc:
        print(f"github-reader state=UNAVAILABLE reason={exc}", file=log)
        return 2

    completed = subprocess_run(
        list(args.command),
        env=_child_environment(source_environment, reader),
        check=False,
    )
    return int(completed.returncode)


if __name__ == "__main__":
    raise SystemExit(run())
