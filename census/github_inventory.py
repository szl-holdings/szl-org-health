"""Resolve the organization identity before locking repository pagination."""
from __future__ import annotations

import urllib.parse
from typing import Any

from .common import paginate_json, request_json

API = "https://api.github.com"


def discover_repositories(
    org: str, *, headers: dict[str, str], timeout: float, retries: int,
    max_pages: int = 20,
) -> tuple[list[dict[str, Any]] | None, dict[str, Any] | None, str | None]:
    metadata, _, error = request_json(
        f"{API}/orgs/{urllib.parse.quote(org, safe='')}",
        headers=headers, timeout=timeout, retries=retries,
    )
    if error:
        return None, None, error
    if not isinstance(metadata, dict):
        return None, None, "organization identity unavailable"
    identifier = metadata.get("id")
    login = metadata.get("login")
    if (
        type(identifier) is not int or identifier <= 0
        or not isinstance(login, str) or login.casefold() != org.casefold()
    ):
        return None, None, "organization identity mismatch"
    # GitHub emits numeric organization URLs in Link, even for named requests.
    # Start on that authenticated identity so the generic exact-path lock holds.
    rows, error = paginate_json(
        f"{API}/organizations/{identifier}/repos"
        "?type=all&sort=full_name&direction=asc&per_page=100",
        headers=headers, timeout=timeout, retries=retries, max_pages=max_pages,
    )
    if error or rows is None:
        return None, metadata, error or "repository inventory unavailable"
    names: set[str] = set()
    for row in rows:
        name = row.get("full_name")
        if (
            not isinstance(name, str) or name.count("/") != 1
            or name.split("/")[0].casefold() != org.casefold()
            or not name.split("/")[1] or name.casefold() in names
        ):
            return None, metadata, "repository inventory has foreign or duplicate identity"
        names.add(name.casefold())
    return rows, metadata, None
