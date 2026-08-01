"""Bounded HTTP, pagination, probe, and DNS primitives."""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from collections.abc import Iterable
from typing import Any

import dns.exception
import dns.resolver

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)


def token_header(env_names: Iterable[str]) -> dict[str, str]:
    for name in env_names:
        token = os.environ.get(name)
        if token:
            return {"Authorization": f"Bearer {token}"}
    return {}


def request_bytes(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 20.0,
    retries: int = 2,
) -> tuple[bytes | None, dict[str, str], str | None]:
    """Return ``(body, response_headers, error)`` with bounded retries."""
    request_headers = {"User-Agent": "szl-org-health/2.0", **(headers or {})}
    last = "unknown"
    for attempt in range(retries + 1):
        request = urllib.request.Request(url, headers=request_headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return (
                    response.read(),
                    {key.lower(): value for key, value in response.headers.items()},
                    None,
                )
        except urllib.error.HTTPError as exc:
            response_headers = {
                key.lower(): value for key, value in (exc.headers or {}).items()
            }
            return None, response_headers, f"http{exc.code}"
        except Exception as exc:  # noqa: BLE001 - converted to explicit UNKNOWN
            last = str(exc)[:160]
            if attempt < retries:
                time.sleep(1.25 * (attempt + 1))
    return None, {}, last


def request_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 20.0,
    retries: int = 2,
) -> tuple[Any | None, dict[str, str], str | None]:
    """Return ``(json, response_headers, error)`` with bounded retries."""
    raw, response_headers, error = request_bytes(
        url,
        headers=headers,
        timeout=timeout,
        retries=retries,
    )
    if error or raw is None:
        return None, response_headers, error
    try:
        return json.loads(raw.decode("utf-8")), response_headers, None
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, response_headers, f"invalid-json:{str(exc)[:120]}"


def next_link(value: str | None) -> str | None:
    if not value:
        return None
    for part in value.split(","):
        match = re.match(r'\s*<([^>]+)>;\s*rel="([^"]+)"', part)
        if match and match.group(2) == "next":
            return match.group(1)
    return None


def paginate_json(
    url: str,
    *,
    headers: dict[str, str],
    timeout: float,
    retries: int,
    max_pages: int = 20,
) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Follow Link pagination and fail closed on malformed/infinite pages."""
    items: list[dict[str, Any]] = []
    page_url: str | None = url
    pages = 0
    while page_url is not None:
        pages += 1
        if pages > max_pages:
            return None, f"pagination exceeded {max_pages} pages"
        data, response_headers, error = request_json(
            page_url, headers=headers, timeout=timeout, retries=retries
        )
        if error:
            return None, error
        if not isinstance(data, list):
            return None, "unexpected non-list API response"
        items.extend(item for item in data if isinstance(item, dict))
        page_url = next_link(response_headers.get("link"))
    return items, None


def http_probe(url: str, timeout: float = 12.0) -> dict[str, Any]:
    request = urllib.request.Request(
        url, headers={"User-Agent": BROWSER_UA}, method="GET"
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return {
                "http": response.status,
                "headers": {
                    key.lower(): value for key, value in response.headers.items()
                },
            }
    except urllib.error.HTTPError as exc:
        return {
            "http": exc.code,
            "headers": {
                key.lower(): value for key, value in (exc.headers or {}).items()
            },
        }
    except Exception as exc:  # noqa: BLE001
        return {"http": 0, "error": str(exc)[:120]}


def resolve_txt(name: str, timeout: float = 8.0) -> str | None:
    """Return TXT data, empty string for authoritative absence, or None UNKNOWN."""
    try:
        answer = dns.resolver.resolve(name, "TXT", search=False, lifetime=timeout)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return ""
    except (dns.exception.Timeout, dns.resolver.NoNameservers, OSError):
        return None
    records = []
    for record in answer:
        chunks = getattr(record, "strings", ())
        records.append(
            "".join(bytes(chunk).decode("utf-8", "replace") for chunk in chunks)
        )
    return "\n".join(records)
