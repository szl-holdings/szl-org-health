"""Bounded HTTP, pagination, probe, and DNS primitives."""
from __future__ import annotations

import json
import math
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from typing import Any

import dns.exception
import dns.resolver

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)

_SENSITIVE_REDIRECT_HEADERS = frozenset(
    {"authorization", "proxy-authorization", "cookie", "cookie2"}
)
_MAX_PAGE_URL_BYTES = 4096
_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_RESPONSE_READ_CHUNK_BYTES = 1024 * 1024
_MAX_JSON_DEPTH = 128
_MAX_JSON_NODES = 1_000_000


def _validated_https_url(
    value: str,
) -> tuple[urllib.parse.SplitResult | None, str | None]:
    """Parse a canonical HTTPS URL without accepting authority ambiguity."""
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > _MAX_PAGE_URL_BYTES
    ):
        return None, "URL is empty or exceeds the bounded length"
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        return None, "URL contains control characters"
    if (
        "\\" in value
        or any(char.isspace() for char in value)
        or any(ord(char) > 0x7F for char in value)
    ):
        return None, "URL contains ambiguous or non-ASCII characters"
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
        hostname = parsed.hostname
    except (TypeError, ValueError):
        return None, "URL authority or port is malformed"
    if parsed.scheme.casefold() != "https":
        return None, "URL must use HTTPS"
    if parsed.username is not None or parsed.password is not None:
        return None, "URL userinfo is forbidden"
    if not hostname or port not in {None, 443}:
        return None, "URL host is missing or effective port is not 443"
    if parsed.fragment:
        return None, "URL fragments are forbidden"
    if not parsed.path.startswith("/"):
        return None, "URL path must be absolute"
    return parsed, None


def _origin(parsed: urllib.parse.SplitResult) -> tuple[str, str, int]:
    return ("https", str(parsed.hostname).casefold(), 443)


class _CredentialSafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Permit safe HTTPS redirects while never forwarding credentials cross-origin."""

    def __init__(
        self,
        *,
        locked_origin: tuple[str, str, int] | None = None,
        locked_path: str | None = None,
    ) -> None:
        super().__init__()
        self._locked_origin = locked_origin
        self._locked_path = locked_path

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        target = urllib.parse.urljoin(req.full_url, newurl)
        current, current_error = _validated_https_url(req.full_url)
        destination, destination_error = _validated_https_url(target)
        if current_error or destination_error or current is None or destination is None:
            raise urllib.error.URLError(
                "unsafe redirect: "
                f"{destination_error or current_error or 'invalid URL'}"
            )
        destination_origin = _origin(destination)
        if (
            self._locked_origin is not None
            and destination_origin != self._locked_origin
        ):
            raise urllib.error.URLError("unsafe redirect: pagination origin changed")
        if self._locked_path is not None and destination.path != self._locked_path:
            raise urllib.error.URLError("unsafe redirect: pagination path changed")

        redirected = super().redirect_request(req, fp, code, msg, headers, target)
        if redirected is None:
            return None
        if _origin(current) != destination_origin:
            for header in tuple(redirected.headers):
                if header.casefold() in _SENSITIVE_REDIRECT_HEADERS:
                    redirected.remove_header(header)
            for header in tuple(redirected.unredirected_hdrs):
                if header.casefold() in _SENSITIVE_REDIRECT_HEADERS:
                    redirected.remove_header(header)
        return redirected


def _safe_network_error(exc: Exception) -> str:
    """Return a bounded diagnostic class without reflecting URLs or credentials."""
    if isinstance(exc, urllib.error.URLError):
        reason = exc.reason
        if isinstance(reason, str) and reason.startswith("unsafe redirect:"):
            return reason[:160]
        return f"URLError:{type(reason).__name__}"
    return type(exc).__name__


def _response_header_map(headers: Any) -> dict[str, str]:
    """Preserve repeated Link fields instead of silently keeping the last one."""
    result: dict[str, str] = {}
    for key, value in headers.items():
        normalized = str(key).casefold()
        rendered = str(value)
        if normalized == "link" and normalized in result:
            result[normalized] = f"{result[normalized]}, {rendered}"
        elif normalized not in result:
            result[normalized] = rendered
    return result


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _bounded_json_tree(value: Any) -> None:
    """Reject excessive nesting, node counts, and non-finite decoded numbers."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_JSON_NODES:
            raise ValueError("JSON node limit exceeded")
        if depth > _MAX_JSON_DEPTH:
            raise ValueError("JSON nesting limit exceeded")
        if isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError("non-finite decoded JSON number")
        elif item is not None and not isinstance(item, (str, bool, int, float)):
            raise ValueError("decoded value is outside the JSON data model")


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
    redirect_origin: tuple[str, str, int] | None = None,
    redirect_path: str | None = None,
    max_bytes: int = _MAX_RESPONSE_BYTES,
) -> tuple[bytes | None, dict[str, str], str | None]:
    """Return ``(body, response_headers, error)`` with bounded retries."""
    parsed, url_error = _validated_https_url(url)
    if url_error or parsed is None:
        return None, {}, f"invalid-url:{url_error or 'unknown'}"
    if redirect_origin is not None and _origin(parsed) != redirect_origin:
        return None, {}, "invalid-url:request origin differs from pagination origin"
    if redirect_path is not None and parsed.path != redirect_path:
        return None, {}, "invalid-url:request path differs from pagination path"
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        return None, {}, "invalid-limit:max_bytes must be a positive integer"

    request_headers = {"User-Agent": "szl-org-health/2.0", **(headers or {})}
    opener = urllib.request.build_opener(
        _CredentialSafeRedirectHandler(
            locked_origin=redirect_origin,
            locked_path=redirect_path,
        )
    )
    last = "unknown"
    for attempt in range(retries + 1):
        request = urllib.request.Request(url, headers=request_headers)
        try:
            with opener.open(request, timeout=timeout) as response:
                response_headers = _response_header_map(response.headers)
                content_length = response_headers.get("content-length")
                if content_length is not None:
                    try:
                        declared_length = int(content_length, 10)
                    except ValueError:
                        return None, response_headers, "invalid-content-length"
                    if declared_length < 0 or declared_length > max_bytes:
                        return None, response_headers, "response-body-limit-exceeded"
                chunks: list[bytes] = []
                total = 0
                while True:
                    # Buffered HTTP readers may allocate the requested size even
                    # for a tiny response. Bound each allocation independently of
                    # the archive ceiling, including one byte to detect overflow.
                    chunk = response.read(
                        min(_RESPONSE_READ_CHUNK_BYTES, max_bytes - total + 1)
                    )
                    if not chunk:
                        return b"".join(chunks), response_headers, None
                    total += len(chunk)
                    if total > max_bytes:
                        return None, response_headers, "response-body-limit-exceeded"
                    chunks.append(chunk)
        except urllib.error.HTTPError as exc:
            response_headers = _response_header_map(exc.headers or {})
            return None, response_headers, f"http{exc.code}"
        except Exception as exc:  # noqa: BLE001 - converted to explicit UNKNOWN
            last = _safe_network_error(exc)
            if attempt < retries:
                time.sleep(1.25 * (attempt + 1))
    return None, {}, last


def request_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 20.0,
    retries: int = 2,
    redirect_origin: tuple[str, str, int] | None = None,
    redirect_path: str | None = None,
    max_bytes: int = _MAX_RESPONSE_BYTES,
) -> tuple[Any | None, dict[str, str], str | None]:
    """Return ``(json, response_headers, error)`` with bounded retries."""
    raw, response_headers, error = request_bytes(
        url,
        headers=headers,
        timeout=timeout,
        retries=retries,
        redirect_origin=redirect_origin,
        redirect_path=redirect_path,
        max_bytes=max_bytes,
    )
    if error or raw is None:
        return None, response_headers, error
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
        _bounded_json_tree(value)
        return value, response_headers, None
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        return None, response_headers, f"invalid-json:{str(exc)[:120]}"


def _link_parts(value: str) -> tuple[list[str] | None, str | None]:
    """Split a Link header only on commas outside URI and quoted sections."""
    if len(value.encode("utf-8")) > _MAX_PAGE_URL_BYTES * 2:
        return None, "Link header exceeds the bounded length"
    parts: list[str] = []
    start = 0
    in_uri = False
    in_quote = False
    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if in_quote and char == "\\":
            escaped = True
            continue
        if char == '"' and not in_uri:
            in_quote = not in_quote
        elif char == "<" and not in_quote:
            if in_uri:
                return None, "Link header contains nested URI brackets"
            in_uri = True
        elif char == ">" and not in_quote:
            if not in_uri:
                return None, "Link header contains an unmatched URI bracket"
            in_uri = False
        elif char == "," and not in_uri and not in_quote:
            parts.append(value[start:index].strip())
            start = index + 1
    if escaped or in_uri or in_quote:
        return None, "Link header contains an unterminated section"
    parts.append(value[start:].strip())
    if any(not part for part in parts):
        return None, "Link header contains an empty relation"
    return parts, None


def _strict_next_link(value: str | None) -> tuple[str | None, str | None]:
    if not value:
        return None, None
    parts, parts_error = _link_parts(value)
    if parts_error or parts is None:
        return None, parts_error or "Link header is malformed"
    candidates: list[str] = []
    for part in parts:
        match = re.fullmatch(r"\s*<([^<>]+)>\s*(;.*)?", part)
        if match is None:
            return None, "Link relation is malformed"
        parameters = match.group(2) or ""
        parsed_parameters, parameter_error = _strict_link_parameters(parameters)
        if parameter_error is not None or parsed_parameters is None:
            return None, parameter_error or "Link parameters are malformed"
        relation = parsed_parameters.get("rel")
        if relation is None:
            continue
        relation_tokens = relation.split()
        if not relation_tokens or any(
            re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]*", token) is None
            for token in relation_tokens
        ):
            return None, "Link rel parameter contains an invalid relation type"
        if "next" not in {token.casefold() for token in relation_tokens}:
            continue
        candidates.append(match.group(1))
    if len(candidates) > 1:
        return None, "multiple next Link relations are ambiguous"
    return (candidates[0], None) if candidates else (None, None)


_LINK_TOKEN_CHARACTERS = frozenset(
    "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)


def _strict_link_parameters(
    value: str,
) -> tuple[dict[str, str | None] | None, str | None]:
    """Parse Link parameters without treating quoted semicolons as delimiters."""
    parameters: dict[str, str | None] = {}
    index = 0
    length = len(value)
    while index < length:
        while index < length and value[index] in " \t":
            index += 1
        if index >= length:
            break
        if value[index] != ";":
            return None, "Link parameter separator is malformed"
        index += 1
        while index < length and value[index] in " \t":
            index += 1
        start = index
        while index < length and value[index] in _LINK_TOKEN_CHARACTERS:
            index += 1
        if start == index:
            return None, "Link parameter name is malformed"
        name = value[start:index].casefold()
        if name in parameters:
            return None, "Link relation contains duplicate parameters"
        while index < length and value[index] in " \t":
            index += 1

        parameter_value: str | None = None
        if index < length and value[index] == "=":
            index += 1
            while index < length and value[index] in " \t":
                index += 1
            if index >= length:
                return None, "Link parameter value is missing"
            if value[index] == '"':
                index += 1
                rendered: list[str] = []
                while index < length and value[index] != '"':
                    char = value[index]
                    if char == "\\":
                        index += 1
                        if index >= length:
                            return None, "Link quoted parameter escape is incomplete"
                        char = value[index]
                    if ord(char) < 0x20 or ord(char) > 0x7E:
                        return None, "Link quoted parameter contains invalid bytes"
                    rendered.append(char)
                    index += 1
                if index >= length or value[index] != '"':
                    return None, "Link quoted parameter is unterminated"
                index += 1
                parameter_value = "".join(rendered)
            else:
                start = index
                while index < length and value[index] in _LINK_TOKEN_CHARACTERS:
                    index += 1
                if start == index:
                    return None, "Link parameter value is malformed"
                parameter_value = value[start:index]
            while index < length and value[index] in " \t":
                index += 1
            if index < length and value[index] != ";":
                return None, "Link parameter suffix is malformed"
        if name == "rel" and parameter_value is None:
            return None, "Link rel parameter is missing a value"
        parameters[name] = parameter_value
    return parameters, None


def next_link(value: str | None) -> str | None:
    """Return one unambiguous next target, preserving the public helper API."""
    target, error = _strict_next_link(value)
    return None if error else target


def paginate_json(
    url: str,
    *,
    headers: dict[str, str],
    timeout: float,
    retries: int,
    max_pages: int = 20,
    max_items: int = 10_000,
) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Follow same-origin, exact-path Link pagination and fail closed."""
    initial, initial_error = _validated_https_url(url)
    if initial_error or initial is None:
        return None, f"invalid pagination URL: {initial_error or 'unknown'}"
    expected_origin = _origin(initial)
    expected_path = initial.path
    items: list[dict[str, Any]] = []
    page_url: str | None = url
    pages = 0
    seen: set[str] = set()
    while page_url is not None:
        pages += 1
        if pages > max_pages:
            return None, f"pagination exceeded {max_pages} pages"
        parsed, page_error = _validated_https_url(page_url)
        if page_error or parsed is None:
            return None, f"invalid pagination URL: {page_error or 'unknown'}"
        if _origin(parsed) != expected_origin:
            return None, "pagination next origin changed"
        if parsed.path != expected_path:
            return None, "pagination next path changed"
        canonical = urllib.parse.urlunsplit(
            ("https", str(parsed.hostname).casefold(), parsed.path, parsed.query, "")
        )
        if canonical in seen:
            return None, "pagination cycle detected"
        seen.add(canonical)
        data, response_headers, error = request_json(
            page_url,
            headers=headers,
            timeout=timeout,
            retries=retries,
            redirect_origin=expected_origin,
            redirect_path=expected_path,
        )
        if error:
            return None, error
        if not isinstance(data, list):
            return None, "unexpected non-list API response"
        if any(not isinstance(item, dict) for item in data):
            return None, "API page contains a non-object entry"
        if len(items) + len(data) > max_items:
            return None, f"pagination exceeded {max_items} items"
        items.extend(data)
        target, link_error = _strict_next_link(response_headers.get("link"))
        if link_error:
            return None, link_error
        page_url = urllib.parse.urljoin(page_url, target) if target else None
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
