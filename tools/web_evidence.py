#!/usr/bin/env python3
"""Bounded, no-key public-web evidence collection.

This module is deliberately an allowlisted control plane rather than a general
purpose crawler.  It accepts explicit URLs, checks robots.txt before every
host, rejects private-network targets by default, enforces byte/time budgets,
and emits one deterministic receipt per URL.  Optional open-source extractors
are used when installed; the standard-library extractor keeps the control
plane runnable in a clean Python environment.

The output is evidence about a fetch and extraction.  It is not a deployment,
publication, authorization, or scientific-quality claim.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import ipaddress
import json
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable


EVIDENCE_CLASSES = {
    "MEASURED",
    "REPORTED",
    "DECLARED",
    "SIMULATED",
    "SAMPLE",
    "MODELED",
    "ROADMAP",
    "UNKNOWN",
    "UNAVAILABLE",
    "BLOCKED",
}


class PolicyError(ValueError):
    """A URL or response violates the local collection policy."""


class BodyTooLarge(PolicyError):
    """A response exceeded the configured byte budget."""


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _sha256(value: bytes | str) -> str:
    raw = value if isinstance(value, bytes) else value.encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _host_matches(host: str, allowed_hosts: frozenset[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == item or host.endswith("." + item) for item in allowed_hosts)


def _assert_safe_url(
    url: str,
    *,
    allowed_hosts: frozenset[str],
    allow_private_network: bool,
    expected_host: str | None = None,
) -> urllib.parse.SplitResult:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        raise PolicyError("URL_SCHEME_NOT_ALLOWED")
    if parsed.username or parsed.password:
        raise PolicyError("URL_USERINFO_NOT_ALLOWED")
    if not parsed.hostname:
        raise PolicyError("URL_HOST_MISSING")
    host = parsed.hostname.lower().rstrip(".")
    if not _host_matches(host, allowed_hosts):
        raise PolicyError("HOST_NOT_ALLOWLISTED")
    if expected_host and host != expected_host:
        raise PolicyError("CROSS_HOST_REDIRECT")
    if allow_private_network:
        return parsed
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        raise PolicyError("PRIVATE_NETWORK_TARGET")
    try:
        addresses = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            addresses = {
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            }
        except (OSError, socket.gaierror) as exc:
            raise PolicyError("DNS_UNRESOLVED") from exc
    if any(not address.is_global for address in addresses):
        raise PolicyError("PRIVATE_NETWORK_TARGET")
    return parsed


class _TextExtractor(HTMLParser):
    """Small dependency-free fallback for pages without Trafilatura."""

    _ignored = {"script", "style", "noscript", "template", "svg"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.text_parts: list[str] = []
        self.links: list[str] = []
        self._ignored_depth = 0
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in self._ignored:
            self._ignored_depth += 1
        if tag == "title":
            self._in_title = True
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(href.strip())

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        if tag in self._ignored and self._ignored_depth:
            self._ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        value = " ".join(data.split())
        if not value or self._ignored_depth:
            return
        if self._in_title:
            self.title_parts.append(value)
        else:
            self.text_parts.append(value)


def _extract(body: bytes, content_type: str, url: str, max_text_chars: int) -> tuple[str, str, list[str], str]:
    """Return title, bounded text, links, and extractor name."""
    charset = "utf-8"
    if "charset=" in content_type.lower():
        charset = content_type.lower().split("charset=", 1)[1].split(";", 1)[0].strip() or charset
    decoded = body.decode(charset, errors="replace")
    if "html" in content_type.lower() or "xhtml" in content_type.lower():
        try:
            from trafilatura import extract as trafilatura_extract  # type: ignore

            extracted = trafilatura_extract(
                decoded,
                url=url,
                output_format="txt",
                include_comments=False,
                include_links=False,
                favor_precision=True,
            )
        except (ImportError, RuntimeError, TypeError, ValueError):
            extracted = None
        if extracted:
            parser = _TextExtractor()
            parser.feed(decoded)
            title = html.unescape(" ".join(parser.title_parts))[:512]
            text = " ".join(extracted.split())[:max_text_chars]
            return title, text, parser.links[:200], "trafilatura"
        parser = _TextExtractor()
        parser.feed(decoded)
        title = html.unescape(" ".join(parser.title_parts))[:512]
        text = " ".join(parser.text_parts)[:max_text_chars]
        return title, text, parser.links[:200], "stdlib-htmlparser"
    return "", " ".join(decoded.split())[:max_text_chars], [], "stdlib-text"


@dataclass(frozen=True)
class CrawlPolicy:
    """Safety and resource limits for one bounded collection run."""

    user_agent: str = "SZL-WebEvidence/1.0 (+https://a11oy.net/)"
    allowed_hosts: frozenset[str] = field(default_factory=frozenset)
    timeout_seconds: float = 15.0
    max_urls: int = 25
    max_bytes_per_response: int = 1_500_000
    max_total_bytes: int = 20_000_000
    max_text_chars: int = 100_000
    min_delay_seconds: float = 1.0
    max_retries: int = 1
    same_host_only: bool = True
    allow_private_network: bool = False
    include_text: bool = False

    def __post_init__(self) -> None:
        if not self.allowed_hosts:
            raise PolicyError("HOST_ALLOWLIST_REQUIRED")
        if self.max_urls < 1 or self.max_bytes_per_response < 1 or self.max_total_bytes < 1:
            raise PolicyError("POSITIVE_BUDGET_REQUIRED")
        if self.timeout_seconds <= 0 or self.min_delay_seconds < 0 or self.max_retries < 0:
            raise PolicyError("INVALID_TIMING_POLICY")


@dataclass
class WebReceipt:
    url: str
    retrieved_at: str
    state: str
    reason: str | None = None
    evidence_class: str = "UNKNOWN"
    status: int | None = None
    fetched_url: str | None = None
    content_type: str | None = None
    bytes_read: int = 0
    body_sha256: str | None = None
    text_sha256: str | None = None
    title: str | None = None
    text: str | None = None
    link_count: int = 0
    extractor: str | None = None
    robots_url: str | None = None
    robots_status: int | None = None
    robots_sha256: str | None = None
    robots_allowed: bool | None = None
    robots_crawl_delay_seconds: float | None = None
    policy: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.evidence_class not in EVIDENCE_CLASSES:
            raise ValueError(f"unknown evidence class: {self.evidence_class}")

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


class _RedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, validate):
        super().__init__()
        self._validate = validate

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        target = urllib.parse.urljoin(req.full_url, newurl)
        self._validate(target)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class WebEvidenceCollector:
    """Sequential collector with per-host robots and request budgets."""

    def __init__(self, policy: CrawlPolicy):
        self.policy = policy
        self._last_request: dict[str, float] = {}
        self._robots: dict[str, tuple[urllib.robotparser.RobotFileParser, WebReceipt]] = {}
        self._total_bytes = 0

    def _validate(self, url: str, expected_host: str | None = None) -> urllib.parse.SplitResult:
        parsed = _assert_safe_url(
            url,
            allowed_hosts=self.policy.allowed_hosts,
            allow_private_network=self.policy.allow_private_network,
            expected_host=expected_host,
        )
        if parsed.hostname is None:
            raise PolicyError("URL_HOST_MISSING")
        return parsed

    def _wait(self, host: str) -> None:
        elapsed = time.monotonic() - self._last_request.get(host, 0.0)
        delay = self.policy.min_delay_seconds - elapsed
        if delay > 0:
            time.sleep(delay)
        self._last_request[host] = time.monotonic()

    def _read(self, response) -> bytes:
        declared = response.headers.get("Content-Length")
        if declared and declared.isdigit() and int(declared) > self.policy.max_bytes_per_response:
            raise BodyTooLarge("RESPONSE_BYTE_LIMIT")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = response.read(min(64 * 1024, self.policy.max_bytes_per_response + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > self.policy.max_bytes_per_response:
                raise BodyTooLarge("RESPONSE_BYTE_LIMIT")
            chunks.append(chunk)
        return b"".join(chunks)

    def _open(self, url: str, *, expected_host: str, accept: str):
        opener = urllib.request.build_opener(
            _RedirectHandler(lambda target: self._validate(target, expected_host if self.policy.same_host_only else None))
        )
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": self.policy.user_agent,
                "Accept": accept,
                "Accept-Encoding": "identity",
            },
        )
        for attempt in range(self.policy.max_retries + 1):
            self._wait(expected_host)
            try:
                return opener.open(req, timeout=self.policy.timeout_seconds)
            except urllib.error.HTTPError as exc:
                if exc.code in {429, 500, 502, 503, 504} and attempt < self.policy.max_retries:
                    retry_after = exc.headers.get("Retry-After")
                    try:
                        wait_for = min(float(retry_after), 30.0) if retry_after else 2.0**attempt
                    except ValueError:
                        wait_for = 2.0**attempt
                    time.sleep(max(0.0, wait_for))
                    continue
                raise
            except (urllib.error.URLError, TimeoutError, socket.timeout):
                if attempt < self.policy.max_retries:
                    time.sleep(min(2.0**attempt, 10.0))
                    continue
                raise

    def _robots_for(self, url: str, host: str) -> tuple[urllib.robotparser.RobotFileParser, WebReceipt]:
        if host in self._robots:
            return self._robots[host]
        parsed = urllib.parse.urlsplit(url)
        robots_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "/robots.txt", "", ""))
        robots_receipt = WebReceipt(
            url=robots_url,
            retrieved_at=_now(),
            state="UNKNOWN",
            robots_url=robots_url,
            policy={"user_agent": self.policy.user_agent},
        )
        parser = urllib.robotparser.RobotFileParser(robots_url)
        try:
            with self._open(robots_url, expected_host=host, accept="text/plain") as response:
                body = self._read(response)
                status = int(response.status)
                robots_receipt.status = status
                robots_receipt.robots_status = status
                robots_receipt.robots_sha256 = _sha256(body)
                robots_receipt.bytes_read = len(body)
                if self._total_bytes + len(body) > self.policy.max_total_bytes:
                    raise BodyTooLarge("TOTAL_BYTE_LIMIT")
                self._total_bytes += len(body)
                if 200 <= status < 300:
                    parser.parse(body.decode("utf-8", errors="replace").splitlines())
                    robots_receipt.state = "MEASURED"
                    robots_receipt.evidence_class = "MEASURED"
                else:
                    raise PolicyError("ROBOTS_UNEXPECTED_STATUS")
        except urllib.error.HTTPError as exc:
            robots_receipt.status = exc.code
            robots_receipt.robots_status = exc.code
            if exc.code in {401, 403, 429} or exc.code >= 500:
                robots_receipt.state = "BLOCKED"
                robots_receipt.evidence_class = "BLOCKED"
                robots_receipt.reason = "ROBOTS_UNAVAILABLE_FAIL_CLOSED"
                self._robots[host] = (parser, robots_receipt)
                return parser, robots_receipt
            if exc.code in {404, 410}:
                parser.parse([])
                robots_receipt.state = "MEASURED"
                robots_receipt.evidence_class = "MEASURED"
                robots_receipt.reason = "ROBOTS_NOT_PUBLISHED"
            else:
                robots_receipt.state = "UNAVAILABLE"
                robots_receipt.evidence_class = "UNAVAILABLE"
                robots_receipt.reason = "ROBOTS_HTTP_ERROR"
        except BodyTooLarge as exc:
            robots_receipt.state = "BLOCKED"
            robots_receipt.evidence_class = "BLOCKED"
            robots_receipt.reason = str(exc) or "ROBOTS_BYTE_LIMIT"
        except (urllib.error.URLError, TimeoutError, socket.timeout, PolicyError) as exc:
            robots_receipt.state = "BLOCKED"
            robots_receipt.evidence_class = "BLOCKED"
            robots_receipt.reason = "ROBOTS_UNREACHABLE_FAIL_CLOSED"
            if isinstance(exc, PolicyError):
                robots_receipt.reason = str(exc)
        robots_receipt.robots_allowed = parser.can_fetch(self.policy.user_agent, url)
        delay = parser.crawl_delay(self.policy.user_agent)
        robots_receipt.robots_crawl_delay_seconds = delay
        self._robots[host] = (parser, robots_receipt)
        return parser, robots_receipt

    def fetch(self, url: str) -> WebReceipt:
        retrieved_at = _now()
        base = {
            "user_agent": self.policy.user_agent,
            "max_bytes_per_response": self.policy.max_bytes_per_response,
            "max_total_bytes": self.policy.max_total_bytes,
            "same_host_only": self.policy.same_host_only,
        }
        try:
            parsed = self._validate(url)
            host = parsed.hostname.lower().rstrip(".")  # type: ignore[union-attr]
            parser, robots = self._robots_for(url, host)
            if robots.state == "BLOCKED":
                return WebReceipt(
                    url=url,
                    retrieved_at=retrieved_at,
                    state="BLOCKED",
                    reason=robots.reason or "ROBOTS_BLOCKED",
                    evidence_class="BLOCKED",
                    robots_url=robots.url,
                    robots_status=robots.status,
                    robots_sha256=robots.robots_sha256,
                    robots_allowed=False,
                    robots_crawl_delay_seconds=robots.robots_crawl_delay_seconds,
                    policy=base,
                )
            if not parser.can_fetch(self.policy.user_agent, url):
                return WebReceipt(
                    url=url,
                    retrieved_at=retrieved_at,
                    state="BLOCKED",
                    reason="ROBOTS_DISALLOW",
                    evidence_class="BLOCKED",
                    robots_url=robots.url,
                    robots_status=robots.status,
                    robots_sha256=robots.robots_sha256,
                    robots_allowed=False,
                    robots_crawl_delay_seconds=robots.robots_crawl_delay_seconds,
                    policy=base,
                )
            if self._total_bytes >= self.policy.max_total_bytes:
                raise PolicyError("TOTAL_BYTE_LIMIT")
            with self._open(url, expected_host=host, accept="text/html,application/xhtml+xml,text/plain") as response:
                status = int(response.status)
                content_type = response.headers.get_content_type()
                if content_type not in {"text/html", "application/xhtml+xml", "text/plain"}:
                    raise PolicyError("CONTENT_TYPE_NOT_ALLOWED")
                body = self._read(response)
                if self._total_bytes + len(body) > self.policy.max_total_bytes:
                    raise BodyTooLarge("TOTAL_BYTE_LIMIT")
                self._total_bytes += len(body)
                final_url = response.geturl()
                final_parsed = self._validate(final_url, host if self.policy.same_host_only else None)
                title, text, links, extractor = _extract(
                    body,
                    response.headers.get("Content-Type", content_type),
                    final_url,
                    self.policy.max_text_chars,
                )
                return WebReceipt(
                    url=url,
                    retrieved_at=retrieved_at,
                    state="MEASURED",
                    evidence_class="MEASURED",
                    status=status,
                    fetched_url=urllib.parse.urlunsplit(final_parsed),
                    content_type=content_type,
                    bytes_read=len(body),
                    body_sha256=_sha256(body),
                    text_sha256=_sha256(text),
                    title=title or None,
                    text=text if self.policy.include_text else None,
                    link_count=len(links),
                    extractor=extractor,
                    robots_url=robots.url,
                    robots_status=robots.status,
                    robots_sha256=robots.robots_sha256,
                    robots_allowed=True,
                    robots_crawl_delay_seconds=robots.robots_crawl_delay_seconds,
                    policy=base,
                )
        except urllib.error.HTTPError as exc:
            state = "BLOCKED" if exc.code in {401, 403, 429} else "UNAVAILABLE"
            return WebReceipt(
                url=url,
                retrieved_at=retrieved_at,
                state=state,
                reason=f"HTTP_{exc.code}",
                evidence_class=state,
                status=exc.code,
                policy=base,
            )
        except BodyTooLarge as exc:
            return WebReceipt(
                url=url,
                retrieved_at=retrieved_at,
                state="BLOCKED",
                reason=str(exc),
                evidence_class="BLOCKED",
                policy=base,
            )
        except PolicyError as exc:
            return WebReceipt(
                url=url,
                retrieved_at=retrieved_at,
                state="BLOCKED",
                reason=str(exc),
                evidence_class="BLOCKED",
                policy=base,
            )
        except (urllib.error.URLError, TimeoutError, socket.timeout, UnicodeError) as exc:
            return WebReceipt(
                url=url,
                retrieved_at=retrieved_at,
                state="UNAVAILABLE",
                reason=type(exc).__name__,
                evidence_class="UNAVAILABLE",
                policy=base,
            )

    def collect(self, urls: Iterable[str]) -> list[WebReceipt]:
        unique: list[str] = []
        seen: set[str] = set()
        for raw in urls:
            url = raw.strip()
            if not url or url.startswith("#") or url in seen:
                continue
            seen.add(url)
            unique.append(url)
        if len(unique) > self.policy.max_urls:
            raise PolicyError("URL_COUNT_LIMIT")
        receipts: list[WebReceipt] = []
        for url in unique:
            receipts.append(self.fetch(url))
        return receipts


def _read_urls(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("urls", nargs="*", help="explicit http(s) URLs")
    parser.add_argument("--url-file", type=Path, help="newline-delimited URL file")
    parser.add_argument("--allow-host", action="append", required=True)
    parser.add_argument("--out", type=Path, required=True, help="JSONL receipt path")
    parser.add_argument("--include-text", action="store_true")
    parser.add_argument("--max-urls", type=int, default=25)
    parser.add_argument("--max-bytes", type=int, default=1_500_000)
    parser.add_argument("--max-total-bytes", type=int, default=20_000_000)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--min-delay", type=float, default=1.0)
    args = parser.parse_args(argv)
    urls = list(args.urls)
    if args.url_file:
        urls.extend(_read_urls(args.url_file))
    try:
        policy = CrawlPolicy(
            allowed_hosts=frozenset(item.lower().rstrip(".") for item in args.allow_host),
            include_text=args.include_text,
            max_urls=args.max_urls,
            max_bytes_per_response=args.max_bytes,
            max_total_bytes=args.max_total_bytes,
            timeout_seconds=args.timeout,
            min_delay_seconds=args.min_delay,
        )
        receipts = WebEvidenceCollector(policy).collect(urls)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("w", encoding="utf-8", newline="\n") as handle:
            for receipt in receipts:
                handle.write(json.dumps(receipt.as_dict(), sort_keys=True) + "\n")
    except (OSError, PolicyError) as exc:
        print(f"web evidence failed: {exc}", file=sys.stderr)
        return 2
    measured = sum(item.state == "MEASURED" for item in receipts)
    print(json.dumps({"receipts": len(receipts), "measured": measured, "out": str(args.out)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
