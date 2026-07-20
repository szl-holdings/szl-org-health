"""Site reachability, response-header, and DNS email-auth evidence."""
from __future__ import annotations

from typing import Any

from .common import http_probe, resolve_txt

SITES = ["a-11-oy.com", "a11oy.net"]
DOMAINS = [
    "szlholdings.com",
    "a-11-oy.com",
    "a11oy.net",
    "alloyszlholdings.com",
    "killinchu.net",
]


def collect_sites() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for site in SITES:
        probe = http_probe(f"https://{site}/")
        headers = probe.get("headers") or {}
        out[site] = {
            "http": probe.get("http"),
            "error": probe.get("error"),
            "hsts": "strict-transport-security" in headers,
            "csp": "content-security-policy" in headers,
            "xfo": "x-frame-options" in headers,
            "nosniff": headers.get("x-content-type-options", "").lower()
            == "nosniff",
        }
    return out


def collect_dns() -> dict[str, dict[str, bool | None]]:
    out: dict[str, dict[str, bool | None]] = {}
    for domain in DOMAINS:
        spf = resolve_txt(domain)
        dmarc = resolve_txt(f"_dmarc.{domain}")
        out[domain] = {
            "spf": None if spf is None else "v=spf1" in spf.lower(),
            "dmarc": None if dmarc is None else "v=dmarc1" in dmarc.lower(),
            "dmarc_reject": None
            if dmarc is None
            else "p=reject" in dmarc.lower(),
        }
    return out
