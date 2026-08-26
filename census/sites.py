"""Site reachability, response-header, and DNS email-auth evidence."""
from __future__ import annotations

from typing import Any

import dns.exception
import dns.resolver

from .common import http_probe, resolve_txt

SITES = ["a-11-oy.com", "a11oy.net"]
DOMAINS = [
    "szlholdings.com",
    "a-11-oy.com",
    "a11oy.net",
    "alloyszlholdings.com",
    "killinchu.net",
]

DOMAIN_NOERROR = "NOERROR"
DOMAIN_NOERROR_NODATA = "NOERROR_NODATA"
DOMAIN_NXDOMAIN = "NXDOMAIN"
DOMAIN_UNKNOWN = "UNKNOWN"


def _resolve_domain_state(domain: str, timeout: float = 8.0) -> str:
    """Resolve domain existence without collapsing NXDOMAIN into NODATA."""
    try:
        dns.resolver.resolve(domain, "SOA", search=False, lifetime=timeout)
    except dns.resolver.NXDOMAIN:
        return DOMAIN_NXDOMAIN
    except dns.resolver.NoAnswer:
        return DOMAIN_NOERROR_NODATA
    except (dns.exception.Timeout, dns.resolver.NoNameservers, OSError):
        return DOMAIN_UNKNOWN
    return DOMAIN_NOERROR


def _record_evidence(value: str | None, marker: str) -> tuple[bool | None, str]:
    if value is None:
        return None, "UNKNOWN"
    present = marker in value.lower()
    return present, "PRESENT" if present else "MISSING"


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


def collect_dns() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for domain in DOMAINS:
        domain_state = _resolve_domain_state(domain)
        if domain_state == DOMAIN_NXDOMAIN:
            # Preserve precise record semantics while projecting False into the
            # legacy booleans so the existing governance gate fails closed.
            out[domain] = {
                "domain_state": DOMAIN_NXDOMAIN,
                "domain_availability": "REGISTRATION_OR_DELEGATION_UNAVAILABLE",
                "spf": False,
                "spf_status": "NOT_EVALUABLE",
                "dmarc": False,
                "dmarc_status": "NOT_EVALUABLE",
                "dmarc_reject": False,
                "dmarc_reject_status": "NOT_EVALUABLE",
                "overall_status": "FAIL_CLOSED",
            }
            continue
        if domain_state == DOMAIN_UNKNOWN:
            out[domain] = {
                "domain_state": DOMAIN_UNKNOWN,
                "domain_availability": "UNKNOWN",
                "spf": None,
                "spf_status": "UNKNOWN",
                "dmarc": None,
                "dmarc_status": "UNKNOWN",
                "dmarc_reject": None,
                "dmarc_reject_status": "UNKNOWN",
                "overall_status": "UNKNOWN",
            }
            continue

        spf = resolve_txt(domain)
        dmarc = resolve_txt(f"_dmarc.{domain}")
        spf_present, spf_status = _record_evidence(spf, "v=spf1")
        dmarc_present, dmarc_status = _record_evidence(dmarc, "v=dmarc1")
        dmarc_reject, dmarc_reject_status = _record_evidence(dmarc, "p=reject")
        record_values = (spf_present, dmarc_present, dmarc_reject)
        if any(value is None for value in record_values):
            overall_status = "UNKNOWN"
        elif all(value is True for value in record_values):
            overall_status = "PASS"
        else:
            overall_status = "FAIL"
        out[domain] = {
            "domain_state": domain_state,
            "domain_availability": "DNS_NAME_OBSERVED",
            "spf": spf_present,
            "spf_status": spf_status,
            "dmarc": dmarc_present,
            "dmarc_status": dmarc_status,
            "dmarc_reject": dmarc_reject,
            "dmarc_reject_status": dmarc_reject_status,
            "overall_status": overall_status,
        }
    return out
