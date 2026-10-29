"""Small public portal view over the already-closed estate projection.

This module performs no provider reads. Its observations describe a public
subset or HTTP transport only; cross-surface parity, runtime readiness, model
evaluation, and release authority remain unknown.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping
from typing import Any

from .report import PUBLIC_PROJECTION_SCHEMA, SCHEMA_VERSION, project_public_report

SCHEMA = "szl.portal-evidence-index/v1"
MAX_OBSERVATION_AGE_SECONDS = 24 * 60 * 60
_ASSET_KINDS = ("models", "datasets", "spaces", "kernels", "collections", "buckets")
_URLS = {
    "github": "https://github.com/szl-holdings",
    "huggingface": "https://huggingface.co/SZLHOLDINGS",
    "product": "https://a-11-oy.com",
    "proof": "https://a11oy.net",
}


def _utc_text(value: dt.datetime) -> str:
    return value.astimezone(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_utc(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _age_seconds(report: Mapping[str, Any], now: dt.datetime) -> int | None:
    collection = report.get("collection")
    if not isinstance(collection, Mapping) or collection.get("schema") != "szl.census-collection/v1":
        return None
    started = _parse_utc(collection.get("started_at"))
    completed = _parse_utc(collection.get("completed_at"))
    if (
        started is None
        or completed is None
        or collection.get("started_at") != report.get("generated_at")
        or started > completed
        or completed > now
    ):
        return None
    return int((now - completed).total_seconds())


def _source(report: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    sources = report.get("sources")
    value = sources.get(name) if isinstance(sources, Mapping) else None
    return value if isinstance(value, Mapping) else {}


def _data(source: Mapping[str, Any]) -> Mapping[str, Any]:
    value = source.get("data")
    return value if isinstance(value, Mapping) else {}


def _http_status(source: Mapping[str, Any], domain: str, recent: bool) -> int | None:
    if not recent or source.get("ok") is not True:
        return None
    site = _data(source).get(domain)
    status = site.get("http") if isinstance(site, Mapping) else None
    return status if type(status) is int and 100 <= status <= 599 else None


def project_portal_index(
    public_report: Mapping[str, Any], *, as_of: dt.datetime | None = None
) -> dict[str, Any]:
    """Return a typed index without admitting raw internal census data.

    The report is projected a second time before selecting fields, so unknown
    extensions, private rows, and arbitrary provider text cannot flow through.
    A recent collection is an observation window, never an authorization gate.
    """

    if (
        not isinstance(public_report, Mapping)
        or public_report.get("projection_schema") != PUBLIC_PROJECTION_SCHEMA
        or public_report.get("schema_version") != SCHEMA_VERSION
        or public_report.get("exposure") != "public"
    ):
        raise ValueError("a closed public estate projection is required")
    if as_of is not None and (not isinstance(as_of, dt.datetime) or as_of.tzinfo is None):
        raise ValueError("as_of must be timezone-aware")

    now = (as_of or dt.datetime.now(dt.UTC)).astimezone(dt.UTC).replace(microsecond=0)
    report = project_public_report(public_report)
    age = _age_seconds(report, now)
    recent = age is not None and age <= MAX_OBSERVATION_AGE_SECONDS

    github = _source(report, "github")
    original_github = _source(public_report, "github")
    repos = _data(github).get("repos")
    github_observed = (
        recent
        and original_github.get("ok") is False
        and original_github.get("diagnostic_state") == "PUBLIC_SUBSET"
        and original_github.get("error") is None
        and github.get("diagnostic_state") == "PUBLIC_SUBSET"
        and isinstance(repos, Mapping)
    )
    github_count = len(repos) if github_observed else None

    huggingface = _source(report, "huggingface")
    assets = _data(huggingface).get("assets")
    asset_counts: dict[str, int | None] = {}
    for kind in _ASSET_KINDS:
        group = assets.get(kind) if isinstance(assets, Mapping) else None
        items = group.get("items") if isinstance(group, Mapping) else None
        asset_counts[kind] = (
            len(items)
            if recent and huggingface.get("ok") is True
            and isinstance(group, Mapping) and group.get("ok") is True
            and isinstance(items, list)
            else None
        )
    huggingface_observed = any(count is not None for count in asset_counts.values())

    sites = _source(report, "sites")
    product_http = _http_status(sites, "a-11-oy.com", recent)
    proof_http = _http_status(sites, "a11oy.net", recent)

    return {
        "schema": SCHEMA,
        "generated_at": report.get("generated_at"),
        "collection": report.get("collection"),
        "freshness": {
            "evaluated_at": _utc_text(now),
            "age_seconds": age,
            "within_24h": recent,
        },
        "layers": {
            "github": {
                "url": _URLS["github"],
                "evidence_class": "MEASURED" if github_observed else "UNKNOWN",
                "scope": "public-repository-subset",
                "public_repositories": github_count,
                "limit": "A public subset does not prove organization-complete discovery or protected CI.",
            },
            "huggingface": {
                "url": _URLS["huggingface"],
                "evidence_class": "MEASURED" if huggingface_observed else "UNKNOWN",
                "scope": "public-asset-subsets",
                "public_asset_counts": asset_counts,
                "limit": "Each unavailable asset class remains null; Hub metadata does not prove inference.",
            },
            "product": {
                "url": _URLS["product"],
                "evidence_class": "MEASURED" if product_http is not None else "UNKNOWN",
                "scope": "http-transport",
                "http_status": product_http,
                "limit": "HTTP status does not prove runtime readiness, source parity, or authorization.",
            },
            "proof": {
                "url": _URLS["proof"],
                "evidence_class": "MEASURED" if proof_http is not None else "UNKNOWN",
                "scope": "http-transport",
                "http_status": proof_http,
                "limit": "HTTP status does not verify a receipt or independent witness.",
            },
        },
        "claim_boundaries": {
            "github_to_huggingface_parity": "UNKNOWN",
            "huggingface_to_product_parity": "UNKNOWN",
            "product_to_proof_verification": "UNKNOWN",
            "runtime_readiness": "UNKNOWN",
            "model_evaluation": "UNKNOWN",
            "release_authority": "UNKNOWN",
        },
    }
