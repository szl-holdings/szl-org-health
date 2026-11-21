"""Assemble independently bounded collectors into one schema-v2 report.

The collector cache holds the internal evidence view. Callers receive a public,
secret-safe projection by default; the full evidence view requires the explicit
``exposure="internal"`` opt-in.
"""

from __future__ import annotations

import concurrent.futures as cf
import copy
import hashlib
import json
import os
import re
import time
import uuid
from collections.abc import Callable, Mapping
from typing import Any

from .github import collect_github
from .github_ci import ci_evidence
from .head_ci import SCOPE as HEAD_CI_SCOPE, STATES as HEAD_CI_STATES
from .governance import evaluate_report
from .huggingface import collect_huggingface
from .sites import collect_dns, collect_sites

SCHEMA_VERSION = 2
PUBLIC_PROJECTION_SCHEMA = "szl.estate-public-projection/v1"
_CACHE: dict[str, Any] = {"data": None, "ts": 0.0}
_CACHE_TTL = 60
_EXPOSURES = {"public", "internal"}


def _timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _observed_collection(collector: Callable[[], Any]) -> tuple[dict, dict]:
    observation = {"started_at": _timestamp()}
    try:
        source = {"ok": True, "data": collector()}
    except Exception as exc:  # independent source failure remains visible
        source = {"ok": False, "error": str(exc)[:160]}
    observation["completed_at"] = _timestamp()
    return source, observation


def _public_collection(value: Any) -> dict | None:
    """Collection timing is public; subject and private source digests are not."""
    if not isinstance(value, Mapping) or value.get("schema") != "szl.census-collection/v1":
        return None
    identity = value.get("id")
    if not isinstance(identity, str) or not re.fullmatch(r"[0-9a-f]{32}", identity):
        return None
    times = {key: value.get(key) for key in ("started_at", "completed_at")}
    if any(not isinstance(t, str) or not _UTC_TIMESTAMP.fullmatch(t) for t in times.values()):
        return None
    return {"schema": "szl.census-collection/v1", "id": identity, **times}
_HF_ASSET_KINDS = (
    "models",
    "datasets",
    "spaces",
    "kernels",
    "collections",
    "buckets",
)
_PUBLIC_GITHUB_REPO = re.compile(r"^[A-Za-z0-9_.-]+$")
_PUBLIC_HF_IDENTIFIER = re.compile(
    r"^SZLHOLDINGS/([A-Za-z0-9](?:[A-Za-z0-9._-]{0,94}[A-Za-z0-9])?)$",
    re.IGNORECASE,
)
_UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GITHUB_CLASSIFICATIONS = {
    "archive",
    "control-plane",
    "production",
    "product-surface",
    "research",
    "unclassified",
}
_GITHUB_CI_STATES = {"success", "failure", "pending", "unknown", "archived"}
_SITE_NAMES = ("a-11-oy.com", "a11oy.net")
_DNS_NAMES = (
    "szlholdings.com",
    "a-11-oy.com",
    "a11oy.net",
    "alloyszlholdings.com",
    "killinchu.net",
)
_DNS_ENUMS = {
    "domain_state": {"NOERROR", "NOERROR_NODATA", "NXDOMAIN", "UNKNOWN"},
    "domain_availability": {
        "DNS_NAME_OBSERVED",
        "REGISTRATION_OR_DELEGATION_UNAVAILABLE",
        "UNKNOWN",
    },
    "spf_status": {"PRESENT", "MISSING", "NOT_EVALUABLE", "UNKNOWN"},
    "dmarc_status": {"PRESENT", "MISSING", "NOT_EVALUABLE", "UNKNOWN"},
    "dmarc_reject_status": {
        "PRESENT",
        "MISSING",
        "NOT_EVALUABLE",
        "UNKNOWN",
    },
    "overall_status": {"PASS", "FAIL", "FAIL_CLOSED", "UNKNOWN"},
}
_SPACE_READINESS_ENUMS = {
    "readiness_state": {
        "NOT_EVALUATED", "UNKNOWN", "TRANSITIONING", "NOT_READY",
        "SOURCE_CONFLICT", "SCOPED_READY_SOURCE_BOUND",
        "SCOPED_READY_SOURCE_UNVERIFIED", "SCOPED_READY_UNVERIFIED",
        "PRODUCTION_HOLD", "PLACEHOLDER", "CONTENT_PRESENT_UNVERIFIED",
    },
    "readiness_scope": {
        "NOT_EVALUATED", "SERVING_PROCESS", "ACTION_AUTHORITY",
        "OPERATOR_PLANE", "STATIC_CONTENT", "PUBLIC_RETRIEVAL_REVIEW",
        "SOURCE_FEED", "INFERENCE_CONFIGURATION",
    },
    "readiness_route": {
        "/", "/readyz", "/api/ready", "/api/anatomy/v1/frontier/status",
        "/readyz/inference",
    },
    "declared_head_match": {"MATCH", "DRIFT", "UNKNOWN", "UNAVAILABLE"},
}


def _error_present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (str, list, tuple, dict)):
        return bool(value)
    return True


def _public_hf_authentication(_value: Any) -> dict[str, Any]:
    """Expose no credential, identity, grant, membership, or probe posture."""
    return {
        "evidence_scope": "PUBLIC_PROJECTION",
        "organization_complete": False,
    }


_HF_COMMON_STRING_FIELDS = ("sha", "last_modified", "card_state")
_HF_COMMON_BOOLEAN_FIELDS = (
    "card_present",
    "license_declared",
    "managed_marker_present",
    "provenance_marker_present",
)
_HF_COMMON_INTEGER_FIELDS = (
    "likes",
    "downloads_30d",
    "file_count_observed",
)
_HF_KIND_STRING_FIELDS = {
    "models": (
        "pipeline_tag",
        "contract",
        "weight_state",
        "artifact_state",
        "payload_manifest_state",
    ),
    "datasets": (),
    "spaces": (
        "sdk",
        "stage",
        "subdomain",
        "source_revision",
        "source_binding_state",
        "operational_state",
    ),
    "kernels": (
        "metadata_state",
        "tree_state",
        "contract_state",
        "selfcheck_state",
    ),
    "collections": ("title", "owner", "last_updated"),
    "buckets": ("created_at", "updated_at", "tree_state", "documentation_state"),
}
_HF_KIND_BOOLEAN_FIELDS = {
    "models": ("payload_manifest_aggregate_verified",),
    "datasets": (),
    "spaces": ("healthz_contract",),
    "kernels": ("build_variants_present",),
    "collections": ("complete",),
    "buckets": ("readme_present",),
}
_HF_KIND_INTEGER_FIELDS = {
    "models": (
        "payload_manifest_declared_files",
        "payload_manifest_verified_files",
    ),
    "datasets": (),
    "spaces": ("http", "healthz", "build_info_http"),
    "kernels": (),
    "collections": ("upvotes",),
    "buckets": ("size_bytes", "total_files"),
}
_HF_KIND_STRING_LIST_FIELDS = {
    "models": (
        "weight_files_observed",
        "estimator_files_observed",
        "embedding_files_observed",
        "model_artifact_files_observed",
        "payload_manifest_missing_files",
        "payload_manifest_mismatched_files",
    ),
    "datasets": (),
    "spaces": (),
    "kernels": (),
    "collections": (),
    "buckets": (),
}


def _bounded_string(value: Any, *, maximum: int = 4096) -> str | None:
    if not isinstance(value, str) or not value or len(value) > maximum:
        return None
    return value


def _public_hf_identifier(value: Any) -> str | None:
    identifier = _bounded_string(value, maximum=512)
    match = _PUBLIC_HF_IDENTIFIER.fullmatch(identifier or "")
    if match is None:
        return None
    return f"SZLHOLDINGS/{match.group(1)}"


def _public_hf_url(kind: str, identifier: str) -> str:
    if kind == "models":
        return f"https://huggingface.co/{identifier}"
    route = {
        "datasets": "datasets",
        "spaces": "spaces",
        "kernels": "kernels",
        "collections": "collections",
        "buckets": "buckets",
    }[kind]
    return f"https://huggingface.co/{route}/{identifier}"


def _public_hardware(value: Any) -> str | dict[str, str] | None:
    if isinstance(value, str):
        return _bounded_string(value, maximum=128)
    if not isinstance(value, Mapping):
        return None
    projected = {
        field: bounded
        for field in ("current", "requested")
        if (bounded := _bounded_string(value.get(field), maximum=128)) is not None
    }
    return projected or None


def _public_hf_item(value: Mapping[str, Any], kind: str) -> dict[str, Any] | None:
    identifier_field = "slug" if kind == "collections" else "id"
    identifier = _public_hf_identifier(value.get(identifier_field))
    if value.get("private") is not False or identifier is None:
        return None

    projected: dict[str, Any] = {
        identifier_field: identifier,
        "private": False,
        "url": _public_hf_url(kind, identifier),
    }
    for field in _HF_COMMON_STRING_FIELDS + _HF_KIND_STRING_FIELDS[kind]:
        bounded = _bounded_string(value.get(field))
        if bounded is not None:
            projected[field] = bounded
    for field in _HF_COMMON_BOOLEAN_FIELDS + _HF_KIND_BOOLEAN_FIELDS[kind]:
        nested = value.get(field)
        if nested is None or isinstance(nested, bool):
            projected[field] = nested
    for field in _HF_COMMON_INTEGER_FIELDS + _HF_KIND_INTEGER_FIELDS[kind]:
        nested = value.get(field)
        if isinstance(nested, int) and not isinstance(nested, bool):
            projected[field] = nested
        elif nested is None:
            projected[field] = None
    for field in _HF_KIND_STRING_LIST_FIELDS[kind]:
        nested = value.get(field)
        if isinstance(nested, list):
            projected[field] = [
                bounded
                for item in nested[:1000]
                if (bounded := _bounded_string(item, maximum=2048)) is not None
            ]
    if kind == "spaces":
        hardware = _public_hardware(value.get("hardware"))
        if hardware is not None:
            projected["hardware"] = hardware
        runtime_revision = value.get("runtime_revision")
        if isinstance(runtime_revision, str) and re.fullmatch(r"[0-9a-f]{40}", runtime_revision):
            projected["runtime_revision"] = runtime_revision
        for field, allowed in _SPACE_READINESS_ENUMS.items():
            candidate = value.get(field)
            if isinstance(candidate, str) and candidate in allowed:
                projected[field] = candidate
        readiness_http = value.get("readiness_http")
        if type(readiness_http) is int and 100 <= readiness_http <= 599:
            projected["readiness_http"] = readiness_http
        if type(value.get("production_ready_declared")) is bool:
            projected["production_ready_declared"] = value["production_ready_declared"]
    return projected


def _public_hf_asset(value: Any, kind: str) -> dict[str, Any]:
    """Return one closed-schema public asset class."""
    if not isinstance(value, Mapping):
        return {
            "ok": False,
            "count": None,
            "diagnostic_state": "INVALID_RESPONSE",
            "error": "SOURCE_UNAVAILABLE",
            "items": [],
        }

    raw_items = value.get("items")
    items_valid = isinstance(raw_items, list)
    public_items: list[dict[str, Any]] = []
    if items_valid:
        for raw_item in raw_items:
            if not isinstance(raw_item, Mapping):
                continue
            item = _public_hf_item(raw_item, kind)
            if item is not None:
                public_items.append(item)

    ok = (
        value.get("ok") is True
        and items_valid
        and not _error_present(value.get("error"))
    )
    return {
        "ok": ok,
        "count": len(public_items) if ok else None,
        "diagnostic_state": (
            "AVAILABLE" if ok else "INVALID_RESPONSE"
            if not items_valid or value.get("diagnostic_state") == "INVALID_RESPONSE"
            else "SOURCE_UNAVAILABLE"
        ),
        "error": None if ok else "SOURCE_UNAVAILABLE",
        "items": public_items,
    }


def _complete_asset_items(
    assets: Mapping[str, Any], kind: str
) -> list[dict[str, Any]] | None:
    asset = assets.get(kind)
    if (
        not isinstance(asset, Mapping)
        or asset.get("ok") is not True
        or not isinstance(asset.get("items"), list)
    ):
        return None
    return [item for item in asset["items"] if isinstance(item, dict)]


def _count(
    items: list[dict[str, Any]] | None,
    predicate: Callable[[dict[str, Any]], bool],
) -> int | None:
    return sum(1 for item in items if predicate(item)) if items is not None else None


def _reachable(item: Mapping[str, Any]) -> bool:
    try:
        status = int(item.get("http") or 0)
    except (TypeError, ValueError):
        return False
    return 200 <= status < 400


def _public_hf_summary(assets: Mapping[str, Any]) -> dict[str, Any]:
    """Recalculate every Hugging Face summary metric from public-only items."""
    summary: dict[str, Any] = {
        kind: (
            assets[kind].get("count")
            if isinstance(assets.get(kind), Mapping) and assets[kind].get("ok") is True
            else None
        )
        for kind in _HF_ASSET_KINDS
    }
    spaces = _complete_asset_items(assets, "spaces")
    kernels = _complete_asset_items(assets, "kernels")
    buckets = _complete_asset_items(assets, "buckets")
    models = _complete_asset_items(assets, "models")

    summary.update(
        {
            "running_spaces": _count(
                spaces, lambda item: item.get("stage") == "RUNNING"
            ),
            "reachable_spaces": _count(spaces, _reachable),
            "dynamic_spaces": _count(spaces, lambda item: item.get("sdk") != "static"),
            "healthz_spaces": _count(spaces, lambda item: item.get("healthz") == 200),
            "source_bound_spaces": _count(
                spaces,
                lambda item: item.get("source_binding_state") == "OBSERVED",
            ),
            "operational_source_bound_spaces": _count(
                spaces,
                lambda item: (
                    item.get("operational_state") == "OPERATIONAL_SOURCE_BOUND"
                ),
            ),
            "reachable_unverified_spaces": _count(
                spaces,
                lambda item: item.get("operational_state") == "REACHABLE_UNVERIFIED",
            ),
            "complete_space_cards": _count(
                spaces, lambda item: item.get("card_state") == "COMPLETE"
            ),
            "kernels_with_observed_metadata": _count(
                kernels, lambda item: item.get("metadata_state") == "OBSERVED"
            ),
            "kernels_with_complete_contracts": _count(
                kernels, lambda item: item.get("contract_state") == "COMPLETE"
            ),
            "documented_buckets": _count(
                buckets,
                lambda item: item.get("documentation_state") == "COMPLETE",
            ),
            "models_with_observed_weights": _count(
                models, lambda item: item.get("weight_state") == "weights-present"
            ),
            "models_with_observed_estimators": _count(
                models, lambda item: bool(item.get("estimator_files_observed"))
            ),
            "models_with_observed_artifacts": _count(
                models, lambda item: item.get("artifact_state") == "artifact-present"
            ),
            "models_with_classified_contracts": _count(
                models, lambda item: item.get("contract") != "unclassified"
            ),
            "models_with_satisfied_artifact_expectations": _count(
                models,
                lambda item: (
                    item.get("artifact_state")
                    in {
                        "artifact-present",
                        "not-required-by-contract",
                        "payload-manifest-verified",
                    }
                ),
            ),
            "models_with_verified_payload_manifests": _count(
                models,
                lambda item: item.get("payload_manifest_state") == "verified",
            ),
            "models_with_incomplete_payload_manifests": _count(
                models,
                lambda item: item.get("payload_manifest_state") == "incomplete",
            ),
        }
    )
    return summary


def _public_hf_data(value: Any) -> dict[str, Any]:
    raw = value if isinstance(value, Mapping) else {}
    raw_assets = raw.get("assets") if isinstance(raw.get("assets"), Mapping) else {}
    assets = {
        kind: _public_hf_asset(raw_assets.get(kind), kind) for kind in _HF_ASSET_KINDS
    }
    return {
        "organization": (
            "SZLHOLDINGS" if raw.get("organization") == "SZLHOLDINGS" else None
        ),
        "authentication": _public_hf_authentication(raw.get("authentication")),
        "assets": assets,
        "summary": _public_hf_summary(assets),
    }


def _public_github_repo(name: Any, value: Any) -> dict[str, Any] | None:
    """Project one repository only when its public visibility is explicit."""
    if (
        not isinstance(name, str)
        or not _PUBLIC_GITHUB_REPO.fullmatch(name)
        or not isinstance(value, Mapping)
        or value.get("visibility") != "public"
    ):
        return None
    if "private" in value and value.get("private") is not False:
        return None
    if "public" in value and value.get("public") is not True:
        return None

    archived = value.get("archived")
    fork = value.get("fork")
    protected = value.get("protected")
    classification = value.get("classification")
    ci = value.get("ci")
    coverage = ci_evidence(value)
    if ci not in {"failure", "archived"} and coverage["ci_coverage"] != "COMPLETE":
        ci = "unknown"
    if ci == "success" and coverage["run_window_observed"] == 0:
        ci = "unknown"
    if ci == "archived" and archived is not True:
        ci = "unknown"
    return {
        "visibility": "public",
        "archived": archived if isinstance(archived, bool) else None,
        "fork": fork if isinstance(fork, bool) else None,
        "ci": ci if ci in _GITHUB_CI_STATES else "unknown",
        # Head observation is a separate, bracketed, explicitly non-release claim.
        "head_ci": (
            value.get("head_ci")
            if value.get("head_ci_scope") == HEAD_CI_SCOPE
            and value.get("head_ci") in HEAD_CI_STATES else "UNAVAILABLE"
        ),
        "head_ci_scope": HEAD_CI_SCOPE,
        **coverage,
        "protected": protected if isinstance(protected, bool) else None,
        "classification": (
            classification
            if classification in _GITHUB_CLASSIFICATIONS
            else "unclassified"
        ),
        "url": f"https://github.com/szl-holdings/{name}",
    }


def _public_github_data(value: Any) -> dict[str, Any]:
    raw = value if isinstance(value, Mapping) else {}
    raw_repos = raw.get("repos") if isinstance(raw.get("repos"), Mapping) else {}
    repos: dict[str, dict[str, Any]] = {}
    for name, raw_repo in raw_repos.items():
        projected = _public_github_repo(name, raw_repo)
        if projected is not None:
            repos[name] = projected
    repos = dict(sorted(repos.items()))

    classifications: dict[str, int] = {}
    for repo in repos.values():
        key = str(repo["classification"])
        classifications[key] = classifications.get(key, 0) + 1
    return {
        "discovery": {
            "complete": False,
            "scope": "public-projection",
            "diagnostic_state": "PUBLIC_REPOSITORIES_ONLY",
        },
        "summary": {
            "total": len(repos),
            "active": sum(
                1 for repo in repos.values() if repo.get("archived") is False
            ),
            "archived": sum(
                1 for repo in repos.values() if repo.get("archived") is True
            ),
            "ci_green": sum(
                1 for repo in repos.values() if repo.get("ci") == "success"
            ),
            "ci_red": sum(1 for repo in repos.values() if repo.get("ci") == "failure"),
            "ci_unknown": sum(
                1 for repo in repos.values() if repo.get("ci") in {"unknown", "pending"}
            ),
            "classifications": classifications,
        },
        "repos": repos,
        # Organization-wide counts can include private repositories and are
        # therefore never copied into the public projection.
        "alerts": {
            "code_scanning_open": None,
            "code_scanning_high": None,
            "secret_scanning_open": None,
            "dependabot_open": None,
            "complete": False,
            "diagnostic_state": "INTERNAL_ONLY",
        },
        "open_prs": None,
        "open_issues": None,
    }


def _public_sites_data(value: Any) -> dict[str, Any]:
    raw = value if isinstance(value, Mapping) else {}
    projected: dict[str, Any] = {}
    for name in _SITE_NAMES:
        site = raw.get(name) if isinstance(raw.get(name), Mapping) else {}
        status = site.get("http")
        projected[name] = {
            "http": (
                status
                if isinstance(status, int)
                and not isinstance(status, bool)
                and 100 <= status <= 599
                else None
            ),
            **{
                field: (site.get(field) if isinstance(site.get(field), bool) else None)
                for field in ("hsts", "csp", "xfo", "nosniff")
            },
        }
    return projected


def _public_dns_data(value: Any) -> dict[str, Any]:
    raw = value if isinstance(value, Mapping) else {}
    projected: dict[str, Any] = {}
    for name in _DNS_NAMES:
        domain = raw.get(name) if isinstance(raw.get(name), Mapping) else {}
        entry: dict[str, Any] = {
            field: (domain.get(field) if isinstance(domain.get(field), bool) else None)
            for field in ("spf", "dmarc", "dmarc_reject")
        }
        for field, allowed in _DNS_ENUMS.items():
            raw_state = domain.get(field)
            entry[field] = raw_state if raw_state in allowed else "UNKNOWN"
        projected[name] = entry
    return projected


def _public_source(
    name: str,
    value: Any,
    projector: Callable[[Any], dict[str, Any]],
) -> dict[str, Any]:
    raw = value if isinstance(value, Mapping) else {}
    data = raw.get("data") if isinstance(raw.get("data"), Mapping) else {}

    if name == "github":
        # The public report deliberately omits private repositories and
        # organization-wide alert totals, so it cannot be a complete source for
        # controls that require the whole estate. Observed failures remain in
        # the projected data and governance can still fail closed on them.
        subset_observed = (not _error_present(raw.get("error"))
                          and isinstance(raw.get("data"), Mapping)) and (
            raw.get("ok") is True or (
                raw.get("diagnostic_state") == "PUBLIC_SUBSET"
                and isinstance(raw.get("data"), Mapping)
            )
        )
        projected = projector(data)
        if not subset_observed:
            # An error-bearing source wrapper cannot lend its old rows a
            # CURRENT_HEAD_GREEN observation. Preserve historical failures.
            projected["repos"] = {
                repo: {**row, "head_ci": "UNAVAILABLE"}
                for repo, row in projected.get("repos", {}).items()
            }
        return {
            "ok": False,
            "diagnostic_state": (
                "PUBLIC_SUBSET" if subset_observed else "SOURCE_UNAVAILABLE"
            ),
            "error": None if subset_observed else "SOURCE_UNAVAILABLE",
            "data": projected,
        }

    ok = (raw.get("ok") is True and isinstance(raw.get("data"), Mapping)
          and not _error_present(raw.get("error")))
    return {
        "ok": ok,
        "diagnostic_state": "AVAILABLE" if ok else "SOURCE_UNAVAILABLE",
        "error": None if ok else "SOURCE_UNAVAILABLE",
        "data": projector(data),
    }


def serialize_report(report: Mapping[str, Any]) -> str:
    """Return the canonical UTF-8 JSON text used for snapshot digests."""
    if not isinstance(report, Mapping):
        raise TypeError("report must be a mapping")
    return json.dumps(report, separators=(",", ":"), sort_keys=True) + "\n"


def project_public_report(internal_report: Mapping[str, Any]) -> dict[str, Any]:
    """Build a deterministic closed-schema view without mutating its input."""
    if not isinstance(internal_report, Mapping):
        raise TypeError("report must be a mapping")

    raw_generated_at = internal_report.get("generated_at")
    generated_at = (
        raw_generated_at
        if isinstance(raw_generated_at, str)
        and _UTC_TIMESTAMP.fullmatch(raw_generated_at)
        else None
    )
    raw_sources = (
        internal_report.get("sources")
        if isinstance(internal_report.get("sources"), Mapping)
        else {}
    )
    raw_source_digest = internal_report.get("source_snapshot_sha256")
    source_snapshot_sha256 = (
        raw_source_digest
        if internal_report.get("projection_schema") == PUBLIC_PROJECTION_SCHEMA
        and internal_report.get("exposure") == "public"
        and isinstance(raw_source_digest, str)
        and _SHA256.fullmatch(raw_source_digest)
        else hashlib.sha256(
            serialize_report(internal_report).encode("utf-8")
        ).hexdigest()
    )
    public: dict[str, Any] = {
        "schema_version": (
            SCHEMA_VERSION
            if internal_report.get("schema_version") == SCHEMA_VERSION
            else None
        ),
        "projection_schema": PUBLIC_PROJECTION_SCHEMA,
        "source_snapshot_sha256": source_snapshot_sha256,
        "generated_at": generated_at,
        "collection": _public_collection(internal_report.get("collection")),
        "exposure": "public",
        "sources": {
            "github": _public_source(
                "github", raw_sources.get("github"), _public_github_data
            ),
            "huggingface": _public_source(
                "huggingface", raw_sources.get("huggingface"), _public_hf_data
            ),
            "sites": _public_source(
                "sites", raw_sources.get("sites"), _public_sites_data
            ),
            "dns": _public_source("dns", raw_sources.get("dns"), _public_dns_data),
        },
    }

    # Internal governance may contain private identifiers in bounded examples.
    # Recompute exclusively from the projected inputs instead of copying it.
    public["governance"] = evaluate_report(public)
    return public


def build_report(
    *,
    exposure: str = "public",
    use_cache: bool = True,
    github_timeout: float = 20.0,
    github_retries: int = 2,
    include_branch_protection: bool = True,
) -> dict[str, Any]:
    """Build a public report by default or an explicit internal evidence view."""
    if exposure not in _EXPOSURES:
        raise ValueError(f"unsupported report exposure: {exposure!r}")

    now = time.time()
    cached = _CACHE.get("data")
    if use_cache and cached and now - float(_CACHE.get("ts") or 0) < _CACHE_TTL:
        return (
            copy.deepcopy(cached)
            if exposure == "internal"
            else project_public_report(cached)
        )

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _timestamp(),
        "exposure": "internal",
        "sources": {},
    }
    collection = {
        "schema": "szl.census-collection/v1",
        "id": uuid.uuid4().hex,
        "started_at": report["generated_at"],
        "subject": {
            "repository": os.environ.get("GITHUB_REPOSITORY"),
            "workflow_sha": os.environ.get("GITHUB_SHA"),
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        },
        "source_observations": {},
    }
    collectors: dict[str, Callable[[], Any]] = {
        "github": lambda: collect_github(
            request_timeout=github_timeout,
            retries=github_retries,
            include_branch_protection=include_branch_protection,
        ),
        "huggingface": collect_huggingface,
        "sites": collect_sites,
        "dns": collect_dns,
    }
    with cf.ThreadPoolExecutor(max_workers=len(collectors)) as executor:
        futures = {executor.submit(_observed_collection, fn): name for name, fn in collectors.items()}
        for future in cf.as_completed(futures):
            name = futures[future]
            source, observation = future.result()
            report["sources"][name] = source
            collection["source_observations"][name] = observation

    collection["completed_at"] = _timestamp()
    collection["sources_sha256"] = hashlib.sha256(
        serialize_report(report["sources"]).encode("utf-8")
    ).hexdigest()
    report["generated_at"] = collection["completed_at"]
    report["collection"] = collection

    # Additive schema-v2 field. Policy evaluation is bounded to this exact
    # census and fails closed without changing source evidence.
    report["governance"] = evaluate_report(report)
    _CACHE["data"] = report
    _CACHE["ts"] = now
    return (
        copy.deepcopy(report)
        if exposure == "internal"
        else project_public_report(report)
    )
