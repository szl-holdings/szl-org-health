"""Bounded, evidence-labelled readiness observations for documented public Spaces.

This is an additive product/readiness layer. It never upgrades a Hub RUNNING
label, a successful root request, or a source claim into production authority.
Only the listed public, source-documented GET routes are contacted.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any

from .common import request_bytes, request_json
from .vertical_contracts import classify_anatomy, classify_anatomy_version, classify_router

SHA40 = re.compile(r"^[0-9a-f]{40}$")

CONTRACTS = {
    "SZLHOLDINGS/a11oy": ("/readyz", "SERVING_PROCESS"),
    "SZLHOLDINGS/szl-second-brain": ("/readyz", "PUBLIC_RETRIEVAL_REVIEW"),
    "SZLHOLDINGS/anatomy": ("/api/anatomy/v1/frontier/status", "SOURCE_FEED"),
    "SZLHOLDINGS/szl-router-control": ("/readyz/inference", "INFERENCE_CONFIGURATION"),
    "SZLHOLDINGS/immune-lattice": ("/readyz", "ACTION_AUTHORITY"),
    "SZLHOLDINGS/szl-frontier": ("/api/ready", "OPERATOR_PLANE"),
    "SZLHOLDINGS/szl-brand-campaign": ("/", "STATIC_CONTENT"),
    "SZLHOLDINGS/szl-router-control": ("/readyz/inference", "INFERENCE_CONFIGURATION"),
    "SZLHOLDINGS/llm-router-live": ("/readyz/inference", "PUBLIC_ROUTER_STATUS"),
    "SZLHOLDINGS/anatomy": ("/evidence", "RELEASE_EVIDENCE"),
}

VERTICAL_ORIGINS = {
    "SZLHOLDINGS/szl-router-control": "szlholdings-szl-router-control.hf.space",
    "SZLHOLDINGS/llm-router-live": "szlholdings-llm-router-live.hf.space",
    "SZLHOLDINGS/anatomy": "szlholdings-anatomy.hf.space",
}

VERTICAL_GET_PATHS = frozenset(
    (host, CONTRACTS[repo_id][0]) for repo_id, host in VERTICAL_ORIGINS.items()
) | {(VERTICAL_ORIGINS["SZLHOLDINGS/anatomy"], "/version")}


def _status(error: str | None, payload: Any) -> int | None:
    if error is None and payload is not None:
        return 200
    if isinstance(error, str) and error.startswith("http") and error[4:].isdigit():
        return int(error[4:])
    return None


def _json(
    root_url: str, route: str, *, fixed_origin: bool = False, max_bytes: int = 8192,
) -> tuple[dict[str, Any] | None, int | None]:
    # A hostile route must never override a previously checked Space root.
    if fixed_origin and (not isinstance(route, str) or not route.startswith("/")
                         or route.startswith("//") or "?" in route or "#" in route):
        return None, None
    url = urllib.parse.urljoin(root_url, route.lstrip("/"))
    bounds: dict[str, object] = {}
    if fixed_origin:
        try:
            origin = urllib.parse.urlsplit(root_url)
            parsed = urllib.parse.urlsplit(url)
        except ValueError:
            return None, None
        if (origin.scheme != "https" or (origin.netloc, route) not in VERTICAL_GET_PATHS
                or parsed.scheme != "https" or parsed.netloc != origin.netloc
                or parsed.query or parsed.fragment):
            return None, None
        bounds = {
            "redirect_origin": ("https", str(origin.hostname).casefold(), 443),
            "redirect_path": parsed.path,
        }
    payload, _, error = request_json(
        url, timeout=6, retries=0, max_bytes=max_bytes, **bounds,
    )
    return (payload if isinstance(payload, dict) else None), _status(error, payload)


def _result(
    state: str,
    route: str,
    scope: str,
    reason: str,
    *,
    http: int | None = None,
    production_ready_declared: bool | None = None,
    declared_head_match: str | None = None,
) -> dict[str, Any]:
    return {
        "readiness_state": state,
        "readiness_route": route,
        "readiness_scope": scope,
        "readiness_reason": reason,
        "readiness_http": http,
        "production_ready_declared": production_ready_declared,
        "declared_head_match": declared_head_match,
    }


def _a11oy(
    root_url: str,
    route: str,
    scope: str,
    source_binding: dict[str, Any],
) -> dict[str, Any]:
    ready, status = _json(root_url, route)
    if status == 503:
        return _result("NOT_READY", route, scope, "READINESS_HTTP_503", http=status)
    if status != 200 or ready is None:
        return _result("UNKNOWN", route, scope, "READINESS_UNAVAILABLE", http=status)
    if ready.get("status") != "ready" or ready.get("organ") != "a11oy":
        return _result("NOT_READY", route, scope, "READINESS_NOT_ASSERTED", http=status)

    honest, honest_status = _json(root_url, "/api/a11oy/v1/honest")
    served_sha = honest.get("git_sha") if honest else None
    if honest_status != 200 or not isinstance(served_sha, str) or not SHA40.fullmatch(served_sha):
        return _result("UNKNOWN", route, scope, "SERVED_SOURCE_UNAVAILABLE", http=status)
    declared_sha = source_binding.get("source_revision")
    if isinstance(declared_sha, str) and SHA40.fullmatch(declared_sha) and declared_sha != served_sha:
        return _result("SOURCE_CONFLICT", route, scope, "SERVED_SOURCE_MISMATCH", http=status)
    if source_binding.get("source_binding_state") == "INVALID":
        return _result("SOURCE_CONFLICT", route, scope, "SOURCE_BINDING_INVALID", http=status)
    if source_binding.get("source_binding_state") == "OBSERVED" and declared_sha == served_sha:
        return _result(
            "SCOPED_READY_SOURCE_BOUND", route, scope, "SERVING_CONTRACT_OBSERVED", http=status
        )
    return _result(
        "SCOPED_READY_SOURCE_UNVERIFIED", route, scope,
        "SERVING_CONTRACT_OBSERVED_SOURCE_UNVERIFIED", http=status,
    )


def _second_brain(root_url: str, route: str, scope: str) -> dict[str, Any]:
    """Check only public retrieval and review. This Space is not Khipu inference."""
    payload, status = _json(root_url, route)
    if status == 503:
        return _result("NOT_READY", route, scope, "RETRIEVAL_HTTP_503", http=status)
    if status != 200 or payload is None:
        return _result("UNKNOWN", route, scope, "RETRIEVAL_UNAVAILABLE", http=status)
    if payload.get("schema") != "szl.second-brain.readiness/v1":
        return _result("UNKNOWN", route, scope, "RETRIEVAL_SCHEMA_UNKNOWN", http=status)
    if payload.get("ready") is False:
        return _result("NOT_READY", route, scope, "PUBLIC_RETRIEVAL_NOT_READY", http=status)
    if payload.get("ready") is not True or payload.get("state") != "READY":
        return _result("UNKNOWN", route, scope, "RETRIEVAL_READINESS_UNVERIFIED", http=status)
    if (payload.get("scope") != "PUBLIC_RETRIEVAL_AND_REVIEW"
            or payload.get("runtime_mode") != "BM25_ONLY"
            or payload.get("model_generation") != "NOT_CONFIGURED"
            or payload.get("execution_authority") != "NONE"):
        return _result("UNKNOWN", route, scope, "RETRIEVAL_SCOPE_CHANGED", http=status)
    return _result(
        "SCOPED_READY_UNVERIFIED", route, scope,
        "PUBLIC_RETRIEVAL_SELF_REPORTED_NO_MODEL_INFERENCE", http=status,
    )


def _anatomy(root_url: str, route: str, scope: str) -> dict[str, Any]:
    """Two independent source feeds; never tests or certifies a WebGL renderer."""
    status_doc, status = _json(root_url, route)
    if status == 503:
        return _result("NOT_READY", route, scope, "FRONTIER_STATUS_HTTP_503", http=status)
    if status != 200 or status_doc is None:
        return _result("UNKNOWN", route, scope, "FRONTIER_STATUS_UNAVAILABLE", http=status)
    if status_doc.get("schema") != "szl.anatomy.frontier-status/v1":
        return _result("UNKNOWN", route, scope, "FRONTIER_STATUS_SCHEMA_UNKNOWN", http=status)
    if status_doc.get("ready") is False:
        return _result("NOT_READY", route, scope, "FRONTIER_STATUS_NOT_READY", http=status)
    if status_doc.get("ready") is not True or status_doc.get("state") != "SOURCE_BOUND_REVIEW_MEMORY":
        return _result("UNKNOWN", route, scope, "FRONTIER_STATUS_UNVERIFIED", http=status)

    holo, holo_http = _json(root_url, "/api/anatomy/v1/holographic-v7")
    if holo_http == 503:
        return _result("NOT_READY", route, scope, "HOLOGRAPHIC_SOURCE_HTTP_503", http=holo_http)
    if holo_http != 200 or holo is None:
        return _result("UNKNOWN", route, scope, "HOLOGRAPHIC_SOURCE_UNAVAILABLE", http=holo_http)
    if holo.get("schema") != "szl.anatomy.holographic-v7/v1":
        return _result("UNKNOWN", route, scope, "HOLOGRAPHIC_SCHEMA_UNKNOWN", http=holo_http)
    if holo.get("ready") is False:
        return _result("NOT_READY", route, scope, "HOLOGRAPHIC_SOURCE_NOT_READY", http=holo_http)
    if holo.get("ready") is not True or holo.get("state") != "SOURCE_BOUND_READ_ONLY":
        return _result("UNKNOWN", route, scope, "HOLOGRAPHIC_SOURCE_UNVERIFIED", http=holo_http)
    frontier = holo.get("frontier")
    if not isinstance(frontier, dict):
        return _result("UNKNOWN", route, scope, "HOLOGRAPHIC_FRONTIER_MISSING", http=holo_http)

    # Bind both source-read surfaces to the same source *claim*. Actual protected
    # GitHub main, Hub commit, signing and renderer checks are separate authorities.
    required = (
        "schema", "ready", "state", "candidate_count", "candidate_set_sha256",
        "second_brain_source_repository", "second_brain_source_revision",
        "content_access", "execution_authority", "promotion_authority",
        "training_authority", "raw_graph_nodes_admitted_to_gradients",
        "private_graph_present",
    )
    if any(status_doc.get(key) != frontier.get(key) for key in required):
        return _result("SOURCE_CONFLICT", route, scope, "HOLOGRAPHIC_FRONTIER_CONFLICT", http=holo_http)
    if (status_doc.get("content_access") != "HANDLES_ONLY"
            or status_doc.get("execution_authority") != "NONE"
            or status_doc.get("promotion_authority") != "NONE"
            or status_doc.get("training_authority") != "NONE"
            or status_doc.get("private_graph_present") is not False
            or type(status_doc.get("raw_graph_nodes_admitted_to_gradients")) is not int
            or status_doc["raw_graph_nodes_admitted_to_gradients"] != 0):
        return _result("NOT_READY", route, scope, "SOURCE_AUTHORITY_BOUNDARY_FAILED", http=holo_http)
    if (status_doc.get("second_brain_source_repository") != "szl-holdings/szl-second-brain"
            or type(status_doc.get("second_brain_source_revision")) is not str
            or SHA40.fullmatch(status_doc["second_brain_source_revision"]) is None
            or type(status_doc.get("candidate_count")) is not int
            or not 0 <= status_doc["candidate_count"] <= 100000
            or type(status_doc.get("candidate_set_sha256")) is not str
            or re.fullmatch(r"[0-9a-f]{64}", status_doc["candidate_set_sha256"]) is None):
        return _result("UNKNOWN", route, scope, "SOURCE_IDENTITY_UNVERIFIED", http=holo_http)
    return _result(
        "SCOPED_READY_UNVERIFIED", route, scope,
        "HANDLES_ONLY_FEEDS_SELF_REPORTED_WEBGL_AND_SIGNATURE_UNVERIFIED", http=holo_http,
    )


def _router_inference(root_url: str, route: str, scope: str) -> dict[str, Any]:
    """503 is intentionally unconfigured; 200 can only be config self-report."""
    payload, status = _json(root_url, route)
    if status == 503:
        return _result("NOT_READY", route, scope, "INFERENCE_HTTP_503_DEFAULT_DENY", http=status)
    if status != 200 or payload is None:
        return _result("UNKNOWN", route, scope, "INFERENCE_READINESS_UNAVAILABLE", http=status)
    if payload.get("ready_for_requests") is False or payload.get("status") == "unavailable":
        return _result("NOT_READY", route, scope, "INFERENCE_CONFIGURATION_NOT_READY", http=status)
    checks = payload.get("checks")
    if (payload.get("ready_for_requests") is not True
            or not isinstance(checks, dict)
            or any(checks.get(key) is not True for key in (
                "registry_valid", "egress_enabled",
                "caller_auth_configured", "provider_configured",
            ))
            or (
                not isinstance(payload.get("model_identity"), str)
                or not payload["model_identity"].strip()
                or payload["model_identity"] in ("UNVERIFIED", "UNKNOWN")
            )
        ):
        return _result("UNKNOWN", route, scope, "INFERENCE_CONFIG_EVIDENCE_INCOMPLETE", http=status)
    return _result(
        "SCOPED_READY_UNVERIFIED", route, scope,
        "CONFIGURATION_ONLY_REAL_COMPLETION_AND_SIGNATURE_UNVERIFIED", http=status,
    )


def _immune_lattice(root_url: str, route: str, scope: str) -> dict[str, Any]:
    ready, status = _json(root_url, route)
    if status == 503:
        return _result("NOT_READY", route, scope, "READINESS_HTTP_503", http=status)
    if status != 200 or ready is None:
        return _result("UNKNOWN", route, scope, "READINESS_UNAVAILABLE", http=status)
    if ready.get("schema") != "szl.immune-readiness/v1":
        return _result("UNKNOWN", route, scope, "READINESS_SCHEMA_UNKNOWN", http=status)
    required = ("ready", "runtime_ready", "read_ready", "authority_ready", "write_ready")
    if ready.get("status") == "NOT_READY" or any(ready.get(field) is False for field in required):
        return _result("NOT_READY", route, scope, "ACTION_AUTHORITY_NOT_READY", http=status)
    if ready.get("status") != "READY" or any(ready.get(field) is not True for field in required):
        return _result("UNKNOWN", route, scope, "READINESS_NOT_ASSERTED", http=status)
    # A route's self-report cannot establish external signing or action authority.
    return _result("SCOPED_READY_UNVERIFIED", route, scope, "AUTHORITY_SELF_REPORTED", http=status)


def _frontier(root_url: str, route: str, scope: str) -> dict[str, Any]:
    ready, status = _json(root_url, route)
    if status != 200 or ready is None or ready.get("schema") != "szl.frontier.readiness/v1":
        return _result("UNKNOWN", route, scope, "READINESS_UNAVAILABLE", http=status)
    source, source_status = _json(root_url, "/api/source")
    if source_status != 200 or source is None or source.get("schema") != "szl.frontier.source-identity/v1":
        return _result("UNKNOWN", route, scope, "SOURCE_IDENTITY_UNAVAILABLE", http=status)

    production = ready.get("productionReady")
    if not isinstance(production, bool):
        return _result("UNKNOWN", route, scope, "PRODUCTION_FLAG_UNKNOWN", http=status)
    head_match = source.get("headMatch")
    if not isinstance(head_match, str) or head_match not in {
        "MATCH", "DRIFT", "UNKNOWN", "UNAVAILABLE"
    }:
        return _result("UNKNOWN", route, scope, "SOURCE_HEAD_MATCH_INVALID", http=status)
    if ready.get("ready") is not True:
        return _result(
            "NOT_READY", route, scope, "OPERATOR_PLANE_NOT_READY", http=status,
            production_ready_declared=production, declared_head_match=head_match,
        )
    if (
        production is False
        or ready.get("productionAuthorization") is False
        or source.get("productionAuthorization") is False
        or head_match == "DRIFT"
        or source.get("runtimeVerified") is False
    ):
        reason = "DECLARED_SOURCE_DRIFT" if head_match == "DRIFT" else "PRODUCTION_HOLD"
        return _result(
            "PRODUCTION_HOLD", route, scope, reason, http=status,
            production_ready_declared=production, declared_head_match=head_match,
        )
    if (
        ready.get("productionAuthorization") is not True
        or source.get("productionAuthorization") is not True
        or source.get("runtimeVerified") is not True
        or head_match != "MATCH"
    ):
        return _result(
            "UNKNOWN", route, scope, "PRODUCTION_EVIDENCE_INCOMPLETE", http=status,
            production_ready_declared=production, declared_head_match=head_match,
        )
    return _result(
        "SCOPED_READY_UNVERIFIED", route, scope, "PRODUCTION_SELF_REPORTED_ONLY",
        http=status, production_ready_declared=production, declared_head_match=head_match,
    )


def _brand_campaign(root_url: str, route: str, scope: str) -> dict[str, Any]:
    # Keep a finite ceiling while allowing the current public campaign page.
    raw, _, error = request_bytes(root_url, timeout=6, retries=0, max_bytes=16384)
    status = _status(error, raw)
    if status != 200 or raw is None:
        return _result("UNKNOWN", route, scope, "STATIC_CONTENT_UNAVAILABLE", http=status)
    try:
        html = raw.decode("utf-8")
    except UnicodeDecodeError:
        return _result("UNKNOWN", route, scope, "STATIC_CONTENT_INVALID", http=status)
    if "<title>My static Space</title>" in html and "Welcome to your static Space!" in html:
        return _result("PLACEHOLDER", route, scope, "STOCK_STATIC_TEMPLATE", http=status)
    return _result("CONTENT_PRESENT_UNVERIFIED", route, scope, "CONTENT_NOT_QUALIFIED", http=status)



def _critical_vertical(
    root_url: str,
    repo_id: str,
    route: str,
    scope: str,
    item: dict[str, Any],
    source_binding: dict[str, Any],
) -> dict[str, Any]:
    """Only fixed HTTPS Space origins; no credentials, POSTs or provider calls."""
    if (repo_id not in VERTICAL_ORIGINS or CONTRACTS.get(repo_id) != (route, scope)):
        return _result("UNKNOWN", route, scope, "VERTICAL_CONTRACT_MISMATCH")
    try:
        parsed = urllib.parse.urlsplit(root_url)
    except ValueError:
        return _result("UNKNOWN", route, scope, "RUNTIME_ORIGIN_MISMATCH")
    if (parsed.scheme != "https" or parsed.netloc != VERTICAL_ORIGINS[repo_id]
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
        return _result("UNKNOWN", route, scope, "RUNTIME_ORIGIN_MISMATCH")

    if repo_id == "SZLHOLDINGS/anatomy":
        version, version_http = _json(root_url, "/version", fixed_origin=True)
        # Reject source conflicts before observing an unrelated evidence revision.
        first = classify_anatomy_version(version, version_http, item.get("sha"), source_binding)
        if first is not None:
            state, reason = first
            return _result(state, "/version", scope, reason, http=version_http)
        evidence, evidence_http = _json(root_url, route, fixed_origin=True, max_bytes=32768)
        state, reason = classify_anatomy(
            version, version_http, evidence, evidence_http, item.get("sha"), source_binding,
        )
        return _result(state, route, scope, reason, http=evidence_http)

    observation, http = _json(root_url, route, fixed_origin=True)
    state, reason = classify_router(
        observation, http, public_status=repo_id == "SZLHOLDINGS/llm-router-live",
    )
    return _result(state, route, scope, reason, http=http)


def collect_space_readiness(
    item: dict[str, Any], root_url: str | None, source_binding: dict[str, Any]
) -> dict[str, Any]:
    """Project only documented public GETs; keep provider/source layers distinct."""
    repo_id = item.get("id")
    if not isinstance(repo_id, str):
        return _result("NOT_EVALUATED", "", "NOT_EVALUATED", "INVALID_SPACE_ID")
    contract = CONTRACTS.get(repo_id)
    if contract is None or item.get("private") is not False:
        return _result("NOT_EVALUATED", "", "NOT_EVALUATED", "NO_PUBLIC_CONTRACT")
    route, scope = contract
    if not isinstance(root_url, str) or not root_url.startswith("https://"):
        return _result("UNKNOWN", route, scope, "RUNTIME_URL_UNAVAILABLE")
    if not isinstance(source_binding, dict):
        source_binding = {}
    runtime = item.get("runtime") if isinstance(item.get("runtime"), dict) else {}
    hub_sha = item.get("sha")
    runtime_sha = runtime.get("sha")
    stage = runtime.get("stage")
    if not isinstance(stage, str):
        return _result("UNKNOWN", route, scope, "PROVIDER_STAGE_INVALID")
    # Preserve explicit provider failures while treating recognized rollout stages as transitional.
    if stage in {"APP_STARTING", "RUNNING_APP_STARTING", "BUILDING", "RUNNING_BUILDING", "STARTING", "STOPPING"}:
        return _result("TRANSITIONING", route, scope, "HUB_RUNTIME_REVISION_MISMATCH")
    if stage != "RUNNING":
        return _result("NOT_READY", route, scope, "PROVIDER_NOT_RUNNING")
    if (
        isinstance(hub_sha, str)
        and SHA40.fullmatch(hub_sha)
        and isinstance(runtime_sha, str)
        and SHA40.fullmatch(runtime_sha)
        and hub_sha != runtime_sha
    ):
        return _result("TRANSITIONING", route, scope, "HUB_RUNTIME_REVISION_MISMATCH")
    if repo_id != "SZLHOLDINGS/szl-brand-campaign" and (
        not isinstance(hub_sha, str)
        or not SHA40.fullmatch(hub_sha)
        or not isinstance(runtime_sha, str)
        or not SHA40.fullmatch(runtime_sha)
    ):
        return _result("UNKNOWN", route, scope, "RUNTIME_REVISION_UNAVAILABLE")
    if repo_id in VERTICAL_ORIGINS:
        return _critical_vertical(root_url, repo_id, route, scope, item, source_binding)
    if repo_id == "SZLHOLDINGS/a11oy":
        return _a11oy(root_url, route, scope, source_binding)
    if repo_id == "SZLHOLDINGS/szl-second-brain":
        return _second_brain(root_url, route, scope)
    if repo_id == "SZLHOLDINGS/anatomy":
        return _anatomy(root_url, route, scope)
    if repo_id == "SZLHOLDINGS/szl-router-control":
        return _router_inference(root_url, route, scope)
    if repo_id == "SZLHOLDINGS/immune-lattice":
        return _immune_lattice(root_url, route, scope)
    if repo_id == "SZLHOLDINGS/szl-frontier":
        return _frontier(root_url, route, scope)
    return _brand_campaign(root_url, route, scope)
