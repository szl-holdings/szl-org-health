#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read-only design patterns mapped to the already closed public SZL evidence.

Reference: Coder-World04/Complete-System-Design, pinned README-only MIT catalog.
This is SZL-original Python application logic, NOT vendor code, not an agent,
not a provider client, not an authorization algorithm and not a benchmark.
"""
from __future__ import annotations

import html
import re
from collections.abc import Mapping
from typing import Any

from .portal_projection import SCHEMA as PORTAL_SCHEMA

SCHEMA = "szl.system-design-evidence-map/v1"
REFERENCE = {
    "repo": "Coder-World04/Complete-System-Design",
    "revision": "b92daa9595f23974e64e55d8ad0a942d75a64d56",
    "readme_sha256": "88b2fb2c7274c23658547b287a6e86ff6a4a095136cf850d877d183c717fccc5",
    "license": "MIT",
    "kind": "EDUCATIONAL_LINK_CATALOG_NOT_SOFTWARE",
    "tracked_files": 2,
    "case_study_table_rows": 41,
    "unique_table_labels": 31,
    "source_url": "https://github.com/Coder-World04/Complete-System-Design/tree/b92daa9595f23974e64e55d8ad0a942d75a64d56",
}
# Original SZL review obligations inspired by topic *names*, not borrowed
# case-study text, implementations or unverified third-party statistics.
# These are source-owner candidates and tests yet to be executed, not passes.
_CONTROLS = (
    ("scaling", "Horizontal and vertical scaling", "UPSTREAM_TOPIC",
     "szl-gpu-bridge", "Track actual replica allocation, burst versus steady load, GPU architecture and recovery.",
     "Pinned head, runtime/GPU witness, 2x-load p95 and rollback receipt."),
    ("load-balancing", "Load balancing and backpressure", "UPSTREAM_TOPIC",
     "szl-router", "Distinguish chosen provider from served response; reject ungoverned fallback.",
     "Matched routes, bounded queue pressure, failure-injection and replay."),
    ("queues", "Message queues and reliable delivery", "UPSTREAM_TOPIC",
     "szl-lake", "Protect append-only receipt identity across partial writes, retries and restarts.",
     "Real durable acknowledgment, duplicate/id-conflict tests and surviving chain head."),
    ("cache-index", "Caching, indexing and proxy boundaries", "UPSTREAM_TOPIC",
     "szl-retrieval-bench", "Bind derived results to source revision, tenant, TTL and invalidation.",
     "Cache-staleness and cross-tenant tests with exact dataset/version receipts."),
    ("network-cdn", "Network and CDN delivery", "UPSTREAM_TOPIC",
     "a11oy-net", "Separate origin, edge HTTP, challenge, deployed byte parity and signed proof.",
     "Origin/edge exact revision, TLS, CSP and paid/unpaid edge behavior."),
    ("sql-consistency", "Sharding, database consistency and schema design", "UPSTREAM_TOPIC",
     "david-leads", "Keep migrations separate from least-privilege transactional runtime.",
     "Neon RLS under runtime role, migration and restoration from disposable backup."),
    ("api-contracts", "API boundaries and versioned components", "UPSTREAM_TOPIC",
     "a11oy", "Make frontend route declarations match backend API schemas and middleware.",
     "Recorded browser/API parity, denied writes and source-bound contract tests."),
    ("concurrency", "Concurrency and failure recovery", "UPSTREAM_TOPIC",
     "szl-org-health", "Bound handlers, retry fanout, stale data and independent source outages.",
     "Timeout/429/5xx flood tests, stable unknowns and bounded active requests."),
    ("capacity-planning", "Performance planning and estimation", "UPSTREAM_TOPIC",
     "szl-org-health", "Keep source-complete inventory separate from observed readiness and cost.",
     "Dated active/archived denominators, stress envelope and dollars-per-verified-outcome."),
    ("ml-evaluation", "Machine-learning system-design case studies", "UPSTREAM_TOPIC",
     "frontier-bench", "Hold model promotion until held-out evaluation and artifact lineage agree.",
     "Pinned dataset, model revision, baseline delta, failures, safety and rollback."),
    ("release-provenance", "Reproducible release and publishing", "SZL_EXTENSION",
     "szl-org-health", "Connect GitHub attestations to HF serving, Cloudflare origin, and PyPI artifacts.",
     "Same-revision install/serve receipt, signed artifact, OIDC publishing and payment settlement."),
)
_PLATFORMS = (
    ("github", "GitHub", "https://github.com/szl-holdings"),
    ("huggingface", "Hugging Face", "https://huggingface.co/SZLHOLDINGS"),
    ("product", "Product", "https://a-11-oy.com"),
    ("proof", "Proof", "https://a11oy.net"),
    ("cloudflare", "Cloudflare monetization", "https://developers.cloudflare.com/monetization-gateway/"),
    ("pypi", "PyPI", "https://pypi.org/org/szl-holdings/"),
)
_DATE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
_ROLES = frozenset({"PUBLIC_SUBSET_OBSERVED", "HTTP_TRANSPORT_OBSERVED", "UNKNOWN"})
_LAYER_SCOPE = {"github": "public-repository-subset", "huggingface": "public-asset-subsets",
                "product": "http-transport", "proof": "http-transport"}
_OWNER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,99}$")


def _utc(value: Any) -> str | None:
    return value if type(value) is str and _DATE.fullmatch(value) else None


def _platform_state(name: str, layer: Any, recent: bool) -> tuple[str, int | None]:
    """Only already-closed public subsets are allowed to become observations."""
    if not recent or type(layer) is not dict or layer.get("evidence_class") != "MEASURED":
        return "UNKNOWN", None
    if layer.get("scope") != _LAYER_SCOPE.get(name):
        return "UNKNOWN", None
    if name in ("product", "proof"):
        code = layer.get("http_status")
        return ("HTTP_TRANSPORT_OBSERVED", code) if type(code) is int and 100 <= code <= 599 else ("UNKNOWN", None)
    if name == "github":
        count = layer.get("public_repositories")
        return ("PUBLIC_SUBSET_OBSERVED", count) if type(count) is int and 0 <= count <= 100000 else ("UNKNOWN", None)
    if name == "huggingface":
        counts = layer.get("public_asset_counts")
        if type(counts) is not dict or not counts:
            return "UNKNOWN", None
        if not all(value is None or (type(value) is int and 0 <= value <= 100000) for value in counts.values()):
            return "UNKNOWN", None
        observed = [value for value in counts.values() if value is not None]
        return ("PUBLIC_SUBSET_OBSERVED", sum(observed)) if observed else ("UNKNOWN", None)
    return "UNKNOWN", None


def project_system_design(portal: Mapping[str, Any]) -> dict[str, Any]:
    """A minimized, strict explanation; NEVER a model/publisher admission gate."""
    if not isinstance(portal, Mapping) or portal.get("schema") != PORTAL_SCHEMA:
        raise ValueError("closed portal evidence is required")
    freshness = portal.get("freshness")
    layers = portal.get("layers")
    if not isinstance(freshness, Mapping) or not isinstance(layers, Mapping):
        raise ValueError("portal contract unavailable")
    recent = freshness.get("within_24h") is True and _utc(freshness.get("evaluated_at")) is not None
    seen_at = _utc(portal.get("generated_at"))
    if seen_at is None:
        recent = False
    sources: list[dict[str, Any]] = []
    for key, title, url in _PLATFORMS:
        state, count = _platform_state(key, layers.get(key), recent)
        if state not in _ROLES:
            state, count = "UNKNOWN", None
        sources.append({
            "id": key, "title": title, "url": url, "observation": state,
            "observed_count_or_http": count,
            "scope": _LAYER_SCOPE.get(key, "NOT_OBSERVED_BY_THIS_COLLECTOR"),
            "production_qualified": False,
            "meaning": ("Historical/public subset only; excludes private estate and protected-main checks."
                        if key == "github" else
                        "Public asset subset only; no model inference, deployment revision or signatures."
                        if key == "huggingface" else
                        "HTTP transport status only, not a successful auth, settlement or signed receipt."
                        if key in ("product", "proof") else
                        "This public census performs no account-level Cloudflare or PyPI verification."),
        })
    controls = []
    for key, title, origin, owner, concern, test in _CONTROLS:
        if _OWNER_RE.fullmatch(owner) is None:
            raise ValueError("candidate owner invalid")
        controls.append({
            "id": key, "title": title, "pattern_source": origin,
            "candidate_owner": f"szl-holdings/{owner}",
            "candidate_owner_url": f"https://github.com/szl-holdings/{owner}",
            "SZL_adaptation": concern, "proof_required": test,
            "qualification": "NOT_EVALUATED", "action_authorized": False,
        })
    return {
        "schema": SCHEMA, "mode": "READ_ONLY_DESIGN_REVIEW",
        "source": dict(REFERENCE),
        "generated_from": PORTAL_SCHEMA,
        "estate_observed_at": seen_at if recent else None,
        "freshness": "PUBLIC_SNAPSHOT_RECENT" if recent else "UNAVAILABLE_OR_STALE",
        "private_estate_included": False,
        "production_ready": False, "model_qualified": False,
        "payment_settlement_verified": False, "pypi_oidc_verified": False,
        "signature_created": False, "provider_writes": 0,
        "controls": controls, "platforms": sources,
        "release_chain": [
            {"from": "github", "to": "huggingface", "state": "NOT_VERIFIED",
             "required": "Protected source SHA and deployment artifact revision are equal."},
            {"from": "huggingface", "to": "product", "state": "NOT_VERIFIED",
             "required": "Live runtime and product origin bind the same exact source plus readiness."},
            {"from": "product", "to": "proof", "state": "NOT_VERIFIED",
             "required": "Independent signed proof and live route bytes verify the same artifact."},
            {"from": "product", "to": "cloudflare", "state": "NOT_VERIFIED",
             "required": "Origin validates x402 PAYMENT-CONTEXT and paid settlement is reconciled."},
            {"from": "github", "to": "pypi", "state": "NOT_VERIFIED",
             "required": "Trusted Publisher OIDC release links exact GitHub source and installed wheel."},
        ],
        "research_boundary": (
            "Referenced upstream repository is a two-file educational MIT README/link catalog. "
            "It does not ship any implemented service, test suite, Python package or audited case-study code."
        ),
        "claims_not_established": (
            "organization-complete inventory", "full-stack runtime readiness", "private repository CI",
            "model accuracy", "production promotion", "paid settlement", "PyPI attestations",
        ),
    }


def render_html(snapshot: dict[str, Any]) -> bytes:
    """Source-only Python HTML, no JavaScript, remote assets, forms or browser secrets."""
    if (type(snapshot) is not dict or snapshot.get("schema") != SCHEMA
            or snapshot.get("mode") != "READ_ONLY_DESIGN_REVIEW"
            or snapshot.get("source") != REFERENCE
            or snapshot.get("production_ready") is not False
            or snapshot.get("provider_writes") != 0):
        raise ValueError("invalid design-map schema")
    # All owner links are constant-bound to known SZL repositories; an
    # arbitrary caller-supplied URL must never become clickable HTML.
    expected_owners = {f"https://github.com/szl-holdings/{c[3]}" for c in _CONTROLS}
    if any(row.get("candidate_owner_url") not in expected_owners for row in snapshot.get("controls", ())):
        raise ValueError("unapproved owner URL")
    expected_platforms = {key: url for key, _, url in _PLATFORMS}
    if any(row.get("url") != expected_platforms.get(row.get("id")) for row in snapshot.get("platforms", ())):
        raise ValueError("unapproved platform URL")

    def esc(text: Any) -> str:
        return html.escape(str(text), quote=True)

    lines = []
    for p in snapshot["platforms"]:
        metric = p["observed_count_or_http"]
        metric = "not observed" if metric is None else str(metric)
        lines.append(
            "<article class='platform'><h3>" + esc(p["title"]) + "</h3><p>"
            + esc(p["observation"]) + " · " + esc(metric) + "</p><p class='quiet'>"
            + esc(p["meaning"]) + "</p><a href='" + esc(p["url"])
            + "' rel='noopener noreferrer'>Inspect existing surface</a></article>"
        )
    controls = []
    for c in snapshot["controls"]:
        controls.append(
            "<article class='control'><p class='tag'>" + esc(c["pattern_source"])
            + " · " + esc(c["qualification"]) + "</p><h3>" + esc(c["title"])
            + "</h3><p>" + esc(c["SZL_adaptation"]) + "</p>"
            + "<p class='quiet'><strong>Required evidence:</strong> " + esc(c["proof_required"])
            + "</p><a href='" + esc(c["candidate_owner_url"])
            + "' rel='noopener noreferrer'>" + esc(c["candidate_owner"])
            + " — inspect owner candidate</a></article>"
        )
    chain = []
    for row in snapshot["release_chain"]:
        chain.append("<li><strong>" + esc(row["from"]) + " → " + esc(row["to"])
                     + "</strong>: " + esc(row["state"])
                     + "<br><span class='quiet'>" + esc(row["required"]) + "</span></li>")
    css = """body{margin:0;background:#09131a;color:#f1f5f9;font:1rem/1.6 system-ui,sans-serif}
    main{max-width:1180px;margin:auto;padding:clamp(1rem,4vw,3rem)}
    h1{line-height:1.15;letter-spacing:-.025em}h2{margin-top:2rem}
    .quiet{color:#b6c6d2}.tag{color:#ffc66b;font-size:.8rem;font-weight:700}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(270px,100%),1fr));gap:1rem}
    article{padding:1.1rem;background:#152633;border:1px solid #41566a;border-radius:12px}
    .control h3,.platform h3{margin:.2rem 0 .65rem}article p{overflow-wrap:anywhere}
    a{color:#8edfe0;text-underline-offset:.25rem}a:focus-visible{outline:3px solid #e8be61;outline-offset:4px}
    .banner{border:1px solid #c1a565;background:#342c20;padding:1rem;border-radius:10px}
    .banner strong{color:#fff0d1}ol li{margin-bottom:1rem}code{overflow-wrap:anywhere}
    """
    body = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<title>SZL | System design evidence map</title><style>" + css + "</style></head>"
        "<body><main><nav><a href='/'>Estate operations</a> · "
        "<a href='/api/system-design'>Machine-readable map</a></nav>"
        "<h1>System design, grounded in evidence</h1>"
        "<p class='banner' role='status'><strong>Design review only — no execution permission.</strong> "
        "Research patterns and public transport observations are not production readiness, "
        "complete private inventory, independent model evaluation, or payment settlement.</p>"
        "<p>External research: <a href='" + esc(snapshot["source"]["source_url"])
        + "' rel='noopener noreferrer'>Complete-System-Design (pinned README)</a>, "
        "an MIT-licensed educational reference, not runnable software.</p>"
        "<p class='quiet'>Public evidence basis: " + esc(snapshot["freshness"]) +
        " · collected: " + esc(snapshot["estate_observed_at"] or "UNKNOWN") + ".</p>"
        "<h2>Existing platform observations</h2><div class='grid'>"
        + "".join(lines) + "</div>"
        "<h2>Architecture controls — all require independent proof</h2><div class='grid'>"
        + "".join(controls) + "</div>"
        "<h2>Cross-surface release dependencies</h2><ol>"
        + "".join(chain) + "</ol>"
        "<p class='quiet'>A 200 response is transport, not an admission decision. "
        "Cloudflare account settlement and PyPI OIDC release proof are not fetched by this view. "
        "Unknown is not false, and missing evidence is not a passing test.</p>"
        "</main></body></html>"
    )
    return body.encode("utf-8")
