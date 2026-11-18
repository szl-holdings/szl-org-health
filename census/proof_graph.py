# SPDX-License-Identifier: Apache-2.0
"""Read-only investor/developer graph of *public* estate observations.

Every edge means membership in a public source subset, never deployment parity,
runtime execution, transaction settlement, or an approved external action.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from urllib.parse import urlsplit

from .portal_projection import project_portal_index
from .report import project_public_report

SCHEMA = "szl.public-source-topology/v1"
KINDS = ("models", "datasets", "spaces", "kernels", "collections", "buckets")
NAME = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
ASSET_ID = re.compile(r"^SZLHOLDINGS/[A-Za-z0-9_.-]{1,120}$", re.I)
MAX_PUBLIC_NODES = 800
HUB = {"github": "https://github.com/szl-holdings",
       "huggingface": "https://huggingface.co/SZLHOLDINGS",
       "product": "https://a-11-oy.com", "proof": "https://a11oy.net"}


def permitted_url(url, host):
    if not isinstance(url, str) or len(url) > 350:
        return False
    try:
        parts = urlsplit(url)
        return (parts.scheme == "https" and parts.hostname == host
                and parts.port is None and not parts.username and not parts.password
                and not parts.query and not parts.fragment)
    except ValueError:
        return False


def _input_public_asset_ids(report):
    """Select exact public ID/URL pairs before the closed projector normalizes URLs.

    Projectors intentionally synthesize canonical URLs from public IDs. A
    mismatched supplied URL cannot become proof merely through normalization.
    """
    permitted = {kind: set() for kind in KINDS}
    sources = report.get("sources") if isinstance(report, Mapping) else None
    hf = sources.get("huggingface") if isinstance(sources, Mapping) else None
    hf_data = hf.get("data") if isinstance(hf, Mapping) else None
    assets = hf_data.get("assets") if isinstance(hf_data, Mapping) else None
    if not isinstance(assets, Mapping):
        return permitted
    for kind in KINDS:
        group = assets.get(kind)
        if not isinstance(group, Mapping) or group.get("ok") is not True:
            continue
        items = group.get("items")
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, Mapping) or item.get("private") is not False:
                continue
            key = "slug" if kind == "collections" else "id"
            identifier = item.get(key)
            if not isinstance(identifier, str) or not ASSET_ID.fullmatch(identifier):
                continue
            url = item.get("url")
            path = ("/" if kind == "models" else f"/{kind}/") + identifier
            if permitted_url(url, "huggingface.co") and urlsplit(url).path == path:
                permitted[kind].add(identifier)
    return permitted


def project_proof_graph(report):
    """Project a closed public report before emitting any node or URL."""
    # Never project the credential-derived internal report directly.
    if not isinstance(report, Mapping) or report.get("exposure") != "public":
        raise ValueError("only a closed public estate projection is admissible")
    exact_public_assets = _input_public_asset_ids(report)
    public = project_public_report(report)
    portal = project_portal_index(public)
    nodes = []
    edges = []
    for kind, url in HUB.items():
        layer = portal["layers"][kind]
        nodes.append({"id": "hub:" + kind, "kind": "hub", "label": kind.upper(),
                      "url": url, "evidence_class": layer["evidence_class"],
                      "claim_scope": layer["scope"],
                      "runtime_verified": False})
    sources = public.get("sources", {})
    github = sources.get("github", {}) if isinstance(sources, dict) else {}
    repos = (github.get("data") or {}).get("repos") if isinstance(github, dict) else None
    head_sample_fresh = (
        github.get("diagnostic_state") == "PUBLIC_SUBSET"
        and github.get("error") is None
        and portal["freshness"]["within_24h"] is True
    )
    if isinstance(repos, Mapping):
        for name, data in sorted(repos.items()):
            if len(nodes) >= MAX_PUBLIC_NODES:
                break
            if not (isinstance(name, str) and NAME.fullmatch(name)
                    and isinstance(data, Mapping)
                    and data.get("visibility") == "public"):
                continue
            url = data.get("url")
            if url != f"https://github.com/szl-holdings/{name}":
                continue
            uid = "repo:" + name
            nodes.append({"id": uid, "kind": "github_repository", "label": name,
                          "url": url, "archived": data.get("archived"),
                          "evidence_class": portal["layers"]["github"]["evidence_class"],
                          "claim_scope": "public-repository-subset",
                          "head_ci": (data.get("head_ci", "UNAVAILABLE")
                                      if head_sample_fresh else "UNAVAILABLE"),
                          "runtime_verified": False})
            edges.append({"source": "hub:github", "target": uid,
                          "relation": "public_membership_observed",
                          "source_deployment_parity": "UNKNOWN"})
    huggingface = sources.get("huggingface", {}) if isinstance(sources, dict) else {}
    assets = (huggingface.get("data") or {}).get("assets") if isinstance(huggingface, dict) else None
    if isinstance(assets, Mapping):
        for kind in KINDS:
            group = assets.get(kind)
            items = group.get("items") if isinstance(group, Mapping) and group.get("ok") is True else None
            if not isinstance(items, list):
                continue
            for asset in items:
                if len(nodes) >= MAX_PUBLIC_NODES:
                    break
                if not isinstance(asset, Mapping) or asset.get("private") is not False:
                    continue
                identifier = asset.get("id") or asset.get("slug")
                url = asset.get("url")
                if not isinstance(identifier, str) or not ASSET_ID.fullmatch(identifier):
                    continue
                if identifier not in exact_public_assets[kind]:
                    continue
                if not permitted_url(url, "huggingface.co"):
                    continue
                expected_path = ("/" if kind == "models" else "/" + kind + "/") + identifier
                if urlsplit(url).path != expected_path:
                    continue  # A same-host URL is not evidence for this exact asset ID.
                uid = kind + ":" + identifier
                nodes.append({"id": uid, "kind": "huggingface_" + kind,
                              "label": identifier.split("/", 1)[1], "url": url,
                              "evidence_class": portal["layers"]["huggingface"]["evidence_class"],
                              "claim_scope": "public-hub-metadata-subset",
                              "runtime_verified": False})
                edges.append({"source": "hub:huggingface", "target": uid,
                              "relation": "public_membership_observed",
                              "source_deployment_parity": "UNKNOWN"})
    # These three dashed cross-provider links are explicit missing proof,
    # not assertions that bytes, deployments, receipts, or settlements agree.
    for left, right in (("github", "huggingface"), ("huggingface", "product"),
                        ("product", "proof")):
        edges.append({"source": "hub:" + left, "target": "hub:" + right,
                      "relation": "PARITY_NOT_ESTABLISHED",
                      "source_deployment_parity": "UNKNOWN"})
    doc = {
        "schema": SCHEMA,
        "generated_at": portal.get("generated_at"),
        "observation_age_seconds": portal["freshness"]["age_seconds"],
        "within_24h": portal["freshness"]["within_24h"],
        "source_scope": "PUBLIC_SUBSET_ONLY",
        "all_repository_coverage": "UNKNOWN",
        "node_limit_reached": len(nodes) >= MAX_PUBLIC_NODES,
        "cross_provider_parity": "UNKNOWN",
        "runtime_readiness": "UNKNOWN",
        "model_quality": "UNKNOWN",
        "revenue_settlement": "UNKNOWN",
        "release_authority": "UNKNOWN",
        "nodes": nodes,
        "edges": edges,
    }
    payload = json.dumps(doc, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    doc["content_sha256"] = hashlib.sha256(payload).hexdigest()
    doc["signature_state"] = "UNSIGNED_STRUCTURAL_HASH_ONLY"
    return doc
