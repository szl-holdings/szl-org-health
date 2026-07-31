"""Dynamic Hugging Face models, datasets, Spaces, collections, and buckets."""
from __future__ import annotations

import concurrent.futures as cf
import urllib.parse
from typing import Any

from .common import http_probe, paginate_json, request_json, token_header

HF_ORG = "SZLHOLDINGS"
HF = "https://huggingface.co"
HEALTHZ_SPACES = {"a11oy", "killinchu", "yarqa", "anatomy"}
WEIGHT_SUFFIXES = (
    ".safetensors",
    ".gguf",
    ".bin",
    ".pt",
    ".pth",
    ".onnx",
    ".ckpt",
)


def hf_headers() -> dict[str, str]:
    return {
        "Accept": "application/json",
        **token_header(("HF_TOKEN", "HUGGING_FACE_HUB_TOKEN")),
    }


def hf_paginate(path: str, timeout: float = 30.0, retries: int = 2):
    return paginate_json(
        f"{HF}{path}",
        headers=hf_headers(),
        timeout=timeout,
        retries=retries,
        max_pages=30,
    )


def query(path: str, pairs: list[tuple[str, str]]) -> str:
    return f"{path}?{urllib.parse.urlencode(pairs)}"


def siblings(item: dict[str, Any]) -> list[str]:
    out = []
    for sibling in item.get("siblings") or []:
        if isinstance(sibling, dict):
            name = sibling.get("rfilename") or sibling.get("path")
        else:
            name = sibling
        if name:
            out.append(str(name))
    return out


def normalize_hf_repo(item: dict[str, Any], kind: str) -> dict[str, Any]:
    repo_id = str(
        item.get("id")
        or item.get("modelId")
        or item.get("datasetId")
        or "unknown"
    )
    repo_siblings = siblings(item)
    normalized = {
        "id": repo_id,
        "sha": item.get("sha"),
        "last_modified": item.get("lastModified") or item.get("last_modified"),
        "private": item.get("private"),
        "likes": item.get("likes"),
        "downloads_30d": item.get("downloads"),
        "file_count_observed": (
            len(repo_siblings) if item.get("siblings") is not None else None
        ),
        "url": f"{HF}/{repo_id}" if kind == "model" else f"{HF}/{kind}s/{repo_id}",
    }
    if kind == "model":
        weight_files = sorted(
            name for name in repo_siblings if name.lower().endswith(WEIGHT_SUFFIXES)
        )
        normalized.update(
            {
                "pipeline_tag": item.get("pipeline_tag"),
                "weight_files_observed": weight_files,
                "artifact_state": (
                    "weights-present"
                    if weight_files
                    else "no-weight-file-observed"
                    if item.get("siblings") is not None
                    else "unknown"
                ),
            }
        )
    return normalized


def space_runtime_url(item: dict[str, Any]) -> str | None:
    subdomain = item.get("subdomain")
    if not subdomain:
        repo_id = str(item.get("id") or "")
        if "/" in repo_id:
            owner, name = repo_id.split("/", 1)
            subdomain = f"{owner}-{name}".lower()
    if not subdomain:
        return None
    suffix = ".static.hf.space" if item.get("sdk") == "static" else ".hf.space"
    return f"https://{subdomain}{suffix}/"


def normalize_space(item: dict[str, Any]) -> dict[str, Any]:
    repo_id = str(item.get("id") or "unknown")
    name = repo_id.split("/", 1)[-1]
    runtime = item.get("runtime") if isinstance(item.get("runtime"), dict) else {}
    root_url = space_runtime_url(item)
    root_probe = (
        http_probe(root_url)
        if root_url
        else {"http": 0, "error": "runtime URL unavailable"}
    )
    healthz = None
    if name in HEALTHZ_SPACES and root_url:
        healthz = http_probe(urllib.parse.urljoin(root_url, "healthz")).get("http")
    return {
        "id": repo_id,
        "sha": item.get("sha"),
        "last_modified": item.get("lastModified"),
        "private": item.get("private"),
        "likes": item.get("likes"),
        "sdk": item.get("sdk"),
        "stage": runtime.get("stage") or "unknown",
        "hardware": runtime.get("hardware") or runtime.get("requestedHardware"),
        "subdomain": item.get("subdomain"),
        "runtime_url": root_url,
        "http": root_probe.get("http"),
        "probe_error": root_probe.get("error"),
        "healthz": healthz,
        "healthz_contract": name in HEALTHZ_SPACES,
        "url": f"{HF}/spaces/{repo_id}",
    }


def asset_result(items: list[dict[str, Any]] | None, error: str | None):
    return {
        "ok": items is not None,
        "count": len(items) if items is not None else None,
        "error": error,
        "items": items if items is not None else [],
    }


def _paths() -> dict[str, str]:
    models = query(
        "/api/models",
        [("author", HF_ORG), ("limit", "500")]
        + [
            ("expand[]", value)
            for value in (
                "author",
                "lastModified",
                "private",
                "sha",
                "pipeline_tag",
                "downloads",
                "likes",
                "siblings",
            )
        ],
    )
    datasets = query(
        "/api/datasets",
        [("author", HF_ORG), ("limit", "500")]
        + [
            ("expand[]", value)
            for value in (
                "author",
                "lastModified",
                "private",
                "sha",
                "downloads",
                "likes",
                "siblings",
            )
        ],
    )
    spaces = query(
        "/api/spaces",
        [("author", HF_ORG), ("limit", "500")]
        + [
            ("expand[]", value)
            for value in (
                "author",
                "lastModified",
                "private",
                "sha",
                "sdk",
                "runtime",
                "subdomain",
                "likes",
            )
        ],
    )
    collections = query(
        "/api/collections",
        [("owner", HF_ORG), ("sort", "lastModified"), ("limit", "100")],
    )
    return {
        "models": models,
        "datasets": datasets,
        "spaces": spaces,
        "collections": collections,
        "buckets": f"/api/buckets/{HF_ORG}",
    }


def _full_collection(item: dict[str, Any]) -> tuple[dict[str, Any], set[str]]:
    slug = str(item.get("slug") or item.get("id") or "")
    detail, _, error = request_json(
        f"{HF}/api/collections/{slug}",
        headers=hf_headers(),
        timeout=20,
        retries=1,
    )
    source = detail if isinstance(detail, dict) else item
    members = source.get("items") if isinstance(source.get("items"), list) else []
    counts: dict[str, int] = {}
    normalized_members = []
    bucket_ids: set[str] = set()
    for member in members:
        if not isinstance(member, dict):
            continue
        member_type = str(member.get("type") or member.get("item_type") or "unknown")
        member_id = str(member.get("id") or member.get("item_id") or "unknown")
        counts[member_type] = counts.get(member_type, 0) + 1
        if member_type == "bucket":
            bucket_ids.add(member_id)
        normalized_members.append({"id": member_id, "type": member_type})
    return (
        {
            "slug": slug,
            "title": source.get("title"),
            "owner": source.get("owner"),
            "private": source.get("private"),
            "last_updated": source.get("lastUpdated") or source.get("last_updated"),
            "upvotes": source.get("upvotes"),
            "item_counts": counts,
            "items": normalized_members,
            "complete": error is None,
            "detail_error": error,
            "url": f"{HF}/collections/{slug}",
        },
        bucket_ids,
    )


def collect_huggingface() -> dict[str, Any]:
    paths = _paths()
    with cf.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            name: executor.submit(hf_paginate, path) for name, path in paths.items()
        }
        raw = {name: future.result() for name, future in futures.items()}

    models_raw, models_error = raw["models"]
    datasets_raw, datasets_error = raw["datasets"]
    spaces_raw, spaces_error = raw["spaces"]
    collections_raw, collections_error = raw["collections"]
    buckets_raw, buckets_error = raw["buckets"]

    models = (
        sorted(
            (normalize_hf_repo(item, "model") for item in models_raw),
            key=lambda value: value["id"],
        )
        if models_raw is not None
        else None
    )
    datasets = (
        sorted(
            (normalize_hf_repo(item, "dataset") for item in datasets_raw),
            key=lambda value: value["id"],
        )
        if datasets_raw is not None
        else None
    )

    spaces: list[dict[str, Any]] | None = None
    if spaces_raw is not None:
        with cf.ThreadPoolExecutor(max_workers=6) as executor:
            spaces = sorted(
                executor.map(normalize_space, spaces_raw), key=lambda value: value["id"]
            )

    collections: list[dict[str, Any]] | None = None
    collection_bucket_ids: set[str] = set()
    if collections_raw is not None:
        with cf.ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(_full_collection, collections_raw))
        collections = sorted(
            (collection for collection, _ in results),
            key=lambda value: value["slug"],
        )
        for _, bucket_ids in results:
            collection_bucket_ids.update(bucket_ids)

    buckets: list[dict[str, Any]] | None = None
    if buckets_raw is not None:
        buckets = sorted(
            (
                {
                    "id": item.get("id"),
                    "private": item.get("private"),
                    "created_at": item.get("createdAt"),
                    "size_bytes": item.get("size"),
                    "total_files": item.get("totalFiles"),
                }
                for item in buckets_raw
            ),
            key=lambda value: str(value["id"]),
        )
    elif collection_bucket_ids:
        buckets = [
            {"id": value, "discovered_via": "collection"}
            for value in sorted(collection_bucket_ids)
        ]
        buckets_error = (
            f"direct bucket listing unavailable ({buckets_error}); collection-only scope"
        )

    assets = {
        "models": asset_result(models, models_error),
        "datasets": asset_result(datasets, datasets_error),
        "spaces": asset_result(spaces, spaces_error),
        "collections": asset_result(collections, collections_error),
        "buckets": asset_result(buckets, buckets_error),
    }
    return {
        "organization": HF_ORG,
        "assets": assets,
        "summary": {
            **{name: source["count"] for name, source in assets.items()},
            "running_spaces": (
                sum(1 for space in spaces or [] if space.get("stage") == "RUNNING")
                if spaces is not None
                else None
            ),
            "reachable_spaces": (
                sum(
                    1
                    for space in spaces or []
                    if 200 <= int(space.get("http") or 0) < 400
                )
                if spaces is not None
                else None
            ),
            "models_with_observed_weights": (
                sum(
                    1
                    for model in models or []
                    if model.get("artifact_state") == "weights-present"
                )
                if models is not None
                else None
            ),
        },
    }
